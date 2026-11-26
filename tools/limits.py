#!/usr/bin/env python3
"""Time limits (notes/time-limits.md, Limits): every timed run against its CPU and wall limit.

  tools/limits.py run NAME CMD...      run CMD, then check its CPU-s and wall against NAME's limits
  tools/limits.py check NAME CPU WALL [--since T]
                                       check a measured run (gate.sh's steps); over a limit with
                                       shares, also its parts checked here since T (epoch s;
                                       default: the run's start) that went over their share
  tools/limits.py summary [--since HOURS] [--all]
                                       this box's hits and the investigation triggers (--all:
                                       every check)
  tools/limits.py unit                 measure this box's base unit (alone: take the heavy lock)
  tools/limits.py table                every limit in seconds on this box
  tools/limits.py split                every whole's shares sum to at most it (exits 1 if not)
  tools/limits.py derive [--gates N]   shares re-derived from this box's last N (default 10) gates
                                       in limits.log, as table rows to copy into the note
  tools/limits.py tests [--jobs N]     every default test against the `test` limit (under tools/heavy)

Limits are multiples of the box's base unit u (tools/baseunit.c: the CPU-s of one fixed work
quantum with every hardware thread busy), both read from the tables in notes/time-limits.md: a CPU limit
is k u, a wall limit k u 16 / threads (16 quanta spread over the box's threads; ostrich has 16). A check never fails the run: it prints one line, and a line per limit exceeded:
`LIMIT CAP` over a whole other limits share (`gate`, `gate.hold`: Tess's cap), an indented
`over share:` for a stage over only its share, `LIMIT` for any other limit; it appends the check to ~/.cache/osis/limits.log (JSON lines:
time, box, name, cpu, wall, limits, the 1-minute load, over), the record of every hit. A limit's
`share of` cell names the whole it is a share of (a gate stage of `gate.hold` or `gate`): the
shares of a whole sum to at most it, so a whole over its limit names its parts over their share.
"""
import json, os, re, resource, socket, statistics, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTE = os.path.join(ROOT, "notes", "time-limits.md")
LOG = os.path.expanduser("~/.cache/osis/limits.log")
BOX = socket.gethostname().split(".")[0]
# The investigation triggers (notes/time-limits.md, Policy): the same limit hit this many
# times within this window, or one run over this multiple of its limit.
REPEAT, WINDOW_H, FAR = 5, 3, 2.0


def tables():
    """({box: unit}, {name: (cpu_units, wall_units, whole or None)}) from notes/time-limits.md."""
    units, limits, kind = {}, {}, None
    for line in open(NOTE):
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if not line.startswith("|"):
            kind = None
        elif cells[0] == "box":
            kind = "units"
        elif cells[0] == "limit":
            kind = "limits"
        elif kind and not set(cells[0]) <= set("-: "):
            try:
                if kind == "units":
                    units[cells[0]] = float(cells[1])
                else:
                    limits[cells[0]] = (float(cells[1]), float(cells[2]), cells[3] if len(cells) > 3 and cells[3] else None)
            except (IndexError, ValueError):
                continue
    return units, limits


def limit(name):
    """(cpu_limit_s, wall_limit_s) on this box, or None with the reason."""
    units, limits = tables()
    if name not in limits:
        return None, f"no limit named {name} in notes/time-limits.md"
    if BOX not in units:
        return None, f"no base unit for box {BOX}: tools/limits.py unit, then add it to notes/time-limits.md"
    u, (cl, wl, _) = units[BOX], limits[name]
    return (cl * u, wl * u * 16 / os.cpu_count()), None


def log(rec):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"limits: log: {e}", file=sys.stderr)


def check(name, cpu, wall, what="", quiet=False, since=None):
    """Check one run; `what` names it within `name` (a test). Returns the limits exceeded. Over a
    limit with shares, also prints its parts checked from here since `since` (default: the run's
    start) that went over their share."""
    lim, why = limit(name)
    if lim is None:
        print(f"   limit {name}: unchecked ({why})")
        return []
    over = [(k, v, l) for k, v, l in (("CPU", cpu, lim[0]), ("wall", wall, lim[1])) if v > l]
    label = f"{name} {what}".strip()
    if not quiet or over:
        print(f"   limit {label}: CPU {cpu:.0f}/{lim[0]:.0f} s, wall {wall:.0f}/{lim[1]:.0f} s")
    role = kind(name)
    for k, v, l in over:
        far = " (over 2x: an investigation, notes/time-limits.md, Policy)" if v > FAR * l else ""
        hit = f"{label} {k} {v:.0f} s > {l:.0f} s ({v / l:.2f}x) on {BOX} at load {os.getloadavg()[0]:.0f}{far}"
        if role == "share":
            print(f"   over share: {hit}, over its share of {tables()[1][name][2]}, not a cap")
        else:
            cap = " CAP" if role == "cap" else ""
            print(f"LIMIT{cap} {hit}: {'over the cap (notes/time-limits.md, Limits); ' if cap else ''}report why (notes/time-limits.md, Patterns)")
    log(dict(t=round(time.time()), box=BOX, name=name, what=what, cpu=round(cpu, 1), wall=round(wall, 1),
             cpu_lim=round(lim[0], 1), wall_lim=round(lim[1], 1), load=round(os.getloadavg()[0], 1),
             over=[k for k, _, _ in over], who=os.getcwd(), **(dict(since=round(since)) if since is not None else {})))
    if over:
        shares(name, since if since is not None else time.time() - wall - 1)
    return over


def kind(name):
    """"cap" for a whole other limits are shares of (`gate`, `gate.hold`: Tess's cap), "share"
    for a share that is no whole itself (a gate stage), "" for a limit on its own."""
    limits = tables()[1]
    if any(w == name for _, _, w in limits.values()):
        return "cap"
    return "share" if name in limits and limits[name][2] else ""


def shares(whole, since):
    """The parts of `whole` checked from this directory since `since` that went over their share."""
    parts = {n for n, (_, _, w) in tables()[1].items() if w == whole}
    if not parts:
        return
    here = os.getcwd()
    hit = [o for o in jsonl([LOG], since) if o["name"] in parts and o.get("who") == here and o["over"]]
    for o in hit:
        print(f"   over its share of {whole}: " + hit_line(o).split(f" {o['box']} ", 1)[1])
    if not hit:
        print(f"   no part of {whole} over its share: the time between its parts, or parts unchecked")


def split():
    """Every whole's shares sum to at most it: 0 if so, else 1 with each whole over."""
    _, limits = tables()
    bad = 0
    for whole in sorted({w for _, _, w in limits.values() if w}):
        parts = [n for n, (_, _, w) in limits.items() if w == whole]
        if whole not in limits:
            print(f"{whole}: no such limit, yet {', '.join(parts)} share it")
            bad = 1
            continue
        for i, k in ((0, "CPU"), (1, "wall")):
            total = sum(limits[n][i] for n in parts)
            ok = total <= limits[whole][i]
            bad |= not ok
            print(f"{whole} {k}: shares {total:g} of {limits[whole][i]:g} u{'' if ok else '  OVER'} ({', '.join(f'{n} {limits[n][i]:g}' for n in parts)})")
    return bad


def runs(top, n):
    """This box's last n checks of `top`, each with {name: [(cpu, wall), ...]}: the checks made in
    its directory since its run began (its `since`, as gate.sh passes it; without one, since the
    check of `top` before it there, at most WINDOW_H back), in order."""
    ev = [o for o in jsonl([LOG]) if o.get("box") == BOX and not o.get("what")]
    out, prev = [], {}
    for o in ev:
        if o["name"] != top:
            continue
        lo = o["since"] - 1 if "since" in o else max(prev.get(o.get("who"), 0), o["t"] - WINDOW_H * 3600)
        prev[o.get("who")] = o["t"]
        got = {}
        for x in ev:
            if x.get("who") == o.get("who") and lo < x["t"] <= o["t"] and x is not o:
                got.setdefault(x["name"], []).append((x["cpu"], x["wall"]))
        got[top] = [(o["cpu"], o["wall"])]
        out.append(got)
    return out[-n:]


def derive(n):
    """Each whole's shares from the last n runs of the top whole: a part's share is the whole's limit
    times the median fraction of the whole it took in the runs where it ran (a stage that runs in
    few gates, as the unification check, is judged by those alone, and the others' shares do not
    move for it), so the rest is the time between the parts. Fractions summing over 1 are scaled
    down to fit. A part never measured keeps its share, taken off the top. Floors, so the shares
    still sum to at most their whole. Prints table rows in u, then each limit of its own seen in
    those runs with its spread; returns {name: (cpu_u, wall_u)}."""
    units, limits = tables()
    if BOX not in units:
        sys.exit(f"limits: no base unit for box {BOX}")
    u = units[BOX]
    whole_of = {k: w for k, (_, _, w) in limits.items() if w}
    tops = sorted({w for w in whole_of.values() if w not in whole_of})
    floor = lambda x: int(x * 10) / 10 if x < 10 else float(int(x))
    out = {}

    def split_whole(whole, budget, rs):
        parts = [k for k, w in whole_of.items() if w == whole]
        ran = {k: [r for r in rs if k in r and whole in r] for k in parts}
        frac = {k: [statistics.median(r[k][i] / r[whole][i] if r[whole][i] else 0 for r in ran[k]) for i in (0, 1)] for k in parts if ran[k]}
        for i in (0, 1):
            avail = budget[i] - sum(limits[k][i] for k in parts if k not in frac)
            scale = 1 / max(1.0, sum(f[i] for f in frac.values()))
            for k in parts:
                out.setdefault(k, list(limits[k][:2]))
                if k in frac:
                    out[k][i] = floor(avail * frac[k][i] * scale)
        for k in parts:
            print(f"| `{k}` | {out[k][0]:g} | {out[k][1]:g} | `{whole}` |   ({frac[k][0]:.0%} of its CPU, {frac[k][1]:.0%} of its wall in the {len(ran[k])} runs it ran)" if k in frac
                  else f"| `{k}` | {out[k][0]:g} | {out[k][1]:g} | `{whole}` |   (not measured: kept)")
        for k in parts:
            if k in whole_of.values():
                split_whole(k, out[k], rs)

    for top in tops:
        rs = runs(top, n)
        print(f"{top}: {len(rs)} runs on {BOX}")
        if rs:
            # a part's time in a run is its checks summed (a stage checked twice in one gate)
            split_whole(top, limits[top][:2], [{k: tuple(map(sum, zip(*v))) for k, v in r.items()} for r in rs])
        # a limit of its own holds each check (each rate replay), so its spread is over checks
        for k in sorted({k for r in rs for k in r if k in limits and k not in whole_of and k != top}):
            v = [x for r in rs for x in r.get(k, [])]
            spread = lambda i: ", ".join(f"{q} {f(x[i] for x in v) / u:.1f}" for q, f in (("median", statistics.median), ("p90", p90), ("most", max)))
            print(f"   `{k}`, its own limit {limits[k][0]:g} u CPU, {limits[k][1]:g} u wall, {len(v)} checks: CPU {spread(0)} u; wall {spread(1)} u")
    return {k: tuple(v) for k, v in out.items()}


def p90(xs):
    """The 90th percentile (nearest rank) of xs."""
    xs = sorted(xs)
    return xs[max(0, -(-9 * len(xs) // 10) - 1)]


def tests(jobs):
    """Every default test as its own process, `jobs` at a time, against the `test` CPU limit; the
    ones over either limit (or near the wall limit, which this concurrent run inflates) again
    alone, each the box's only test. Take the heavy lock first."""
    common = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip()
    if os.path.dirname(common) == ROOT:
        sys.exit(f"limits: {ROOT} is the main checkout, and `tests` builds and runs every default test: "
                 "run it from a task worktree under tools/heavy")
    from pertest import default_tests, test_env, timed
    todo, env = default_tests(ROOT), test_env()
    print(f"{len(todo)} default tests in {len({t[2] for t in todo})} binaries, {jobs} at a time")
    lim, why = limit("test")
    if lim is None:
        sys.exit(f"limits: {why}")
    from concurrent.futures import ThreadPoolExecutor

    def one(t):
        exe, cwd, _, n = t
        rc, cpu, wall, _ = timed([exe, "--exact", n, "--test-threads=1"], cwd, env)
        return t, rc, cpu, wall
    with ThreadPoolExecutor(jobs) as ex:
        res = list(ex.map(one, todo))
    again = [(t, cpu, wall) for t, rc, cpu, wall in res if cpu > lim[0] / 2 or wall > lim[1] / 2]
    failed = [t[3] for t, rc, _, _ in res if rc]
    print(f"{sum(r[2] for r in res):.0f} CPU-s in all; {len(failed)} failed{': ' + ' '.join(failed[:10]) if failed else ''}; "
          f"{len(again)} over half a limit, timed again alone:")
    hits = 0
    for (exe, cwd, label, n), cpu0, wall0 in sorted(again, key=lambda x: -x[1]):
        _, cpu, wall, _ = timed([exe, "--exact", n, "--test-threads=1"], cwd, env)
        print(f"   ({label} {n}: {cpu0:.0f} CPU-s, {wall0:.0f} s beside the others)")
        hits += bool(check("test", cpu, wall, f"{label} {n}"))
    print(f"{hits} tests over a limit")


def run(name, cmd):
    t0, r0 = time.time(), resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        rc = subprocess.call(cmd)
    except OSError as e:
        sys.exit(f"limits: {cmd[0]}: {e}")
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    safe_check(name, r1.ru_utime + r1.ru_stime - r0.ru_utime - r0.ru_stime, time.time() - t0)
    return 128 - rc if rc < 0 else rc


def safe_check(name, cpu, wall):
    """`check` for a wrapper whose exit code is its command's: a broken table or log prints, never raises."""
    try:
        check(name, cpu, wall)
    except Exception as e:  # noqa: BLE001: report-only
        print(f"   limit {name}: unchecked ({type(e).__name__}: {e})")


def jsonl(paths, since=0):
    """The objects of JSON-lines logs (limits.log, tools/heavy's) from epoch second `since` on;
    a missing file or a bad line is skipped."""
    out = []
    for path in paths:
        try:
            lines = open(path).readlines()
        except OSError:
            continue
        for line in lines:
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if o.get("t", 0) >= since:
                out.append(o)
    return out


def stamp(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t))


def hit_line(o):
    parts = [f"{k} {o[k.lower()]:.0f}/{o[k.lower() + '_lim']:.0f} s" for k in ("CPU", "wall") if k in o["over"]]
    what = f" {o['what']}" if o.get("what") else ""
    return f"- {stamp(o['t'])} {o['box']} `{o['name']}`{what} {', '.join(parts)} at load {o['load']:.0f}"


def summary(hours, every):
    ev = jsonl([LOG], time.time() - hours * 3600 if hours else 0)
    hits = [o for o in ev if o["over"]]
    tag = lambda n: {"cap": " (CAP)", "share": " (share)"}.get(kind(n), "")
    for o in (ev if every else hits):
        print(hit_line(o) + tag(o["name"]) if o["over"] else f"  {stamp(o['t'])} {o['box']} `{o['name']}` CPU {o['cpu']:.0f}/{o['cpu_lim']:.0f} s, "
              f"wall {o['wall']:.0f}/{o['wall_lim']:.0f} s at load {o['load']:.0f}")
    caps = sum(1 for o in hits if kind(o["name"]) == "cap")
    part = sum(1 for o in hits if kind(o["name"]) == "share")
    print(f"{len(ev)} checks, {len(hits)} over a limit ({caps} over a cap, {part} over a share only), on {BOX} ({LOG})")
    # triggers: one limit (name and kind) hit REPEAT times within WINDOW_H; one run over FAR x
    by = {}
    for o in hits:
        for k in o["over"]:
            by.setdefault((f'{o["name"]}` {o.get("what", "")}'.strip(), k, o["name"]), []).append(o["t"])
    for (n, k, name), ts in sorted(by.items()):
        for i in range(len(ts) - REPEAT + 1):
            if ts[i + REPEAT - 1] - ts[i] <= WINDOW_H * 3600:
                print(f"TRIGGER `{n} {k}{tag(name)}: {REPEAT} hits within {WINDOW_H} h from {stamp(ts[i])}: investigate")
                break
    for o in hits:
        for k in o["over"]:
            v, l = o[k.lower()], o[k.lower() + "_lim"]
            if v > FAR * l:
                print(f"TRIGGER `{o['name']}` {k}{tag(o['name'])} {v / l:.1f}x its limit at {stamp(o['t'])}: investigate")


def unit():
    src = os.path.join(ROOT, "tools", "baseunit.c")
    exe = os.path.expanduser("~/.cache/osis/baseunit")
    if not os.path.exists(exe) or os.path.getmtime(src) > os.path.getmtime(exe):
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        subprocess.check_call(["cc", "-O2", "-Wall", "-pthread", "-o", exe, src])
    runs = []
    for _ in range(5):
        m = re.search(r"WALL (\S+) CPU (\S+)", subprocess.check_output([exe], text=True))
        runs.append(float(m[2]) / 16)
        print(f"{runs[-1]:.3f} CPU-s per quantum (wall {float(m[1]):.1f} s), load {os.getloadavg()[0]:.1f}")
    runs.sort()
    print(f"| {BOX} | {runs[2]:.3f} |   (the median of 5; take the lock first: tools/heavy tools/limits.py unit)")


def table():
    units, limits = tables()
    print(f"box {BOX}: unit {units.get(BOX, 'unmeasured')}")
    for n in limits:
        lim, why = limit(n)
        print(f"  {n:24s} " + (f"CPU {lim[0]:7.0f} s  wall {lim[1]:7.0f} s" if lim else why))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["run"] and len(a) > 2:
        sys.exit(run(a[1], a[2:]))
    elif a[:1] == ["check"] and len(a) in (4, 6) and (len(a) == 4 or a[4] == "--since"):
        check(a[1], float(a[2]), float(a[3]), since=float(a[5]) if len(a) == 6 else None)
    elif a[:1] == ["summary"]:
        h = float(a[a.index("--since") + 1]) if "--since" in a else 0
        summary(h, "--all" in a)
    elif a[:1] == ["tests"]:
        tests(int(a[a.index("--jobs") + 1]) if "--jobs" in a else max(1, os.cpu_count() // 2))
    elif a == ["unit"]:
        unit()
    elif a == ["table"]:
        table()
    elif a == ["split"]:
        sys.exit(split())
    elif a[:1] == ["derive"]:
        derive(int(a[a.index("--gates") + 1]) if "--gates" in a else 10)
    else:
        sys.exit(__doc__)
