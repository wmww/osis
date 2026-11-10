#!/usr/bin/env python3
"""Time limits (notes/build.md, Time limits): every timed run against its CPU and wall limit.

  tools/limits.py run NAME CMD...      run CMD, then check its CPU-s and wall against NAME's limits
  tools/limits.py check NAME CPU WALL  check a measured run (gate.sh's steps)
  tools/limits.py summary [--since HOURS] [--all]
                                       this box's hits, the investigation triggers, and the hits
                                       notes/time-limits.md does not record yet (--all: every check)
  tools/limits.py unit                 measure this box's base unit (alone: take the heavy lock)
  tools/limits.py table                every limit in seconds on this box
  tools/limits.py tests [--jobs N]     every default test against the `test` limit (under tools/heavy)

Limits are multiples of the box's base unit u (tools/baseunit.c: the CPU-s of one fixed work
quantum with every hardware thread busy), both read from the tables in notes/build.md: a CPU limit
is k u, a wall limit k u 16 / threads (16 quanta spread over the box's threads; ostrich has 16). A check never fails the run: it prints one line, and an over-limit line starting
`LIMIT` for each limit exceeded, and appends the check to ~/.cache/osis/limits.log (JSON lines:
time, box, name, cpu, wall, limits, the 1-minute load, over). Hits are copied to the committed
notes/time-limits.md with the agent's reason (`summary` prints them in its format).
"""
import json, os, re, resource, socket, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTE = os.path.join(ROOT, "notes", "build.md")
RECORD = os.path.join(ROOT, "notes", "time-limits.md")
LOG = os.path.expanduser("~/.cache/osis/limits.log")
BOX = socket.gethostname().split(".")[0]
# The investigation triggers (notes/coordination.md, Time limits): the same limit hit this many
# times within this window, or one run over this multiple of its limit.
REPEAT, WINDOW_H, FAR = 5, 3, 2.0


def tables():
    """({box: unit}, {name: (cpu_units, wall_units)}) from notes/build.md."""
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
                    limits[cells[0]] = (float(cells[1]), float(cells[2]))
            except (IndexError, ValueError):
                continue
    return units, limits


def limit(name):
    """(cpu_limit_s, wall_limit_s) on this box, or None with the reason."""
    units, limits = tables()
    if name not in limits:
        return None, f"no limit named {name} in notes/build.md"
    if BOX not in units:
        return None, f"no base unit for box {BOX}: tools/limits.py unit, then add it to notes/build.md"
    u, (cl, wl) = units[BOX], limits[name]
    return (cl * u, wl * u * 16 / os.cpu_count()), None


def log(rec):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"limits: log: {e}", file=sys.stderr)


def check(name, cpu, wall, what="", quiet=False):
    """Check one run; `what` names it within `name` (a test). Returns the limits exceeded."""
    lim, why = limit(name)
    if lim is None:
        print(f"   limit {name}: unchecked ({why})")
        return []
    over = [(k, v, l) for k, v, l in (("CPU", cpu, lim[0]), ("wall", wall, lim[1])) if v > l]
    label = f"{name} {what}".strip()
    if not quiet or over:
        print(f"   limit {label}: CPU {cpu:.0f}/{lim[0]:.0f} s, wall {wall:.0f}/{lim[1]:.0f} s")
    for k, v, l in over:
        far = " (over 2x: an investigation, notes/coordination.md Time limits)" if v > FAR * l else ""
        print(f"LIMIT {label} {k} {v:.0f} s > {l:.0f} s ({v / l:.2f}x) on {BOX} at load {os.getloadavg()[0]:.0f}{far}: "
              f"report why (notes/time-limits.md)")
    log(dict(t=round(time.time()), box=BOX, name=name, what=what, cpu=round(cpu, 1), wall=round(wall, 1),
             cpu_lim=round(lim[0], 1), wall_lim=round(lim[1], 1), load=round(os.getloadavg()[0], 1),
             over=[k for k, _, _ in over], who=os.getcwd()))
    return over


def timed(cmd, cwd=None, env=None):
    """(rc, CPU-s, wall, output) of one process, its children included."""
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.read()
    _, status, ru = os.wait4(p.pid, 0)
    return os.waitstatus_to_exitcode(status), ru.ru_utime + ru.ru_stime, time.time() - t0, out.decode(errors="replace")


def tests(jobs):
    """Every default test as its own process, `jobs` at a time, against the `test` CPU limit; the
    ones over either limit (or near the wall limit, which this concurrent run inflates) again
    alone, each the box's only test. Take the heavy lock first."""
    out = subprocess.run(["cargo", "test", "--locked", "--no-run", "--message-format=json"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    bins = []
    for line in out.splitlines():
        o = json.loads(line)
        if o.get("reason") == "compiler-artifact" and o.get("executable") and o["profile"]["test"]:
            # `path+file:///…/dir#name@0.1.0`, or `…/name#0.1.0` when the name is the dir's
            url, frag = o["package_id"].rsplit("#", 1)
            pkg = frag.split("@")[0] if "@" in frag else url.rstrip("/").rsplit("/", 1)[-1]
            bins.append((o["executable"], os.path.dirname(o["manifest_path"]), f"{pkg} {o['target']['name']}"))
    # what `cargo test` sets that a test may read: .cargo/config.toml's [env]
    env = dict(os.environ, PROPTEST_CASES=os.environ.get("PROPTEST_CASES", "32"))
    todo = []
    for exe, cwd, label in bins:
        def listed(*a):
            r = subprocess.run([exe, "--list", "--format=terse", *a], cwd=cwd, env=env, capture_output=True, text=True)
            return {l.rsplit(": ", 1)[0] for l in r.stdout.splitlines() if l.endswith(": test")}
        todo += [(exe, cwd, label, n) for n in sorted(listed() - listed("--ignored"))]
    print(f"{len(todo)} default tests in {len(bins)} binaries, {jobs} at a time")
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
    check(name, r1.ru_utime + r1.ru_stime - r0.ru_utime - r0.ru_stime, time.time() - t0)
    return 128 - rc if rc < 0 else rc


def read_log(since):
    out = []
    try:
        for line in open(LOG):
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if o.get("t", 0) >= since:
                out.append(o)
    except OSError:
        pass
    return out


def stamp(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def hit_line(o):
    parts = [f"{k} {o[k.lower()]:.0f}/{o[k.lower() + '_lim']:.0f} s" for k in ("CPU", "wall") if k in o["over"]]
    what = f" {o['what']}" if o.get("what") else ""
    return f"- {stamp(o['t'])} {o['box']} `{o['name']}`{what} {', '.join(parts)} at load {o['load']:.0f}"


def summary(hours, every):
    ev = read_log(time.time() - hours * 3600 if hours else 0)
    hits = [o for o in ev if o["over"]]
    for o in (ev if every else hits):
        print(hit_line(o) if o["over"] else f"  {stamp(o['t'])} {o['box']} `{o['name']}` CPU {o['cpu']:.0f}/{o['cpu_lim']:.0f} s, "
              f"wall {o['wall']:.0f}/{o['wall_lim']:.0f} s at load {o['load']:.0f}")
    print(f"{len(ev)} checks, {len(hits)} over a limit, on {BOX} ({LOG})")
    # triggers: one limit (name and kind) hit REPEAT times within WINDOW_H; one run over FAR x
    by = {}
    for o in hits:
        for k in o["over"]:
            by.setdefault((f'{o["name"]}` {o.get("what", "")}'.strip(), k), []).append(o["t"])
    for (n, k), ts in sorted(by.items()):
        for i in range(len(ts) - REPEAT + 1):
            if ts[i + REPEAT - 1] - ts[i] <= WINDOW_H * 3600:
                print(f"TRIGGER `{n} {k}: {REPEAT} hits within {WINDOW_H} h from {stamp(ts[i])}: investigate")
                break
    for o in hits:
        for k in o["over"]:
            v, l = o[k.lower()], o[k.lower() + "_lim"]
            if v > FAR * l:
                print(f"TRIGGER `{o['name']}` {k} {v / l:.1f}x its limit at {stamp(o['t'])}: investigate")
    known = open(RECORD).read() if os.path.exists(RECORD) else ""
    new = [o for o in hits if hit_line(o).split(" CPU ")[0].split(" wall ")[0] not in known]
    if new:
        print(f"\nnot yet in notes/time-limits.md (add each with its reason):")
        for o in new:
            print(hit_line(o) + ": <why>")


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
    elif a[:1] == ["check"] and len(a) == 4:
        check(a[1], float(a[2]), float(a[3]))
    elif a[:1] == ["summary"]:
        h = float(a[a.index("--since") + 1]) if "--since" in a else 0
        summary(h, "--all" in a)
    elif a[:1] == ["tests"]:
        tests(int(a[a.index("--jobs") + 1]) if "--jobs" in a else max(1, os.cpu_count() // 2))
    elif a == ["unit"]:
        unit()
    elif a == ["table"]:
        table()
    else:
        sys.exit(__doc__)
