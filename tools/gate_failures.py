#!/usr/bin/env python3
"""The gate's failure summary (notes/gate.md, The summary): every failure of its test
stages, each marked KNOWN (listed in tools/known_failures.txt, with its issue) or NEW.

  tools/gate_failures.py SEL RESULTS [ROOT]   SEL: the gate's selection file (`run LIMIT CMD` and
      `expect LIMIT` lines: the stages expected); RESULTS: `LIMIT EXIT LOG` per stage run; ROOT:
      where the known list and issues/ are (default: this checkout; tools/gate_failures_test.py
      passes a fabricated one)
Exit 0 when every stage passed, 3 when only KNOWN failures failed, 1 on any NEW one (NEW-TEXT
included).

tools/known_failures.txt: one failure on main per line, `NAME REPRO ISSUE PATTERN`: NAME a test's
crate and libtest path (`osis-engine/order::held_set_decides_plain`; failures match by the path
alone, tools/policy.py checks the crate holds the test) or `sim-sweep:SCENARIO`; REPRO the setting that
shows it failing on main, prefixed `rate:` when the failure needs some seeds the gate's random
offsets seldom draw (its issue says so); ISSUE its issues/ file; PATTERN (the rest of the line) a Python regex
searched in each failing unit of NAME's text: each `seed N ... (replay: ...)` line of its panic
(of each failing sim seed, its lines), or its whole panic when it names no seed. A failure is
KNOWN when every unit matches a pattern listed for its NAME (the gate's seeds are random: its
failing seed is never REPRO's); a listed NAME failing with a unit no pattern matches is NEW-TEXT (a
second failure behind the known one). A line may carry a baseline before PATTERN, `counts:CHECK=N,...`
(REPRO then the setting tools/prop_run.py runs that test at: `-` or `VAR=VAL,...`): the failure's
counts (`"CHECK": N` pairs from PATTERN's match to the next `}`, a space in CHECK as `_`) equal to it
are KNOWN (`same failing counts`), else NEW-COUNTS, counted NEW. A target tools/test_watch.py stopped as hung fails each test it
names, its unit `hung: no test finished for N s`. Anything the parser cannot account for is NEW: a
stage that did not run, a target that ended before its summary (a crash, a signal, a hung-seed
exit, a hang naming no test) or exited non-zero after it, an `error` cargo printed outside a target, a failed-target count that does not
add up, a sim sweep without its closing tally. tools/policy.py checks the list (`known`).

A line `NAME slow:S ISSUE` lists a slow default test instead (notes/gate.md, The summary: Slow
tests). Each test's wall in the default-test stages (libtest's `<W.WWWs>`, tools/test_time.sh;
its longest over the stages) is checked: over the per-test bound (the `test` wall limit on this
box, or GATE_SLOW_S) and unlisted, or over a listed S, it is NEW-SLOW, counted NEW, with the line
to add or raise; a listed test under the bound over HEADROOM is a stale line (KNOWN-BUT-PASSED). A
test such a stage ran without a time (doctests aside) is NEW: the runner did not apply.

A listed NAME that ran and passed in every stage that ran it (a `test NAME ... ok` line, a sim
tally of 0 failed) and failed in none is listed under `KNOWN-BUT-PASSED`: its line is stale (the
landing removes it) unless it fails at a rate; when every line of NAME is a `rate:` one, it says
passing is expected instead. It changes no exit code: the exit-3 line counts them, and
tools/gate.sh's pass line does from this output.

First it lists the property and sim stages' runs by CPU-seconds, costliest first: each test's own
process (tools/prop_run.py's `gate: cost NAME: W s, C CPU-s`), or in a log without those each summary
line ending `..., W s, C CPU-s` (osis_base::testenv::run_jobs, sim-sweep, the order harness's
`NAME (SIZE): ...` line, which names test NAME_SIZE), then each test the stage ran with neither.
"""
import collections, math, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN = "tools/known_failures.txt"
SEGMENT = re.compile(r"^\s+(Running |Doc-tests )")
RESULT = re.compile(r"^test result: (ok|FAILED)\.")
# libtest's result lines, with `--report-time`'s ` <W.WWWs>` (tools/test_time.sh) or without
FAILED = re.compile(r"^test (.+?) \.\.\. FAILED(?: <[\d.]+s>)?$")
PASSED = re.compile(r"^test (.+?) \.\.\. ok(?: <[\d.]+s>)?$")
TIMED = re.compile(r"^test (.+?) \.\.\. (?:ok|FAILED) <([\d.]+)s>$")
HINT = re.compile(r"^error: (?:doc)?test failed, to rerun pass `(.*)`$")
TARGETS = re.compile(r"^error: (\d+) targets? failed:$")
# `seed N (replay: CMD): why` (osis_base::testenv) or `seed N, EMPHASIS (replay: CMD; ...` (order)
SEED = re.compile(r"\b(seed \d+[^()\n]*?) \(replay: ([^;)\n]*)")
SIM_FAILING = re.compile(r'^failing: osis_sim::replay\("(\w+)", (\d+)\)')
SIM_TALLY = re.compile(r"^(\w+) (\d+) (\d+)$")
# tools/test_watch.py stopping a target: why, then each test still running
HUNG = re.compile(r"^gate: hung: (no test finished .*)$")
HUNG_TEST = re.compile(r"^gate: hung test: (.+)$")
# a runner's summary line (not its `(running)` progress line): `NAME[ (SIZE)]: ..., W s, C CPU-s`
CPU = re.compile(r"^(\S+?)(?: \(([^()]*)\))?: .*, ([\d.]+) s, ([\d.]+) CPU-s(?:;.*)?$")
# tools/prop_run.py's line: one test's own process
PROCESS_CPU = re.compile(r"^gate: cost (\S+): ([\d.]+) s, ([\d.]+) CPU-s$")
COST_STAGES = ("gate.properties", "gate.sim")
# The default-test stages, run with per-test times (tools/test_watch.py) and checked against the bound
TIMED_STAGES = ("default-tests", "gate.gui-tests")
# R: minor consequence. A test's wall in a gate swings with the box's load (1-2.5x at the loads
# gates see): a `slow:` line is suggested at this multiple of the wall seen, and is stale once its
# test runs under the bound divided by it. 1: a listed test flags, and a stale one comes back, on
# any load rise; infinity: a listed test grows unseen and its line never goes.
HEADROOM = 2


Known = collections.namedtuple("Known", "issue pattern rate counts env slow")
SLOW = re.compile(r"^slow:(\d+)$")
COUNTS = re.compile(r"^counts:((?:[^\s=,]+=\d+)(?:,[^\s=,]+=\d+)*)$")
SETTING = re.compile(r"^-$|^(\w+=[^\s,]*)(,\w+=[^\s,]*)*$")


def known(root=ROOT):
    """({NAME: [Known, ...]}, [error, ...]) from the known-failures list. `rate` when its REPRO is
    `rate:...` (fails on some seeds only); `counts` ({check: failing count}) when the line has a
    `counts:` baseline, then `env` its REPRO's settings, which the gate runs it at."""
    names, errs, seen = {}, [], {}
    path = os.path.join(root, KNOWN)
    if not os.path.exists(path):
        return names, [f"{KNOWN}: missing"]
    for n, line in enumerate(open(path), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            errs.append(f"{KNOWN}:{n}: duplicate of line {seen[line]} (drop one)")
            continue
        seen[line] = n
        f = line.split(None, 3)
        counts, env = None, {}
        if len(f) > 1 and f[1].startswith("slow:"):
            m = SLOW.match(f[1])
            if len(f) != 3 or not m or int(m.group(1)) == 0:
                errs.append(f"{KNOWN}:{n}: want `NAME slow:SECONDS ISSUE` (SECONDS a whole number over 0), got {line!r}")
            elif not (f[2].startswith("issues/") and f[2].endswith(".md") and os.path.isfile(os.path.join(root, f[2]))):
                errs.append(f"{KNOWN}:{n}: {f[2]}: no such issue file (fixed? drop the line)")
            else:
                names.setdefault(test_path(f[0]), []).append(Known(f[2], None, False, None, {}, int(m.group(1))))
            continue
        if len(f) == 4 and f[3].startswith("counts:"):
            c, _, pat = f[3].partition(" ")
            m = COUNTS.match(c)
            if not m or not pat.strip():
                errs.append(f"{KNOWN}:{n}: want `NAME REPRO ISSUE counts:CHECK=N,... PATTERN` (a space in CHECK written `_`), got {line!r}")
                continue
            counts = {k: int(v) for k, v in (kv.split("=") for kv in m.group(1).split(","))}
            if not SETTING.match(f[1]):
                errs.append(f"{KNOWN}:{n}: a `counts:` line's REPRO is the setting the gate runs it at: `-` or `VAR=VAL,...`, got {f[1]!r}")
                continue
            env = dict(kv.split("=", 1) for kv in f[1].split(",")) if f[1] != "-" else {}
            f[3] = pat.strip()
        if len(f) != 4:
            errs.append(f"{KNOWN}:{n}: want `NAME REPRO ISSUE PATTERN`, got {line!r}")
            continue
        name, repro, issue, pat = f
        if not (issue.startswith("issues/") and issue.endswith(".md") and os.path.isfile(os.path.join(root, issue))):
            errs.append(f"{KNOWN}:{n}: {issue}: no such issue file (fixed? drop the line)")
            continue
        try:
            pat = re.compile(pat, re.M)
        except re.error as e:
            errs.append(f"{KNOWN}:{n}: bad pattern {pat!r}: {e}")
            continue
        names.setdefault(test_path(name), []).append(Known(issue, pat, repro.startswith("rate:"), counts, env, None))
    for name, ks in names.items():
        if sum(k.slow is not None for k in ks) > 1:
            errs.append(f"{KNOWN}: {name}: more than one `slow:` line")
        if any(k.counts is not None for k in ks) and sum(k.slow is None for k in ks) > 1:
            errs.append(f"{KNOWN}: {name}: a test with a `counts:` line has no other line (its counts are the whole of its failure)")
    return names, errs


def counted_envs(root=ROOT):
    """{test path: its `counts:` line's settings}: what tools/prop_run.py runs each at."""
    return {name: k.env for name, ks in known(root)[0].items() for k in ks if k.counts is not None}


def failing_counts(unit, pattern):
    """{check: count} a failure states: the `"CHECK": N` pairs from the end of the pattern's match
    to the next `}` (a Debug map printed after the pattern), each CHECK's spaces as `_`."""
    m = pattern.search(unit)
    if not m:
        return None
    body = unit[m.end():].split("}", 1)[0]
    return {re.sub(r"\s", "_", k): int(v) for k, v in re.findall(r'"([^"\\]+)": (\d+)\b', body)}


def test_path(name):
    """NAME as a failure names it: a test's libtest path (its `CRATE/` dropped), or `sim-sweep:SCENARIO`."""
    return name if name.startswith("sim-sweep:") else name.rpartition("/")[2]


def cargo_failures(text):
    """[(name, units, shown)] of a `cargo test --no-fail-fast` log: each failing test with its
    units (`known`) and its seed lines to show; anything unaccounted for as (None, why, [])."""
    segs, stray, hints, declared = [], [], 0, None
    cur = None
    for line in text.split("\n"):
        if SEGMENT.match(line):
            cur = {"head": line.strip(), "lines": [], "result": None, "hint": None}
            segs.append(cur)
            continue
        m = HINT.match(line)
        if m:
            hints += 1
            if cur is None or cur["hint"] is not None:
                stray.append(line)
            else:
                cur["hint"] = m.group(1)
            continue
        m = TARGETS.match(line)
        if m:
            declared = int(m.group(1))
        elif cur is not None and cur["result"] is None:
            cur["lines"].append(line)
            r = RESULT.match(line)
            if r:
                cur["result"] = r.group(1)
        elif line.startswith("error"):
            stray.append(line)
    out = []
    for s in segs:
        where = f"`{s['hint']}`" if s["hint"] else s["head"]
        hung = [m.group(1) for l in s["lines"] if (m := HUNG.match(l))]
        if s["result"] is None and hung:
            names = list(dict.fromkeys(m.group(1) for l in s["lines"] if (m := HUNG_TEST.match(l))))
            if not names:
                out.append((None, f"{where} hung ({hung[0]}), no test named (libtest names one after 60 s): read its output", []))
            for name in names:
                out.append((name, [f"hung: {hung[0]}"], []))
        elif s["result"] is None:
            out.append((None, f"{where} ended before its summary (a crash, a signal, a hung-seed exit): read its output", []))
        elif s["result"] == "ok" and s["hint"]:
            out.append((None, f"{where} passed its tests but exited non-zero (a crash after its summary): read its output", []))
        elif s["result"] == "FAILED":
            names = failing(s["lines"])
            if not names:
                out.append((None, f"{where} failed without naming a test: read its output", []))
            for name in names:
                out.append((name, *units(s["lines"], name, names)))
    for line in stray[:3]:
        out.append((None, f"cargo outside a test target: {line[:200]}", []))
    if declared is None and (hints or out):
        out.append((None, "cargo ended without its failed-targets count (killed? not --no-fail-fast?): read its output", []))
    elif declared is not None and declared != hints:
        out.append((None, f"cargo counted {declared} failed targets, the log shows {hints}: read its output", []))
    return out


def failing(lines):
    """A target's failing tests: its `test X ... FAILED` lines and the list after its last `failures:`."""
    names = [FAILED.match(l).group(1) for l in lines if FAILED.match(l)]
    last = max((i for i, l in enumerate(lines) if l == "failures:"), default=None)
    if last is not None:
        names += [l[4:] for l in lines[last + 1:] if l.startswith("    ") and l[4:].strip()]
    return list(dict.fromkeys(names))


def units(lines, name, names):
    """(units, shown) of one failing test: its panic section's seed lines (or the whole section
    when it names none), and each seed's `seed N ... (replay: CMD)` to show."""
    heads = {f"---- {n} stdout ----" for n in names}
    last = max((i for i, l in enumerate(lines) if l == "failures:"), default=len(lines))
    sec, inside = [], False
    for i, l in enumerate(lines):
        if l in heads:
            inside = l == f"---- {name} stdout ----"
        elif i >= last:
            inside = False
        elif inside:
            sec.append(l)
    seeded = list(dict.fromkeys(l for l in sec if SEED.search(l)))
    shown = list(dict.fromkeys(f"{a} (replay: {b})" for l in seeded for a, b in SEED.findall(l)))
    return (seeded or ["\n".join(sec)]), shown


def passed(text, sim):
    """The tests a stage log shows passing: its `test X ... ok` lines, or a sim sweep's
    scenarios tallied with no failing seed (`sim-sweep:SCENARIO`)."""
    lines = text.split("\n")
    if not sim:
        return {m.group(1) for l in lines if (m := PASSED.match(l))}
    if "scenario seeds failed" not in lines:
        return set()
    t = lines.index("scenario seeds failed")
    return {f"sim-sweep:{m.group(1)}" for l in lines[t + 1:] if (m := SIM_TALLY.match(l)) and m.group(3) == "0"}


def sim_failures(text):
    """Each failing scenario of a sim-sweep log with its seeds' lines as units, or (None, why, [])
    when the sweep did not end with its tally or the tally and the failing list disagree."""
    lines = text.split("\n")
    if "scenario seeds failed" not in lines or not any(l.startswith("elapsed ") for l in lines):
        return [(None, "sim-sweep ended without its tally (a build error, a crash, a hung-seed exit): read its output", [])]
    t = lines.index("scenario seeds failed")
    tally = sum(int(m.group(3)) for l in lines[t + 1:] if (m := SIM_TALLY.match(l)))
    seeds = sorted({(m.group(1), int(m.group(2))) for l in lines if (m := SIM_FAILING.match(l))})
    out = []
    if tally != len(seeds):
        out.append((None, f"sim-sweep's tally counts {tally} failing seeds, its failing list {len(seeds)}: read its output", []))
    by = collections.defaultdict(list)
    for n, s in seeds:
        mine = [l for l in lines if f'replay("{n}", {s})' in l or f"scenario `{n}`, seed {s}," in l]
        by[n].append(("\n".join(mine), f'seed {s} (replay: osis_sim::replay("{n}", {s}))'))
    for n, us in by.items():
        out.append((f"sim-sweep:{n}", [u for u, _ in us], [s for _, s in us]))
    return out


def fmt_counts(c):
    return ",".join(f"{k}={v}" for k, v in sorted(c.items())) or "none"


def costs(text):
    """([(cpu, wall, name)], [test]) of a stage log: each test's own process as tools/prop_run.py
    measured it (`gate: cost NAME: W s, C CPU-s`) when the log has those, else each runner
    summary line's cost; and each test that ran (passed or failed) with neither."""
    rows, named, own = [], set(), []
    for l in text.split("\n"):
        m = PROCESS_CPU.match(l)
        if m:
            rows.append((float(m.group(3)), float(m.group(2)), m.group(1)))
            named.add(m.group(1))
            continue
        m = CPU.match(l)
        if m:
            name = m.group(1) + (f" ({m.group(2)})" if m.group(2) else "")
            own.append(((float(m.group(4)), float(m.group(3)), name), m.group(1) + ("_" + re.sub(r"\W+", "_", m.group(2)) if m.group(2) else "")))
    if not rows:
        rows = [r for r, _ in own]
        named = {n for _, n in own}
    ran = [m.group(1) for l in text.split("\n") if (m := PASSED.match(l) or FAILED.match(l))]
    return sorted(rows, reverse=True), [t for t in dict.fromkeys(ran) if t not in named]


def times(text):
    """{test: its longest wall in s} of a stage log's `--report-time` result lines, and the count
    of tests a `Running` target passed or failed without one (doctests have none)."""
    out, bare, doc = {}, 0, False
    for l in text.split("\n"):
        m = SEGMENT.match(l)
        if m:
            doc = m.group(1).startswith("Doc")
        elif m := TIMED.match(l):
            out[m.group(1)] = max(out.get(m.group(1), 0.0), float(m.group(2)))
        elif not doc and (PASSED.match(l) or FAILED.match(l)):
            bare += 1
    return out, bare


def bound():
    """(The per-test wall bound in s, None) or (None, why): the `test` wall limit on this box
    (notes/time-limits.md, Limits), or GATE_SLOW_S (tools/gate_failures_test.py)."""
    if os.environ.get("GATE_SLOW_S"):
        return float(os.environ["GATE_SLOW_S"]), None
    import limits
    lim, why = limits.limit("test")
    return (lim[1], None) if lim else (None, why)


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    sel, res = sys.argv[1:3]
    root = sys.argv[3] if len(sys.argv) == 4 else ROOT
    expected = collections.Counter()
    if os.path.exists(sel):
        expected.update(l.split()[1] for l in open(sel).read().split("\n") if l.startswith(("run ", "expect ")))
    results = [l.split(" ", 2) for l in open(res).read().split("\n") if l] if os.path.exists(res) else []
    ran = collections.Counter(r[0] for r in results)
    names, errs = known(root)
    rows = []  # (kind, stage, text)
    ok, bad = collections.defaultdict(set), set()  # passing name -> stages; names failing anywhere
    for e in errs:
        rows.append(("NEW", "known list", e))
    for stage, n in (expected - ran).items():
        rows.append(("NEW", stage, f"did not run{f' ({n} of its runs)' if n > 1 else ''} (the heavy-lock hold ended early: read its output)"))
    for r in results:
        stage, rc, log = (r + ["", ""])[:3]
        text = open(log, errors="replace").read() if os.path.exists(log) else ""
        for n in passed(text, stage == "gate.sim"):
            ok[n].add(stage)
        if rc == "0":
            continue
        fails = sim_failures(text) if stage == "gate.sim" else cargo_failures(text)
        if not fails:
            fails = [(None, f"exited {rc or '?'} without naming a failing test (a build error, a crash): read its output", [])]
        for name, us, shown in fails:
            bad.add(name)
            if name is None:
                rows.append(("NEW", stage, us))
                continue
            listed = [k for k in names.get(name, []) if k.slow is None]
            hit = [next((k.issue for k in listed if k.pattern.search(u)), None) for u in us]
            base = listed[0].counts if listed else None
            now = None
            if base is not None and all(hit):
                now = collections.Counter()
                for u in us:
                    now.update(failing_counts(u, listed[0].pattern))
            if now is not None and dict(now) != base:
                rows.append(("NEW-COUNTS", stage, f"{name}: listed ({listed[0].issue}) with failing counts {fmt_counts(base)}, this run {fmt_counts(now)}: "
                             "the branch changed what fails: read it; a landing that explains it refreshes the `counts:` (notes/coordination.md, Known failures)"))
            elif listed and all(hit):
                rows.append(("KNOWN", stage, f"{name}: {', '.join(dict.fromkeys(hit))}{', same failing counts' if now is not None else ''}"))
            elif listed:
                miss = next(u for u, h in zip(us, hit) if h is None).strip().split("\n")[0][:200]
                rows.append(("NEW-TEXT", stage, f"{name}: listed ({', '.join(dict.fromkeys(k.issue for k in listed))}), but this failure matches none of its patterns: {miss}"))
            else:
                rows.append(("NEW", stage, name))
            rows += [("", "", s) for s in shown[:3]] + ([("", "", f"... {len(shown) - 3} more seeds")] if len(shown) > 3 else [])
    cost, bare = [], []
    for stage, _, log in ((r + ["", ""])[:3] for r in results):
        if stage in COST_STAGES and os.path.exists(log):
            c, b = costs(open(log, errors="replace").read())
            cost += c
            bare += b
    if cost or bare:
        print(f"== property and sim CPU-s, costliest first ({sum(c for c, _, _ in cost):.0f} CPU-s measured)")
        for c, w, name in sorted(cost, reverse=True):
            print(f"   {c:8.1f} CPU-s {w:7.1f} s  {name}")
        for name in bare:
            print(f"          (no CPU line)  {name}")
    # each default test's wall against the bound, or its `slow:` line
    walls, bare = {}, 0
    for stage, _, log in ((r + ["", ""])[:3] for r in results):
        if stage in TIMED_STAGES and os.path.exists(log):
            t, b = times(open(log, errors="replace").read())
            bare += b
            for n, w in t.items():
                if w >= walls.get(n, (-1.0, ""))[0]:
                    walls[n] = (w, stage)
    limit, why = bound()
    slow_lines = {n: k for n, ks in names.items() for k in ks if k.slow is not None}
    stale_slow = {}
    if bare:
        rows.append(("NEW", "default tests", f"{bare} tests ran without a time (tools/test_watch.py runs them under tools/test_time.sh, which adds one): read its output"))
    if walls and limit is None:
        print(f"== per-test times not checked: {why}")
    elif walls:
        within = 0
        for n, (w, stage) in sorted(walls.items(), key=lambda x: -x[1][0]):
            k = slow_lines.get(n)
            if k and w <= k.slow:
                within += 1
                if w <= limit / HEADROOM:
                    stale_slow[n] = f"{stage}; {k.issue}; slow:{k.slow}, ran {w:.1f} s, under {limit:.0f} s / {HEADROOM}"
            elif k:
                rows.append(("NEW-SLOW", stage, f"{n}: {w:.1f} s, over its listed slow:{k.slow} ({k.issue}): slim it, or raise the line to slow:{math.ceil(HEADROOM * w)} with the reason in its issue"))
            elif w > limit:
                rows.append(("NEW-SLOW", stage, f"{n}: {w:.1f} s, over the per-test bound {limit:.0f} s (the `test` wall limit): slim it, or list it in {KNOWN} as `CRATE/{n} slow:{math.ceil(HEADROOM * w)} ISSUE` with the reason in ISSUE"))
        print(f"== per-test times: {len(walls)} tests, bound {limit:.0f} s; {within} listed `slow:` within their line")
    failed = sum(1 for r in results if r[1:2] != ["0"])
    print(f"== test stages: {len(results)} run of {max(sum(expected.values()), len(results))}, {failed} failed")
    for kind, stage, text in rows:
        print(f"   {kind:5} {stage}  {text}" if kind else f"         {text}")
    stale = []
    fails_known = {n: [k for k in ks if k.slow is None] for n, ks in names.items()}
    for name in sorted(n for n, ks in fails_known.items() if ks and n in ok and n not in bad):
        stages = ', '.join(sorted(ok[name]))
        if all(k.rate for k in fails_known[name]):
            issues = ', '.join(dict.fromkeys(k.issue for k in fails_known[name]))
            print(f"   KNOWN, passed: {name} ({stages}): fails at a rate ({issues}): passing this run is expected")
        else:
            stale.append(f"   KNOWN-BUT-PASSED: {name} ({stages}; {', '.join(dict.fromkeys(k.issue for k in fails_known[name] if not k.rate))})")
    stale += [f"   KNOWN-BUT-PASSED: {n} ({why})" for n, why in sorted(stale_slow.items())]
    if stale:
        print(f"== KNOWN-BUT-PASSED ({len(stale)}): listed, not `rate:`, passing in this run. Remove each line from {KNOWN} "
              "in this landing (and its issue, if fixed), or mark it `rate:` if its issue shows it fails on some seeds only")
        print("\n".join(stale))
    tail = f"; {len(stale)} KNOWN-BUT-PASSED to remove" if stale else ""
    new = sum(1 for k, _, _ in rows if k in ("NEW", "NEW-TEXT", "NEW-COUNTS", "NEW-SLOW"))
    old = sum(1 for k, _, _ in rows if k == "KNOWN")
    if new:
        print(f"== gate FAILED: {new} NEW, {old} KNOWN{tail}")
        return 1
    if old:
        print(f"== gate FAILED, KNOWN failures only ({old}, {KNOWN}): mergeable (notes/coordination.md, Known failures){tail}")
        return 3
    if failed:
        print(f"== gate FAILED: {failed} stages failed, the summary found no failure in them: read their output")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
