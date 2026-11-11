#!/usr/bin/env python3
"""The gate's failure summary (notes/testing.md, The gate's summary): every failure of its test
stages, each marked KNOWN (listed in tools/known_failures.txt, with its issue) or NEW.

  tools/gate_failures.py SEL RESULTS [ROOT]   SEL: the gate's selection file (`run LIMIT CMD` and
      `expect LIMIT` lines: the stages expected); RESULTS: `LIMIT EXIT LOG` per stage run; ROOT:
      where the known list and issues/ are (default: this checkout; tools/gate_failures_test.py
      passes a fabricated one)
Exit 0 when every stage passed, 3 when only KNOWN failures failed, 1 on any NEW one.

tools/known_failures.txt: one failure on main per line, `NAME REPRO ISSUE PATTERN`: NAME a test's
libtest path (`order::held_set_decides_plain`) or `sim-sweep:SCENARIO`; REPRO the setting that
shows it failing on main; ISSUE its issues/ file; PATTERN (the rest of the line) a Python regex
searched in each failing unit of NAME's text: each `seed N ... (replay: ...)` line of its panic
(of each failing sim seed, its lines), or its whole panic when it names no seed. A failure is
KNOWN when every unit matches a pattern listed for its NAME (the gate's seeds are random: its
failing seed is never REPRO's). Anything the parser cannot account for is NEW: a stage that did
not run, a target that ended before its summary (a crash, a signal, a hung-seed exit) or exited
non-zero after it, an `error` cargo printed outside a target, a failed-target count that does not
add up, a sim sweep without its closing tally. tools/policy.py checks the list (`known`).
"""
import collections, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN = "tools/known_failures.txt"
SEGMENT = re.compile(r"^\s+(Running |Doc-tests )")
RESULT = re.compile(r"^test result: (ok|FAILED)\.")
FAILED = re.compile(r"^test (.+) \.\.\. FAILED$")
HINT = re.compile(r"^error: (?:doc)?test failed, to rerun pass `(.*)`$")
TARGETS = re.compile(r"^error: (\d+) targets? failed:$")
# `seed N (replay: CMD): why` (osis_base::testenv) or `seed N, EMPHASIS (replay: CMD; ...` (order)
SEED = re.compile(r"\b(seed \d+[^()\n]*?) \(replay: ([^;)\n]*)")
SIM_FAILING = re.compile(r'^failing: osis_sim::replay\("(\w+)", (\d+)\)$')
SIM_TALLY = re.compile(r"^(\w+) (\d+) (\d+)$")


def known(root=ROOT):
    """({NAME: [(issue, pattern), ...]}, [error, ...]) from the known-failures list."""
    names, errs = {}, []
    path = os.path.join(root, KNOWN)
    if not os.path.exists(path):
        return names, [f"{KNOWN}: missing"]
    for n, line in enumerate(open(path), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split(None, 3)
        if len(f) != 4:
            errs.append(f"{KNOWN}:{n}: want `NAME REPRO ISSUE PATTERN`, got {line!r}")
            continue
        name, _, issue, pat = f
        if not (issue.startswith("issues/") and issue.endswith(".md") and os.path.isfile(os.path.join(root, issue))):
            errs.append(f"{KNOWN}:{n}: {issue}: no such issue file (fixed? drop the line)")
            continue
        try:
            pat = re.compile(pat, re.M)
        except re.error as e:
            errs.append(f"{KNOWN}:{n}: bad pattern {pat!r}: {e}")
            continue
        names.setdefault(name, []).append((issue, pat))
    return names, errs


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
        if s["result"] is None:
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
    for e in errs:
        rows.append(("NEW", "known list", e))
    for stage, n in (expected - ran).items():
        rows.append(("NEW", stage, f"did not run{f' ({n} of its runs)' if n > 1 else ''} (the heavy-lock hold ended early: read its output)"))
    for r in results:
        stage, rc, log = (r + ["", ""])[:3]
        if rc == "0":
            continue
        text = open(log, errors="replace").read() if os.path.exists(log) else ""
        fails = sim_failures(text) if stage == "gate.sim" else cargo_failures(text)
        if not fails:
            fails = [(None, f"exited {rc or '?'} without naming a failing test (a build error, a crash): read its output", [])]
        for name, us, shown in fails:
            if name is None:
                rows.append(("NEW", stage, us))
                continue
            listed = names.get(name, [])
            hit = [next((i for i, p in listed if p.search(u)), None) for u in us]
            if listed and all(hit):
                rows.append(("KNOWN", stage, f"{name}: {', '.join(dict.fromkeys(hit))}"))
            elif listed:
                miss = next(u for u, h in zip(us, hit) if h is None).strip().split("\n")[0][:200]
                rows.append(("NEW", stage, f"{name}: listed ({', '.join(dict.fromkeys(i for i, _ in listed))}), but this failure matches none of its patterns: {miss}"))
            else:
                rows.append(("NEW", stage, name))
            rows += [("", "", s) for s in shown[:3]] + ([("", "", f"... {len(shown) - 3} more seeds")] if len(shown) > 3 else [])
    failed = sum(1 for r in results if r[1:2] != ["0"])
    print(f"== test stages: {len(results)} run of {max(sum(expected.values()), len(results))}, {failed} failed")
    for kind, stage, text in rows:
        print(f"   {kind:5} {stage}  {text}" if kind else f"         {text}")
    new = sum(1 for k, _, _ in rows if k == "NEW")
    old = sum(1 for k, _, _ in rows if k == "KNOWN")
    if new:
        print(f"== gate FAILED: {new} NEW, {old} KNOWN")
        return 1
    if old:
        print(f"== gate FAILED, KNOWN failures only ({old}, {KNOWN}): mergeable (notes/coordination.md, Known failures)")
        return 3
    if failed:
        print(f"== gate FAILED: {failed} stages failed, the summary found no failure in them: read their output")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
