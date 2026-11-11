#!/usr/bin/env python3
"""The gate's failure summary (notes/testing.md, The gate's summary): every failure of its test
stages, each marked KNOWN (listed in tools/known_failures.txt, with its issue) or NEW.

  tools/gate_failures.py SEL RESULTS [ROOT]   SEL: the gate's selection file (`run LIMIT CMD` lines,
      the stages expected); RESULTS: `LIMIT EXIT LOG` per stage run; ROOT: where the known list
      and issues/ are (default: this checkout; tools/gate_failures_test.py passes a fabricated one)
Exit 0 when every stage passed, 3 when only KNOWN failures failed, 1 on any NEW one (a stage that
did not run or failed without naming a test is NEW).

tools/known_failures.txt: one failure on main per line, `NAME REPRO ISSUE`: NAME a test's libtest
path (`order::held_set_decides_plain`) or `sim-sweep:SCENARIO`; REPRO the setting that shows it
failing on main (`OSIS_ORDER_SEED=N`, or the scenario's seed); ISSUE its issues/ file. A failure
is KNOWN by NAME alone: the gate's seeds are random, so its failing seed is never the listed one.
tools/policy.py checks the list (`errors`): an entry whose issue file is gone fails it.
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN = "tools/known_failures.txt"
FAILED = re.compile(r"^test (.+) \.\.\. FAILED$")
TARGET = re.compile(r"^error: test failed, to rerun pass `(.*)`$")
SEGMENT = re.compile(r"^\s+(Running |Doc-tests )")
# `seed N (replay: CMD): why` (osis_base::testenv) or `seed N, EMPHASIS (replay: CMD; ...` (order)
SEED = re.compile(r"\b(seed \d+[^()\n]*?) \(replay: ([^;)\n]*)")
SIM = re.compile(r'osis_sim::replay\("(\w+)", (\d+)\)')


def known(root=ROOT):
    """({NAME: [issue, ...]}, [error, ...]) from the known-failures list."""
    names, errs = {}, []
    path = os.path.join(root, KNOWN)
    if not os.path.exists(path):
        return names, [f"{KNOWN}: missing"]
    for n, line in enumerate(open(path), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if len(f) != 3:
            errs.append(f"{KNOWN}:{n}: want `NAME REPRO ISSUE`, got {line!r}")
            continue
        name, _, issue = f
        if not (issue.startswith("issues/") and issue.endswith(".md") and os.path.isfile(os.path.join(root, issue))):
            errs.append(f"{KNOWN}:{n}: {issue}: no such issue file (fixed? drop the line)")
            continue
        names.setdefault(name, []).append(issue)
    return names, errs


def cargo_failures(text):
    """[(name, detail)] of a `cargo test` log: each failing test with the seed lines of its panic,
    and a failing target that named no failing test or ended before its summary as name None."""
    lines = text.split("\n")
    out = []
    seg = []
    for line in lines:
        if SEGMENT.match(line):
            seg = []
        seg.append(line)
        m = TARGET.match(line)
        if m:
            names = [FAILED.match(l).group(1) for l in seg if FAILED.match(l)]
            for name in names:
                out.append((name, seeds(seg, name)))
            if not names or not any(l.startswith("test result: ") for l in seg):
                out.append((None, f"target `{m.group(1)}` failed without naming a test or before its summary (a crash, a hung-seed exit): read its output"))
            seg = []
    return out


def seeds(seg, name):
    """The `seed N (replay: ...)` lines of one test's panic section."""
    found, inside = [], False
    for l in seg:
        if l.startswith("---- "):
            inside = l == f"---- {name} stdout ----"
        elif l == "failures:":
            inside = False
        elif inside:
            found += [f"{a} (replay: {b})" for a, b in SEED.findall(l) if f"{a} (replay: {b})" not in found]
    return found


def sim_failures(text):
    found = sorted({(m.group(1), int(m.group(2))) for m in SIM.finditer(text)})
    return [(f"sim-sweep:{n}", [f'seed {s} (replay: osis_sim::replay("{n}", {s}))']) for n, s in found]


def main():
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    sel, res = sys.argv[1:3]
    root = sys.argv[3] if len(sys.argv) == 4 else ROOT
    expected = []
    if os.path.exists(sel):
        expected = [l.split()[1] for l in open(sel).read().split("\n") if l.startswith("run ")]
    results = [l.split(" ", 2) for l in open(res).read().split("\n") if l] if os.path.exists(res) else []
    ran = {r[0] for r in results}
    names, errs = known(root)
    rows = []  # (kind, stage, text)
    for e in errs:
        rows.append(("NEW", "known list", e))
    for stage in expected:
        if stage not in ran:
            rows.append(("NEW", stage, "did not run (the heavy-lock hold ended early: read its output)"))
    for stage, rc, log in results:
        if rc == "0":
            continue
        text = open(log, errors="replace").read() if os.path.exists(log) else ""
        fails = sim_failures(text) if stage == "gate.sim" else cargo_failures(text)
        if not fails:
            fails = [(None, f"exited {rc} without naming a failing test (a build error, a crash): read its output")]
        for name, detail in fails:
            if name is None:
                rows.append(("NEW", stage, detail))
                continue
            issues = names.get(name)
            text = name + (f": {', '.join(issues)}" if issues else "")
            rows.append(("KNOWN" if issues else "NEW", stage, text))
            rows += [("", "", s) for s in detail[:3]] + ([("", "", f"... {len(detail) - 3} more seeds")] if len(detail) > 3 else [])
    failed = sum(1 for _, rc, _ in results if rc != "0")
    print(f"== test stages: {len(results)} run of {max(len(expected), len(ran))}, {failed} failed")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
