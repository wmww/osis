#!/usr/bin/env python3
"""Tests tools/gate_failures.py on fabricated stage logs and a fabricated known list. Exit 1 on a mismatch."""
import os, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_failures

# `cargo test --no-fail-fast` (cargo 1.99's format): one target with a seed harness failure in
# both seed formats and a plain one, then a passing doctest target
KNOWN_ONLY = """     Running unittests src/lib.rs (target/debug/deps/probe-1)

running 3 tests
test ok ... ok
test order::known_plain ... FAILED
test other_large ... FAILED

failures:

---- order::known_plain stdout ----
panicked at x.rs:1:1:
known_plain: 2 of 8 seeds failed or hung:
seed 41 (replay: OSIS_ORDER_SEED=41 cargo test x): order #3 reads Some

seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x; as made; for check(42, Cfg { a: 1 })): h = vec![]
seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x; as made; for check(42, Cfg { a: 1 })): h = vec![]

---- other_large stdout ----
assertion failed: floor

failures:
    order::known_plain
    other_large

test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: test failed, to rerun pass `--lib`
   Doc-tests probe

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

"""
COUNT1 = "error: 1 target failed:\n    `--lib`\n"
# targets that crashed: a hung-seed exit (process::exit inside a test) and a SIGKILL (OOM)
EXITED = """     Running tests/exit.rs (target/debug/deps/exit-2)

running 1 test
error: test failed, to rerun pass `--test exit`
"""
KILLED = """     Running tests/kill.rs (target/debug/deps/kill-3)

running 2 tests
test a ... ok
error: test failed, to rerun pass `--test kill`

Caused by:
  process didn't exit successfully: `target/debug/deps/kill-3` (signal: 9, SIGKILL: kill)
"""
# its tests passed, then the process failed (a panic or abort after libtest's summary)
LATE = """     Running tests/late.rs (target/debug/deps/late-4)

running 1 test
test fine ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: test failed, to rerun pass `--test late`

Caused by:
  process didn't exit successfully: `target/debug/deps/late-4` (signal: 6, SIGABRT: process abort signal)
"""
DOCTEST = """   Doc-tests probe

running 1 test
test src/lib.rs - f (line 1) ... FAILED

failures:

---- src/lib.rs - f (line 1) stdout ----
Test executable failed (exit status: 101).

failures:
    src/lib.rs - f (line 1)

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s

error: doctest failed, to rerun pass `--doc`
"""
SIM = """sim-sweep: 3 scenarios, seeds 7..22, 16 jobs
FAIL sim failure in scenario `no_host_chain`, seed 9, step 4: agreement lost
replay: osis_sim::replay("no_host_chain", 9)
FAIL sim failure in scenario `evil_host_drops`, seed 8, step 2: agreement lost
replay: osis_sim::replay("evil_host_drops", 8)
scenario seeds failed
no_host 15 0
no_host_chain 15 1
evil_host_drops 15 1
failing: osis_sim::replay("evil_host_drops", 8)
failing: osis_sim::replay("no_host_chain", 9)
elapsed 3 s
"""
# a hung seed: the runner prints its failures and exits before the sweep's tally
SIM_HUNG = """sim-sweep: 2 scenarios, seeds 7..22, 16 jobs
FAIL sim failure in scenario `no_host_chain`, seed 9, step 4: agreement lost
replay: osis_sim::replay("no_host_chain", 9)
sim-sweep: osis_sim::replay("no_host", 7) used 600 CPU-s (OSIS_SEED_TIMEOUT_SECS): hung, moving on
sim-sweep: 30 of 30 run, 1 failing, 1 hung
failures:
osis_sim::replay("no_host_chain", 9): agreement lost
"""

fails = 0


def check(name, got, want):
    global fails
    if got != want:
        print(f"FAIL {name}:\n got  {got!r}\n want {want!r}")
        fails = 1


def names(text):
    return [n for n, _, _ in gate_failures.cargo_failures(text)]


got = gate_failures.cargo_failures(KNOWN_ONLY + COUNT1)
check("cargo names", [n for n, _, _ in got], ["order::known_plain", "other_large"])
check("cargo units: each seed line", got[0][1], ["seed 41 (replay: OSIS_ORDER_SEED=41 cargo test x): order #3 reads Some", "seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x; as made; for check(42, Cfg { a: 1 })): h = vec![]"])
check("cargo seeds shown", got[0][2], ["seed 41 (replay: OSIS_ORDER_SEED=41 cargo test x)", "seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x)"])
check("cargo unit: a panic without seeds", (got[1][1], got[1][2]), (["assertion failed: floor\n"], []))
check("hung-seed exit", names(EXITED + COUNT1), [None])
check("SIGKILL", names(KILLED + COUNT1), [None])
check("crash after the summary", names(LATE + COUNT1), [None])
check("doctest", names(DOCTEST + COUNT1), ["src/lib.rs - f (line 1)"])
check("count off", names(KNOWN_ONLY + "error: 2 targets failed:\n"), ["order::known_plain", "other_large", None])
check("no count: cargo killed", names(KNOWN_ONLY), ["order::known_plain", "other_large", None])
check("truncated mid-target", names(KNOWN_ONLY + "     Running tests/b.rs (b-5)\n\nrunning 3 tests\ntest x ... ok\n"), ["order::known_plain", "other_large", None, None])
check("cargo error outside a target", names(KNOWN_ONLY + "error: could not compile `osis-node`\n" + COUNT1), ["order::known_plain", "other_large", None])
check("passing log", gate_failures.cargo_failures(KNOWN_ONLY.split("     Running")[0] + "   Doc-tests probe\n\nrunning 0 tests\n\ntest result: ok. 0 passed\n"), [])
check("sim", [(n, s) for n, _, s in gate_failures.sim_failures(SIM)], [("sim-sweep:evil_host_drops", ['seed 8 (replay: osis_sim::replay("evil_host_drops", 8))']), ("sim-sweep:no_host_chain", ['seed 9 (replay: osis_sim::replay("no_host_chain", 9))'])])
check("sim unit has its failure", "agreement lost" in gate_failures.sim_failures(SIM)[1][1][0], True)
check("sim hung exit", [n for n, _, _ in gate_failures.sim_failures(SIM_HUNG)], [None])
check("sim tally off", [n for n, _, _ in gate_failures.sim_failures(SIM.replace("no_host 15 0", "no_host 15 1"))], [None, "sim-sweep:evil_host_drops", "sim-sweep:no_host_chain"])

d = tempfile.mkdtemp()
os.makedirs(f"{d}/tools")
os.makedirs(f"{d}/issues")
open(f"{d}/issues/known.md", "w").write("# k\n")
open(f"{d}/issues/sim.md", "w").write("# s\n")


def known(text):
    open(f"{d}/{gate_failures.KNOWN}", "w").write(text)
    return gate_failures.known(d)


ns, errs = known("# comment\norder::known_plain OSIS_ORDER_SEED=1 issues/known.md ^seed \\d+, Lists # not a comment\n")
check("known", ({k: [(i, p.pattern) for i, p in v] for k, v in ns.items()}, errs), ({"order::known_plain": [("issues/known.md", "^seed \\d+, Lists # not a comment")]}, []))
_, errs = known("a 1 issues/gone.md x\nb 2 issues/known.md\nc 3 notes/x.md x\nd 4 issues/known.md (\n")
check("known refuses", [e.split(": ", 1)[1].split(":")[0] for e in errs], ["issues/gone.md", "want `NAME REPRO ISSUE PATTERN`, got 'b 2 issues/known.md'", "notes/x.md", "bad pattern '('"])


def summary(listed, stages, expected=None):
    """The summary's exit and lines against a known list and [(stage, exit, log text)]."""
    known(listed)
    for i, (_, _, text) in enumerate(stages):
        open(f"{d}/{i}.log", "w").write(text)
    open(f"{d}/sel", "w").write("".join(f"run {s} cmd\n" for s in (expected or [s for s, _, _ in stages])))
    open(f"{d}/res", "w").write("".join(f"{s} {rc} {d}/{i}.log\n" for i, (s, rc, _) in enumerate(stages)))
    r = subprocess.run([sys.executable, gate_failures.__file__, f"{d}/sel", f"{d}/res", d], capture_output=True, text=True)
    return r.returncode, r.stdout


SEEDS = r"order::known_plain 1 issues/known.md ^seed \d+(, Lists)? \(replay: "
LISTED = f"{SEEDS}\nother_large 1 issues/known.md floor\nsim-sweep:no_host_chain 9 issues/sim.md agreement\nsim-sweep:evil_host_drops 8 issues/sim.md agreement\n"
rc, out = summary(LISTED, [("default-tests", "101", KNOWN_ONLY + COUNT1), ("gate.sim", "1", SIM)])
check("only known: exit 3", (rc, "KNOWN failures only (4," in out), (3, True))
check("only known: issue shown", "KNOWN gate.sim  sim-sweep:no_host_chain: issues/sim.md" in out, True)
check("seed lines shown", "seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x)\n" in out, True)
for what, text in [("hung-seed exit", EXITED), ("SIGKILL", KILLED), ("crash after summary", LATE), ("doctest", DOCTEST)]:
    rc, out = summary(LISTED, [("default-tests", "101", KNOWN_ONLY + text + "error: 2 targets failed:\n")])
    check(f"known + {what}: NEW", (rc, "1 NEW, 2 KNOWN" in out), (1, True))
rc, out = summary(LISTED, [("default-tests", "137", KNOWN_ONLY)])
check("known, then cargo killed: NEW", (rc, "1 NEW, 2 KNOWN" in out), (1, True))
rc, out = summary(LISTED, [("gate.sim", "101", SIM_HUNG)])
check("sim hung exit of a known scenario: NEW", (rc, "1 NEW, 0 KNOWN" in out), (1, True))
# a new bug in a listed test: a seed line no pattern names
rc, out = summary(LISTED.replace("(, Lists)?", ""), [("default-tests", "101", KNOWN_ONLY + COUNT1)])
check("listed test, new failure text: NEW", (rc, "1 NEW, 1 KNOWN" in out, "matches none of its patterns: seed 42, Lists" in out), (1, True, True))
rc, out = summary(f"{SEEDS}\nother_large 1 issues/known.md hung\n", [("default-tests", "101", KNOWN_ONLY + COUNT1)])
check("listed test without seeds, other panic: NEW", (rc, "1 NEW, 1 KNOWN" in out), (1, True))
rc, out = summary("", [("gate.properties", "101", KNOWN_ONLY + COUNT1)])
check("unlisted is NEW", (rc, "2 NEW, 0 KNOWN" in out), (1, True))
rc, out = summary(LISTED, [("default-tests", "101", "error[E0425]: cannot find value\n")])
check("build error is NEW", (rc, "NEW   default-tests  cargo outside a test target: error[E0425]" in out), (1, True))
rc, out = summary(LISTED, [("default-tests", "101", "")])
check("empty log is NEW", (rc, "exited 101 without naming" in out), (1, True))
rc, out = summary(LISTED, [("default-tests", "0", "")], ["default-tests", "gate.sim"])
check("a stage that did not run is NEW", (rc, "NEW   gate.sim  did not run" in out), (1, True))
rc, out = summary(LISTED, [("gate.properties", "0", "")], ["gate.properties", "gate.properties"])
check("a repeated stage counted", (rc, "did not run" in out), (1, True))
rc, out = summary(LISTED, [], ["default-tests"])
check("no results at all (the hold never ran) is NEW", (rc, "NEW   default-tests  did not run" in out), (1, True))
rc, out = summary(LISTED, [("default-tests", "0", ""), ("gate.sim", "0", "")])
check("pass", (rc, out), (0, "== test stages: 2 run of 2, 0 failed\n"))
rc, out = summary("x 1 issues/gone.md p\n", [("default-tests", "0", "")])
check("a bad list fails the gate", (rc, "NEW   known list" in out), (1, True))

shutil.rmtree(d)
print(f"gate failures: {'ok' if not fails else 'FAILED'}")
sys.exit(fails)
