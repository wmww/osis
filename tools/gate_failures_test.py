#!/usr/bin/env python3
"""Tests tools/gate_failures.py on fabricated stage logs and a fabricated known list. Exit 1 on a mismatch."""
import os, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_failures

# `cargo test --no-fail-fast` (cargo 1.99's format): one target with a seed harness failure in
# both seed formats and a plain one, then a passing doctest target
KNOWN_ONLY = """     Running unittests src/lib.rs (target/debug/deps/probe-1)
gate: binary probe/probe

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
INSTR 1000000000

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
# a target tools/test_watch.py stopped: one test named (libtest's 60-second notice), one finished
HUNG = """     Running tests/hang.rs (target/debug/deps/hang-6)

running 3 tests
test fine ... ok
test slow::spin has been running for over 60 seconds
test quick has been running for over 60 seconds
test quick ... ok
gate: hung: no test finished for 110 s
gate: hung test: slow::spin
gate: hung: stopped 77 (hang-6), 1 processes
error: test failed, to rerun pass `--test hang`

Caused by:
  process didn't exit successfully: `target/debug/deps/hang-6` (signal: 9, SIGKILL: kill)
"""
# its tests passed, then the process failed (a panic or abort after libtest's summary)
LATE = """     Running tests/late.rs (target/debug/deps/late-4)
gate: binary late/late

running 1 test
test fine ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
INSTR 1000000000

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
FAIL sim failure in scenario `three_random`, seed 9, step 4: agreement lost
replay: osis_sim::replay("three_random", 9)
FAIL sim failure in scenario `crash_restart`, seed 8, step 2: agreement lost
replay: osis_sim::replay("crash_restart", 8)
scenario seeds failed
drift_parks 15 0
three_random 15 1
crash_restart 15 1
failing: osis_sim::replay("crash_restart", 8)  (sim-sweep --seeds 1 --from 8 --only crash_restart)
failing: osis_sim::replay("three_random", 9)  (sim-sweep --seeds 1 --from 9 --only three_random)
elapsed 3 s
"""
# a hung seed: the runner prints its failures and exits before the sweep's tally
SIM_HUNG = """sim-sweep: 2 scenarios, seeds 7..22, 16 jobs
FAIL sim failure in scenario `three_random`, seed 9, step 4: agreement lost
replay: osis_sim::replay("three_random", 9)
sim-sweep: osis_sim::replay("drift_parks", 7) used 600 CPU-s (OSIS_SEED_TIMEOUT_SECS): hung, moving on
sim-sweep: 30 of 30 run, 1 failing, 1 hung
failures:
osis_sim::replay("three_random", 9): agreement lost
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
check("hung", gate_failures.cargo_failures(HUNG + COUNT1), [("slow::spin", ["hung: no test finished for 110 s"], [])])
check("hung, no test named", names(HUNG.replace("gate: hung test: slow::spin\n", "") + COUNT1), [None])
check("crash after the summary", names(LATE + COUNT1), [None])
check("doctest", names(DOCTEST + COUNT1), ["src/lib.rs - f (line 1)"])
check("count off", names(KNOWN_ONLY + "error: 2 targets failed:\n"), ["order::known_plain", "other_large", None])
check("no count: cargo killed", names(KNOWN_ONLY), ["order::known_plain", "other_large", None])
check("truncated mid-target", names(KNOWN_ONLY + "     Running tests/b.rs (b-5)\n\nrunning 3 tests\ntest x ... ok\n"), ["order::known_plain", "other_large", None, None])
check("cargo error outside a target", names(KNOWN_ONLY + "error: could not compile `osis-engine`\n" + COUNT1), ["order::known_plain", "other_large", None])
check("passing log", gate_failures.cargo_failures(KNOWN_ONLY.split("     Running")[0] + "   Doc-tests probe\n\nrunning 0 tests\n\ntest result: ok. 0 passed\n"), [])
check("sim", [(n, s) for n, _, s in gate_failures.sim_failures(SIM)], [("sim-sweep:crash_restart", ['seed 8 (replay: osis_sim::replay("crash_restart", 8))']), ("sim-sweep:three_random", ['seed 9 (replay: osis_sim::replay("three_random", 9))'])])
check("sim unit has its failure", "agreement lost" in gate_failures.sim_failures(SIM)[1][1][0], True)
check("sim hung exit", [n for n, _, _ in gate_failures.sim_failures(SIM_HUNG)], [None])
check("sim tally off", [n for n, _, _ in gate_failures.sim_failures(SIM.replace("drift_parks 15 0", "drift_parks 15 1"))], [None, "sim-sweep:crash_restart", "sim-sweep:three_random"])

d = tempfile.mkdtemp()
os.makedirs(f"{d}/tools")
os.makedirs(f"{d}/issues")
open(f"{d}/issues/known.md", "w").write("# k\n")
open(f"{d}/issues/sim.md", "w").write("# s\n")
# the fixtures' binaries, each 1 G instructions
open(f"{d}/{gate_failures.COST}", "w").write("# comment\nprobe/probe 1.5\nlate/late 1.5\n")


def known(text):
    open(f"{d}/{gate_failures.KNOWN}", "w").write(text)
    return gate_failures.known(d)


ns, errs = known("# comment\norder::known_plain OSIS_ORDER_SEED=1 issues/known.md ^seed \\d+, Lists # not a comment\n")
check("known", ({k: [(x.issue, x.pattern.pattern, x.rate) for x in v] for k, v in ns.items()}, errs), ({"order::known_plain": [("issues/known.md", "^seed \\d+, Lists # not a comment", False)]}, []))
ns, _ = known("a rate:OSIS_ORDER_START=3 issues/known.md x\n")
check("known rate", [x.rate for x in ns["a"]], [True])
ns, errs = known("a OSIS_ROLES_START=0,OSIS_ROLES_SEEDS=2 issues/known.md counts:safety_N=3,admin=12 family: \\{\n")
check("known counts", ([(x.counts, x.env, x.pattern.pattern) for x in ns["a"]], errs), ([({"safety_N": 3, "admin": 12}, {"OSIS_ROLES_START": "0", "OSIS_ROLES_SEEDS": "2"}, "family: \\{")], []))
check("counted envs", gate_failures.counted_envs(d), {"a": {"OSIS_ROLES_START": "0", "OSIS_ROLES_SEEDS": "2"}})
_, errs = known("a rate:S=1 issues/known.md counts:x=1 p\nb - issues/known.md counts:x p\nc - issues/known.md counts:x=1\nd - issues/known.md counts:x=1 p\nd - issues/known.md q\n")
check("known counts refuses", [e.split(":", 2)[-1].strip()[:40] for e in errs], ["a `counts:` line's REPRO is the setting ", "want `NAME REPRO ISSUE counts:CHECK=N,..", "want `NAME REPRO ISSUE counts:CHECK=N,..", "a test with a `counts:` line has no othe"])
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
LISTED = f"{SEEDS}\nother_large 1 issues/known.md floor\nsim-sweep:three_random 9 issues/sim.md agreement\nsim-sweep:crash_restart 8 issues/sim.md agreement\n"
rc, out = summary(LISTED, [("default-tests", "101", KNOWN_ONLY + COUNT1), ("gate.sim", "1", SIM)])
check("only known: exit 3", (rc, "KNOWN failures only (4," in out), (3, True))
check("only known: issue shown", "KNOWN gate.sim  sim-sweep:three_random: issues/sim.md" in out, True)
check("seed lines shown", "seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x)\n" in out, True)
for what, text in [("hung-seed exit", EXITED), ("SIGKILL", KILLED), ("crash after summary", LATE), ("doctest", DOCTEST)]:
    rc, out = summary(LISTED, [("default-tests", "101", KNOWN_ONLY + text + "error: 2 targets failed:\n")])
    check(f"known + {what}: NEW", (rc, "1 NEW, 2 KNOWN" in out), (1, True))
rc, out = summary("", [("default-tests", "101", HUNG + COUNT1)])
check("hung test: NEW, named", (rc, "NEW   default-tests  slow::spin" in out), (1, True))
rc, out = summary("slow::spin 1 issues/known.md ^hung: \n", [("default-tests", "101", HUNG + COUNT1)])
check("listed hang: KNOWN", (rc, "KNOWN default-tests  slow::spin: issues/known.md" in out), (3, True))
rc, out = summary(LISTED, [("default-tests", "137", KNOWN_ONLY)])
check("known, then cargo killed: NEW", (rc, "1 NEW, 2 KNOWN" in out), (1, True))
rc, out = summary(LISTED, [("gate.sim", "101", SIM_HUNG)])
check("sim hung exit of a known scenario: NEW", (rc, "1 NEW, 0 KNOWN" in out), (1, True))
# a new bug in a listed test: a seed line no pattern names
rc, out = summary(LISTED.replace("(, Lists)?", ""), [("default-tests", "101", KNOWN_ONLY + COUNT1)])
check("listed test, new failure text: NEW-TEXT", (rc, "1 NEW, 1 KNOWN" in out, "NEW-TEXT default-tests  order::known_plain: listed (issues/known.md), but this failure matches none of its patterns: seed 42, Lists" in out), (1, True, True))
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
rc, out = summary(f"{LISTED}ok 1 issues/known.md x\n", [("default-tests", "0", "test ok ... ok\n")])
check("pass with a stale line: exit 0, listed", (rc, out.split("\n")[-2]), (0, "   KNOWN-BUT-PASSED: ok (default-tests; issues/known.md)"))
# a listed test that ran and passed is reported, its exit unchanged; one failing elsewhere is not
rc, out = summary(f"{LISTED}ok 1 issues/known.md x\nfine 1 issues/known.md x\ndrift_parks 1 issues/sim.md x\nsim-sweep:drift_parks 1 issues/sim.md x\n", [("default-tests", "101", KNOWN_ONLY + COUNT1), ("gate.gui", "0", HUNG.replace("test fine ... ok", "test ok ... ok")), ("gate.sim", "1", SIM)])
check("known but passed", (rc, [l for l in out.split("\n") if "KNOWN-BUT-PASSED:" in l], out.split("\n")[-2].endswith("; 2 KNOWN-BUT-PASSED to remove")), (3, ["   KNOWN-BUT-PASSED: ok (default-tests, gate.gui; issues/known.md)", "   KNOWN-BUT-PASSED: sim-sweep:drift_parks (gate.sim; issues/sim.md)"], True))
rc, out = summary(f"{LISTED}quick 1 issues/known.md x\n", [("default-tests", "0", "test quick ... ok\n"), ("gate.gui", "101", "     Running tests/q.rs (q-1)\ngate: binary q/q\nINSTR 1000000000\n\nrunning 1 test\ntest quick ... FAILED\n\nfailures:\n\n---- quick stdout ----\nx\n\nfailures:\n    quick\n\ntest result: FAILED. 0 passed; 1 failed\n\nerror: test failed, to rerun pass `--test q`\n" + COUNT1)])
check("known, passed in one stage, failed in another: not reported", (rc, "KNOWN-BUT-PASSED" in out), (3, False))
# a line failing at a rate: passing is expected, said so; a name with one plain line keeps the question
rc, out = summary(f"{LISTED}ok rate:S=1 issues/known.md x\nfine rate:S=1 issues/known.md x\nfine 2 issues/sim.md y\n", [("default-tests", "101", KNOWN_ONLY + COUNT1), ("gate.gui", "0", HUNG.replace("test fine ... ok", "test ok ... ok") + "test fine ... ok\n")])
check("known at a rate, passed", (rc, [l for l in out.split("\n") if "passed:" in l or "   KNOWN-BUT-PASSED:" in l]), (3, ["   KNOWN, passed: ok (default-tests, gate.gui): fails at a rate (issues/known.md): passing this run is expected", "   KNOWN-BUT-PASSED: fine (gate.gui; issues/sim.md)"]))
# the property and sim stages' runs by CPU-s: runner summary lines (not progress lines), the order
# harness's `NAME (SIZE)` line naming test NAME_SIZE, then tests with no line
PROPS = """a::p_large: 3 seeds from 0 (OSIS_COVERED_START=0)
a::p_large: 1 of 3 run, 0 failing, 0 hung, 16 threads, 60.0 s, 900.0 CPU-s (running)
a::p_large: 3 of 3 run, 0 failing, 0 hung, 16 threads, 70.5 s, 1000.5 CPU-s
test a::p_large ... ok
order::held_set_decides (plain): 8 seeds from 0, 6 steps, 1 failing, 9.0 s, 120.0 CPU-s; held-model compared 3 aspects over 2 nodes
test order::held_set_decides_plain ... ok
test b::q_exhaustive ... ok
"""
check("costs", gate_failures.costs(PROPS), ([(1000.5, 70.5, "a::p_large"), (120.0, 9.0, "order::held_set_decides (plain)")], ["b::q_exhaustive"]))
rc, out = summary("", [("default-tests", "0", "a::x: 1 of 1 run, 0 failing, 0 hung, 1 threads, 1.0 s, 5.0 CPU-s\n"), ("gate.properties", "0", PROPS), ("gate.sim", "0", "sim-sweep: 75 of 75 run, 0 failing, 0 hung, 16 threads, 10.9 s, 150.0 CPU-s\n")])
check("cost table", (rc, out.split("== test stages")[0]), (0, "== property and sim CPU-s, costliest first (1270 CPU-s measured)\n"
      "     1000.5 CPU-s    70.5 s  a::p_large\n      150.0 CPU-s    10.9 s  sim-sweep\n      120.0 CPU-s     9.0 s  order::held_set_decides (plain)\n          (no CPU line)  b::q_exhaustive\n"))
# tools/prop_run.py's per-process lines replace the tests' own in that log; a test with none is listed
PROCESS = PROPS + "gate: cost a::p_large: 71.0 s, 1010.0 CPU-s\ngate: cost order::held_set_decides_plain: 9.5 s, 125.0 CPU-s\ngate: cost c::r_plain: 2.0 s, 30.0 CPU-s\ntest c::r_plain ... ok\n"
check("process costs", gate_failures.costs(PROCESS), ([(1010.0, 71.0, "a::p_large"), (125.0, 9.5, "order::held_set_decides_plain"), (30.0, 2.0, "c::r_plain")], ["b::q_exhaustive"]))
# a `counts:` line: the same failing counts are KNOWN, other counts NEW-COUNTS (the branch changed what fails)
FAMILY = """     Running unittests src/lib.rs (target/debug/deps/roles-1)

running 1 test
test paths::tests::small_family_holds_large ... FAILED
gate: cost paths::tests::small_family_holds_large: 9.0 s, 80.0 CPU-s

failures:

---- paths::tests::small_family_holds_large stdout ----
panicked at x.rs:1:1:
family: {"admin": 12, "safety N": 3}
{"admin": "first: {\\"x\\": 5}"}

failures:
    paths::tests::small_family_holds_large

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s

error: test failed, to rerun pass `--lib`
"""
LINE = "roles-model/paths::tests::small_family_holds_large - issues/known.md counts:admin=12,safety_N=3 family: \\{\n"
rc, out = summary(LINE, [("gate.properties", "101", FAMILY + COUNT1)])
check("same counts: KNOWN", (rc, "KNOWN gate.properties  paths::tests::small_family_holds_large: issues/known.md, same failing counts" in out), (3, True))
rc, out = summary(LINE.replace("admin=12", "admin=11"), [("gate.properties", "101", FAMILY + COUNT1)])
check("other counts: NEW-COUNTS", (rc, "NEW-COUNTS gate.properties  paths::tests::small_family_holds_large: listed (issues/known.md) with failing counts admin=11,safety_N=3, this run admin=12,safety_N=3" in out, "1 NEW, 0 KNOWN" in out), (1, True, True))
rc, out = summary(LINE.replace(",safety_N=3", ""), [("gate.properties", "101", FAMILY + COUNT1)])
check("a check failing beyond the baseline: NEW-COUNTS", (rc, "NEW-COUNTS" in out), (1, True))
rc, out = summary(LINE.replace("family: ", "other: "), [("gate.properties", "101", FAMILY + COUNT1)])
check("counts line, other text: NEW-TEXT", (rc, "NEW-TEXT" in out), (1, True))
rc, out = summary("x 1 issues/gone.md p\n", [("default-tests", "0", "")])
check("a bad list fails the gate", (rc, "NEW   known list" in out), (1, True))

# each default-test binary's instructions (tools/test_count.sh's lines) against tools/test_cost.txt
COUNTED = """     Running unittests src/lib.rs (target/debug/deps/c-1)
gate: binary c/c

running 1 test
test a ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
INSTR 3000000000
     Running tests/it/main.rs (target/debug/deps/it-2)
gate: binary c/it

running 1 test
test b ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
INSTR 1000000000
   Doc-tests c
gate: binary c/rust_out

running 1 test
INSTR 5
test src/lib.rs - f (line 1) ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s

"""
check("instructions", gate_failures.instructions(COUNTED), ({"c/c": 3000000000, "c/it": 1000000000}, []))
check("a binary without a count", gate_failures.instructions(COUNTED.replace("INSTR 1000000000\n", "INSTR unavailable (kernel.perf_event_paranoid=4, needs <= 2)\n"))[1], ["Running tests/it/main.rs (target/debug/deps/it-2)"])
check("lines written", [gate_failures.line_g(n) for n in (1592775257047, 34000000, 1000000000, 2000000000)], ["2400", "0.051", "1.5", "3"])


def costed(lines, stages):
    open(f"{d}/{gate_failures.COST}", "w").write(lines)
    return summary("", stages)


rc, out = costed("c/c 4\nc/it 1.5\nother/x 1\n", [("default-tests", "0", COUNTED)])
check("counts within their lines pass", (rc, out), (0, "== test cost: 2 binaries, 4 G instructions (tools/test_cost.txt)\n== test stages: 1 run of 1, 0 failed\n"))
rc, out = costed("c/c 2\n", [("default-tests", "0", COUNTED)])
check("over its line or with none: NEW-COST", (rc, [l for l in out.split("\n") if "COST" in l], out.split("\n")[-2]), (1, [
    "   NEW-COST default-tests  c/c: 3 G instructions, 1.50x its line 2: slim it, or raise the line to 4.5 with the reason in the commit message",
    "   NEW-COST default-tests  c/it: 1 G instructions, no line: add `c/it 1.5` to tools/test_cost.txt"], "== gate FAILED: 2 NEW, 0 KNOWN"))
rc, out = costed("c/c 7\nc/it 2\nc/gone 1\n", [("default-tests", "0", COUNTED)])
check("under half its line, or not run beside its crate: STALE-COST", (rc, out.split("\n")[-4:-1]), (0, [
    "== STALE-COST (2): test-cost lines past their binaries' counts. Update each in tools/test_cost.txt in this landing",
    "   STALE-COST: c/c (default-tests; 3 G instructions, under its line 7 / 2: lower it to 4.5)",
    "   STALE-COST: c/gone (its crate ran, it did not: drop the line)"]))
rc, out = costed("c/c 4\nc/it 1.5\n", [("default-tests", "0", COUNTED.replace("INSTR 3000000000", "INSTR 1000000000")), ("gate.gui-tests", "0", COUNTED.replace("INSTR 3000000000", "INSTR 5000000000"))])
check("a binary's largest count over the counted stages", (rc, "NEW-COST gate.gui-tests  c/c: 5 G" in out), (1, True))
rc, out = costed("c/c 4\n", [("default-tests", "0", COUNTED.replace("INSTR 1000000000\n", ""))])
check("a binary without a count is NEW (the runner did not apply)", (rc, "NEW   default-tests  Running tests/it/main.rs (target/debug/deps/it-2) ran without an instruction count" in out), (1, True))
rc, out = costed("", [("default-tests", "101", HUNG + COUNT1)])
check("a stopped target is its hang, not a missing count", (rc, "instruction count" in out), (1, False))
rc, out = costed("", [("gate.properties", "0", COUNTED)])
check("properties are not counted", (rc, "test cost" in out), (0, False))
rc, out = costed("c/c 0\nc 3\nc/it x\nc/it 1.5\nc/it 2\n", [("default-tests", "0", COUNTED)])
check("a bad test-cost list fails the gate", [l.split(": ", 1)[1][:30] for l in out.split("\n") if "test-cost list" in l], ["want `CRATE/NAME G` (G over 0)"] * 3 + ["c/it: a second line"])


shutil.rmtree(d)
print(f"gate failures: {'ok' if not fails else 'FAILED'}")
sys.exit(fails)
