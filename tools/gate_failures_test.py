#!/usr/bin/env python3
"""Tests tools/gate_failures.py on fabricated stage logs and a fabricated known list. Exit 1 on a mismatch."""
import os, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_failures

# `cargo test --no-fail-fast`: a target with a seed harness failure and a plain one, a target that
# crashed before its summary, a passing doctest target
CARGO = """     Running unittests src/lib.rs (target/debug/deps/probe-1)

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
assertion failed

failures:
    order::known_plain
    other_large

test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: test failed, to rerun pass `--lib`
     Running tests/a.rs (target/debug/deps/a-2)

running 1 test
error: test failed, to rerun pass `--test a`
   Doc-tests probe

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: 2 targets failed:
    `--lib`
    `--test a`
"""
SIM = """sim-sweep: 2 scenarios, seeds 7..22, 16 jobs
FAIL no_host_chain seed 9: agreement
scenario seeds failed
no_host 15 0
no_host_chain 15 1
evil_host_drops 15 1
failing: osis_sim::replay("evil_host_drops", 8)
failing: osis_sim::replay("no_host_chain", 9)
elapsed 3 s
"""

fails = 0


def check(name, got, want):
    global fails
    if got != want:
        print(f"FAIL {name}:\n got  {got!r}\n want {want!r}")
        fails = 1


got = gate_failures.cargo_failures(CARGO)
check("cargo names", [n for n, _ in got], ["order::known_plain", "other_large", None])
check("cargo seeds", got[0][1], ["seed 41 (replay: OSIS_ORDER_SEED=41 cargo test x)", "seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x)"])
check("cargo no seeds", got[1][1], [])
check("crash names its target", "`--test a`" in got[2][1], True)
check("sim", [n for n, _ in gate_failures.sim_failures(SIM)], ["sim-sweep:evil_host_drops", "sim-sweep:no_host_chain"])

d = tempfile.mkdtemp()
os.makedirs(f"{d}/tools")
os.makedirs(f"{d}/issues")
open(f"{d}/issues/known.md", "w").write("# k\n")
open(f"{d}/issues/sim.md", "w").write("# s\n")


def known(text):
    open(f"{d}/{gate_failures.KNOWN}", "w").write(text)
    return gate_failures.known(d)


names, errs = known("# comment\norder::known_plain OSIS_ORDER_SEED=1 issues/known.md\nsim-sweep:evil_host_drops 8 issues/sim.md  # trailing\n")
check("known", (names, errs), ({"order::known_plain": ["issues/known.md"], "sim-sweep:evil_host_drops": ["issues/sim.md"]}, []))
_, errs = known("a 1 issues/gone.md\nb 2\nc 3 notes/x.md\n")
check("known refuses", [e.split(": ", 1)[1] for e in errs], ["issues/gone.md: no such issue file (fixed? drop the line)", "want `NAME REPRO ISSUE`, got 'b 2'", "notes/x.md: no such issue file (fixed? drop the line)"])


def summary(listed, stages, expected=None):
    """The summary's exit and lines against a known list and {stage: (exit, log text)}."""
    known(listed)
    for i, (stage, (rc, text)) in enumerate(stages.items()):
        open(f"{d}/{i}.log", "w").write(text)
    open(f"{d}/sel", "w").write("".join(f"run {s} cmd\n" for s in (expected or stages)))
    open(f"{d}/res", "w").write("".join(f"{s} {rc} {d}/{i}.log\n" for i, (s, (rc, _)) in enumerate(stages.items())))
    r = subprocess.run([sys.executable, gate_failures.__file__, f"{d}/sel", f"{d}/res", d], capture_output=True, text=True)
    return r.returncode, r.stdout


LISTED = "order::known_plain 1 issues/known.md\nother_large 1 issues/known.md\nsim-sweep:no_host_chain 9 issues/sim.md\nsim-sweep:evil_host_drops 8 issues/sim.md\n"
rc, out = summary(LISTED, {"default-tests": ("0", ""), "gate.sim": ("1", SIM)})
check("only known: exit 3", rc, 3)
check("only known: line", "KNOWN failures only (2," in out, True)
check("only known: issue shown", "KNOWN gate.sim  sim-sweep:no_host_chain: issues/sim.md" in out, True)
rc, out = summary(LISTED, {"default-tests": ("101", CARGO), "gate.sim": ("1", SIM)})
check("crash is NEW", (rc, "1 NEW, 4 KNOWN" in out), (1, True))
check("seed lines shown", "seed 42, Lists (replay: OSIS_ORDER_SEED=42 cargo test x)\n" in out, True)
rc, out = summary("", {"gate.properties": ("1", CARGO)})
check("unlisted is NEW", (rc, "3 NEW, 0 KNOWN" in out), (1, True))
rc, out = summary(LISTED, {"default-tests": ("101", "error[E0425]: cannot find value\n")})
check("unnamed failure is NEW", (rc, "exited 101 without naming" in out), (1, True))
rc, out = summary(LISTED, {"default-tests": ("0", "")}, ["default-tests", "gate.sim"])
check("a stage that did not run is NEW", (rc, "NEW   gate.sim  did not run" in out), (1, True))
rc, out = summary(LISTED, {"default-tests": ("0", ""), "gate.sim": ("0", "")})
check("pass", (rc, out), (0, "== test stages: 2 run of 2, 0 failed\n"))
rc, out = summary("x 1 issues/gone.md\n", {"default-tests": ("0", "")})
check("a bad list fails the gate", (rc, "NEW   known list" in out), (1, True))

shutil.rmtree(d)
print(f"gate failures: {'ok' if not fails else 'FAILED'}")
sys.exit(fails)
