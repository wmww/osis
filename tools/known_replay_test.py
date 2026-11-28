#!/usr/bin/env python3
"""Tests tools/known_replay.py in a temp repo with a fake `cargo` on PATH (prints $FAKE_LOG, exits
$FAKE_RC, records each call): only lines HEAD adds are replayed; a line passes when its replay fails
with each seed line matched and its own pattern matching one; refused when its pattern matches only
text off the seed line, when the replay passes, or when only another line's pattern matches.
Exit 1 on a mismatch."""
import os, subprocess, sys, tempfile

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_replay.py")
NAME = "c/m::t_plain"
LOG = """     Running tests/it/main.rs (target/debug/deps/it-5)

running 1 test
test m::t_plain ... FAILED

failures:

---- m::t_plain stdout ----
panicked at x.rs:1:1:
t_plain: 1 of 1 seeds failed:
seed 7 (replay: T_START=7 cargo test t): node 2 reads thing 3 unlike the reference
event log:
  N holds otherwise

failures:
    m::t_plain

test result: FAILED. 0 passed; 1 failed

error: test failed, to rerun pass `--test it`
error: 1 target failed:
    `--test it`
"""
PASS = "     Running tests/it/main.rs (target/debug/deps/it-5)\n\nrunning 1 test\ntest m::t_plain ... ok\n\ntest result: ok. 1 passed; 0 failed\n"
fail = 0


def check(what, got, want):
    global fail
    if got != want:
        print(f"FAIL {what}: got {got!r}, want {want!r}")
        fail = 1


with tempfile.TemporaryDirectory() as d:
    git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    os.makedirs(f"{d}/tools")
    os.makedirs(f"{d}/issues")
    os.makedirs(f"{d}/bin")
    open(f"{d}/issues/x.md", "w").write("# x\n")
    open(f"{d}/bin/cargo", "w").write('#!/bin/sh\necho "${T_START:-} $*" >> "$CALLS"\ncat "$FAKE_LOG"\nexit "$FAKE_RC"\n')
    os.chmod(f"{d}/bin/cargo", 0o755)
    known = f"{d}/tools/known_failures.txt"
    old = f"{NAME} rate:T_START=1 issues/x.md reads thing"
    open(known, "w").write(f"# header\n{old}\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    def run(lines, log, rc):
        open(known, "w").write("# header\n" + "".join(l + "\n" for l in lines))
        open(f"{d}/log", "w").write(log)
        open(f"{d}/calls", "w").close()
        env = dict(os.environ, PATH=f"{d}/bin:{os.environ['PATH']}", FAKE_LOG=f"{d}/log", FAKE_RC=str(rc), CALLS=f"{d}/calls")
        r = subprocess.run([sys.executable, TOOL, base], cwd=d, env=env, capture_output=True, text=True)
        calls = open(f"{d}/calls").read().splitlines()
        return r.returncode, len(calls), r.stdout, calls

    check("no new line: nothing replayed", run([old], LOG, 101)[:2], (0, 0))
    check("a new non-rate line: nothing replayed", run([old, f"{NAME} - issues/x.md unlike"], LOG, 101)[:2], (0, 0))
    rc, calls, out, cmds = run([old, f"{NAME} rate:T_START=7,T_SEEDS=1 issues/x.md node \\d+ reads"], LOG, 101)
    check("seed line matched: holds", (rc, calls), (0, 1))
    check("replayed at its REPRO, as the gate does", cmds, ["7 test --locked --no-fail-fast -p c --tests -- --exact m::t_plain --include-ignored"])
    rc, calls, out, _ = run([f"{NAME} rate:T_START=7 issues/x.md N holds otherwise"], LOG, 101)
    check("pattern off the seed line: refused", (rc, calls, "NEW-TEXT" in out or "matching none" in out), (1, 1, True))
    rc, _, out, _ = run([old, f"{NAME} rate:T_START=7 issues/x.md reads"], PASS, 0)
    check("replay passes: refused", (rc, "STALE-RATE" in out), (1, True))
    rc, _, out, _ = run([old, f"{NAME} rate:T_START=7 issues/x.md event log"], LOG, 101)
    check("own pattern dead, another matches: refused", (rc, "this line's pattern matches none" in out), (1, True))

sys.exit(fail)
