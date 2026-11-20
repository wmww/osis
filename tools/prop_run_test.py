#!/usr/bin/env python3
"""Tests tools/prop_run.py against a fake libtest binary: each test in its own process with its CPU
line, one libtest-shaped output tools/gate_failures.py parses, a `counts:` line's setting applied,
a crashed child left without a summary. Exit 1 on a mismatch."""
import contextlib, io, os, shutil, stat, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_failures, prop_run

# libtest's shape: `--list [filters]`, `--exact NAME [--ignored]`
FAKE = r'''#!/usr/bin/env python3
import os, sys
TESTS = ["a::spin_large", "a::fail_large", "b::envy_plain", "c::crash_large", "repro_x_large"]
args = sys.argv[1:]
if "--list" in args:
    skips = [args[i + 1] for i, a in enumerate(args) if a == "--skip"]
    filt = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] != "--skip")]
    for t in TESTS:
        if (not filt or any(f in t for f in filt)) and not any(s in t for s in skips):
            print(f"{t}: test")
    sys.exit(0)
assert "--ignored" in args and args[0] == "--exact", args
n = args[1]
if n == "c::crash_large":
    print("\nrunning 1 test")
    sys.exit(1)
if n == "a::spin_large":
    x = 0
    for i in range(3_000_000):
        x += i
print(f"\nrunning 1 test\ntest {n} ... {'ok' if n == 'a::spin_large' else 'FAILED'}")
if n == "a::spin_large":
    print("\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n")
    sys.exit(0)
why = f'family: {{"x": {os.environ.get("X", "unset")}}}' if n == "b::envy_plain" else "assertion failed: floor"
print(f"\nfailures:\n\n---- {n} stdout ----\n{why}\n\nfailures:\n    {n}\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n")
sys.exit(101)
'''

fails = 0


def check(name, got, want):
    global fails
    if got != want:
        print(f"FAIL {name}:\n got  {got!r}\n want {want!r}")
        fails = 1


def run(*args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = prop_run.main([fake, *args], d)
    return rc, buf.getvalue()


d = tempfile.mkdtemp()
fake = os.path.join(d, "fake")
open(fake, "w").write(FAKE)
os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
os.makedirs(f"{d}/tools")
os.makedirs(f"{d}/issues")
open(f"{d}/issues/k.md", "w").write("# k\n")
open(f"{d}/{gate_failures.KNOWN}", "w").write("crate/b::envy_plain X=5 issues/k.md counts:x=5 family: \\{\n")

os.environ["X"] = "9"
rc, out = run("--ignored", "spin_large", "fail_large", "envy_plain", "--skip", "repro_")
check("exit on a failure", rc, 101)
lines = [l for l in out.split("\n") if l.startswith(("test a", "test b", "gate: cost"))]
check("each test's line, then its cost", (sorted(lines[::2]), [l.split()[2].rstrip(":") for l in lines[1::2]] == [l.split()[1] for l in lines[::2]]),
      (["test a::fail_large ... FAILED", "test a::spin_large ... ok", "test b::envy_plain ... FAILED"], True))
c, bare = gate_failures.costs(out)
check("costs name every test", (sorted(n for _, _, n in c), bare), (["a::fail_large", "a::spin_large", "b::envy_plain"], []))
check("the spinning test costs most", max(c)[2], "a::spin_large")
log = "     Running unittests src/lib.rs (fake)\n" + out + "error: test failed, to rerun pass `--lib`\nerror: 1 target failed:\n    `--lib`\n"
got = sorted(gate_failures.cargo_failures(log))
check("parsed failures", [(n, [x.strip() for x in u]) for n, u, _ in got], [("a::fail_large", ["assertion failed: floor"]), ("b::envy_plain", ['family: {"x": 5}'])])
check("the counts line's setting, not the gate's", 'family: {"x": 5}' in out, True)
check("a failing count parsed", gate_failures.failing_counts(got[1][1][0], gate_failures.known(d)[0]["b::envy_plain"][0].pattern), {"x": 5})

rc, out = run("--ignored", "spin_large")
check("pass", (rc, out.strip().split("\n")[-1].startswith("test result: ok. 1 passed; 0 failed;")), (0, True))
rc, out = run("--ignored", "nothing_matches")
check("no test", (rc, "running 0 tests" in out, "test result: ok. 0 passed" in out), (0, True, True))
rc, out = run("--ignored", "spin_large", "crash_large")
check("a crash: no summary line, non-zero", (rc != 0, "test result:" in out, "c::crash_large ended without one test's result" in out), (True, False, True))
check("a crash parses as unaccounted", [n for n, _, _ in gate_failures.cargo_failures("     Running x (fake)\n" + out + "error: test failed, to rerun pass `--lib`\nerror: 1 target failed:\n")], [None])

shutil.rmtree(d)
print(f"prop_run: {'ok' if not fails else 'FAILED'}")
sys.exit(fails)
