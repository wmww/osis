#!/usr/bin/env python3
"""Tests tools/targets.py against a fake cargo: one run per listed target with the selection
replaced, a doctest run only of listed packages with doctests and only when no kind is named,
runs side by side (each output whole), the first non-zero exit, and tools/prop_run.py's shared
slot pool. Exit 1 on a mismatch."""
import os, shutil, stat, subprocess, sys, tempfile

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, TOOLS)
import prop_run

# `test ... --no-run --message-format=json`: three targets of two packages; a run of target T
# prints its command, sleeps T's seconds, and exits 101 for `--test bad`; `metadata`: package b's
# library has doctests
FAKE = r'''#!/usr/bin/env python3
import json, os, sys, time
a = sys.argv[1:]
if a[0] == "metadata":
    lib = lambda d: [{"kind": ["lib"], "doctest": d}]
    print(json.dumps({"packages": [{"id": "A", "name": "a", "targets": lib(False)}, {"id": "B", "name": "b", "targets": lib(True)}]}))
    sys.exit(0)
if "--no-run" in a:
    art = lambda p, k, n: print(json.dumps({"reason": "compiler-artifact", "package_id": p, "target": {"kind": [k], "name": n}, "profile": {"test": True}, "executable": "/x"}))
    art("A", "lib", "a"); art("A", "test", "slow"); art("B", "test", "bad")
    print(json.dumps({"reason": "compiler-artifact", "package_id": "B", "target": {"kind": ["lib"], "name": "b"}, "profile": {"test": False}, "executable": None}))
    sys.exit(0)
print("     Running " + " ".join(a))
sys.stdout.flush()
time.sleep(0.6 if "slow" in a else 0.1)
print("end " + " ".join(a))
sys.exit(101 if "bad" in a else 0)
'''

fails = 0


def check(name, got, want):
    global fails
    if got != want:
        print(f"FAIL {name}:\n got  {got!r}\n want {want!r}")
        fails = 1


d = tempfile.mkdtemp()
bin_ = os.path.join(d, "bin")
os.makedirs(bin_)
open(f"{bin_}/cargo", "w").write(FAKE)
os.chmod(f"{bin_}/cargo", 0o755)
env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}")


def run(*args):
    r = subprocess.run([sys.executable, f"{TOOLS}/targets.py", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=d)
    return r.returncode, r.stdout.split("\n")


rc, out = run("cargo", "test", "--locked", "--no-fail-fast", "-p", "a", "--workspace")
runs = sorted(l for l in out if l.startswith("     Running"))
check("one run per target, the selection replaced; doctests of b alone", runs, [
    "     Running test --locked --no-fail-fast -p a --lib", "     Running test --locked --no-fail-fast -p a --test slow",
    "     Running test --locked --no-fail-fast -p b --doc", "     Running test --locked --no-fail-fast -p b --test bad"])
check("each output whole", all(out[i + 1] == "end" + out[i][len("     Running"):] for i, l in enumerate(out) if l.startswith("     Running")), True)
check("side by side: the slow target ends last", [l for l in out if l.startswith("end")][-1], "end test --locked --no-fail-fast -p a --test slow")
check("a failing run's exit", rc, 101)
rc, out = run("cargo", "test", "--tests", "-p", "a", "--", "--ignored", "x")
check("a named kind: no doctests; libtest args kept", sorted(l for l in out if l.startswith("     Running")),
      ["     Running test -p a --lib -- --ignored x", "     Running test -p a --test slow -- --ignored x", "     Running test -p b --test bad -- --ignored x"])

# the pool: a token per slot, taken without blocking; given back
r, w = os.pipe()
os.write(w, b"..")
s = prop_run.Slots(f"{r},{w}")
check("two slots taken, the third refused", [s.take(), s.take(), s.take()], [True, True, False])
s.give()
check("a slot given back is taken", s.take(), True)

# prop_run under a one-slot pool: one test at a time, costliest by the last run first
fake = os.path.join(d, "libtest")
open(fake, "w").write(r'''#!/usr/bin/env python3
import os, sys, time
a = sys.argv[1:]
if "--list" in a:
    print("t::a: test\nt::b: test\nt::c: test")
    sys.exit(0)
open(os.environ["LOG"], "a").write(f"start {a[1]} {os.environ.get('GATE_SLOTS', '-')}\n")
time.sleep(0.05)
open(os.environ["LOG"], "a").write(f"end {a[1]}\n")
print(f"\nrunning 1 test\ntest {a[1]} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s\n")
''')
os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
costs = os.path.join(d, "prop-costs")
open(costs, "w").write("- t::b 1.0\n- t::c 0.5\n- t::a 2.0\n- t::c 9.0\n")
r, w = os.pipe()
os.write(w, b".")
log = os.path.join(d, "log")
code = (f"import sys; sys.path.insert(0, {TOOLS!r}); import prop_run; prop_run.COSTS = {costs!r}; "
        f"sys.exit(prop_run.main([{fake!r}, '--ignored']))")
p = subprocess.run([sys.executable, "-c", code], env=dict(os.environ, GATE_SLOTS=f"{r},{w}", LOG=log), pass_fds=(r, w),
                   stdout=subprocess.PIPE, text=True)
check("one slot: one at a time, last cost first; the pool not passed on", (p.returncode, open(log).read().split("\n")),
      (0, ["start t::c -", "end t::c", "start t::a -", "end t::a", "start t::b -", "end t::b", ""]))
check("the slot given back", os.read(r, 1), b".")
check("each test's cost appended", len(open(costs).read().split("\n")), 8)

shutil.rmtree(d)
print(f"targets: {'ok' if not fails else 'FAILED'}")
sys.exit(fails)
