#!/usr/bin/env python3
"""Tests tools/cpuprof_report.py on a fabricated sample file with a fake llvm-symbolizer (one
address holding an inlined call). Exit 1 on a mismatch."""
import os, subprocess, sys, tempfile

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpuprof_report.py")
d = tempfile.mkdtemp()
# address -> frames innermost first (function, line); 0x2 is `walk` inlined into `outer`
FRAMES = {"0x1": [("leaf::h0123456789abcdef", "a.rs:1:1")], "0x2": [("walk", "w.rs:7:3"), ("outer", "o.rs:2:1")],
          "0x3": [("caller_a", "c.rs:1:1")], "0x4": [("caller_b", "c.rs:2:1")], "0x5": [("main", "m.rs:1:1")]}
os.makedirs(f"{d}/bin")
with open(f"{d}/bin/llvm-symbolizer", "w") as f:
    f.write(f"""#!{sys.executable}
import sys
frames = {FRAMES!r}
inl = "--inlines" in sys.argv
for a in sys.stdin.read().split():
    fr = frames[a] if inl else frames[a][-1:]
    print("\\n".join(f"{{n}}\\n{{l}}" for n, l in fr) + "\\n")
""")
os.chmod(f"{d}/bin/llvm-symbolizer", 0o755)
# stacks innermost first: leaf under outer from caller_a (2), from caller_b (1); main alone (1)
with open(f"{d}/samples", "w") as f:
    f.write("# taken 4\nb:1 b:2 b:3 b:5\nb:1 b:2 b:3 b:5\nb:1 b:2 b:4 b:5\nb:5\n")
fails = 0


def report(*a):
    r = subprocess.run([sys.executable, TOOL, f"{d}/samples", "10", *a], capture_output=True, text=True, env=dict(os.environ, PATH=f"{d}/bin:" + os.environ["PATH"]))
    assert r.returncode == 0, r.stderr
    return r.stdout


def check(name, text, want, absent=()):
    global fails
    for w in want:
        if w not in text:
            print(f"FAIL {name}: missing {w!r}\n{text}")
            fails = 1
    for w in absent:
        if w in text:
            print(f"FAIL {name}: has {w!r}\n{text}")
            fails = 1


check("plain: inlined walk folded into outer", report(), [" 75.0% outer", " 75.0% leaf\n", "100.0% main"], absent=["walk"])
check("--inlines: walk its own frame, self by source line", report("--inlines"), [" 75.0% walk", " 75.0% leaf (a.rs:1:1)", " 25.0% main (m.rs:1:1)"])
check("--callers: who calls walk", report("--inlines", "--callers", "walk"), ["--- callers of walk (3 samples)", " 50.0% caller_a", " 25.0% caller_b"])
check("--callers at the base", report("--callers", "main"), ["--- callers of main (4 samples)", "100.0% (root)"])
check("--under: only outer and below", report("--under", "outer"), ["[under outer]: 3 samples of 4", "100.0% outer", "100.0% leaf"], absent=["caller_a", "main"])
print("cpuprof_report: FAILED" if fails else "cpuprof_report: ok")
sys.exit(fails)
