#!/usr/bin/env python3
"""cpuprof_report.py SAMPLES [N] [FILTER...]: the N functions with the most samples, inclusive and
self, from a tools/cpuprof sample file (symbols by llvm-symbolizer, once); with FILTERs, one report
per filter over the samples with a frame whose name contains it."""
import collections
import glob
import re
import shutil
import subprocess
import sys

path = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 40
sym = shutil.which("llvm-symbolizer") or next(iter(sorted(glob.glob("/usr/bin/llvm-symbolizer-*"), reverse=True)), None)
if sym is None:
    sys.exit("cpuprof: no llvm-symbolizer on PATH")
lines = [line for line in open(path) if line.strip()]
taken = next((int(x.split()[2]) for x in lines if x.startswith("# taken ")), None)
samples = [line.split() for line in lines if not line.startswith("#")]
addrs = collections.defaultdict(set)
for s in samples:
    for f in s:
        if ":" not in f:
            continue
        obj, a = f.rsplit(":", 1)
        addrs[obj].add(a)
name = {}
for obj, aa in addrs.items():
    aa = sorted(aa)
    r = subprocess.run([sym, "--obj=" + obj, "--functions=linkage", "--no-inlines", "--demangle"], input="\n".join("0x" + a for a in aa), capture_output=True, text=True)
    for a, block in zip(aa, r.stdout.strip().split("\n\n")):
        name[(obj, a)] = re.sub(r"::h[0-9a-f]{16}$", "", block.split("\n")[0])
stacks = [[name.get(tuple(f.rsplit(":", 1)), "??") for f in s] for s in samples]
if taken and taken > len(samples):
    print(f"TRUNCATED: the first {len(samples)} of {taken} samples taken, so only the run's start: rerun with "
          f"CPUPROF_INSTR about {taken / len(samples):.1f}x larger")
for filt in sys.argv[3:] or [None]:
    incl, own, total = collections.Counter(), collections.Counter(), 0
    for fns in stacks:
        if filt and not any(filt in f for f in fns):
            continue
        total += 1
        if fns:
            own[fns[0]] += 1
        incl.update(set(fns))
    print(f"{path}{f' [{filt}]' if filt else ''}: {total} samples of {len(samples)}")
    print("--- inclusive")
    for f, c in incl.most_common(n):
        print(f"{100 * c / max(total, 1):5.1f}% {f[:160]}")
    print("--- self")
    for f, c in own.most_common(n // 2):
        print(f"{100 * c / max(total, 1):5.1f}% {f[:160]}")
