#!/usr/bin/env python3
"""cpuprof_report.py SAMPLES [N] [FILTER]: the N functions with the most samples, inclusive and
self, from a tools/cpuprof sample file (symbols by llvm-symbolizer)."""
import collections
import re
import shutil
import subprocess
import sys

path = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 40
filt = sys.argv[3] if len(sys.argv) > 3 else None
sym = next((s for s in ["llvm-symbolizer", "llvm-symbolizer-18"] if shutil.which(s)), None)
if sym is None:
    sys.exit("cpuprof: no llvm-symbolizer on PATH")
samples = [line.split() for line in open(path) if line.strip()]
addrs = collections.defaultdict(set)
for s in samples:
    for f in s:
        obj, a = f.rsplit(":", 1)
        addrs[obj].add(a)
name = {}
for obj, aa in addrs.items():
    aa = sorted(aa)
    r = subprocess.run([sym, "--obj=" + obj, "--functions=linkage", "--no-inlines", "--demangle"], input="\n".join("0x" + a for a in aa), capture_output=True, text=True)
    for a, block in zip(aa, r.stdout.strip().split("\n\n")):
        name[(obj, a)] = re.sub(r"::h[0-9a-f]{16}$", "", block.split("\n")[0])
incl, own, total = collections.Counter(), collections.Counter(), 0
for s in samples:
    fns = [name.get(tuple(f.rsplit(":", 1)), "??") for f in s]
    if filt and not any(filt in f for f in fns):
        continue
    total += 1
    if fns:
        own[fns[0]] += 1
    incl.update(set(fns))
print(f"{path}: {total} samples of {len(samples)}")
print("--- inclusive")
for f, c in incl.most_common(n):
    print(f"{100 * c / max(total, 1):5.1f}% {f[:160]}")
print("--- self")
for f, c in own.most_common(n // 2):
    print(f"{100 * c / max(total, 1):5.1f}% {f[:160]}")
