#!/usr/bin/env python3
"""cpuprof_report.py SAMPLES [N] [FILTER...] [--inlines] [--callers FN] [--under FN]: the N
functions with the most samples, inclusive and self, from a tools/cpuprof sample file (symbols by
llvm-symbolizer, once); with FILTERs, one report per filter over the samples with a frame whose
name contains it.
  --inlines     each inlined call its own frame (llvm-symbolizer --inlines), innermost first, and
                the self table by innermost source line: a walk inlined into its caller shows
  --callers FN  also, per sample holding a frame whose name contains FN, the frame calling its
                outermost one (`(root)` at the stack's base): what FN's cost is spent for
  --under FN    only samples holding FN, each cut to FN and what it calls: what FN spends on
The symbolizer is llvm-symbolizer on PATH, else the newest /usr/bin/llvm-symbolizer-*."""
import collections
import glob
import re
import shutil
import subprocess
import sys


def symbolize(sym, obj, addrs, inlines):
    """{addr: [(function, file:line), ...]} innermost first; one entry each without inlines."""
    r = subprocess.run([sym, "--obj=" + obj, "--functions=linkage", "--inlines" if inlines else "--no-inlines", "--demangle"],
                       input="\n".join("0x" + a for a in addrs), capture_output=True, text=True)
    out = {}
    for a, block in zip(addrs, r.stdout.strip().split("\n\n")):
        ls = block.split("\n")
        pairs = list(zip(ls[::2], ls[1::2])) or [(ls[0], "")]
        out[a] = [(re.sub(r"::h[0-9a-f]{16}$", "", f), loc) for f, loc in pairs]
    return out


def outermost(fns, fn):
    """The index of the outermost frame whose name contains fn, or None."""
    return next((i for i in range(len(fns) - 1, -1, -1) if fn in fns[i][0]), None)


def main(argv):
    inlines, callers, under, pos = False, None, None, []
    it = iter(argv)
    for a in it:
        if a == "--inlines":
            inlines = True
        elif a in ("--callers", "--under"):
            v = next(it, None)
            if v is None:
                sys.exit(__doc__)
            callers, under = (v, under) if a == "--callers" else (callers, v)
        else:
            pos.append(a)
    if not pos:
        sys.exit(__doc__)
    path = pos[0]
    n = int(pos[1]) if len(pos) > 1 else 40
    filters = pos[2:]
    sym = shutil.which("llvm-symbolizer") or next(iter(sorted(glob.glob("/usr/bin/llvm-symbolizer-*"), reverse=True)), None)
    if sym is None:
        sys.exit("cpuprof: no llvm-symbolizer on PATH")
    lines = [line for line in open(path) if line.strip()]
    taken = next((int(x.split()[2]) for x in lines if x.startswith("# taken ")), None)
    samples = [line.split() for line in lines if not line.startswith("#")]
    addrs = collections.defaultdict(set)
    for s in samples:
        for f in s:
            if ":" in f:
                obj, a = f.rsplit(":", 1)
                addrs[obj].add(a)
    name = {}
    for obj, aa in addrs.items():
        for a, frames in symbolize(sym, obj, sorted(aa), inlines).items():
            name[(obj, a)] = frames
    stacks = [[fr for f in s for fr in name.get(tuple(f.rsplit(":", 1)), [("??", "")])] for s in samples]
    if under:
        stacks = [fns[:i + 1] for fns in stacks if (i := outermost(fns, under)) is not None]
    if taken and taken > len(samples):
        print(f"TRUNCATED: the first {len(samples)} of {taken} samples taken, so only the run's start: rerun with "
              f"CPUPROF_INSTR about {taken / len(samples):.1f}x larger")
    for filt in filters or [None]:
        incl, own, by, total = collections.Counter(), collections.Counter(), collections.Counter(), 0
        for fns in stacks:
            if filt and not any(filt in f for f, _ in fns):
                continue
            total += 1
            if fns:
                own[f"{fns[0][0]} ({fns[0][1]})" if inlines else fns[0][0]] += 1
            incl.update({f for f, _ in fns})
            if callers and (i := outermost(fns, callers)) is not None:
                by[fns[i + 1][0] if i + 1 < len(fns) else "(root)"] += 1
        what = "".join(f" [{x}]" for x in (filt, under and f"under {under}") if x)
        print(f"{path}{what}: {total} samples of {len(samples)}")
        print("--- inclusive")
        for f, c in incl.most_common(n):
            print(f"{100 * c / max(total, 1):5.1f}% {f[:160]}")
        print("--- self" + (" (innermost source line)" if inlines else ""))
        for f, c in own.most_common(n // 2):
            print(f"{100 * c / max(total, 1):5.1f}% {f[:200]}")
        if callers:
            print(f"--- callers of {callers} ({sum(by.values())} samples)")
            for f, c in by.most_common(n):
                print(f"{100 * c / max(total, 1):5.1f}% {f[:160]}")


if __name__ == "__main__":
    main(sys.argv[1:])
