#!/usr/bin/env python3
"""memprof_report.py A [B] [--per N] [--top K] [--stacks]: what a tools/memprof dump holds live, by
owner: the innermost osis frame past the allocator and collections, or for a memo
(`osis_base::memo`) its table type and the memo method allocating. With B, each owner's bytes
in B less A, divided by N (`--per`): what each unit of work added between two runs (a test at n
and at 10n, N = 9n). `--stacks`: also the K largest stacks, osis frames only."""
import collections
import glob
import re
import shutil
import subprocess
import sys

SKIP = ("hashbrown", "alloc::", "core::", "std::", "costs::scoped", "__rust", "<alloc", "<core", "<std", "malloc", "calloc", "realloc")
MEMO = re.compile(r"osis_base::memo::(?:effects::|cutoff::)?(Effects|Memo|Cutoff|Stamped|StampedSet)<")
SHORT = ("osis_base::ids::", "osis_engine::sync::", "alloc::sync::", "alloc::collections::btree::map::", "alloc::vec::", "core::option::")


def symbolize(sym, obj, addrs):
    r = subprocess.run([sym, "--obj=" + obj, "--functions=linkage", "--no-inlines", "--demangle"],
                       input="\n".join("0x" + a for a in addrs), capture_output=True, text=True)
    out = {}
    for a, block in zip(addrs, r.stdout.strip().split("\n\n")):
        ls = block.split("\n")
        out[a] = (re.sub(r"::h[0-9a-f]{16}$", "", ls[0]), ls[1].rsplit("/", 1)[-1] if len(ls) > 1 else "")
    return out


def load(path, sym):
    lines = [x.split() for x in open(path) if x.strip()]
    head = next((x for x in lines if x[0] == "#"), [])
    rows = [(int(x[0]), int(x[1]), x[2:]) for x in lines if x[0] != "#"]
    addrs = collections.defaultdict(set)
    for _, _, fr in rows:
        for f in fr:
            obj, a = f.rsplit(":", 1)
            addrs[obj].add(a)
    name = {}
    for obj, aa in addrs.items():
        for a, v in symbolize(sym, obj, sorted(aa)).items():
            name[(obj, a)] = v
    return head, [(b, n, [name.get(tuple(f.rsplit(":", 1)), ("??", "")) for f in fr]) for b, n, fr in rows]


def short(s):
    for x in SHORT:
        s = s.replace(x, "")
    return s


def owner(frames):
    method = ""
    for fn, loc in frames:
        if fn.startswith(SKIP) or any(s in fn for s in ("hashbrown", "costs::scoped")):
            continue
        m = MEMO.search(fn)
        if m and "{closure" not in fn.split(">>::")[-1]:
            t = fn[m.start():]
            end = t.find(">>::")
            return short(t[:end + 2] if end >= 0 else t[:200]) + "::" + (method or t.rsplit(">>::", 1)[-1].split("::<")[0])
        if "osis_base::memo::" in fn:
            method = method or fn.rsplit("::", 1)[-1]
            continue
        if "osis" in fn and "cbor" not in fn:
            return f"{fn[:160]} @ {loc}"
    return frames[0][0] if frames else "?"


def main(argv):
    per, top, stacks, pos = 1, 50, False, []
    it = iter(argv)
    for a in it:
        if a == "--per":
            per = int(next(it))
        elif a == "--top":
            top = int(next(it))
        elif a == "--stacks":
            stacks = True
        else:
            pos.append(a)
    if not pos:
        sys.exit(__doc__)
    sym = shutil.which("llvm-symbolizer") or next(iter(sorted(glob.glob("/usr/bin/llvm-symbolizer-*"), reverse=True)), None)
    if sym is None:
        sys.exit("memprof: no llvm-symbolizer on PATH")
    dumps = [load(p, sym) for p in pos[:2]]
    by = []
    for head, rows in dumps:
        c = collections.Counter()
        for b, _, fr in rows:
            c[owner(fr)] += b
        by.append(c)
        print(f"{' '.join(head)}: {sum(c.values()) / 1024:.0f} KB live in {len(rows)} stacks")
    if len(by) == 2:
        a, b = by
        d = {k: (b[k] - a[k]) / per for k in set(a) | set(b)}
        print(f"B less A, per {per}: {sum(d.values()):.0f} B")
        for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:top]:
            print(f"{v:>9.0f} {k}")
    else:
        for k, v in by[0].most_common(top):
            print(f"{v:>9} {k}")
    if stacks:
        rows = sorted(dumps[-1][1], key=lambda r: -r[0])[:top]
        for b, n, fr in rows:
            print(f"{b:>9} B in {n}")
            for fn, loc in [f for f in fr if "osis" in f[0]][:14]:
                print(f"            {fn[:180]} @ {loc}")


if __name__ == "__main__":
    main(sys.argv[1:])
