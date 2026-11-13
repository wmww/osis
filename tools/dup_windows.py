#!/usr/bin/env python3
"""Find repeated code: every window of N consecutive non-trivial lines seen more than once.

  tools/dup_windows.py [--lines N] [--top K] PATH...   (.rs files under each PATH; N defaults to 4)

A cleanup's first targets (notes/coordination.md, Standing agents): tools/dead_pub.py finds names
nobody calls, this finds copies, which is where most cleanups found their volume. Lines are
compared stripped of whitespace; blank lines, comments and lone braces are skipped. Overlapping
windows of one copy are merged into a run; runs are listed longest first with each place they occur.
"""
import argparse, os, re, sys
from collections import defaultdict

TRIVIAL = re.compile(r"^(//.*|[{}()\[\];,]*|\}\s*else\s*\{|#\[.*\])$")


def lines_of(path):
    out = []
    for n, raw in enumerate(open(path, errors="replace"), 1):
        s = re.sub(r"\s+", " ", raw.strip())
        if s and not TRIVIAL.match(s):
            out.append((n, s))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=4)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    files = []
    for p in a.paths:
        if os.path.isfile(p):
            files.append(p)
        for d, dirs, fs in os.walk(p):
            dirs[:] = [x for x in dirs if x not in ("target", "patches")]
            files += [os.path.join(d, f) for f in fs if f.endswith(".rs")]
    seen = defaultdict(list)  # window text -> [(file, index into its lines)]
    content = {}
    for f in files:
        ls = content[f] = lines_of(f)
        for i in range(len(ls) - a.lines + 1):
            seen["\n".join(s for _, s in ls[i:i + a.lines])].append((f, i))
    # a window repeated at (f, i) extends a run starting at (f, i - 1) when that one repeated too
    dup = {(f, i) for places in seen.values() if len(places) > 1 for f, i in places}
    runs = []
    for f, i in sorted(dup):
        if (f, i - 1) in dup:
            continue
        j = i
        while (f, j + 1) in dup:
            j += 1
        ls = content[f]
        key = "\n".join(s for _, s in ls[i:i + a.lines])
        runs.append((j - i + a.lines, f, ls[i][0], ls[j + a.lines - 1][0], key))
    groups = defaultdict(list)
    for length, f, start, end, key in runs:
        groups[key].append((length, f, start, end))
    ranked = sorted(groups.values(), key=lambda g: -max(x[0] for x in g) * len(g))
    for g in ranked[:a.top]:
        print(f"{max(x[0] for x in g)} lines x {len(g)}: " + ", ".join(f"{f}:{s}-{e}" for _, f, s, e in g))
    return 0


if __name__ == "__main__":
    sys.exit(main())
