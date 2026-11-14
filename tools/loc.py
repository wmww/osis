#!/usr/bin/env python3
"""Rust lines of code per crate, split into implementation and test.

Counts non-blank, non-comment lines (doc comments count as comments).
Test code: files under tests/, benches/ or fuzz_targets/; items marked
#[test] or #[cfg(...)] whose predicate needs `test` (e.g. any(test, fuzzing));
and whole modules pulled in by a test-gated `mod x;`.

Usage: tools/loc.py [--all] [--files CRATE]
  --all          include vendored crates (libs/kit/patches)
  --files CRATE  per-file breakdown for one crate (name or path)
"""
import bisect
import os
import re
import subprocess
import sys

from rustsrc import mod_paths, sanitize, toml

VENDORED = ("libs/kit/patches/",)
TEST_DIRS = ("tests", "benches", "fuzz_targets")
ITEM_KW = {"fn", "mod", "impl", "struct", "enum", "trait", "union", "macro_rules"}
QUALIFIERS = {"pub", "async", "unsafe", "const", "extern", "default", "safe"}


def match_close(s, i):
    """s[i] is an opening bracket; return index of its match."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[s[i]]]
    j = i + 1
    while j < len(s) and stack:
        ch = s[j]
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            stack.pop()
        j += 1
    return j - 1


def is_test_attr(body):
    body = re.sub(r"\s+", "", body)
    if body == "test" or body.endswith("::test"):
        return True
    m = re.fullmatch(r"cfg\((.*)\)", body)
    return bool(m and re.search(r"\btest\b", m.group(1)) and "not(" not in m.group(1))


def skip_ws_attrs(s, i):
    while True:
        while i < len(s) and s[i].isspace():
            i += 1
        if s.startswith("#[", i) or s.startswith("#![", i):
            i = match_close(s, s.index("[", i)) + 1
        else:
            return i


def item_end(s, i):
    """End index (exclusive) of the item/statement/field starting at i."""
    words = re.findall(r"[A-Za-z_]\w*|\S", s[i:i + 200])
    k = 0
    while k < len(words) and (words[k] in QUALIFIERS or words[k] in ("(", ")", "crate", "super", "self", "in")
                              or words[k].startswith('"') or words[k] == "x"):
        k += 1
    first = words[k] if k < len(words) else ""
    block_item = first in ITEM_KW or first == "{" or (first.isidentifier() and k + 1 < len(words) and words[k + 1] == "!")
    depth, j = 0, i
    while j < len(s):
        ch = s[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return j
            if depth == 0 and ch == "}" and block_item:
                return j + 1
        elif depth == 0 and ch in ";,":
            return j + 1
        j += 1
    return j


def mod_decl(s, i):
    m = re.match(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", s[i:])
    return m.group(1) if m else None


def analyze(path):
    """Return (code line numbers, test line numbers, test-gated mod names, whole-file-test)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        s = sanitize(f.read())
    lines = s.split("\n")
    code = {k for k, line in enumerate(lines) if line.strip()}
    line_starts = [0]
    for line in lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    def line_of(pos):
        return bisect.bisect_right(line_starts, pos) - 1

    test, mods, whole = set(), [], False
    for m in re.finditer(r"#(!?)\[", s):
        close = match_close(s, m.end() - 1)
        if not is_test_attr(s[m.end():close]):
            continue
        if m.group(1):  # inner attribute: whole file
            whole = True
            continue
        start = skip_ws_attrs(s, close + 1)
        name = mod_decl(s, start)
        if name:
            mods.append(name)
        end = item_end(s, start)
        test.update(range(line_of(m.start()), line_of(max(end - 1, start)) + 1))
    return code, test, mods, whole


def main():
    args = sys.argv[1:]
    include_all = "--all" in args
    only = args[args.index("--files") + 1] if "--files" in args else None
    root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    os.chdir(root)
    files = subprocess.check_output(["git", "ls-files", "*.rs", "*Cargo.toml"], text=True).split()
    if not include_all:
        files = [f for f in files if not f.startswith(VENDORED)]

    crates = {}  # dir -> name
    for f in files:
        if os.path.basename(f) == "Cargo.toml":
            name = toml(f).get("package", {}).get("name")
            if name:
                crates[os.path.dirname(f)] = name
    rs = [f for f in files if f.endswith(".rs")]

    info = {f: analyze(f) for f in rs}
    test_prefixes = []
    for f, (_, _, mods, _) in info.items():
        for name in mods:
            test_prefixes += mod_paths(f, name)

    def crate_of(f):
        d = os.path.dirname(f)
        while d and d not in crates:
            d = os.path.dirname(d)
        return d if d in crates else None

    totals, per_file = {}, {}
    for f in rs:
        c = crate_of(f)
        if c is None:
            continue
        code, test, _, whole = info[f]
        rel = os.path.relpath(f, c).split(os.sep)
        whole = (whole or rel[0] in TEST_DIRS or any(f == p or f.startswith(p) for p in test_prefixes))
        t = len(code) if whole else len(code & test)
        i = len(code) - t
        a = totals.setdefault(c, [0, 0])
        a[0] += i
        a[1] += t
        per_file.setdefault(c, []).append((i, t, f))

    if only:
        c = next((d for d, n in crates.items() if only in (n, d, d.rstrip("/"))), None)
        if c is None:
            sys.exit(f"no crate {only!r}")
        rows = sorted(per_file.get(c, []), key=lambda r: (-r[0], -r[1]))
        print(f"{'impl':>7} {'test':>7}  file")
        for i, t, f in rows:
            print(f"{i:>7,} {t:>7,}  {f}")
        return

    rows = sorted(((v[0], v[1], crates[d], d) for d, v in totals.items()), key=lambda r: (-r[0], -r[1]))
    w = max(len(r[2]) for r in rows)
    print(f"{'crate':<{w}} {'impl':>7} {'test':>7}  path")
    for i, t, name, d in rows:
        print(f"{name:<{w}} {i:>7,} {t:>7,}  {d}")
    ti = sum(r[0] for r in rows)
    tt = sum(r[1] for r in rows)
    print(f"{'total':<{w}} {ti:>7,} {tt:>7,}")


if __name__ == "__main__":
    main()
