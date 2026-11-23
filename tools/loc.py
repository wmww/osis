#!/usr/bin/env python3
"""Rust lines of code per crate, split into implementation and test.

Counts non-blank, non-comment lines (doc comments count as comments).
Test code: files under tests/, benches/ or fuzz_targets/; items marked
#[test] or #[cfg(...)] whose predicate needs `test` (e.g. any(test, fuzzing));
whole modules pulled in by a test-gated `mod x;`; and whole crates that are
test infrastructure (models, vectors, sim, fuzz, benches: TEST_CRATES).
Sections, each with its total: core (core/), auxiliary (the rest), gui (GUI_CRATES).

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
TEST_CRATES = ("core/test/", "core/bench/")
GUI_CRATES = ("libs/kit", "app", "app/android")
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
BOLD, GRAY, NAME, IMPL, TEST = "1", "90", "34", "1;36", "1;32"


def paint(text, *codes):
    return f"\033[{';'.join(codes)}m{text}\033[0m" if COLOR and codes and text else text
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
        whole = (whole or rel[0] in TEST_DIRS or (c + "/").startswith(TEST_CRATES)
                 or any(f == p or f.startswith(p) for p in test_prefixes))
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
        print(paint(f"{'impl':>7} {'test':>7}  file", BOLD))
        for i, t, f in rows:
            print(f"{i:>7,} {t:>7,}  {f}")
        return

    rows = sorted(((v[0], v[1], d) for d, v in totals.items()), key=lambda r: (-r[0], -r[1]))
    # paths split at the last "/": heads right-aligned, so the crate names line up
    hw = max(len(r[2].rpartition("/")[0]) + 1 for r in rows if "/" in r[2])
    w = max([hw + len(r[2].rpartition("/")[2]) for r in rows] + [len("auxiliary total")]) + 2

    def group(d):
        return "gui" if d in GUI_CRATES else "core" if d.startswith("core/") else "auxiliary"

    def row(d, i, t):
        head, _, last = d.rpartition("/")
        name = paint(f"{head + '/' if head else '':>{hw}}", GRAY) + paint(last, NAME)
        print(f"{name}{' ' * (w - hw - len(last))} {i:>7,} {t:>7,}")

    def total(label, sub):
        i, t = sum(r[0] for r in sub), sum(r[1] for r in sub)
        print(f"{paint(f'{label:<{w}}', NAME)} {paint(f'{i:>7,}', IMPL)} {paint(f'{t:>7,}', TEST)}")

    print(paint(f"{'path':<{w}} {'impl':>7} {'test':>7}", BOLD))
    for g in ("core", "auxiliary", "gui"):
        sub = [r for r in rows if group(r[2]) == g]
        for i, t, d in sub:
            row(d, i, t)
        total(f"{g} total", sub)
        print()
    total("total", rows)


if __name__ == "__main__":
    main()
