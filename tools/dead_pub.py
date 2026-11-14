#!/usr/bin/env python3
"""Dead `pub` items (notes/gate.md, Policy checks): rustc's dead-code lint stops at `pub`, so an
item whose only callers are its own crate's tests lives on. Lists every `pub` fn, method, const,
static and type defined outside test code in a core crate (core/*, not core/test or core/bench) whose name
appears nowhere but its definition, its own crate's tests (`tests/`, `benches/`, `#[cfg(test)]` and
`#[cfg(any(test, fuzzing))]` items and the files they include), `use` lines, and (for a type)
`impl` headers. A use in any other workspace crate, its tests included, counts as live.
A text scan by name, so a name shared with anything used elsewhere reads as live (misses, never
false alarms beyond macros building names). tools/dead_pub_allow.txt lists the hits kept on
purpose: `<crate>::<name>  <reason>`; a reason starting `deferred:` marks one left for a branch
in that area. Every entry must still be a hit.
Usage: python3 tools/dead_pub.py   (exit 1 on any unlisted hit or stale entry; policy.py runs it)"""
import functools, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import ROOT, members, mod_paths, read, rs_files, sanitize

ALLOW = os.path.join(ROOT, "tools/dead_pub_allow.txt")

IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
# a `\b` before a literal is a lookbehind after it: sre scans fast for a pattern that starts with one
DEF = re.compile(r"pub(?<!\wpub)\s+(?:const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*(fn|const|static|struct|enum|type|trait|union)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)")
TEST_CFG = re.compile(r"#\[cfg\((test|doctest|any\(test,\s*fuzzing\))\)\]")
USE = re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]*;")
IMPL = re.compile(r"impl(?<!\wimpl)\b[^{;]*\{")

ATTR = re.compile(r"\s*#\[")
BRACKET = re.compile(r"[\[\]]")
BRACE = re.compile(r"[{}]")
HEAD_END = re.compile(r"[;{]")

def item_end(text, i):
    """End of the item starting at `i` (after its attributes): its `;` or its matching `}`."""
    while (m := ATTR.match(text, i)):
        i, depth = m.end(), 1
        for b in BRACKET.finditer(text, i):
            depth += 1 if b.group() == "[" else -1
            if not depth:
                i = b.end()
                break
        else:
            i = len(text)
    h = HEAD_END.search(text, i)
    if not h or h.group() == ";":
        return i, (h.end() if h else len(text) + 1)
    depth = 0
    for b in BRACE.finditer(text, h.start()):
        depth += 1 if b.group() == "{" else -1
        if not depth:
            return i, b.end()
    return i, len(text)

class File:
    def __init__(self, path, crate, test):
        self.path, self.crate = path, crate
        self.text = sanitize(read(path), " ")
        self.test_all = test
        self.test_spans, self.child_tests = [], []
        if not test:
            for m in TEST_CFG.finditer(self.text):
                start, end = item_end(self.text, m.end())
                self.test_spans.append((m.start(), end))
                mm = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;", self.text[start:end])
                if mm:
                    self.child_tests += mod_paths(path, mm.group(1))

    @functools.cached_property
    def use_spans(self):
        return [m.span() for m in USE.finditer(self.text)]

    @functools.cached_property
    def impl_spans(self):
        return [m.span() for m in IMPL.finditer(self.text)]

    def in_test(self, pos):
        return self.test_all or any(a <= pos < b for a, b in self.test_spans)

def inside(spans, pos):
    return any(a <= pos < b for a, b in spans)

def occurrences(text, n):
    """Where identifier `n` stands in `text` as a whole word."""
    i = text.find(n)
    while i >= 0:
        j = i + len(n)
        if not (i and (text[i - 1].isalnum() or text[i - 1] == "_")) and not (j < len(text) and (text[j].isalnum() or text[j] == "_")):
            yield i
        i = text.find(n, i + 1)

def scan():
    # core/test/fuzz is outside the workspace (cargo-fuzz), its targets still users
    crates = members(["core/test/*"])
    files = []
    for m, name in sorted(crates.items()):
        test_mods = set()
        for p in sorted(rs_files(m, crates), key=lambda p: (p.count(os.sep), os.path.basename(p) not in ("lib.rs", "mod.rs", "main.rs"))):
            r = os.path.relpath(p, m)
            test = r.startswith(("tests/", "benches/", "examples/")) or any(p.startswith(t) for t in test_mods)
            f = File(p, name, test)
            test_mods.update(f.child_tests)
            files.append(f)
    return crates, files

def hits():
    crates, files = scan()
    # core/bench is measurement code like core/test: its items exist for its own benches and tests
    core = {n for m, n in crates.items() if os.path.relpath(m, ROOT).startswith("core/") and not os.path.relpath(m, ROOT).startswith(("core/test/", "core/bench"))}
    defs = {}  # (crate, name) -> (kind, file, pos)
    for f in files:
        rel = os.path.relpath(f.path, ROOT)
        if f.crate not in core or f.test_all or "/src/" not in "/" + rel or "/src/bin/" in rel or rel.endswith("/src/main.rs"):
            continue
        for m in DEF.finditer(f.text):
            if f.in_test(m.start()):
                continue
            defs.setdefault((f.crate, m.group(2)), (m.group(1), f, m.start(2)))
    by_name = {}
    for crate, n in defs:
        by_name.setdefault(n, []).append(crate)
    live = set()  # (crate, name) used live
    for f in files:
        for n in set(IDENT.findall(f.text)) & by_name.keys():
            for crate in by_name[n]:
                if (crate, n) in live:
                    continue
                if f.crate != crate:
                    live.add((crate, n))
                    continue
                kind, df, dpos = defs[(crate, n)]
                for pos in occurrences(f.text, n):
                    if (df is f and dpos == pos) or f.in_test(pos):
                        continue
                    if kind != "trait" and inside(f.use_spans, pos):
                        continue
                    if kind in ("struct", "enum", "type", "union") and inside(f.impl_spans, pos):
                        continue
                    live.add((crate, n))
                    break
    out = []
    for (crate, n), (kind, f, pos) in sorted(defs.items()):
        if (crate, n) not in live:
            line = f.text.count("\n", 0, pos) + 1
            out.append((f"{crate}::{n}", f"{os.path.relpath(f.path, ROOT)}:{line}", kind))
    return out

def allowlist():
    entries, bad = {}, []
    for i, line in enumerate(open(ALLOW), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, reason = line.partition(" ")
        if not reason.strip():
            bad.append(f"tools/dead_pub_allow.txt:{i}: `{key}` has no reason")
        entries[key] = reason.strip()
    return entries, bad

def check():
    """Violations: unlisted hits and stale allowlist entries."""
    found = hits()
    entries, bad = allowlist()
    keys = {k for k, _, _ in found}
    for key, where, kind in found:
        if key not in entries:
            bad.append(f"{where}: pub {kind} {key} is used only by its own crate's tests, or not at all (remove it, or list it in tools/dead_pub_allow.txt with a reason)")
    for key in sorted(set(entries) - keys):
        bad.append(f"tools/dead_pub_allow.txt: {key} is no longer dead (drop its line)")
    return bad

if __name__ == "__main__":
    if sys.argv[1:] == ["--all"]:
        entries, _ = allowlist()
        for key, where, kind in hits():
            print(f"{where}: {kind} {key}{'  [' + entries[key] + ']' if key in entries else ''}")
        sys.exit(0)
    bad = check()
    for b in bad:
        print(b)
    sys.exit(1 if bad else 0)
