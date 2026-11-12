#!/usr/bin/env python3
"""Dead `pub` items (notes/testing.md, Policy checks): rustc's dead-code lint stops at `pub`, so an
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
import glob, os, re, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOW = os.path.join(ROOT, "tools/dead_pub_allow.txt")

IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
DEF = re.compile(r"\bpub\s+(?:const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*(fn|const|static|struct|enum|type|trait|union)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)")
TEST_CFG = re.compile(r"#\[cfg\((test|doctest|any\(test,\s*fuzzing\))\)\]")
USE = re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?use\s+[^;]*;")
IMPL = re.compile(r"\bimpl\b[^{;]*\{")

def blank(text):
    """Comments, strings and char literals replaced by spaces (offsets and newlines kept)."""
    out, i, n = [], 0, len(text)
    pat = re.compile(r"//[^\n]*|/\*|r(#*)\"|b?\"|b?'(?:\\.|[^\\'\n])'")
    while i < n:
        m = pat.search(text, i)
        if not m:
            out.append(text[i:])
            break
        out.append(text[i:m.start()])
        s, tok = m.start(), m.group(0)
        if tok.startswith("//"):
            e = m.end()
        elif tok == "/*":
            depth, e = 1, m.end()
            while depth and e < n:
                if text.startswith("/*", e):
                    depth, e = depth + 1, e + 2
                elif text.startswith("*/", e):
                    depth, e = depth - 1, e + 2
                else:
                    e += 1
        elif tok.startswith("r") and tok.endswith('"'):
            end = text.find('"' + m.group(1), m.end())
            e = n if end < 0 else end + 1 + len(m.group(1))
        elif tok.endswith('"'):
            e = m.end()
            while e < n and text[e] != '"':
                e += 2 if text[e] == "\\" else 1
            e += 1
        else:
            e = m.end()
        out.append(re.sub(r"[^\n]", " ", text[s:e]))
        i = e
    return "".join(out)

def item_end(text, i):
    """End of the item starting at `i` (after its attributes): its `;` or its matching `}`."""
    while True:
        m = re.match(r"\s*#\[", text[i:])
        if not m:
            break
        i, depth = i + m.end(), 1
        while depth and i < len(text):
            depth += {"[": 1, "]": -1}.get(text[i], 0)
            i += 1
    j = i
    while j < len(text) and text[j] not in ";{":
        j += 1
    if j >= len(text) or text[j] == ";":
        return i, j + 1
    depth = 0
    while j < len(text):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        j += 1
        if depth == 0:
            break
    return i, j

def module_files(src, name):
    d = os.path.dirname(src)
    if os.path.basename(src) not in ("lib.rs", "mod.rs", "main.rs"):
        d = os.path.join(d, os.path.splitext(os.path.basename(src))[0])
    return [os.path.join(d, name + ".rs"), os.path.join(d, name)]

class File:
    def __init__(self, path, crate, test):
        self.path, self.crate = path, crate
        self.text = blank(open(path, errors="replace").read())
        self.test_all = test
        self.test_spans, self.child_tests = [], []
        if not test:
            for m in TEST_CFG.finditer(self.text):
                start, end = item_end(self.text, m.end())
                self.test_spans.append((m.start(), end))
                mm = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;", self.text[start:end])
                if mm:
                    self.child_tests += module_files(path, mm.group(1))
        self.use_spans = [m.span() for m in USE.finditer(self.text)]
        self.impl_spans = [m.span() for m in IMPL.finditer(self.text)]

    def in_test(self, pos):
        return self.test_all or any(a <= pos < b for a, b in self.test_spans)

def inside(spans, pos):
    return any(a <= pos < b for a, b in spans)

def members():
    ws = tomllib.load(open(os.path.join(ROOT, "Cargo.toml"), "rb"))
    out = {}
    # core/test/fuzz is outside the workspace (cargo-fuzz), its targets still users
    for pat in ws["workspace"]["members"] + ["core/test/*"]:
        for m in glob.glob(os.path.join(ROOT, pat)):
            man = os.path.join(m, "Cargo.toml")
            if os.path.isfile(man):
                out[os.path.normpath(m)] = tomllib.load(open(man, "rb"))["package"]["name"]
    return out

def scan():
    crates = members()
    files = []
    for m, name in sorted(crates.items()):
        paths = []
        for p in glob.glob(os.path.join(m, "**/*.rs"), recursive=True):
            r = os.path.relpath(p, m)
            if r.startswith(("target/", "patches/")):
                continue
            # a member nested in this one (app/android in app) is its own crate
            if any(o != m and p.startswith(o + os.sep) and o.startswith(m + os.sep) for o in crates):
                continue
            paths.append(p)
        test_mods = set()
        built = []
        for p in sorted(paths, key=lambda p: (p.count(os.sep), os.path.basename(p) not in ("lib.rs", "mod.rs", "main.rs"))):
            r = os.path.relpath(p, m)
            test = r.startswith(("tests/", "benches/", "examples/")) or any(p == t or p.startswith(t + os.sep) or p == t + ".rs" for t in test_mods)
            f = File(p, name, test)
            for c in f.child_tests:
                test_mods.add(c[:-3] if c.endswith(".rs") else c)
            built.append(f)
        files += built
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
        for m in IDENT.finditer(f.text):
            n = m.group(0)
            if n not in by_name:
                continue
            pos = m.start()
            for crate in by_name[n]:
                if (crate, n) in live:
                    continue
                kind, df, dpos = defs[(crate, n)]
                if df is f and dpos == pos:
                    continue
                if f.crate != crate:
                    live.add((crate, n))
                    continue
                if f.in_test(pos):
                    continue
                if kind != "trait" and inside(f.use_spans, pos):
                    continue
                if kind in ("struct", "enum", "type", "union") and inside(f.impl_spans, pos):
                    continue
                live.add((crate, n))
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
