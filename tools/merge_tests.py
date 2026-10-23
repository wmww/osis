#!/usr/bin/env python3
"""Consolidate each crate's integration tests into one test binary (notes/testing.md, Tiers).

Every crate whose tests/ holds more than one top-level .rs file gets tests/it/main.rs declaring
each former file as a module; the files, their proptest regression files and the shared helper
directories (tests/<dir>/mod.rs) move under tests/it/ with `git mv`. In each moved file `mod
common;` becomes `use crate::common;`, a leading `#![cfg(...)]` moves onto its `mod` line, and
relative include!/include_str! paths gain a `../`. Then, in sources, notes/ and issues/, `--test
<file> [name]` becomes `--test it <file>::[name]` and `[<crate dir>/]tests/<file>.rs` becomes
`.../tests/it/<file>.rs` (a bare path only when no unconsolidated crate has that file). Re-running is harmless: a crate with
tests/it/ is skipped, and rewritten `--test it` invocations no longer match.

Usage (repo root): python3 tools/merge_tests.py"""
import glob, os, re, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOPS = ["crates/*", "sim", "vectors", "models/*"]
CFG = re.compile(r"^#!\[(cfg\(.*\))\]\s*$")
MOD = re.compile(r"^(\s*)(?:pub\s+)?mod (\w+);\s*$")
INCLUDE = re.compile(r'(include(?:_str|_bytes)?!\(\s*")(?!/)([^"]+)"')


def git_mv(src, dst):
    subprocess.run(["git", "mv", src, dst], cwd=ROOT, check=True)


def consolidate(crate):
    tests = os.path.join(ROOT, crate, "tests")
    files = sorted(glob.glob(os.path.join(tests, "*.rs")))
    if len(files) < 2 or os.path.exists(os.path.join(tests, "it")):
        return None
    helpers = sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob(os.path.join(tests, "*/mod.rs")))
    it = os.path.join(tests, "it")
    os.makedirs(it)
    mods = []
    for path in files:
        name = os.path.basename(path)[:-3]
        lines = open(path).read().split("\n")
        cfg, out = None, []
        for line in lines:
            m = CFG.match(line)
            if m and cfg is None and all(not l.strip() or l.startswith(("//", "#!")) for l in out):
                cfg = m.group(1)
                continue
            m = MOD.match(line)
            if m and m.group(2) in helpers:
                line = f"{m.group(1)}use crate::{m.group(2)};"
            line = INCLUDE.sub(lambda m: f'{m.group(1)}../{m.group(2)}"', line)
            out.append(line)
        git_mv(path, os.path.join(it, os.path.basename(path)))
        open(os.path.join(it, os.path.basename(path)), "w").write("\n".join(out))
        reg = path[:-3] + ".proptest-regressions"
        if os.path.exists(reg):
            git_mv(reg, os.path.join(it, os.path.basename(reg)))
        mods.append((name, cfg))
    for h in helpers:
        git_mv(os.path.join(tests, h), os.path.join(it, h))
    pkg = re.search(r'^name\s*=\s*"([^"]+)"', open(os.path.join(ROOT, crate, "Cargo.toml")).read(), re.M).group(1)
    main = [f"//! {pkg} integration tests: one binary, one module per area (notes/testing.md, Tiers).",
            "#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]", ""]
    main += [f"mod {h};" for h in helpers]
    main += [(f"#[{c}]\n" if c else "") + f"mod {n};" for n, c in mods]
    open(os.path.join(it, "main.rs"), "w").write("\n".join(main) + "\n")
    return pkg, [n for n, _ in mods]


# `-p <pkg> ... --test <mod> [name]` within one line, `--test` not yet `it`.
TEST_ARG = re.compile(r"-p ([\w-]+)([^`\n]*?) --test (?!it\b)(\w+)(?: ((?!-)[\w:]+))?")


def rewrite_invocations(moved):
    paths = glob.glob(os.path.join(ROOT, "notes/*.md")) + glob.glob(os.path.join(ROOT, "issues/*.md"))
    for top in TOPS:
        paths += glob.glob(os.path.join(ROOT, top, "**/*.rs"), recursive=True)

    def sub(m):
        pkg, mid, mod, name = m.groups()
        if mod not in moved.get(pkg, ()):
            return m.group(0)
        return f"-p {pkg}{mid} --test it {mod}::{name or ''}"

    for path in paths:
        if "/target/" in path:
            continue
        text = open(path).read()
        new = TEST_ARG.sub(sub, text)
        if new != text:
            open(path, "w").write(new)


# `[<dir>/]tests/<file>.rs`: rewritten when <dir> (or, bare, only consolidated crates) has that module.
TEST_PATH = re.compile(r"\b((?:[\w-]+/)*)tests/(\w+)\.rs\b")


def rewrite_paths(by_dir):
    single = {os.path.basename(p)[:-3] for top in TOPS for p in glob.glob(os.path.join(ROOT, top, "tests/*.rs"))}
    bare = set().union(*by_dir.values()) - single

    def sub(m):
        prefix, mod = m.groups()
        ok = mod in by_dir.get(prefix.rstrip("/").split("/")[-1], ()) if prefix else mod in bare
        return f"{prefix}tests/it/{mod}.rs" if ok else m.group(0)

    paths = [p for p in glob.glob(os.path.join(ROOT, "notes/*.md")) if not p.endswith("testing-map.md")]
    paths += glob.glob(os.path.join(ROOT, "issues/*.md"))
    for top in TOPS:
        paths += glob.glob(os.path.join(ROOT, top, "**/*.rs"), recursive=True)
    for path in paths:
        if "/target/" in path:
            continue
        text = open(path).read()
        new = TEST_PATH.sub(sub, text)
        if new != text:
            open(path, "w").write(new)


def main():
    moved = {}
    for top in TOPS:
        for crate in sorted(glob.glob(os.path.join(ROOT, top))):
            if os.path.exists(os.path.join(crate, "Cargo.toml")):
                r = consolidate(os.path.relpath(crate, ROOT))
                if r:
                    moved[r[0]] = r[1]
                    print(f"{r[0]}: {len(r[1])} files -> tests/it")
    # Crates consolidated by an earlier run still get their invocations rewritten.
    for main_rs in glob.glob(os.path.join(ROOT, "**/tests/it/main.rs"), recursive=True):
        crate = os.path.dirname(os.path.dirname(os.path.dirname(main_rs)))
        pkg = re.search(r'^name\s*=\s*"([^"]+)"', open(os.path.join(crate, "Cargo.toml")).read(), re.M).group(1)
        moved.setdefault(pkg, re.findall(r"^mod (\w+);", open(main_rs).read(), re.M))
    rewrite_invocations(moved)
    by_dir = {}
    for main_rs in glob.glob(os.path.join(ROOT, "**/tests/it/main.rs"), recursive=True):
        d = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(main_rs))))
        by_dir[d] = re.findall(r"^mod (\w+);", open(main_rs).read(), re.M)
    rewrite_paths(by_dir)


main()
