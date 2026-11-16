#!/usr/bin/env python3
"""The cleanup's `#[deprecated]` probe (notes/coordination.md, Cleanup): mark every `pub` item and
field in CRATE's src/ `#[deprecated]`, run one `cargo clippy --all-targets --message-format=short`
(with --gui also one `-p osis-kit -p osis-app -p osis-android`), and list per item its use sites
outside CRATE's own src/: the items nobody uses, then those only tests use (under tests/, benches/
or core/test/, a `tests*.rs`, a file declared `#[cfg(test)] mod x;`, or below a
`#[cfg(test)] mod x {`). The tree is restored afterwards, always; a probe killed hard leaves its
backup in target/deprecated-probe/, which the next run restores first.
A use is matched to its item by name and owner (the impl's type, the field's struct), so two `new`s
of different types stay apart; rustc names a free item by its visible path, so a module owner
matches the name in any module. A variant or tuple-field use counts for its type. Not marked:
`pub use`, `pub mod`, tuple fields, trait impls, anything inside a header not plain `pub`.
Usage: tools/deprecated_probe.py [--gui] [-v] CRATE   (a package name, e.g. osis-blob; -v also lists
every used item with its sites)"""
import argparse, collections, os, re, shutil, signal, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import ROOT, members

BACKUP = os.path.join(ROOT, "target", "deprecated-probe")
ITEM = re.compile(r"^(\s*)pub (?:(?:const|async|unsafe) )*(fn|struct|enum|trait|type|const|static|union) (\w+)")
FIELD = re.compile(r"^(\s*)pub (\w+)\s*:")
OWNER = re.compile(r"^\s*(?:pub(?:\([\w:]+\))? )?(?:unsafe )?(impl|struct|enum|union|trait|mod)\b(.*)")
USE = re.compile(r"^(\S+?):(\d+):\d+: warning: use of deprecated [a-z ]+`([^`]+)`")
TESTY = re.compile(r"(^|/)(tests|benches)/|^core/test/|(^|/)tests?(_\w+)?\.rs$")


def strip_generics(s):
    """`s` from its first top-level name on, skipping a leading `<...>`."""
    s = s.strip()
    if s.startswith("<"):
        depth = 0
        for i, c in enumerate(s.replace("->", "-_")):  # an `Fn(..) -> T` bound's arrow
            depth += {"<": 1, ">": -1}.get(c, 0)
            if depth == 0:
                return s[i + 1:].strip()
    return s


def headers(lines, i, indent):
    """The headers enclosing line `i` (at `indent`), innermost first: each less-indented line above it
    that is not a `where`, brace, comment or attribute line; an OWNER match or None (a fn body)."""
    for j in range(i - 1, -1, -1):
        line = lines[j]
        ind = len(line) - len(line.lstrip())
        if not line.strip() or ind >= indent or re.match(r"^\s*(where\b|\{|//|#)", line):
            continue
        yield OWNER.match(line)
        indent = ind


def owner_of(lines, i, indent, module):
    """(name, is a module) of the type or module a line at `indent` belongs to: its innermost header;
    None inside a fn body, a trait impl, or anything not plain `pub` (a `pub(crate) mod tests`)."""
    found = None
    for m in headers(lines, i, indent):
        if m is None:
            return None
        kind, rest = m.group(1), strip_generics(m.group(2))
        if kind == "impl" and re.search(r"\bfor\b", rest):
            return None
        if kind != "impl" and not m.group(0).lstrip().startswith("pub "):
            return None
        if found is None:
            name = re.match(r"(?:\w+::)*(\w+)", rest.lstrip("&*' "))
            if not name:
                return None
            found = (name.group(1), kind == "mod")
    return found or (module, True)


def mark(crate_dir, crate, originals):
    """Mark the crate's pub items, keeping each changed file's text in `originals` before writing it;
    returns {(owner, name): [declaration]} and the module names (owners that are no type)."""
    items, modules = collections.defaultdict(list), set()
    src = os.path.join(crate_dir, "src")
    crate_mod = crate.replace("-", "_")
    for dirpath, _, files in os.walk(src):
        for f in sorted(files):
            if not f.endswith(".rs"):
                continue
            path = os.path.join(dirpath, f)
            text = open(path).read()
            lines = text.split("\n")
            stem = f[:-3]
            module = os.path.basename(dirpath) if stem == "mod" else crate_mod if (stem in ("lib", "main") and dirpath == src) else stem
            modules.add(module)
            out = []
            for i, line in enumerate(lines):
                m = ITEM.match(line) or FIELD.match(line)
                if m and not line.lstrip().startswith(("pub use", "pub mod", "pub crate", "pub super", "pub self")):
                    indent = len(m.group(1))
                    name = m.group(m.lastindex)
                    found = owner_of(lines, i, indent, module) if indent else (module, True)
                    if found is not None:
                        owner, is_mod = found
                        if is_mod:
                            modules.add(owner)
                        items[(owner, name)].append(f"{os.path.relpath(path, ROOT)}:{i + 1}")
                        out.append(" " * indent + "#[deprecated]")
                out.append(line)
            if len(out) != len(lines):
                originals[path] = text
                with open(path, "w") as fh:
                    fh.write("\n".join(out))
    return items, modules


def restore(originals):
    for path, text in originals.items():
        with open(path, "w") as f:
            f.write(text)


def backup(originals):
    os.makedirs(BACKUP)
    for n, (path, text) in enumerate(originals.items()):
        with open(os.path.join(BACKUP, str(n)), "w") as f:
            f.write(path + "\n" + text)


def restore_backup():
    """Put back the files a killed probe left marked."""
    if not os.path.isdir(BACKUP):
        return
    for name in os.listdir(BACKUP):
        path, text = open(os.path.join(BACKUP, name)).read().split("\n", 1)
        with open(path, "w") as f:
            f.write(text)
    shutil.rmtree(BACKUP)
    print(f"deprecated_probe: restored the files a killed probe left marked", file=sys.stderr)


def text_of(path, cache={}):
    if path not in cache:
        try:
            cache[path] = open(os.path.join(ROOT, path)).read()
        except OSError:
            cache[path] = ""
    return cache[path]


CFG_TEST_MOD = r"#\[cfg\(test\)\]\s*(?:#\[[^\n]*\]\s*)*(?:pub(?:\([\w:]+\))? )?mod {}\s*"


def is_test(path, line):
    """Whether a use site is test code: a test path, a file its parent declares `#[cfg(test)] mod x;`,
    or below a `#[cfg(test)] mod x {` in its file."""
    if TESTY.search(path):
        return True
    d, f = os.path.split(path)
    name = f[:-3]
    parents = [os.path.join(d, p) for p in ("mod.rs", "lib.rs", "main.rs")] + [d + ".rs"]
    if name != "mod" and any(re.search(CFG_TEST_MOD.format(name) + ";", text_of(p)) for p in parents if p != path):
        return True
    m = re.search(CFG_TEST_MOD.format(r"\w+") + r"\{", text_of(path))
    return bool(m) and line > text_of(path).count("\n", 0, m.start()) + 1


def segments(item_path):
    """A rustc item path's segments, generic arguments dropped and an `<impl X>` read as X:
    `a::BlobWriter::<'a>::new` and `a::<impl a::BlobWriter<'a>>::new` are both [a, BlobWriter, new]."""
    segs, depth, cur = [], 0, ""
    for c in item_path.replace("->", "-_") + "::":
        depth += {"<": 1, ">": -1}.get(c, 0)
        if c == ":" and depth == 0:
            if cur:
                m = re.match(r"<impl (?:.*\bfor )?&?(?:mut )?(?:\w+::)*(\w+)", cur)
                if m or not cur.startswith("<"):
                    segs.append(m.group(1) if m else re.sub(r"<.*", "", cur))
            cur = ""
        else:
            cur += c
    return segs


def resolve(item_path, items, modules):
    """The marked items a use names. rustc names an item by its visible path (a re-export's), so a
    module owner matches any module item of that name; a variant or tuple field of a marked type
    counts as a use of the type."""
    segs = segments(item_path)
    for i in range(len(segs) - 1, 0, -1):
        owner, name = segs[i - 1], segs[i]
        if (owner, name) in items and owner not in modules:
            return [(owner, name)]
        found = [k for k in items if k[1] == name and k[0] in modules]
        if found:
            return found
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gui", action="store_true")
    ap.add_argument("-v", action="store_true")
    ap.add_argument("crate")
    a = ap.parse_args()
    dirs = {name: d for d, name in members().items()}
    if a.crate not in dirs:
        sys.exit(f"deprecated_probe: no workspace crate {a.crate!r}")
    crate_src = os.path.relpath(dirs[a.crate], ROOT) + "/src/"
    restore_backup()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(1))
    originals = {}
    try:
        items, modules = mark(dirs[a.crate], a.crate, originals)
        backup(originals)
        runs = [[]] + ([["-p", "osis-kit", "-p", "osis-app", "-p", "osis-android"]] if a.gui else [])
        output = ""
        for extra in runs:
            cmd = ["cargo", "clippy", "--all-targets", "--message-format=short", *extra]
            print("deprecated_probe:", " ".join(cmd), file=sys.stderr)
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
            output += r.stderr
            if r.returncode:
                errors = [l for l in r.stderr.splitlines() if ": error" in l]
                print(f"deprecated_probe: clippy failed ({len(errors)} errors), the uses listed are partial:", *errors[:10], sep="\n", file=sys.stderr)
    finally:
        restore(originals)
        shutil.rmtree(BACKUP, ignore_errors=True)
    uses = collections.defaultdict(set)
    unmatched = set()
    for line in output.splitlines():
        m = USE.match(line)
        if not m or m.group(1).startswith(crate_src):
            continue
        keys = resolve(m.group(3), items, modules)
        if not keys:
            unmatched.add(m.group(3))
        for k in keys:
            uses[k].add((m.group(1), int(m.group(2))))
    unused = sorted(k for k in items if k not in uses)
    test_only = sorted(k for k in uses if all(is_test(p, n) for p, n in uses[k]))
    show = lambda k: f"{k[0]}::{k[1]}  ({', '.join(items[k])})"
    print(f"unused outside {crate_src} ({len(unused)}):")
    for k in unused:
        print("  " + show(k))
    print(f"used only by tests ({len(test_only)}):")
    for k in test_only:
        print("  " + show(k) + "  <- " + ", ".join(sorted({p for p, _ in uses[k]})))
    if a.v:
        print("used:")
        for k in sorted(set(uses) - set(test_only)):
            print("  " + show(k) + "  <- " + ", ".join(sorted({p for p, _ in uses[k]})))
    for u in sorted(unmatched):
        print(f"deprecated_probe: a use of `{u}` matched no marked item", file=sys.stderr)
    print(f"deprecated_probe: {len(items)} items marked, {len(unused)} unused, {len(test_only)} test-only", file=sys.stderr)


if __name__ == "__main__":
    main()
