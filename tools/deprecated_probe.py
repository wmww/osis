#!/usr/bin/env python3
"""The cleanup's `#[deprecated]` probe (notes/coordination.md, Cleanup): mark every `pub` item and
field in CRATE's src/ `#[deprecated]`, run one `cargo clippy --workspace --all-targets
--message-format=short` (every member, the GUI's included) and `cargo +nightly fuzz check` of the
fuzz targets (core/test/fuzz, outside the workspace), and list per item its use sites outside
CRATE's own src/: the items nobody uses, then those only tests use (under tests/, benches/
or core/test/, a `tests*.rs`, a file declared `#[cfg(test)] mod x;`, or below a
`#[cfg(test)] mod x {`). The tree is restored afterwards, always; a probe killed hard leaves its
backup in target/deprecated-probe/, which the next run restores first.
A use is matched to its item by name and owner (the impl's type, the field's struct), so two `new`s
of different types stay apart; rustc names a free item by its visible path, so a module owner
matches the name in any module. A variant or tuple-field use counts for its type. Not marked:
`pub use`, `pub mod`, tuple fields, trait impls, anything inside a header not plain `pub`.

--dead: then find which of the unused items are dead, not merely used only inside CRATE: narrow each
to `pub(crate)` (a free item also leaves every `pub use` in src/ naming it), run
`cargo clippy -p CRATE --lib --message-format=short` and list rustc's never used / read /
constructed warnings (dead in the lib build: unused, or used by CRATE's tests alone), less those
naming only items used outside CRATE by non-test code (a method of a narrowed type); a warning
naming some such items beside dead ones lists them as not dead. An item a
narrowing breaks the build over (a type named in a still-`pub` signature, a re-export the scan
missed, a use of the alias a dropped `pub use … as` gave it) is put back `pub` and the run repeated; those are listed as kept. Needs CRATE's src/
committed (no diff against HEAD); after restoring, `git diff` of it must be empty again.
Usage: tools/deprecated_probe.py [--dead] [-v] CRATE   (a package name, e.g. osis-blob; -v
also lists every used item with its sites)"""
import argparse, collections, glob, os, re, shutil, signal, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import ROOT, members

BACKUP = os.path.join(ROOT, "target", "deprecated-probe")
ITEM = re.compile(r"^(\s*)pub (?:(?:const|async|unsafe) )*(fn|struct|enum|trait|type|const|static|union) (\w+)")
FIELD = re.compile(r"^(\s*)pub (\w+)\s*:")
OWNER = re.compile(r"^\s*(?:pub(?:\([\w:]+\))? )?(?:unsafe )?(impl|struct|enum|union|trait|mod)\b(.*)")
DEAD = re.compile(r"^(\S+?):(\d+):\d+: (?:warning|error): (.*\bnever (?:used|read|constructed)\b.*)$")
ERROR = re.compile(r"^(\S+?):(\d+):\d+: error(?:\[E\d+\])?: (.*)$")
USE = re.compile(r"^(\S+?):(\d+):\d+: warning: use of deprecated [a-z ]+`([^`]+)`")
# cargo-fuzz passes no --message-format: rustc's long form, the message line then its ` --> ` line
LONG_USE = re.compile(r"^warning: use of deprecated [a-z ]+`([^`]+)`.*\n\s*--> (\S+?):(\d+):\d+", re.M)
FUZZ = os.path.join(ROOT, "core", "test", "fuzz")
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


def use_sites(output, cwd):
    """(path from the repository root, line, item path) of each deprecated use in a build's output,
    short form (`--message-format=short`) or rustc's long one; paths are relative to `cwd`."""
    found = [(m.group(1), m.group(2), m.group(3)) for l in output.splitlines() if (m := USE.match(l))]
    found += [(m.group(2), m.group(3), m.group(1)) for m in LONG_USE.finditer(output)]
    return sorted({(os.path.relpath(os.path.join(cwd, p), ROOT), int(n), item) for p, n, item in found})


def outside(warning, items, used):
    """(the names a dead-code warning lists, those of them used outside the crate by non-test code
    (`used`): methods or fields of a narrowed type, not dead). The warning's line is its first
    item's declaration (narrowing keeps line numbers), which gives the owner of every name it lists."""
    m = DEAD.match(warning)
    if not m:
        return [], []
    at = f"{m.group(1)}:{m.group(2)}"
    owners = {k[0] for k, ds in items.items() if at in ds}
    names = re.findall(r"`(\w+)`", m.group(3))
    if len(owners) != 1:
        return names, []
    return names, [n for n in names if (next(iter(owners)), n) in used]


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


def narrowed(text, lines, free):
    """`text` with `pub ` made `pub(crate) ` on each of `lines` (1-based) and each name of `free`
    dropped from its `pub use` statements (a statement left empty goes, its lines left blank: line
    numbers stay those of the declarations)."""
    out = text.split("\n")
    for n in lines:
        out[n - 1] = re.sub(r"\bpub ", "pub(crate) ", out[n - 1], count=1)
    text = "\n".join(out)

    def drop(m):
        new = rewrite(m)
        return new + "\n" * (m.group(0).count("\n") - new.count("\n"))

    def rewrite(m):
        stmt = m.group(0)
        # each piece but those whose item (the last segment before any `as`) is in `free`
        names = lambda part: [x for x in part if x.strip() and re.split(r"\s+as\s+", x.strip())[0].split("::")[-1] not in free]
        if "{" in stmt:
            head, inner = stmt.split("{", 1)
            inner, tail = inner.rsplit("}", 1)
            kept = names(inner.split(","))
            return f"{head}{{{', '.join(x.strip() for x in kept)}}}{tail}" if kept else ""
        path = stmt[len(m.group(1)):].rstrip(";").strip()
        return stmt if names([path]) else ""
    return re.sub(r"^(\s*pub use )[^;]*;", drop, text, flags=re.M)


def aliases(text):
    """{alias: item name} of each `pub use` piece renaming its item (`X as Y`): an error naming the
    alias, which narrowing X dropped, names X."""
    out = {}
    for stmt in re.findall(r"^\s*pub use ([^;]*);", text, flags=re.M):
        for m in re.finditer(r"(?:\w+::)*(\w+)\s+as\s+(\w+)", stmt):
            out[m.group(2)] = m.group(1)
    return out


def dead(crate, crate_dir, decls, free_names):
    """Narrow `decls` ({key: ["path:line"]}), clippy CRATE's lib, restore; returns (the dead-code
    warnings in CRATE's src/, the keys kept pub over a build error, the errors left if any)."""
    src = os.path.relpath(os.path.join(crate_dir, "src"), ROOT)
    keep, warnings, left = set(), [], []
    while True:
        lines, free = collections.defaultdict(set), set()
        for k, at in decls.items():
            if k in keep:
                continue
            for d in at:
                path, n = d.rsplit(":", 1)
                lines[os.path.join(ROOT, path)].add(int(n))
            if k in free_names:
                free.add(k[1])
        originals, renamed = {}, {}
        try:
            for dirpath, _, files in os.walk(os.path.join(crate_dir, "src")):
                for f in files:
                    path = os.path.join(dirpath, f)
                    if not f.endswith(".rs"):
                        continue
                    text = open(path).read()
                    renamed.update(aliases(text))
                    new = narrowed(text, lines.get(path, ()), free)
                    if new != text:
                        originals[path] = text
            backup(originals)
            for path in originals:
                with open(path, "w") as fh:
                    fh.write(narrowed(originals[path], lines.get(path, ()), free))
            cmd = ["cargo", "clippy", "-p", crate, "--lib", "--message-format=short"]
            print("deprecated_probe:", " ".join(cmd), file=sys.stderr)
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        finally:
            restore(originals)
            shutil.rmtree(BACKUP, ignore_errors=True)
        out = r.stderr.splitlines()
        errors = [l for l in out if ERROR.match(l) and not DEAD.match(l)]
        if not errors:
            warnings = [l for l in out if (m := DEAD.match(l)) and m.group(1).startswith(src + "/")]
            return warnings, keep, []
        # put back `pub` on every narrowed item an error names (by name in backticks, or its line)
        named = set(re.findall(r"`(?:\w+::)*(\w+)`", " ".join(errors)))
        named |= {renamed[n] for n in named if n in renamed}
        at = {(m.group(1), m.group(2)) for l in errors if (m := ERROR.match(l))}
        hit = {k for k, ds in decls.items() if k not in keep and (k[1] in named or any(tuple(d.rsplit(":", 1)) in at for d in ds))}
        if not hit:
            return [], keep, errors
        keep |= hit


def clean(path):
    """Whether `path` has no change against HEAD (untracked files included)."""
    r = subprocess.run(["git", "status", "--porcelain", "--", path], cwd=ROOT, capture_output=True, text=True, check=True)
    return not r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dead", action="store_true")
    ap.add_argument("-v", action="store_true")
    ap.add_argument("crate")
    a = ap.parse_args()
    dirs = {name: d for d, name in members().items()}
    if a.crate not in dirs:
        sys.exit(f"deprecated_probe: no workspace crate {a.crate!r}")
    crate_src = os.path.relpath(dirs[a.crate], ROOT) + "/src/"
    restore_backup()
    if a.dead and not clean(crate_src):
        sys.exit(f"deprecated_probe: --dead needs {crate_src} committed (it checks the tree is restored by git diff): wip-commit first")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(1))
    originals = {}
    try:
        items, modules = mark(dirs[a.crate], a.crate, originals)
        backup(originals)
        sites = []
        for cmd, cwd in [(["cargo", "clippy", "--workspace", "--all-targets", "--message-format=short"], ROOT),
                         (["cargo", "+nightly", "fuzz", "check", "--fuzz-dir", "."], FUZZ)]:
            print("deprecated_probe:", " ".join(cmd), file=sys.stderr)
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
            sites += use_sites(r.stderr, cwd)
            if r.returncode:
                errors = [l for l in r.stderr.splitlines() if "error" in l]
                print(f"deprecated_probe: {' '.join(cmd[:3])} failed, the uses listed are partial:", *errors[:10], sep="\n", file=sys.stderr)
    finally:
        restore(originals)
        shutil.rmtree(BACKUP, ignore_errors=True)
    print("deprecated_probe: uses searched in every workspace member (core and GUI) and the fuzz targets", file=sys.stderr)
    uses = collections.defaultdict(set)
    unmatched = set()
    for path, line, item in sites:
        if path.startswith(crate_src):
            continue
        keys = resolve(item, items, modules)
        if not keys:
            unmatched.add(item)
        for k in keys:
            uses[k].add((path, line))
    unused = sorted(k for k in items if k not in uses)
    test_only = sorted(k for k in uses if all(is_test(p, n) for p, n in uses[k]))
    show = lambda k: f"{k[0]}::{k[1]}  ({', '.join(items[k])})"
    # osis-android compiles only for target_os = "android", so the host clippy run sees none of its
    # uses: an item its sources name is marked for a check by hand (the gate's Android lint compiles
    # them: notes/gate.md, Steps)
    android = "\n".join(open(f).read() for f in glob.glob(os.path.join(ROOT, "app/android/src/**/*.rs"), recursive=True))
    in_android = {k for k in unused if re.search(rf"\b{re.escape(k[1])}\b", android)}
    print(f"unused outside {crate_src} ({len(unused)}):")
    for k in unused:
        print("  " + show(k) + ("  (named in app/android/src, not compiled here: check by hand)" if k in in_android else ""))
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
    if a.dead:
        warnings, kept, errors = dead(a.crate, dirs[a.crate], {k: items[k] for k in unused}, {k for k in unused if k[0] in modules})
        used = {k for k in uses if k not in test_only}
        hidden, shown = [], []
        for w in warnings:
            names, out = outside(w, items, used)
            if names and len(out) == len(names):
                hidden.append(w)
            else:
                droid = [n for n in names if any(k[1] == n for k in in_android)]
                shown.append(w + (f"  (used outside, not dead: {', '.join(out)})" if out else "")
                             + (f"  (named in app/android/src, not compiled here: {', '.join(droid)})" if droid else ""))
        warnings = shown
        if not clean(crate_src):
            sys.exit(f"deprecated_probe: {crate_src} differs from HEAD after restoring: check git diff")
        if errors:
            print(f"deprecated_probe: the narrowed build fails over no listed item; no dead list:", *errors[:10], sep="\n", file=sys.stderr)
            sys.exit(1)
        print(f"dead in the lib build (unused, or used by {a.crate}'s tests alone) ({len(warnings)} warnings):")
        for w in warnings:
            print("  " + w)
        if hidden:
            print(f"deprecated_probe: {len(hidden)} warnings left out: they name only items used outside {crate_src} (a method of a narrowed type)", file=sys.stderr)
        if kept:
            print(f"kept pub (narrowing broke the build) ({len(kept)}):")
            for k in sorted(kept):
                print("  " + show(k))


if __name__ == "__main__":
    main()
