#!/usr/bin/env python3
"""The gate's selection (notes/gate.md, The selection): a branch's properties and sim scenarios at small
size, computed from what it touched. tools/gate.sh runs them in its one hold of the heavy lock.

  tools/test_select.py [--base REV | --all] [--offset N]          print the selection and its commands
  tools/test_select.py --paths PATH...                            select for these paths, not a diff
  tools/test_select.py --emit FILE ...                             also append the gate's `build CMD`, `check CMD` and `run LIMIT CMD` lines to FILE
  tools/test_select.py --listed NAME... -- CMD...                  run CMD (a `cargo test ... -- --list`), fail naming each NAME it lists no test of

The default base is the merge base with origin/main as last fetched, as in the gate (local main lags).

The set: every property test, at small size, of the crates the paths touch and their dependents
(the Cargo graph), and every sim scenario if osis-sim is one of those; `--all` selects every crate.
A file in PINNED (run-time data whose meaning an instant check fixes) selects nothing.
A dependent is reached through normal and build edges; a dev (or cfg(fuzzing)) edge selects that
one crate and stops, since a dev dependency is linked only into that crate's own tests, and of a
crate reached only so, only the properties in files that can call the dependency (`reaching`).

A property test is an `#[ignore]` test whose name ends in a size word (SIZE_WORD), before any
`_spec_*` suffix. Nothing else names one: a new property test is picked up by its name alone.

A name the scan finds can still be in no built target (a file no target compiles): libtest's
filters would then run nothing and pass. So the gate lists each selection's tests with the built
binaries before its hold (`check`, `--listed`) and stops on a selected name nothing lists.

Offsets: one random value per run (--offset to repeat one) starts every harness seed range and
sim sweep, so a gate samples seeds no earlier gate ran.
"""
import json, os, random, re, shlex, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_paths

SIZE_WORD = re.compile(r"_(large|plain|exhaustive)(_spec_\w*)?$")
IGNORE = re.compile(r"^(?!\s*//).*#\[(ignore\b|cfg_attr\(.*\bignore\b)")
FN = re.compile(r"^(?!\s*//).*?\bfn\s+(\$?\w+)")
# How far past `#[ignore]` the test's `fn` can be: only other attributes and comments sit between.
FN_WITHIN = 10
# Sim seeds at small size: a tenth of the 150 of a release-check sim run, as for every harness
# (osis_base::testenv::large).
SIM_SEEDS = 15
# Variables that shift a harness's seeds without choosing one: every `_START`, and the two
# xor'ed into each run's seed. `OSIS_ORDER_SEED` and the like pick a single seed: never set.
XOR_SEEDS = ("OSIS_CRDT_SEED", "OSIS_PERM_SEED")
# Build configuration of the whole workspace: every crate.
WHOLE = ("Cargo.toml", "Cargo.lock", ".cargo/", "rust-toolchain")
# Paths that hold no code a test runs, with what covers them instead.
OUTSIDE = (
    ("notes/", "notes"), ("spec/", "spec"), ("issues/", "issues"), ("docs/", "docs"),
    ("tools/", "the tools' own tests, in the gate"),
    ("core/test/tla/", "core/test/tla/run.sh <module> for an edited module"),
    ("core/test/fuzz/", "fuzz targets, by hand"),
)
# Files inside a crate that compile into nothing and whose meaning to every reader an instant check fixes
# from the sources: an edit that could change what a test sees fails that check, so no test is
# selected. A file listed here must be read at run time only (no include_str!, no build.rs).
PINNED = (
    ("core/base/testenv-known.txt", "tools/policy.py keeps it equal to the OSIS_* names the sources use"),
)


def run(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def metadata():
    """The workspace: {name: dir relative to root}, {name: [(dependent, kinds)]}."""
    m = json.loads(run("cargo", "metadata", "--format-version", "1", "--locked"))
    root = m["workspace_root"]
    names = {}
    dirs = {}
    for p in m["packages"]:
        if p["id"] in m["workspace_members"]:
            names[p["id"]] = p["name"]
            dirs[p["name"]] = os.path.relpath(os.path.dirname(p["manifest_path"]), root)
    users = {n: [] for n in dirs}
    for node in m["resolve"]["nodes"]:
        if node["id"] not in names:
            continue
        for d in node["deps"]:
            if d["pkg"] in names:
                # a normal edge under cfg(fuzzing) is built only into the fuzz targets (by hand):
                # to the gate it links test code only, as a dev edge does
                kinds = {"dev" if k.get("target") == "cfg(fuzzing)" else k["kind"] or "normal" for k in d["dep_kinds"]}
                users[names[d["pkg"]]].append((names[node["id"]], kinds, d["name"]))
    return dirs, users


def changed(base):
    if base is None:
        base = run("git", "merge-base", "HEAD", "refs/remotes/origin/main").strip()
    return sorted(gate_paths.changed(base, None))


def owner(path, dirs):
    """The crate whose directory holds `path`, the deepest one if nested."""
    found = [(len(d), n) for n, d in dirs.items() if path.startswith(d + "/")]
    return max(found)[1] if found else None


def schema_readers(path, dirs):
    """The crates whose Rust sources name this schema file (build.rs, include_str!)."""
    name = path.split("/", 1)[1]
    hits = subprocess.run(["git", "grep", "-l", "-F", f"schema/{name}", "--", "*.rs"], capture_output=True, text=True).stdout
    return {c for c in (owner(f, dirs) for f in hits.split()) if c}


def classify(paths, dirs):
    """(crates touched, whole workspace?, {path: why it selects nothing})."""
    touched, whole, nothing = set(), False, {}
    for p in paths:
        c = owner(p, dirs)
        pinned = next((why for f, why in PINNED if p == f), None)
        if pinned:
            nothing[p] = pinned
        elif c:
            touched.add(c)
        elif p.startswith(WHOLE):
            whole = True
        elif p.startswith("schema/") and p.endswith(".osis"):
            readers = schema_readers(p, dirs)
            touched |= readers
            if not readers:
                nothing[p] = "no workspace crate reads it"
        else:
            nothing[p] = next((why for prefix, why in OUTSIDE if p.startswith(prefix)), "no crate, not classified: read it")
    return touched, whole, nothing


def closure(touched, users):
    """`touched` and its dependents, as {crate: None (every property) or the extern names of the
    dev dependencies it was reached through}: normal and build edges propagate, a dev edge selects
    and stops. A crate reached by a dev edge first and a normal edge later still propagates."""
    carried, via, todo = set(touched), {}, list(touched)
    while todo:
        for user, kinds, name in users.get(todo.pop(), ()):
            if kinds == {"dev"}:
                via.setdefault(user, set()).add(name)
            elif user not in carried:
                carried.add(user)
                todo.append(user)
    return {c: None if c in carried else via[c] for c in carried | set(via)}


def reaching(files, idents):
    """The files of one crate whose tests can call into a dev dependency named in `idents`: those
    naming it, then, within one test target (a dev dependency is linked only into test code, which
    no other target sees; files under no lib.rs or main.rs count as one target), to a fixed point:
    those naming the module of a file found (`m::`, not `std::m::`, or `m` in a `use`, as for
    `use crate::m as n`), using a macro one defines (`name!`), and a file's child modules
    (`super::*` brings its names in unnamed). None when a crate root (lib.rs, main.rs) names one (its
    items reach every module unnamed) or a file mounts code by `#[path]` or `include!` (a module not
    named by its file)."""
    text = {f: open(f, encoding="utf-8").read() for f in files}
    if any(re.search(r"#\[\s*path\b|\binclude!", t) for t in text.values()):
        return None
    roots = {os.path.dirname(f) for f in files if os.path.basename(f) in ("lib.rs", "main.rs")}

    def target(f):
        d = os.path.dirname(f)
        while d and d not in roots:
            d = os.path.dirname(d)
        return d

    def module(f):
        """(the module's name, the directory of its children)"""
        stem = os.path.splitext(f)[0]
        if os.path.basename(stem) == "mod":
            return os.path.basename(os.path.dirname(f)), os.path.dirname(f)
        return os.path.basename(stem), stem

    names = [re.compile(rf"\b{re.escape(i)}\b") for i in idents]
    found = {f for f, t in text.items() if any(n.search(t) for n in names)}
    todo = list(found)
    while todo:
        f = todo.pop()
        if os.path.basename(f) in ("lib.rs", "main.rs"):
            return None
        name, kids = module(f)
        m = re.escape(name)
        ways = [rf"(?<!std::)(?<!core::)(?<!alloc::)\b{m}::", rf"^\s*(pub\S*\s+)?use\s[^;]*\b{m}\b"]
        ways += [rf"\b{re.escape(k)}!" for k in re.findall(r"macro_rules!\s*(\w+)", text[f])]
        used = re.compile("|".join(ways), re.M)
        for g, t in text.items():
            if g not in found and target(g) == target(f) and (used.search(t) or g.startswith(kids + "/")):
                found.add(g)
                todo.append(g)
    return found


def crate_files(pkg_dir, nested):
    """The crate's .rs files, nested crates left to themselves."""
    return [f for f in run("git", "ls-files", "-z", "--", pkg_dir).split("\0")
            if f.endswith(".rs") and not any(f.startswith(n + "/") for n in nested)]


def ignored_tests(files):
    """({name of an `#[ignore]` test: the files defining one of that name}, `file:line` of each
    `#[ignore]` no name could be read for)."""
    names, unread = {}, []
    for f in files:
        lines = open(f, encoding="utf-8").read().split("\n")
        for i, line in enumerate(lines):
            if IGNORE.match(line):
                m = next(filter(None, (FN.search(s) for s in lines[i:i + FN_WITHIN])), None)
                if m and not m.group(1).startswith("$"):
                    names.setdefault(m.group(1), set()).add(f)
                else:
                    unread.append(f"{f}:{i + 1}")
    return names, unread


def properties(selected, dirs):
    """({crate: property test names}, other `#[ignore]` names in those crates, unread `#[ignore]`s).
    A crate reached through dev dependencies only keeps the properties in files reaching them."""
    props, others, unread = {}, set(), []
    for c in sorted(selected):
        nested = [d for n, d in dirs.items() if n != c and d.startswith(dirs[c] + "/")]
        files = crate_files(dirs[c], nested)
        names, missed = ignored_tests(files)
        unread += missed
        keep = reaching(files, selected[c]) if selected[c] else None
        chosen = {n for n, fs in names.items() if SIZE_WORD.search(n) and not n.startswith("repro_") and (keep is None or not fs.isdisjoint(keep))}
        if chosen:
            props[c] = sorted(chosen)
        others |= set(names) - chosen
    return props, others, unread


def cargo_args(props, others):
    """`cargo test` arguments for the properties. libtest filters match substrings, so an ignored
    test that is not selected and contains a selected name gets its own --skip; a name selected in one
crate runs wherever it is (a skip of it would drop the selected one)."""
    wanted = sorted({t for v in props.values() for t in v})
    pkgs = [a for c in sorted(props) for a in ("-p", c)]
    skips = sorted(o for o in others if o not in wanted and any(w in o for w in wanted))
    filters = ["--ignored", *wanted, "--skip", "repro_"] + [a for o in skips for a in ("--skip", o)]
    return pkgs, filters


def envs(offset):
    known = open("core/base/testenv-known.txt").read().split()
    vs = sorted(v for v in known if v.endswith("_START") or v in XOR_SEEDS)
    return [f"{v}={offset}" for v in vs]


def listed(wanted, cmd):
    """Run `cmd` (a `cargo test ... -- --list` of the built targets); 1 naming each wanted test
    whose name no listed test ends in."""
    r = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    if r.returncode:
        print(f"gate: listing the selected tests failed (exit {r.returncode}): {shlex.join(cmd)}")
        return 1
    have = {l[:-len(": test")].rsplit("::", 1)[-1] for l in r.stdout.split("\n") if l.endswith(": test")}
    missing = [w for w in wanted if w not in have]
    for w in missing:
        print(f"gate: selected test {w} is in no built test target (a file the scan reads that no target compiles?): fix the selection, don't skip it")
    print(f"   {len(wanted) - len(missing)} of {len(wanted)} selected tests listed")
    return 1 if missing else 0


def main():
    args = sys.argv[1:]
    if args[:1] == ["--listed"] and "--" in args:
        i = args.index("--")
        return listed(args[1:i], args[i + 1:])
    every = "--all" in args
    base = offset = paths = emit = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--all":
            i += 1
        elif a == "--emit":
            emit = args[i + 1]
            i += 2
        elif a == "--base":
            base = args[i + 1]
            i += 2
        elif a == "--offset":
            offset = int(args[i + 1])
            i += 2
        elif a == "--paths":
            paths = args[i + 1:]
            i = len(args)
        else:
            sys.exit(__doc__)
    os.chdir(run("git", "rev-parse", "--show-toplevel").strip())
    given = paths is not None
    if paths is None:
        paths = [] if every else changed(base)
    if offset is None:
        offset = random.randrange(10**12)

    dirs, users = metadata()
    touched, whole, nothing = classify(paths, dirs)
    whole = whole or every
    selected = dict.fromkeys(dirs) if whole else closure(touched, users)
    props, others, unread = properties(selected, dirs)
    sim = "osis-sim" in selected

    # unlocked builds first, with the same cargo arguments as the runs, so the runs build nothing
    build, checks, cmds = [], [], []
    if props:
        pkgs, filters = cargo_args(props, others)
        build.append(["cargo", "test", "--locked", *pkgs, "--tests", "--no-run"])
        wanted = sorted({t for v in props.values() for t in v})
        checks.append(["python3", "tools/test_select.py", "--listed", *wanted, "--", "cargo", "test", "--locked", "--quiet", *pkgs, "--tests", "--", "--list", *filters])
        cmds.append(("gate.properties", ["env", *envs(offset), "cargo", "test", "--locked", "--no-fail-fast", *pkgs, "--tests", "--", *filters]))
    if sim:
        build.append(["cargo", "build", "--locked", "--bin", "sim-sweep"])
        cmds.append(("gate.sim", ["cargo", "run", "--locked", "--bin", "sim-sweep", "--", "--seeds", str(SIM_SEEDS), "--from", str(offset)]))
    if emit:
        with open(emit, "a") as f:
            f.writelines([f"build {shlex.join(b)}\n" for b in build] + [f"check {shlex.join(c)}\n" for c in checks] + [f"run {n} {shlex.join(c)}\n" for n, c in cmds])

    print(f"paths: {'every crate (--all)' if every else len(paths)}")
    for p, why in sorted(nothing.items()):
        print(f"  selects nothing: {p} ({why})")
    print(f"crates touched: {', '.join(sorted(touched)) or 'none'}{' (workspace build config: every crate)' if whole and not every else ''}")
    # more than half: the graph says so, and trimming it by hand would hide a real dependent
    note = " (nearly everything: expected for a crate this far down the graph)" if not whole and len(selected) * 2 > len(dirs) else ""
    print(f"crates selected: {len(selected)} of {len(dirs)}{note}: {', '.join(sorted(selected)) or 'none'}")
    for c, via in sorted(selected.items()):
        if via:
            print(f"  {c} through dev dependencies only: the properties in files reaching {', '.join(sorted(via))}")
    count = sum(len(v) for v in props.values())
    print(f"property tests: {count}")
    for c, names in props.items():
        print(f"  {c}: {' '.join(names)}")
    for u in unread:
        print(f"  not read: {u} (an #[ignore] with no named fn, so not selected: check it by hand)")
    print(f"sim: {'every scenario, ' + str(SIM_SEEDS) + ' seeds from ' + str(offset) if sim else 'none'}")
    if cmds:
        # --paths takes the rest of the line, so it goes last
        how = ["--all"] if every else ["--paths", *paths] if given else ["--base", base] if base else []
        print(f"offset: {offset} (replay this selection: {shlex.join(['tools/test_select.py', '--offset', str(offset), *how])})")
    if not cmds:
        print("nothing to run")
        return 0
    print("commands (tools/gate.sh builds and checks, then runs these in its hold of the heavy lock):")
    for c in build + checks + [c for _, c in cmds]:
        print("  " + shlex.join(c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
