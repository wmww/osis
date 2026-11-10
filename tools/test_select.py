#!/usr/bin/env python3
"""The gate's selection (notes/testing.md, The gate): a branch's properties and sim scenarios at small
size, computed from what it touched. tools/gate.sh runs them in its one hold of the heavy lock.

  tools/test_select.py [--base REV | --all] [--offset N]          print the selection and its commands
  tools/test_select.py --paths PATH...                            select for these paths, not a diff
  tools/test_select.py --emit [--base REV | --all] [--offset N]   for the gate: `build CMD` and `run LIMIT CMD` lines

The set: every property test, at small size, of the crates the paths touch and their dependents
(the Cargo graph), and every sim scenario if osis-sim is one of those; `--all` selects every crate.
A dependent is reached through normal and build edges; a dev edge selects that one crate and
stops, since a dev dependency is linked only into that crate's own tests.

A property test is an `#[ignore]` test whose name ends in a size word (SIZE_WORD), before any
`_spec_*` suffix. Nothing else names one: a new property test is picked up by its name alone.

Offsets: one random value per run (--offset to repeat one) starts every harness seed range and
sim sweep, so a gate samples seeds no earlier gate ran.
"""
import json, os, random, re, shlex, subprocess, sys

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


def run(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def metadata():
    """The workspace: root, {name: dir relative to root}, {name: [(dependent, kinds)]}."""
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
                kinds = {k["kind"] or "normal" for k in d["dep_kinds"]}
                users[names[d["pkg"]]].append((names[node["id"]], kinds))
    return root, dirs, users


def changed(base):
    if base is None:
        base = run("git", "merge-base", "HEAD", "main").strip()
    diff = run("git", "diff", "--no-renames", "--name-only", "-z", base, "--")
    new = run("git", "ls-files", "--others", "--exclude-standard", "-z")
    return sorted({p for p in (diff + new).split("\0") if p})


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
        if c:
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
    """`touched` and its dependents: normal and build edges propagate, a dev edge selects and stops.
    A crate reached by a dev edge first and a normal edge later still propagates."""
    selected, carried, todo = set(touched), set(touched), list(touched)
    while todo:
        for user, kinds in users.get(todo.pop(), ()):
            selected.add(user)
            if kinds != {"dev"} and user not in carried:
                carried.add(user)
                todo.append(user)
    return selected


def ignored_tests(pkg_dir, nested):
    """(names of the `#[ignore]` tests under a crate, nested crates left to themselves;
    `file:line` of each `#[ignore]` no name could be read for)."""
    names, unread = set(), []
    for f in run("git", "ls-files", "-z", "--", pkg_dir).split("\0"):
        if not f.endswith(".rs") or any(f.startswith(n + "/") for n in nested):
            continue
        lines = open(f, encoding="utf-8").read().split("\n")
        for i, line in enumerate(lines):
            if IGNORE.match(line):
                m = next(filter(None, (FN.search(s) for s in lines[i:i + FN_WITHIN])), None)
                if m and not m.group(1).startswith("$"):
                    names.add(m.group(1))
                else:
                    unread.append(f"{f}:{i + 1}")
    return names, unread


def properties(selected, dirs):
    """({crate: property test names}, other `#[ignore]` names in those crates, unread `#[ignore]`s)."""
    props, others, unread = {}, set(), []
    for c in sorted(selected):
        nested = [d for n, d in dirs.items() if n != c and d.startswith(dirs[c] + "/")]
        names, missed = ignored_tests(dirs[c], nested)
        unread += missed
        chosen = {n for n in names if SIZE_WORD.search(n) and not n.startswith("repro_")}
        if chosen:
            props[c] = sorted(chosen)
        others |= names - chosen
    return props, others, unread


def cargo_args(props, others):
    """`cargo test` arguments for the properties. libtest filters match substrings, so an ignored
    test that is not selected and contains a selected name gets its own --skip."""
    wanted = sorted({t for v in props.values() for t in v})
    pkgs = [a for c in sorted(props) for a in ("-p", c)]
    skips = sorted(o for o in others if any(w in o for w in wanted))
    filters = ["--ignored", *wanted, "--skip", "repro_"] + [a for o in skips for a in ("--skip", o)]
    return pkgs, filters


def envs(offset):
    known = open("core/base/testenv-known.txt").read().split()
    vs = sorted(v for v in known if v.endswith("_START") or v in XOR_SEEDS)
    return [f"{v}={offset}" for v in vs]


def main():
    args = sys.argv[1:]
    emit = "--emit" in args
    every = "--all" in args
    base = offset = paths = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--emit", "--all"):
            i += 1
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

    root, dirs, users = metadata()
    touched, whole, nothing = classify(paths, dirs)
    whole = whole or every
    selected = set(dirs) if whole else closure(touched, users)
    props, others, unread = properties(selected, dirs)
    sim = "osis-sim" in selected

    # unlocked builds first, with the same cargo arguments as the runs, so the runs build nothing
    build, cmds = [], []
    if props:
        pkgs, filters = cargo_args(props, others)
        build.append(["cargo", "test", "--locked", *pkgs, "--tests", "--no-run"])
        cmds.append(("gate.properties", ["env", *envs(offset), "cargo", "test", "--locked", "--no-fail-fast", *pkgs, "--tests", "--", *filters]))
    if sim:
        build.append(["cargo", "build", "--locked", "--bin", "sim-sweep"])
        cmds.append(("gate.sim", ["cargo", "run", "--locked", "--bin", "sim-sweep", "--", "--seeds", str(SIM_SEEDS), "--from", str(offset)]))
    if emit:
        for b in build:
            print("build " + shlex.join(b))
        for n, c in cmds:
            print(f"run {n} " + shlex.join(c))
        return 0

    print(f"paths: {'every crate (--all)' if every else len(paths)}")
    for p, why in sorted(nothing.items()):
        print(f"  selects nothing: {p} ({why})")
    print(f"crates touched: {', '.join(sorted(touched)) or 'none'}{' (workspace build config: every crate)' if whole and not every else ''}")
    # more than half: the graph says so, and trimming it by hand would hide a real dependent
    note = " (nearly everything: expected for a crate this far down the graph)" if not whole and len(selected) * 2 > len(dirs) else ""
    print(f"crates selected: {len(selected)} of {len(dirs)}{note}: {', '.join(sorted(selected)) or 'none'}")
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
    print("commands (tools/gate.sh builds, then runs these in its hold of the heavy lock):")
    for c in build + [c for _, c in cmds]:
        print("  " + shlex.join(c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
