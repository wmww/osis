#!/usr/bin/env python3
"""Tests tools/test_select.py on a fabricated workspace in a throwaway repo. Exit 1 on a mismatch."""
import contextlib, functools, io, os, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_select

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_select.py")

# base <- mid <- top; model is only a dev-dependency of mid and pathy, and a fuzzing-only one of fz
# (base <- fz <- fzuser); osis-sim depends on mid; leaf depends on nothing.
CRATES = {
    "core/base": ("osis-base", ""),
    "core/mid": ("osis-mid", 'osis-base = { path = "../base" }\n[dev-dependencies]\nheld-model = { path = "../test/model" }\n'),
    "core/top": ("osis-top", 'osis-mid = { path = "../mid" }\n'),
    "core/test/model": ("held-model", ""),
    "core/test/sim": ("osis-sim", 'osis-mid = { path = "../../mid" }\n'),
    "core/leaf": ("osis-leaf", ""),
    "core/fz": ("osis-fz", "osis-base = { path = \"../base\" }\n[target.'cfg(fuzzing)'.dependencies]\nheld-model = { path = \"../test/model\" }\n"),
    "core/fzuser": ("osis-fzuser", 'osis-fz = { path = "../fz" }\n'),
    "core/pathy": ("osis-pathy", '[dev-dependencies]\nheld-model = { path = "../test/model" }\n'),
}
PROP = '#[test]\n#[ignore = "property"]\nfn {}() {{}}\n'


def write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def git(*a):
    subprocess.run(["git", *a], check=True, capture_output=True)


def out(*a):
    """test_select's report for args `a` at offset 7: run in process (the workspace's `cargo metadata`
    read once, as its manifests never change here), the first call as a command."""
    args = [*a, "--offset", "7"] if "--paths" not in a else ["--offset", "7", *a]
    if not calls:
        calls.append(1)
        r = subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return r.stdout
    sys.argv = [TOOL, *args]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert not test_select.main()
    return buf.getvalue()


calls = []


fails = 0


def check(name, text, *want, absent=()):
    global fails
    for w in want:
        if w not in text:
            print(f"FAIL {name}: missing {w!r}\n{text}")
            fails = 1
    for w in absent:
        if w in text:
            print(f"FAIL {name}: has {w!r}\n{text}")
            fails = 1


d = tempfile.mkdtemp()
os.chdir(d)
members = ", ".join(f'"{p}"' for p in CRATES)
write("Cargo.toml", f"[workspace]\nresolver = \"2\"\nmembers = [{members}]\n")
for path, (name, deps) in CRATES.items():
    write(f"{path}/Cargo.toml", f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n[lib]\npath = "src/lib.rs"\n[dependencies]\n{deps}')
write("core/base/src/lib.rs", PROP.format("base_prop_large") + '#[test] #[ignore] fn base_inline_large() {}\n#[test]\n#[ignore]\n// fn decoy_large names nothing\nfn base_after_comment_large() {}\n')
# a size word in the middle, a repro, a by-hand run, an example, a networking test: none are properties
write("core/mid/src/lib.rs", "#[cfg(test)]\n// helpers\nmod t;\n#[cfg(test)] pub(crate) mod t2;\n#[cfg(any(test, feature = \"x\"))]\nmod t3;\n" + PROP.format("mid_prop_plain_spec_crdt_4") + PROP.format("mid_by_hand_spec_crdt_4") + PROP.format("quic_large_transfer") + PROP.format("repro_big_large") + "#[test]\nfn mid_quick() {}\n")
write("core/mid/tests/it/main.rs", PROP.format("mid_it_plain") + PROP.format("mid_it_plain_over_quic"))
# reaching the dev dependency: naming it, through a module that does (not std's of that name, not
# another target's), as a child of a module that does
write("core/mid/tests/it/helper.rs", "use held_model::X;\nmacro_rules! via_helper { () => { X } }\n" + PROP.format("mid_helper_large") + PROP.format("mid_dup_large"))
write("core/mid/tests/it/via.rs", "fn f() { crate::helper::g() }\n" + PROP.format("mid_via_helper_large"))
# a comment saying use is no `use`; a same-named test elsewhere does not drop the one reaching
write("core/mid/tests/it/stdname.rs", "// we use helper here;\nfn f() { std::helper::g() }\n" + PROP.format("mid_std_large") + PROP.format("mid_dup_large") + PROP.format("model_large"))
# a module renamed on use, a macro of a file found, a single-file target's child module
write("core/mid/tests/it/renamed.rs", "use crate::helper as h;\nfn f() { h::g() }\n" + PROP.format("mid_renamed_large"))
write("core/mid/tests/it/macro.rs", "fn f() { via_helper!() }\n" + PROP.format("mid_macro_large"))
write("core/mid/tests/single.rs", "mod sub;\nfn f() { sub::g() }\n" + PROP.format("mid_single_large"))
write("core/mid/tests/single/sub.rs", "use held_model::Z;\n")
# a module mounted by #[path]: not named by its file, so every property
write("core/pathy/src/lib.rs", '#[cfg(test)]\n#[path = "t/impl.rs"]\nmod helper;\n')
write("core/pathy/src/t/impl.rs", "use held_model::X;\n")
write("core/pathy/src/b.rs", "fn f() { helper::g() }\n" + PROP.format("pathy_large"))
write("core/mid/tests/it/kids/mod.rs", "use held_model::Y;\nmod child;\n")
write("core/mid/tests/it/kids/child.rs", "use super::*;\n" + PROP.format("mid_child_large"))
write("core/mid/src/other.rs", "fn f() { helper::g() }\n" + PROP.format("mid_other_target_large"))
# test-only code: modules under exactly #[cfg(test)] (on the line before, on the same line, or by a
# parent module that is); not cfg(any(test, ..)); a tests/ file a dependent reads as text
write("core/mid/src/t.rs", "mod inner;\n" + PROP.format("mid_cfg_test_large"))
write("core/mid/src/t/inner.rs", "")
write("core/mid/src/t2.rs", "")
write("core/mid/src/t3.rs", "")
write("core/mid/tests/it/read.rs", "")
write("core/top/src/r.rs", 'const S: &str = include_str!("../../mid/tests/it/read.rs");\n')
write("core/fz/src/lib.rs", "#[cfg(fuzzing)]\npub use held_model::X;\n")
write("core/fz/src/a.rs", PROP.format("fz_large"))
write("core/fzuser/src/lib.rs", PROP.format("fzuser_large"))
write("core/top/src/lib.rs", PROP.format("top_exhaustive"))
write("core/test/model/src/lib.rs", PROP.format("model_large"))
write("core/test/sim/src/lib.rs", "")
write("core/leaf/src/lib.rs", PROP.format("leaf_large") + "macro_rules! t { ($n:ident) => { #[test]\n#[ignore]\nfn $n() {} } }\n")
for f in ("notes/a.md", "tools/x.sh", "schema/core.osis", "schema/README.md", "schema/orphan.osis"):
    write(f, "x\n")
write("core/mid/build.rs", '// reads "../../schema/core.osis"\n')
write("core/base/testenv-known.txt", "OSIS_ORDER_START\nOSIS_ORDER_SEEDS\nOSIS_ORDER_SEED\nOSIS_CRDT_SEED\n")
subprocess.run(["cargo", "metadata", "--format-version", "1"], check=True, capture_output=True)
test_select.metadata = functools.cache(test_select.metadata)
git("init", "-q", "-b", "main")
git("config", "user.email", "t@t")
git("config", "user.name", "t")
git("add", "-A")
git("commit", "-qm", "init")
# the default base is the merge base with origin/main: a remote whose main is this one
git("remote", "add", "origin", ".")
git("fetch", "-q", "origin", "main")

t = out("--paths", "notes/a.md")
check("notes only", t, "selects nothing: notes/a.md", "crates selected: 0 of 9", "nothing to run", absent=["cargo test"])

t = out("--paths", "core/mid/src/lib.rs")
check("dependents", t, "crates selected: 3 of 9", "mid_it_plain ", "mid_prop_plain_spec_crdt_4", "mid_std_large", "mid_other_target_large", "osis-top: top_exhaustive", "every scenario, 15 seeds from 7", "cargo test --locked --no-fail-fast", absent=["osis-base:", "quic_large_transfer ", "held-model:", "repro_big_large ", "mid_by_hand"])
check("replay line", t, "offset: 7 (replay this selection: tools/test_select.py --offset 7 --paths core/mid/src/lib.rs)")
check("substring filter", t, "--skip mid_it_plain_over_quic")
check("env", t, "OSIS_ORDER_START=7", "OSIS_CRDT_SEED=7", absent=["OSIS_ORDER_SEED=", "OSIS_ORDER_SEEDS="])

t = out("--paths", "core/test/model/src/lib.rs")
check("dev edge selects and stops", t, "crates selected: 4 of 9", "held-model: model_large", "osis-mid: mid_child_large mid_dup_large mid_helper_large mid_macro_large mid_renamed_large mid_single_large mid_via_helper_large\n", "osis-pathy: pathy_large",
      "osis-mid through dev dependencies only", "osis-fz: fz_large", absent=["osis-top:", "every scenario", "fzuser_large", "mid_it_plain ", "mid_prop_plain", "mid_std_large", "mid_other_target_large", "--skip model_large", "--skip mid_dup_large"])

# test-only edits select their own crate's properties in the same place (tests/ or src/), no dependent
t = out("--paths", "core/mid/tests/it/via.rs")
check("tests/ edit", t, "crates selected: 1 of 9: osis-mid", "test-only edits: the properties under its tests/", "mid_it_plain ", "mid_helper_large", "mid_single_large",
      absent=["mid_prop_plain_spec_crdt_4", "mid_cfg_test_large", "top_exhaustive", "every scenario"])
for f in ("core/mid/src/t.rs", "core/mid/src/t/inner.rs", "core/mid/src/t2.rs"):
    t = out("--paths", f)
    check(f"cfg(test) edit {f}", t, "crates selected: 1 of 9: osis-mid", "under its src/", "mid_cfg_test_large", "mid_prop_plain_spec_crdt_4", "mid_other_target_large", absent=["mid_it_plain ", "top_exhaustive", "every scenario"])
t = out("--paths", "core/mid/src/t.rs", "core/mid/tests/it/via.rs")
check("both targets", t, "under its src/ and tests/", "mid_cfg_test_large", "mid_it_plain ", absent=["top_exhaustive"])
for f, why in (("core/mid/src/t3.rs", "cfg(any(test, ..))"), ("core/mid/tests/it/read.rs", "read as text by a dependent"), ("core/mid/src/gone.rs", "not in the tree"),
               ("core/mid/build.rs", "outside tests/ and src/"), ("core/pathy/src/b.rs", "a #[path] crate")):
    t = out("--paths", f)
    check(f"not test-only: {why}", t, absent=["test-only"])
check("not test-only: carries on", out("--paths", "core/mid/src/t3.rs"), "top_exhaustive", "every scenario")
t = out("--paths", "core/mid/tests/it/via.rs", "core/mid/src/lib.rs")
check("test-only beside code: the code's selection", t, "crates selected: 3 of 9", "top_exhaustive", "mid_it_plain ", absent=["test-only"])
t = out("--paths", "core/mid/tests/it/via.rs", "core/test/model/src/lib.rs")
check("test-only beside a dev-reach of the same crate", t, "mid_it_plain ", "mid_helper_large", "model_large", absent=["top_exhaustive", "mid_cfg_test_large"])

t = out("--paths", "core/base/src/lib.rs")
check("low crate", t, "crates selected: 6 of 9", "(nearly everything", "base_prop_large", "fzuser_large", "base_inline_large", "base_after_comment_large", "top_exhaustive", "every scenario", absent=["leaf_large", "held-model:", "decoy_large"])

t = out("--paths", "core/base/testenv-known.txt")
check("pinned by policy.py", t, "selects nothing: core/base/testenv-known.txt (tools/policy.py", "crates touched: none", "nothing to run", absent=["base_prop_large"])

t = out("--paths", "core/base/testenv-known.txt", "core/leaf/src/lib.rs")
check("pinned beside code", t, "crates touched: osis-leaf", "crates selected: 1 of 9", "leaf_large", absent=["base_prop_large"])

t = out("--paths", "Cargo.lock")
check("workspace config", t, "crates selected: 9 of 9", "every crate", "leaf_large", "model_large", "not read: core/leaf/src/lib.rs:5")

t = out("--paths", "tools/x.sh")
check("tools", t, "selects nothing: tools/x.sh (the tools' own tests", "nothing to run")

t = out("--paths", "schema/core.osis")
check("schema file names its readers", t, "crates touched: osis-mid", "top_exhaustive")

t = out("--paths", "schema/orphan.osis", "schema/README.md")
check("schema without a reader", t, "schema/orphan.osis (no workspace crate reads it)", "schema/README.md (no crate, not classified", "nothing to run")

t = out("--paths", "core/test/tla/x.tla", "weird.txt")
check("outside any crate", t, "(core/test/tla/run.sh", "weird.txt (no crate, not classified", "nothing to run")

# a real diff: uses merge-base with origin/main and picks up untracked files
git("checkout", "-qb", "t")
write("core/leaf/src/lib.rs", PROP.format("leaf_large") + "// edit\n")
git("add", "-A")
git("commit", "-qm", "edit")
write("core/top/new.rs", "// new\n")
t = out()
check("diff from merge-base", t, "paths: 2", "crates touched: osis-leaf, osis-top", "leaf_large", "top_exhaustive")
# manifests changed in comments and blank lines only select nothing; a real manifest change does
with open("Cargo.toml", "a") as f:
    f.write("\n# a comment\n")
with open("core/mid/Cargo.toml", "a") as f:
    f.write("  # another\n")
t = out()
check("comment-only manifests", t, "selects nothing: Cargo.toml (TOML comments", "selects nothing: core/mid/Cargo.toml (TOML comments",
      "crates touched: osis-leaf, osis-top", absent=["every crate", "osis-mid"])
with open("core/mid/Cargo.toml", "a") as f:
    f.write("[features]\n")
check("a manifest change", out(), "crates touched: osis-leaf, osis-mid, osis-top")
git("checkout", "--", "Cargo.toml", "core/mid/Cargo.toml")

# --emit FILE: the gate's `build`, `check` and `run` lines appended to FILE, builds first, with the same
# packages and offset; the report still printed
emitted = os.path.abspath("emitted")
write(emitted, "kept\n")
# `rate:` lines replayed: a selected crate's and the sim's; an unselected crate's and a plain line not
write("tools/known_failures.txt", "osis-mid/m::mid_it_plain rate:OSIS_ORDER_SEED=5,OSIS_SYNC_START=1 issues/i.md p\nosis-leaf/leaf_large rate:OSIS_ORDER_SEED=5 issues/i.md p\n"
      "osis-mid/m::mid_prop_plain 1 issues/i.md p\nsim-sweep:two_nodes rate:9 issues/i.md p\n")
check("--emit report", out("--emit", emitted, "--paths", "core/mid/src/lib.rs"), "crates selected")
lines = open(emitted).read().splitlines()
kinds = [l.split(" ", 1)[0] for l in lines]
if kinds != ["kept", "build", "build", "check", "run", "run", "run", "run"]:
    print(f"FAIL --emit: line kinds {kinds}\n" + "\n".join(lines))
    fails = 1
check("--emit", "\n".join(lines), "build cargo test --locked -p osis-mid -p osis-top --tests --no-run", "build cargo build --locked --bin sim-sweep",
      "check python3 tools/test_select.py --listed mid_cfg_test_large mid_child_large ", "_RUNNER=" + test_select.RUNNER + " python3 tools/targets.py cargo test --locked --no-fail-fast ", " model_large top_exhaustive -- cargo", "cargo test --locked --quiet -p osis-mid -p osis-top --tests -- --list --ignored ",
      "run gate.properties env ", "OSIS_ORDER_START=7 ", "run gate.sim cargo run --locked --bin sim-sweep -- --seeds 15 --from 7",
      "run gate.replay printf 'gate: replay %s %s\\n' osis-mid/m::mid_it_plain rate:OSIS_ORDER_SEED=5,OSIS_SYNC_START=1 && env OSIS_ORDER_SEED=5 OSIS_SYNC_START=1 cargo test --locked --no-fail-fast -p osis-mid --tests -- --exact m::mid_it_plain --include-ignored",
      "run gate.replay printf 'gate: replay %s %s\\n' sim-sweep:two_nodes rate:9 && cargo run --locked --bin sim-sweep -- --seeds 1 --from 9 --only two_nodes",
      absent=["paths:", "crates selected", "osis-leaf", "mid_prop_plain 1"])
os.remove("tools/known_failures.txt")
write(emitted, "")
out("--emit", emitted, "--paths", "notes/a.md")
check("--emit nothing", open(emitted).read(), absent=["build", "run"])

# --listed: every wanted name must end a listed test's path; a filter matching nothing fails loudly
def listed(*a):
    return subprocess.run([sys.executable, TOOL, "--listed", *a], capture_output=True, text=True)
r = listed("a_large", "b_large", "--", "printf", "m::a_large: test\\nn::b_large: test\\n")
if r.returncode != 0:
    print(f"FAIL --listed all present: {r.stdout}{r.stderr}")
    fails = 1
r = listed("a_large", "gone_large", "--", "printf", "m::a_large: test\\nm::gone_large_x: test\\n")
if r.returncode != 1 or "gone_large is in no built test target" not in r.stdout or "a_large is in" in r.stdout:
    print(f"FAIL --listed missing: {r.returncode} {r.stdout}{r.stderr}")
    fails = 1
if listed("a_large", "--", "false").returncode != 1:
    print("FAIL --listed: a failing listing passed")
    fails = 1

# --all: every crate, whatever the diff
t = out("--all")
check("--all", t, "every crate (--all)", "crates selected: 9 of 9", "leaf_large", "model_large")

# closure, on edges in the order that once lost a dependent: y is reached by a dev edge first
via = {"x": [("y", {"dev"}, "x"), ("z", {"normal"}, "x")], "z": [("y", {"normal"}, "z")], "y": [("w", {"normal"}, "y")]}
if test_select.closure({"x"}, via) != dict.fromkeys(["x", "y", "z", "w"]):
    print("FAIL closure: a dev edge reached first stopped a normal edge")
    fails = 1
if test_select.closure({"x"}, {"x": [("y", {"dev"}, "x")], "y": [("w", {"normal"}, "y")]}) != {"x": None, "y": {"x"}}:
    print("FAIL closure: a dev edge carried on")
    fails = 1

os.chdir("/")
shutil.rmtree(d)
print("test_select: ok" if not fails else "test_select: FAILED")
sys.exit(fails)
