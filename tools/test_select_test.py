#!/usr/bin/env python3
"""Tests tools/test_select.py on a fabricated workspace in a throwaway repo. Exit 1 on a mismatch."""
import os, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_select

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_select.py")

# base <- mid <- top; model is only a dev-dependency of mid; osis-sim depends on mid; leaf depends on nothing.
CRATES = {
    "core/base": ("osis-base", ""),
    "core/mid": ("osis-mid", 'osis-base = { path = "../base" }\n[dev-dependencies]\nheld-model = { path = "../test/model" }\n'),
    "core/top": ("osis-top", 'osis-mid = { path = "../mid" }\n'),
    "core/test/model": ("held-model", ""),
    "core/test/sim": ("osis-sim", 'osis-mid = { path = "../../mid" }\n'),
    "core/leaf": ("osis-leaf", ""),
}
PROP = '#[test]\n#[ignore = "property"]\nfn {}() {{}}\n'


def write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def git(*a):
    subprocess.run(["git", *a], check=True, capture_output=True)


def out(*a):
    r = subprocess.run([sys.executable, TOOL, *a, "--offset", "7"] if "--paths" not in a else [sys.executable, TOOL, "--offset", "7", *a], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


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
# a size word in the middle, a repro, an example, a networking test: none are properties
write("core/mid/src/lib.rs", PROP.format("mid_prop_plain_spec_crdt_4") + PROP.format("quic_large_transfer") + PROP.format("repro_big_large") + "#[test]\nfn mid_quick() {}\n")
write("core/mid/tests/it/main.rs", PROP.format("mid_it_plain") + PROP.format("mid_it_plain_over_quic"))
write("core/top/src/lib.rs", PROP.format("top_exhaustive"))
write("core/test/model/src/lib.rs", PROP.format("model_large"))
write("core/test/sim/src/lib.rs", "")
write("core/leaf/src/lib.rs", PROP.format("leaf_large") + "macro_rules! t { ($n:ident) => { #[test]\n#[ignore]\nfn $n() {} } }\n")
for f in ("notes/a.md", "tools/x.sh", "schema/core.osis", "schema/README.md", "schema/orphan.osis"):
    write(f, "x\n")
write("core/mid/build.rs", '// reads "../../schema/core.osis"\n')
write("core/base/testenv-known.txt", "OSIS_ORDER_START\nOSIS_ORDER_SEEDS\nOSIS_ORDER_SEED\nOSIS_CRDT_SEED\n")
subprocess.run(["cargo", "metadata", "--format-version", "1"], check=True, capture_output=True)
git("init", "-q", "-b", "main")
git("config", "user.email", "t@t")
git("config", "user.name", "t")
git("add", "-A")
git("commit", "-qm", "init")

t = out("--paths", "notes/a.md")
check("notes only", t, "selects nothing: notes/a.md", "crates selected: 0 of 6", "nothing to run", absent=["cargo test"])

t = out("--paths", "core/mid/src/lib.rs")
check("dependents", t, "crates selected: 3 of 6", "osis-mid: mid_it_plain mid_prop_plain_spec_crdt_4", "osis-top: top_exhaustive", "every scenario, 15 seeds from 7", "cargo test --locked --no-fail-fast", absent=["osis-base:", "quic_large_transfer ", "held-model:", "repro_big_large "])
check("replay line", t, "offset: 7 (replay this selection: tools/test_select.py --offset 7 --paths core/mid/src/lib.rs)")
check("substring filter", t, "--skip mid_it_plain_over_quic")
check("env", t, "OSIS_ORDER_START=7", "OSIS_CRDT_SEED=7", absent=["OSIS_ORDER_SEED=", "OSIS_ORDER_SEEDS="])

t = out("--paths", "core/test/model/src/lib.rs")
check("dev edge selects and stops", t, "crates selected: 2 of 6", "held-model: model_large", "osis-mid:", absent=["osis-top:", "every scenario"])

t = out("--paths", "core/base/src/lib.rs")
check("low crate", t, "crates selected: 4 of 6", "(nearly everything", "base_prop_large", "base_inline_large", "base_after_comment_large", "top_exhaustive", "every scenario", absent=["leaf_large", "model_large", "decoy_large"])

t = out("--paths", "Cargo.lock")
check("workspace config", t, "crates selected: 6 of 6", "every crate", "leaf_large", "model_large", "not read: core/leaf/src/lib.rs:5")

t = out("--paths", "tools/x.sh")
check("tools", t, "selects nothing: tools/x.sh (the tools' own tests", "nothing to run")

t = out("--paths", "schema/core.osis")
check("schema file names its readers", t, "crates touched: osis-mid", "top_exhaustive")

t = out("--paths", "schema/orphan.osis", "schema/README.md")
check("schema without a reader", t, "schema/orphan.osis (no workspace crate reads it)", "schema/README.md (no crate, not classified", "nothing to run")

t = out("--paths", "core/test/tla/x.tla", "weird.txt")
check("outside any crate", t, "(core/test/tla/run.sh", "weird.txt (no crate, not classified", "nothing to run")

# a real diff: uses merge-base with main and picks up untracked files
git("checkout", "-qb", "t")
write("core/leaf/src/lib.rs", PROP.format("leaf_large") + "// edit\n")
git("add", "-A")
git("commit", "-qm", "edit")
write("core/top/new.rs", "// new\n")
t = out()
check("diff from merge-base", t, "paths: 2", "crates touched: osis-leaf, osis-top", "leaf_large", "top_exhaustive")

# --emit: the gate's `build` and `run` lines, builds first, with the same packages and offset
lines = out("--emit", "--paths", "core/mid/src/lib.rs").splitlines()
kinds = [l.split(" ", 1)[0] for l in lines]
if kinds != ["build", "build", "run", "run"]:
    print(f"FAIL --emit: line kinds {kinds}\n" + "\n".join(lines))
    fails = 1
check("--emit", "\n".join(lines), "build cargo test --locked -p osis-mid -p osis-top --tests --no-run", "build cargo build --locked --bin sim-sweep",
      "OSIS_ORDER_START=7 ", "cargo run --locked --bin sim-sweep -- --seeds 15 --from 7", absent=["paths:", "crates selected"])
check("--emit nothing", out("--emit", "--paths", "notes/a.md"), absent=["build", "run"])

# --all: every crate, whatever the diff
t = out("--all")
check("--all", t, "every crate (--all)", "crates selected: 6 of 6", "leaf_large", "model_large")

# closure, on edges in the order that once lost a dependent: y is reached by a dev edge first
via = {"x": [("y", {"dev"}), ("z", {"normal"})], "z": [("y", {"normal"})], "y": [("w", {"normal"})]}
if test_select.closure({"x"}, via) != {"x", "y", "z", "w"}:
    print("FAIL closure: a dev edge reached first stopped a normal edge")
    fails = 1
if test_select.closure({"x"}, {"x": [("y", {"dev"})], "y": [("w", {"normal"})]}) != {"x", "y"}:
    print("FAIL closure: a dev edge carried on")
    fails = 1

os.chdir("/")
shutil.rmtree(d)
print("test_select: ok" if not fails else "test_select: FAILED")
sys.exit(fails)
