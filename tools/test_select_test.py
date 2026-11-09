#!/usr/bin/env python3
"""Tests tools/test_select.py on a fabricated workspace in a throwaway repo. Exit 1 on a mismatch."""
import os, shutil, subprocess, sys, tempfile

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
PROP = '#[test]\n#[ignore = "tier 2"]\nfn {}() {{}}\n'


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
write("core/base/src/lib.rs", PROP.format("base_prop_large"))
# a size word in the middle, a repro, an example, a networking test: none are properties
write("core/mid/src/lib.rs", PROP.format("mid_prop_tier2_spec_crdt_4") + PROP.format("quic_large_transfer") + PROP.format("repro_big_large") + "#[test]\nfn mid_quick() {}\n")
write("core/mid/tests/it/main.rs", PROP.format("mid_it_plain") + PROP.format("mid_it_plain_over_quic"))
write("core/top/src/lib.rs", PROP.format("top_exhaustive"))
write("core/test/model/src/lib.rs", PROP.format("model_large"))
write("core/test/sim/src/lib.rs", "")
write("core/leaf/src/lib.rs", PROP.format("leaf_large"))
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
check("dependents", t, "crates selected: 3 of 6", "osis-mid: mid_it_plain mid_prop_tier2_spec_crdt_4", "osis-top: top_exhaustive", "every scenario, 15 seeds from 7", "tools/heavy", absent=["osis-base:", "quic_large_transfer ", "held-model:", "repro_big_large "])
check("substring filter", t, "--skip mid_it_plain_over_quic")
check("env", t, "OSIS_ORDER_START=7", "OSIS_CRDT_SEED=7", absent=["OSIS_ORDER_SEED=", "OSIS_ORDER_SEEDS="])

t = out("--paths", "core/test/model/src/lib.rs")
check("dev edge selects and stops", t, "crates selected: 2 of 6", "held-model: model_large", "osis-mid:", absent=["osis-top:", "every scenario"])

t = out("--paths", "core/base/src/lib.rs")
check("low crate", t, "crates selected: 4 of 6", "(nearly everything", "base_prop_large", "top_exhaustive", "every scenario", absent=["leaf_large", "model_large"])

t = out("--paths", "Cargo.lock")
check("workspace config", t, "crates selected: 6 of 6", "every crate", "leaf_large", "model_large")

t = out("--paths", "tools/x.sh")
check("tools", t, "selects nothing: tools/x.sh (the tools' own tests", "nothing to run")

t = out("--paths", "schema/core.osis")
check("schema file names its readers", t, "crates touched: osis-mid", "top_exhaustive")

t = out("--paths", "schema/orphan.osis", "schema/README.md")
check("schema without a reader", t, "schema/orphan.osis (no workspace crate reads it)", "schema/README.md (no crate, not classified", "nothing to run")

t = out("--paths", "core/test/tla/x.tla", "weird.txt", "app/a.rs", "libs/kit/b.rs")
check("outside any crate", t, "(core/test/tla/run.sh", "weird.txt (no crate, not classified", "app/a.rs (the gate's GUI steps", "libs/kit/b.rs (the gate's GUI steps", "nothing to run")

# a real diff: uses merge-base with main and picks up untracked files
git("checkout", "-qb", "t")
write("core/leaf/src/lib.rs", PROP.format("leaf_large") + "// edit\n")
git("add", "-A")
git("commit", "-qm", "edit")
write("core/top/new.rs", "// new\n")
t = out()
check("diff from merge-base", t, "paths: 2", "crates touched: osis-leaf, osis-top", "leaf_large", "top_exhaustive")

os.chdir("/")
shutil.rmtree(d)
print("test_select: ok" if not fails else "test_select: FAILED")
sys.exit(fails)
