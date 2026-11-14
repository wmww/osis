#!/usr/bin/env python3
"""Tests tools/policy.py (dead_pub.py and doc_refs.py with it) by planting violations, at least one
per check, in a copy of the working tree and asserting each is reported, and a near miss is not;
and that `rustsrc.has`'s prefilter never rejects a text its pattern matches. A check that silently
stops finding violations would otherwise pass every gate.
Usage: tools/policy_test.py [--tools REV]   (REV: run REV's checker scripts on the same plants, to
show a plant is valid against a known-good version; exit 1 on a mismatch)"""
import os, re, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)
from rustsrc import has

CHECKERS = ("policy.py", "dead_pub.py", "doc_refs.py", "rustsrc.py", "gate_failures.py")
fails = 0


def fail(msg):
    global fails
    print(f"FAIL {msg}")
    fails = 1


# has(): the prefilter (the pattern minus its `\b`s) must match wherever the pattern does
HAS_CASES = [  # (pattern, text that matches it)
    (r"\bfoo\b|\bbar\(", "x bar("),
    (r"(?<!\bself)\.engine\.tick\(", "myself.engine.tick("),  # a `\b` in a negative lookbehind
    (r"(?!\bx)y", "y"),
    (r"^\bfoo", "foo"),
    (r"a[\b]c", "a\bc"),  # a backspace in a class
    (r"\\b\b q", "\\b q"),  # a literal backslash before b
    (r"\.(set_trust|disputes)\s*\(|\bTrust\s*\{", "x.disputes ("),
]
for pat, text in HAS_CASES:
    if not re.search(pat, text):
        fail(f"has case {pat!r}: the case itself does not match")
    elif not has(re.compile(pat), text):
        fail(f"has({pat!r}, {text!r}): the prefilter rejected a match")
if has(re.compile(r"\bTrust\s*\{"), "NoTrust {"):
    fail("has: matched where the pattern does not")

ISSUE = "issues/paired-peer-runtime-flake.md"
V = "OSIS" + "_"  # split, so this file names no variable env_vars would count
# (path, old text or None to append, new text)
PLANTS = [
    # unsafe, lints, test = false, crate roots, android, dependencies
    ("core/base/src/ids.rs", None, "\nfn planted_unsafe() { unsafe {} }\n"),
    ("core/base/Cargo.toml", "[lints]\nworkspace = true\n", ""),
    ("core/test/crdt-model/Cargo.toml", 'unsafe_code = "forbid"', 'unsafe_code = "deny"'),
    ("core/test/held-model/Cargo.toml", "crdt-model.workspace = true\n", "crdt-model.workspace = true\nosis-base.workspace = true\n"),
    ("app/android/Cargo.toml", 'unsafe_code = "deny"', 'unsafe_code = "allow"'),
    ("core/test/crdt-model/src/lib.rs", None, "\n#[cfg(test)]\nmod planted {}\n"),
    ("core/schema/src/lib.rs", None, "\n/// ```\n/// planted();\n/// ```\nfn planted_doc() {}\n"),
    ("core/schema/src/bin/osis-schema-gen.rs", None, "\n#[cfg(test)]\nmod planted {}\n"),
    ("core/label/src/lib.rs", "#![forbid(unsafe_code)]", ""),
    ("app/android/src/gpu.rs", None, "\nfn planted() {\n    // SAFETY: planted\n    unsafe { planted() }\n}\n"),
    ("core/crypto/Cargo.toml", "[dependencies]\n", '[dependencies]\nplanted-dep = "1"\n'),
    # env_vars
    ("core/base/src/format.rs", None, f'\nconst _P: &str = "{V}PROBE_PLANTED";\n'),
    ("tools/gate.sh", None, f"\n# {V}PLANTED_UNKNOWN\n"),
    ("core/base/testenv-known.txt", None, f"{V}PLANTED_UNUSED\n"),
    # host_blind
    ("core/host/Cargo.toml", "[dependencies]\n", "[dependencies]\nosis-engine.workspace = true\n"),
    ("core/host/src/lib.rs", None, "\nuse osis_crypto::OpenKey;\nuse osis_proto::*;\nuse osis_label::{blob_id, planted_label};\n"),
    ("core/node/src/lib.rs", None, "\nuse osis_host::PlantedHost;\n"),
    # dispute_types
    ("core/crdt/src/lib.rs", None, "\nuse osis_perm::trust::Planted;\n"),
    ("core/store/src/lib.rs", None, "\nfn planted(x: X) { x.disputes(); }\n"),
    ("core/commit/src/lib.rs", None, "\nfn planted() { let _ = Dispute { }; }\n"),
    ("core/keys/src/lib.rs", None, "\nfn planted(_: DisputeInfo) {}\n"),
    ("libs/chat/src/lib.rs", None, "\nuse osis_perm::Trust;\n"),
    ("libs/chat/src/lib.rs", None, "\nfn near_miss(x: X) { x.disputes(); }\n"),  # outside core: allowed
    # real_lan_tests
    ("core/node/tests/it/awaits.rs", None, "\nfn planted_lan() { Lan::bind(4242); }\n"
     "fn planted_bare() { let _ = Config { runtime: Runtime::Own, x: 1 }; }\n"
     "fn planted_default() { let mut cfg = Config::default(); cfg.runtime = Runtime::Tokio; }\n"
     "fn near_miss() { Lan::bind(0); Lan::bind(s.port()); }\n"),
    ("core/transport/src/lib.rs", None, "\n#[cfg(test)]\nmod planted_lan { fn f() { Lan::bind(4243); } }\n"),
    ("cli/tests/it/cli.rs", None, "\nfn planted_cli() { Command::new(OSIS).arg(\"x\"); }\n"),
    # peer_ticks
    ("core/node/tests/it/caches.rs", None, "\nfn planted(p: P) { p.engine.tick(); }\n"),
    ("core/node/tests/it/compaction.rs", None, "\nfn planted(myself: P) { myself.engine.reexamine(); }\n"),
    ("core/node/tests/it/corrupt.rs", None, "\nfn near_miss(&self) { self.engine.tick(); }\n"),
    # test_copies, checked_bytes
    ("core/crypto/src/lib.rs", None, "\nfn planted(x: X) { x.test_copy(); }\n"),
    ("core/perm/src/lib.rs", None, "\nfn planted(b: B) { let _ = Checked(b); }\n"),
    ("core/engine/src/apply/mod.rs", None, "\nfn planted(b: B) { let _ = Checked::verified(b); }\n"),
    # known_failures
    ("tools/known_failures.txt", None, f"planted::no_such_test_fn - {ISSUE} x\nsim-sweep:no_such_scenario - {ISSUE} x\n"
     f"planted::a - issues/planted-missing.md x\nplanted::b - {ISSUE} (\n"),
    # ended_names, in each kind of file it reads; the last without a final newline
    ("core/base/src/hash.rs", None, "\n// the ended_things here\n"),
    ("schema/app.osis", None, "\n# EndedIn\n"),
    ("tools/prune-incremental.sh", None, "\n# Status::Ended\n"),
    ("core/test/tla/sync/MC.tla", None, "\n\\* NoLeakEnded"),
    # doc_refs
    ("notes/build.md", None, "\nSee notes/no-such-planted.md and notes/gate.md, Planted Nonexistent Section.\n"),
    # dead_pub
    ("core/crdt/src/stream.rs", None, "\npub fn planted_dead_fn() {}\npub fn planted_test_only() {}\npub struct PlantedType;\n"
     "impl PlantedType {}\npub fn planted_live() {}\n#[cfg(test)]\nmod planted_t { fn f() { super::planted_test_only(); } }\n"),
    ("core/perm/src/lib.rs", None, "\nfn planted_user() { osis_crdt::planted_live(); }\n"),
    ("tools/dead_pub_allow.txt", None, "osis-crdt::not_a_planted_item  test hook\n"),
    # union_lists: a duplicate line in each union-merged list, a key listed twice, a union list unchecked
    ("tools/dead_pub_allow.txt", None, "osis-crdt::not_a_planted_item  test hook\nosis-crdt::not_a_planted_item  table\n"),
    ("core/base/testenv-known.txt", None, f"{V}BENCH_MS\n"),
    ("tools/known_failures.txt", None, f"planted::no_such_test_fn - {ISSUE} x\n"),
    (".gitattributes", None, "notes/time-limits.md merge=union\n"),
]

EXPECT = [  # regexes the output must hold
    r"core/base/src/ids\.rs:\d+: unsafe code",
    r"core/base: needs \[lints\] workspace = true",
    r"core/test/crdt-model: model needs \[lints.rust\] unsafe_code",
    r"core/test/held-model: depends on workspace crate `osis-base`",
    r"app/android: needs the workspace lints",
    r"core/test/crdt-model: \[lib\] test = false but src/ has #\[cfg\(test\)\]",
    r"core/schema/src/lib\.rs: doctest = false but it has a doctest",
    r"core/schema: bin osis-schema-gen has test = false",
    r"core/label/src/lib\.rs: crate root lacks #!\[forbid\(unsafe_code\)\]",
    r"app/android: 2 unsafe blocks",
    r"dependency `planted-dep` \(core/crypto\) has no line",
    r"OSIS[_]PROBE_PLANTED is a throwaway probe",
    r"OSIS[_]PLANTED_UNKNOWN is read but not in",
    r"OSIS[_]PLANTED_UNUSED is in core/base/testenv-known\.txt but nothing reads it",
    r"core/host/Cargo\.toml: dependencies osis-engine is not one hosting may use",
    r"core/host/src/lib\.rs: names OpenKey",
    r"core/host/src/lib\.rs: osis_proto::\* is not for the host",
    r"core/host/src/lib\.rs: osis_crypto::OpenKey is not on the host's allowlist",
    r"core/host/src/lib\.rs: osis_label::planted_label is not on the host's allowlist",
    r"core/node/src/lib\.rs: osis_host::PlantedHost is not the host's public surface",
    r"core/crdt/src/lib\.rs: names osis_perm::trust::Planted",
    r"core/store/src/lib\.rs: calls a dispute query",
    r"core/commit/src/lib\.rs: calls a dispute query",
    r"core/keys/src/lib\.rs: names the trust store",
    r"libs/chat/src/lib\.rs: names osis_perm::Trust",
    r"core/node/tests/it/awaits\.rs: Lan::bind in a test on a fixed port: fn planted_lan",
    r"core/node/tests/it/awaits\.rs: a test node from a bare Config is on the real LAN: Config \{ runtime",
    r"core/node/tests/it/awaits\.rs: a test node from a bare Config is on the real LAN: let mut cfg",
    r"core/transport/src/lib\.rs: Lan::bind in a test on a fixed port",
    r"cli/tests/it/cli\.rs: runs osis without --no-lan: fn planted_cli",
    r"core/node/tests/it/caches\.rs:\d+: engine\.tick\(\)",
    r"core/node/tests/it/compaction\.rs:\d+: engine\.tick\(\)",
    r"core/crypto/src/lib\.rs:\d+: a world-copy hook outside tests",
    r"core/perm/src/lib\.rs:\d+: osis_crdt::Checked built outside",
    r"core/engine/src/apply/mod\.rs: 2 Checked::verified uses, want 1",
    r"planted::no_such_test_fn: no such test",
    r"sim-sweep:no_such_scenario: no such sim scenario",
    r"issues/planted-missing\.md: no such issue file",
    r"bad pattern '\('",
    r"core/base/src/hash\.rs:\d+: `ended_things`",
    r"schema/app\.osis:\d+: `EndedIn`",
    r"tools/prune-incremental\.sh:\d+: `Status::Ended`",
    r"core/test/tla/sync/MC\.tla:\d+: `NoLeakEnded`",
    r"notes/build\.md:\d+: notes/no-such-planted\.md does not exist",
    r"notes/build\.md:\d+: notes/gate\.md, \"planted nonexistent section\": no such section",
    r"pub fn osis-crdt::planted_dead_fn is used only",
    r"pub fn osis-crdt::planted_test_only is used only",
    r"pub struct osis-crdt::PlantedType is used only",
    r"tools/dead_pub_allow\.txt: osis-crdt::not_a_planted_item is no longer dead",
    r"tools/dead_pub_allow\.txt:\d+: duplicate of line \d+",
    r"tools/dead_pub_allow\.txt:\d+: `osis-crdt::not_a_planted_item` listed twice with different reasons",
    r"core/base/testenv-known\.txt:\d+: duplicate of line \d+",
    r"tools/known_failures\.txt:\d+: duplicate of line \d+",
    r"\.gitattributes: notes/time-limits\.md has merge=union but no stale-line check",
]
ABSENT = [  # near misses: what the plants show must not be reported
    r"libs/chat/src/lib\.rs: calls a dispute query",
    r"core/node/tests/it/awaits\.rs: Lan::bind in a test on a fixed port: fn near_miss",
    r"core/node/tests/it/corrupt\.rs:\d+: engine",
    r"osis-crdt::planted_live",
]


def main():
    args = sys.argv[1:]
    rev = args[1] if args[:1] == ["--tools"] and len(args) == 2 else None
    if args and not rev:
        print(__doc__)
        return 2
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT, check=True,
                           capture_output=True).stdout.decode().split("\0")
    with tempfile.TemporaryDirectory(prefix="policy-test-") as d:
        for f in files:
            if f and os.path.isfile(os.path.join(ROOT, f)) and not os.path.islink(os.path.join(ROOT, f)):
                os.makedirs(os.path.dirname(os.path.join(d, f)), exist_ok=True)
                shutil.copyfile(os.path.join(ROOT, f), os.path.join(d, f))
        if rev:
            for c in CHECKERS:
                text = subprocess.run(["git", "show", f"{rev}:tools/{c}"], cwd=ROOT, check=True, capture_output=True).stdout
                open(os.path.join(d, "tools", c), "wb").write(text)

        def policy():
            r = subprocess.run([sys.executable, "-B", "tools/policy.py"], cwd=d, capture_output=True, text=True)
            return r.returncode, r.stdout + r.stderr

        git = lambda *a: subprocess.run(["git", *a], cwd=d, check=True, capture_output=True)
        git("init", "-q")
        git("add", "-A")  # doc_refs reads `git ls-files`
        # the gate runs policy.py on the tree itself just before
        code, out = policy() if rev else (0, "")
        if code != 0:
            fail(f"the unplanted copy fails policy.py:\n{out}")
        for path, old, new in PLANTS:
            p = os.path.join(d, path)
            text = open(p).read()
            if old is None:
                text += new
            elif text.count(old) != 1:
                fail(f"plant {path}: {old!r} is not there once")
                continue
            else:
                text = text.replace(old, new)
            open(p, "w").write(text)
        code, out = policy()
        if code == 0:
            fail("policy.py passed the planted tree")
        for e in EXPECT:
            if not re.search(e, out):
                fail(f"not reported: {e}")
        for e in ABSENT:
            if re.search(e, out):
                fail(f"reported a near miss: {e}")
        if fails:
            print(out)
    print("policy_test: " + ("FAILED" if fails else f"ok, {len(EXPECT)} planted violations found, {len(ABSENT)} near misses passed"))
    return fails


if __name__ == "__main__":
    sys.exit(main())
