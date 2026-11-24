#!/usr/bin/env python3
"""Tests tools/policy.py (doc_refs.py, code_refs.py and spec_map.py with it) by planting violations, at least one
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

CHECKERS = ("policy.py", "doc_refs.py", "code_refs.py", "spec_map.py", "rustsrc.py", "gate_failures.py")
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

ISSUE = "issues/sync-unbuilt.md"
V = "OSIS" + "_"  # split, so this file names no variable env_vars would count
# (path, old text or None to append, new text)
PLANTS = [
    # lints, test = false, android, dependencies
    ("core/base/Cargo.toml", "[lints]\nworkspace = true\n", ""),
    ("core/test/crdt-model/Cargo.toml", 'unsafe_code = "forbid"', 'unsafe_code = "deny"'),
    ("core/test/held-model/Cargo.toml", "crdt-model.workspace = true\n", "crdt-model.workspace = true\nosis-base.workspace = true\n"),
    ("app/android/Cargo.toml", 'unsafe_code = "deny"', 'unsafe_code = "allow"'),
    ("core/test/crdt-model/src/lib.rs", None, "\n#[cfg(test)]\nmod planted {}\n"),
    ("core/schema/src/lib.rs", None, "\n/// ```\n/// planted();\n/// ```\nfn planted_doc() {}\n"),
    ("core/schema/src/bin/osis-schema-gen.rs", None, "\n#[cfg(test)]\nmod planted {}\n"),
    ("app/android/src/gpu.rs", None, "\nfn planted() {\n    // SAFETY: planted\n    unsafe { planted() }\n}\n"),
    ("core/crypto/Cargo.toml", "[dependencies]\n", '[dependencies]\nplanted-dep = "1"\n'),
    # env_vars
    ("core/base/src/format.rs", None, f'\nconst _P: &str = "{V}PROBE_PLANTED";\n'),
    ("tools/gate.sh", None, f"\n# {V}PLANTED_UNKNOWN\n"),
    ("core/base/testenv-known.txt", None, f"{V}PLANTED_UNUSED\n"),
    # dispute_types
    ("core/store/src/lib.rs", None, "\nfn planted(x: X) { x.disputes(); }\n"),
    ("core/commit/src/lib.rs", None, "\nfn planted(x: X) { x.set_trust(&t); }\n"),
    ("core/keys/src/lib.rs", None, "\nfn planted(_: DisputeInfo) {}\n"),
    ("libs/chat/src/lib.rs", None, "\nfn near_miss(x: X) { x.disputes(); }\n"),  # outside core: allowed
    # real_lan_tests
    ("core/sync/tests/it/flows.rs", None, "\nfn planted_lan() { Lan::bind(4242); }\n"
     "fn planted_bare() { let _ = Config { runtime: Runtime::Own, x: 1 }; }\n"
     "fn planted_default() { let mut cfg = Config::default(); cfg.runtime = Runtime::Tokio; }\n"
     "fn near_miss() { Lan::bind(0); Lan::bind(s.port()); }\n"),
    ("core/transport/src/lib.rs", None, "\n#[cfg(test)]\nmod planted_lan { fn f() { Lan::bind(4243); } }\n"),
    ("cli/tests/it/cli.rs", None, "\nfn planted_cli() { Command::new(OSIS).arg(\"x\"); }\n"),
    # peer_ticks
    ("core/engine/tests/it/caches.rs", None, "\nfn planted(p: P) { p.engine.tick(); }\n"),
    ("core/engine/tests/it/covered.rs", None, "\nfn planted(myself: P) { myself.engine.reexamine(); }\n"),
    ("core/engine/tests/it/flows.rs", None, "\nfn near_miss(&self) { self.engine.tick(); }\n"),
    # test_copies, checked_bytes
    ("core/crypto/src/lib.rs", None, "\nfn planted(x: X) { x.test_copy(); }\n"),
    ("core/perm/src/lib.rs", None, "\nfn planted(b: B) { let _ = Checked(b); }\n"),
    ("core/engine/src/apply/mod.rs", None, "\nfn planted(b: B) { let _ = Checked::verified(b); }\n"),
    # known_failures
    ("tools/known_failures.txt", None, f"osis-engine/planted::no_such_test_fn - {ISSUE} x\nsim-sweep:no_such_scenario - {ISSUE} x\n"
     f"planted::a - issues/planted-missing.md x\nplanted::b - {ISSUE} (\n"),
    # test_cost
    ("tools/test_cost.txt", None, "planted-crate/it 3\nosis-base/planted 0\n"),
    # row_prefixes
    ("core/sync/src/life.rs", None, '\nconst PLANTED_ROW: &[u8] = b"zq/";\nconst PLANTED_SUB: &[u8] = b"zq/x";\nfn planted_inline() -> &\'static [u8] { b"zr/k" }\n'),
    # record_tags
    ("core/sync/src/store/rows.rs", "    pub(crate) const REFUSED: u8 = b'r';", "    pub(crate) const REFUSED: u8 = b'r';\n    pub(crate) const PLANTED_TAG: u8 = b'r';"),
    ("core/sync/src/life.rs", None, "\nfn planted_tag(t: &mut T) { t.record_put_row(&rec, b'z', &s, b\"\", Vec::new()); }\n"),
    # pinned_seeds
    ("core/sync/tests/it/faults.rs", None, "\nfn planted_seed() { let _ = World::new(77); let _ = world(0, 3); let _ = w.history(5); }\n"),
    # doc_refs
    ("notes/build.md", None, "\nSee notes/no-such-planted.md and notes/gate.md, Planted Nonexistent Section.\n"),
    # code_refs: a stale name, a listed name now in the code, a duplicate listed line
    ("notes/build.md", None, "\nSee `Engine::planted_gone_fn` and `planted_listed_name`.\n"),
    ("tools/code_refs_allow.txt", None, "planted_listed_name  placeholder\nEngine  placeholder\nplanted_listed_name  placeholder\n"),
    # files made after the `git add`, untracked: cited, they count (a near miss)
    ("core/base/src/planted_fresh.rs", None, "fn planted_fresh_fn() {}\n"),
    # code_refs in doc comments: a name only a comment keeps, a type's member it lacks
    ("core/base/src/planted_doc.rs", None, "/// `planted_doc_gone` and `PlantedDoc::gone`.\npub struct PlantedDoc {\n    pub here: u8, // planted_doc_gone\n}\n"),
    ("notes/planted-fresh.md", None, "# Fresh\n> Summary: planted.\n"),
    ("notes/build.md", None, "\nSee notes/planted-fresh.md, `core/base/src/planted_fresh.rs` and `planted_fresh_fn`.\n"),
    # spec_anchors: a test citing nothing, an anchor naming no rule
    ("core/base/src/planted_spec.rs", None, "#[test]\nfn planted_uncited() {}\n\n// spec/wire.md §4 (planted no such anchor)\n#[test]\nfn planted_stray() {}\n"),
    # registries: a number taken twice; a marker off its heading; an unmarked list after (a near miss)
    ("notes/planted-registry.md", None, "# Planted\n> Summary: planted.\n\n## Open\n<!-- registry -->\n1. a\n2. b\n2. c\n\n## Other\n5. x\n1. y\ntext\n<!-- registry -->\n"),
    # union_lists: a duplicate line in each union-merged list, a key listed twice, a union list unchecked
    ("core/base/testenv-known.txt", None, f"{V}BENCH_MS\n"),
    ("tools/known_failures.txt", None, f"osis-engine/planted::no_such_test_fn - {ISSUE} x\n"),
    (".gitattributes", None, "notes/time-limits.md merge=union\n"),
]

EXPECT = [  # regexes the output must hold
    r"core/base: needs \[lints\] workspace = true",
    r"core/test/crdt-model: model needs \[lints.rust\] unsafe_code",
    r"core/test/held-model: depends on workspace crate `osis-base`",
    r"app/android: needs the workspace lints",
    r"core/test/crdt-model: \[lib\] test = false but src/ has #\[cfg\(test\)\]",
    r"core/schema/src/lib\.rs: doctest = false but it has a doctest",
    r"core/schema: bin osis-schema-gen has test = false",
    r"app/android: 2 unsafe blocks",
    r"dependency `planted-dep` \(core/crypto\) has no line",
    r"OSIS[_]PROBE_PLANTED is a throwaway probe",
    r"OSIS[_]PLANTED_UNKNOWN is read but not in",
    r"OSIS[_]PLANTED_UNUSED is in core/base/testenv-known\.txt but nothing reads it",
    r"core/store/src/lib\.rs: calls a dispute query",
    r"core/commit/src/lib\.rs: calls a dispute query",
    r"core/keys/src/lib\.rs: names the trust store",
    r"core/sync/tests/it/flows\.rs: Lan::bind in a test on a fixed port: fn planted_lan",
    r"core/sync/tests/it/flows\.rs: a test node from a bare Config is on the real LAN: Config \{ runtime",
    r"core/sync/tests/it/flows\.rs: a test node from a bare Config is on the real LAN: let mut cfg",
    r"core/transport/src/lib\.rs: Lan::bind in a test on a fixed port",
    r"cli/tests/it/cli\.rs: runs osis without --no-lan: fn planted_cli",
    r"core/engine/tests/it/caches\.rs:\d+: engine\.tick\(\)",
    r"core/engine/tests/it/covered\.rs:\d+: engine\.tick\(\)",
    r"core/crypto/src/lib\.rs:\d+: a world-copy hook outside tests",
    r"core/perm/src/lib\.rs:\d+: osis_crdt::Checked built outside",
    r"core/engine/src/apply/mod\.rs: 2 Checked::verified uses, want 1",
    r"osis-engine/planted::no_such_test_fn: no such test in osis-engine",
    r"planted::a: want CRATE/PATH",
    r"sim-sweep:no_such_scenario: no such sim scenario",
    r"issues/planted-missing\.md: no such issue file",
    r"bad pattern '\('",
    r"tools/test_cost\.txt: planted-crate/it: want CRATE/NAME, CRATE a workspace package",
    r"tools/test_cost\.txt:\d+: want `CRATE/NAME G` \(G over 0\), got 'osis-base/planted 0'",
    r"sync store: row key 'zq/x' \(core/sync/src/life\.rs:\d+ PLANTED_SUB\) and 'zq/' \(core/sync/src/life\.rs:\d+ PLANTED_ROW\) collide|sync store: row key 'zq/' \(core/sync/src/life\.rs:\d+ PLANTED_ROW\) and 'zq/x' \(core/sync/src/life\.rs:\d+ PLANTED_SUB\) collide",
    r"core/sync/src/life\.rs: a row key `b\"zr/\.\.\.` written as a literal",
    r"core/sync/src/store/rows\.rs: record tags REFUSED and PLANTED_TAG are both b'r'",
    r"core/sync/src/life\.rs: a record row written with a literal tag",
    r"core/sync/tests/it/faults\.rs:\d+: World::new\(77, \.\.\) pins a seed",
    r"notes/build\.md:\d+: notes/no-such-planted\.md does not exist",
    r"notes/build\.md:\d+: notes/gate\.md, \"planted nonexistent section\": no such section",
    r"notes/build\.md:\d+: `planted_gone_fn`: no such name",
    r"core/base/src/planted_doc\.rs:1: `planted_doc_gone`: no such name",
    r"core/base/src/planted_doc\.rs:1: `PlantedDoc::gone`: no `gone` in the code's `PlantedDoc`",
    r"tools/code_refs_allow\.txt:\d+: `Engine` is in the code",
    r"tools/code_refs_allow\.txt:\d+: `planted_listed_name` listed twice",
    r"tools/code_refs_allow\.txt:\d+: duplicate of line \d+",
    r"core/base/testenv-known\.txt:\d+: duplicate of line \d+",
    r"tools/known_failures\.txt:\d+: duplicate of line \d+",
    r"\.gitattributes: notes/time-limits\.md has merge=union but no stale-line check",
    r"notes/planted-registry\.md:\d+: registry item 2 after 2 in ## Open",
    r"notes/planted-registry\.md:\d+: <!-- registry --> belongs on the line under a section's heading",
    r"spec_map: uncited test: \S*planted_uncited",
    r"spec_map: stray anchor: `\S*planted_stray`",
]
ABSENT = [  # near misses: what the plants show must not be reported
    r"libs/chat/src/lib\.rs: calls a dispute query",
    r"core/sync/tests/it/flows\.rs: Lan::bind in a test on a fixed port: fn near_miss",
    r"core/engine/tests/it/flows\.rs:\d+: engine",
    r"core/transport/src/lib\.rs:\d+: `",
    r"notes/build\.md:\d+: `eager",
    r"complaints/planted",
    r"Account\.tla",
    r"faults\.rs:\d+: (world|history)\(",
    r"planted.fresh",
    r"registry item 1 after 5",
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
            # an appended plant needs no file: a deleted fixture file is planted afresh
            text = open(p).read() if old is not None or os.path.exists(p) else ""
            os.makedirs(os.path.dirname(p), exist_ok=True)
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
