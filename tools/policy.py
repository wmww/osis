#!/usr/bin/env python3
"""Policy checks (notes/gate.md, Policy checks), each failure naming its rule: workspace lints on
(so the compiler forbids unsafe; app/android denies it and keeps its one block), every external
dependency has its line in notes/architecture.md §5, no target marked `test = false` /
`doctest = false` has tests that would silently not run, held-model depends only on crdt-model and roles-model,
core/base/testenv-known.txt lists exactly the `OSIS_*` variables the sources name (`env_vars`),
dispute queries stay in their places (`dispute_types`), no test binds the real LAN port or announces on the
real LAN (`real_lan_tests`), a test peer ticks through its wake (`peer_ticks`), world copies stay
test-only (`test_copies`), only the engine's `apply::checked` vouches for checked delta bytes
(`checked_bytes`), signature verdicts are read back only where kept (`kept_verdicts`), sync keeps
no hashed collection (`sync_hashed`), sync's tests pin no harness seed (`pinned_seeds`),
tools/known_failures.txt names existing issues, tests and valid patterns (`known_failures`),
tools/test_cost.txt's lines are well formed and name workspace packages (`test_cost`), an
`#[ignore = "..."]` naming an issue names an existing issues/ file (`ignore_issues`),
union-merged lists have no duplicate and a stale-line check (`union_lists`), a notes section
marked `<!-- registry -->` numbers its items uniquely and increasingly (`registries`), store row keys and sync's
record tags are distinct and never literals (`row_prefixes`, `record_tags`), every pointer into
notes/, issues/ or spec/ names an existing file and section (tools/doc_refs.py), and every code name
notes/ and issues/ cite in backticks exists (tools/code_refs.py), and every test cites the spec and every
anchor names a rule (`spec_anchors`: tools/spec_map.py --uncited --gaps), and no text uses a removed
concept's word (`dead_words`).
Usage: python3 tools/policy.py [--baseline [REF]]   (every workspace member, the GUI's included;
vendored crates under libs/kit/patches/ are not ours and are skipped; exit 1 on any violation).
--baseline prints and fails on only the violations REF (default origin/main) does not have, matched
by message with line numbers dropped; REF's own policy runs on its tree, its output cached per commit
under target/policy-baseline/."""
import collections, functools, glob, multiprocessing, os, re, shutil, stat, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_refs, doc_refs, gate_failures, spec_map
from rustsrc import ROOT, has, members as workspace_members, read, rs_files, toml as load

errs = []
ws = load(os.path.join(ROOT, "Cargo.toml"))
internal = {n for n, d in ws["workspace"]["dependencies"].items() if isinstance(d, dict) and "path" in d}
members = sorted(workspace_members())


def code(text):
    """`text` without its `//` comments."""
    return re.sub(r"//[^\n]*", "", text)


@functools.cache
def code_of(path):
    """`path`'s text without its `//` comments, made once per run."""
    return code(read(path))


CODE_TOPS = ("core", "cli", "libs", "app")


@functools.cache
def all_files():
    """(path, path from the root) of every file under CODE_TOPS, schema/ and tools/, not under
    target/ or vendored patches/: the one walk every check filters."""
    out = []
    for top in CODE_TOPS + ("schema", "tools"):
        for dirpath, dirs, files in os.walk(os.path.join(ROOT, top)):
            dirs[:] = sorted(d for d in dirs if d not in ("target", "patches"))
            for f in sorted(files):
                out.append((os.path.join(dirpath, f), os.path.relpath(os.path.join(dirpath, f), ROOT)))
    return out


def walk(tops, exts):
    """The files of `all_files` under the `tops` dirs ending in one of `exts`."""
    tops = tuple(t + "/" for t in tops)
    return [(p, rel) for p, rel in all_files() if rel.startswith(tops) and rel.endswith(exts)]

arch = open(os.path.join(ROOT, "notes/architecture.md")).read()
allow = arch.split("## 5. Dependency allowlist", 1)[-1].split("\n## ", 1)[0]

def dep_tables(manifest):
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield manifest.get(key, {})
    for t in manifest.get("target", {}).values():
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield t.get(key, {})

# app/android's unsafe blocks (one allowed)
android_unsafe = []
external = {n: "workspace" for n, d in ws["workspace"]["dependencies"].items() if n not in internal}
UNSAFE = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b|extern\b)")
DOCTEST = re.compile(r"^\s*//[/!]\s*```(?!text)")  # an opening fence rustdoc compiles

def test_off_violations(m, rel, man):
    """Targets with tests turned off must have none (notes/gate.md, Policy checks)."""
    lib = man.get("lib", {})
    srcs = glob.glob(os.path.join(m, "src/**/*.rs"), recursive=True)
    lib_srcs = [s for s in srcs if "/src/bin/" not in s and not s.endswith("/src/main.rs")]
    if lib.get("test") is False and any("#[cfg(test)]" in read(s) for s in lib_srcs):
        yield f"{rel}: [lib] test = false but src/ has #[cfg(test)]"
    if lib.get("doctest") is False:
        for s in lib_srcs:
            fences = [l for l in read(s).split("\n") if "```" in l and re.match(r"^\s*//[/!]\s*```", l)]
            if any(DOCTEST.match(l) for l in fences[::2]):
                yield f"{os.path.relpath(s, ROOT)}: doctest = false but it has a doctest"
    for b in man.get("bin", []):
        paths = [b["path"]] if "path" in b else [f"src/bin/{b['name']}.rs", "src/main.rs"]
        path = next((os.path.join(m, p) for p in paths if os.path.exists(os.path.join(m, p))), None)
        if b.get("test") is False and path and "#[cfg(test)]" in read(path):
            yield f"{rel}: bin {b['name']} has test = false but #[cfg(test)]"

for m in members:
    rel = os.path.relpath(m, ROOT)
    man = load(os.path.join(m, "Cargo.toml"))
    lints = man.get("lints", {})
    is_model = rel.startswith(("core/test/crdt-model", "core/test/roles-model", "core/test/held-model"))
    # held-model is an independent reading of the spec: its workspace dependencies are the other
    # models, crdt-model (its values) and roles-model (`evidence` judges by `paths`)
    if rel == "core/test/held-model":
        for table in dep_tables(man):
            for name, spec in table.items():
                if name not in ("crdt-model", "roles-model") and (name in internal or (isinstance(spec, dict) and "path" in spec)):
                    errs.append(f"{rel}: depends on workspace crate `{name}`; it may depend on crdt-model and roles-model only")
    # app/android: the workspace lints with unsafe_code at deny, for its one unsafe call (the NDK
    # makes a native window of the view's Surface only through a raw JNI call; notes/android.md)
    is_android = rel == "app/android"
    if is_android:
        want = {"rust": {"unsafe_code": "deny"}, "clippy": ws["workspace"].get("lints", {}).get("clippy", {})}
        if lints != want:
            errs.append(f"{rel}: needs the workspace lints with [lints.rust] unsafe_code = \"deny\"")
    elif is_model:
        if lints.get("rust", {}).get("unsafe_code") != "forbid":
            errs.append(f"{rel}: model needs [lints.rust] unsafe_code = \"forbid\"")
    elif lints.get("workspace") is not True:
        errs.append(f"{rel}: needs [lints] workspace = true")
    errs.extend(test_off_violations(m, rel, man))
    for table in dep_tables(man):
        for name, spec in table.items():
            if name in internal or (isinstance(spec, dict) and "path" in spec):
                continue
            external.setdefault(name, rel)
    # elsewhere the workspace lint (or a model's own) forbids unsafe: the compiler refuses it
    for src in rs_files(m, members) if is_android else []:
        srel = os.path.relpath(src, ROOT)
        lines = read(src).splitlines()
        for i, line in enumerate(lines, 1):
            if UNSAFE.search(code(line)):
                # app/android's one unsafe block, under its SAFETY comment
                if line.strip().startswith("unsafe {") and any(l.strip().startswith("// SAFETY:") for l in lines[max(0, i - 4):i - 1]):
                    android_unsafe.append(srel)
                    continue
                errs.append(f"{srel}:{i}: unsafe code")

if len(android_unsafe) > 1:
    errs.append(f"app/android: {len(android_unsafe)} unsafe blocks; it may have one ({', '.join(android_unsafe)})")

for name, where in sorted(external.items()):
    if f"`{name}`" not in allow:
        errs.append(f"dependency `{name}` ({where}) has no line in notes/architecture.md §5")

REGISTRY = "<!-- registry -->"


def registries():
    """A notes section marked as a registry (REGISTRY on the line under its heading: its items are
    cited by number elsewhere, `OPEN 10`, finding 31) numbers its top-level items uniquely and in
    increasing order: two branches each adding the next number collide, and a reader of either
    citation finds the wrong item. A new item takes the next number at rebase time."""
    for path in glob.glob(os.path.join(ROOT, "notes", "**", "*.md"), recursive=True):
        rel = os.path.relpath(path, ROOT)
        lines = read(path).splitlines()
        for i, line in enumerate(lines):
            if line.strip() != REGISTRY:
                continue
            if i == 0 or not lines[i - 1].startswith("#"):
                yield f"{rel}:{i + 1}: {REGISTRY} belongs on the line under a section's heading"
                continue
            last = None
            for n, item in enumerate(lines[i + 1:], i + 2):
                if item.startswith("#"):
                    break
                m = re.match(r"(\d+)\. ", item)
                if not m:
                    continue
                k = int(m[1])
                if last is not None and k <= last:
                    yield f"{rel}:{n}: registry item {k} after {last} in {lines[i - 1].strip()}: numbers unique and increasing (take the next free number at rebase time)"
                last = k


def env_vars():
    """core/base/testenv-known.txt names every `OSIS_*` variable the repo's sources name, and no other
    (a set variable it lacks fails the harnesses as a typo). Each finding by file:line: a stale name
    at its line in the list, an unlisted one where it is first named."""
    listed = "core/base/testenv-known.txt"
    known = {}
    for n, line in enumerate(open(os.path.join(ROOT, listed)), 1):
        for v in line.split():
            known.setdefault(v, n)
    used = {}  # each name, where it is first named
    for path, rel in walk(CODE_TOPS + ("tools",), (".rs", ".sh", ".py", ".toml")):
        text = read(path)
        # a name ending in `_` is a prefix (a filter over the environment)
        # the `\b` as a lookbehind after the literal, for speed (`has`)
        for m in re.finditer(r"OSIS_(?<!\wOSIS_)[A-Z0-9_]+", text):
            if not m[0].endswith("_") and m[0] not in used:
                used[m[0]] = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
    for v in sorted(v for v in used if v not in known and v.startswith("OSIS_PROBE_")):
        yield f"{used[v]}: {v} is a throwaway probe (notes/build.md): remove it before committing"
    for v in sorted(v for v in used if v not in known and not v.startswith("OSIS_PROBE_")):
        yield f"{used[v]}: {v} is read but not in {listed}"
    for v in sorted(v for v in known if v not in used):
        yield f"{listed}:{known[v]}: {v} is listed but nothing reads it"

# notes/disputes.md, the coherence rule: the dispute queries are private to osis-perm and
# the API layer; nothing else names a side or asks whether a dispute is open.
# The trust store (core/engine/src/sides.rs) is the rule's second exception: durable sides, fed
# to the walk; its end-to-end tests are core/engine/tests/it/disputes.rs.
DISPUTE_DIRS = ("core/perm/", "core/osis/", "core/engine/src/sides.rs", "core/engine/tests/it/disputes.rs")
DISPUTE_CALLS = re.compile(r"\.(set_trust|disputes|seed_commits)\s*\(")
# The engine's own dispute names (the store and its event) outside the store itself: only its
# hooks (the `Core` field and the update, commit and rollback calls, the load at open, the
# event's definition and the module's export).
SIDES_NAMES = re.compile(r"\bsides::|\bDisputeInfo\b|\bDisputeDetected\b|\.choose\s*\(")
SIDES_HOOKS = ("core/engine/src/engine/mod.rs", "core/engine/src/apply/mod.rs", "core/engine/src/events/mod.rs", "core/engine/src/lib.rs")

def dispute_types():
    for path, rel in walk(("core",), ".rs"):
        if rel.startswith(DISPUTE_DIRS) or rel.startswith("core/test/"):
            continue
        # the public `osis` calls (`disputes`, `choose_side`) are for every app; the names
        # are checked inside core only
        if has(DISPUTE_CALLS, code_of(path)):
            yield f"{rel}: calls a dispute query of osis-perm (private to osis-perm and the API layer)"
        elif not rel.startswith(SIDES_HOOKS) and has(SIDES_NAMES, code_of(path)):
            yield f"{rel}: names the trust store or its dispute event (engine sides.rs, its hooks and the API layer only)"

# notes/testing.md (Conventions): agents run tests side by side, so none binds the real LAN port or
# announces on the real network. `Lan::bind` in tests takes a free port (0, or another socket's);
# `osis` from a CLI test runs with `--no-lan`; a node a test builds starts from
# `internals::Opening` (LAN off), never a bare `Config` with a runtime.
LAN_BIND = re.compile(r"\bLan::bind\(\s*(?!0\s*\)|\w+\.port\(\)\s*\))")
CLI_RUN = re.compile(r"CARGO_BIN_EXE_osis|\bCommand::new\(OSIS\)|\bmain_with\(|\brun\(\[")
NODE_RUNTIME = r"(osis::)?Runtime::(Own|Tokio)"
BARE_NODE = re.compile(r"\bConfig\s*\{[^}]*\bruntime:\s*" + NODE_RUNTIME + r"[^}]*\}")
DEFAULT_CFG = re.compile(r"let mut (\w+)\s*=\s*(osis::)?Config::default\(\)")

def real_lan_tests():
    for path, rel in walk(CODE_TOPS, ".rs"):
        text = code_of(path)
        if "/tests/" not in "/" + rel:
            if "#[cfg(test)]" not in text:
                continue
            text = text.split("#[cfg(test)]", 1)[1]
        for m in BARE_NODE.finditer(text):
            if not re.search(r"\blan:", m[0]):
                yield f"{rel}: a test node from a bare Config is on the real LAN: {' '.join(m[0].split())[:80]} (use internals::Opening)"
        for m in DEFAULT_CFG.finditer(text):
            if re.search(rf"\b{m[1]}\.runtime\s*=\s*{NODE_RUNTIME}", text) and not re.search(rf"\b{m[1]}\.lan\s*=", text):
                yield f"{rel}: a test node from a bare Config is on the real LAN: {m[0]} (use internals::Opening)"
        for line in text.splitlines() if "Lan::bind(" in text or rel.startswith("cli/tests/") else []:
            if LAN_BIND.search(line):
                yield f"{rel}: Lan::bind in a test on a fixed port: {line.strip()[:80]} (use 0 or another socket's port)"
            if rel.startswith("cli/tests/") and CLI_RUN.search(line) and "--no-lan" not in line and "const OSIS" not in line:
                yield f"{rel}: runs osis without --no-lan: {line.strip()[:80]}"

# notes/engine-apply.md (Unjudgeable commits and parts): a test peer runs what is due through `Peer::tick`/`Peer::reexamine`,
# which fetch again what the step woke, as node-sync does; `<peer>.engine.tick()` skips that.
PEER_TICK = re.compile(r"(?<!\bself)\.engine\.(tick|reexamine)\(")

def peer_ticks():
    for path, rel in walk(("core",), ".rs"):
        if ".engine." not in code_of(path):
            continue
        for n, line in enumerate(code_of(path).split("\n"), 1):
            if PEER_TICK.search(line):
                yield f"{rel}:{n}: engine.tick()/reexamine() on a peer skips its wake (use Peer::tick/reexamine)"

# notes/test-harnesses.md (Copied worlds): a test copy is the same node twice (identity, session, rng
# stream), so product code never makes one. Product sources name the copy hooks only in the
# files that define them; tests, the test crates and the LocalPeer harness may use them freely.
COPY_HOOKS = re.compile(r"\btest_copy\b|\btest_copy_boxed\b|\bcopying::|\btest_subscribe_with\b")
COPY_DEFS = {"core/base/src/copying.rs", "core/crypto/src/rng.rs", "core/store/src/memory.rs", "core/store/src/root.rs",
             "core/store/src/backend.rs", "core/store/src/pager.rs", "core/store/src/store.rs", "core/engine/src/engine/testing.rs",
             "core/engine/src/engine/mod.rs", "core/base/src/memo/mod.rs", "core/base/src/memo/effects.rs", "core/engine/src/events/mod.rs",
             "core/engine/src/local_peer.rs",
             "core/store/src/cipher.rs",
             "core/sync/src/driver/mod.rs", "core/sync/src/store/mod.rs", "core/sync/src/store/cipher.rs"}

def product_lines(pat, skip):
    """(file, line number) of each line of a member's src/ (core/test's and files `skip(rel)` aside)
    whose code matches `pat`."""
    for m in members:
        for path in glob.glob(os.path.join(m, "src/**/*.rs"), recursive=True):
            rel = os.path.relpath(path, ROOT)
            # `pat` matches within a line, so a file it misses has no line it matches
            if not skip(rel) and not rel.startswith("core/test/") and has(pat, code_of(path)):
                for n, line in enumerate(code_of(path).split("\n"), 1):
                    if pat.search(line):
                        yield rel, n

def test_copies():
    for rel, n in product_lines(COPY_HOOKS, lambda rel: rel in COPY_DEFS):
        yield f"{rel}:{n}: a world-copy hook outside tests (notes/test-harnesses.md, Copied worlds)"

# notes/engine-paged.md (Checked once): `osis_crdt::Checked` vouches that bytes passed the full
# check on this node, and the decode-only readers trust it. Product code builds one only in the
# engine's `apply::checked` (a part `examine` accepted, of a stored record, or a stored state); test modules may
# build them freely.
CHECKED = re.compile(r"\bChecked::verified\b|\bChecked\(")
CHECKED_DEFS = {"core/crdt/src/stream.rs", "core/engine/src/apply/mod.rs"}

def checked_bytes():
    for rel, n in product_lines(CHECKED, lambda rel: rel in CHECKED_DEFS or os.path.basename(rel).startswith("tests_")):
        yield f"{rel}:{n}: osis_crdt::Checked built outside the engine's apply::checked (notes/engine-paged.md, Checked once)"
    # within the engine's file, the one helper
    n = len(CHECKED.findall(code_of(os.path.join(ROOT, "core/engine/src/apply/mod.rs"))))
    if n != 1:
        yield f"core/engine/src/apply/mod.rs: {n} Checked::verified uses, want 1 (apply::checked)"

# notes/engine.md (Signature verdicts): `osis_commit::Signed` vouches that signature bytes verified
# on this node. Product code reads one back from bytes only where this node kept it: a commit
# record's head (`engine/index.rs`) and a pending copy's row (`apply/mod.rs`, `kept_verdict`).
FROM_KEPT = re.compile(r"\bSigned::from_kept\b")
FROM_KEPT_USES = {"core/engine/src/engine/index.rs": 1, "core/engine/src/apply/mod.rs": 1}

def kept_verdicts():
    for rel, n in product_lines(FROM_KEPT, lambda rel: rel in FROM_KEPT_USES or rel == "core/commit/src/header.rs" or os.path.basename(rel).startswith("tests_")):
        yield f"{rel}:{n}: osis_commit::Signed read back outside where this node keeps verdicts (notes/engine.md, Signature verdicts)"
    for rel, want in FROM_KEPT_USES.items():
        n = len(FROM_KEPT.findall(code_of(os.path.join(ROOT, rel))))
        if n != want:
            yield f"{rel}: {n} Signed::from_kept uses, want {want}"

# notes/sync-test-harness.md (Determinism): a world replays from its seed, so sync's order never comes
# from a hash seed. Sync's product code keeps no hashed collection (BTreeMap/BTreeSet).
HASHED = re.compile(r"\b(HashMap|HashSet)\b")

def sync_hashed():
    for rel, n in product_lines(HASHED, lambda rel: not rel.startswith(("core/sync/src/", "core/engine/src/sync/"))):
        yield f"{rel}:{n}: a hashed collection in sync (its order varies per run; use BTreeMap/BTreeSet)"


# notes/principles.md (Never pin a seed of a random test): a bug a random test finds gets a
# hand-written reproducer at seed 0, never its random history replayed on its world seed. Sync's
# harness `world`, `history` and `World::new` take a seed first; in tests a literal one is 0.
PINNED_SEED = re.compile(r"(?<![\w.])(world|history|World::new)\(\s*(0*[1-9][0-9_]*)\s*[,)]")

def pinned_seeds():
    for path, rel in walk(("core/sync/tests",), ".rs"):
        for n, line in enumerate(code_of(path).split("\n"), 1):
            m = PINNED_SEED.search(line)
            if m:
                yield f"{rel}:{n}: {m[1]}({m[2]}, ..) pins a seed (notes/principles.md, Never pin a seed: a hand-written reproducer at seed 0)"


def known_failures():
    _, bad = gate_failures.known(ROOT)
    yield from bad
    sim = read(os.path.join(ROOT, "core/test/sim/src/scenarios.rs"))
    dirs = {name: m for m, name in workspace_members().items()}
    fns = {}  # per crate, `\bfn`, its `\b` after the literal for speed (`has`)
    for line in read(os.path.join(ROOT, gate_failures.KNOWN)).splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name = line.split()[0]
        if name.startswith("sim-sweep:"):
            if f'"{name.split(":", 1)[1]}"' not in sim:
                yield f"{gate_failures.KNOWN}: {name}: no such sim scenario"
            continue
        crate, _, path = name.rpartition("/")
        if crate not in dirs:
            yield f"{gate_failures.KNOWN}: {name}: want CRATE/PATH, CRATE a workspace package"
            continue
        if crate not in fns:
            fns[crate] = {f for p in rs_files(dirs[crate], members) for f in re.findall(r"fn(?<!\wfn) (\w+)", read(p))}
        if path.split("::")[-1] not in fns[crate]:
            yield f"{gate_failures.KNOWN}: {name}: no such test in {crate}"

def test_cost():
    lines, bad = gate_failures.budgets(ROOT)
    yield from bad
    crates = set(workspace_members().values())
    for name in lines:
        if name.split("/")[0] not in crates:
            yield f"{gate_failures.COST}: {name}: want CRATE/NAME, CRATE a workspace package"


# Line lists under git's union merge (.gitattributes `merge=union`): a hunk both sides changed keeps
# both, so a line both sides added comes twice (`union_lists` refuses it) and a line one side removed
# beside the other's change comes back: each list needs a check that refuses a stale line, named here.
UNION_STALE = {
    "tools/code_refs_allow.txt": "code_refs: in the code, or cited nowhere",
    "core/base/testenv-known.txt": "env_vars: nothing reads it",
}

def union_lists():
    for line in read(os.path.join(ROOT, ".gitattributes")).splitlines():
        f = line.split()
        if not f or f[0].startswith("#") or "merge=union" not in f[1:]:
            continue
        path = f[0]
        if path not in UNION_STALE:
            yield f".gitattributes: {path} has merge=union but no stale-line check (UNION_STALE in tools/policy.py)"
        if not os.path.isfile(os.path.join(ROOT, path)):
            yield f".gitattributes: {path}: no such file"
            continue
        seen = {}
        for n, item in enumerate(open(os.path.join(ROOT, path)), 1):
            item = item.strip()
            if not item or item.startswith("#"):
                continue
            if item in seen:
                yield f"{path}:{n}: duplicate of line {seen[item]} (drop one)"
            else:
                seen[item] = n

def find_all(text, sub):
    i = text.find(sub)
    while i >= 0:
        yield i
        i = text.find(sub, i + 1)

# Local-row keys share one namespace per store (the engine's, sync's): each kind of row is a byte
# constant, `const NAME: &[u8] = b"...";`, written nowhere else as a literal, and no key constant is
# a prefix of another (a scan of one would read the other's rows). The engine's `node/` names are
# index tables, a namespace of their own.
ROW_STORES = {"engine": ("core/engine/src/",), "sync": ("core/sync/src/",)}
ROW_CONST = re.compile(r'const (\w+): &\[u8\] = b"([^"]*)";')
ROW_INLINE = re.compile(r'b"[A-Za-z]{1,3}/')

def row_prefixes():
    for store, tops in ROW_STORES.items():
        keys = []
        for path, rel in all_files():
            if not rel.startswith(tops) or not rel.endswith(".rs"):
                continue
            text = code_of(path)
            for m in ROW_CONST.finditer(text):
                if not m.group(2).startswith("node/"):
                    keys.append((m.group(2), f"{rel}:{text.count(chr(10), 0, m.start()) + 1} {m.group(1)}"))
            for m in ROW_INLINE.finditer(ROW_CONST.sub("", text)):
                yield f"{rel}: a row key `{m.group(0)}...` written as a literal (name it as a `const`, tools/policy.py row_prefixes)"
        for i, (a, wa) in enumerate(keys):
            for b, wb in keys[i + 1:]:
                if a.startswith(b) or b.startswith(a):
                    yield f"{store} store: row key {a!r} ({wa}) and {b!r} ({wb}) collide (one is a prefix of the other)"

# A peer record's rows are keyed by a one-byte tag per kind (sync's `store::rows::tag`): each tag
# is its own byte, named there and nowhere written as a literal.
RECORD_TAGS = "core/sync/src/store/rows.rs"
RECORD_TAG = re.compile(r"const (\w+): u8 = b'(.)';")
RECORD_CALL = re.compile(r"record_(?:put|get|remove)_(?:wide_)?rows?\([^,]*,\s*b'")

def record_tags():
    text = code_of(os.path.join(ROOT, RECORD_TAGS))
    block = text.split("mod tag", 1)[1].split("\n}", 1)[0] if "mod tag" in text else ""
    seen = {}
    for m in RECORD_TAG.finditer(block):
        if m.group(2) in seen:
            yield f"{RECORD_TAGS}: record tags {seen[m.group(2)]} and {m.group(1)} are both b'{m.group(2)}'"
        seen.setdefault(m.group(2), m.group(1))
    for path, rel in all_files():
        if rel.startswith("core/sync/src/") and rel.endswith(".rs") and RECORD_CALL.search(code_of(path)):
            yield f"{rel}: a record row written with a literal tag (name it in {RECORD_TAGS}'s `tag`)"

# An ignored test waits on an issue: its reason names the issue's file, which must exist, so deleting
# the issue fails until the test runs again or names what it now waits on. A reason naming an issue
# only by word ("issue", a bare slug, `issues/x` without `.md`) names no file to check.
IGNORE = re.compile(r'#\[ignore\s*=\s*"([^"]*)"\]')
ISSUE_FILE = re.compile(r"issues/([A-Za-z0-9_-]+)\.md")

def ignore_issues():
    for path, rel in walk(CODE_TOPS, ".rs"):
        text = read(path)
        if "#[ignore" not in text:
            continue
        for n, line in enumerate(text.split("\n"), 1):
            m = IGNORE.search(line)
            if not m or not re.search(r"\bissues?\b", m[1]):
                continue
            files = ISSUE_FILE.findall(m[1])
            if not files:
                yield f"{rel}:{n}: #[ignore = \"{m[1]}\"] names an issue but no issues/<name>.md file"
            for f in files:
                if not os.path.isfile(os.path.join(ROOT, "issues", f + ".md")):
                    yield f"{rel}:{n}: #[ignore] names issues/{f}.md, which does not exist (run the test, or name what it waits on)"


def spec_anchors():
    """tools/spec_map.py --uncited --gaps: what the gate's instant step would refuse."""
    _, uncited, open_r, problems = spec_map.render()
    yield from (f"spec_map: uncited test: {u}" for u in uncited)
    yield from (f"spec_map: no test or issue: {f} §{s} ({a})" for f, s, a in open_r)
    yield from (f"spec_map: {p}" for p in problems)


# issues/deprecated-terms.md (Gone): a fully removed concept whose word has no other sense, so no
# text may use it again. The registry itself, history logs and the kept audit of the removed
# account system (notes/account-membership-design.md §1) are exempt.
DEAD_WORDS = {w: re.compile(p) for w, p in {
    "key actor": r"(?i)\bkey[ _-]?actors?\b",
    "account root": r"(?i)\baccount[ _-]?roots?\b",
    "account side": r"(?i)\baccount[ _-]?sides?\b",
    "account epoch": r"(?i)\baccount[ _-]?epochs?\b",
    "signing chain": r"(?i)\bsigning[ _-]?chains?\b",
    "chain write": r"(?i)\bchain[ _-]?writes?\b",
    "node card": r"(?i)\bnode[ _-]?cards?\b",
    "reach.0": r"\breach\.0\b",
    "client actor": r"(?i)\bclient[ _-]?actors?\b",
    "main actor": r"(?i)\bmain[ _-]?actors?\b",
    "own actor": r"(?i)\bown[ _-]?actors?\b",
    "link actor": r"(?i)\blink[ _-]?actors?\b",
    "UnknownActor": r"\bUnknownActor\b|\bUNKNOWN_ACTOR\b",
    "public link": r"(?i)\bpublic[ _-]?links?\b|\bPUBLIC_LINKS?\b",
}.items()}

# Words of key parts (notes/stub-rewrite.md), refused in every tracked file.
STUB_DEAD_WORDS = {w: re.compile(p) for w, p in {
    "edge piece": r"(?i)\bedge[ _-]?pieces?\b",
    "key part": r"(?i)\bkey[ _-]parts?\b|\bkey_part\w*",
    "public piece": r"(?i)\bpublic[ _-]pieces?\b",
    "held for keys": r"(?i)\bheld[ _-]for[ _-]keys\b",
    "keys-open travel": r"(?i)\bkeys[ _-]open[ _-]travel\b",
    "sync alone": r"(?i)\bsync[ _-]alone\b",
    "follows_public": r"\bfollows_public\b",
    "by_public": r"\bby_public\w*",
    "deliver_copy": r"\bdeliver_copy\b",
    "sealed copy": r"(?i)\bsealed[ _-]cop(y|ies)\b",
    "EdgePiece": r"\bEdgePiece\b",
}.items()}


def dead_words():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split("\n")
    skip = ("docs/", "notes/complaints/", "libs/kit/patches/", "issues/deprecated-terms.md", "tools/policy.py", "notes/account-membership-design.md")
    for rel in tracked:
        if not rel or rel.startswith(skip) or not os.path.exists(os.path.join(ROOT, rel)):
            continue
        for n, line in enumerate(read(os.path.join(ROOT, rel)).split("\n"), 1):
            for word, pat in DEAD_WORDS.items():
                if pat.search(line):
                    yield f"{rel}:{n}: uses \"{word}\", a removed concept (issues/deprecated-terms.md, Gone)"
            for word, pat in STUB_DEAD_WORDS.items():
                if pat.search(line):
                    yield f"{rel}:{n}: uses \"{word}\", a removed concept (issues/deprecated-terms.md, Gone)"


# the slowest first, so the pool balances
CHECKS = [doc_refs.check, spec_anchors, code_refs.check, row_prefixes, record_tags, known_failures, test_cost, union_lists, registries, test_copies, ignore_issues, checked_bytes, kept_verdicts, sync_hashed, pinned_seeds, real_lan_tests, peer_ticks, env_vars, dispute_types, dead_words]


def run(check):
    return list(check())


# the checks are independent: forked workers share what is read so far, each check's output kept in order
with multiprocessing.get_context("fork").Pool(min(4, os.cpu_count() or 1)) as pool:
    for out in pool.map(run, CHECKS, chunksize=1):
        errs.extend(out)

LINE_NO = re.compile(r"(\.\w+):\d+\b")  # `path.ext:12` (and `:12:3`): the key drops line numbers


def baseline(ref):
    """REF's violations: its own tools/policy.py run on its tree (read-tree into a scratch index,
    checkout-index into a temp dir; the git dir and index stand in for a checkout), cached by commit."""
    def git(*args, env=None):
        return subprocess.run(["git", *args], cwd=env["GIT_WORK_TREE"] if env else ROOT, env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    try:
        commit = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except subprocess.CalledProcessError:
        sys.exit(f"policy: no commit {ref!r}")
    cache_dir = os.path.join(ROOT, "target", "policy-baseline")
    cache = os.path.join(cache_dir, commit)
    if not os.path.exists(cache):
        os.makedirs(cache_dir, exist_ok=True)
        tmp = tempfile.mkdtemp(dir=cache_dir)
        try:
            env = dict(os.environ, GIT_DIR=os.path.abspath(os.path.join(ROOT, git("rev-parse", "--git-dir"))),
                       GIT_WORK_TREE=os.path.join(tmp, "tree"), GIT_INDEX_FILE=os.path.join(tmp, "index"))
            os.mkdir(env["GIT_WORK_TREE"])
            git("read-tree", commit, env=env)
            git("checkout-index", "-a", env=env)
            out = subprocess.run([sys.executable, "tools/policy.py"], cwd=env["GIT_WORK_TREE"], env=env,
                                 capture_output=True, text=True)
            if out.returncode not in (0, 1):
                sys.exit(f"policy: {ref}'s policy run failed:\n{out.stderr}")
            with open(cache + f".{os.getpid()}", "w") as f:
                f.write(out.stdout)
            os.replace(cache + f".{os.getpid()}", cache)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    with open(cache) as f:
        return [l for l in f.read().splitlines() if not l.startswith("policy: ")]


def verdict(failed, what):
    """The last line, then the exit: FAILED or ok first, so a tail of the output shows which. A pipe
    gives the shell its last command's exit, not policy's, so `policy.py | tail && git commit`
    commits past a failure: piped, a failure says so."""
    piped = stat.S_ISFIFO(os.fstat(1).st_mode)
    hide = "; exit 1, which this pipe hides from `&&`: run policy.py unpiped" if failed and piped else ""
    print(f"policy: {'FAILED' if failed else 'ok'}: {what}{hide}", flush=True)
    sys.exit(1 if failed else 0)


if "--baseline" in sys.argv:
    i = sys.argv.index("--baseline")
    ref = sys.argv[i + 1] if i + 1 < len(sys.argv) else "origin/main"
    old = collections.Counter(LINE_NO.sub(r"\1", e) for e in baseline(ref))
    new = []
    for e in errs:
        k = LINE_NO.sub(r"\1", e)
        if old[k]:
            old[k] -= 1
        else:
            new.append(e)
    for e in new:
        print(e)
    verdict(bool(new), f"{len(errs)} violations, {len(new)} new against {ref}, {len(errs) - len(new)} already there")

for e in errs:
    print(e)
verdict(bool(errs), f"{len(errs)} violations ({len(members)} members, {len(external)} external deps)")
