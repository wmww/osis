#!/usr/bin/env python3
"""Policy checks (notes/testing.md, Policy checks): unsafe forbidden everywhere in the workspace,
workspace lints on, every external dependency has its line in notes/architecture.md §5, and no
target marked `test = false` / `doctest = false` has unit tests / doctests that would silently not run,
and core/base/testenv-known.txt lists exactly the `OSIS_*` variables the sources name, and
osis-host cannot reach decryption (`host_blind`).
Usage: python3 tools/policy.py [WORKSPACE]   (from the repo root; WORKSPACE: the directory of a
workspace's root manifest, `.` (core, default) or `libs/kit` (the GUI workspace, notes/app.md); vendored
crates under `patches/` are not ours and are skipped; exit 1 on any violation)"""
import glob, os, re, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
errs = []

def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)

WS = os.path.normpath(os.path.join(ROOT, sys.argv[1] if len(sys.argv) > 1 else "."))
ws = load(os.path.join(WS, "Cargo.toml"))
internal = {n for n, d in ws["workspace"]["dependencies"].items() if isinstance(d, dict) and "path" in d}
members = sorted(os.path.normpath(m) for pat in ws["workspace"]["members"] for m in glob.glob(os.path.join(WS, pat))
                 if os.path.isfile(os.path.join(m, "Cargo.toml")))

arch = open(os.path.join(ROOT, "notes/architecture.md")).read()
allow = arch.split("## 5. Dependency allowlist", 1)[-1].split("\n## ", 1)[0]

def dep_tables(manifest):
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield manifest.get(key, {})
    for t in manifest.get("target", {}).values():
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield t.get(key, {})

external = {n: "workspace" for n, d in ws["workspace"]["dependencies"].items() if n not in internal}
UNSAFE = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b|extern\b)")
DOCTEST = re.compile(r"^\s*//[/!]\s*```(?!text)")  # an opening fence rustdoc compiles

def test_off_violations(m, rel, man):
    """Targets with tests turned off must have none (notes/testing.md, Build hygiene)."""
    lib = man.get("lib", {})
    srcs = glob.glob(os.path.join(m, "src/**/*.rs"), recursive=True)
    lib_srcs = [s for s in srcs if "/src/bin/" not in s and not s.endswith("/src/main.rs")]
    if lib.get("test") is False and any("#[cfg(test)]" in open(s).read() for s in lib_srcs):
        yield f"{rel}: [lib] test = false but src/ has #[cfg(test)]"
    if lib.get("doctest") is False:
        for s in lib_srcs:
            fences = [l for l in open(s) if re.match(r"^\s*//[/!]\s*```", l)]
            if any(DOCTEST.match(l) for l in fences[::2]):
                yield f"{os.path.relpath(s, ROOT)}: doctest = false but it has a doctest"
    for b in man.get("bin", []):
        paths = [b["path"]] if "path" in b else [f"src/bin/{b['name']}.rs", "src/main.rs"]
        path = next((os.path.join(m, p) for p in paths if os.path.exists(os.path.join(m, p))), None)
        if b.get("test") is False and path and "#[cfg(test)]" in open(path).read():
            yield f"{rel}: bin {b['name']} has test = false but #[cfg(test)]"

for m in members:
    rel = os.path.relpath(m, ROOT)
    man = load(os.path.join(m, "Cargo.toml"))
    lints = man.get("lints", {})
    is_model = rel.startswith(("core/test/crdt-model", "core/test/roles-model", "core/test/held-model"))
    # held-model is an independent reading of the spec: its one workspace dependency is crdt-model,
    # the other independent reading (its values)
    if rel == "core/test/held-model":
        for table in dep_tables(man):
            for name, spec in table.items():
                if name != "crdt-model" and (name in internal or (isinstance(spec, dict) and "path" in spec)):
                    errs.append(f"{rel}: depends on workspace crate `{name}`; it may depend on crdt-model only")
    # app/android: the workspace lints with unsafe_code at deny, for its one `#[unsafe(no_mangle)]`
    # entry point (NativeActivity finds `android_main` by name; notes/android.md)
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
    for src in glob.glob(os.path.join(m, "**/*.rs"), recursive=True):
        if os.path.relpath(src, m).startswith(("target/", "patches/")):
            continue
        # a member nested in this one (app/android in app) is checked as itself
        if any(o != m and src.startswith(o + os.sep) and o.startswith(m + os.sep) for o in members):
            continue
        srel = os.path.relpath(src, ROOT)
        text = open(src).read()
        for i, line in enumerate(text.splitlines(), 1):
            if UNSAFE.search(line.split("//", 1)[0]):
                errs.append(f"{srel}:{i}: unsafe code")
        if is_android and len(re.findall(r"\bunsafe\b", re.sub(r"//[^\n]*", "", text))) != text.count("#[unsafe(no_mangle)]"):
            errs.append(f"{srel}: unsafe beyond the entry point's #[unsafe(no_mangle)]")
        if is_android and text.count("#[unsafe(no_mangle)]") > 1:
            errs.append(f"{srel}: more than one #[unsafe(no_mangle)]")
        root_file = srel.endswith(("/src/lib.rs", "/src/main.rs")) or "/src/bin/" in srel
        if root_file and not is_model and not is_android and "#![forbid(unsafe_code)]" not in text:
            errs.append(f"{srel}: crate root lacks #![forbid(unsafe_code)]")

for name, where in sorted(external.items()):
    if f"`{name}`" not in allow:
        errs.append(f"dependency `{name}` ({where}) has no line in notes/architecture.md §5")

def env_vars():
    """core/base/testenv-known.txt names every `OSIS_*` variable the repo's sources name, and no other
    (a set variable it lacks fails the harnesses as a typo)."""
    known = set(open(os.path.join(ROOT, "core/base/testenv-known.txt")).read().split())
    used = set()
    for top in ("core", "cli", "libs", "app", "tools"):
        for dirpath, dirs, files in os.walk(os.path.join(ROOT, top)):
            dirs[:] = [d for d in dirs if d not in ("target", "patches")]
            for f in files:
                path = os.path.join(dirpath, f)
                if not f.endswith((".rs", ".sh", ".py", ".toml")):
                    continue
                # a name ending in `_` is a prefix (a filter over the environment)
                used |= {v for v in re.findall(r"\bOSIS_[A-Z0-9_]+", open(path, errors="replace").read()) if not v.endswith("_")}
    for v in sorted(used - known):
        yield f"{v} is read but not in core/base/testenv-known.txt"
    for v in sorted(known - used):
        yield f"{v} is in core/base/testenv-known.txt but nothing reads it"

def paths_of(text, crate):
    """Every path named under `crate::` in `text` (comments dropped), `{a, b::{c}}` groups
    expanded; `*` for a glob; `<crate> as` aliases flagged as `as`."""
    text = re.sub(r"//[^\n]*", "", text)
    out = []
    if re.search(rf"\b{crate}\s+as\b", text):
        out.append("as")
    def expand(s, i, prefix):
        # parses a path tree at s[i:], appending full paths; returns the index after it
        seg = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*|\*|\{)", s[i:])
        if not seg:
            return i
        tok, i = seg.group(1), i + seg.end()
        if tok == "{":
            while True:
                i = expand(s, i, prefix)
                m = re.match(r"\s*(,|\})", s[i:])
                if not m:
                    return i
                i += m.end()
                if m.group(1) == "}":
                    return i
                if re.match(r"\s*\}", s[i:]):
                    i += re.match(r"\s*\}", s[i:]).end()
                    return i
        path = prefix + [tok]
        m = re.match(r"\s*::", s[i:])
        if m and tok != "*":
            return expand(s, i + m.end(), path)
        m = re.match(r"\s+as\s+[A-Za-z_][A-Za-z0-9_]*", s[i:])
        if m:
            i += m.end()
        out.append("::".join(path))
        return i
    for m in re.finditer(rf"\b{crate}\s*::", text):
        expand(text, m.end(), [])
    return out

HOST_DEPS = {"osis-base", "osis-crypto", "osis-label", "osis-proto", "osis-store", "osis-transport", "tokio"}
HOST_CRYPTO = {"VerifyingKey", "Signature", "WRAP_LEN", "OsRng", "RngCore", "CryptoRngCore"}
HOST_LABEL = {"blob_id", "Prefix", "prefix_bytes", "verify_stamp", "step::parse_entry_box", "step::entry_box_bytes", "Address", "address_to_text", "address_from_text", "ClaimSet", "Step", "StepId"}
HOST_PROTO_DENY = {"examples"}
NODE_HOST = {"driver", "Hub", "HostStore", "HostConfig", "HostPolicy", "Admission", "LabelCaps"}

def allowed(path, allow):
    return any(path == a or path.startswith(a + "::") for a in allow)

def host_blind():
    """The host cannot touch decryption (notes/serving.md, Decisions): osis-host depends only on the
    crates hosting needs and names only allowlisted osis-crypto and osis-label items (fails
    closed: a new decrypting call fails here); osis-node names only the host's public surface."""
    man = load(os.path.join(ROOT, "core/host/Cargo.toml"))
    for key, extra in (("dependencies", set()), ("dev-dependencies", {"proptest"})):
        for d in sorted(set(man.get(key, {})) - HOST_DEPS - extra):
            yield f"core/host/Cargo.toml: {key} {d} is not one hosting may use"
    for src in glob.glob(os.path.join(ROOT, "core/host/src/**/*.rs"), recursive=True):
        if os.path.basename(src) == "tests.rs":
            continue
        rel = os.path.relpath(src, ROOT)
        text = open(src).read()
        if "OpenKey" in text:
            yield f"{rel}: names OpenKey"
        # osis-proto's client engine (replication pushes with it) opens a label only with an
        # `OpenKey` (refused above); its examples hold secrets; a glob would hide both
        for p in paths_of(text, "osis_proto"):
            if p in ("*", "as") or p.endswith("::*") or p.split("::")[0] in HOST_PROTO_DENY:
                yield f"{rel}: osis_proto::{p} is not for the host (glob, alias or examples)"
        for crate, allow in (("osis_crypto", HOST_CRYPTO), ("osis_label", HOST_LABEL)):
            for p in paths_of(text, crate):
                if p in ("*", "as") or p.endswith("::*"):
                    yield f"{rel}: {crate} glob or alias"
                elif not allowed(p, allow):
                    yield f"{rel}: {crate}::{p} is not on the host's allowlist"
    for src in glob.glob(os.path.join(ROOT, "core/node/src/**/*.rs"), recursive=True):
        rel = os.path.relpath(src, ROOT)
        for p in paths_of(open(src).read(), "osis_host"):
            if p in ("*", "as") or not allowed(p, NODE_HOST):
                yield f"{rel}: osis_host::{p} is not the host's public surface"

# notes/disputes-plan.md, the coherence rule: the dispute types are private to osis-perm and
# the API layer; nothing else names a side or asks whether a dispute is open.
# The trust store (core/engine/src/sides.rs) is the rule's second exception: durable sides, fed
# to the walk; its end-to-end tests are core/node/tests/it/disputes.rs.
DISPUTE_DIRS = ("core/perm/", "core/osis/", "core/engine/src/sides.rs", "core/node/tests/it/disputes.rs")
DISPUTE_PATHS = {"Trust", "Dispute", "Detected", "trust", "DETECT_MAX"}
DISPUTE_CALLS = re.compile(r"\.(set_trust|disputes|disputes_up_to|evaluate_with|trusted_active|take_detected)\s*\(|\bTrust\s*\{|\bDispute\s*\{")
# The engine's own dispute names (the store, its event and diagnostic) outside the store itself:
# only its hooks (the `Core` field and the update, commit and rollback calls, the load at open,
# the event's definition and the module's export).
SIDES_NAMES = re.compile(r"\bsides::|\bDisputeInfo\b|\bDisputeDetected\b|\bDisputesUnexamined\b|\.choose\s*\(")
SIDES_HOOKS = ("core/engine/src/engine/mod.rs", "core/engine/src/apply/mod.rs", "core/engine/src/events/mod.rs", "core/engine/src/lib.rs")

def dispute_types():
    for top in ("core", "cli", "libs", "app"):
        for dirpath, dirs, files in os.walk(os.path.join(ROOT, top)):
            dirs[:] = [d for d in dirs if d not in ("target", "patches")]
            for f in files:
                if not f.endswith(".rs"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, f), ROOT)
                if rel.startswith(DISPUTE_DIRS) or rel.startswith("core/test/"):
                    continue
                text = open(os.path.join(dirpath, f), errors="replace").read()
                named = [p for p in paths_of(text, "osis_perm") if p.split("::")[-1] in DISPUTE_PATHS or p.startswith("trust::")]
                if named:
                    yield f"{rel}: names osis_perm::{named[0]} (dispute types are private to osis-perm and the API layer)"
                # the public `osis` calls (`disputes`, `choose_side`) are for every app; the names
                # are checked inside core only
                elif top == "core" and DISPUTE_CALLS.search(re.sub(r"//[^\n]*", "", text)):
                    yield f"{rel}: calls a dispute query of osis-perm (private to osis-perm and the API layer)"
                elif top == "core" and not rel.startswith(SIDES_HOOKS) and SIDES_NAMES.search(re.sub(r"//[^\n]*", "", text)):
                    yield f"{rel}: names the trust store or its dispute event (engine sides.rs, its hooks and the API layer only)"

if WS == ROOT:
    errs.extend(env_vars())
    errs.extend(host_blind())
    errs.extend(dispute_types())

for e in errs:
    print(e)
print(f"policy: {len(members)} members, {len(external)} external deps, {len(errs)} violations")
sys.exit(1 if errs else 0)
