#!/usr/bin/env python3
"""Policy checks (notes/testing.md, Policy checks): unsafe forbidden everywhere in the workspace,
workspace lints on, every external dependency has its line in notes/architecture.md §5, and no
target marked `test = false` / `doctest = false` has unit tests / doctests that would silently not run,
and core/base/testenv-known.txt lists exactly the `OSIS_*` variables the sources name.
Usage: python3 tools/policy.py [WORKSPACE]   (from the repo root; WORKSPACE: the directory of a
workspace's root manifest, `.` (core, default) or `kit` (the GUI workspace, notes/app.md); vendored
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
    is_model = rel.startswith(("core/test/crdt-model", "core/test/membership-model"))
    if is_model:
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
        srel = os.path.relpath(src, ROOT)
        text = open(src).read()
        for i, line in enumerate(text.splitlines(), 1):
            if UNSAFE.search(line.split("//", 1)[0]):
                errs.append(f"{srel}:{i}: unsafe code")
        root_file = srel.endswith(("/src/lib.rs", "/src/main.rs")) or "/src/bin/" in srel
        if root_file and not is_model and "#![forbid(unsafe_code)]" not in text:
            errs.append(f"{srel}: crate root lacks #![forbid(unsafe_code)]")

for name, where in sorted(external.items()):
    if f"`{name}`" not in allow:
        errs.append(f"dependency `{name}` ({where}) has no line in notes/architecture.md §5")

def env_vars():
    """core/base/testenv-known.txt names every `OSIS_*` variable the repo's sources name, and no other
    (a set variable it lacks fails the harnesses as a typo)."""
    known = set(open(os.path.join(ROOT, "core/base/testenv-known.txt")).read().split())
    used = set()
    for top in ("core", "cli", "kit", "app", "tools"):
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

if WS == ROOT:
    errs.extend(env_vars())

for e in errs:
    print(e)
print(f"policy: {len(members)} members, {len(external)} external deps, {len(errs)} violations")
sys.exit(1 if errs else 0)
