#!/usr/bin/env python3
"""Policy checks (notes/testing.md, Policy checks): unsafe forbidden everywhere in the workspace,
workspace lints on, and every external dependency has its line in notes/architecture.md §5.
Usage: python3 tools/policy.py   (from the repo root; exit 1 on any violation)"""
import glob, os, re, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
errs = []

def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)

ws = load(os.path.join(ROOT, "Cargo.toml"))
internal = {n for n, d in ws["workspace"]["dependencies"].items() if isinstance(d, dict) and "path" in d}
members = sorted(m for pat in ws["workspace"]["members"] for m in glob.glob(os.path.join(ROOT, pat))
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

for m in members:
    rel = os.path.relpath(m, ROOT)
    man = load(os.path.join(m, "Cargo.toml"))
    lints = man.get("lints", {})
    is_model = rel.startswith("models/")
    if is_model:
        if lints.get("rust", {}).get("unsafe_code") != "forbid":
            errs.append(f"{rel}: model needs [lints.rust] unsafe_code = \"forbid\"")
    elif lints.get("workspace") is not True:
        errs.append(f"{rel}: needs [lints] workspace = true")
    for table in dep_tables(man):
        for name, spec in table.items():
            if name in internal or (isinstance(spec, dict) and "path" in spec):
                continue
            external.setdefault(name, rel)
    for src in glob.glob(os.path.join(m, "**/*.rs"), recursive=True):
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

for e in errs:
    print(e)
print(f"policy: {len(members)} members, {len(external)} external deps, {len(errs)} violations")
sys.exit(1 if errs else 0)
