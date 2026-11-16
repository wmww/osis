#!/usr/bin/env python3
"""Code names in notes (notes/gate.md, Policy checks): every code name a note or issue cites in
backticks exists, so a rename or deletion fails the branch that made it, not a later reader.
Checked, in each inline backtick span of notes/ and issues/ (fenced blocks are sketches, not citations):
  names: each segment of an `a::b` path, a name called (`foo(`), a name with `_` (`foo_bar`,
      `MAX_PROOFS`) and a CamelCase name with an inner capital (`LocalPeer`): the word occurs in a
      tracked file outside docs/ (not Markdown, but spec/'s), is a tracked file's name without its
      extension (a TLA model's .cfg), or is a test's name less its `_spec_...` tail. A word match,
      not a definition: a name only a comment keeps passes. Skipped: a name starting or ending in
      `_`, shorter than 3, or beside `*`, `<`, `>`, `{`, `}`, `$`, `-`, `/` (a pattern, placeholder,
      flag or alternative); `a_{b,c}` names `a_b` and `a_c`.
  paths: a span that is a relative path of a source extension (`core/x/src/y.rs`, `apply/mod.rs`):
      a tracked file's path ends with it, also with `src/` left out (`store/store.rs`) or its crate
      named by package (`osis-keys/tests/it/x.rs`).
Not read: notes/complaints/ (consumed), the Investigations section of notes/time-limits.md (a record
of what ran then), spec/ (its names are wire and grammar terms). Names not in our code on purpose
(third-party, placeholder, planned, rejected, removed) are listed in tools/code_refs_allow.txt with a
reason; a listed name that is in the code, or that no note or issue cites, fails.
Usage: python3 tools/code_refs.py   (exit 1 on any stale name; policy.py runs it)"""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import members

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOW = "tools/code_refs_allow.txt"
NOT_SRC = (".md", ".ttf", ".snap", ".vec")
PATH_EXTS = (".rs", ".tla", ".cfg", ".py", ".sh", ".toml", ".osis", ".java", ".kt")
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SPAN = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
FENCE = re.compile(r"^[ \t]*```.*?^[ \t]*```[^\n]*$", re.M | re.S)
CAMEL = re.compile(r"[A-Z][a-z0-9]+[A-Z]")
PATHLIKE = re.compile(r"^(?:\./)?[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*$")
# beside these a word is a pattern, a placeholder or a flag (`foo_*`, `<name>`, `--no-lan`, `X/Y`)
GLOB = set("*<>{}$-/")
BRACES = re.compile(r"(\w*)\{(\w+(?:,\w+)+)\}")
# a test's name ends in the spec section it covers (tools/spec_map.py); a note may leave it out
SPEC_TAIL = re.compile(r"_spec_\w*$")


def cited(text):
    """(line number, name or path, kind) of each code citation in `text`."""
    text = FENCE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    for s in SPAN.finditer(text):
        span, line = s.group(1).strip(), text.count("\n", 0, s.start()) + 1
        if PATHLIKE.match(span) and span.endswith(PATH_EXTS):
            yield line, span[2:] if span.startswith("./") else span, "path"
            continue
        # `a_{b,c}` names `a_b` and `a_c`
        span = BRACES.sub(lambda m: " ".join(m.group(1) + x for x in m.group(2).split(",")), span)
        for w in WORD.finditer(span):
            name, a, b = w.group(0), w.start(), w.end()
            before, after = span[max(0, a - 1):a], span[b:b + 1]
            if name.startswith("_") or name.endswith("_") or len(name) < 3 or GLOB & {before, after}:
                continue
            pathy = span[max(0, a - 2):a] == "::" or span[b:b + 2] == "::"
            if pathy or after == "(" or "_" in name or CAMEL.match(name):
                yield line, name, "name"


def skipped(rel, text):
    """`text` with the parts not checked blanked (line numbers kept)."""
    if rel == "notes/time-limits.md" and "\n## Investigations" in text:
        a = text.index("\n## Investigations") + 1
        e = text.find("\n## ", a)
        e = len(text) if e < 0 else e
        text = text[:a] + "\n" * text.count("\n", a, e) + text[e:]
    return text


def allow_list(root):
    """{name: (line, reason)} of the allow list, and its errors (a name listed twice)."""
    out, errs = {}, []
    p = os.path.join(root, ALLOW)
    for n, line in enumerate(open(p) if os.path.isfile(p) else [], 1):
        line = line.strip()
        if line and not line.startswith("#"):
            name, _, why = line.partition(" ")
            if name in out:
                errs.append(f"{ALLOW}:{n}: `{name}` listed twice (line {out[name][0]})")
            out.setdefault(name, (n, why.strip()))
    return out, errs


def stale(docs, words, ends, allow):
    """Stale citations in `docs` ({path: text}) against the code's `words` and path tails `ends`,
    and stale lines of `allow` ({name: (line, reason)})."""
    used = set()
    for rel, text in docs.items():
        seen = set()
        for line, name, kind in cited(skipped(rel, text)):
            if name in allow:
                used.add(name)
            elif not (name in words if kind == "name" else name in ends) and name not in seen:
                seen.add(name)
                yield f"{rel}:{line}: `{name}`: no such {kind} in the code ({ALLOW} for a third-party name or placeholder)"
    for name, (n, why) in sorted(allow.items(), key=lambda x: x[1][0]):
        if not why:
            yield f"{ALLOW}:{n}: `{name}` has no reason"
        if name in words or name in ends:
            yield f"{ALLOW}:{n}: `{name}` is in the code (drop the line)"
        elif name not in used:
            yield f"{ALLOW}:{n}: `{name}` is cited nowhere (drop the line)"


def code_names(root, tracked):
    """The words of the code (and of spec/, which names wire fields and constants), and every tail
    of each source path."""
    words = set()
    for rel in tracked:
        # not the tools' own test fixtures, whose planted names are none
        if (rel.startswith("spec/") or not rel.endswith(NOT_SRC)) and rel != ALLOW and not rel.startswith("docs/") \
                and not re.match(r"tools/\w+_test\.", rel) and os.path.isfile(os.path.join(root, rel)):
            words.update(WORD.findall(open(os.path.join(root, rel), errors="replace").read()))
    words |= {SPEC_TAIL.sub("", w) for w in words if "_spec_" in w}
    # a file's name without its extension (a TLA model's .cfg, a script) is a name too
    words.update(os.path.splitext(os.path.basename(r))[0] for r in tracked)
    # a path cites a file by any tail of its path, also with the crate's src/ left out
    # (`store/store.rs`) or its directory named by its package (`osis-keys/tests/it/x.rs`)
    ends = set()
    for f in tracked:
        if f.endswith(PATH_EXTS):
            for g in {f, f.replace("/src/", "/")}:
                parts = g.split("/")
                ends.update("/".join(parts[i:]) for i in range(len(parts)))
    for d, pkg in members().items():
        d = os.path.relpath(d, root) + "/"
        ends.update(pkg + "/" + f[len(d):] for f in tracked if f.startswith(d) and f.endswith(PATH_EXTS))
    return words, ends


def check(root=ROOT):
    tracked = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
    docs = {rel: open(os.path.join(root, rel), errors="replace").read() for rel in tracked
            if rel.startswith(("notes/", "issues/")) and rel.endswith(".md") and not rel.startswith("notes/complaints/")
            and os.path.isfile(os.path.join(root, rel))}
    allow, errs = allow_list(root)
    yield from errs
    yield from stale(docs, *code_names(root, tracked), allow)


if __name__ == "__main__":
    errs = list(check())
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
