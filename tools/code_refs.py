#!/usr/bin/env python3
"""Code names in notes and doc comments (notes/gate.md, Policy checks): every code name a note, an
issue or a Rust doc comment (`///`, `//!`, not in vendored crates) cites in backticks exists, so a
rename or deletion fails the branch that made it, not a later reader.
Checked, in each inline backtick span (fenced blocks are sketches, not citations):
  names: each segment of an `a::b` path, a name called (`foo(`), a name with `_` (`foo_bar`,
      `MAX_PROOFS`), a CamelCase name with an inner capital (`LocalPeer`) and a span that is one
      capitalised word (`Payloads`): the word occurs in code (Rust outside its comments, its
      literals included; any other repo file outside docs/ that is not Markdown, and spec/), is a
      repo file's name without its extension (a TLA model's .cfg), or is a test's name less its
      `_spec_...` tail or its `_plain`/`_large`/`_exhaustive` size. A name only a comment keeps
      fails. Skipped: a name starting or ending in `_`, shorter than 3, or beside `*`, `<`, `>`,
      `{`, `}`, `$`, `-`, `/` (a pattern, placeholder, flag or alternative); `a_{b,c}` names `a_b`
      and `a_c`.
  members: `Type::item` (not `Enum::Variant::item`), where our Rust defines `Type`: `item` is one of
      its variants, fields or associated items (of its impls, or its `Deref` target's), or the code
      writes `Type::item` itself (a std, third-party or generated type of that name). Read by regex
      from rustfmt'd source at the item's own brace depth; a type a macro fills in passes any item.
  families: a name ending in `_` followed by `*` (a test family, not after another pattern
      character): some code word starts with it, so a family whose tests all went fails.
  paths: a span that is a relative path of a source extension (`core/x/src/y.rs`, `apply/mod.rs`):
      a repo file's path ends with it, also with `src/` left out (`store/store.rs`) or its crate
      named by package (`osis-keys/tests/it/x.rs`).
  model tests: a Rust string `"<crate>-model mod::test_name ..."` (a test citing a model's test as
      its source): core/test/<crate> has that fn and each module named.
A repo file is tracked, or untracked and not ignored (a new file counts before its `git add`).
Not read: notes/complaints/ (consumed), the Investigations section of notes/time-limits.md (a record
of what ran then), notes/stub-rewrite.md (its inventory names the code the rewrite deletes), spec/ (its names are wire and grammar terms). Names not in our code on purpose
(third-party, placeholder, planned, rejected, removed; `Type::item` too) are listed in
tools/code_refs_allow.txt with a reason; a listed name that is in the code, or that nothing cites,
fails.
Usage: python3 tools/code_refs.py   (exit 1 on any stale name; policy.py runs it)"""
import bisect, itertools, os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import members as members_of

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOW = "tools/code_refs_allow.txt"
# lists of names, not code: a renamed name they still hold would pass (their own checks catch it)
LISTS = {ALLOW, "tools/known_failures.txt"}
NOT_SRC = (".md", ".ttf", ".snap", ".vec")
PATH_EXTS = (".rs", ".tla", ".cfg", ".py", ".sh", ".toml", ".osis", ".java", ".kt")
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SPAN = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
FENCE = re.compile(r"^[ \t]*```.*?^[ \t]*```[^\n]*$", re.M | re.S)
CAMEL = re.compile(r"[A-Z][a-z0-9]+[A-Z]")
CAPITAL = re.compile(r"[A-Z][a-z0-9]+")
PATHLIKE = re.compile(r"^(?:\./)?[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*$")
# beside these a word is a pattern, a placeholder or a flag (`foo_*`, `<name>`, `--no-lan`, `X/Y`)
GLOB = set("*<>{}$-/")
BRACES = re.compile(r"(\w*)\{(\w+(?:,\w+)+)\}")
# a test's name ends in the spec section it covers (tools/spec_map.py); a note may leave it out
SPEC_TAIL = re.compile(r"_spec_\w*$")
# a property runs as `_plain`, `_large` or `_exhaustive` tests (notes/testing.md); a note may name them at once
SIZE_TAIL = re.compile(r"_(?:plain|large|exhaustive)$")
OWNER = re.compile(r"\b([A-Z]\w*)::$")
PAIR = re.compile(r"[A-Z]\w*::[A-Za-z_]\w*")
# Rust: a comment or literal (its first character, then the rest: the charset lead keeps the scan fast;
# block comments are taken as not nested), a doc comment line, an item that has members, and a line that
# may declare one, indented (a variant, a line a macro fills in: a metavariable or a call, an associated fn, const
# or type, a field); the last two read text that
# starts with a newline, which also keeps their scan fast
LIT = re.compile(r'''[/"'r](?:(?<=/)(?:/[^\n]*|\*.*?\*/)|(?<=")(?:[^"\\]|\\.)*"|(?<=')(?:\\(?:u\{\w+\}|x\w\w|.)|[^'\\\n])'|(?<=r)(#*)".*?"\1)''', re.S)
DOC = re.compile(r"\n[ \t]*//(?:/(?!/)|!)(.*)")
VIS = r"(?:pub(?:\([^)\n]*\))?[ \t]+)?"
HEAD = re.compile(r"\n[ \t]*" + VIS + r"(?:(?:unsafe|default)[ \t]+)*(impl|struct|enum|trait|union)\b([^{;]*)([{;])")
CAND = re.compile(r"\n[ \t]+(?:(?P<v>[A-Z]\w*)|(?P<x>\$|[a-z_]\w*![ \t]*[({\[])|" + VIS + r"(?:(?:(?:const|async|unsafe|default|extern[ \t]+\"[^\"\n]*\")[ \t]+)*"
                  r"(?:fn|const|type)[ \t]+(?:r#)?(?P<m>\w+)|(?:r#)?(?P<f>[A-Za-z_]\w*)[ \t]*:(?!:)))")
# in a type's member set: the type's members are partly a macro's (unknown), or also those of `Deref` target
OPEN, DEREF = "$", "Deref="
# a derived or std trait's method, every type's
DERIVED = {"default", "clone", "eq", "cmp", "partial_cmp", "hash", "fmt", "from", "into", "try_from", "to_string", "drop", "deref"}
TARGET = re.compile(r"\btype[ \t]+Target[ \t]*=[ \t&]*(?:dyn[ \t]+)?(?:\w+::)*(\w+)")
# vendored crates: their names are code, their docs not ours to check
VENDORED = "libs/kit/patches/"


def cited(text):
    """(line number, name or path, kind) of each code citation in `text`."""
    text = FENCE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    line, last = 1, 0
    for s in SPAN.finditer(text):
        line, last = line + text.count("\n", last, s.start()), s.start()
        span = s.group(1).strip()
        if PATHLIKE.match(span) and span.endswith(PATH_EXTS):
            yield line, span[2:] if span.startswith("./") else span, "path"
            continue
        # `a_{b,c}` names `a_b` and `a_c`
        span = BRACES.sub(lambda m: " ".join(m.group(1) + x for x in m.group(2).split(",")), span)
        for w in WORD.finditer(span):
            name, a, b = w.group(0), w.start(), w.end()
            before, after = span[max(0, a - 1):a], span[b:b + 1]
            # `foo_*` names a family: some code word starts with `foo_`
            if name.endswith("_") and after == "*" and not name.startswith("_") and len(name) >= 3 and before not in GLOB:
                yield line, name, "prefix"
                continue
            if name.startswith("_") or name.endswith("_") or len(name) < 3 or GLOB & {before, after}:
                continue
            pathy = span[max(0, a - 2):a] == "::" or span[b:b + 2] == "::"
            # `Type::item`: the item is one of the type's own when the code defines the type
            # not `Enum::Variant::item`, whose item is the variant's payload's
            if (o := OWNER.search(span[:a])) and not re.search(r"\b[A-Z]\w*::$", span[:o.start()]):
                yield line, o.group(1) + "::" + name, "member"
            if pathy or after == "(" or "_" in name or CAMEL.match(name) or CAPITAL.fullmatch(span):
                yield line, name, "name"


def skipped(rel, text):
    """`text` with the parts not checked blanked (line numbers kept)."""
    if rel == "notes/stub-rewrite.md":  # its inventory names the code the rewrite deletes
        return "\n" * text.count("\n")
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


def stale(docs, words, ends, allow, members=None):
    """Stale citations in `docs` ({path: text}) against the code's `words`, path tails `ends` and
    `members` ({type: its variants, fields and associated items}), and stale lines of `allow`
    ({name: (line, reason)})."""
    used, by_order, members = set(), sorted(words), members or {}

    def has_member(owner, item, seen):
        # a type a macro fills in is open; a `Deref` target's members are the type's too
        seen.add(owner)
        got = members.get(owner, ())
        return item in got or item in DERIVED or OPEN in got or any(has_member(t[len(DEREF):], item, seen) for t in got
                                                 if t.startswith(DEREF) and t[len(DEREF):] not in seen)

    def found(name, kind):
        if kind == "prefix":
            i = bisect.bisect_left(by_order, name)
            return i < len(by_order) and by_order[i].startswith(name)
        if kind == "member":
            owner, item = name.split("::")
            return name in words or owner not in members or has_member(owner, item, set())
        return name in words if kind == "name" else name in ends
    for rel, text in docs.items():
        seen = set()
        for line, name, kind in cited(skipped(rel, text)):
            if name in allow:
                used.add(name)
            elif not found(name, kind) and name not in seen:
                seen.add(name)
                what = f"no `{name.split('::')[1]}` in the code's `{name.split('::')[0]}`" if kind == "member" else f"no such {kind} in the code"
                yield f"{rel}:{line}: `{name}`: {what} ({ALLOW} for a third-party name or placeholder)"
    for name, (n, why) in sorted(allow.items(), key=lambda x: x[1][0]):
        if not why:
            yield f"{ALLOW}:{n}: `{name}` has no reason"
        if name in words or name in ends:
            yield f"{ALLOW}:{n}: `{name}` is in the code (drop the line)"
        elif name not in used:
            yield f"{ALLOW}:{n}: `{name}` is cited nowhere (drop the line)"


def owner(kind, head):
    """The type an item header names: `struct Name`, `impl<T> Trait for path::Name<T> where ...`."""
    if kind != "impl":
        m = re.match(r"\s*(?:r#)?(\w+)", head)
        return m and m.group(1)
    h = head.strip()
    if h.startswith("<"):
        d = 0
        for i, c in enumerate(h):
            d += (c == "<") - (c == ">")
            if d == 0:
                h = h[i + 1:]
                break
    h = re.split(r"\bfor\b", re.split(r"\bwhere\b", h)[0])[-1]
    m = re.match(r"[\s&]*(?:dyn\s+|mut\s+)?(?:\w+::)*(\w+)", h)
    return m and m.group(1)


def rust(src, members):
    """Rust source `src`: its code with comments left out (literals kept: an env var or a test is named
    in a string), its doc comments ({line: text}), and each type's members (variants, fields and the
    associated items of its impls, at the item's own brace depth) added to `members`."""
    strings = []

    def lit(m):
        t = m.group()
        if t[0] != "/":
            strings.append(t)
        return "\n" * t.count("\n")
    bare = "\n" + LIT.sub(lit, src)
    src = "\n" + src
    docs, line, last = {}, 0, 0
    for m in DOC.finditer(src):
        line += src.count("\n", last, m.start() + 1)
        last = m.start() + 1
        docs[line] = m.group(1)
    # line j of `lines` is the source's line j
    lines = bare.split("\n")
    starts = [0, *itertools.accumulate(len(l) + 1 for l in lines)]

    def pick(kind, c):
        return c.group("v") if kind == "enum" else c.group("f") if kind in ("struct", "union") else c.group("m")
    heads = {}
    for m in HEAD.finditer(bare):
        if m.group(3) == "{" and (name := owner(m.group(1), m.group(2))):
            p = m.end() - 1
            n = bisect.bisect_right(starts, p) - 1
            rest = bare[p + 1:starts[n + 1]]
            if rest.count("{") >= rest.count("}"):
                heads[n] = (m.group(1), name)
                if m.group(1) == "impl" and re.search(r"\bDeref\b", m.group(2)) and (t := TARGET.search(bare, p)):
                    members.setdefault(name, set()).add(DEREF + t.group(1))
            else:
                # on one line: `enum Kind { A, B }`
                for part in rest[:rest.find("}")].split(","):
                    if (c := CAND.match("\n " + part)) and (v := pick(m.group(1), c)):
                        members.setdefault(name, set()).add(v)
    if heads:
        # each line's brace depth at its start
        depth = [0, *itertools.accumulate(l.count("{") - l.count("}") for l in lines)]
        order = sorted(heads)
        # where each item's body ends: the first line after it starting shallower than its body
        at = {}
        for j, v in enumerate(depth):
            at.setdefault(v, []).append(j)
        end = {}
        for n in order:
            d = depth[n + 1]
            end[n] = min((ls[i] for v, ls in at.items() if v < d and (i := bisect.bisect_right(ls, n)) < len(ls)), default=len(lines))
        for c in CAND.finditer(bare):
            j = bisect.bisect_right(starts, c.start() + 1) - 1
            # a member is on a line straight inside its item's braces: the nearest item before it
            # whose body it is in, one level deeper
            for n in reversed(order[:bisect.bisect_left(order, j)]):
                if j < end[n]:
                    kind, name = heads[n]
                    if depth[j] == depth[n + 1] and (v := OPEN if c.group("x") else pick(kind, c)):
                        members.setdefault(name, set()).add(v)
                    break
    return bare + " ".join(strings), docs


def code_names(root, files):
    """The words of the code (and of spec/, which names wire fields and constants), every tail of
    each source path, each Rust type's members, and the Rust doc comments ({path: text})."""
    words, members, docs = set(), {}, {}
    for rel in files:
        # not the tools' own test fixtures, whose planted names are none
        if (rel.startswith("spec/") or not rel.endswith(NOT_SRC)) and rel not in LISTS and not rel.startswith("docs/") \
                and not re.match(r"tools/\w+_test\.", rel) and os.path.isfile(os.path.join(root, rel)):
            text = open(os.path.join(root, rel), errors="replace").read()
            if rel.endswith(".rs"):
                text, doc = rust(text, members)
                # `Type::item` as the code writes it: a std, third-party or generated type's item
                words.update(PAIR.findall(text))
                if doc and not rel.startswith(VENDORED):
                    n = max(doc)
                    docs[rel] = "\n".join(doc.get(i, "") for i in range(1, n + 1))
            words.update(WORD.findall(text))
    words |= {SPEC_TAIL.sub("", w) for w in words if "_spec_" in w}
    words |= {SIZE_TAIL.sub("", w) for w in words if w.endswith(("_plain", "_large", "_exhaustive"))}
    # a file's name without its extension (a TLA model's .cfg, a script) is a name too
    words.update(os.path.splitext(os.path.basename(r))[0] for r in files)
    # a path cites a file by any tail of its path, also with the crate's src/ left out
    # (`store/store.rs`) or its directory named by its package (`osis-keys/tests/it/x.rs`)
    ends = set()
    for f in files:
        if f.endswith(PATH_EXTS):
            for g in {f, f.replace("/src/", "/")}:
                parts = g.split("/")
                ends.update("/".join(parts[i:]) for i in range(len(parts)))
    for d, pkg in members_of().items():
        d = os.path.relpath(d, root) + "/"
        ends.update(pkg + "/" + f[len(d):] for f in files if f.startswith(d) and f.endswith(PATH_EXTS))
    return words, ends, members, docs


# a Rust string citing a model crate's test (core/test/<name>-model): `"roles-model mod::test_name ..."`
MODEL_CITE = re.compile(r'"([a-z]+-model) ((?:\w+::)+\w+)')


def model_citations(root, files):
    """Each Rust string citing a model crate's test whose crate (core/test/<crate>) has no such
    module or fn."""
    def model(crate):
        d = f"core/test/{crate}/"
        body = "".join(open(os.path.join(root, f), errors="replace").read() for f in files
                       if f.startswith(d) and f.endswith(".rs") and os.path.isfile(os.path.join(root, f)))
        stems = {os.path.splitext(os.path.basename(f))[0] for f in files if f.startswith(d)}
        return set(re.findall(r"\bfn (\w+)", body)), set(re.findall(r"\bmod (\w+)", body)) | stems
    models = {}
    for rel in files:
        if not rel.endswith(".rs") or rel.startswith(VENDORED) or not os.path.isfile(os.path.join(root, rel)):
            continue
        text = open(os.path.join(root, rel), errors="replace").read()
        for m in MODEL_CITE.finditer(text):
            crate, cite = m.groups()
            if crate not in models:
                models[crate] = model(crate)
            fns, mods = models[crate]
            *path, name = cite.split("::")
            if name not in fns or not set(path) <= mods:
                yield f"{rel}:{text.count(chr(10), 0, m.start()) + 1}: `{crate} {cite}`: no such test in core/test/{crate}"


def check(root=ROOT):
    # tracked files and untracked ones not ignored: a new file counts before its `git add`
    files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=root, capture_output=True, text=True).stdout.split()
    docs = {rel: open(os.path.join(root, rel), errors="replace").read() for rel in files
            if rel.startswith(("notes/", "issues/")) and rel.endswith(".md") and not rel.startswith("notes/complaints/")
            and os.path.isfile(os.path.join(root, rel))}
    allow, errs = allow_list(root)
    yield from errs
    words, ends, members, rdocs = code_names(root, files)
    yield from stale({**docs, **rdocs}, words, ends, allow, members)
    yield from model_citations(root, files)


if __name__ == "__main__":
    errs = list(check())
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
