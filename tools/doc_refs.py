#!/usr/bin/env python3
"""Doc pointers (notes/gate.md, Policy checks): every pointer into notes/, issues/ or spec/ names a
file that exists, and a pointer into a notes or spec file names a part of it that exists:
  `<file>, Section` / `<file> (Section)` / `<file> Section`: the words (starting with a capital)
      start with, or are the start of, a heading, bold lead, list item or `Lead:` paragraph of the
      file, or a name its grammar defines (a fenced block line's first word, `Name :=`). A first
      word with `_` or `::`, or all in capitals, is code or an acronym: not checked.
  `<file> §N[.M]`, also `§N, §M`, `§N and §M`, `§N-§M`: a heading numbered N[.M] exists.
  `<file> §N Section` / `<file> §N (Section)`: as above, within §N (within the file when several
      sections are named).
Deleted issues and renamed sections otherwise leave pointers that rot unseen. Skipped: docs/
(may lag), vendored patches, complaints (consumed), the tools' own test fixtures.
Usage: python3 tools/doc_refs.py   (exit 1 on any stale pointer; policy.py runs it)"""
import os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PATH = re.compile(r"\b((?:notes|issues|spec)/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.md)")
NUM = r"\d+(?:\.\d+)*"
# Section numbers right after the path: §N, then more joined by `,`/and/or/to (each with its §) or a range.
SECS = re.compile(rf"[ \t]+§ ?{NUM}(?:(?:\s*[-–]\s*§?|(?:\s*,\s*|\s+(?:and|or|to)\s+)§) ?{NUM})*")
# What names a section after the path or the numbers: `, Name`, ` (Name`, or ` Name`.
NAME = re.compile(r"(,\s*|\s+\(|[ \t]+)([A-Z].{0,100})", re.S)
WRAP = re.compile(r"\s*\n\s*(?://[/!]?|#|\(\*|\*)?\s*")
HEADING = re.compile(rf"^(#+)\s+({NUM})\.?\s", re.M)


def norm(s):
    return re.sub(r"\s+", " ", re.sub(r"[`*_§]", "", s)).strip().lower()


def section(text, num):
    """The text of the heading numbered `num` up to the next heading of its level or above, or None."""
    for m in HEADING.finditer(text):
        if m.group(2) == num:
            end = re.compile(rf"^#{{1,{len(m.group(1))}}}\s", re.M).search(text, m.end())
            return text[m.start():end.start() if end else len(text)]
    return None


def leads(text):
    """The starts a pointer may name: headings, bold leads, list items, `Lead:` paragraphs, names a grammar defines."""
    lines = text.splitlines()
    c = [re.sub(r"^#+\s*", "", l) for l in lines if l.startswith("#")]
    c += re.findall(r"\*\*([^*\n]+)\*\*", text)
    c += [re.sub(r"^\s*([-*]|\d+\.)\s+", "", l) for l in lines if re.match(r"^\s*([-*]|\d+\.)\s", l)]
    c += [m.group(1) for m in re.finditer(r"^[ \t]*([A-Z][^:\n]{2,60}):", text, re.M)]
    # A name a grammar defines: a fenced block line's first word, or `Name :=`.
    c += [w for b in re.findall(r"^```[^\n]*\n(.*?)^```", text, re.M | re.S) for w in re.findall(r"^([A-Z]\w+)\b", b, re.M)]
    c += re.findall(r"\b([A-Z]\w*) :=", text)
    c = [norm(re.sub(r"\s*\([^)]*\)\s*$", "", x)) for x in c]
    c = [x for x in c if x]
    return c + [re.sub(r"^\d+(\.\d+)*\.? ", "", x) for x in c]


def named(rest, cands):
    """Whether `rest` (the text after the pointer) starts with one of `cands`, or names its start."""
    terms = {norm(re.split(r"[):;.,]| \(| —", s)[0]) for s in (rest.split("\n")[0], WRAP.sub(" ", rest))}
    r = norm(WRAP.sub(" ", rest))
    ok = any(r.startswith(x) or any(t.startswith(x) or (len(t) > 2 and x.startswith(t)) for t in terms) for x in cands)
    return ok, max(terms, key=len)


def identifier(rest):
    """A bare word after the path that is code or a constant, not a section name."""
    w = rest.split(None, 1)[0] if rest.split() else ""
    w = w.rstrip(".,:;)")
    return "_" in w or "::" in w or (len(w) > 1 and w.isupper())


def refs(rel, text, read):
    """Stale pointers in `text` (file `rel`); `read(p)` gives a doc's text, or None if it does not exist."""
    cache = {}

    def cands(p, nums):
        key = (p, nums)
        if key not in cache:
            t = read(p)
            cache[key] = leads(section(t, nums[0]) if len(nums) == 1 else t)
        return cache[key]

    for m in PATH.finditer(text):
        p = m.group(1)
        where = lambda: f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
        t = read(p)
        if t is None:
            yield where(), f"{p} does not exist"
            continue
        if p.startswith("issues/"):
            continue
        end, nums = m.end(), ()
        s = SECS.match(text, end)
        if s:
            nums = tuple(re.findall(NUM, s.group(0)))
            missing = [n for n in nums if section(t, n) is None]
            if missing:
                yield where(), f"{p} §{', §'.join(missing)}: no such numbered section"
                continue
            end = s.end()
        n = NAME.match(text, end)
        if not n:
            continue
        rest = n.group(2)
        if identifier(rest):
            continue
        ok, term = named(rest, cands(p, nums))
        if not ok:
            at = f" §{nums[0]}" if len(nums) == 1 else ""
            yield where(), f"{p}{at}, \"{term}\": no such section, bold lead, list item or `Lead:` paragraph there"


def check():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    ignored = {l.strip() for l in open(os.path.join(ROOT, ".gitignore")) if l.strip().endswith(".md")}
    docs = {}

    def read(p):
        if p not in docs:
            f = os.path.join(ROOT, p)
            docs[p] = open(f, errors="replace").read() if os.path.isfile(f) else ("" if p in ignored else None)
        return docs[p]

    for rel in tracked:
        if rel.startswith(("docs/", "libs/kit/patches/", "notes/complaints/")) or re.match(r"tools/\w+_test\.", rel) \
                or not rel.endswith((".md", ".rs", ".py", ".sh", ".tla", ".cfg", ".toml", ".txt", ".osis")) \
                or not os.path.isfile(os.path.join(ROOT, rel)):
            continue
        for where, msg in refs(rel, open(os.path.join(ROOT, rel), errors="replace").read(), read):
            yield f"{where}: {msg}"


if __name__ == "__main__":
    errs = list(check())
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)
