#!/usr/bin/env python3
"""Spec-to-test map (notes/testing.md, Spec citations). Collects every Rust test (`#[test]`
functions, proptest cases included) and every live vector case, with the spec sections each
cites, and writes notes/testing-map.md: per numbered spec section, the tests citing it; every
MUST / MUST NOT sentence of spec/*.md plus the refusal rules listed in RULES, each with the tests
and issues citing its anchor; then gaps (sections nothing cites, MUSTs and rules without a test)
and uncited tests.

Anchors: a citation `spec/<file>.md §N (anchor)` names one rule of §N. Every MUST sentence must
match a RULES entry (by a substring of the sentence), else it is listed as unanchored. A rule is
tested when a test cites its anchor, issued when an issue in issues/ does.

A test's citations: `spec/<file>.md §N[.M]` in the comment or attribute lines right above it
(a bare `§N` refers to the last file named there, else to the file header's); without any, the
citations of the file's `//!` header (marked inherited). Vector cases cite through `spec:`.
Exempt from `--uncited`: the models in core/test/ (oracles, not the implementation) and tests whose comment says
`spec: none` (test infrastructure itself), or that cite nothing in a file whose `//!` header says
`spec: none` (client surfaces specified in notes/, not spec/).

Usage (repo root):
  python3 tools/spec_map.py            write notes/testing-map.md (generated, gitignored)
  python3 tools/spec_map.py --uncited  exit 1 if some test cites nothing (CI)
  python3 tools/spec_map.py --gaps     exit 1 if a MUST or rule has neither a test nor an issue"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "notes/testing-map.md")
SOURCES = ["core", "cli"]
MODELS = ("core/test/crdt-model/", "core/test/membership-model/")
# An anchor is a parenthesis right after the section holding no citation of its own; matched by
# lookahead so citations inside other parentheses are still found.
CITE = re.compile(r"(spec/[\w-]+\.md)?\s*§\s*(\d+(?:\.\d+)*)(?=\s*\(([^()§]*)\))?")
FN = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)")
SHOWN = 8


def citations(text, default_file=None):
    out, cur = [], default_file
    for m in CITE.finditer(text):
        if m.group(1):
            cur = m.group(1)
        if cur:
            out.append((cur, m.group(2), (m.group(3) or "").strip().lower() or None))
    return out


def rust_tests():
    tests = []
    for top in SOURCES:
        for path in sorted(glob.glob(os.path.join(ROOT, top, "**/*.rs"), recursive=True)):
            if "/target/" in path:
                continue
            rel = os.path.relpath(path, ROOT)
            lines = open(path).read().splitlines()
            header = " ".join(l[3:] for l in lines if l.startswith("//!"))
            header_cites = citations(header)
            header_file = header_cites[0][0] if header_cites else None
            header_cites = [(f, s, None) for f, s, _ in header_cites]
            for i, line in enumerate(lines):
                if line.strip() != "#[test]":
                    continue
                name = None
                for nxt in lines[i + 1 : i + 8]:
                    m = FN.match(nxt)
                    if m:
                        name = m.group(1)
                        break
                if not name:
                    continue
                above, j = [], i - 1
                while j >= 0 and lines[j].strip().startswith(("//", "#[")):
                    above.append(lines[j])
                    j -= 1
                comment = " ".join(l.strip().lstrip("/!") for l in reversed(above))
                own = citations(comment + " " + name.replace("_", " "), header_file)
                exempt = "spec: none" in comment or rel.startswith(MODELS) or (not own and "spec: none" in header)
                tests.append({"id": f"{rel}::{name}", "cites": own or header_cites, "inherited": not own, "exempt": exempt})
    return tests


def vector_cases():
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "core/test/vectors/**/*.vec"), recursive=True)):
        rel = os.path.relpath(path, ROOT)
        for rec in open(path).read().split("\n\n"):
            fields = dict(l.split(": ", 1) for l in rec.splitlines() if ": " in l and not l.startswith("#"))
            if "case" in fields and "pending" not in fields:
                out.append({"id": f"{rel}#{fields['case']}", "cites": citations(fields.get("spec", "")), "inherited": False, "exempt": False})
    return out


def spec_sections():
    secs = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "spec/*.md"))):
        rel = os.path.relpath(path, ROOT)
        for line in open(path):
            m = re.match(r"^#{2,4}\s+(\d+(?:\.\d+)*)\.?\s+(.*)", line)
            if m:
                secs.setdefault(rel, []).append((m.group(1), m.group(2).strip()))
    return secs


# (file, section, anchor, a substring of the rule's sentence). Every MUST sentence matches one;
# the others are refusal rules ("cannot", "refused", "only") checked by negative tests.
RULES = [
    ("spec/commits.md", "1", "delta fits a blob", "Paging and chunking keep every delta and page within a blob"),
    ("spec/commits.md", "2", "membership no expires", "Membership commits MUST NOT carry `expires`"),
    ("spec/commits.md", "2", "created one minting", "`/created` part MUST be exactly one minting of the record"),
    ("spec/commits.md", "3", "shared key commit form", "(link key, recovery key) MUST use it"),
    ("spec/commits.md", "4", "signature", "signature MUST verify"),
    ("spec/commits.md", "5", "keep at least", "compaction MUST NOT drop it"),
    ("spec/commits.md", "5", "keep at most", "every node MUST drop the body"),
    ("spec/commits.md", "5", "covering copies", "Every write the covering snapshot holds under a dot the body holds a write of"),
    ("spec/commits.md", "5", "purge not membership", "It MUST NOT name membership deltas"),
    ("spec/commits.md", "5", "purge no expires", "A commit carrying a purge request MUST NOT carry `expires`"),
    ("spec/crypto.md", "1", "batch verification", "Batch and single verification MUST agree"),
    ("spec/crypto.md", "4", "encrypt under covering epoch", "MUST NOT **encrypt under**"),
    ("spec/crypto.md", "4", "removed member", "covers** a departure of M if it holds no box for M"),
    ("spec/crypto.md", "3", "fresh deposit seed", "MUST write a fresh one in each rotation of the read role"),
    ("spec/data-model.md", "5", "cbor profile", "A decoder MUST reject anything outside it"),
    ("spec/data-model.md", "6", "chunk threshold", "MUST be chunked; below it MUST NOT be"),
    ("spec/permissions.md", "1", "owner not removable", "cannot be removed by other admins"),
    ("spec/permissions.md", "1", "membership-class by admins", "are written only by its admins"),
    ("spec/permissions.md", "2", "invite scope", "Invite holders cannot change or remove any other edge"),
    ("spec/permissions.md", "2", "edge inbox delivery", "MUST also be delivered to G as an inbox blob"),
    ("spec/permissions.md", "6", "linked frontier bounds", "A linked frontier's tree blobs MUST be in the commit's chunk list"),
    ("spec/permissions.md", "3", "required rotation", "MUST do so before it next encrypts"),
    ("spec/permissions.md", "3", "left out", "MUST NOT box a member actor M"),
    ("spec/permissions.md", "3", "removal placement", "MUST, in the same sync and before any other upload"),
    ("spec/permissions.md", "3", "drop lost secrets", "MUST drop those role secrets"),
    ("spec/permissions.md", "4", "stranded heartbeat", "It MUST place one with `stranded: true`"),
    ("spec/permissions.md", "5.1", "frontier received", "a frontier MUST NOT cover what A had not received"),
    ("spec/permissions.md", "5.2", "dot reuse", "A revoked actor cannot reuse a covered dot"),
    ("spec/permissions.md", "7", "one import", "a client MUST NOT import t"),
    ("spec/permissions.md", "9", "link finalized", "MUST write it once L's edge expired or was self-removed"),
    ("spec/sync.md", "2", "home label", "It MUST have one when it names it as its inbox"),
    ("spec/sync.md", "5", "stale sync key", "is answered with that step's child on the path"),
    ("spec/sync.md", "5", "claim refusals", "Otherwise refused like an unknown key"),
    ("spec/sync.md", "5", "dropped claim set", "A claim at a step whose set the server has dropped is refused"),
    ("spec/sync.md", "5", "register", "refuse anything else"),
    ("spec/sync.md", "5", "claim set hash", "it MUST hash to the step's"),
    ("spec/sync.md", "5", "upload refusals", "Refused: a bad stamp"),
    ("spec/sync.md", "5", "deposit refusals", "Refused like an upload, when the label's deposit budget is full"),
    ("spec/sync.md", "5", "delete keys", "a delete signature that verifies under the blob prefix's commitment"),
    ("spec/sync.md", "5", "download needs open", "only for labels opened on the connection"),
    ("spec/sync.md", "6", "flow control", "MUST NOT close a connection over unwritten bytes below"),
    ("spec/sync.md", "5", "member peer", "A member peer serving a label applies the same rule"),
    ("spec/sync.md", "5", "deposit budget", "reports the remaining budget only to a deposit"),
    ("spec/sync.md", "10", "lan replay", "other than the first it verified that announcement from"),
    ("spec/sync.md", "10", "server key check", "a client MUST check the server's key"),
    ("spec/sync.md", "10", "no 0-rtt", "0-RTT MUST NOT be used"),
    ("spec/sync.md", "10", "mutual auth", "Both sides MUST authenticate"),
    ("spec/versioning.md", "1", "read older", "Readers MUST accept every older version forever"),
    ("spec/versioning.md", "1", "oldest writer version", "Writers MUST emit the oldest version"),
    ("spec/versioning.md", "2", "park unknown", "A node MUST NOT discard, reject or crash"),
    ("spec/versioning.md", "2", "reject malformed", "MUST be rejected, never parked"),
    ("spec/versioning.md", "4", "additive revision", "MUST be an additive superset"),
    ("spec/versioning.md", "4", "additive revision", "a new revision MUST NOT"),
    ("spec/versioning.md", "5", "mistyped reads absent", "MUST NOT be taken as a value of the type"),
    ("spec/wire.md", "5", "unpad", "which MUST be present"),
    ("spec/wire.md", "10", "reserved flags", "reserved and MUST be zero"),
]
# Rules nothing can test yet, with why; not counted as gaps.
VACUOUS = {
    ("spec/crypto.md", "1", "batch verification"): "no batch verification exists (osis-crypto sign.rs)",
    ("spec/versioning.md", "1", "read older"): "FORMAT_VERSION is 1: no older version",
    ("spec/versioning.md", "1", "oldest writer version"): "FORMAT_VERSION is 1: every commit is version 1",
}
# Sentences that use the words without stating a rule.
NOT_RULES = ["MUST, MUST NOT, SHOULD are normative"]
SENTENCE = re.compile(r"(?<=[.;:])\s+(?=[A-Z*`])")


def spec_sentences():
    """(file, section, sentence) for every sentence of spec/*.md, sections as numbered headings."""
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "spec/*.md"))):
        rel, sec = os.path.relpath(path, ROOT), "0"
        for line in open(path):
            m = re.match(r"^#{2,4}\s+(\d+(?:\.\d+)*)\.?\s+(.*)", line)
            if m:
                sec = m.group(1)
                continue
            for s in SENTENCE.split(line.strip().lstrip("-0123456789. ")):
                if s:
                    out.append((rel, sec, s))
    return out


def rules():
    """The checklist: MUST sentences and RULES entries, with problems (unanchored, stale)."""
    sents = spec_sentences()
    items, problems = {}, []
    for f, sec, a, sub in RULES:
        hit = [s for g, n, s in sents if g == f and n == sec and sub in s]
        if not hit:
            problems.append(f"stale rule: {f} §{sec} ({a}): `{sub}` not found")
            continue
        it = items.setdefault((f, sec, a), {"musts": [], "text": hit[0]})
        it["musts"] += [s for s in hit if re.search(r"\bMUST\b", s)]
    for f, sec, s in sents:
        if re.search(r"\bMUST\b", s) and not any(n in s for n in NOT_RULES):
            if not any(g == f and n == sec and sub in s for g, n, _, sub in RULES):
                problems.append(f"unanchored MUST: {f} §{sec}: {s[:120]}")
    shoulds = [(f, sec, s) for f, sec, s in sents if re.search(r"\bSHOULD\b", s) and not any(n in s for n in NOT_RULES)]
    return items, problems, shoulds


def issue_cites():
    by = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "issues/*.md"))):
        for f, s, a in citations(open(path).read()):
            if a:
                by.setdefault((f, s, a), set()).add(os.path.relpath(path, ROOT))
    return by


def short(s, n=110):
    s = s.replace("|", "/")
    return s if len(s) <= n else s[: n - 1] + "…"


def render():
    tests = rust_tests() + vector_cases()
    secs = spec_sections()
    by, anchored = {}, {}
    for t in tests:
        for f, s, a in set(t["cites"]):
            # A citation of §N.M also counts for §N.
            parts = s.split(".")
            for k in range(1, len(parts) + 1):
                by.setdefault((f, ".".join(parts[:k])), set()).add(t["id"])
            if a:
                anchored.setdefault((f, s, a), set()).add(t["id"])
    items, problems, shoulds = rules()
    issued = issue_cites()
    musts = sum(1 for it in items.values() if it["musts"])
    tested = {k for k in items if anchored.get(k)}
    gaps_r = [k for k in items if k not in tested and k not in VACUOUS]
    open_r = [k for k in gaps_r if not issued.get(k)]
    lines = [
        "# Spec-to-test map",
        "> Summary: Generated by tools/spec_map.py (do not edit): for each numbered spec section, the tests and vector cases citing it; every MUST sentence and refusal rule with the tests and issues citing its anchor; then the gaps and the tests that cite nothing.",
        "",
        f"{len(tests)} tests and vector cases; {sum(1 for t in tests if t['inherited'])} cite only through their file header.",
        f"Rules: {len(items)} anchors ({musts} holding MUST sentences, the rest refusal rules); {len(tested)} tested, {len(gaps_r) - len(open_r)} untested with an issue, {len(open_r)} with neither, {len(VACUOUS)} vacuous.",
        "",
    ]
    gaps = []
    for f, its in secs.items():
        lines += [f"## {f}", "", "| § | section | n | tests |", "|---|---|---|---|"]
        for s, title in its:
            ids = sorted(by.get((f, s), ()))
            if not ids:
                gaps.append(f"{f} §{s} {title}")
            shown = ", ".join(f"`{i}`" for i in ids[:SHOWN]) + (f" +{len(ids) - SHOWN}" if len(ids) > SHOWN else "")
            lines.append(f"| {s} | {title} | {len(ids)} | {shown} |")
        lines.append("")
    lines += ["## MUSTs and refusal rules", "", "Cite a rule as `spec/<file>.md §N (anchor)`.", "", "| rule | kind | tests | issues | sentence |", "|---|---|---|---|---|"]
    for (f, s, a), it in items.items():
        ids = sorted(anchored.get((f, s, a), ()))
        shown = ", ".join(f"`{i}`" for i in ids[:4]) + (f" +{len(ids) - 4}" if len(ids) > 4 else "")
        iss = ", ".join(sorted(issued.get((f, s, a), ()))) or (f"vacuous: {VACUOUS[(f, s, a)]}" if (f, s, a) in VACUOUS else "")
        lines.append(f"| {f} §{s} ({a}) | {'MUST' if it['musts'] else 'rule'} | {shown} | {iss} | {short(it['text'])} |")
    lines += ["", "## MUSTs without a test", ""]
    lines += [f"- {f} §{s} ({a}): {', '.join(sorted(issued[(f, s, a)])) if issued.get((f, s, a)) else 'no issue'}" for f, s, a in gaps_r] or ["None."]
    lines += [""]
    if problems:
        lines += ["## Rule table problems", ""] + [f"- {p}" for p in problems] + [""]
    lines += ["## SHOULDs (not gated; notes/testing.md)", ""] + [f"- {f} §{s}: {short(t, 140)}" for f, s, t in shoulds] + [""]
    unknown = sorted({f"{f} §{s}" for t in tests for f, s, _ in t["cites"] if not any(x == s for x, _ in secs.get(f, []))})
    lines += ["## Gaps (sections nothing cites)", ""] + [f"- {g}" for g in gaps] + [""]
    if unknown:
        lines += ["## Citations of unknown sections", ""] + [f"- {u}" for u in unknown] + [""]
    uncited = [t["id"] for t in tests if not t["cites"] and not t["exempt"]]
    exempt = [t["id"] for t in tests if not t["cites"] and t["exempt"]]
    lines += ["## Uncited tests", ""] + ([f"- `{u}`" for u in uncited] or ["None."]) + [""]
    lines += ["## Exempt (models, or `spec: none` infrastructure tests)", "", f"{len(exempt)} tests.", ""]
    return "\n".join(lines), uncited, open_r, problems


def main():
    text, uncited, open_r, problems = render()
    if "--uncited" in sys.argv:
        for u in uncited:
            print(f"uncited test: {u}")
        sys.exit(1 if uncited else 0)
    if "--gaps" in sys.argv:
        for f, s, a in open_r:
            print(f"no test or issue: {f} §{s} ({a})")
        for p in problems:
            print(p)
        sys.exit(1 if open_r or problems else 0)
    with open(OUT, "w") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(OUT, ROOT)}")


main()
