#!/usr/bin/env python3
"""The gate steps a branch's changed paths select (notes/gate.md, Components pay for themselves).

  tools/gate_paths.py [-v] BASE [REV]   the paths changed from BASE to the working tree (untracked
      files included), or to commit REV; prints gate.sh's `core= gui= unify= doc=` assignments.
      -v: why a diff of docs and Rust is not comments-only (each line that is not)

gui=1: a path under libs/kit/ or app/. unify=1: a Cargo.toml, Cargo.lock or .cargo/ path.
core: '' when every path is the GUI's; `docs` when the rest is Markdown under spec/, notes/ or
issues/; `comments` when the rest is that Markdown and .rs files whose every changed line, removed
or added, is a whole-line `//` comment (below); else 1. Under docs or comments, a Rust line that
reads or includes a file under spec/, notes/ or issues/ (a one-line call `git grep` finds) makes
core 1 and is named on stderr.
doc: on the comments path, the crates (space-separated) whose changed comments include a doc
comment: their doctests run.

A whole-line comment is a `//` comment that starts its line after blanks only: the line then starts
and ends outside any other comment or literal, so the changed lines remove or add only comments and
every other token stays as it was (a line inside a `/* */` block or a multi-line string is not
one). The token stream of an unchanged line can move to another line number: no test reads one
(panic locations and `#[track_caller]` only print them). A plain comment (`//`, `////`) reaches no
compiler or macro. A doc comment (`///` not `////`, `//!`) is a `#[doc]` attribute: one inside a
macro call's or macro_rules' brackets falls through (the macro may read it), as does one in a crate
that is not a workspace member or that reaches a proc macro outside DOCS_BLIND (a direct
dependency's, or one a direct dependency depends on: clap's derive turns doc comments into help
text); else its crate's doctests run, when it has a library. An added, deleted or untracked .rs
file falls through, as does one that is a symlink at either end (its blob is its target) and one
whose name a one-line call reading a .rs file as text names (`include_str!("../msg.rs")`: a test
parsing a source sees its comments). The diff is read with --text: a NUL byte makes git call a
file binary and show no lines.
"""
import bisect, json, os, re, shlex, subprocess, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import lex, sanitize

GUI = ("libs/kit/", "app/")
DOCS = re.compile(r"(spec|notes|issues)/.*\.md")
UNIFY = re.compile(r"(.*/)?Cargo\.toml|Cargo\.lock|\.cargo/.*", re.S)
READERS = r"(include(_str|_bytes)?!|read_to_string|fs::read|File::open|\.join)\(.*(spec|notes|issues)/"
SOURCE_READERS = r'(include_str!|include_bytes!|read_to_string|fs::read|File::open)\(.*\.rs"'
# proc macros known to ignore doc attributes; any other reachable one makes a doc comment code
DOCS_BLIND = {"curve25519-dalek-derive", "jiff-static", "tokio-macros", "tracing-attributes", "zeroize_derive"}


def git(*args, check=True):
    return subprocess.run(["git", *args], capture_output=True, check=check).stdout


def changed(base, rev):
    """Every path changed from base to rev (None: the working tree, untracked files included); a
    rename is both its paths, so a file moved from core into libs/kit/ still selects core."""
    out = git("diff", "--no-renames", "--name-only", "-z", base, *([rev] if rev else []), "--")
    if not rev:
        out += git("ls-files", "--others", "--exclude-standard", "-z")
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def blobs(rev, paths):
    """{path: text at rev, or None (absent)}, through one `git cat-file --batch`; rev None: the
    working tree."""
    if rev is None:
        return {p: read(p) for p in paths}
    out = subprocess.run(["git", "cat-file", "--batch"], input="".join(f"{rev}:{p}\n" for p in paths).encode(),
                         capture_output=True, check=True).stdout
    res, i = {}, 0
    for s in paths:
        nl = out.index(b"\n", i)
        head = out[i:nl].split()
        if head[-1] == b"missing" or head[1] != b"blob":
            res[s], i = None, nl + 1
            continue
        size = int(head[2])
        res[s] = out[nl + 1:nl + 1 + size].decode("utf-8", "replace")
        i = nl + 1 + size + 1
    return res


def hunks(base, rev, paths):
    """{path: (removed old line numbers, added new line numbers)}, 1-based, from `git diff -U0`."""
    if not paths:
        return {}
    spec = ["--", *(":(literal)" + p for p in paths)]
    rng = [base, *([rev] if rev else [])]
    names = [p.decode("utf-8", "surrogateescape") for p in git("diff", "--no-renames", "--name-only", "-z", *rng, *spec).split(b"\0") if p]
    # --text: a file git takes for binary (a NUL byte) would show no hunk
    patch = git("diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", "--text", "-U0", *rng, *spec).decode("utf-8", "replace")
    sections = re.split(r"^diff --git ", patch, flags=re.M)[1:]
    if len(sections) != len(names):
        raise RuntimeError(f"git diff: {len(sections)} sections for {len(names)} paths")
    out = {}
    for name, sec in zip(names, sections):
        rem, add = [], []
        for m in re.finditer(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", sec, re.M):
            a, b, c, d = int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)
            rem += range(a, a + b)
            add += range(c, c + d)
        out[name] = (rem, add)
    return out


def links(base, rev, paths):
    """The `paths` that are not a regular file at base or at rev (a symlink's blob is its target)."""
    if not paths:
        return []
    out = git("diff", "--no-renames", "--raw", "-z", base, *([rev] if rev else []), "--", *(":(literal)" + p for p in paths)).split(b"\0")
    return sorted({out[k + 1].decode("utf-8", "surrogateescape") for k in range(0, len(out) - 1, 2)
                   if any(m not in (b"100644", b"100755", b"000000") for m in out[k].lstrip(b":").split()[:2])})


def sources_read(paths):
    """`path: reader` for each of the .rs `paths` whose name a one-line call reading a .rs file as
    text names (a test parsing a source sees its comments)."""
    out = subprocess.run(["git", "grep", "-n", "-E", SOURCE_READERS, "--", "*.rs"], capture_output=True, text=True).stdout.splitlines()
    return [f"{p}: read as text by {l}" for p in paths for l in out if re.search(r"\b" + re.escape(os.path.basename(p)) + '"', l)]


def comment_lines(src):
    """{line number (1-based): comment} of the lines of `src` that are wholly a `//` comment."""
    starts = [0] + [m.end() for m in re.finditer("\n", src)]
    out = {}
    for kind, s, e, _, _ in lex(src):
        if kind == "line":
            ln = bisect.bisect_right(starts, s) - 1
            if not src[starts[ln]:s].strip():
                out[ln + 1] = src[s:e]
    return out


def macro_lines(src):
    """The line numbers (1-based) of `src` that start inside a macro call's or macro_rules'
    brackets (`f!(..)`, `f! { .. }`, `macro_rules! f { .. }`), comments and literals aside. A
    keyword before `!` (`if !(..)`) counts too: more falls through, never less."""
    code = sanitize(src)
    starts = [0] + [m.end() for m in re.finditer("\n", code)]
    brackets = list(re.finditer(r"[(){}\[\]]", code))
    out, stack, k = set(), [], 0
    for n, at in enumerate(starts, 1):
        while k < len(brackets) and brackets[k].start() < at:
            b = brackets[k]
            if b[0] in "([{":
                stack.append(macro_before(code[max(0, b.start() - 200):b.start()]))
            elif stack:
                stack.pop()
            k += 1
        if any(stack):
            out.add(n)
    return out


def macro_before(text):
    """Whether `text` ends as before a macro call's or macro_rules' bracket: `name!`, `name! name`."""
    t = text.rstrip()
    if t[-1:].isalnum() or t[-1:] == "_":
        t = t.rstrip("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_").rstrip()
    return t.endswith("!") and (t[:-1].rstrip()[-1:].isalnum() or t[:-1].rstrip()[-1:] == "_")


def is_doc(comment):
    return comment.startswith("//!") or (comment.startswith("///") and not comment.startswith("////"))


def rs_verdict(base, rev, paths):
    """(lines that are not whole-line comments as `path:N: text`, files with a changed doc
    comment) for the .rs `paths` changed from base to rev (None: the working tree)."""
    if any("\n" in p for p in paths):
        return ["a .rs path with a newline"], []
    old, new = blobs(base, paths), blobs(rev, paths)
    present = [p for p in paths if old[p] is not None and new[p] is not None]
    bad, docs = [f"{p}: added or deleted" for p in paths if p not in present], []
    bad += [f"{p}: not a regular file" for p in links(base, rev, present)] + sources_read(present)
    for p, (rem, add) in hunks(base, rev, present).items():
        doc = False
        for side, nums in (("-", rem), ("+", add)):
            src = (old if side == "-" else new)[p]
            lines, cl = src.split("\n"), comment_lines(src)
            in_macro = None
            for n in nums:
                c = cl.get(n)
                text = lines[n - 1] if n <= len(lines) else ""
                if c is None:
                    bad.append(f"{p}:{side}{n}: {text.strip()}")
                elif is_doc(c):
                    in_macro = macro_lines(src) if in_macro is None else in_macro
                    if n in in_macro:
                        bad.append(f"{p}:{side}{n}: a doc comment inside a macro: {text.strip()}")
                    doc = True
        if doc:
            docs.append(p)
    return bad, docs


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except (FileNotFoundError, IsADirectoryError):
        return None


def doc_crates(files):
    """(crates whose doctests cover the doc comments changed in `files`, reasons they cannot)."""
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"], capture_output=True, check=True).stdout)
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["workspace_root"]
    dirs = {os.path.relpath(os.path.dirname(pkgs[i]["manifest_path"]), root): i for i in meta["workspace_members"]}
    procs = {i for i, p in pkgs.items() if any("proc-macro" in t["kind"] for t in p["targets"])}

    def deps(i, kinds):
        return [d["pkg"] for d in nodes[i]["deps"] if any(k["kind"] in kinds for k in d["dep_kinds"])]

    crates, why = set(), []
    for f in files:
        owner = max((d for d in dirs if d == "." or f.startswith(d + "/")), key=len, default=None)
        if owner is None:
            why.append(f"{f}: a doc comment outside the workspace's crates")
            continue
        i = dirs[owner]
        reach = {x for d in deps(i, (None, "dev", "build")) for x in [d, *deps(d, (None,))]}
        other = sorted(pkgs[x]["name"] for x in reach & procs if pkgs[x]["name"] not in DOCS_BLIND)
        if other:
            why.append(f"{f}: a doc comment in {pkgs[i]['name']}, which reaches {', '.join(other)} (may read doc comments)")
        elif any(k in ("lib", "rlib", "proc-macro") for t in pkgs[i]["targets"] for k in t["kind"]):
            crates.add(pkgs[i]["name"])
    return sorted(crates), why


def readers():
    out = subprocess.run(["git", "grep", "-n", "-E", READERS, "--", "*.rs"], capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if not l.startswith(GUI)]


def classify(base, rev=None, verbose=False):
    """{core, gui, unify, doc} for the paths changed from base to rev (None: the working tree)."""
    paths = changed(base, rev)
    rest = [p for p in paths if not p.startswith(GUI)]
    res = dict(core="1" if rest else "", gui="1" if len(rest) < len(paths) else "",
               unify="1" if any(UNIFY.fullmatch(p) for p in paths) else "", doc="")
    rs = [p for p in rest if not DOCS.fullmatch(p)]
    if not rest or any(not p.endswith(".rs") for p in rs):
        return res
    why, crates = [], []
    if rs:
        try:
            why, docs = rs_verdict(base, rev, rs)
            if not why and docs:
                crates, why = doc_crates(docs)
        except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as e:
            why = [f"cannot judge the Rust diff: {e}"]
    if why:
        if verbose:
            print(f"gate: not comments-only ({len(why)} below): full gate", file=sys.stderr)
            print("\n".join(why), file=sys.stderr)
        return res
    if any(DOCS.fullmatch(p) for p in rest) and (r := readers()):
        print("gate: docs or comments diff, but these read spec/, notes/ or issues/ (add them to the docs step): full gate", file=sys.stderr)
        print("\n".join(r), file=sys.stderr)
        return res
    res.update(core="comments" if rs else "docs", doc=" ".join(crates))
    return res


def main():
    os.chdir(git("rev-parse", "--show-toplevel").decode().strip())
    args = sys.argv[1:]
    verbose = bool(args) and args[0] == "-v"
    args = args[verbose:]
    if len(args) not in (1, 2):
        sys.exit(__doc__)
    res = classify(args[0], args[1] if len(args) == 2 else None, verbose)
    for k in ("core", "gui", "unify", "doc"):
        print(f"{k}={shlex.quote(res[k])}")


if __name__ == "__main__":
    main()
