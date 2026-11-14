"""The workspace's crates and Rust sources, as tools/policy.py, dead_pub.py and loc.py read them."""
import functools, glob, os, re, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


@functools.cache
def read(path):
    """`path`'s text, read once per run (the checks share it)."""
    with open(path, errors="replace") as f:
        return f.read()


@functools.cache
def _loose(pat):
    r"""`pat` without its `\b`s, which matches wherever `pat` does; `pat` itself where dropping one
    could narrow it (in a negative lookaround), or the text may not be a `\b` (`[\b]`, `\\b`)."""
    s = pat.pattern
    if "(?" in s or "[" in s or "\\\\" in s:
        return pat
    return re.compile(s.replace(r"\b", ""), pat.flags)


def has(pat, text):
    r"""Whether `pat` matches in `text`, fast: sre scans quickly only for a pattern that starts with a
    literal, which a leading `\b` hides; `_loose` rejects a text first, scanning fast."""
    return bool(_loose(pat).search(text) and pat.search(text))


def members(extra=()):
    """{absolute dir: package name} of the workspace members and of the crates the `extra` globs name."""
    out = {}
    for pat in toml(os.path.join(ROOT, "Cargo.toml"))["workspace"]["members"] + list(extra):
        for m in glob.glob(os.path.join(ROOT, pat)):
            if os.path.isfile(os.path.join(m, "Cargo.toml")):
                out[os.path.normpath(m)] = toml(os.path.join(m, "Cargo.toml"))["package"]["name"]
    return out


def rs_files(m, crates):
    """The .rs files of crate dir `m`: not target/ or vendored patches/, nor those of a crate of
    `crates` nested in it (app/android in app)."""
    for p in glob.glob(os.path.join(m, "**/*.rs"), recursive=True):
        if os.path.relpath(p, m).startswith(("target/", "patches/")):
            continue
        if any(o != m and p.startswith(o + os.sep) and o.startswith(m + os.sep) for o in crates):
            continue
        yield p


def mod_paths(file, name):
    """Where `mod name;` declared in `file` lives: `name.rs`, or a prefix for `name/`."""
    d, base = os.path.dirname(file), os.path.basename(file)
    if base not in ("lib.rs", "main.rs", "mod.rs"):
        d = os.path.join(d, base[:-3])
    sub = os.path.join(d, name)
    return [sub + ".rs", sub + os.sep]


# what starts a comment or literal: a raw string only where no identifier runs into it
_START = re.compile(r'//|/\*|(?<!\w)[bc]?r#*"|"|\'')
_STR = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)


def lex(src):
    """The comments and literals of `src` in order, as (kind, start, end, inner_start, inner_end):
    kind `line` (a `//` comment, to its line's end), `block` (`/* */`, nested), `str` (a string,
    raw or not, any prefix), `char`; inner is a literal's contents between its quotes, or the whole
    comment. A `'` that starts no char literal (a lifetime, a label) is code."""
    out = []
    i, n = 0, len(src)
    while (m := _START.search(src, i)):
        s, t = m.start(), m.group()
        if t == "//":
            j = src.find("\n", s)
            j = n if j < 0 else j
            out.append(("line", s, j, s, j))
        elif t == "/*":
            depth, j = 1, s + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(("block", s, j, s, j))
        elif t == '"':
            # unterminated: to the end
            j = (q.end() if (q := _STR.match(src, s)) else n)
            out.append(("str", s, j, s + 1, j - 1 if q else n))
        elif t != "'":
            close = '"' + "#" * t.count("#")
            j = src.find(close, m.end())
            j = n if j < 0 else j
            out.append(("str", s, j + len(close), m.end(), j))
            j += len(close)
        elif s + 1 < n and src[s + 1] == "\\":
            j = src.find("'", s + 3)
            j = n if j < 0 else j
            out.append(("char", s, j + 1, s + 1, j))
            j += 1
        elif s + 2 < n and src[s + 2] == "'":
            out.append(("char", s, s + 3, s + 1, s + 2))
            j = s + 3
        else:
            j = s + 1
        i = j
    return out


def sanitize(src, fill="x"):
    """Comments blanked to spaces, string and char literal contents replaced by `fill`, their
    quotes kept; newlines and offsets kept."""

    def blank(s, c=" "):
        return "\n".join(c * len(part) for part in s.split("\n"))

    out, last = [], 0
    for kind, s, e, a, b in lex(src):
        out.append(src[last:s])
        out.append(blank(src[s:e]) if kind in ("line", "block") else src[s:a] + blank(src[a:b], fill) + src[b:e])
        last = e
    out.append(src[last:])
    return "".join(out)
