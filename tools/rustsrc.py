"""The workspace's crates and Rust sources, as tools/policy.py, dead_pub.py and loc.py read them."""
import glob, os, re, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


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


def sanitize(src, fill="x"):
    """Comments blanked to spaces, string and char literal contents replaced by `fill`, their
    quotes kept; newlines and offsets kept."""
    out = []
    i, n = 0, len(src)
    prev_ident = False  # previous char was part of an identifier

    def blank(s, c=" "):
        return "".join("\n" if ch == "\n" else c for ch in s)

    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(blank(src[i:j]))
            i = j
            prev_ident = False
            continue
        if c == "/" and src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(blank(src[i:j]))
            i = j
            prev_ident = False
            continue
        # raw strings: r"..", r#".."#, br, cr
        if not prev_ident and c in "rbc":
            m = re.match(r'(?:b|c)?r(#*)"', src[i:i + 300])
            if m:
                close = '"' + m.group(1)
                start = i + m.end()
                j = src.find(close, start)
                j = n if j < 0 else j
                out.append(src[i:start] + blank(src[start:j], fill) + close)
                i = j + len(close)
                prev_ident = False
                continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append('"' + blank(src[i + 1:j], fill) + '"')
            i = j + 1
            prev_ident = False
            continue
        if c == "'":
            # char literal ('a', '\n', '\u{..}') vs lifetime/label ('a)
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 3)
                j = n if j < 0 else j
                out.append("'" + blank(src[i + 1:j], fill) + "'")
                i = j + 1
                prev_ident = False
                continue
            if i + 2 < n and src[i + 2] == "'":
                out.append("'" + fill + "'")
                i += 3
                prev_ident = False
                continue
        out.append(c)
        prev_ident = c.isalnum() or c == "_"
        i += 1
    return "".join(out)
