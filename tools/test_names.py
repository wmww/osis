#!/usr/bin/env python3
"""tools/test_names.py [--ignored] BIN FRAG...: the tests of the built test binary BIN whose names
hold every FRAG (AND, where libtest's filters OR: `paths:: _plain` there also runs every `_plain`
of the binary and every ignored test of `paths::`), one per line. A FRAG ending in `::` is a path
prefix (the name's start or after a `::`), so `content::` leaves out `paths::content_x::` but not
`paths::content::`; `^content::` anchors it at the name's start. `--ignored`: the ignored tests only.
Lists from BIN (`cargo test -p CRATE --test it --no-run` prints its path), so nothing rebuilds.
Exit 1, naming nothing, when no test matches: guard the use, since `--exact` with no name runs all:

    n=$(tools/test_names.py --ignored BIN paths:: _plain) && cargo test -p osis-perm --test it -- --ignored --exact $n
"""
import subprocess, sys


def matches(name, frag):
    if frag.startswith("^"):
        return name.startswith(frag[1:])
    if frag.endswith("::"):
        return name.startswith(frag) or "::" + frag in name
    return frag in name


def main(argv):
    ignored = argv[:1] == ["--ignored"]
    argv = argv[1:] if ignored else argv
    if len(argv) < 2:
        sys.exit(__doc__)
    bin_, frags = argv[0], argv[1:]
    r = subprocess.run([bin_, "--list", "--format", "terse"] + (["--ignored"] if ignored else []),
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"test_names: {bin_} --list exited {r.returncode}: {r.stderr.strip()}")
    names = [l[: -len(": test")] for l in r.stdout.splitlines() if l.endswith(": test")]
    hit = [n for n in names if all(matches(n, f) for f in frags)]
    if not hit:
        sys.exit(f"test_names: no {'ignored ' if ignored else ''}test of {bin_} holds all of {' '.join(frags)}")
    print("\n".join(hit))


if __name__ == "__main__":
    main(sys.argv[1:])
