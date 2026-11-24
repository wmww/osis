#!/usr/bin/env python3
"""tools/ignores.py [--run LOGDIR] [PREFIX]: the tests ignored with a reason starting PREFIX
(default `sync rewrite: `), from the source (nothing builds): per reason, each test's crate,
file:line and fn name. `--run LOGDIR`: then run them, one `cargo test -p CRATE --no-fail-fast --
--ignored NAME...` per crate (output to LOGDIR/CRATE.log), and print each test's verdict, `missing`
for a test that ran in no binary. Exit 1 when any failed or is missing.
A by-hand test whose name holds one of the names (`x` beside `x_large`) also runs; its line says so."""
import collections, os, re, subprocess, sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustsrc import ROOT, members, rs_files

IGNORE = re.compile(r'#\[ignore\s*=\s*"([^"]*)"\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)')
VERDICT = re.compile(r"^test (\S+?)(?: - should panic)? \.\.\. (\w+)", re.M)


def find(prefix, root=ROOT):
    """[(crate, path relative to root, line, fn, reason)] of the tests whose ignore reason starts `prefix`."""
    crates = members()
    out = []
    for d, name in sorted(crates.items()):
        for p in sorted(rs_files(d, crates)):
            text = open(p, errors="replace").read()
            if prefix not in text:
                continue
            for m in IGNORE.finditer(text):
                if m.group(1).startswith(prefix):
                    out.append((name, os.path.relpath(p, root), text.count("\n", 0, m.start()) + 1, m.group(2), m.group(1)))
    return out


def verdicts(log, names):
    """{name: verdict} for each of `names` from a libtest log (`missing` if it ran nowhere), and the
    other tests the filters also ran."""
    got, extra = {}, []
    for full, v in VERDICT.findall(log):
        fn = full.rsplit("::", 1)[-1]
        if fn in names:
            got[fn] = v if got.get(fn, "ok") == "ok" else got[fn]
        else:
            extra.append(f"{full} {v}")
    return {n: got.get(n, "missing") for n in names}, extra


def main(argv):
    run = None
    if argv[:1] == ["--run"]:
        if len(argv) < 2:
            sys.exit(__doc__)
        run, argv = argv[1], argv[2:]
    prefix = argv[0] if argv else "sync rewrite: "
    tests = find(prefix)
    if not tests:
        sys.exit(f"ignores: no test ignored with a reason starting {prefix!r}")
    by_reason = collections.defaultdict(list)
    for t in tests:
        by_reason[t[4]].append(t)
    for reason, ts in sorted(by_reason.items()):
        print(f"{reason} ({len(ts)})")
        for crate, path, line, fn, _ in ts:
            print(f"  {crate} {path}:{line} {fn}")
    print(f"ignores: {len(tests)} tests")
    if run is None:
        return 0
    os.makedirs(run, exist_ok=True)
    bad = 0
    by_crate = collections.defaultdict(list)
    for crate, _, _, fn, _ in tests:
        by_crate[crate].append(fn)
    for crate, fns in sorted(by_crate.items()):
        log = os.path.join(run, f"{crate}.log")
        cmd = ["cargo", "test", "-p", crate, "--no-fail-fast", "--", "--ignored"] + fns
        print("ignores:", " ".join(cmd[:6]), f"... > {log}", file=sys.stderr, flush=True)
        with open(log, "w") as f:
            subprocess.run(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        got, extra = verdicts(open(log, errors="replace").read(), set(fns))
        for fn in fns:
            print(f"{got[fn]:8} {crate} {fn}")
            bad += got[fn] != "ok"
        for e in extra:
            print(f"also ran {crate} {e}")
    print(f"ignores: {len(tests) - bad} of {len(tests)} pass")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
