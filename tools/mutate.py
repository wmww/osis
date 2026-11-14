#!/usr/bin/env python3
"""One mutation probe (a row of a module's mutation table): breaks a rule in code, builds the
tests with it, puts the file back, then runs the built tests and prints one Markdown table row:
the mutation and the tests that failed ("none": no test catches it).

Usage: python3 tools/mutate.py FILE OLD NEW -- <cargo test args> [-- <test binary args>]
  e.g. python3 tools/mutate.py core/sync/src/read/judge.rs 'a >= b' 'a > b' -- -p osis-sync --test it -- read::

OLD must occur exactly once in FILE; NEW must be non-empty and differ from OLD. The file is put
back from its text as read before the edit (never from git, so uncommitted work in it survives)
as soon as the build ends, before any test runs; if it changed during the build (someone else
edited it), it is left alone and the path of the original's copy, kept beside it, is printed. Tests run from the built binaries, so
the tree is never mutated while they run."""
import json, os, shutil, subprocess, sys, tempfile


def main(argv):
    if "--" not in argv or argv.index("--") != 3:
        sys.exit(__doc__)
    path, old, new = argv[:3]
    rest = argv[4:]
    cargo_args, test_args = (rest[: rest.index("--")], rest[rest.index("--") + 1 :]) if "--" in rest else (rest, [])
    text = open(path).read()
    if text.count(old) != 1:
        sys.exit(f"mutate: OLD occurs {text.count(old)} times in {path}; it must occur once")
    if not new or new == old:
        sys.exit("mutate: NEW must be non-empty and differ from OLD")
    # beside the file, so one left behind is seen
    fd, saved = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".orig", dir=os.path.dirname(path) or ".")
    os.close(fd)
    shutil.copy2(path, saved)
    mutated = text.replace(old, new)
    with open(path, "w") as f:
        f.write(mutated)
    try:
        build = subprocess.run(["cargo", "test", "--no-run", "--message-format=json", *cargo_args], stdout=subprocess.PIPE, text=True)
    finally:
        if open(path).read() == mutated:
            # written anew (a fresh mtime), so the next build rebuilds it
            with open(path, "w") as f:
                f.write(text)
            os.remove(saved)
        else:
            print(f"mutate: {path} changed during the build; left as it is, the original is at {saved}", file=sys.stderr)
    row = f"| `{path}`: `{old}` -> `{new}` |"
    if build.returncode != 0:
        print(f"{row} does not build |")
        return 0
    bins = []
    for line in build.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
            bins.append((m["executable"], os.path.dirname(m["manifest_path"])))
    failed = []
    for exe, cwd in bins:
        r = subprocess.run([exe, *test_args], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        failed += [l.split()[1] for l in r.stdout.splitlines() if l.startswith("test ") and l.rstrip().endswith("FAILED")]
        if r.returncode != 0 and not failed:
            failed.append(f"{os.path.basename(exe)} exited {r.returncode}")
    print(f"{row} {', '.join(failed) if failed else 'none'} |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
