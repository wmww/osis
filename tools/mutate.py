#!/usr/bin/env python3
"""Mutation probes (rows of a module's mutation table): breaks a rule in code, builds the tests
with it, puts the file back, then runs the built tests and prints one Markdown table row per
mutation: the mutation and the tests that failed ("none": no test catches it).

Usage: python3 tools/mutate.py FILE OLD NEW [FILE OLD NEW]... -- <cargo test args> [-- <test binary args>]
  e.g. python3 tools/mutate.py core/sync/src/read/judge.rs 'a >= b' 'a > b' -- -p osis-sync --test it -- read::

OLD must occur exactly once in FILE; NEW must be non-empty and differ from OLD. One mutation is a
plain edit. Several are built once: each OLD, an expression, becomes
`(if <OSIS_MUTANT is i> { NEW } else { OLD })`, and the built binaries run once per mutation
with OSIS_MUTANT=i (a build per mutation of a crate low in the tree costs minutes; a statement
or pattern that is not an expression fails the one build: probe it alone). Files are put back from
their text as read before the edit (never from git, so uncommitted work survives) as soon as the
build ends, before any test runs; a file changed during the build (someone else edited it) is left
alone and the path of the original's copy, kept beside it, is printed. Tests run from the built
binaries, so the tree is never mutated while they run. A mutation that storms runs each seed to
its timeout: set OSIS_SEED_TIMEOUT_SECS to a few times a seed's normal CPU-s for seeded tests.

Each mutation's test output goes whole to a file (MUTATE_OUT, a directory, or a fresh one under
TMPDIR), printed on stderr with each failing test's panic message, so a failure under a plant is
read without rebuilding it. MUTATE_HEAVY=1 runs the tests in holds of tools/heavy,
MUTATE_PER_HOLD mutations per hold (never run mutate.py itself under it: a batch would hold the
lock for its whole length).
The variable is read once per site, so a plant in a hot path costs nothing per call."""
import json, os, shutil, subprocess, sys, tempfile

VAR = "OSIS_MUTANT"


def panics(text):
    """Each failing test's name and the message line after its panic, as libtest prints them."""
    name, lines = None, text.splitlines()
    for k, l in enumerate(lines):
        if l.startswith("---- ") and l.endswith(" stdout ----"):
            name = l[5:-12]
        elif " panicked at " in l and name:
            msg = lines[k + 1] if k + 1 < len(lines) else ""
            yield f"{name}: {msg} (at {l.split(' panicked at ')[1].rstrip(':')})"
            name = None


def run_bins(bins, test_args, env, mutants):
    """Per mutation (`mutants`: the OSIS_MUTANT value of each, None for a plain edit), each built
    binary's (exe, exit code, output), the binaries run side by side from their package dirs (a
    binary's slow tail leaves cores to the others). MUTATE_HEAVY: MUTATE_PER_HOLD mutations
    (default 1) in each hold of the heavy lock, the build unlocked, run by this script again."""
    if env.get("MUTATE_HEAVY") and not env.get("HEAVY_HELD"):
        with tempfile.TemporaryDirectory(prefix="mutate-run-") as d:
            with open(os.path.join(d, "in.json"), "w") as f:
                json.dump([bins, test_args, mutants], f)
            heavy = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy")
            subprocess.run([heavy, sys.executable, os.path.abspath(__file__), "--run-bins", d], env=env, check=True)
            with open(os.path.join(d, "out.json")) as f:
                return json.load(f)
    out = []
    for i in mutants:
        e = dict(env, **({VAR: i} if i is not None else {}))
        with tempfile.TemporaryDirectory(prefix="mutate-out-") as d:
            runs = []
            for k, (exe, cwd) in enumerate(bins):
                f = open(os.path.join(d, str(k)), "w+")
                runs.append((exe, f, subprocess.Popen([exe, *test_args], cwd=cwd, env=e, stdout=f, stderr=subprocess.STDOUT)))
            res = []
            for exe, f, p in runs:
                rc = p.wait()
                f.seek(0)
                res.append((exe, rc, f.read()))
                f.close()
        out.append(res)
    return out


def main(argv):
    if argv[:1] == ["--run-bins"]:
        with open(os.path.join(argv[1], "in.json")) as f:
            bins, test_args, mutants = json.load(f)
        with open(os.path.join(argv[1], "out.json"), "w") as f:
            json.dump(run_bins(bins, test_args, dict(os.environ), mutants), f)
        return 0
    if "--" not in argv or argv.index("--") % 3 or not argv.index("--"):
        sys.exit(__doc__)
    k = argv.index("--")
    muts = [tuple(argv[i : i + 3]) for i in range(0, k, 3)]
    rest = argv[k + 1 :]
    cargo_args, test_args = (rest[: rest.index("--")], rest[rest.index("--") + 1 :]) if "--" in rest else (rest, [])
    texts = {}
    for path, old, new in muts:
        texts.setdefault(path, open(path).read())
        if texts[path].count(old) != 1:
            sys.exit(f"mutate: OLD occurs {texts[path].count(old)} times in {path}; it must occur once: {old!r}")
        if not new or new == old:
            sys.exit("mutate: NEW must be non-empty and differ from OLD")
    mutated = dict(texts)
    for i, (path, old, new) in enumerate(muts):
        if len(muts) == 1:
            sub = new
        else:
            # the variable read once per site: a read per call slows hot paths several-fold
            on = f'{{ static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new(); *ON.get_or_init(|| std::env::var_os("{VAR}").is_some_and(|v| v == "{i}")) }}'
            sub = f"(if {on} {{ {new} }} else {{ {old} }})"
        if mutated[path].count(old) != 1:
            sys.exit(f"mutate: {old!r} overlaps another mutation of {path}")
        mutated[path] = mutated[path].replace(old, sub)
    saved = {}
    for path in texts:
        # beside the file, so one left behind is seen
        fd, saved[path] = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".orig", dir=os.path.dirname(path) or ".")
        os.close(fd)
        shutil.copy2(path, saved[path])
        with open(path, "w") as f:
            f.write(mutated[path])
    try:
        build = subprocess.run(["cargo", "test", "--no-run", "--message-format=json", *cargo_args], stdout=subprocess.PIPE, text=True)
    finally:
        for path, text in texts.items():
            if open(path).read() == mutated[path]:
                # written anew (a fresh mtime), so the next build rebuilds it
                with open(path, "w") as f:
                    f.write(text)
                os.remove(saved[path])
            else:
                print(f"mutate: {path} changed during the build; left as it is, the original is at {saved[path]}", file=sys.stderr)
    rows = [f"| `{path}`: `{old}` -> `{new}` |" for path, old, new in muts]
    if build.returncode != 0:
        for row in rows:
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
    out_dir = os.environ.get("MUTATE_OUT") or tempfile.mkdtemp(prefix="mutate-")
    os.makedirs(out_dir, exist_ok=True)
    per = max(1, int(os.environ.get("MUTATE_PER_HOLD", "1")))
    done = {}
    for i, row in enumerate(rows):
        if i not in done:
            ids = list(range(i, min(i + per, len(rows))))
            res = run_bins(bins, test_args, dict(os.environ), [str(k) if len(muts) > 1 else None for k in ids])
            done.update(zip(ids, res))
        failed, out = [], []
        for exe, rc, text in done.pop(i):
            out.append(f"==== {exe} (exit {rc})\n{text}")
            fails = [l.split()[1] for l in text.splitlines() if l.startswith("test ") and l.rstrip().endswith("FAILED")]
            failed += fails
            if rc != 0 and not fails:
                failed.append(f"{os.path.basename(exe)} exited {rc}")
        log = os.path.join(out_dir, f"mutant-{i}.log")
        with open(log, "w") as f:
            f.write("".join(out))
        print(f"{row} {', '.join(failed) if failed else 'none'} |", flush=True)
        if failed:
            print(f"mutate: mutation {i}'s output: {log}", file=sys.stderr)
            for line in panics("".join(out)):
                print(f"  {line}", file=sys.stderr)
        sys.stderr.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
