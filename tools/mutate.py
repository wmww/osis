#!/usr/bin/env python3
"""Mutation probes (rows of a module's mutation table): breaks a rule in code, builds the tests
with it, puts the file back, then runs the built tests and prints one Markdown table row per
mutation: the mutation and the tests that failed ("none": no test catches it).

Usage: python3 tools/mutate.py FILE OLD NEW [+ FILE OLD NEW]... [FILE OLD NEW ...]... -- <cargo test args> [-- <test binary args>]
  e.g. python3 tools/mutate.py core/sync/src/read/judge.rs 'a >= b' 'a > b' -- -p osis-sync --test it -- read::

A `+` between two FILE OLD NEW sites makes them one mutation (a control spanning two sites:
both planted together, one row).

OLD must occur exactly once in FILE; NEW must be non-empty and differ from OLD. One mutation is a
plain edit. Several are built once: each OLD, an expression, becomes
`(if <OSIS_MUTANT is i> { NEW } else { OLD })`, and the built binaries run once per mutation
with OSIS_MUTANT=i (a build per mutation of a crate low in the tree costs minutes). An OLD or NEW
that starts with `.` (a method-call suffix) or ends with `;` (a statement) is refused before
building: include the receiver, drop the `;`, or give it alone. Any other text that is not an
expression (a pattern) fails to build: its compiler errors are printed, its row says
"does not build", and the others are built again without it. Files are put back from
their text as read before the edit (never from git, so uncommitted work survives) as soon as the
build ends, before any test runs; a file changed during the build (someone else edited it) is left
alone and the path of the original's copy, kept beside it, is printed. The build is a `cargo test`
with tools/heavy's recording runner (`tools/heavy`, module doc): each test binary is copied as built,
with cargo's args, cwd and env (`.cargo/config.toml`'s `[env]` included), and the tests run from the
copies: neither the mutated tree nor a later rebuild in this worktree reaches them. Without a target
selection the build adds `--tests` (doctests would run while building, not from copies). A mutation that storms runs each seed to
its timeout: set OSIS_SEED_TIMEOUT_SECS to a few times a seed's normal CPU-s for seeded tests.

Each mutation's test output goes whole to a file (MUTATE_OUT, a directory, or a fresh one under
TMPDIR), printed on stderr with each failing test's panic message, so a failure under a plant is
read without rebuilding it. MUTATE_HEAVY=1 runs the tests in holds of tools/heavy,
MUTATE_PER_HOLD mutations per hold (never run mutate.py itself under it: a batch would hold the
lock for its whole length).
The variable is read once per site, so a plant in a hot path costs nothing per call."""
import importlib.machinery, importlib.util, json, os, shutil, subprocess, sys, tempfile

VAR = "OSIS_MUTANT"
TOOLS = os.path.dirname(os.path.abspath(__file__))
_l = importlib.machinery.SourceFileLoader("heavy", os.path.join(TOOLS, "heavy"))
heavy = importlib.util.module_from_spec(importlib.util.spec_from_loader("heavy", _l))
_l.exec_module(heavy)
# cargo's target selection flags: without one, `cargo test` also runs doctests while it builds
SELECT = ("--lib", "--bin", "--bins", "--test", "--tests", "--example", "--examples", "--bench", "--benches", "--all-targets", "--doc")


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


def run_bins(bins, mutants):
    """Per mutation (`mutants`: the OSIS_MUTANT value of each, None for a plain edit), each
    binary's (built path, exit code, output). `bins` are tools/heavy's recorded runs (a copy's
    argv, cwd, cargo's env, the built path), run side by side (a binary's slow tail leaves cores to
    the others). MUTATE_HEAVY: MUTATE_PER_HOLD mutations (default 1) in each hold of the heavy
    lock, the build unlocked, run by this script again."""
    if os.environ.get("MUTATE_HEAVY") and not os.environ.get("HEAVY_HELD"):
        with tempfile.TemporaryDirectory(prefix="mutate-run-") as d:
            with open(os.path.join(d, "in.json"), "w") as f:
                json.dump([bins, mutants], f)
            subprocess.run([os.path.join(TOOLS, "heavy"), sys.executable, os.path.abspath(__file__), "--run-bins", d], check=True)
            with open(os.path.join(d, "out.json")) as f:
                return json.load(f)
    out = []
    for i in mutants:
        with tempfile.TemporaryDirectory(prefix="mutate-out-") as d:
            runs = []
            for k, b in enumerate(bins):
                f = open(os.path.join(d, str(k)), "w+")
                e = dict(b["env"], **({VAR: i} if i is not None else {}))
                runs.append((b["bin"], f, subprocess.Popen(b["argv"], cwd=b["cwd"], env=e, stdout=f, stderr=subprocess.STDOUT)))
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
            bins, mutants = json.load(f)
        with open(os.path.join(argv[1], "out.json"), "w") as f:
            json.dump(run_bins(bins, mutants), f)
        return 0
    if "--" not in argv or not argv.index("--"):
        sys.exit(__doc__)
    k = argv.index("--")
    # sites (FILE, OLD, NEW), each with its mutation's index: a `+` joins a site to the one before
    muts, group, i = [], [], 0
    while i < k:
        joined = argv[i] == "+" and bool(muts)
        i += joined
        if i + 3 > k or "+" in argv[i : i + 3]:
            sys.exit(__doc__)
        muts.append(tuple(argv[i : i + 3]))
        group.append(group[-1] if joined else len(set(group)))
        i += 3
    n = len(set(group))
    rest = argv[k + 1 :]
    cargo_args, test_args = (rest[: rest.index("--")], rest[rest.index("--") + 1 :]) if "--" in rest else (rest, [])
    texts = {}
    for path, old, new in muts:
        texts.setdefault(path, open(path).read())
        if texts[path].count(old) != 1:
            sys.exit(f"mutate: OLD occurs {texts[path].count(old)} times in {path}; it must occur once: {old!r}")
        if not new or new == old:
            sys.exit("mutate: NEW must be non-empty and differ from OLD")
        for x in (old, new) if n > 1 else ():
            if x.lstrip().startswith(".") or x.rstrip().endswith(";"):
                sys.exit(f"mutate: {x!r} is not an expression ({'a method-call suffix' if x.lstrip().startswith('.') else 'a statement'}): "
                         "with several mutations each OLD and NEW is wrapped as one; include the receiver, drop the `;`, or give it alone")
    # each OLD's span in its file as read; spans of one file must be disjoint
    spans = {}
    for i, (path, old, new) in enumerate(muts):
        if n == 1:
            sub = new
        else:
            # the variable read once per site: a read per call slows hot paths several-fold
            on = f'{{ static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new(); *ON.get_or_init(|| std::env::var_os("{VAR}").is_some_and(|v| v == "{group[i]}")) }}'
            sub = f"(if {on} {{ {new} }} else {{ {old} }})"
        at = texts[path].index(old)
        spans.setdefault(path, []).append((at, at + len(old), sub, i))
    mutated, sites = dict(texts), [None] * len(muts)
    for path, ss in spans.items():
        ss.sort()
        if any(x[1] > y[0] for x, y in zip(ss, ss[1:])):
            sys.exit(f"mutate: two mutations of {path} overlap")
        text, parts, prev = texts[path], [], 0
        for lo, hi, sub, i in ss:
            parts.append(text[prev:lo])
            # its lines in the mutated file, to name the mutation a build error points into
            first = "".join(parts).count("\n") + 1
            sites[i] = (path, first, first + sub.count("\n"))
            parts.append(sub)
            prev = hi
        parts.append(text[prev:])
        mutated[path] = "".join(parts)
    rec = tempfile.mkdtemp(prefix="mutate-bins-")
    saved = {}
    for path in texts:
        # beside the file, so one left behind is seen
        fd, saved[path] = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".orig", dir=os.path.dirname(path) or ".")
        os.close(fd)
        shutil.copy2(path, saved[path])
        with open(path, "w") as f:
            f.write(mutated[path])
    try:
        return built(muts, group, rest, cargo_args, test_args, texts, mutated, saved, sites, rec)
    finally:
        shutil.rmtree(rec, ignore_errors=True)


def built(muts, group, rest, cargo_args, test_args, texts, mutated, saved, sites, rec):
    """Build with the mutated texts in place (copies of the binaries into rec), put the files back,
    then run and report."""
    select = [] if any(a.split("=")[0] in SELECT for a in cargo_args) else ["--tests"]
    try:
        with tempfile.TemporaryFile("w+") as f:
            rc, bins = heavy.build(["cargo", "test", "--message-format=json", *select, *cargo_args, "--", *test_args], rec, f)
            f.seek(0)
            build_out = f.read()
    finally:
        for path, text in texts.items():
            if open(path).read() == mutated[path]:
                # written anew (a fresh mtime), so the next build rebuilds it
                with open(path, "w") as f:
                    f.write(text)
                os.remove(saved[path])
            else:
                print(f"mutate: {path} changed during the build; left as it is, the original is at {saved[path]}", file=sys.stderr)
    n = len(set(group))
    rows = [" + ".join(f"| `{path}`: `{old}` -> `{new}`"[2 * (k > 0):] for k, (path, old, new) in enumerate(m for m, g in zip(muts, group) if g == j)) + " |"
            for j in range(n)]
    if rc != 0:
        errors, other = [], []
        for line in build_out.splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                other.append(line)
                continue
            if m.get("reason") == "compiler-message" and m["message"].get("level") == "error":
                errors.append(m["message"])
                print(m["message"].get("rendered", ""), file=sys.stderr)
        if not errors:  # not a compile error (a bad cargo argument): cargo's own words
            print("\n".join(l for l in other if not l.lstrip().startswith(("Compiling", "Checking"))), file=sys.stderr)
        # the mutations whose substituted lines an error points into
        bad = {group[i] for e in errors for sp in e.get("spans", []) for i, (path, lo, hi) in enumerate(sites)
               if os.path.abspath(sp["file_name"]) == os.path.abspath(path) and sp["line_start"] <= hi and sp["line_end"] >= lo}
        for i in sorted(bad) or range(len(rows)):
            print(f"{rows[i]} does not build |")
        kept = [j for j in range(n) if j not in bad]
        if bad and kept:
            # the others built again without the broken ones (one more build, not a lost batch)
            print(f"mutate: {len(bad)} mutation(s) do not build; building the other {len(kept)} again", file=sys.stderr)
            args = []
            for j in kept:
                for k, m in enumerate(m for m, g in zip(muts, group) if g == j):
                    args += (["+"] if k else []) + list(m)
            return main(args + ["--", *rest])
        return 0
    out_dir = os.environ.get("MUTATE_OUT") or tempfile.mkdtemp(prefix="mutate-")
    os.makedirs(out_dir, exist_ok=True)
    per = max(1, int(os.environ.get("MUTATE_PER_HOLD", "1")))
    done = {}
    for i, row in enumerate(rows):
        if i not in done:
            ids = list(range(i, min(i + per, len(rows))))
            res = run_bins(bins, [str(k) if n > 1 else None for k in ids])
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
