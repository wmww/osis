#!/usr/bin/env python3
"""Every default test alone under tools/icount (notes/test-harnesses.md, Measuring).

  tools/pertest.py run OUT [--jobs N] [MATCH...]
      build the default tests (`cargo test --no-run`, this checkout) and copy the binaries to
      OUT.bins/, then, under tools/heavy (taken here, after the build: edits made while it waits
      for the lock change nothing it measures), run each listed, non-ignored test as its own
      process (`--exact NAME --test-threads=1`, from its package dir) under tools/icount, N at a
      time (default: half the hardware threads); write OUT as tab-separated lines: binary, test,
      instructions, CPU-s, exit code. MATCH keeps the tests whose "binary test" contains one of
      them (binary is `<package> <target>`, e.g. `osis-node it`). --jobs 1 takes no lock.
  tools/pertest.py top OUT [N]          per-binary totals, then the N costliest tests (default 30)
  tools/pertest.py compare OLD NEW [N]  per-binary totals of both, then the N largest moves by
                                        test (default 30); tests in one file only are listed apart

A test's count repeats to under 0.1% run to run; its CPU-s move 20-40% with load. Against an older
revision: a second worktree (`wt claim <name> <rev>`), `run` there, `compare` here. Each test runs
in a fresh process, so a cached setup (notes/test-harnesses.md, Copied worlds) is built by every
test using it: measure a cached setup's saving over the whole binary (`tools/icount BIN -q`).
"""
import json, os, shutil, subprocess, sys, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICOUNT = os.path.join(ROOT, "tools", "icount")


def test_env():
    """What `cargo test` sets that a test may read: .cargo/config.toml's [env]."""
    return dict(os.environ, PROPTEST_CASES=os.environ.get("PROPTEST_CASES", "32"),
                PROPTEST_DISABLE_FAILURE_PERSISTENCE="1")


def default_tests(root=ROOT):
    """Build the default tests; [(executable, package dir, "<package> <target>", test name)] for
    every listed test that is not `#[ignore]`."""
    out = subprocess.run(["cargo", "test", "--locked", "--no-run", "--message-format=json"], cwd=root,
                         capture_output=True, text=True, check=True).stdout
    env, todo = test_env(), []
    for line in out.splitlines():
        o = json.loads(line)
        if o.get("reason") != "compiler-artifact" or not o.get("executable") or not o["profile"]["test"]:
            continue
        # `path+file:///…/dir#name@0.1.0`, or `…/name#0.1.0` when the name is the dir's
        url, frag = o["package_id"].rsplit("#", 1)
        pkg = frag.split("@")[0] if "@" in frag else url.rstrip("/").rsplit("/", 1)[-1]
        exe, cwd = o["executable"], os.path.dirname(o["manifest_path"])

        def listed(*a):
            r = subprocess.run([exe, "--list", "--format=terse", *a], cwd=cwd, env=env, capture_output=True, text=True)
            return {l.rsplit(": ", 1)[0] for l in r.stdout.splitlines() if l.endswith(": test")}
        todo += [(exe, cwd, f"{pkg} {o['target']['name']}", n) for n in sorted(listed() - listed("--ignored"))]
    return todo


def timed(cmd, cwd=None, env=None):
    """(exit code, CPU-s, wall, output) of one process, its children included."""
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.read()
    _, status, ru = os.wait4(p.pid, 0)
    return os.waitstatus_to_exitcode(status), ru.ru_utime + ru.ru_stime, time.time() - t0, out.decode(errors="replace")


def run(out, jobs, match):
    todo = [t for t in default_tests() if not match or any(m in f"{t[2]} {t[3]}" for m in match)]
    copy = out + ".bins"
    os.makedirs(copy, exist_ok=True)
    placed = {}
    for exe in sorted({t[0] for t in todo}):
        placed[exe] = os.path.join(copy, os.path.basename(exe))
        shutil.copy2(exe, placed[exe])
    todo = [(placed[e], c, b, n) for e, c, b, n in todo]
    with open(out + ".todo", "w") as f:
        json.dump(todo, f)
    me = [sys.executable, os.path.abspath(__file__), "measure", out, str(jobs)]
    lock = [] if jobs == 1 or os.environ.get("HEAVY_HELD") else [os.path.join(ROOT, "tools", "heavy")]
    try:
        return subprocess.call(lock + me)
    finally:
        # the copies go however the run ends
        shutil.rmtree(copy, ignore_errors=True)
        if os.path.exists(out + ".todo"):
            os.remove(out + ".todo")


def measure(out, jobs):
    todo = [tuple(t) for t in json.load(open(out + ".todo"))]
    print(f"{len(todo)} tests in {len({t[2] for t in todo})} binaries, {jobs} at a time", flush=True)
    env = test_env()

    def one(t):
        exe, cwd, label, n = t
        rc, cpu, _, text = timed([ICOUNT, exe, "--exact", n, "--test-threads=1"], cwd, env)
        instr = [l for l in text.splitlines() if l.startswith("INSTR ")]
        return label, n, int(instr[-1].split()[1]) if instr else -1, cpu, rc
    with ThreadPoolExecutor(jobs) as ex, open(out, "w") as f:
        for r in ex.map(one, todo):
            f.write("\t".join(map(str, (r[0], r[1], r[2], f"{r[3]:.2f}", r[4]))) + "\n")
    rows = load(out)
    bad = [k for k, (_, _, rc) in rows.items() if rc]
    print(f"{sum(v[0] for v in rows.values()) / 1e9:.1f} G, {sum(v[1] for v in rows.values()):.0f} CPU-s; "
          f"{len(bad)} failed{': ' + ', '.join(' '.join(k) for k in bad[:10]) if bad else ''}")
    return 1 if bad else 0


def load(path):
    """{(binary, test): (instructions, CPU-s, exit code)}"""
    rows = {}
    for line in open(path):
        b, n, i, c, rc = line.rstrip("\n").split("\t")
        rows[(b, n)] = (int(i), float(c), int(rc))
    return rows


def per_binary(rows):
    s = defaultdict(lambda: [0, 0])
    for (b, _), (i, _, _) in rows.items():
        s[b][0] += i
        s[b][1] += 1
    return s


def top(path, n):
    rows = load(path)
    total = sum(v[0] for v in rows.values())
    print(f"{len(rows)} tests, {total / 1e9:.1f} G")
    for b, (i, k) in sorted(per_binary(rows).items(), key=lambda x: -x[1][0]):
        print(f"  {i / 1e9:9.1f} G {k:5d}  {b}")
    print(f"costliest {n}:")
    for (b, t), (i, c, rc) in sorted(rows.items(), key=lambda x: -x[1][0])[:n]:
        print(f"  {i / 1e9:8.2f} G {c:7.1f} s  {b} {t}{'  FAILED' if rc else ''}")


def compare(old, new, n):
    a, b = load(old), load(new)
    both = a.keys() & b.keys()
    ta, tb = sum(a[k][0] for k in both), sum(b[k][0] for k in both)
    print(f"{len(both)} tests in both: {ta / 1e9:.1f} -> {tb / 1e9:.1f} G ({(tb - ta) / max(ta, 1):+.1%})")
    pa, pb = per_binary({k: a[k] for k in both}), per_binary({k: b[k] for k in both})
    for bin_ in sorted(pa, key=lambda x: -pa[x][0]):
        x, y = pa[bin_][0], pb[bin_][0]
        if x != y:
            print(f"  {x / 1e9:9.1f} -> {y / 1e9:9.1f} G ({(y - x) / max(x, 1):+6.1%})  {bin_}")
    print(f"largest {n} moves:")
    for k in sorted(both, key=lambda k: -abs(b[k][0] - a[k][0]))[:n]:
        print(f"  {a[k][0] / 1e9:8.2f} -> {b[k][0] / 1e9:8.2f} G  {' '.join(k)}")
    for name, only, rows in (("old", a.keys() - b.keys(), a), ("new", b.keys() - a.keys(), b)):
        if only:
            print(f"only in {name}: {len(only)} tests, {sum(rows[k][0] for k in only) / 1e9:.1f} G")
            for k in sorted(only, key=lambda k: -rows[k][0])[:n]:
                print(f"  {rows[k][0] / 1e9:8.2f} G  {' '.join(k)}")


if __name__ == "__main__":
    a = sys.argv[1:]

    def opt(name, default):
        if name in a:
            i = a.index(name)
            v = a[i + 1]
            del a[i:i + 2]
            return v
        return default
    if a[:1] == ["run"] and len(a) >= 2:
        jobs = int(opt("--jobs", max(1, os.cpu_count() // 2)))
        sys.exit(run(a[1], jobs, a[2:]))
    elif a[:1] == ["measure"] and len(a) == 3:
        sys.exit(measure(a[1], int(a[2])))
    elif a[:1] == ["top"] and len(a) in (2, 3):
        top(a[1], int(a[2]) if len(a) == 3 else 30)
    elif a[:1] == ["compare"] and len(a) in (3, 4):
        compare(a[1], a[2], int(a[3]) if len(a) == 4 else 30)
    else:
        sys.exit(__doc__)
