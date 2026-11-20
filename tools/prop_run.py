#!/usr/bin/env python3
"""Cargo's runner for the gate's properties stage (notes/gate.md, The selection): each selected
test in its own process, so the gate measures every property's CPU itself, whatever its harness
prints.

  tools/prop_run.py BIN [LIBTEST ARGS...]   (as CARGO_TARGET_<HOST>_RUNNER; cargo sets cwd and env)

Lists BIN's tests matching ARGS (`--list`, the same filters, `--ignored` and `--skip`s), then runs
each as `BIN --exact NAME` (keeping `--ignored`/`--include-ignored`), as many at once as libtest
would run threads (RUST_TEST_THREADS, else every core). Each child's own CPU-s and wall come from
its rusage (wait4): `gate: cost NAME: W s, C CPU-s` after its `test NAME ... ok|FAILED` line.
tools/gate_failures.py reads those lines for the cost table.

Its output is one libtest run (`running N tests`, the test lines, the failures' sections, `test
result:`; exit 101 on a failure), so tools/gate_failures.py parses the target as before. A child
that ends without its own `test result:` line (a crash, a signal, a hung-seed exit) or that ran
no test: its output is printed and the target ends without a summary line, which the summary
counts NEW, as for a crashed target.

A test listed in tools/known_failures.txt with a `counts:` baseline runs at that line's REPRO
setting (`VAR=VAL,...`; `-` keeps the gate's), so its failing counts compare with the baseline
(tools/gate_failures.py, notes/coordination.md, Known failures)."""
import os, re, subprocess, sys, tempfile, time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_failures

KEEP = ("--ignored", "--include-ignored", "--nocapture", "--show-output")


def listed(bin_, args):
    r = subprocess.run([bin_, "--list", *args], stdout=subprocess.PIPE, text=True, errors="replace")
    if r.returncode:
        sys.stdout.write(r.stdout)
        print(f"gate: listing {bin_}'s tests failed (exit {r.returncode})")
        sys.exit(r.returncode)
    return [l[:-len(": test")] for l in r.stdout.split("\n") if l.endswith(": test")]


def section(out, name):
    """The child's `---- NAME stdout ----` section, up to its `failures:` list."""
    lines = out.split("\n")
    head = f"---- {name} stdout ----"
    if head not in lines:
        return []
    i = lines.index(head) + 1
    j = next((k for k in range(i, len(lines)) if lines[k] == "failures:"), len(lines))
    return lines[i:j]


def main(argv, root=gate_failures.ROOT):
    if not argv:
        sys.exit(__doc__)
    bin_, args = argv[0], argv[1:]
    names = listed(bin_, args)
    keep = [a for a in args if a in KEEP]
    envs = gate_failures.counted_envs(root)
    width = int(os.environ.get("RUST_TEST_THREADS") or os.cpu_count() or 1)
    print(f"\nrunning {len(names)} test{'' if len(names) == 1 else 's'}", flush=True)
    t0 = time.time()
    todo, running, done = list(names), {}, {}
    while todo or running:
        while todo and len(running) < width:
            n = todo.pop(0)
            out = tempfile.TemporaryFile("w+", errors="replace")
            env = dict(os.environ, **envs.get(n, {}))
            p = subprocess.Popen([bin_, "--exact", n, *keep], stdout=out, stdin=subprocess.DEVNULL, env=env)
            running[p.pid] = (n, out, time.time(), p)
        pid, status, ru = os.wait4(-1, 0)
        if pid not in running:
            continue
        n, out, s, p = running.pop(pid)
        p.returncode = os.waitstatus_to_exitcode(status)  # reaped here: Popen must not wait again
        out.seek(0)
        text = out.read()
        out.close()
        ok = p.returncode == 0 and re.search(r"^test result: ok\. 1 passed;", text, re.M)
        failed = re.search(r"^test result: FAILED\. 0 passed; 1 failed;", text, re.M)
        done[n] = (bool(ok), bool(failed), text, p.returncode)
        print(f"test {n} ... {'ok' if ok else 'FAILED'}")
        print(f"gate: cost {n}: {time.time() - s:.1f} s, {ru.ru_utime + ru.ru_stime:.1f} CPU-s", flush=True)
    broken = [n for n in names if not done[n][0] and not done[n][1]]
    if broken:
        for n in broken:
            print(f"gate: {n} ended without one test's result (exit {done[n][3]}: a crash, a signal, a hung-seed exit, or no such test); its output:")
            sys.stdout.write(done[n][2])
        return done[broken[0]][3] or 101
    bad = [n for n in names if done[n][1]]
    if bad:
        print("\nfailures:\n")
        for n in bad:
            print(f"---- {n} stdout ----")
            print("\n".join(section(done[n][2], n)))
        print("\nfailures:")
        for n in bad:
            print(f"    {n}")
    print(f"\ntest result: {'FAILED' if bad else 'ok'}. {len(names) - len(bad)} passed; {len(bad)} failed; 0 ignored; 0 measured; 0 filtered out; finished in {time.time() - t0:.2f}s\n", flush=True)
    return 101 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
