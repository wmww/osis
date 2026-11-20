#!/usr/bin/env python3
"""Tests tools/mutate.py against a fake cargo (it calls its runner the way cargo does, with cargo's
env): each mutation runs copies of the binaries built for it, with cargo's env and OSIS_MUTANT, so
a rebuild while a MUTATE_HEAVY run waits for the lock changes nothing it runs; the file is put back
before the run; an OLD that is not an expression is refused before building. Exit 1 on a mismatch."""
import fcntl, json, os, subprocess, sys, tempfile

sys.dont_write_bytecode = True
MUTATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutate.py")

# the plan's binaries run through the runner with what cargo adds to the env ([env]: the suite's proptest count)
FAKE_CARGO = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
open(os.environ["FAKE_ARGS"], "w").write(json.dumps(sys.argv[1:]))
runner = next(v for k, v in os.environ.items() if k.startswith("CARGO_TARGET_") and k.endswith("_RUNNER")).split()
for b in json.load(open(os.environ["FAKE_PLAN"])):
    subprocess.run([*runner, b, *sys.argv[sys.argv.index("--") + 1:]], env=dict(os.environ, PROPTEST_CASES="32"), check=True)
'''

ok = True


def check(what, got, want):
    global ok
    if got != want:
        print(f"FAIL {what}:\n  got  {got!r}\n  want {want!r}")
        ok = False


with tempfile.TemporaryDirectory(prefix="mutate-test-") as d:
    bindir = os.path.join(d, "bin")
    os.makedirs(bindir)
    with open(os.path.join(bindir, "cargo"), "w") as f:
        f.write(FAKE_CARGO)
    os.chmod(os.path.join(bindir, "cargo"), 0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PROPTEST_", "MUTATE_", "HEAVY_")) and k != "OSIS_MUTANT"}
    env.update(PATH=bindir + ":" + os.environ["PATH"], XDG_RUNTIME_DIR=d, HOME=d, TMPDIR=d, FAKE_PLAN=os.path.join(d, "plan.json"),
               FAKE_ARGS=os.path.join(d, "args.json"), RUSTUP_HOME=os.environ.get("RUSTUP_HOME", os.path.expanduser("~/.rustup")),
               CARGO_HOME=os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo")))
    # a test binary: fails test `t` under mutation 1
    exe = os.path.join(d, "it")
    with open(exe, "w") as f:
        f.write('#!/bin/sh\necho "cases=$PROPTEST_CASES args=$*"\n'
                'if [ "$OSIS_MUTANT" = 1 ]; then echo "test t ... FAILED"; exit 101; fi\necho "test t ... ok"\n')
    os.chmod(exe, 0o755)
    with open(env["FAKE_PLAN"], "w") as f:
        json.dump([exe], f)
    src = os.path.join(d, "x.rs")
    with open(src, "w") as f:
        f.write("fn f() -> bool { a < b && c }\n")

    def mutate(*a, **e):
        return subprocess.Popen([sys.executable, MUTATE, *a], env=dict(env, **e), cwd=d, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # queued behind a hold, the runs are the copies built for the mutations, whatever the worktree builds meanwhile
    lock = os.open(os.path.join(d, "osis-gate.lock"), os.O_RDWR | os.O_CREAT, 0o666)
    fcntl.flock(lock, fcntl.LOCK_EX)
    p = mutate(src, "a < b", "a <= b", src, "c", "!c", "--", "-p", "x", "--", "--exact", "t", MUTATE_HEAVY="1", MUTATE_OUT=os.path.join(d, "out"))
    for line in p.stderr:
        if "waiting for" in line:
            break
    check("file put back before the run", open(src).read(), "fn f() -> bool { a < b && c }\n")
    with open(exe, "w") as f:
        f.write("#!/bin/sh\necho rebuilt\n")
    fcntl.flock(lock, fcntl.LOCK_UN)
    out, _ = p.communicate()
    check("rows from the copies", (p.returncode, [l for l in out.splitlines() if not l.startswith("   limit ")]),
          (0, ["| `%s`: `a < b` -> `a <= b` | none |" % src, "| `%s`: `c` -> `!c` | t |" % src]))
    check("cargo's env and args reach the copy", open(os.path.join(d, "out", "mutant-0.log")).read().splitlines()[1], "cases=32 args=--exact t")
    check("no target selected: --tests", json.load(open(env["FAKE_ARGS"])), ["test", "--message-format=json", "--tests", "-p", "x", "--", "--exact", "t"])
    check("copies removed", [x for x in os.listdir(d) if x.startswith(("mutate-bins-", "osis-heavy-"))], [])

    # `+` joins two sites into one mutation: one row, both planted under one OSIS_MUTANT value
    with open(src, "w") as f:
        f.write("fn f() -> bool { a < b && c || d }\n")
    with open(env["FAKE_PLAN"], "w") as f:
        json.dump([exe], f)
    with open(exe, "w") as f:
        f.write('#!/bin/sh\nif [ "$OSIS_MUTANT" = 1 ]; then echo "test t ... FAILED"; exit 101; fi\necho "test t ... ok"\n')
    p = mutate(src, "a < b", "a <= b", "+", src, "c", "!c", src, "d", "!d", "--", "-p", "x")
    out, err = p.communicate()
    check("grouped rows", (p.returncode, [l for l in out.splitlines() if not l.startswith("   limit ")]),
          (0, ["| `%s`: `a < b` -> `a <= b` + `%s`: `c` -> `!c` | none |" % (src, src), "| `%s`: `d` -> `!d` | t |" % src]))
    check("grouped: file put back", open(src).read(), "fn f() -> bool { a < b && c || d }\n")
    with open(src, "w") as f:
        f.write("fn f() -> bool { a < b && c }\n")

    # an OLD found in another's wrapper text is no overlap (`c` above); overlapping spans are refused
    os.remove(env["FAKE_ARGS"])
    p = mutate(src, "a < b", "a <= b", src, "b && c", "b || c", "--", "--lib")
    _, err = p.communicate()
    check("overlapping spans", (p.returncode, "overlap" in err, os.path.exists(env["FAKE_ARGS"])), (1, True, False))

    # a method-call suffix or a statement among several mutations: refused before any build
    for old in (".then_with(g)", "x;"):
        with open(src, "w") as f:
            f.write(f"fn f() {{ a{old} zz }}\n")
        p = mutate(src, old, "y", src, "zz", "!zz", "--", "--lib")
        _, err = p.communicate()
        check(f"refused {old}", (p.returncode, "not an expression" in err, os.path.exists(env["FAKE_ARGS"])), (1, True, False))
print(f"mutate: {'ok' if ok else 'FAILED'}")
sys.exit(0 if ok else 1)
