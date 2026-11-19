#!/usr/bin/env python3
"""Tests tools/heavy against a fake cargo (it calls its runner the way cargo does): a queued cargo
run runs the binaries as they were at invocation, with cargo's args, cwd and env; --no-fail-fast
and exit codes as cargo's; a failed build never queues; other commands run as given. Exit 1 on a
mismatch."""
import fcntl, json, os, subprocess, sys, tempfile

sys.dont_write_bytecode = True
HEAVY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy")

FAKE_CARGO = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
runner = next(v for k, v in os.environ.items() if k.startswith("CARGO_TARGET_") and k.endswith("_RUNNER")).split()
for r in json.load(open(os.environ["FAKE_PLAN"])):
    print(f"     Running {r['desc']} ({r['bin']})", file=sys.stderr, flush=True)
    subprocess.run([*runner, r["bin"], *r["args"]], cwd=r["cwd"], env=dict(os.environ, FAKE_SET="by-cargo"), check=True)
print("   Compiling noise", file=sys.stderr)
sys.exit(int(os.environ.get("FAKE_RC", "0")))
'''

fails = 0


def expect(what, got, want):
    global fails
    if got != want:
        fails += 1
        print(f"FAIL {what}:\n  got  {got!r}\n  want {want!r}")


d = tempfile.mkdtemp(prefix="heavy-test-")
bindir = os.path.join(d, "bin")
os.makedirs(bindir)
with open(os.path.join(bindir, "cargo"), "w") as f:
    f.write(FAKE_CARGO)
os.chmod(os.path.join(bindir, "cargo"), 0o755)
ENV = dict(os.environ, PATH=bindir + ":" + os.environ["PATH"], XDG_RUNTIME_DIR=d, HOME=d, TMPDIR=d,
           RUSTUP_HOME=os.environ.get("RUSTUP_HOME", os.path.expanduser("~/.rustup")), CARGO_HOME=os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo")), FAKE_PLAN=os.path.join(d, "plan.json"))
ENV.pop("HEAVY_HELD", None)


def binary(name, body):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(p, 0o755)
    return p


def plan(*runs):
    with open(ENV["FAKE_PLAN"], "w") as f:
        json.dump([dict(desc=f"tests/{os.path.basename(b)}.rs", bin=b, args=list(a), cwd=c) for b, a, c in runs], f)


def heavy(*cmd, **env):
    r = subprocess.run([HEAVY, *cmd], env=dict(ENV, **env), capture_output=True, text=True, cwd=d)
    return r.returncode, lines(r.stdout), r.stderr


def lines(out):
    """The command's output lines, words single-spaced, without tools/limits.py's line."""
    return [" ".join(l.split()) for l in out.splitlines() if not l.startswith("   limit ")]


sub = os.path.join(d, "pkg")
os.makedirs(sub)
ok = binary("ok", 'echo "ok $PWD $FAKE_SET $FOO $HEAVY_HELD $*"')
bad = binary("bad", "echo bad; exit 3")

# args, cwd, cargo's env and the caller's reach the copy; cargo's Running line is printed when it runs
plan((ok, ["--exact", "x"], sub))
rc, out, err = heavy("cargo", "test", "-p", "x", FOO="foo")
expect("ok rc", rc, 0)
expect("ok out", out, [f"ok {sub} by-cargo foo 1 --exact x"])
expect("Running once, at the run", err.count("Running tests/ok.rs"), 1)
expect("build output passes", "Compiling noise" in err, True)

# without --no-fail-fast the first failing binary stops the run; exit 101 as cargo
plan((bad, [], d), (ok, [], d))
rc, out, _ = heavy("cargo", "test")
expect("fail-fast rc", rc, 101)
expect("fail-fast out", out, ["bad"])
rc, out, _ = heavy("cargo", "test", "--no-fail-fast")
expect("no-fail-fast rc", rc, 101)
expect("no-fail-fast out", out, ["bad", f"ok {d} by-cargo 1"])

# cargo run: the binary's own exit code; behind env VAR=VAL
plan((bad, [], d))
expect("run rc", heavy("env", "A=1", "cargo", "run", "--bin", "bad")[0], 3)

# a failed build exits with cargo's code and runs nothing
plan((ok, [], d))
rc, out, _ = heavy("cargo", "test", FAKE_RC="7")
expect("build failure", (rc, out), (7, []))

# a non-cargo command runs as given
rc, out, _ = heavy("sh", "-c", "echo $HEAVY_HELD; exit 4")
expect("plain", (rc, out), (4, ["1"]))

# queued behind another hold, the run executes the binary as it was at invocation
plan((ok, [], d))
lock = os.open(os.path.join(d, "osis-gate.lock"), os.O_RDWR | os.O_CREAT, 0o666)
fcntl.flock(lock, fcntl.LOCK_EX)
p = subprocess.Popen([HEAVY, "cargo", "test"], env=ENV, cwd=d, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
for line in p.stderr:
    if "waiting for" in line:
        break
binary("ok", "echo edited")
fcntl.flock(lock, fcntl.LOCK_UN)
out, _ = p.communicate()
expect("stale-free", (p.returncode, lines(out)), (0, [f"ok {d} by-cargo 1"]))
expect("copies removed", [x for x in os.listdir(d) if x.startswith("osis-heavy-")], [])

# the short lane runs beside a held heavy lock without waiting, and logs its run as the lane's
fcntl.flock(lock, fcntl.LOCK_EX)
rc, out, err = heavy("--short", "sh", "-c", "echo $HEAVY_HELD")
expect("short beside a hold", (rc, out, "waiting" in err), (0, ["1"], False))
log = [json.loads(l) for l in open(os.path.join(d, ".cache/osis/heavy.log"))]
expect("short logged", [o.get("lane") for o in log if o["ev"] == "acq"][-1], "short")
expect("short refuses --limit", heavy("--short", "--limit", "gate", "true")[0], 1)
fcntl.flock(lock, fcntl.LOCK_UN)

# past a cap the lane kills the run's whole tree (exit 137); caps given directly, as limit
# heavy.short's are too large to wait for in a test
LANE = r"""
import importlib.machinery, importlib.util, json, sys
l = importlib.machinery.SourceFileLoader("heavy", sys.argv[1])
h = importlib.util.module_from_spec(importlib.util.spec_from_loader("heavy", l)); l.exec_module(h)
cpu, wall, rss, cmd = float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), sys.argv[5:]
h.SHORT_RSS = rss
who = dict(who="t", branch="t", sess="", via="", cmd="t")
rc = h.hold(cmd, "heavy", None, who, [dict(argv=cmd, cwd=None, env=None)], None, (cpu, wall))
print(rc)
"""
spin = "while :; do :; done"
pidf = os.path.join(d, "pids")


def lane(cpu, wall, rss, *cmd):
    """(the exit code printed, stderr); output through files, so a survivor cannot hang a pipe"""
    with open(os.path.join(d, "lane.out"), "w+") as o, open(os.path.join(d, "lane.err"), "w+") as e:
        subprocess.run([sys.executable, "-c", LANE, HEAVY, str(cpu), str(wall), str(rss), *cmd], env=ENV, stdout=o, stderr=e, cwd=d)
        o.seek(0), e.seek(0)
        return o.read().split()[-1:], e.read()


def alive(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


big = str(1 << 40)
got, err = lane(1, 60, big, "sh", "-c", rf'sh -c "echo \$\$ >> {pidf}; {spin}" & sh -c "echo \$\$ >> {pidf}; {spin}"; wait')
expect("CPU cap over a tree", (got, "CPU-s" in err), (["137"], True))
left = [int(p) for p in open(pidf).read().split() if alive(p)]
expect("the whole tree killed", left, [])
for p in left:
    os.kill(p, 9)
got, err = lane(60, 1, big, "sleep", "30")
expect("wall cap", (got, "wall" in err), (["137"], True))
got, err = lane(60, 60, "1", "sleep", "30")
expect("memory cap", (got, "resident" in err), (["137"], True))
got, _ = lane(60, 60, big, "sh", "-c", "exit 5")
expect("within the caps: the command's code", got, ["5"])

subprocess.run(["rm", "-rf", d])
print("heavy_test: ok" if not fails else f"heavy_test: {fails} failed")
sys.exit(1 if fails else 0)
