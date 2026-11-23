#!/usr/bin/env python3
"""Tests tools/heavy against a fake cargo (it calls its runner the way cargo does): a queued cargo
run runs the binaries as they were at invocation, with cargo's args, cwd and env; --no-fail-fast
and exit codes as cargo's; a failed build never queues; other commands run as given. Exit 1 on a
mismatch."""
import fcntl, json, os, subprocess, sys, tempfile, time

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

# a release build is refused before anything builds, unless HEAVY_RELEASE is set
plan((ok, [], d))
rc, out, err = heavy("cargo", "run", "--release", "--bin", "ok")
expect("release refused", (rc, out, "release" in err), (1, [], True))
expect("release with HEAVY_RELEASE", heavy("cargo", "run", "--release", "--bin", "ok", HEAVY_RELEASE="1")[0], 0)
expect("--release after -- is the binary's", heavy("cargo", "run", "--bin", "ok", "--", "--release")[0], 0)

# a module filter beside a name-fragment filter under --ignored is refused (libtest ORs them)
rc, out, err = heavy("cargo", "test", "-p", "x", "--", "--ignored", "paths::", "_plain")
expect("OR'd filters refused", (rc, out, "ORs filters" in err), (1, [], True))
expect("with --exact it runs", heavy("cargo", "test", "-p", "x", "--", "--ignored", "--exact", "paths::a_plain")[0], 0)
expect("a list of names runs", heavy("cargo", "test", "-p", "x", "--", "--ignored", "a_plain", "b_large", "--skip", "repro_")[0], 0)

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

# queued with --log, the log file says it waits before the run's own output
fcntl.flock(lock, fcntl.LOCK_EX)
logf = os.path.join(d, "logs", "q.log")
p = subprocess.Popen([HEAVY, "--log", logf, "sh", "-c", "echo ran"], env=ENV, cwd=d, stderr=subprocess.PIPE, text=True)
for line in p.stderr:
    if "waiting for" in line:
        break
expect("log says waiting", [l.split(" (")[0] for l in open(logf).read().splitlines()], ["heavy: waiting for " + os.path.join(d, "osis-gate.lock")])
fcntl.flock(lock, fcntl.LOCK_UN)
p.communicate()
expect("log then the run", [l for l in open(logf).read().splitlines() if not l.startswith("heavy: waited")][1:], ["ran"])
expect("copies removed", [x for x in os.listdir(d) if x.startswith("osis-heavy-")], [])

# the short lane runs beside a held heavy lock without waiting, and logs its run as the lane's
fcntl.flock(lock, fcntl.LOCK_EX)
rc, out, err = heavy("--short", "sh", "-c", "echo $HEAVY_HELD")
expect("short beside a hold", (rc, out, "waiting" in err), (0, ["1"], False))
log = [json.loads(l) for l in open(os.path.join(d, ".cache/osis/heavy.log"))]
expect("short logged", [o.get("lane") for o in log if o["ev"] == "acq"][-1], "short")
expect("short refuses --limit", heavy("--short", "--limit", "gate", "true")[0], 1)
fcntl.flock(lock, fcntl.LOCK_UN)

# past a cap the lane kills the run's whole tree and reruns it in a hold; caps and polling given
# directly, as limit heavy.short's are too large to wait for in a test. Each command spins (or
# sleeps, or takes memory) on its first run and prints on its rerun, told apart by a marker file.
LANE = r"""
import importlib.machinery, importlib.util, json, sys
l = importlib.machinery.SourceFileLoader("heavy", sys.argv[1])
h = importlib.util.module_from_spec(importlib.util.spec_from_loader("heavy", l)); l.exec_module(h)
cpu, wall, rss, sub, cmds = float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), sys.argv[5] or None, json.loads(sys.argv[6])
h.SHORT_RSS, h.SHORT_POLL_S = rss, 0.1
who = dict(who="t", branch="t", sess="", via="", cmd="t")
rc = h.hold(["t", "--no-fail-fast"], "heavy", None, who, [dict(argv=c, bin=c[0], cwd=None, env=None) for c in cmds], sub, (cpu, wall))
print(rc)
"""
spin = "while :; do :; done"
pidf = os.path.join(d, "pids")


def lane(cpu, wall, rss, *cmds, sub=""):
    """(the exit code printed, stdout lines before it, stderr, the log's acq events as lanes);
    output through files, so a survivor cannot hang a pipe"""
    open(os.path.join(d, ".cache/osis/heavy.log"), "w").close()
    with open(os.path.join(d, "lane.out"), "w+") as o, open(os.path.join(d, "lane.err"), "w+") as e:
        subprocess.run([sys.executable, "-c", LANE, HEAVY, str(cpu), str(wall), str(rss), sub, json.dumps(cmds)], env=ENV, stdout=o, stderr=e, cwd=d)
        o.seek(0), e.seek(0)
        out, err = [x for x in o.read().split("\n") if x and not x.startswith("   limit ")], e.read()
    log = [json.loads(x) for x in open(os.path.join(d, ".cache/osis/heavy.log"))]
    return out[-1:], out[:-1], err, [o.get("lane", "hold") for o in log if o["ev"] == "acq"]


def once(n, first, then):
    """sh: `first` on the first run, `then` on later ones"""
    m = os.path.join(d, f"mark{n}")
    return ["sh", "-c", f"if [ -e {m} ]; then {then}; else touch {m}; {first}; fi"]


def alive(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


big = str(1 << 40)
got, out, err, acqs = lane(0.5, 60, big, once(1, rf'sh -c "echo \$\$ >> {pidf}; {spin}" & sh -c "echo \$\$ >> {pidf}; {spin}"; wait', "echo again"))
expect("CPU cap over a tree, rerun in a hold", (got, out, "CPU-s" in err, "rerunning it in a hold" in err, acqs), (["0"], ["again"], True, True, ["short", "hold"]))
left = [int(p) for p in open(pidf).read().split() if alive(p)]
expect("the whole tree killed", left, [])
for p in left:
    os.kill(p, 9)
got, out, err, _ = lane(60, 1, big, once(2, "sleep 30", "exit 6"))
expect("wall cap", (got, "wall" in err), (["6"], True))
got, out, err, _ = lane(60, 60, "1", once(3, "sleep 30", "exit 7"))
expect("memory cap", (got, "resident" in err), (["7"], True))
got, _, _, acqs = lane(60, 60, big, ["sh", "-c", "exit 5"])
expect("within the caps: the command's code, no hold", (got, acqs), (["5"], ["short"]))
# a cargo test: binaries before the stop are not rerun, and a failure among them still fails it
got, out, _, acqs = lane(60, 1, big, ["sh", "-c", "echo a; exit 1"], once(4, "sleep 30", "echo b"), sub="test")
expect("test reruns from the stopped binary", (got, out, acqs), (["101"], ["a", "b"], ["short", "hold"]))
# a command once stopped runs in the lane again (no memory of past runs)
rc, out, _ = heavy("--short", "sh", "-c", "echo fits")
expect("a --short runs", (rc, out), (0, ["fits"]))

# a quiet hold yields to a waiter: window and sampling shrunk to fit a test
HOLD = r"""
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("heavy", sys.argv[1])
h = importlib.util.module_from_spec(importlib.util.spec_from_loader("heavy", l)); l.exec_module(h)
h.YIELD_CORES, h.YIELD_WINDOW_S, h.SAMPLE_S = float(sys.argv[2]), 0.5, 0.1
cmd = sys.argv[3:]
who = dict(who="t", branch="t", sess="", via="", cmd="t")
print(h.hold(cmd, "heavy", None, who, [dict(argv=cmd, cwd=None, env=None)], None))
"""
WAITER = r"""
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o666)
fcntl.flock(fd, fcntl.LOCK_EX)
t = time.time()
time.sleep(float(sys.argv[2]))
print(t, time.time())
"""
with open(os.path.join(d, "spin.py"), "w") as f:
    f.write("import sys, time\nt = time.time() + float(sys.argv[1])\nwhile time.time() < t:\n    pass\n")
logf = os.path.join(d, ".cache/osis/heavy.log")
waitf = os.path.join(d, "wait")


def spinners(n, secs):
    return f"for i in {' '.join(map(str, range(n)))}; do {sys.executable} {d}/spin.py {secs} & done; wait"


def yielding(cores, job, hold_s=0.0, waiter=True):
    """Hold the lock for job (a sh script) with a waiter that holds it hold_s once it has it.
    Returns (the holder's printed exit code, its log events, (waiter's acquire, release) times, end)."""
    open(logf, "w").close()
    with open(os.path.join(d, "hold.err"), "w") as e:
        hp = subprocess.Popen([sys.executable, "-c", HOLD, HEAVY, str(cores), "sh", "-c", job], env=dict(ENV, HEAVY_WAIT_FILE=waitf), cwd=d,
                              stdout=subprocess.PIPE, stderr=e, text=True)
        while not os.path.getsize(logf):  # the hold is taken
            time.sleep(0.01)
        wp = waiter and subprocess.Popen([sys.executable, "-c", WAITER, os.path.join(d, "osis-gate.lock"), str(hold_s)],
                                         env=ENV, stdout=subprocess.PIPE, text=True)
        out, _ = hp.communicate()
        end = time.time()
        w = tuple(map(float, wp.communicate()[0].split())) if wp else None
    return out.split()[-1:], [json.loads(x) for x in open(logf)], w, end


# one spinning process: under 1.5 cores, so the waiter gets the lock while it still runs
rc, ev, (wacq, _), end = yielding(1.5, spinners(1, 2))
expect("spinner yields", (rc, [o["ev"] for o in ev if o["ev"] in ("yld", "back")], wacq < end - 0.5), (["0"], ["yld"], True))
# idle, then over its share beside the waiter's hold: stopped until it holds the lock again, then done
rc, ev, (_, wrel), _ = yielding(0.5, f"sleep 1; {spinners(4, 0.5)}", hold_s=1.5)
backs = [o for o in ev if o["ev"] == "back"]
expect("idle then busy: yields, stops, resumes", (rc, [o["ev"] for o in ev if o["ev"] in ("yld", "back")], [o["paused"] for o in backs]),
       (["0"], ["yld", "back"], [True]))
expect("resumed only after the waiter's hold", backs and backs[0]["t"] >= wrel - 0.05, True)
# the wait to take the lock back is a wait, not the hold's: written to the wait file, left out of held
acq, rel = next(o for o in ev if o["ev"] == "acq"), next(o for o in ev if o["ev"] == "rel")
expect("retake wait left out of held", bool(backs) and abs(rel["held"] + backs[0]["wait"] - (rel["t"] - acq["t"])) < 0.2, True)
expect("retake wait in the wait file", bool(backs) and open(waitf).read().strip() == f"{acq['wait'] + backs[0]['wait']:.0f}", True)
# a busy run keeps the lock with a waiter (two spinners: over 0.5 cores at any load); a quiet one
# keeps it with none
rc, ev, (wacq, _), end = yielding(0.5, spinners(2, 1.5))
expect("busy keeps the lock", (rc, [o["ev"] for o in ev if o["ev"] == "yld"], wacq >= end - 0.5), (["0"], [], True))
rc, ev, _, _ = yielding(1.5, "sleep 1", waiter=False)
expect("no waiter: no yield", (rc, [o["ev"] for o in ev if o["ev"] == "yld"]), (["0"], []))

subprocess.run(["rm", "-rf", d])
print("heavy_test: ok" if not fails else f"heavy_test: {fails} failed")
sys.exit(1 if fails else 0)
