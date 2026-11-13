#!/usr/bin/env python3
"""Runs a `cargo test` command with a hang bound (notes/gate.md, Hung tests): its output (stderr
merged) passes through unchanged, and when no test of the running target has finished for HANG
times the `test` wall limit (notes/build.md, Time limits), and at least twice libtest's 60-second
notice, counted from the target's start or its last finished test, the target is stopped: every
process below each `cargo` process in CMD's tree (the test binary or rustdoc and what they
started) and every orphan of that tree (the watcher is their subreaper), by PID, never by name. It
first prints
`gate: hung: WHY` and a `gate: hung test: NAME` line per test still running (those libtest said
had run over 60 seconds and that have not finished since; a test starts only when another ends or
its target starts, so each has run the whole bound). cargo then goes on with the next target
(`--no-fail-fast`); tools/gate_failures.py reports each named test as failed, "hung". On SIGTERM
or SIGHUP the watcher kills its whole tree and exits 128 + the signal.

  tools/test_watch.py CMD...    exits with CMD's exit status
GATE_HANG_S, if set, is the bound in seconds instead (tools/gate_select_test.sh's fake hang).
"""
import ctypes, os, re, select, signal, subprocess, sys, time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import limits

# R: a run-away bound. 0: every target is stopped before its first test ends; infinity: a hung test
# holds the gate and the box-wide heavy lock until someone notices. Past it a test has run 10 times
# its limit, five times the overrun that starts an investigation (notes/build.md, Time limits): a
# hang, or a test so slow that failing it costs nothing. The wall limit shrinks with the box's
# threads, a single test's wall does not: the floor, twice libtest's notice, keeps the bound past
# it on any box, so the running tests are named (fastbox-0: 10 x 11 s, so 120 s).
HANG = 10
NOTICE = 60
SEGMENT = re.compile(r"^\s+(Running |Doc-tests )")
FINISHED = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)")
SLOW = re.compile(r"^test (.+) has been running for over 60 seconds$")


def bound():
    """The hang bound in seconds, or None with no `test` limit on this box."""
    if os.environ.get("GATE_HANG_S"):
        return float(os.environ["GATE_HANG_S"])
    lim, why = limits.limit("test")
    if lim is None:
        print(f"gate: no hang bound: {why}", flush=True)
        return None
    return max(HANG * lim[1], 2 * NOTICE)


def stat(pid):
    """(comm, ppid, starttime) of pid, or None once it is gone."""
    try:
        s = open(f"/proc/{pid}/stat").read()
    except OSError:
        return None
    comm, rest = s[s.index("(") + 1:s.rindex(")")], s[s.rindex(")") + 2:].split()
    return comm, int(rest[1]), int(rest[19])


def tree(root):
    """{pid: (comm, ppid, starttime)} of root and every process below it."""
    procs = {int(p): st for p in os.listdir("/proc") if p.isdigit() and (st := stat(int(p)))}
    kids = {}
    for p, (_, pp, _) in procs.items():
        kids.setdefault(pp, []).append(p)
    out, todo = {}, [root]
    while todo:
        p = todo.pop()
        if p in procs:
            out[p] = procs[p]
            todo += kids.get(p, [])
    return out


def below(t, p):
    """p and every process of t below it."""
    out, todo = [], [p]
    while todo:
        q = todo.pop()
        out.append(q)
        todo += [c for c, (_, pp, _) in t.items() if pp == q]
    return out


def stop(child, everything=False):
    """Kills the running target: what runs below each `cargo` in child's tree (all of child's tree
    when none is a cargo, or with `everything`), and every orphan reparented to this watcher.
    Returns (roots stopped as `pid (comm)`, processes killed)."""
    me = os.getpid()
    t = tree(me)
    orphans = [c for c, (_, pp, _) in t.items() if pp == me and c != child]
    cargos = [p for p in below(t, child) if p in t and t[p][0] == "cargo"]
    tops = [c for c, (comm, pp, _) in t.items() if pp in cargos and comm != "cargo"] if cargos and not everything else [child]
    tops = [p for p in tops + orphans if p in t]
    victims = [q for p in tops for q in below(t, p)]
    fds = []
    for q in victims:
        # a pidfd pins the process: the same start time after opening it means the pid is not reused
        try:
            fd = os.pidfd_open(q)
        except OSError:
            continue
        st = stat(q)
        if st and st[2] == t[q][2]:
            fds.append(fd)
        else:
            os.close(fd)
    for fd in fds:
        try:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        except OSError:
            pass
        os.close(fd)
    return [f"{p} ({t[p][0]})" for p in tops], len(fds)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    hang = bound()
    # PR_SET_CHILD_SUBREAPER: a process orphaned below (its cargo killed) stays in this tree
    ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)
    child = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def quit(sig, _):
        stop(child.pid, everything=True)
        os._exit(128 + sig)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, quit)
    fd, out = child.stdout.fileno(), sys.stdout.buffer
    # the clock runs inside a target: since its start or its last finished test
    last, slow, part = None, {}, b""
    while True:
        wait = None if last is None or hang is None else max(0.0, last + hang - time.monotonic())
        ready, _, _ = select.select([fd], [], [], wait)
        if not ready:
            # libtest on one thread prints `test NAME ... ` when the test starts, and no notice
            if m := re.match(rb"^test (.+) \.\.\. $", part):
                slow[m.group(1).decode(errors="replace")] = True
            if part:
                out.write(b"\n")
                out.flush()
                part = b""
            names = list(slow)
            print(f"gate: hung: no test finished for {hang:.0f} s", flush=True)
            for n in names:
                print(f"gate: hung test: {n}", flush=True)
            tops, n = stop(child.pid)
            print(f"gate: hung: stopped {', '.join(tops) or 'nothing (gone)'}, {n} processes", flush=True)
            last, slow = None, {}
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        out.write(chunk)
        out.flush()
        part += chunk
        *lines, part = part.split(b"\n")
        for line in lines:
            line = line.decode(errors="replace").rstrip("\r")
            if SEGMENT.match(line):
                last, slow = time.monotonic(), {}
            elif m := FINISHED.match(line):
                last = time.monotonic()
                slow.pop(m.group(1), None)
            elif m := SLOW.match(line):
                slow[m.group(1)] = True
    return child.wait()


if __name__ == "__main__":
    rc = main()
    sys.exit(rc if rc >= 0 else 128 - rc)
