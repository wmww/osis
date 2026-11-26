#!/usr/bin/env python3
"""Runs a `cargo test` command one cargo per test target, side by side, so no core idles while a
target ends on its slowest tests (notes/gate.md, Steps: the hold's stages).

  tools/targets.py [--watch] cargo test ARGS... [-- LIBTEST ARGS...]

Lists the targets ARGS select (`cargo test ARGS --no-run --message-format=json`), then runs each
as `cargo test ARGS' -p PKG --lib|--bin B|--test T|--example E|--bench B [-- LIBTEST ARGS]` (ARGS'
being ARGS without their package and target selection), plus one `--doc` run of ARGS' packages when
ARGS select no target kind (cargo's default, which runs doctests), of the listed packages whose
library has doctests. At most as many runs at once as
the box has hardware threads, costliest first by tools/test_cost.txt (its line for the target; none
or a doctest run: last). Each run's output (stderr merged) is printed whole when it ends, so the
log reads as cargo's own, one target's segment at a time; the exit is 0 when every run's was, else
the first non-zero one.

--watch runs each under tools/test_watch.py (its hang bound per target and the instruction count
per binary). A property run (tools/prop_run.py as cargo's runner) shares one pool of hardware-thread
slots across all of them: SLOTS_VAR names a pipe holding one token per thread, inherited by every
run. On SIGTERM or SIGHUP every run's process group is sent SIGTERM (a watcher then stops its tree)
and this exits 128 + the signal.

The jobs bound: at 0 nothing runs; at infinity every target's cargo and binary are resident at once
(about 40 cargos in the default tests). A run keeps at least one thread busy, so as many runs as
threads keep every core busy whatever each one's width; more only adds memory."""
import json, os, signal, subprocess, sys, tempfile

sys.dont_write_bytecode = True
TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
ROOT = os.path.dirname(TOOLS)
WATCH = os.path.join(TOOLS, "test_watch.py")
COST = os.path.join(ROOT, "tools", "test_cost.txt")
SLOTS_VAR = "GATE_SLOTS"
# package selection (with a value, or alone) and target selection (`--test T` takes one)
PKG_VALUE = ("-p", "--package", "--exclude")
PKG_FLAG = ("--workspace", "--all")
KIND_VALUE = ("--bin", "--test", "--example", "--bench")
KIND_FLAG = ("--lib", "--bins", "--tests", "--examples", "--benches", "--all-targets", "--doc")


def split(args):
    """(cargo ARGS without their package and target selection, whether a target kind was named,
    libtest's args after `--`)."""
    cargo, rest = (args[:args.index("--")], args[args.index("--") + 1:]) if "--" in args else (args, [])
    kept, kinds, i = [], False, 0
    while i < len(cargo):
        a, i = cargo[i], i + 1
        if a in PKG_VALUE or a in KIND_VALUE:
            kinds, i = kinds or a in KIND_VALUE, i + 1
        elif a.split("=")[0] in PKG_VALUE or a in PKG_FLAG:
            pass
        elif a in KIND_FLAG or a.split("=")[0] in KIND_VALUE:
            kinds = True
        else:
            kept.append(a)
    return kept, kinds, rest


def listed(cargo):
    """([(package, flag, target name)] of every test executable `cargo CARGO --no-run` builds, [each
    of their packages whose library has doctests])."""
    r = subprocess.run([*cargo, "--no-run", "--message-format=json"], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)
    if r.returncode:
        sys.exit(f"targets: listing the targets failed (exit {r.returncode}): {' '.join(cargo)}")
    meta = json.loads(subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
                                     stdout=subprocess.PIPE, check=True, text=True).stdout)
    names = {p["id"]: p["name"] for p in meta["packages"]}
    doc = {p["name"] for p in meta["packages"] if any(t.get("doctest") and "lib" in t["kind"] for t in p["targets"])}
    out = []
    for line in r.stdout.split("\n"):
        d = json.loads(line) if line.startswith("{") else {}
        if d.get("reason") != "compiler-artifact" or not d.get("executable") or not d["profile"]["test"]:
            continue
        kind, name = d["target"]["kind"][0], d["target"]["name"]
        flag = {"bin": ["--bin", name], "test": ["--test", name], "example": ["--example", name], "bench": ["--bench", name]}.get(kind, ["--lib"])
        out.append((names[d["package_id"]], flag, name))
    return out, sorted({p for p, _, _ in out} & doc)


def costs():
    """{CRATE/NAME: G} of tools/test_cost.txt."""
    out = {}
    for l in open(COST) if os.path.exists(COST) else []:
        f = l.split()
        if len(f) == 2 and not l.startswith("#"):
            try:
                out[f[0]] = float(f[1])
            except ValueError:
                pass
    return out


def compact():
    """tools/prop_run.py's cost record cut to each test's last line, before any runner appends."""
    import prop_run
    last = prop_run.last_costs()
    if last:
        try:
            with open(prop_run.COSTS + ".new", "w") as f:
                f.writelines(f"- {n} {c:.1f}\n" for n, c in sorted(last.items()))
            os.replace(prop_run.COSTS + ".new", prop_run.COSTS)
        except OSError:
            pass


def main(argv):
    watch = bool(argv) and argv[0] == "--watch"
    argv = argv[1:] if watch else argv
    if len(argv) < 2 or argv[1] != "test":
        sys.exit(__doc__)
    kept, kinds, rest = split(argv[2:])
    base = argv[:2] + kept
    head = argv[:argv.index("--")] if "--" in argv else argv
    g = costs()
    runs, doc = listed(head)
    runs.sort(key=lambda t: -g.get(f"{t[0]}/{t[2]}", -1))
    cmds = [[*base, "-p", p, *flag, *(["--", *rest] if rest else [])] for p, flag, _ in runs]
    if not kinds and doc:
        cmds.append([*base, *[a for p in doc for a in ("-p", p)], "--doc", *(["--", *rest] if rest else [])])
    width = os.cpu_count() or 1
    compact()
    r, w = os.pipe()
    os.write(w, b"." * width)
    env = dict(os.environ, **{SLOTS_VAR: f"{r},{w}"})
    running = {}

    def quit(sig, _):
        for p in list(running):
            try:
                os.killpg(p, signal.SIGTERM)
            except OSError:
                pass
        os._exit(128 + sig)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, quit)
    rc, todo = 0, list(cmds)
    while todo or running:
        while todo and len(running) < width:
            c = todo.pop(0)
            out = tempfile.TemporaryFile("w+b")
            p = subprocess.Popen([sys.executable, WATCH, *c] if watch else c, stdout=out, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, env=env, pass_fds=(r, w), start_new_session=True)
            running[p.pid] = (p, out)
        pid, status = os.wait()
        if pid not in running:
            continue
        p, out = running.pop(pid)
        code = os.waitstatus_to_exitcode(status)
        p.returncode = code
        out.seek(0)
        sys.stdout.buffer.write(out.read())
        sys.stdout.buffer.flush()
        out.close()
        rc = rc or (code if code >= 0 else 128 - code)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
