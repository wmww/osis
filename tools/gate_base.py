#!/usr/bin/env python3
"""The gate's base replays (notes/gate.md, On the base): each NEW failing unit of the property and sim
stages that names its seed, replayed on the merge base's binary, so a seed failing on main as it
stands is told from one the branch broke.

  tools/gate_base.py SEL RESULTS BASE [ROOT]   SEL, RESULTS: the gate's selection and stage results
      (tools/gate_failures.py); BASE: the merge base; ROOT: where the known list is (default: this
      checkout; tools/gate_base_test.py passes a fabricated one). Run by tools/gate.sh at the end of
      its heavy hold, from the worktree root.

The NEW units are tools/gate_failures.py's (`new_units`: no known line accounts for them). With none,
it builds and runs nothing. Else it builds every target they failed in at BASE with one
tools/bin-at call (the gate's own profile and arguments: no new artifact set; the checkout back
leaves the branch's changed crates to rebuild, which nothing in the gate does after it), then runs
each unit's replay on those binaries, side by side, one per hardware thread: a test's binary with
the property stage's environment and the unit's own variables, `--exact NAME`, in its crate's
directory as cargo runs it; a sim seed as `sim-sweep --seeds 1 --from SEED --only SCENARIO`. Each
replay's log (SEL.base.N.log, first lines `gate: base NAME SHA` and `gate: unit REPLAY`) is added
to RESULTS as a `gate.base EXIT LOG` line for the summary. When nothing can be compared (BASE is
HEAD, the build failed: uncommitted changes, a base that does not compile) one log says why
(`gate: base none: WHY`) and the units stay NEW.
"""
import concurrent.futures, json, os, re, shlex, subprocess, sys

sys.dont_write_bytecode = True
TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
import gate_failures as gf

HINT = re.compile(r"^-p (\S+) (?:--lib|--test (\S+))$")
ASSIGN = re.compile(r"^\w+=")
SIM = re.compile(r'^osis_sim::replay\("(\w+)", (\d+)\)$')


def units(sel, results, names):
    """[(NAME, REPLAY, TARGET)] of every NEW unit naming its seed: TARGET (KIND, CRATE, NAME) the
    binary that replays it (`test`/`lib` from cargo's hint, `bin` sim-sweep)."""
    out = []
    for stage, rc, log in results:
        if stage not in gf.COST_STAGES or rc == "0" or not os.path.exists(log):
            continue
        text = open(log, errors="replace").read()
        sim = stage == "gate.sim"
        fails = gf.sim_failures(text) if sim else gf.cargo_failures(text)
        hints = {} if sim else gf.failing_targets(text)
        for name, us, _ in fails:
            if name is None:
                continue
            if sim:
                target = ("bin", None, "sim-sweep")
            elif m := HINT.match(hints.get(name, "")):
                target = ("test", m.group(1), m.group(2)) if m.group(2) else ("lib", m.group(1), None)
            else:
                continue
            for u in gf.new_units(name, us, names):
                rep = gf.unit_replay(u)
                if rep and (name, rep) not in [(n, r) for n, r, _ in out]:
                    out.append((name, rep, target))
    return out


def stage_env(sel):
    """The property stage's variables (its `env` assignments but cargo's runner): the offsets a
    unit's own replay may not repeat (a seed xor'ed with OSIS_CRDT_SEED)."""
    for l in open(sel).read().split("\n"):
        if l.startswith("run gate.properties "):
            words = shlex.split(l)[2:]
            if words[:1] == ["env"]:
                env = {}
                for w in words[1:]:
                    if not ASSIGN.match(w):
                        break
                    k, v = w.split("=", 1)
                    if not k.endswith("_RUNNER"):
                        env[k] = v
                return env
    return {}


def command(name, rep, target, bins, dirs, env):
    """(argv, cwd, env) replaying one unit on the base binaries."""
    kind, crate, tname = target
    if kind == "bin":
        m = SIM.match(rep)
        return [os.path.join(bins, crate, "bin-sim-sweep"), "--seeds", "1", "--from", m.group(2), "--only", m.group(1)], os.getcwd(), dict(os.environ)
    own = {}
    for w in shlex.split(rep):
        if not ASSIGN.match(w):
            break
        k, v = w.split("=", 1)
        own[k] = v
    exe = os.path.join(bins, crate, "lib" if kind == "lib" else f"test-{tname}")
    return [exe, "--exact", name, "--include-ignored"], dirs[crate], {**os.environ, **env, **own, "CARGO_MANIFEST_DIR": dirs[crate]}


def main():
    if len(sys.argv) not in (4, 5):
        sys.exit(__doc__)
    sel, res, base = sys.argv[1:4]
    root = sys.argv[4] if len(sys.argv) == 5 else gf.ROOT
    results = [(l.split(" ", 2) + ["", ""])[:3] for l in open(res).read().split("\n") if l] if os.path.exists(res) else []
    names, _ = gf.known(root)
    todo = units(sel, results, names)
    if not todo:
        print("   no NEW seed: no base replay")
        return 0

    def none(why):
        log = f"{sel}.base.0.log"
        open(log, "w").write(f"gate: base none: {why}\n")
        open(res, "a").write(f"{gf.BASE_STAGE} 1 {log}\n")
        print(f"   base replay: {why}")
        return 0
    head = subprocess.run(["git", "rev-parse", "HEAD"], stdout=subprocess.PIPE, text=True).stdout.strip()
    sha = subprocess.run(["git", "rev-parse", "--verify", f"{base}^{{commit}}"], stdout=subprocess.PIPE, text=True).stdout.strip()
    if not sha or sha == head:
        return none(f"the base is HEAD: {len(todo)} NEW seeds have nothing to compare with")
    meta = json.loads(subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], stdout=subprocess.PIPE, text=True, check=True).stdout)
    dirs = {p["name"]: os.path.dirname(p["manifest_path"]) for p in meta["packages"]}
    # the sim seeds' binary: sim-sweep, in the package defining it
    sim = next((p["name"] for p in meta["packages"] for t in p["targets"] if t["name"] == "sim-sweep" and "bin" in t["kind"]), None)
    todo = [(n, r, (k, sim, t) if k == "bin" else (k, c, t)) for n, r, (k, c, t) in todo]
    targets, args = [], []
    for _, _, t in todo:
        if t in targets:
            continue
        targets.append(t)
        kind, crate, tname = t
        args += ["-p", crate, "--bin", tname] if kind == "bin" else ["--lib", crate] if kind == "lib" else ["-p", crate, "--test", tname]
    bins = f"{sel}.base/"
    print(f"   {len(todo)} NEW seeds in {len(targets)} targets: building them at the base {sha[:9]}", flush=True)
    b = subprocess.run([os.path.join(TOOLS, "bin-at"), sha, bins, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if b.returncode:
        tail = [l for l in b.stdout.split("\n") if l.strip()][-1:] or ["no output"]
        return none(f"tools/bin-at {sha[:9]} failed (exit {b.returncode}: {tail[0][:200]}): {len(todo)} NEW seeds not compared")
    env = stage_env(sel)

    def one(i, u):
        name, rep, target = u
        argv, cwd, e = command(name, rep, target, bins, dirs, env)
        log = f"{sel}.base.{i}.log"
        with open(log, "w") as f:
            f.write(f"gate: base {name} {sha}\ngate: unit {rep}\n")
            f.flush()
            rc = subprocess.run(argv, cwd=cwd, env=e, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT).returncode
        return f"{gf.BASE_STAGE} {rc} {log}\n"
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 1) as pool:
        lines = list(pool.map(one, range(1, len(todo) + 1), todo))
    open(res, "a").writelines(lines)
    print(f"   {len(todo)} NEW seeds replayed on the base {sha[:9]} (the summary says which fail there too)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
