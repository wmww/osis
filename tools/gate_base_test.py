#!/usr/bin/env python3
"""Tests tools/gate_base.py and the summary's ON-BASE marks end to end: a one-crate repo whose
properties and fake sim-sweep fail on some seeds at a base and on more at HEAD, the gate's stage
logs made by running them at HEAD (tools/targets.py, as the gate does), then the base replays and
tools/gate_failures.py's summary. Exit 1 on a mismatch."""
import os, shutil, subprocess, sys, tempfile

sys.dont_write_bytecode = True
TOOLS = os.path.dirname(os.path.abspath(__file__))

# seeds START..START+SEEDS, each failing when, xor'ed with PROBE_X (a gate offset its replay
# line leaves out, as osis-crdt's), it is in BAD
LIB = """pub fn seeds(name: &str, target: &str, bad: &[u64]) {
    let var = |k: &str, d: u64| std::env::var(k).ok().map(|v| v.parse().unwrap()).unwrap_or(d);
    let (start, n, x) = (var("PROBE_START", 0), var("PROBE_SEEDS", 1), var("PROBE_X", 0));
    let failed: Vec<String> = (start..start + n).filter(|s| bad.contains(&(s ^ x)))
        .map(|s| format!("seed {s} (replay: PROBE_START={s} PROBE_SEEDS=1 cargo test -p probe {target} -- --ignored --exact {name}): bad")).collect();
    assert!(failed.is_empty(), "{name}: {} seeds failed:\\n{}", failed.len(), failed.join("\\n"));
}
#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn lib_plain() { super::seeds("tests::lib_plain", "--lib", &[6]) }
}
"""
IT = """#[test]
#[ignore]
fn some_plain() { probe::seeds("some_plain", "--test it", &[BAD]) }
#[test]
#[ignore]
fn all_plain() { probe::seeds("all_plain", "--test it", &[3]) }
"""
SIM = """fn main() {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str| a.iter().position(|x| x == k).map(|i| a[i + 1].clone());
    let (n, from): (u64, u64) = (get("--seeds").unwrap().parse().unwrap(), get("--from").unwrap().parse().unwrap());
    let bad: &[(&str, u64)] = &[BAD];
    let mut tally = vec![];
    let mut failing = vec![];
    for sc in ["drift", "fresh"] {
        if get("--only").is_some_and(|o| o != sc) { continue; }
        let f: Vec<u64> = (from..from + n).filter(|s| bad.contains(&(sc, *s))).collect();
        for s in &f {
            println!("FAIL sim failure in scenario `{sc}`, seed {s}, step 1: agreement lost");
            println!("replay: osis_sim::replay(\\"{sc}\\", {s})");
            failing.push((sc, *s));
        }
        tally.push(format!("{sc} {n} {}", f.len()));
    }
    println!("scenario seeds failed\\n{}", tally.join("\\n"));
    for (sc, s) in &failing { println!("failing: osis_sim::replay(\\"{sc}\\", {s})  (sim-sweep --seeds 1 --from {s} --only {sc})"); }
    println!("elapsed 0 s");
    std::process::exit(if failing.is_empty() { 0 } else { 1 });
}
"""

fails = 0


def check(name, got, want):
    global fails
    if got != want:
        print(f"FAIL {name}:\n got  {got!r}\n want {want!r}")
        fails = 1


def run(*cmd, cwd, env=None, ok=True):
    r = subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if ok and r.returncode:
        sys.exit(f"{' '.join(cmd)}: exit {r.returncode}\n{r.stdout}")
    return r


def write(repo, it_bad, sim_bad):
    os.makedirs(f"{repo}/src/bin", exist_ok=True)
    os.makedirs(f"{repo}/tests", exist_ok=True)
    open(f"{repo}/src/lib.rs", "w").write(LIB)
    open(f"{repo}/tests/it.rs", "w").write(IT.replace("BAD", it_bad))
    open(f"{repo}/src/bin/sim-sweep.rs", "w").write(SIM.replace("BAD", sim_bad))


d = tempfile.mkdtemp()
try:
    repo, wt = f"{d}/repo", f"{d}/wt"
    os.makedirs(repo)
    git = lambda *a, cwd=repo: run("git", *a, cwd=cwd).stdout.strip()
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    open(f"{repo}/Cargo.toml", "w").write('[package]\nname = "probe"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n')
    open(f"{repo}/.gitignore", "w").write("target\nCargo.lock\n")
    # the base: some_plain fails at 3 and 5, sim drift at seed 9
    write(repo, "3, 5", '("drift", 9)')
    git("add", "-A")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    # HEAD: some_plain also at 7, sim fresh at seed 8
    write(repo, "3, 5, 7", '("drift", 9), ("fresh", 8)')
    git("commit", "-qam", "head")
    git("worktree", "add", "-q", "-b", "task", wt, "HEAD")

    # the gate's stage logs at HEAD: seeds 0..8, offset 1 xor'ed in (some_plain fails at 2, 4 and 6,
    # all_plain at 2, the lib's at 7), sim seeds 7..10
    sel, res = f"{d}/sel", f"{d}/sel.res"
    env = {"PROBE_X": "1", "PROBE_START": "0", "PROBE_SEEDS": "8"}
    props = ["cargo", "test", "--no-fail-fast", "-p", "probe", "--tests", "--", "--ignored"]
    open(sel, "w").write("run gate.properties env PROBE_X=1 PROBE_START=0 CARGO_TARGET_X_RUNNER=/nowhere python3 tools/targets.py " + " ".join(props) + "\n"
                         "run gate.sim cargo run --bin sim-sweep -- --seeds 4 --from 7\n")
    p = run("python3", f"{TOOLS}/targets.py", *props, cwd=wt, env=env, ok=False)
    open(f"{d}/props.log", "w").write(p.stdout)
    s = run("cargo", "run", "-q", "--bin", "sim-sweep", "--", "--seeds", "4", "--from", "7", cwd=wt, ok=False)
    open(f"{d}/sim.log", "w").write(s.stdout)
    stages = f"gate.properties {p.returncode} {d}/props.log\ngate.sim {s.returncode} {d}/sim.log\n"
    open(res, "w").write(stages)

    known = f"{d}/known"
    os.makedirs(f"{known}/tools")
    os.makedirs(f"{known}/issues")
    open(f"{known}/issues/k.md", "w").write("# k\n")
    open(f"{known}/tools/test_cost.txt", "w").write("")

    def listed(text):
        open(f"{known}/tools/known_failures.txt", "w").write(text)

    def summary():
        r = run("python3", f"{TOOLS}/gate_failures.py", sel, res, known, cwd=wt, ok=False)
        return r.returncode, [l.strip() for l in r.stdout.split("\n") if l.startswith("   ")]

    # every failure KNOWN: nothing to replay, nothing built
    listed("some_plain - issues/k.md bad\nall_plain - issues/k.md bad\ntests::lib_plain - issues/k.md bad\nsim-sweep:drift - issues/k.md lost\nsim-sweep:fresh - issues/k.md lost\n")
    r = run("python3", f"{TOOLS}/gate_base.py", sel, res, base, known, cwd=wt)
    check("all KNOWN: no replay", (r.stdout.strip(), open(res).read()), ("no NEW seed: no base replay", stages))
    check("all KNOWN: nothing built", os.path.exists(f"{sel}.base"), False)

    # the base is HEAD: nothing to compare, each stays NEW
    listed("")
    r = run("python3", f"{TOOLS}/gate_base.py", sel, res, git("rev-parse", "HEAD", cwd=wt), known, cwd=wt)
    code, lines = summary()
    check("base is HEAD: each NEW", (code, sorted(l.split(": ")[0] for l in lines if l.startswith(("NEW", "ON-BASE"))), lines[-1]),
          (1, ["NEW   gate.properties  all_plain", "NEW   gate.properties  some_plain", "NEW   gate.properties  tests::lib_plain", "NEW   gate.sim  sim-sweep:drift", "NEW   gate.sim  sim-sweep:fresh"],
           "base replay: the base is HEAD: 7 NEW seeds have nothing to compare with"))
    open(res, "w").write(stages)
    for f in os.listdir(d):
        if f.startswith("sel.base"):
            os.remove(f"{d}/{f}")

    # uncommitted changes: tools/bin-at refuses, each stays NEW
    open(f"{wt}/Cargo.toml", "a").write("\n")
    run("python3", f"{TOOLS}/gate_base.py", sel, res, base, known, cwd=wt)
    code, lines = summary()
    check("dirty tree: NEW, why said", (code, any(l.startswith("ON-BASE") for l in lines), lines[-1].split(" (exit")[0], "uncommitted" in lines[-1]),
          (1, False, f"base replay: tools/bin-at {base[:9]} failed", True))
    git("checkout", "Cargo.toml", cwd=wt)
    open(res, "w").write(stages)

    # nothing listed: every seed replayed on the base
    r = run("python3", f"{TOOLS}/gate_base.py", sel, res, base, known, cwd=wt)
    check("replayed: the branch back", git("symbolic-ref", "--short", "HEAD", cwd=wt), "task")
    check("replayed: one line per seed", sum(1 for l in open(res) if l.startswith("gate.base ")), 7)
    code, lines = summary()
    got = [l for l in lines if l.startswith(("NEW", "ON-BASE", "seed", "base replay"))]
    sha = base[:9]
    check("on base", (code, sorted(got)), (1, sorted([
        f"ON-BASE gate.properties  all_plain: its failing seeds fail on the base {sha} too: failing on main, so add its known line (tools/known_failures.txt; notes/coordination.md, Known failures)",
        "seed 2 (replay: PROBE_START=2 PROBE_SEEDS=1 cargo test -p probe --test it -- --ignored --exact all_plain) (fails on the base too)",
        f"NEW   gate.properties  some_plain: 1 of 3 new failing seeds pass on the base {sha} (each failing there too marked)",
        "seed 2 (replay: PROBE_START=2 PROBE_SEEDS=1 cargo test -p probe --test it -- --ignored --exact some_plain) (fails on the base too)",
        "seed 4 (replay: PROBE_START=4 PROBE_SEEDS=1 cargo test -p probe --test it -- --ignored --exact some_plain) (fails on the base too)",
        "seed 6 (replay: PROBE_START=6 PROBE_SEEDS=1 cargo test -p probe --test it -- --ignored --exact some_plain)",
        f"ON-BASE gate.properties  tests::lib_plain: its failing seeds fail on the base {sha} too: failing on main, so add its known line (tools/known_failures.txt; notes/coordination.md, Known failures)",
        "seed 7 (replay: PROBE_START=7 PROBE_SEEDS=1 cargo test -p probe --lib -- --ignored --exact tests::lib_plain) (fails on the base too)",
        f"ON-BASE gate.sim  sim-sweep:drift: its failing seeds fail on the base {sha} too: failing on main, so add its known line (tools/known_failures.txt; notes/coordination.md, Known failures)",
        'seed 9 (replay: osis_sim::replay("drift", 9)) (fails on the base too)',
        "NEW   gate.sim  sim-sweep:fresh",
        'seed 8 (replay: osis_sim::replay("fresh", 8))',
    ])))
    # some_plain's new seed listed (KNOWN) and fresh too: only on-base ones left, mergeable
    listed("some_plain - issues/k.md seed 6 \nsim-sweep:fresh - issues/k.md lost\n")
    code, lines = summary()
    check("only KNOWN and ON-BASE: exit 3", (code, sorted(l.split(": ")[0] for l in lines if l.startswith(("NEW", "ON-BASE")))),
          (3, ["ON-BASE gate.properties  all_plain", "ON-BASE gate.properties  some_plain", "ON-BASE gate.properties  tests::lib_plain", "ON-BASE gate.sim  sim-sweep:drift"]))
    check("a listed test's other seeds on the base", any("some_plain: its seeds no pattern matches fail on the base" in l for l in lines), True)
    # a listed test with a seed no pattern matches, passing on the base: NEW-TEXT stays
    listed("some_plain - issues/k.md seed [24] \n")
    code, lines = summary()
    check("NEW-TEXT passing on the base", (code, [l.split(": ")[0] for l in lines if l.startswith("NEW") and "some_plain" in l]), (1, ["NEW-TEXT gate.properties  some_plain"]))
finally:
    shutil.rmtree(d, ignore_errors=True)
print("gate base: " + ("FAILED" if fails else "ok"))
sys.exit(fails)
