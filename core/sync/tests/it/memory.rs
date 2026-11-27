//! What a node keeps in memory per commit (issues/memory-per-commit.md), by hand under
//! `tools/memprof`: run at n and at 10n, then `tools/memprof --report A B --per 9n`.
use crate::harness::World;
use crate::harness::history::value_ak;
use osis_base::{Tid, Value};
use osis_engine::Mutation;

/// A two-node world (node 1 its account's second node) and a dependent of A made by node 0.
fn world() -> (World, Tid) {
    let mut w = World::new(0);
    w.add_node();
    w.pair(0);
    w.run();
    let a = w.node(0).account.unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a);
        m.set(t, &value_ak(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    w.run();
    (w, t)
}

// spec: none (measurement: spec/requirements.md Scale; issues/memory-per-commit.md).
/// By hand (`MEM_N` commits, default 50): node 0 writes a small value on a dependent of A
/// `MEM_N` times, each synced to node 1 and a second apart; the world is left live at exit, so
/// `tools/memprof` records what both nodes keep.
#[test]
#[ignore = "by hand: tools/memprof probe"]
fn memory_per_commit_probe() {
    let n: u64 = std::env::var("MEM_N").ok().and_then(|v| v.parse().ok()).unwrap_or(50);
    let (mut w, t) = world();
    for i in 0..n {
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(format!("v{i}"))).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        w.advance(1_000);
    }
    let disk: u64 = (0..2).map(|i| w.disk_use(i).iter().map(|x| x.1 + x.3).sum::<u64>()).sum();
    eprintln!("{n} commits: disks (both nodes, rows and blobs) {disk} B");
    std::mem::forget(w);
}

// spec: none (measurement: issues/memory-per-commit.md).
/// By hand: where a held commit's followed keys' reads come from. Node 0 writes `MEM_N` small
/// values (default 3) as `memory_per_commit_probe` does; prints, per node, each followed key
/// of the engine's per-commit rows and of sync read with its held reads by container
/// (`memo::HeldReads`), then each (follower, container)'s reads in all.
#[test]
#[ignore = "by hand: prints what following each key holds"]
fn held_reads_by_container_probe() {
    let n: u64 = std::env::var("MEM_N").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let (mut w, t) = world();
    write_values(&mut w, t, 0, n);
    for i in 0..2 {
        let held: Vec<_> = w.engine(i).sync_held_reads().into_iter().chain(w.node(i).node.read().held_reads()).collect();
        let mut total = std::collections::BTreeMap::<(&str, &str), usize>::new();
        for h in &held {
            let reads: Vec<String> = h.reads.iter().map(|(c, k)| format!("{} {k}", unpathed(c))).collect();
            eprintln!("n{i} {} {}: {}", h.follower, h.key, reads.join(", "));
            for (c, k) in &h.reads {
                *total.entry((h.follower, c)).or_default() += k;
            }
        }
        eprintln!("n{i} reads by follower and container, {n} commits:");
        for ((f, c), k) in total {
            eprintln!("  {f} <- {}: {k}", unpathed(c));
        }
    }
}

/// `s` with each path's modules left out (`osis_base::memo::Stamped<osis_base::ids::Tid, ..>` as
/// `Stamped<Tid, ..>`).
fn unpathed(s: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    let mut rest = s.chars().peekable();
    while let Some(c) = rest.next() {
        if c == ':' && rest.peek() == Some(&':') {
            rest.next();
            word.clear();
        } else if c.is_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            out.push_str(&std::mem::take(&mut word));
            out.push(c);
        }
    }
    out + &word
}

/// The reads both nodes' followers of held commits hold (engine rows and sync read).
fn reads_held(w: &mut World) -> usize {
    (0..2).map(|i| w.engine(i).sync_reads_held() + w.node(i).node.read().reads_held()).sum()
}

/// Node 0 writes `n` small values on `t`, each synced to node 1 a second apart.
fn write_values(w: &mut World, t: Tid, from: u64, n: u64) {
    for i in from..from + n {
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(format!("v{i}"))).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        w.advance(1_000);
    }
}

// spec: none (measurement: spec/requirements.md Scale; issues/memory-per-commit.md).
/// What a held commit's followers keep is its own facts: per commit, a node's rows and sync
/// read hold the reads of that commit's bodies, facts and judgements, each reading one row per
/// thing for what is the thing's (how it syncs, its secret actor, whether its keys open it, the
/// read floor), never that derivation's reads copied in. Counted at 10, 40 and 100 commits: the
/// same reads per commit in both stretches, under what a copy of the per-thing derivations makes.
#[test]
fn a_held_commit_keeps_the_reads_of_its_own_facts() {
    let (mut w, t) = world();
    write_values(&mut w, t, 0, 10);
    let a = reads_held(&mut w);
    write_values(&mut w, t, 10, 30);
    let b = reads_held(&mut w);
    write_values(&mut w, t, 40, 60);
    let c = reads_held(&mut w);
    let (first, second) = ((b - a) as f64 / 30.0 / 2.0, (c - b) as f64 / 60.0 / 2.0);
    eprintln!("reads held per commit per node: {first:.1}, then {second:.1}");
    assert!((first - second).abs() <= 2.0, "flat per commit: {first:.1} then {second:.1}");
    // a commit's own facts are about 46 reads a node; with each per-thing derivation's reads
    // copied into its rows, 120
    assert!(second <= 70.0, "{second:.1} reads per commit per node: a per-thing derivation copied into each commit's rows");
}
