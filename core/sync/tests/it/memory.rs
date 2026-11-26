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
