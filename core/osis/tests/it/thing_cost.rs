//! What one thing costs through the API (notes/thing-cost.md; spec/requirements.md Cost,
//! spec/sync-set.md §2 Cost), made as the app makes them: a
//! dependent thing minted with the app's home as admin (held by it, kept a day), and an
//! independent thing minted with the account as admin and held by home (as `osis-chat`'s `create` makes a
//! chat). The maker and the account's second node: commits, store rows by family, the sync
//! store's bytes, bytes the second node downloads, KEM and signature operations.

use crate::common::*;
use osis::internals::{Internals as _, MemStoreMeasures as _, costs};
use osis::{MemStore, Osis, Tid};
use std::collections::BTreeMap;

type Census = BTreeMap<String, (usize, usize)>;

fn grown(a: &Census, b: &Census) -> Vec<(String, i64, i64)> {
    let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|k| {
            let (x, y) = (a.get(k).copied().unwrap_or_default(), b.get(k).copied().unwrap_or_default());
            (x != y).then(|| (k.clone(), y.0 as i64 - x.0 as i64, y.1 as i64 - x.1 as i64))
        })
        .collect()
}

fn ops() -> BTreeMap<&'static str, u64> {
    costs::take().into_iter().filter(|(k, _, _)| k.starts_with("kem") || k.starts_with("sign") || k.starts_with("verify")).map(|(k, _, n)| (k, n)).collect()
}

struct Node {
    db: Osis,
    store: MemStore,
}

impl Node {
    fn census(&self) -> Census {
        self.db.engine(|e| e.census().unwrap())
    }
    /// Both stores' bytes, physical (encrypted pages and blobs).
    fn sync_bytes(&self) -> i64 {
        let all = self.store.held_split();
        (all.0 + all.1) as i64
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)] // read by its Debug print
struct Cost {
    commits: usize,
    maker_rows: i64,
    maker_physical: i64,
    download: usize,
    reader_rows: i64,
    reader_physical: i64,
    maker_ops: BTreeMap<&'static str, u64>,
    reader_ops: BTreeMap<&'static str, u64>,
}

fn make(a: &Node, b: &Node, home: Tid, independent: bool, label: &str, show: bool) -> Cost {
    let (c0, r0, p0, q0) = (a.census(), b.census(), a.sync_bytes(), b.sync_bytes());
    let before: std::collections::BTreeSet<_> = a.db.engine(|e| e.commit_ids()).into_iter().collect();
    costs::take();
    let mut w = a.db.write();
    let t = if independent { w.create(a.db.me(), None).unwrap() } else { w.create(home, None).unwrap() };
    keep_all(&mut w, t);
    w.hold(home, t).unwrap();
    w.commit().unwrap();
    a.db.settle();
    let maker_ops = ops();
    let mut new: Vec<_> = a.db.engine(|e| e.commit_ids()).into_iter().filter(|c| !before.contains(c)).collect();
    new.sort_by_key(|c| a.db.engine(|e| e.header(c).unwrap().ts));
    let pks: Vec<_> = a.db.engine(|e| new.iter().map(|c| e.package(c).unwrap().unwrap()).collect());
    let mut cost = Cost { commits: new.len(), maker_ops, ..Cost::default() };
    if show {
        eprintln!("== {label}: {} commits", new.len());
    }
    for pk in &pks {
        let size = pk.bytes.len() + pk.blobs.iter().map(|b| b.1.len()).sum::<usize>() + pk.lists.iter().map(Vec::len).sum::<usize>();
        cost.download += size;
        if show {
            let h = a.db.engine(|e| e.header(&pk.id).unwrap().clone());
            let on: Vec<String> = h.aspects.iter().map(|x| format!("{}.{}", if x.tid == t { "t" } else if x.tid == home { "home" } else { "other" }, x.ak.as_str())).collect();
            eprintln!("  commit {:?}: {size} B (header {} B): {on:?}", h.kind, h.encode().len());
        }
    }
    costs::take();
    for pk in &pks {
        b.db.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    b.db.engine(|e| e.settle_needs().unwrap());
    b.db.settle();
    cost.reader_ops = ops();
    let (mg, rg) = (grown(&c0, &a.census()), grown(&r0, &b.census()));
    cost.maker_rows = mg.iter().map(|x| x.2).sum();
    cost.reader_rows = rg.iter().map(|x| x.2).sum();
    cost.maker_physical = a.sync_bytes() - p0;
    cost.reader_physical = b.sync_bytes() - q0;
    if show {
        eprintln!("  maker rows by family (rows, bytes): {mg:?}");
        eprintln!("  reader rows by family: {rg:?}");
        eprintln!("  {cost:?}");
    }
    cost
}

// The breakdown table of notes/thing-cost.md, through the API; `THING_COST=1` prints it.
#[test]
#[ignore = "sync rewrite: copies per (commit, thing)"]
fn what_a_thing_costs_as_the_app_makes_it() {
    let c = clock();
    let (sa, sb) = (MemStore::new(), MemStore::new());
    let a = osis::internals::create(cfg(1, sa.clone(), &c)).unwrap();
    let j = osis::internals::pair(cfg(2, sb.clone(), &c), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    let (a, b) = (Node { db: a, store: sa }, Node { db: b, store: sb });
    let root = a.db.account_root();
    let mut w = a.db.write();
    let home = w.create(root, None).unwrap();
    w.hold(root, home).unwrap();
    w.commit().unwrap();
    deliver(&a.db, &b.db);
    let show = std::env::var_os("THING_COST").is_some();
    make(&a, &b, home, false, "dependent warm-up", false);
    make(&a, &b, home, true, "independent warm-up", false);
    // compactions of home's `holds.0` come every few makes:
    // averaged over `n`
    let n = 10;
    let per = |independent: bool, label: &str| {
        let all: Vec<Cost> = (0..n).map(|i| make(&a, &b, home, independent, label, show && i == 0)).collect();
        let avg = |f: &dyn Fn(&Cost) -> i64| all.iter().map(f).sum::<i64>() / n as i64;
        let ops = |f: &dyn Fn(&Cost) -> &BTreeMap<&'static str, u64>| {
            let mut m = BTreeMap::<&'static str, u64>::new();
            for c in &all {
                for (k, v) in f(c) {
                    *m.entry(k).or_default() += v;
                }
            }
            m.into_iter().map(|(k, v)| (k, v as f64 / n as f64)).collect::<Vec<_>>()
        };
        eprintln!(
            "{label}, per thing over {n}: commits {:.1}, maker rows {} B ({} B physical), download {} B, reader rows {} B ({} B physical); maker ops {:?}; reader ops {:?}",
            avg(&|c| c.commits as i64 * 10) as f64 / 10.0,
            avg(&|c| c.maker_rows),
            avg(&|c| c.maker_physical),
            avg(&|c| c.download as i64),
            avg(&|c| c.reader_rows),
            avg(&|c| c.reader_physical),
            ops(&|c| &c.maker_ops),
            ops(&|c| &c.reader_ops),
        );
        all
    };
    let dependent = per(false, "dependent (minted with home)");
    let independent = per(true, "independent (minted with the account, held by home)");
    let sum = |all: &[Cost], f: &dyn Fn(&Cost) -> i64| all.iter().map(f).sum::<i64>();
    assert!(dependent.iter().all(|c| c.commits >= 1) && independent.iter().all(|c| c.commits >= 2), "an independent thing held outside the root's unit: its rotation carrying its record, the strong holding it");
    assert!(sum(&dependent, &|c| c.maker_rows) < 2_000 * n as i64 && sum(&dependent, &|c| c.download as i64) < 1_300 * n as i64);
    assert!(sum(&independent, &|c| c.maker_rows) < 17_000 * n as i64 && sum(&independent, &|c| c.download as i64) < 11_200 * n as i64);
}
