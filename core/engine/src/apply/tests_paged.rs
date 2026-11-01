//! Applying a delta a piece at a time leaves what applying it whole does (issues/
//! durable-decode-bound.md step 3; spec/crdt.md §8): the same random history runs in two worlds
//! of four nodes, one applying every part decoded whole through the pre-streaming join
//! (`Core::whole_apply`, `oracle::joins`), and after every step each node's ingest outcomes,
//! states, deaths and indexes must agree. Histories: paged maps and sets filled, edited and
//! replaced (root resets), turned into registers (encoding changes), a map with a paged part
//! and unpaged entries in one aspect, multi-aspect commits, compaction snapshots, writes by a
//! node without the role (invalid deltas, un-merging), bounded retention (deaths), and partial,
//! reordered deliveries, some first without their pages (pending, then applied).

use crate::local_peer::{LocalPeer, Package};
use crate::Mutation;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::core_types as ct;
use osis_schema::{Bound, Codec, PurgeBy, Retention};
use std::collections::BTreeMap;

const T0: WallMs = WallMs(1_700_000_000_000);
const NODES: usize = 4;
/// Peer 2 is removed halfway with a frontier before all its writes: its deltas turn or arrive
/// invalid (un-merging).
const ROGUE: usize = 2;

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

fn aks() -> [Ak; 4] {
    ["t:big.0", "t:mix.0", "t:set.0", "t:reg.0"].map(|a| Ak::new(a).unwrap())
}

/// One world: the nodes, the thing, and what each delivery returned.
struct World {
    lp: LocalPeer,
    t: Tid,
    log: Vec<String>,
}

fn world(seed: u64, whole: bool) -> World {
    let mut lp = LocalPeer::new(NODES, seed, T0).unwrap();
    for p in &mut lp.peers {
        p.engine.core.whole_apply = whole;
    }
    let a = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap();
    for w in [1, 2, 3] {
        let w = lp.peers[w].engine.tid();
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(w))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None }.to_value()) }).unwrap();
        lp.peers[0].commit(m).unwrap();
    }
    lp.sync_all().unwrap();
    World { lp, t, log: Vec::new() }
}

/// A string about 24 bytes long, so a few thousand entries page (`PAGE_TARGET`).
fn s(i: u64, g: u64) -> Value {
    Value::Str(format!("value-{i:08}-g-{g:08}"))
}

fn big_map(r: &mut Rng, g: u64) -> Value {
    let n = 1500 + r.below(2500);
    let off = r.below(1000);
    Value::Map((0..n).map(|i| (Value::Int((i + off) as i64), s(i, g))).collect())
}

/// The value of aspect `asp` after a fill.
fn fill_value(asp: usize, r: &mut Rng, g: u64) -> Value {
    match asp {
        0 => big_map(r, g),
        1 => Value::Map(BTreeMap::from([(Value::Str("big".into()), big_map(r, g)), (Value::Str("x".into()), Value::Int(g as i64))])),
        2 => Value::Set((0..1500 + r.below(2500)).map(|i| s(i + r.below(3), g)).collect()),
        _ => Value::Int(g as i64),
    }
}

/// A few keys changed in the current value.
fn edited(v: Option<Value>, r: &mut Rng, g: u64) -> Value {
    match v {
        Some(Value::Map(mut m)) => {
            if let Some(Value::Map(inner)) = m.get_mut(&Value::Str("big".into())) {
                for _ in 0..3 {
                    inner.insert(Value::Int(r.below(4000) as i64), s(r.below(9), g));
                }
            } else {
                for _ in 0..3 {
                    let k = Value::Int(r.below(4000) as i64);
                    if r.below(2) == 0 {
                        m.remove(&k);
                    } else {
                        m.insert(k, s(r.below(9), g));
                    }
                }
            }
            Value::Map(m)
        }
        Some(Value::Set(mut x)) => {
            for _ in 0..3 {
                x.insert(s(r.below(5000), g));
            }
            if let Some(f) = x.iter().next().cloned() {
                x.remove(&f);
            }
            Value::Set(x)
        }
        _ => Value::Int(g as i64),
    }
}

impl World {
    /// Runs one step of the script; every world draws the same numbers.
    fn step(&mut self, r: &mut Rng, g: u64) {
        let aks = aks();
        let by = r.below(NODES as u64) as usize;
        let what = r.below(10);
        let asp = r.below(3) as usize;
        let t = self.t;
        let mut m = Mutation::new();
        match what {
            // a fill, a replace (a root reset), or a multi-aspect commit
            0..=2 => {
                let v = fill_value(asp, r, g);
                if what == 1 {
                    m.replace(t, &aks[asp], &v).unwrap();
                } else {
                    m.set(t, &aks[asp], &v).unwrap();
                }
                if what == 2 {
                    m.set(t, &aks[3], &Value::Int(g as i64)).unwrap();
                }
                // a relative bound: deaths are tracked; 0 drops dead bodies at once
                match r.below(3) {
                    0 => {
                        m.retention(t, &aks[asp], Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(3_600_000) } }).unwrap();
                    }
                    1 => {
                        m.retention(t, &aks[asp], Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } }).unwrap();
                    }
                    _ => {}
                }
            }
            3 | 4 => {
                let cur = self.lp.peers[by].engine.get(&t, &aks[asp]).unwrap();
                m.set(t, &aks[asp], &edited(cur, r, g)).unwrap();
            }
            // another encoding over a paged collection
            5 => {
                m.set(t, &aks[asp], &Value::Int(g as i64)).unwrap();
            }
            6 => {
                let c = self.lp.peers[by].engine.snapshot(&t, &aks[asp]);
                self.log.push(format!("snapshot by {by}: {c:?}"));
                return;
            }
            _ => {
                self.send(r);
                return;
            }
        }
        let c = self.lp.peers[by].commit(m);
        self.log.push(format!("commit by {by}: {c:?}"));
    }

    /// Delivers the commits one node holds that another lacks, in a random order, some first
    /// without their pages.
    fn send(&mut self, r: &mut Rng) {
        let from = r.below(NODES as u64) as usize;
        let to = (from + 1 + r.below(NODES as u64 - 1) as usize) % NODES;
        let mut pks: Vec<Package> = self.lp.packages(from).unwrap();
        let held: Vec<CommitId> = self.lp.peers[to].engine.commit_ids();
        pks.retain(|p| !held.contains(&p.id));
        for i in (1..pks.len()).rev() {
            pks.swap(i, r.below(i as u64 + 1) as usize);
        }
        for pk in pks {
            if !pk.blobs.is_empty() && r.below(3) == 0 {
                let bare = Package { blobs: Vec::new(), ..pk.clone() };
                let out = self.lp.deliver(to, &bare);
                self.log.push(format!("{from}->{to} bare {:?}: {out:?}", pk.id));
            }
            let out = self.lp.deliver(to, &pk);
            self.log.push(format!("{from}->{to} {:?}: {out:?}", pk.id));
        }
    }

    /// Node 0 removes the rogue with a frontier before all its writes.
    fn demote(&mut self) {
        let (t, rogue) = (self.t, self.lp.peers[ROGUE].engine.tid());
        let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(rogue, std::collections::BTreeSet::from([t]))]), content: BTreeMap::from([(rogue, std::collections::BTreeSet::from([t]))]) };
        let f = self.lp.peers[0].engine.frontier(&scope, T0).unwrap();
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(rogue)) }).unwrap();
        m.frontier(f.to_value());
        let c = self.lp.peers[0].commit(m);
        self.log.push(format!("demote: {c:?}"));
    }

    fn sync(&mut self) {
        for from in 0..NODES {
            for to in 0..NODES {
                if from != to {
                    for pk in self.lp.packages(from).unwrap() {
                        let out = self.lp.deliver(to, &pk);
                        self.log.push(format!("{from}->{to} {:?}: {out:?}", pk.id));
                    }
                }
            }
        }
    }

    /// What must agree: per node, every aspect's state and read, every held commit's deaths
    /// there, what pends, and the indexes.
    fn seen(&mut self) -> Vec<String> {
        let t = self.t;
        let mut out = Vec::new();
        for (i, p) in self.lp.peers.iter_mut().enumerate() {
            for a in aks() {
                out.push(format!("{i} {a} state {:?}", p.engine.state(&t, &a).unwrap()));
                for c in p.engine.commit_ids() {
                    out.push(format!("{i} {a} {c:?} deaths {:?}", p.engine.deaths(&c, &t, &a).map_err(|e| e.to_string())));
                }
            }
            out.push(format!("{i} pending {:?}", p.engine.pending()));
            out.push(format!("{i} index {:?}", p.engine.index_digest()));
        }
        out
    }
}

/// Runs `steps` steps of seed `seed` in both worlds, comparing after each.
fn differential(seed: u64, steps: u64) -> BTreeMap<&'static str, u64> {
    crate::costs::take();
    let mut new = world(seed, false);
    let mut old = world(seed, true);
    let (mut rn, mut ro) = (Rng(seed | 1), Rng(seed | 1));
    for g in 0..=steps {
        if g == steps {
            new.sync();
            old.sync();
        } else if g == steps / 2 {
            new.demote();
            old.demote();
        } else {
            new.step(&mut rn, g);
            old.step(&mut ro, g);
        }
        assert_eq!(new.log, old.log, "seed {seed} step {g}: outcomes differ");
        let (a, b) = (new.seen(), old.seen());
        if let Some((x, y)) = a.iter().zip(&b).find(|(x, y)| x != y) {
            panic!("seed {seed} step {g}: page-by-page apply differs from whole\n new {}\n old {}\nlog {:#?}", &x[..x.len().min(3000)], &y[..y.len().min(3000)], new.log);
        }
        assert_eq!(a.len(), b.len());
    }
    let mut c: BTreeMap<&'static str, u64> = crate::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
    c.insert("waited for pages", new.log.iter().filter(|l| l.contains("WaitBlobs")).count() as u64);
    c
}

#[test]
fn paged_apply_matches_whole_spec_crdt_8() {
    let c = differential(7, 14);
    // the history reached what it is for: paged deltas streamed, a reset joined by pages, a
    // commit waiting for its pages
    assert!(["apply: piece", "reset: by pages", "waited for pages"].iter().all(|k| c.get(k).is_some_and(|n| *n > 0)), "{c:?}");
}

#[test]
#[ignore = "tier 2"]
fn paged_apply_matches_whole_large_spec_crdt_8() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_PAGED_APPLY_START", "OSIS_PAGED_APPLY_SEEDS", 1..25);
    seeds.announce("paged apply");
    // a thread per core, each taking the next seed
    let next = std::sync::atomic::AtomicU64::new(seeds.range.start);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| {
                loop {
                    let seed = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if seed >= seeds.range.end {
                        break;
                    }
                    differential(seed, 30);
                }
            });
        }
    });
}

/// Runs `script` in a world applying page by page and in one applying whole, then compares
/// them; returns the cost counts of the page-by-page world's last step.
fn both(seed: u64, script: impl Fn(&mut World) -> Vec<Package>) -> BTreeMap<&'static str, u64> {
    let mut seen = Vec::new();
    let mut counts = BTreeMap::new();
    for whole in [false, true] {
        let mut w = world(seed, whole);
        let pks = script(&mut w);
        crate::costs::take();
        for pk in &pks {
            let out = w.lp.deliver(3, pk);
            w.log.push(format!("{:?}: {out:?}", pk.id));
        }
        if !whole {
            counts = crate::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
        }
        let mut v = w.seen();
        v.extend(w.log.clone());
        seen.push(v);
    }
    if let Some((x, y)) = seen[0].iter().zip(&seen[1]).find(|(x, y)| x != y) {
        panic!("page-by-page apply differs from whole\n new {}\n old {}", &x[..x.len().min(3000)], &y[..y.len().min(3000)]);
    }
    counts
}

/// The packages of `ids` from node `from`.
fn packages(w: &mut World, from: usize, ids: &[CommitId]) -> Vec<Package> {
    ids.iter().map(|id| w.lp.peers[from].engine.package(id).unwrap().unwrap()).collect()
}

fn bounded() -> Retention {
    Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(3_600_000) } }
}

/// Node 3 holds a paged map (its own fill, so its deltas carry bounded retention); node 0
/// replaces the map (a root reset) and snapshots it; node 3 gets the snapshot alone: its
/// skeleton's reset prunes the paged state a page at a time, the old writes dying there.
#[test]
fn snapshot_root_reset_prunes_pages_spec_crdt_8() {
    let c = both(5, |w| {
        let (t, a) = (w.t, aks()[0].clone());
        let mut r = Rng(21);
        let mut m = Mutation::new();
        m.set(t, &a, &big_map(&mut r, 0)).unwrap().retention(t, &a, bounded()).unwrap();
        let fill = w.lp.peers[0].commit(m).unwrap().unwrap();
        let pk = packages(w, 0, &[fill]);
        w.lp.deliver(3, &pk[0]).unwrap();
        let mut m = Mutation::new();
        m.replace(t, &a, &big_map(&mut r, 1)).unwrap().retention(t, &a, bounded()).unwrap();
        w.lp.peers[0].commit(m).unwrap().unwrap();
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        packages(w, 0, &[snap])
    });
    assert!(c.get("reset: by pages").is_some_and(|n| *n > 0) && c.get("apply: piece").is_some_and(|n| *n > 2), "{c:?}");
}

/// One commit with a paged map and a small entry in one aspect and a register in another,
/// into a node holding that map paged: the second wire page joins state pages the first
/// loaded, wrote and dropped.
#[test]
fn paged_and_unpaged_parts_spec_crdt_8() {
    let c = both(6, |w| {
        let (t, aks) = (w.t, aks());
        let mut r = Rng(31);
        let mut m = Mutation::new();
        m.set(t, &aks[1], &fill_value(1, &mut r, 0)).unwrap();
        let first = w.lp.peers[1].commit(m).unwrap().unwrap();
        let pk = packages(w, 1, &[first]);
        w.lp.deliver(3, &pk[0]).unwrap();
        let mut m = Mutation::new();
        m.set(t, &aks[1], &fill_value(1, &mut r, 1)).unwrap().set(t, &aks[3], &Value::Int(1)).unwrap();
        let second = w.lp.peers[1].commit(m).unwrap().unwrap();
        packages(w, 1, &[second])
    });
    let (pieces, loads) = (c.get("apply: piece").copied().unwrap_or(0), c.get("state page load").copied().unwrap_or(0));
    assert!(pieces > 2 && loads > pieces, "{c:?}");
}
