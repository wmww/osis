//! Applying a delta a piece at a time leaves what applying it whole does (issues/
//! durable-decode-bound.md step 3; spec/crdt.md §8): the same random history runs in two worlds
//! of four nodes, one applying every part decoded whole through the pre-streaming join
//! (`Core::whole_apply`, `oracle::joins`), and after every step each node's ingest outcomes,
//! states and indexes must agree, and after the last when each body was replaced. Histories: paged maps and sets filled, edited and
//! replaced (root resets), turned into registers (encoding changes), a map with a paged part
//! and unpaged entries in one aspect, multi-aspect commits, compaction snapshots, writes by a
//! node without the role (invalid deltas, un-merging), bounded retention (when replaced), and partial,
//! reordered deliveries, some first without their pages (pending, then applied).

use crate::local_peer::{LocalPeer, Package};
use crate::Mutation;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::core_types as ct;
use osis_schema::{Codec, PurgeBy, Retention};
use std::collections::BTreeMap;

const T0: WallMs = WallMs(1_700_000_000_000);
const NODES: usize = 4;
/// Peer 2 is removed halfway with a frontier before all its writes: its deltas turn or arrive
/// invalid (un-merging).
const ROGUE: usize = 2;

struct Rng(u64);
impl Rng {
    /// A distinct history per seed (below 2^63): xorshift needs a nonzero state.
    fn new(seed: u64) -> Rng {
        Rng(seed << 1 | 1)
    }
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
    let a = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap();
    for w in [1, 2, 3] {
        let w = lp.peers[w].engine.me();
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(w))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
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
        1 => Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), big_map(r, g)), (Value::Str("x".into()), Value::Int(g as i64))])),
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

/// Node 0 removes writer `who` with a frontier before all its writes: the removal's commit.
fn demote_peer(w: &mut World, who: usize) -> CommitId {
    let (t, x) = (w.t, w.lp.peers[who].engine.me());
    let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(x, std::collections::BTreeSet::from([t]))]), content: BTreeMap::from([(x, std::collections::BTreeSet::from([t]))]) };
    let f = w.lp.peers[0].engine.frontier(&scope, T0).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(x)) }).unwrap();
    m.frontier(f.to_value());
    w.lp.peers[0].commit(m).unwrap().unwrap()
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
                // a relative bound: when replaced is judged
                match r.below(3) {
                    0 => {
                        m.retention(t, &aks[asp], bounded()).unwrap();
                    }
                    1 => {
                        m.retention(t, &aks[asp], Retention { by: PurgeBy::Writer, history: Some(osis_schema::History::PurgeOnReplace) }).unwrap();
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
        let c = demote_peer(self, ROGUE);
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

    /// What must agree: per node, every aspect's state and read, what pends, and the indexes,
    /// and with `judged` when each held commit was replaced there (each judgment also checks
    /// the streamed deaths against the whole state's, `oracle::deaths`); states pretty-printed
    /// if `pretty` (`first_diff`). `stored`: also each state loaded afresh must equal the cached
    /// one (a reload of every page). Judged on the final held sets only.
    fn seen(&mut self, stored: bool, judged: bool, pretty: bool) -> Vec<String> {
        let t = self.t;
        let mut out = Vec::new();
        for (i, p) in self.lp.peers.iter_mut().enumerate() {
            for a in aks() {
                // the stored pages, not only what loading them gives (it prunes again)
                assert_eq!(p.engine.stale_page_writes(&t, &a).unwrap(), 0, "node {i} {a}: a page holds writes its skeleton prunes");
                let st = p.engine.state(&t, &a).unwrap();
                if stored {
                    let s = p.engine.stored_state(&t, &a).unwrap();
                    assert!(s == st, "node {i} {a}: the store does not hold the cached state\n{}", first_diff(&format!("{s:#?}"), &format!("{st:#?}"), ["stored", "cached"]));
                }
                out.push(if pretty { format!("{i} {a} state {st:#?}") } else { format!("{i} {a} state {st:?}") });
                if judged {
                    for c in p.engine.commit_ids() {
                        out.push(format!("{i} {a} {c:?} replaced {:?}", p.engine.replaced_at(&c, &t, &a).map_err(|e| e.to_string())));
                    }
                }
            }
            out.push(format!("{i} pending {:?}", p.engine.pending()));
            out.push(format!("{i} index {:?}", p.engine.index_digest()));
        }
        out
    }
}

/// Where two pretty-printed (`{:#?}`) values first differ: the path to the first differing
/// line (each enclosing line, by indentation, with the whole key of a map entry) and a few
/// lines of each side from there.
fn first_diff(x: &str, y: &str, names: [&str; 2]) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (x.lines().collect(), y.lines().collect());
    let i = a.iter().zip(&b).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()));
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut path: Vec<&str> = Vec::new();
    let mut at = a.get(i).or(b.get(i)).map_or(0, |l| indent(l));
    let mut j = i.min(a.len());
    while j > 0 {
        j -= 1;
        if indent(a[j]) < at {
            at = indent(a[j]);
            let end = j;
            // `}: Entry {` closes a key printed over several lines: back to its opening line
            if a[j].trim_start().starts_with(['}', ')', ']']) {
                while j > 0 && indent(a[j - 1]) > at {
                    j -= 1;
                }
                j = j.saturating_sub(1);
            }
            path.extend(a[j..=end].iter().rev());
        }
    }
    path.reverse();
    let tail = |v: &[&str]| v[i.min(v.len())..(i + 8).min(v.len())].join("\n");
    format!("at line {i} under\n{}\n--- {}\n{}\n--- {}\n{}", path.join("\n"), names[0], tail(&a), names[1], tail(&b))
}

#[test]
fn first_diff_names_the_entry() {
    let v = |c: Option<u8>| format!("{:#?}", BTreeMap::from([((1, "a"), (0, None)), ((2, "b"), (1, c))]));
    let d = first_diff(&v(None), &v(Some(3)), ["x", "y"]);
    assert!(d.contains("        \"b\",\n    ): (\n--- x\n        None,"), "{d}");
}

/// Runs `steps` steps of seed `seed` in both worlds, comparing after each, the stored states
/// with the cached ones and when each body was replaced after the last (`stored_each`: the
/// stored states after each).
fn differential(seed: u64, steps: u64, stored_each: bool) -> BTreeMap<&'static str, u64> {
    crate::costs::take();
    let mut new = world(seed, false);
    let mut old = world(seed, true);
    let (mut rn, mut ro) = (Rng::new(seed), Rng::new(seed));
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
        let stored = stored_each || g == steps;
        let (a, b) = (new.seen(stored, g == steps, false), old.seen(stored, g == steps, false));
        assert_eq!(a.len(), b.len(), "seed {seed} step {g}: held commits differ");
        if a != b {
            let (a, b) = (new.seen(false, g == steps, true), old.seen(false, g == steps, true));
            let (x, y) = a.iter().zip(&b).find(|(x, y)| x != y).unwrap();
            panic!("seed {seed} step {g}: page-by-page apply differs from whole\n{}\nlog {:#?}", first_diff(x, y, ["page by page", "whole"]), new.log);
        }
    }
    let mut c: BTreeMap<&'static str, u64> = crate::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
    c.insert("waited for pages", new.log.iter().filter(|l| l.contains("WaitBlobs")).count() as u64);
    c
}

#[test]
fn paged_apply_matches_whole_spec_crdt_8() {
    // seed 14: among seeds 0..32 at 14 steps, the cheapest reaching all three (seed 3 took 2.5x)
    let c = differential(14, 14, false);
    // the history reached what it is for: paged deltas streamed, a reset joined by pages, a
    // commit waiting for its pages
    assert!(["apply: piece", "reset: by pages", "waited for pages"].iter().all(|k| c.get(k).is_some_and(|n| *n > 0)), "{c:?}");
}

#[test]
#[ignore = "tier 2"]
fn paged_apply_matches_whole_large_spec_crdt_8() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_PAGED_APPLY_START", "OSIS_PAGED_APPLY_SEEDS", osis_base::testenv::large(1..25));
    let replay = |s: u64| format!("OSIS_PAGED_APPLY_START={s} OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8");
    seeds.run("apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8", replay, |seed| differential(seed, 30, true));
}

/// Runs `script` in a world applying page by page and in one applying whole, then compares
/// them (states, when replaced, indexes, each delivery's outcome or error); returns the cost counts of
/// the page-by-page world's deliveries and their outcomes.
fn both(seed: u64, script: impl Fn(&mut World) -> Vec<Package>) -> (BTreeMap<&'static str, u64>, Vec<String>) {
    let mut worlds = Vec::new();
    let mut counts = BTreeMap::new();
    let mut outs = Vec::new();
    for whole in [false, true] {
        let mut w = world(seed, whole);
        let pks = script(&mut w);
        crate::costs::take();
        for pk in &pks {
            let out = w.lp.deliver(3, pk);
            w.log.push(format!("{:?}: {out:?}", pk.id));
            if !whole {
                outs.push(format!("{out:?}"));
            }
        }
        if !whole {
            counts = crate::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
        }
        worlds.push(w);
    }
    // compared printed flat, pretty-printed again only to show a difference
    let mut seen = |pretty: bool| worlds.iter_mut().map(|w| [w.seen(!pretty, true, pretty), w.log.clone()].concat()).collect::<Vec<_>>();
    if seen(false).windows(2).any(|x| x[0] != x[1]) {
        let v = seen(true);
        let (x, y) = v[0].iter().zip(&v[1]).find(|(x, y)| x != y).expect("page-by-page apply differs from whole in length");
        panic!("page-by-page apply differs from whole\n{}", first_diff(x, y, ["page by page", "whole"]));
    }
    (counts, outs)
}

/// The packages of `ids` from node `from`.
fn packages(w: &mut World, from: usize, ids: &[CommitId]) -> Vec<Package> {
    ids.iter().map(|id| w.lp.peers[from].engine.package(id).unwrap().unwrap()).collect()
}

/// A relative keep at least: when replaced is judged, no body drops for it.
fn bounded() -> Retention {
    Retention { by: PurgeBy::Writer, history: Some(osis_schema::History::Keep { until: None, after: Some(3_600_000) }) }
}

/// Node 3 holds a paged map (its own fill, so its deltas carry bounded retention); node 0
/// replaces the map (a root reset) and snapshots it; node 3 gets the snapshot alone: its
/// skeleton's reset prunes the paged state a page at a time, the old writes dying there.
#[test]
fn snapshot_root_reset_prunes_pages_spec_crdt_8() {
    let (c, _) = both(5, |w| {
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
    let (c, _) = both(6, |w| {
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

/// Node 3 gets node 1's rewrite of a map held in a map entry, large enough to page, before the
/// fill creating that entry (seed 8130018 of the large differential): the state pages the map
/// under a record without its creation, which then arrives. The store must hold it as the
/// cache does (`seen` reloads), applied by pieces and whole: the fill paged itself (its pages
/// carry the creation), and small as a replace (a root reset: `join_reset`).
#[test]
fn entry_creation_after_its_paged_content_spec_crdt_5_6() {
    for replace in [false, true] {
        let (c, _) = both(8, |w| {
            let (t, a) = (w.t, aks()[1].clone());
            let mut r = Rng(51);
            let mut m = Mutation::new();
            if replace {
                let small = Value::Map((0..10).map(|i| (Value::Int(i), s(i as u64, 0))).collect());
                m.replace(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), small), (Value::Str("x".into()), Value::Int(0))]))).unwrap();
            } else {
                m.set(t, &a, &fill_value(1, &mut r, 0)).unwrap();
            }
            let fill = w.lp.peers[0].commit(m).unwrap().unwrap();
            let pk = packages(w, 0, &[fill]);
            w.lp.deliver(1, &pk[0]).unwrap();
            let mut m = Mutation::new();
            m.set(t, &a, &fill_value(1, &mut r, 1)).unwrap();
            let rewrite = w.lp.peers[1].commit(m).unwrap().unwrap();
            let mut pks = packages(w, 1, &[rewrite]);
            pks.push(pk[0].clone());
            pks
        });
        assert_eq!(c.contains_key("reset: by pages"), replace, "{c:?}");
    }
}

/// Made-up delete keys and the thing's dedup secret, for hand-built commits.
struct Forged(osis_base::CreationRecord);
impl osis_commit::Secrets for Forged {
    fn dedup(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([3; 32])).verifying_key())
    }
    fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([1; 32])).verifying_key())
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([2; 32])).verifying_key())
    }
}

/// Pages handed to a blob writer, each first changed by `mutate` (its index, its plaintext).
struct Mutating<'a, 'b> {
    inner: osis_label::BlobWriter<'a>,
    n: usize,
    mutate: &'b dyn Fn(usize, &mut Vec<u8>),
}
impl osis_crdt::PageSink for Mutating<'_, '_> {
    fn put(&mut self, plaintext: &[u8]) -> std::result::Result<osis_base::Link, osis_crdt::PageError> {
        let mut p = plaintext.to_vec();
        (self.mutate)(self.n, &mut p);
        self.n += 1;
        self.inner.put(&p)
    }
    fn params(&self) -> osis_crdt::PageParams {
        self.inner.params()
    }
}

/// A content snapshot of `(w.t, ak)` by peer `by` at `ts` carrying `f`, paged, each page first
/// changed by `mutate` (hand-built, unchecked).
fn forge_snapshot(w: &mut World, by: usize, ak: &Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, mutate: &dyn Fn(usize, &mut Vec<u8>)) -> Package {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, writer_ctx};
    let t = w.t;
    let rec = w.lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
    let sec = Forged(rec);
    let author = w.lp.peers[by].engine.me();
    let retention = osis_commit::retention::snapshot_retention(ak.as_str(), []);
    let keys = osis_commit::delete_keys(&sec, &t, &retention).unwrap();
    let blind = [9u8; 16];
    let framing = osis_label::Framing { dedup: osis_commit::Secrets::dedup(&sec, &t).unwrap(), expiry: None, keys: keys.iter().map(|k| (k.level, k.verifying_key().unwrap())).collect(), blind };
    let mut blobs = osis_label::MemoryBlobs::default();
    let mut rng = osis_crypto::SeededRng::from_u64(9);
    let snap = osis_crdt::Snapshot { absorbed: Default::default(), nonce: [7; 16], fragment: f, frontiers: Default::default() };
    let bytes = {
        let mut sink = Mutating { inner: osis_label::BlobWriter::new(&framing, &mut blobs, &mut rng), n: 0, mutate };
        osis_crdt::encode_snapshot(&snap, &writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, author, 0, 0), Some(&mut sink)).unwrap()
    };
    let mut aw = AspectWrite::new(t, ak.clone(), 0, 0, bytes);
    aw.retention = retention;
    aw.chunks = blobs.0.keys().copied().collect();
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    cb.blind = Some(blind);
    let forge_key = w.lp.peers[by].engine.sign_forged(&mut cb);
    let c = cb.build(&forge_key, &sec, &mut osis_commit::MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit;
    Package { id: c.id(), bytes: c.encode(), blobs: blobs.0.into_iter().collect(), lists: Vec::new() }
}

/// A session of a made-up node `src` (made-up sources sort by their bytes among the peers'
/// sessions, so a write by source 1 lands on the first page, by 0xfe on the last).
fn made_up(src: u8) -> osis_crdt::Source {
    osis_crdt::Source::session(osis_crdt::Session { node: Tid::from_bytes([src; 15]), nonce: [src; osis_crdt::SESSION_NONCE_LEN] })
}

/// A big map of `n` entries by made-up source `src`.
fn forged_map(ts: osis_base::Ts, n: u64, src: u8) -> osis_crdt::Fragment {
    let mut w = osis_crdt::Writer::new(ts, made_up(src), 1 << 40);
    let v = Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    osis_crdt::create(&mut w, &osis_crdt::AnyView, &v).unwrap()
}

/// One entry `k` by a made-up node `src` stamped `ts`.
fn one_entry(ts: osis_base::Ts, src: u8, k: i64) -> osis_crdt::Fragment {
    let mut w = osis_crdt::Writer::new(ts, made_up(src), 1 << 41);
    osis_crdt::create(&mut w, &osis_crdt::AnyView, &Value::Map(osis_base::ValueMap::from([(Value::Int(k), Value::Str("late".into()))]))).unwrap()
}

/// A keyed removal of a made-up entry (malformed outside role-class aspects).
fn keyed_removal(ts: osis_base::Ts, src: u8) -> osis_crdt::Fragment {
    let w = osis_crdt::Writer::new(ts, made_up(src), 1 << 42).keyed_removals(true);
    osis_crdt::reset_entries(&w, &[(osis_crdt::Dot::new(made_up(src), 5), Value::Int(-1))])
}

/// Changes the first register fragment (`[0, ...]`) of a page into an unknown encoding.
fn unknown_encoding(p: &mut Vec<u8>) {
    fn walk(v: &mut Value) -> bool {
        match v {
            Value::List(xs) => {
                if xs.len() >= 2 && xs.first() == Some(&Value::Int(0)) {
                    xs[0] = Value::Int(99);
                    return true;
                }
                xs.iter_mut().any(walk)
            }
            Value::Map(m) => {
                let mut x: Vec<(Value, Value)> = std::mem::take(m).into_iter().collect();
                let hit = x.iter_mut().any(|(_, v)| walk(v));
                *m = x.into_iter().collect();
                hit
            }
            _ => false,
        }
    }
    let lim = osis_base::Limits { max_depth: 64, max_bytes: p.len() };
    let mut v = osis_base::decode(p, &lim).unwrap();
    assert!(walk(&mut v), "no register in the page");
    *p = osis_base::encode(&v);
}

/// Hostile paged snapshots with several problems each (a carried write stamped after the
/// commit, a keyed map removal, an unknown encoding: parked, missing pages: pending) are
/// refused, parked or pend exactly as when decoded whole, with the same error; a sound one
/// applies the same.
#[test]
fn hostile_paged_snapshots_match_whole_spec_crdt_8() {
    let a = aks()[0].clone();
    let none: &dyn Fn(usize, &mut Vec<u8>) = &|_, _| {};
    let last_page: &dyn Fn(usize, &mut Vec<u8>) = &|i, p| {
        if i == 1 {
            unknown_encoding(p)
        }
    };
    // (name, late entry source (`None`: none), keyed removal source, page mutation, bare first,
    // the last delivery's outcome)
    type Case<'a> = (&'a str, Option<u8>, Option<u8>, &'a dyn Fn(usize, &mut Vec<u8>), bool, &'a str);
    let (late_err, keyed_err) = ("stamped after its commit", "keyed map removal");
    let cases: [Case<'_>; 8] = [
        ("sound", None, None, none, false, "Applied"),
        ("sound, pages late", None, None, none, true, "Applied"),
        ("late write first page", Some(1), None, none, false, late_err),
        ("late write last page", Some(0xfe), None, none, false, late_err),
        ("late, keyed later", Some(1), Some(0xfe), none, false, keyed_err),
        ("keyed, late later", Some(0xfe), Some(1), none, true, keyed_err),
        ("late, unknown encoding later", Some(1), None, last_page, false, "Parked"),
        ("keyed, unknown encoding later", None, Some(1), last_page, true, "Parked"),
    ];
    for (name, late, keyed, mutate, bare, want) in cases {
        let (_, outs) = both(9, |w| {
            let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
            let later = osis_base::Ts::make(WallMs(w.lp.peers[0].engine.now().0 + 1_000), 0).unwrap();
            let mut f = forged_map(now, 2000, 0x80);
            if let Some(src) = late {
                f.join(one_entry(later, src, 7));
            }
            if let Some(src) = keyed {
                f.join(keyed_removal(now, src));
            }
            let pk = forge_snapshot(w, 0, &a, now, f, mutate);
            assert!(pk.blobs.len() >= 2, "{name}: not paged");
            if bare { vec![Package { blobs: Vec::new(), ..pk.clone() }, pk] } else { vec![pk] }
        });
        assert!(!bare || outs[0].contains("WaitBlobs"), "{name}: {outs:?}");
        assert!(outs.last().is_some_and(|o| o.contains(want)), "{name}: {outs:?}");
    }
}

/// Node 3 holds node 1's paged map; node 0's valid paged snapshot copies node 1's writes, some
/// with another value (on a later page) or faithfully, with writes of its own: joined per page
/// exactly as whole (the copy order, spec/crdt.md §4.1, deaths; nothing compared with the held
/// delta, so no rebuild), with a carried write stamped late refused the same.
#[test]
fn paged_snapshot_differing_copies_match_whole_spec_perm_5_2() {
    let a = aks()[0].clone();
    // (name, how many of node 1's entries the snapshot changes from the end, a late write)
    for (name, changed, late) in [("faithful", 0u64, false), ("differs in the last entries", 5, false), ("differs, late", 5, true)] {
        let (c, outs) = both(10, |w| {
            let t = w.t;
            let b = w.lp.peers[1].engine.me();
            let n = 2000u64;
            let v = |g: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, g))).collect());
            let mut m = Mutation::new();
            m.set(t, &a, &v(0)).unwrap().retention(t, &a, bounded()).unwrap();
            let fill = w.lp.peers[1].commit(m).unwrap().unwrap();
            let pk = packages(w, 1, &[fill]);
            w.lp.deliver(3, &pk[0]).unwrap();
            w.lp.deliver(0, &pk[0]).unwrap();
            let h = osis_commit::CommitBlob::decode(&pk[0].bytes).unwrap().header;
            // node 1's writes again, the last `changed` values otherwise
            let mut wr = osis_crdt::Writer::new(h.ts, h.form.own_source(b, osis_base::CommitId([0; 32])), h.aspects[0].lo);
            let copy = Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, if i + changed >= n { 1 } else { 0 }))).collect());
            let mut f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &copy).unwrap();
            for _ in 0..3 {
                w.lp.advance(1_000);
            }
            let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
            f.join(one_entry(now, 0xfe, 5000));
            if late {
                f.join(one_entry(osis_base::Ts::make(WallMs(w.lp.peers[0].engine.now().0 + 1_000), 0).unwrap(), 1, 5001));
            }
            let pk = forge_snapshot(w, 0, &a, now, f, &|_, _| {});
            assert!(pk.blobs.len() >= 2, "{name}: no later page");
            vec![pk]
        });
        let want = if late { "stamped after its commit" } else { "Applied" };
        assert!(outs.last().is_some_and(|o| o.contains(want)), "{name}: {outs:?}");
        assert!(!c.contains_key("apply: vouched rebuild"), "{name}: {c:?}");
    }
}

/// The rogue fills a map holding a paged map, node 1 edits inside it (its writes nested under
/// the rogue's creations), node 0 removes the rogue with a frontier before the fill: node 3
/// gets the three in several orders, the fill invalid on arrival joining and un-merging a page
/// at a time (earlier pages already written and dropped) or turning invalid once applied.
#[test]
fn invalid_paged_delta_unmerges_per_piece_spec_perm_5_2() {
    let mix = aks()[1].clone();
    // applied, then turned invalid (the in-place un-merge of a state whose pages were dropped);
    // invalid on arrival
    for order in [[0usize, 1, 2], [2, 0, 1]] {
        let (c, _) = both(11, |w| {
            let t = w.t;
            let mut r = Rng(41);
            let mut m = Mutation::new();
            m.set(t, &mix, &fill_value(1, &mut r, 0)).unwrap();
            let fill = w.lp.peers[ROGUE].commit(m).unwrap().unwrap();
            let pk = packages(w, ROGUE, &[fill]);
            w.lp.deliver(1, &pk[0]).unwrap();
            let cur = w.lp.peers[1].engine.get(&t, &mix).unwrap();
            let mut m = Mutation::new();
            m.set(t, &mix, &edited(cur, &mut r, 1)).unwrap();
            let edit = w.lp.peers[1].commit(m).unwrap().unwrap();
            let before: Vec<CommitId> = w.lp.peers[0].engine.commit_ids();
            w.demote();
            let demote = w.lp.peers[0].engine.commit_ids().into_iter().find(|c| !before.contains(c)).unwrap();
            let mut pks = packages(w, ROGUE, &[fill]);
            pks.extend(packages(w, 1, &[edit]));
            pks.extend(packages(w, 0, &[demote]));
            order.iter().map(|i| pks[*i].clone()).collect()
        });
        assert!(c.get("apply: piece").is_some_and(|n| *n > 2), "{order:?}: {c:?}");
    }
}

/// A streamed apply failing midway (after earlier pieces joined, their state pages written into
/// the store transaction and spilled to the backend early under a small spill budget) leaves
/// nothing: the state reads as before, a reopen finds the backend's rows as before, and the
/// commit applies afterwards as on a node that never failed.
#[test]
fn failed_streamed_apply_leaves_nothing_spec_commits_4() {
    let (big, set) = (aks()[0].clone(), aks()[2].clone());
    let mut w = world(12, false);
    let t = w.t;
    // node 3 holds two paged aspects; node 1 replaces both in one commit (a reset joined by pages)
    let mut m = Mutation::new();
    let set_of = |g: u64| Value::Set((0..2000).map(|i| s(i, g)).collect());
    let map_of = |g: u64| Value::Map((0..2000).map(|i| (Value::Int(i), s(i as u64, g))).collect());
    m.set(t, &big, &map_of(0)).unwrap().set(t, &set, &set_of(0)).unwrap();
    let fill = w.lp.peers[1].commit(m).unwrap().unwrap();
    let pk = packages(&mut w, 1, &[fill]);
    w.lp.deliver(3, &pk[0]).unwrap();
    let mut m = Mutation::new();
    m.replace(t, &big, &map_of(1)).unwrap().replace(t, &set, &set_of(1)).unwrap();
    let next = w.lp.peers[1].commit(m).unwrap().unwrap();
    let pk = packages(&mut w, 1, &[next]).remove(0);
    // node 3 again, spilling every few KiB
    let p = &mut w.lp.peers[3];
    let mut cfg = crate::engine::Config::default();
    cfg.store.spill_bytes = 4096;
    let clock: std::sync::Arc<dyn osis_base::Clock> = p.clock.clone();
    p.engine = crate::Engine::open(Box::new(p.backend.clone()), Box::new(p.root.clone()), cfg.clone(), clock.clone(), Box::new(osis_crypto::SeededRng::from_u64(77))).unwrap();
    let read = |p: &mut crate::local_peer::Peer| [&big, &set].map(|a| p.engine.state(&t, a).unwrap());
    let before = read(p);
    let rows = p.backend.dump();
    // two parts of a skeleton and a page each: fail in the first part's page, the second
    // part's skeleton, its page
    for k in [1usize, 2, 3] {
        p.engine.core.piece_fault = Some(k);
        let e = p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap_err();
        assert!(e.to_string().contains("piece fault"), "{e}");
        assert!(p.backend.dump().iter().any(|(k, _)| k.first() == Some(&b'j')), "nothing spilled");
        assert_eq!(read(p), before, "after a fault at piece {k}");
    }
    p.engine.core.piece_fault = None;
    // the failed engine gone, the spilled rows are rolled back
    let spare = crate::Engine::create(Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), crate::engine::Config::default(), clock.clone(), Box::new(osis_crypto::SeededRng::from_u64(79))).unwrap();
    drop(std::mem::replace(&mut p.engine, spare));
    assert_eq!(p.backend.dump(), rows, "the backend's rows as before");
    p.engine = crate::Engine::open(Box::new(p.backend.clone()), Box::new(p.root.clone()), cfg, clock, Box::new(osis_crypto::SeededRng::from_u64(78))).unwrap();
    assert_eq!(read(p), before);
    assert!(matches!(w.lp.deliver(3, &pk), Ok(crate::Ingested::Applied(_))));
    w.lp.deliver(2, &pk).unwrap();
    let want = [&big, &set].map(|a| w.lp.peers[2].engine.state(&t, a).unwrap());
    assert_eq!(read(&mut w.lp.peers[3]), want);
}


/// A commit adding and removing one key of the paged map in a map entry (node 1's: net, an
/// explicit `W` on the map and no element) reaches the map's page set with no dot: the pages
/// loaded for it still give the entry's creation, kept in the set's path only (node 1 commits
/// it, node 3 applies it; every node then holds one state, stored as cached).
#[test]
fn elementless_write_keeps_entry_creation_spec_crdt_5_6() {
    both(8, |w| {
        let (t, a) = (w.t, aks()[1].clone());
        let mut r = Rng(51);
        let mut m = Mutation::new();
        m.set(t, &a, &fill_value(1, &mut r, 0)).unwrap();
        let fill = w.lp.peers[0].commit(m).unwrap().unwrap();
        let pk = packages(w, 0, &[fill]);
        for to in [1, 3] {
            w.lp.deliver(to, &pk[0]).unwrap();
        }
        let big = || PathSeg::Key(Value::Str("big".into()));
        let mut m = Mutation::new();
        m.op(t, &a, PathOp { path: vec![big(), PathSeg::Key(Value::Int(99_999))], op: Op::Set(Value::Int(1)) }).unwrap();
        m.op(t, &a, PathOp { path: vec![big()], op: Op::Remove(Value::Int(99_999)) }).unwrap();
        let c = w.lp.peers[1].commit(m).unwrap().unwrap();
        let pk = packages(w, 1, &[c]);
        w.lp.deliver(0, &pk[0]).unwrap();
        let want = w.lp.peers[0].engine.state(&t, &a).unwrap();
        assert!(w.lp.peers[1].engine.stored_state(&t, &a).unwrap() == want, "the committer's store lost what node 0 holds");
        pk
    });
}

/// spec/commits.md §5 (when replaced, never of paging): a snapshot of a map whose `big` entry
/// holds a paged map streams `big`'s creation on every page's path. A root reset kills every
/// write of it, then a register write replaces the map. Each write died once, at the reset: the
/// snapshot is replaced there, as its fill delta is, not at the register write.
#[test]
fn death_on_many_pages_dated_once_spec_commits_5() {
    let mut w = world(13, false);
    let (t, a) = (w.t, aks()[1].clone());
    let big = Value::Map((0..4000).map(|i| (Value::Int(i), s(i as u64, 0))).collect());
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), big), (Value::Str("x".into()), Value::Int(0))]))).unwrap().retention(t, &a, bounded()).unwrap();
    let fill = w.lp.peers[0].commit(m).unwrap().unwrap();
    w.lp.advance(10);
    let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
    w.lp.advance(10);
    let mut m = Mutation::new();
    m.replace(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("x".into()), Value::Int(1))]))).unwrap().retention(t, &a, bounded()).unwrap();
    let reset = w.lp.peers[0].commit(m).unwrap().unwrap();
    w.lp.advance(10);
    let mut m = Mutation::new();
    m.replace(t, &a, &Value::Int(2)).unwrap().retention(t, &a, bounded()).unwrap();
    w.lp.peers[0].commit(m).unwrap().unwrap();
    let e = &mut w.lp.peers[0].engine;
    let ai = e.header(&snap).unwrap().aspects.iter().position(|x| x.ak == a).unwrap();
    let pieces = e.run(|tx| {
        let mut n = 0;
        crate::apply::each_held_piece(tx, &snap, ai, &mut |_, _| {
            n += 1;
            Ok(())
        })?;
        Ok(n)
    });
    let pieces = pieces.unwrap(); assert!(pieces > 2, "{pieces}: the snapshot's `big` pages under one path");
    let at = Some(e.header(&reset).unwrap().ts);
    assert_eq!(e.replaced_at(&fill, &t, &a).unwrap(), at);
    assert_eq!(e.replaced_at(&snap, &t, &a).unwrap(), at);
}

/// Node 1 fills a map holding a paged map, replaces it (a root reset; the new `big` entry under
/// another dot) and rewrites the new paged map; node 3 gets the fill, the rewrite (paged under
/// an entry it has no creation of) and then the replace: the reset joined by pages leaves the
/// old `big` collection without a position, so the store must keep none of it, as a whole
/// layout would (seed 262014 of the large differential).
#[test]
fn reset_drops_dead_paged_collection_spec_crdt_8() {
    let (c, _) = both(13, |w| {
        let (t, a) = (w.t, aks()[1].clone());
        let mut r = Rng(61);
        let mut m = Mutation::new();
        m.set(t, &a, &fill_value(1, &mut r, 0)).unwrap();
        let fill = w.lp.peers[1].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.replace(t, &a, &fill_value(1, &mut r, 1)).unwrap();
        let replace = w.lp.peers[1].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.set(t, &a, &fill_value(1, &mut r, 2)).unwrap();
        let rewrite = w.lp.peers[1].commit(m).unwrap().unwrap();
        packages(w, 1, &[fill, rewrite, replace])
    });
    assert!(c.get("reset: laid out").is_some_and(|n| *n > 0), "{c:?}");
}

/// The rogue fills a paged set alone; node 3 gets the fill, then node 0's removal of the rogue:
/// the rebuild leaves the state absent, page by page as whole (seed 262094: the old in-place
/// un-merge kept an empty set while the set was not noted loaded whole).
#[test]
fn unmerge_emptying_every_page_leaves_none_spec_perm_5_2() {
    let (c, _) = both(14, |w| {
        let (t, set) = (w.t, aks()[2].clone());
        let mut r = Rng(71);
        let mut m = Mutation::new();
        m.set(t, &set, &fill_value(2, &mut r, 0)).unwrap();
        let fill = w.lp.peers[ROGUE].commit(m).unwrap().unwrap();
        let demote = demote_peer(w, ROGUE);
        let mut pks = packages(w, ROGUE, &[fill]);
        pks.extend(packages(w, 0, &[demote]));
        pks
    });
    assert!(c.get("rejudge: rebuild").is_some_and(|n| *n > 0), "{c:?}");
}

/// The rogue fills a paged map; node 1 rewrites it (its writes nested under the rogue's
/// entries); node 3 gets the rewrite, node 0's removal of the rogue, then the fill, invalid on
/// arrival: un-merged a piece at a time, the state is what a rebuild gives once the last piece
/// un-merged, not before (seed 262035: checked after each piece).
#[test]
fn invalid_fill_after_nested_rewrite_spec_perm_5_2() {
    let (c, _) = both(15, |w| {
        let (t, big) = (w.t, aks()[0].clone());
        let mut r = Rng(81);
        let mut m = Mutation::new();
        m.set(t, &big, &fill_value(0, &mut r, 0)).unwrap();
        let fill = w.lp.peers[ROGUE].commit(m).unwrap().unwrap();
        let pk = packages(w, ROGUE, &[fill]);
        w.lp.deliver(1, &pk[0]).unwrap();
        let mut m = Mutation::new();
        m.set(t, &big, &fill_value(0, &mut r, 1)).unwrap();
        let rewrite = w.lp.peers[1].commit(m).unwrap().unwrap();
        let demote = demote_peer(w, ROGUE);
        let mut pks = packages(w, 1, &[rewrite]);
        pks.extend(packages(w, 0, &[demote]));
        pks.extend(pk);
        pks
    });
    assert!(c.get("apply: piece").is_some_and(|n| *n > 2), "{c:?}");
}

/// Two writers fill a paged set, the one whose dots sort first alone in its first page; node 3
/// gets both fills and the first writer's removal (the un-merge empties the first page, kept as
/// the collection's first), reopens (nothing loaded), then gets the second writer's removal:
/// that un-merge empties every other page and must leave the state absent, which only the
/// first page, not loaded, can tell.
#[test]
fn unmerge_leaving_empty_first_page_leaves_none_spec_perm_5_2() {
    let (c, _) = both(16, |w| {
        let (t, set) = (w.t, aks()[2].clone());
        let mut ws = [1usize, 2, 3];
        ws.sort_by_key(|i| w.lp.peers[*i].engine.me());
        let (x, y) = (ws[0], ws[2]);
        let mut r = Rng(91);
        let mut fills = Vec::new();
        for (by, g) in [(x, 0), (y, 1)] {
            let mut m = Mutation::new();
            m.set(t, &set, &fill_value(2, &mut r, g)).unwrap();
            fills.push(w.lp.peers[by].commit(m).unwrap().unwrap());
        }
        let (dx, dy) = (demote_peer(w, x), demote_peer(w, y));
        let mut pks = packages(w, x, &[fills[0]]);
        pks.extend(packages(w, y, &[fills[1]]));
        pks.extend(packages(w, 0, &[dx]));
        for pk in &pks {
            w.lp.deliver(3, pk).unwrap();
        }
        let p = &mut w.lp.peers[3];
        let clock: std::sync::Arc<dyn osis_base::Clock> = p.clock.clone();
        p.engine = crate::Engine::open(Box::new(p.backend.clone()), Box::new(p.root.clone()), crate::engine::Config::default(), clock, Box::new(osis_crypto::SeededRng::from_u64(77))).unwrap();
        packages(w, 0, &[dy])
    });
    assert!(c.get("rejudge: rebuild").is_some_and(|n| *n > 0), "{c:?}");
}

/// The rogue fills a map holding a paged map (its `big` entry), node 1 adds to the paged map
/// (entries of its own, in pages apart from the rogue's), node 0 writes another key; node 3 gets
/// the three, then the rogue's removal: the un-merge takes the `big` entry with every page below it, node 1's too
/// (seed 131013).
#[test]
fn unmerge_takes_paged_collection_below_invalid_entry_spec_perm_5_2() {
    let (c, _) = both(17, |w| {
        let (t, mix) = (w.t, aks()[1].clone());
        let mut r = Rng(101);
        let mut m = Mutation::new();
        m.set(t, &mix, &fill_value(1, &mut r, 0)).unwrap();
        let fill = w.lp.peers[ROGUE].commit(m).unwrap().unwrap();
        let pk = packages(w, ROGUE, &[fill]);
        w.lp.deliver(1, &pk[0]).unwrap();
        // entries of node 1's own, superseding none of the rogue's writes (else a rebuild)
        let mut v = w.lp.peers[1].engine.get(&t, &mix).unwrap().unwrap();
        if let Value::Map(m) = &mut v
            && let Some(Value::Map(big)) = m.get_mut(&Value::Str("big".into()))
        {
            big.extend((0..400).map(|i| (Value::Int(10_000 + i), s(i as u64, 1))));
        }
        let mut m = Mutation::new();
        m.set(t, &mix, &v).unwrap();
        let rewrite = w.lp.peers[1].commit(m).unwrap().unwrap();
        // something else left in the state (else it goes whole)
        let mut m = Mutation::new();
        m.op(t, &mix, PathOp { path: vec![PathSeg::Key(Value::Str("y".into()))], op: Op::Set(Value::Int(1)) }).unwrap();
        let other = w.lp.peers[0].commit(m).unwrap().unwrap();
        let demote = demote_peer(w, ROGUE);
        let mut pks = pk;
        pks.extend(packages(w, 1, &[rewrite]));
        pks.extend(packages(w, 0, &[other]));
        pks.extend(packages(w, 0, &[demote]));
        pks
    });
    assert!(c.get("rejudge: rebuild").is_some_and(|n| *n > 0), "{c:?}");
}

/// Node 1 puts a paged map under key `big` (the skeleton then holds nothing of it), the rogue
/// key `y`; node 3 gets both, reopens (only the skeleton cached), then the rogue's removal: the
/// un-merge empties all that is loaded, and the state must keep `big` from its pages.
#[test]
fn unmerge_emptying_skeleton_keeps_paged_entry_spec_perm_5_2() {
    let (c, _) = both(18, |w| {
        let (t, mix) = (w.t, aks()[1].clone());
        let mut r = Rng(121);
        let mut m = Mutation::new();
        m.set(t, &mix, &Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), big_map(&mut r, 0))]))).unwrap();
        let fill = w.lp.peers[1].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.op(t, &mix, PathOp { path: vec![PathSeg::Key(Value::Str("y".into()))], op: Op::Set(Value::Int(1)) }).unwrap();
        let put = w.lp.peers[ROGUE].commit(m).unwrap().unwrap();
        let demote = demote_peer(w, ROGUE);
        let mut pks = packages(w, 1, &[fill]);
        pks.extend(packages(w, ROGUE, &[put]));
        for pk in &pks {
            w.lp.deliver(3, pk).unwrap();
        }
        let p = &mut w.lp.peers[3];
        let clock: std::sync::Arc<dyn osis_base::Clock> = p.clock.clone();
        p.engine = crate::Engine::open(Box::new(p.backend.clone()), Box::new(p.root.clone()), crate::engine::Config::default(), clock, Box::new(osis_crypto::SeededRng::from_u64(77))).unwrap();
        packages(w, 0, &[demote])
    });
    assert!(c.get("rejudge: rebuild").is_some_and(|n| *n > 0), "{c:?}");
}

/// Retention reads a paged body a piece at a time (issues/durable-decode-bound.md step 4): node
/// 3 holds a fill of a map in a map entry (its creation in the skeleton, its writes in pages)
/// and node 0's snapshot of it, drops the fill as covered, then gets node 0's purge of it: the
/// snapshot carrying purged values is stripped, and the fill's leftover comes from the coverer's
/// pieces. By pieces and whole alike, the streamed readers checked against the whole ones on
/// the way (`retention::oracle`: `covered`, `body_live`).
#[test]
fn covered_paged_fill_purged_spec_commits_5() {
    let a = aks()[1].clone();
    let mut seen = Vec::new();
    for whole in [false, true] {
        let mut w = world(44, whole);
        let t = w.t;
        let mut m = Mutation::new();
        m.set(t, &a, &fill_value(1, &mut Rng(75), 0)).unwrap();
        let fill = w.lp.peers[0].commit(m).unwrap().unwrap();
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        let pks = packages(&mut w, 0, &[fill, snap]);
        let mut m = Mutation::new();
        m.set(t, &aks()[3], &Value::Int(9)).unwrap();
        m.purge(osis_commit::PurgeItem::Commit { commit: fill, tid: t, ak: a.clone() });
        let purge = w.lp.peers[0].commit(m).unwrap().unwrap();
        let purge = packages(&mut w, 0, &[purge]);
        for pk in pks.iter().chain(&purge) {
            if pk.id == purge[0].id {
                let e = &mut w.lp.peers[3].engine;
                w.log.push(format!("covered {:?} min {:?}", e.covered(&snap, &fill, &t, &a), e.body_min_ts(&snap, &t, &a)));
                w.log.push(format!("drop {:?}", e.drop_body(&fill, &t, &a)));
            }
            let out = w.lp.deliver(3, pk);
            w.log.push(format!("{:?}: {out:?}", pk.id));
        }
        let mut v = w.seen(true, true, true);
        v.extend(w.log.clone());
        seen.push(v);
    }
    if let Some((x, y)) = seen[0].iter().zip(&seen[1]).find(|(x, y)| x != y) {
        panic!("page-by-page differs from whole\n{}", first_diff(x, y, ["page by page", "whole"]));
    }
    assert!(seen[0].iter().any(|l| l.starts_with("covered Ok(Some(true))")) && seen[0].iter().any(|l| l == "drop Ok(())"), "the snapshot covers the fill: {:?}", &seen[0][seen[0].len() - 5..]);
}
