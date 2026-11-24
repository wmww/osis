//! Applying a delta a piece at a time leaves what applying it whole does (issues/
//! durable-decode-bound.md step 3; spec/crdt.md §8): the same random history runs in two worlds
//! of four nodes, one applying every part decoded whole through the pre-streaming join
//! (`Core::whole_apply`, `oracle::join_into_state`; every other decision of a part's apply is
//! `atomic::join_part`'s in both worlds), and after every step each node's ingest outcomes,
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
use osis_schema::{PurgeBy};
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
    /// Per node and aspect, the read point and cached state at its last stored check (`seen`).
    checked: BTreeMap<(usize, Ak), (crate::engine::ReadPoint, Option<osis_crdt::Fragment>)>,
}

/// The four nodes: node 0 creates the thing with its retention and makes nodes 1-3 writers,
/// and all sync.
fn build(seed: u64) -> (LocalPeer, Tid) {
    let mut lp = LocalPeer::new(NODES, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let a = lp.peers[0].engine.me();
    let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
    let mut m = Mutation::new();
    // a relative bound on `big` and `mix` (when replaced is judged), purge on replace on `reg`
    let keep = ct::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(3_600_000) }), ..Default::default() };
    let purge = ct::RetentionEntry { history: Some(osis_schema::History::PurgeOnReplace), ..Default::default() };
    let [big, mix, _, reg] = aks();
    m.set(t, &ct::RETENTION, &ct::RetentionSetting::from(BTreeMap::from([(big, keep), (mix, keep), (reg, purge)]))).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.hold(t);
    for w in [1, 2, 3] {
        let w = lp.peers[w].engine.me();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    }
    lp.sync_all().unwrap();
    (lp, t)
}

/// One world over `lp`, its nodes applying whole if `whole`.
fn of(mut lp: LocalPeer, t: Tid, whole: bool) -> World {
    for p in &mut lp.peers {
        p.engine.core.whole_apply = whole;
    }
    World { lp, t, log: Vec::new(), checked: BTreeMap::new() }
}

/// A copy of the one shared world (`build(0)`).
fn world(whole: bool) -> World {
    let (lp, t) = LocalPeer::cached("apply::tests_paged::world", || build(0));
    of(lp, t, whole)
}

/// A short string (an edit's value).
fn s(i: u64, g: u64) -> Value {
    Value::Str(format!("value-{i:08}-g-{g:08}"))
}

/// A random paged map: a half to two and a half times `ENTRIES` fat entries at a random key offset.
fn big_map(r: &mut Rng, g: u64) -> Value {
    let n = ENTRIES / 2 + r.below(2 * ENTRIES);
    let off = r.below(ENTRIES / 2);
    Value::Map((0..n).map(|i| (Value::Int((i + off) as i64), fat(i, g))).collect())
}

/// Entries of the hand-written tests' paged collections: enough that an un-merge or delete of
/// some keeps the rest paged. Cost follows the entry count, so each entry is fat: together they
/// span `WIRE_PIECES` wire chunks of the mean size (`CHUNK_MIN` plus the content-defined cut's
/// mean gap), several state pages too.
const ENTRIES: u64 = 128;
const WIRE_PIECES: usize = 3;
const ENTRY_BYTES: usize = WIRE_PIECES * (osis_base::format::CHUNK_MIN + (1 << osis_base::format::CHUNK_MASK_BITS)) / ENTRIES as usize;

/// A string of `ENTRY_BYTES`, distinct per `(i, g)`, its filler varied (content-defined cuts
/// find no boundary in repeated bytes).
fn fat(i: u64, g: u64) -> Value {
    let mut r = Rng::new(i << 20 | g);
    let head = format!("value-{i:08}-g-{g:08}-");
    let fill: String = (head.len()..ENTRY_BYTES).map(|_| char::from(b'a' + r.below(26) as u8)).collect();
    Value::Str(head + &fill)
}

/// `n` fat entries keyed `0..n` (the values of generation `g`).
fn fat_map(n: u64, g: u64) -> Value {
    Value::Map((0..n).map(|i| (Value::Int(i as i64), fat(i, g))).collect())
}

/// A hand-written fill of aspect `asp` (`fill_value`'s shapes, `ENTRIES` fat entries).
fn fixed_fill(asp: usize, g: u64) -> Value {
    match asp {
        0 => fat_map(ENTRIES, g),
        1 => Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), fat_map(ENTRIES, g)), (Value::Str("x".into()), Value::Int(g as i64))])),
        2 => Value::Set((0..ENTRIES).map(|i| fat(i, g)).collect()),
        _ => Value::Int(g as i64),
    }
}

/// The value of aspect `asp` after a fill.
fn fill_value(asp: usize, r: &mut Rng, g: u64) -> Value {
    match asp {
        0 => big_map(r, g),
        1 => Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), big_map(r, g)), (Value::Str("x".into()), Value::Int(g as i64))])),
        2 => Value::Set((0..ENTRIES / 2 + r.below(2 * ENTRIES)).map(|i| fat(i + r.below(3), g)).collect()),
        _ => Value::Int(g as i64),
    }
}

/// A few keys changed in the current value.
fn edited(v: Option<Value>, r: &mut Rng, g: u64) -> Value {
    match v {
        Some(Value::Map(mut m)) => {
            if let Some(Value::Map(inner)) = m.get_mut(&Value::Str("big".into())) {
                for _ in 0..3 {
                    inner.insert(Value::Int(r.below(3 * ENTRIES) as i64), s(r.below(9), g));
                }
            } else {
                for _ in 0..3 {
                    let k = Value::Int(r.below(3 * ENTRIES) as i64);
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
                x.insert(fat(r.below(3 * ENTRIES), g));
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
    let scope = crate::apply::receipt::DemotionScope { roles: BTreeMap::from([(x, std::collections::BTreeSet::from([t]))]), content: BTreeMap::from([(x, std::collections::BTreeSet::from([t]))]) };
    let f = w.lp.peers[0].engine.frontier(&scope, T0).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(x)) }).unwrap();
    m.frontier(osis_perm::Frontier::new(f.commits));
    w.lp.peers[0].commit(m).unwrap().unwrap()
}

impl World {
    /// Node `by` commits what `f` writes.
    fn commit(&mut self, by: usize, f: impl FnOnce(&mut Mutation)) -> CommitId {
        let mut m = Mutation::new();
        f(&mut m);
        self.lp.peers[by].commit(m).unwrap().unwrap()
    }
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
                // purgeable by every writer, or the untyped default
                if r.below(3) < 2 {
                    m.purge_by(t, &aks[asp], PurgeBy::Writer).unwrap();
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

    /// Delivers the commits on T one node holds that another lacks, in a random order, some
    /// first without their pages (what else each holds, its own root's, draws nothing).
    fn send(&mut self, r: &mut Rng) {
        let from = r.below(NODES as u64) as usize;
        let to = (from + 1 + r.below(NODES as u64 - 1) as usize) % NODES;
        let t = self.t;
        let mut pks: Vec<Package> = self.lp.packages_for(from, to).unwrap();
        pks.retain(|p| osis_commit::CommitBlob::decode(&p.bytes).is_ok_and(|b| b.header.aspects.iter().any(|a| a.tid == t)));
        // a commit applied as its header with parts waiting is still sent
        let held: Vec<CommitId> = self.lp.peers[to].engine.commit_ids();
        let waiting: Vec<CommitId> = self.lp.peers[to].engine.pending().into_iter().map(|x| x.0).collect();
        pks.retain(|p| !held.contains(&p.id) || waiting.contains(&p.id));
        for i in (1..pks.len()).rev() {
            pks.swap(i, r.below(i as u64 + 1) as usize);
        }
        for pk in pks {
            if !pk.blobs.is_empty() && r.below(3) == 0 {
                let bare = Package { blobs: Vec::new(), ..pk.clone() };
                let out = deliver(&mut self.lp, to, &bare);
                self.log.push(format!("{from}->{to} bare {:?}: {out}", pk.id));
            }
            let out = deliver(&mut self.lp, to, &pk);
            self.log.push(format!("{from}->{to} {:?}: {out}", pk.id));
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
                    for pk in self.lp.packages_for(from, to).unwrap() {
                        let out = deliver(&mut self.lp, to, &pk);
                        self.log.push(format!("{from}->{to} {:?}: {out}", pk.id));
                    }
                }
            }
        }
    }

    /// What must agree: per node, every aspect's state and read, what pends, and the indexes,
    /// and with `judged` when each held commit was replaced there, each held part's deaths at its
    /// positions checked against the whole state's (`oracle::deaths`); states pretty-printed
    /// if `pretty` (`first_diff`). `stored`: also each state loaded afresh must equal the cached
    /// one (a reload of every page). Judged on the final held sets only.
    fn seen(&mut self, stored: bool, judged: bool, pretty: bool) -> Vec<String> {
        let t = self.t;
        let mut out = Vec::new();
        for (i, p) in self.lp.peers.iter_mut().enumerate() {
            for a in aks() {
                let st = p.engine.state(&t, &a).unwrap();
                // both checks below are reads: while the read point stands they repeat
                // themselves (`Engine::point`), so a node and aspect checked at this point with
                // this cached state passes again
                let at = p.engine.point();
                let repeat = stored && self.checked.get(&(i, a.clone())).is_some_and(|(x, s)| *x == at && *s == st);
                if !repeat {
                    // the stored pages, not only what loading them gives (it prunes again)
                    assert_eq!(p.engine.stale_page_writes(&t, &a).unwrap(), 0, "node {i} {a}: a page holds writes its skeleton prunes");
                }
                if stored && !repeat {
                    let s = p.engine.stored_state(&t, &a).unwrap();
                    assert!(s == st, "node {i} {a}: the store does not hold the cached state\n{}", first_diff(&format!("{s:#?}"), &format!("{st:#?}"), ["stored", "cached"]));
                    self.checked.insert((i, a.clone()), (at, st.clone()));
                }
                out.push(if pretty { format!("{i} {a} state {st:#?}") } else { format!("{i} {a} state {st:?}") });
                if judged {
                    for c in p.engine.commit_ids() {
                        out.push(format!("{i} {a} {c:?} replaced {:?}", p.engine.replaced_at(&c, &t, &a).map_err(|e| e.to_string())));
                        let (at, whole) = p.engine.read(|tx| crate::retention::bounds::deaths_and_whole(tx, &c, &t, &a)).unwrap().unwrap_or_default();
                        assert_eq!(at, whole, "node {i} {a} {c:?}: deaths at the part's positions vs the whole state");
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
    osis_base::costs::take();
    let (mut lp, t) = build(seed);
    let mut old = of(lp.copy().unwrap(), t, true);
    let mut new = of(lp, t, false);
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
    let mut c: BTreeMap<&'static str, u64> = osis_base::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
    c.insert("waited for pages", new.log.iter().filter(|l| l.contains("WaitBlobs")).count() as u64);
    c
}

#[test]
#[ignore = "property"]
fn paged_apply_matches_whole_plain_spec_crdt_8() {
    let c = differential(0, 14, false);
    // the history reached what it is for: paged deltas streamed, a reset joined by pages, a
    // commit waiting for its pages
    assert!(["apply: piece", "reset: by pages", "waited for pages"].iter().all(|k| c.get(k).is_some_and(|n| *n > 0)), "{c:?}");
}

#[test]
#[ignore = "property"]
fn paged_apply_matches_whole_large_spec_crdt_8() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_PAGED_APPLY_START", "OSIS_PAGED_APPLY_SEEDS", osis_base::testenv::large(1..25));
    let replay = |s: u64| format!("OSIS_PAGED_APPLY_START={s} OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8");
    seeds.run("apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8", replay, |seed| differential(seed, 30, true));
}

/// Runs `script` in a world applying page by page and in one applying whole, then compares
/// them (states, when replaced, indexes, each delivery's outcome or error); returns the cost counts of
/// the page-by-page world's deliveries and their outcomes.
fn both(script: impl Fn(&mut World) -> Vec<Package>) -> Both {
    both_in(world, script).0
}

/// What `both` returns: the cost counts and outcomes of the page-by-page world's deliveries.
type Both = (BTreeMap<&'static str, u64>, Vec<String>);

/// `both` in worlds `make` gives (applying whole if its argument), with the worlds.
fn both_in(make: impl Fn(bool) -> World, script: impl Fn(&mut World) -> Vec<Package>) -> (Both, Vec<World>) {
    let mut worlds = Vec::new();
    let mut counts = BTreeMap::new();
    let mut outs = Vec::new();
    for whole in [false, true] {
        let mut w = make(whole);
        let pks = script(&mut w);
        osis_base::costs::take();
        for pk in &pks {
            let out = deliver(&mut w.lp, 3, pk);
            w.log.push(format!("{:?}: {out}", pk.id));
            if !whole {
                outs.push(out);
            }
        }
        if !whole {
            counts = osis_base::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
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
    ((counts, outs), worlds)
}

/// Delivers `pk` to node `to`: the outcome, and what of the commit waits there after (a part
/// waits under its applied commit, spec/commits.md §4).
fn deliver(lp: &mut LocalPeer, to: usize, pk: &Package) -> String {
    let out = lp.deliver(to, pk);
    let waits = lp.peers[to].engine.pending().into_iter().find(|x| x.0 == pk.id).map(|x| x.1);
    format!("{out:?} waits {waits:?}")
}

/// The packages of `ids` from node `from`.
fn packages(w: &mut World, from: usize, ids: &[CommitId]) -> Vec<Package> {
    ids.iter().map(|id| w.lp.peers[from].engine.package(id).unwrap().unwrap()).collect()
}

/// Node 3 holds a paged map (its own fill, so its deltas carry bounded retention); node 0
/// replaces the map (a root reset) and snapshots it; node 3 gets the snapshot alone: its
/// skeleton's reset prunes the paged state a page at a time, the old writes dying there.
#[test]
fn snapshot_root_reset_prunes_pages_spec_crdt_8() {
    let (c, _) = both(|w| {
        let (t, a) = (w.t, aks()[0].clone());
        let fill = w.commit(0, |m| { m.set(t, &a, &fat_map(ENTRIES, 0)).unwrap(); });
        let pk = packages(w, 0, &[fill]);
        w.lp.deliver(3, &pk[0]).unwrap();
        w.commit(0, |m| { m.replace(t, &a, &fat_map(ENTRIES, 1)).unwrap(); });
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        packages(w, 0, &[snap])
    });
    assert!(c.get("reset: by pages").is_some_and(|n| *n > 0) && c.get("apply: piece").is_some_and(|n| *n > 2), "{c:?}");
}

/// The page levels of the paged position in part `ai` of node `n`'s commit `c`, leaves included:
/// the links followed down from the root list's first, each page opened under its link's key.
fn wire_depth(w: &mut World, n: usize, c: &CommitId, ai: usize) -> usize {
    fn first(v: &Value) -> Option<osis_base::Link> {
        let Value::List(items) = v else { return None };
        match items.first() {
            Some(Value::Link(l)) => Some(**l),
            _ => items.iter().find_map(first),
        }
    }
    let e = &mut w.lp.peers[n].engine;
    let (_, record) = e.package_with_record(c).unwrap().unwrap();
    let delta = &record.parts.iter().find(|p| p.ai == ai).unwrap().delta;
    let mut at = first(&osis_base::decode(delta, &osis_base::Limits::DEFAULT).unwrap());
    let mut d = 0;
    while let Some(l) = at {
        d += 1;
        let blob = e.blob(&l.blob).unwrap().unwrap();
        let (_, pt) = osis_blob::open(&blob, &osis_crypto::Secret32::from_bytes(l.key)).unwrap();
        at = match osis_base::decode(&pt, &osis_base::Limits::DEFAULT).unwrap() {
            Value::List(items) => items.first().and_then(|x| if let Value::Link(l) = x { Some(**l) } else { None }),
            _ => None,
        };
    }
    d
}

/// §8 end to end at any depth: under small wire pages (`PageParams::set_test`, every page plug
/// of the nodes) a map whose compaction snapshot pages at four levels or more is written by node
/// 0 and delivered alone to node 3, which applies it page by page as the whole world does (the
/// same states, outcomes and judgments), and reads it whole and at single entries as node 0 does.
#[test]
fn deep_link_tree_compacts_syncs_and_reads_spec_crdt_8() {
    let small = osis_crdt::PageParams { target: 400, cut: osis_base::ChunkParams { min: 32, max: 160, mask_bits: 5 }, fanout: 3, ..osis_crdt::PageParams::FORMAT };
    let _pages = osis_crdt::PageParams::set_test(Some(small));
    let a = aks()[0].clone();
    let map = Value::Map((0..300).map(|i| (Value::Int(i), s(i as u64, 0))).collect());
    let (_, mut worlds) = both_in(
        |whole| {
            let (lp, t) = build(0);
            of(lp, t, whole)
        },
        |w| {
            let t = w.t;
            w.commit(0, |m| { m.set(t, &a, &map).unwrap(); });
            let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
            let ai = w.lp.peers[0].engine.package_with_record(&snap).unwrap().unwrap().1.parts[0].ai;
            let d = wire_depth(w, 0, &snap, ai);
            assert!(d >= 4, "four page levels or more: {d}");
            packages(w, 0, &[snap])
        },
    );
    let w = &mut worlds[0];
    let t = w.t;
    assert_eq!(w.lp.peers[3].engine.get(&t, &a).unwrap(), Some(map.clone()), "read whole");
    for i in [0i64, 151, 299] {
        let path = [PathSeg::Key(Value::Int(i))];
        assert_eq!(w.lp.peers[3].engine.get_at(&t, &a, &path).unwrap(), w.lp.peers[0].engine.get_at(&t, &a, &path).unwrap(), "entry {i}");
        assert_eq!(w.lp.peers[3].engine.get_at(&t, &a, &path).unwrap(), Some(s(i as u64, 0)));
    }
}

/// §3.2, §8 end to end: under small wire pages node 0 writes 100 commits, a key each, into one
/// map and snapshots it, so the snapshot's `Commits` table is paged (its root list links); node 3,
/// getting the snapshot alone (its table pages reached by sync's walk like any page), applies it
/// and reads what node 0 reads.
#[test]
fn paged_root_tables_compact_sync_and_read_spec_crdt_8() {
    let small = osis_crdt::PageParams { target: 400, cut: osis_base::ChunkParams { min: 32, max: 160, mask_bits: 5 }, fanout: 3, ..osis_crdt::PageParams::FORMAT };
    let _pages = osis_crdt::PageParams::set_test(Some(small));
    let (lp, t) = build(0);
    let mut w = of(lp, t, false);
    let a = aks()[0].clone();
    for k in 0..100u64 {
        w.commit(0, |m| { m.op(t, &a, PathOp { path: vec![PathSeg::Key(Value::Int(k as i64))], op: Op::Set(s(k, 0)) }).unwrap(); });
    }
    let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
    let (_, record) = w.lp.peers[0].engine.package_with_record(&snap).unwrap().unwrap();
    let Value::List(root) = osis_base::decode(&record.parts[0].delta, &osis_base::Limits::DEFAULT).unwrap() else { panic!() };
    assert!(matches!(&root[2], Value::List(ls) if !ls.is_empty() && ls.iter().all(|l| matches!(l, Value::Link(_)))), "Commits paged: {:?}", root[2]);
    let pk = packages(&mut w, 0, &[snap]);
    w.lp.deliver(3, &pk[0]).unwrap();
    assert_eq!(w.lp.peers[3].engine.get(&t, &a).unwrap(), w.lp.peers[0].engine.get(&t, &a).unwrap(), "read whole");
    assert_eq!(w.lp.peers[3].engine.get(&t, &a).unwrap().map(|v| if let Value::Map(m) = v { m.len() } else { 0 }), Some(100));
}

/// What a commit listener on node 3 hears of `big` once the keep bound (an hour after replaced)
/// passes (and as it applies), after node 3, holding node 0's fill, gets the snapshot of node 0's replace: the
/// replaced fill leaves history, and the snapshot's apply judged what it killed as a whole join
/// does, so the same is told whether the reset joined by pages or whole (notes/engine-paged.md).
#[test]
fn leaving_told_alike_paged_or_whole_spec_commits_5() {
    let told = |whole: bool| {
        let mut w = world(whole);
        let (t, a) = (w.t, aks()[0].clone());
        let fill = w.commit(0, |m| { m.set(t, &a, &fat_map(ENTRIES, 0)).unwrap(); });
        let pk = packages(&mut w, 0, &[fill]);
        w.lp.deliver(3, &pk[0]).unwrap();
        w.commit(0, |m| { m.replace(t, &a, &fat_map(ENTRIES, 1)).unwrap(); });
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        let pk = packages(&mut w, 0, &[snap]);
        w.lp.peers[3].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
        heard(&mut w, &a);
        w.lp.deliver(3, &pk[0]).unwrap();
        let applied = heard(&mut w, &a);
        w.lp.advance(2 * 3_600_000);
        w.lp.peers[3].tick().unwrap();
        let left = heard(&mut w, &a);
        assert!(left.contains(&fill), "{whole}: the replaced fill is told as it leaves: {left:?}");
        (applied, left)
    };
    assert_eq!(told(false), told(true));
}

/// As `leaving_told_alike_paged_or_whole_*`, where the snapshot node 3 gets, joined in pieces or whole, kills the fill's
/// first entry (node 0 overwrote it) in one page while it carries a write half an hour later
/// in another (past the last entry): the fill is told leaving at the same time whether the
/// snapshot joined in pieces or whole, though the piece killing it does not reach the later write.
#[test]
fn leaving_told_alike_paged_or_whole_later_write_elsewhere_spec_commits_5() {
    let entry = |k: u64, g: u64| PathOp { path: vec![PathSeg::Key(Value::Int(k as i64))], op: Op::Set(fat(k, g)) };
    let told = |whole: bool| {
        let mut w = world(whole);
        let (t, a) = (w.t, aks()[0].clone());
        let fill = w.commit(0, |m| { m.set(t, &a, &fat_map(ENTRIES, 0)).unwrap(); });
        let pk = packages(&mut w, 0, &[fill]);
        w.lp.deliver(3, &pk[0]).unwrap();
        w.commit(0, |m| { m.op(t, &a, entry(0, 1)).unwrap(); });
        w.lp.advance(1_800_000);
        w.commit(0, |m| { m.op(t, &a, entry(ENTRIES + 10, 1)).unwrap(); });
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        let pk = packages(&mut w, 0, &[snap]);
        w.lp.peers[3].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
        heard(&mut w, &a);
        osis_base::costs::take();
        w.lp.deliver(3, &pk[0]).unwrap();
        let joins = osis_base::costs::take().iter().find(|x| x.0 == "apply: join").map_or(0, |x| x.2);
        assert!(whole || joins > 1, "the snapshot joins in pieces where not whole: {joins}");
        let applied = heard(&mut w, &a);
        // an hour after the overwrite, then after the later write
        let mut at = Vec::new();
        for _ in 0..2 {
            w.lp.advance(3_600_000 / 2 + 60_000);
            w.lp.peers[3].tick().unwrap();
            at.push(heard(&mut w, &a));
        }
        w.lp.advance(3_600_000);
        w.lp.peers[3].tick().unwrap();
        at.push(heard(&mut w, &a));
        assert!(at.iter().any(|x| x.contains(&fill)), "{whole}: the replaced fill is told as it leaves: {at:?}");
        (applied, at)
    };
    assert_eq!(told(false), told(true));
}

/// Node 0 fills `mix` (a paged map under key `big`); node 1, holding the fill, fills `big`
/// again (writes on the fill's entries); a minute later node 0, not holding that, replaces `mix`
/// (a root reset: a new `big` record) and half an hour later adds an entry to the new `big`.
/// Node 3 holds the fill and gets the replace, the later entry, then node 1's fill, joined in
/// pieces or whole: node 1's writes die under the replace's reset, so node 1's fill is told
/// leaving history an hour after the replace (spec/commits.md §5), never an hour after the
/// later entry, which a whole join's reach takes in (the records of key `big`) and a piece's
/// does not.
#[test]
fn rekill_dated_by_its_superseder_paged_or_whole_spec_commits_5() {
    let told = |whole: bool| {
        let mut w = world(whole);
        let (t, a) = (w.t, aks()[1].clone());
        let fill = w.commit(0, |m| {
            m.set(t, &a, &fixed_fill(1, 0)).unwrap();
        });
        let pk = packages(&mut w, 0, &[fill]);
        for to in [1, 3] {
            w.lp.deliver(to, &pk[0]).unwrap();
        }
        let refill = w.commit(1, |m| {
            m.set(t, &a, &fixed_fill(1, 2)).unwrap();
        });
        w.lp.advance(60_000);
        let replace = w.commit(0, |m| {
            m.replace(t, &a, &fixed_fill(1, 1)).unwrap();
        });
        w.lp.advance(1_800_000);
        let later = w.commit(0, |m| {
            let path = vec![PathSeg::Key(Value::Str("big".into())), PathSeg::Key(Value::Int(ENTRIES as i64 + 10))];
            m.op(t, &a, PathOp { path, op: Op::Set(s(0, 3)) }).unwrap();
        });
        let mut pks = packages(&mut w, 0, &[replace, later]);
        pks.extend(packages(&mut w, 1, &[refill]));
        w.lp.peers[3].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
        let heard = |w: &mut World| heard_on(w, &a).contains(&refill);
        for pk in &pks {
            w.lp.deliver(3, pk).unwrap();
        }
        heard(&mut w);
        // an hour after the replace (half an hour from now), then after the later entry
        let mut at = Vec::new();
        for _ in 0..2 {
            w.lp.advance(1_800_000 + 60_000);
            at.push(heard(&mut w));
        }
        at
    };
    assert_eq!(told(false), vec![true, false], "in pieces: node 1's fill leaves an hour after the replace");
    assert_eq!(told(true), vec![true, false], "whole: node 1's fill leaves an hour after the replace");
}

/// What node 3's commit listener heard of `a`: the commits named.
fn heard(w: &mut World, a: &Ak) -> std::collections::BTreeSet<CommitId> {
    let mut out = std::collections::BTreeSet::new();
    for e in w.lp.peers[3].drain_events() {
        if let crate::Event::Commits(ch) = e {
            out.extend(ch.iter().filter(|x| x.ak == *a).map(|x| x.id));
        }
    }
    out
}

/// What node 3's commit listener hears of `a` on a tick (`heard`).
fn heard_on(w: &mut World, a: &Ak) -> std::collections::BTreeSet<CommitId> {
    w.lp.peers[3].tick().unwrap();
    heard(w, a)
}

/// Node 0 puts key `k` in `big`, then a second entry of `k` beside it (a concurrent put's
/// shape); node 1, holding only the first, removes `k`: a removal of the first entry alone. Node
/// 3 gets all three, joined in pieces or whole: the first is told leaving history an hour after
/// the removal, the second never (it still wins, spec/commits.md §5), though the removal's join
/// took the first entry's keyed record, and with it key `k`, out of the records it reaches
/// (`Fragment::reach_after`).
#[test]
fn removal_of_one_entry_of_a_key_kills_it_alone_spec_commits_5() {
    let key = || Value::Str("k".into());
    for whole in [false, true] {
        let mut w = world(whole);
        let (t, a) = (w.t, aks()[0].clone());
        let first = w.commit(0, |m| { m.set(t, &a, &Value::Map(osis_base::ValueMap::from([(key(), s(0, 0))]))).unwrap(); });
        let pk = packages(&mut w, 0, &[first]);
        w.lp.deliver(1, &pk[0]).unwrap();
        let second = w.commit(0, |m| { m.op(t, &a, PathOp { path: vec![PathSeg::Key(key())], op: Op::Put(s(0, 1)) }).unwrap(); });
        w.lp.advance(60_000);
        let removal = w.commit(1, |m| { m.op(t, &a, PathOp { path: Vec::new(), op: Op::Remove(key()) }).unwrap(); });
        let mut pks = packages(&mut w, 0, &[first, second]);
        pks.extend(packages(&mut w, 1, &[removal]));
        w.lp.peers[3].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
        for pk in &pks {
            w.lp.deliver(3, pk).unwrap();
        }
        assert_eq!(w.lp.peers[3].engine.get(&t, &a).unwrap(), Some(Value::Map(osis_base::ValueMap::from([(key(), s(0, 1))]))), "{whole}: the second entry reads");
        heard_on(&mut w, &a);
        w.lp.advance(3_600_000 + 60_000);
        let left = heard_on(&mut w, &a);
        assert!(left.contains(&first), "{whole}: the removed entry leaves history: {left:?}");
        assert!(!left.contains(&second), "{whole}: the entry still winning is never told leaving: {left:?}");
    }
}

/// Node 3 holds node 0's entry; node 1 overwrites it, ten minutes later node 2, holding that,
/// overwrites it again; node 3 gets the two overwrites in either order. The entry was replaced
/// by node 1's write (spec/commits.md §5), so in either order it is judged replaced then and is
/// told leaving history an hour after it, never earlier and alike in either order (its row is
/// its replaced-at: notes/engine-retention-dating.md Rows).
#[test]
fn overwrites_in_either_order_never_tell_early_spec_commits_5() {
    let at = |first_later: bool| {
        let mut w = world(false);
        let (t, a) = (w.t, aks()[0].clone());
        let entry = |g: u64| PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Set(s(0, g)) };
        let fill = w.commit(0, |m| { m.set(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Int(0), s(0, 0))]))).unwrap(); });
        let pk = packages(&mut w, 0, &[fill]);
        for to in [1, 2, 3] {
            w.lp.deliver(to, &pk[0]).unwrap();
        }
        w.lp.advance(60_000);
        let one = w.commit(1, |m| { m.op(t, &a, entry(1)).unwrap(); });
        let p1 = packages(&mut w, 1, &[one]);
        w.lp.deliver(2, &p1[0]).unwrap();
        w.lp.advance(600_000);
        let two = w.commit(2, |m| { m.op(t, &a, entry(2)).unwrap(); });
        let p2 = packages(&mut w, 2, &[two]);
        w.lp.peers[3].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
        let order = if first_later { [&p2[0], &p1[0]] } else { [&p1[0], &p2[0]] };
        for pk in order {
            w.lp.deliver(3, pk).unwrap();
        }
        let replaced = w.lp.peers[3].engine.replaced_at(&fill, &t, &a).unwrap();
        heard_on(&mut w, &a);
        // a minute short of an hour after node 1's write, then by minutes
        w.lp.advance(3_600_000 - 600_000 - 60_000);
        let mut told = None;
        for i in 0..14 {
            if heard_on(&mut w, &a).contains(&fill) {
                told = Some(i);
                break;
            }
            w.lp.advance(60_000);
        }
        (replaced, told)
    };
    let (in_order, reversed) = (at(false), at(true));
    assert_eq!(in_order.0, reversed.0, "judged replaced alike in either order");
    assert!(in_order.1.is_some_and(|i| i >= 1), "never told early: {in_order:?}");
    assert_eq!(in_order, reversed, "told alike in either order");
}

/// Node 3 holds node 0's fill; three hours later node 0 overwrites its first entry and
/// snapshots; node 3 gets the snapshot alone, which also carries the fill's other entries,
/// stamped at the fill. The fill was replaced by the overwrite, so it stays in history (an hour
/// after replaced) until an hour after the overwrite, joined in pieces or whole: a kill dates
/// by what superseded the dying write, never by the writes the snapshot only carries.
#[test]
fn killed_fill_leaves_an_hour_after_its_overwrite_spec_commits_5() {
    for whole in [false, true] {
        let mut w = world(whole);
        let (t, a) = (w.t, aks()[0].clone());
        let fill = w.commit(0, |m| { m.set(t, &a, &fat_map(ENTRIES, 0)).unwrap(); });
        let pk = packages(&mut w, 0, &[fill]);
        w.lp.deliver(3, &pk[0]).unwrap();
        w.lp.advance(3 * 3_600_000);
        w.commit(0, |m| { m.op(t, &a, PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Set(fat(0, 1)) }).unwrap(); });
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        let pk = packages(&mut w, 0, &[snap]);
        w.lp.peers[3].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
        w.lp.peers[3].drain_events();
        w.lp.deliver(3, &pk[0]).unwrap();
        let told = |w: &mut World| heard_on(w, &a).contains(&fill);
        told(&mut w);
        w.lp.advance(3_600_000 - 60_000);
        assert!(!told(&mut w), "{whole}: the fill is in history until an hour after its overwrite");
        w.lp.advance(2 * 60_000);
        assert!(told(&mut w), "{whole}: the fill leaves an hour after its overwrite");
    }
}

/// One commit with a paged map and a small entry in one aspect and a register in another,
/// into a node holding that map paged: the second wire page joins state pages the first
/// loaded, wrote and dropped.
#[test]
fn paged_and_unpaged_parts_spec_crdt_8() {
    let (c, _) = both(|w| {
        let (t, aks) = (w.t, aks());
        let first = w.commit(1, |m| { m.set(t, &aks[1], &fixed_fill(1, 0)).unwrap(); });
        let pk = packages(w, 1, &[first]);
        w.lp.deliver(3, &pk[0]).unwrap();
        let second = w.commit(1, |m| { m.set(t, &aks[1], &fixed_fill(1, 1)).unwrap().set(t, &aks[3], &Value::Int(1)).unwrap(); });
        packages(w, 1, &[second])
    });
    let (pieces, loads) = (c.get("apply: piece").copied().unwrap_or(0), c.get("state page load").copied().unwrap_or(0));
    assert!(pieces > 2 && loads > pieces, "{c:?}");
}

/// Node 3's own write on the purge-on-replace register is replaced by node 1's second register
/// write, which arrives without node 1's first (seed 33767158382 of the large differential): the
/// later write is an own whole replace, so node 3's cover passes the hole below it, listing node
/// 1's session to its counter 2. Applied whole, the part must stand as an own replace too: each
/// world makes every decision of a part's apply but the join itself in one place (`join_part`).
#[test]
fn own_replace_passes_hole_whole_or_paged_spec_crdt_8() {
    let script = |w: &mut World| {
        let (t, reg) = (w.t, aks()[3].clone());
        w.commit(3, |m| { m.set(t, &reg, &Value::Int(0)).unwrap(); });
        let mut last = None;
        for g in 1..=2 {
            let mut m = Mutation::new();
            m.set(t, &reg, &Value::Int(g)).unwrap();
            last = w.lp.peers[1].commit(m).unwrap();
        }
        packages(w, 1, &[last.unwrap()])
    };
    both(script);
    let mut w = world(false);
    let pks = script(&mut w);
    w.lp.deliver(3, &pks[0]).unwrap();
    let e = &w.lp.peers[3].engine;
    let me = e.me();
    let held = e.core.ix.snapshots.get(&(w.t, aks()[3].clone())).cloned().unwrap_or_default();
    let cover = held.iter().find(|(_, c, _, _, _)| e.core.ix.commits.get(c).is_some_and(|m| m.view.signer == me)).expect("node 3 covers its replaced write");
    assert!(cover.2.sources().any(|(_, f)| f == 2), "the cover passes the hole below node 1's replace: {:?}", cover.2);
}

/// Node 3 gets node 1's rewrite of a map held in a map entry, large enough to page, before the
/// fill creating that entry (seed 8130018 of the large differential): the state pages the map
/// under a record without its creation, which then arrives. The store must hold it as the
/// cache does (`seen` reloads), applied by pieces and whole: the fill paged itself (its pages
/// carry the creation), and small as a replace (a root reset: `join_reset`).
#[test]
fn entry_creation_after_its_paged_content_spec_crdt_5_6() {
    for replace in [false, true] {
        let (c, _) = both(|w| {
            let (t, a) = (w.t, aks()[1].clone());
            let mut m = Mutation::new();
            if replace {
                let small = Value::Map((0..10).map(|i| (Value::Int(i), s(i as u64, 0))).collect());
                m.replace(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), small), (Value::Str("x".into()), Value::Int(0))]))).unwrap();
            } else {
                m.set(t, &a, &fixed_fill(1, 0)).unwrap();
            }
            let fill = w.lp.peers[0].commit(m).unwrap().unwrap();
            let pk = packages(w, 0, &[fill]);
            w.lp.deliver(1, &pk[0]).unwrap();
            let rewrite = w.commit(1, |m| { m.set(t, &a, &fixed_fill(1, 1)).unwrap(); });
            let mut pks = packages(w, 1, &[rewrite]);
            pks.push(pk[0].clone());
            pks
        });
        assert_eq!(c.contains_key("reset: by pages"), replace, "{c:?}");
    }
}

/// Pages handed to a blob writer, each first changed by `mutate` (its index, its plaintext).
struct Mutating<'a, 'b> {
    inner: osis_blob::BlobWriter<'a>,
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
    forge_snapshot_in(w, by, ak, ts, f, mutate, false, None)
}

/// Makes a paged position's root list from the encoder's (`forge_snapshot_in`), putting link
/// pages through the closure it is given.
type Reroot<'a> = &'a dyn Fn(&mut dyn FnMut(&[osis_base::Link]) -> osis_base::Link, Vec<osis_base::Link>) -> Vec<osis_base::Link>;

/// `forge_snapshot`, an ephemeral commit if `memory` (its pages ephemeral blobs), the first paged
/// position's root list made by `reroot` if given.
#[allow(clippy::too_many_arguments)]
fn forge_snapshot_in(w: &mut World, by: usize, ak: &Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, mutate: &dyn Fn(usize, &mut Vec<u8>), memory: bool, reroot: Option<Reroot<'_>>) -> Package {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, writer_ctx};
    let t = w.t;
    let rec = w.lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
    let sec = w.lp.peers[0].engine.hand_secrets(&[rec]);
    let author = w.lp.peers[by].engine.me();
    let purge_by = osis_commit::retention::snapshot_purge_by(ak.as_str());
    let keys = osis_commit::delete_keys(&sec, &t, &purge_by).unwrap();
    let blind = [9u8; 16];
    let framing = osis_blob::Framing { thing: t, dedup: osis_commit::Secrets::dedup(&sec, &t).unwrap(), expiry: None, keys: keys.iter().map(|k| (k.level, k.verifying_key().unwrap())).collect(), class: if memory { osis_blob::Class::Ephemeral } else { osis_blob::Class::Durable } };
    let mut blobs = osis_blob::MemoryBlobs::default();
    let mut rng = osis_crypto::SeededRng::from_u64(0);
    let snap = osis_crdt::Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [7; 16], fragment: f, frontiers: Default::default() };
    let bytes = {
        let mut sink = Mutating { inner: osis_blob::BlobWriter::new(&framing, &mut blobs, &mut rng), n: 0, mutate };
        let mut bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Form::Commit, Kind::ContentSnapshot, ts, author, 0, 0), Some(&mut sink)).unwrap();
        if let Some(reroot) = reroot {
            let list = |ls: &[osis_base::Link]| osis_base::encode(&Value::List(ls.iter().map(|l| Value::link(*l)).collect()));
            let mut top = None;
            osis_base::visit_link_sites(&bytes, &osis_base::Limits::DEFAULT, &mut |s| {
                if let (osis_base::LinkSite::List { links, .. }, None) = (s, &top) {
                    top = Some(links);
                }
            })
            .unwrap();
            let top = top.expect("a paged position");
            let old = list(&top);
            let new = list(&reroot(&mut |ls| osis_crdt::PageSink::put(&mut sink.inner, &list(ls)).unwrap(), top));
            let at = bytes.windows(old.len()).position(|x| x == old).unwrap();
            bytes.splice(at..at + old.len(), new);
        }
        bytes
    };
    let mut aw = AspectWrite::new(t, ak.clone(), 0, 0, bytes);
    aw.purge_by = purge_by;
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, osis_commit::Path::default(), Form::Commit);
    cb.aspects.push(aw);
    cb.blind = Some(blind);
    if memory {
        cb.ephemeral = Some(osis_commit::EphClass::Plain);
    }
    let forge_key = w.lp.peers[by].engine.identity().signing().clone();
    let c = cb.build(&forge_key, &sec, &mut osis_commit::MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit;
    Package { id: c.id(), bytes: c.encode(), blobs: blobs.0.into_iter().collect() }
}

/// A session of a made-up node `src` (made-up sources sort by their bytes among the peers'
/// sessions, so a write by source 1 lands on the first page, by 0xfe on the last).
fn made_up(src: u8) -> osis_crdt::Source {
    osis_crdt::Source::session(osis_crdt::Session { node: Tid::from_bytes([src; 15]), nonce: [src; osis_crdt::SESSION_NONCE_LEN] })
}

/// A big map of `n` entries by made-up source `src`.
fn forged_map(ts: osis_base::Ts, n: u64, src: u8) -> osis_crdt::Fragment {
    let mut w = osis_crdt::Writer::new(ts, made_up(src), 1 << 40);
    let v = Value::Map((0..n).map(|i| (Value::Int(i as i64), fat(i, 0))).collect());
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
    let lim = osis_base::Limits::new(64, p.len());
    let mut v = osis_base::decode(p, &lim).unwrap();
    assert!(walk(&mut v), "no register in the page");
    *p = osis_base::encode(&v);
}

/// spec/crdt.md §8, spec/sync-compaction.md §2 caps: an ephemeral delta's page counts at most
/// `MAX_PAGE_ITEMS` items as a durable one's does: a received memory snapshot whose page holds
/// more (a string of that many bytes) is bad input at the engine, refused before it is decoded.
#[test]
fn ephemeral_page_past_items_refused_spec_crdt_8() {
    let mut w = world(false);
    let ak = Ak::new("t:big+.0").unwrap();
    // after the writer's grant: a snapshot stamped at its ms is ordered before it and waits
    w.lp.advance(1_000);
    let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
    let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
    let v = Value::Map(osis_base::ValueMap::from([(Value::Int(1), Value::Str("t".repeat(osis_base::format::MAX_PAGE_ITEMS + 1)))]));
    let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &v).unwrap();
    let pk = forge_snapshot_in(&mut w, 1, &ak, now, f, &|_, _| {}, true, None);
    assert_eq!(pk.blobs.len(), 1, "one page");
    let e = &mut w.lp.peers[3].engine;
    e.put_memory_blobs(pk.blobs.clone()).unwrap();
    let err = e.ingest_memory(&pk.bytes, u64::MAX).unwrap_err();
    assert_eq!(osis_base::Classified::class(&err), osis_base::ErrorClass::BadInput, "{err}");
    assert!(err.to_string().contains("MAX_PAGE_ITEMS"), "{err}");
    assert!(!e.holds_memory(&pk.id) && !e.memory_pending(&pk.id), "nothing kept");
}

/// spec/sync-compaction.md §2 caps, notes/ephemeral.md Bounds: a received memory commit waits for the blobs
/// its walk reaches (pages, value roots) only once its author's signature checks: a false one is bad input at
/// once, nothing kept waiting (charged against the sync ID's cap); a true one waits undecoded.
#[test]
fn memory_commit_waits_only_signed_spec_sync_9() {
    let mut w = world(false);
    let ak = Ak::new("t:big+.0").unwrap();
    let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
    let pk = forge_snapshot_in(&mut w, 1, &ak, now, forged_map(now, ENTRIES, 0x80), &|_, _| {}, true, None);
    assert!(pk.blobs.len() >= 2, "paged");
    let mut forged = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    forged.sigs = osis_commit::Sigs::signed(&pk.id, &osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32])));
    let e = &mut w.lp.peers[3].engine;
    let err = e.ingest_memory(&forged.encode(), u64::MAX).unwrap_err();
    assert_eq!(osis_base::Classified::class(&err), osis_base::ErrorClass::BadInput, "{err}");
    assert!(!e.memory_pending(&pk.id), "nothing kept waiting");
    osis_base::costs::take();
    let out = e.ingest_memory(&pk.bytes, u64::MAX).unwrap();
    assert_eq!(out, crate::Ingested::Pending(pk.id, crate::Reason::WaitBlobs));
    assert!(!osis_base::costs::take().iter().any(|x| x.0 == "examine"), "nothing of it examined");
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
        let (_, outs) = both(|w| {
            let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
            let later = osis_base::Ts::make(WallMs(w.lp.peers[0].engine.now().0 + 1_000), 0).unwrap();
            let mut f = forged_map(now, ENTRIES, 0x80);
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
        let (c, outs) = both(|w| {
            let t = w.t;
            let b = w.lp.peers[1].engine.me();
            let n = ENTRIES;
            let v = |g: u64| fat_map(n, g);
            let fill = w.commit(1, |m| { m.set(t, &a, &v(0)).unwrap(); });
            let pk = packages(w, 1, &[fill]);
            w.lp.deliver(3, &pk[0]).unwrap();
            w.lp.deliver(0, &pk[0]).unwrap();
            let h = osis_commit::CommitBlob::decode(&pk[0].bytes).unwrap().header;
            // node 1's writes again, the last `changed` values otherwise
            let mut wr = osis_crdt::Writer::new(h.ts, h.form.own_source(b, osis_base::CommitId([0; 32])), h.aspects[0].lo);
            let copy = Value::Map((0..n).map(|i| (Value::Int(i as i64), fat(i, if i + changed >= n { 1 } else { 0 }))).collect());
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
        assert!(!c.contains_key("rebuild"), "{name}: {c:?}");
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
        let (c, _) = both(|w| {
            let t = w.t;
            let mut r = Rng::new(0);
            let fill = w.commit(ROGUE, |m| { m.set(t, &mix, &fixed_fill(1, 0)).unwrap(); });
            let pk = packages(w, ROGUE, &[fill]);
            w.lp.deliver(1, &pk[0]).unwrap();
            let cur = w.lp.peers[1].engine.get(&t, &mix).unwrap();
            let edit = w.commit(1, |m| { m.set(t, &mix, &edited(cur, &mut r, 1)).unwrap(); });
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
    let mut w = world(false);
    let t = w.t;
    // node 3 holds two paged aspects; node 1 replaces both in one commit (a reset joined by pages)
    let mut m = Mutation::new();
    let set_of = |g: u64| Value::Set((0..ENTRIES).map(|i| fat(i, g)).collect());
    let map_of = |g: u64| fat_map(ENTRIES, g);
    m.set(t, &big, &map_of(0)).unwrap().set(t, &set, &set_of(0)).unwrap();
    let fill = w.lp.peers[1].commit(m).unwrap().unwrap();
    let pk = packages(&mut w, 1, &[fill]);
    w.lp.deliver(3, &pk[0]).unwrap();
    let next = w.commit(1, |m| { m.replace(t, &big, &map_of(1)).unwrap().replace(t, &set, &set_of(1)).unwrap(); });
    let pk = packages(&mut w, 1, &[next]).remove(0);
    // node 3 again, spilling every few KiB
    let p = &mut w.lp.peers[3];
    let mut cfg = crate::engine::Config::default();
    cfg.store.spill_bytes = 4096;
    p.restart_with(0, cfg.clone()).unwrap();
    let read = |p: &mut crate::local_peer::Peer| [&big, &set].map(|a| p.engine.state(&t, a).unwrap());
    let before = read(p);
    let rows = p.backend.dump();
    // two parts of a skeleton and a page each: fail in the first part's page, the second
    // part's skeleton, its page
    for k in [1usize, 2, 3] {
        p.engine.core.piece_fault = Some(k);
        let wrote = p.backend.faults().writes();
        let e = p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap_err();
        assert!(e.to_string().contains("piece fault"), "{e}");
        // spilled (the next transaction's start rolls the spills back: a debug check's, at once)
        assert!(p.backend.faults().writes() > wrote, "nothing spilled");
        assert_eq!(read(p), before, "after a fault at piece {k}");
    }
    p.engine.core.piece_fault = None;
    // the failed engine gone, the spilled rows are rolled back
    let spare = crate::Engine::create(Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), osis_store::BlobArea::memory().unwrap(), crate::engine::Config::default(), p.clock.clone(), Box::new(osis_crypto::SeededRng::from_u64(0))).unwrap();
    drop(std::mem::replace(&mut p.engine, spare));
    assert_eq!(p.backend.dump(), rows, "the backend's rows as before");
    p.restart_with(0, cfg).unwrap();
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
    both(|w| {
        let (t, a) = (w.t, aks()[1].clone());
        let fill = w.commit(0, |m| { m.set(t, &a, &fixed_fill(1, 0)).unwrap(); });
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

/// spec/commits.md §5 (when a body was replaced): when replaced, never of paging: a snapshot of a map whose `big` entry
/// holds a paged map streams `big`'s creation on every page's path. A root reset kills every
/// write of it, then a register write replaces the map. Each write died once, at the reset: the
/// snapshot is replaced there, as its fill delta is, not at the register write.
#[test]
fn death_on_many_pages_dated_once_spec_commits_5() {
    let mut w = world(false);
    let (t, a) = (w.t, aks()[1].clone());
    let big = fat_map(ENTRIES, 0);
    let fill = w.commit(0, |m| {
        m.set(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), big), (Value::Str("x".into()), Value::Int(0))]))).unwrap();
    });
    w.lp.advance(10);
    let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
    w.lp.advance(10);
    let reset = w.commit(0, |m| {
        m.replace(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("x".into()), Value::Int(1))]))).unwrap();
    });
    w.lp.advance(10);
    w.commit(0, |m| { m.replace(t, &a, &Value::Int(2)).unwrap(); });
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
    let (c, _) = both(|w| {
        let (t, a) = (w.t, aks()[1].clone());
        let fill = w.commit(1, |m| { m.set(t, &a, &fixed_fill(1, 0)).unwrap(); });
        let replace = w.commit(1, |m| { m.replace(t, &a, &fixed_fill(1, 1)).unwrap(); });
        let rewrite = w.commit(1, |m| { m.set(t, &a, &fixed_fill(1, 2)).unwrap(); });
        packages(w, 1, &[fill, rewrite, replace])
    });
    assert!(c.get("reset: laid out").is_some_and(|n| *n > 0), "{c:?}");
}

/// The rogue fills a paged set alone; node 3 gets the fill, then node 0's removal of the rogue:
/// the rebuild leaves the state absent, page by page as whole (seed 262094: the old in-place
/// un-merge kept an empty set while the set was not noted loaded whole).
#[test]
fn unmerge_emptying_every_page_leaves_none_spec_perm_5_2() {
    let (c, _) = both(|w| {
        let (t, set) = (w.t, aks()[2].clone());
        let fill = w.commit(ROGUE, |m| { m.set(t, &set, &fixed_fill(2, 0)).unwrap(); });
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
    let (c, _) = both(|w| {
        let (t, big) = (w.t, aks()[0].clone());
        let fill = w.commit(ROGUE, |m| { m.set(t, &big, &fixed_fill(0, 0)).unwrap(); });
        let pk = packages(w, ROGUE, &[fill]);
        w.lp.deliver(1, &pk[0]).unwrap();
        let rewrite = w.commit(1, |m| { m.set(t, &big, &fixed_fill(0, 1)).unwrap(); });
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
    let (c, _) = both(|w| {
        let (t, set) = (w.t, aks()[2].clone());
        let mut ws = [1usize, 2, 3];
        ws.sort_by_key(|i| w.lp.peers[*i].engine.me());
        let (x, y) = (ws[0], ws[2]);
        let mut fills = Vec::new();
        for (by, g) in [(x, 0), (y, 1)] {
            let mut m = Mutation::new();
            m.set(t, &set, &fixed_fill(2, g)).unwrap();
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
        p.restart(0).unwrap();
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
    let (c, _) = both(|w| {
        let (t, mix) = (w.t, aks()[1].clone());
        let fill = w.commit(ROGUE, |m| { m.set(t, &mix, &fixed_fill(1, 0)).unwrap(); });
        let pk = packages(w, ROGUE, &[fill]);
        w.lp.deliver(1, &pk[0]).unwrap();
        // entries of node 1's own, superseding none of the rogue's writes (else a rebuild)
        let mut v = w.lp.peers[1].engine.get(&t, &mix).unwrap().unwrap();
        if let Value::Map(m) = &mut v
            && let Some(Value::Map(big)) = m.get_mut(&Value::Str("big".into()))
        {
            big.extend((0..ENTRIES / 2).map(|i| (Value::Int((ENTRIES + i) as i64), fat(i, 1))));
        }
        let rewrite = w.commit(1, |m| { m.set(t, &mix, &v).unwrap(); });
        // something else left in the state (else it goes whole)
        let other = w.commit(0, |m| {
            m.op(t, &mix, PathOp { path: vec![PathSeg::Key(Value::Str("y".into()))], op: Op::Set(Value::Int(1)) }).unwrap();
        });
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
    let (c, _) = both(|w| {
        let (t, mix) = (w.t, aks()[1].clone());
        let fill = w.commit(1, |m| {
            m.set(t, &mix, &Value::Map(osis_base::ValueMap::from([(Value::Str("big".into()), fat_map(ENTRIES, 0))]))).unwrap();
        });
        let put = w.commit(ROGUE, |m| {
            m.op(t, &mix, PathOp { path: vec![PathSeg::Key(Value::Str("y".into()))], op: Op::Set(Value::Int(1)) }).unwrap();
        });
        let demote = demote_peer(w, ROGUE);
        let mut pks = packages(w, 1, &[fill]);
        pks.extend(packages(w, ROGUE, &[put]));
        for pk in &pks {
            w.lp.deliver(3, pk).unwrap();
        }
        let p = &mut w.lp.peers[3];
        p.restart(0).unwrap();
        packages(w, 0, &[demote])
    });
    assert!(c.get("rejudge: rebuild").is_some_and(|n| *n > 0), "{c:?}");
}

/// Retention reads a paged body a piece at a time (issues/durable-decode-bound.md step 4): node
/// 3 holds a fill of a map in a map entry (its creation in the skeleton, its writes in pages)
/// and node 0's snapshot of it, drops the fill as covered, then gets node 0's purge of it: the
/// snapshot carrying purged values is stripped, and the fill's leftover comes from the coverer's
/// pieces. By pieces and whole alike, the streamed readers checked against the whole ones on
/// the way (`retention::oracle`: `covered`, `live`).
#[test]
fn covered_paged_fill_purged_spec_commits_5() {
    let a = aks()[1].clone();
    let mut seen = Vec::new();
    for whole in [false, true] {
        let mut w = world(whole);
        let t = w.t;
        let fill = w.commit(0, |m| { m.set(t, &a, &fixed_fill(1, 0)).unwrap(); });
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        let pks = packages(&mut w, 0, &[fill, snap]);
        let mut m = Mutation::new();
        m.set(t, &aks()[3], &Value::Int(9)).unwrap();
        m.purge_commit(fill, t, a.clone());
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

// notes/decode-bounds.md (a node holds a bounded piece of what it reads for itself), spec/wire.md
// §12: finding a paged state's tree roots holds its skeleton and a page with its keys' records at
// a time (the roots as the whole read's), and judging a paged body covered holds a group of its
// pages about the two parts' root bytes: both flat in the size, never the whole.
#[test]
fn internal_reads_hold_a_piece_at_a_time_spec_wire_12() {
    let a = aks()[0].clone();
    let peaks = |n: u64| {
        let mut w = world(false);
        let t = w.t;
        let Value::Map(mut v) = fat_map(n, 0) else { unreachable!() };
        // two large values: links the roots find
        for i in 0..2u8 {
            v.insert(Value::Str(format!("large-{i}")), Value::Bytes((0..osis_base::format::CHUNK_THRESHOLD + 100).map(|j| (j * 7 + usize::from(i)) as u8).collect()));
        }
        let fill = w.commit(0, |m| { m.set(t, &a, &Value::Map(v)).unwrap(); });
        let snap = w.lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        let e = &mut w.lp.peers[0].engine;
        let whole = e.state(&t, &a).unwrap().unwrap().approx_bytes() as u64;
        let body = e.run(|tx| crate::apply::held_fragment(tx, &fill, 0)).unwrap().unwrap().approx_bytes() as u64;
        // as after a restart: nothing of the state loaded, no roots counted
        e.core.states.clear();
        e.core.pages.clear();
        e.core.tree_roots = osis_base::memo::Memo::new("tree roots");
        e.core.tree_reach.clear();
        e.core.covers = osis_base::memo::Memo::new("covered");
        osis_base::costs::take();
        e.tree_refs(&t, &std::collections::BTreeSet::new()).unwrap();
        assert!(!e.core.states.contains_key(&(t, a.clone())), "the roots left none of the state loaded");
        assert_eq!(e.covered(&snap, &fill, &t, &a).unwrap(), Some(true));
        let c: BTreeMap<_, _> = osis_base::costs::take().into_iter().map(|x| (x.0, x.2)).collect();
        let (roots, group) = (c.get("paged state: piece held").copied().unwrap_or(0), c.get("covered: body group held").copied().unwrap_or(0));
        assert!(roots > 0 && group > 0, "n={n}: {c:?}");
        [roots, whole, group, body]
    };
    let (small, big) = (peaks(ENTRIES), peaks(4 * ENTRIES));
    let says = format!("[state piece held, state, body group held, body]: {small:?} at {ENTRIES} entries, {big:?} at {}", 4 * ENTRIES);
    // a state page is about `PAGE_BYTES`; a body's wire pages vary with their content-defined cuts
    assert!(big[0] <= 2 * small[0] && big[0] * 8 < big[1], "a state piece, flat in the size: {says}");
    assert!(big[2] * 3 < big[3], "a body group, far below the body: {says}");
}

/// spec/crdt.md §4.1, §4.8, §8: a paged set of references nested in a map entry (`mix`, history
/// kept); node 1 forges snapshots carrying copies of the set's lowest and highest elements'
/// writes, each holding one new, greater reference (copy order picks it: two elements then read
/// as one value). Node 3, holding the fill, applies them page by page as it does whole: the
/// set's reach takes the references the state's copies at the forged dots name (the reference
/// index moves off the replaced ones), and nothing fails.
#[test]
fn forged_copies_in_a_paged_nested_set_apply_as_whole_spec_crdt_4_1() {
    let (c, outs) = both(|w| {
        let (t, a) = (w.t, aks()[1].clone());
        let weak = |i: u64| Value::Weak(Tid::from_bytes({
            let mut b = [0u8; 15];
            b[7..].copy_from_slice(&i.to_be_bytes());
            b
        }));
        let n = 4000;
        let fill = w.commit(0, |m| {
            m.set(t, &a, &Value::Map(osis_base::ValueMap::from([(Value::Str("refs".into()), Value::Set((1..=n).map(weak).collect())), (Value::Str("x".into()), Value::Int(1))]))).unwrap();
        });
        let pk = packages(w, 0, &[fill]);
        w.lp.deliver(1, &pk[0]).unwrap();
        w.lp.deliver(3, &pk[0]).unwrap();
        let st = w.lp.peers[1].engine.stored_state(&t, &a).unwrap().unwrap();
        // the set's elements: every write but the entry creations, lowest and highest counter
        let mut ws: Vec<(osis_crdt::Dot, osis_base::Ts)> = st.writes().into_iter().filter_map(|(d, ts)| Some((d, ts?))).collect();
        ws.sort_by_key(|(d, _)| d.ctr);
        let (lo, hi) = (ws[ws.len() - n as usize].clone(), ws[ws.len() - 1].clone());
        let copy = |(d, ts): &(osis_crdt::Dot, osis_base::Ts), v: Value| {
            let mut b = osis_crdt::DeltaBuilder::new(&st, osis_crdt::Writer::new(*ts, d.src.clone(), d.ctr));
            b.apply(&PathOp { path: vec![PathSeg::Key(Value::Str("refs".into()))], op: Op::Add(v) }, &osis_crdt::AnyView).unwrap();
            b.finish().unwrap().0
        };
        let mut out = Vec::new();
        for (x, v) in [(&lo, weak(n + 1)), (&hi, weak(n + 1))] {
            w.lp.advance(1_000);
            let now = osis_base::Ts::make(w.lp.peers[1].engine.now(), 0).unwrap();
            out.push(forge_snapshot(w, 1, &a, now, copy(x, v), &|_, _| {}));
        }
        assert!(out[0].blobs.is_empty(), "a copy is one element: unpaged");
        out
    });
    assert!(outs.iter().all(|o| o.contains("Applied")), "{outs:?}");
    assert!(c.get("state page load").is_some_and(|n| *n > 0) && c.get("apply: piece").is_some_and(|n| *n > 0), "the nested set paged: {c:?}");
}

/// The link pages of a paged position under `top` as delivered in `pk`, followed down the first
/// link: its levels, leaves included.
fn levels_in(pk: &Package, top: &[osis_base::Link]) -> usize {
    let blobs: BTreeMap<osis_base::BlobId, &Vec<u8>> = pk.blobs.iter().map(|(b, x)| (*b, x)).collect();
    let (mut at, mut d) = (top.first().copied(), 0);
    while let Some(l) = at {
        d += 1;
        let (_, pt) = osis_blob::open(blobs[&l.blob], &osis_crypto::Secret32::from_bytes(l.key)).unwrap();
        at = match osis_base::decode(&pt, &osis_base::Limits::DEFAULT).unwrap() {
            Value::List(items) => items.first().and_then(|x| if let Value::Link(l) = x { Some(**l) } else { None }),
            _ => None,
        };
    }
    d
}

/// Node 3 gets commit `pk` without its blobs, then each round the blobs its walk names
/// (`Engine::blob_wants`, as node-sync fetches them) from `pk`, until it waits for nothing: the
/// rounds, the blobs delivered, and what node 3 reads of `a` then.
fn fetch_rounds(w: &mut World, pk: &Package, a: &Ak) -> (usize, usize, Option<Value>) {
    let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
    let t = w.t;
    let e = &mut w.lp.peers[3].engine;
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    let waits = |e: &mut crate::Engine| e.pending().into_iter().find(|x| x.0 == pk.id).map(|x| x.1);
    assert_eq!(waits(e), Some(crate::Reason::WaitBlobs), "its part waits for its pages");
    let (mut rounds, mut blobs) = (0, 0);
    loop {
        let wants = e.blob_wants().unwrap();
        let give: Vec<_> = wants.missing.iter().filter_map(|b| held.get(b).map(|x| (*b, x.clone()))).collect();
        if give.is_empty() {
            break;
        }
        assert!(rounds < 100, "rounds bounded");
        rounds += 1;
        blobs += give.len();
        if let Err(err) = e.put_blobs(give) {
            assert_ne!(osis_base::Classified::class(&err), osis_base::ErrorClass::Local, "{err}");
        }
    }
    assert_eq!(waits(e), None, "applied or refused, not left waiting");
    (rounds, blobs, e.get(&t, a).unwrap())
}

/// spec/sync-streams.md (page discovery), spec/wire.md §6 (page by page):
/// sync's walk applies the tree rule (`osis_crdt::LinkTree`) as pages come, so fetch rounds stay
/// within about log2 of the pages delivered whatever the shape. Under small pages (fan-out 3,
/// and 2: a binary tree, what a writer grinding link hashes gets): honest trees take a round per
/// level and apply; a chain of 1,000 single-link pages is refused at its first page; a right
/// spine of single-link pages beside an honest subtree, at the subtree's leaf depth (the
/// subtree's pages delivered); a level-2 page off its level's end holding one link, in round 2.
/// Every refused shape delivered whole to nodes 1 and 2 is bad input there, no local error, and
/// every node reads the aspect alike. Fails without the tree rule (the chain takes a round per
/// page), and with the decoder stopping at a missing page (the level-2 shape is left waiting for
/// pages the walk no longer fetches).
#[test]
fn hostile_link_trees_cost_rounds_by_pages_spec_wire_6() {
    let a = aks()[0].clone();
    let fan = |fanout| osis_crdt::PageParams { target: 400, cut: osis_base::ChunkParams { min: 32, max: 160, mask_bits: 5 }, fanout, ..osis_crdt::PageParams::FORMAT };
    // leaf pages larger than a link: a few fit the root list
    let wide = osis_crdt::PageParams { cut: osis_base::ChunkParams { min: 128, max: 512, mask_bits: 7 }, ..fan(3) };
    let _pages = osis_crdt::PageParams::set_test(Some(fan(3)));
    // a world built under the pages it runs with (its states' link pages are read by that rule)
    let world_at = |params: osis_crdt::PageParams| {
        let (lp, t) = LocalPeer::cached(&format!("apply::tests_paged::world {params:?}"), || build(0));
        of(lp, t, false)
    };
    let map = |n: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    let forge = |w: &mut World, n: u64, reroot: Option<Reroot<'_>>| {
        // stamped after the write recording the step whose keys it lists (spec/crypto.md §7)
        w.lp.advance(1);
        let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
        let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
        let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &map(n)).unwrap();
        forge_snapshot_in(w, 0, &a, now, f, &|_, _| {}, false, reroot)
    };
    let top = |pk: &Package| {
        let delta = &osis_commit::CommitBlob::decode(&pk.bytes).unwrap().parts[0].delta;
        let mut top = Vec::new();
        osis_base::visit_link_sites(delta, &osis_base::Limits::DEFAULT, &mut |s| {
            if let (osis_base::LinkSite::List { links, .. }, true) = (s, top.is_empty()) {
                top = links;
            }
        })
        .unwrap();
        top
    };
    // honest trees: a round per level
    let mut depths = Vec::new();
    for (params, n) in [(wide, 12), (fan(3), 10), (fan(3), 20), (fan(2), 300)] {
        let fanout = params.fanout;
        let _params = osis_crdt::PageParams::set_test(Some(params));
        let mut w = world_at(params);
        let pk = forge(&mut w, n, None);
        let levels = levels_in(&pk, &top(&pk));
        let (rounds, blobs, read) = fetch_rounds(&mut w, &pk, &a);
        assert!(read == Some(map(n)) && rounds == levels, "fan-out {fanout}, {n} entries: {rounds} rounds, {levels} levels");
        if fanout == 2 {
            assert!(1usize << (levels - 2) <= blobs, "binary: {levels} levels over {blobs} pages");
        }
        depths.push(levels);
    }
    assert!(depths.contains(&2) && depths.contains(&3) && depths.iter().any(|d| *d >= 4), "{depths:?}");
    // a root list of several links (each about 230 bytes with its delete keys)
    let roomy = osis_crdt::PageParams { target: 1000, ..fan(3) };
    let _roomy = osis_crdt::PageParams::set_test(Some(roomy));
    let chain: Reroot<'_> = &|put, top| {
        let mut l = put(&top);
        for _ in 0..1_000 {
            l = put(&[l]);
        }
        vec![l]
    };
    // beside the first of the honest root list's link pages (closed by the rule), a spine of 50
    let spine: Reroot<'_> = &|put, top| {
        let mut l = put(&top[1..]);
        for _ in 0..50 {
            l = put(&[l]);
        }
        vec![top[0], l]
    };
    // the honest root's first link, then a link page of a one-link page and the rest
    let level2: Reroot<'_> = &|put, top| {
        let (y, z) = (put(&top[1..2]), put(&top[2..]));
        vec![top[0], put(&[y, z])]
    };
    for (name, reroot, want_rounds) in [("chain", chain, 1), ("spine", spine, 0), ("level 2", level2, 2)] {
        let mut w = world_at(roomy);
        let honest = forge(&mut w, 300, None);
        let ht = top(&honest);
        assert!(ht.len() >= 3, "{name}: the honest root list holds three links or more");
        let levels = levels_in(&honest, &ht);
        let pk = forge(&mut w, 300, Some(reroot));
        let (rounds, blobs, read) = fetch_rounds(&mut w, &pk, &a);
        assert_eq!(read, None, "{name}: refused");
        let want = if want_rounds == 0 { levels } else { want_rounds };
        assert_eq!(rounds, want, "{name}: rounds ({blobs} blobs; honest {levels} levels)");
        assert!(blobs < honest.blobs.len(), "{name}: {blobs} blobs, fewer than the honest tree's {}", honest.blobs.len());
        for to in [1, 2] {
            if let Err(err) = w.lp.deliver(to, &pk) {
                assert_ne!(osis_base::Classified::class(&err), osis_base::ErrorClass::Local, "{name}: node {to}: {err}");
            }
        }
        let t = w.t;
        let reads: Vec<Option<Value>> = w.lp.peers.iter_mut().map(|p| p.engine.get(&t, &a).unwrap()).collect();
        assert!(reads.iter().all(|r| *r == reads[0]), "{name}: all read alike: {reads:?}");
    }
}

/// Small pages: a 400-byte target, leaf pages cut at 32 to 160 bytes, fan-out 3.
fn small_pages() -> osis_crdt::PageParams {
    osis_crdt::PageParams { target: 400, cut: osis_base::ChunkParams { min: 32, max: 160, mask_bits: 5 }, fanout: 3, ..osis_crdt::PageParams::FORMAT }
}

/// A copy of the shared world built under `params` (its states' pages read by that rule).
fn world_under(params: osis_crdt::PageParams) -> World {
    let (lp, t) = LocalPeer::cached(&format!("apply::tests_paged::world {params:?}"), || build(0));
    of(lp, t, false)
}

/// Node 3 gets commit `pk` without its blobs, then each round the blobs its walk names
/// (`Engine::blob_wants`) from `pk` (`one`: only the first of them, as a server trickling them
/// would), until the walk names none it lacks; then every blob of `pk` (large values' chunks,
/// fetched lazily). The rounds, and whether the commit still waited when the walk ran dry.
fn walk_fill(w: &mut World, pk: &Package, one: bool) -> (usize, bool) {
    let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
    let e = &mut w.lp.peers[3].engine;
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    let mut rounds = 0;
    loop {
        let wants = e.blob_wants().unwrap();
        let mut give: Vec<_> = wants.missing.iter().filter_map(|b| held.get(b).map(|x| (*b, x.clone()))).collect();
        if give.is_empty() {
            break;
        }
        if one {
            give.truncate(1);
        }
        assert!(rounds < 5_000, "rounds bounded");
        rounds += 1;
        e.put_blobs(give).unwrap();
    }
    let waits = e.pending().into_iter().any(|x| x.0 == pk.id);
    e.put_blobs(pk.blobs.clone()).unwrap();
    (rounds, waits)
}

/// spec/sync-streams.md (page discovery), spec/wire.md §6: every value an honest writer commits,
/// paged small, is fetched whole by sync's walk alone and applies: the reference model's bulk
/// values over every encoding (nested maps, sets, lists, structs, enums), and large values
/// standing alone, in a list of links in a register, and as one-link lists in the entries of a
/// paged map (the walk takes a list of links for a position's tree; their blobs are tree roots).
#[test]
#[ignore = "property"]
fn honest_values_sync_through_the_fetch_walk_plain_spec_wire_6() {
    use crdt_model::r#gen::{Rng as MRng, bulk_value, kitchen_sink};
    let params = small_pages();
    let a = aks()[1].clone();
    let big = |i: u64| Value::Str(format!("{:x}", i % 16).repeat(osis_base::format::CHUNK_THRESHOLD + 1 + i as usize));
    let name = "apply::tests_paged::honest_values_sync_through_the_fetch_walk_plain_spec_wire_6";
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_HONEST_PAGES_START", "OSIS_HONEST_PAGES_SEEDS", 0..8);
    let replay = |s: u64| format!("OSIS_HONEST_PAGES_START={s} OSIS_HONEST_PAGES_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact {name}");
    seeds.run(name, replay, |seed| {
        // per seed thread: the page parameters are the thread's
        let _pages = osis_crdt::PageParams::set_test(Some(params));
        let mut r = MRng(seed + 1);
        let generated = osis_base::decode(&bulk_value(&mut r, &kitchen_sink(), 0).canonical(), &osis_base::Limits::DEFAULT).unwrap();
        let mut v = vec![(Value::Str("gen".into()), generated)];
        // large values in two of any eight consecutive seeds, sized by the seed's place among
        // them (an offset seed's own number would size a value past memory)
        let k = seed % 8;
        if k < 2 {
            v.push((Value::Str("lone".into()), big(k * 100)));
            v.push((Value::Str("list".into()), Value::List(vec![big(k * 100 + 1), big(k * 100 + 2)])));
            v.push((Value::Str("map".into()), Value::Map((0..12).map(|i| (Value::Int(i), Value::List(vec![big(k * 100 + 10 + i as u64)]))).collect())));
        }
        let v = Value::Map(v.into_iter().collect());
        let mut w = world_under(params);
        let t = w.t;
        let c = w.commit(0, |m| { m.set(t, &a, &v).unwrap(); });
        let pk = w.lp.peers[0].engine.package(&c).unwrap().unwrap();
        let (rounds, waits) = walk_fill(&mut w, &pk, false);
        assert!(!waits, "seed {seed}: left waiting after {rounds} rounds");
        let want = w.lp.peers[0].engine.get(&t, &a).unwrap();
        assert!(want.is_some() && w.lp.peers[3].engine.get(&t, &a).unwrap() == want, "seed {seed}: node 3 reads what node 0 does");
        // every value pages under the small pages (the generated one alone too): the walk takes
        // more than one round
        assert!(rounds > 1, "seed {seed}: fetched in one round, nothing paged");
    });
}

/// spec/sync-streams.md (page discovery), spec/crdt.md §3.3 rule 7: the walk follows paged
/// positions as deep as a writer may nest them. A map paged at every level, nested as deep as
/// the writer takes (`MAX_VALUE_DEPTH`), is fetched whole by the walk alone (a round per level
/// at least) and applies; one level deeper the writer refuses it. Fails with the walk's nesting
/// cut below `MAX_VALUE_DEPTH` (the commit left waiting for pages nobody fetches).
#[test]
fn deepest_nested_pages_sync_through_the_fetch_walk_spec_wire_6() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let a = aks()[1].clone();
    // a level of a few long entries pages as well as many short ones, at a fraction of the
    // entries a whole-state check reads at every depth
    let level = |inner: Option<Value>, d: u64| Value::Map((0..4).map(|i| (Value::Int(i as i64), Value::Str(format!("{:?}", s(i, d)).repeat(5)))).chain(inner.map(|v| (Value::Str("n".into()), v))).collect());
    let nested = |d: u64| (0..d).fold(None, |acc, i| Some(level(acc, i))).unwrap();
    let mut w = world_under(params);
    let t = w.t;
    let mut deepest = None;
    for d in (40..=osis_base::format::MAX_VALUE_DEPTH as u64 + 2).rev() {
        let mut m = Mutation::new();
        if m.set(t, &a, &nested(d)).is_ok()
            && let Ok(Some(c)) = w.lp.peers[0].commit(m)
        {
            deepest = Some((d, c));
            break;
        }
    }
    let (d, c) = deepest.expect("a nesting the writer takes");
    assert!(d + 1 >= osis_base::format::MAX_VALUE_DEPTH as u64, "nested {d} deep");
    let pk = w.lp.peers[0].engine.package(&c).unwrap().unwrap();
    let (rounds, waits) = walk_fill(&mut w, &pk, false);
    assert!(!waits && rounds as u64 >= d, "{d} levels: {rounds} rounds, waits {waits}");
    assert_eq!(w.lp.peers[3].engine.get(&t, &a).unwrap(), Some(nested(d)));
}

/// How node 3 is given the blobs of the commits it waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Deliver {
    /// Every blob its walks want, a round at a time.
    Rounds,
    /// One wanted blob per delivery (a server trickling them).
    One,
    /// Every blob of the package one per delivery, last first.
    Reverse,
    /// Every blob of the package one per delivery, first first (leaves before the link pages above).
    Forward,
    /// One wanted blob of the first commit, then one of the second, then one blob nobody wants.
    Interleaved,
}

/// A paged map of `n` entries, generation `g`, written by node 0 on aspect `a`, as a package.
fn paged_package(w: &mut World, a: &Ak, n: u64, g: u64) -> Package {
    let t = w.t;
    let c = w.commit(0, |m| { m.set(t, a, &Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, g))).collect())).unwrap(); });
    w.lp.peers[0].engine.package(&c).unwrap().unwrap()
}

/// What node 3 did to fill paged commits of `n` entries given as `how`: (blobs delivered, pages
/// the decoders read, blobs the walks opened, examinations, signature checks).
fn fill_costs(n: u64, how: Deliver) -> (usize, u64, u64, u64, u64) {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let [_, mix, set, _] = aks();
    let mut w = world_under(params);
    let mut pks = vec![paged_package(&mut w, &mix, n, 0)];
    if how == Deliver::Interleaved {
        pks.push(paged_package(&mut w, &set, n, 1));
    }
    // a commit node 3 never sees: its blobs are wanted by nothing there
    let other = paged_package(&mut w, &mix, n, 2);
    let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pks.iter().flat_map(|p| p.blobs.iter().cloned()).collect();
    let e = &mut w.lp.peers[3].engine;
    for pk in &pks {
        e.ingest(&pk.bytes, Vec::new()).unwrap();
    }
    osis_base::costs::take();
    let mut given = 0;
    let put = |e: &mut crate::Engine, given: &mut usize, b: Vec<(osis_base::BlobId, Vec<u8>)>| {
        *given += b.len();
        e.put_blobs(b).unwrap();
    };
    match how {
        Deliver::Rounds | Deliver::One | Deliver::Interleaved => {
            let mut unrelated = other.blobs.iter();
            for round in 0.. {
                assert!(round < 50_000, "rounds bounded");
                let wants = e.blob_wants().unwrap();
                let mut give: Vec<_> = wants.missing.iter().filter_map(|b| held.get(b).map(|x| (*b, x.clone()))).collect();
                if give.is_empty() {
                    break;
                }
                match how {
                    Deliver::Rounds => put(e, &mut given, give),
                    Deliver::One => put(e, &mut given, vec![give.swap_remove(0)]),
                    _ => {
                        // one of each commit's wants, then an unrelated blob
                        for pk in &pks {
                            if let Some(b) = give.iter().position(|(b, _)| pk.blobs.iter().any(|x| x.0 == *b)) {
                                put(e, &mut given, vec![give.swap_remove(b)]);
                            }
                        }
                        if let Some(b) = unrelated.next() {
                            put(e, &mut given, vec![b.clone()]);
                        }
                    }
                }
            }
        }
        Deliver::Reverse => pks[0].blobs.iter().rev().for_each(|b| put(e, &mut given, vec![b.clone()])),
        Deliver::Forward => pks[0].blobs.iter().for_each(|b| put(e, &mut given, vec![b.clone()])),
    }
    let costs = osis_base::costs::take();
    let get = |k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
    for pk in &pks {
        assert!(!e.pending().iter().any(|x| x.0 == pk.id), "{how:?}: applied, not left waiting");
    }
    let t = w.t;
    let want = Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    assert_eq!(w.lp.peers[3].engine.get(&t, &mix).unwrap(), Some(want), "{how:?}: node 3 reads the map");
    (given, get("pages read"), get("reach: blobs opened"), get("examine"), get("examine: signature"))
}

/// notes/sync-facade.md (Blob waits), spec/commits.md §4: filling a paged commit costs each
/// page it delivers a bounded number of reads, whatever the batching a server picks: given a
/// round at a time, one page per delivery (a server trickling them), every blob last first or
/// first first, and interleaved with the pages of another waiting commit and with blobs nothing
/// waits for. At n and 10n entries: pages read by the decoders and blobs opened by the walks
/// within a constant per page delivered, and the commit examined (decoded, its signature
/// checked) once, not once per page. Fails with every waiting commit
/// examined at each blob stored (quadratic one page at a time).
#[test]
fn a_trickled_fill_reads_each_page_a_bounded_number_of_times_spec_commits_4() {
    let mut out = Vec::new();
    for how in [Deliver::Rounds, Deliver::One, Deliver::Reverse, Deliver::Forward, Deliver::Interleaved] {
        for n in [60u64, 600] {
            let (given, read, opened, examines, sigs) = fill_costs(n, how);
            out.push((how, n, given, read, opened, examines, sigs));
        }
    }
    eprintln!("(delivery, entries, blobs given, pages read, walk opens, examines, signature checks): {out:#?}");
    // per page: one walk step (and the compaction trigger's weighing after), three reads (the
    // checked decode once it lacks nothing, the streamed apply, and the body's writes noted for
    // dating: `mix` keeps history, `retention::bounds::held_writes`); per commit one
    // examination
    for (how, n, given, read, opened, examines, sigs) in &out {
        let (given, commits) = (*given as u64, if *how == Deliver::Interleaved { 2 } else { 1 });
        assert!(*read <= 3 * given && *opened <= 2 * given, "{how:?} {n}: reads per blob delivered bounded: {out:?}");
        assert!(*examines <= commits && *sigs <= commits, "{how:?} {n}: examined once: {out:?}");
    }
}

/// spec/commits.md §4, notes/sync-facade.md (Blob waits): a blob arriving costs only the
/// waits that want it. With 1 and 10 commits waiting on node 3 for disjoint pages: a blob
/// nothing waits for opens nothing, takes no walk on and examines nothing; a page one of them
/// wants takes exactly that one's walk on (examining nothing while it still lacks pages). Fails
/// with every waiting commit examined at each blob stored.
#[test]
fn a_blob_costs_only_the_waits_that_want_it_spec_commits_4() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let [_, mix, _, _] = aks();
    for k in [1u64, 10] {
        let mut w = world_under(params);
        let pks: Vec<Package> = (0..k).map(|g| paged_package(&mut w, &mix, 60, g)).collect();
        let other = paged_package(&mut w, &mix, 60, 99);
        let e = &mut w.lp.peers[3].engine;
        for pk in &pks {
            e.ingest(&pk.bytes, Vec::new()).unwrap();
        }
        assert_eq!(e.pending().len(), k as usize, "{k}: each waits for its pages");
        let wants = e.blob_wants().unwrap().missing;
        let examined = e.examined();
        osis_base::costs::take();
        // a blob nothing here waits for (a peer's, a page of a commit not held)
        e.put_blobs(vec![other.blobs[0].clone()]).unwrap();
        let costs = osis_base::costs::take();
        let get = |costs: &[(&str, std::time::Duration, u64)], k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
        assert_eq!((e.examined() - examined, get(&costs, "reach: walks advanced"), get(&costs, "reach: blobs opened"), get(&costs, "pages read")), (0, 0, 0, 0), "{k}: an unrelated blob costs nothing");
        // a page the last commit wants: its walk alone is taken on
        let last = pks.last().unwrap();
        let b = last.blobs.iter().find(|(b, _)| wants.contains(b)).unwrap().clone();
        e.put_blobs(vec![b]).unwrap();
        let costs = osis_base::costs::take();
        assert_eq!(get(&costs, "reach: walks advanced"), 1, "{k}: one walk taken on");
        assert_eq!(e.examined() - examined, 0, "{k}: nothing examined while it lacks pages");
        assert_eq!(get(&costs, "pages read"), 0, "{k}: nothing decoded");
    }
}

/// spec/commits.md §4: two waiting commits linking the same pages (a forger reusing another
/// commit's links) are both woken by each page, each walk placing it once; both apply. The
/// same page delivered twice brings nothing the second time.
#[test]
fn commits_sharing_pages_are_each_woken_once_per_page_spec_commits_4() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let a = aks()[1].clone();
    let mut w = world_under(params);
    let map = |n: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    let forge = |w: &mut World, reroot: Option<Reroot<'_>>, ms: u64| {
        w.lp.advance(ms);
        let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
        let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
        let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &map(60)).unwrap();
        forge_snapshot_in(w, 0, &a, now, f, &|_, _| {}, false, reroot)
    };
    let first = forge(&mut w, None, 1);
    let delta = &osis_commit::CommitBlob::decode(&first.bytes).unwrap().parts[0].delta;
    let mut top = Vec::new();
    osis_base::visit_link_sites(delta, &osis_base::Limits::DEFAULT, &mut |s| {
        if let (osis_base::LinkSite::List { links, .. }, true) = (s, top.is_empty()) {
            top = links;
        }
    })
    .unwrap();
    let same: Reroot<'_> = &|_, _| top.clone();
    let second = forge(&mut w, Some(same), 1_000);
    assert_ne!(first.id, second.id);
    let held: BTreeMap<osis_base::BlobId, Vec<u8>> = first.blobs.iter().cloned().collect();
    let e = &mut w.lp.peers[3].engine;
    e.ingest(&first.bytes, Vec::new()).unwrap();
    e.ingest(&second.bytes, Vec::new()).unwrap();
    assert_eq!(e.pending().len(), 2);
    osis_base::costs::take();
    let mut given = 0u64;
    loop {
        let wants = e.blob_wants().unwrap().missing;
        let Some(b) = wants.iter().find_map(|b| held.get(b).map(|x| (*b, x.clone()))) else { break };
        given += 1;
        e.put_blobs(vec![b.clone()]).unwrap();
        // again: held already, nothing new
        e.put_blobs(vec![b]).unwrap();
    }
    let costs = osis_base::costs::take();
    let get = |k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
    assert!(e.pending().is_empty(), "both applied: {:?}", e.pending());
    assert_eq!(given, first.blobs.len() as u64);
    assert_eq!(get("reach: walks advanced"), 2 * given, "each page wakes both, once");
    assert_eq!(get("reach: blobs opened"), 2 * given, "each walk places each page once");
    assert_eq!(get("examine"), 2, "each examined once, when it lacks nothing");
}

/// spec/requirements.md (peer input never causes unbounded allocation): a waiting commit keeps
/// only what it lacks. W forged commits linking one held tree of L links, each lacking a page
/// never sent, keep W frontiers: walk memory O(W + L), at W and 10W, never O(W × L) (each walk
/// keeping the tree it reached).
#[test]
fn commits_over_one_held_tree_keep_only_what_they_lack_spec_commits_4() {
    // room in a root list for more than one link
    let params = osis_crdt::PageParams { target: 1000, ..small_pages() };
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let a = aks()[1].clone();
    let mut w = world_under(params);
    let map = |n: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    let forge = |w: &mut World, reroot: Option<Reroot<'_>>| {
        w.lp.advance(1_000);
        let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
        let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
        let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &map(200)).unwrap();
        forge_snapshot_in(w, 0, &a, now, f, &|_, _| {}, false, reroot)
    };
    let held = forge(&mut w, None);
    let delta = &osis_commit::CommitBlob::decode(&held.bytes).unwrap().parts[0].delta;
    let mut top = Vec::new();
    osis_base::visit_link_sites(delta, &osis_base::Limits::DEFAULT, &mut |s| {
        if let (osis_base::LinkSite::List { links, .. }, true) = (s, top.is_empty()) {
            top = links;
        }
    })
    .unwrap();
    let e = &mut w.lp.peers[3].engine;
    e.ingest(&held.bytes, Vec::new()).unwrap();
    e.put_blobs(held.blobs.clone()).unwrap();
    assert!(e.pending().is_empty(), "the tree's commit applied");
    let links = held.blobs.len();
    assert!(links >= 20 && top.len() >= 2, "{links} links, {} in the root list", top.len());
    let mut kept = Vec::new();
    let mut made = 0u64;
    for n in [3, 30] {
        while made < n {
            made += 1;
            // the held tree's root list, its first link a page never sent
            let mut lacked = top[0];
            lacked.blob.0[..8].copy_from_slice(&made.to_le_bytes());
            let reroot: Reroot<'_> = &|_, _| std::iter::once(lacked).chain(top.iter().skip(1).copied()).collect();
            let pk = forge(&mut w, Some(reroot));
            w.lp.peers[3].engine.ingest(&pk.bytes, Vec::new()).unwrap();
        }
        let e = &w.lp.peers[3].engine;
        assert_eq!(e.pending().len() as u64, n);
        kept.push(e.core.walks.kept_entries());
    }
    // each walk: the page it lacks and the tree it lies in
    assert_eq!(kept, [2 * 3, 2 * 30], "walk entries kept at 3 and 30 commits over {links} links");
}

/// spec/wire.md §6 (page by page), notes/decode-bounds.md (Link trees): a page that makes its
/// tree refusable refuses the commit's part as soon as it is held, delivered one page at a time:
/// arriving first (held before the link page naming it), while a sibling page stays missing for
/// good, or trickled as the walk asks; the commit examined at most twice. The shape: an honest root list's first
/// link, then a link page whose first link is a one-link page (off its level's end).
#[test]
fn a_refusing_page_refuses_as_it_is_held_spec_wire_6() {
    let a = aks()[0].clone();
    let roomy = osis_crdt::PageParams { target: 1000, ..small_pages() };
    let _roomy = osis_crdt::PageParams::set_test(Some(roomy));
    let map = |n: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    // (the one-link page `y`, its link page `l`, the honest root's first link `top0`)
    let ids: std::cell::RefCell<Vec<osis_base::BlobId>> = Default::default();
    let level2: Reroot<'_> = &|put, top| {
        let (y, z) = (put(&top[1..2]), put(&top[2..]));
        let l = put(&[y, z]);
        *ids.borrow_mut() = vec![y.blob, l.blob, top[0].blob];
        vec![top[0], l]
    };
    for order in ["first", "trickled", "sibling missing"] {
        let mut w = world_under(roomy);
        let t = w.t;
        let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
        let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
        let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &map(300)).unwrap();
        let pk = forge_snapshot_in(&mut w, 0, &a, now, f, &|_, _| {}, false, Some(level2));
        let [y, l, top0] = ids.borrow().clone().try_into().unwrap();
        let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
        let e = &mut w.lp.peers[3].engine;
        e.ingest(&pk.bytes, Vec::new()).unwrap();
        let waits = |e: &crate::Engine| e.core.ix.pending.contains_key(&pk.id);
        assert!(waits(e), "{order}: waits for its pages");
        osis_base::costs::take();
        let put = |e: &mut crate::Engine, b: &osis_base::BlobId| e.put_blobs(vec![(*b, held[b].clone())]);
        match order {
            "first" => {
                put(e, &y).unwrap();
                assert!(waits(e), "{order}: not wanted yet");
                put(e, &l).unwrap();
            }
            "trickled" => loop {
                let wants = e.blob_wants().unwrap().missing;
                let Some(b) = wants.iter().find(|b| held.contains_key(b)).copied() else { break };
                put(e, &b).unwrap();
            },
            _ => {
                put(e, &l).unwrap();
                assert!(waits(e) && e.wants_blob(&top0), "{order}: its sibling wanted");
                put(e, &y).unwrap();
            }
        }
        assert!(!waits(e), "{order}: refused");
        let costs = osis_base::costs::take();
        let examines = costs.iter().find(|c| c.0 == "examine").map_or(0, |c| c.2);
        assert!(examines <= 2, "{order}: examined {examines} times");
        assert_eq!(e.get(&t, &a).unwrap(), None, "{order}: nothing applied");
    }
}

/// spec/commits.md §4 (Examined again), every path
/// a blob wait goes through: a page held in a transaction that fails at each store write in
/// turn, in a waking round that fails, and a reload midway (the walks derived again from what is
/// held): the fill goes on, one page at a time as node-sync would ask, and the commit applies.
/// Fails with a blob wait lost when its walk goes (nothing names the pages again).
#[test]
fn a_fill_goes_on_past_failed_writes_rounds_and_reloads_spec_commits_4() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let [_, mix, _, _] = aks();
    let want = Value::Map((0..60).map(|i| (Value::Int(i), s(i as u64, 0))).collect());
    // what the walks ask for, one blob at a time, `n` of them (all with `None`)
    let fill = |e: &mut crate::Engine, held: &BTreeMap<osis_base::BlobId, Vec<u8>>, n: Option<usize>| {
        for _ in 0..n.unwrap_or(usize::MAX) {
            let wants = e.blob_wants().unwrap().missing;
            let Some(b) = wants.iter().find_map(|b| held.get(b).map(|x| (*b, x.clone()))) else { break };
            e.put_blobs(vec![b]).unwrap();
        }
    };
    // deliveries one at a time until it applies: a failure at the 11th, and at the last (the
    // arrival that ends the wait: its round examines, applies, writes)
    let deliveries = {
        let mut w = world_under(params);
        let pk = paged_package(&mut w, &mix, 60, 0);
        let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
        let e = &mut w.lp.peers[3].engine;
        e.ingest(&pk.bytes, Vec::new()).unwrap();
        let mut d = 0;
        while !e.pending().is_empty() {
            fill(e, &held, Some(1));
            d += 1;
            assert!(d <= held.len() + 1, "the commit waits for more than its blobs: {:?}", e.pending());
        }
        d
    };
    for case in ["failed write", "failed write, the last page", "failed round", "reload"] {
        let at = if case.ends_with("last page") { deliveries - 1 } else { 10 };
        for n in 0.. {
            let mut w = world_under(params);
            let t = w.t;
            let pk = paged_package(&mut w, &mix, 60, 0);
            let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
            let p = &mut w.lp.peers[3];
            p.engine.ingest(&pk.bytes, Vec::new()).unwrap();
            fill(&mut p.engine, &held, Some(at));
            assert!(p.engine.pending().iter().any(|x| x.0 == pk.id), "{case}: waits midway");
            let b = p.engine.blob_wants().unwrap().missing.into_iter().find(|b| held.contains_key(b)).unwrap();
            match case {
                "failed write" | "failed write, the last page" => {
                    p.backend.faults().at(n, osis_store::Fault::Fail);
                    let r = p.engine.put_blobs(vec![(b, held[&b].clone())]);
                    if p.backend.faults().writes() <= n {
                        r.unwrap();
                        break;
                    }
                    p.backend.faults().revive();
                    // the reload a failed write owes (an arrival's own failing, or a later
                    // write's its round leaves to the next step), at once as node-sync's step
                    // does (`engine_reloaded`)
                    assert!(r.is_err() || p.engine.reload_owed(), "{case} {n}");
                    p.engine.run(|_| Ok(())).unwrap();
                }
                "failed round" => {
                    p.engine.fail_round = true;
                    assert!(p.engine.put_blobs(vec![(b, held[&b].clone())]).is_err(), "{case}: the round failed");
                    p.tick().unwrap();
                }
                _ => {
                    osis_base::costs::take();
                    p.engine.reload().unwrap();
                    p.tick().unwrap();
                    let costs = osis_base::costs::take();
                    let get = |k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
                    assert!(get("examine") <= 1 && get("reach: blobs opened") <= held.len() as u64, "{case}: one examination, one pass over the pages held: {costs:?}");
                }
            }
            // from the failure on: one pass over what is held to derive the walks again, then a
            // bounded cost per page delivered and one examination to apply
            osis_base::costs::take();
            fill(&mut p.engine, &held, None);
            let costs = osis_base::costs::take();
            let get = |k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
            assert!(get("examine") <= 2 && get("reach: blobs opened") <= 2 * held.len() as u64, "{case} {n}: linear after the failure: {costs:?}");
            assert!(p.engine.pending().is_empty(), "{case} {n}: applied, not left waiting: {:?}", p.engine.pending());
            assert_eq!(p.engine.get(&t, &mix).unwrap(), Some(want.clone()), "{case} {n}");
            if !case.starts_with("failed write") {
                break;
            }
        }
    }
}

/// spec/commits.md §4 (Examined again), notes/sync-facade.md (Blob waits): every hold of a blob a
/// wait lacks wakes it, whatever path holds it. A commit waiting at node 3 for pages node 3 then
/// holds by a write of its own (a forger's commit linking the pages that write makes: its root
/// list taken from the same write in a copy of the world) is woken by that write, nothing
/// delivered. Fails with an own write's holds not noted.
#[test]
fn an_own_write_holding_a_wanted_page_ends_the_wait_spec_commits_4() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let a = aks()[1].clone();
    let map = |n: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), s(i, 0))).collect());
    let own = |w: &mut World| {
        let t = w.t;
        let c = w.commit(3, |m| { m.set(t, &a, &map(60)).unwrap(); });
        w.lp.peers[3].engine.package(&c).unwrap().unwrap()
    };
    // node 3's write, made in a copy: its pages and root list
    let mut copy = world_under(params);
    let x = own(&mut copy);
    let delta = &osis_commit::CommitBlob::decode(&x.bytes).unwrap().parts[0].delta;
    let mut top = Vec::new();
    osis_base::visit_link_sites(delta, &osis_base::Limits::DEFAULT, &mut |s| {
        if let (osis_base::LinkSite::List { links, .. }, true) = (s, top.is_empty()) {
            top = links;
        }
    })
    .unwrap();
    assert!(!top.is_empty(), "paged");
    let mut w = world_under(params);
    let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
    let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
    let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &map(60)).unwrap();
    let same: Reroot<'_> = &|_, _| top.clone();
    let y = forge_snapshot_in(&mut w, 0, &a, now, f, &|_, _| {}, false, Some(same));
    let p = &mut w.lp.peers[3];
    p.engine.ingest(&y.bytes, Vec::new()).unwrap();
    assert!(p.engine.pending().iter().any(|x| x.0 == y.id), "waits for its pages");
    let wants = p.engine.blob_wants().unwrap().missing;
    assert!(wants.iter().any(|b| x.blobs.iter().any(|x| x.0 == *b)), "wants node 3's pages");
    // the same write again: its pages alike
    let again = own(&mut w);
    assert!(x.blobs.iter().all(|b| again.blobs.contains(b)), "node 3's write alike in both worlds");
    let p = &mut w.lp.peers[3];
    p.tick().unwrap();
    assert!(!p.engine.pending().iter().any(|x| x.0 == y.id), "ended, nothing delivered: {:?}", p.engine.pending());
}

/// spec/commits.md §4 (Examined again), notes/sync-facade.md (Blob waits): a page a waiting
/// commit's walk already placed, then released here (any release: a purge, a rollback's undo),
/// is wanted again once the walk's other pages are held (the judging finds it missing and walks
/// the part afresh), and the commit applies when it comes. Fails with the walk taking the page as
/// held for good (the commit left waiting, nothing wanted).
#[test]
fn a_placed_page_released_is_wanted_again_spec_commits_4() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let mix = aks()[1].clone();
    let mut w = world_under(params);
    let t = w.t;
    let pk = paged_package(&mut w, &mix, 60, 0);
    let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
    let e = &mut w.lp.peers[3].engine;
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    let wants = |e: &mut crate::Engine| e.blob_wants().unwrap().missing.into_iter().filter(|b| held.contains_key(b)).collect::<Vec<_>>();
    // the first round: placed by the walk
    let first = wants(e);
    e.put_blobs(first.iter().map(|b| (*b, held[b].clone())).collect()).unwrap();
    assert!(!wants(e).is_empty(), "more pages wanted");
    let gone = first[0];
    e.run(|tx| tx.blobs.release(&gone, false)).unwrap();
    assert!(!e.run(|tx| tx.blobs.held(&gone)).unwrap(), "released");
    let mut rounds = 0;
    loop {
        let give = wants(e);
        if give.is_empty() {
            break;
        }
        rounds += 1;
        assert!(rounds < 100);
        e.put_blobs(give.into_iter().map(|b| (b, held[&b].clone())).collect()).unwrap();
    }
    assert!(e.pending().is_empty(), "applied: {:?}", e.pending());
    let want = Value::Map((0..60).map(|i| (Value::Int(i), s(i as u64, 0))).collect());
    assert_eq!(e.get(&t, &mix).unwrap(), Some(want));
}

/// spec/wire.md §6, notes/sync-facade.md (Blob waits): a refusable page refuses the part whatever
/// the order the pages came in and whatever else is missing, so every node ends alike. The
/// shape: an honest root list's first link, a leaf holding nested paged positions, beside a link
/// page whose first link is a one-link page (refusable alone); the nested positions' pages are
/// never delivered. Given the leaf, the link page and the refusable page in each order (and an
/// engine reload after, its walks derived afresh), the part is refused once all three are held
/// and nothing more is wanted. Fails with a refusal leaving the nested positions the leaf brought
/// wanted (the commit waits for pages its verdict does not need, and a walk derived afresh,
/// reaching the refusal first, lacks nothing while the judging still finds them missing).
#[test]
fn a_refusal_beside_a_leaf_of_nested_positions_ends_alike_in_every_order_spec_wire_6() {
    let a = aks()[1].clone();
    let roomy = osis_crdt::PageParams { target: 1000, ..small_pages() };
    let _roomy = osis_crdt::PageParams::set_test(Some(roomy));
    let nested = |i: u64| Value::Map((0..40).map(|j| (Value::Int(j), s(j as u64, i))).collect());
    let map = |n: u64| Value::Map((0..n).map(|i| (Value::Int(i as i64), nested(i))).collect());
    let ids: std::cell::RefCell<Vec<osis_base::BlobId>> = Default::default();
    let level2: Reroot<'_> = &|put, top| {
        let (y, z) = (put(&top[1..2]), put(&top[2..]));
        let l = put(&[y, z]);
        *ids.borrow_mut() = vec![top[0].blob, l.blob, y.blob];
        vec![top[0], l]
    };
    let orders: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for order in orders {
        for reload in [false, true] {
            let mut w = world_under(roomy);
            let now = osis_base::Ts::make(w.lp.peers[0].engine.now(), 0).unwrap();
            let mut wr = osis_crdt::Writer::new(now, made_up(0x80), 1 << 40);
            let f = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &map(3)).unwrap();
            let pk = forge_snapshot_in(&mut w, 0, &a, now, f, &|_, _| {}, false, Some(level2));
            let three: Vec<osis_base::BlobId> = ids.borrow().clone();
            let held: BTreeMap<osis_base::BlobId, Vec<u8>> = pk.blobs.iter().cloned().collect();
            let e = &mut w.lp.peers[3].engine;
            e.ingest(&pk.bytes, Vec::new()).unwrap();
            assert!(e.core.ix.pending.contains_key(&pk.id), "{order:?}: waits for its pages");
            let wanted = |e: &mut crate::Engine| e.blob_wants().unwrap().missing.into_iter().filter(|b| held.contains_key(b)).collect::<Vec<_>>();
            for (k, i) in order.into_iter().enumerate() {
                e.put_blobs(vec![(three[i], held[&three[i]].clone())]).unwrap();
                if k == 0 && i == 0 {
                    assert!(wanted(e).iter().any(|b| *b != three[1]), "the leaf brings nested positions' pages to fetch");
                }
                // walks derived afresh midway
                if k == 1 && reload {
                    e.reload().unwrap();
                    e.reexamine().unwrap();
                }
            }
            let wanted = wanted(e);
            assert!(!e.core.ix.pending.contains_key(&pk.id) && wanted.is_empty(), "{order:?} reload {reload}: refused, nothing wanted: pending {:?}, {} wanted", e.pending(), wanted.len());
        }
    }
}

/// spec/sync-streams.md §5 (Pages of a delta are fetched before its commit is applied: a large value's tree lazily),
/// spec/commits.md §4: a durable paged part waits for its pages only, never for its large values' trees: given
/// every page and none of the value's tree (a peer that applied it without fetching them), it
/// applies. Fails with the part's wait keyed on the value's root as well.
#[test]
fn a_paged_part_waits_for_pages_not_value_roots_spec_sync_streams_5() {
    let params = small_pages();
    let _pages = osis_crdt::PageParams::set_test(Some(params));
    let mix = aks()[1].clone();
    let big = Value::Str("ab".repeat(osis_base::format::CHUNK_THRESHOLD));
    let write = |w: &mut World, v: Value| {
        let t = w.t;
        let c = w.commit(0, |m| { m.set(t, &mix, &v).unwrap(); });
        w.lp.peers[0].engine.package(&c).unwrap().unwrap()
    };
    // the value's tree alone (its blobs alike: the same thing, aspect and bytes)
    let tree: std::collections::BTreeSet<osis_base::BlobId> = write(&mut world_under(params), big.clone()).blobs.iter().map(|b| b.0).collect();
    let mut w = world_under(params);
    let t = w.t;
    let mut v: BTreeMap<Value, Value> = (0..60).map(|i| (Value::Int(i), s(i as u64, 0))).collect();
    v.insert(Value::Str("large".into()), big);
    let pk = write(&mut w, Value::Map(v.into_iter().collect()));
    assert!(pk.blobs.iter().any(|b| tree.contains(&b.0)), "the value's tree among its blobs");
    let pages: Vec<(osis_base::BlobId, Vec<u8>)> = pk.blobs.iter().filter(|b| !tree.contains(&b.0)).cloned().collect();
    let want = w.lp.peers[0].engine.get(&t, &mix).unwrap();
    assert!(want.is_some());
    let e = &mut w.lp.peers[3].engine;
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    assert!(e.pending().iter().any(|x| x.0 == pk.id), "waits for its pages");
    e.put_blobs(pages).unwrap();
    assert!(e.pending().is_empty(), "applied with its pages, the value's tree fetched lazily: {:?}", e.pending());
    assert_eq!(e.get(&t, &mix).unwrap(), want, "node 3 reads what node 0 does");
}
