#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Shared test helpers: a test schema with one aspect per encoding, grants, delivery.

use osis_commit::Kind;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::{LocalPeer, Package};
use osis_node::{Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{Aspect, Codec, StaticSchema};

pub const T0: WallMs = WallMs(1_700_000_000_000);

pub static TEST: StaticSchema = StaticSchema::new(
    "test.osis",
    r#"
version 1;
type item = struct { 0 name: string, 1 n: int };
type shape = enum { 0 dot, 1 circle(int) };
type book = struct { 0 entries: map<string, string>, 1 note: string };
aspect t:reg.0: string;
aspect t:count.0: counter<int>;
aspect t:hi.0: max<int>;
aspect t:lo.0: min<int>;
aspect t:rec.0: item;
aspect t:shape.0: shape;
aspect t:tags.0: set<string>;
aspect t:map.0: map<string, item>;
aspect t:big.0: map<string, string>;
aspect t:gone.0: string [by: writer, keep_at_most: 0s];
aspect t:gone2.0: string [by: writer, keep_at_most: 0s];
aspect t:gonemap.0: map<string, string> [by: writer, keep_at_most: 0s];
aspect t:brief.0: string [expires: 1h];
aspect t:kept.0: string [by: writer, keep_at_least: 1d];
aspect t:keptset.0: set<string> [by: writer, keep_at_least: 1d];
aspect t:short.0: string [by: writer, keep_at_most: 10m];
aspect t:short2.0: string [by: writer, keep_at_most: 10m];
aspect t:list.0: list<string>;
aspect t:text.0: text;
aspect t:blob.0: blob;
aspect t:book.0: book;
aspect t:docs.0: map<string, text>;
aspect t:shortmap.0: map<string, string> [by: writer, keep_at_most: 10m];
"#,
);

pub const REG: Aspect<Value> = Aspect::new("t:reg.0", &TEST);
pub const COUNT: Aspect<Value> = Aspect::new("t:count.0", &TEST);
pub const HI: Aspect<Value> = Aspect::new("t:hi.0", &TEST);
pub const LO: Aspect<Value> = Aspect::new("t:lo.0", &TEST);
pub const REC: Aspect<Value> = Aspect::new("t:rec.0", &TEST);
pub const SHAPE: Aspect<Value> = Aspect::new("t:shape.0", &TEST);
pub const TAGS: Aspect<Value> = Aspect::new("t:tags.0", &TEST);
pub const MAP: Aspect<Value> = Aspect::new("t:map.0", &TEST);
pub const BIG: Aspect<Value> = Aspect::new("t:big.0", &TEST);
pub const GONE: Aspect<Value> = Aspect::new("t:gone.0", &TEST);
pub const GONE2: Aspect<Value> = Aspect::new("t:gone2.0", &TEST);
pub const GONEMAP: Aspect<Value> = Aspect::new("t:gonemap.0", &TEST);
pub const BRIEF: Aspect<Value> = Aspect::new("t:brief.0", &TEST);
pub const KEPT: Aspect<Value> = Aspect::new("t:kept.0", &TEST);
pub const KEPTSET: Aspect<Value> = Aspect::new("t:keptset.0", &TEST);
pub const SHORT: Aspect<Value> = Aspect::new("t:short.0", &TEST);
pub const SHORT2: Aspect<Value> = Aspect::new("t:short2.0", &TEST);
pub const LIST: Aspect<Value> = Aspect::new("t:list.0", &TEST);
pub const TEXT: Aspect<Value> = Aspect::new("t:text.0", &TEST);
pub const BLOB: Aspect<Value> = Aspect::new("t:blob.0", &TEST);
pub const BOOK: Aspect<Value> = Aspect::new("t:book.0", &TEST);
pub const DOCS: Aspect<Value> = Aspect::new("t:docs.0", &TEST);
pub const SHORTMAP: Aspect<Value> = Aspect::new("t:shortmap.0", &TEST);

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

pub fn item(name: &str, n: i64) -> Value {
    Value::Map([(Value::Int(0), s(name)), (Value::Int(1), Value::Int(n))].into_iter().collect())
}

pub fn net(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::new(n, seed, T0).unwrap()
}

/// A new thing owned by peer `i`'s node.
pub fn new_thing(lp: &mut LocalPeer, i: usize) -> Tid {
    let p = lp.peer(i).unwrap();
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("new")).unwrap();
    p.commit(m).unwrap();
    t
}

pub fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None, tied: None }
}

/// Peer `i` writes `holder`'s edge on `thing` as remove + put (`None` removes it), with an
/// optional frontier.
pub fn set_edge(e: &mut Engine, thing: Tid, holder: Tid, edge: Option<ct::Edge>, frontier: Option<Value>) -> CommitId {
    // an edge change is remove + put (spec/permissions.md §2)
    let mut m = Mutation::new();
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    if let Some(x) = edge {
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(x.to_value()) }).unwrap();
    }
    if let Some(f) = frontier {
        m.frontier(f);
    }
    e.commit(m).unwrap().unwrap()
}

/// Delivers every commit of `from` to `to`.
pub fn sync(lp: &mut LocalPeer, from: usize, to: usize) {
    lp.sync(from, to).unwrap();
}

pub fn packages(lp: &mut LocalPeer, from: usize) -> Vec<Package> {
    lp.packages(from).unwrap()
}

pub fn is_role(e: &Engine, id: &CommitId) -> bool {
    e.header(id).is_some_and(|h| h.kind == Kind::Role)
}

/// Canonical bytes of every aspect state of `tids` (convergence check).
pub fn states(e: &mut Engine, tids: &[Tid]) -> Vec<(Tid, Ak, Option<Value>)> {
    let mut out = Vec::new();
    for (t, a) in e.all_aspects().unwrap() {
        if tids.contains(&t) {
            out.push((t, a.clone(), e.get(&t, &a).unwrap()));
        }
    }
    out.sort_by(|x, y| (x.0, x.1.as_str()).cmp(&(y.0, y.1.as_str())));
    out
}

// Forensic attack (spec/commits.md §5, spec/requirements.md Deletion: forward secure): peers
// whose backend records every row written.

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether an attacker decrypts `marker` from the rows ever written, starting from the keys the
/// current tree yields and harvesting keys from opened tree nodes.
pub fn recoverable(p: &mut osis_node::local_peer::Peer, marker: &[u8]) -> bool {
    plaintexts(p).iter().any(|x| contains(x, marker))
}

/// Every row plaintext an attacker recovers.
pub fn plaintexts(p: &mut osis_node::local_peer::Peer) -> Vec<Vec<u8>> {
    let history = p.backend.history();
    let mut keys = p.engine.forensic_keys().unwrap();
    let mut known: std::collections::HashSet<[u8; 32]> = keys.iter().copied().collect();
    let mut opened = vec![false; history.len()];
    let mut tried = 0;
    let mut found = Vec::new();
    while tried < keys.len() {
        let batch: Vec<[u8; 32]> = keys[tried..].to_vec();
        tried = keys.len();
        for (i, (row, value)) in history.iter().enumerate() {
            if opened[i] {
                continue;
            }
            for k in &batch {
                if let Some(plain) = osis_store::forensic_open(row, value, k) {
                    for nk in osis_store::forensic_node_keys(row, &plain) {
                        if known.insert(nk) {
                            keys.push(nk);
                        }
                    }
                    found.push(plain);
                    opened[i] = true;
                    break;
                }
            }
        }
    }
    found
}

/// A thread per core, or the number in env `var`.
pub fn threads(var: &str) -> usize {
    osis_base::testenv::u64_var(var).map_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()), |n| n as usize).max(1)
}

/// `f` over `items` on up to `threads` threads, results in order.
pub fn par_map<T: Send>(items: &[u64], threads: usize, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let threads = threads.clamp(1, items.len().max(1));
    let next = AtomicUsize::new(0);
    let (f, next) = (&f, &next);
    let mut out: Vec<(usize, T)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&x) = items.get(i) else { break };
                        mine.push((i, f(x)));
                    }
                    mine
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    out.sort_by_key(|x| x.0);
    out.into_iter().map(|x| x.1).collect()
}

/// Seconds one seed of a seed runner may run before the process stops naming it
/// (`OSIS_SEED_TIMEOUT_SECS` overrides). Minor consequence, test-only: at 0 every run stops at
/// its first seed; at infinity a hung seed hangs the run silently. 600 s is far past any seed's
/// cost (the slowest, ephemeral random windows, take seconds even at load 30).
pub const SEED_TIMEOUT_SECS: u64 = 600;

/// `par_map`, watched: when one item has run longer than `SEED_TIMEOUT_SECS`, prints
/// `label(item)` of every item still running past libtest's capture and exits the process
/// (a hung thread cannot be stopped; without this the run hangs silently).
pub fn par_map_watched<T: Send>(name: &str, items: &[u64], threads: usize, label: impl Fn(u64) -> String + Sync, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    use std::collections::BTreeMap;
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};
    let limit = Duration::from_secs(osis_base::testenv::u64_var("OSIS_SEED_TIMEOUT_SECS").unwrap_or(SEED_TIMEOUT_SECS));
    // items running, with their start; None once the run is over
    let state: Mutex<Option<BTreeMap<u64, Instant>>> = Mutex::new(Some(BTreeMap::new()));
    let wake = Condvar::new();
    struct Over<'a>(&'a Mutex<Option<BTreeMap<u64, Instant>>>, &'a Condvar);
    impl Drop for Over<'_> {
        fn drop(&mut self) {
            *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.1.notify_all();
        }
    }
    let lock = || state.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut g = lock();
            while let Some(running) = g.as_ref() {
                let now = Instant::now();
                let oldest = running.values().min().copied();
                match oldest {
                    Some(t) if now.duration_since(t) >= limit => {
                        let hung: Vec<String> = running.iter().map(|(&x, t)| format!("  {} running {} s", label(x), now.duration_since(*t).as_secs())).collect();
                        osis_base::testenv::visible(true, &format!("{name}: a seed ran past {} s (OSIS_SEED_TIMEOUT_SECS); stopping. Still running:\n{}", limit.as_secs(), hung.join("\n")));
                        std::process::exit(101);
                    }
                    Some(t) => g = wake.wait_timeout(g, limit - now.duration_since(t)).unwrap_or_else(|e| e.into_inner()).0,
                    None => g = wake.wait(g).unwrap_or_else(|e| e.into_inner()),
                }
            }
        });
        let _over = Over(&state, &wake);
        par_map(items, threads, |x| {
            if let Some(r) = lock().as_mut() {
                r.insert(x, Instant::now());
            }
            wake.notify_all();
            let out = f(x);
            if let Some(r) = lock().as_mut() {
                r.remove(&x);
            }
            out
        })
    })
}

/// `f`, a panic as an error.
pub fn caught<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|e| {
        let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
        Err(format!("panicked: {msg}"))
    })
}

/// `f(seed)` for every seed on `threads(threads_var)` threads, a panic as its seed's failure.
/// Prints each failing seed with `replay(seed)` as it fails, then a summary line, then panics
/// listing every failure in seed order; else the results in seed order.
pub fn run_seeds<T: Send>(name: &str, seeds: &[u64], threads_var: &str, replay: impl Fn(u64) -> String + Sync, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    run_seeds_noted(name, seeds, false, threads_var, replay, f)
}

/// `run_seeds`, its summary line past libtest's capture when `visible` (a range from the
/// environment: a passing run shows it without `--nocapture`).
pub fn run_seeds_noted<T: Send>(name: &str, seeds: &[u64], visible: bool, threads_var: &str, replay: impl Fn(u64) -> String + Sync, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    let t0 = std::time::Instant::now();
    let replay = &replay;
    let results = par_map_watched(name, seeds, threads(threads_var), |seed| format!("seed {seed} (replay: {})", replay(seed)), |seed| {
        caught(|| Ok(f(seed))).map_err(|e| {
            let msg = format!("seed {seed} (replay: {}): {e}", replay(seed));
            eprintln!("{msg}\n");
            msg
        })
    });
    let fails: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    let summary = format!("{name}: {} seeds from {}, {} failing, {:.1} s", seeds.len(), seeds.first().copied().unwrap_or(0), fails.len(), t0.elapsed().as_secs_f64());
    osis_base::testenv::visible(visible, &summary);
    if !fails.is_empty() {
        let list: Vec<&str> = fails.iter().map(|m| m.as_str()).collect();
        panic!("{summary}\n{} of {} seeds failed:\n{}", fails.len(), seeds.len(), list.join("\n\n"));
    }
    results.into_iter().flatten().collect()
}

/// A content snapshot of `(t, a)` by peer `by` at `ts` carrying `f` (hand-built, unchecked).
pub fn forge_snapshot(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment) -> Vec<u8> {
    forge_snapshot_with(lp, by, t, a, ts, f, Default::default())
}

pub fn forge_snapshot_with(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers) -> Vec<u8> {
    forge_snapshot_absorbing(lp, by, t, a, ts, f, frontiers, Default::default())
}

/// `forge_snapshot_with` listing `absorbed` (commit ID -> author).
#[allow(clippy::too_many_arguments)]
pub fn forge_snapshot_absorbing(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_base::Ak, ts: osis_base::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers, absorbed: std::collections::BTreeMap<osis_base::CommitId, Tid>) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    let author = lp.peers[by].engine.tid();
    let snap = osis_crdt::Snapshot { absorbed, nonce: [7; 16], fragment: f, frontiers };
    let bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Kind::ContentSnapshot, ts, author, 0, 0), None).unwrap();
    let mut aw = AspectWrite::new(t, a.clone(), 0, 0, bytes);
    aw.retention = osis_commit::retention::snapshot_retention(a.as_str(), [], 0);
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, author, Form::Node);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[by].engine.identity().keys().signing, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

/// Secrets for hand-built commits with `writer` retention: dedup, and made-up delete keys
/// (hosts' business).
pub struct Keys(pub osis_base::CreationRecord);
impl osis_commit::Secrets for Keys {
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

/// Whether commit `id` (header `h`) owns one of `dots`, carried writes by aspect
/// (`Engine::carried_dots`): its node-form range on the aspect holds one, or a commit-form dot
/// names it.
pub fn owns_carried(h: &osis_commit::Header, id: &CommitId, dots: &std::collections::BTreeSet<(Tid, Ak, osis_crdt::Dot)>) -> bool {
    h.aspects.iter().any(|a| {
        dots.iter().filter(|(t, k, _)| *t == a.tid && *k == a.ak).any(|(_, _, d)| match d.src.kind() {
            osis_crdt::SourceKind::Node(n) => h.form == osis_commit::Form::Node && *n == h.author && a.lo <= d.ctr && d.ctr < a.hi,
            osis_crdt::SourceKind::Commit(c) => c == id,
            osis_crdt::SourceKind::Session(_) | osis_crdt::SourceKind::Derived(_) => false,
        })
    })
}
