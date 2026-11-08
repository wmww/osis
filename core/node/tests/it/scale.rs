#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Scale checks at the engine (tier 2, release; numbers in notes/testing.md, "Scale checks"):
//! `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 scale::`.

use osis_base::{Ak, BlobId, Clock, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::{HolderKeys, Recipient, rotate};
use osis_node::{Config, Engine, Mutation};
use osis_schema::{Aspect, RawKey, Codec, StaticSchema};
use osis_schema::core_types as ct;
use osis_store::{Backend, BackendError, KeyValue, MemoryBackend, MemoryRoot, WriteBatch};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A backend counting durable batches and their bytes.
struct Counting {
    inner: MemoryBackend,
    batches: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl Backend for Counting {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.get(key)
    }
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        self.inner.scan(start, end, limit)
    }
    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        self.batches.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(batch.bytes() as u64, Ordering::Relaxed);
        // OSIS_SCALE_ROWS: each row written, by kind (`u` unit, `n` key-tree node) and slot
        if std::env::var_os("OSIS_SCALE_ROWS").is_some() {
            let rows: Vec<String> = batch.ops.iter().filter_map(|o| match o { osis_store::Op::Put(k, v) => Some(format!("{}{}:{}", char::from(k[0]), k.get(1..9).map_or(0, |x| u64::from_be_bytes(x.try_into().unwrap())), v.len())), _ => None }).collect();
            println!("rows: {}", rows.join(" "));
        }
        self.inner.commit(batch)
    }
    fn get_blob(&self, id: &BlobId) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.get_blob(id)
    }
    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.read_blob(id, offset, len)
    }
    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        self.inner.blob_len(id)
    }
}

fn engine(seed: u64) -> (Engine, Arc<AtomicU64>, Arc<AtomicU64>) {
    let (e, batches, bytes, _) = engine_reopenable(seed);
    (e, batches, bytes)
}

/// The store's backend and root, to open the node again.
struct Reopen(MemoryBackend, MemoryRoot);

impl Reopen {
    /// Opens the node again over the same store (a new session: nothing cached).
    fn open(&self, batches: &Arc<AtomicU64>, bytes: &Arc<AtomicU64>) -> Engine {
        let b = Counting { inner: self.0.clone(), batches: batches.clone(), bytes: bytes.clone() };
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(WallMs(1_700_000_000_000)));
        Engine::open(Box::new(b), Box::new(self.1.clone()), Config::default(), clock, Box::new(SeededRng::from_u64(99))).unwrap()
    }
}

fn engine_reopenable(seed: u64) -> (Engine, Arc<AtomicU64>, Arc<AtomicU64>, Reopen) {
    let (batches, bytes) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (inner, root) = (MemoryBackend::new(), MemoryRoot::new());
    let b = Counting { inner: inner.clone(), batches: batches.clone(), bytes: bytes.clone() };
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(WallMs(1_700_000_000_000)));
    let e = Engine::create(Box::new(b), Box::new(root.clone()), Config::default(), clock, Box::new(SeededRng::from_u64(seed))).unwrap();
    (e, batches, bytes, Reopen(inner, root))
}

static SCALE: StaticSchema = StaticSchema::new("scale.osis", "revision 1; aspect s:text.0: text; aspect s:tags.0: set<string>; purgeable_by(writer) keep_history(1d) aspect s:kept.0: set<string>; purgeable_by(writer) purge_on_replace aspect s:gone.0: map<string, string>;\n");
const TEXT: Aspect<Value> = Aspect::new("s:text.0", &SCALE);
const TAGS: Aspect<Value> = Aspect::new("s:tags.0", &SCALE);
const KEPT: Aspect<Value> = Aspect::new("s:kept.0", &SCALE);
const GONE: Aspect<Value> = Aspect::new("s:gone.0", &SCALE);

/// A size from `var`, else `release` in a release build and `dev` in a dev one. A dev build
/// re-examines every pending commit at each re-examination (`check_unchanged`, debug only): a
/// first sync of 10^4 commits there takes 9 min instead of 30 s.
fn size(var: &str, release: usize, dev: usize) -> usize {
    std::env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(if cfg!(debug_assertions) { dev } else { release })
}

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

// spec/crdt.md §8; spec/requirements.md, Scale: maps with millions of keys; a change inside a huge value costs
// O(change). Measures one map entry edit at 10^4..10^6 keys: bytes the engine writes to the
// store and the commit it produces. `OSIS_SCALE_MAX` caps the size (default 10^6).
#[test]
#[ignore]
fn big_map_edit_cost() {
    let max: usize = size("OSIS_SCALE_MAX", 1_000_000, 1_000_000);
    let a = ak("app:big.0");
    let mut n = 10_000;
    while n <= max {
        let (mut e, batches, bytes, reopen) = engine_reopenable(n as u64);
        let me = e.tid();
        let kv: osis_base::ValueMap = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
        let t0 = Instant::now();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &a, &Value::Map(kv)).unwrap();
        let first = e.commit(m).unwrap().unwrap();
        let fill = t0.elapsed();
        let first_len = e.package(&first).unwrap().map(|p| p.bytes.len() + p.blobs.iter().map(|b| b.1.len()).sum::<usize>()).unwrap();
        let (b0, w0) = (batches.load(Ordering::Relaxed), bytes.load(Ordering::Relaxed));
        let t1 = Instant::now();
        let mut m = Mutation::new();
        m.op(t, &a, PathOp { path: vec![PathSeg::Key(Value::Int(n as i64 / 2))], op: Op::Set(Value::Int(-1)) }).unwrap();
        let id = e.commit(m).unwrap().unwrap();
        let edit = t1.elapsed();
        let (b1, w1) = (batches.load(Ordering::Relaxed), bytes.load(Ordering::Relaxed));
        let pkg = e.package(&id).unwrap().unwrap();
        let wire = pkg.bytes.len() + pkg.blobs.iter().map(|b| b.1.len()).sum::<usize>();
        println!(
            "map {n} keys: fill commit {fill:?} ({first_len} B with pages); one edit {edit:?}, store writes {} B in {} batches, commit {wire} B ({} blobs)",
            w1 - w0,
            b1 - b0,
            pkg.blobs.len()
        );
        // a new session: the first read of one key and the first edit load only their pages
        drop(e);
        let mut e = reopen.open(&batches, &bytes);
        let t2 = Instant::now();
        let v = e.get_at(&t, &a, &[PathSeg::Key(Value::Int(n as i64 / 3))]).unwrap();
        let read = t2.elapsed();
        assert_eq!(v, Some(Value::Int(n as i64 / 3)));
        let t3 = Instant::now();
        let mut m = Mutation::new();
        m.op(t, &a, PathOp { path: vec![PathSeg::Key(Value::Int(n as i64 / 4))], op: Op::Set(Value::Int(-2)) }).unwrap();
        e.commit(m).unwrap().unwrap();
        println!("map {n} keys, new session: first read of one key {read:?}, first edit {:?}", t3.elapsed());
        n *= 10;
    }
}

// spec/requirements.md, Scale; spec/data-model.md §6: a real registration for 2100 readers: its
// claim set, above `CHUNK_THRESHOLD`, stays inline in `label.0` and its role commit applies.
#[test]
#[ignore]
fn registration_of_thousands_of_readers() {
    let (mut e, _, _) = engine(7);
    let me = e.tid();
    let mut m = Mutation::new();
    let a = e.new_thing(&mut m, me);
    e.commit(m).unwrap().unwrap();
    let all = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
    let own = [Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }];
    let view = e.epochs(&a).unwrap();
    let r0 = rotate(&a, &all, &view, &Default::default(), &own, &osis_keys::Names::default(), &mut SeededRng::from_u64(2)).unwrap();
    let write = |m: &mut Mutation, r: &osis_keys::Rotation| {
        for (k, b) in &r.secrets.boxes {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
        }
        for (k, h) in &r.secrets.history {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
        }
        for (role, ks) in &r.keys.keysets {
            let f = match role {
                Role::Read => 0,
                Role::Write => 1,
                Role::Admin => 2,
            };
            m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
        }
    };
    let mut m = Mutation::new();
    write(&mut m, &r0);
    m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Replace(Some([7u8; 32]).to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap();
    // holders with a read keyset each, in commits of a hundred
    let ep = Epoch::new(1, [3; 32]).unwrap();
    let template = r0.keys.keysets.get(&Role::Read).unwrap().clone();
    let mut holders = own.to_vec();
    for batch in 0..21u8 {
        let mut m = Mutation::new();
        for i in 0..100u8 {
            let kem = KeyActorKeys::from_seed(&Secret32::from_bytes([batch, i, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9])).kem.public().clone();
            let h = e.new_thing(&mut m, me);
            let ks = ct::Keyset { kem_key: ct::KemKey::X25519MlKem768(kem.as_bytes().to_vec()), ..template.clone() };
            m.op(h, &ct::KEYS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Replace(Some(ks).to_value()) }).unwrap();
            m.op(a, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(h))], op: Op::Set(ct::Edge { role: Role::Read, until: None, invite: None, tied: None }.to_value()) }).unwrap();
            holders.push(Recipient { holder: h, role: Role::Read, keys: HolderKeys::Actor { keysets: [(Role::Read, (ep, kem))].into_iter().collect(), own: BTreeMap::new() } });
        }
        e.commit_hostile(m).unwrap().unwrap();
    }
    let view = e.epochs(&a).unwrap();
    let state = e.get(&a, &ak("secrets.0")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap_or_default();
    let r = rotate(&a, &BTreeSet::from([Role::Read]), &view, &state, &holders, &osis_keys::Names::default(), &mut SeededRng::from_u64(1)).unwrap();
    let mut m = Mutation::new();
    write(&mut m, &r);
    e.commit_hostile(m).unwrap().unwrap();
    let t = Instant::now();
    let (label, _) = e.create_label(&a, &[]).unwrap();
    let labels = e.get_typed(&a, &ct::LABEL).unwrap().unwrap();
    let claims = labels.values().flat_map(|l| l.steps.values()).filter_map(|s| s.claims.as_ref()).map(Vec::len).max().unwrap();
    println!("label {label:?} for 2100 readers: {claims} B of claims in {:?}", t.elapsed());
    assert!(claims > osis_base::format::CHUNK_THRESHOLD, "{claims}");
}

// spec/requirements.md, Scale: direct rosters hold thousands of holders; spec/crypto.md §4: a
// rotation boxes each remaining role secret to each holder. Measures the rotation commit that a
// removal from a roster of N writers carries (read and write rotated; each account holder gets a
// sealed box per role; notes/chat.md estimates 2.7 KB per holder).
#[test]
#[ignore]
fn roster_removal_cost() {
    for n in [100usize, 1_000] {
        let (mut e, batches, bytes) = engine(7);
        let me = e.tid();
        let mut m = Mutation::new();
        let a = e.new_thing(&mut m, me);
        e.commit(m).unwrap().unwrap();
        // Account-like holders: keysets per role (one KEM key reused; box size does not depend on it).
        let kem = KeyActorKeys::from_seed(&Secret32::from_bytes([9; 32])).kem.public().clone();
        let ep = Epoch::new(1, [3; 32]).unwrap();
        let mut holders = vec![Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }];
        for i in 0..n - 1 {
            let mut b = [0u8; 15];
            b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            let keysets = [Role::Read, Role::Write].into_iter().map(|r| (r, (ep, kem.clone()))).collect();
            holders.push(Recipient { holder: Tid::from_bytes(b), role: Role::Write, keys: HolderKeys::Actor { keysets, own: BTreeMap::new() } });
        }
        // secrets of its own are all three roles' (spec/crypto.md §3): the thing gets them first
        let all = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
        let view = e.epochs(&a).unwrap();
        let r0 = rotate(&a, &all, &view, &Default::default(), &holders[..1], &osis_keys::Names::default(), &mut SeededRng::from_u64(2)).unwrap();
        let mut m = Mutation::new();
        for (k, b) in &r0.secrets.boxes {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
        }
        for (k, h) in &r0.secrets.history {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
        }
        for (role, ks) in &r0.keys.keysets {
            let f = match role {
                Role::Read => 0,
                Role::Write => 1,
                Role::Admin => 2,
            };
            m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
        }
        e.commit(m).unwrap().unwrap();
        let roles = BTreeSet::from([Role::Read, Role::Write]);
        let t0 = Instant::now();
        let view = e.epochs(&a).unwrap();
        let state = e.get(&a, &ak("secrets.0")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap_or_default();
        let r = rotate(&a, &roles, &view, &state, &holders, &osis_keys::Names::default(), &mut SeededRng::from_u64(1)).unwrap();
        let sealed = t0.elapsed();
        let mut m = Mutation::new();
        for (k, b) in &r.secrets.boxes {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
        }
        for (k, h) in &r.secrets.history {
            m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
        }
        for (role, ks) in &r.keys.keysets {
            let f = match role {
                Role::Read => 0,
                Role::Write => 1,
                Role::Admin => 2,
            };
            m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
        }
        let t1 = Instant::now();
        let id = e.commit(m).unwrap().unwrap();
        let committed = t1.elapsed();
        let pkg = e.package(&id).unwrap().unwrap();
        let total = pkg.bytes.len() + pkg.blobs.iter().map(|b| b.1.len()).sum::<usize>();
        let boxes = r.secrets.boxes.len();
        println!(
            "roster {n}: rotation commit {total} B ({} blobs), {boxes} boxes, {:.0} B per remaining holder; seal {sealed:?}, commit {committed:?}",
            pkg.blobs.len(),
            total as f64 / (n - 1) as f64
        );
        assert!(boxes >= 2 * (n - 1));
        // Budget: notes/chat.md, 2.7 KB per remaining holder per rotation, plus about 10%.
        assert!(total <= 3000 * (n - 1), "{total} B for {n} holders");
        // One history entry more afterwards: with the box map paged, only the skeleton (the small
        // fields) is rewritten, not the whole `secrets.0` state.
        let mut m2 = Mutation::new();
        m2.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(Value::Int(999_999))], op: Op::Set(Value::Bytes(vec![7; 64])) }).unwrap();
        let w0 = bytes.load(Ordering::Relaxed);
        let t2 = Instant::now();
        e.commit(m2).unwrap().unwrap();
        println!("roster {n}: one more secrets.0 entry {:?}, store writes {} B ({} batches total)", t2.elapsed(), bytes.load(Ordering::Relaxed) - w0, batches.load(Ordering::Relaxed));
    }
}

// spec/crdt.md §5.6; spec/requirements.md, Scale: a change inside a huge value costs O(change), at any depth.
// One edit of a key of a 10^5-key map held in an entry of a root map (a deep collection).
// spec: none (spec/requirements.md has no numbered sections)
#[test]
#[ignore = "tier 2"]
fn deep_map_edit_cost() {
    let a = ak("app:deep.0");
    for n in [10_000usize, 100_000] {
        let (mut e, batches, bytes) = engine(n as u64 + 1);
        let me = e.tid();
        let inner: osis_base::ValueMap = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
        let outer = Value::Map(osis_base::ValueMap::from([(Value::Str("inner".into()), Value::Map(inner)), (Value::Str("x".into()), Value::Int(1))]));
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &a, &outer).unwrap();
        e.commit(m).unwrap().unwrap();
        let (b0, w0) = (batches.load(Ordering::Relaxed), bytes.load(Ordering::Relaxed));
        let t1 = Instant::now();
        let mut m = Mutation::new();
        m.op(t, &a, PathOp { path: vec![PathSeg::Key(Value::Str("inner".into())), PathSeg::Key(Value::Int(n as i64 / 2))], op: Op::Set(Value::Int(-1)) }).unwrap();
        e.commit(m).unwrap().unwrap();
        let edit = t1.elapsed();
        let (b1, w1) = (batches.load(Ordering::Relaxed), bytes.load(Ordering::Relaxed));
        println!("deep map {n} keys: one edit {edit:?}, store writes {} B in {} batches", w1 - w0, b1 - b0);
        assert_eq!(e.get_at(&t, &a, &[PathSeg::Key(Value::Str("inner".into())), PathSeg::Key(Value::Int(n as i64 / 2))]).unwrap(), Some(Value::Int(-1)));
    }
}

// spec/crdt.md §5.5 (set ops resolved by value), §8; spec/requirements.md, Scale (a change
// costs O(change)): adding and removing elements by value in a 10^5-element set, each op in a
// new session: the pages loaded (`state page load` spans) and the time.
#[test]
#[ignore = "tier 2"]
fn big_set_by_value_cost() {
    let n = 100_000usize;
    let a = ak("app:set.0");
    let s = |x: String| Value::Str(x);
    let (mut e, batches, bytes, reopen) = engine_reopenable(8);
    let me = e.tid();
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, me);
    m.set(t, &a, &Value::Set((0..n).map(|i| s(format!("e{i}"))).collect())).unwrap();
    e.commit(m).unwrap().unwrap();
    drop(e);
    let ops = [
        ("add new", Op::Add(s("x".into())), true),
        ("add present", Op::Add(s(format!("e{}", n / 2))), false),
        ("remove", Op::Remove(s(format!("e{}", n / 3))), true),
        ("remove absent", Op::Remove(s("y".into())), false),
    ];
    for (name, op, writes) in ops {
        let mut e = reopen.open(&batches, &bytes);
        osis_node::costs::take();
        let t0 = Instant::now();
        let mut m = Mutation::new();
        m.op(t, &a, PathOp { path: vec![], op }).unwrap();
        assert_eq!(e.commit(m).unwrap().is_some(), writes, "{name}");
        let dt = t0.elapsed();
        let loads = osis_node::costs::take().iter().find(|x| x.0 == "state page load").map_or(0, |x| x.2);
        println!("set {n} elements, new session: {name} by value {dt:?}, {loads} pages loaded");
        assert!(loads <= 4, "{name}: {loads} pages loaded");
    }
    let mut e = reopen.open(&batches, &bytes);
    let Some(Value::Set(v)) = e.get(&t, &a).unwrap() else { panic!() };
    assert_eq!(v.len(), n);
    assert!(v.contains(&s("x".into())) && !v.contains(&s(format!("e{}", n / 3))));
}

// spec/requirements.md, Scale (O(change)); spec/commits.md §7 (undo): one insert into a
// 10^5-char text keeps an undo buffer of what undoing it reads, not the text; the first access
// to the text in a new session; the undo commit.
#[test]
#[ignore = "tier 2"]
fn text_undo_and_first_access_cost() {
    let n = 100_000usize;
    let (mut e, batches, bytes, reopen) = engine_reopenable(5);
    let me = e.tid();
    let text: String = (0..n).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, me);
    m.set(t, &TEXT, &Value::Str(text)).unwrap();
    e.commit(m).unwrap().unwrap();
    let w0 = bytes.load(Ordering::Relaxed);
    let t1 = Instant::now();
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: vec![], op: Op::Insert { at: n / 2, items: vec![Value::Str("XYZ".into())] } }).unwrap();
    let id = e.commit(m).unwrap().unwrap();
    let insert = t1.elapsed();
    let w1 = bytes.load(Ordering::Relaxed);
    println!("text {n} chars: one insert {insert:?}, store writes {} B (undo buffer included; the text is loaded whole: the write keeps the stored placement)", w1 - w0);
    // later edits in the session keep it too
    let k = 10;
    for i in 0..k {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: vec![], op: Op::Insert { at: (i * 7919) % n, items: vec![Value::Str("Q".into())] } }).unwrap();
        e.commit(m).unwrap().unwrap();
    }
    println!("text {n} chars: later inserts in the session, store writes {} B each", (bytes.load(Ordering::Relaxed) - w1) / k as u64);
    drop(e);
    let t2 = Instant::now();
    let mut e = reopen.open(&batches, &bytes);
    let opened = t2.elapsed();
    let t3 = Instant::now();
    let v = e.get(&t, &ak("s:text.0")).unwrap();
    let first = t3.elapsed();
    assert!(matches!(&v, Some(Value::Str(x)) if x.len() == n + 3 + k));
    println!("text {n} chars: open {opened:?}, first read {first:?}");
    let t4 = Instant::now();
    e.revert(&id).unwrap().unwrap();
    println!("text {n} chars: undo commit {:?}", t4.elapsed());
}

// spec/crdt.md §5.7 (ops resolve by index against the placement), §6, §8; spec/requirements.md,
// Scale (a change costs O(change)): a 10^5-char text, each step in a new session: a read of 100
// chars at a random index, one local insert (through the stored placement), one received insert
// (the join follows the stored placement), then two reads; then local inserts, deletes and moves
// by index at random places, edits as a text session writes them, and an undo; pages loaded and
// written (`state page load`, `state page write` spans), placement rows written, store bytes and
// time.
#[test]
#[ignore = "tier 2"]
fn text_range_and_edit_cost() {
    let n = 100_000usize;
    let mut lp = osis_node::local_peer::LocalPeer::new(2, 31, WallMs(1_700_000_000_000)).unwrap();
    let a = ak("s:text.0");
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    let b = lp.peers[1].engine.tid();
    m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(b))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    // not periodic: an edit whose window repeats elsewhere in its base matches the whole text
    let mut rng = SeededRng::from_u64(5);
    let text: String = (0..n).map(|_| char::from(b'a' + (osis_crypto::RngCore::next_u64(&mut rng) % 26) as u8)).collect();
    let mut m = Mutation::new();
    m.set(t, &TEXT, &Value::Str(text.clone())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    let at = (osis_crypto::RngCore::next_u64(&mut rng) % (n as u64 - 100)) as usize;
    let measure = |name: &str, t0: Instant| {
        let c = osis_node::costs::take();
        let count = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
        println!("text {n} chars, new session: {name} {:?}, {} pages loaded, {} placement blocks written", t0.elapsed(), count("state page load"), count("placement block write"));
    };
    lp.peers[1].restart(41).unwrap();
    osis_node::costs::take();
    let t0 = Instant::now();
    let got = lp.peers[1].engine.get_range(&t, &a, &[], at..at + 100).unwrap();
    measure("read of 100 chars at a random index", t0);
    assert_eq!(got, Some(Value::Str(text[at..at + 100].into())));
    lp.peers[1].restart(42).unwrap();
    osis_node::costs::take();
    let t0 = Instant::now();
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: vec![], op: Op::Insert { at, items: vec![Value::Str("XYZ".into())] } }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    measure("one insert", t0);
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: vec![], op: Op::Insert { at: n / 3, items: vec![Value::Str("UVW".into())] } }).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
    lp.peers[1].restart(43).unwrap();
    osis_node::costs::take();
    let t0 = Instant::now();
    lp.deliver(1, &pk).unwrap();
    measure("one received insert", t0);
    // the edits kept the stored placement: reads load only their pages
    for name in ["read of 100 chars after edits", "next read of 100 chars"] {
        lp.peers[1].restart(44).unwrap();
        osis_node::costs::take();
        let t0 = Instant::now();
        assert!(lp.peers[1].engine.get_range(&t, &a, &[], at..at + 100).unwrap().is_some());
        measure(name, t0);
    }
    // ASCII: byte indexes are char indexes; the later position first
    let mut want = text.clone();
    let mut ins = [(at, "XYZ"), (n / 3, "UVW")];
    ins.sort();
    for (i, x) in ins.iter().rev() {
        want.insert_str(*i, x);
    }
    assert_eq!(lp.peers[1].engine.get(&t, &a).unwrap(), Some(Value::Str(want)));
    // local inserts, deletes and moves by index at random places, each in a new session (the
    // typing hot path), then an undo of the last: pages loaded, placement rows written, store
    // bytes written
    let (mut e, _, bytes, reopen) = engine_reopenable(8);
    let me = e.tid();
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, me);
    m.set(t, &TEXT, &Value::Str(text.clone())).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut want: Vec<char> = text.chars().collect();
    let mut last = None;
    for step in 0..11 {
        drop(e);
        e = reopen.open(&Arc::new(AtomicU64::new(0)), &bytes);
        osis_node::costs::take();
        let w0 = bytes.load(Ordering::Relaxed);
        let t0 = Instant::now();
        let r = osis_crypto::RngCore::next_u64(&mut rng) as usize;
        let before = want.clone();
        let (name, op) = if step >= 9 {
            // what a text session writes: the whole text before and after
            let at = r % (want.len() - 5);
            let base = Value::Str(want.iter().collect());
            want.splice(at..at + 2, "EDIT".chars());
            ("edit (2 chars replaced by 4)", Op::Edit { base, new: Value::Str(want.iter().collect()) })
        } else if step % 3 == 0 {
            let at = r % want.len();
            want.splice(at..at, "XYZ".chars());
            ("insert of 3 chars", Op::Insert { at, items: vec![Value::Str("XYZ".into())] })
        } else if step % 3 == 2 {
            let at = r % (want.len() - 4);
            let moved: Vec<char> = want.drain(at..at + 4).collect();
            let to = (r / 7) % (want.len() + 1);
            want.splice(to..to, moved);
            ("move of 4 chars", Op::Move { at, len: 4, to })
        } else {
            let at = r % (want.len() - 5);
            want.drain(at..at + 5);
            ("delete of 5 chars", Op::Delete { at, len: 5 })
        };
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: vec![], op }).unwrap();
        last = Some((e.commit(m).unwrap().unwrap(), before));
        let c = osis_node::costs::take();
        if std::env::var_os("OSIS_SCALE_ROWS").is_some() {
            println!("costs: {c:?}");
        }
        let count = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
        println!("text {n} chars, new session: local {name} {:?}, {} pages loaded, {} pages and {} placement rows written, store writes {} B", t0.elapsed(), count("state page load"), count("state page write"), count("placement block write") + count("placement row write"), bytes.load(Ordering::Relaxed) - w0);
    }
    let (id, before) = last.unwrap();
    drop(e);
    let mut e = reopen.open(&Arc::new(AtomicU64::new(0)), &bytes);
    osis_node::costs::take();
    let (w0, t0) = (bytes.load(Ordering::Relaxed), Instant::now());
    e.revert(&id).unwrap().unwrap();
    let c = osis_node::costs::take();
    let count = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
    println!("text {n} chars, new session: undo of the last {:?}, {} pages loaded, {} placement rows written, store writes {} B", t0.elapsed(), count("state page load"), count("placement block write") + count("placement row write"), bytes.load(Ordering::Relaxed) - w0);
    drop(e);
    let mut e = reopen.open(&Arc::new(AtomicU64::new(0)), &bytes);
    osis_node::costs::take();
    let t0 = Instant::now();
    let got = e.get_range(&t, &a, &[], 500..600).unwrap();
    let c = osis_node::costs::take();
    let count = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
    println!("text {n} chars, new session: read of 100 chars after them {:?}, {} pages loaded", t0.elapsed(), count("state page load"));
    assert_eq!(got, Some(Value::Str(before[500..600].iter().collect())));
    assert_eq!(e.get(&t, &a).unwrap(), Some(Value::Str(before.into_iter().collect())));
}

// spec/permissions.md §5.1; spec/requirements.md, Scale (no operation O(history)): a role change while the node
// holds 10^4 content commits on other things of its own tree, and opening that store; then 10^4
// edge writes (`OSIS_SCALE_EDGES`, `OSIS_SCALE_DEMOTE`; 10^2 and 10^3 in a dev build, `size`).
// spec: none (spec/requirements.md has no numbered sections)
#[test]
#[ignore = "tier 2"]
fn role_change_and_open_cost() {
    let a = ak("app:v.0");
    let (mut e, batches, bytes, reopen) = engine_reopenable(6);
    let me = e.tid();
    let mut things = Vec::new();
    for _ in 0..100 {
        let mut m = Mutation::new();
        things.push(e.new_thing(&mut m, me));
        let t = *things.last().unwrap();
        m.set(t, &a, &Value::Int(0)).unwrap();
        e.commit(m).unwrap().unwrap();
    }
    let t0 = Instant::now();
    for i in 0..10_000i64 {
        let mut m = Mutation::new();
        m.set(things[(i % 100) as usize], &a, &Value::Int(i + 1)).unwrap();
        e.commit(m).unwrap().unwrap();
    }
    println!("10^4 content commits: {:?}", t0.elapsed());
    let t4 = Instant::now();
    let mut m = Mutation::new();
    let fresh = e.new_thing(&mut m, me);
    m.set(fresh, &a, &Value::Int(1)).unwrap();
    e.commit(m).unwrap().unwrap();
    println!("a new thing with 10^4 commits held: {:?}", t4.elapsed());
    let other = Tid::from_bytes([7; 15]);
    osis_node::costs::take();
    let t1 = Instant::now();
    let mut m = Mutation::new();
    m.op(things[0], &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(other))], op: Op::Set(ct::Edge { role: Role::Read, until: None, invite: None, tied: None }.to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap();
    println!("one grant with 10^4 commits held: {:?}", t1.elapsed());
    for (k, d, c) in osis_node::costs::take() {
        println!("  {k}: {d:?} ({c})");
    }
    drop(e);
    let t2 = Instant::now();
    let mut e = reopen.open(&batches, &bytes);
    let opened = t2.elapsed();
    let t3 = Instant::now();
    e.rebuild_index().unwrap();
    println!("open with 10^4 commits held: {opened:?} (rebuilding the index from every commit record: {:?})", t3.elapsed());
    // the record edge and the grant
    assert_eq!(e.roster(&things[0]).len(), 2);
    // 10^4 edge writes in the tree's one role component: 20 holders' roles toggled
    // a dev build: about 0.27 s per edge write with 10^4 commits held (debug-only checks)
    let n: usize = size("OSIS_SCALE_EDGES", 10_000, 100);
    let holders: Vec<Tid> = (0..20u8).map(|i| Tid::from_bytes([100 + i; 15])).collect();
    osis_node::costs::take();
    let t5 = Instant::now();
    for i in 0..n {
        let role = if (i / 20) % 2 == 0 { Role::Read } else { Role::Write };
        // an edge change is remove + put (spec/permissions.md §2)
        crate::common::set_edge(&mut e, things[i % 100], holders[i % 20], Some(crate::common::edge(role)), None);
    }
    println!("{n} edge writes: {:?}", t5.elapsed());
    for (k, d, c) in osis_node::costs::take() {
        println!("  {k}: {d:?} ({c})");
    }
    let roster = e.roster(&things[1]);
    drop(e);
    // three opens: the box's load varies, the least is the cost
    for k in 0..3 {
        osis_node::costs::take();
        let t6 = Instant::now();
        let e = reopen.open(&batches, &bytes);
        println!("open {k} with {n} edge writes held: {:?} ({} role components restored from their saved walks)", t6.elapsed(), e.walks_restored());
        for (k, d, c) in osis_node::costs::take() {
            println!("  {k}: {d:?} ({c})");
        }
        assert_eq!(e.roster(&things[1]), roster);
    }
    demotion_heavy_open();
}

/// Several admins writing edges on 20 docs of one org, the first admin demoting and re-granting
/// them all along (their writes it had not received drop), commits reaching the first admin in
/// batches: the first admin's open restored from its saved walk against evaluated anew.
fn demotion_heavy_open() {
    use osis_node::local_peer::LocalPeer;
    let n: usize = size("OSIS_SCALE_DEMOTE", 10_000, 1_000);
    let mut lp = LocalPeer::new(6, 77, WallMs(1_700_000_000_000)).unwrap();
    let admins: Vec<Tid> = (1..6).map(|i| lp.peers[i].engine.tid()).collect();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let org = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].engine.commit(m).unwrap();
    let mut m = Mutation::new();
    let docs: Vec<Tid> = (0..20).map(|_| lp.peers[0].engine.new_thing(&mut m, org)).collect();
    lp.peers[0].engine.commit(m).unwrap();
    let set = |e: &mut Engine, t: Tid, holder: Tid, role: Option<Role>| -> Option<osis_base::CommitId> {
        // an edge change is remove + put (spec/permissions.md §2)
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
        if let Some(r) = role {
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(ct::Edge { role: r, until: None, invite: None, tied: None }.to_value()) }).unwrap();
        }
        e.commit(m).ok().flatten()
    };
    for a in &admins {
        set(&mut lp.peers[0].engine, org, *a, Some(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let holders: Vec<Tid> = (0..30u8).map(|i| Tid::from_bytes([150 + i; 15])).collect();
    let mut x: u64 = 0x5eed;
    let mut rnd = |k: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % k
    };
    let mut queue: Vec<(usize, osis_base::CommitId)> = Vec::new();
    let t0 = Instant::now();
    for i in 0..n {
        for p in &lp.peers {
            p.clock.advance(1);
        }
        if i % 40 == 39 {
            // the first admin demotes an admin to write on the org, and re-grants it 20 writes later
            let a = admins[(i / 40) % 5];
            set(&mut lp.peers[0].engine, org, a, Some(Role::Write));
        } else if i % 40 == 19 && i > 40 {
            let a = admins[(i / 40 - 1) % 5];
            set(&mut lp.peers[0].engine, org, a, Some(Role::Admin));
        } else {
            let w = 1 + rnd(5) as usize;
            let roles = [None, Some(Role::Read), Some(Role::Write)];
            let (d, h, r) = (docs[rnd(20) as usize], holders[rnd(30) as usize], roles[rnd(3) as usize]);
            if let Some(id) = set(&mut lp.peers[w].engine, d, h, r) {
                queue.push((w, id));
            }
        }
        // the admins' commits reach the first admin in batches, a few late
        if i % 50 == 49 {
            let keep = queue.len() / 10;
            let (now, late): (Vec<_>, Vec<_>) = queue.drain(..).enumerate().partition(|(j, _)| !j.is_multiple_of(10) || keep == 0);
            queue = late.into_iter().map(|(_, x)| x).collect();
            for (_, (w, id)) in now {
                let pk = lp.peers[w].engine.package(&id).unwrap().unwrap();
                let _ = lp.deliver(0, &pk);
            }
        }
    }
    for (w, id) in std::mem::take(&mut queue) {
        let pk = lp.peers[w].engine.package(&id).unwrap().unwrap();
        let _ = lp.deliver(0, &pk);
    }
    println!("{n} edge writes by 5 admins with demotions every 40, delivered to the first admin: {:?}", t0.elapsed());
    let roster = lp.peers[0].engine.roster(&docs[0]);
    let t1 = Instant::now();
    lp.peers[0].restart(1).unwrap();
    println!("first admin's open, walk restored: {:?} ({} restored)", t1.elapsed(), lp.peers[0].engine.walks_restored());
    assert_eq!(lp.peers[0].engine.roster(&docs[0]), roster);
    lp.peers[0].engine.damage_walks(0).unwrap();
    let t2 = Instant::now();
    lp.peers[0].restart(2).unwrap();
    println!("first admin's open, walk evaluated anew: {:?} ({} restored)", t2.elapsed(), lp.peers[0].engine.walks_restored());
    assert_eq!(lp.peers[0].engine.roster(&docs[0]), roster);
}

mod long_aspect;
mod role_history;

use crate::net;

// spec/sync.md §6; spec/requirements.md, Scale: a first sync of N commits costs O(N). A writer
// writes N content commits (100 things, N/100 writes each) in a label at one host while a
// fresh reader syncs: the time at the reader, the writer and the hub, and the engine phases
// (`osis_node::costs`); then another fresh reader ingests every commit directly (`Engine::ingest`,
// no sync). `OSIS_SCALE_N` sets N (default 10^4; 10^3 in a dev build, `size`, which checks no budget).
#[test]
#[ignore = "tier 2"]
fn first_sync_cost() {
    let n: usize = size("OSIS_SCALE_N", 10_000, 1_000);
    let mut net = net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Read), (c, Role::Read)], &[host]);
    let things: Vec<Tid> = (0..100).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
    net.set_online(c, false);
    let t0 = Instant::now();
    for i in 0..n {
        net.write(a, things[i % things.len()], &format!("v{i}"));
    }
    let fill = t0.elapsed();
    net.busy.clear();
    osis_node::costs::take();
    let t1 = Instant::now();
    net.run();
    let first = t1.elapsed();
    let phases = osis_node::costs::take();
    let last = Some(net::s(&format!("v{}", n - 1)));
    assert_eq!(net.read(b, things[(n - 1) % 100]), last);
    let held = net.engine(b).commit_ids().len();
    assert!(held >= n, "{held} commits at the reader");
    let (rb, wa, hub) = (net.busy.get(&b).copied().unwrap_or_default(), net.busy.get(&a).copied().unwrap_or_default(), net.hub_busy);
    let ids = net.engine(a).commit_ids();
    let t2 = Instant::now();
    for id in &ids {
        let pk = net.engine(a).package(id).unwrap().unwrap();
        net.engine(c).ingest(&pk.bytes, pk.blobs).unwrap();
    }
    let direct = t2.elapsed();
    assert_eq!(net.read(c, things[(n - 1) % 100]), last);
    println!("first sync of {n} commits: {first:?} (reader {rb:?}, writer {wa:?}, hub {hub:?}); writing them {fill:?}; {} commits ingested directly: {direct:?}", ids.len());
    println!("engine phases during the sync, both nodes (inclusive; calls):");
    for (k, d, c) in &phases {
        println!("  {k}: {d:?} ({c})");
    }
    // at 10^4: ingest 3-4 s, the whole sync about 10 s; re-examining every pending commit after
    // each applied one took 540 s of 580
    let ingest = phases.iter().find(|p| p.0 == "ingest").map(|p| p.1).unwrap_or_default();
    let scale = (n as u64).max(1_000);
    if cfg!(debug_assertions) {
        return;
    }
    assert!(ingest.as_secs() < 30 * scale / 10_000, "ingesting {n} commits took {ingest:?}");
    assert!(first.as_secs() < 60 * scale / 10_000, "first sync of {n} commits took {first:?}");
}

// spec/sync.md §6, §7; spec/requirements.md, Scale: a change costs O(change). A label holding N
// content commits (100 things, N/100 writes each) at one host, synced by a writer and a
// reader; then one more write: the passes it causes at both nodes (time, and the entries and
// bodies they judge) do not grow with N. `OSIS_SCALE_MAX` caps N (default 10^4; 10^3 in a dev
// build, `size`).
#[test]
#[ignore = "tier 2"]
fn sync_pass_cost() {
    let max: usize = size("OSIS_SCALE_MAX", 10_000, 1_000);
    let mut n = 1_000;
    while n <= max {
        let mut net = net::Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.node(2, &[host]);
        let g = net.group(a, &[(b, Role::Read)], &[host]);
        let things: Vec<Tid> = (0..100).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
        let t0 = Instant::now();
        for i in 0..n {
            net.write(a, things[i % things.len()], &format!("v{i}"));
        }
        let fill = t0.elapsed();
        let t1 = Instant::now();
        net.run();
        let first = t1.elapsed();
        let l = net.label(a);
        let held = net.host_ids(host, &l).len();
        assert!(held >= n, "{held} entries at the host");
        // settled: a quiet round, then one new write
        net.advance(61_000);
        let before = (net.sync(a).pass_stats(), net.sync(b).pass_stats());
        let t2 = Instant::now();
        net.write(a, things[0], "one more");
        net.run();
        let one = t2.elapsed();
        let after = (net.sync(a).pass_stats(), net.sync(b).pass_stats());
        assert_eq!(net.read(b, things[0]), Some(net::s("one more")));
        println!("sync {n} commits ({held} entries): writes {fill:?}, first sync {first:?}; one more write synced in {one:?}, passes before/after (writer, reader): {before:?} / {after:?}");
        n *= 10;
    }
}

// spec/sync.md §5 (co-reader peer), §6; spec/requirements.md, Scale: a change to a label served
// with no host costs its local passes O(change). A dialable node and a writer, a label at no
// host holding N content commits (100 things); then one more write: the passes it causes at
// the serving node (time; passes, full, bodies, entries). `OSIS_SCALE_MAX` caps N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn sync_local_pass_cost() {
    let max: usize = size("OSIS_SCALE_MAX", 10_000, 10_000);
    let d = |x: osis_node::sync::PassStats, y: osis_node::sync::PassStats| (y.passes - x.passes, y.full - x.full, y.bodies - x.bodies, y.entries - x.entries);
    let mut n = 1_000;
    while n <= max {
        let mut net = net::Net::new();
        let a = net.node(1, &[]);
        let b = net.node(2, &[]);
        let acts = net.sync(a).publish_reach([0xa1; 32], Vec::new()).unwrap();
        net.actions(a, acts);
        let g = net.group(a, &[(b, Role::Read)], &[]);
        let things: Vec<Tid> = (0..100).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
        let t0 = Instant::now();
        for i in 0..n {
            net.write(a, things[i % things.len()], &format!("v{i}"));
        }
        net.run();
        let fill = t0.elapsed();
        net.advance(61_000);
        let s0 = net.sync(a).pass_stats();
        let t1 = Instant::now();
        net.write(a, things[0], "one more");
        net.run();
        let one = t1.elapsed();
        let s1 = net.sync(a).pass_stats();
        println!("local label of {n} commits (fill {fill:?}): one more write {one:?}, (passes, full, bodies, entries) {:?}", d(s0, s1));
        n *= 10;
    }
}

// spec/sync.md §6, §7; spec/permissions.md §4; spec/requirements.md, Scale: a role change
// re-judges only the labels whose verdicts can read it. 10 labels of `OSIS_SCALE_LABEL` (default
// 10^3) content commits each at one host, a writer and a reader; then an edge write on an
// actor no label's closure reaches (it should judge about nothing), then one on the first
// label's group (only that label's entries).
#[test]
#[ignore = "tier 2"]
fn sync_roles_pass_cost() {
    let n: usize = size("OSIS_SCALE_LABEL", 1_000, 1_000);
    let mut net = net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let addr = net.address(host);
    let groups: Vec<Tid> = (0..10).map(|i| net.group_seeded(a, &[(b, Role::Read)], vec![addr.clone()], 1 + i)).collect();
    let t0 = Instant::now();
    for g in &groups {
        let things: Vec<Tid> = (0..10).map(|i| net.item(a, *g, *g, &format!("t{i}"))).collect();
        for i in 0..n {
            net.write(a, things[i % things.len()], &format!("v{i}"));
        }
    }
    let fill = t0.elapsed();
    let t1 = Instant::now();
    net.run();
    let first = t1.elapsed();
    net.pair(c, a);
    net.advance(61_000);
    let stats = |net: &mut net::Net| (net.sync(a).pass_stats(), net.sync(b).pass_stats());
    let me = net.tid(a);
    let other = net.tid(c);
    // an actor of this node no label's closure holds
    let e = net.engine(a);
    let mut m = Mutation::new();
    let u = e.new_thing(&mut m, me);
    m.set(u, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    net.run();
    net.advance(61_000);
    let s0 = stats(&mut net);
    let t2 = Instant::now();
    net::set_edge(net.engine(a), u, other, Role::Read);
    net.run();
    let unrelated = t2.elapsed();
    let s1 = stats(&mut net);
    net.advance(61_000);
    let s2 = stats(&mut net);
    let t3 = Instant::now();
    net::set_edge(net.engine(a), groups[0], other, Role::Read);
    net.run();
    let related = t3.elapsed();
    let s3 = stats(&mut net);
    let d = |x: osis_node::sync::PassStats, y: osis_node::sync::PassStats| (y.passes - x.passes, y.full - x.full, y.bodies - x.bodies, y.entries - x.entries);
    println!(
        "10 labels x {n} commits: writes {fill:?}, first sync {first:?}; unrelated edge {unrelated:?}, (passes, full, bodies, entries) writer {:?} reader {:?}; related edge {related:?}, writer {:?} reader {:?}",
        d(s0.0, s1.0),
        d(s0.1, s1.1),
        d(s2.0, s3.0),
        d(s2.1, s3.1)
    );
}

// spec/commits.md §5 (replaced, judged from the held set), spec/requirements.md, Scale (no
// operation O(history)): a set of N one-element commits, then 5 deltas by another writer older
// than all of them. Each late delta applied and the first commit judged alone, then 5 more in
// one batch, then one 5 commits late: an unbounded set (nothing judged) against a keep-at-least
// one, and the keep-at-least one compacted after the N commits; then every body judged, as
// node-sync does after a validity flip. `OSIS_SCALE_N` sets N (default 3000).
#[test]
#[ignore = "tier 2"]
fn late_delta_deaths_cost_spec_crdt_4_8() {
    let n: usize = size("OSIS_SCALE_N", 3000, 3000);
    for (name, asp, key, compact) in [("unbounded set", &TAGS, "s:tags.0", false), ("keep-at-least set", &KEPT, "s:kept.0", false), ("keep-at-least set, compacted", &KEPT, "s:kept.0", true)] {
        let mut lp = osis_node::local_peer::LocalPeer::new(2, 41, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(b))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        let add = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, v: String| {
            let mut m = Mutation::new();
            m.op(t, asp, PathOp { path: Vec::new(), op: Op::Add(Value::Str(v)) }).unwrap();
            lp.peers[i].commit(m).unwrap().unwrap()
        };
        // the late writer's deltas: older than everything below
        let mut late = Vec::new();
        for i in 0..10 {
            late.push(add(&mut lp, 1, format!("late{i}")));
        }
        lp.advance(1_000);
        let t0 = Instant::now();
        let mut ids = Vec::new();
        for i in 0..n {
            ids.push(add(&mut lp, 0, format!("e{i}")));
        }
        let fill = t0.elapsed();
        let k = ak(key);
        if compact {
            // every late delta below is older than the compaction
            lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
        }
        let pks = lp.packages(1).unwrap();
        let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
        let mut each = Vec::new();
        for c in &late[..5] {
            let t1 = Instant::now();
            lp.deliver(0, &pk(c)).unwrap();
            lp.peers[0].engine.replaced_at(&ids[0], &t, &k).unwrap();
            each.push(t1.elapsed());
        }
        osis_node::costs::take();
        let t2 = Instant::now();
        for c in &late[5..] {
            lp.deliver(0, &pk(c)).unwrap();
        }
        lp.peers[0].engine.replaced_at(&ids[0], &t, &k).unwrap();
        let batch = t2.elapsed();
        let t3 = Instant::now();
        add(&mut lp, 0, "z".into());
        let local = t3.elapsed();
        // a late delta from the recent past: 5 commits sort after it
        lp.advance(1);
        let recent = add(&mut lp, 1, "recent".into());
        lp.advance(1);
        for i in 0..5 {
            add(&mut lp, 0, format!("r{i}"));
        }
        let pks = lp.packages(1).unwrap();
        let t4 = Instant::now();
        lp.deliver(0, &pks.iter().find(|p| p.id == recent).unwrap().clone()).unwrap();
        lp.peers[0].engine.replaced_at(&ids[0], &t, &k).unwrap();
        let recent = t4.elapsed();
        let t5 = Instant::now();
        for c in &ids {
            lp.peers[0].engine.replaced_at(c, &t, &k).unwrap();
        }
        println!("{name} n={n}: fill {fill:?}; late deltas each {each:?}; 5 late deltas in one batch {batch:?}; one in-order local write {local:?}; a recent late delta {recent:?}; every body judged {:?}", t5.elapsed());
        for (k, d, c) in osis_node::costs::take() {
            println!("  {k}: {d:?} ({c})");
        }
    }
}


// spec/permissions.md §5.2, spec/crdt.md §4.6 (un-merge a function of the held set), spec/
// requirements.md, Scale: a set of N one-element commits by the first admin (0) and one add by writer B
// (1); admin C (2), who never saw it, revokes B: the add goes invalid at the first admin (a flip). Then
// B's add written after the revoke reaches the first admin invalid. Both un-merge in place (validity only
// fell, the add supersedes nothing), O(state), no body read. `OSIS_SCALE_N` sets N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn validity_flip_cost_spec_permissions_5_2() {
    let n: usize = size("OSIS_SCALE_N", 10_000, 10_000);
    let mut lp = osis_node::local_peer::LocalPeer::new(3, 43, WallMs(1_700_000_000_000)).unwrap();
    let me = lp.peers[0].engine.tid();
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    for (x, r) in [(b, Role::Write), (c, Role::Admin)] {
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(x))], op: Op::Set(ct::Edge { role: r, until: None, invite: None, tied: None }.to_value()) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    lp.sync_all().unwrap();
    let add = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, v: String| {
        let mut m = Mutation::new();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(Value::Str(v)) }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let t0 = Instant::now();
    for i in 0..n {
        add(&mut lp, 0, format!("e{i}"));
    }
    let fill = t0.elapsed();
    let bs = add(&mut lp, 1, "b".into());
    let pk1 = lp.packages(1).unwrap();
    lp.deliver(0, pk1.iter().find(|p| p.id == bs).unwrap()).unwrap();
    // C revokes B without having seen the add
    let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([t]))]), content: BTreeMap::from([(b, BTreeSet::from([t]))]) };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(b)) }).unwrap();
    m.frontier(f.to_value());
    let rv = lp.peers[2].commit(m).unwrap().unwrap();
    let late = add(&mut lp, 1, "late".into());
    let pk2 = lp.packages(2).unwrap();
    let pk1 = lp.packages(1).unwrap();
    let k = ak("s:tags.0");
    let tags = |lp: &mut osis_node::local_peer::LocalPeer| match lp.peers[0].engine.get(&t, &k).unwrap() {
        Some(Value::Set(s)) => s.len(),
        _ => 0,
    };
    assert_eq!(tags(&mut lp), n + 1);
    osis_node::costs::take();
    let t1 = Instant::now();
    lp.deliver(0, pk2.iter().find(|p| p.id == rv).unwrap()).unwrap();
    let flip = t1.elapsed();
    assert_eq!(tags(&mut lp), n);
    let t2 = Instant::now();
    lp.deliver(0, pk1.iter().find(|p| p.id == late).unwrap()).unwrap();
    let arrive = t2.elapsed();
    assert_eq!(tags(&mut lp), n);
    println!("n={n}: fill {fill:?}; revoke flipping one add invalid {flip:?}; an invalid add arriving {arrive:?}");
    for (k, d, c) in osis_node::costs::take() {
        println!("  {k}: {d:?} ({c})");
    }
}

/// Sets key `k` of map aspect `asp` of `t` to `v` at node `n`, one commit.
fn put_key(net: &mut net::Net, n: usize, t: Tid, asp: &Aspect<Value>, k: &str, v: &str) -> osis_base::CommitId {
    put_keys(net, n, t, asp, &[k.to_string()], v)
}

/// Sets keys `ks` of map aspect `asp` of `t` to `v` at node `n`, one commit.
fn put_keys(net: &mut net::Net, n: usize, t: Tid, asp: &Aspect<Value>, ks: &[String], v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    for k in ks {
        m.op(t, asp, PathOp { path: vec![PathSeg::Key(net::s(k))], op: Op::Set(net::s(v)) }).unwrap();
    }
    net.engine(n).commit(m).unwrap().unwrap()
}

// spec/sync.md §6, §7; spec/commits.md §5; spec/requirements.md, Scale: a change to one body of
// a big aspect judges O(change), not the aspect. N keys on one thing (`OSIS_SCALE_N`, default
// 10^3) in at most 10^3 commits (`OSIS_SCALE_PER` keys each, default N/10^3 rounded up: a commit
// costs its joins at both nodes, about 14 ms per one-key commit at 10^4, so 10^4 bodies takes
// `OSIS_SCALE_PER=1`) at one host, a writer and a reader: (1) under purge on replace (every body
// live) one more key, then one overwriting the first body's keys (kills that body, dropped with
// the kill); (2) under an expiry, an older commit expiring
// alone; (3) N things in the group, one write (the closure taken once per pass;
// `OSIS_SCALE_CLOSURE` things, default N; created `OSIS_SCALE_BATCH` per commit, default 500;
// the setup's time and spans printed: creation is O(things created) at both nodes). The passes'
// (passes, full, bodies, entries) at both nodes.
#[test]
#[ignore = "tier 2"]
fn sync_aspect_pass_cost() {
    let n: usize = size("OSIS_SCALE_N", 1_000, 1_000);
    let d = |x: osis_node::sync::PassStats, y: osis_node::sync::PassStats| (y.passes - x.passes, y.full - x.full, y.bodies - x.bodies, y.entries - x.entries);
    let mut net = net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "t");
    let u = net.item(a, g, g, "u");
    // expires 30 min before the N below
    put_key(&mut net, a, u, &net::BRIEFMAP, "first", "v");
    net.run();
    net.advance(1_800_000);
    let t0 = Instant::now();
    let per = size("OSIS_SCALE_PER", n.div_ceil(1_000), n.div_ceil(1_000)).max(1);
    let keys: Vec<String> = (0..n).map(|i| format!("k{i}")).collect();
    for ks in keys.chunks(per) {
        put_keys(&mut net, a, t, &net::GONEMAP, ks, "v");
        put_keys(&mut net, a, u, &net::BRIEFMAP, ks, "v");
    }
    net.run();
    let fill = t0.elapsed();
    let bodies = n.div_ceil(per);
    net.advance(61_000);
    let stats = |net: &mut net::Net| (net.sync(a).pass_stats(), net.sync(b).pass_stats());
    let s0 = stats(&mut net);
    let t1 = Instant::now();
    put_key(&mut net, a, t, &net::GONEMAP, "new", "v");
    net.run();
    let one = t1.elapsed();
    let s1 = stats(&mut net);
    net.advance(1_000);
    let s2 = stats(&mut net);
    let t2 = Instant::now();
    put_keys(&mut net, a, t, &net::GONEMAP, &keys[..per.min(n)], "w");
    net.run();
    let kill = t2.elapsed();
    let s3 = stats(&mut net);
    println!("purge-on-replace map of {n} keys in {bodies} live bodies (fill {fill:?}): one more key {one:?}, writer {:?} reader {:?}; overwriting a body {kill:?}, writer {:?} reader {:?}", d(s0.0, s1.0), d(s0.1, s1.1), d(s2.0, s3.0), d(s2.1, s3.1));
    // the expiring map: its first commit expires alone, the N stay
    let s4 = stats(&mut net);
    let t3 = Instant::now();
    net.advance(1_800_000);
    let exp = t3.elapsed();
    let s5 = stats(&mut net);
    println!("expiring map of {n} keys in {bodies} live commits: an older one expiring {exp:?} (in a 30 min tick), writer {:?} reader {:?}", d(s4.0, s5.0), d(s4.1, s5.1));
    // a big closure
    let k: usize = size("OSIS_SCALE_CLOSURE", n, n);
    // things per commit (`OSIS_SCALE_BATCH`): one commit of 10^4 costs O(k) at both ends
    let batch: usize = size("OSIS_SCALE_BATCH", 500, 500).max(1);
    osis_node::costs::take();
    let t5 = Instant::now();
    let e = net.engine(a);
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    for i in (0..k).step_by(batch) {
        let mut m = Mutation::new();
        for _ in i..k.min(i + batch) {
            let x = e.new_thing(&mut m, g);
            items.items.insert(x);
        }
        m.set(g, &ct::GROUP, &items).unwrap();
        e.commit(m).unwrap();
    }
    let commits = t5.elapsed();
    net.run();
    net.advance(61_000);
    let setup = t5.elapsed();
    let spans: Vec<String> = osis_node::costs::take().into_iter().map(|(s, d, c)| format!("{s} {d:.2?}/{c}")).collect();
    println!("closure setup, {batch} things per commit: commits at the writer {commits:?}, spans {}", spans.join(", "));
    let s6 = stats(&mut net);
    let t4 = Instant::now();
    net.write(a, t, "one more");
    net.run();
    let w = t4.elapsed();
    let s7 = stats(&mut net);
    println!("closure of {k} things (setup {setup:?}): one write {w:?}, writer {:?} reader {:?}", d(s6.0, s7.0), d(s6.1, s7.1));
}

// spec/permissions.md §5.2 (a held delta gives its writes; a snapshot's copies of them taken
// before it are compared), spec/requirements.md, Scale: a fresh node gets the first admin's snapshot of a
// set of N one-element commits first, then the commits, then a writer's snapshot of the result;
// each commit compares against the snapshot's copies of its writes (indexed once), so the whole
// costs O(N log N), not O(N^2). `OSIS_SCALE_N` sets N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn snapshot_first_sync_cost_spec_permissions_5_2() {
    let n: usize = size("OSIS_SCALE_N", 10_000, 2_000);
    let mut lp = osis_node::local_peer::LocalPeer::new(2, 45, WallMs(1_700_000_000_000)).unwrap();
    let me = lp.peers[0].engine.tid();
    let w = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(w))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let base = lp.packages(0).unwrap();
    for i in 0..n {
        let mut m = Mutation::new();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(Value::Str(format!("e{i}"))) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    let k = ak("s:tags.0");
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
    for p in &base {
        lp.deliver(1, p).unwrap();
    }
    let t0 = Instant::now();
    lp.deliver(1, pks.iter().find(|p| p.id == snap).unwrap()).unwrap();
    let first = t0.elapsed();
    osis_node::costs::take();
    let t1 = Instant::now();
    for p in pks.iter().filter(|p| p.id != snap && !base.iter().any(|b| b.id == p.id)) {
        lp.deliver(1, p).unwrap();
    }
    let rest = t1.elapsed();
    let t2 = Instant::now();
    lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    let again = t2.elapsed();
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), lp.peers[0].engine.get(&t, &k).unwrap());
    println!("n={n}: the snapshot first {first:?}; then the {n} commits {rest:?}; a snapshot of the result {again:?}");
    for (k, d, c) in osis_node::costs::take() {
        println!("  {k}: {d:?} ({c})");
    }
}

// spec/commits.md §5 (a snapshot dropped at its bound stands in), spec/permissions.md
// §5.1, notes/testing.md budgets: B (1) gets the first admin's writes only through K snapshots of one
// map key, each received apart and dropped at its purge-on-replace cover once the next replaces it;
// then B's demotion frontier for the first admin (it lists the snapshots, received, none covered).
// `OSIS_SCALE_N` sets K (default 1000; 5 commits per snapshot).
#[test]
#[ignore = "tier 2"]
fn dropped_snapshot_frontier_cost_spec_commits_5() {
    let k: usize = size("OSIS_SCALE_N", 1000, 1000);
    let mut lp = osis_node::local_peer::LocalPeer::new(2, 47, WallMs(1_700_000_000_000)).unwrap();
    let me = lp.peers[0].engine.tid();
    let b = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(b))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let key = ak("s:gone.0");
    let t0 = Instant::now();
    for i in 0..k {
        for j in 0..5 {
            let mut m = Mutation::new();
            m.op(t, &GONE, PathOp { path: vec![PathSeg::Key(Value::Str("k".into()))], op: Op::Set(Value::Str(format!("v{i}.{j}"))) }).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
        }
        let s = lp.peers[0].engine.snapshot(&t, &key).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&s).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
        lp.advance(1_000);
        lp.peers[1].engine.tick().unwrap();
    }
    let fill = t0.elapsed();
    let e = &mut lp.peers[1].engine;
    let kept = e.drop_counts()[2];
    let scope = osis_perm::DemotionScope { roles: BTreeMap::new(), content: BTreeMap::from([(me, BTreeSet::from([t]))]) };
    let now = e.now();
    let t2 = Instant::now();
    let f = e.frontier(&scope, now).unwrap();
    let frontier = t2.elapsed();
    assert!(f.commits.len() >= k);
    println!("k={k} ({kept} kept): fill {fill:?}; demotion frontier {frontier:?} ({} commits)", f.commits.len());
}

/// Resident set size of this process (KiB; Linux).
fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    s.split_whitespace().nth(1).and_then(|p| p.parse::<u64>().ok()).unwrap_or(0) * 4
}

/// A net where `x` writes ephemeral data on durable thing `t` that `b` holds: (net, b, x, t).
fn eph_net() -> (crate::net::Net, usize, usize, Tid) {
    use crate::net::*;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let x = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (x, Role::Write)], &[host]);
    let t = net.item(a, g, g, "durable");
    net.run();
    (net, b, x, t)
}

/// Node `x`'s ephemeral commits setting `per` keys of `doc:notes.0` of `t` each, `commits` times
/// (fresh keys every time), as blobs.
fn eph_map_commits(net: &mut crate::net::Net, x: usize, t: Tid, commits: usize, per: usize, value: &Value) -> Vec<osis_commit::CommitBlob> {
    let notes = crate::common::ak("doc:notes+.0");
    let mut blobs = Vec::new();
    for c in 0..commits {
        let mut m = Mutation::new();
        for e in 0..per {
            m.op(t, &notes, PathOp { path: vec![PathSeg::Key(Value::Int((c * per + e) as i64))], op: Op::Set(value.clone()) }).unwrap();
        }
        net.engine(x).write(m).unwrap();
        blobs.extend(take_memory(net, x));
    }
    blobs
}

/// Node `x`'s own memory commits not placed by its sync engine yet, as blobs (each once).
fn take_memory(net: &mut crate::net::Net, x: usize) -> Vec<osis_commit::CommitBlob> {
    thread_local! { static TAKEN: std::cell::RefCell<std::collections::BTreeSet<osis_base::CommitId>> = Default::default(); }
    let ids = net.sync(x).unplaced_memory_commits();
    let e = net.engine(x);
    ids.into_iter().filter(|c| TAKEN.with(|t| t.borrow_mut().insert(*c))).filter_map(|c| e.memory_blob(&c).unwrap()).collect()
}

// issues/eph-node-cost-bounds.md (memory), spec/sync.md §9 (caps): RSS a holder gains per
// encoded byte held, against what the node cap charges (`Engine::memory_charge`), for
// `OSIS_EPH_SHAPE` tiny (many tiny map entries), large (a few 8 KB strings) or aspects (one small
// write on each of many aspects). `OSIS_EPH_PER` entries per commit (tiny), `OSIS_EPH_ROOM`: what
// the holder may hold (`Engine::ingest_memory`, as a node passes its cap's room; unset: no
// bound). Run each shape alone (a fresh process):
// `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 scale::eph_decoded_memory`.
#[test]
#[ignore]
fn eph_decoded_memory() {
    let shape = std::env::var("OSIS_EPH_SHAPE").unwrap_or_else(|_| "tiny".into());
    let (mut net, b, x, t) = eph_net();
    let (commits, per, value) = match shape.as_str() {
        "large" => (size("OSIS_EPH_COMMITS", 64, 4), 4, crate::net::s(&"v".repeat(8000))),
        "aspects" => (size("OSIS_EPH_COMMITS", 16, 2), 2000, Value::Int(1)),
        _ => (size("OSIS_EPH_COMMITS", 64, 4), size("OSIS_EPH_PER", 2000, 2000), Value::Int(1)),
    };
    let room: u64 = std::env::var("OSIS_EPH_ROOM").ok().and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
    let blobs = if shape == "aspects" {
        // one register write on each of `per` aspects, `commits` times (fresh aspects each time)
        let mut blobs = Vec::new();
        for c in 0..commits {
            let mut m = Mutation::new();
            for e in 0..per {
                m.set(t, &crate::common::ak(&format!("x:a{:06}+.0", c * per + e)), &value).unwrap();
            }
            net.engine(x).write(m).unwrap();
            blobs.extend(take_memory(&mut net, x));
        }
        blobs
    } else {
        eph_map_commits(&mut net, x, t, commits, per, &value)
    };
    let blob_bytes: usize = blobs.iter().map(|b| b.parts.iter().map(|p| p.delta.len()).sum::<usize>()).sum();
    let rss0 = rss_kib();
    let mut refused = 0;
    for bl in blobs {
        let ids: Vec<_> = net.engine(b).memory_commits().into_iter().map(|h| h.0).collect();
        let charged: u64 = ids.iter().map(|id| net.engine(b).memory_charge(id).unwrap()).sum();
        let left = room.saturating_sub(charged);
        if matches!(net.engine(b).ingest_memory(&bl.encode(), left).unwrap(), osis_node::Ingested::TooLarge(_)) {
            refused += 1;
        }
    }
    println!("decoded memory ({shape}): {refused} commits refused for the room");
    let rss = rss_kib().saturating_sub(rss0);
    let writes = commits * per;
    let ids: Vec<_> = net.engine(b).memory_commits().into_iter().map(|h| h.0).collect();
    let charge: u64 = ids.iter().map(|id| net.engine(b).memory_charge(id).unwrap()).sum();
    let held = charge as usize;
    println!("decoded memory ({shape}): charged {} KiB", charge / 1024);
    println!("decoded memory ({}): {commits} commits x {per} entries: {} KiB encoded (held {} KiB), RSS +{rss} KiB: {:.1}x, {} B per write", shape, blob_bytes / 1024, held / 1024, rss as f64 * 1024.0 / blob_bytes.max(1) as f64, rss * 1024 / writes as u64);
}

// spec/crdt.md §4.7, spec/commits.md §5 (an expired ephemeral delta is held as its leftover until a
// snapshot covers it): what a holder keeps per expired ephemeral commit, and that a snapshot frees
// it. `x` writes `OSIS_EPH_COMMITS` commits, each one expiring list element (a disappearing
// message: never superseded), `b` holds them. Past their expiry `b` holds their leftovers; `x`
// expires them too, its compaction trigger weighs the leftovers and writes a snapshot, `b` takes
// it and drops every leftover. Prints RSS, held commits and the charge at each stage, and the
// expiry's phases. Run alone:
// `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 scale::eph_leftover_memory`.
#[test]
#[ignore]
fn eph_leftover_memory() {
    let (mut net, b, x, t) = eph_net();
    let n = size("OSIS_EPH_COMMITS", 2_000, 200);
    let log = crate::common::LOG;
    let mut m = Mutation::new();
    m.set(t, &log, &Value::List(vec![Value::Str("start".into())])).unwrap();
    net.engine(x).write(m).unwrap();
    let mut blobs = take_memory(&mut net, x);
    let t0 = std::time::Instant::now();
    for c in 0..n {
        let mut m = Mutation::new();
        m.op(t, &log, PathOp { path: vec![], op: Op::Insert { at: c + 1, items: vec![Value::Str(c.to_string())] } }).unwrap();
        m.expires(t, &log, osis_base::WallMs(net.now() + 60_000)).unwrap();
        net.engine(x).write(m).unwrap();
        blobs.extend(take_memory(&mut net, x));
    }
    let t1 = t0.elapsed();
    let held = |net: &mut crate::net::Net| -> (usize, u64) {
        let ids: Vec<_> = net.engine(b).memory_commits().into_iter().filter(|h| h.1 > 0).map(|h| h.0).collect();
        let charge = ids.iter().map(|id| net.engine(b).memory_charge(id).unwrap()).sum();
        (ids.len(), charge)
    };
    let base = (rss_kib(), held(&mut net));
    for bl in &blobs {
        net.engine(b).ingest_memory(&bl.encode(), u64::MAX).unwrap();
    }
    let t2 = t0.elapsed();
    let ingested = (rss_kib(), held(&mut net));
    net.clock.advance(61_000);
    osis_node::costs::take();
    net.sync(b).expire_due();
    let t3 = t0.elapsed();
    for (k, d, c) in osis_node::costs::take() {
        println!("leftover memory: expiry phase {k}: {d:?} x{c}");
    }
    let expired = (rss_kib(), held(&mut net));
    net.sync(x).expire_due();
    let snaps = net.engine(x).memory_compactions(false).unwrap();
    for bl in take_memory(&mut net, x) {
        net.engine(b).ingest_memory(&bl.encode(), u64::MAX).unwrap();
    }
    let covered = (rss_kib(), held(&mut net));
    println!("leftover memory: {n} expiring commits; write {t1:?}, ingest {:?}, expire {:?}; {} snapshot(s) by x", t2 - t1, t3 - t2, snaps.len());
    for (stage, (rss, (commits, charge))) in [("baseline", base), ("ingested", ingested), ("expired", expired), ("covered", covered)] {
        println!("leftover memory: {stage}: RSS {rss} KiB, {commits} commits held, charged {charge} B");
    }
    assert!(snaps.len() == 1 && covered.1.0 <= base.1.0 + 1, "the leftovers dropped under x's snapshot");
    let ak = crate::common::ak("t:log+.0");
    assert_eq!(net.engine(b).get(&t, &ak).unwrap(), net.engine(x).get(&t, &ak).unwrap());
}

/// Peak resident set (KiB) since the last `reset_peak` (Linux `VmHWM`).
fn peak_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find_map(|l| l.strip_prefix("VmHWM:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

/// Resets `peak_kib` to the current resident set (Linux `clear_refs` 5).
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

/// Packages as bytes (`big_map_apply_memory` hands them to a child process).
fn encode_packages(pks: &[osis_node::local_peer::Package]) -> Vec<u8> {
    let b = |x: &[u8]| Value::Bytes(x.to_vec());
    osis_base::encode(&Value::List(pks.iter().map(|p| Value::List(vec![b(&p.id.0), b(&p.bytes), Value::List(p.blobs.iter().map(|(i, x)| Value::List(vec![b(&i.0), b(x)])).collect())])).collect()))
}

fn decode_packages(bytes: &[u8]) -> Vec<osis_node::local_peer::Package> {
    let lim = osis_base::Limits { max_depth: 8, max_bytes: bytes.len() };
    let bytes_of = |v: &Value| match v {
        Value::Bytes(x) => x.clone(),
        _ => panic!("package file"),
    };
    let arr = |v: &Value| -> [u8; 32] { bytes_of(v).try_into().unwrap() };
    let Value::List(pks) = osis_base::decode(bytes, &lim).unwrap() else { panic!("package file") };
    pks.iter()
        .map(|p| {
            let Value::List(f) = p else { panic!("package file") };
            let Value::List(blobs) = &f[2] else { panic!("package file") };
            let blobs = blobs
                .iter()
                .map(|x| {
                    let Value::List(x) = x else { panic!("package file") };
                    (BlobId(arr(&x[0])), bytes_of(&x[1]))
                })
                .collect();
            osis_node::local_peer::Package { id: osis_base::CommitId(arr(&f[0])), bytes: bytes_of(&f[1]), blobs }
        })
        .collect()
}

// spec/requirements.md, Scale (a value needs not be whole in memory), spec/crdt.md §8 (pages),
// issues/durable-decode-bound.md:
// peak memory above the resident set before each step, while one node writes an N-key map in one
// commit and snapshots it, then, each in a fresh process (so no step reuses memory an earlier one
// freed), a node holding the thing applies that commit, one starts from the snapshot alone, and
// one holding both judges the commit covered and the snapshot live and drops the commit.
// The stores are in memory, so what a step stores stays resident too (`kept`).
// `OSIS_SCALE_N` sets N (default 10^6 in release: the writer peaks at about 10 GB, run it alone).
#[test]
#[ignore]
fn big_map_apply_memory() {
    let step = |what: &str, f: &mut dyn FnMut()| {
        let rss0 = rss_kib();
        reset_peak();
        let t0 = Instant::now();
        f();
        let wall = t0.elapsed();
        let (peak, rss1) = (peak_kib(), rss_kib());
        println!("{what}: {wall:?}, peak +{} MiB, kept +{} MiB", peak.saturating_sub(rss0) / 1024, rss1.saturating_sub(rss0) / 1024);
    };
    let n = size("OSIS_SCALE_N", 1_000_000, 10_000);
    let a = ak("app:big.0");
    // the child: a fresh node takes the thing's commits, then the one measured
    if let Ok(file) = std::env::var("OSIS_SCALE_APPLY_FILE") {
        let bytes = std::fs::read(&file).unwrap();
        let mut pks = decode_packages(&bytes);
        let (target, t) = (pks.pop().unwrap(), pks.pop().unwrap());
        let Value::List(t) = osis_base::decode(&t.bytes, &osis_base::Limits { max_depth: 4, max_bytes: t.bytes.len() }).unwrap() else { panic!() };
        let (Value::Tid(t), Value::Int(now)) = (&t[0], &t[1]) else { panic!() };
        let mut p = osis_node::local_peer::Peer::new(5, WallMs(*now as u64)).unwrap();
        for pk in &pks {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        drop(bytes);
        let what = std::env::var("OSIS_SCALE_APPLY").unwrap_or_default();
        if what == "covered" {
            // holding the commit (`fill`, the thing package's ID) and the snapshot: compaction's
            // reads of both (issues/durable-decode-bound.md step 4)
            let (fill, snap) = (pks.last().unwrap().id, target.id);
            p.engine.ingest(&target.bytes, target.blobs.clone()).unwrap();
            step(&format!("n={n} judge the commit covered"), &mut || assert_eq!(p.engine.covered(&snap, &fill, t, &a).unwrap(), Some(true)));
            step(&format!("n={n} judge the snapshot live"), &mut || assert!(p.engine.body_live(&snap, t, &a).unwrap()));
            step(&format!("n={n} drop the covered commit"), &mut || p.engine.drop_body(&fill, t, &a).unwrap());
            assert_eq!(p.engine.get_at(t, &a, &[PathSeg::Key(Value::Int(7))]).unwrap(), Some(Value::Int(7)));
            return;
        }
        step(&format!("n={n} apply the {what}"), &mut || {
            p.engine.ingest(&target.bytes, target.blobs.clone()).unwrap();
        });
        assert_eq!(p.engine.get_at(t, &a, &[PathSeg::Key(Value::Int(7))]).unwrap(), Some(Value::Int(7)));
        step(&format!("n={n} reopen and read one key"), &mut || {
            p.restart(6).unwrap();
            assert_eq!(p.engine.get_at(t, &a, &[PathSeg::Key(Value::Int(7))]).unwrap(), Some(Value::Int(7)));
        });
        return;
    }
    let mut lp = osis_node::local_peer::LocalPeer::new(1, 49, WallMs(1_700_000_000_000)).unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let setup = lp.packages(0).unwrap();
    let kv: osis_base::ValueMap = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let mut fill = None;
    step(&format!("n={n} write the commit"), &mut || {
        let mut m = Mutation::new();
        m.set(t, &a, &Value::Map(kv.clone())).unwrap();
        fill = lp.peers[0].commit(m).unwrap();
    });
    drop(kv);
    let mut snap = None;
    step(&format!("n={n} snapshot"), &mut || snap = lp.peers[0].engine.snapshot(&t, &a).unwrap());
    let (fill, snap) = (fill.unwrap(), snap.unwrap());
    let fill = lp.peers[0].engine.package(&fill).unwrap().unwrap();
    let snap = lp.peers[0].engine.package(&snap).unwrap().unwrap();
    let size_of = |p: &osis_node::local_peer::Package| p.bytes.len() + p.blobs.iter().map(|b| b.1.len()).sum::<usize>();
    println!("n={n}: commit {} KiB, snapshot {} KiB with pages", size_of(&fill) / 1024, size_of(&snap) / 1024);
    // the thing and the clock, as a package for the child
    let now = lp.peers[0].clock.now_wall_ms().0 as i64;
    let meta = osis_node::local_peer::Package { id: fill.id, bytes: osis_base::encode(&Value::List(vec![Value::Tid(t), Value::Int(now)])), blobs: Vec::new() };
    drop(lp);
    for (what, pk) in [("commit", &fill), ("snapshot", &snap), ("covered", &snap)] {
        let file = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("big-map-apply-{}.bin", std::process::id()));
        let mut pks = setup.clone();
        if what == "covered" {
            pks.push(fill.clone());
        }
        pks.extend([meta.clone(), pk.clone()]);
        std::fs::write(&file, encode_packages(&pks)).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "scale::big_map_apply_memory", "--nocapture", "--test-threads", "1"])
            .env("OSIS_SCALE_APPLY_FILE", &file)
            .env("OSIS_SCALE_APPLY", what)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&file);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{what}: {text}\n{}", String::from_utf8_lossy(&out.stderr));
        for l in text.lines().filter(|l| l.contains("n=")) {
            println!("{}", l.trim_start_matches("test scale::big_map_apply_memory ... "));
        }
    }
}

// spec/permissions.md §5.2 (a valid snapshot's copies govern a held original), notes/testing.md
// budgets: B (1) holds N set elements as the first admin's delta (one commit); the first admin adds one
// and snapshots; B joins that snapshot (copies of every held write), then one ordinary delta. For
// an unbounded and a keep-at-least set. `OSIS_SCALE_N` sets N (default 10^5).
#[test]
#[ignore = "tier 2"]
fn snapshot_join_cost_spec_permissions_5_2() {
    let n: usize = size("OSIS_SCALE_N", 100_000, 10_000);
    for (name, asp, key) in [("unbounded set", &TAGS, "s:tags.0"), ("keep-at-least set", &KEPT, "s:kept.0")] {
        let mut lp = osis_node::local_peer::LocalPeer::new(2, 49, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(w))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let t0 = Instant::now();
        let mut m = Mutation::new();
        m.set(t, asp, &Value::Set((0..n).map(|i| Value::Str(format!("e{i}"))).collect())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let fill = t0.elapsed();
        let t0 = Instant::now();
        lp.sync_all().unwrap();
        let synced = t0.elapsed();
        let k = ak(key);
        let add = |lp: &mut osis_node::local_peer::LocalPeer, v: &str| {
            let mut m = Mutation::new();
            m.op(t, asp, PathOp { path: Vec::new(), op: Op::Add(Value::Str(v.into())) }).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap()
        };
        add(&mut lp, "x");
        let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
        let one = add(&mut lp, "y");
        let pks = lp.packages(0).unwrap();
        let x = pks.iter().find(|p| p.id != snap && p.id != one && lp.peers[1].engine.package(&p.id).unwrap().is_none()).unwrap().clone();
        lp.deliver(1, &x).unwrap();
        osis_node::costs::take();
        let t0 = Instant::now();
        lp.deliver(1, pks.iter().find(|p| p.id == snap).unwrap()).unwrap();
        let join = t0.elapsed();
        let t1 = Instant::now();
        lp.deliver(1, pks.iter().find(|p| p.id == one).unwrap()).unwrap();
        let delta = t1.elapsed();
        assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), lp.peers[0].engine.get(&t, &k).unwrap());
        println!("{name}, n={n}: fill {fill:?}, sync {synced:?}; valid snapshot join {join:?}; then one delta {delta:?}");
        for (k, d, c) in osis_node::costs::take() {
            println!("  {k}: {d:?} ({c})");
        }
    }
}

// spec/permissions.md §6: what a role change costs an aspect of N commits with R requests on it
// (`retention::rejudge_purges`): a join, an honest demotion, a fall and a rise; named requests by an
// admin, aspect-wide ones by a plain writer with no right. `OSIS_SCALE_N`, `OSIS_SCALE_R`.
#[test]
#[ignore = "tier 2"]
fn purge_rejudge_cost() {
    use crate::common::{edge, new_thing, set_edge};
    use osis_base::{Ak, Role, Tid, Value};
    use osis_commit::PurgeItem;
    use osis_node::Mutation;
    use osis_schema::{Aspect, StaticSchema};
    static S: StaticSchema = StaticSchema::new("purgecost.osis", "revision 1; purgeable_by(author, admin) keep_history(forever) aspect l:msgs.0: string;\n");
    const MSG: Aspect<Value> = Aspect::new("l:msgs.0", &S);
    let var = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (n, r) = (var("OSIS_SCALE_N", 100_000), var("OSIS_SCALE_R", 10_000));
    let k = Ak::new("l:msgs.0").unwrap();
    for wide in [false, true] {
        let mut lp = crate::common::net(5, 0x9a);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let (x, y): (Tid, Tid) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(if wide { Role::Write } else { Role::Admin })), None);
        lp.sync_all().unwrap();
        let t0 = Instant::now();
        let mut ids = Vec::new();
        for i in 0..n {
            let mut m = Mutation::new();
            m.set(t, &MSG, &Value::Str(format!("m{i}"))).unwrap();
            ids.push(lp.peers[0].commit(m).unwrap().unwrap());
        }
        println!("wide {wide}: fill {n}: {:?}", t0.elapsed());
        let join = |lp: &mut osis_node::local_peer::LocalPeer, what: &str, who: Tid, e: Option<Role>| {
            let t1 = Instant::now();
            set_edge(&mut lp.peers[0].engine, t, who, e.map(edge), None);
            println!("wide {wide}: {what}: {:?}", t1.elapsed());
        };
        join(&mut lp, "join, no request", y, Some(Role::Write));
        let t2 = Instant::now();
        lp.advance(1);
        let mut pks = Vec::new();
        // delivering an aspect-wide request walks the aspect (`retention::on_apply`)
        let r = if wide { r / 10 } else { r };
        for i in 0..r {
            let mut m = Mutation::new();
            m.purge(if wide { PurgeItem::Aspect { tid: t, ak: k.clone() } } else { PurgeItem::Commit { commit: ids[i * n / r], tid: t, ak: k.clone() } });
            m.set(t, &MSG, &Value::Str(format!("p{i}"))).unwrap();
            let c = lp.peers[1].commit(m).unwrap().unwrap();
            pks.push(lp.peers[1].engine.package(&c).unwrap().unwrap());
        }
        println!("wide {wide}: sign {r}: {:?}", t2.elapsed());
        let t3 = Instant::now();
        for p in &pks {
            lp.deliver(0, p).unwrap();
        }
        println!("wide {wide}: deliver {r}: {:?}", t3.elapsed());
        let z = lp.peers[3].engine.tid();
        join(&mut lp, "join", z, Some(Role::Write));
        join(&mut lp, "fall (no frontier)", x, None);
        join(&mut lp, "rise", x, Some(if wide { Role::Write } else { Role::Admin }));
        if wide {
            join(&mut lp, "fall 2", x, None);
        } else {
            // an honest demotion: the frontier lists the requests
            let t4 = Instant::now();
            let d = osis_node::flows::Demotion { holder: x, new: None, retain: None };
            let done = lp.peers[0].engine.demote(&t, &d).unwrap();
            let size = done.commits.iter().filter_map(|c| lp.peers[0].engine.header(c)).filter_map(|h| h.frontier.clone()).map(|f| osis_base::encode(&f).len()).max();
            println!("wide {wide}: honest demotion: {:?}, frontier {size:?} bytes", t4.elapsed());
        }
    }
}

// spec/sync.md §2 (Route): the cost of `Engine::unrouted`, which every status runs under the engine lock: things with one holder, carried by a labeled group (the usual case) or with no route
#[test]
#[ignore = "tier 2"]
fn unrouted_cost() {
    let n = size("UNROUTED_N", 1000, 100);
    for carried in [true, false] {
        let (mut e, _, _) = engine(9);
        let me = e.tid();
        let group = |e: &mut Engine| {
            let mut m = Mutation::new();
            let g = e.new_thing(&mut m, me);
            m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
            e.commit(m).unwrap();
            e.give_own_secrets(&g).unwrap();
            g
        };
        let (g, other) = (group(&mut e), group(&mut e));
        e.create_label(&g, &[osis_label::Address { url: "quic://h".into(), key: [1; 32] }]).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let start = Instant::now();
        let mut items = Vec::new();
        for _ in 0..n {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, me);
            e.commit(m).unwrap();
            e.give_own_secrets(&t).unwrap();
            let holder = if carried { g } else { other };
            let mut m = Mutation::new();
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(edge.to_value()) }).unwrap();
            e.commit(m).unwrap();
            items.push(t);
        }
        if carried {
            let mut m = Mutation::new();
            m.set(g, &ct::GROUP, &ct::Group { items: items.iter().copied().collect(), ..Default::default() }).unwrap();
            for t in &items {
                m.set(*t, &ct::GROUPS, &BTreeSet::from([g])).unwrap();
            }
            e.commit(m).unwrap();
        }
        println!("carried {carried}: {n} things built in {:?}", start.elapsed());
        for _ in 0..3 {
            let t = Instant::now();
            let rows = e.unrouted().len();
            println!("  unrouted {:?}, {rows} rows", t.elapsed());
        }
    }
}

// spec/permissions.md §5.2 (Addenda): a thing with addenda is judged whole where it would be
// judged only for the authors whose roles moved. N one-element commits on t by its first admin
// (0); B (1) writes one, received by C (2) alone; 0 removes B and C's addendum keeps it. Team T
// (3) holds write on t; T then gains a member E (4): the walk continues under T, re-judging t for
// E alone, or whole with the addendum held. Printed with and without C's addendum at 0.
// `OSIS_SCALE_N` sets N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn addenda_rejudge_cost_spec_permissions_5_2() {
    let n: usize = size("OSIS_SCALE_N", 10_000, 1_000);
    for with in [false, true] {
        let mut lp = osis_node::local_peer::LocalPeer::new(5, 44, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let ids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.tid()).collect();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, ids[0]);
        lp.peers[0].commit(m).unwrap().unwrap();
        let grant = |lp: &mut osis_node::local_peer::LocalPeer, by: usize, on: Tid, x: Tid| {
            let mut m = Mutation::new();
            m.op(on, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(x))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
            lp.peers[by].commit(m).unwrap().unwrap()
        };
        for x in [ids[1], ids[2], ids[3]] {
            grant(&mut lp, 0, t, x);
        }
        lp.sync_all().unwrap();
        let add = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, v: String| {
            let mut m = Mutation::new();
            m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(Value::Str(v)) }).unwrap();
            lp.peers[i].commit(m).unwrap().unwrap()
        };
        for i in 0..n {
            add(&mut lp, 0, format!("e{i}"));
        }
        lp.advance(1_000);
        let bs = add(&mut lp, 1, "b".into());
        let pk = lp.packages(1).unwrap().into_iter().find(|p| p.id == bs).unwrap();
        lp.deliver(2, &pk).unwrap();
        lp.advance(1_000);
        let d = osis_node::flows::Demotion { holder: ids[1], new: None, retain: None };
        let rv = *lp.peers[0].engine.demote(&t, &d).unwrap().commits.last().unwrap();
        lp.advance(1_000);
        let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == rv).unwrap();
        lp.deliver(2, &pk).unwrap();
        let k = ak("s:tags.0");
        let tags = |lp: &mut osis_node::local_peer::LocalPeer| match lp.peers[0].engine.get(&t, &k).unwrap() {
            Some(Value::Set(s)) => s.len(),
            _ => 0,
        };
        if with {
            let known: BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
            for pk in lp.packages(2).unwrap().into_iter().filter(|p| !known.contains(&p.id)) {
                lp.deliver(0, &pk).unwrap();
            }
        }
        assert_eq!(tags(&mut lp), n + usize::from(with), "C's addendum keeps B's add");
        let g = grant(&mut lp, 3, ids[3], ids[4]);
        let pk = lp.packages(3).unwrap().into_iter().find(|p| p.id == g).unwrap();
        osis_node::costs::take();
        let t0 = Instant::now();
        lp.deliver(0, &pk).unwrap();
        let took = t0.elapsed();
        println!("n={n}, addendum held {with}: a member joining a holder of t {took:?}");
        for (k, d, c) in osis_node::costs::take() {
            println!("  {k}: {d:?} ({c})");
        }
    }
}

// spec: none (a measure, spec/requirements.md Scale: purge on replace costs a snapshot of the
// aspect per replacing edit). Bytes the store writes and time per replacing write, purge on
// replace against the same write with no history promised: a map of `OSIS_SCALE_N` (default
// 2000) entries of 100 bytes, one entry overwritten 20 times; a small register overwritten 200
// times. By hand, release:
// `cargo test --release -p osis-node --test it -- --ignored --nocapture scale::purge_on_replace_cost`
#[test]
#[ignore = "scale: by hand"]
fn purge_on_replace_cost() {
    use crate::common::{BIG, GONE, GONEMAP, REG, net, new_thing, s};
    let n: usize = std::env::var("OSIS_SCALE_N").ok().and_then(|x| x.parse().ok()).unwrap_or(2000);
    let written = |p: &mut osis_node::local_peer::Peer| p.backend.history().iter().map(|(r, v)| r.len() + v.len()).sum::<usize>();
    for (name, map) in [("purge on replace", &GONEMAP), ("no history", &BIG)] {
        let mut lp = net(1, 0x5ca1e);
        lp.peers[0].backend.record_history();
        let t = new_thing(&mut lp, 0);
        let fill: osis_base::ValueMap = (0..n).map(|i| (s(&format!("k{i:05}")), s(&"f".repeat(100)))).collect();
        let mut m = Mutation::new();
        m.set(t, map, &Value::Map(fill)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let before = written(&mut lp.peers[0]);
        let at = Instant::now();
        let edits = 20;
        for i in 0..edits {
            let mut m = Mutation::new();
            m.op(t, map, PathOp { path: vec![PathSeg::Key(s("k00007"))], op: Op::Set(s(&format!("v{i}"))) }).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
        }
        let per = at.elapsed() / edits;
        println!("COST map of {n} entries, {name}: {} bytes and {per:?} per replacing edit", (written(&mut lp.peers[0]) - before) / edits as usize);
    }
    for (name, reg) in [("purge on replace", &GONE), ("no history", &REG)] {
        let mut lp = net(1, 0x5ca1f);
        lp.peers[0].backend.record_history();
        let t = new_thing(&mut lp, 0);
        let before = written(&mut lp.peers[0]);
        let at = Instant::now();
        let edits = 200;
        for i in 0..edits {
            let mut m = Mutation::new();
            m.set(t, reg, &s(&format!("value {i}"))).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
        }
        let per = at.elapsed() / edits;
        println!("COST register, {name}: {} bytes and {per:?} per write", (written(&mut lp.peers[0]) - before) / edits as usize);
    }
}

// spec/commits.md §5 (keep for D, a snapshot replaced at the latest death among the writes no
// later snapshot carries): a kept set (D one day) edited hourly, compacted every C edits, each
// edit killing one long-lived element. After each edit every held snapshot is judged, as
// node-sync does on a death (`mark_killed`), and one past its bound and covered by the newest
// is dropped, as node-sync's compaction does. Prints the cost per edit and the snapshots held, which the D
// window bounds (a later snapshot keeps the history of the long-lived writes).
// `OSIS_SCALE_N` sets the elements (default 300).
#[test]
#[ignore = "tier 2"]
fn kept_snapshots_rejudged_per_death_cost_spec_commits_5() {
    let n: usize = size("OSIS_SCALE_N", 300, 300);
    let edits = 200;
    let every = 10;
    let mut lp = osis_node::local_peer::LocalPeer::new(1, 43, WallMs(1_700_000_000_000)).unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let k = ak("s:kept.0");
    let op = |lp: &mut osis_node::local_peer::LocalPeer, o: Op| {
        lp.advance(1);
        let mut m = Mutation::new();
        m.op(t, &KEPT, PathOp { path: Vec::new(), op: o }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    for i in 0..n {
        op(&mut lp, Op::Add(Value::Str(format!("e{i}"))));
    }
    let mut snaps = Vec::new();
    let mut per = Vec::new();
    for i in 0..edits {
        lp.advance(3_600_000);
        op(&mut lp, Op::Remove(Value::Str(format!("e{i}"))));
        op(&mut lp, Op::Add(Value::Str(format!("n{i}"))));
        if i % every == 0 {
            lp.advance(1);
            snaps.push(lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap());
        }
        let t0 = Instant::now();
        let mut replaced = 0;
        for s in &snaps {
            replaced += usize::from(lp.peers[0].engine.replaced_at(s, &t, &k).unwrap().is_some());
        }
        let took = t0.elapsed();
        let now = lp.peers[0].engine.now().0;
        let e = &mut lp.peers[0].engine;
        let last = *snaps.last().unwrap();
        snaps.retain(|s| {
            let gone = *s != last && e.drop_from(s, &t, &k).unwrap().is_some_and(|at| at <= now) && e.covered(&last, s, &t, &k).unwrap() == Some(true);
            if gone {
                e.drop_body(s, &t, &k).unwrap();
            }
            !gone
        });
        per.push((snaps.len(), replaced, took));
    }
    for (i, (s, r, d)) in per.iter().enumerate().filter(|(i, _)| i % 20 == 19) {
        println!("edit {i}: {s} snapshots held ({r} judged with a dead write), all judged {d:?}");
    }
}
