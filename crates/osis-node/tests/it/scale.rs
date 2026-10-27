#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Scale checks at the engine (tier 2, release; numbers in notes/testing.md, "Scale checks"):
//! `cargo test --release --workspace --test it scale:: -- --ignored --nocapture --test-threads 1`.

use osis_core::{Ak, BlobId, Clock, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::{MemberKeys, Recipient, rotate};
use osis_node::{Config, Engine, Mutation};
use osis_schema::{Aspect, AspectKey, Codec, StaticSchema};
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

static SCALE: StaticSchema = StaticSchema::new("scale.osis", "schema 0x5ca1e5ca1e5ca1e5ca1e5ca1e5ca1e50; revision 1; aspect /s/text: text; aspect /s/tags: set<string>; aspect /s/kept: set<string> [by: writer, keep_at_least: 1d];\n");
const TEXT: Aspect<Value> = Aspect::new("/s/text", &SCALE);
const TAGS: Aspect<Value> = Aspect::new("/s/tags", &SCALE);
const KEPT: Aspect<Value> = Aspect::new("/s/kept", &SCALE);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

// spec/crdt.md §8; spec/requirements.md, Scale: maps with millions of keys; a change inside a huge value costs
// O(change). Measures one map entry edit at 10^4..10^6 keys: bytes the engine writes to the
// store and the commit it produces. `OSIS_SCALE_MAX` caps the size (default 10^6).
#[test]
#[ignore]
fn big_map_edit_cost() {
    let max: usize = std::env::var("OSIS_SCALE_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let a = ak("/app/big");
    let mut n = 10_000;
    while n <= max {
        let (mut e, batches, bytes, reopen) = engine_reopenable(n as u64);
        let me = e.tid();
        let kv: BTreeMap<Value, Value> = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
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

// spec/requirements.md, Scale: direct rosters hold thousands of members; spec/crypto.md §4: a
// rotation boxes each remaining role secret to each member. Measures the rotation commit that a
// removal from a roster of N writers carries (read and write rotated; each person member gets a
// sealed box per role; notes/chat.md estimates 2.7 KB per member).
#[test]
#[ignore]
fn roster_removal_cost() {
    for n in [100usize, 1_000] {
        let (mut e, batches, bytes) = engine(7);
        let me = e.tid();
        let mut m = Mutation::new();
        let a = e.new_thing(&mut m, me);
        e.commit(m).unwrap().unwrap();
        // Person-like members: keysets per role (one KEM key reused; box size does not depend on it).
        let kem = KeyActorKeys::from_seed(&Secret32::from_bytes([9; 32])).kem.public().clone();
        let ep = Epoch::new(1, [3; 16]).unwrap();
        let mut members = vec![Recipient { member: me, role: Role::Admin, keys: MemberKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }];
        for i in 0..n - 1 {
            let mut b = [0u8; 15];
            b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            let keysets = [Role::Read, Role::Write].into_iter().map(|r| (r, (ep, kem.clone()))).collect();
            members.push(Recipient { member: Tid::from_bytes(b), role: Role::Write, keys: MemberKeys::Actor { keysets, own: BTreeMap::new() } });
        }
        // secrets of its own are all three roles' (spec/crypto.md §3): the thing gets them first
        let all = BTreeSet::from([Role::Read, Role::Write, Role::Admin]);
        let view = e.epochs(&a).unwrap();
        let r0 = rotate(&a, &all, &view, &Default::default(), &members[..1], &|_, _| true, &mut SeededRng::from_u64(2)).unwrap();
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
        let state = e.get(&a, &ak("/secrets")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap_or_default();
        let r = rotate(&a, &roles, &view, &state, &members, &|_, _| true, &mut SeededRng::from_u64(1)).unwrap();
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
            "roster {n}: rotation commit {total} B ({} blobs), {boxes} boxes, {:.0} B per remaining member; seal {sealed:?}, commit {committed:?}",
            pkg.blobs.len(),
            total as f64 / (n - 1) as f64
        );
        assert!(boxes >= 2 * (n - 1));
        // Budget: notes/chat.md, 2.7 KB per remaining member per rotation, plus about 10%.
        assert!(total <= 3000 * (n - 1), "{total} B for {n} members");
        // One history entry more afterwards: with the box map paged, only the skeleton (the small
        // fields) is rewritten, not the whole `/secrets` state.
        let mut m2 = Mutation::new();
        m2.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(Value::Int(999_999))], op: Op::Set(Value::Bytes(vec![7; 64])) }).unwrap();
        let w0 = bytes.load(Ordering::Relaxed);
        let t2 = Instant::now();
        e.commit(m2).unwrap().unwrap();
        println!("roster {n}: one more /secrets entry {:?}, store writes {} B ({} batches total)", t2.elapsed(), bytes.load(Ordering::Relaxed) - w0, batches.load(Ordering::Relaxed));
    }
}

// spec/crdt.md §5.6; spec/requirements.md, Scale: a change inside a huge value costs O(change), at any depth.
// One edit of a key of a 10^5-key map held in an entry of a root map (a deep collection).
// spec: none (spec/requirements.md has no numbered sections)
#[test]
#[ignore = "tier 2"]
fn deep_map_edit_cost() {
    let a = ak("/app/deep");
    for n in [10_000usize, 100_000] {
        let (mut e, batches, bytes) = engine(n as u64 + 1);
        let me = e.tid();
        let inner: BTreeMap<Value, Value> = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
        let outer = Value::Map(BTreeMap::from([(Value::Str("inner".into()), Value::Map(inner)), (Value::Str("x".into()), Value::Int(1))]));
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
    let a = ak("/app/set");
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
    let v = e.get(&t, &ak("/s/text")).unwrap();
    let first = t3.elapsed();
    assert!(matches!(&v, Some(Value::Str(x)) if x.len() == n + 3 + k));
    println!("text {n} chars: open {opened:?}, first read {first:?}");
    let t4 = Instant::now();
    e.undo(&id).unwrap().unwrap();
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
    let a = ak("/s/text");
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    let b = lp.peers[1].engine.tid();
    m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(b))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, since: None }.to_value()) }).unwrap();
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
    e.undo(&id).unwrap().unwrap();
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

// spec/permissions.md §5.1; spec/requirements.md, Scale (no operation O(history)): a membership change while the node
// holds 10^4 content commits on other things of its own tree, and opening that store.
// spec: none (spec/requirements.md has no numbered sections)
#[test]
#[ignore = "tier 2"]
fn membership_change_and_open_cost() {
    let a = ak("/app/v");
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
    m.op(things[0], &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(other))], op: Op::Set(ct::Edge { role: Role::Read, until: None, invite: None, since: None }.to_value()) }).unwrap();
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
    assert_eq!(e.roster(&things[0]).len(), 1);
    // 10^4 edge writes in the tree's one membership component: 20 members' roles toggled
    let n: usize = std::env::var("OSIS_SCALE_EDGES").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let members: Vec<Tid> = (0..20u8).map(|i| Tid::from_bytes([100 + i; 15])).collect();
    osis_node::costs::take();
    let t5 = Instant::now();
    for i in 0..n {
        let role = if (i / 20) % 2 == 0 { Role::Read } else { Role::Write };
        // an edge change is remove + put (spec/permissions.md §2)
        crate::common::set_edge(&mut e, things[i % 100], members[i % 20], Some(crate::common::edge(role)), None);
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
        println!("open {k} with {n} edge writes held: {:?} ({} membership components restored from their saved walks)", t6.elapsed(), e.walks_restored());
        for (k, d, c) in osis_node::costs::take() {
            println!("  {k}: {d:?} ({c})");
        }
        assert_eq!(e.roster(&things[1]), roster);
    }
    demotion_heavy_open();
}

/// Several admins writing edges on 20 docs of one org, the owner demoting and re-granting
/// them all along (their writes it had not received drop), commits reaching the owner in
/// batches: the owner's open restored from its saved walk against evaluated anew.
fn demotion_heavy_open() {
    use osis_node::local_peer::LocalPeer;
    let n: usize = std::env::var("OSIS_SCALE_DEMOTE").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let mut lp = LocalPeer::new(6, 77, WallMs(1_700_000_000_000)).unwrap();
    let admins: Vec<Tid> = (1..6).map(|i| lp.peers[i].engine.tid()).collect();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let org = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].engine.commit(m).unwrap();
    let mut m = Mutation::new();
    let docs: Vec<Tid> = (0..20).map(|_| lp.peers[0].engine.new_thing(&mut m, org)).collect();
    lp.peers[0].engine.commit(m).unwrap();
    let set = |e: &mut Engine, t: Tid, member: Tid, role: Option<Role>| -> Option<osis_core::CommitId> {
        // an edge change is remove + put (spec/permissions.md §2)
        let mut m = Mutation::new();
        m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) }).unwrap();
        if let Some(r) = role {
            m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(ct::Edge { role: r, until: None, invite: None, since: None }.to_value()) }).unwrap();
        }
        e.commit(m).ok().flatten()
    };
    for a in &admins {
        set(&mut lp.peers[0].engine, org, *a, Some(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let members: Vec<Tid> = (0..30u8).map(|i| Tid::from_bytes([150 + i; 15])).collect();
    let mut x: u64 = 0x5eed;
    let mut rnd = |k: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % k
    };
    let mut queue: Vec<(usize, osis_core::CommitId)> = Vec::new();
    let t0 = Instant::now();
    for i in 0..n {
        for p in &lp.peers {
            p.clock.advance(1);
        }
        if i % 40 == 39 {
            // the owner demotes an admin to write on the org, and re-grants it 20 writes later
            let a = admins[(i / 40) % 5];
            set(&mut lp.peers[0].engine, org, a, Some(Role::Write));
        } else if i % 40 == 19 && i > 40 {
            let a = admins[(i / 40 - 1) % 5];
            set(&mut lp.peers[0].engine, org, a, Some(Role::Admin));
        } else {
            let w = 1 + rnd(5) as usize;
            let roles = [None, Some(Role::Read), Some(Role::Write)];
            let (d, mem, r) = (docs[rnd(20) as usize], members[rnd(30) as usize], roles[rnd(3) as usize]);
            if let Some(id) = set(&mut lp.peers[w].engine, d, mem, r) {
                queue.push((w, id));
            }
        }
        // the admins' commits reach the owner in batches, a few late
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
    println!("{n} edge writes by 5 admins with demotions every 40, delivered to the owner: {:?}", t0.elapsed());
    let roster = lp.peers[0].engine.roster(&docs[0]);
    let t1 = Instant::now();
    lp.peers[0].restart(1).unwrap();
    println!("owner's open, walk restored: {:?} ({} restored)", t1.elapsed(), lp.peers[0].engine.walks_restored());
    assert_eq!(lp.peers[0].engine.roster(&docs[0]), roster);
    lp.peers[0].engine.damage_walks(0).unwrap();
    let t2 = Instant::now();
    lp.peers[0].restart(2).unwrap();
    println!("owner's open, walk evaluated anew: {:?} ({} restored)", t2.elapsed(), lp.peers[0].engine.walks_restored());
    assert_eq!(lp.peers[0].engine.roster(&docs[0]), roster);
}

use crate::net;

// spec/sync.md §6; spec/requirements.md, Scale: a first sync of N commits costs O(N). A writer
// writes N content commits (100 things, N/100 writes each) in a label at one server while a
// fresh reader syncs: the time at the reader, the writer and the hub, and the engine phases
// (`osis_node::costs`); then another fresh reader ingests every commit directly (`Engine::ingest`,
// no sync). `OSIS_SCALE_N` sets N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn first_sync_cost() {
    let n: usize = std::env::var("OSIS_SCALE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let mut net = net::Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[]);
    let g = net.group(a, &[(b, Role::Read), (c, Role::Read)], &[sv]);
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
    assert!(ingest.as_secs() < 30 * scale / 10_000, "ingesting {n} commits took {ingest:?}");
    assert!(first.as_secs() < 60 * scale / 10_000, "first sync of {n} commits took {first:?}");
}

// spec/sync.md §6, §7; spec/requirements.md, Scale: a change costs O(change). A label holding N
// content commits (100 things, N/100 writes each) at one server, synced by a writer and a
// reader; then one more write: the passes it causes at both nodes (time, and the entries and
// bodies they judge) do not grow with N. `OSIS_SCALE_MAX` caps N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn sync_pass_cost() {
    let max: usize = std::env::var("OSIS_SCALE_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let mut n = 1_000;
    while n <= max {
        let mut net = net::Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let b = net.node(2, &[sv]);
        let g = net.group(a, &[(b, Role::Read)], &[sv]);
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
        let held = net.server_ids(sv, &l).len();
        assert!(held >= n, "{held} entries at the server");
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

// spec/sync.md §6, §7; spec/permissions.md §4; spec/requirements.md, Scale: a membership change
// re-judges only the labels whose verdicts can read it. 10 labels of `OSIS_SCALE_LABEL` (default
// 10^3) content commits each at one server, a writer and a reader; then an edge write on an
// actor no label's closure reaches (it should judge about nothing), then one on the first
// label's group (only that label's entries).
#[test]
#[ignore = "tier 2"]
fn sync_membership_pass_cost() {
    let n: usize = std::env::var("OSIS_SCALE_LABEL").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000);
    let mut net = net::Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let addr = net.address(sv);
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

// spec/crdt.md §4.8 (deaths whatever the arrival order), spec/requirements.md, Scale (no
// operation O(history)): a set of N one-element commits, then 5 deltas by another writer older
// than all of them. Each late delta applied and its deaths read alone, then 5 more in one batch
// read once (`Engine::defer_deaths`), then one 5 commits late: an unbounded set (no deaths kept)
// against a keep-at-least one (each batch replays the window its late deltas can change), and
// the keep-at-least one compacted after the N commits (the window plays the snapshot's copies).
// `OSIS_SCALE_N` sets N (default 3000).
#[test]
#[ignore = "tier 2"]
fn late_delta_deaths_cost_spec_crdt_4_8() {
    let n: usize = std::env::var("OSIS_SCALE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(3000);
    for (name, asp, key, compact) in [("unbounded set", &TAGS, "/s/tags", false), ("keep-at-least set", &KEPT, "/s/kept", false), ("keep-at-least set, compacted", &KEPT, "/s/kept", true)] {
        let mut lp = osis_node::local_peer::LocalPeer::new(2, 41, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(b))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, since: None }.to_value()) }).unwrap();
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
        let pk = |c: &osis_core::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
        let mut each = Vec::new();
        for c in &late[..5] {
            let t1 = Instant::now();
            lp.deliver(0, &pk(c)).unwrap();
            lp.peers[0].engine.deaths(&ids[0], &t, &k).unwrap();
            each.push(t1.elapsed());
        }
        osis_node::costs::take();
        let t2 = Instant::now();
        lp.peers[0].engine.defer_deaths(true).unwrap();
        for c in &late[5..] {
            lp.deliver(0, &pk(c)).unwrap();
        }
        lp.peers[0].engine.defer_deaths(false).unwrap();
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
        lp.peers[0].engine.deaths(&ids[0], &t, &k).unwrap();
        println!("{name} n={n}: fill {fill:?}; late deltas each {each:?}; 5 late deltas in one batch {batch:?}; one in-order local write {local:?}; a recent late delta {:?}", t4.elapsed());
        for (k, d, c) in osis_node::costs::take() {
            println!("  {k}: {d:?} ({c})");
        }
    }
}


// spec/permissions.md §5.2, spec/crdt.md §4.6 (un-merge a function of the held set), spec/
// requirements.md, Scale: a set of N one-element commits by the owner (0) and one add by writer B
// (1); admin C (2), who never saw it, revokes B: the add goes invalid at the owner (a flip). Then
// B's add written after the revoke reaches the owner invalid. Both un-merge in place (validity only
// fell, the add supersedes nothing), O(state), no body read. `OSIS_SCALE_N` sets N (default 10^4).
#[test]
#[ignore = "tier 2"]
fn validity_flip_cost_spec_permissions_5_2() {
    let n: usize = std::env::var("OSIS_SCALE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let mut lp = osis_node::local_peer::LocalPeer::new(3, 43, WallMs(1_700_000_000_000)).unwrap();
    let me = lp.peers[0].engine.tid();
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    for (x, r) in [(b, Role::Write), (c, Role::Admin)] {
        let mut m = Mutation::new();
        m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(x))], op: Op::Set(ct::Edge { role: r, until: None, invite: None, since: None }.to_value()) }).unwrap();
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
    let scope = osis_perm::DemotionScope { membership: BTreeMap::from([(b, BTreeSet::from([t]))]), content: BTreeMap::from([(b, BTreeSet::from([t]))]) };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(b)) }).unwrap();
    m.frontier(f.to_value());
    let rv = lp.peers[2].commit(m).unwrap().unwrap();
    let late = add(&mut lp, 1, "late".into());
    let pk2 = lp.packages(2).unwrap();
    let pk1 = lp.packages(1).unwrap();
    let k = ak("/s/tags");
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
fn put_key(net: &mut net::Net, n: usize, t: Tid, asp: &Aspect<Value>, k: &str, v: &str) -> osis_core::CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, PathOp { path: vec![PathSeg::Key(net::s(k))], op: Op::Set(net::s(v)) }).unwrap();
    net.engine(n).commit(m).unwrap().unwrap()
}

// spec/sync.md §6, §7; spec/commits.md §5; spec/requirements.md, Scale: a change to one body of
// a big aspect judges O(change), not the aspect. N one-key commits on one thing (`OSIS_SCALE_N`,
// default 10^3) at one server, a writer and a reader: (1) under keep at most (every body live,
// waiting for its timed delete) one more key, then one overwriting a key (kills one body); (2)
// under an expiry, an older commit expiring alone; (3) N things in the group, one write (the
// closure taken once per pass; `OSIS_SCALE_CLOSURE` things, default N). The passes' (passes,
// full, bodies, entries) at both nodes.
#[test]
#[ignore = "tier 2"]
fn sync_aspect_pass_cost() {
    let n: usize = std::env::var("OSIS_SCALE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000);
    let d = |x: osis_node::sync::PassStats, y: osis_node::sync::PassStats| (y.passes - x.passes, y.full - x.full, y.bodies - x.bodies, y.entries - x.entries);
    let mut net = net::Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "t");
    let u = net.item(a, g, g, "u");
    // expires 30 min before the N below
    put_key(&mut net, a, u, &net::BRIEFMAP, "first", "v");
    net.run();
    net.advance(1_800_000);
    let t0 = Instant::now();
    for i in 0..n {
        put_key(&mut net, a, t, &net::SHORTMAP, &format!("k{i}"), "v");
        put_key(&mut net, a, u, &net::BRIEFMAP, &format!("k{i}"), "v");
    }
    net.run();
    let fill = t0.elapsed();
    net.advance(61_000);
    let stats = |net: &mut net::Net| (net.sync(a).pass_stats(), net.sync(b).pass_stats());
    let s0 = stats(&mut net);
    let t1 = Instant::now();
    put_key(&mut net, a, t, &net::SHORTMAP, "new", "v");
    net.run();
    let one = t1.elapsed();
    let s1 = stats(&mut net);
    net.advance(1_000);
    let s2 = stats(&mut net);
    let t2 = Instant::now();
    put_key(&mut net, a, t, &net::SHORTMAP, "k0", "w");
    net.run();
    let kill = t2.elapsed();
    let s3 = stats(&mut net);
    println!("keep-at-most map of {n} live bodies (fill {fill:?}): one more key {one:?}, writer {:?} reader {:?}; overwriting one {kill:?}, writer {:?} reader {:?}", d(s0.0, s1.0), d(s0.1, s1.1), d(s2.0, s3.0), d(s2.1, s3.1));
    // the expiring map: its first commit expires alone, the N stay
    let s4 = stats(&mut net);
    let t3 = Instant::now();
    net.advance(1_800_000);
    let exp = t3.elapsed();
    let s5 = stats(&mut net);
    println!("expiring map of {n} live commits: an older one expiring {exp:?} (in a 30 min tick), writer {:?} reader {:?}", d(s4.0, s5.0), d(s4.1, s5.1));
    // a big closure
    let k: usize = std::env::var("OSIS_SCALE_CLOSURE").ok().and_then(|s| s.parse().ok()).unwrap_or(n);
    let e = net.engine(a);
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    let mut m = Mutation::new();
    for _ in 0..k {
        let x = e.new_thing(&mut m, g);
        items.items.insert(x);
    }
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap();
    net.run();
    net.advance(61_000);
    let s6 = stats(&mut net);
    let t4 = Instant::now();
    net.write(a, t, "one more");
    net.run();
    let w = t4.elapsed();
    let s7 = stats(&mut net);
    println!("closure of {k} things: one write {w:?}, writer {:?} reader {:?}", d(s6.0, s7.0), d(s6.1, s7.1));
}
