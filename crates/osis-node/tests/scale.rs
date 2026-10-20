#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Scale checks at the engine (tier 2, release; numbers in notes/testing.md, "Scale checks"):
//! `cargo test --release -p osis-node --test scale -- --ignored --nocapture --test-threads 1`.

use osis_core::{Ak, BlobId, Clock, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::{MemberKeys, Recipient, rotate};
use osis_node::{Config, Engine, Mutation};
use osis_schema::{AspectKey, Codec};
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
    let (batches, bytes) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let b = Counting { inner: MemoryBackend::new(), batches: batches.clone(), bytes: bytes.clone() };
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(WallMs(1_700_000_000_000)));
    let e = Engine::create(Box::new(b), Box::new(MemoryRoot::new()), Config::default(), clock, Box::new(SeededRng::from_u64(seed))).unwrap();
    (e, batches, bytes)
}

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

// spec/requirements.md, Scale: maps with millions of keys; a change inside a huge value costs
// O(change). Measures one map entry edit at 10^4..10^6 keys: bytes the engine writes to the
// store and the commit it produces. `OSIS_SCALE_MAX` caps the size (default 10^6).
#[test]
#[ignore]
fn big_map_edit_cost() {
    let max: usize = std::env::var("OSIS_SCALE_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let a = ak("/app/big");
    let mut n = 10_000;
    while n <= max {
        let (mut e, batches, bytes) = engine(n as u64);
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
        let (mut e, _, _) = engine(7);
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
    }
}
