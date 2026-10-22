#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Scale checks at the engine (tier 2, release; numbers in notes/testing.md, "Scale checks"):
//! `cargo test --release -p osis-node --test scale -- --ignored --nocapture --test-threads 1`.

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

static SCALE: StaticSchema = StaticSchema::new("scale.osis", "schema 0x5ca1e5ca1e5ca1e5ca1e5ca1e5ca1e50; revision 1; aspect /s/text: text;\n");
const TEXT: Aspect<Value> = Aspect::new("/s/text", &SCALE);

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
    println!("text {n} chars: one insert {insert:?}, store writes {} B (undo buffer included)", w1 - w0);
    drop(e);
    let t2 = Instant::now();
    let mut e = reopen.open(&batches, &bytes);
    let opened = t2.elapsed();
    let t3 = Instant::now();
    let v = e.get(&t, &ak("/s/text")).unwrap();
    let first = t3.elapsed();
    assert!(matches!(&v, Some(Value::Str(x)) if x.len() == n + 3));
    println!("text {n} chars: open {opened:?}, first read {first:?}");
    let t4 = Instant::now();
    e.undo(&id).unwrap().unwrap();
    println!("text {n} chars: undo commit {:?}", t4.elapsed());
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
    let t1 = Instant::now();
    let mut m = Mutation::new();
    m.op(things[0], &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(other))], op: Op::Set(ct::Edge { role: Role::Read, until: None, invite: None, since: None }.to_value()) }).unwrap();
    e.commit(m).unwrap().unwrap();
    println!("one grant with 10^4 commits held: {:?}", t1.elapsed());
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
    let t5 = Instant::now();
    for i in 0..n {
        let role = if (i / 20) % 2 == 0 { Role::Read } else { Role::Write };
        let mut m = Mutation::new();
        m.op(things[i % 100], &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(members[i % 20]))], op: Op::Set(ct::Edge { role, until: None, invite: None, since: None }.to_value()) }).unwrap();
        e.commit(m).unwrap().unwrap();
    }
    println!("{n} edge writes: {:?}", t5.elapsed());
    let roster = e.roster(&things[1]);
    drop(e);
    for k in 0..2 {
        let t6 = Instant::now();
        let e = reopen.open(&batches, &bytes);
        println!("open {k} with {n} edge writes held: {:?} ({} membership components restored from their saved walks)", t6.elapsed(), e.walks_restored());
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
        let mut m = Mutation::new();
        let op = match role {
            Some(r) => PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(ct::Edge { role: r, until: None, invite: None, since: None }.to_value()) },
            None => PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) },
        };
        m.op(t, &ct::MEMBERS, op).unwrap();
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

mod net;

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
