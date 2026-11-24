//! Scale checks (spec/requirements.md, Scale): each test counts the work an operation does
//! (pages loaded and written, store bytes, commits judged, bodies read) at a size n and at 10n
//! and asserts the growth Scale allows: `flat` for a change that costs O(change), `linear` for a
//! cost that may grow with the data. Counts, never time (notes/principles.md).
//! The engine, store, crdt and commit layers alone (`osis_engine::local_peer`); sync's checks come
//! with the new sync (notes/test-scale.md, Checks to restore).

use crate::common::{BIG, GONEMAP, REFS, TEXT, edge, net, new_thing, s, set_edge, edge_write};
use osis_base::{Ak, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::{HolderKeys, Recipient, rotate};
use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_schema::core_types as ct;
use osis_schema::{Codec, RawKey};
use osis_store::{Io, MemoryBackend};
use std::collections::{BTreeMap, BTreeSet};

/// What one operation did: the engine's cost spans by count, the store's reads and writes, and
/// the bytes handed to the store before paging (`osis_store::bytes_handed`).
#[derive(Debug)]
pub(crate) struct Work {
    pub(crate) spans: BTreeMap<&'static str, u64>,
    pub(crate) io: Io,
    pub(crate) handed: u64,
}

impl Work {
    pub(crate) fn n(&self, span: &str) -> u64 {
        self.spans.get(span).copied().unwrap_or(0)
    }
    /// Pages of paged states and placement blocks loaded.
    fn loads(&self) -> u64 {
        self.n("state page load") + self.n("placement block load")
    }
    /// Pages of paged states and placement blocks and rows written.
    fn page_writes(&self) -> u64 {
        self.n("state page write") + self.n("placement block write") + self.n("placement row write")
    }
}

/// Runs `f`, counting its work on this thread (spans; debug-only checks excluded) and at `b`.
pub(crate) fn measured<T>(b: &MemoryBackend, f: impl FnOnce() -> T) -> (T, Work) {
    osis_base::costs::take();
    let (io, handed) = (b.io(), osis_store::bytes_handed());
    let r = f();
    let spans = osis_base::costs::take().into_iter().map(|(k, _, c)| (k, c)).collect();
    (r, Work { spans, io: b.io() - io, handed: osis_store::bytes_handed() - handed })
}

/// A cost at 10n about the cost at n: at most a log's growth (O(change)).
#[track_caller]
pub(crate) fn flat(what: &str, small: u64, big: u64) {
    println!("{what}: {small} at n, {big} at 10n");
    assert!(big <= 2 * small + 2, "{what}: {small} at n, {big} at 10n: grows with the data");
}

/// A cost at 10n at most about ten times the cost at n (O(n), or O(n log n)): not quadratic.
#[track_caller]
pub(crate) fn linear(what: &str, small: u64, big: u64) {
    println!("{what}: {small} at n, {big} at 10n");
    assert!(big <= 15 * small + 15, "{what}: {small} at n, {big} at 10n: grows faster than the data");
}

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn set_key(m: &mut Mutation, t: Tid, a: &Ak, path: Vec<PathSeg>, v: Value) {
    m.op(t, a, PathOp { path, op: Op::Set(v) }).unwrap();
}

/// A 200-byte string: n entries page from about 15 on (3 KB).
fn long(i: usize) -> Value {
    s(&format!("{i:08}{}", "v".repeat(192)))
}

/// One node holding a new thing of its own (`new_thing` on `net(1, 0)`): built once.
fn one_thing() -> (LocalPeer, Tid) {
    LocalPeer::cached("scale::one_thing", || {
        let mut lp = net(1, 0);
        let t = new_thing(&mut lp, 0);
        (lp, t)
    })
}

/// `app:big.0`, the paged map of `big_map`.
fn big() -> Ak {
    ak("app:big.0")
}

/// The path of entry `k` of `big_map`'s map.
fn entry(k: usize, nested: bool) -> Vec<PathSeg> {
    let key = PathSeg::Key(s(&format!("k{k:06}")));
    if nested { vec![PathSeg::Key(s("inner")), key] } else { vec![key] }
}

/// `one_thing` with `app:big.0` a map of n `long` entries, written in one commit; `nested`: the
/// map sits in an entry of a root map. Built once per (n, nested).
fn big_map(n: usize, nested: bool) -> (LocalPeer, Tid) {
    LocalPeer::cached(&format!("scale::big_map/{n}/{nested}"), || {
        let (mut lp, t) = one_thing();
        let inner: osis_base::ValueMap = (0..n).map(|i| (s(&format!("k{i:06}")), long(i))).collect();
        let v = if nested { Value::Map(osis_base::ValueMap::from([(s("inner"), Value::Map(inner)), (s("x"), Value::Int(1))])) } else { Value::Map(inner) };
        let mut m = Mutation::new();
        m.set(t, &big(), &v).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        (lp, t)
    })
}

/// Peer 0 sets entry `k` of `big_map`'s map to `v`.
fn edit_entry(lp: &mut LocalPeer, t: Tid, k: usize, nested: bool, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    set_key(&mut m, t, &big(), entry(k, nested), s(v));
    lp.peers[0].commit(m).unwrap().unwrap()
}

/// Map edits at n entries (`big_map`): (store bytes of an edit; a new session's first read of
/// one key in pages loaded; its first edit in pages loaded and written and store bytes).
fn map_edit(n: usize, nested: bool) -> [u64; 5] {
    let (mut lp, t) = big_map(n, nested);
    let (b, a) = (lp.peers[0].backend.clone(), big());
    let (_, w0) = measured(&b, || edit_entry(&mut lp, t, n / 2, nested, "x"));
    lp.peers[0].restart(1).unwrap();
    let (got, read) = measured(&b, || lp.peers[0].engine.get_at(&t, &a, &entry(n / 3, nested)).unwrap());
    assert_eq!(got, Some(long(n / 3)));
    lp.peers[0].restart(2).unwrap();
    let (_, first) = measured(&b, || edit_entry(&mut lp, t, n / 4, nested, "y"));
    assert_eq!(lp.peers[0].engine.get_at(&t, &a, &entry(n / 4, nested)).unwrap(), Some(s("y")));
    [w0.io.written_bytes, read.loads(), first.loads(), first.page_writes(), first.io.written_bytes]
}

// spec/crdt.md §8, §5.6; spec/requirements.md, Scale: a change inside a huge value costs
// O(change), at any depth. One entry edit of a paged map of n and 10n entries, at the root and
// inside a map entry: store bytes, and in a new session the first read of one key and the first
// edit load and write only their pages.
#[test]
fn map_edit_is_flat() {
    for nested in [false, true] {
        let (small, big) = (map_edit(500, nested), map_edit(5000, nested));
        for (i, what) in ["edit: store bytes", "new session read: pages loaded", "new session edit: pages loaded", "new session edit: pages written", "new session edit: store bytes"].iter().enumerate() {
            flat(&format!("nested {nested}, {what}"), small[i], big[i]);
        }
    }
}

/// Debug builds' undo check (`memo::Undoable`) at n entries of a paged map (`big_map`): the
/// writes it noted in an edit, and in a transaction writing 10 rows then rolled back.
fn undo_check(n: usize) -> [u64; 2] {
    let (mut lp, t) = big_map(n, false);
    let noted = osis_base::memo::undoable_writes_noted;
    let n0 = noted();
    edit_entry(&mut lp, t, n / 2, false, "x");
    let n1 = noted();
    let r = lp.peers[0].engine.run(|tx| {
        for i in 0..10u8 {
            tx.txn.put_local(&[b'u', i], b"x", osis_store::Shred::No)?;
        }
        Err::<(), _>(osis_engine::Error::BadInput("rolled back"))
    });
    assert!(r.is_err());
    [n1 - n0, noted() - n1]
}

// spec: none (internal: debug builds' check that an undone transaction left every container
// marked undoable as it was, `memo::Undoable`). Its cost is per key a transaction wrote, not per
// key the store or an index holds: an edit of a paged map of n and 10n entries, and a rolled-back
// transaction writing 10 rows (each row noted, and its family's table whole).
#[cfg(debug_assertions)]
#[test]
fn the_undo_check_costs_what_was_written() {
    let (small, big) = (undo_check(500), undo_check(5000));
    flat("edit: undoable writes noted", small[0], big[0]);
    flat("rolled back: undoable writes noted", small[1], big[1]);
    assert!((10..=30).contains(&small[1]), "10 rows written: {} noted", small[1]);
}

/// A covered drop at n entries of a paged map (`big_map`): two one-entry edits (one replacing the
/// other's write, one live), a snapshot covering both, then each dropped as covered: (store
/// bytes, pages written) per drop.
fn covered_drop(n: usize) -> [u64; 2] {
    let (mut lp, t) = big_map(n, false);
    let (b, a) = (lp.peers[0].backend.clone(), big());
    let (dead, live) = (edit_entry(&mut lp, t, n / 2, false, "x"), edit_entry(&mut lp, t, n / 3, false, "y"));
    edit_entry(&mut lp, t, n / 2, false, "z");
    lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
    let (_, w) = measured(&b, || {
        for c in [dead, live] {
            lp.peers[0].engine.drop_body(&c, &t, &a).unwrap();
        }
    });
    assert_eq!(lp.peers[0].engine.get_at(&t, &a, &entry(n / 3, false)).unwrap(), Some(s("y")));
    [w.io.written_bytes / 2, w.page_writes() / 2]
}

// spec/commits.md §5 (Covered: every local copy of a dropped body goes), spec/requirements.md
// (Scale: O(change)): a body dropped as covered rewrites shredded the pages holding its writes,
// not the whole state: store bytes and pages written per drop flat from n to 10n entries.
#[test]
fn covered_drop_is_flat() {
    let (small, big) = (covered_drop(500), covered_drop(5000));
    flat("covered drop: store bytes", small[0], big[0]);
    flat("covered drop: pages written", small[1], big[1]);
}

/// Set ops by value at n elements, each in a new session: pages loaded and written per op.
fn set_ops(n: usize) -> Vec<(u64, u64)> {
    let (mut lp, t) = one_thing();
    let b = lp.peers[0].backend.clone();
    let a = crate::common::TAGS;
    let e = |i: usize| s(&format!("{i:08}{}", "e".repeat(92)));
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Set((0..n).map(e).collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let ops = [(Op::Add(s("x")), true), (Op::Add(e(n / 2)), false), (Op::Remove(e(n / 3)), true), (Op::Remove(s("y")), false)];
    let mut out = Vec::new();
    for (k, (op, writes)) in ops.into_iter().enumerate() {
        lp.peers[0].restart(k as u64).unwrap();
        let (c, w) = measured(&b, || {
            let mut m = Mutation::new();
            m.op(t, &a, PathOp { path: vec![], op }).unwrap();
            lp.peers[0].commit(m).unwrap()
        });
        assert_eq!(c.is_some(), writes);
        out.push((w.loads(), w.page_writes()));
    }
    let Some(Value::Set(v)) = lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap() else { panic!() };
    assert!(v.len() == n && v.contains(&s("x")) && !v.contains(&e(n / 3)));
    out
}

// spec/crdt.md §5.5 (add v; remove v): set ops resolved by value, §8; spec/requirements.md, Scale: adding and
// removing by value in a paged set, each op in a new session, loads and writes only its pages
// (the value index), at n and 10n elements.
#[test]
fn set_by_value_is_flat() {
    let (small, big) = (set_ops(1000), set_ops(10_000));
    for (i, what) in ["add new", "add present", "remove", "remove absent"].iter().enumerate() {
        flat(&format!("{what}: pages loaded"), small[i].0, big[i].0);
        flat(&format!("{what}: pages written"), small[i].1, big[i].1);
    }
}

/// A set of n tids: a removal of a member (spec/crdt.md §5.5, what `delete` writes in a `holds.0`) and
/// an add back, each in a new session: pages loaded and written, and the commit's bytes.
fn tid_removals(n: usize) -> Vec<(u64, u64, u64)> {
    let (mut lp, x) = one_thing();
    let b = lp.peers[0].backend.clone();
    let t = |i: usize| {
        let mut b = [0u8; 15];
        b[7..].copy_from_slice(&(i as u64).to_be_bytes());
        Value::Weak(Tid::from_bytes(b))
    };
    let mut m = Mutation::new();
    m.set(x, &REFS, &Value::Set((0..n).map(t).collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut out = Vec::new();
    for (k, op) in [Op::Remove(t(n / 3)), Op::Add(t(n / 3))].into_iter().enumerate() {
        lp.peers[0].restart(k as u64).unwrap();
        let (c, w) = measured(&b, || {
            let mut m = Mutation::new();
            m.op(x, &REFS, PathOp { path: vec![], op }).unwrap();
            lp.peers[0].commit(m).unwrap()
        });
        let id = c.expect("each writes");
        let bytes = lp.peers[0].engine.package(&id).unwrap().map_or(0, |p| p.bytes.len() as u64);
        out.push((w.loads(), w.page_writes(), bytes));
    }
    let Some(Value::Set(v)) = lp.peers[0].engine.get(&x, &ak("t:refs.0")).unwrap() else { panic!() };
    assert!(v.len() == n && v.contains(&t(n / 3)));
    out
}

// spec/crdt.md §5.5, spec/requirements.md Scale (deleting costs what changed): removing a reference from
// a paged set and adding it back, each in a new session, loads and writes only their pages (the
// value index finds the reference's records), and the commit is one record, at n and 10n members.
#[test]
fn tid_removal_is_flat() {
    let (small, big) = (tid_removals(4000), tid_removals(40_000));
    for (i, what) in ["remove a member", "add back"].iter().enumerate() {
        flat(&format!("{what}: pages loaded"), small[i].0, big[i].0);
        flat(&format!("{what}: pages written"), small[i].1, big[i].1);
        flat(&format!("{what}: commit bytes"), small[i].2, big[i].2);
    }
}

/// What `text_ops` counts per step: pages loaded, pages and placement rows written, store bytes
/// written, store rows read and store blob bytes read (spans: debug checks left out).
fn text_counts(w: &Work) -> [u64; 5] {
    [w.loads(), w.page_writes(), w.io.written_bytes, w.n("store rows read"), w.n("store blob bytes read")]
}

/// The steps of `text_ops`.
const TEXT_STEPS: [&str; 8] = ["read of 100 chars", "insert", "delete", "move of 4", "edit", "undo of the edit", "move of 600", "read after them"];

/// Text ops at n chars, each in a new session: `text_counts` per step (`TEXT_STEPS`): a read of
/// 100 chars at an index, an insert, a delete, a move of 4 chars, an edit as a text session
/// writes it, an undo of the edit, a move of 600 chars (past a placement block's 256 rows: it
/// moves whole blocks), a read after them.
fn text_ops(n: usize) -> Vec<[u64; 5]> {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    // kept a day: an undo reverts from kept history
    let t = crate::common::new_thing_keeping(&mut lp, 0, &[("t:text.0", crate::common::DAY)]);
    let a = ak("t:text.0");
    // not periodic: an edit whose window repeats elsewhere in its base matches the whole text
    let mut rng = SeededRng::from_u64(0);
    let mut want: Vec<char> = (0..n).map(|_| char::from(b'a' + (osis_crypto::RngCore::next_u64(&mut rng) % 26) as u8)).collect();
    let mut m = Mutation::new();
    m.set(t, &TEXT, &Value::Str(want.iter().collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut out = Vec::new();
    let mut last: Option<(osis_base::CommitId, Vec<char>)> = None;
    for step in 0..8u64 {
        lp.peers[0].restart(step).unwrap();
        let at = n / 3 + step as usize * 7;
        let e = &mut lp.peers[0].engine;
        let before = want.clone();
        let op = match step {
            0 | 7 => {
                let (got, w) = measured(&b, || e.get_range(&t, &a, &[], at..at + 100).unwrap());
                assert_eq!(got, Some(Value::Str(want[at..at + 100].iter().collect())));
                out.push(text_counts(&w));
                continue;
            }
            1 => {
                want.splice(at..at, "XYZ".chars());
                Op::Insert { at, items: vec![s("XYZ")] }
            }
            2 => {
                want.drain(at..at + 5);
                Op::Delete { at, len: 5 }
            }
            3 | 6 => {
                let len = if step == 3 { 4 } else { 600 };
                let moved: Vec<char> = want.drain(at..at + len).collect();
                let to = n / 2;
                want.splice(to..to, moved);
                Op::Move { at, len, to }
            }
            4 => {
                let base = Value::Str(want.iter().collect());
                want.splice(at..at + 2, "EDIT".chars());
                Op::Edit { base, new: Value::Str(want.iter().collect()) }
            }
            _ => {
                let (id, before) = last.take().unwrap();
                let (r, w) = measured(&b, || e.revert(&id).unwrap());
                assert!(r.is_some());
                want = before;
                out.push(text_counts(&w));
                continue;
            }
        };
        let (id, w) = measured(&b, || {
            let mut m = Mutation::new();
            m.op(t, &TEXT, PathOp { path: vec![], op }).unwrap();
            e.commit(m).unwrap().unwrap()
        });
        last = Some((id, before));
        println!("{} at {n}: held writes: {} pages written; store units written {}", TEXT_STEPS[step as usize], w.n("held writes: pages written"), w.io.writes);
        out.push(text_counts(&w));
    }
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Str(want.iter().collect())));
    out
}

// spec/crdt.md §5.7 (index paths never go on the wire): ops resolve by index against the placement, §6, §8; spec/commits.md §5
// (when a body was replaced: dated from the held writes); spec/requirements.md, Scale: in a
// paged text of n and 10n chars written in one kept commit, each op in a new session: a read of
// 100 chars, an insert, a delete, a move of a few chars, an edit as a text session writes it, an
// undo, a move of a few blocks, loads and writes only its pages and placement rows (through the
// stored placement), reads a fixed number of store rows, and reads no blob of the kept first
// commit (its held writes and its date are rows), but: the delete, the aspect's first death,
// which reads the held bodies once to build its held writes (once for the aspect, in no later
// session: every later step reads none), so its store bytes and rows read are the build's; and
// the undo, which reads the pages holding the chars it restores: at most two wire pages
// (`CHUNK_MAX` each: a dot's leaf and the one a run before it may reach from), where the text's
// one page at n is no measure for a page at 10n. 10n is 800k chars: about 3 minutes in a debug
// build.
#[test]
#[ignore = "by hand: an 800k-char text, about 4 minutes in a debug build"]
fn text_edits_are_flat() {
    let (small, big) = (text_ops(80_000), text_ops(800_000));
    for (i, what) in TEXT_STEPS.iter().enumerate() {
        let first_death = *what == "delete";
        for (k, count) in ["pages loaded", "pages written", "store bytes", "store rows read"].iter().enumerate() {
            if first_death && k >= 2 {
                linear(&format!("{what} (builds the held writes): {count}"), small[i][k], big[i][k]);
            } else {
                flat(&format!("{what}: {count}"), small[i][k], big[i][k]);
            }
        }
        println!("{what}: store blob bytes read: {} at n, {} at 10n", small[i][4], big[i][4]);
        if first_death {
            // the text's body once (its chars and their run records), the insert's beside it
            assert!(small[i][4] > 0 && small[i][4] <= 2 * 80_000 && big[i][4] <= 2 * 800_000, "{what}: blob bytes read {} at n, {} at 10n: the kept body more than once", small[i][4], big[i][4]);
        } else if *what == "undo of the edit" {
            let pages = 2 * osis_base::format::CHUNK_MAX as u64;
            assert!(small[i][4] <= pages && big[i][4] <= pages, "{what}: blob bytes read {} at n, {} at 10n: more than two pages of the kept body", small[i][4], big[i][4]);
        } else {
            assert_eq!((small[i][4], big[i][4]), (0, 0), "{what}: reads a blob of the kept body");
        }
    }
}

/// Writes a rotation's boxes, history and keysets on `a`.
fn write_rotation(m: &mut Mutation, a: Tid, r: &osis_keys::Rotation) {
    for (k, b) in &r.secrets.boxes {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
    }
    for (k, h) in &r.secrets.history {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
    }
    for (role, ks) in &r.keys.keysets {
        let f = osis_keys::aspects::keyset_field(*role);
        m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
    }
}

/// A removal from a roster of n writers: (the rotation commit's bytes, its boxes, store bytes of
/// one more history entry afterwards).
fn roster_removal(n: usize) -> (u64, usize, u64) {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let e = &mut lp.peers[0].engine;
    let me = e.me();
    let mut m = Mutation::new();
    let a = e.new_thing(&mut m, me);
    e.commit(m).unwrap().unwrap();
    // account-like holders: keysets per role (one KEM key reused; a box's size does not depend on it)
    let kem = KeyActorKeys::from_seed(&Secret32::from_bytes([9; 32])).kem.public().clone();
    let ep = Epoch::new(1, [3; 32]).unwrap();
    let mut holders = vec![Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None }, floor: 0 }];
    for i in 0..n - 1 {
        let mut x = [0u8; 15];
        x[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        let keysets = [Role::Read, Role::Write].into_iter().map(|r| (r, vec![(ep, kem.clone())])).collect();
        holders.push(Recipient { holder: Tid::from_bytes(x), role: Role::Write, keys: HolderKeys::Actor { keysets, own: BTreeMap::new() }, floor: 0 });
    }
    // secrets of its own are all three roles' (spec/crypto.md §3): the thing gets them first
    let all = BTreeSet::from(Role::ALL);
    let view = e.epochs(&a).unwrap();
    let r0 = rotate(&a, &all, &view, &Default::default(), &holders[..1], &osis_keys::Names::default(), &mut SeededRng::from_u64(2)).unwrap();
    let mut m = Mutation::new();
    write_rotation(&mut m, a, &r0);
    e.commit(m).unwrap().unwrap();
    let view = e.epochs(&a).unwrap();
    let state = e.get_typed(&a, &ct::SECRETS).unwrap().unwrap_or_default();
    let r = rotate(&a, &BTreeSet::from([Role::Read, Role::Write]), &view, &state, &holders, &osis_keys::Names::default(), &mut SeededRng::from_u64(1)).unwrap();
    let mut m = Mutation::new();
    write_rotation(&mut m, a, &r);
    let id = e.commit(m).unwrap().unwrap();
    let pkg = e.package(&id).unwrap().unwrap();
    let total = (pkg.bytes.len() + pkg.blobs.iter().map(|b| b.1.len()).sum::<usize>()) as u64;
    // one history entry more: a well-typed box under a new (role, epoch); with the box map paged
    // only the small fields are rewritten, not the whole `secrets.0` state
    let (k, h) = r.secrets.history.iter().next().unwrap();
    let k = osis_keys::aspects::history_key(k.role, &Epoch::new(1000, [5; 32]).unwrap());
    let (_, w) = measured(&b, || {
        let mut m = Mutation::new();
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    (total, r.secrets.boxes.len(), w.io.written_bytes)
}

// spec/requirements.md, Scale: direct rosters hold thousands of holders; spec/crypto.md §4: a
// rotation boxes each remaining role secret to each holder. A removal from a roster of n and
// 10n writers (read and write rotated): the rotation commit is linear in holders, at most
// 3000 B per remaining holder past a fixed 4 KiB (notes/chat.md: 2.7 KB); one more `secrets.0` entry afterwards
// writes about the same bytes at both sizes (the box map is paged).
#[test]
fn roster_removal_is_linear() {
    let (n, small, big) = (20, roster_removal(20), roster_removal(200));
    for (k, (total, boxes, _)) in [(n, small), (10 * n, big)] {
        assert!(boxes >= 2 * (k - 1), "{boxes} boxes for {k} holders");
        println!("roster {k}: rotation commit {total} B, {boxes} boxes");
        // plus the commit's own fixed part (header, keysets, the admin's boxes)
        assert!(total <= 3000 * (k as u64 - 1) + 4096, "{total} B for {k} holders");
    }
    linear("rotation commit bytes", small.0, big.0);
    flat("one more secrets.0 entry: store bytes", small.2, big.2);
}

/// Store bytes per write overwriting one entry of a map of n 100-byte entries.
fn replacing_edit(n: usize, map: &osis_schema::Aspect<Value>) -> u64 {
    let (mut lp, t) = one_thing();
    let b = lp.peers[0].backend.clone();
    let fill: osis_base::ValueMap = (0..n).map(|i| (s(&format!("k{i:05}")), s(&"f".repeat(100)))).collect();
    let mut m = Mutation::new();
    m.set(t, map, &Value::Map(fill)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let edits = 2;
    let (_, w) = measured(&b, || {
        for i in 0..edits {
            let mut m = Mutation::new();
            m.op(t, map, PathOp { path: vec![PathSeg::Key(s("k00007"))], op: Op::Set(s(&format!("v{i}"))) }).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
        }
    });
    w.handed / edits
}

// spec/commits.md §5 (purge on replace); spec/requirements.md (Cost the app chooses): under
// purge on replace every edit that replaces earlier content costs a snapshot of the aspect,
// O(its state); with no history promised an edit costs O(change). Bytes handed to the store per
// replacing edit (rows and blobs, before paging: `all_flat`) at n and 10n entries (at 2000 about
// 525 KB, the snapshot's body blob about 246 KB of it, against about 4 KB): what purge on replace
// adds, the snapshot, grows with the state.
#[test]
fn purge_on_replace_pays_its_state() {
    let (gone, plain) = ([replacing_edit(200, &GONEMAP), replacing_edit(2000, &GONEMAP)], [replacing_edit(200, &BIG), replacing_edit(2000, &BIG)]);
    linear("purge on replace: store bytes handed per edit", gone[0], gone[1]);
    flat("no history: store bytes handed per edit", plain[0], plain[1]);
    // what purge on replace adds, its snapshot, grows with the state
    let extra = |i: usize| gone[i].saturating_sub(plain[i]);
    assert!(extra(1) >= 5 * extra(0), "purge on replace pays O(state): {gone:?} against {plain:?}");
    assert!(gone[1] <= 600_000 && plain[1] <= 8_000, "at 2000 entries: {} B with purge on replace, {} B with no history", gone[1], plain[1]);
}
/// pending commits read again, perm commits walked) added as spans.
fn measured_at<T>(lp: &mut LocalPeer, i: usize, f: impl FnOnce(&mut LocalPeer) -> T) -> (T, Work) {
    let b = lp.peers[i].backend.clone();
    let c = |lp: &LocalPeer| [lp.peers[i].engine.death_walks(), lp.peers[i].engine.replaced_reads(), lp.peers[i].engine.examined(), osis_perm::commits_walked()];
    let c0 = c(lp);
    let (r, mut w) = measured(&b, || f(&mut *lp));
    for (k, (x, y)) in ["death walks", "replaced reads", "examined", "perm commits walked"].into_iter().zip(c0.into_iter().zip(c(lp))) {
        // a restart counts from 0 again
        w.spans.insert(k, if y >= x { y - x } else { y });
    }
    (r, w)
}

/// Peer `by` adds `v` to `asp` on `t`.
fn add(lp: &mut LocalPeer, by: usize, t: Tid, asp: &osis_schema::Aspect<Value>, v: String) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, PathOp { path: Vec::new(), op: Op::Add(Value::Str(v)) }).unwrap();
    lp.peers[by].commit(m).unwrap().unwrap()
}

/// `net(n, 0)`, peer 0 mint admin of a new thing, peers 1.. granted `roles` on it in turn,
/// synced: built once per (n, roles).
fn shared_thing(n: usize, roles: &[Role]) -> (LocalPeer, Tid) {
    LocalPeer::cached(&format!("scale::shared_thing/{n}/{roles:?}"), || {
        let mut lp = net(n, 0);
        let t = new_thing(&mut lp, 0);
        for (i, r) in roles.iter().enumerate() {
            let x = lp.peers[i + 1].engine.me();
            set_edge(&mut lp.peers[0].engine, t, x, Some(edge(*r)), None);
        }
        lp.sync_all().unwrap();
        (lp, t)
    })
}

/// Late deltas into a set of n one-element commits (`asp`, compacted after them or not): a late
/// delta older than all of them arriving and the first commit judged, then one 5 commits late.
fn late_deltas(n: usize, asp: &osis_schema::Aspect<Value>, compact: bool) -> [Work; 2] {
    // the world before the compaction, alike with and without it: built once per (n, asp)
    let (mut lp, (t, late, ids)) = LocalPeer::cached(&format!("scale::late_deltas/{n}/{}", asp.ak()), || {
        let (mut lp, t) = shared_thing(2, &[Role::Write]);
        let late: Vec<_> = (0..3).map(|i| add(&mut lp, 1, t, asp, format!("late{i}"))).collect();
        lp.advance(1_000);
        let ids: Vec<_> = (0..n).map(|i| add(&mut lp, 0, t, asp, format!("e{i}"))).collect();
        (lp, (t, late, ids))
    });
    let k = ak(asp.ak());
    if compact {
        lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    }
    let pks = lp.packages_for(1, 0).unwrap();
    let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
    lp.deliver(0, &pk(&late[0])).unwrap();
    let (_, old) = measured_at(&mut lp, 0, |lp| {
        lp.deliver(0, &pk(&late[1])).unwrap();
        lp.peers[0].engine.replaced_at(&ids[0], &t, &k).unwrap();
    });
    lp.advance(1);
    let recent = add(&mut lp, 1, t, asp, "recent".into());
    lp.advance(1);
    for i in 0..5 {
        add(&mut lp, 0, t, asp, format!("r{i}"));
    }
    let pk = lp.packages_for(1, 0).unwrap().into_iter().find(|p| p.id == recent).unwrap();
    let (_, recent) = measured_at(&mut lp, 0, |lp| {
        lp.deliver(0, &pk).unwrap();
        lp.peers[0].engine.replaced_at(&ids[0], &t, &k).unwrap();
    });
    [old, recent]
}

/// The phases counted at either size, each once.
fn phases<'a>(small: &'a Work, big: &'a Work) -> BTreeSet<&'a str> {
    small.spans.keys().chain(big.spans.keys()).copied().collect()
}

/// The bytes one row write may move between sizes for no growth: a state crossing into paging, or
/// a page split, rewrites one whole page (a state page about 3 KB, a store page at most 8 KB).
const ONE_PAGE: u64 = 8 * 1024;

/// Bytes handed to the store at 10n about those at n (`flat`), give or take `ONE_PAGE`.
#[track_caller]
fn flat_bytes(what: &str, small: u64, big: u64) {
    println!("{what}: {small} at n, {big} at 10n");
    assert!(big <= 2 * small + ONE_PAGE, "{what}: {small} at n, {big} at 10n: grows with the data");
}

/// Every counted phase grows at most like a log from n to 10n, the store's among them: the rows
/// handed to it ("store rows written"), their bytes (`Work::handed`, within `ONE_PAGE`) and the
/// units it wrote. Not the units' bytes: a unit holds 4-11 KB, and where keys land (commit IDs,
/// splits) moves whole units between sizes, so their bytes are noise beside these counts.
#[track_caller]
fn all_flat(what: &str, small: &Work, big: &Work) {
    for k in phases(small, big) {
        flat(&format!("{what}: {k}"), small.n(k), big.n(k));
    }
    flat_bytes(&format!("{what}: store bytes handed"), small.handed, big.handed);
    flat(&format!("{what}: store units written"), small.io.writes, big.io.writes);
}

/// Every counted phase, the bytes handed to the store and the units it wrote grow at most
/// linearly from n to 10n (`all_flat`).
#[track_caller]
fn all_linear(what: &str, small: &Work, big: &Work) {
    for k in phases(small, big) {
        linear(&format!("{what}: {k}"), small.n(k), big.n(k));
    }
    linear(&format!("{what}: store bytes handed"), small.handed, big.handed);
    linear(&format!("{what}: store units written"), small.io.writes, big.io.writes);
}

// spec/commits.md §5 (when a body was replaced), spec/crdt.md §4.8; spec/requirements.md,
// Scale (no operation O(history)): a set of n and 10n one-element commits, then a delta by
// another writer older than all of them, and one 5 commits late, each arriving and the first
// commit judged: in an unbounded set, a keep-at-least one, and that one compacted. Every counted
// phase (death walks, replaced reads among them) is flat.
#[test]
fn late_delta_deaths_are_flat_spec_crdt_4_8() {
    use crate::common::{KEPTSET, TAGS};
    for (name, asp, compact) in [("unbounded set", &TAGS, false), ("keep-at-least set", &KEPTSET, false), ("compacted keep-at-least set", &KEPTSET, true)] {
        let (a, b) = (late_deltas(30, asp, compact), late_deltas(300, asp, compact));
        all_flat(&format!("{name}, a delta older than all"), &a[0], &b[0]);
        all_flat(&format!("{name}, a delta 5 commits late"), &a[1], &b[1]);
    }
}

/// n one-element commits by the mint admin (0) and one add by writer B (1); admin C (2), who
/// never saw it, revokes B: (the revoke arriving at 0, flipping the add invalid; B's add written
/// after the revoke arriving invalid). No peer writes addenda (`Engine::write_addenda`): 0's would keep B's add.
fn validity_flip(n: usize) -> [Work; 2] {
    use crate::common::TAGS;
    let (mut lp, t) = shared_thing(3, &[Role::Write, Role::Admin]);
    for p in &mut lp.peers {
        p.engine.write_addenda(false);
    }
    let (b, k) = (lp.peers[1].engine.me(), ak("t:tags.0"));
    for i in 0..n {
        add(&mut lp, 0, t, &TAGS, format!("e{i}"));
    }
    let bs = add(&mut lp, 1, t, &TAGS, "b".into());
    let pk = lp.packages_for(1, 0).unwrap().into_iter().find(|p| p.id == bs).unwrap();
    lp.deliver(0, &pk).unwrap();
    let scope = osis_engine::DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([t]))]), content: BTreeMap::from([(b, BTreeSet::from([t]))]) };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(b)) }).unwrap();
    m.frontier(osis_perm::Frontier::new(f.commits));
    let rv = lp.peers[2].commit(m).unwrap().unwrap();
    let late = add(&mut lp, 1, t, &TAGS, "late".into());
    let rv = lp.packages_for(2, 0).unwrap().into_iter().find(|p| p.id == rv).unwrap();
    let late = lp.packages_for(1, 0).unwrap().into_iter().find(|p| p.id == late).unwrap();
    let tags = |lp: &mut LocalPeer| match lp.peers[0].engine.get(&t, &k).unwrap() {
        Some(Value::Set(s)) => s.len(),
        _ => 0,
    };
    assert_eq!(tags(&mut lp), n + 1);
    let (_, flip) = measured_at(&mut lp, 0, |lp| lp.deliver(0, &rv).unwrap());
    assert_eq!(tags(&mut lp), n);
    let (_, arrive) = measured_at(&mut lp, 0, |lp| lp.deliver(0, &late).unwrap());
    assert_eq!(tags(&mut lp), n);
    [flip, arrive]
}

/// B (1) holds n set elements as the mint admin's delta; the mint admin adds one and
/// snapshots; B joins the snapshot, then one ordinary delta: (the join, the delta).
fn snapshot_join(n: usize, asp: &osis_schema::Aspect<Value>) -> [Work; 2] {
    let (mut lp, t) = shared_thing(2, &[Role::Write]);
    let mut m = Mutation::new();
    // 1000-byte elements: the set pages at both sizes
    m.set(t, asp, &Value::Set((0..n).map(|i| Value::Str(format!("{i:08}{}", "e".repeat(992)))).collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let k = ak(asp.ak());
    let x = add(&mut lp, 0, t, asp, "x".into());
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let one = add(&mut lp, 0, t, asp, "y".into());
    let pks = lp.packages_for(0, 1).unwrap();
    let pk = |c: osis_base::CommitId| pks.iter().find(|p| p.id == c).unwrap().clone();
    lp.deliver(1, &pk(x)).unwrap();
    let (_, join) = measured_at(&mut lp, 1, |lp| lp.deliver(1, &pk(snap)).unwrap());
    let (_, delta) = measured_at(&mut lp, 1, |lp| lp.deliver(1, &pk(one)).unwrap());
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), lp.peers[0].engine.get(&t, &k).unwrap());
    [join, delta]
}

/// `net(2, 0)`, peer 0 mint admin of a new thing peer 1 reads (`new_shared`; content of a thing
/// outside a node's closure waits, spec/commits.md §4): the thing and the commits held then.
/// Built once.
fn reader_net() -> (LocalPeer, (Tid, BTreeSet<osis_base::CommitId>)) {
    LocalPeer::cached("scale::reader_net", || {
        let mut lp = net(2, 0);
        let t = crate::common::new_shared(&mut lp, 0);
        let base = lp.commit_ids(0).into_iter().collect();
        (lp, (t, base))
    })
}

/// A fresh node gets the mint admin's snapshot of a set of n one-element commits, then the
/// commits: the work of the commits.
fn snapshot_first(n: usize) -> Work {
    use crate::common::TAGS;
    let (mut lp, (t, base)) = reader_net();
    for i in 0..n {
        add(&mut lp, 0, t, &TAGS, format!("e{i}"));
    }
    let k = ak("t:tags.0");
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks = crate::common::packages_to(&mut lp, 0, 1);
    for p in pks.iter().filter(|p| base.contains(&p.id) || p.id == snap) {
        lp.deliver(1, p).unwrap();
    }
    let (_, w) = measured_at(&mut lp, 1, |lp| {
        for p in pks.iter().filter(|p| !base.contains(&p.id) && p.id != snap) {
            lp.deliver(1, p).unwrap();
        }
    });
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), lp.peers[0].engine.get(&t, &k).unwrap());
    w
}

// spec/permissions.md §5.2, spec/crdt.md §4.6 (function of the held set; exactly the writes of invalid deltas are removed); spec/requirements.md, Scale: among n and 10n held
// commits, a revoke flipping one add invalid rebuilds the aspect from its held bodies (every
// change but a valid join is a rebuild, one path: a rare event may cost O(the aspect's bodies)),
// its other counted work linear at most; an invalid add arriving takes nothing and reads no held
// body.
#[test]
fn validity_flip_is_linear_and_invalid_arrival_flat_spec_permissions_5_2() {
    let (a, b) = (validity_flip(12), validity_flip(120));
    all_linear("a revoke flipping an add", &a[0], &b[0]);
    flat("a revoke flipping an add: commits re-judged", a[0].n("rejudge: a commit"), b[0].n("rejudge: a commit"));
    all_flat("an invalid add arriving", &a[1], &b[1]);
}

// spec/permissions.md §5.2 (copies; also where the receiver holds the write's own delta); spec/
// requirements.md, Scale: B holds n and 10n set elements as one delta, then joins the mint
// admin's snapshot of them (a snapshot is O(state): linear), then one ordinary delta (flat), in an
// unbounded and a keep-at-least set.
#[test]
fn snapshot_join_is_flat_spec_permissions_5_2() {
    use crate::common::{KEPTSET, TAGS};
    for asp in [&TAGS, &KEPTSET] {
        let (a, b) = (snapshot_join(80, asp), snapshot_join(800, asp));
        all_linear(&format!("{}: snapshot join", asp.ak()), &a[0], &b[0]);
        all_flat(&format!("{}: then a delta", asp.ak()), &a[1], &b[1]);
    }
}

// spec/permissions.md §5.2 (copies; never compared with it); spec/requirements.md, Scale: a fresh node holding the snapshot of n and 10n one-element
// commits, then getting the commits, does linear work, not quadratic.
#[test]
fn commits_after_their_snapshot_are_linear_spec_permissions_5_2() {
    all_linear("commits after their snapshot", &snapshot_first(12), &snapshot_first(120));
}

/// A fresh reader's first sync of a thing holding n one-element commits (200-byte elements), each content commit
/// arriving before every commit it waits on (the thing's record, the reader's grant: all pend),
/// then those: (its work, pending commits examined again).
fn first_sync(n: usize) -> (Work, u64) {
    use crate::common::TAGS;
    let (mut lp, (t, base)) = reader_net();
    // 200-byte elements: the state is paged at either size
    for i in 0..n {
        add(&mut lp, 0, t, &TAGS, format!("{i:08}{}", "e".repeat(192)));
    }
    let pks = crate::common::packages_to(&mut lp, 0, 1);
    let (_, w) = measured_at(&mut lp, 1, |lp| {
        for p in pks.iter().filter(|p| !base.contains(&p.id)).chain(pks.iter().filter(|p| base.contains(&p.id))) {
            lp.deliver(1, p).unwrap();
        }
    });
    let k = ak("t:tags.0");
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), lp.peers[0].engine.get(&t, &k).unwrap());
    let examined = w.n("examined");
    (w, examined)
}

// spec/commits.md §4 (Pending storage); spec/requirements.md, Scale (no operation O(history)): a
// first sync of n and 10n commits, each arriving before what it waits on, does linear work: each
// pending commit is examined again a fixed number of times, as what it waits on arrives, not after every
// commit applied.
#[test]
fn a_first_sync_is_linear_spec_commits_4() {
    let ((a, ea), (b, eb)) = (first_sync(40), first_sync(400));
    assert!(ea >= 40 && eb >= 400, "the content commits pended: {ea}, {eb} examined again");
    assert!(eb <= 2 * 400 + 40, "each pending commit examined again a few times: {eb} for 400");
    all_linear("a first sync", &a, &b);
}

/// n one-element commits on t by its mint admin (0); B (1) writes one, received by C (2)
/// alone; 0 removes B and C's addendum keeps B's add (held at 0 if `with`). Holder T (a thing 0
/// makes, 3 its admin) holds write on t and gains a member E (4) by 3: the work of that grant
/// arriving at 0.
fn addenda_rejudge(n: usize, with: bool) -> Work {
    // the world up to C's addendum, alike with and without it: built once per n
    let (mut lp, (t, holder, ids)) = LocalPeer::cached(&format!("scale::addenda_rejudge/{n}"), || {
        use crate::common::TAGS;
        let (mut lp, t) = shared_thing(5, &[Role::Write, Role::Write, Role::Write]);
        let ids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
        let holder = new_thing(&mut lp, 0);
        set_edge(&mut lp.peers[0].engine, holder, ids[3], Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, holder, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        for i in 0..n {
            add(&mut lp, 0, t, &TAGS, format!("e{i}"));
        }
        lp.advance(1_000);
        let bs = add(&mut lp, 1, t, &TAGS, "b".into());
        let pk = lp.packages_for(1, 2).unwrap().into_iter().find(|p| p.id == bs).unwrap();
        lp.deliver(2, &pk).unwrap();
        lp.advance(1_000);
        let d = osis_engine::flows::Demotion { holder: ids[1], new: None, retain: None };
        let rv = *lp.peers[0].engine.demote(&t, &d).unwrap().commits.last().unwrap();
        lp.advance(1_000);
        let pk = lp.packages_for(0, 2).unwrap().into_iter().find(|p| p.id == rv).unwrap();
        lp.deliver(2, &pk).unwrap();
        (lp, (t, holder, ids))
    });
    if with {
        // C's addendum, then B's add again once vouched for
        lp.sync(2, 0).unwrap();
        lp.sync(2, 0).unwrap();
    }
    let Some(Value::Set(v)) = lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap() else { panic!() };
    assert_eq!(v.len(), n + usize::from(with), "C's addendum keeps B's add");
    let g = set_edge(&mut lp.peers[3].engine, holder, ids[4], Some(edge(Role::Write)), None);
    let pk = lp.packages_for(3, 0).unwrap().into_iter().find(|p| p.id == g).unwrap();
    measured_at(&mut lp, 0, |lp| lp.deliver(0, &pk).unwrap()).1
}

// spec/permissions.md §5.2 (Addenda: a thing with addenda is judged whole where it would be
// judged only for the authors whose roles moved); spec/requirements.md, Scale: a member joining
// a holder of a thing of n and 10n commits re-judges nothing per commit without an addendum,
// and at most linearly with one held.
#[test]
fn addenda_rejudge_spec_permissions_5_2() {
    all_flat("a member joining a holder, no addendum", &addenda_rejudge(20, false), &addenda_rejudge(200, false));
    all_linear("a member joining a holder, an addendum held", &addenda_rejudge(20, true), &addenda_rejudge(200, true));
}

/// Bob (1), a writer of t holding k things of his own, writes 3 edits of t and 3 grants on his
/// things to Alice (0); before they reach her she removes him from t, judging her removal's
/// addenda. The work of his commits, stamped before the removal, arriving at Alice.
fn addenda_wake(k: usize) -> Work {
    use crate::common::TAGS;
    let (mut lp, t) = shared_thing(3, &[Role::Write, Role::Write]);
    let (alice, bob) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
    let mut mine = Vec::new();
    for _ in 0..k {
        let q = new_thing(&mut lp, 1);
        lp.hold(q);
        mine.push(q);
    }
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let mut sent = Vec::new();
    for (i, q) in mine.iter().take(3).enumerate() {
        sent.push(add(&mut lp, 1, t, &TAGS, format!("b{i}")));
        sent.push(set_edge(&mut lp.peers[1].engine, *q, alice, Some(edge(Role::Read)), None));
    }
    lp.advance(1_000);
    lp.peers[0].engine.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None }).unwrap();
    lp.advance(1_000);
    lp.peers[0].tick().unwrap();
    let pks: Vec<_> = lp.packages_for(1, 0).unwrap().into_iter().filter(|p| sent.contains(&p.id)).collect();
    assert_eq!(pks.len(), sent.len(), "Bob's commits sent");
    measured_at(&mut lp, 0, |lp| {
        for pk in &pks {
            lp.deliver(0, pk).unwrap();
        }
    })
    .1
}

// spec/permissions.md §5.2 (Addenda); spec/requirements.md, Scale; notes/principles.md
// (Fast by construction): a removed party's commits stamped before its removal arriving after
// it, edge writes among them, cost the same whatever the removed party holds: the removal is
// woken by what the commits name (their edges and stated paths), never by the removed party's
// reach.
#[test]
fn addenda_wake_is_flat_in_the_removed_partys_reach_spec_permissions_5_2() {
    all_flat("a removed party's backdated commits", &addenda_wake(10), &addenda_wake(100));
}

/// Peer 0 applies `o` to `t`'s kept set (`t:keptset.0`, D one day) a millisecond on.
fn kept_op(lp: &mut LocalPeer, t: Tid, o: Op) -> osis_base::CommitId {
    lp.advance(1);
    let mut m = Mutation::new();
    m.op(t, &crate::common::KEPTSET, PathOp { path: Vec::new(), op: o }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap()
}

/// `one_thing` with n elements `e{i}` added to its kept set, one per commit (`kept_op`): the
/// commits.
fn kept_set(n: usize) -> (LocalPeer, Tid, Vec<osis_base::CommitId>) {
    let (mut lp, t) = one_thing();
    let ids = (0..n).map(|i| kept_op(&mut lp, t, Op::Add(Value::Str(format!("e{i}"))))).collect();
    (lp, t, ids)
}

/// A kept set (D one day, `kept_set`) edited every 8 hours `edits` times (its window: 3 edits), compacted every 2 edits,
/// each edit killing one long-lived element; after each edit every held snapshot is judged and
/// those past their bound and covered by the newest dropped, as node-sync does: (snapshots held
/// at the end, the work of the last edit's judging).
fn kept_snapshots(edits: usize) -> (usize, Work) {
    let (mut lp, t, _) = kept_set(edits);
    let k = ak("t:keptset.0");
    let mut snaps = Vec::new();
    let mut last = None;
    for i in 0..edits {
        lp.advance(8 * 3_600_000);
        kept_op(&mut lp, t, Op::Remove(Value::Str(format!("e{i}"))));
        kept_op(&mut lp, t, Op::Add(Value::Str(format!("n{i}"))));
        if i % 2 == 0 {
            lp.advance(1);
            snaps.push(lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap());
        }
        let (_, w) = measured_at(&mut lp, 0, |lp| {
            for s in &snaps {
                lp.peers[0].engine.replaced_at(s, &t, &k).unwrap();
            }
        });
        last = Some(w);
        let now = lp.peers[0].engine.now().0;
        let e = &mut lp.peers[0].engine;
        let newest = *snaps.last().unwrap();
        snaps.retain(|s| {
            let gone = *s != newest && e.drop_from(s, &t, &k).unwrap() <= now && e.covered(&newest, s, &t, &k).unwrap() == Some(true);
            if gone {
                e.drop_body(s, &t, &k).unwrap();
            }
            !gone
        });
    }
    (snaps.len(), last.unwrap())
}

// spec/commits.md §5 (for a duration D after replaced; a snapshot's at the latest death among the writes it carries that no held valid snapshot stamped later carries); spec/requirements.md, Scale: a kept set edited n and 10n times keeps
// the snapshots of its D window, not all; judging them reads each whole, O(the set's state),
// and walks flat (death walks, replaced reads).
#[test]
fn kept_snapshots_stay_within_their_window_spec_commits_5() {
    let ((s1, w1), (s2, w2)) = (kept_snapshots(8), kept_snapshots(80));
    flat("snapshots held", s1 as u64, s2 as u64);
    all_linear("judging the held snapshots", &w1, &w2);
    for k in ["death walks", "replaced reads"] {
        flat(&format!("judging the held snapshots: {k}"), w1.n(k), w2.n(k));
    }
}

/// A kept set (`kept_set`) of n elements, compacted: the work of one more element added, then of
/// a body the snapshot covers dropped (`Engine::drop_body`), each with its transaction's dating.
fn kept_set_changes(n: usize) -> [Work; 2] {
    let (mut lp, t, ids) = kept_set(n);
    let k = ak("t:keptset.0");
    lp.advance(1);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let (_, edit) = measured_at(&mut lp, 0, |lp| kept_op(lp, t, Op::Add(Value::Str("more".into()))));
    let (_, drop) = measured_at(&mut lp, 0, |lp| lp.peers[0].engine.drop_body(&ids[0], &t, &k).unwrap());
    [edit, drop]
}

// spec/commits.md §5 (when a body was replaced); spec/requirements.md, Scale (no operation
// O(history)): on a dated aspect of n and 10n bodies, a body joining and a covered body leaving
// each note or forget that body's writes alone in the aspect's held writes (no copy of them, no
// body read anew) and date again only what its writes may move.
#[test]
fn a_body_joining_or_leaving_dates_only_what_it_moves_spec_commits_5() {
    let (a, b) = (kept_set_changes(20), kept_set_changes(200));
    for (what, a, b) in [("an element added", &a[0], &b[0]), ("a covered body dropped", &a[1], &b[1])] {
        for k in ["deaths: a body", "held writes", "replaced at"] {
            flat(&format!("{what}: {k}"), a.n(k), b.n(k));
        }
    }
}

/// A kept set (`kept_set`) of n elements, compacted, then each removed one
/// per commit; then every held body judged once, as a sync pass does:
/// (bodies judged, the work).
fn judge_every_body(n: usize) -> (u64, Work) {
    let (mut lp, t, mut ids) = kept_set(n);
    let k = ak("t:keptset.0");
    lp.advance(1);
    ids.push(lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap());
    ids.extend((0..n).map(|i| kept_op(&mut lp, t, Op::Remove(Value::Str(format!("e{i}"))))));
    let (_, w) = measured_at(&mut lp, 0, |lp| {
        for c in &ids {
            lp.peers[0].engine.replaced_at(c, &t, &k).unwrap();
        }
    });
    (ids.len() as u64, w)
}

// spec/commits.md §5 (when a body was replaced); spec/requirements.md,
// Scale: judging every held body of an aspect of n and 10n bodies, a judgment reads about one
// held body for the deaths it dates (`deaths: a body`), not the bodies after it.
#[test]
fn judging_every_body_reads_each_once_spec_commits_5() {
    let ((j1, w1), (j2, w2)) = (judge_every_body(20), judge_every_body(200));
    flat("bodies read for deaths per judgment", w1.n("deaths: a body") / j1, w2.n("deaths: a body") / j2);
    flat("replaced reads per judgment", w1.n("replaced reads") / j1, w2.n("replaced reads") / j2);
}

/// An aspect of n messages kept forever by the mint admin, r requests by admin X naming n/r
/// of them each: (a join of a new writer, X's removal (the requests fall), X's re-grant (they
/// rise)) at the mint admin.
fn purge_rejudge(n: usize) -> [Work; 3] {
    use osis_schema::{Aspect, StaticSchema};
    static S: StaticSchema = StaticSchema::new("purgecost.osis", "revision 1; purge_by(author, admin) aspect l:msg.0: string;\n");
    const MSG: Aspect<Value> = Aspect::new("l:msg.0", &S);
    let r = n / 10;
    let (mut lp, t) = shared_thing(4, &[Role::Admin]);
    let k = ak("l:msg.0");
    let x = lp.peers[1].engine.me();
    let mut ids = Vec::new();
    for i in 0..n {
        let mut m = Mutation::new();
        m.set(t, &MSG, &Value::Str(format!("m{i}"))).unwrap();
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    lp.advance(1);
    let mut pks = Vec::new();
    for i in 0..r {
        let mut m = Mutation::new();
        m.purge(lp.peers[0].engine.purge_item(&ids[i * n / r], t, k.clone()).unwrap());
        m.set(t, &MSG, &Value::Str(format!("p{i}"))).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        pks.push(lp.peers[1].engine.package(&c).unwrap().unwrap());
    }
    for p in &pks {
        lp.deliver(0, p).unwrap();
    }
    let z = lp.peers[2].engine.me();
    let step = |lp: &mut LocalPeer, who: Tid, e: Option<Role>| measured_at(lp, 0, |lp| set_edge(&mut lp.peers[0].engine, t, who, e.map(edge), None)).1;
    [step(&mut lp, z, Some(Role::Write)), step(&mut lp, x, None), step(&mut lp, x, Some(Role::Admin))]
}

// spec/permissions.md §6 (a request holds role r exactly where); spec/
// requirements.md, Scale: on an aspect of n and 10n kept commits with n/10 named purge requests,
// a join with no request does flat work; the requester's removal and re-grant, which make every
// request fall or rise together, rebuild the aspect once (after every verdict, not once per
// request), and every counted phase (bodies read by that rebuild, commits re-judged, store
// bytes) grows at most linearly.
#[test]
fn purge_rejudge_is_linear_in_requests_spec_permissions_6() {
    let (a, b) = (purge_rejudge(30), purge_rejudge(300));
    all_flat("a join", &a[0], &b[0]);
    for (k, what) in [(1, "the requests falling"), (2, "the requests rising")] {
        assert_eq!((a[k].n("rebuild"), b[k].n("rebuild")), (1, 1), "{what}: rebuilds at n, 10n");
        all_linear(what, &a[k], &b[k]);
    }
}

/// B (1) gets the mint admin's writes of one purge-on-replace key only through k snapshots,
/// each dropped at its cover once the next replaces it: B's demotion frontier for the mint
/// admin, in listed commits and encoded bytes.
fn dropped_frontier(k: usize) -> (usize, usize) {
    let (mut lp, t) = shared_thing(2, &[Role::Write]);
    let me = lp.peers[0].engine.me();
    let key = ak("t:gonemap.0");
    for i in 0..k {
        for j in 0..2 {
            let mut m = Mutation::new();
            m.op(t, &GONEMAP, PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s(&format!("v{i}.{j}"))) }).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
        }
        let sn = lp.peers[0].engine.snapshot(&t, &key).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&sn).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
        lp.advance(1_000);
        lp.peers[1].tick().unwrap();
    }
    let e = &mut lp.peers[1].engine;
    let scope = osis_engine::DemotionScope { roles: BTreeMap::new(), content: BTreeMap::from([(me, BTreeSet::from([t]))]) };
    let now = e.now();
    let f = e.frontier(&scope, now).unwrap();
    (f.commits.len(), osis_base::encode(&f.to_value()).len())
}

// spec/permissions.md §5.1 (a commit is listed whether A still holds its body, dropped it or compacted it), spec/permissions.md §5.1:
// a node holding a writer's work only through k and 10k dropped snapshots lists each in its
// demotion frontier by ID: linear, at most 40 B per snapshot.
#[test]
fn dropped_snapshot_frontier_is_linear_spec_commits_5() {
    let ((c1, b1), (c2, b2)) = (dropped_frontier(6), dropped_frontier(60));
    assert!(c1 >= 6 && c2 >= 60, "{c1}, {c2} commits listed");
    linear("frontier commits", c1 as u64, c2 as u64);
    assert!(b2 <= 40 * c2 + 64, "{b2} B for {c2} commits");
    linear("frontier bytes", b1 as u64, b2 as u64);
}

/// n content commits on 10 things of the node's own tree: (a grant on one of them, opening the
/// store again).
fn grant_and_open(n: usize) -> [Work; 2] {
    let mut lp = net(1, 0);
    let things: Vec<Tid> = (0..10).map(|_| new_thing(&mut lp, 0)).collect();
    for i in 0..n {
        let mut m = Mutation::new();
        m.set(things[i % 10], &crate::common::REG, &s(&format!("v{i}"))).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    let (_, grant) = measured_at(&mut lp, 0, |lp| edge_write(&mut lp.peers[0].engine, things[0], Tid::from_bytes([7; 15]), Some(edge(Role::Read)), None));
    let roster = lp.peers[0].engine.roster(&things[0]);
    let (_, open) = measured_at(&mut lp, 0, |lp| lp.peers[0].restart(1).unwrap());
    assert_eq!(lp.peers[0].engine.roster(&things[0]), roster);
    [grant, open]
}

// spec/permissions.md §5.1; spec/requirements.md, Scale (no operation O(history)): with n and
// 10n content commits held on the node's own tree, a grant does flat work (it judges no content
// commit), and an open from the persisted index rebuilds nothing, at most linear work (headers).
#[test]
fn grant_is_flat_in_content_commits() {
    let (a, b) = (grant_and_open(30), grant_and_open(300));
    all_flat("a grant", &a[0], &b[0]);
    all_linear("open", &a[1], &b[1]);
    assert_eq!(b[1].n("rebuild"), 0, "open rebuilds nothing");
}

static LONG: osis_schema::StaticSchema = osis_schema::StaticSchema::new("long.osis", "revision 1; purge_by(author, admin) aspect l:msg.0: string;\n");
const MSGS: osis_schema::Aspect<Value> = osis_schema::Aspect::new("l:msg.0", &LONG);

/// One aspect kept forever, n 200-byte writes by 4 writers (the mint admin and 3 granted write),
/// every node holding them: (one more write at writer 1, it arriving at the mint admin, the
/// mint admin removing writer 2 (a fall of its writes)).
fn long_aspect(n: usize) -> [Work; 3] {
    let (mut lp, t) = shared_thing(4, &[Role::Write, Role::Write, Role::Write]);
    let w = |lp: &mut LocalPeer, by: usize, i: usize| {
        let mut m = Mutation::new();
        m.set(t, &MSGS, &s(&format!("{i:08}{}", "m".repeat(192)))).unwrap();
        lp.peers[by].commit(m).unwrap().unwrap()
    };
    for i in 0..n {
        w(&mut lp, i % 4, i);
    }
    lp.sync_all().unwrap();
    let (c, one) = measured_at(&mut lp, 1, |lp| w(lp, 1, n));
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    let (_, recv) = measured_at(&mut lp, 0, |lp| lp.deliver(0, &pk).unwrap());
    let x = lp.peers[2].engine.me();
    let (_, fall) = measured_at(&mut lp, 0, |lp| {
        let d = osis_engine::flows::Demotion { holder: x, new: None, retain: None };
        lp.peers[0].engine.demote(&t, &d).unwrap()
    });
    [one, recv, fall]
}

// spec/requirements.md, Scale (no operation O(history)); spec/commits.md §5 (kept while live): keep forever: one
// aspect of n and 10n kept writes by several writers (a chat's messages): a write and its
// arrival do flat work; removing a writer, whose writes fall, at most linear.
#[test]
fn long_aspect_writes_are_flat() {
    let (a, b) = (long_aspect(40), long_aspect(400));
    all_flat("a write", &a[0], &b[0]);
    all_flat("a write arriving", &a[1], &b[1]);
    all_linear("a writer removed", &a[2], &b[2]);
}

/// n edge writes on one thing by its mint admin (5 holders granted and removed in turn), then
/// a fresh node ingesting them one by one: (its work; then the mint admin's grant to a new
/// holder, its removal of a holder, and the joiner ingesting those two).
fn role_history_join(n: usize) -> [Work; 4] {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    // a history `roles.0` pages at before the measured one, so n and 10n compare paged states
    for i in 0..PAGED_HISTORY {
        edge_write(&mut lp.peers[0].engine, t, Tid::from_bytes([i as u8 + 100; 15]), Some(edge(Role::Read)), None);
    }
    let base: BTreeSet<_> = lp.commit_ids(0).into_iter().collect();
    for i in 0..n {
        // a grant, then its removal: a holder's records (a map key's) stay few, so a write
        // reads the key's few records, not the history (a paged map's join loads every record
        // of the keys it touches)
        let h = Tid::from_bytes([(i / 2) as u8 + 1; 15]);
        let e = (i % 2 == 0).then(|| edge(Role::Read));
        edge_write(&mut lp.peers[0].engine, t, h, e, None);
    }
    let pks = lp.packages_for(0, 1).unwrap();
    for p in pks.iter().filter(|p| base.contains(&p.id)) {
        lp.deliver(1, p).unwrap();
    }
    let (_, join) = measured_at(&mut lp, 1, |lp| {
        for p in pks.iter().filter(|p| !base.contains(&p.id)) {
            lp.deliver(1, p).unwrap();
        }
    });
    let (g, grant) = measured_at(&mut lp, 0, |lp| edge_write(&mut lp.peers[0].engine, t, Tid::from_bytes([99; 15]), Some(edge(Role::Read)), None));
    let (r, removal) = measured_at(&mut lp, 0, |lp| edge_write(&mut lp.peers[0].engine, t, Tid::from_bytes([99; 15]), None, None));
    let pks: Vec<_> = [g, r].iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap()).collect();
    let (_, arrive) = measured_at(&mut lp, 1, |lp| {
        for p in &pks {
            lp.deliver(1, p).unwrap();
        }
    });
    assert_eq!(lp.peers[1].engine.roster(&t), lp.peers[0].engine.roster(&t));
    [join, grant, removal, arrive]
}

/// Edge writes on other holders before a role history (`role_history_join`): `roles.0` (an entry
/// each) pages from about 3 KB of entries.
const PAGED_HISTORY: usize = 64;

// spec/permissions.md §5.1; spec/requirements.md, Scale (a node that starts holding a thing
// fetches and judges all of its role history: O(the history)): a fresh node ingesting n and 10n
// edge writes on one thing one by one does linear work, and at the end of the history a grant,
// a removal and their arrival do flat work: perm places each write without walking the
// history, and the node re-judges only the commits whose writes apply otherwise
// (`Changed::reached`).
#[test]
fn role_history_join_is_linear() {
    let (a, b) = (role_history_join(12), role_history_join(120));
    all_linear("a joiner ingesting a role history", &a[0], &b[0]);
    for (i, what) in ["a grant", "a removal", "their arrival"].iter().enumerate() {
        all_flat(&format!("at the end of a role history, {what}"), &a[i + 1], &b[i + 1]);
    }
}

/// A thing keeping `t:kept.0` and signal `t:log~0` a day, watched by a commit listener: n
/// overwrites of the register and n fires, a minute apart. Then (a setting keeping both two
/// days, which moves no body in or out of history; the first replaced value and the first two
/// fires leaving history as their window passes and the engine ticks; a setting shortening the
/// window by a minute, so the next value and fire leave at once), each with the commits it told
/// the listener as a span.
fn history_moves(n: usize) -> [Work; 3] {
    const DAY_MS: u64 = 86_400_000;
    let two = osis_schema::History::Keep { until: None, after: Some(2 * DAY_MS) };
    let mut lp = net(1, 0);
    let t = crate::common::new_thing_keeping(&mut lp, 0, &[("t:log~0", crate::common::DAY)]);
    let (kept, log) = (ak("t:kept.0"), ak("t:log~0"));
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.listen_commits(std::sync::Arc::new(|_| true));
    let start = lp.peers[0].engine.now().0;
    let mut vals = Vec::new();
    let mut fires = Vec::new();
    for i in 0..n {
        lp.advance(60_000);
        for (k, out) in [(&kept, &mut vals), (&log, &mut fires)] {
            let mut m = Mutation::new();
            m.set(t, k, &Value::Str(format!("v{i}"))).unwrap();
            out.push(lp.peers[0].commit(m).unwrap().unwrap());
        }
    }
    lp.advance(60_000);
    let mut x = crate::common::test_setting();
    x.rules.extend(crate::common::setting(&[("t:kept.0", two), ("t:log~0", two)]).rules);
    let step = |lp: &mut LocalPeer, f: &dyn Fn(&mut LocalPeer)| {
        while rx.try_recv().is_ok() {}
        let (_, mut w) = measured_at(lp, 0, |lp| f(lp));
        let told = rx.try_iter().filter_map(|e| if let osis_engine::Event::Commits(ch) = e { Some(ch.len() as u64) } else { None }).sum();
        w.spans.insert("commits told", told);
        w
    };
    let change = step(&mut lp, &|lp| { crate::common::set_setting(lp, 0, t, &x); });
    for (c, k) in [(&vals[0], &kept), (&fires[0], &log), (&vals[n - 1], &kept)] {
        assert!(lp.peers[0].engine.listed_at(c, &[(t, k.clone())]).unwrap(), "in history before the window passes");
    }
    // the first value was replaced by the second, written a minute after it with the second fire
    let now = lp.peers[0].engine.now().0;
    lp.advance(start + 2 * 60_000 + 2 * DAY_MS + 1 - now);
    let pass = step(&mut lp, &|lp| lp.peers[0].tick().unwrap());
    let listed = |lp: &mut LocalPeer, c: &osis_base::CommitId, k: &Ak| lp.peers[0].engine.listed_at(c, &[(t, k.clone())]).unwrap();
    assert!(!listed(&mut lp, &vals[0], &kept) && !listed(&mut lp, &fires[0], &log) && !listed(&mut lp, &fires[1], &log), "left history");
    assert!(listed(&mut lp, &vals[1], &kept) && listed(&mut lp, &fires[2], &log), "still in history");
    let short = osis_schema::History::Keep { until: None, after: Some(2 * DAY_MS - 60_000) };
    let mut x = crate::common::test_setting();
    x.rules.extend(crate::common::setting(&[("t:kept.0", short), ("t:log~0", short)]).rules);
    let shorten = step(&mut lp, &|lp| { crate::common::set_setting(lp, 0, t, &x); });
    assert!(!listed(&mut lp, &vals[1], &kept) && !listed(&mut lp, &fires[2], &log), "left history at the shortening");
    assert!(listed(&mut lp, &vals[2], &kept) && listed(&mut lp, &fires[3], &log), "still in history");
    [change, pass, shorten]
}

// notes/engine-retention-history.md Leaving history; spec/commits.md §5, spec/requirements.md Scale: a setting change that moves no body
// in or out of history, a window passing over a constant number of bodies and a setting change
// moving a constant number out, read no body and walk no commit that stays listed: every counted phase, the commits
// told the listener, and the store rows read and written are flat in the history held.
#[test]
fn setting_change_and_window_passing_are_flat_spec_commits_5() {
    let (a, b) = (history_moves(20), history_moves(200));
    for (what, i) in [("a setting change", 0), ("a window passing", 1), ("a shortening", 2)] {
        all_flat(what, &a[i], &b[i]);
        flat(&format!("{what}: store rows read"), a[i].io.reads, b[i].io.reads);
    }
}

/// A thing keeping `t:kept.0` a day, overwritten n times by its admin, a minute apart: the work of
/// one more overwrite.
fn kept_overwrite(n: usize) -> Work {
    let (mut lp, t) = one_thing();
    let kept = ak("t:kept.0");
    let put = |lp: &mut LocalPeer, v: String| {
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &kept, &Value::Str(v)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    for i in 0..n {
        put(&mut lp, format!("v{i}"));
    }
    measured_at(&mut lp, 0, |lp| put(lp, "last".into())).1
}

// notes/engine-retention-dating.md Rows; spec/commits.md §5, spec/requirements.md Scale: an overwrite of a kept register dates
// two bodies from the held writes, the one it replaces and itself (a date is the latest death of
// the part's winners, so each is read for them), and notes only its own body in the held writes,
// at n and 10n.
#[test]
fn kept_overwrite_dates_what_it_replaces_spec_commits_5() {
    let (a, b) = (kept_overwrite(20), kept_overwrite(200));
    assert_eq!((a.n("deaths: a body"), b.n("deaths: a body")), (1, 1), "its own body noted");
    assert_eq!((a.n("replaced at"), b.n("replaced at")), (2, 2), "two bodies dated");
    all_flat("an overwrite of a kept register", &a, &b);
}


/// one before, and a snapshot over them (a chat turned disappearing): peer 1 given the commits
/// newest first and the snapshot before them. The work of peer 0's tick as the first expiring
/// entry expires, then the second; both peers read alike after each. Also the size of each
/// peer's bound of what the snapshot carries valued.
fn expiries(n: usize) -> ([Work; 2], Vec<usize>) {
    const HOUR: u64 = 3_600_000;
    let (mut lp, t) = shared_thing(2, &[Role::Write]);
    let k = ak(BIG.ak());
    let now0 = lp.peers[0].engine.now().0;
    let mut ids = Vec::new();
    for i in 0..n {
        let mut m = Mutation::new();
        set_key(&mut m, t, &k, vec![PathSeg::Key(s(&format!("d{i:06}")))], long(i));
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    for i in 0..n {
        let mut m = Mutation::new();
        m.expires(t, &k, osis_base::WallMs(now0 + HOUR + 500 + 1_000 * i as u64)).unwrap();
        set_key(&mut m, t, &k, vec![PathSeg::Key(s(&format!("k{i:06}")))], long(i));
        ids.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    ids.push(lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap());
    let pks = lp.packages_for(0, 1).unwrap();
    for c in ids.iter().rev() {
        lp.deliver(1, pks.iter().find(|p| p.id == *c).unwrap()).unwrap();
    }
    let bounds: Vec<usize> = (0..2).flat_map(|i| lp.peers[i].engine.carried_bounds(&t, &k)).collect();
    let mut out = Vec::new();
    lp.advance(HOUR);
    for step in 0..2 {
        lp.advance(1_000);
        let e = &lp.peers[0].engine;
        let r0 = e.rebuilds();
        let (_, mut w) = measured_at(&mut lp, 0, |lp| lp.peers[0].tick().unwrap());
        let e = &lp.peers[0].engine;
        w.spans.insert("rebuilds", e.rebuilds() - r0);
        lp.peers[1].tick().unwrap();
        let read = lp.peers[0].engine.get(&t, &k).unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), read, "step {step}: peers read alike");
        let Some(Value::Map(m)) = read else { panic!("step {step}: the map reads {read:?}") };
        assert_eq!(m.len(), 2 * n - step - 1, "step {step}: entries left");
        assert!(!m.contains_key(&s(&format!("k{step:06}"))), "step {step}: the expired entry goes");
        out.push(w);
    }
    (out.try_into().unwrap(), bounds)
}

// spec/crdt.md §4.7, spec/requirements.md Scale: an expiry costs O(what expires): its writes,
// superseding nothing held, leave the state in place (`apply::remove_in_place`), no body of the
// aspect read but the expiring one, its pages alone loaded and written, at n and 10n held bodies. The debug build checks each against a
// rebuild (`check_rebuilt`). The bound each holder keeps of what the snapshot carries valued
// (`retention::snapshot::Carried`) is one entry per source: one, at n and 10n valued writes.
#[test]
fn expiry_is_flat_spec_crdt_4_7() {
    let ((small, sb), (big, bb)) = (expiries(40), expiries(400));
    assert_eq!((sb, bb), (vec![1, 1], vec![1, 1]), "the snapshot's bound at each peer, at n and 10n");
    for i in 0..2 {
        assert_eq!(big[i].n("rebuilds"), 0, "expiry {i} rebuilt the aspect");
        assert_eq!(big[i].n("rebuild: body"), 0, "expiry {i} read the aspect's bodies");
        all_flat(&format!("expiry {i}"), &small[i], &big[i]);
    }
}

/// A thing holding `n` bodies on other aspects and a large value: the work of judging the chunks
/// one more write-and-compact of the value drops (parts read, tree links counted and blobs read),
/// after a first round asked about the thing once.
fn chunk_drop(n: usize) -> (u64, u64) {
    use crate::common::BLOB;
    let (mut lp, t) = one_thing();
    let k = ak(BLOB.ak());
    let mut m = Mutation::new();
    for i in 0..n {
        m.set(t, &ak(&format!("u:other{i:04}.0")), &s("v")).unwrap();
    }
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut v = vec![0u8; 1 << 20];
    osis_crypto::RngCore::fill_bytes(&mut SeededRng::from_u64(1), &mut v);
    let mut round = |lp: &mut LocalPeer, at: usize| {
        v.splice(at..at, [7u8; 50]);
        let mut m = Mutation::new();
        m.set(t, &BLOB, &Value::Bytes(v.clone())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        let snap = e.snapshot(&t, &k).unwrap().unwrap();
        for c in e.commit_ids() {
            if c != snap && e.covered(&snap, &c, &t, &k).unwrap() == Some(true) {
                e.drop_body(&c, &t, &k).unwrap();
            }
        }
        lp.advance(4_000_000);
    };
    round(&mut lp, 100_000);
    round(&mut lp, 300_000);
    osis_base::costs::take();
    round(&mut lp, 600_000);
    let c: BTreeMap<_, _> = osis_base::costs::take().into_iter().map(|(k, _, c)| (k, c)).collect();
    let n = |k: &str| c.get(k).copied().unwrap_or(0);
    (n("tree refs: parts read"), n("tree refs: links counted") + n("tree refs: blobs read"))
}

// spec/sync-compaction.md §1 (freed links): a dropped body's chunk goes once nothing held links it; spec/requirements.md,
// Scale: judging the chunks a write-and-compact drops reads the sources that changed (the new
// bodies, the value's state), not every body held on the thing.
#[test]
fn chunk_drop_judgment_is_flat() {
    let (small, big) = (chunk_drop(10), chunk_drop(100));
    assert!(small.0 > 0, "the round judged dropped chunks");
    flat("chunk drop: parts read", small.0, big.0);
    flat("chunk drop: tree links", small.1, big.1);
}

/// Bob reads alice's things `d` (three writes on it) and `other`, his own thing holding `n` rows
/// of each table a forgetting clears of what it forgets: expiry timers (writes expiring
/// tomorrow), purge requests' named permanent drops and freed links (8 KiB values kept forever,
/// each purged), and commits pending (alice's writes on `other`, stamped past his drift). Alice
/// removes him from `d`: (the commits his drop of the lost secrets looks at, `forget: commits
/// scanned`; the store rows it reads). His indexes then read as an open of his store does.
fn lost_forget(n: usize) -> (u64, u64) {
    use crate::flows::{edge_of, people, spread, thing_of};
    let (mut lp, ps) = people(2);
    let (reg, big) = (ak("t:reg.0"), ak("x:b.0"));
    let d = thing_of(&mut lp, 0, ps[0]);
    let other = thing_of(&mut lp, 0, ps[0]);
    for t in [d, other] {
        lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    }
    for v in 0..3 {
        let mut m = Mutation::new();
        m.set(d, &reg, &Value::Int(v)).unwrap();
        lp.peers[0].engine.commit(m).unwrap().unwrap();
    }
    let mine = thing_of(&mut lp, 1, ps[1]);
    let e = &mut lp.peers[1].engine;
    let mut m = Mutation::new();
    m.set(mine, &ct::RETENTION, &ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() }), ..Default::default() }).unwrap();
    e.commit(m).unwrap().unwrap();
    let tomorrow = osis_base::WallMs(e.now().0 + 86_400_000);
    for v in 0..n {
        let e = &mut lp.peers[1].engine;
        let mut m = Mutation::new();
        m.set(mine, &reg, &Value::Int(v as i64)).unwrap().expires(mine, &reg, tomorrow).unwrap();
        e.commit(m).unwrap().unwrap();
        let mut x = vec![0u8; 8 << 10];
        osis_crypto::RngCore::fill_bytes(&mut SeededRng::from_u64(v as u64), &mut x);
        let mut m = Mutation::new();
        m.set(mine, &big, &Value::Bytes(x)).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.purge(e.purge_item(&c, mine, big.clone()).unwrap());
        m.set(mine, &ct::PURGE, &e.now()).unwrap();
        e.commit(m).unwrap().unwrap();
        lp.advance(1);
    }
    spread(&mut lp);
    assert!(lp.peers[1].engine.get(&d, &reg).unwrap().is_some());
    lp.peers[0].engine.demote(&d, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    spread(&mut lp);
    lp.peers[0].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    for v in 0..n {
        let mut m = Mutation::new();
        m.set(other, &reg, &Value::Int(v as i64)).unwrap();
        let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)));
    }
    let (lost, w) = measured_at(&mut lp, 1, |lp| lp.peers[1].engine.drop_lost_secrets().unwrap());
    assert!(lost.contains(&d), "{lost:?}");
    assert_eq!(lp.peers[1].engine.get(&d, &reg).unwrap(), None, "forgotten");
    assert!(lp.peers[1].engine.get(&mine, &reg).unwrap().is_some(), "kept");
    assert_eq!(lp.peers[1].engine.pending().len(), n, "alice's writes on the other thing wait on");
    lp.peers[1].engine.check_index();
    (w.n("forget: commits scanned"), w.n("store rows read"))
}

// spec/permissions.md §3 (Lost access): forgetting what a lost read reached costs what it
// forgets: it looks at the commits on the lost things alone, found through the indexes and moved
// in place (each held commit looked at would be linear), and reads the store rows of what it
// forgets, not every timer, pending commit, purge drop or freed link held elsewhere: at n and 10n
// of each on another thing, the commits looked at are the same and the store rows read flat.
#[test]
fn losing_access_costs_what_was_lost() {
    let (a, b) = (lost_forget(3), lost_forget(30));
    assert!(a.0 > 0 && a.0 == b.0, "commits looked at, with 3 rows of each elsewhere {}, with 30 {}", a.0, b.0);
    flat("forget: store rows read", a.1, b.1);
}

/// Alice grants bob read on her thing and removes him `n` times (each a role commit at her
/// account's epoch); the commit records an open of her store decodes.
fn open_role_reads(n: usize) -> u64 {
    use crate::flows::{edge_of, people, thing_of};
    let (mut lp, ps) = people(2);
    let d = thing_of(&mut lp, 0, ps[0]);
    for _ in 0..n {
        lp.peers[0].engine.grant(&d, &ps[1], &edge_of(Role::Read)).unwrap();
        lp.advance(10);
        lp.peers[0].engine.demote(&d, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: None }).unwrap();
        lp.advance(10);
    }
    let e = &mut lp.peers[0].engine;
    osis_base::costs::take();
    e.reload().unwrap();
    let cs = osis_base::costs::take();
    e.check_index();
    cs.iter().filter(|c| c.0 == "commit read").map(|c| c.2).sum()
}

// spec: none (store layout, notes/engine-store.md `c/`: an open decodes no commit record): the role commits' signatures
// (`Indexes::role_sigs`) come with the header bytes an open reads, at n and 10n role commits.
#[test]
fn an_open_decodes_no_role_commit_record() {
    let (a, b) = (open_role_reads(3), open_role_reads(30));
    flat("open: commit records decoded", a, b);
}

/// The work of `K` one-element adds, a commit each, to a set of `n` elements (as the account
/// root's `holds.0` gains a strong per made thing), compactions included.
fn set_adds(n: usize) -> Work {
    const K: usize = 10;
    let (mut lp, t) = one_thing();
    let b = lp.peers[0].backend.clone();
    let a = crate::common::TAGS;
    let e = |i: usize| s(&format!("{i:08}{}", "e".repeat(16)));
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Set((0..n).map(e).collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let (_, w) = measured(&b, || {
        for i in n..n + K {
            let mut m = Mutation::new();
            m.op(t, &a, PathOp { path: vec![], op: Op::Add(e(i)) }).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
        }
    });
    let Some(Value::Set(v)) = lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap() else { panic!() };
    assert_eq!(v.len(), n + K);
    w
}

// spec/requirements.md, Scale (a change costs what it changed); spec/crdt.md §8: a set gaining
// one element per write writes the page the element lands in, not the whole set: the store
// bytes written per add are flat from n to 10n elements (a page or two at n, about 50 KB at
// 10n). Fails if a state below some size is written whole.
#[test]
fn a_set_grown_one_element_a_write_writes_what_it_gained() {
    let (small, big) = (set_adds(150), set_adds(1500));
    flat("an add: store bytes written", small.io.written_bytes, big.io.written_bytes);
}

/// A fresh reader gets n commits each replacing the last on a kept register (`t:kept.0`, dated),
/// all before the thing's record and its grant (they pend), then those, waking them in one
/// transaction, the reader listening to commits: its work.
fn kept_backlog(n: usize) -> Work {
    use crate::common::KEPT;
    let (mut lp, (t, base)) = reader_net();
    for i in 0..n {
        let mut m = Mutation::new();
        m.set(t, &KEPT, &s(&format!("v{i}"))).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    let pks = crate::common::packages_to(&mut lp, 0, 1);
    for p in pks.iter().filter(|p| !base.contains(&p.id)) {
        lp.deliver(1, p).unwrap();
    }
    // a listener reads each woken part's keep bound in the transaction (its listing)
    lp.peers[1].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
    let (_, w) = measured_at(&mut lp, 1, |lp| {
        for p in pks.iter().filter(|p| base.contains(&p.id)) {
            lp.deliver(1, p).unwrap();
        }
    });
    let k = ak("t:kept.0");
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(s(&format!("v{}", n - 1))));
    w
}

// spec/commits.md §5 (when a body was replaced); spec/requirements.md, Scale (no operation
// O(history)): a transaction applying n and 10n commits on a dated aspect reads each replaced
// part's date inside it, and a read asks whether the transaction changed the aspect in one lookup: the
// transaction's change log is read a fixed number of times, not once per date read.
#[test]
fn a_dated_read_in_a_transaction_reads_no_change_log_spec_commits_5() {
    let (a, b) = (kept_backlog(30), kept_backlog(300));
    let (ra, rb) = (a.n("replaced reads"), b.n("replaced reads"));
    // each woken part but the live one: a live write's listing reads its state, no keep bound
    // (`listing::keep_bound`)
    assert!(ra >= 29 && rb >= 299, "a date read per commit replaced: {ra}, {rb}");
    flat("change log entries read per date read", a.n("commits log entries read") / ra, b.n("commits log entries read") / rb);
    all_linear("a kept backlog woken", &a, &b);
}

/// A text kept a day after replaced, written whole n times, one commit each (each write a reset,
/// spec/crdt.md §5.1): the work of one more whole write.
fn whole_text_writes(n: usize) -> Work {
    let mut lp = net(1, 0);
    let t = crate::common::new_thing_keeping(&mut lp, 0, &[("t:text.0", crate::common::DAY)]);
    let write = |lp: &mut LocalPeer, i: usize| {
        lp.advance(1);
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Replace(Value::Str(format!("text {i}"))) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    };
    for i in 0..n {
        write(&mut lp, i);
    }
    measured_at(&mut lp, 0, |lp| write(lp, n)).1
}

// spec/commits.md §5 (when a body was replaced); spec/requirements.md, Scale: a text written
// whole n and 10n times, a write dates again the bodies it newly replaces, not every earlier
// one (each already replaced by the write before it).
#[test]
fn a_whole_write_redates_only_what_it_replaces_spec_commits_5() {
    let (a, b) = (whole_text_writes(20), whole_text_writes(200));
    flat("bodies dated (replaced at)", a.n("replaced at"), b.n("replaced at"));
}

/// n grants on one thing to holders that are no key actor, then an open.
fn grants_and_open(n: usize) -> Work {
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
    for i in 0..n {
        let mut b = [7u8; 15];
        b[..2].copy_from_slice(&(i as u16).to_be_bytes());
        edge_write(&mut lp.peers[0].engine, t, Tid::from_bytes(b), Some(edge(Role::Read)), None);
    }
    let roster = lp.peers[0].engine.roster(&t);
    let (_, open) = measured_at(&mut lp, 0, |lp| lp.peers[0].restart(1).unwrap());
    assert_eq!(lp.peers[0].engine.roster(&t), roster);
    open
}

// spec/permissions.md §5.1; spec/requirements.md, Scale (no operation O(history)): an open holding n and 10n role commits
// on one thing gives the walk its role commits once, not one update each (each judging every
// grant for key access).
#[test]
fn open_is_linear_in_role_commits() {
    let (a, b) = (grants_and_open(20), grants_and_open(200));
    all_linear("open", &a, &b);
}

/// The path wait's work for a write acting as `r` on `x` at a node holding three layers of forged
/// edge writes on `x`, each unjudgeable (spec/commits.md §4 Unjudgeable) though its part is held
/// (it also writes its own path's end, which is judgeable): one through each of `n` fresh things
/// (`fs`) on `e`'s edge, one through `e` on each of `n` things' (`qs`), one through each of those
/// on `r`'s. The write reads `r`'s edge: `n` writes, each reading one `qs` edge, each reading `e`'s.
fn forged_layers(n: usize) -> u64 {
    use osis_engine::Ingested;
    let mut lp = net(2, 0);
    let x = crate::common::new_shared(&mut lp, 0);
    let fs: Vec<Tid> = (0..n).map(|_| new_thing(&mut lp, 0)).collect();
    let qs: Vec<Tid> = (0..n).map(|_| new_thing(&mut lp, 0)).collect();
    let (e, r) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    crate::common::sync(&mut lp, 0, 1);
    let rec = lp.peers[0].engine.get_typed(&x, &ct::CREATED).unwrap().unwrap();
    let mut lo = 1u64 << 40;
    let mut forge = |lp: &mut LocalPeer, via: Tid, to: &[Tid]| {
        lp.advance(1_000);
        lo += 1 << 20;
        let mut v = osis_base::ValueMap::from([(Value::Weak(via), edge(Role::Read).to_value())]);
        v.extend(to.iter().map(|t| (Value::Weak(*t), edge(Role::Admin).to_value())));
        let f = crate::validity::forge_by(&lp.peers[0].engine, rec.clone(), x, &ak("roles.0"), &Value::Map(v), lo, osis_commit::Kind::Role, osis_commit::Path { purge: 0, things: vec![via], direct: 0 });
        assert!(matches!(lp.peers[1].receive(&f, Vec::new()).unwrap(), Ingested::Applied(_)));
    };
    for &f in &fs {
        forge(&mut lp, f, &[e]);
    }
    forge(&mut lp, e, &qs);
    for &q in &qs {
        forge(&mut lp, q, &[r]);
    }
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(x, &crate::common::REG, &s("as r")).unwrap();
    m.act_as(r);
    lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    let (_, w) = measured_at(&mut lp, 1, |lp| crate::common::sync(lp, 0, 1));
    assert!(lp.peers[1].engine.pending().iter().any(|(_, why)| matches!(why, osis_engine::Reason::MissingChain(_))), "the write waits");
    w.n("path wait: write read")
}

// spec/commits.md §4 Unjudgeable, spec/requirements.md Scale: the path wait reads each held write
// on an edge once per part judged, however many writes' paths share that edge: linear in the
// writes held, n forged writes on each layer.
#[test]
fn the_path_wait_reads_each_write_once_spec_commits_4() {
    linear("path wait: writes read", forged_layers(3), forged_layers(30));
}

/// What holder `b` is charged for an ephemeral log on `t` (`Engine::memory_charge` of every
/// memory commit it holds) once node `x` appended `n` elements, each by a commit of its own
/// expiring a minute on, all expired and covered by `x`'s snapshot; and the bytes `b`'s state of
/// the log holds (`Fragment::approx_bytes`).
fn expired_log_charge(n: usize) -> [u64; 2] {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let mut taken = BTreeSet::new();
    // x's memory commits not handed to b before, as blobs
    let mut fresh = |lp: &mut LocalPeer| -> Vec<osis_commit::CommitBlob> {
        let e = &mut lp.peers[0].engine;
        let ids: Vec<_> = e.memory_commits().into_iter().filter(|h| h.2 && taken.insert(h.0)).map(|h| h.0).collect();
        ids.iter().filter_map(|c| e.memory_blob(c).unwrap()).collect()
    };
    let log = crate::common::LOG;
    let mut m = Mutation::new();
    m.set(t, &log, &Value::List(vec![s("start")])).unwrap();
    lp.peers[0].engine.write(m).unwrap();
    for c in 0..n {
        let mut m = Mutation::new();
        m.op(t, &log, PathOp { path: vec![], op: Op::Insert { at: c + 1, items: vec![s(&c.to_string())] } }).unwrap();
        m.expires(t, &log, osis_base::WallMs(lp.peers[0].engine.now().0 + 60_000)).unwrap();
        lp.peers[0].engine.write(m).unwrap();
    }
    for bl in fresh(&mut lp) {
        lp.peers[1].engine.ingest_memory(&bl.encode(), u64::MAX).unwrap();
    }
    lp.advance(61_000);
    lp.peers[1].tick().unwrap();
    lp.peers[0].tick().unwrap();
    assert!(!lp.peers[0].engine.compactions().unwrap().is_empty(), "x snapshots the expired log");
    for bl in fresh(&mut lp) {
        lp.peers[1].engine.ingest_memory(&bl.encode(), u64::MAX).unwrap();
    }
    let ak = Ak::new("t:log+.0").unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak).unwrap(), lp.peers[0].engine.get(&t, &ak).unwrap());
    let e = &mut lp.peers[1].engine;
    let ids: Vec<_> = e.memory_commits().into_iter().filter(|h| h.1 > 0).map(|h| h.0).collect();
    let state = e.core.states.get(&(t, ak)).cloned().flatten().map_or(0, |f| f.approx_bytes() as u64);
    [ids.iter().map(|id| e.memory_charge(id).unwrap()).sum(), state]
}

// spec/crdt.md §4.7, §5.7, spec/sync-compaction.md §2: what a holder is charged per expired
// element of an ephemeral list once a snapshot covers them (each stays a value-less record, as a
// late insert may anchor at it), from n to 10n elements: a few bytes each (the snapshot's encoded
// bytes, in each copy held), never a decoded record each; the holder's state holds as few.
#[test]
fn expired_list_elements_charge_a_few_bytes_each() {
    let (small, big) = (expired_log_charge(10), expired_log_charge(100));
    let per = [(big[0] - small[0]) / 90, big[1].saturating_sub(small[1]) / 90];
    println!("per expired element: charged {} B, state {} B ({small:?} at 10, {big:?} at 100)", per[0], per[1]);
    assert!(per[0] <= 48 && per[1] <= 16, "per expired element: charged {} B, state {} B ({small:?} at 10, {big:?} at 100)", per[0], per[1]);
}
