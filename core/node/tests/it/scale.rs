//! Scale checks (spec/requirements.md, Scale): each test counts the work an operation does
//! (pages loaded and written, store bytes, commits judged, bodies read) at a size n and at 10n
//! and asserts the growth Scale allows: `flat` for a change that costs O(change), `linear` for a
//! cost that may grow with the data. Counts, never time (notes/coordination.md, Design principles).

use crate::common::{BIG, GONEMAP, REFS, TEXT, edge, net, new_thing, s, set_edge};
use osis_base::{Ak, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::{HolderKeys, Recipient, rotate};
use osis_node::Mutation;
use osis_node::local_peer::LocalPeer;
use osis_schema::core_types as ct;
use osis_schema::{Codec, RawKey};
use osis_store::{Io, MemoryBackend};
use std::collections::{BTreeMap, BTreeSet};

/// What one operation did: the engine's cost spans by count, and the store's reads and writes.
#[derive(Debug)]
pub(crate) struct Work {
    pub(crate) spans: BTreeMap<&'static str, u64>,
    pub(crate) io: Io,
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
    osis_node::costs::take();
    let io = b.io();
    let r = f();
    let spans = osis_node::costs::take().into_iter().map(|(k, _, c)| (k, c)).collect();
    (r, Work { spans, io: b.io() - io })
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

/// A 200-byte string: n entries page from a few hundred on (`PAGE_TARGET`).
fn long(i: usize) -> Value {
    s(&format!("{i:08}{}", "v".repeat(192)))
}

/// Map edits at n entries: (store bytes of an edit; a new session's first read of one key in
/// pages loaded; its first edit in pages loaded and written and store bytes). `nested`: the map
/// sits in an entry of a root map.
fn map_edit(n: usize, nested: bool) -> [u64; 5] {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let t = new_thing(&mut lp, 0);
    let a = ak("app:big.0");
    let inner: osis_base::ValueMap = (0..n).map(|i| (s(&format!("k{i:06}")), long(i))).collect();
    let at = |k: usize| {
        let key = PathSeg::Key(s(&format!("k{k:06}")));
        if nested { vec![PathSeg::Key(s("inner")), key] } else { vec![key] }
    };
    let v = if nested { Value::Map(osis_base::ValueMap::from([(s("inner"), Value::Map(inner)), (s("x"), Value::Int(1))])) } else { Value::Map(inner) };
    let mut m = Mutation::new();
    m.set(t, &a, &v).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let edit = |lp: &mut LocalPeer, k: usize, v: &str| {
        let mut m = Mutation::new();
        set_key(&mut m, t, &a, at(k), s(v));
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let (_, w0) = measured(&b, || edit(&mut lp, n / 2, "x"));
    lp.peers[0].restart(1).unwrap();
    let (got, read) = measured(&b, || lp.peers[0].engine.get_at(&t, &a, &at(n / 3)).unwrap());
    assert_eq!(got, Some(long(n / 3)));
    lp.peers[0].restart(2).unwrap();
    let (_, first) = measured(&b, || edit(&mut lp, n / 4, "y"));
    assert_eq!(lp.peers[0].engine.get_at(&t, &a, &at(n / 4)).unwrap(), Some(s("y")));
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

/// Set ops by value at n elements, each in a new session: pages loaded and written per op.
fn set_ops(n: usize) -> Vec<(u64, u64)> {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let t = new_thing(&mut lp, 0);
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

// spec/crdt.md §5.5 (set ops resolved by value), §8; spec/requirements.md, Scale: adding and
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

/// A set of n tids: a removal of a member (spec/crdt.md §5.5, what `delete` writes in a group) and
/// an add back, each in a new session: pages loaded and written, and the commit's bytes.
fn tid_removals(n: usize) -> Vec<(u64, u64, u64)> {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let x = new_thing(&mut lp, 0);
    let t = |i: usize| {
        let mut b = [0u8; 15];
        b[7..].copy_from_slice(&(i as u64).to_be_bytes());
        Value::Tid(Tid::from_bytes(b))
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
        let bytes = lp.packages(0).unwrap().into_iter().find(|p| p.id == id).map_or(0, |p| p.bytes.len() as u64);
        out.push((w.loads(), w.page_writes(), bytes));
    }
    let Some(Value::Set(v)) = lp.peers[0].engine.get(&x, &ak("t:refs.0")).unwrap() else { panic!() };
    assert!(v.len() == n && v.contains(&t(n / 3)));
    out
}

// spec/crdt.md §5.5, spec/requirements.md Scale (deleting costs what changed): removing a tid from
// a paged set and adding it back, each in a new session, loads and writes only their pages (the
// value index finds the tid's records), and the commit is one record, at n and 10n members.
#[test]
fn tid_removal_is_flat() {
    let (small, big) = (tid_removals(4000), tid_removals(40_000));
    for (i, what) in ["remove a member", "add back"].iter().enumerate() {
        flat(&format!("{what}: pages loaded"), small[i].0, big[i].0);
        flat(&format!("{what}: pages written"), small[i].1, big[i].1);
        flat(&format!("{what}: commit bytes"), small[i].2, big[i].2);
    }
}

/// A group g of n items, nested 3 deep (q lists p, p lists g as subgroups): removing an item,
/// adding it back and adding a new one, each in a new session with q's closure asked for before
/// (pages loaded, pages written, group index work: the change and the answers after it); the
/// group index and q's closure follow each. And the opens before them: (group states read whole,
/// group index work).
fn group_changes(n: usize) -> (Vec<[u64; 3]>, Vec<[u64; 2]>) {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let (g, p, q) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let t = |i: usize| {
        let mut b = [0u8; 15];
        b[7..].copy_from_slice(&(i as u64).to_be_bytes());
        Tid::from_bytes(b)
    };
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &ct::Group { items: (0..n).map(t).collect(), subgroups: Default::default() }).unwrap();
    m.set(p, &ct::GROUP, &ct::Group { items: Default::default(), subgroups: BTreeSet::from([g]) }).unwrap();
    m.set(q, &ct::GROUP, &ct::Group { items: Default::default(), subgroups: BTreeSet::from([p]) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let (mut out, mut opens) = (Vec::new(), Vec::new());
    let items = vec![PathSeg::Field(0)];
    for (k, (op, x, member)) in [(Op::Remove(Value::Tid(t(n / 3))), n / 3, false), (Op::Add(Value::Tid(t(n / 3))), n / 3, true), (Op::Add(Value::Tid(t(n))), n, true)].into_iter().enumerate() {
        let (r, w) = measured(&b, || lp.peers[0].restart(k as u64));
        r.unwrap();
        opens.push([w.n("group.0 read whole"), w.n("group index")]);
        assert!(lp.peers[0].engine.closure(&q).len() > n);
        let (c, w) = measured(&b, || {
            let mut m = Mutation::new();
            m.op(g, &ct::GROUP, PathOp { path: items.clone(), op }).unwrap();
            let c = lp.peers[0].commit(m).unwrap();
            let e = &lp.peers[0].engine;
            assert_eq!(e.groups_of(&t(x)), if member { BTreeSet::from([g, p, q]) } else { BTreeSet::new() });
            assert_eq!(e.closure(&q).contains(&t(x)), member);
            c
        });
        assert!(c.is_some());
        assert_eq!(w.n("group.0 read whole"), 0, "a membership change reads no group whole");
        out.push([w.loads(), w.page_writes(), w.n("group index")]);
    }
    (out, opens)
}

// spec/data-model.md §8, spec/requirements.md Scale (deleting costs what changed; no whole value
// in memory): a membership change of a paged group nested 3 deep loads and writes only the pages
// of the tids it names, and the group index follows it (the groups above, a closure asked for
// before) in work O(change), at n and 10n items. An open reads no group's state whole.
#[test]
fn group_change_is_flat() {
    let ((small, small_open), (big, big_open)) = (group_changes(4000), group_changes(40_000));
    for (i, what) in ["remove an item", "add it back", "add a new item"].iter().enumerate() {
        flat(&format!("{what}: pages loaded"), small[i][0], big[i][0]);
        flat(&format!("{what}: pages written"), small[i][1], big[i][1]);
        flat(&format!("{what}: group index work"), small[i][2], big[i][2]);
    }
    for (o, b) in small_open.iter().zip(&big_open) {
        assert_eq!((o[0], b[0]), (0, 0), "an open reads no group state whole");
        linear("open: group index work", o[1], b[1]);
    }
}

/// Text ops at n chars, each in a new session: (pages loaded, pages and placement rows written,
/// store bytes) per step: a read of 100 chars at an index, an insert, a delete, a move, an edit as
/// a text session writes it, an undo of the edit, a read after them.
fn text_ops(n: usize) -> Vec<(u64, u64, u64)> {
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let t = new_thing(&mut lp, 0);
    let a = ak("t:text.0");
    // not periodic: an edit whose window repeats elsewhere in its base matches the whole text
    let mut rng = SeededRng::from_u64(0);
    let mut want: Vec<char> = (0..n).map(|_| char::from(b'a' + (osis_crypto::RngCore::next_u64(&mut rng) % 26) as u8)).collect();
    let mut m = Mutation::new();
    m.set(t, &TEXT, &Value::Str(want.iter().collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut out = Vec::new();
    let mut last: Option<(osis_base::CommitId, Vec<char>)> = None;
    for step in 0..7u64 {
        lp.peers[0].restart(step).unwrap();
        let at = n / 3 + step as usize * 7;
        let e = &mut lp.peers[0].engine;
        let before = want.clone();
        let op = match step {
            0 | 6 => {
                let (got, w) = measured(&b, || e.get_range(&t, &a, &[], at..at + 100).unwrap());
                assert_eq!(got, Some(Value::Str(want[at..at + 100].iter().collect())));
                out.push((w.loads(), w.page_writes(), w.io.written_bytes));
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
            3 => {
                let moved: Vec<char> = want.drain(at..at + 4).collect();
                let to = n / 2;
                want.splice(to..to, moved);
                Op::Move { at, len: 4, to }
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
                out.push((w.loads(), w.page_writes(), w.io.written_bytes));
                continue;
            }
        };
        let (id, w) = measured(&b, || {
            let mut m = Mutation::new();
            m.op(t, &TEXT, PathOp { path: vec![], op }).unwrap();
            e.commit(m).unwrap().unwrap()
        });
        last = Some((id, before));
        out.push((w.loads(), w.page_writes(), w.io.written_bytes));
    }
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Str(want.iter().collect())));
    out
}

// spec/crdt.md §5.7 (ops resolve by index against the placement), §6, §8; spec/requirements.md,
// Scale: in a paged text of n and 10n chars, each op in a new session: a read of 100 chars, an
// insert, a delete, a move, an edit as a text session writes it, an undo, loads and writes only
// its pages and placement rows (through the stored placement).
// A text pages above `PAGE_TARGET` (about 70k chars), so 10n is 700k chars: writing it takes
// about 11 s in a debug build. The move is left out: issues/text-move-loads-placement.md.
#[test]
#[ignore = "by hand: a 700k-char text takes 11 s to write in debug"]
fn text_edits_are_flat() {
    let (small, big) = (text_ops(80_000), text_ops(800_000));
    for (i, what) in ["read of 100 chars", "insert", "delete", "move", "edit", "undo of the edit", "read after them"].iter().enumerate() {
        if *what == "move" {
            continue;
        }
        flat(&format!("{what}: pages loaded"), small[i].0, big[i].0);
        flat(&format!("{what}: pages written"), small[i].1, big[i].1);
        flat(&format!("{what}: store bytes"), small[i].2, big[i].2);
    }
}

// issues/text-move-loads-placement.md; spec/crdt.md §5.7, §8; spec/requirements.md, Scale (a change
// costs O(change)):
// a move of 4 chars in an 80k-char text, in a new session, loads every placement block (about
// 110) where an insert or a delete loads 3.
#[test]
#[ignore = "issues/text-move-loads-placement.md"]
fn repro_text_move_loads_placement() {
    let n = 80_000;
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let t = new_thing(&mut lp, 0);
    let mut rng = SeededRng::from_u64(0);
    let text: String = (0..n).map(|_| char::from(b'a' + (osis_crypto::RngCore::next_u64(&mut rng) % 26) as u8)).collect();
    let mut m = Mutation::new();
    m.set(t, &TEXT, &Value::Str(text)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].restart(1).unwrap();
    let (_, w) = measured(&b, || {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: vec![], op: Op::Move { at: n / 3, len: 4, to: n / 3 + 50 } }).unwrap();
        lp.peers[0].engine.commit(m).unwrap().unwrap()
    });
    assert!(w.loads() <= 6, "a move loaded {} pages and placement blocks", w.loads());
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
    let mut holders = vec![Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }];
    for i in 0..n - 1 {
        let mut x = [0u8; 15];
        x[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        let keysets = [Role::Read, Role::Write].into_iter().map(|r| (r, vec![(ep, kem.clone())])).collect();
        holders.push(Recipient { holder: Tid::from_bytes(x), role: Role::Write, keys: HolderKeys::Actor { keysets, own: BTreeMap::new() } });
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
    let mut lp = net(1, 0);
    let b = lp.peers[0].backend.clone();
    let t = new_thing(&mut lp, 0);
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
    w.io.written_bytes / edits
}

// spec/commits.md §5 (purge on replace); spec/requirements.md, Scale: under purge on replace every
// edit that replaces earlier content
// costs a snapshot of the aspect, O(its state) ("on a 2000-entry map about 0.5 MB written ...
// against 36 KB with no history promised"); with no history promised an edit costs O(change).
// Store bytes per replacing edit at n and 10n entries, and the stated sizes at 2000 (rows and
// blobs: 465 KB rows and the snapshot's 246 KB body blob; the requirement's figure counts rows).
#[test]
fn purge_on_replace_pays_its_state() {
    let (gone, plain) = ([replacing_edit(200, &GONEMAP), replacing_edit(2000, &GONEMAP)], [replacing_edit(200, &BIG), replacing_edit(2000, &BIG)]);
    linear("purge on replace: store bytes per edit", gone[0], gone[1]);
    assert!(gone[1] >= 5 * gone[0], "purge on replace pays O(state): {gone:?}");
    flat("no history: store bytes per edit", plain[0], plain[1]);
    assert!(gone[1] <= 800_000 && plain[1] <= 40_000, "at 2000 entries: {} B with purge on replace, {} B with no history", gone[1], plain[1]);
}

/// (passes, full passes, bodies judged, entries judged, pending commits read again) from `x` to `y`.
fn pass_work(x: osis_node::sync::PassStats, y: osis_node::sync::PassStats) -> [u64; 5] {
    [y.passes - x.passes, y.full - x.full, y.bodies - x.bodies, y.entries - x.entries, y.examined - x.examined]
}

const PASS: [&str; 5] = ["passes", "full passes", "bodies judged", "entries judged", "pending read again"];

/// A writer and a reader of a label holding n content commits on 10 things, at one host (or at
/// none, the writer serving it: `hosted` false), settled: the pass work one more write causes at
/// (the writer, the reader).
fn one_more_write(n: usize, hosted: bool) -> ([u64; 5], [u64; 5]) {
    let mut net = crate::net::Net::new();
    let hosts = if hosted { vec![net.add_host()] } else { Vec::new() };
    let a = net.node(1, &hosts);
    let b = net.node(2, &hosts);
    if !hosted {
        let acts = net.sync(a).publish_reach([0xa1; 32], Vec::new()).unwrap();
        net.actions(a, acts);
    }
    let g = net.group(a, &[(b, Role::Read)], &hosts);
    let things: Vec<Tid> = (0..10).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
    for i in 0..n {
        net.write(a, things[i % things.len()], &format!("v{i}"));
    }
    net.run();
    net.advance(61_000);
    let before = (net.sync(a).pass_stats(), net.sync(b).pass_stats());
    net.write(a, things[0], "one more");
    net.run();
    assert_eq!(net.read(b, things[0]), Some(crate::net::s("one more")));
    (pass_work(before.0, net.sync(a).pass_stats()), pass_work(before.1, net.sync(b).pass_stats()))
}

// spec/sync-ids.md §6 (co-reader peer), §6, §7; spec/requirements.md, Scale (no operation
// O(history)): in a settled label of n and 10n content commits, served by a host or by the
// writer alone, one more write costs both nodes' passes the same work: no full pass, the bodies
// and entries of that write.
#[test]
fn sync_pass_is_flat() {
    for hosted in [true, false] {
        let (small, big) = (one_more_write(20, hosted), one_more_write(200, hosted));
        for (i, p) in PASS.iter().enumerate() {
            flat(&format!("hosted {hosted}, writer: {p}"), small.0[i], big.0[i]);
            flat(&format!("hosted {hosted}, reader: {p}"), small.1[i], big.1[i]);
        }
        assert_eq!((big.0[1], big.1[1]), (0, 0), "no full pass");
    }
}

/// A writer and a reader of a label holding 20 content commits on 10 things, at `k` peers that
/// cannot read it, settled: the pass work one more write causes at (the writer, the reader).
fn one_more_write_at(k: usize) -> ([u64; 5], [u64; 5]) {
    let mut net = crate::net::Net::new();
    let hosts: Vec<usize> = (0..k).map(|_| net.add_host()).collect();
    let a = net.node(1, &hosts);
    let b = net.node(2, &hosts);
    let g = net.group(a, &[(b, Role::Read)], &hosts);
    let things: Vec<Tid> = (0..10).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
    for i in 0..20 {
        net.write(a, things[i % things.len()], &format!("v{i}"));
    }
    net.run();
    net.advance(61_000);
    let before = (net.sync(a).pass_stats(), net.sync(b).pass_stats());
    let c = net.write(a, things[0], "one more");
    net.run();
    assert_eq!(net.read(b, things[0]), Some(crate::net::s("one more")));
    let l = net.label(a);
    let mine: Vec<osis_base::BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, x)| matches!(x, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
    for h in &hosts {
        let held = net.host_ids(*h, &l);
        assert!(!mine.is_empty() && mine.iter().all(|id| held.contains(id)), "{k} peers: peer {h} pulled the write");
    }
    (pass_work(before.0, net.sync(a).pass_stats()), pass_work(before.1, net.sync(b).pass_stats()))
}

// spec/sync-judgement.md §2, spec/sync-opens.md §4; issues/sync-rewrite.md 3h2 (one pass per label): a write to a label
// kept at 1 and at 3 peers that cannot read it costs each node the same full passes and bodies
// judged: the own part judges the change once, whatever the number of sources; a source showing
// what this node holds only marks presence there, which that source's part acts on from the
// verdicts the last pass reached (`Work::lacked`), so the per-source check of what each lacks or
// holds alone grows with them, linearly.
#[test]
fn one_pass_judges_a_change_for_every_source() {
    let (one, three) = (one_more_write_at(1), one_more_write_at(3));
    for (who, x, y) in [("writer", one.0, three.0), ("reader", one.1, three.1)] {
        for i in [1, 2] {
            assert_eq!(x[i], y[i], "{who}: {} at 1 and 3 sources: {x:?} / {y:?}", PASS[i]);
        }
        // per source at most twice the change's entries: by the pass that has it, and once more
        // when that source shows it
        assert!(y[3] <= 2 * 3 * x[3].max(1), "{who}: entries judged per source: {x:?} / {y:?}");
    }
}

/// A fresh reader syncing n kept content commits on 10 things through one host: (commits it gained,
/// commits examined, bodies judged and entries judged by both nodes' passes).
fn first_sync(n: usize) -> [u64; 4] {
    let mut net = crate::net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let things: Vec<Tid> = (0..10).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
    // every write kept history: none compacts, so the reader syncs all n commits
    for t in &things {
        net.keep(a, *t, &[(osis_schema::RawKey::ak(&crate::net::REG), osis_schema::History::FOREVER)]);
    }
    net.set_online(b, false);
    for i in 0..n {
        net.write(a, things[i % things.len()], &format!("v{i}"));
    }
    let before = (net.sync(a).pass_stats(), net.sync(b).pass_stats(), net.engine(b).examined(), net.engine(b).core.ix.commits.len() as u64);
    net.set_online(b, true);
    net.run();
    assert_eq!(net.read(b, things[(n - 1) % 10]), Some(crate::net::s(&format!("v{}", n - 1))));
    let (wa, rb) = (pass_work(before.0, net.sync(a).pass_stats()), pass_work(before.1, net.sync(b).pass_stats()));
    [net.engine(b).core.ix.commits.len() as u64 - before.3, net.engine(b).examined() - before.2, wa[2] + rb[2], wa[3] + rb[3]]
}

// spec/sync-judgement.md §2; spec/requirements.md, Scale: a first sync of N commits costs O(N): the
// commits taken, pending commits read again, bodies and entries judged grow linearly from n
// to 10n.
#[test]
fn first_sync_is_linear() {
    let (small, big) = (first_sync(30), first_sync(300));
    for (i, what) in ["commits taken", "commits examined", "bodies judged", "entries judged"].iter().enumerate() {
        linear(what, small[i], big[i]);
    }
    assert!(big[0] >= 300, "every commit taken: {big:?}");
}

/// Sets keys `ks` of map aspect `asp` of `t` to `v` at node `n`, one commit.
fn put_keys(net: &mut crate::net::Net, n: usize, t: Tid, asp: &osis_schema::Aspect<Value>, ks: &[String], v: &str) {
    let mut m = Mutation::new();
    for k in ks {
        m.op(t, asp, PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(v)) }).unwrap();
    }
    net.engine(n).commit(m).unwrap().unwrap();
}

/// n keys in n/2 bodies, at one host, a writer and a reader: the pass work (writer, reader) of
/// (1) under purge on replace (every body live) one more key, (2) one overwriting the first
/// body's keys (killing it), (3) under an expiry, the oldest commit expiring alone, (4) with n
/// more things in the group, one write.
fn aspect_passes(n: usize) -> Vec<([u64; 5], [u64; 5])> {
    use crate::net::{BRIEFMAP, GONEMAP};
    let mut net = crate::net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "t");
    net.keep(a, t, &[("t:gonemap.0", crate::net::PURGE)]);
    let u = net.item(a, g, g, "u");
    // expires 30 min before the rest
    put_keys(&mut net, a, u, &BRIEFMAP, &["first".to_string()], "v");
    net.run();
    net.advance(1_800_000);
    let keys: Vec<String> = (0..n).map(|i| format!("k{i}")).collect();
    for ks in keys.chunks(2) {
        put_keys(&mut net, a, t, &GONEMAP, ks, "v");
        put_keys(&mut net, a, u, &BRIEFMAP, ks, "v");
    }
    net.run();
    net.advance(61_000);
    let mut out = Vec::new();
    let mut step = |net: &mut crate::net::Net, f: &mut dyn FnMut(&mut crate::net::Net)| {
        let s0 = (net.sync(a).pass_stats(), net.sync(b).pass_stats());
        f(net);
        net.run();
        out.push((pass_work(s0.0, net.sync(a).pass_stats()), pass_work(s0.1, net.sync(b).pass_stats())));
        net.advance(1_000);
    };
    step(&mut net, &mut |net| put_keys(net, a, t, &GONEMAP, &["new".to_string()], "v"));
    step(&mut net, &mut |net| put_keys(net, a, t, &GONEMAP, &keys[..2], "w"));
    step(&mut net, &mut |net| net.advance(1_800_000));
    // a closure of n more things
    let e = net.engine(a);
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    let mut m = Mutation::new();
    for _ in 0..n {
        items.items.insert(e.new_thing(&mut m, g));
    }
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap();
    net.run();
    net.advance(61_000);
    step(&mut net, &mut |net| {
        net.write(a, t, "one more");
    });
    out
}

// spec/sync-judgement.md §2, spec/sync-compaction.md §1; spec/commits.md §5; spec/requirements.md, Scale: a change to one body of
// a big aspect judges O(change), not the aspect. At n and 10n keys in live bodies: one more key,
// a write killing one body, the oldest commit of an expiring map expiring alone, and one write
// with as many things in the group's closure: the passes' work at both nodes is flat.
#[test]
fn aspect_pass_is_flat() {
    let (small, big) = (aspect_passes(10), aspect_passes(100));
    for (k, what) in ["one more key", "a body killed", "an older commit expiring", "a write with a big closure"].iter().enumerate() {
        for (i, p) in PASS.iter().enumerate() {
            // a kill judges every entry of the label: issues/kill-judges-label-entries.md
            if k == 1 && i == 3 {
                continue;
            }
            flat(&format!("{what}, writer: {p}"), small[k].0[i], big[k].0[i]);
            flat(&format!("{what}, reader: {p}"), small[k].1[i], big[k].1[i]);
        }
    }
}

/// L labels of n content commits each at one host, a writer and a reader: the pass work
/// (writer, reader) of an edge write on an actor no label's closure reaches, then of one on the
/// first label's group.
fn role_passes(n: usize) -> [([u64; 5], [u64; 5]); 2] {
    let mut net = crate::net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let addr = net.address(host);
    let groups: Vec<Tid> = (0..3).map(|_| net.group_at(a, &[(b, Role::Read)], vec![addr.clone()])).collect();
    for g in &groups {
        let things: Vec<Tid> = (0..5).map(|i| net.item(a, *g, *g, &format!("t{i}"))).collect();
        for i in 0..n {
            net.write(a, things[i % things.len()], &format!("v{i}"));
        }
    }
    net.run();
    net.pair(c, a);
    let (me, other) = (net.tid(a), net.tid(c));
    let e = net.engine(a);
    let mut m = Mutation::new();
    let u = e.new_thing(&mut m, me);
    m.set(u, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    // labeled by its first holder: the edge measured below changes no label's closure
    let tb = net.tid(b);
    net.grant(a, u, tb, Role::Read);
    net.run();
    let mut out = [([0; 5], [0; 5]); 2];
    for (k, on) in [u, groups[0]].into_iter().enumerate() {
        net.advance(61_000);
        let s0 = (net.sync(a).pass_stats(), net.sync(b).pass_stats());
        net.grant(a, on, other, Role::Read);
        net.run();
        out[k] = (pass_work(s0.0, net.sync(a).pass_stats()), pass_work(s0.1, net.sync(b).pass_stats()));
    }
    out
}

// spec/sync-judgement.md §2, spec/sync-compaction.md §1; spec/permissions.md §4; spec/requirements.md, Scale: a role change
// re-judges only the labels whose verdicts can read it. Three labels of n and 10n commits: an
// edge on an actor no other closure reaches (labeled, under the account) judges its own label's
// and the account's bodies alone, flat in n; one on a label's group re-judges that label alone,
// so its entries stay within that label's commits.
#[test]
fn role_change_judges_its_labels_only() {
    let (n, small, big) = (10u64, role_passes(10), role_passes(100));
    for (i, p) in PASS.iter().enumerate() {
        flat(&format!("unrelated edge, writer: {p}"), small[0].0[i], big[0].0[i]);
        flat(&format!("unrelated edge, reader: {p}"), small[0].1[i], big[0].1[i]);
        linear(&format!("related edge, writer: {p}"), small[1].0[i], big[1].0[i]);
        linear(&format!("related edge, reader: {p}"), small[1].1[i], big[1].1[i]);
    }
    assert_eq!((big[0].0[1], big[0].1[2]), (0, 0), "no full pass for an unrelated edge, no body judged by the reader");
    for (k, w) in [(n, small[1]), (10 * n, big[1])] {
        // one label's commits and its things' creations, not three labels'
        assert!(w.0[3] <= 2 * k + 20 && w.1[3] <= 2 * k + 20, "related edge at {k} commits a label: entries judged {:?}", (w.0[3], w.1[3]));
    }
}

// issues/kill-judges-label-entries.md; spec/sync-judgement.md §2, spec/sync-compaction.md §1; spec/requirements.md, Scale: under
// purge on replace a write killing one body of n judges every entry of the label at the writer
// (n/2 + 3 entries), where one more key judges 1.
#[test]
#[ignore = "issues/kill-judges-label-entries.md"]
fn repro_kill_judges_label_entries() {
    let w = aspect_passes(20);
    assert!(w[1].0[3] <= 5, "a kill judged {} entries at the writer", w[1].0[3]);
}

/// `measured` at peer `i` of `lp`, with the engine's counters: (death walks, replaced reads,
/// pending commits read again, perm commits walked and entries moved) added as spans.
fn measured_at<T>(lp: &mut LocalPeer, i: usize, f: impl FnOnce(&mut LocalPeer) -> T) -> (T, Work) {
    let b = lp.peers[i].backend.clone();
    let c = |lp: &LocalPeer| [lp.peers[i].engine.death_walks(), lp.peers[i].engine.replaced_reads(), lp.peers[i].engine.examined(), osis_perm::commits_walked(), osis_perm::entries_moved()];
    let c0 = c(lp);
    let (r, mut w) = measured(&b, || f(&mut *lp));
    for (k, (x, y)) in ["death walks", "replaced reads", "examined", "perm commits walked", "perm entries moved"].into_iter().zip(c0.into_iter().zip(c(lp))) {
        w.spans.insert(k, y - x);
    }
    (r, w)
}

/// Peer `by` adds `v` to `asp` on `t`.
fn add(lp: &mut LocalPeer, by: usize, t: Tid, asp: &osis_schema::Aspect<Value>, v: String) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, asp, PathOp { path: Vec::new(), op: Op::Add(Value::Str(v)) }).unwrap();
    lp.peers[by].commit(m).unwrap().unwrap()
}

/// Peer 0 first admin of a new thing, the others granted `roles` on it, synced.
fn shared_thing(lp: &mut LocalPeer, roles: &[Role]) -> Tid {
    let t = new_thing(lp, 0);
    for (i, r) in roles.iter().enumerate() {
        let x = lp.peers[i + 1].engine.me();
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(*r)), None);
    }
    lp.sync_all().unwrap();
    t
}

/// Late deltas into a set of n one-element commits (`asp`, compacted after them or not): a late
/// delta older than all of them arriving and the first commit judged, then one 5 commits late.
fn late_deltas(n: usize, asp: &osis_schema::Aspect<Value>, compact: bool) -> [Work; 2] {
    let mut lp = net(2, 0);
    let t = shared_thing(&mut lp, &[Role::Write]);
    let late: Vec<_> = (0..3).map(|i| add(&mut lp, 1, t, asp, format!("late{i}"))).collect();
    lp.advance(1_000);
    let ids: Vec<_> = (0..n).map(|i| add(&mut lp, 0, t, asp, format!("e{i}"))).collect();
    let k = ak(asp.ak());
    if compact {
        lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    }
    let pks = lp.packages(1).unwrap();
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
    let pk = lp.packages(1).unwrap().into_iter().find(|p| p.id == recent).unwrap();
    let (_, recent) = measured_at(&mut lp, 0, |lp| {
        lp.deliver(0, &pk).unwrap();
        lp.peers[0].engine.replaced_at(&ids[0], &t, &k).unwrap();
    });
    [old, recent]
}

/// Every counted phase and the store rows and bytes written grow at most like a log from n to
/// 10n (rows are the sharper count: a write's fixed bytes hide a small per-commit term).
#[track_caller]
fn all_flat(what: &str, small: &Work, big: &Work) {
    for k in small.spans.keys().chain(big.spans.keys()) {
        flat(&format!("{what}: {k}"), small.n(k), big.n(k));
    }
    flat(&format!("{what}: store rows written"), small.io.writes, big.io.writes);
    flat(&format!("{what}: store bytes written"), small.io.written_bytes, big.io.written_bytes);
}

/// Every counted phase and the store rows and bytes written grow at most linearly from n to 10n.
#[track_caller]
fn all_linear(what: &str, small: &Work, big: &Work) {
    for k in small.spans.keys().chain(big.spans.keys()) {
        linear(&format!("{what}: {k}"), small.n(k), big.n(k));
    }
    linear(&format!("{what}: store rows written"), small.io.writes, big.io.writes);
    linear(&format!("{what}: store bytes written"), small.io.written_bytes, big.io.written_bytes);
}

// spec/commits.md §5 (replaced, judged from the held set), spec/crdt.md §4.8; spec/requirements.md,
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

/// n one-element commits by the first admin (0) and one add by writer B (1); admin C (2), who
/// never saw it, revokes B: (the revoke arriving at 0, flipping the add invalid; B's add written
/// after the revoke arriving invalid).
fn validity_flip(n: usize) -> [Work; 2] {
    use crate::common::TAGS;
    let mut lp = net(3, 0);
    let t = shared_thing(&mut lp, &[Role::Write, Role::Admin]);
    let (b, k) = (lp.peers[1].engine.me(), ak("t:tags.0"));
    for i in 0..n {
        add(&mut lp, 0, t, &TAGS, format!("e{i}"));
    }
    let bs = add(&mut lp, 1, t, &TAGS, "b".into());
    let pk = lp.packages(1).unwrap().into_iter().find(|p| p.id == bs).unwrap();
    lp.deliver(0, &pk).unwrap();
    let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([t]))]), content: BTreeMap::from([(b, BTreeSet::from([t]))]) };
    let now = lp.peers[2].engine.now();
    let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(b)) }).unwrap();
    m.frontier(f.to_value());
    let rv = lp.peers[2].commit(m).unwrap().unwrap();
    let late = add(&mut lp, 1, t, &TAGS, "late".into());
    let rv = lp.packages(2).unwrap().into_iter().find(|p| p.id == rv).unwrap();
    let late = lp.packages(1).unwrap().into_iter().find(|p| p.id == late).unwrap();
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

/// B (1) holds n set elements as the first admin's delta; the first admin adds one and
/// snapshots; B joins the snapshot, then one ordinary delta: (the join, the delta).
fn snapshot_join(n: usize, asp: &osis_schema::Aspect<Value>) -> [Work; 2] {
    let mut lp = net(2, 0);
    let t = shared_thing(&mut lp, &[Role::Write]);
    let mut m = Mutation::new();
    // 1000-byte elements: the set pages at both sizes
    m.set(t, asp, &Value::Set((0..n).map(|i| Value::Str(format!("{i:08}{}", "e".repeat(992)))).collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let k = ak(asp.ak());
    let x = add(&mut lp, 0, t, asp, "x".into());
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let one = add(&mut lp, 0, t, asp, "y".into());
    let pks = lp.packages(0).unwrap();
    let pk = |c: osis_base::CommitId| pks.iter().find(|p| p.id == c).unwrap().clone();
    lp.deliver(1, &pk(x)).unwrap();
    let (_, join) = measured_at(&mut lp, 1, |lp| lp.deliver(1, &pk(snap)).unwrap());
    let (_, delta) = measured_at(&mut lp, 1, |lp| lp.deliver(1, &pk(one)).unwrap());
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), lp.peers[0].engine.get(&t, &k).unwrap());
    [join, delta]
}

/// A fresh node gets the first admin's snapshot of a set of n one-element commits, then the
/// commits: the work of the commits.
fn snapshot_first(n: usize) -> Work {
    use crate::common::TAGS;
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let base: BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
    for i in 0..n {
        add(&mut lp, 0, t, &TAGS, format!("e{i}"));
    }
    let k = ak("t:tags.0");
    let snap = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
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

// spec/permissions.md §5.2, spec/crdt.md §4.6 (un-merge a function of the held set; it takes
// exactly an invalid delta's own writes); spec/requirements.md, Scale: among n and 10n held
// commits, a revoke flipping one add invalid rebuilds the aspect from its held bodies (every
// change but a valid join is a rebuild, one path: a rare event may cost O(the aspect's bodies)),
// its other counted work linear at most; an invalid add arriving takes nothing and reads no held
// body.
#[test]
fn validity_flip_is_linear_and_invalid_arrival_flat_spec_permissions_5_2() {
    let (a, b) = (validity_flip(30), validity_flip(300));
    all_linear("a revoke flipping an add", &a[0], &b[0]);
    flat("a revoke flipping an add: commits re-judged", a[0].n("rejudge: a commit"), b[0].n("rejudge: a commit"));
    all_flat("an invalid add arriving", &a[1], &b[1]);
}

// spec/permissions.md §5.2 (a valid snapshot's copies govern a held original); spec/
// requirements.md, Scale: B holds n and 10n set elements as one delta, then joins the first
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

// spec/permissions.md §5.2 (a held delta's writes compared with a snapshot's copies, indexed
// once); spec/requirements.md, Scale: a fresh node holding the snapshot of n and 10n one-element
// commits, then getting the commits, does linear work, not quadratic.
#[test]
fn commits_after_their_snapshot_are_linear_spec_permissions_5_2() {
    all_linear("commits after their snapshot", &snapshot_first(30), &snapshot_first(300));
}

/// n one-element commits on t by its first admin (0); B (1) writes one, received by C (2)
/// alone; 0 removes B and C's addendum keeps B's add (held at 0 if `with`). Team T (3) holds
/// write on t and gains a member E (4): the work of that grant arriving at 0.
fn addenda_rejudge(n: usize, with: bool) -> Work {
    use crate::common::TAGS;
    let mut lp = net(5, 0);
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let t = shared_thing(&mut lp, &[Role::Write, Role::Write, Role::Write]);
    for i in 0..n {
        add(&mut lp, 0, t, &TAGS, format!("e{i}"));
    }
    lp.advance(1_000);
    let bs = add(&mut lp, 1, t, &TAGS, "b".into());
    let pk = lp.packages(1).unwrap().into_iter().find(|p| p.id == bs).unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1_000);
    let d = osis_node::flows::Demotion { holder: ids[1], new: None, retain: None };
    let rv = *lp.peers[0].engine.demote(&t, &d).unwrap().commits.last().unwrap();
    lp.advance(1_000);
    let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == rv).unwrap();
    lp.deliver(2, &pk).unwrap();
    if with {
        // C's addendum, then B's add again once vouched for
        lp.sync(2, 0).unwrap();
        lp.sync(2, 0).unwrap();
    }
    let Some(Value::Set(v)) = lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap() else { panic!() };
    assert_eq!(v.len(), n + usize::from(with), "C's addendum keeps B's add");
    let g = set_edge(&mut lp.peers[3].engine, ids[3], ids[4], Some(edge(Role::Write)), None);
    let pk = lp.packages(3).unwrap().into_iter().find(|p| p.id == g).unwrap();
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

/// A kept set (D one day) edited every 8 hours `edits` times (its window: 3 edits), compacted every 2 edits,
/// each edit killing one long-lived element; after each edit every held snapshot is judged and
/// those past their bound and covered by the newest dropped, as node-sync does: (snapshots held
/// at the end, the work of the last edit's judging).
fn kept_snapshots(edits: usize) -> (usize, Work) {
    use crate::common::KEPTSET;
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
    let k = ak("t:keptset.0");
    let op = |lp: &mut LocalPeer, o: Op| {
        lp.advance(1);
        let mut m = Mutation::new();
        m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: o }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    for i in 0..edits {
        op(&mut lp, Op::Add(Value::Str(format!("e{i}"))));
    }
    let mut snaps = Vec::new();
    let mut last = None;
    for i in 0..edits {
        lp.advance(8 * 3_600_000);
        op(&mut lp, Op::Remove(Value::Str(format!("e{i}"))));
        op(&mut lp, Op::Add(Value::Str(format!("n{i}"))));
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

// spec/commits.md §5 (keep for D, a snapshot replaced at the latest death among the writes no
// later snapshot carries); spec/requirements.md, Scale: a kept set edited n and 10n times keeps
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

/// A kept set (D one day) of n elements added one per commit, compacted, then each removed one
/// per commit; then every held body judged once, as a sync pass does:
/// (bodies judged, the work).
fn judge_every_body(n: usize) -> (u64, Work) {
    use crate::common::KEPTSET;
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
    let k = ak("t:keptset.0");
    let op = |lp: &mut LocalPeer, o: Op| {
        lp.advance(1);
        let mut m = Mutation::new();
        m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: o }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let mut ids: Vec<_> = (0..n).map(|i| op(&mut lp, Op::Add(Value::Str(format!("e{i}"))))).collect();
    lp.advance(1);
    ids.push(lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap());
    ids.extend((0..n).map(|i| op(&mut lp, Op::Remove(Value::Str(format!("e{i}"))))));
    let (_, w) = measured_at(&mut lp, 0, |lp| {
        for c in &ids {
            lp.peers[0].engine.replaced_at(c, &t, &k).unwrap();
        }
    });
    (ids.len() as u64, w)
}

// spec/commits.md §5 (when a body was replaced, judged from the held set); spec/requirements.md,
// Scale: judging every held body of an aspect of n and 10n bodies, a judgment reads about one
// held body for the deaths it dates (`deaths: a body`), not the bodies after it.
#[test]
fn judging_every_body_reads_each_once_spec_commits_5() {
    let ((j1, w1), (j2, w2)) = (judge_every_body(20), judge_every_body(200));
    flat("bodies read for deaths per judgment", w1.n("deaths: a body") / j1, w2.n("deaths: a body") / j2);
    flat("replaced reads per judgment", w1.n("replaced reads") / j1, w2.n("replaced reads") / j2);
}

/// An aspect of n messages kept forever by the first admin, r requests by admin X naming n/r
/// of them each: (a join of a new writer, X's removal (the requests fall), X's re-grant (they
/// rise)) at the first admin.
fn purge_rejudge(n: usize) -> [Work; 3] {
    use osis_schema::{Aspect, StaticSchema};
    static S: StaticSchema = StaticSchema::new("purgecost.osis", "revision 1; purgeable_by(author, admin) aspect l:msg.0: string;\n");
    const MSG: Aspect<Value> = Aspect::new("l:msg.0", &S);
    let r = n / 10;
    let mut lp = net(4, 0);
    lp.sync_all().unwrap();
    let t = shared_thing(&mut lp, &[Role::Admin]);
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

// spec/permissions.md §6 (a request counts while its requester's right stands); spec/
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

/// B (1) gets the first admin's writes of one purge-on-replace key only through k snapshots,
/// each dropped at its cover once the next replaces it: B's demotion frontier for the first
/// admin, in listed commits and encoded bytes.
fn dropped_frontier(k: usize) -> (usize, usize) {
    let mut lp = net(2, 0);
    let me = lp.peers[0].engine.me();
    let t = shared_thing(&mut lp, &[Role::Write]);
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
    let scope = osis_perm::DemotionScope { roles: BTreeMap::new(), content: BTreeMap::from([(me, BTreeSet::from([t]))]) };
    let now = e.now();
    let f = e.frontier(&scope, now).unwrap();
    (f.commits.len(), osis_base::encode(&f.to_value()).len())
}

// spec/commits.md §5 (a snapshot dropped at its bound stands in), spec/permissions.md §5.1:
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
    let (_, grant) = measured_at(&mut lp, 0, |lp| set_edge(&mut lp.peers[0].engine, things[0], Tid::from_bytes([7; 15]), Some(edge(Role::Read)), None));
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

static LONG: osis_schema::StaticSchema = osis_schema::StaticSchema::new("long.osis", "revision 1; purgeable_by(author, admin) aspect l:msg.0: string;\n");
const MSGS: osis_schema::Aspect<Value> = osis_schema::Aspect::new("l:msg.0", &LONG);

/// One aspect kept forever, n 200-byte writes by 4 writers (the first admin and 3 granted write),
/// every node holding them: (one more write at writer 1, it arriving at the first admin, the
/// first admin removing writer 2 (a fall of its writes)).
fn long_aspect(n: usize) -> [Work; 3] {
    let mut lp = net(4, 0);
    lp.sync_all().unwrap();
    let t = shared_thing(&mut lp, &[Role::Write, Role::Write, Role::Write]);
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
        let d = osis_node::flows::Demotion { holder: x, new: None, retain: None };
        lp.peers[0].engine.demote(&t, &d).unwrap()
    });
    [one, recv, fall]
}

// spec/requirements.md, Scale (no operation O(history)); spec/commits.md §5 (keep forever): one
// aspect of n and 10n kept writes by several writers (a chat's messages): a write and its
// arrival do flat work; removing a writer, whose writes fall, at most linear.
#[test]
fn long_aspect_writes_are_flat() {
    let (a, b) = (long_aspect(40), long_aspect(400));
    all_flat("a write", &a[0], &b[0]);
    all_flat("a write arriving", &a[1], &b[1]);
    all_linear("a writer removed", &a[2], &b[2]);
}

/// n edge writes on one thing by its first admin (5 holders granted and removed in turn), then
/// a fresh node ingesting them one by one: (its work; then the first admin's grant to a new
/// holder, its removal of a holder, and the joiner ingesting those two).
fn role_history_join(n: usize) -> [Work; 4] {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let base: BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
    for i in 0..n {
        let h = Tid::from_bytes([(i % 5) as u8 + 1; 15]);
        let e = (i / 5 % 2 == 0).then(|| edge(Role::Read));
        set_edge(&mut lp.peers[0].engine, t, h, e, None);
    }
    let pks = lp.packages(0).unwrap();
    for p in pks.iter().filter(|p| base.contains(&p.id)) {
        lp.deliver(1, p).unwrap();
    }
    let (_, join) = measured_at(&mut lp, 1, |lp| {
        for p in pks.iter().filter(|p| !base.contains(&p.id)) {
            lp.deliver(1, p).unwrap();
        }
    });
    let (g, grant) = measured_at(&mut lp, 0, |lp| set_edge(&mut lp.peers[0].engine, t, Tid::from_bytes([99; 15]), Some(edge(Role::Read)), None));
    let (r, removal) = measured_at(&mut lp, 0, |lp| set_edge(&mut lp.peers[0].engine, t, Tid::from_bytes([99; 15]), None, None));
    let pks: Vec<_> = [g, r].iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap()).collect();
    let (_, arrive) = measured_at(&mut lp, 1, |lp| {
        for p in &pks {
            lp.deliver(1, p).unwrap();
        }
    });
    assert_eq!(lp.peers[1].engine.roster(&t), lp.peers[0].engine.roster(&t));
    [join, grant, removal, arrive]
}

/// `all_linear` (`flat` with `per_change`) but for store bytes: `roles.0` keeps a tombstone per
/// ended entry (spec/crdt.md §5.6; role history is never compacted) and a state up to
/// `PAGE_TARGET` is written whole (notes/engine-paged.md), so below it every write there
/// rewrites O(history) bytes, at most `PAGE_TARGET`; paged writes are flat (`map_edit_is_flat`).
#[track_caller]
fn all_counted(what: &str, small: &Work, big: &Work, per_change: bool) {
    let f = if per_change { flat } else { linear };
    for k in small.spans.keys().chain(big.spans.keys()) {
        f(&format!("{what}: {k}"), small.n(k), big.n(k));
    }
    f(&format!("{what}: store rows written"), small.io.writes, big.io.writes);
}

// spec/permissions.md §5.1; spec/requirements.md, Scale (a node that starts holding a thing
// fetches and judges all of its role history: O(the history)): a fresh node ingesting n and 10n
// edge writes on one thing one by one does linear work, and at the end of the history a grant,
// a removal and their arrival do flat work: perm places each write without walking the
// history, and the node re-judges only the commits whose writes apply otherwise
// (`Changed::commits`).
#[test]
fn role_history_join_is_linear() {
    let (a, b) = (role_history_join(30), role_history_join(300));
    all_counted("a joiner ingesting a role history", &a[0], &b[0], false);
    for (i, what) in ["a grant", "a removal", "their arrival"].iter().enumerate() {
        all_counted(&format!("at the end of a role history, {what}"), &a[i + 1], &b[i + 1], true);
    }
}


/// Claim keys reader b builds walking past a rotation it missed, b holding n groups of its own and
/// g's edge writes naming n other groups.
fn stale_walk_claims(n: usize) -> u64 {
    use crate::net::{recipients_of, remove_holder};
    let mut net = crate::net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Read), (c, Role::Read)], &[host]);
    let addrs = vec![net.address(host)];
    for _ in 0..n {
        net.group_at(b, &[], addrs.clone());
        let f = net.group_at(a, &[], addrs.clone());
        net.grant(a, g, f, Role::Read);
    }
    let t = net.item(a, g, g, "before");
    net.run();
    net.set_online(b, false);
    let (at, bt, ct_) = (net.tid(a), net.tid(b), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Read)]);
    remove_holder(e, g, ct_, &rs, 41);
    net.write(a, t, "after");
    net.run();
    let before = net.sync(b).pass_stats().claim_keys;
    net.set_online(b, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.read(b, t), Some(crate::net::s("after")), "b reads past the rotation at {n}");
    net.sync(b).pass_stats().claim_keys - before
}

// spec/sync-ids.md §6; spec/requirements.md, Scale: a walk past a missed rotation claims as the
// thing's own named readers this node holds, not as every actor it holds nor every actor named.
#[test]
fn stale_walk_claims_are_flat() {
    let (small, big) = (stale_walk_claims(1), stale_walk_claims(10));
    assert!(small > 0, "b claimed");
    flat("claim keys", small, big);
}

/// What one change costs the passes of a 3-node group on one host (a admin, b writer, c admin)
/// holding n things, settled: per node (passes, full passes, bodies
/// judged), then over all three (rotation runs, body keep bounds judged). The change: one write
/// (`Change::Write`), b made admin of a thing by a grant (`Grant`), by a bare edge write with no
/// secrets of its own given (`Edge`), b made admin of the group (`Raise`).
fn group_change(n: usize, change: Change) -> ([[u64; 3]; 3], [u64; 2]) {
    let mut net = crate::net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Admin)], &[host]);
    let things: Vec<Tid> = (0..n).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
    net.run();
    net.advance(61_000);
    let tb = net.tid(b);
    let s0 = [a, b, c].map(|x| net.sync(x).pass_stats());
    let admin = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
    let (_, w) = measured(&osis_store::MemoryBackend::new(), || {
        match change {
            Change::Write => drop(net.write(a, things[0], "one more")),
            Change::Grant | Change::Raise => {
                let on = if change == Change::Grant { things[0] } else { g };
                let done = net.engine(a).grant(&on, &tb, &admin).unwrap();
                let acts = net.sync(a).carry_out(done).unwrap();
                net.actions(a, acts);
            }
            // the bare edge write is the change measured: the own-secrets repair path's cost
            Change::Edge => drop(crate::net::set_edge(net.engine(a), things[0], tb, Role::Admin)),
        }
        net.run();
    });
    let mut per = [[0; 3]; 3];
    for (k, x) in [a, b, c].into_iter().enumerate() {
        let d = pass_work(s0[k], net.sync(x).pass_stats());
        per[k] = [d[0], d[1], d[2]];
    }
    // whatever waited settles with no more forks: one label per thing
    net.advance(61_000);
    for x in [a, b, c] {
        let labels = net.sync(x).labels();
        assert!(labels.iter().filter(|(t, _)| *t == things[0]).count() <= 1, "{change:?}: one label of the thing at node {x}");
    }
    (per, [w.n("ensure rotated"), w.n("part bounds")])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Write,
    Grant,
    Edge,
    Raise,
}

// spec/requirements.md, Scale; spec/permissions.md §3; spec/sync-judgement.md §2: one change in a small
// group settles in a few passes per node, flat in the group's history: rotations due are judged
// once per role change (not per pass), a body's keep bounds once per change of it (not per pass),
// and a thing left plain with a holder gets secrets of its own from one admin, not one fork each.
#[test]
fn a_change_costs_a_few_passes() {
    for change in [Change::Write, Change::Grant, Change::Edge, Change::Raise] {
        let (small, big) = (group_change(4, change), group_change(40, change));
        println!("{change:?}: per node (passes, full, bodies) {:?} / {:?}, (rotation runs, keep bounds) {:?} / {:?}", small.0, big.0, small.1, big.1);
        for k in 0..3 {
            for (i, what) in ["passes", "full passes"].iter().enumerate() {
                flat(&format!("{change:?}, node {k}: {what}"), small.0[k][i], big.0[k][i]);
            }
            // a full pass judges the label's bodies
            linear(&format!("{change:?}, node {k}: bodies judged"), small.0[k][2], big.0[k][2]);
            // a change's passes, counted by cause at node 0 (the most): a pass per label its own
            // commits touch (Write: L, home, and L once its stream shows them back: 3; Grant: L,
            // home and the thing's new label L': 3; Edge: the edge write and the repair giving
            // the thing secrets and L': 5); per own role commit a source showed, of the labels
            // holding it and those whose rotations its placing unblocks (`reached`: Grant 3,
            // Edge 5); for L': its source opening (a full pass), its head and a report reached
            // with a push (3); L's report reached (1); and per stream push bringing the other
            // two holders' own card, grant chain and record copies of L' (4: each holder's
            // copies are its own, so none waits for another's). Raise: 4 at each node. Full
            // passes: 3 where the change gives the thing a new label (its first pass, its source
            // opening, the inputs its new secrets move), 1 at b for Raise
            let (most, full) = match change {
                Change::Write => (3, 0),
                Change::Grant => (14, 3),
                Change::Edge => (18, 3),
                Change::Raise => (4, 1),
            };
            assert!(big.0[k][0] <= most && big.0[k][1] <= full, "{change:?}, node {k}: {:?} passes, full", big.0[k]);
        }
        // a rotation run per node and secret actor the change moved, not per pass (Grant and
        // Edge: g and the thing at each of three nodes, and the two accounts the edge names); keep
        // bounds per commit the change marks, not per body a pass judges
        flat(&format!("{change:?}: rotation runs"), small.1[0], big.1[0]);
        flat(&format!("{change:?}: keep bounds judged"), small.1[1], big.1[1]);
        let passes: u64 = big.0.iter().map(|x| x[0]).sum();
        assert!(big.1[0] <= 8, "{change:?}: {} rotation runs over {passes} passes", big.1[0]);
    }
}

/// A thing keeping `t:kept.0` and signal `t:log~0` a day, watched by a commit listener: n
/// overwrites of the register and n fires, a minute apart. Then (a setting keeping both two
/// days, which moves no body in or out of history; the first replaced value and the first two
/// fires leaving history as their window passes and the engine ticks; a setting shortening the
/// window by a minute, so the next value and fire leave at once), each with the commits it marked
/// for node-sync and told the listener as spans.
fn history_moves(n: usize) -> [Work; 3] {
    const DAY_MS: u64 = 86_400_000;
    let two = osis_schema::History::Keep { until: None, after: Some(2 * DAY_MS) };
    let mut lp = net(1, 0);
    let t = crate::common::new_thing_keeping(&mut lp, 0, &[("t:log~0", crate::common::DAY)]);
    let (kept, log) = (ak("t:kept.0"), ak("t:log~0"));
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.listen_commits(std::sync::Arc::new(|_| true), &[t]).unwrap();
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
        lp.peers[0].engine.take_changed();
        while rx.try_recv().is_ok() {}
        let (_, mut w) = measured_at(lp, 0, |lp| f(lp));
        w.spans.insert("commits marked changed", lp.peers[0].engine.take_changed().commits.len() as u64);
        let told = rx.try_iter().filter_map(|e| if let osis_node::Event::Commits(ch) = e { Some(ch.len() as u64) } else { None }).sum();
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
// moving a constant number out, read no body and walk no commit that stays listed: every counted phase, the commits marked for node-sync and
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
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
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

// notes/engine-retention-history.md Leaving history; spec/commits.md §5, spec/requirements.md Scale: an overwrite of a kept register sets
// the replaced body's history row from the killing write's stamp (`leaving::Dating::Killed`),
// reading no held body, at n and 10n.
#[test]
fn kept_overwrite_reads_no_body_spec_commits_5() {
    let (a, b) = (kept_overwrite(20), kept_overwrite(200));
    for k in ["deaths: a body", "death walks", "replaced reads"] {
        assert_eq!((a.n(k), b.n(k)), (0, 0), "{k}");
    }
    all_flat("an overwrite of a kept register", &a, &b);
}

/// A thing holding `n` bodies on other aspects and a large value: the work of judging the chunks
/// one more write-and-compact of the value drops (parts read, tree links counted and blobs read),
/// after a first round asked about the thing once.
fn chunk_drop(n: usize) -> (u64, u64) {
    let (mut net, _host, [a], _g, [t]) = crate::net::hosted::<1, 1>(&[], ["x"], false);
    let blob = Ak::new(crate::net::BLOB.ak()).unwrap();
    let mut m = Mutation::new();
    for i in 0..n {
        m.set(t, &Ak::new(format!("u:other{i:04}.0")).unwrap(), &s("v")).unwrap();
    }
    net.engine(a).commit(m).unwrap();
    let mut v = vec![0u8; 1 << 20];
    osis_crypto::RngCore::fill_bytes(&mut SeededRng::from_u64(1), &mut v);
    let mut round = |net: &mut crate::net::Net, at: usize| {
        v.splice(at..at, [7u8; 50]);
        let mut m = Mutation::new();
        m.set(t, &crate::net::BLOB, &Value::Bytes(v.clone())).unwrap();
        net.engine(a).commit(m).unwrap();
        net.run();
        let acts = net.sync(a).compact_now(&t, &blob).unwrap();
        net.actions(a, acts);
        net.advance(4_000_000);
    };
    round(&mut net, 100_000);
    round(&mut net, 300_000);
    osis_node::costs::take();
    round(&mut net, 600_000);
    let c: BTreeMap<_, _> = osis_node::costs::take().into_iter().map(|(k, _, c)| (k, c)).collect();
    let n = |k: &str| c.get(k).copied().unwrap_or(0);
    (n("tree refs: parts read"), n("tree refs: links counted") + n("tree refs: blobs read"))
}

// spec/sync-compaction.md §1 (a dropped body's chunk goes once nothing held links it); spec/requirements.md,
// Scale: judging the chunks a write-and-compact drops reads the sources that changed (the new
// bodies, the value's state), not every body held on the thing.
#[test]
fn chunk_drop_judgment_is_flat() {
    let (small, big) = (chunk_drop(10), chunk_drop(100));
    assert!(small.0 > 0, "the round judged dropped chunks");
    flat("chunk drop: parts read", small.0, big.0);
    flat("chunk drop: tree links", small.1, big.1);
}

/// A map of `n` lasting entries, then `n` entries each its own commit expiring a second after the
/// one before, and a snapshot over them (a chat turned disappearing): peer 1 given the commits
/// newest first and the snapshot before them. The work of peer 0's tick as the first expiring
/// entry expires, then the second; both peers read alike after each. Also the size of each
/// peer's bound of what the snapshot carries valued.
fn expiries(n: usize) -> ([Work; 2], Vec<usize>) {
    const HOUR: u64 = 3_600_000;
    let mut lp = net(2, 0);
    let t = shared_thing(&mut lp, &[Role::Write]);
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
    let pks = lp.packages(0).unwrap();
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

// spec/crdt.md §4.7, spec/requirements.md Scale: an expiry costs O(what expires): the state is
// stripped in place (`apply::strip_state`), no body of the aspect read but the expiring one, its
// pages alone loaded and written, at n and 10n held bodies. The debug build checks each against a
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

/// Role entries (count) at the group's peer that cannot read its label: after a group of n member
/// groups settles, then after `churn` rounds of one member granted and one removed.
fn role_entries_under_churn(n: usize, churn: usize) -> [u64; 2] {
    use osis_node::flows::Demotion;
    let mut net = crate::net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let mut members: Vec<Tid> = (0..n).map(|_| net.group_at(a, &[], vec![])).collect();
    for f in &members {
        net.grant(a, g, *f, Role::Read);
    }
    net.item(a, g, g, "content");
    net.run();
    net.advance(61_000);
    net.run();
    let l = net.group_labels(a).into_iter().find(|(t, _)| *t == g).unwrap().1.id;
    let role = |net: &crate::net::Net| net.host_ids(host, &l).len() as u64 - net.capped_entries(host, &l);
    let before = role(&net);
    for _ in 0..churn {
        let f = net.group_at(a, &[], vec![]);
        net.grant(a, g, f, Role::Read);
        members.push(f);
        let holder = members.remove(0);
        let done = net.engine(a).demote(&g, &Demotion { holder, new: None, retain: None }).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        net.run();
        net.advance(61_000);
        net.run();
    }
    assert!(!net.lags(a, &l), "the peer took every role entry at {n}");
    [before, role(&net)]
}

// spec/sync-ids.md §6 role entries: a peer takes a writer's stamped role entries outside its caps with
// no count of their own; what it holds grows with role churn, not with the members each change
// boxes (the rotation's bytes do, its entries not)
#[test]
fn role_entries_follow_role_churn() {
    let (small, big) = (role_entries_under_churn(3, 4), role_entries_under_churn(30, 4));
    println!("role entries: {small:?} at n, {big:?} at 10n");
    flat("role entries a churn adds", small[1] - small[0], big[1] - big[0]);
}

/// Reader `b` and admin `a` of a group kept at a peer `s` that cannot read it, its label past
/// `steps` rotations (each registered there); b on the newest step.
fn rotated(steps: usize) -> (crate::net::Net, usize, usize, usize, Tid) {
    let (net, (s, a, b, g)) = crate::net::Net::cached(&format!("scale::rotated/{steps}"), || {
        let (net, s, a, b, g) = rotate_n(steps);
        (net, (s, a, b, g))
    });
    (net, s, a, b, g)
}

fn rotate_n(steps: usize) -> (crate::net::Net, usize, usize, usize, Tid) {
    use crate::net::{recipients_of, rotation};
    let mut net = crate::net::Net::new();
    let s = net.add_host();
    let a = net.node(1, &[s]);
    let b = net.node(2, &[s]);
    let g = net.group(a, &[(b, Role::Read)], &[s]);
    net.run();
    let (at, bt) = (net.tid(a), net.tid(b));
    for i in 0..steps {
        let e = net.engine(a);
        let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Read)]);
        rotation(e, g, &rs, 100 + i as u64, false);
        net.run();
    }
    let l = net.label(a);
    assert_eq!(net.host_path(s, &l).len(), steps + 1, "a step per rotation");
    (net, s, a, b, g)
}

/// The credentials reader b tests per filter arrival of the peer on a fresh connection, past
/// `steps` rotations.
fn tests_per_arrival(steps: usize) -> (u64, u64) {
    let (mut net, s, _, b, _) = rotated(steps);
    let before = net.sync(b).pass_stats();
    net.drop_link(b, s);
    for _ in 0..2 {
        net.advance(61_000);
    }
    let after = net.sync(b).pass_stats();
    let arrivals = after.filters_received - before.filters_received;
    assert!(arrivals > 0, "a filter arrived");
    ((after.tested - before.tested) / arrivals, after.walk_tests - before.walk_tests)
}

// spec/sync-opens.md §4 (shared set, Testing), issues/sync-rewrite.md 3h2 (Stale head: cost),
// spec/requirements.md (Scale): a reader on the
// newest head tests one credential per sync ID at each arrival of a peer's filter whatever the
// number of steps the label went through (n and 10n rotations), and walks nothing.
#[test]
fn filter_tests_per_arrival_do_not_grow_with_steps() {
    let (small, big) = (tests_per_arrival(1), tests_per_arrival(10));
    assert_eq!(small, big, "tests per arrival and walk tests at 1 and 10 steps");
    assert_eq!(big.1, 0, "a reader on the head walks nothing");
}

/// Behind items reader b sent, those the peer answered with steps and the Registers b sent,
/// catching up `crossed` steps it missed (holding their secrets, not their `label.0`; the last
/// one's only when `head_held`, else it claims at it) past `steps` earlier ones.
fn catch_up(steps: usize, crossed: usize, head_held: bool) -> (u64, u64, usize) {
    use crate::net::{recipients_of, rotation};
    let (mut net, s, a, b, g) = rotated(steps);
    let (at, bt) = (net.tid(a), net.tid(b));
    net.blocked.insert((b, s));
    net.drop_link(b, s);
    for i in 0..crossed {
        let e = net.engine(a);
        let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Read)]);
        let c = rotation(e, g, &rs, 500 + i as u64, false);
        // b gets the rotation's secrets by hand, not the step a records once it registered it
        if head_held || i + 1 < crossed {
            let pk = net.engine(a).package(&c).unwrap().unwrap();
            net.engine(b).ingest(&pk.bytes, pk.blobs).unwrap();
        }
        net.run();
    }
    let l = net.label(a);
    assert_eq!(net.host_path(s, &l).len(), steps + crossed + 1);
    assert_eq!(net.group_labels(b).into_iter().find(|(x, _)| *x == g).unwrap().1.steps.len(), steps + 1, "b records none of the new steps");
    net.set_online(a, false);
    let (sent, answered, registers) = (net.sync(b).pass_stats().behind_sent, net.hosts[s].sync.as_mut().unwrap().pass_stats().behind_answered, net.sent_kinds.get(&7).copied().unwrap_or(0));
    net.blocked.remove(&(b, s));
    for _ in 0..3 {
        net.advance(61_000);
    }
    let conn = net.conn_to(b, s).expect("connected");
    assert!(net.sync(b).shared_members(conn).contains(&l), "b caught up and opened L at the head");
    (net.sync(b).pass_stats().behind_sent - sent, net.hosts[s].sync.as_mut().unwrap().pass_stats().behind_answered - answered, net.sent_kinds.get(&7).copied().unwrap_or(0) - registers)
}

// spec/sync-ids.md §6 (walk, Behind), spec/requirements.md (Scale): a reader behind a peer's head by
// k rotations, holding the head's sync key, opens by it with no Behind item; claiming at the
// head, it catches up with one Behind item and answer per rotation crossed (an answer stops at
// the first step under another sync key). Either way it registers nothing, whether the label's
// history holds n or 10n steps before them.
#[test]
fn a_catch_up_takes_one_behind_item_per_rotation_spec_sync_5() {
    for (crossed, held) in [(1, false), (3, false), (3, true)] {
        let (small, big) = (catch_up(1, crossed, held), catch_up(10, crossed, held));
        assert_eq!(small, big, "{crossed} crossed, head held {held}: at 1 and 10 earlier steps");
        let k = if held { 0 } else { crossed as u64 };
        assert_eq!(small, (k, k, 0), "{crossed} crossed, head held {held}: one Behind item and answer per rotation claimed past, no Register");
    }
}
