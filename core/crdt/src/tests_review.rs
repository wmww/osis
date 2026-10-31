//! Regressions from the crdt-core review (spec/crdt.md §4.6, §5.6, §7, §8, §9).

use crate::codec::{decode_snapshot, encode_snapshot};
use crate::fragment::{Bag, BagKind, Elem, Encoding, Fragment, Meta, RegWrite, Register, Slots};
use crate::ops::{Writer, create, diff};
use crate::page::{MemoryPages, PageParams, PageSink};
use crate::stamp::{CounterRange, Dot, Interner, Source, Stamp};
use crate::testutil::{TyView, ts};
use crate::undo::{Undone, undo};
use crate::view::{AnyView, View};
use crate::wire::{DeltaCtx, DeltaKind, Frontiers, Snapshot};
use crdt_model::ops::Ty;
use osis_base::{ChunkParams, Link, Tid, Value};
use std::borrow::Cow;
use std::collections::BTreeMap;

fn st(t: u64, n: u8, c: u64) -> Stamp {
    Stamp { ts: ts(t << 16), dot: Dot::new(Source::node(Tid::from_bytes([n; 15])), c) }
}
fn reg(s: Stamp, v: i64) -> Register {
    Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(Value::Int(v)) }) }
}

/// §7: a `Slots` that arrives without the register's embedding (a snapshot) is embedded on join,
/// whatever the receiver held.
#[test]
fn unembedded_slots_are_embedded_spec_7() {
    let c = st(20, 2, 1);
    let counter = Fragment::Bag(Bag {
        kind: BagKind::Counter,
        meta: Meta::default(),
        elems: BTreeMap::from([(c.dot.clone(), Elem { reset: None, frag: Some(Box::new(Fragment::Register(reg(c.clone(), 3)))) })]),
    });
    let snap = Fragment::Slots(Slots { reg: Some(reg(st(10, 1, 1), 5)), members: BTreeMap::from([(Encoding::Counter, counter)]) });
    let mut x = Fragment::default();
    x.join(snap.clone());
    let mut y = Fragment::Register(reg(st(5, 3, 1), 1));
    y.join(snap);
    assert_eq!(x.read(), Some(Value::Int(8)));
    assert_eq!(x, y);
}

/// A writer's view of `map<struct{1}, int>`: keys project by dropping fields other than 1.
#[derive(Clone, Copy)]
struct OldKeys(u8);
impl View for OldKeys {
    fn encoding(&self) -> Option<Encoding> {
        Some(if self.0 == 0 { Encoding::Map } else { Encoding::Register })
    }
    fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
        match (self.0, v) {
            (1, Value::Map(m)) => Some(Cow::Owned(Value::Map(m.iter().filter(|(k, _)| **k == Value::Int(1)).map(|(k, v)| (k.clone(), v.clone())).collect()))),
            _ => Some(Cow::Borrowed(v)),
        }
    }
    fn field(&self, _: u64) -> Option<Self> {
        None
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, _: u64) -> Option<Self> {
        None
    }
    fn element(&self) -> Option<Self> {
        Some(OldKeys(2))
    }
    fn key(&self) -> Option<Self> {
        Some(OldKeys(1))
    }
}

/// §5.6, §9: a diff through a view that projects keys writes the stored (immutable) key, into
/// every stored key the view merges.
#[test]
fn map_diff_keeps_stored_keys_spec_5_6() {
    let key = |b: i64| Value::Map([(Value::Int(1), Value::Int(1)), (Value::Int(2), Value::Int(b))].into_iter().collect());
    let short = Value::Map([(Value::Int(1), Value::Int(1))].into_iter().collect());
    let node = Source::node(Tid::from_bytes([1; 15]));
    let mut w = Writer::new(ts(1 << 16), node.clone(), 1);
    let base = Value::Map([(key(2), Value::Int(0)), (key(3), Value::Int(0))].into_iter().collect());
    let mut s = create(&mut w, &AnyView, &base).unwrap();
    let mut w2 = Writer::new(ts(2 << 16), node, 10);
    let d = diff(&mut w2, Some(&s), &OldKeys(0), &Value::Map([(short, Value::Int(7))].into_iter().collect())).unwrap().unwrap();
    let Fragment::Map(m) = &d else { panic!("map") };
    let keys: Vec<Option<Value>> = m.entries.keys().map(|id| id.key().cloned()).collect();
    assert_eq!(keys, vec![Some(key(2)), Some(key(3))]);
    s.join(d);
    assert_eq!(s.read(), Some(Value::Map([(key(2), Value::Int(7)), (key(3), Value::Int(7))].into_iter().collect())));
}

/// §4.6: redo (undo of an undo) of a counter contribution re-adds it.
#[test]
fn bag_redo_spec_4_6() {
    let view = TyView(Ty::Counter);
    let node = Source::node(Tid::from_bytes([1; 15]));
    let mut w = Writer::new(ts(10 << 16), node.clone(), 1);
    let s0 = create(&mut w, &view, &Value::Int(5)).unwrap();
    let mut wu = Writer::new(ts(20 << 16), node.clone(), 2);
    let u1 = undo(&mut wu, &Undone { delta: &s0, source: &node, range: CounterRange { lo: 1, hi: 2 }, restored: &|_| false }, &s0, &Fragment::default(), &view).unwrap().unwrap();
    let mut s1 = s0.clone();
    s1.join(u1.clone());
    assert_eq!(s1.read(), None, "absent before (§4.6)");
    let mut wr = Writer::new(ts(30 << 16), node.clone(), 3);
    let redo = undo(&mut wr, &Undone { delta: &u1, source: &node, range: wu.range(), restored: &|_| false }, &s1, &s0, &view).unwrap().unwrap();
    let mut s2 = s1.clone();
    s2.join(redo);
    assert_eq!(s2.read(), Some(Value::Int(5)));
}

// ---- page expansion and paging shape (§8, spec/wire.md §6)

const SMALL: PageParams = PageParams { target: 2000, cut: ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };

fn scx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 40), own: Source::node(Tid::from_bytes([250; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// A snapshot whose root set's element array is `elems`: hand-built bytes.
fn snapshot_with(elems: Value) -> Vec<u8> {
    let l = Value::List;
    osis_base::encode(&l(vec![Value::Bytes(vec![0; 16]), l(vec![]), l(vec![]), l(vec![Value::Int(6), l(vec![]), l(vec![]), elems]), l(vec![]), l(vec![])]))
}

fn rejects(bytes: &[u8], pages: &mut MemoryPages, why: &str) {
    let e = decode_snapshot(bytes, &scx(), &mut Interner::new(), Some(pages)).unwrap_err();
    assert!(e.to_string().contains(why), "{e}");
}

/// A bare set element record of the snapshotter's own source.
fn element(i: i64) -> Value {
    Value::List(vec![Value::Int(i), Value::List(vec![]), Value::List(vec![])])
}

#[test]
fn paging_rejections_spec_8() {
    let mut pages = MemoryPages::with_params(SMALL);
    let page = pages.put(&osis_base::encode(&Value::List(vec![element(1)]))).unwrap();
    // a paged array below the threshold
    rejects(&snapshot_with(Value::List(vec![Value::Link(page)])), &mut pages, "not canonical");
    // links mixed with elements
    rejects(&snapshot_with(Value::List(vec![Value::Link(page), element(2)])), &mut pages, "mixed");
    // one page linked twice
    rejects(&snapshot_with(Value::List(vec![Value::Link(page), Value::Link(page)])), &mut pages, "twice");
    // a third level: a link page of link pages
    let inner = pages.put(&osis_base::encode(&Value::List(vec![Value::Link(page)]))).unwrap();
    let outer = pages.put(&osis_base::encode(&Value::List(vec![Value::Link(inner)]))).unwrap();
    rejects(&snapshot_with(Value::List(vec![Value::Link(outer)])), &mut pages, "third");
    // a link page above the fan-out
    let many: Vec<Link> = (0..9).map(|i| pages.put(&osis_base::encode(&Value::List(vec![element(10 + i)]))).unwrap()).collect();
    let wide = pages.put(&osis_base::encode(&Value::List(many.into_iter().map(Value::Link).collect()))).unwrap();
    rejects(&snapshot_with(Value::List(vec![Value::Link(wide)])), &mut pages, "fan-out");
}

/// A valid paged snapshot still decodes after the expansion limits.
#[test]
fn paging_limits_accept_valid_spec_8() {
    let mut s = Fragment::default();
    for i in 0..400u64 {
        let mut w = Writer::new(ts(1 << 16), Source::node(Tid::from_bytes([1; 15])), 1 + i);
        s.join(create(&mut w, &AnyView, &Value::Set([Value::Str(format!("item {i}"))].into_iter().collect())).unwrap());
    }
    let mut pages = MemoryPages::with_params(SMALL);
    let snap = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: s.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &scx(), Some(&mut pages)).unwrap();
    assert_eq!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut pages)).unwrap().fragment, s);
}

/// The stamp of a register fragment's write.
fn written(f: &Fragment) -> Stamp {
    match f {
        Fragment::Register(r) => r.write.as_ref().map(|w| w.stamp.clone()).unwrap(),
        _ => panic!("register"),
    }
}

/// §4.6: undo steps back through repeated writes of one register: once the second write is
/// undone, the winner is that undo's restoring write of the first value, so undoing the first
/// writes the value before it; redo steps forward again. Another writer's value in between
/// blocks the chain (the undo restored that value, not the undone one).
#[test]
fn register_undo_chain_spec_4_6() {
    let view = TyView(Ty::Register);
    let me = Source::node(Tid::from_bytes([1; 15]));
    let write = |t: u64, n: u8, lo: u64, v: i64| {
        let mut w = Writer::new(ts(t << 16), Source::node(Tid::from_bytes([n; 15])), lo);
        let f = create(&mut w, &view, &Value::Int(v)).unwrap();
        (f, w.range())
    };
    // undo of `d` (written in `range` by `src`) against `cur`, with the pre-commit `before`;
    // `undos` are the stamps written by undo commits in effect
    let undo_of = |t: u64, lo: u64, d: &Fragment, src: &Source, range: CounterRange, cur: &Fragment, before: &Fragment, undos: &[Stamp]| {
        let restored = |s: &Stamp| undos.contains(s);
        let mut w = Writer::new(ts(t << 16), me.clone(), lo);
        undo(&mut w, &Undone { delta: d, source: src, range, restored: &restored }, cur, before, &view).unwrap()
    };
    let (c0, _) = write(5, 1, 1, 0);
    let (c1, r1) = write(10, 1, 2, 1);
    let (c2, r2) = write(20, 1, 3, 2);
    let mut s = c0.clone();
    let s0 = s.clone();
    s.join(c1.clone());
    let s1 = s.clone();
    s.join(c2.clone());
    let s2 = s.clone();
    let u2 = undo_of(30, 4, &c2, &me, r2, &s, &s1, &[]).unwrap();
    s.join(u2.clone());
    assert_eq!(s.read(), Some(Value::Int(1)));
    let s3 = s.clone();
    // today's rule alone: the first write no longer wins, nothing to write
    assert_eq!(undo_of(40, 5, &c1, &me, r1, &s, &s0, &[]), None);
    let u1 = undo_of(40, 5, &c1, &me, r1, &s, &s0, &[written(&u2)]).unwrap();
    s.join(u1.clone());
    assert_eq!(s.read(), Some(Value::Int(0)));
    // redo: undo of the undo of the first write (it wins), then of the second's (chained)
    let ru1 = undo_of(50, 6, &u1, &me, CounterRange { lo: 5, hi: 6 }, &s, &s3, &[written(&u2), written(&u1)]).unwrap();
    s.join(ru1.clone());
    assert_eq!(s.read(), Some(Value::Int(1)));
    let ru2 = undo_of(60, 7, &u2, &me, CounterRange { lo: 4, hi: 5 }, &s, &s2, &[written(&ru1)]).unwrap();
    s.join(ru2);
    assert_eq!(s.read(), Some(Value::Int(2)));
    // another writer's 5 between the two writes: undoing the second restores 5, and the first
    // one's undo then writes nothing
    let (b, _) = write(15, 2, 1, 5);
    let mut s = c0;
    s.join(c1.clone());
    s.join(b);
    let sb = s.clone();
    s.join(c2.clone());
    let u2 = undo_of(30, 4, &c2, &me, r2, &s, &sb, &[]).unwrap();
    s.join(u2.clone());
    assert_eq!(s.read(), Some(Value::Int(5)));
    assert_eq!(undo_of(40, 5, &c1, &me, r1, &s, &s0, &[written(&u2)]), None);
}

/// §4.1 copy order (ephemeral security review M3): two writes under one stamp with different
/// values (a forged copy of another's write inside a snapshot) join alike in either order.
#[test]
fn same_stamp_substitution_diverges() {
    let src = Source::node(Tid::from_bytes([3; 15]));
    let alice = create(&mut Writer::new(ts(1 << 16), src.clone(), 1), &AnyView, &Value::Str("alice".into())).unwrap();
    let forged = create(&mut Writer::new(ts(1 << 16), src, 1), &AnyView, &Value::Str("forged".into())).unwrap();
    let mut x = alice.clone();
    x.join(forged.clone());
    let mut y = forged;
    y.join(alice);
    assert_eq!(x.read(), y.read(), "join is order dependent for same-stamp writes");
}

/// §4.1 copy order: copies of one map entry creation with differing keys, and of one text
/// creation with differing chars, join alike in both orders (the greater key, the greater char).
#[test]
fn same_stamp_copies_converge_spec_4_1() {
    let src = Source::node(Tid::from_bytes([3; 15]));
    let mk = |v: Value| create(&mut Writer::new(ts(1 << 16), src.clone(), 1), &AnyView, &v).unwrap();
    let m = |k: i64| Value::Map([(Value::Int(k), Value::Int(9))].into_iter().collect());
    for (a, b, want) in [
        // a map key is part of the entry's identity (§5.6): two keys, two entries
        (mk(m(1)), mk(m(2)), Some(Value::Map([(Value::Int(1), Value::Int(9)), (Value::Int(2), Value::Int(9))].into_iter().collect()))),
        (mk(Value::Str("alice".into())), mk(Value::Str("forged".into())), Some(Value::Str("forged".into()))),
    ] {
        let mut x = a.clone();
        x.join(b.clone());
        let mut y = b;
        y.join(a);
        assert_eq!(x, y);
        assert_eq!(x.read(), want);
    }
    // links as keys: equal as `Value`s (by hash), copies by their bytes
    let link = |b: u8| Value::Link(Link { hash: [9; 32], blob: osis_base::BlobId([b; 32]), suite: 1, key: [b; 32] });
    let (a, b) = (mk(Value::Map([(link(1), Value::Int(9))].into_iter().collect())), mk(Value::Map([(link(2), Value::Int(9))].into_iter().collect())));
    let mut x = a.clone();
    x.join(b.clone());
    let mut y = b;
    y.join(a);
    let bytes = |f: &Fragment| osis_base::cbor::encode(&f.read().unwrap());
    assert_eq!(bytes(&x), bytes(&y), "link keys join by bytes");
    let t = |s: &str| create(&mut Writer::new(ts(1 << 16), src.clone(), 1), &TyView(Ty::Text), &Value::Str(s.into())).unwrap();
    let (a, b) = (t("abc"), t("xb"));
    let mut x = a.clone();
    x.join(b.clone());
    let mut y = b;
    y.join(a);
    assert_eq!(x, y);
    assert_eq!(x.read(), Some(Value::Str("xbc".into())), "per element: the greater char");
}

/// spec/permissions.md §5.2, §7: an un-merge at a `Slots` position whose register is older than
/// a map member's entry creation keeps that creation for the join (the member is not judged below
/// the register's embedding while it holds a creation another body's content needs).
#[test]
fn slots_unmerge_keeps_member_creation_spec_7() {
    use crate::fragment::{Entry, Map};
    let (a, b) = (st(2, 1, 1), st(3, 2, 1));
    let k = Value::Str("k".into());
    let inner = |created: Option<Stamp>| {
        let e = Entry { reset: None, frag: Some(Box::new(Fragment::Register(reg(b.clone(), 7)))), created };
        Fragment::Map(Map::new(Meta::default(), BTreeMap::from([(crate::fragment::Eid::new(a.dot.clone(), Some(k.clone())), e)])))
    };
    let mut full = Fragment::default();
    full.join(Fragment::Slots(Slots { reg: Some(reg(st(1, 3, 1), 5)), members: BTreeMap::from([(Encoding::Map, inner(Some(a.clone())))]) }));
    assert!(matches!(full, Fragment::Slots(_)), "{full:?}");
    let bdelta = inner(None);
    let mut stripped = full.clone();
    stripped.strip_copies(&|d| d.src == b.dot.src);
    assert!(matches!(&stripped, Fragment::Slots(s) if s.members.contains_key(&Encoding::Map)), "{stripped:?}");
    let mut un = stripped.clone();
    un.remove_dots(&|d| d.src == Source::node(Tid::from_bytes([4; 15])));
    assert_eq!(un, stripped, "nothing of the fourth author");
    for (name, x) in [("stripped", stripped), ("stripped, un-merged", un)] {
        let mut y = bdelta.clone();
        y.join(x);
        assert_eq!(y, full, "{name}");
    }
}

// issues/forged-creation-copies.md: copies of one text creation with other `ts` (a forged copy)
// and an undelete repeating another char: the char goes with the greater creation, so a repeated
// char folded in before the greater creation arrives is lost on one path and kept on the other.
#[test]
#[ignore = "issues/forged-creation-copies.md"]
fn repro_forged_creation_ts_undelete_char() {
    use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
    let d = Dot::new(Source::node(Tid::from_bytes([5; 15])), 1);
    let s1 = Stamp { ts: ts(1 << 16), dot: d.clone() };
    let s2 = Stamp { ts: ts(2 << 16), dot: d.clone() };
    let mk = |e: SeqElem| Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::from([(d.clone(), e)])));
    let made = |s: &Stamp, c: char| mk(SeqElem { created: Some((s.clone(), Anchor::Head)), content: SeqContent::Char(c), pos: vec![(s.clone(), Anchor::Head, None)], ..SeqElem::bare() });
    let (a, c) = (made(&s1, 'x'), made(&s2, 'w'));
    let b = mk(SeqElem { content: SeqContent::Char('y'), deleted: Some((st(3, 9, 1), false)), ..SeqElem::bare() });
    let mut x = a.clone();
    x.join(b.clone());
    x.join(c.clone());
    let mut y = c;
    y.join(b);
    y.join(a);
    assert_eq!(x.read(), y.read());
}

/// A map entry record: its creation stamp (the dot), key, reset and value.
type Rec = (Stamp, Option<Value>, Option<Stamp>, Option<i64>);

/// Records of map entries `(dot, key)`: a creation (value `v`) or a removal (`reset`).
fn entry_map(recs: Vec<Rec>) -> Fragment {
    use crate::fragment::{Eid, Entry, Map};
    let entries = recs
        .into_iter()
        .map(|(d, k, reset, v)| {
            let frag = v.map(|v| Box::new(Fragment::Register(reg(d.clone(), v))));
            let created = frag.as_ref().map(|_| d.clone());
            (Eid::new(d.dot, k), Entry { reset, frag, created })
        })
        .collect();
    Fragment::Map(Map::new(Meta::default(), entries))
}

/// Every join order of `parts` gives the same state, read as `want`.
fn all_orders(parts: &[Fragment], want: Option<Value>) {
    let mut first: Option<Fragment> = None;
    let n = parts.len();
    let mut idx: Vec<usize> = (0..n).collect();
    // Heap's algorithm over the join orders
    let mut c = vec![0; n];
    let mut check = |idx: &[usize]| {
        let mut s = Fragment::default();
        for i in idx {
            s.join(parts[*i].clone());
        }
        assert_eq!(s.read(), want, "order {idx:?}");
        match &first {
            None => first = Some(s),
            Some(f) => assert_eq!(&s, f, "order {idx:?}"),
        }
    };
    check(&idx);
    let mut i = 0;
    while i < n {
        if c[i] < i {
            if i % 2 == 0 { idx.swap(0, i) } else { idx.swap(c[i], i) }
            check(&idx);
            c[i] += 1;
            i = 0;
        } else {
            c[i] = 0;
            i += 1;
        }
    }
}

/// §5.6: a map record acts only on the entry of its key. A removal carrying another key than the
/// entry's leaves it live; one carrying its key removes it, also when it arrives first (the
/// tombstone keeps the key); a dot created under two keys (an equivocating writer) is two
/// entries, and a removal of one key leaves the other.
#[test]
fn map_removal_acts_on_its_key_spec_5_6() {
    let (a, b) = (Value::Str("a".into()), Value::Str("b".into()));
    let map = |kv: &[(&Value, i64)]| Some(Value::Map(kv.iter().map(|(k, v)| ((*k).clone(), Value::Int(*v))).collect()));
    let c = st(1, 1, 1);
    let rm = st(2, 2, 1);
    let created = entry_map(vec![(c.clone(), Some(a.clone()), None, Some(7))]);
    // another key: nothing removed
    all_orders(&[created.clone(), entry_map(vec![(c.clone(), Some(b.clone()), Some(rm.clone()), None)])], map(&[(&a, 7)]));
    // its key: removed, in either order
    all_orders(&[created.clone(), entry_map(vec![(c.clone(), Some(a.clone()), Some(rm.clone()), None)])], map(&[]));
    // the tombstone keeps its key
    let mut t = entry_map(vec![(c.clone(), Some(a.clone()), Some(rm.clone()), None)]);
    t.join(created.clone());
    let Fragment::Map(m) = &t else { panic!("map") };
    assert_eq!(m.entries().map(|(_, r, k, f)| (r.cloned(), k.cloned(), f.is_some())).collect::<Vec<_>>(), vec![(Some(rm.clone()), Some(a.clone()), false)]);
    // one dot, two keys: two entries; a removal of one leaves the other
    let other = entry_map(vec![(c.clone(), Some(b.clone()), None, Some(8))]);
    all_orders(&[created.clone(), other.clone()], map(&[(&a, 7), (&b, 8)]));
    all_orders(&[created, other, entry_map(vec![(c, Some(a), Some(rm), None)])], map(&[(&b, 8)]));
}

/// §5.6, §4.7: the key-erased record of a dot (a value-less creation, as a snapshot of an
/// expiring delta carries it) joins into the dot's keyed records' read, hides them while it
/// holds the dot's greatest creation alone, and its reset reaches every record of the dot,
/// as a keyed record's reset reaches it.
#[test]
fn map_key_erased_record_spec_5_6() {
    let k = Value::Str("k".into());
    let c = st(1, 1, 1);
    let rm = st(3, 2, 1);
    let valued = entry_map(vec![(c.clone(), Some(k.clone()), None, Some(7))]);
    let mut erased = valued.clone();
    erased.strip(&|_| true);
    // the valued creation shows the entry; the key-erased copy alone hides it
    let mut s = erased.clone();
    assert_eq!(s.read(), None, "hidden");
    s.join(valued.clone());
    assert_eq!(s.read(), Some(Value::Map([(k.clone(), Value::Int(7))].into_iter().collect())), "the valued copy shows it");
    // a keyed removal reaches the key-erased record: nothing of the dot left live or hidden
    let removal = entry_map(vec![(c.clone(), Some(k.clone()), Some(rm.clone()), None)]);
    all_orders(&[erased.clone(), valued.clone(), removal.clone()], Some(Value::Map(Default::default())));
    let mut s = erased.clone();
    s.join(removal);
    let Fragment::Map(m) = &s else { panic!("map") };
    assert!(m.entries().all(|(_, _, _, f)| f.is_none()), "{s:?}");
    // a key-erased removal reaches the keyed records
    let mut erm = entry_map(vec![(c.clone(), Some(k.clone()), Some(rm), None)]);
    erm.strip(&|_| true);
    all_orders(&[valued, erm], Some(Value::Map(Default::default())));
}

/// issues/forged-creation-copies.md (map residue): a dot under two keys (a forged copy), one
/// removed. A node past the creation's `T` folds both into the key-erased record, whose reset
/// then prunes the other key's record too; a node before `T` holding that snapshot beside the
/// valued records reads the other key gone, one without it reads it live, until it passes `T`.
#[test]
#[ignore = "issues/forged-creation-copies.md"]
fn repro_forged_key_hidden_by_erased_reset() {
    let (a, b) = (Value::Str("a".into()), Value::Str("b".into()));
    let c = st(1, 1, 1);
    let rm = st(3, 2, 1);
    let mut x = entry_map(vec![(c.clone(), Some(a.clone()), None, Some(7))]);
    x.join(entry_map(vec![(c.clone(), Some(a), Some(rm), None)]));
    x.join(entry_map(vec![(c, Some(b), None, Some(8))]));
    let mut s = x.clone();
    s.strip(&|_| true);
    let mut y = x.clone();
    y.join(s);
    assert_eq!(y.read(), x.read(), "valued copy wins");
}
