//! Sequences (spec/crdt.md §5.7, §6): differential join/read and wire against core/test/crdt-model, run
//! rejections, range records, the worked examples of notes/crdt.md.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::fragment::Meta;
use crate::linearize::place;
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::seq_span::{expand, nth};
use crate::stamp::{Dot, Interner, Stamp};
use crate::testutil::{frag, history, history_with, joined, mapply, node, reads, sess_value, snap_cx, snapshot, snapshot_bytes, source, struct_list, ts, via_snapshot, wired, writer_cx};
pub(crate) use crate::testutil::{Pager, partial_follow, partial_follow_in};
use crate::tests_wire::{delta, i, l, rejects, wcx};
use crate::wire::{Delta, DeltaCtx};
use crdt_model::ops::{self as mops, Ty, Writer as MWriter};
use crdt_model::stamp::Source as MSource;
use crdt_model::state::{Content, Frag as MFrag};
use crdt_model::wire::{Ctx, encode_snapshot as m_encode_snapshot};
use osis_base::{ErrorClass, Value};
use proptest::prelude::*;
use std::collections::BTreeMap;

/// Maps whose entries hold texts and lists, directly, in a struct and in a nested map.
pub(crate) fn map_of_text() -> Vec<Ty> {
    let rec = Ty::Struct([(1, Ty::Text), (2, Ty::List(Box::new(Ty::Text)))].into_iter().collect());
    let m = |v: Ty| Ty::Map(Box::new(Ty::Register), Box::new(v));
    vec![Ty::Struct([(1, m(Ty::Text)), (2, m(rec)), (3, m(m(Ty::Text)))].into_iter().collect())]
}

proptest! {
    /// §5.7 undelete: random deleted chars undeleted with their content reach a node that only
    /// holds the snapshot (deleted chars not carried) and read the same there.
    #[test]
    fn random_undelete_spec_5_7(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history_with(&mut r, &[Ty::Text], vec![MSource::session(1, 0), MSource::session(2, 0)], 6);
        let mut full = Fragment::default();
        for c in &commits {
            full.join(frag(&c.delta));
        }
        let mut boot = via_snapshot(&full);
        let Fragment::Seq(sq) = &full else { return Ok(()) };
        let dead: Vec<Dot> = sq.elems().iter().filter(|(_, e)| e.flag() && matches!(e.content, SeqContent::Char(_))).map(|(d, _)| d.clone()).filter(|_| r.chance(1, 2)).collect();
        if dead.is_empty() {
            return Ok(());
        }
        let st = Stamp::new(ts(1 << 30), node(7), 1);
        let mut d = Seq::empty(true);
        for x in &dead {
            let mut e = SeqElem::bare();
            e.deleted = Some((st.clone(), false));
            e.undel = sq.elems()[x].char();
            d.elems_mut().insert(x.clone(), e);
        }
        let u = wired(&Fragment::Seq(d), &crate::testutil::ctx_of(&crate::ops::Writer::new(ts(1 << 30), node(7), 1)));
        full.join(u.clone());
        boot.join(u);
        prop_assert_eq!(full.read(), boot.read());
        // the bootstrapped node holds the undelete's copy of each char, the full one both copies
        prop_assert_eq!(joined(&full, &boot), full);
    }

    /// §6: range records place, read and encode like their elements, and own the writes their
    /// elements own (`holds_owned` answers as `writes`, spec/commits.md §5), `Derived` dots
    /// included (random histories, every uniform stretch coalesced).
    #[test]
    fn ranges_act_like_their_elements_spec_6(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
        // text slots: embedded chars (`Derived` dots) beside range records
        let types: &[Ty] = if seed % 2 == 0 { &[Ty::Text, struct_list()] } else { &[Ty::Register, Ty::Text] };
        let mut state = None;
        for c in history(&mut r, types, 3, 6) {
            mapply(&mut state, c.delta);
            let f = match frag(state.as_ref().unwrap()) {
                Fragment::Slots(x) => x.slots.get(&crate::fragment::Encoding::Text).cloned().unwrap_or_default(),
                f => f,
            };
            let Fragment::Seq(_) = &f else { continue };
            let flat = expanded(&f);
            prop_assert_eq!(order(&f), order(&flat));
            prop_assert_eq!(f.read(), flat.read());
            prop_assert_eq!(snapshot_bytes(&f), snapshot_bytes(&flat));
        }
        let Some(st) = state.as_ref() else { return Ok(()) };
        let f = frag(st);
        for g in [f.clone(), via_snapshot(&f)] {
            let ws: Vec<Dot> = g.writes().into_iter().map(|(d, _)| d).collect();
            for n in 1..=3u8 {
                let src = node(n);
                for lo in [1u64, 2, 5, 9, 20] {
                    for len in [1u64, 3, 50] {
                        let want = ws.iter().any(|d| d.src == src && lo <= d.ctr && d.ctr < lo + len);
                        let got = g.holds_owned(&|s, a, b| *s == src && a < lo + len && lo < b);
                        prop_assert_eq!(got, want, "src {} lo {} len {}", n, lo, len);
                    }
                }
            }
        }
    }
}

/// §6.2: cycle breaking is linear. Adversarial graph: a chain of 20,000 plus 20,000 mutual-`cur`
/// pairs whose `prev` is the chain's tail (each victim's new edge walks into the chain).
#[test]
fn cycle_breaking_is_linear_spec_6_2() {
    let (len, k) = (20_000u64, 20_000u64);
    let mut elems = chain(len);
    let a = node(1);
    let tail = Anchor::Dot(Dot::new(a.clone(), len));
    let (mut c, mut m) = (len + 1, 10_000_000u64);
    for _ in 0..k {
        let (x, y) = (Dot::new(a.clone(), c), Dot::new(a.clone(), c + 1));
        let mut ex = char_at(x.clone(), 2, tail.clone(), 'a');
        ex.pos.insert(0, (Stamp::new(ts(3 << 16), a.clone(), m), Anchor::Dot(y.clone()), None));
        let mut ey = char_at(y.clone(), 2, tail.clone(), 'b');
        ey.pos.insert(0, (Stamp::new(ts(3 << 16), a.clone(), m + 1), Anchor::Dot(x.clone()), None));
        elems.insert(x, ex);
        elems.insert(y, ey);
        c += 2;
        m += 2;
    }
    let _ = crate::linearize::walk_probe();
    let p = crate::linearize::place_idx(&elems);
    let walked = crate::linearize::walk_probe();
    let n = (len + 2 * k) as usize;
    assert_eq!(p.order.len(), n);
    // linear: a few steps per node (re-walking the chain per victim would be len * k)
    assert!(walked <= 2 * n, "cycle breaking walked {walked} steps for {n} nodes");
}

/// Joins of `snapshot_then_edit`: all, followed by the cached placement (no whole pass), and
/// of those that split a range record or anchor inside one (`split`, and `missed`: not
/// followed) or touch or anchor at a `Derived` dot (`derived`, `missed_derived`).
#[derive(Debug, Default)]
pub(crate) struct Follows {
    pub joins: usize,
    pub kept: usize,
    pub split: usize,
    pub missed: usize,
    pub derived: usize,
    pub missed_derived: usize,
    /// Joins a whole placement followed, and of those a placement held in part followed too.
    pub whole: usize,
    pub partial: usize,
    /// Blocks the partial follows loaded, of all their placements' blocks.
    pub loaded: usize,
    pub blocks: usize,
}

/// Text built by a random history (`upgraded`: then a string register write over it, embedded as
/// characters with `Derived` dots, §7, and text edits of those, the position's text slot taken
/// alone) and bootstrapped from a snapshot (deleted stretches arrive as range records, deleted
/// chars without content); then edited by a new writer through the wire: an insert anchored at a
/// random placed element (half the time, while there are any, one inside a range record, so the
/// insert splits it, or an embedded one), then a
/// random text op (undelete of part of a deleted run, delete, move, insert, now and then a
/// replace), `n` times. After every join the read equals the model's text slot and the cached
/// placement a whole pass (`check_lin`).
pub(crate) fn snapshot_then_edit(mut r: crate::testutil::SeedRng, upgraded: bool, n: usize) -> Follows {
    use crdt_model::stamp::Dot as MDot;
    use crdt_model::state::{Anchor as MAnchor, Composite};
    let mut deltas: Vec<MFrag> = history(&mut r, &[Ty::Text], 3, 8).into_iter().map(|c| c.delta).collect();
    let mut m = None;
    for d in &deltas {
        mapply(&mut m, d.clone());
    }
    if upgraded {
        let mut w = MWriter::new(MSource::session(8, 0), 100 << 16, 1);
        let v = crdt_model::value::Value::Str(crdt_model::r#gen::random_text(&mut r, 12));
        let d = crdt_model::ops::create(&mut w, &Ty::Register, &v);
        mapply(&mut m, d.clone());
        deltas.push(d);
        let mut w = MWriter::new(MSource::session(7, 0), 101 << 16, 1);
        for k in 0..8 {
            w.next_commit((102 + k) << 16);
            if let Some(d) = crdt_model::r#gen::random_op(&mut r, &mut w, &Ty::Text, m.as_ref()) {
                mapply(&mut m, d.clone());
                deltas.push(d);
            }
        }
    }
    let mut full = Fragment::default();
    for d in &deltas {
        full.join(frag(d));
    }
    let mut ours = via_snapshot(&full);
    let mut f = Follows::default();
    // the text slot alone (the writer's deltas are newer than the register's write, so the
    // slot joins them as the position does)
    if let Fragment::Slots(x) = &ours {
        match x.slots.get(&crate::fragment::Encoding::Text) {
            Some(t) => ours = t.clone(),
            None => return f,
        }
    }
    let mread = |m: &Option<MFrag>| m.as_ref().and_then(|x| x.slot(9)).and_then(|x| x.read()).map(|v| crate::testutil::value(&v));
    let mut w = MWriter::new(MSource::session(9, 0), 1 << 30, 1);
    let mut deliver = |d: MFrag, w: &MWriter, m: &mut Option<MFrag>, ours: &mut Fragment| {
        mapply(m, d.clone());
        let d = wired(&frag(&d), &writer_cx(w));
        let before = match &*ours {
            Fragment::Seq(x) => Some(x.clone()),
            _ => None,
        };
        let (mut splits, mut derived) = (false, false);
        if let (Some(st), Fragment::Seq(ds)) = (&before, &d) {
            let inside = |x: &Dot| crate::seq_span::find(st.elems(), x).is_some_and(|(k, _)| k != x);
            for (dot, de) in ds.elems() {
                let anchors = || de.pos.iter().filter_map(|(_, a, _)| if let Anchor::Dot(x) = a { Some(x) } else { None });
                splits |= inside(dot) || inside(&nth(dot, de.span)) || anchors().any(|x| crate::seq_span::find(st.elems(), x).is_some_and(|(k, e)| x.ctr - k.ctr + 1 < e.span));
                derived |= dot.src.is_derived() || anchors().any(|x| x.src.is_derived());
            }
        }
        let cached = before.as_ref().is_some_and(|x| x.lin_check().is_some());
        // a placement held in part, with the records held in part
        let partial = match (&before, &d) {
            (Some(st), Fragment::Seq(ds)) if cached => partial_follow(st, ds, 1 + f.joins % 8),
            _ => None,
        };
        let _ = crate::seq_lin::probe();
        ours.join(d);
        // followed: no whole pass in the join, and still cached
        let after = crate::seq_lin::probe().1 == 0 && matches!(&*ours, Fragment::Seq(x) if x.lin_check().is_some());
        f.whole += usize::from(cached && after);
        f.partial += usize::from(cached && after && partial.is_some());
        if let Some((l, b)) = partial {
            f.loaded += l;
            f.blocks += b;
        }
        crate::testutil::check_lin(ours);
        assert_eq!(ours.read(), mread(m));
        f.joins += 1;
        f.kept += usize::from(cached && after);
        f.split += usize::from(cached && after && splits);
        f.missed += usize::from(cached && !after && splits);
        f.derived += usize::from(cached && after && derived);
        f.missed_derived += usize::from(cached && !after && derived);
    };
    for k in 0..n as u64 {
        // the placement read before each join, so the join has a cache to follow
        let _ = ours.read();
        let order = match m.as_ref().and_then(|x| x.slot(9)) {
            Some(MFrag::Seq { elems, .. }) => crdt_model::seq::linearize_full(elems).0,
            _ => Vec::new(),
        };
        w.next_commit((1 << 30) + 2 * k + 1);
        // half the time, when any, at a rare anchor: inside a range record (before its last
        // element: a split) or an embedded char
        let rare: Vec<&MDot> = match &ours {
            Fragment::Seq(st) => order
                .iter()
                .filter(|x| {
                    let d = crate::testutil::dot(x);
                    d.src.is_derived() || crate::seq_span::find(st.elems(), &d).is_some_and(|(k, e)| d.ctr - k.ctr + 1 < e.span)
                })
                .collect(),
            _ => Vec::new(),
        };
        let anchor: Option<&MDot> = if !rare.is_empty() && r.chance(1, 2) { Some(rare[r.below(rare.len())]) } else { order.get(r.below(order.len() + 1)) };
        let mut d = MFrag::Seq { text: true, c: Composite { reset: None, w: None, w_valueless: false }, elems: Default::default() };
        let cs = crdt_model::r#gen::random_text(&mut r, 3);
        if !cs.is_empty() {
            crdt_model::ops::insert_run(&mut w, &mut d, anchor.map_or(MAnchor::Head, |x| MAnchor::Dot(x.clone())), chars(&cs));
            deliver(d, &w, &mut m, &mut ours);
        }
        let _ = ours.read();
        w.next_commit((1 << 30) + 2 * k + 2);
        if let Some(d) = crdt_model::r#gen::random_op(&mut r, &mut w, &Ty::Text, m.as_ref()) {
            deliver(d, &w, &mut m, &mut ours);
        }
    }
    f
}

/// §6 (a deterministic function of state), `seq_lin`: writes splitting a range record of a
/// snapshot-bootstrapped text, or anchoring inside one, are followed by the cached placement, not
/// rebuilt (each kind of split alone: `ranges_split_where_writes_land_spec_6`). §6.1, §7
/// (embedding), `seq_lin`: writes on embedded characters (`Derived` dots) of an upgraded text, and
/// inserts anchored at them, are followed too. §6, §8 (pages are joined independently),
/// `seq_place`: a placement held in part (a node's stored one: blocks and dot-map chunks loaded on
/// a miss) over records held in part (pages loaded on a miss) follows the joins a whole one
/// follows, and what it writes back reads as a whole pass. Histories plain and upgraded in turn
/// until both rare kinds (splits, `Derived` dots) were met a few times.
#[test]
fn snapshot_edits_follow_cache_spec_6() {
    let mut t = Follows::default();
    let mut runs = 0;
    while (t.split < 3 || t.derived < 3) && runs < 60 {
        let x = snapshot_then_edit(crate::testutil::rng(runs / 2), runs % 2 == 1, 30);
        runs += 1;
        t.joins += x.joins;
        t.kept += x.kept;
        t.split += x.split;
        t.missed += x.missed;
        t.derived += x.derived;
        t.missed_derived += x.missed_derived;
        t.whole += x.whole;
        t.partial += x.partial;
        t.loaded += x.loaded;
        t.blocks += x.blocks;
    }
    assert!(t.split >= 3 && t.derived >= 3, "{runs} histories: {t:?}");
    // every join of a kind the cache follows is followed (whole and held in part); the rest
    // (resets, records partly new) are few
    assert!(t.missed == 0 && t.missed_derived == 0 && t.partial == t.whole, "{t:?}");
    assert!(t.kept * 10 >= t.joins * 9, "{t:?}");
    // the blocks the joins look at, not every block
    assert!(t.loaded * 2 < t.blocks, "{t:?}");
}

/// What decoding a snapshot of `f` gives: the chars of deleted elements dropped (§3.3 rule 5),
/// those of embedded ones put back by the decoder's prune of a `Slots` (§7).
pub(crate) fn as_carried(f: &Fragment) -> Fragment {
    let mut f = f.clone();
    f.drop_deleted_chars();
    f.prune(None, &mut crate::Changes::new());
    f
}

/// The model's text slot at a position: a slot not held beside a register is the register's
/// embedding (§7 Canonical form), what a text op writes against.
fn text_slot(f: &MFrag) -> MFrag {
    f.slot(9).cloned().unwrap_or_else(|| {
        let mut e = crdt_model::embed::embed(f.slot(0).expect("a register"), 9).expect("embeds");
        e.prune(None);
        e
    })
}

/// §3.3 rules 5 and 7, §7: a snapshot of a text upgraded from a string whose deleted embedded
/// char is not carried round-trips through both decoders and reads alike. §5.7 Live: a node
/// bootstrapped from it holds the deleted embedded char again (the decoder returns the
/// re-embedded position); an undelete carrying no char (as a writer bootstrapped without the char
/// may send) shows nothing there, as on a node with the full history, and the state re-encodes
/// and decodes.
#[test]
fn bootstrapped_undelete_of_embedded_char_spec_4_6() {
    use crdt_model::value::Value as MValue;
    let mut m = None;
    mapply(&mut m, mops::create(&mut mw(1, 50), &Ty::Text, &MValue::Str("xy".into())));
    mapply(&mut m, mops::create(&mut mw(2, 100), &Ty::Register, &MValue::Str("ab".into())));
    let d = mops::seq_delete(&mut mw(3, 102), &text_slot(m.as_ref().unwrap()), 0, 1).unwrap();
    mapply(&mut m, d);
    let st = m.as_ref().unwrap();
    assert!(matches!(st, MFrag::Slots { .. }));
    let full = frag(st);
    let bytes = snapshot_bytes(&full);
    assert_eq!(bytes, m_encode_snapshot(st, &[], [0; 16], &mut Ctx::new(1 << 40, MSource::session(250, 0), 1)));
    let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
    let (mback, _) = crdt_model::wire::decode_snapshot(&bytes, &mut Ctx::new(1 << 40, MSource::session(250, 0), 1)).unwrap();
    assert_eq!(back.read(), Some(Value::Str("b".into())));
    assert_eq!(back.read(), full.read());
    assert_eq!(frag(&mback).read(), back.read());
    assert_eq!(back, full, "the embedded char is held again");
    // joined into an empty state, the embedding restores the char locally
    assert_eq!(joined(&Fragment::default(), &back), full);
    // the deleted embedded char, undeleted without content
    let Some(MFrag::Seq { elems, .. }) = st.slot(9) else { panic!() };
    let dead: Vec<_> = elems.iter().filter(|(_, e)| e.is_deleted(true)).map(|(d, _)| d.clone()).collect();
    assert_eq!(dead.len(), 1);
    let mut w = mw(4, 103);
    let u = mops::seq_undelete(&mut w, &MFrag::Seq { text: true, c: Default::default(), elems: BTreeMap::new() }, &dead);
    let u = wired(&frag(&u), &writer_cx(&w));
    let (whole, boot) = (joined(&full, &u), joined(&back, &u));
    assert_eq!(whole.read(), Some(Value::Str("b".into())));
    assert_eq!(boot.read(), whole.read());
    assert_eq!(via_snapshot(&boot).read(), whole.read());
}

/// §7 (embedding), `seq_lin`: joins at a `Slots` position that leave its register and effective
/// reset as they are (text edits of a text upgraded from a string) follow the text slot's cached
/// placement and read like the model (the join itself is checked against a whole pass).
#[test]
fn slots_join_follows_cache_spec_7() {
    use crdt_model::value::Value as MValue;
    // whether the join followed the cached placement: no whole pass, still cached
    let put = |d: MFrag, m: &mut Option<MFrag>, ours: &mut Fragment| {
        mapply(m, d.clone());
        let _ = ours.read();
        let _ = crate::seq_lin::probe();
        ours.join(frag(&d));
        let text = match &*ours {
            Fragment::Slots(x) => x.slots.get(&crate::fragment::Encoding::Text),
            f => Some(f),
        };
        let followed = crate::seq_lin::probe().1 == 0 && matches!(text, Some(Fragment::Seq(x)) if x.lin_check().is_some());
        crate::testutil::check_lin(ours);
        assert_eq!(ours.read(), m.as_ref().and_then(|x| x.read()).map(|v| crate::testutil::value(&v)));
        followed
    };
    let (mut joins, mut kept) = (0, 0);
    for seed in (1..12).step_by(2) {
        let mut r = crate::testutil::fixed(seed);
        let (mut m, mut ours) = (None, Fragment::default());
        put(mops::create(&mut mw(1, 50), &Ty::Text, &MValue::Str("xy".into())), &mut m, &mut ours);
        put(mops::create(&mut mw(2, 100), &Ty::Register, &MValue::Str("abcdefghij".repeat(4))), &mut m, &mut ours);
        let mut w = mw(3, 101);
        for k in 0..40 {
            w.next_commit((102 + k) << 16);
            let Some(d) = crdt_model::r#gen::random_op(&mut r, &mut w, &Ty::Text, m.as_ref()) else { continue };
            let was = matches!(ours, Fragment::Slots(_));
            let followed = put(d, &mut m, &mut ours);
            if was && matches!(ours, Fragment::Slots(_)) {
                joins += 1;
                kept += usize::from(followed);
            }
        }
    }
    assert!(joins >= 15 && kept * 10 >= joins * 9, "{kept} of {joins} followed");
}

// ---- §3.3 rule 7 for runs (writer of node 1, range [3, 6), ts 5·2^16)

fn text_with(runs: Vec<Value>) -> Value {
    l(vec![i(9), l(vec![]), l(vec![]), l(runs)])
}
fn list_with(runs: Vec<Value>) -> Value {
    l(vec![i(8), l(vec![]), l(vec![]), l(runs)])
}
fn run(dot: Value, n: i64, creation: Value, content: Value, posw: Vec<Value>, flagw: Vec<Value>) -> Value {
    l(vec![dot, i(n), creation, content, l(posw), l(flagw)])
}
fn s(x: &str) -> Value {
    Value::Str(x.into())
}
fn reg(v: i64) -> Value {
    l(vec![i(0), l(vec![]), i(0), i(v)])
}
/// A creation run from HEAD by this commit.
fn created(n: i64) -> Value {
    l(vec![i(0), l(vec![l(vec![i(0), i(n)])])])
}

fn accepts(f: Value, cx: &DeltaCtx) -> Fragment {
    decode_delta(&delta(vec![], vec![], f), cx, &mut Interner::new(), None).unwrap().fragment
}

/// §3.2 Run: creations, flag writes, position writes and undeletes carrying their chars decode.
#[test]
fn accepts_valid_runs_spec_3_2() {
    let f = accepts(text_with(vec![run(i(3), 3, created(3), s("abc"), vec![], vec![])]), &wcx());
    assert_eq!(f.read(), Some(s("abc")));
    // a flag write on earlier elements, a position write, an undelete carrying its chars
    accepts(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(1), i(0), Value::Bool(true)])])]), &wcx());
    accepts(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![l(vec![i(0), l(vec![i(0), i(4)]), i(2)])], vec![])]), &wcx());
    accepts(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(1), i(0), Value::Bool(false), s("xy")])])]), &wcx());
    let f = accepts(list_with(vec![run(i(3), 2, created(2), l(vec![reg(1), reg(2)]), vec![], vec![])]), &wcx());
    assert_eq!(f.read(), Some(l(vec![i(1), i(2)])));
}

/// §3.3 rule 7: every malformed run is bad input; where a rule has a bound (`MAX_DELTA_BARE`, a
/// segment's source, `Derived` creations) the run just inside it decodes.
#[test]
fn rejects_bad_runs_spec_3_3() {
    let bad = |f: Value| rejects(&delta(vec![], vec![], f), &wcx(), ErrorClass::BadInput);
    // n = 0 and n > 2^16
    bad(text_with(vec![run(i(1), 0, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    bad(text_with(vec![run(i(1), (1 << 16) + 1, l(vec![]), l(vec![]), vec![], vec![])]));
    // flag and position indices out of range, reversed flag range
    bad(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(2), i(0), Value::Bool(true)])])]));
    bad(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(1), i(0), i(0), Value::Bool(true)])])]));
    bad(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![l(vec![i(1), l(vec![i(0), i(4)]), i(2)])], vec![])]));
    // text chars without a creation (an undelete's ride its flag write), chars on a delete,
    // undelete chars short of or beyond the range
    bad(text_with(vec![run(i(1), 2, l(vec![]), s("xy"), vec![], vec![l(vec![i(0), i(1), i(0), Value::Bool(false)])])]));
    bad(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true), s("x")])])]));
    bad(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(1), i(0), Value::Bool(false), s("x")])])]));
    bad(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(false), s("xy")])])]));
    // an undelete in a list run
    bad(list_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(false)])])]));
    // content length differs from the content-carrying elements
    bad(text_with(vec![run(i(3), 3, created(3), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 3, created(3), s("abcd"), vec![], vec![])]));
    bad(list_with(vec![run(i(3), 2, created(2), l(vec![reg(1)]), vec![], vec![])]));
    // segments: short, too long, of another commit's source
    bad(text_with(vec![run(i(3), 3, created(2), s("abc"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 2, created(3), s("ab"), vec![], vec![])]));
    // own creation above the range, a creation outside the range, a creation repeated as a PosW
    bad(text_with(vec![run(i(5), 2, created(2), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(1), 2, created(2), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 1, created(1), s("a"), vec![l(vec![i(0), i(0), i(0)])], vec![])]));
    // non-maximal runs (rule 3) and unsorted runs (rule 2): caught by the canonical re-encode
    bad(text_with(vec![run(i(3), 1, created(1), s("a"), vec![], vec![]), run(i(4), 1, l(vec![i(3), l(vec![l(vec![i(0), i(1)])])]), s("b"), vec![], vec![])]));
    bad(text_with(vec![run(i(2), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])]), run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    // content for a deleted element, an empty list element fragment
    bad(text_with(vec![run(i(1), 1, l(vec![]), s("a"), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    bad(list_with(vec![run(i(3), 1, created(1), l(vec![l(vec![i(0), l(vec![])])]), vec![], vec![])]));
    // a flag write off the delta stamp
    bad(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), l(vec![i(0), i(4)]), Value::Bool(true)])])]));
    // a run carrying no write, in any delta; at most `MAX_DELTA_BARE` content-less elements per
    // writer's delta: k · MAX_RUN of them pass, one run more does not
    let srcs = || vec![sess_value(osis_base::Tid::from_bytes([9; 15]))];
    let m = crate::MAX_RUN as i64;
    let k = (osis_base::format::MAX_DELTA_BARE / crate::MAX_RUN) as i64;
    let flag = || vec![l(vec![i(0), i(m - 1), i(0), Value::Bool(true)])];
    let runs = |k: i64, f: &dyn Fn() -> Vec<Value>| text_with((0..k).map(|j| run(l(vec![i(1), i(1 + j * m)]), m, l(vec![]), l(vec![]), vec![], f())).collect());
    rejects(&delta(srcs(), vec![], runs(1, &Vec::new)), &wcx(), ErrorClass::BadInput);
    rejects(&delta(srcs(), vec![], runs(1, &Vec::new)), &snap_cx(), ErrorClass::BadInput);
    decode_delta(&delta(srcs(), vec![], runs(k, &flag)), &wcx(), &mut Interner::new(), None).unwrap();
    rejects(&delta(srcs(), vec![], runs(k + 1, &flag)), &wcx(), ErrorClass::BadInput);
    // a segment's commit has the run's source
    let (a, b) = (osis_base::Tid::from_bytes([1; 15]), osis_base::Tid::from_bytes([2; 15]));
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(10), i(0), i(1)])])]), l(vec![i(2), l(vec![l(vec![i(10), i(0), i(1)])])])];
    let segment_of = |ci: i64| {
        let r = run(l(vec![i(1), i(1)]), 1, l(vec![i(0), l(vec![l(vec![i(ci), i(1)])])]), s("a"), vec![], vec![]);
        let f = text_with(vec![r, run(l(vec![i(2), i(1)]), 1, l(vec![i(0), l(vec![l(vec![i(2), i(1)])])]), s("b"), vec![], vec![])]);
        delta(vec![sess_value(a), sess_value(b)], commits.clone(), f)
    };
    decode_delta(&segment_of(1), &snap_cx(), &mut Interner::new(), None).unwrap();
    rejects(&segment_of(2), &snap_cx(), ErrorClass::BadInput);
    // a creation run of a `Derived` source (of own dot 3) only in snapshots (embedded
    // characters); an anchor at an embedded character is fine
    let f = text_with(vec![run(l(vec![i(1), i(1)]), 1, created(1), s("a"), vec![], vec![])]);
    rejects(&delta(vec![l(vec![i(0), i(3)])], vec![], f), &wcx(), ErrorClass::BadInput);
    let f = text_with(vec![run(i(3), 1, l(vec![l(vec![i(2), i(1)]), l(vec![l(vec![i(0), i(1)])])]), s("q"), vec![], vec![])]);
    decode_delta(&delta(vec![sess_value(osis_base::Tid::from_bytes([9; 15])), l(vec![i(1), i(4)])], vec![], f), &wcx(), &mut Interner::new(), None).unwrap();
    // runs that overlap (the second starts inside the first, or lies within it), in a snapshot
    // of a typed text that decodes with one run
    let Value::List(mut top) = osis_base::decode(&snapshot_bytes(&typed("abcde").1), &osis_base::Limits::DEFAULT).unwrap() else { panic!("snapshot") };
    let mk = |at: i64, n: i64, cs: &str| run(l(vec![i(1), i(at)]), n, l(vec![i(0), l(vec![l(vec![i(1), i(n)])])]), s(cs), vec![], vec![]);
    for (runs, ok) in [(vec![mk(1, 5, "abcde")], true), (vec![mk(1, 5, "abcde"), mk(3, 3, "cde")], false), (vec![mk(1, 5, "abcde"), mk(2, 1, "b")], false)] {
        top[3] = text_with(runs);
        let r = decode_snapshot(&osis_base::encode(&Value::List(top.clone())), &snap_cx(), &mut Interner::new(), None);
        match r {
            Ok(_) => assert!(ok, "overlapping runs accepted"),
            Err(e) => assert!(!ok && osis_base::Classified::class(&e) == ErrorClass::BadInput, "{e}"),
        }
    }
}

// ---- notes/crdt.md, Worked examples (model ops, joined by this implementation)

fn chars(x: &str) -> Vec<Content> {
    x.chars().map(Content::Char).collect()
}
fn mw(n: u8, t: u64) -> MWriter {
    MWriter::new(MSource::session(n, 0), t << 16, 1)
}
/// `base` joined with model deltas `ds` in order.
fn after(base: &Fragment, ds: &[&MFrag]) -> Fragment {
    ds.iter().fold(base.clone(), |f, d| joined(&f, &frag(d)))
}
/// The read of `base` joined with `ds`, the same state in either order (§4.1).
fn converged(base: &Fragment, ds: &[&MFrag]) -> Option<String> {
    let st = after(base, ds);
    assert_eq!(st, after(base, &ds.iter().rev().copied().collect::<Vec<_>>()), "order-independent");
    reads(&st)
}
fn txt(x: &str) -> Option<String> {
    Some(x.into())
}
/// `x` typed by node 1 at t=1, as a model state and ours.
fn typed(x: &str) -> (MFrag, Fragment) {
    let mut st = mops::seq_insert(&mut mw(1, 1), None, true, 0, chars(x));
    st.prune(None);
    let f = frag(&st);
    (st, f)
}
/// Model writer `n` at `t` with counters from `lo`.
fn mw_at(n: u8, t: u64, lo: u64) -> MWriter {
    let mut w = mw(n, t);
    (w.lo, w.next) = (lo, lo);
    w
}
/// The fragment of delta bytes, as CBOR.
fn fragment_value(bytes: &[u8]) -> Value {
    let Value::List(top) = osis_base::decode(bytes, &osis_base::Limits::new(64, 1 << 20)).unwrap() else { panic!() };
    top[3].clone()
}
/// The wire fragment of model delta `d` by `w`.
fn wire_of(d: &MFrag, w: &MWriter) -> Value {
    fragment_value(&encode_delta(&Delta { nonce: [0; 16], fragment: frag(d) }, &writer_cx(w), None).unwrap())
}

#[test]
fn typing_spec_example() {
    let mut a = mw(1, 1);
    let d = mops::seq_insert(&mut a, None, true, 0, chars("FOOBAR"));
    assert_eq!(wire_of(&d, &a), text_with(vec![run(i(1), 6, l(vec![i(0), l(vec![l(vec![i(0), i(6)])])]), s("FOOBAR"), vec![], vec![])]));
    assert_eq!(reads(&frag(&d)), txt("FOOBAR"));
}

#[test]
fn concurrent_inserts_at_one_anchor_spec_example() {
    let (m, base) = typed("FOOBAR");
    let mut b = mw(2, 2);
    let x = mops::seq_insert(&mut b, Some(&m), true, 3, chars("x"));
    assert_eq!(wire_of(&x, &b), text_with(vec![run(i(1), 1, l(vec![l(vec![i(1), i(3)]), l(vec![l(vec![i(0), i(1)])])]), s("x"), vec![], vec![])]));
    let y = mops::seq_insert(&mut mw(3, 3), Some(&m), true, 3, chars("y"));
    assert_eq!(converged(&base, &[&x, &y]), txt("FOOyxBAR"));
}

#[test]
fn move_with_concurrent_insert_spec_example() {
    let (m, base) = typed("FOOBAR");
    let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 3, chars("x"));
    let mv = mops::seq_move(&mut mw_at(1, 3, 7), &m, 0, 3, 3).unwrap();
    assert_eq!(converged(&base, &[&x, &mv]), txt("BARFOOx"));
}

#[test]
fn range_with_several_roots_spec_example() {
    let mut w = mw(1, 1);
    let mut st: Option<MFrag> = None;
    for (k, c) in ["c", "b", "a"].iter().enumerate() {
        w.next_commit((k as u64 + 1) << 16);
        let d = mops::seq_insert(&mut w, st.as_ref(), true, 0, chars(c));
        mapply(&mut st, d);
    }
    let m = st.unwrap();
    let base = frag(&m);
    assert_eq!(reads(&base), txt("abc"));
    w.next_commit(4 << 16);
    let mv = mops::seq_move(&mut w, &m, 0, 2, 1).unwrap();
    assert_eq!(reads(&after(&base, &[&mv])), txt("cab"));
}

#[test]
fn concurrent_moves_of_one_element_spec_example() {
    let (m, base) = typed("abc");
    let m1 = mops::seq_move(&mut mw(2, 5), &m, 0, 1, 2).unwrap();
    let m2 = mops::seq_move(&mut mw(3, 4), &m, 0, 1, 1).unwrap();
    assert_eq!(converged(&base, &[&m1, &m2]), txt("bca"));
}

#[test]
fn cycle_spec_example() {
    let (m, base) = typed("acb");
    let m1 = mops::seq_move(&mut mw(2, 5), &m, 0, 1, 2).unwrap();
    let m2 = mops::seq_move(&mut mw(3, 4), &m, 2, 1, 1).unwrap();
    assert_eq!(converged(&base, &[&m1, &m2]), txt("cba"));
}

#[test]
fn reset_against_a_newer_insert_spec_example() {
    let (m, base) = typed("abc");
    let rep = mops::replace(&mut mw_at(1, 5, 4), &Ty::Text, &crdt_model::value::Value::Str("xyz".into()));
    let q = mops::seq_insert(&mut mw(2, 6), Some(&m), true, 2, chars("q"));
    assert_eq!(converged(&base, &[&rep, &q]), txt("xyzq"));
    let old = mops::seq_insert(&mut mw(3, 3), Some(&m), true, 2, chars("o"));
    assert_eq!(reads(&after(&base, &[&old, &rep])), txt("xyz"));
    // remove_aspect instead: absent until q arrives, then q
    let rm = mops::remove(&mut mw(1, 5), 9);
    assert_eq!(after(&base, &[&rm]).read(), None);
    assert_eq!(reads(&after(&base, &[&rm, &q])), txt("q"));
}

#[test]
fn move_displaces_a_concurrent_insert_spec_example() {
    let (m, base) = typed("abcd");
    let mv = mops::seq_move(&mut mw(2, 5), &m, 1, 1, 3).unwrap();
    let x = mops::seq_insert(&mut mw(3, 4), Some(&m), true, 1, chars("x"));
    assert_eq!(reads(&after(&base, &[&mv, &x])), txt("acdbx"));
}

#[test]
fn delete_vs_move_spec_example() {
    let (m, base) = typed("abc");
    let del = mops::seq_delete(&mut mw(2, 4), &m, 1, 1).unwrap();
    let mv = mops::seq_move(&mut mw(3, 5), &m, 1, 1, 2).unwrap();
    assert_eq!(converged(&base, &[&del, &mv]), txt("ac"));
    // an insert anchored at b (made before the delete) appears after c
    let q = mops::seq_insert(&mut mw(4, 6), Some(&m), true, 2, chars("q"));
    assert_eq!(reads(&after(&base, &[&del, &mv, &q])), txt("acq"));
}

#[test]
fn unknown_anchor_spec_example() {
    let (m, base) = typed("FOOBAR");
    let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 3, chars("x"));
    let rep = mops::replace(&mut mw_at(1, 5, 7), &Ty::Text, &crdt_model::value::Value::Str("Z".into()));
    let e = Fragment::default();
    assert_eq!(reads(&after(&e, &[&x])), txt("x"), "at END until its anchor arrives");
    assert_eq!(reads(&after(&e, &[&x, &rep])), txt("Z"));
    assert_eq!(reads(&joined(&after(&e, &[&x, &rep]), &base)), txt("Z"), "x (t=2) is older than the reset");
    // a newer insert into the reset text is placed once its anchor arrives
    let y = mops::seq_insert(&mut mw(3, 6), Some(&m), true, 3, chars("y"));
    assert_eq!(reads(&after(&e, &[&y])), txt("y"));
    assert_eq!(reads(&after(&e, &[&y, &rep])), txt("Zy"));
    assert_eq!(reads(&after(&e, &[&y, &rep, &m])), txt("Zy"));
}

/// §8: a text with many runs pages and re-joins to itself.
#[test]
fn text_pages_spec_8() {
    use crate::page::{MemoryPages, PageParams};
    let params = PageParams { target: 2000, cut: osis_base::ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };
    let text: String = (0..1500).map(|k| (b'a' + (k % 26) as u8) as char).collect();
    let (_, mut st) = typed(&text);
    // every third char deleted by its own commit: one run per char
    let Fragment::Seq(s) = &mut st else { panic!() };
    for (k, e) in s.elems_mut().values_mut().enumerate().filter(|(k, _)| k % 3 == 0) {
        e.deleted = Some((Stamp::new(ts((k as u64 + 2) << 16), node(2), k as u64 + 1), true));
    }
    let mut pages = MemoryPages::with_params(params);
    let bytes = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut pages)).unwrap();
    assert!(!pages.is_empty());
    let got = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), Some(&mut pages)).unwrap();
    assert_eq!(got.fragment, as_carried(&st));
    assert_eq!(got.fragment.read(), st.read());
}

// ---- range records (spec/requirements.md Scale: input never causes unbounded allocation)

fn st(t: u64, b: u8, c: u64) -> Stamp {
    Stamp::new(ts(t << 16), node(b), c)
}
fn seq_of(elems: BTreeMap<Dot, SeqElem>, reset: Option<Stamp>) -> Fragment {
    Fragment::Seq(Seq::new(true, Meta { reset, ..Meta::default() }, elems))
}
fn one(d: Dot, e: SeqElem) -> Fragment {
    seq_of(BTreeMap::from([(d, e)]), None)
}
/// A created char `c` of `dot` at `t`, anchored at `at`.
fn char_at(dot: Dot, t: u64, at: Anchor, c: char) -> SeqElem {
    let s = Stamp { ts: ts(t << 16), dot };
    SeqElem { created: Some((s.clone(), at.clone())), content: SeqContent::Char(c), pos: vec![(s, at, None)], deleted: None, undel: None, valueless: false, span: 1 }
}
/// `len` chars typed by node 1 at t = 1, chained from HEAD.
fn chain(len: u64) -> BTreeMap<Dot, SeqElem> {
    let (a, mut prev) = (node(1), Anchor::Head);
    (1..=len)
        .map(|c| {
            let d = Dot::new(a.clone(), c);
            (d.clone(), char_at(d.clone(), 1, std::mem::replace(&mut prev, Anchor::Dot(d)), 'a'))
        })
        .collect()
}
fn long_text(len: u64) -> Fragment {
    seq_of(chain(len), None)
}
/// `long_text(MAX_RUN - 1)` deleted by one range write of node 2.
fn deleted_text() -> Fragment {
    let len = crate::MAX_RUN - 1;
    joined(&long_text(len), &one(Dot::new(node(1), 1), SeqElem { deleted: Some((st(2, 2, 1), true)), span: len, ..SeqElem::bare() }))
}
fn records(f: &Fragment) -> usize {
    match f {
        Fragment::Seq(s) => s.elems().len(),
        _ => panic!("not a sequence"),
    }
}
/// Every placed element in order.
fn order(f: &Fragment) -> Vec<Dot> {
    let Fragment::Seq(s) = f else { panic!("not a sequence") };
    let p = place(s.elems(), s.text);
    p.iter().flat_map(|r| (0..r.span).map(move |i| nth(&r.dot, i))).collect()
}
fn expanded(f: &Fragment) -> Fragment {
    let Fragment::Seq(s) = f else { panic!("not a sequence") };
    Fragment::Seq(Seq::new(s.text, s.meta.clone(), expand(s.elems().clone())))
}
/// `a` and `b` place, read and encode alike.
#[track_caller]
fn alike(a: &Fragment, b: &Fragment) {
    assert_eq!(order(a), order(b));
    assert_eq!(a.read(), b.read());
    assert_eq!(snapshot_bytes(a), snapshot_bytes(b));
}

/// §3.2 Run, issue run amplification: a snapshot run of `MAX_RUN` - 1 deleted elements is a few
/// bytes and decodes to one record, not one per element. A reset text holds no record, and a run
/// carrying no write (`[Dot, n, [], [], [], []]`) is rejected in a snapshot too (§3.3 rule 7).
#[test]
fn snapshot_runs_decode_to_ranges_spec_3_2() {
    let reset = joined(&long_text(crate::MAX_RUN - 1), &seq_of(BTreeMap::new(), Some(st(2, 2, 1))));
    assert_eq!(records(&reset), 0, "a reset leaves no record");
    let deleted = deleted_text();
    assert_eq!(records(&deleted), crate::MAX_RUN as usize - 1, "a range write splits nothing into a per-element state");
    let bytes = snapshot_bytes(&deleted);
    // 138 bytes, 66 of them its two session sources
    assert!(bytes.len() < 144, "{} bytes", bytes.len());
    let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
    assert_eq!(records(&back), 1);
    assert_eq!(back, as_carried(&deleted));
    assert_eq!(back.read(), deleted.read());
    assert_eq!(order(&back), order(&deleted));
    assert_eq!(snapshot_bytes(&back), bytes);
    // the deleted run with its flag write taken out: a run of nothing but dots
    let v = osis_base::decode(&bytes, &osis_base::Limits::new(16, 1 << 20)).unwrap();
    let Value::List(mut top) = v else { panic!("snapshot") };
    let Value::List(f) = &mut top[3] else { panic!("fragment") };
    let Value::List(runs) = &mut f[3] else { panic!("runs") };
    let Value::List(r) = &mut runs[0] else { panic!("run") };
    r[5] = l(vec![]);
    let bare = osis_base::encode(&Value::List(top));
    assert!(decode_snapshot(&bare, &snap_cx(), &mut Interner::new(), None).is_err());
}

/// §4.2, §5.7, §6: writes landing inside a range record (an insert anchored in it, a move and an
/// undelete of one of its elements, a reset between its creations) split it only there, and
/// give the same state, read and order as the per-element state; the cached placement follows
/// each split (`seq_lin`: no whole pass), the reset aside.
#[test]
fn ranges_split_where_writes_land_spec_6() {
    let ranged = via_snapshot(&deleted_text());
    assert_eq!(records(&ranged), 1);
    let flat = expanded(&ranged);
    let x = st(3, 3, 1);
    let insert = one(x.dot.clone(), char_at(x.dot.clone(), 3, Anchor::Dot(Dot::new(node(1), 1000)), 'x'));
    let mv = one(Dot::new(node(1), 500), SeqElem { pos: vec![(st(4, 3, 2), Anchor::Head, None)], ..SeqElem::bare() });
    let undelete = one(Dot::new(node(1), 2000), SeqElem { deleted: Some((st(5, 3, 3), false)), undel: Some('u'), ..SeqElem::bare() });
    // creations of t = 1 below (1, node 1, 3000) go: a reset inside the chain
    let reset = seq_of(BTreeMap::new(), Some(st(1, 1, 3_000)));
    let (mut a, mut b) = (ranged.clone(), flat.clone());
    for (k, d) in [insert, mv, undelete, reset].into_iter().enumerate() {
        if k == 3 {
            assert_eq!(reads(&a), txt("xu"));
        }
        let _ = a.read();
        let _ = crate::seq_lin::probe();
        a.join(d.clone());
        if k < 3 {
            assert_eq!(crate::seq_lin::probe().1, 0, "join {k} followed, no whole pass");
            assert!(matches!(&a, Fragment::Seq(x) if x.lin_check() == Some(true)), "join {k} keeps the cache");
        }
        b.join(d);
        assert_eq!(a, b);
        assert_eq!(a.read(), b.read());
        assert_eq!(order(&a), order(&b));
        assert!(records(&a) <= 12, "{} records", records(&a));
    }
    // the reset pruned the undeleted char's creation, so only its flag revived (§5.7)
    assert_eq!(reads(&a), txt("x"));
    assert_eq!(via_snapshot(&a), as_carried(&a));
}

/// §4.7: a list range record whose elements' creations expire in part (two commits' counters in
/// one record, as a snapshot may carry them) strips like its elements.
#[test]
fn range_strips_like_its_elements_spec_4_7() {
    let at = |c: u64| if c == 1 { Anchor::Head } else { Anchor::Dot(Dot::new(node(1), c - 1)) };
    let el = |c: u64, span: u64| SeqElem { created: Some((st(1, 1, c), at(c))), pos: vec![(st(1, 1, c), at(c), None)], deleted: Some((st(2, 2, 1), true)), span, ..SeqElem::bare() };
    let list = |elems: BTreeMap<Dot, SeqElem>| Fragment::Seq(Seq::new(false, Meta::default(), elems));
    let ranged = list(BTreeMap::from([(Dot::new(node(1), 1), el(1, 4))]));
    let flat = list((1..=4).map(|c| (Dot::new(node(1), c), el(c, 1))).collect());
    let strip = |f: &Fragment| {
        let mut g = f.clone();
        g.strip(&|d| d.src == node(1) && d.ctr <= 2);
        expanded(&g)
    };
    assert_eq!(strip(&ranged), strip(&flat));
}

/// `op` applied by node 4 at t = 9: the delta and the joined state.
fn apply_op(f: &Fragment, op: crate::ops::Op) -> (Fragment, Fragment) {
    let mut b = crate::delta::DeltaBuilder::new(f, crate::ops::Writer::new(ts(9 << 16), node(4), 1));
    b.apply(&crate::ops::PathOp { path: vec![], op }, &crate::testutil::TyView(Ty::Text)).unwrap();
    let (d, _) = b.finish().unwrap();
    let s = joined(f, &d);
    (d, s)
}

/// §5.7 move, §6.1: elements anchored at virtual anchors (records a reset dropped) sit on END by
/// their anchors' dots, so moving a selection of them moves each; a state from a snapshot and one
/// built element by element give the same writes and read.
#[test]
fn move_over_virtual_anchors_spec_5_7() {
    let mut elems = chain(5);
    for (k, c) in "hello".chars().enumerate() {
        elems.get_mut(&Dot::new(node(1), k as u64 + 1)).unwrap().content = SeqContent::Char(c);
    }
    elems.insert(Dot::new(node(3), 1), char_at(Dot::new(node(3), 1), 3, Anchor::Dot(Dot::new(node(2), 5)), 'a'));
    elems.insert(Dot::new(node(3), 2), char_at(Dot::new(node(3), 2), 3, Anchor::Dot(Dot::new(node(2), 10)), 'x'));
    let flat = seq_of(elems, None);
    assert_eq!(reads(&flat), txt("helloax"));
    let (d1, s1) = apply_op(&flat, crate::ops::Op::Move { at: 5, len: 2, to: 0 });
    let (d2, s2) = apply_op(&via_snapshot(&flat), crate::ops::Op::Move { at: 5, len: 2, to: 0 });
    assert_eq!(d1, d2);
    assert_eq!(reads(&s1), txt("axhello"));
    assert_eq!(s1, s2);
    assert_eq!(order(&s1), order(&s2));
}

/// §6.1 sibling order: two children of one anchor whose chosen position writes carry one sibling
/// key (copies of one write, §4.1) go by dot ascending, whichever arrived first.
#[test]
fn equal_sibling_keys_go_by_dot_spec_6_1() {
    let key = st(3, 9, 1);
    let el = |b: u8, c: char| {
        let d = Dot::new(node(b), 1);
        let mut e = char_at(d.clone(), 1, Anchor::Head, c);
        e.pos.push((Stamp { ts: ts(5 << 16), dot: Dot::new(node(b), 2) }, Anchor::Head, Some(key.clone())));
        crate::seq::top2(&mut e.pos);
        (d, e)
    };
    let (lo, hi) = (el(2, 'a'), el(3, 'b'));
    assert!(lo.0 < hi.0);
    let f = joined(&one(hi.0.clone(), hi.1), &one(lo.0.clone(), lo.1));
    assert_eq!(order(&f), vec![lo.0, hi.0]);
    assert_eq!(reads(&f), txt("ab"));
}

/// The flag-only range `(node 2, 1..=10)` (deleted, created elsewhere) as one record, and the
/// same element by element.
fn flagged_ten() -> (Fragment, Fragment) {
    let flag = || SeqElem { deleted: Some((st(1, 2, 1), true)), ..SeqElem::bare() };
    let flat = seq_of((1..=10).map(|c| (Dot::new(node(2), c), flag())).collect(), None);
    (one(Dot::new(node(2), 1), SeqElem { span: 10, ..flag() }), flat)
}
/// Dot 1 of `Derived(node 2, 5)`.
fn derived_dot() -> Dot {
    Dot::new(crate::stamp::Source::derived(Dot::new(node(2), 5)).unwrap(), 1)
}

/// §2.2, §7: a `Derived(S, 5)` record sorts between `(S, 5)` and `(S, 6)`: joining one splits a
/// range of `S` there (`split_at`), and a range delta over it is cut there (`join_elems`).
#[test]
fn derived_keys_split_ranges_spec_7() {
    let (mut a, mut b) = flagged_ten();
    let emb = one(derived_dot(), char_at(derived_dot(), 4, Anchor::Head, 'q'));
    let flag = one(Dot::new(node(2), 1), SeqElem { deleted: Some((st(5, 5, 1), true)), span: 10, ..SeqElem::bare() });
    for d in [emb, flag] {
        a.join(d.clone());
        b.join(d);
        assert_eq!(a, b);
        alike(&a, &b);
    }
    assert_eq!(records(&a), 3);
}

/// §6.1: an element anchored at a `Derived(S, 5)` dot absent from the state sits under a
/// virtual anchor between `(S, 5)` and `(S, 6)` on END; a range of `S` places around it like
/// its elements do (hidden order included).
#[test]
fn virtual_derived_anchor_inside_range_spec_6_1() {
    let (mut a, mut b) = flagged_ten();
    let y = one(Dot::new(node(3), 1), char_at(Dot::new(node(3), 1), 4, Anchor::Dot(derived_dot()), 'y'));
    let z = one(Dot::new(node(3), 2), char_at(Dot::new(node(3), 2), 4, Anchor::Dot(Dot::new(node(2), 10)), 'z'));
    for d in [y, z] {
        a.join(d.clone());
        b.join(d);
    }
    assert_eq!(order(&a), order(&b));
    assert_eq!(reads(&a), txt("yz"));
    // a delete over the selection flags the same hidden elements
    let (d1, _) = apply_op(&a, crate::ops::Op::Delete { at: 0, len: 2 });
    let (d2, _) = apply_op(&b, crate::ops::Op::Delete { at: 0, len: 2 });
    assert_eq!(d1, d2);
}

/// §6.2: a creation chain whose first element anchors inside its own run is a cycle; as one
/// range record it breaks like its elements.
#[test]
fn chain_anchored_into_itself_spec_6_2() {
    let s0 = st(1, 1, 1);
    let at = Anchor::Dot(Dot::new(node(1), 3));
    let e = SeqElem { created: Some((s0.clone(), at.clone())), pos: vec![(s0, at, None)], deleted: Some((st(2, 2, 1), true)), span: 5, ..SeqElem::bare() };
    let a = joined(&one(Dot::new(node(1), 1), e), &one(Dot::new(node(3), 1), char_at(Dot::new(node(3), 1), 4, Anchor::Dot(Dot::new(node(1), 5)), 'v')));
    alike(&a, &expanded(&a));
    assert_eq!(reads(&a), txt("v"));
}

// spec/crdt.md §6.2: a received insert anchored at its own dot is a cycle of one, demoted to END
// and shown there; the cached placement used to hide it (fuzz: seq_follow).
#[test]
fn self_anchored_insert_placed_spec_6_2() {
    use crate::fuzzing::{seq_follow_cx, seq_follow_state};
    let hex = "002700845001010101010101010101010101010101808084098080818601028201818200026261628080";
    let data: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    let mut st = seq_follow_state();
    let [src, l0, l1, bytes @ ..] = &data[..] else { panic!() };
    assert_eq!(usize::from(u16::from_le_bytes([*l0, *l1])), bytes.len());
    let d = decode_delta(bytes, &seq_follow_cx(*src, 0), &mut Interner::new(), None).unwrap();
    let _ = st.read();
    st.join(d.fragment);
    crate::testutil::check_lin(&st);
    assert!(matches!(st.read(), Some(Value::Str(x)) if x.ends_with("ab")));
}

/// §6, §8 (pages are joined independently), `seq_place`: the placement of a sequence with no
/// records, stored and loaded in part, lists its dot map's first chunk, so a join's misses name
/// only chunks the stored form holds (the whole map had none; fuzz: seq_ops).
#[test]
fn empty_placement_held_in_part_follows_spec_6() {
    let (Fragment::Seq(d), _) = apply_op(&Fragment::default(), crate::ops::Op::Insert { at: 0, items: vec![s("ab")] }) else { panic!("a text delta") };
    let empty = Seq::empty(true);
    assert!(Pager::new(&empty, 1).whole.chunk(None).is_some(), "the first chunk is stored");
    // loads what the follow misses (it panicked loading a chunk the stored form lacked)
    let _ = partial_follow(&empty, &d, 1);
}

/// §6.1: a cached placement follows a delta moving element X (under p, by sibling key K, before
/// Z) and Y onto p, Y first, where X's writes after the join name p with a key below K (`second`:
/// a forged copy of X's chosen write, or an undo's restoring write): X sits by K until re-placed.
#[test]
fn moved_row_keeps_key_spec_6_1() {
    type Pos = Vec<(Stamp, Anchor, Option<Stamp>)>;
    let pa = Anchor::Dot(Dot::new(node(1), 1));
    let (c1, w5, w6) = (st(1, 1, 2), st(5, 3, 0), st(6, 3, 1));
    let check = |base_x: Pos, delta_x: Pos| {
        let (p, x, y) = (Dot::new(node(1), 1), c1.dot.clone(), Dot::new(node(1), 4));
        let mut elems = BTreeMap::new();
        elems.insert(p.clone(), char_at(p, 1, Anchor::Head, 'c'));
        let mut xe = char_at(x.clone(), 1, base_x[0].1.clone(), 'c');
        xe.pos = base_x;
        elems.insert(x.clone(), xe);
        elems.insert(Dot::new(node(1), 3), char_at(Dot::new(node(1), 3), 4, pa.clone(), 'c'));
        elems.insert(y.clone(), char_at(y.clone(), 1, Anchor::Head, 'c'));
        let mut cached = seq_of(elems, None);
        let _ = cached.read();
        let d = BTreeMap::from([(x, SeqElem { pos: delta_x, ..SeqElem::bare() }), (y, SeqElem { pos: vec![(st(3, 2, 1), pa.clone(), None)], ..SeqElem::bare() })]);
        cached.join(seq_of(d, None));
        crate::testutil::check_lin(&cached);
    };
    // X created at p (t1), moved to HEAD (t5), back to p (t6); concurrently an undo of t5 (t7:
    // back to p with key t1) and a move to HEAD (t8)
    check(vec![(w6.clone(), pa.clone(), None), (w5, Anchor::Head, None)], vec![(st(8, 4, 1), Anchor::Head, None), (st(7, 5, 1), pa.clone(), Some(c1.clone()))]);
    // forged: the delta's copy of X's chosen write t6 carries key t1, beside a move to HEAD
    check(vec![(w6.clone(), pa.clone(), None), (c1.clone(), pa.clone(), None)], vec![(st(8, 4, 1), Anchor::Head, None), (w6.clone(), pa.clone(), Some(c1.clone()))]);
    // forged: the copy alone (X stays under p, its key drops)
    check(vec![(w6.clone(), pa.clone(), None), (c1.clone(), pa.clone(), None)], vec![(w6, pa.clone(), Some(c1.clone()))]);
}

/// `base` read (its placement cached), then `d` joined: the cached placement is a whole pass
/// (`check_lin`), and the state places and reads as the element by element join does.
#[track_caller]
fn joins_as_flat(base: Fragment, d: Fragment) {
    let mut a = base.clone();
    let _ = a.read();
    a.join(d.clone());
    crate::testutil::check_lin(&a);
    alike(&a, &joined(&expanded(&base), &expanded(&d)));
}

/// §6.1 sibling order, `seq_lin`: a delta placing a new element N and moving X under one anchor
/// by one sibling key (X's write carries N's creation stamp as its key, as a forged copy may)
/// orders them by dot, N's below X's, though N is placed first.
#[test]
fn equal_keys_in_one_delta_go_by_dot_spec_6_1() {
    let (p, n, x) = (Dot::new(node(1), 1), Dot::new(node(2), 1), Dot::new(node(3), 1));
    let at_p = Anchor::Dot(p.clone());
    let base = seq_of(BTreeMap::from([(p.clone(), char_at(p, 1, Anchor::Head, 'p')), (x.clone(), char_at(x.clone(), 2, Anchor::Head, 'x'))]), None);
    let ne = char_at(n.clone(), 5, at_p.clone(), 'n');
    let key = ne.pos[0].0.clone();
    let mv = SeqElem { pos: vec![(st(6, 4, 1), at_p, Some(key))], ..SeqElem::bare() };
    let d = seq_of(BTreeMap::from([(n, ne), (x, mv)]), None);
    assert_eq!(reads(&joined(&base, &d)), txt("pnx"));
    joins_as_flat(base, d);
}

/// §4.2, §6, `seq_lin`: a range record over held records with a gap between them (elements
/// the state lacks) is partly new: the placement places the new elements too.
#[test]
fn range_over_a_gap_places_the_gap_spec_6() {
    let range = |c: u64, at: Anchor, span: u64| {
        let s = Stamp { ts: ts(1 << 16), dot: Dot::new(node(1), c) };
        SeqElem { created: Some((s.clone(), at.clone())), pos: vec![(s, at, None)], deleted: Some((st(2, 2, 1), true)), span, ..SeqElem::bare() }
    };
    let q = Dot::new(node(3), 1);
    let base = seq_of(BTreeMap::from([(Dot::new(node(1), 1), range(1, Anchor::Head, 4)), (Dot::new(node(1), 7), range(7, Anchor::Dot(Dot::new(node(1), 6)), 4)), (q.clone(), char_at(q, 3, Anchor::Head, 'q'))]), None);
    joins_as_flat(base, one(Dot::new(node(1), 1), range(1, Anchor::Head, 10)));
}

/// §2.2, §7, `seq_lin`: a new `Derived(S, 5)` record splits a range of `S` there; the cached
/// placement takes it as a whole pass does.
#[test]
fn derived_record_inside_a_range_places_spec_7() {
    let d = Dot::new(crate::stamp::Source::derived(Dot::new(node(1), 5)).unwrap(), 1);
    let emb = one(d.clone(), char_at(d, 4, Anchor::Head, 'q'));
    let ten = joined(&long_text(10), &one(Dot::new(node(1), 1), SeqElem { deleted: Some((st(2, 2, 1), true)), span: 10, ..SeqElem::bare() }));
    joins_as_flat(via_snapshot(&ten), emb);
}

/// A state's part at a delta's positions judges the delta as the whole state does (`covered`,
/// `Parts::kills`, spec/commits.md §5), and the part of paged pieces is the part of their join: for
/// any shape of delta, forged ones included. A false "joins unchanged" would lose history.
pub(crate) fn part_judges_as_whole(st: &Fragment, d: &Fragment, r: &mut crdt_model::r#gen::Rng) {
    let unchanged = |x: &Fragment| snapshot_bytes(&joined(x, d)) == snapshot_bytes(x);
    assert_eq!(crate::testutil::contains(st, d), joined(st, d) == *st, "the part judges as the whole");
    assert_eq!(unchanged(&st.part_at(d)), unchanged(st), "the part's bytes judge as the whole's");
    if let Fragment::Seq(s) = st {
        // pages of the state: whole records, each with its meta
        let mut pieces = vec![BTreeMap::new()];
        for (k, e) in s.elems() {
            if r.chance(1, 3) {
                pieces.push(BTreeMap::new());
            }
            pieces.last_mut().unwrap().insert(k.clone(), e.clone());
        }
        let mut from_pieces = Fragment::default();
        for p in pieces {
            from_pieces.join(Fragment::Seq(Seq::new(s.text, s.meta.clone(), p)).part_at(d));
        }
        assert_eq!(unchanged(&from_pieces), unchanged(st), "pieces' part judges as the whole");
    }
    // what a join of the source's part kills of a fragment, as `Parts::kills` keeps them
    let kills = |x: Fragment| d.winners().minus(&joined(d, &x).winners());
    assert_eq!(kills(st.part_at(d)), kills(st.clone()), "a source's part kills as the source");
}

/// §3.3 rule 3: runs past `MAX_RUN` (a creation chain longer than a run, deleted stretches as
/// range records of more than `MAX_RUN`) encode byte-identically with the model and round trip,
/// and a reset above them all leaves nothing.
#[test]
fn long_runs_match_model_spec_3_3() {
    use crdt_model::stamp::{Dot as MDot, Stamp as MStamp};
    use crdt_model::state::{Anchor as MAnchor, Composite, SeqElem as MElem};
    let src = MSource::session(1, 0);
    let n = crate::MAX_RUN + 1000;
    let mut elems = BTreeMap::new();
    let mut a = MAnchor::Head;
    for c in 1..=n {
        let d = MDot { source: src.clone(), ctr: c };
        let s = MStamp { ts: 3 << 16, dot: d.clone() };
        elems.insert(d.clone(), MElem::new(s, a, Content::Char('a')));
        a = MAnchor::Dot(d);
    }
    let mut state = Some(MFrag::Seq { text: true, c: Composite::default(), elems });
    let by2 = |t: u64, ctr: u64| MStamp { ts: t << 16, dot: MDot { source: MSource::session(2, 0), ctr } };
    let seq = |c: Composite, elems: BTreeMap<MDot, MElem>| MFrag::Seq { text: true, c, elems };
    // a delete of most of it, a move inside the deleted stretch, then a reset above it all
    let del = (10..n - 10).map(|c| (MDot { source: src.clone(), ctr: c }, MElem::write(Content::None, vec![], Some((by2(5, 1), true)))));
    mapply(&mut state, seq(Composite::default(), del.collect()));
    let mv = MElem::write(Content::None, vec![(by2(6, 2), MAnchor::Head, None)], None);
    mapply(&mut state, seq(Composite::default(), BTreeMap::from([(MDot { source: src.clone(), ctr: 2000 }, mv)])));
    for reset in [false, true] {
        if reset {
            mapply(&mut state, seq(Composite { reset: Some(by2(7, 3)), w: None, w_valueless: false }, BTreeMap::new()));
        }
        let st = state.as_ref().unwrap();
        let ours = frag(st);
        let bytes = snapshot_bytes(&ours);
        assert!(bytes == m_encode_snapshot(st, &[], [0; 16], &mut Ctx::new(1 << 40, MSource::session(250, 0), 1)), "snapshot bytes equal the model's (reset {reset})");
        let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
        assert_eq!(back, as_carried(&ours));
        assert_eq!(back.read(), ours.read());
    }
}

/// §4.6, §4.7: an undelete's char is its own writer's value: un-merging the element's creator
/// keeps it with the undelete (`holds_dots` still sees the record).
#[test]
fn unmerge_keeps_undelete_char_spec_4_7() {
    let flag = Stamp { ts: ts(9), dot: Dot { src: node(2), ctr: 1 } };
    let el = SeqElem { deleted: Some((flag.clone(), false)), undel: Some('x'), ..SeqElem::bare() };
    let mut f = one(Dot { src: node(1), ctr: 5 }, el);
    assert!(f.holds_dots(&|d| d.src == node(1)));
    f.remove_writes(&|d| d.src == node(1));
    let Fragment::Seq(s) = &f else { panic!("a sequence") };
    let left: Vec<_> = s.elems().values().map(|e| (e.deleted.clone(), e.undel)).collect();
    assert_eq!(left, vec![(Some((flag, false)), Some('x'))]);
}

// spec: none (costs, spec/requirements.md Scale): a sequence's part at a delta's positions holds
// the records with its dots, not the sequence: a `covered` costs about the body's records.
#[test]
fn part_at_a_sequence_is_the_deltas_records() {
    let dot = |ctr: u64| Dot { src: node(1), ctr };
    let rec = |ctr: u64| (dot(ctr), char_at(dot(ctr), 1, Anchor::Head, 'x'));
    let whole = seq_of((0..1000).map(|c| rec(2 * c)).collect(), None);
    let delta = seq_of([rec(1000), rec(1002)].into(), None);
    let Fragment::Seq(part) = whole.part_at(&delta) else { panic!("a sequence's part is one") };
    assert_eq!(part.elems().keys().cloned().collect::<Vec<_>>(), vec![dot(1000), dot(1002)]);
    assert!(crate::testutil::contains(&whole, &delta));
}

// §6.1, §4.6: a sequence's order is computed from valid writes only. The read of the bodies
// held, each without the invalid writes, equals the read of the valid bodies alone, in either
// arrival order: an invalid insert's elements do not exist for ordering, so what anchors at them
// sits at their virtual place on `END`, as at a node that never received them.
mod valid_order {
    use super::*;
    use crdt_model::value::Value as MValue;

    /// The model state after joining `ds` (a writer's view).
    fn view(ds: &[&MFrag]) -> MFrag {
        let mut m = None;
        for d in ds {
            mapply(&mut m, (*d).clone());
        }
        m.expect("a view")
    }
    /// Reads the bodies, each without node `bad`'s writes, in order and reversed; both equal the
    /// read of the other bodies alone.
    fn read_valid(bodies: &[&MFrag], bad: u8) -> Option<Value> {
        let bad = source(&MSource::session(bad, 0));
        let held = |order: &mut dyn Iterator<Item = &&MFrag>| {
            let mut st = Fragment::default();
            for b in order {
                let mut f = frag(b);
                f.remove_writes(&|d| d.src == bad);
                st.join(f);
            }
            st
        };
        let all = held(&mut bodies.iter());
        assert_eq!(all, held(&mut bodies.iter().rev()), "order-independent");
        let mut valid = Fragment::default();
        for b in bodies {
            let f = frag(b);
            if !f.holds_dots(&|d| d.src == bad) {
                valid.join(f);
            }
        }
        assert_eq!(all.read(), valid.read(), "as if the invalid bodies were never held");
        all.read()
    }
    fn text(x: &str) -> Option<Value> {
        Some(Value::Str(x.into()))
    }

    #[test]
    fn insert_after_an_invalid_insert_is_placed() {
        let (m, _) = typed("ab");
        let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 1, chars("X"));
        let seen = view(&[&m, &x]);
        // y after X, at a node that held X valid
        let y = mops::seq_insert(&mut mw(3, 3), Some(&seen), true, 2, chars("y"));
        assert_eq!(read_valid(&[&m, &x, &y], 9), text("aXyb"), "all valid");
        assert_eq!(read_valid(&[&m, &x, &y], 2), text("aby"), "X invalid: y at X's place on END");
    }

    #[test]
    fn chain_and_siblings_under_an_invalid_insert_keep_their_order() {
        let (m, _) = typed("ab");
        let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 1, chars("X"));
        let y = mops::seq_insert(&mut mw(3, 3), Some(&view(&[&m, &x])), true, 2, chars("y"));
        let z = mops::seq_insert(&mut mw(4, 4), Some(&view(&[&m, &x, &y])), true, 3, chars("z"));
        // a newer sibling of y at X goes nearer X (§6.1)
        let w = mops::seq_insert(&mut mw(5, 5), Some(&view(&[&m, &x, &y])), true, 2, chars("w"));
        let all = [&m, &x, &y, &z, &w];
        assert_eq!(read_valid(&all, 9), text("aXwyzb"));
        assert_eq!(read_valid(&all, 2), text("abwyz"));
    }

    #[test]
    fn list_insert_after_an_invalid_insert_is_placed() {
        let int = |w: &mut MWriter, i: i64| Content::Frag(Box::new(mops::create(w, &Ty::Register, &MValue::Int(i))));
        let mut a = mw(1, 1);
        let c = vec![int(&mut a, 1), int(&mut a, 2)];
        let mut m = mops::seq_insert(&mut a, None, false, 0, c);
        m.prune(None);
        let mut b = mw(2, 2);
        let c = vec![int(&mut b, 7)];
        let x = mops::seq_insert(&mut b, Some(&m), false, 1, c);
        let mut cw = mw(3, 3);
        let c = vec![int(&mut cw, 3)];
        let y = mops::seq_insert(&mut cw, Some(&view(&[&m, &x])), false, 2, c);
        let list = |v: &[i64]| Some(Value::List(v.iter().map(|i| Value::Int(*i)).collect()));
        assert_eq!(read_valid(&[&m, &x, &y], 9), list(&[1, 7, 3, 2]));
        assert_eq!(read_valid(&[&m, &x, &y], 2), list(&[1, 2, 3]));
    }

    /// An aspect whose only writes are invalid reads absent, as at a node that never held them
    /// (no record of theirs is left to make it present).
    #[test]
    fn only_invalid_inserts_read_absent() {
        let x = mops::seq_insert(&mut mw(2, 2), None, true, 0, chars("X"));
        assert_eq!(read_valid(&[&x], 2), None);
    }

    /// An invalid move changes nothing.
    #[test]
    fn invalid_move_changes_nothing() {
        let (m, _) = typed("abc");
        let mv = mops::seq_move(&mut mw(2, 2), &m, 0, 1, 2).unwrap();
        assert_eq!(read_valid(&[&m, &mv], 9), text("bca"));
        assert_eq!(read_valid(&[&m, &mv], 2), text("abc"));
    }

    /// A valid move of an invalid element places it (content-less), with what anchors at it.
    #[test]
    fn valid_move_of_an_invalid_element_places_it() {
        let (m, _) = typed("ab");
        let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 1, chars("X"));
        let mv = mops::seq_move(&mut mw(3, 3), &view(&[&m, &x]), 1, 1, 2).unwrap();
        let after = view(&[&m, &x, &mv]);
        let y = mops::seq_insert(&mut mw(4, 4), Some(&after), true, 3, chars("y"));
        let c = mops::seq_insert(&mut mw(5, 5), Some(&after), true, 1, chars("c"));
        let all = [&m, &x, &mv, &y, &c];
        assert_eq!(read_valid(&all, 9), text("acbXy"));
        assert_eq!(read_valid(&all, 2), text("acby"));
    }

    /// Invalid flag writes change nothing: an undelete over a valid delete, a delete.
    #[test]
    fn invalid_flags_change_nothing() {
        let (m, _) = typed("ab");
        let d = mops::seq_delete(&mut mw(3, 2), &m, 0, 1).unwrap();
        let seen = view(&[&m, &d]);
        let MFrag::Seq { elems, .. } = &seen else { panic!() };
        let a = elems.keys().next().unwrap().clone();
        let u = mops::seq_undelete(&mut mw(2, 3), &seen, &[a]);
        assert_eq!(read_valid(&[&m, &d, &u], 9), text("ab"));
        assert_eq!(read_valid(&[&m, &d, &u], 2), text("b"));
        let bd = mops::seq_delete(&mut mw(2, 4), &m, 1, 1).unwrap();
        assert_eq!(read_valid(&[&m, &bd], 2), text("ab"));
    }

    /// A reset prunes an older insert anchored at an invalid one; a newer one survives at the
    /// virtual anchor, whether the invalid insert is older or newer than the reset.
    #[test]
    fn reset_over_an_invalid_insert() {
        let (m, _) = typed("ab");
        let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 1, chars("X"));
        let seen = view(&[&m, &x]);
        let y_old = mops::seq_insert(&mut mw(3, 3), Some(&seen), true, 2, chars("o"));
        let r = mops::replace(&mut mw(1, 5), &Ty::Text, &MValue::Str("Z".into()));
        let y = mops::seq_insert(&mut mw(4, 6), Some(&seen), true, 2, chars("y"));
        let all = [&m, &x, &y_old, &r, &y];
        assert_eq!(read_valid(&all, 9), text("Zy"));
        assert_eq!(read_valid(&all, 2), text("Zy"));
        // Bob's insert newer than the reset
        let x2 = mops::seq_insert(&mut mw(2, 7), Some(&view(&[&m, &r])), true, 1, chars("X"));
        let y2 = mops::seq_insert(&mut mw(4, 8), Some(&view(&[&m, &r, &x2])), true, 2, chars("y"));
        let all = [&m, &r, &x2, &y2];
        assert_eq!(read_valid(&all, 9), text("ZXy"));
        assert_eq!(read_valid(&all, 2), text("Zy"));
    }

    /// An invalid reset changes nothing.
    #[test]
    fn invalid_reset_changes_nothing() {
        let (m, _) = typed("ab");
        let r = mops::replace(&mut mw(2, 5), &Ty::Text, &MValue::Str("Z".into()));
        let y = mops::seq_insert(&mut mw(4, 6), Some(&m), true, 1, chars("y"));
        let all = [&m, &r, &y];
        assert_eq!(read_valid(&all, 9), text("Zy"));
        assert_eq!(read_valid(&all, 2), text("ayb"));
    }

    /// An expired insert keeps its place (§4.7); once invalid too, it leaves nothing.
    #[test]
    fn expired_then_invalid_insert_leaves_nothing() {
        let (m, _) = typed("ab");
        let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 1, chars("X"));
        let y = mops::seq_insert(&mut mw(3, 3), Some(&view(&[&m, &x])), true, 2, chars("y"));
        let bad = source(&MSource::session(2, 0));
        let mut xs = frag(&x);
        xs.strip(&|d| d.src == bad);
        let mut st = Fragment::default();
        for f in [frag(&m), xs.clone(), frag(&y)] {
            st.join(f);
        }
        assert_eq!(reads(&st), txt("ayb"), "expired: X keeps its place, no char");
        let mut un = Fragment::default();
        for mut f in [frag(&m), xs, frag(&y)] {
            f.remove_writes(&|d| d.src == bad);
            un.join(f);
        }
        assert_eq!(un, after(&frag(&m), &[&y]), "expired then invalid: as never held");
    }
}

/// spec/commits.md §5 (live writes: a sequence element record counts for its creator while it
/// holds the creation): node 1 types a char, node 2 deletes it at t = 3, a reset at t = 2 prunes
/// the creation; the record stays for the delete flag, which is node 2's live write, and holds
/// none of node 1's.
#[test]
fn a_record_without_its_creation_holds_no_live_write_of_its_creator_spec_commits_5() {
    let d = Dot::new(node(1), 1);
    let mut f = one(d.clone(), char_at(d.clone(), 1, Anchor::Head, 'a'));
    f.join(one(d.clone(), SeqElem { deleted: Some((st(3, 2, 1), true)), ..SeqElem::bare() }));
    f.join(seq_of(BTreeMap::new(), Some(st(2, 3, 1))));
    f.prune(None, &mut crate::Changes::new());
    assert_eq!(records(&f), 1, "the record stays for its delete flag");
    let of = |b: u8| move |s: &crate::stamp::Source, _: u64, _: u64| *s == node(b);
    assert!(f.holds_owned_write(&of(2)), "the delete is node 2's live write");
    assert!(!f.holds_owned_write(&of(1)), "the creation is gone: no live write of node 1");
    let ours = |w: Vec<(Dot, Option<osis_base::Ts>)>| w.iter().any(|(x, _)| x.src == node(1));
    assert!(ours(f.writes()) && !ours(f.live_writes()), "live_writes agrees");
}

/// spec/crdt.md §4.8: a join that splits a range record (a delete of one of its elements, older
/// or newer than the record's own delete), or joins a range record over pieces of itself (a join
/// never merges records, so the pieces stay apart), supersedes at its reach before and after what it supersedes in the whole
/// state (`Fragment::reach_after`: the engine dates deaths there, and a death with no superseder
/// is `Corrupt`). Each element of a three-element range, a text and a list, alone, in a struct
/// and in a map entry.
#[test]
fn a_join_splitting_a_range_record_supersedes_at_its_reach_what_it_does_whole_spec_4_8() {
    use crdt_model::value::Value as MValue;
    let wrap = |how: usize, f: Fragment| match how {
        0 => f,
        1 => Fragment::Struct(crate::fragment::Struct { meta: Meta::default(), fields: [(4, f)].into_iter().collect() }),
        _ => {
            let e = crate::fragment::Eid::new(Dot::new(node(9), 1), Some(Value::Int(7)));
            let entry = crate::fragment::Entry { reset: None, frag: Some(Box::new(f)), created: Some(Stamp::new(ts(1), node(9), 1)) };
            Fragment::Map(crate::fragment::Map::new(Meta::default(), [(e, entry)].into_iter().collect()))
        }
    };
    let ranged = |f: &Fragment| matches!(f, Fragment::Seq(s) if s.elems().values().any(|e| e.span > 1));
    for text in [true, false] {
        let ty = if text { Ty::Text } else { Ty::List(Box::new(Ty::Register)) };
        let v = if text { MValue::Str("abc".into()) } else { MValue::List(vec![MValue::Int(1), MValue::Int(2), MValue::Int(3)]) };
        let mut m0 = mops::create(&mut mw(1, 1), &ty, &v);
        m0.prune(None);
        for (t1, t2) in [(5, 9), (9, 5)] {
            let range = frag(&mops::seq_delete(&mut mw(3, t2), &m0, 0, 3).unwrap());
            assert!(ranged(&range), "the delete is one range record");
            for hit in 0..3 {
                let one = frag(&mops::seq_delete(&mut mw(2, t1), &m0, hit, 1).unwrap());
                // the range's own delete without element `hit`, the range joined over it
                let Fragment::Seq(rs) = &range else { unreachable!() };
                let mut gap = crate::seq_span::expand(rs.elems().clone());
                gap.retain(|d, _| d.ctr != hit as u64 + 1);
                let gap = Fragment::Seq(Seq::new(text, Meta::default(), crate::seq_span::coalesce(gap)));
                for (before, y, split) in [(&range, &one, true), (&gap, &range, false)] {
                    assert!(!split || records(&joined(before, y)) > records(before), "the join splits the range record");
                    for how in 0..3 {
                        let (before, y) = (wrap(how, before.clone()), wrap(how, y.clone()));
                        let after = joined(&before, &y);
                        crate::tests_model::reach_holds_the_change(&before, &after, &y, true);
                    }
                }
            }
        }
    }
}

/// spec/commits.md §5, spec/crdt.md §4.8: the deaths of a join read at its reach before and after
/// (as `Killed::note` reads them) are dated each by its own superseder, never an earlier write on
/// another element of the same range record the wider reach after a split takes in: a range
/// delete at t5, then its first element deleted again at t9, then its last at t12.
#[test]
fn each_element_of_a_split_range_record_dies_at_its_own_delete_spec_commits_5() {
    use crdt_model::value::Value as MValue;
    let mut m0 = mops::create(&mut mw(1, 1), &Ty::Text, &MValue::Str("abc".into()));
    m0.prune(None);
    let mut st = frag(&mops::seq_delete(&mut mw(3, 5), &m0, 0, 3).unwrap());
    for (i, (t, hit)) in [(9, 0usize), (12, 2)].into_iter().enumerate() {
        let y = frag(&mops::seq_delete(&mut mw(4, t), &m0, hit, 1).unwrap());
        let at = st.reach(&y);
        let mut before = at.winners();
        before.extend(y.winners());
        let after = joined(&st, &y);
        let won = after.reach_after(&y, &at).winners();
        let dead = before.minus(&won);
        let mut by = crate::winners::ByWrite::<()>::default();
        by.note(&before, |_, _| ());
        by.note(&won, |_, _| ());
        let item = Dot::new(source(&MSource::session(1, 0)), hit as u64 + 1);
        assert_eq!(dead.len(), 1, "join {i}: one write dies");
        for w in &dead {
            assert_eq!(w.path.last(), Some(&crate::winners::Place::Item(item.clone())), "join {i}: the hit element's");
            assert_eq!(by.first_superseding(w, |s, _| Some(s.ts)), Some(ts(t << 16)), "join {i}: dated by its own delete");
        }
        st = after;
    }
}

/// spec/crdt.md §4.8 When, spec/commits.md §5: a move stamped below its element's creation (a
/// writer's clock behind) held alone wins; a snapshot carrying the creation and a later delete
/// kills it, the creation superseding it though it wins nowhere (the delete beats it). Its death
/// is dated by the creation, the earliest write held that supersedes it, never by the delete.
#[test]
fn a_move_below_its_creation_dies_at_the_creation_though_a_delete_beats_it_spec_4_8() {
    let d = Dot::new(node(1), 1);
    let mv = SeqElem { pos: vec![(st(5, 2, 1), Anchor::Head, None)], ..SeqElem::bare() };
    let state = one(d.clone(), mv);
    let y = one(d.clone(), SeqElem { deleted: Some((st(20, 3, 1), true)), ..char_at(d.clone(), 10, Anchor::Head, 'a') });
    let at = state.reach(&y);
    let mut before = at.winners();
    before.extend(y.winners());
    let after = joined(&state, &y);
    let dead = before.minus(&after.reach_after(&y, &at).winners());
    assert_eq!(dead.iter().map(|w| w.kind).collect::<Vec<_>>(), vec![crate::winners::Kind::Pos], "the move dies");
    let w = dead.first().unwrap();
    let mut winning = crate::winners::ByWrite::<()>::default();
    winning.note(&before, |_, _| ());
    winning.note(&after.winners(), |_, _| ());
    assert_eq!(winning.first_superseding(w, |s, _| Some(s.ts)), None, "no winning write supersedes it");
    let mut held = crate::winners::ByWrite::<()>::default();
    held.note(&at.held_writes(), |_, _| ());
    held.note(&y.held_writes(), |_, _| ());
    assert_eq!(held.first_superseding(w, |s, _| Some(s.ts)), Some(ts(10 << 16)), "dated by the creation");
    crate::tests_model::reach_holds_the_change(&state, &after, &y, true);
}

/// The writes a join of `y` into `state` kills, each with its date read as `Killed::note` reads
/// it (the held writes at the reach before the join and in `y`), after the reach law holds.
fn deaths_dated(state: &Fragment, y: &Fragment) -> Vec<(crate::winners::Kind, Option<osis_base::Ts>)> {
    let at = state.reach(y);
    let mut before = at.winners();
    before.extend(y.winners());
    let after = joined(state, y);
    crate::tests_model::reach_holds_the_change(state, &after, y, true);
    let mut held = crate::winners::ByWrite::<()>::default();
    let at_after = after.reach_after(y, &at);
    held.note(&at.held_writes(), |_, _| ());
    held.note(&y.held_writes(), |_, _| ());
    held.note(&at_after.held_writes(), |_, _| ());
    before.minus(&at_after.winners()).iter().map(|w| (w.kind, held.first_superseding(w, |s, _| Some(s.ts)))).collect()
}

/// spec/crdt.md §2.3, §4.8, §5.7 Join (a forged copy: the creator repeats its element's counter
/// on a later move): the move stamped with the element's own dot, above the creation, is a
/// position write of its own, not the creation's, so a move it beats dies by it.
#[test]
fn a_move_beaten_by_a_move_stamped_with_the_elements_dot_dies_by_it_spec_4_8() {
    let (a, b) = (Dot::new(node(1), 1), Dot::new(node(1), 2));
    let mut e = char_at(a.clone(), 10, Anchor::Head, 'a');
    e.pos.insert(0, (st(30, 1, 1), Anchor::Dot(b.clone()), None));
    let state = seq_of(BTreeMap::from([(a.clone(), e), (b.clone(), char_at(b.clone(), 10, Anchor::Dot(a.clone()), 'b'))]), None);
    let y = one(a.clone(), SeqElem { pos: vec![(st(20, 2, 1), Anchor::Head, None)], ..SeqElem::bare() });
    assert_eq!(deaths_dated(&state, &y), vec![(crate::winners::Kind::Pos, Some(ts(30 << 16)))]);
}

/// spec/crdt.md §2.3, §4.8: a forged copy as above, in a delta without the creation: the
/// move stamped with the element's dot reads as the creation's own in the delta alone, and as a
/// move of its own once joined beside the creation, where it beats the state's move: that move
/// dies by it (the engine reads the held writes at the reach after the join too).
#[test]
fn a_move_stamped_with_the_elements_dot_in_a_delta_without_the_creation_kills_by_itself_spec_4_8() {
    let (a, b) = (Dot::new(node(1), 1), Dot::new(node(1), 2));
    let mut e = char_at(a.clone(), 10, Anchor::Head, 'a');
    e.pos.insert(0, (st(20, 2, 1), Anchor::Dot(b.clone()), None));
    let state = seq_of(BTreeMap::from([(a.clone(), e), (b.clone(), char_at(b.clone(), 10, Anchor::Dot(a.clone()), 'b'))]), None);
    let y = one(a.clone(), SeqElem { pos: vec![(st(30, 1, 1), Anchor::Head, None)], ..SeqElem::bare() });
    assert_eq!(deaths_dated(&state, &y), vec![(crate::winners::Kind::Pos, Some(ts(30 << 16)))]);
}
