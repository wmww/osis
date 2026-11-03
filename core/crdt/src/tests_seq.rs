//! Sequences (spec/crdt.md §5.7, §6): differential join/read and wire against core/test/crdt-model, run
//! rejections, the worked examples of notes/crdt.md.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::fragment::Meta;
use crate::linearize::place;
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::seq_span::{expand, nth};
use crate::stamp::{Dot, Source, Stamp};
use std::collections::BTreeMap;
use crate::stamp::{CounterRange, Interner};
use crate::testutil::{frag, history, history_with, mapply, source, ts};
use crate::tests_join::lockstep;
pub(crate) use crate::testutil::{Pager, partial_follow, partial_follow_in};
use crate::tests_wire::{delta, i, l, rejects, snap_cx, wcx, writer_cx};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Frontiers, Snapshot};
use crdt_model::r#gen::kitchen_sink;
use crdt_model::ops::{self as mops, Ty, Writer as MWriter};
use crdt_model::stamp::Source as MSource;
use crdt_model::state::{Content, Frag as MFrag};
use crdt_model::wire::{Ctx, encode_delta as m_encode_delta, encode_snapshot as m_encode_snapshot};
use osis_base::{ErrorClass, Value};
use proptest::prelude::*;

fn inner() -> Ty {
    Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())
}

proptest! {
    /// §5.7, §6: text join and read equal the model's under random delivery and duplication.
    #[test]
    fn text_join_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::Text], 3, 5);
    }

    /// §5.7 Read, §6: a list's read (elements in placement order, which moves and inserts at
    /// random places take far from dot order) equals the model's after every join.
    #[test]
    fn list_read_order_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::List(Box::new(Ty::Register))], 4, 10);
    }

    /// §5.7: list join (element resets, nested fragments) equals the model's.
    #[test]
    fn list_join_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::List(Box::new(inner()))], 3, 6);
    }

    /// §5.7 nested in every other encoding.
    #[test]
    fn kitchen_sink_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[kitchen_sink()], 2, 4);
    }

    /// §7: register and text at one position (embedded characters, Derived anchors).
    #[test]
    fn text_slots_match_model_spec_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::Register, Ty::Text, Ty::List(Box::new(Ty::Register))], 3, 6);
    }

    /// §3.2 Run, §3.3: sequence deltas and snapshots encode byte-identically with the model.
    #[test]
    fn seq_wire_matches_model_spec_3_2(seed in any::<u64>()) {
        let types = [Ty::Text, Ty::List(Box::new(inner()))];
        wire_matches(seed, &types, (1..=3).map(MSource::node).collect());
    }

    /// §3.3 rule 2: commit form.
    #[test]
    fn seq_wire_commit_form_spec_3_3(seed in any::<u64>()) {
        let sources = [0x80u8, 0x10, 0xf0].iter().map(|b| MSource::Commit([*b; 32])).collect();
        wire_matches(seed, &[Ty::Text, Ty::List(Box::new(Ty::Register))], sources);
    }

    /// §7: snapshots carry embedded characters (Derived sources).
    #[test]
    fn seq_wire_slots_spec_7(seed in any::<u64>()) {
        wire_matches(seed, &[Ty::Register, Ty::Text], (1..=3).map(MSource::node).collect());
    }

    /// §4.7: strip of text and list states equals the model's and commutes with join.
    #[test]
    fn seq_expiry_laws_spec_4_7(seed in any::<u64>()) {
        crate::tests_life::expiry_laws(seed, &Ty::Text);
        crate::tests_life::expiry_laws(seed, &Ty::List(Box::new(inner())));
    }

    /// §4.6: un-merge of text and list (created elements stay as hidden anchors).
    #[test]
    fn seq_unmerge_spec_4_6(seed in any::<u64>()) {
        crate::tests_life::unmerge_check(seed, &Ty::Text);
        crate::tests_life::unmerge_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §4.8: `remove_writes` of text and list states, rejoined with the commits, is the state.
    #[test]
    fn seq_remove_writes_rejoins_spec_4_8(seed in any::<u64>()) {
        crate::tests_life::remove_writes_check(seed, &Ty::Text);
        crate::tests_life::remove_writes_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §4.8: a dead text or list write is a joined side's by exact stamp.
    #[test]
    fn seq_deaths_held_by_stamp_spec_4_8(seed in any::<u64>()) {
        crate::tests_life::holds_stamp_check(seed, &Ty::Text);
        crate::tests_life::holds_stamp_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §4.8: a deleted text creation dies whichever way its record arrives (new or held, at any
    /// depth).
    #[test]
    fn deleted_creation_dies_in_any_order_spec_4_8(seed in any::<u64>()) {
        crate::tests_life::deleted_creation_dies_check(seed, &Ty::Text);
        crate::tests_life::deleted_creation_dies_check(seed, &Ty::Map(Box::new(Ty::Register), Box::new(Ty::Text)));
        crate::tests_life::deleted_creation_dies_check(seed, &Ty::List(Box::new(Ty::Struct([(1, Ty::Text)].into_iter().collect()))));
    }

    /// spec/permissions.md §5.2: `copies_within` and `strip_copies` of text and list states.
    #[test]
    fn seq_copies_agree_and_rejoin_spec_perm_5_2(seed in any::<u64>()) {
        crate::tests_life::copies_check(seed, &Ty::Text);
        crate::tests_life::copies_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §8: bootstrap from a text or list snapshot, then concurrent edits, converges.
    #[test]
    fn seq_bootstrap_then_edit_spec_8(seed in any::<u64>()) {
        crate::tests_life::bootstrap_check(seed, &Ty::Text);
        crate::tests_life::bootstrap_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §5.7 undelete: random deleted chars undeleted with their content reach a node that only
    /// holds the snapshot (deleted chars not carried) and read the same there.
    #[test]
    fn random_undelete_spec_5_7(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history_with(&mut r, &[Ty::Text], vec![MSource::node(1), MSource::node(2)], 6);
        let mut full = Fragment::default();
        for c in &commits {
            full.join(frag(&c.delta));
        }
        let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: full.clone(), frontiers: Frontiers::default() };
        let bytes = encode_snapshot(&snap, &snap_cx(), None).unwrap();
        let mut boot = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
        let Fragment::Seq(sq) = &full else { return Ok(()) };
        let dead: Vec<crate::stamp::Dot> = sq.elems().iter().filter(|(_, e)| e.flag() && matches!(e.content, SeqContent::Char(_))).map(|(d, _)| d.clone()).filter(|_| r.chance(1, 2)).collect();
        if dead.is_empty() {
            return Ok(());
        }
        let src = crate::stamp::Source::node(osis_base::Tid::from_bytes([7; 15]));
        let st = crate::stamp::Stamp::new(ts(1 << 30), src.clone(), 1);
        let mut d = crate::seq::Seq::empty(true);
        for x in &dead {
            let mut e = crate::seq::SeqElem::bare();
            e.deleted = Some((st.clone(), false));
            e.undel = sq.elems()[x].char();
            d.elems_mut().insert(x.clone(), e);
        }
        let cx = DeltaCtx { ts: ts(1 << 30), own: src, range: CounterRange { lo: 1, hi: 2 }, kind: DeltaKind::Writer };
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: Fragment::Seq(d) }, &cx, None).unwrap();
        let u = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment;
        full.join(u.clone());
        boot.join(u);
        prop_assert_eq!(full.read(), boot.read());
        // the bootstrapped node holds the undelete's copy of each char, the full one both copies
        let mut j = full.clone();
        j.join(boot);
        prop_assert_eq!(j, full);
    }

    /// §3.3 rule 7: mutated sequence deltas are rejected or decode, never panic.
    #[test]
    fn mutated_seq_delta_never_panics_spec_3_3(seed in any::<u64>(), pos in any::<usize>(), byte in any::<u8>()) {
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history_with(&mut r, &[Ty::Text, Ty::List(Box::new(inner()))], vec![MSource::node(1), MSource::node(2)], 3);
        let mut state = Fragment::default();
        for c in &commits {
            let cx = writer_cx(&c.w);
            let mut bytes = encode_delta(&Delta { nonce: [1; 16], fragment: frag(&c.delta) }, &cx, None).unwrap();
            let p = pos % bytes.len();
            bytes[p] = byte;
            if let Ok(d) = decode_delta(&bytes, &cx, &mut Interner::new(), None) {
                state.join(d.fragment);
                let _ = state.read();
            }
        }
    }
}

/// §6.2: cycle breaking is linear. Adversarial graph: a chain of 20,000 plus 20,000 mutual-`cur`
/// pairs whose `prev` is the chain's tail (each victim's new edge walks into the chain).
#[test]
fn cycle_breaking_is_linear_spec_6_2() {
    use crate::seq::{Anchor, SeqElem};
    use crate::stamp::{Dot, Source, Stamp};
    let (len, k) = (20_000u64, 20_000u64);
    let a = Source::node(osis_base::Tid::from_bytes([1; 15]));
    let st = |t: u64, c: u64| Stamp::new(ts(t << 16), a.clone(), c);
    let mut elems = std::collections::BTreeMap::new();
    let mut prev = Anchor::Head;
    for c in 1..=len {
        let s = st(1, c);
        elems.insert(Dot::new(a.clone(), c), SeqElem { created: Some((s.clone(), prev.clone())), content: SeqContent::Char('x'), pos: vec![(s, prev.clone(), None)], deleted: None, undel: None, span: 1 });
        prev = Anchor::Dot(Dot::new(a.clone(), c));
    }
    let tail = prev;
    let (mut c, mut m) = (len + 1, 10_000_000u64);
    for _ in 0..k {
        let (x, y) = (Dot::new(a.clone(), c), Dot::new(a.clone(), c + 1));
        let (cx, cy, mx, my) = (st(2, c), st(2, c + 1), st(3, m), st(3, m + 1));
        c += 2;
        m += 2;
        elems.insert(x.clone(), SeqElem { created: Some((cx.clone(), tail.clone())), content: SeqContent::Char('a'), pos: vec![(mx, Anchor::Dot(y.clone()), None), (cx, tail.clone(), None)], deleted: None, undel: None, span: 1 });
        elems.insert(y.clone(), SeqElem { created: Some((cy.clone(), tail.clone())), content: SeqContent::Char('b'), pos: vec![(my, Anchor::Dot(x.clone()), None), (cy, tail.clone(), None)], deleted: None, undel: None, span: 1 });
    }
    let t = std::time::Instant::now();
    let p = crate::linearize::place_idx(&elems);
    let took = t.elapsed();
    assert_eq!(p.order.len(), (len + 2 * k) as usize);
    // linear: well under a second in release; a generous bound for a loaded debug build
    assert!(took.as_secs() < 10, "cycle breaking took {took:?}");
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
/// chars without content); then edited by a new writer through the wire: an insert anchored at a random placed element (hidden ones inside range
/// records and embedded ones included), then a random text op (undelete of part of a deleted
/// run, delete, move, insert, now and then a replace), `n` times. After every join the read
/// equals the model's text slot and the cached placement a whole pass (`check_lin`).
pub(crate) fn snapshot_then_edit(mut r: crate::testutil::SeedRng, upgraded: bool, n: usize) -> Follows {
    use crdt_model::stamp::Dot as MDot;
    use crdt_model::state::{Anchor as MAnchor, Composite};
    let mut deltas: Vec<MFrag> = history(&mut r, &[Ty::Text], 3, 8).into_iter().map(|c| c.delta).collect();
    let mut m = None;
    for d in &deltas {
        mapply(&mut m, d.clone());
    }
    if upgraded {
        let mut w = MWriter::new(MSource::node(8), 100 << 16, 1);
        let v = crdt_model::value::Value::Str(crdt_model::r#gen::random_text(&mut r, 12));
        let d = crdt_model::ops::create(&mut w, &Ty::Register, &v);
        mapply(&mut m, d.clone());
        deltas.push(d);
        let mut w = MWriter::new(MSource::node(7), 101 << 16, 1);
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
    let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: full, frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &snap_cx(), None).unwrap();
    let mut ours = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
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
    let mut w = MWriter::new(MSource::node(9), 1 << 30, 1);
    let mut deliver = |d: MFrag, w: &MWriter, m: &mut Option<MFrag>, ours: &mut Fragment| {
        mapply(m, d.clone());
        let cx = writer_cx(w);
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: frag(&d) }, &cx, None).unwrap();
        let d = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment;
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
    let text = Ty::Text;
    for k in 0..n as u64 {
        // the placement read before each join, so the join has a cache to follow
        let _ = ours.read();
        let order = match m.as_ref().and_then(|x| x.slot(9)) {
            Some(MFrag::Seq { elems, .. }) => crdt_model::seq::linearize_full(elems).0,
            _ => Vec::new(),
        };
        w.next_commit((1 << 30) + 2 * k + 1);
        let anchor: Option<&MDot> = order.get(r.below(order.len() + 1));
        let mut d = MFrag::Seq { text: true, c: Composite { reset: None, w: None }, elems: Default::default() };
        let cs = crdt_model::r#gen::random_text(&mut r, 3);
        if !cs.is_empty() {
            crdt_model::ops::insert_run(&mut w, &mut d, anchor.map_or(MAnchor::Head, |x| MAnchor::Dot(x.clone())), cs.chars().map(Content::Char).collect());
            deliver(d, &w, &mut m, &mut ours);
        }
        let _ = ours.read();
        w.next_commit((1 << 30) + 2 * k + 2);
        if let Some(d) = crdt_model::r#gen::random_op(&mut r, &mut w, &text, m.as_ref()) {
            deliver(d, &w, &mut m, &mut ours);
        }
    }
    f
}

proptest! {
    /// §5.7, §6 (`seq_lin`): a text bootstrapped from a snapshot takes inserts anchored at every
    /// kind of element, undeletes of parts of deleted runs, deletes and moves like the model, and
    /// the cached placement follows writes that split a range record.
    #[test]
    fn snapshot_text_edits_match_model_spec_6(seed in any::<u64>()) {
        snapshot_then_edit(crate::testutil::rng(seed | 1), false, 30);
    }

    /// §6.1, §7 (`seq_lin`): the same over a text upgraded from a string (embedded characters,
    /// `Derived` dots and anchors at them, held or virtual).
    #[test]
    fn snapshot_slots_edits_match_model_spec_7(seed in any::<u64>()) {
        snapshot_then_edit(crate::testutil::rng(seed | 1), true, 30);
    }
}

/// §6 (`seq_lin`): writes splitting a range record of a snapshot-bootstrapped text, or anchoring
/// inside one, are followed by the cached placement, not rebuilt (fixed seeds).
#[test]
fn range_splits_follow_cache_spec_6() {
    let mut t = Follows::default();
    for seed in (1..24).step_by(2) {
        let x = snapshot_then_edit(crate::testutil::fixed(seed), false, 30);
        t.joins += x.joins;
        t.kept += x.kept;
        t.split += x.split;
        t.missed += x.missed;
    }
    assert!(t.split >= 25 && t.missed * 30 <= t.split, "{t:?}");
    assert!(t.kept * 10 >= t.joins * 9, "{t:?}");
}

/// §6, §8 (`seq_place`): a placement held in part (a node's stored one: blocks and dot-map
/// chunks loaded on a miss) over records held in part (pages loaded on a miss) follows the
/// joins a whole one follows, and what it writes back reads as a whole pass (fixed seeds).
#[test]
fn partial_placement_follows_like_whole_spec_6() {
    let mut t = Follows::default();
    for seed in (1..24).step_by(2) {
        for upgraded in [false, true] {
            let x = snapshot_then_edit(crate::testutil::fixed(seed), upgraded, 30);
            t.whole += x.whole;
            t.partial += x.partial;
            t.loaded += x.loaded;
            t.blocks += x.blocks;
        }
    }
    assert!(t.whole >= 500 && t.partial * 100 >= t.whole * 98, "{t:?}");
    // the blocks the joins look at, not every block
    assert!(t.loaded * 2 < t.blocks, "{t:?}");
}

/// §6.1, §7 (`seq_lin`): writes on embedded characters (`Derived` dots) of an upgraded text, and
/// inserts anchored at them, are followed by the cached placement (fixed seeds).
#[test]
fn derived_dots_follow_cache_spec_7() {
    let mut t = Follows::default();
    for seed in (1..24).step_by(2) {
        let x = snapshot_then_edit(crate::testutil::fixed(seed), true, 30);
        t.joins += x.joins;
        t.kept += x.kept;
        t.derived += x.derived;
        t.missed_derived += x.missed_derived;
    }
    assert!(t.derived >= 10 && t.missed_derived * 20 <= t.derived, "{t:?}");
}

/// Tier 2: the differential suite at size (more writers, rounds and seeds).
#[test]
#[ignore]
fn seq_differential_large_spec_5_7() {
    for seed in (1..200).step_by(2) {
        lockstep(seed, &[Ty::Text], 4, 16);
        lockstep(seed, &[Ty::List(Box::new(inner()))], 4, 12);
        lockstep(seed, &[Ty::Register, Ty::Text], 4, 10);
        wire_matches(seed, &[Ty::Text, Ty::List(Box::new(inner())), kitchen_sink()], (1..=4).map(MSource::node).collect());
    }
}

/// What decoding a snapshot of `f` gives: the chars of deleted elements dropped (§3.3 rule 5),
/// those of embedded ones put back by the decoder's prune of a `Slots` (§7).
fn as_carried(f: &Fragment) -> Fragment {
    let mut f = f.clone();
    f.drop_deleted_chars();
    f.prune(None, &mut crate::Changes::new());
    f
}

/// Every delta of a random history encodes like the model's and decodes back to itself; snapshots
/// of the joined state likewise (deleted text carried without its chars).
fn wire_matches(seed: u64, types: &[Ty], sources: Vec<MSource>) {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = history_with(&mut r, types, sources, 5);
    let mut state = None;
    for c in &commits {
        let mut mcx = Ctx::new(c.w.ts, c.w.source.clone(), c.w.lo);
        let mbytes = m_encode_delta(&c.delta, [7; 16], &mut mcx);
        let cx = writer_cx(&c.w);
        let d = Delta { nonce: [7; 16], fragment: frag(&c.delta) };
        let bytes = encode_delta(&d, &cx, None).unwrap();
        assert_eq!(bytes, mbytes, "delta bytes equal the model's");
        let back = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap();
        crate::testutil::check_bound(&bytes, &back.fragment);
        assert_eq!(back, d, "delta round trip");
        mapply(&mut state, c.delta.clone());
        let st = state.as_ref().unwrap();
        let msnap = m_encode_snapshot(st, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default() };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "snapshot bytes equal the model's");
        let back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        crate::testutil::check_bound(&sbytes, &back.fragment);
        assert_eq!(back.fragment, as_carried(&s.fragment), "snapshot round trip");
        assert_eq!(back.fragment.read(), s.fragment.read());
        let (mback, _) = crdt_model::wire::decode_snapshot(&sbytes, &mut Ctx::new(1 << 40, MSource::node(250), 1)).unwrap();
        assert_eq!(frag(&mback), back.fragment, "model snapshot round trip");
    }
}

/// §3.3 rules 5 and 7, §7: a snapshot of a text upgraded from a string whose deleted embedded
/// char is not carried round-trips through both decoders and reads alike (reviewer's probe).
#[test]
fn snapshot_deleted_embedded_char_spec_3_3() {
    use crdt_model::value::Value as MValue;
    let mut m = None;
    let mut w = MWriter::new(MSource::node(1), 50 << 16, 1);
    mapply(&mut m, mops::create(&mut w, &Ty::Text, &MValue::Str("xy".into())));
    let mut w = MWriter::new(MSource::node(2), 100 << 16, 1);
    mapply(&mut m, mops::create(&mut w, &Ty::Register, &MValue::Str("ab".into())));
    let mut w = MWriter::new(MSource::node(3), 102 << 16, 1);
    let d = mops::seq_delete(&mut w, m.as_ref().and_then(|x| x.slot(9)).unwrap(), 0, 1).unwrap();
    mapply(&mut m, d);
    let st = m.as_ref().unwrap();
    assert!(matches!(st, MFrag::Slots { .. }));
    let msnap = m_encode_snapshot(st, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
    let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
    assert_eq!(bytes, msnap);
    let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
    let (mback, _) = crdt_model::wire::decode_snapshot(&bytes, &mut Ctx::new(1 << 40, MSource::node(250), 1)).unwrap();
    assert_eq!(back.read(), Some(Value::Str("b".into())));
    assert_eq!(back.read(), s.fragment.read());
    assert_eq!(frag(&mback).read(), back.read());
    // joined into an empty state, the embedding restores the char locally
    let mut j = Fragment::default();
    j.join(back);
    assert_eq!(j, s.fragment);
}

/// §3.3 rules 5 and 7, §4.6, §7: a node bootstrapped from a snapshot of an upgraded text holds a
/// deleted embedded char again (the decoder returns the re-embedded position), so a content-less
/// undelete of it (as a writer bootstrapped without the char sends) reads like on a node with the
/// full history, and the state re-encodes and decodes (reviewer's probe).
#[test]
fn bootstrapped_undelete_of_embedded_char_spec_4_6() {
    use crdt_model::value::Value as MValue;
    let mut m = None;
    let mut w = MWriter::new(MSource::node(1), 50 << 16, 1);
    mapply(&mut m, mops::create(&mut w, &Ty::Text, &MValue::Str("xy".into())));
    let mut w = MWriter::new(MSource::node(2), 100 << 16, 1);
    mapply(&mut m, mops::create(&mut w, &Ty::Register, &MValue::Str("ab".into())));
    let mut w = MWriter::new(MSource::node(3), 102 << 16, 1);
    let d = mops::seq_delete(&mut w, m.as_ref().and_then(|x| x.slot(9)).unwrap(), 0, 1).unwrap();
    mapply(&mut m, d);
    let full = frag(m.as_ref().unwrap());
    let snap = |f: &Fragment| {
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: f.clone(), frontiers: Frontiers::default() };
        let bytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment
    };
    let mut boot = snap(&full);
    assert_eq!(boot, full, "the embedded char is held again");
    // the deleted embedded char, undeleted without content
    let Some(MFrag::Seq { elems, .. }) = m.as_ref().and_then(|x| x.slot(9)) else { panic!() };
    let dead: Vec<_> = elems.iter().filter(|(_, e)| e.is_deleted(true)).map(|(d, _)| d.clone()).collect();
    assert_eq!(dead.len(), 1);
    let mut w = MWriter::new(MSource::node(4), 103 << 16, 1);
    let empty = MFrag::Seq { text: true, c: Default::default(), elems: BTreeMap::new() };
    let u = mops::seq_undelete(&mut w, &empty, &dead);
    let cx = writer_cx(&w);
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: frag(&u) }, &cx, None).unwrap();
    let u = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment;
    let mut whole = full.clone();
    whole.join(u.clone());
    boot.join(u);
    assert_eq!(whole.read(), Some(Value::Str("ab".into())));
    assert_eq!(boot.read(), whole.read());
    assert_eq!(snap(&boot).read(), whole.read());
}

/// §7 (`seq_lin`): joins at a `Slots` position that leave its register and effective reset as
/// they are (text edits of a text upgraded from a string) follow the text slot's cached
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
        let mut r = crate::testutil::rng(seed);
        let (mut m, mut ours) = (None, Fragment::default());
        let mut w = MWriter::new(MSource::node(1), 50 << 16, 1);
        put(mops::create(&mut w, &Ty::Text, &MValue::Str("xy".into())), &mut m, &mut ours);
        let mut w = MWriter::new(MSource::node(2), 100 << 16, 1);
        put(mops::create(&mut w, &Ty::Register, &MValue::Str("abcdefghij".repeat(4))), &mut m, &mut ours);
        let mut w = MWriter::new(MSource::node(3), 101 << 16, 1);
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
    // own creation above the range, a creation outside the range, own counter used twice
    bad(text_with(vec![run(i(5), 2, created(2), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(1), 2, created(2), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 1, created(1), s("a"), vec![l(vec![i(0), i(0), i(0)])], vec![])]));
    // non-maximal runs (rule 3) and unsorted runs (rule 2): caught by the canonical re-encode
    bad(text_with(vec![run(i(3), 1, created(1), s("a"), vec![], vec![]), run(i(4), 1, l(vec![i(3), l(vec![l(vec![i(0), i(1)])])]), s("b"), vec![], vec![])]));
    bad(text_with(vec![run(i(2), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])]), run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    // content for a deleted element, an empty list element fragment
    bad(text_with(vec![run(i(1), 1, l(vec![]), s("a"), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    bad(list_with(vec![run(i(3), 1, created(1), l(vec![l(vec![i(0), l(vec![])])]), vec![], vec![])]));
}

/// §3.3 rule 7: no bare-anchor run in a writer's delta (an import's or a snapshot's may carry
/// them); at most `MAX_DELTA_BARE` content-less elements per writer or import delta, bare
/// anchors included; a writer's flag writes carry the delta stamp.
#[test]
fn rejects_bare_and_oversized_runs_spec_3_3() {
    let other = osis_base::Tid::from_bytes([9; 15]);
    let srcs = || vec![Value::Bytes(other.as_bytes().to_vec())];
    let m = crate::MAX_RUN as i64;
    let k = (osis_base::format::MAX_DELTA_BARE / crate::MAX_RUN) as i64;
    let flag = || vec![l(vec![i(0), i(m - 1), i(0), Value::Bool(true)])];
    let runs = |k: i64, f: &dyn Fn() -> Vec<Value>| text_with((0..k).map(|j| run(l(vec![i(1), i(1 + j * m)]), m, l(vec![]), l(vec![]), vec![], f())).collect());
    let import = DeltaCtx { kind: DeltaKind::Import, ..wcx() };
    // bare anchors: rejected in a writer's delta, bounded in an import
    rejects(&delta(srcs(), vec![], runs(1, &Vec::new)), &wcx(), ErrorClass::BadInput);
    decode_delta(&delta(srcs(), vec![], runs(k, &Vec::new)), &import, &mut Interner::new(), None).unwrap();
    rejects(&delta(srcs(), vec![], runs(k + 1, &Vec::new)), &import, ErrorClass::BadInput);
    // k · MAX_RUN = MAX_DELTA_BARE flagged elements pass, one run more does not
    decode_delta(&delta(srcs(), vec![], runs(k, &flag)), &wcx(), &mut Interner::new(), None).unwrap();
    rejects(&delta(srcs(), vec![], runs(k + 1, &flag)), &wcx(), ErrorClass::BadInput);
    // a flag write off the delta stamp
    let off = text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), l(vec![i(0), i(4)]), Value::Bool(true)])])]);
    rejects(&delta(vec![], vec![], off), &wcx(), ErrorClass::BadInput);
}

/// §3.3 rule 7, §8: a snapshot carries bare anchors (a reset text).
#[test]
fn snapshot_carries_bare_anchors_spec_3_3() {
    let (m, base) = typed("abc");
    let rm = mops::remove(&mut mw(1, 5), 9);
    let st = joined(&base, &[&rm]);
    let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
    assert_eq!(decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment, st);
    let _ = m;
}

/// §3.3 rule 7: a segment's commit has the run's source.
#[test]
fn rejects_segment_of_another_source_spec_3_3() {
    let (a, b) = (osis_base::Tid::from_bytes([1; 15]), osis_base::Tid::from_bytes([2; 15]));
    let srcs = vec![Value::Bytes(a.as_bytes().to_vec()), Value::Bytes(b.as_bytes().to_vec())];
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(10), i(0), i(1)])])]), l(vec![i(2), l(vec![l(vec![i(10), i(0), i(1)])])])];
    let with = |ci: i64| {
        let r = run(l(vec![i(1), i(1)]), 1, l(vec![i(0), l(vec![l(vec![i(ci), i(1)])])]), s("a"), vec![], vec![]);
        let f = text_with(vec![r, run(l(vec![i(2), i(1)]), 1, l(vec![i(0), l(vec![l(vec![i(2), i(1)])])]), s("b"), vec![], vec![])]);
        delta(srcs.clone(), commits.clone(), f)
    };
    decode_delta(&with(1), &snap_cx(), &mut Interner::new(), None).unwrap();
    rejects(&with(2), &snap_cx(), ErrorClass::BadInput);
}

/// §3.3 rule 7: a creation run of a `Derived` source only in snapshots (embedded characters).
#[test]
fn rejects_derived_creation_in_writer_delta_spec_3_3() {
    let f = text_with(vec![run(l(vec![i(1), i(1)]), 1, created(1), s("a"), vec![], vec![])]);
    // Sources: Derived of own dot 3
    rejects(&delta(vec![l(vec![i(0), i(3)])], vec![], f), &wcx(), ErrorClass::BadInput);
    // an anchor at an embedded character is fine
    let f = text_with(vec![run(i(3), 1, l(vec![l(vec![i(2), i(1)]), l(vec![l(vec![i(0), i(1)])])]), s("q"), vec![], vec![])]);
    let other = osis_base::Tid::from_bytes([9; 15]);
    let srcs = vec![Value::Bytes(other.as_bytes().to_vec()), l(vec![i(1), i(4)])];
    decode_delta(&delta(srcs, vec![], f), &wcx(), &mut Interner::new(), None).unwrap();
}

// ---- notes/crdt.md, Worked examples (model ops, joined by this implementation)

fn chars(x: &str) -> Vec<Content> {
    x.chars().map(Content::Char).collect()
}
fn mw(n: u8, t: u64) -> MWriter {
    MWriter::new(MSource::node(n), t << 16, 1)
}
fn joined(base: &Fragment, ds: &[&MFrag]) -> Fragment {
    let mut f = base.clone();
    for d in ds {
        f.join(frag(d));
    }
    f
}
fn reads(f: &Fragment) -> Option<String> {
    match f.read() {
        Some(Value::Str(x)) => Some(x),
        _ => None,
    }
}
/// `x` typed by node 1 at t=1, as a model state and ours.
fn typed(x: &str) -> (MFrag, Fragment) {
    let mut a = mw(1, 1);
    let mut st = mops::seq_insert(&mut a, None, true, 0, chars(x));
    st.prune(None);
    let f = frag(&st);
    (st, f)
}
/// The model writer's header as a delta context.
fn cx_of(w: &MWriter) -> DeltaCtx {
    DeltaCtx { ts: ts(w.ts), own: source(&w.source), range: CounterRange { lo: w.lo, hi: w.hi() }, kind: DeltaKind::Writer }
}
fn fragment_value(bytes: &[u8]) -> Value {
    let Value::List(top) = osis_base::decode(bytes, &osis_base::Limits { max_depth: 64, max_bytes: 1 << 20 }).unwrap() else { panic!() };
    top[3].clone()
}

#[test]
fn typing_spec_example() {
    let mut a = mw(1, 1);
    let d = mops::seq_insert(&mut a, None, true, 0, chars("FOOBAR"));
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: frag(&d) }, &cx_of(&a), None).unwrap();
    let runs = l(vec![run(i(1), 6, l(vec![i(0), l(vec![l(vec![i(0), i(6)])])]), s("FOOBAR"), vec![], vec![])]);
    assert_eq!(fragment_value(&bytes), l(vec![i(9), l(vec![]), l(vec![]), runs]));
    assert_eq!(reads(&frag(&d)).as_deref(), Some("FOOBAR"));
}

#[test]
fn concurrent_inserts_at_one_anchor_spec_example() {
    let (m, base) = typed("FOOBAR");
    let mut b = mw(2, 2);
    let x = mops::seq_insert(&mut b, Some(&m), true, 3, chars("x"));
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: frag(&x) }, &cx_of(&b), None).unwrap();
    let runs = l(vec![run(i(1), 1, l(vec![l(vec![i(1), i(3)]), l(vec![l(vec![i(0), i(1)])])]), s("x"), vec![], vec![])]);
    assert_eq!(fragment_value(&bytes), l(vec![i(9), l(vec![]), l(vec![]), runs]));
    let mut c = mw(3, 3);
    let y = mops::seq_insert(&mut c, Some(&m), true, 3, chars("y"));
    assert_eq!(reads(&joined(&base, &[&x, &y])).as_deref(), Some("FOOyxBAR"));
    assert_eq!(reads(&joined(&base, &[&y, &x])).as_deref(), Some("FOOyxBAR"));
}

#[test]
fn move_with_concurrent_insert_spec_example() {
    let (m, base) = typed("FOOBAR");
    let mut b = mw(2, 2);
    let x = mops::seq_insert(&mut b, Some(&m), true, 3, chars("x"));
    let mut a = mw(1, 3);
    a.lo = 7;
    a.next = 7;
    let mv = mops::seq_move(&mut a, &m, 0, 3, 3).unwrap();
    assert_eq!(reads(&joined(&base, &[&x, &mv])).as_deref(), Some("BARFOOx"));
    assert_eq!(reads(&joined(&base, &[&mv, &x])).as_deref(), Some("BARFOOx"));
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
    assert_eq!(reads(&base).as_deref(), Some("abc"));
    w.next_commit(4 << 16);
    let mv = mops::seq_move(&mut w, &m, 0, 2, 1).unwrap();
    assert_eq!(reads(&joined(&base, &[&mv])).as_deref(), Some("cab"));
}

#[test]
fn concurrent_moves_of_one_element_spec_example() {
    let (m, base) = typed("abc");
    let m1 = mops::seq_move(&mut mw(2, 5), &m, 0, 1, 2).unwrap();
    let m2 = mops::seq_move(&mut mw(3, 4), &m, 0, 1, 1).unwrap();
    assert_eq!(reads(&joined(&base, &[&m1, &m2])).as_deref(), Some("bca"));
    assert_eq!(reads(&joined(&base, &[&m2, &m1])).as_deref(), Some("bca"));
}

#[test]
fn cycle_spec_example() {
    let (m, base) = typed("acb");
    let m1 = mops::seq_move(&mut mw(2, 5), &m, 0, 1, 2).unwrap();
    let m2 = mops::seq_move(&mut mw(3, 4), &m, 2, 1, 1).unwrap();
    assert_eq!(reads(&joined(&base, &[&m1, &m2])).as_deref(), Some("cba"));
    assert_eq!(reads(&joined(&base, &[&m2, &m1])).as_deref(), Some("cba"));
}

#[test]
fn reset_against_a_newer_insert_spec_example() {
    let (m, base) = typed("abc");
    let mut a = mw(1, 5);
    a.lo = 4;
    a.next = 4;
    let rep = mops::replace(&mut a, &Ty::Text, &crdt_model::value::Value::Str("xyz".into()));
    let q = mops::seq_insert(&mut mw(2, 6), Some(&m), true, 2, chars("q"));
    assert_eq!(reads(&joined(&base, &[&rep, &q])).as_deref(), Some("xyzq"));
    assert_eq!(joined(&base, &[&rep, &q]), joined(&base, &[&q, &rep]));
    let old = mops::seq_insert(&mut mw(3, 3), Some(&m), true, 2, chars("o"));
    assert_eq!(reads(&joined(&base, &[&old, &rep])).as_deref(), Some("xyz"));
    // remove_aspect instead: absent until q arrives, then q
    let rm = mops::remove(&mut mw(1, 5), 9);
    assert_eq!(joined(&base, &[&rm]).read(), None);
    assert_eq!(reads(&joined(&base, &[&rm, &q])).as_deref(), Some("q"));
}

#[test]
fn move_displaces_a_concurrent_insert_spec_example() {
    let (m, base) = typed("abcd");
    let mv = mops::seq_move(&mut mw(2, 5), &m, 1, 1, 3).unwrap();
    let x = mops::seq_insert(&mut mw(3, 4), Some(&m), true, 1, chars("x"));
    assert_eq!(reads(&joined(&base, &[&mv, &x])).as_deref(), Some("acdbx"));
}

#[test]
fn delete_vs_move_spec_example() {
    let (m, base) = typed("abc");
    let del = mops::seq_delete(&mut mw(2, 4), &m, 1, 1).unwrap();
    let mv = mops::seq_move(&mut mw(3, 5), &m, 1, 1, 2).unwrap();
    let st = joined(&base, &[&del, &mv]);
    assert_eq!(reads(&st).as_deref(), Some("ac"));
    assert_eq!(st, joined(&base, &[&mv, &del]));
    // an insert anchored at b (made before the delete) appears after c
    let q = mops::seq_insert(&mut mw(4, 6), Some(&m), true, 2, chars("q"));
    assert_eq!(reads(&joined(&st, &[&q])).as_deref(), Some("acq"));
}

#[test]
fn unknown_anchor_spec_example() {
    let (m, base) = typed("FOOBAR");
    let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 3, chars("x"));
    let mut early = Fragment::default();
    early.join(frag(&x));
    assert_eq!(reads(&early).as_deref(), Some(""), "hidden until its anchor arrives");
    let mut a = mw(1, 5);
    a.lo = 7;
    a.next = 7;
    let rep = mops::replace(&mut a, &Ty::Text, &crdt_model::value::Value::Str("Z".into()));
    early.join(frag(&rep));
    assert_eq!(reads(&early).as_deref(), Some("Z"));
    early.join(base);
    assert_eq!(reads(&early).as_deref(), Some("Z"), "x (t=2) is older than the reset");
    // a newer insert into the reset text is placed once its anchor arrives
    let y = mops::seq_insert(&mut mw(3, 6), Some(&m), true, 3, chars("y"));
    let mut late = Fragment::default();
    late.join(frag(&y));
    late.join(frag(&rep));
    assert_eq!(reads(&late).as_deref(), Some("Z"));
    late.join(frag(&m));
    assert_eq!(reads(&late).as_deref(), Some("Zy"));
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
    let b = crate::stamp::Source::node(osis_base::Tid::from_bytes([2; 15]));
    for (k, e) in s.elems_mut().values_mut().enumerate().filter(|(k, _)| k % 3 == 0) {
        e.deleted = Some((crate::stamp::Stamp::new(ts((k as u64 + 2) << 16), b.clone(), k as u64 + 1), true));
    }
    let mut pages = MemoryPages::with_params(params);
    let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &snap_cx(), Some(&mut pages)).unwrap();
    assert!(!pages.is_empty());
    let got = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), Some(&mut pages)).unwrap();
    assert_eq!(got.fragment, as_carried(&st));
    assert_eq!(got.fragment.read(), st.read());
}

// ---- range records (spec/requirements.md Scale: input never causes unbounded allocation)

fn n(b: u8) -> crate::stamp::Source {
    crate::stamp::Source::node(osis_base::Tid::from_bytes([b; 15]))
}
fn st(t: u64, b: u8, c: u64) -> Stamp {
    Stamp::new(ts(t << 16), n(b), c)
}
fn seq_of(elems: BTreeMap<Dot, SeqElem>, reset: Option<Stamp>) -> Fragment {
    Fragment::Seq(Seq::new(true, Meta { reset, w: None }, elems))
}
fn one(d: Dot, e: SeqElem) -> Fragment {
    seq_of(BTreeMap::from([(d, e)]), None)
}
/// `len` chars typed by node 1 at t = 1, chained from HEAD.
fn long_text(len: u64) -> Fragment {
    let mut elems = BTreeMap::new();
    let mut prev = Anchor::Head;
    for c in 1..=len {
        let s = st(1, 1, c);
        elems.insert(s.dot.clone(), SeqElem { created: Some((s.clone(), prev.clone())), content: SeqContent::Char('a'), pos: vec![(s.clone(), prev, None)], deleted: None, undel: None, span: 1 });
        prev = Anchor::Dot(s.dot);
    }
    seq_of(elems, None)
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
fn snapshot_of(f: &Fragment) -> Vec<u8> {
    encode_snapshot(&Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() }, &snap_cx(), None).unwrap()
}

/// §3.2 Run, issue run amplification: a snapshot run of `MAX_RUN` - 1 bare anchors (a reset
/// text) or deleted elements is a few bytes and decodes to one record, not one per element.
#[test]
fn snapshot_runs_decode_to_ranges_spec_3_2() {
    let len = crate::MAX_RUN - 1;
    let mut bare = long_text(len);
    bare.join(seq_of(BTreeMap::new(), Some(st(2, 2, 1))));
    let mut deleted = long_text(len);
    deleted.join(one(Dot::new(n(1), 1), SeqElem { deleted: Some((st(2, 2, 1), true)), span: len, ..SeqElem::bare() }));
    assert_eq!(records(&deleted), len as usize, "a range write splits nothing into a per-element state");
    for (what, f) in [("bare", &bare), ("deleted", &deleted)] {
        let bytes = snapshot_of(f);
        assert!(bytes.len() < 110, "{what}: {} bytes", bytes.len());
        let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
        assert_eq!(records(&back), 1, "{what}");
        assert_eq!(back, as_carried(f), "{what}");
        assert_eq!(back.read(), f.read(), "{what}");
        assert_eq!(order(&back), order(f), "{what}");
        assert_eq!(snapshot_of(&back), bytes, "{what}");
    }
    // the reset text's run is the attack shape: [Dot, n, [], [], [], []]
    let v = osis_base::decode(&snapshot_of(&bare), &osis_base::Limits { max_depth: 16, max_bytes: 1 << 20 }).unwrap();
    let Value::List(top) = v else { panic!("snapshot") };
    let Value::List(f) = &top[3] else { panic!("fragment") };
    assert_eq!(f[3], l(vec![run(l(vec![i(2), i(1)]), len as i64, l(vec![]), l(vec![]), vec![], vec![])]));
}

/// §4.2, §5.7, §6: writes landing inside a range record (an insert anchored in it, a move and an
/// undelete of one of its elements, a reset between its creations) split it only there, and
/// give the same state, read and order as the per-element state.
#[test]
fn ranges_split_where_writes_land_spec_6() {
    let len = crate::MAX_RUN - 1;
    let mut deleted = long_text(len);
    deleted.join(one(Dot::new(n(1), 1), SeqElem { deleted: Some((st(2, 2, 1), true)), span: len, ..SeqElem::bare() }));
    let ranged = decode_snapshot(&snapshot_of(&deleted), &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
    assert_eq!(records(&ranged), 1);
    let flat = expanded(&ranged);
    let x = st(3, 3, 1);
    let at = Anchor::Dot(Dot::new(n(1), 1000));
    let insert = one(x.dot.clone(), SeqElem { created: Some((x.clone(), at.clone())), content: SeqContent::Char('x'), pos: vec![(x.clone(), at, None)], deleted: None, undel: None, span: 1 });
    let mv = one(Dot::new(n(1), 500), SeqElem { pos: vec![(st(4, 3, 2), Anchor::Head, None)], ..SeqElem::bare() });
    let undelete = one(Dot::new(n(1), 2000), SeqElem { deleted: Some((st(5, 3, 3), false)), undel: Some('u'), ..SeqElem::bare() });
    // creations of t = 1 below (1, node 1, 3000) go: a reset inside the chain
    let reset = seq_of(BTreeMap::new(), Some(st(1, 1, 3_000)));
    let (mut a, mut b) = (ranged.clone(), flat.clone());
    for (k, d) in [insert, mv, undelete, reset].into_iter().enumerate() {
        if k == 3 {
            assert_eq!(reads(&a).as_deref(), Some("xu"));
        }
        a.join(d.clone());
        b.join(d);
        assert_eq!(a, b);
        assert_eq!(a.read(), b.read());
        assert_eq!(order(&a), order(&b));
        assert!(records(&a) <= 12, "{} records", records(&a));
    }
    // the reset pruned the undeleted char's creation, so only its flag revived (§5.7)
    assert_eq!(reads(&a).as_deref(), Some("x"));
    let bytes = snapshot_of(&a);
    assert_eq!(bytes, snapshot_of(&b));
    assert_eq!(decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment, as_carried(&a));
}

proptest! {
    /// §6: range records place, read and encode like their elements (random histories, every
    /// uniform stretch coalesced).
    #[test]
    fn ranges_place_like_elements_spec_6(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
        // text slots: embedded chars (`Derived` dots) beside range records
        let types: &[Ty] = if seed % 2 == 0 { &[Ty::Text, Ty::List(Box::new(inner()))] } else { &[Ty::Register, Ty::Text] };
        let commits = crate::testutil::history(&mut r, types, 3, 6);
        let mut state = None;
        for c in &commits {
            mapply(&mut state, c.delta.clone());
            let f = match frag(state.as_ref().unwrap()) {
                Fragment::Slots(x) => x.slots.get(&crate::fragment::Encoding::Text).cloned().unwrap_or_default(),
                f => f,
            };
            let Fragment::Seq(_) = &f else { continue };
            let flat = expanded(&f);
            prop_assert_eq!(order(&f), order(&flat));
            prop_assert_eq!(f.read(), flat.read());
            prop_assert_eq!(snapshot_of(&f), snapshot_of(&flat));
        }
    }
}

/// A created char `c` of `dot` at `t`, anchored at `at`.
fn char_at(dot: Dot, t: u64, at: Anchor, c: char) -> SeqElem {
    let s = Stamp { ts: ts(t << 16), dot };
    SeqElem { created: Some((s.clone(), at.clone())), content: SeqContent::Char(c), pos: vec![(s, at, None)], deleted: None, undel: None, span: 1 }
}
/// Through a snapshot: uniform stretches become range records.
pub(crate) fn via_snapshot(f: &Fragment) -> Fragment {
    decode_snapshot(&snapshot_of(f), &snap_cx(), &mut Interner::new(), None).unwrap().fragment
}
/// `op` applied by node 4 at t = 9: the delta and the joined state.
fn apply_op(f: &Fragment, op: crate::ops::Op) -> (Fragment, Fragment) {
    let mut b = crate::batch::Batch::new(f, crate::ops::Writer::new(ts(9 << 16), n(4), 1));
    b.apply(&crate::ops::PathOp { path: vec![], op }, &crate::testutil::TyView(Ty::Text)).unwrap();
    let (d, _) = b.finish().unwrap();
    let mut s = f.clone();
    s.join(d.clone());
    (d, s)
}

/// §5.7 move, §6: bare anchors left by a reset sit on END one by one, so moving a selection
/// that spans some moves each of them; a state from a snapshot (range records) and one built
/// element by element give the same writes and read.
#[test]
fn move_over_bare_ranges_spec_5_7() {
    let mut elems = BTreeMap::new();
    let mut prev = Anchor::Head;
    for (k, c) in "hello".chars().enumerate() {
        let d = Dot::new(n(1), k as u64 + 1);
        elems.insert(d.clone(), char_at(d.clone(), 1, prev, c));
        prev = Anchor::Dot(d);
    }
    for c in 1..=10 {
        elems.insert(Dot::new(n(2), c), SeqElem::bare());
    }
    elems.insert(Dot::new(n(3), 1), char_at(Dot::new(n(3), 1), 3, Anchor::Dot(Dot::new(n(2), 5)), 'a'));
    elems.insert(Dot::new(n(3), 2), char_at(Dot::new(n(3), 2), 3, Anchor::Dot(Dot::new(n(2), 10)), 'x'));
    let flat = seq_of(elems, None);
    assert_eq!(reads(&flat).as_deref(), Some("helloax"));
    let ranged = via_snapshot(&flat);
    assert!(records(&ranged) < 10, "{} records", records(&ranged));
    let (d1, s1) = apply_op(&flat, crate::ops::Op::Move { at: 5, len: 2, to: 0 });
    let (d2, s2) = apply_op(&ranged, crate::ops::Op::Move { at: 5, len: 2, to: 0 });
    assert_eq!(d1, d2);
    assert_eq!(reads(&s1).as_deref(), Some("axhello"));
    assert_eq!(s1, s2);
    assert_eq!(order(&s1), order(&s2));
}

/// The bare range `(node 2, 1..=10)` as one record, and the same element by element.
fn bare_ten() -> (Fragment, Fragment) {
    let flat = seq_of((1..=10).map(|c| (Dot::new(n(2), c), SeqElem::bare())).collect(), None);
    let mut e = SeqElem::bare();
    e.span = 10;
    (seq_of(BTreeMap::from([(Dot::new(n(2), 1), e)]), None), flat)
}

/// §2.2, §7: a `Derived(S, 5)` record sorts between `(S, 5)` and `(S, 6)`: joining one splits a
/// range of `S` there (`split_at`), and a range delta over it is cut there (`join_elems`).
#[test]
fn derived_keys_split_ranges_spec_7() {
    let (mut a, mut b) = bare_ten();
    let dd = Dot::new(crate::stamp::Source::derived(Dot::new(n(2), 5)).unwrap(), 1);
    let emb = one(dd.clone(), char_at(dd, 4, Anchor::Head, 'q'));
    let flag = one(Dot::new(n(2), 1), SeqElem { deleted: Some((st(5, 5, 1), true)), span: 10, ..SeqElem::bare() });
    for d in [emb, flag] {
        a.join(d.clone());
        b.join(d);
        assert_eq!(a, b);
        assert_eq!(order(&a), order(&b));
        assert_eq!(a.read(), b.read());
    }
    assert_eq!(records(&a), 3);
    assert_eq!(snapshot_of(&a), snapshot_of(&b));
}

/// §6.1: an element anchored at a `Derived(S, 5)` dot absent from the state sits under a
/// virtual anchor between `(S, 5)` and `(S, 6)` on END; a range of `S` places around it like
/// its elements do (hidden order included).
#[test]
fn virtual_derived_anchor_inside_range_spec_6_1() {
    let (mut a, mut b) = bare_ten();
    let dd = Dot::new(crate::stamp::Source::derived(Dot::new(n(2), 5)).unwrap(), 1);
    let y = one(Dot::new(n(3), 1), char_at(Dot::new(n(3), 1), 4, Anchor::Dot(dd), 'y'));
    let z = one(Dot::new(n(3), 2), char_at(Dot::new(n(3), 2), 4, Anchor::Dot(Dot::new(n(2), 10)), 'z'));
    for d in [y, z] {
        a.join(d.clone());
        b.join(d);
    }
    assert_eq!(order(&a), order(&b));
    assert_eq!(reads(&a).as_deref(), Some("yz"));
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
    let at = Anchor::Dot(Dot::new(n(1), 3));
    let e = SeqElem { created: Some((s0.clone(), at.clone())), pos: vec![(s0, at, None)], deleted: Some((st(2, 2, 1), true)), span: 5, ..SeqElem::bare() };
    let mut a = seq_of(BTreeMap::from([(Dot::new(n(1), 1), e)]), None);
    a.join(one(Dot::new(n(3), 1), char_at(Dot::new(n(3), 1), 4, Anchor::Dot(Dot::new(n(1), 5)), 'v')));
    let b = expanded(&a);
    assert_eq!(order(&a), order(&b));
    assert_eq!(reads(&a).as_deref(), Some("v"));
    assert_eq!(snapshot_of(&a), snapshot_of(&b));
}

/// §3.3 rule 7: runs that overlap (here the second starts inside the first) are bad input.
#[test]
fn rejects_overlapping_runs_spec_3_3() {
    let runs = vec![run(i(1), 5, l(vec![]), l(vec![]), vec![], vec![]), run(i(3), 5, l(vec![]), l(vec![]), vec![], vec![])];
    let bytes = osis_base::encode(&l(vec![Value::Bytes(vec![0; 16]), l(vec![]), l(vec![]), text_with(runs), l(vec![])]));
    let e = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap_err();
    assert_eq!(osis_base::Classified::class(&e), ErrorClass::BadInput, "{e}");
}

proptest! {
    /// spec/commits.md §5 (a body's live writes, judged by owner dot): `holds_owned` answers as
    /// `writes` does, over range records and `Derived` dots too (random histories, as held and
    /// through a snapshot).
    #[test]
    fn holds_owned_like_writes_spec_commits_5(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
        let types: &[Ty] = if seed % 2 == 0 { &[Ty::Text, Ty::List(Box::new(inner()))] } else { &[Ty::Register, Ty::Text] };
        let commits = crate::testutil::history(&mut r, types, 3, 6);
        let mut state = None;
        for c in &commits {
            mapply(&mut state, c.delta.clone());
        }
        let Some(st) = state.as_ref() else { return Ok(()) };
        let f = frag(st);
        for g in [f.clone(), via_snapshot(&f)] {
            let ws: Vec<Dot> = g.writes().into_iter().map(|(d, _)| d).collect();
            for n in 1..=3u8 {
                let src = crate::stamp::Source::node(osis_base::Tid::from_bytes([n; 15]));
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


/// §6, §8 (`seq_place`): the placement of a sequence with no records, stored and loaded in part,
/// lists its dot map's first chunk, so a join's misses name only chunks the stored form holds
/// (the whole map had none; fuzz: seq_ops).
#[test]
fn empty_placement_held_in_part_follows_spec_6() {
    use crate::{Batch, Op, PathOp, Writer};
    let view = crate::testutil::TyView(Ty::Text);
    let src = crate::stamp::Source::node(osis_base::Tid::from_bytes([1; 15]));
    let e = Fragment::default();
    let mut b = Batch::new(&e, Writer::new(ts(1 << 16), src, 1));
    b.apply(&PathOp { path: vec![], op: Op::Insert { at: 0, items: vec![Value::Str("ab".into())] } }, &view).unwrap();
    let (d, _) = b.finish().unwrap();
    let Fragment::Seq(d) = d else { panic!("a text delta") };
    let empty = Seq::empty(true);
    assert!(Pager::new(&empty, 1).whole.chunk(None).is_some(), "the first chunk is stored");
    // loads what the follow misses (it panicked loading a chunk the stored form lacked)
    let _ = partial_follow(&empty, &d, 1);
}

/// §6.1: a cached placement follows a delta moving element X (under p, by sibling key K, before
/// Z) and Y onto p, Y first, where X's writes after the join name p with a key below K (`second`:
/// a forged copy of X's chosen write, or an undo's restoring write): X sits by K until re-placed.
fn moved_row_keeps_key(base_x: Vec<(Stamp, Anchor, Option<Stamp>)>, delta_x: Vec<(Stamp, Anchor, Option<Stamp>)>, x_created: Stamp) {
    let (p, x, y) = (Dot::new(n(1), 1), x_created.dot.clone(), Dot::new(n(1), 4));
    let pa = Anchor::Dot(p.clone());
    let mk = |s: Stamp, a: Anchor| SeqElem { created: Some((s.clone(), a.clone())), content: SeqContent::Char('c'), pos: vec![(s, a, None)], deleted: None, undel: None, span: 1 };
    let mut elems = BTreeMap::new();
    elems.insert(p.clone(), mk(st(1, 1, 1), Anchor::Head));
    let mut xe = mk(x_created.clone(), base_x[0].1.clone());
    xe.pos = base_x;
    elems.insert(x.clone(), xe);
    elems.insert(Dot::new(n(1), 3), mk(st(4, 1, 3), pa.clone()));
    elems.insert(y.clone(), mk(st(1, 1, 4), Anchor::Head));
    let base = seq_of(elems, None);
    let mut d = BTreeMap::new();
    d.insert(x, SeqElem { pos: delta_x, ..SeqElem::bare() });
    d.insert(y, SeqElem { pos: vec![(st(3, 2, 1), pa, None)], ..SeqElem::bare() });
    let mut cached = base;
    let _ = cached.read();
    cached.join(seq_of(d, None));
    crate::testutil::check_lin(&cached);
}

#[test]
fn moved_row_keeps_key_spec_6_1() {
    let pa = Anchor::Dot(Dot::new(n(1), 1));
    // X created at p (t1), moved to HEAD (t5), back to p (t6); concurrently an undo of t5 (t7:
    // back to p with key t1) and a move to HEAD (t8)
    let (c1, w5, w6) = (st(1, 1, 2), st(5, 3, 0), st(6, 3, 1));
    moved_row_keeps_key(vec![(w6.clone(), pa.clone(), None), (w5, Anchor::Head, None)], vec![(st(8, 4, 1), Anchor::Head, None), (st(7, 5, 1), pa.clone(), Some(c1.clone()))], c1.clone());
    // forged: the delta's copy of X's chosen write t6 carries key t1, beside a move to HEAD
    moved_row_keeps_key(vec![(w6.clone(), pa.clone(), None), (c1.clone(), pa.clone(), None)], vec![(st(8, 4, 1), Anchor::Head, None), (w6.clone(), pa.clone(), Some(c1.clone()))], c1.clone());
    // forged: the copy alone (X stays under p, its key drops)
    moved_row_keeps_key(vec![(w6.clone(), pa.clone(), None), (c1.clone(), pa.clone(), None)], vec![(w6, pa, Some(c1.clone()))], c1);
}

/// Hostile single-record deltas on one text or list (§5.7, §6): creation chains anchored at
/// random dots (their own run, unknown dots, later dots), forged copies of one creation or
/// position write with other anchors or keys, moves with random anchors and sibling keys (cycles
/// through chains and range records), deletes, undeletes, resets; with `slots` (text), register
/// writes of strings at the position (§7: embedded chars, `Derived` dots moved, deleted and
/// anchored at, held or not).
fn hostile_writes(r: &mut crdt_model::r#gen::Rng, list: bool, slots: bool, n: usize) -> Vec<MFrag> {
    use crdt_model::stamp::{Dot as MDot, Source as MSrc, Stamp as MStamp};
    use crdt_model::state::{Anchor as MAnchor, Composite, SeqElem as MElem};
    let srcs = [MSource::node(1), MSource::node(2), MSource::node(3)];
    // the dots of the register writes so far (their embedded chars: `Derived(d)`, 1..)
    let mut regs: Vec<MDot> = Vec::new();
    fn dot(r: &mut crdt_model::r#gen::Rng, srcs: &[MSrc; 3], regs: &[MDot]) -> MDot {
        if !regs.is_empty() && r.chance(1, 4) {
            return MDot { source: MSrc::Derived(Box::new(regs[r.below(regs.len())].clone())), ctr: 1 + r.below(4) as u64 };
        }
        MDot { source: srcs[r.below(3)].clone(), ctr: 1 + r.below(12) as u64 }
    }
    fn anchor(r: &mut crdt_model::r#gen::Rng, srcs: &[MSrc; 3], regs: &[MDot]) -> MAnchor {
        if r.chance(1, 6) { MAnchor::Head } else { MAnchor::Dot(dot(r, srcs, regs)) }
    }
    let content = |r: &mut crdt_model::r#gen::Rng, s: &MStamp| Content::Frag(Box::new(MFrag::Register { reset: None, write: Some((s.clone(), Some(crdt_model::value::Value::Int(r.below(3) as i64)))) }));
    // chars at random: creation copies of one dot and undeletes may carry other chars (forged
    // copies, §4.1 copy order, §5.7)
    let any_char = |r: &mut crdt_model::r#gen::Rng| char::from(b'a' + r.below(4) as u8);
    let seq = |elems: BTreeMap<MDot, MElem>, reset: Option<MStamp>| MFrag::Seq { text: !list, c: Composite { reset, w: None }, elems };
    // stamps: ts in a small range so writes interleave; position write counters apart from dots
    let mut pos_ctr = 100u64;
    let mut out = Vec::new();
    for _ in 0..n {
        let t = (1 + r.below(30) as u64) << 16;
        let k = r.below(20);
        let mut elems = BTreeMap::new();
        if k < 8 {
            // a creation chain of 1..4 elements (never of a `Derived` source: a writer's delta
            // rejects them)
            let d = MDot { source: srcs[r.below(3)].clone(), ctr: 1 + r.below(12) as u64 };
            let len = 1 + r.below(4) as u64;
            let mut a = anchor(r, &srcs, &regs);
            // mostly one creation `ts` per dot (so copies of one stamp meet, differing in char
            // or anchor), sometimes another (a forged copy under another `ts`, §5.7 Join)
            let forged = r.chance(1, 4);
            for i in 0..len {
                let e = MDot { source: d.source.clone(), ctr: d.ctr + i };
                let ct = if forged { t } else { (1 + (srcs.iter().position(|x| *x == e.source).unwrap() as u64 * 7 + e.ctr * 3) % 30) << 16 };
                let s = MStamp { ts: ct, dot: e.clone() };
                let c = if list { content(r, &s) } else { Content::Char(any_char(r)) };
                elems.insert(e.clone(), MElem::new(s, a.clone(), c));
                a = MAnchor::Dot(e);
            }
        } else if k < 15 {
            // a move (or a forged copy of an earlier position write: same counter)
            let d = dot(r, &srcs, &regs);
            if r.chance(1, 4) {
                pos_ctr = pos_ctr.saturating_sub(r.below(3) as u64);
            }
            pos_ctr += 1;
            let src = srcs[r.below(3)].clone();
            let s = MStamp { ts: t, dot: MDot { source: src, ctr: pos_ctr } };
            let key = if r.chance(1, 3) && t > 1 << 16 { Some(MStamp { ts: t - (1 << 16), dot: dot(r, &srcs, &[]) }) } else { None };
            elems.insert(d, MElem::write(Content::None, vec![(s, anchor(r, &srcs, &regs), key)], None));
        } else if k < 19 {
            // a delete or (text) an undelete with a char; a run of 1..3
            let d = dot(r, &srcs, &regs);
            let len = 1 + r.below(3) as u64;
            pos_ctr += 1;
            let s = MStamp { ts: t, dot: MDot { source: srcs[r.below(3)].clone(), ctr: pos_ctr } };
            let undel = !list && r.chance(1, 3);
            for i in 0..len {
                let e = MDot { source: d.source.clone(), ctr: d.ctr + i };
                // an undelete's chars: some elements' missing (the undo buffer lacked them)
                let c = if undel && !r.chance(1, 5) { Some(any_char(r)) } else { None };
                elems.insert(e, MElem::flag(s.clone(), !undel, c));
            }
        } else if slots && r.chance(1, 2) {
            // an old app's save: a register write of a string (a reset of everything older)
            pos_ctr += 1;
            let d = MDot { source: srcs[r.below(3)].clone(), ctr: pos_ctr };
            let v: String = (0..r.below(4)).map(|i| char::from(b'a' + ((d.ctr + i as u64 + 1) % 4) as u8)).collect();
            out.push(MFrag::Register { reset: None, write: Some((MStamp { ts: t, dot: d.clone() }, Some(crdt_model::value::Value::Str(v)))) });
            regs.push(d);
            continue;
        } else {
            pos_ctr += 1;
            let s = MStamp { ts: t / 2, dot: MDot { source: srcs[r.below(3)].clone(), ctr: pos_ctr } };
            out.push(seq(elems, Some(s)));
            continue;
        }
        out.push(seq(elems, None));
    }
    out
}

/// Joins `writes` in a random order (each once or twice) into a placement read before every
/// join (so it is followed, not rebuilt): state and read equal the model's after each join, the
/// cached placement equals a whole pass, and snapshots encode byte-identically with the model's.
fn hostile_lockstep(seed: u64, list: bool, slots: bool) {
    let mut r = crate::testutil::rng(seed | 1);
    // deltas of 1..4 writes each (a delta is a state fragment: their join)
    let mut writes = Vec::new();
    let mut single = hostile_writes(&mut r, list, slots, 48).into_iter().peekable();
    while single.peek().is_some() {
        let mut d = None;
        for w in single.by_ref().take(1 + r.below(4)) {
            mapply(&mut d, w);
        }
        writes.extend(d);
    }
    // a char without a creation (no wire form: rejected, §3.3 rule 7) joins as none
    for w in &mut writes {
        if let MFrag::Seq { text: true, elems, .. } = w {
            for e in elems.values_mut().filter(|e| e.created.is_none()) {
                if r.chance(1, 4) {
                    e.content = Content::Char(char::from(b'a' + r.below(4) as u8));
                }
            }
        }
    }
    let mut reference = None;
    for w in &writes {
        mapply(&mut reference, w.clone());
    }
    for _ in 0..3 {
        let mut order: Vec<usize> = (0..writes.len()).collect();
        for k in (1..order.len()).rev() {
            order.swap(k, r.below(k + 1));
        }
        let mut model = None;
        let mut ours = Fragment::default();
        for k in order {
            let reps = if r.chance(1, 5) { 2 } else { 1 };
            for _ in 0..reps {
                let _ = ours.read();
                // a placement held in part follows like a whole pass where it follows (a reset
                // is joined over records loaded whole)
                if let (Fragment::Seq(st), Fragment::Seq(d)) = (&ours, frag(&writes[k]))
                    && d.meta.reset.is_none()
                {
                    let _ = crate::testutil::partial_follow(st, &d, 1 + r.below(4));
                }
                mapply(&mut model, writes[k].clone());
                ours.join(frag(&writes[k]));
                crate::testutil::check_lin(&ours);
                assert_eq!(ours, crate::testutil::ostate(&model), "state after joining write {k}");
                assert_eq!(ours.read(), model.as_ref().and_then(|m| m.read()).map(|v| crate::testutil::value(&v)), "read after write {k}");
            }
        }
        assert_eq!(ours, crate::testutil::ostate(&reference), "converged");
        let st = reference.as_ref().unwrap();
        let msnap = m_encode_snapshot(st, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: ours.clone(), frontiers: Frontiers::default() };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "snapshot bytes equal the model's");
        let back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        assert_eq!(back.fragment.read(), ours.read(), "snapshot read");
    }
    // un-merge of one author (§4.6): the join of the bodies each without its writes equals the
    // model's and does not depend on the order; removing them in place from the state agrees
    // unless `dots_supersede` says the bodies are needed (the author held a winner or a top-2
    // position write)
    let bad = crate::testutil::source(&MSource::node(2));
    let unmerged = |order: &mut dyn Iterator<Item = &MFrag>| {
        let mut out = Fragment::default();
        for w in order {
            let mut b = frag(w);
            b.remove_dots(&|d| d.src == bad);
            out.join(b);
        }
        out
    };
    let mut model = None;
    for w in &writes {
        let mut m = w.clone();
        m.unmerge(&|s| *s == MSource::node(2));
        mapply(&mut model, m);
    }
    let ours = unmerged(&mut writes.iter());
    assert_eq!(ours, crate::testutil::ostate(&model), "un-merged bodies equal the model's");
    assert_eq!(ours, unmerged(&mut writes.iter().rev()), "un-merge order-independent");
    let state = crate::testutil::ostate(&reference);
    let pred = |d: &Dot| d.src == bad;
    if !state.dots_supersede(&pred) {
        let mut fast = state.clone();
        if fast.holds_dots(&pred) {
            fast.remove_dots(&pred);
            fast.prune(None, &mut crate::Changes::new());
        }
        assert_eq!(fast, ours, "in-place un-merge agrees");
    }
    // expiry of node 1's early dots (§4.7): stripping commutes with join, undeletes' chars
    // of those creations included
    let gone = crate::testutil::source(&MSource::node(1));
    let exp = |d: &Dot| d.src == gone && d.ctr <= 6;
    let mut late = crate::testutil::ostate(&reference);
    late.strip(&exp);
    for order in [writes.iter().collect::<Vec<_>>(), writes.iter().rev().collect()] {
        let mut early = Fragment::default();
        for w in order {
            let mut b = frag(w);
            b.strip(&exp);
            early.join(b);
            early.strip(&exp);
        }
        assert_eq!(early, late, "expiry commutes with join");
    }
    if let Fragment::Seq(sq) = &late {
        for (d, e) in sq.elems() {
            assert!(!exp(d.owner()) || e.char().is_none(), "an expired creation's char outlives it: {d:?}");
        }
    }
}

proptest! {
    /// §5.7, §6.2: hostile writes on a text converge with the model in every order.
    #[test]
    fn hostile_text_matches_model_spec_6_2(seed in any::<u64>()) {
        hostile_lockstep(seed, false, false);
    }

    /// §7: the same with register writes of strings at the position (embedded chars).
    #[test]
    fn hostile_text_slots_match_model_spec_7(seed in any::<u64>()) {
        hostile_lockstep(seed, false, true);
    }

    /// §5.7, §6.2: the same on a list.
    #[test]
    fn hostile_list_matches_model_spec_6_2(seed in any::<u64>()) {
        hostile_lockstep(seed, true, false);
    }
}


/// §3.3 rule 3: runs past `MAX_RUN` (a creation chain longer than a run, deleted stretches and
/// bare anchors as range records of more than `MAX_RUN`) encode byte-identically with the model and
/// round trip.
#[test]
fn long_runs_match_model_spec_3_3() {
    use crdt_model::stamp::{Dot as MDot, Stamp as MStamp};
    use crdt_model::state::{Anchor as MAnchor, Composite, SeqElem as MElem};
    let src = MSource::node(1);
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
    // a delete of most of it, a move inside the deleted stretch, then a reset leaving bare
    // anchors below it for the first copy only
    let del = MStamp { ts: 5 << 16, dot: MDot { source: MSource::node(2), ctr: 1 } };
    let mut d = BTreeMap::new();
    for c in 10..n - 10 {
        d.insert(MDot { source: src.clone(), ctr: c }, MElem::write(Content::None, vec![], Some((del.clone(), true))));
    }
    mapply(&mut state, MFrag::Seq { text: true, c: Composite::default(), elems: d });
    let mv = MStamp { ts: 6 << 16, dot: MDot { source: MSource::node(2), ctr: 2 } };
    let mut d = BTreeMap::new();
    d.insert(MDot { source: src.clone(), ctr: 2000 }, MElem::write(Content::None, vec![(mv, MAnchor::Head, None)], None));
    mapply(&mut state, MFrag::Seq { text: true, c: Composite::default(), elems: d });
    for reset in [false, true] {
        if reset {
            let r = MStamp { ts: 7 << 16, dot: MDot { source: MSource::node(2), ctr: 3 } };
            mapply(&mut state, MFrag::Seq { text: true, c: Composite { reset: Some(r), w: None }, elems: BTreeMap::new() });
        }
        let st = state.as_ref().unwrap();
        let msnap = m_encode_snapshot(st, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
        let ours = frag(st);
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: ours.clone(), frontiers: Frontiers::default() };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert!(sbytes == msnap, "snapshot bytes equal the model's (reset {reset})");
        let back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        assert_eq!(back.fragment, as_carried(&ours));
        assert_eq!(back.fragment.read(), ours.read());
    }
}

/// §4.6, §4.7: an undelete's char on an element whose creation is gone is still the creator's
/// content, so `holds_dots` sees it and the in-place un-merge drops it (seed from
/// `hostile_text_slots_match_model_spec_7` at 4000 cases).
#[test]
fn unmerge_sees_undelete_char_of_bare_record_spec_4_7() {
    hostile_lockstep(12048209148398675115, false, true);
}

// spec: none (costs, spec/requirements.md Scale): a sequence's part at a delta's positions holds
// the records with its dots, not the sequence: a `covered` costs about the body's records.
#[test]
fn part_at_a_sequence_is_the_deltas_records() {
    let src = Source::node(osis_base::Tid::from_bytes([1; 15]));
    let dot = |ctr: u64| Dot { src: src.clone(), ctr };
    let rec = |ctr: u64| {
        let st = Stamp { ts: ts(ctr + 1), dot: dot(ctr) };
        SeqElem { created: Some((st.clone(), Anchor::Head)), content: SeqContent::Char('x'), pos: vec![(st, Anchor::Head, None)], deleted: None, undel: None, span: 1 }
    };
    let whole: BTreeMap<Dot, SeqElem> = (0..1000).map(|c| (dot(2 * c), rec(2 * c))).collect();
    let delta: BTreeMap<Dot, SeqElem> = [(dot(1000), rec(1000)), (dot(1002), rec(1002))].into();
    let (whole, delta) = (Fragment::Seq(Seq::new(true, Meta::default(), whole)), Fragment::Seq(Seq::new(true, Meta::default(), delta)));
    let Fragment::Seq(part) = whole.part_at(&delta) else { panic!("a sequence's part is one") };
    assert_eq!(part.elems().keys().cloned().collect::<Vec<_>>(), vec![dot(1000), dot(1002)]);
    assert!(whole.contains(&delta));
    // and the index of its copies holds what the ranges name, not the sequence's
    let ranges = [(src.clone(), 1000, 1001), (src.clone(), 1100, 1104)];
    let ix = whole.copy_index_in(&ranges);
    assert_eq!(ix.dots().cloned().collect::<Vec<_>>(), vec![dot(1000), dot(1100), dot(1102)]);
}
