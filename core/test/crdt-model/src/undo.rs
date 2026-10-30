//! Undo (spec §4.6, per-encoding "Undo" lines of §5.1, §5.2, §5.7), from the spec text alone.
//!
//! Choices where the spec leaves one (read-equivalent unless noted):
//! - Fresh counters are consumed in the delta's dot order (fields by id, entries/elements by dot), each
//!   restored position write before re-inserted list elements; within one re-add the entry or element dot
//!   comes as in the model's `create`/`insert_run` (map entry dot first, list content first).
//! - Restored position writes are stamped in ascending order of the stamp of the position they restore
//!   (the undo buffer's `cur`); they carry its sibling key (§5.7), so this only matters to cycle breaking.
//! - A re-inserted list element is anchored at the deleted element's own dot, so it lands right after it.
//! - A delete or undelete flag write is inverted only on elements whose flag the undone write changed:
//!   a delete range's elements already hidden in the undo buffer stay hidden.
//! - A set remove is undone by one re-add per distinct value removed.
//! - An element or entry the undone commit created is undone by the creation rule (element reset, text
//!   delete flag), never by "Absent before" at its fragment: the read is the same.
//! - A register-root `replace` is undone by the register rule.
//! - "Absent before": a value-carrying write held value-less (§4.7) does not block the reset; once the outermost
//!   absent P is blocked, no deeper position is tried.
//! - A case write without a reset (an enum created at an absent spot whose P was blocked) writes nothing.
use crate::ops::{create, key_state, live_elems, live_entries, register, remove, replace, Ty, Writer};
use crate::stamp::{Dot, Stamp};
use crate::state::{Anchor, Content, Eid, Elem, Entry, Frag, SeqElem, sib_key};
use crate::value::Value;
use std::collections::BTreeMap;

/// Which rules an undo applied, for coverage checks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// "Absent before" at the aspect root / at a nested position.
    pub absent_root: usize,
    pub absent_nested: usize,
    /// "Absent before" found P but P holds value-carrying writes or `W` of other commits: per-write rules applied.
    pub absent_blocked: usize,
    /// A fragment reset undone by `replace` with the pre-reset value.
    pub replace: usize,
    /// A bag `set`/`remove_aspect` undone without a fragment reset (§5.2).
    pub bag_reset: usize,
    /// A register write stepped back to the previous value.
    pub register: usize,
    /// A register write left alone: no longer the winner, or nothing to restore below a present composite.
    pub register_kept: usize,
    /// An element the original created, reset or delete-flagged.
    pub creation: usize,
    /// A text flag inverted.
    pub flag: usize,
    /// A list element / set value / map key re-added with a fresh dot.
    pub list_reinsert: usize,
    pub set_readd: usize,
    pub key_readd: usize,
    /// A position write restored / left alone.
    pub position: usize,
    pub position_kept: usize,
    /// A register or position stepped back through an undo commit's restoring write (`restored`).
    pub stepped: usize,
}

struct Cx<'a> {
    made: &'a dyn Fn(&Dot) -> bool,
    restored: &'a dyn Fn(&Stamp) -> bool,
    stats: Stats,
}

/// The undo delta of `undone` (one aspect's delta of the undone commit, full stamps). `made`: elements the
/// original created (its source and counter range). `state`: the current local state. `before`: the undo buffer,
/// the complete state before the undone commit (`None`: the aspect held nothing). `restored(s)`: the write stamped
/// `s` was written by an undo commit in effect and every later non-undo commit holding writes of the aspect is not
/// in effect (§4.6). `w` is the undo commit's writer. `None` when the undo writes nothing.
pub fn undo(w: &mut Writer, ty: &Ty, undone: &Frag, made: &dyn Fn(&Dot) -> bool, state: &Frag, before: Option<&Frag>, restored: &dyn Fn(&Stamp) -> bool) -> Option<Frag> {
    undo_stats(w, ty, undone, made, state, before, restored).0
}

/// `undo` with the rules it applied.
pub fn undo_stats(w: &mut Writer, ty: &Ty, undone: &Frag, made: &dyn Fn(&Dot) -> bool, state: &Frag, before: Option<&Frag>, restored: &dyn Fn(&Stamp) -> bool) -> (Option<Frag>, Stats) {
    let mut cx = Cx { made, restored, stats: Stats::default() };
    let out = at(&mut cx, w, ty, undone, Some(state), before, true, true).filter(|f| !f.is_empty());
    (out, cx.stats)
}

/// The undo writes at one position: `d` the undone delta there, `s` the current state, `b` the undo buffer.
#[allow(clippy::too_many_arguments)]
fn at(cx: &mut Cx, w: &mut Writer, ty: &Ty, d: &Frag, s: Option<&Frag>, b: Option<&Frag>, root: bool, mut absent_ok: bool) -> Option<Frag> {
    // "Absent before": P is the outermost absent composite (or root) on the path; checked top-down, so the first
    // hit. Its reset applies only if every value-carrying write and explicit `W` P holds (deleted sequence
    // elements' creations aside) is the undone commit's or one `restored` allows; otherwise the
    // per-write rules apply at and below P (P is unique: no deeper position is tried).
    let present = b.map_or(false, |b| b.present());
    if absent_ok && !present && (root || ty.enc() != 0) {
        let mut own = true;
        if let Some(s) = s {
            let mut st = Vec::new();
            valued(s, &mut st);
            own = st.iter().all(|x| (cx.made)(&x.dot) || (cx.restored)(x));
        }
        absent_ok = false;
        if !own {
            cx.stats.absent_blocked += 1;
        } else if root {
            cx.stats.absent_root += 1;
        } else {
            cx.stats.absent_nested += 1;
        }
        if own {
            return Some(remove(w, ty.enc()));
        }
    }
    let s = s.and_then(|s| s.slot(ty.enc()));
    let b = b.and_then(|b| b.slot(ty.enc()));
    if ty.enc() != 0 && d.reset().is_some() {
        if let Frag::Bag { .. } = d {
            cx.stats.bag_reset += 1;
            return bag(cx, w, d, b, true);
        }
        cx.stats.replace += 1;
        // nothing for the reset itself when the pre-reset value was absent ("Absent before" blocked); the delta's
        // writes below it then take their own rules
        if let Some(v) = b.filter(|b| b.present()).and_then(|b| b.read()) {
            return Some(replace(w, ty, &v));
        }
    }
    match (ty, d) {
        (Ty::Register, Frag::Register { write: Some((sd, v)), .. }) => {
            let cur = match s {
                Some(Frag::Register { write, .. }) => write.as_ref(),
                _ => None,
            };
            let stepped = cur.map_or(false, |(cs, cv)| cs != sd && cv.is_some() && cv == v && (cx.restored)(cs));
            let winner = stepped || cur.map_or(false, |(cs, _)| cs == sd);
            // nothing to restore: a register below a present composite is not written (no reset there)
            let prev = b.filter(|b| b.present()).and_then(|b| b.read());
            match (winner, prev) {
                (true, Some(p)) => {
                    cx.stats.register += 1;
                    cx.stats.stepped += usize::from(stepped);
                    Some(Frag::Register { reset: None, write: Some((w.delta(), Some(p))) })
                }
                _ => {
                    cx.stats.register_kept += 1;
                    None
                }
            }
        }
        (Ty::Counter | Ty::Max | Ty::Min, Frag::Bag { .. }) => bag(cx, w, d, b, false),
        (Ty::Struct(fts), Frag::Struct { fields, .. }) => {
            let mut out = BTreeMap::new();
            for (id, fd) in fields {
                let Some(ft) = fts.get(id) else { continue };
                let sf = match s {
                    Some(Frag::Struct { fields, .. }) => fields.get(id),
                    _ => None,
                };
                let bf = match b {
                    Some(Frag::Struct { fields, .. }) => fields.get(id),
                    _ => None,
                };
                if let Some(x) = at(cx, w, ft, fd, sf, bf, false, absent_ok) {
                    out.insert(*id, x);
                }
            }
            (!out.is_empty()).then(|| Frag::Struct { c: Default::default(), fields: out })
        }
        (Ty::Enum(cases), Frag::Enum { payloads, .. }) => {
            // a case write is undone by the fragment reset rule: re-insert above, or nothing (pre-reset value
            // absent); payload writes take their own rules
            let mut out = BTreeMap::new();
            for (id, pd) in payloads {
                let Some(Some(pt)) = cases.get(id) else { continue };
                let sp = match s {
                    Some(Frag::Enum { payloads, .. }) => payloads.get(id),
                    _ => None,
                };
                let bp = match b {
                    Some(Frag::Enum { payloads, .. }) => payloads.get(id),
                    _ => None,
                };
                if let Some(x) = at(cx, w, pt, pd, sp, bp, false, absent_ok) {
                    out.insert(*id, x);
                }
            }
            (!out.is_empty()).then(|| Frag::Enum { c: Default::default(), case: None, payloads: out })
        }
        (Ty::Set(_), Frag::Set { elems, .. }) => {
            let u = w.delta();
            let mut out = BTreeMap::new();
            let mut readd: Vec<Value> = Vec::new();
            let belems = match b {
                Some(Frag::Set { elems, .. }) => Some(elems),
                _ => None,
            };
            for (dot, e) in elems {
                if e.frag.is_some() && (cx.made)(dot) {
                    cx.stats.creation += 1;
                    out.insert(dot.clone(), Elem { reset: Some(u.clone()), frag: None });
                } else if e.reset.is_some() {
                    let v = belems.and_then(|be| be.get(dot)).and_then(|be| be.frag.as_ref()).and_then(|f| f.read());
                    if let Some(v) = v {
                        if !readd.contains(&v) {
                            readd.push(v);
                        }
                    }
                }
            }
            for v in readd {
                cx.stats.set_readd += 1;
                let nd = w.stamp().dot;
                out.insert(nd, Elem { reset: None, frag: Some(Box::new(register(w, v))) });
            }
            (!out.is_empty()).then(|| Frag::Set { c: Default::default(), elems: out })
        }
        (Ty::Map(_, vt), Frag::Map { entries, .. }) => {
            let u = w.delta();
            let sentries = match s {
                Some(Frag::Map { entries, .. }) => Some(entries),
                _ => None,
            };
            let bentries = match b {
                Some(Frag::Map { entries, .. }) => Some(entries),
                _ => None,
            };
            // below a key, a position's value is that of the join of the key's live entries (§4.6, §5.6)
            let at_key = |es: Option<&BTreeMap<Eid, Entry>>, k: &Value| -> Option<Frag> {
                let es = es?;
                let dots = live_entries(es).remove(k)?;
                key_state(es, &dots)
            };
            let mut out = BTreeMap::new();
            let mut removed: BTreeMap<Value, Vec<Eid>> = BTreeMap::new();
            for (id, e) in entries {
                if e.frag.is_some() && (cx.made)(&id.0) {
                    cx.stats.creation += 1;
                    out.insert(w.removal(id), Entry { reset: Some(u.clone()), frag: None, created: None });
                } else if e.reset.is_some() {
                    // the live records it removed: its own, or a key-erased record's every record of the dot
                    for (x, _) in bentries.map(crate::state::live_records).unwrap_or_default() {
                        if let (true, Some(k)) = (x.0 == id.0 && (id.1.is_none() || x == *id), &x.1) {
                            removed.entry(k.clone()).or_default().push(x.clone());
                        }
                    }
                } else if let (Some(k), Some(fd)) = (&id.1, &e.frag) {
                    let (sv, bv) = (at_key(sentries, k), at_key(bentries, k));
                    if let Some(x) = at(cx, w, vt, fd, sv.as_ref(), bv.as_ref(), false, absent_ok) {
                        out.insert(id.clone(), Entry { reset: None, frag: Some(Box::new(x)), created: None });
                    }
                }
            }
            for (k, dots) in removed {
                let Some(v) = bentries.and_then(|be| key_state(be, &dots)).and_then(|f| f.read()) else { continue };
                cx.stats.key_readd += 1;
                let st = w.stamp();
                let frag = create(w, vt, &v);
                out.insert((st.dot.clone(), Some(k)), Entry { reset: None, frag: Some(Box::new(frag)), created: Some(st) });
            }
            (!out.is_empty()).then(|| Frag::Map { c: Default::default(), entries: out })
        }
        (Ty::Text | Ty::List(_), Frag::Seq { text, elems, .. }) => seq(cx, w, ty, *text, elems, s, b, absent_ok),
        _ => None,
    }
}

/// Bag undo (§5.2): a contribution by an element reset on its dot; a re-added contribution (undo of an element
/// reset) with a fresh dot; with `reset` (a `set` or `remove_aspect`) also every live contribution of the undo
/// buffer re-added, and no fragment reset.
fn bag(cx: &mut Cx, w: &mut Writer, d: &Frag, b: Option<&Frag>, reset: bool) -> Option<Frag> {
    let Frag::Bag { kind, elems, .. } = d else { return None };
    let belems = match b {
        Some(Frag::Bag { elems, .. }) => Some(elems),
        _ => None,
    };
    let u = w.delta();
    let mut out = BTreeMap::new();
    let mut readd: Vec<Value> = Vec::new();
    for (dot, e) in elems {
        if e.frag.is_some() && (cx.made)(dot) {
            cx.stats.creation += 1;
            out.insert(dot.clone(), Elem { reset: Some(u.clone()), frag: None });
        } else if e.reset.is_some() && !reset {
            if let Some(v) = belems.and_then(|be| be.get(dot)).and_then(|be| be.frag.as_ref()).and_then(|f| f.read()) {
                readd.push(v);
            }
        }
    }
    if reset {
        if let Some(be) = belems {
            readd.extend(live_elems(be).into_iter().map(|(_, v)| v));
        }
    }
    for v in readd {
        let nd = w.stamp().dot;
        out.insert(nd, Elem { reset: None, frag: Some(Box::new(register(w, v))) });
    }
    (!out.is_empty()).then(|| Frag::Bag { kind: *kind, c: Default::default(), elems: out })
}

/// Sequence undo (§5.7): insert by a delete flag (text) or element reset (list); a text delete by an undelete
/// carrying the char, a list delete by re-inserting the value with a fresh dot; a move by a position write back to
/// the pre-move anchor when the undone write is still `cur` (or §4.6 steps back); nested element edits recursively.
#[allow(clippy::too_many_arguments)]
fn seq(cx: &mut Cx, w: &mut Writer, ty: &Ty, text: bool, elems: &BTreeMap<Dot, SeqElem>, s: Option<&Frag>, b: Option<&Frag>, absent_ok: bool) -> Option<Frag> {
    let selems = match s {
        Some(Frag::Seq { elems, .. }) => Some(elems),
        _ => None,
    };
    let belems = match b {
        Some(Frag::Seq { elems, .. }) => Some(elems),
        _ => None,
    };
    let et = match ty {
        Ty::List(et) => Some(&**et),
        _ => None,
    };
    let u = w.delta();
    let mut out: BTreeMap<Dot, SeqElem> = BTreeMap::new();
    let mut moves: Vec<(Stamp, Dot, Anchor, Stamp)> = Vec::new();
    let mut reinserts: Vec<(Dot, Value)> = Vec::new();
    for (dot, e) in elems {
        if e.created.is_some() && (cx.made)(dot) {
            cx.stats.creation += 1;
            out.insert(dot.clone(), SeqElem::write(Content::None, vec![], Some((u.clone(), true))));
            continue;
        }
        let be = belems.and_then(|be| be.get(dot));
        if let Some((_, flag)) = &e.deleted {
            if text {
                // invert only what the undone write changed
                let was = be.map_or(false, |be| be.is_deleted(true));
                if *flag != was {
                    cx.stats.flag += 1;
                    let content = if *flag { be.map_or(Content::None, |be| be.content.clone()) } else { Content::None };
                    let r = out.entry(dot.clone()).or_insert_with(|| SeqElem::write(Content::None, vec![], None));
                    r.deleted = Some((u.clone(), was));
                    r.content = content;
                }
            } else if let Some(Content::Frag(f)) = be.map(|be| &be.content) {
                if let Some(v) = f.read() {
                    reinserts.push((dot.clone(), v));
                }
            }
        }
        if let Some(p) = e.pos.iter().max_by(|x, y| x.0.cmp(&y.0)) {
            let (sd, anchor) = (&p.0, &p.1);
            let cur = selems.and_then(|se| se.get(dot)).and_then(|se| se.pos.first());
            // equal in value: anchor and sibling key (§4.6)
            let stepped = cur.map_or(false, |c| c.0 != *sd && c.1 == *anchor && sib_key(c) == sib_key(p) && (cx.restored)(&c.0));
            let winner = stepped || cur.map_or(false, |c| c.0 == *sd);
            match (winner, be.and_then(|be| be.pos.first())) {
                (true, Some(b)) => {
                    cx.stats.stepped += usize::from(stepped);
                    // the restored write carries the old one's sibling key, so it sorts where it was (§5.7)
                    moves.push((b.0.clone(), dot.clone(), b.1.clone(), sib_key(b).clone()))
                }
                _ => cx.stats.position_kept += 1,
            }
        }
        if let (Content::Frag(fd), Some(et)) = (&e.content, et) {
            let sv = selems.and_then(|se| se.get(dot)).and_then(|se| match &se.content {
                Content::Frag(f) => Some(&**f),
                _ => None,
            });
            let bv = be.and_then(|be| match &be.content {
                Content::Frag(f) => Some(&**f),
                _ => None,
            });
            if let Some(x) = at(cx, w, et, fd, sv, bv, false, absent_ok) {
                out.entry(dot.clone()).or_insert_with(|| SeqElem::write(Content::None, vec![], None)).content = Content::Frag(Box::new(x));
            }
        }
    }
    moves.sort();
    for (_, dot, anchor, key) in moves {
        cx.stats.position += 1;
        let st = w.stamp();
        out.entry(dot).or_insert_with(|| SeqElem::write(Content::None, vec![], None)).pos = vec![(st, anchor, Some(key))];
    }
    for (dot, v) in reinserts {
        cx.stats.list_reinsert += 1;
        let content = Content::Frag(Box::new(create(w, et.expect("list"), &v)));
        let st = w.stamp();
        out.insert(st.dot.clone(), SeqElem::new(st, Anchor::Dot(dot), content));
    }
    (!out.is_empty()).then(|| Frag::Seq { text, c: Default::default(), elems: out })
}


/// The stamps of the writes held in `f` that block "Absent before": explicit `W` and value-carrying writes (§4.7)
/// held with their value (register values, case writes, set and bag element values, map entry creations, sequence
/// element creations), deleted sequence elements' creations aside.
fn valued(f: &Frag, out: &mut Vec<Stamp>) {
    if let Some(c) = f.composite() {
        out.extend(c.w.clone());
    }
    match f {
        Frag::Register { write, .. } => out.extend(write.as_ref().filter(|w| w.1.is_some()).map(|w| w.0.clone())),
        Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.values().filter_map(|e| e.frag.as_deref()).for_each(|x| valued(x, out)),
        Frag::Struct { fields, .. } => fields.values().for_each(|x| valued(x, out)),
        Frag::Enum { case, payloads, .. } => {
            out.extend(case.as_ref().filter(|c| c.1.is_some()).map(|c| c.0.clone()));
            payloads.values().for_each(|x| valued(x, out));
        }
        Frag::Map { entries, .. } => {
            for ((_, k), e) in entries {
                out.extend(e.created.clone().filter(|_| k.is_some()));
                if let Some(x) = &e.frag {
                    valued(x, out);
                }
            }
        }
        Frag::Seq { text, elems, .. } => {
            for e in elems.values() {
                if !e.is_deleted(*text) && !matches!(e.content, Content::None) {
                    out.extend(e.created.as_ref().map(|c| c.0.clone()));
                }
                if let Content::Frag(x) = &e.content {
                    valued(x, out);
                }
            }
        }
        Frag::Slots { .. } => f.members().into_iter().for_each(|m| valued(m, out)),
    }
}
