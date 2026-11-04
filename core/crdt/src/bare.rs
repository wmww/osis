//! Bare structure of a map entry's records (spec/crdt.md §5.6 Bare anchors): a keyed record
//! holds only its writes and the records on their paths; every record of the dot holding no
//! write at or below it (a sequence's bare anchors and the records around them) is held by the
//! dot's key-erased record, so no key outlives its entry's content.
//!
//! Both are functions of the dot's records together (the union of their records and each one's
//! writes), so the state is the same in any arrival order.

use crate::fragment::{Enum, Fragment, Map, Meta, Struct};
use crate::seq::{Seq, SeqContent, SeqElem};
use crate::seq_span::{Elems, holds, nth, split_at};
use crate::state::{SlotRef, assemble, parts};
use crate::stamp::Dot;
use std::collections::BTreeMap;

/// A sequence element's own writes: creation, position, flag (a char needs the creation).
fn own(e: &SeqElem) -> bool {
    e.created.is_some() || !e.pos.is_empty() || e.deleted.is_some()
}

impl Fragment {
    /// Whether a record somewhere below holds no write at or below it.
    fn has_bare(&self) -> bool {
        match self {
            Fragment::Register(_) | Fragment::Bag(_) | Fragment::Set(_) => false,
            Fragment::Struct(s) => s.fields.values().any(Fragment::has_bare),
            Fragment::Enum(e) => e.payloads.values().any(Fragment::has_bare),
            Fragment::Map(m) => m.entries.values().any(|en| en.frag.as_deref().is_some_and(Fragment::has_bare)),
            Fragment::Seq(s) => s.elems().values().any(|e| match &e.content {
                SeqContent::Frag(f) => f.has_bare(),
                _ => !own(e),
            }),
            Fragment::Slots(s) => s.slots.values().any(Fragment::has_bare),
        }
    }

    /// Cuts out every record holding no write at or below it, returned with its path (shells
    /// holding no write); `None` if there is none.
    pub(crate) fn take_bare(&mut self) -> Option<Fragment> {
        if !self.has_bare() {
            return None;
        }
        let cut = |m: &mut BTreeMap<u64, Fragment>| -> BTreeMap<u64, Fragment> {
            let out = m.iter_mut().filter_map(|(k, f)| Some((*k, f.take_bare()?))).collect();
            m.retain(|_, f| !f.is_empty());
            out
        };
        Some(match self {
            Fragment::Register(_) | Fragment::Bag(_) | Fragment::Set(_) => return None,
            Fragment::Struct(s) => Fragment::Struct(Struct { meta: Meta::default(), fields: cut(&mut s.fields) }),
            Fragment::Enum(e) => Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads: cut(&mut e.payloads) }),
            Fragment::Map(m) => {
                let mut out = BTreeMap::new();
                for (id, en) in m.entries.iter_mut() {
                    let Some(f) = en.frag.as_deref_mut() else { continue };
                    if let Some(b) = f.take_bare() {
                        out.insert(id.clone(), crate::fragment::Entry { frag: Some(Box::new(b)), ..Default::default() });
                    }
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                m.entries.retain(|_, en| en.reset.is_some() || en.frag.is_some() || en.created.is_some());
                m.reindex();
                Fragment::Map(Map::new(Meta::default(), out))
            }
            Fragment::Seq(s) => {
                let mut out = Elems::new();
                let elems = s.elems_mut();
                let dots: Vec<Dot> = elems.keys().cloned().collect();
                for d in dots {
                    let Some(e) = elems.get_mut(&d) else { continue };
                    let mine = own(e);
                    match &mut e.content {
                        SeqContent::Frag(f) => {
                            if let Some(b) = f.take_bare() {
                                out.insert(d.clone(), SeqElem { content: SeqContent::Frag(Box::new(b)), ..SeqElem::bare() });
                            }
                            if f.is_empty() {
                                e.content = SeqContent::None;
                                if !mine {
                                    elems.remove(&d);
                                }
                            }
                        }
                        _ if !mine => {
                            out.extend(elems.remove_entry(&d));
                        }
                        _ => {}
                    }
                }
                Fragment::Seq(Seq::new(s.text, Meta::default(), out))
            }
            Fragment::Slots(_) => {
                let (reg, mut slots) = parts(std::mem::take(self));
                let out: BTreeMap<_, _> = slots.iter_mut().filter_map(|(k, f)| Some((*k, f.take_bare()?))).collect();
                *self = assemble(reg, slots);
                assemble(None, out)
            }
        })
    }

    /// Drops the records holding no write at or below them that `by` also holds (§5.6 Bare
    /// anchors: there they are on a write's path).
    pub(crate) fn drop_held(&mut self, by: &Fragment) {
        if let Fragment::Slots(s) = self {
            for (enc, f) in s.slots.iter_mut() {
                if let Some(SlotRef::Frag(g)) = by.slot(*enc) {
                    f.drop_held(g);
                }
            }
            let (reg, slots) = parts(std::mem::take(self));
            *self = assemble(reg, slots);
            return;
        }
        if let Fragment::Slots(_) = by {
            if let Some(SlotRef::Frag(g)) = by.slot(self.encoding()) {
                self.drop_held(g);
            }
            return;
        }
        let nested = |m: &mut BTreeMap<u64, Fragment>, b: &BTreeMap<u64, Fragment>| {
            m.retain(|k, f| {
                if let Some(g) = b.get(k) {
                    f.drop_held(g);
                }
                !f.is_empty()
            });
        };
        match (self, by) {
            (Fragment::Struct(a), Fragment::Struct(b)) => nested(&mut a.fields, &b.fields),
            (Fragment::Enum(a), Fragment::Enum(b)) => nested(&mut a.payloads, &b.payloads),
            (Fragment::Map(a), Fragment::Map(b)) => {
                // the records of one dot are one entry: any of them holding a record holds it
                a.entries.retain(|id, en| {
                    if let Some(f) = en.frag.as_deref_mut() {
                        for g in b.of_dot(&id.dot).filter_map(|(_, x)| x.frag.as_deref()) {
                            f.drop_held(g);
                        }
                        if f.is_empty() {
                            en.frag = None;
                        }
                    }
                    en.reset.is_some() || en.frag.is_some() || en.created.is_some()
                });
                a.reindex();
            }
            (Fragment::Seq(a), Fragment::Seq(b)) if a.text == b.text => drop_held_elems(a, b),
            _ => {}
        }
    }
}

/// `drop_held` of a sequence: its bare records (ranges split where needed) and the contents of
/// its write-less list elements, against the records of `b`.
fn drop_held_elems(a: &mut Seq, b: &Seq) {
    // the pieces of `b`'s records inside `a`'s bare ranges, and `a`'s write-less containers `b` holds
    let mut pieces: Vec<(Dot, u64)> = Vec::new();
    let mut inner: Vec<Dot> = Vec::new();
    for (k, e) in a.elems().iter().filter(|(_, e)| !own(e)) {
        if matches!(e.content, SeqContent::Frag(_)) {
            if crate::seq_span::find(b.elems(), k).is_some() {
                inner.push(k.clone());
            }
            continue;
        }
        let end = nth(k, e.span);
        let first = crate::seq_span::find(b.elems(), k).map(|(x, _)| x.clone());
        let rest = b.elems().range::<Dot, _>((std::ops::Bound::Excluded(k), std::ops::Bound::Excluded(&end))).map(|(x, _)| x.clone());
        for (x, span) in first.into_iter().chain(rest).filter(|x| x.src == k.src).filter_map(|x| Some((x.clone(), b.elems().get(&x)?.span))) {
            let lo = x.ctr.max(k.ctr);
            let hi = (x.ctr + span).min(end.ctr);
            if lo < hi {
                pieces.push((Dot::new(k.src.clone(), lo), hi - lo));
            }
        }
    }
    if pieces.is_empty() && inner.is_empty() {
        return;
    }
    let elems = a.elems_mut();
    for (lo, n) in pieces {
        split_at(elems, &lo);
        split_at(elems, &nth(&lo, n));
        let gone: Vec<Dot> = elems.range(&lo..&nth(&lo, n)).filter(|(x, e)| holds(&lo, n, x) && !own(e) && matches!(e.content, SeqContent::None)).map(|(x, _)| x.clone()).collect();
        for x in gone {
            elems.remove(&x);
        }
    }
    for d in inner {
        let Some(SeqContent::Frag(g)) = crate::seq_span::find(b.elems(), &d).map(|(_, e)| &e.content) else {
            // held by `b` with no content of its own: the container goes once nothing is left in it
            continue;
        };
        if let Some(e) = elems.get_mut(&d)
            && let SeqContent::Frag(f) = &mut e.content
        {
            f.drop_held(g);
            if f.is_empty() {
                elems.remove(&d);
            }
        }
    }
}

#[cfg(any(test, fuzzing))]
impl Fragment {
    /// Whether no keyed record at any depth holds a record with no write at or below it (§5.6
    /// Bare anchors): no record of a removed or reset entry repeats its key.
    pub(crate) fn keys_hold_writes(&self) -> bool {
        match self {
            Fragment::Register(_) | Fragment::Bag(_) | Fragment::Set(_) => true,
            Fragment::Struct(s) => s.fields.values().all(Fragment::keys_hold_writes),
            Fragment::Enum(e) => e.payloads.values().all(Fragment::keys_hold_writes),
            Fragment::Map(m) => m.entries.iter().all(|(id, en)| en.frag.as_deref().is_none_or(|f| f.keys_hold_writes() && (id.key.is_none() || !f.has_bare()))),
            Fragment::Seq(s) => s.elems().values().all(|e| match &e.content {
                SeqContent::Frag(f) => f.keys_hold_writes(),
                _ => true,
            }),
            Fragment::Slots(s) => s.slots.values().all(Fragment::keys_hold_writes),
        }
    }
}
