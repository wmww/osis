//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge (§4.6): removing writes by owner
//! dot, and whether that may be done in place.

use crate::changes::Changes;
use crate::fragment::{Bag, Elem, Fragment, Map, Register, Set, Slots};
use crate::remap::{Next, Rec, Visit, walk};
use crate::seq::{self, SeqContent};
use crate::stamp::{Dot, Stamp};
use std::collections::BTreeMap;

impl Fragment {
    /// Holds every value-carrying write owned by an expired (or purged) delta value-less (§4.7).
    /// `expired` is asked about owner dots (never `Derived`). Commutes with join; a node past a
    /// delta's `T` applies it after every join.
    pub fn strip(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_values(expired);
        // drops `Derived` records left without a write
        self.prune(None, &mut Changes::new());
    }

    pub(crate) fn strip_values(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        let exp = |d: &Dot| expired(d.owner());
        let reg = |r: &mut Register| {
            if let Some(w) = &mut r.write
                && exp(&w.stamp.dot)
            {
                w.value = None;
            }
        };
        match self {
            Fragment::Slots(Slots { reg: r, members }) => {
                r.iter_mut().for_each(reg);
                members.values_mut().for_each(|f| f.strip_values(expired));
            }
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired))
            }
            Fragment::Struct(s) => s.fields.values_mut().for_each(|f| f.strip_values(expired)),
            Fragment::Enum(e) => {
                if let Some(c) = &mut e.case
                    && exp(&c.stamp.dot)
                {
                    c.case = None;
                }
                e.payloads.values_mut().for_each(|f| f.strip_values(expired));
            }
            Fragment::Map(m) => {
                // the key is the creation's value, wherever a record of the entry repeats it
                m.erase_keys(&exp);
                for f in m.entries.values_mut().filter_map(|en| en.frag.as_mut()) {
                    f.strip_values(expired);
                }
            }
            Fragment::Seq(s) => seq::strip_values(s, expired),
        }
    }

    /// Removes every write whose owner dot (`Derived` dots: the underlying dot) matches `pred`,
    /// in place: un-merge of single deltas (spec/permissions.md §5.2, spec/crdt.md §4.6). The
    /// result is for a join or a `prune`, which give it canonical form (it may keep a map entry
    /// holding only its creation, and a `Slots` position without its register's embedding).
    pub fn remove_dots(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, false);
    }

    /// Removes exactly the writes whose owner dot matches `pred`, keeping others' writes nested
    /// in a record a matching dot created (a map entry's or list element's content): a
    /// snapshot's copies of writes played elsewhere, the others still superseding there.
    pub fn remove_writes(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, true);
    }

    pub(crate) fn remove_dots_in(&mut self, pred: &dyn Fn(&Dot) -> bool, nested: bool) {
        let bad = |s: &Option<Stamp>| s.as_ref().is_some_and(|s| pred(s.dot.owner()));
        match self {
            Fragment::Slots(_) => {
                // in place, not re-joined: a join would prune the creations kept below (a map
                // entry holding only its creation); the consumer's join or prune embeds and
                // prunes (§7)
                let Fragment::Slots(Slots { reg, members }) = std::mem::take(self) else { return };
                let reg = reg.map(|mut r| {
                    if bad(&r.reset) {
                        r.reset = None;
                    }
                    if r.write.as_ref().is_some_and(|w| pred(w.stamp.dot.owner())) {
                        r.write = None;
                    }
                    r
                });
                let members = members.into_iter().map(|(k, mut f)| {
                    f.remove_dots_in(pred, nested);
                    (k, f)
                });
                *self = crate::state::assemble(reg, members.collect());
                return;
            }
            Fragment::Register(r) => {
                if bad(&r.reset) {
                    r.reset = None;
                }
                if r.write.as_ref().is_some_and(|w| pred(w.stamp.dot.owner())) {
                    r.write = None;
                }
            }
            _ => {}
        }
        if let Some(m) = self.meta_mut() {
            if bad(&m.reset) {
                m.reset = None;
            }
            if bad(&m.w) {
                m.w = None;
            }
        }
        match self {
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => remove_dots_elems(elems, pred, nested),
            Fragment::Struct(s) => s.fields.retain(|_, f| {
                f.remove_dots_in(pred, nested);
                !f.is_empty()
            }),
            Fragment::Enum(e) => {
                if e.case.as_ref().is_some_and(|c| pred(c.stamp.dot.owner())) {
                    e.case = None;
                }
                e.payloads.retain(|_, f| {
                    f.remove_dots_in(pred, nested);
                    !f.is_empty()
                });
            }
            Fragment::Map(Map { entries, .. }) => entries.retain(|id, en| {
                let d = &id.dot;
                if en.reset.as_ref().is_some_and(|r| pred(r.dot.owner())) {
                    en.reset = None;
                }
                if pred(d.owner()) {
                    en.created = None;
                    if !nested {
                        en.frag = None;
                    }
                }
                if let Some(f) = &mut en.frag {
                    f.remove_dots_in(pred, nested);
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                // an entry's creation whose own dot stays is kept, though nothing else is left
                // in it: a join gives it to the entry where another body holds content, and
                // prunes it otherwise (§5.6); so the result is joined or pruned before use
                en.reset.is_some() || en.frag.is_some() || en.created.is_some()
            }),
            Fragment::Seq(s) => seq::remove_dots(s, pred, nested),
            Fragment::Register(_) | Fragment::Slots(_) => {}
        }
    }

    /// Whether `remove_dots(pred)` in place could differ from removing them from every held
    /// body before the join (§4.6): one of their writes in this state may have superseded
    /// another's (a register, case, reset, `W`, flag or non-creation position write of theirs).
    /// The content of a record they created goes whole either way, so it is not looked into.
    pub fn dots_supersede(&self, pred: &dyn Fn(&Dot) -> bool) -> bool {
        self.dots_in(pred, false)
    }

    /// Whether the fragment holds a write or record `remove_dots(pred)` would remove or change.
    pub fn holds_dots(&self, pred: &dyn Fn(&Dot) -> bool) -> bool {
        self.dots_in(pred, true)
    }

    /// Whether the fragment holds a write stamped exactly `s`: a register, case, reset or `W`
    /// write, a map entry's creation, a sequence element's creation (in a range record too),
    /// position or flag write. Unlike `holds_dots`, a record keyed by `s`'s dot whose creation
    /// is gone (a removed entry kept for its reset) does not count, nor another write sharing
    /// the dot.
    pub fn holds_stamp(&self, s: &Stamp) -> bool {
        walk(&mut HoldsStamp(s), self)
    }

    /// `holds_dots` with `holds`, else `dots_supersede`.
    pub(crate) fn dots_in(&self, pred: &dyn Fn(&Dot) -> bool, holds: bool) -> bool {
        walk(&mut DotsIn { pred, holds }, self)
    }
}

/// `Fragment::holds_stamp`.
struct HoldsStamp<'a>(&'a Stamp);

impl Visit for HoldsStamp<'_> {
    fn stamp(&mut self, x: &Stamp) -> bool {
        x == self.0
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        let s = self.0;
        let hit = match r {
            Rec::Elem(..) => false,
            Rec::Entry(_, e) => e.created.as_ref() == Some(s),
            Rec::Seq(d, el) => {
                // a range record's creations are its elements' dots at the record's `ts`
                let created = el.created.as_ref().is_some_and(|(c, _)| c == s || (c.ts == s.ts && crate::seq_span::holds(d, el.span, &s.dot)));
                created || el.pos.iter().any(|p| p.0 == *s) || el.deleted.as_ref().is_some_and(|x| x.0 == *s)
            }
        };
        if hit { Next::Stop } else { Next::On }
    }
}

/// `Fragment::dots_in`: their writes, and records they created (`holds`: whose content goes
/// with them; else not looked into).
struct DotsIn<'a> {
    pred: &'a dyn Fn(&Dot) -> bool,
    holds: bool,
}

impl Visit for DotsIn<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        (self.pred)(s.dot.owner())
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        let pred = self.pred;
        // `own`: whether a record of theirs counts with `holds`; `other`: a write of theirs on it
        let (d, own, other) = match r {
            Rec::Elem(d, _) | Rec::Entry(d, _) => (d, true, false),
            // a sequence element: with content; a flag or a position write of theirs other than
            // the element's own creation, which `remove_dots` keeps
            Rec::Seq(d, el) => (d, !matches!(el.content, SeqContent::None), el.deleted.as_ref().is_some_and(|x| pred(x.0.dot.owner())) || el.pos.iter().any(|p| p.0.dot != *d && pred(p.0.dot.owner()))),
        };
        let theirs = pred(d.owner());
        if other || (self.holds && theirs && own) {
            Next::Stop
        } else if self.holds || !theirs {
            Next::On
        } else {
            Next::NoContent
        }
    }
}

fn remove_dots_elems(elems: &mut BTreeMap<Dot, Elem>, pred: &dyn Fn(&Dot) -> bool, nested: bool) {
    elems.retain(|d, el| {
        if el.reset.as_ref().is_some_and(|r| pred(r.dot.owner())) {
            el.reset = None;
        }
        if pred(d.owner()) && !nested {
            el.frag = None;
        } else if let Some(f) = &mut el.frag {
            f.remove_dots_in(pred, nested);
            if f.is_empty() {
                el.frag = None;
            }
        }
        el.reset.is_some() || el.frag.is_some()
    });
}
