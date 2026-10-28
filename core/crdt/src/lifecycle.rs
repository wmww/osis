//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge (§4.6): removing writes by owner
//! dot, and whether that may be done in place.

use crate::changes::Changes;
use crate::fragment::{Bag, Elem, Fragment, Map, Register, Set, Slots};
use crate::seq;
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
                for (d, en) in m.entries.iter_mut() {
                    // the key is the creation's value; a key repeated by another record is ignored
                    if exp(d) {
                        en.key = None;
                    }
                    if let Some(f) = &mut en.frag {
                        f.strip_values(expired);
                    }
                }
            }
            Fragment::Seq(s) => seq::strip_values(s, expired),
        }
    }

    /// Removes every write whose owner dot (`Derived` dots: the underlying dot) matches `pred`,
    /// in place: un-merge of single deltas (spec/permissions.md §5.2, spec/crdt.md §4.6).
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
                let Fragment::Slots(Slots { reg, members }) = std::mem::take(self) else { return };
                let mut out = Fragment::default();
                let mut ch = Changes::new();
                if let Some(r) = reg {
                    let mut f = Fragment::Register(r);
                    f.remove_dots_in(pred, nested);
                    out.join_into(f, None, &mut ch);
                }
                for (_, mut f) in members {
                    f.remove_dots_in(pred, nested);
                    out.join_into(f, None, &mut ch);
                }
                *self = out;
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
            Fragment::Map(Map { entries, .. }) => entries.retain(|d, en| {
                if en.reset.as_ref().is_some_and(|r| pred(r.dot.owner())) {
                    en.reset = None;
                }
                if pred(d.owner()) && nested {
                    en.created = None;
                }
                if pred(d.owner()) && !nested {
                    en.frag = None;
                } else if let Some(f) = &mut en.frag {
                    f.remove_dots_in(pred, nested);
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                if en.frag.is_none() {
                    en.key = None;
                    en.created = None;
                }
                en.reset.is_some() || en.frag.is_some()
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
        let eq = |x: &Stamp| x == s;
        let opt = |x: &Option<Stamp>| x.as_ref().is_some_and(eq);
        let sub = |f: &Fragment| f.holds_stamp(s);
        if self.meta().is_some_and(|m| opt(&m.reset) || opt(&m.w)) {
            return true;
        }
        let reg = |r: &Register| opt(&r.reset) || r.write.as_ref().is_some_and(|w| eq(&w.stamp));
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Slots(x) => x.reg.as_ref().is_some_and(reg) || x.members.values().any(sub),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values().any(|e| opt(&e.reset) || e.frag.as_deref().is_some_and(sub)),
            Fragment::Struct(x) => x.fields.values().any(sub),
            Fragment::Enum(e) => e.case.as_ref().is_some_and(|c| eq(&c.stamp)) || e.payloads.values().any(sub),
            Fragment::Map(m) => m.entries.values().any(|e| opt(&e.reset) || opt(&e.created) || e.frag.as_deref().is_some_and(sub)),
            Fragment::Seq(q) => q.elems().iter().any(|(d, el)| {
                // a range record's creations are its elements' dots at the record's `ts`
                let created = el.created.as_ref().is_some_and(|(c, _)| eq(c) || (c.ts == s.ts && crate::seq_span::holds(d, el.span, &s.dot)));
                created || el.pos.iter().any(|p| eq(&p.0)) || el.deleted.as_ref().is_some_and(|x| eq(&x.0)) || matches!(&el.content, crate::seq::SeqContent::Frag(f) if sub(f))
            }),
        }
    }

    /// `holds_dots` with `holds`, else `dots_supersede`.
    pub(crate) fn dots_in(&self, pred: &dyn Fn(&Dot) -> bool, holds: bool) -> bool {
        let a = |s: &Stamp| pred(s.dot.owner());
        let sub = |f: &Fragment| f.dots_in(pred, holds);
        if self.meta().is_some_and(|m| m.reset.as_ref().is_some_and(a) || m.w.as_ref().is_some_and(a)) {
            return true;
        }
        let reg = |r: &Register| r.reset.as_ref().is_some_and(a) || r.write.as_ref().is_some_and(|w| a(&w.stamp));
        // an element or entry: one they created, its reset, its content
        let rec = |d: &Dot, reset: Option<&Stamp>, f: Option<&Fragment>| {
            let theirs = pred(d.owner());
            (holds && theirs) || reset.is_some_and(a) || ((holds || !theirs) && f.is_some_and(sub))
        };
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Slots(s) => s.reg.as_ref().is_some_and(reg) || s.members.values().any(sub),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.iter().any(|(d, e)| rec(d, e.reset.as_ref(), e.frag.as_deref())),
            Fragment::Struct(s) => s.fields.values().any(sub),
            Fragment::Enum(e) => e.case.as_ref().is_some_and(|c| a(&c.stamp)) || e.payloads.values().any(sub),
            Fragment::Map(m) => m.entries.iter().any(|(d, e)| rec(d, e.reset.as_ref(), e.frag.as_deref())),
            Fragment::Seq(s) => seq::dots_in(s, pred, holds),
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
