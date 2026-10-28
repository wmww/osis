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
        let a = |s: &Stamp| pred(s.dot.owner());
        let sub = |f: &Fragment| f.dots_supersede(pred);
        if self.meta().is_some_and(|m| m.reset.as_ref().is_some_and(a) || m.w.as_ref().is_some_and(a)) {
            return true;
        }
        let reg = |r: &crate::fragment::Register| r.reset.as_ref().is_some_and(a) || r.write.as_ref().is_some_and(|w| a(&w.stamp));
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Slots(s) => s.reg.as_ref().is_some_and(reg) || s.members.values().any(sub),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                elems.iter().any(|(d, e)| e.reset.as_ref().is_some_and(a) || (!pred(d.owner()) && e.frag.as_deref().is_some_and(sub)))
            }
            Fragment::Struct(s) => s.fields.values().any(sub),
            Fragment::Enum(e) => e.case.as_ref().is_some_and(|c| a(&c.stamp)) || e.payloads.values().any(sub),
            Fragment::Map(m) => m.entries.iter().any(|(d, e)| e.reset.as_ref().is_some_and(a) || (!pred(d.owner()) && e.frag.as_deref().is_some_and(sub))),
            Fragment::Seq(s) => seq::dots_supersede(s, pred),
        }
    }

    /// Whether the fragment holds a write or record `remove_dots(pred)` would remove or change.
    pub fn holds_dots(&self, pred: &dyn Fn(&Dot) -> bool) -> bool {
        let a = |s: &Stamp| pred(s.dot.owner());
        let sub = |f: &Fragment| f.holds_dots(pred);
        if self.meta().is_some_and(|m| m.reset.as_ref().is_some_and(a) || m.w.as_ref().is_some_and(a)) {
            return true;
        }
        let reg = |r: &crate::fragment::Register| r.reset.as_ref().is_some_and(a) || r.write.as_ref().is_some_and(|w| a(&w.stamp));
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Slots(s) => s.reg.as_ref().is_some_and(reg) || s.members.values().any(sub),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.iter().any(|(d, e)| pred(d.owner()) || e.reset.as_ref().is_some_and(a) || e.frag.as_deref().is_some_and(sub)),
            Fragment::Struct(s) => s.fields.values().any(sub),
            Fragment::Enum(e) => e.case.as_ref().is_some_and(|c| a(&c.stamp)) || e.payloads.values().any(sub),
            Fragment::Map(m) => m.entries.iter().any(|(d, e)| pred(d.owner()) || e.reset.as_ref().is_some_and(a) || e.frag.as_deref().is_some_and(sub)),
            Fragment::Seq(s) => seq::holds_dots(s, pred),
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
