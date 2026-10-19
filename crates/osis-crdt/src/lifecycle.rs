//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge by author (§4.6).

use crate::changes::Changes;
use crate::fragment::{Bag, Elem, Fragment, Map, Set, Slots};
use crate::seq;
use crate::stamp::{Dot, Source, Stamp};
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
        match self {
            Fragment::Slots(Slots { reg, members }) => {
                if let Some(r) = reg
                    && let Some(w) = &mut r.write
                    && exp(&w.stamp.dot)
                {
                    w.value = None;
                }
                members.values_mut().for_each(|f| f.strip_values(expired));
            }
            Fragment::Register(r) => {
                if let Some(w) = &mut r.write
                    && exp(&w.stamp.dot)
                {
                    w.value = None;
                }
            }
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

    /// Removes every write whose dot's author matches `author` (`Derived` dots count for the
    /// author of the underlying dot), in place. Un-merge applies it to each held body (§4.6).
    pub fn remove_author(&mut self, author: &dyn Fn(&Source) -> bool) {
        let bad = |s: &Option<Stamp>| s.as_ref().is_some_and(|s| author(s.dot.src.author()));
        match self {
            Fragment::Slots(_) => {
                let Fragment::Slots(Slots { reg, members }) = std::mem::take(self) else { return };
                let mut out = Fragment::default();
                let mut ch = Changes::new();
                if let Some(r) = reg {
                    let mut f = Fragment::Register(r);
                    f.remove_author(author);
                    out.join_into(f, None, &mut ch);
                }
                for (_, mut f) in members {
                    f.remove_author(author);
                    out.join_into(f, None, &mut ch);
                }
                *self = out;
                return;
            }
            Fragment::Register(r) => {
                if bad(&r.reset) {
                    r.reset = None;
                }
                if r.write.as_ref().is_some_and(|w| author(w.stamp.dot.src.author())) {
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
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => remove_author_elems(elems, author),
            Fragment::Struct(s) => s.fields.retain(|_, f| {
                f.remove_author(author);
                !f.is_empty()
            }),
            Fragment::Enum(e) => {
                if e.case.as_ref().is_some_and(|c| author(c.stamp.dot.src.author())) {
                    e.case = None;
                }
                e.payloads.retain(|_, f| {
                    f.remove_author(author);
                    !f.is_empty()
                });
            }
            Fragment::Map(Map { entries, .. }) => entries.retain(|d, en| {
                if en.reset.as_ref().is_some_and(|r| author(r.dot.src.author())) {
                    en.reset = None;
                }
                if author(d.src.author()) {
                    en.frag = None;
                } else if let Some(f) = &mut en.frag {
                    f.remove_author(author);
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                if en.frag.is_none() {
                    en.key = None;
                }
                en.reset.is_some() || en.frag.is_some()
            }),
            Fragment::Seq(s) => seq::remove_author(s, author),
            Fragment::Register(_) | Fragment::Slots(_) => {}
        }
    }

    /// Whether removing `author`'s writes in place could expose a write it superseded: it holds
    /// a register, case, reset or `W` (a position winner needs the retained bodies, §4.6).
    pub fn author_supersedes(&self, author: &dyn Fn(&Source) -> bool) -> bool {
        let a = |s: &Stamp| author(s.dot.src.author());
        let sub = |f: &Fragment| f.author_supersedes(author);
        // `W` is max-joined like a register: the author's may have topped another's
        if self.meta().is_some_and(|m| m.reset.as_ref().is_some_and(a) || m.w.as_ref().is_some_and(a)) || self.reset().as_ref().is_some_and(a) {
            return true;
        }
        match self {
            Fragment::Register(r) => r.write.as_ref().is_some_and(|w| a(&w.stamp)),
            Fragment::Slots(s) => s.reg.as_ref().is_some_and(|r| r.write.as_ref().is_some_and(|w| a(&w.stamp))) || s.members.values().any(sub),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values().any(|e| e.reset.as_ref().is_some_and(a)),
            Fragment::Struct(s) => s.fields.values().any(sub),
            Fragment::Enum(e) => e.case.as_ref().is_some_and(|c| a(&c.stamp)) || e.payloads.values().any(sub),
            Fragment::Map(m) => m.entries.values().any(|e| e.reset.as_ref().is_some_and(a) || e.frag.as_deref().is_some_and(sub)),
            // positions and flags: conservatively, any sequence write by the author
            Fragment::Seq(_) => true,
        }
    }
}

fn remove_author_elems(elems: &mut BTreeMap<Dot, Elem>, author: &dyn Fn(&Source) -> bool) {
    elems.retain(|d, el| {
        if el.reset.as_ref().is_some_and(|r| author(r.dot.src.author())) {
            el.reset = None;
        }
        if author(d.src.author()) {
            el.frag = None;
        } else if let Some(f) = &mut el.frag {
            f.remove_author(author);
            if f.is_empty() {
                el.frag = None;
            }
        }
        el.reset.is_some() || el.frag.is_some()
    });
}

/// Un-merge (§4.6): the join of every held body and value-less residue for the aspect (the
/// node's current state among them, as a snapshot it holds), each without `author`'s writes.
/// A function of the held set, never of arrival order.
pub fn unmerge(held: impl IntoIterator<Item = Fragment>, author: &dyn Fn(&Source) -> bool) -> Fragment {
    let mut out = Fragment::default();
    let mut ch = Changes::new();
    for mut b in held {
        b.remove_author(author);
        out.join_into(b, None, &mut ch);
    }
    out
}

/// The in-place fast path of un-merge: removes `author`'s writes from `state` directly when that
/// equals the join of held bodies (the author superseded nothing, §4.6). `false` if the caller
/// must use `unmerge` with the retained bodies.
pub fn unmerge_in_place(state: &mut Fragment, author: &dyn Fn(&Source) -> bool) -> bool {
    if state.author_supersedes(author) {
        return false;
    }
    state.remove_author(author);
    state.prune(None, &mut Changes::new());
    true
}
