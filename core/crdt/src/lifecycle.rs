//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge (§4.6): removing writes by owner
//! dot, and whether that may be done in place.

use crate::changes::Changes;
use crate::fragment::{Bag, Elem, Fragment, Map, Register, Set, Slots};
use crate::remap::{Next, Rec, Visit, walk};
use crate::seq::{self, SeqContent};
use crate::stamp::{Dot, Stamp};
use osis_base::Value;
use std::collections::BTreeMap;

impl Fragment {
    /// Holds every value-carrying write owned by an expired (or purged) delta value-less (§4.7).
    /// `expired` is asked about owner dots (never `Derived`). Commutes with join; a node past a
    /// delta's `T` applies it after every join.
    pub fn strip(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_merging(expired);
    }

    /// `strip`, telling whether moving an entry's records to its key-erased record (§4.7, §5.6)
    /// joined a write beaten by another of the dot's records: a death the join may not have
    /// dated (spec/commits.md §5).
    pub fn strip_merging(&mut self, expired: &dyn Fn(&Dot) -> bool) -> bool {
        let mut ch = Changes::new();
        self.strip_values(expired, &mut ch);
        // drops `Derived` records left without a write
        self.prune(None, &mut Changes::new());
        !ch.deaths().is_empty()
    }

    /// Whether the fragment holds a value-less write (§4.7) of the commit of stamp `c` (its `ts`
    /// and source): a register or case write without its value, a key-erased record's creation,
    /// a text element's creation whose char is gone (a deleted element's tells nothing: snapshots
    /// never carry it). A list element whose content holds one is not live (§5.7 Live): its
    /// creation's value, the content its commit wrote, is held value-less.
    pub(crate) fn valueless_of(&self, c: &Stamp) -> bool {
        let same = |s: &Stamp| s.ts == c.ts && s.dot.owner().src == c.dot.owner().src;
        let reg = |r: &Register| r.write.as_ref().is_some_and(|w| w.value.is_none() && same(&w.stamp));
        match self {
            Fragment::Slots(Slots { reg: r, slots }) => r.as_ref().is_some_and(reg) || slots.values().any(|f| f.valueless_of(c)),
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values().filter_map(|e| e.frag.as_deref()).any(|f| f.valueless_of(c)),
            Fragment::Struct(s) => s.fields.values().any(|f| f.valueless_of(c)),
            Fragment::Enum(e) => e.case.as_ref().is_some_and(|k| k.case.is_none() && same(&k.stamp)) || e.payloads.values().any(|f| f.valueless_of(c)),
            Fragment::Map(m) => m.entries.iter().any(|(id, en)| (id.key.is_none() && en.created.as_ref().is_some_and(same)) || en.frag.as_deref().is_some_and(|f| f.valueless_of(c))),
            Fragment::Seq(s) => s.elems().values().any(|el| match &el.content {
                SeqContent::Frag(f) => f.valueless_of(c),
                SeqContent::None => s.text && !el.flag() && el.char().is_none() && el.created.as_ref().is_some_and(|(s, _)| same(s)),
                SeqContent::Char(_) => false,
            }),
        }
    }

    pub(crate) fn strip_values(&mut self, expired: &dyn Fn(&Dot) -> bool, ch: &mut Changes) {
        let exp = |d: &Dot| expired(d.owner());
        let reg = |r: &mut Register| {
            if let Some(w) = &mut r.write
                && exp(&w.stamp.dot)
            {
                w.value = None;
            }
        };
        match self {
            Fragment::Slots(Slots { reg: r, slots }) => {
                r.iter_mut().for_each(reg);
                slots.values_mut().for_each(|f| f.strip_values(expired, ch));
            }
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired, ch))
            }
            Fragment::Struct(s) => s.fields.values_mut().for_each(|f| f.strip_values(expired, ch)),
            Fragment::Enum(e) => {
                if let Some(c) = &mut e.case
                    && exp(&c.stamp.dot)
                {
                    c.case = None;
                }
                e.payloads.values_mut().for_each(|f| f.strip_values(expired, ch));
            }
            Fragment::Map(m) => {
                // the key is the creation's value, wherever a record of the entry repeats it
                m.erase_keys(&exp, ch);
                for f in m.entries.values_mut().filter_map(|en| en.frag.as_mut()) {
                    f.strip_values(expired, ch);
                }
            }
            Fragment::Seq(s) => seq::strip_values(s, expired, ch),
        }
    }

    /// Removes every write whose owner dot (`Derived` dots: the underlying dot) matches `pred`,
    /// with the records such dots created and others' writes nested in them, in place: un-merge
    /// of single deltas (spec/permissions.md §5.2, spec/crdt.md §4.6). The result is for a join
    /// or a `prune`, which give it canonical form (it may keep a map entry holding only its
    /// creation, and a `Slots` position without its register's embedding).
    pub fn remove_dots(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, &|_, _| false);
    }

    /// `remove_dots`, except that a record created by a matching dot `keep` accepts keeps
    /// others' writes nested in it (a map entry's or list element's content): the record stays
    /// in the state, a valid snapshot's copy keeping it (§4.6). `keep` is asked with the
    /// record's dot and, for a keyed map entry record, its key (records of one dot with
    /// different keys are independent, §5.6).
    pub fn remove_dots_keeping(&mut self, pred: &dyn Fn(&Dot) -> bool, keep: &dyn Fn(&Dot, Option<&Value>) -> bool) {
        self.remove_dots_in(pred, keep);
    }

    /// Removes exactly the writes whose owner dot matches `pred`, keeping others' writes nested
    /// in a record a matching dot created: a snapshot's copies of writes played elsewhere, the
    /// others still superseding there.
    pub fn remove_writes(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, &|_, _| true);
    }

    pub(crate) fn remove_dots_in(&mut self, pred: &dyn Fn(&Dot) -> bool, keep: &dyn Fn(&Dot, Option<&Value>) -> bool) {
        let bad = |s: &Option<Stamp>| s.as_ref().is_some_and(|s| pred(s.dot.owner()));
        match self {
            Fragment::Slots(_) => {
                // in place, not re-joined: a join would prune the creations kept below (a map
                // entry holding only its creation); the consumer's join or prune embeds and
                // prunes (§7)
                let Fragment::Slots(Slots { reg, slots }) = std::mem::take(self) else { return };
                let reg = reg.map(|mut r| {
                    if bad(&r.reset) {
                        r.reset = None;
                    }
                    if r.write.as_ref().is_some_and(|w| pred(w.stamp.dot.owner())) {
                        r.write = None;
                    }
                    r
                });
                let slots = slots.into_iter().map(|(k, mut f)| {
                    f.remove_dots_in(pred, keep);
                    (k, f)
                });
                *self = crate::state::assemble(reg, slots.collect());
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
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => remove_dots_elems(elems, pred, keep),
            Fragment::Struct(s) => s.fields.retain(|_, f| {
                f.remove_dots_in(pred, keep);
                !f.is_empty()
            }),
            Fragment::Enum(e) => {
                if e.case.as_ref().is_some_and(|c| pred(c.stamp.dot.owner())) {
                    e.case = None;
                }
                e.payloads.retain(|_, f| {
                    f.remove_dots_in(pred, keep);
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
                    if !keep(d.owner(), id.key()) {
                        en.frag = None;
                    }
                }
                if let Some(f) = &mut en.frag {
                    f.remove_dots_in(pred, keep);
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                // an entry's creation whose own dot stays is kept, though nothing else is left
                // in it: a join gives it to the entry where another body holds content, and
                // prunes it otherwise (§5.6); so the result is joined or pruned before use
                en.reset.is_some() || en.frag.is_some() || en.created.is_some()
            }),
            Fragment::Seq(s) => seq::remove_dots(s, pred, keep),
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

    /// Whether no writer's delta of a commit at `ts` or earlier can change this fragment (its
    /// stamps are all at the commit's `ts`, §2.4): a register holding a write or reset past `ts`,
    /// which resets everything older at the position, in any encoding (§5.1, §7).
    pub fn settled_above(&self, ts: osis_base::Ts) -> bool {
        let Fragment::Register(r) = self else { return false };
        r.reset.iter().map(|s| s.ts).chain(r.write.iter().map(|w| w.stamp.ts)).any(|x| x > ts)
    }

    /// Whether the fragment holds a write stamped exactly `s`: a register, case, reset or `W`
    /// write, a map entry's creation, a sequence element's creation (in a range record too),
    /// position or flag write. Unlike `holds_dots`, a record keyed by `s`'s dot whose creation
    /// is gone (a removed entry kept for its reset) does not count, nor another write sharing
    /// the dot.
    pub fn holds_stamp(&self, s: &Stamp) -> bool {
        walk(&mut HoldsStamp(s), self)
    }

    /// The stamps `holds_stamp` finds here, indexed: one walk, then a lookup per stamp.
    pub fn stamps(&self) -> Stamps {
        let mut s = Stamps::default();
        walk(&mut s, self);
        s
    }

    /// Whether a keyed map entry record carries a reset: a removal or tombstone naming its key,
    /// allowed only in role-class aspects (spec/crdt.md §5.6).
    pub fn keyed_resets(&self) -> bool {
        walk(&mut KeyedResets, self)
    }

    /// Adds the owner dot of every write and live record here to `out` (a range record's first).
    pub(crate) fn owner_dots(&self, out: &mut std::collections::BTreeSet<Dot>) {
        walk(&mut OwnerDots(out), self);
    }

    /// Whether a write of the delta owning dot `d` is here: a write stamped with its dot or a
    /// record's creation; unlike `holds_dots`, a tombstone keyed by `d` (the remover's) is not.
    pub fn holds_write(&self, d: &Dot) -> bool {
        walk(&mut HoldsWrite(d), self)
    }

    /// `holds_dots` with `holds`, else `dots_supersede`.
    pub(crate) fn dots_in(&self, pred: &dyn Fn(&Dot) -> bool, holds: bool) -> bool {
        walk(&mut DotsIn { pred, holds }, self)
    }
}

/// `Fragment::owner_dots`.
struct OwnerDots<'a>(&'a mut std::collections::BTreeSet<Dot>);

impl Visit for OwnerDots<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        self.0.insert(s.dot.owner().clone());
        false
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        // a tombstone or deleted element is not read: its creation's content is not copied
        let (d, live) = match r {
            Rec::Elem(d, x) => (d, x.frag.is_some()),
            Rec::Entry(id, e) => (&id.dot, e.created.is_some() || e.frag.is_some()),
            Rec::Seq(d, el) => (d, !el.deleted.as_ref().is_some_and(|x| x.1)),
        };
        if !live {
            return Next::NoContent;
        }
        self.0.insert(d.owner().clone());
        Next::On
    }
}

/// `Fragment::holds_write`.
struct HoldsWrite<'a>(&'a Dot);

impl Visit for HoldsWrite<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        s.dot.owner() == self.0
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        let hit = match r {
            Rec::Elem(d, x) => x.frag.is_some() && d.owner() == self.0,
            Rec::Entry(id, e) => e.created.is_some() && id.dot.owner() == self.0,
            Rec::Seq(d, el) => el.created.is_some() && d.owner() == self.0,
        };
        if hit { Next::Stop } else { Next::On }
    }
}

/// `Fragment::keyed_resets`.
struct KeyedResets;

impl Visit for KeyedResets {
    fn stamp(&mut self, _: &Stamp) -> bool {
        false
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        match r {
            Rec::Entry(id, e) if id.key.is_some() && e.reset.is_some() => Next::Stop,
            _ => Next::On,
        }
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

/// `Fragment::stamps`: the stamps `HoldsStamp` matches exactly, and the sequence records'
/// creations by `ts` (a range record's elements are created at its `ts`, `seq_span`).
#[derive(Default)]
pub struct Stamps {
    exact: std::collections::BTreeSet<Stamp>,
    created: BTreeMap<osis_base::Ts, Vec<(Dot, u64)>>,
}

impl Stamps {
    /// `Fragment::holds_stamp(s)` of the fragment indexed.
    pub fn holds(&self, s: &Stamp) -> bool {
        self.exact.contains(s) || self.created.get(&s.ts).is_some_and(|v| v.iter().any(|(d, span)| crate::seq_span::holds(d, *span, &s.dot)))
    }
}

impl Visit for Stamps {
    fn stamp(&mut self, x: &Stamp) -> bool {
        self.exact.insert(x.clone());
        false
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        match r {
            Rec::Elem(..) => {}
            Rec::Entry(_, e) => self.exact.extend(e.created.clone()),
            Rec::Seq(d, el) => {
                if let Some((c, _)) = &el.created {
                    self.exact.insert(c.clone());
                    self.created.entry(c.ts).or_default().push((d.clone(), el.span));
                }
                self.exact.extend(el.pos.iter().map(|p| p.0.clone()));
                self.exact.extend(el.deleted.as_ref().map(|x| x.0.clone()));
            }
        }
        Next::On
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
            Rec::Elem(d, _) | Rec::Entry(crate::fragment::Eid { dot: d, .. }, _) => (d, true, false),
            // a sequence element: with content (an undelete's copy of its char included, §4.7);
            // a flag or a position write of theirs other than the element's own creation, which
            // `remove_dots` keeps
            Rec::Seq(d, el) => (d, !matches!(el.content, SeqContent::None) || el.undel.is_some(), el.deleted.as_ref().is_some_and(|x| pred(x.0.dot.owner())) || el.pos.iter().any(|p| p.0.dot != *d && pred(p.0.dot.owner()))),
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

fn remove_dots_elems(elems: &mut BTreeMap<Dot, Elem>, pred: &dyn Fn(&Dot) -> bool, keep: &dyn Fn(&Dot, Option<&Value>) -> bool) {
    elems.retain(|d, el| {
        if el.reset.as_ref().is_some_and(|r| pred(r.dot.owner())) {
            el.reset = None;
        }
        if pred(d.owner()) && !keep(d.owner(), None) {
            el.frag = None;
        } else if let Some(f) = &mut el.frag {
            f.remove_dots_in(pred, keep);
            if f.is_empty() {
                el.frag = None;
            }
        }
        el.reset.is_some() || el.frag.is_some()
    });
}
