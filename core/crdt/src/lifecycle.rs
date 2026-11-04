//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge (§4.6): removing writes by owner
//! dot, and whether that may be done in place.

use crate::changes::Changes;
use crate::fragment::{Bag, Eid, Elem, Entry, Enum, Fragment, Map, Meta, Register, Set, Slots, Struct};
use crate::remap::{Next, Rec, Visit, walk};
use crate::seq::{self, Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Stamp};
use osis_base::Value;
use std::collections::BTreeMap;

impl Fragment {
    /// The value-less copy of the writes `expired` owns (§4.7): what a snapshot carries of an
    /// expiring delta, a residue. It says nothing of whether they expired here: a valued copy
    /// joined with it reads valued. `expired` is asked about owner dots (never `Derived`).
    pub fn strip(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_values(expired, false, &mut Changes::new());
        // drops `Derived` records left without a write
        self.prune(None, &mut Changes::new());
    }

    /// Holds the writes `expired` owns value-less at this node (§4.7): `strip`, and a list
    /// element they created gets its creation's own stamp as its reset (§5.7 Live). Commutes
    /// with join; a node past a delta's `T`, or holding a purge of it, applies it after every
    /// join and rebuild.
    pub fn expire(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_values(expired, true, &mut Changes::new());
        self.prune(None, &mut Changes::new());
    }

    pub(crate) fn strip_values(&mut self, expired: &dyn Fn(&Dot) -> bool, at_node: bool, ch: &mut Changes) {
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
                slots.values_mut().for_each(|f| f.strip_values(expired, at_node, ch));
            }
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => {
                elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired, at_node, ch))
            }
            Fragment::Struct(s) => s.fields.values_mut().for_each(|f| f.strip_values(expired, at_node, ch)),
            Fragment::Enum(e) => {
                if let Some(c) = &mut e.case
                    && exp(&c.stamp.dot)
                {
                    c.case = None;
                }
                e.payloads.values_mut().for_each(|f| f.strip_values(expired, at_node, ch));
            }
            Fragment::Map(m) => {
                // the key is the creation's value, wherever a record of the entry repeats it
                m.erase_keys(&exp, ch);
                for f in m.entries.values_mut().filter_map(|en| en.frag.as_mut()) {
                    f.strip_values(expired, at_node, ch);
                }
            }
            Fragment::Seq(s) => seq::strip_values(s, expired, at_node, ch),
        }
    }

    /// The writes of a compacting writer's sweep (spec/crdt.md §4.8, spec/sync.md §7): a reset at
    /// `r` of each map entry and list element that is not live and whose reset or expiry here
    /// (`gone`, owner dots) hid what is written in it, so that it dies and its bytes go. A record
    /// merely lacking its creation is no such thing: the creation may still arrive. Below a
    /// record it resets nothing more (that reset takes it all). Not for role-class aspects (a
    /// removal there names its key).
    pub fn sweep(&self, r: &Stamp, gone: &dyn Fn(&Dot) -> bool) -> Option<Fragment> {
        match self {
            Fragment::Register(_) | Fragment::Bag(_) | Fragment::Set(_) => None,
            Fragment::Slots(_) => self.chosen().sweep(r, gone),
            Fragment::Struct(s) => {
                let fields: BTreeMap<u64, Fragment> = s.fields.iter().filter_map(|(k, f)| Some((*k, f.sweep(r, gone)?))).collect();
                (!fields.is_empty()).then(|| Fragment::Struct(Struct { meta: Meta::default(), fields }))
            }
            Fragment::Enum(e) => {
                let payloads: BTreeMap<u64, Fragment> = e.payloads.iter().filter_map(|(k, f)| Some((*k, f.sweep(r, gone)?))).collect();
                (!payloads.is_empty()).then(|| Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads }))
            }
            Fragment::Map(m) => {
                let mut entries = BTreeMap::new();
                for (id, en) in &m.entries {
                    if m.is_live(id) {
                        if let Some(inner) = en.frag.as_deref().and_then(|f| f.sweep(r, gone)) {
                            entries.insert(id.clone(), Entry { frag: Some(Box::new(inner)), ..Entry::default() });
                        }
                    } else if id.key.is_some() || en.frag.is_some() || en.reset.is_some() {
                        let recs = || m.of_dot(&id.dot);
                        let hid = gone(id.dot.owner()) || recs().any(|(_, x)| x.reset.is_some());
                        // a key a record repeats goes with any write, a value-less one too; a
                        // key-erased record has bytes to lose only in a valued one. A sequence's
                        // bare anchors are no write: no reset takes them, so swept they would
                        // come up at every compaction
                        let holds = recs().any(|(i, x)| x.frag.as_deref().is_some_and(|f| if i.key.is_some() { f.all_max().is_some() } else { f.written().is_some() }));
                        if hid && holds && !recs().any(|(i, _)| m.is_live(i)) {
                            entries.insert(Eid::erased(id.dot.clone()), Entry::tomb(r));
                        }
                    }
                }
                (!entries.is_empty()).then(|| Fragment::Map(Map::new(Meta::default(), entries)))
            }
            Fragment::Seq(s) if s.text => None,
            Fragment::Seq(s) => {
                let mut out = Seq::empty(false);
                for (d, el) in s.elems() {
                    let SeqContent::Frag(f) = &el.content else { continue };
                    if seq::is_visible(el, false) {
                        if let Some(inner) = f.sweep(r, gone) {
                            out.elems_mut().insert(d.clone(), SeqElem { content: SeqContent::Frag(Box::new(inner)), ..SeqElem::bare() });
                        }
                    } else if f.written().is_some() && (el.reset().is_some() || gone(d.owner())) {
                        out.elems_mut().insert(d.clone(), SeqElem { deleted: Some((r.clone(), true)), ..SeqElem::bare() });
                    }
                }
                (!out.elems().is_empty()).then_some(Fragment::Seq(out))
            }
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
                // in it: a write of its own (§5.6)
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
