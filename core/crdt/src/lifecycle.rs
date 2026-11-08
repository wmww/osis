//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge (§4.6): removing writes by origin
//! dot, and whether that may be done in place.

use crate::changes::Changes;
use crate::fragment::{Bag, Eid, Elem, Entry, Enum, Fragment, Map, Meta, Register, Set, Slots, Struct};
use crate::remap::{Next, Rec, Visit, walk};
use crate::seq::{self, Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Stamp};
use osis_base::Value;
use std::collections::BTreeMap;

impl Fragment {
    /// Holds the writes `expired` owns value-less (§4.7): what a node past a delta's `T`, or
    /// holding a purge of it, applies after every join and rebuild, and what a snapshot carries
    /// of an expiring delta. Takes only those writes' values: their map writes move to their
    /// dot's key-erased record. Commutes with join. `expired` is asked about origin dots (never
    /// `Derived`).
    pub fn strip(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_values(expired, &mut Changes::new());
        // the moved map writes meet their dot's records; `Derived` records left without a
        // write go
        self.prune(None, &mut Changes::new());
    }

    /// Adds to `out` the origin dot of every value-less write here (§4.7): a register write or
    /// enum case without its value, a value-less `W`, a key-erased map entry creation, a text
    /// element's creation without its char (not deleted), a list creation held value-less.
    pub fn valueless_dots(&self, out: &mut std::collections::BTreeSet<Dot>) {
        let reg = |r: &Register, out: &mut std::collections::BTreeSet<Dot>| {
            if let Some(w) = &r.write
                && w.value.is_none()
            {
                out.insert(w.stamp.dot.origin().clone());
            }
        };
        if let Some(m) = self.meta()
            && let (Some(w), true) = (&m.w, m.w_valueless)
        {
            out.insert(w.dot.origin().clone());
        }
        match self {
            Fragment::Slots(Slots { reg: r, slots }) => {
                r.iter().for_each(|r| reg(r, out));
                slots.values().for_each(|f| f.valueless_dots(out));
            }
            Fragment::Register(r) => reg(r, out),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values().filter_map(|e| e.frag.as_deref()).for_each(|f| f.valueless_dots(out)),
            Fragment::Struct(s) => s.fields.values().for_each(|f| f.valueless_dots(out)),
            Fragment::Enum(e) => {
                if let Some(c) = &e.case
                    && c.case.is_none()
                {
                    out.insert(c.stamp.dot.origin().clone());
                }
                e.payloads.values().for_each(|f| f.valueless_dots(out));
            }
            Fragment::Map(m) => {
                for (id, en) in &m.entries {
                    if id.key.is_none() && en.created.is_some() {
                        out.insert(id.dot.origin().clone());
                    }
                    if let Some(f) = en.frag.as_deref() {
                        f.valueless_dots(out);
                    }
                }
            }
            Fragment::Seq(s) => {
                for (d, el) in s.elems() {
                    if el.valueless {
                        out.insert(d.origin().clone());
                    }
                    match &el.content {
                        SeqContent::Frag(f) => f.valueless_dots(out),
                        // a range record: each element is its own value-less creation
                        SeqContent::None if s.text && el.created.is_some() && !el.deleted.as_ref().is_some_and(|x| x.1) => {
                            out.extend((0..el.span).map(|k| crate::seq_span::nth(d, k).origin().clone()));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub(crate) fn strip_values(&mut self, expired: &dyn Fn(&Dot) -> bool, ch: &mut Changes) {
        let exp = |d: &Dot| expired(d.origin());
        let reg = |r: &mut Register| {
            if let Some(w) = &mut r.write
                && exp(&w.stamp.dot)
            {
                w.value = None;
            }
        };
        // `W` writes the value "an empty composite"
        if let Some(m) = self.meta_mut()
            && m.w.as_ref().is_some_and(|w| exp(&w.dot))
            && !m.w_valueless
        {
            m.w_valueless = true;
            ch.touch();
        }
        match self {
            Fragment::Slots(Slots { reg: r, slots }) => {
                r.iter_mut().for_each(reg);
                slots.values_mut().for_each(|f| f.strip_values(expired, ch));
            }
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired, ch)),
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
                // each write repeats its record's key as its own value
                m.erase_keys(&exp);
                for f in m.entries.values_mut().filter_map(|en| en.frag.as_mut()) {
                    f.strip_values(expired, ch);
                }
                m.reindex();
            }
            Fragment::Seq(s) => seq::strip_values(s, expired, ch),
        }
    }

    /// Keeps only the writes `j` holds as well, at the same position and as the same copy (§4.1
    /// copy order: of two copies the join holds one): a map record against the join of its
    /// dot's records (§5.6). `j` is pruned; the result is for a prune, which gives it canonical
    /// form.
    pub(crate) fn restrict(&mut self, j: &Fragment) {
        self.filter_by(j, Keep::Held);
    }

    /// Drops the writes `j` holds at the same position and stamp, any copy: a key-erased record
    /// against its dot's keyed records, whose copies carry the key, a value of their own (§5.6).
    pub(crate) fn without(&mut self, j: &Fragment) {
        self.filter_by(j, Keep::NotHeld);
    }

    pub(crate) fn filter_by(&mut self, j: &Fragment, keep: Keep) {
        if let Fragment::Slots(_) = self {
            let Fragment::Slots(Slots { reg, slots }) = std::mem::take(self) else { return };
            let reg = reg.and_then(|r| {
                let mut f = Fragment::Register(r);
                f.filter_slot(j, keep);
                match f {
                    Fragment::Register(r) => Some(r),
                    _ => None,
                }
            });
            let slots = slots.into_iter().map(|(k, mut f)| {
                f.filter_slot(j, keep);
                (k, f)
            });
            *self = crate::state::assemble(reg, slots.collect());
            return;
        }
        self.filter_slot(j, keep);
    }

    /// `filter_by` of one slot, against `j`'s slot of its encoding or else the embedding of
    /// `j`'s register slot (§7).
    fn filter_slot(&mut self, j: &Fragment, keep: Keep) {
        use crate::fragment::Encoding;
        let enc = self.encoding();
        let t = match j.slot(enc) {
            Some(t) => Some(t.to_fragment()),
            None => match j.slot(Encoding::Register) {
                Some(crate::state::SlotRef::Reg(r)) if enc != Encoding::Register => crate::state::embed(r, enc).map(|mut t| {
                    t.prune(None, &mut Changes::new());
                    t
                }),
                _ => None,
            },
        };
        let Some(t) = t else {
            if keep == Keep::Held {
                *self = Fragment::empty(enc).unwrap_or_default();
            }
            return;
        };
        if let (Some(m), Some(tm)) = (self.meta_mut(), t.meta()) {
            if !keep.stays(m.reset == tm.reset, m.reset.is_some() && m.reset == tm.reset) {
                m.reset = None;
            }
            if !keep.stays((&m.w, m.w_valueless) == (&tm.w, tm.w_valueless), m.w.is_some() && m.w == tm.w) {
                m.w = None;
                m.w_valueless = false;
            }
        }
        let missing = keep == Keep::NotHeld;
        let sub = |f: &mut Option<Box<Fragment>>, t: Option<&Fragment>| match (f.as_mut(), t) {
            (Some(x), Some(t)) => {
                x.filter_by(t, keep);
                if x.is_empty() {
                    *f = None;
                }
            }
            (_, None) if missing => {}
            _ => *f = None,
        };
        let elems = |es: &mut BTreeMap<Dot, Elem>, te: &BTreeMap<Dot, Elem>| {
            es.retain(|d, el| {
                let Some(t) = te.get(d) else { return missing };
                if !keep.stays(el.reset == t.reset, el.reset.is_some() && el.reset == t.reset) {
                    el.reset = None;
                }
                sub(&mut el.frag, t.frag.as_deref());
                el.reset.is_some() || el.frag.is_some()
            });
        };
        let children = |c: &mut BTreeMap<u64, Fragment>, tc: &BTreeMap<u64, Fragment>| {
            c.retain(|k, f| {
                let Some(t) = tc.get(k) else { return missing };
                f.filter_by(t, keep);
                !f.is_empty()
            });
        };
        match (&mut *self, &t) {
            (Fragment::Register(r), Fragment::Register(tr)) => {
                if !keep.stays(r.reset == tr.reset, r.reset.is_some() && r.reset == tr.reset) {
                    r.reset = None;
                }
                let held = r.write.is_some() && r.write.as_ref().map(|w| &w.stamp) == tr.write.as_ref().map(|w| &w.stamp);
                if !keep.stays(r.write == tr.write, held) {
                    r.write = None;
                }
            }
            (Fragment::Bag(Bag { elems: es, .. }), Fragment::Bag(Bag { elems: te, .. })) | (Fragment::Set(Set { elems: es, .. }), Fragment::Set(Set { elems: te, .. })) => elems(es, te),
            (Fragment::Struct(a), Fragment::Struct(b)) => children(&mut a.fields, &b.fields),
            (Fragment::Enum(a), Fragment::Enum(b)) => {
                let held = a.case.is_some() && a.case.as_ref().map(|c| &c.stamp) == b.case.as_ref().map(|c| &c.stamp);
                if !keep.stays(a.case == b.case, held) {
                    a.case = None;
                }
                children(&mut a.payloads, &b.payloads);
            }
            (Fragment::Map(a), Fragment::Map(b)) => {
                a.entries.retain(|id, en| {
                    let Some(t) = b.entries.get(id) else { return missing };
                    if !keep.stays(en.reset == t.reset, en.reset.is_some() && en.reset == t.reset) {
                        en.reset = None;
                    }
                    if !keep.stays(en.created == t.created, en.created.is_some() && en.created == t.created) {
                        en.created = None;
                    }
                    sub(&mut en.frag, t.frag.as_deref());
                    en.holds()
                });
                a.reindex();
            }
            (Fragment::Seq(a), Fragment::Seq(b)) if a.text == b.text => seq::filter_by(a, b, keep),
            (x, _) if keep == Keep::Held => *x = Fragment::empty(enc).unwrap_or_default(),
            _ => {}
        }
    }

    /// The writes of a compacting writer's sweep (spec/crdt.md §4.8, spec/sync.md §7): a reset at
    /// `r` of each map entry and list element that a removal ended (removal is final) and that
    /// still holds a write, so that it dies and its bytes go. A record not live for want of a
    /// creation or a value is no such thing: the creation or a valued write may still arrive.
    /// Below a record it resets nothing more (that reset takes it all). Not for role-class
    /// aspects (a removal there names its key).
    pub fn sweep(&self, r: &Stamp) -> Option<Fragment> {
        match self {
            Fragment::Register(_) | Fragment::Bag(_) | Fragment::Set(_) => None,
            Fragment::Slots(_) => self.chosen().sweep(r),
            Fragment::Struct(s) => {
                let fields: BTreeMap<u64, Fragment> = s.fields.iter().filter_map(|(k, f)| Some((*k, f.sweep(r)?))).collect();
                (!fields.is_empty()).then(|| Fragment::Struct(Struct { meta: Meta::default(), fields }))
            }
            Fragment::Enum(e) => {
                let payloads: BTreeMap<u64, Fragment> = e.payloads.iter().filter_map(|(k, f)| Some((*k, f.sweep(r)?))).collect();
                (!payloads.is_empty()).then(|| Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads }))
            }
            Fragment::Map(m) => {
                let mut entries = BTreeMap::new();
                for (id, en) in &m.entries {
                    if m.is_live(id) {
                        if let Some(inner) = en.frag.as_deref().and_then(|f| f.sweep(r)) {
                            entries.insert(id.clone(), Entry { frag: Some(Box::new(inner)), ..Entry::default() });
                        }
                    } else if id.key.is_some() || en.frag.is_some() {
                        let recs = || m.of_dot(&id.dot);
                        // a key a record repeats goes with any write, a value-less one too; a
                        // key-erased record has bytes to lose only in a valued one
                        let holds = recs().any(|(i, x)| x.frag.as_deref().is_some_and(|f| if i.key.is_some() { f.all_max().is_some() } else { f.written().is_some() }));
                        if holds && recs().any(|(_, x)| x.reset.is_some()) && !recs().any(|(i, _)| m.is_live(i)) {
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
                        if let Some(inner) = f.sweep(r) {
                            out.elems_mut().insert(d.clone(), SeqElem { content: SeqContent::Frag(Box::new(inner)), ..SeqElem::bare() });
                        }
                    } else if f.written().is_some() && el.reset().is_some() {
                        out.elems_mut().insert(d.clone(), SeqElem { deleted: Some((r.clone(), true)), ..SeqElem::bare() });
                    }
                }
                (!out.elems().is_empty()).then_some(Fragment::Seq(out))
            }
        }
    }

    /// Removes every write whose origin dot (`Derived` dots: the underlying dot) matches `pred`,
    /// with the records such dots created and others' writes nested in them, from one body:
    /// un-merge (spec/permissions.md §5.2, spec/crdt.md §4.6, defined per body). The result is for a join
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

    /// Removes exactly the writes whose origin dot matches `pred`, element and entry creations
    /// included, keeping others' writes nested in a record a matching dot created: what an
    /// invalid snapshot body or a snapshot turned invalid gave (spec/permissions.md §5.2), or a
    /// snapshot's copies of writes played elsewhere, the others still superseding there.
    pub fn remove_writes(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        self.remove_dots_in(pred, &|_, _| true);
    }

    pub(crate) fn remove_dots_in(&mut self, pred: &dyn Fn(&Dot) -> bool, keep: &dyn Fn(&Dot, Option<&Value>) -> bool) {
        let bad = |s: &Option<Stamp>| s.as_ref().is_some_and(|s| pred(s.dot.origin()));
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
                    if r.write.as_ref().is_some_and(|w| pred(w.stamp.dot.origin())) {
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
                if r.write.as_ref().is_some_and(|w| pred(w.stamp.dot.origin())) {
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
                m.w_valueless = false;
            }
        }
        match self {
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => remove_dots_elems(elems, pred, keep),
            Fragment::Struct(s) => s.fields.retain(|_, f| {
                f.remove_dots_in(pred, keep);
                !f.is_empty()
            }),
            Fragment::Enum(e) => {
                if e.case.as_ref().is_some_and(|c| pred(c.stamp.dot.origin())) {
                    e.case = None;
                }
                e.payloads.retain(|_, f| {
                    f.remove_dots_in(pred, keep);
                    !f.is_empty()
                });
            }
            Fragment::Map(Map { entries, .. }) => entries.retain(|id, en| {
                let d = &id.dot;
                if en.reset.as_ref().is_some_and(|r| pred(r.dot.origin())) {
                    en.reset = None;
                }
                if pred(d.origin()) {
                    en.created = None;
                    if !keep(d.origin(), id.key()) {
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

    /// Whether the fragment holds a write or record `remove_dots(pred)` would remove or change.
    pub fn holds_dots(&self, pred: &dyn Fn(&Dot) -> bool) -> bool {
        walk(&mut DotsIn(pred), self)
    }

    /// Whether a delta of a commit at `ts` or earlier (its stamps all at the commit's `ts`, §2.4)
    /// can no longer change this fragment: its own reset or a register write is past `ts`, which
    /// resets everything older at the position, in any encoding (§4.2, §5.1, §7 One reset per
    /// position), and a record left with no write goes (§4.2).
    pub fn settled_above(&self, ts: osis_base::Ts) -> bool {
        let reg = match self {
            Fragment::Register(r) => Some(r),
            Fragment::Slots(s) => s.reg.as_ref(),
            _ => None,
        };
        self.reset().iter().chain(reg.and_then(|r| r.write.as_ref()).map(|w| &w.stamp)).any(|x| x.ts > ts)
    }

    /// Whether the fragment holds a write stamped exactly `s`: a register, case, reset or `W`
    /// write, a map entry's creation, a sequence element's creation (in a range record too),
    /// position or flag write. Unlike `holds_dots`, a record keyed by `s`'s dot whose creation
    /// is gone (a removed entry kept for its reset) does not count, nor another write sharing
    /// the dot.
    pub fn holds_stamp(&self, s: &Stamp) -> bool {
        walk(&mut HoldsStamp(s), self)
    }

    /// Whether a keyed map entry record carries a reset: a removal or tombstone naming its key,
    /// allowed only in role-class aspects (spec/crdt.md §5.6).
    pub fn keyed_resets(&self) -> bool {
        walk(&mut KeyedResets, self)
    }

    /// Adds the origin dot of every write and live record here to `out` (a range record's first).
    pub fn origin_dots(&self, out: &mut std::collections::BTreeSet<Dot>) {
        walk(&mut OriginDots(out), self);
    }

    /// Whether a write of the delta carrying dot `d` is here: a write stamped with its dot or a
    /// record's creation; unlike `holds_dots`, a tombstone keyed by `d` (the remover's) is not.
    pub fn holds_write(&self, d: &Dot) -> bool {
        walk(&mut HoldsWrite(d), self)
    }

}

/// `Fragment::origin_dots`.
struct OriginDots<'a>(&'a mut std::collections::BTreeSet<Dot>);

impl Visit for OriginDots<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        self.0.insert(s.dot.origin().clone());
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
        self.0.insert(d.origin().clone());
        Next::On
    }
}

/// `Fragment::holds_write`.
struct HoldsWrite<'a>(&'a Dot);

impl Visit for HoldsWrite<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        s.dot.origin() == self.0
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        let hit = match r {
            Rec::Elem(d, x) => x.frag.is_some() && d.origin() == self.0,
            Rec::Entry(id, e) => e.created.is_some() && id.dot.origin() == self.0,
            Rec::Seq(d, el) => el.created.is_some() && d.origin() == self.0,
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

/// `Fragment::holds_dots`: their writes, and records they created.
struct DotsIn<'a>(&'a dyn Fn(&Dot) -> bool);

impl Visit for DotsIn<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        (self.0)(s.dot.origin())
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        let pred = self.0;
        let held = match r {
            Rec::Elem(d, _) | Rec::Entry(crate::fragment::Eid { dot: d, .. }, _) => pred(d.origin()),
            // a sequence record (a range record: any of its elements) loses its creation or goes;
            // a flag or position write of theirs
            Rec::Seq(d, el) => (0..el.span).any(|k| pred(crate::seq_span::nth(d, k).origin())) || el.deleted.as_ref().is_some_and(|x| pred(x.0.dot.origin())) || el.pos.iter().any(|p| pred(p.0.dot.origin())),
        };
        if held { Next::Stop } else { Next::On }
    }
}

fn remove_dots_elems(elems: &mut BTreeMap<Dot, Elem>, pred: &dyn Fn(&Dot) -> bool, keep: &dyn Fn(&Dot, Option<&Value>) -> bool) {
    elems.retain(|d, el| {
        if el.reset.as_ref().is_some_and(|r| pred(r.dot.origin())) {
            el.reset = None;
        }
        if pred(d.origin()) && !keep(d.origin(), None) {
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

/// What `Fragment::filter_by` keeps of a fragment against another.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keep {
    /// The writes the other holds as the same copy.
    Held,
    /// The writes the other holds none of at their position and stamp.
    NotHeld,
}

impl Keep {
    /// Whether a write stays: `copy`, the other holds the same copy; `held`, it holds a write
    /// of that stamp there.
    pub(crate) fn stays(self, copy: bool, held: bool) -> bool {
        match self {
            Keep::Held => copy,
            Keep::NotHeld => !held,
        }
    }
}
