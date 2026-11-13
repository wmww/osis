//! Expiry (value-less writes, spec/crdt.md §4.7) and un-merge (§4.6): removing writes by origin
//! dot, and whether that may be done in place.

use crate::changes::Changes;
use crate::fragment::{Bag, Eid, Elem, Entry, Enum, Fragment, Map, Meta, Register, Set, Slots, Struct};
use crate::walk::{Next, Rec, Visit, walk};
use crate::seq::{self, Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Stamp};
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

    /// Calls `f` with the origin dot of every value-carrying write held here with its value
    /// (§4.7): every write `strip` of its dot would change, and every write of a keyed map record
    /// (each carries the record's key). A dot may come more than once; once stripped of a dot's
    /// values, a fragment names it no more.
    pub fn each_valued(&self, f: &mut dyn FnMut(&Dot)) {
        let reg = |r: &Register, f: &mut dyn FnMut(&Dot)| {
            if let Some(w) = &r.write
                && w.value.is_some()
            {
                f(w.stamp.dot.origin());
            }
        };
        if let Some(m) = self.meta()
            && let (Some(w), false) = (&m.w, m.w_valueless)
        {
            f(w.dot.origin());
        }
        match self {
            Fragment::Slots(Slots { reg: r, slots }) => {
                if let Some(r) = r {
                    reg(r, f);
                }
                slots.values().for_each(|s| s.each_valued(f));
            }
            Fragment::Register(r) => reg(r, f),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values().filter_map(|e| e.frag.as_deref()).for_each(|s| s.each_valued(f)),
            Fragment::Struct(s) => s.fields.values().for_each(|s| s.each_valued(f)),
            Fragment::Enum(e) => {
                if let Some(c) = &e.case
                    && c.case.is_some()
                {
                    f(c.stamp.dot.origin());
                }
                e.payloads.values().for_each(|s| s.each_valued(f));
            }
            Fragment::Map(m) => {
                for (id, en) in &m.entries {
                    // each write of a keyed record carries its key
                    if id.key.is_some() {
                        if let Some(r) = &en.reset {
                            f(r.dot.origin());
                        }
                        if en.created.is_some() {
                            f(id.dot.origin());
                        }
                        if let Some(x) = en.frag.as_deref() {
                            walk(&mut EachWrite(&mut *f), x);
                        }
                    }
                    if let Some(s) = en.frag.as_deref() {
                        s.each_valued(f);
                    }
                }
            }
            Fragment::Seq(s) => {
                for (d, el) in s.elems() {
                    // an undelete's char is its flag write's own value
                    if el.undel.is_some()
                        && let Some((st, _)) = &el.deleted
                    {
                        f(st.dot.origin());
                    }
                    // a range record's creations (list) or chars (text), each its own
                    let each = !s.text && el.created.is_some() && !el.valueless || matches!(el.content, SeqContent::Char(_));
                    if each {
                        (0..el.span).for_each(|k| f(crate::seq_span::nth(d, k).origin()));
                    }
                    if let SeqContent::Frag(x) = &el.content {
                        x.each_valued(f);
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
            Fragment::Bag(Bag { elems, .. }) => elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired, ch)),
            Fragment::Set(x) => x.elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired, ch)),
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

    /// Keeps only the writes `j` holds a copy of, at the same position and stamp: the join of a
    /// map dot's records against one record, which takes its writes as their join of copies
    /// (§5.6). The result is for a prune, which gives it canonical form.
    pub(crate) fn restrict(&mut self, j: &Fragment) {
        self.filter_by(j, Keep::Held);
    }

    /// Drops the writes `j` holds at the same position and stamp, any copy: a map record against
    /// its dot's records with greater keys, where those writes sit (§5.6).
    pub(crate) fn without(&mut self, j: &Fragment) {
        self.filter_by(j, Keep::NotHeld);
    }

    /// A `Slots` position's writes are its register slot's and each slot's own: a slot's
    /// embedding of the register is the register's writes (§7), so it is left out here and
    /// stays or goes with them (embedded again into the result).
    pub(crate) fn filter_by(&mut self, j: &Fragment, keep: Keep) {
        if let Fragment::Slots(_) = self {
            let Fragment::Slots(Slots { reg, slots }) = std::mem::take(self) else { return };
            let slots: BTreeMap<_, _> = slots
                .into_iter()
                .map(|(k, mut f)| {
                    if let Some(e) = reg.as_ref().and_then(|r| embedding(r, k)) {
                        f.filter_slot(&e, Keep::NotHeld);
                    }
                    f.filter_slot(j, keep);
                    (k, f)
                })
                .collect();
            let reg = reg.and_then(|r| {
                let mut f = Fragment::Register(r);
                f.filter_slot(j, keep);
                match f {
                    Fragment::Register(r) => Some(r),
                    _ => None,
                }
            });
            *self = crate::state::prune_slots(reg, slots, None, &mut Changes::new());
            return;
        }
        self.filter_slot(j, keep);
    }

    /// `filter_by` of one slot, against `j`'s slot of its encoding or else the embedding of
    /// `j`'s register (§7).
    fn filter_slot(&mut self, j: &Fragment, keep: Keep) {
        let enc = self.encoding();
        let t = match j.slot(enc) {
            Some(t) => Some(t.to_fragment()),
            None => match j {
                Fragment::Register(r) | Fragment::Slots(Slots { reg: Some(r), .. }) => embedding(r, enc),
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
            if !keep.stays(m.reset.is_some() && m.reset == tm.reset) {
                m.reset = None;
            }
            if !keep.stays(m.w.is_some() && m.w == tm.w) {
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
                if !keep.stays(el.reset.is_some() && el.reset == t.reset) {
                    el.reset = None;
                }
                if !keep.stays(el.gone.is_some() && el.gone.as_ref().map(|g| &g.stamp) == t.gone.as_ref().map(|g| &g.stamp)) {
                    el.gone = None;
                }
                sub(&mut el.frag, t.frag.as_deref());
                el.holds()
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
                if !keep.stays(r.reset.is_some() && r.reset == tr.reset) {
                    r.reset = None;
                }
                let held = r.write.is_some() && r.write.as_ref().map(|w| &w.stamp) == tr.write.as_ref().map(|w| &w.stamp);
                if !keep.stays(held) {
                    r.write = None;
                }
            }
            (Fragment::Bag(Bag { elems: es, .. }), Fragment::Bag(Bag { elems: te, .. })) => elems(es, te),
            (Fragment::Set(a), Fragment::Set(b)) => elems(&mut a.elems, &b.elems),
            (Fragment::Struct(a), Fragment::Struct(b)) => children(&mut a.fields, &b.fields),
            (Fragment::Enum(a), Fragment::Enum(b)) => {
                let held = a.case.is_some() && a.case.as_ref().map(|c| &c.stamp) == b.case.as_ref().map(|c| &c.stamp);
                if !keep.stays(held) {
                    a.case = None;
                }
                children(&mut a.payloads, &b.payloads);
            }
            (Fragment::Map(a), Fragment::Map(b)) => {
                // a map entry is its dot, whichever of the dot's records holds a copy (§4.8 Which
                // write): `b`'s records of a dot, joined, against each of `a`'s
                let mut by_dot: BTreeMap<&Dot, Entry> = BTreeMap::new();
                for (id, en) in &b.entries {
                    let t = by_dot.entry(&id.dot).or_insert_with(|| Entry { reset: None, frag: None, created: None });
                    t.reset = crate::stamp::max_opt(t.reset.take(), en.reset.clone());
                    t.created = crate::stamp::max_opt(t.created.take(), en.created.clone());
                    if let Some(f) = en.frag.as_deref() {
                        match &mut t.frag {
                            Some(x) => x.join_into(f.clone(), None, &mut Changes::new()),
                            None => t.frag = Some(Box::new(f.clone())),
                        }
                    }
                }
                a.entries.retain(|id, en| {
                    let Some(t) = by_dot.get(&id.dot) else { return missing };
                    if !keep.stays(en.reset.is_some() && en.reset == t.reset) {
                        en.reset = None;
                    }
                    if !keep.stays(en.created.is_some() && en.created == t.created) {
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
    /// `r` of each map entry and list element that is not live, holds a write, and whose creation
    /// is dead (removal is final), so that it dies and its bytes go; for text, a delete at `r` of
    /// each element whose creation is dead holding an undelete's char. A creation is dead when the
    /// record has a reset of its own (a removal is written above the creation it removes), or when
    /// no creation of it is held though `reflected` says the state reflects the delta that wrote
    /// it: a reset pruned it. A record lacking its creation otherwise may still show (the creation
    /// may arrive, or turn valid), and one holding it does not hold it dead (a valued write may
    /// still arrive under an expired creation). Below a record it resets nothing more (that reset
    /// takes it all). An enum's payloads of a case not current are no such thing: any case write
    /// stamped between the enum's reset and theirs shows them. Not for role-class aspects (a
    /// removal there names its key). One commit's worth: at most `MAX_DELTA_BARE` content-less
    /// elements (§3.3 rule 7), the first ones in state order; the writer sweeps again for the rest.
    pub fn sweep(&self, r: &Stamp, reflected: &dyn Fn(&Dot) -> bool) -> Option<Fragment> {
        let mut left = osis_base::format::MAX_DELTA_BARE;
        self.sweep_at_most(r, reflected, &mut left)
    }

    /// `sweep` taking at most `left` content-less elements, less what it takes.
    pub(crate) fn sweep_at_most(&self, r: &Stamp, reflected: &dyn Fn(&Dot) -> bool, left: &mut u64) -> Option<Fragment> {
        match self {
            Fragment::Register(_) | Fragment::Bag(_) | Fragment::Set(_) => None,
            Fragment::Slots(_) => self.chosen().sweep_at_most(r, reflected, left),
            Fragment::Struct(s) => {
                let fields: BTreeMap<u64, Fragment> = s.fields.iter().filter_map(|(k, f)| Some((*k, f.sweep_at_most(r, reflected, left)?))).collect();
                (!fields.is_empty()).then(|| Fragment::Struct(Struct { meta: Meta::default(), fields }))
            }
            Fragment::Enum(e) => {
                let payloads: BTreeMap<u64, Fragment> = e.payloads.iter().filter_map(|(k, f)| Some((*k, f.sweep_at_most(r, reflected, left)?))).collect();
                (!payloads.is_empty()).then(|| Fragment::Enum(Enum { meta: Meta::default(), case: None, payloads }))
            }
            Fragment::Map(m) => {
                let mut entries = BTreeMap::new();
                for (id, en) in &m.entries {
                    if m.is_live(id) {
                        // judged on what the record reads as: its fragment joined with its dot's
                        // key-erased record's (§5.6), where an expired creation sits
                        if let Some(inner) = m.record_frag(id).and_then(|f| f.sweep_at_most(r, reflected, left)) {
                            entries.insert(id.clone(), Entry { frag: Some(Box::new(inner)), ..Entry::default() });
                        }
                    } else if id.key.is_some() || en.frag.is_some() {
                        let recs = || m.of_dot(&id.dot);
                        // a key a record repeats goes with any write, a value-less one too; a
                        // key-erased record has bytes to lose only in a valued one
                        let holds = recs().any(|(i, x)| x.frag.as_deref().is_some_and(|f| if i.key.is_some() { f.all_max().is_some() } else { f.written().is_some() }));
                        let dead = || recs().any(|(_, x)| x.reset.is_some()) || (recs().all(|(_, x)| x.created.is_none()) && reflected(&id.dot));
                        if holds && !recs().any(|(i, _)| m.is_live(i)) && dead() {
                            entries.insert(Eid::erased(id.dot.clone()), Entry::tomb(r));
                        }
                    }
                }
                // live records of one dot under several keys share the key-erased record's
                // content: prune puts each write in one record (§5.6)
                (!entries.is_empty()).then(|| {
                    let mut out = Fragment::Map(Map::new(Meta::default(), entries));
                    out.prune(None, &mut Changes::new());
                    out
                })
            }
            Fragment::Seq(s) if s.text => {
                let mut out = Seq::empty(true);
                for (d, el) in s.elems() {
                    // an undelete's char under a creation a reset pruned: the element never shows
                    // again (§5.7), and a delete beats the undelete
                    if el.created.is_none() && el.undel.is_some() && (0..el.span).all(|i| reflected(&Dot::new(d.src.clone(), d.ctr + i))) {
                        let span = el.span.min(*left);
                        if span == 0 {
                            break;
                        }
                        *left -= span;
                        out.elems_mut().insert(d.clone(), SeqElem { deleted: Some((r.clone(), true)), span, ..SeqElem::bare() });
                    }
                }
                (!out.elems().is_empty()).then_some(Fragment::Seq(out))
            }
            Fragment::Seq(s) => {
                let mut out = Seq::empty(false);
                for (d, el) in s.elems() {
                    let SeqContent::Frag(f) = &el.content else { continue };
                    if seq::is_visible(el, false) {
                        if let Some(inner) = f.sweep_at_most(r, reflected, left) {
                            out.elems_mut().insert(d.clone(), SeqElem { content: SeqContent::Frag(Box::new(inner)), ..SeqElem::bare() });
                        }
                    } else if *left > 0 && f.written().is_some() && (el.reset().is_some() || (el.created.is_none() && reflected(d))) {
                        *left -= 1;
                        out.elems_mut().insert(d.clone(), SeqElem { deleted: Some((r.clone(), true)), ..SeqElem::bare() });
                    }
                }
                (!out.elems().is_empty()).then_some(Fragment::Seq(out))
            }
        }
    }

    /// Removes exactly the writes whose origin dot (`Derived` dots: the underlying dot) matches
    /// `pred`, element and entry creations included, from one body: un-merge (spec/crdt.md §4.6,
    /// defined per body; others' writes nested in a record a matching dot created stay), what an
    /// invalid snapshot body or a snapshot turned invalid gave (spec/permissions.md §5.2), or a
    /// snapshot's copies of writes played elsewhere. A record left with no write goes. The result
    /// is for a join or a `prune`, which give it canonical form (it may keep a map entry holding
    /// only its creation, and a `Slots` position without its register's embedding).
    pub fn remove_writes(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        let bad = |s: &Option<Stamp>| s.as_ref().is_some_and(|s| pred(s.dot.origin()));
        match self {
            Fragment::Slots(_) => {
                // in place, not re-joined: a join would prune the creations kept below (a map
                // entry holding only its creation); the consumer's join or prune embeds and
                // prunes (§7)
                let Fragment::Slots(Slots { reg, slots }) = std::mem::take(self) else { return };
                let reg = reg.map(|mut r| {
                    remove_reg_writes(&mut r, pred);
                    r
                });
                let slots = slots.into_iter().map(|(k, mut f)| {
                    f.remove_writes(pred);
                    (k, f)
                });
                *self = crate::state::assemble(reg, slots.collect());
                return;
            }
            Fragment::Register(r) => remove_reg_writes(r, pred),
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
            Fragment::Bag(Bag { elems, .. }) => remove_writes_elems(elems, pred),
            Fragment::Set(x) => remove_writes_elems(&mut x.elems, pred),
            Fragment::Struct(s) => s.fields.retain(|_, f| {
                f.remove_writes(pred);
                !f.is_empty()
            }),
            Fragment::Enum(e) => {
                if e.case.as_ref().is_some_and(|c| pred(c.stamp.dot.origin())) {
                    e.case = None;
                }
                e.payloads.retain(|_, f| {
                    f.remove_writes(pred);
                    !f.is_empty()
                });
            }
            // an entry's creation whose own dot stays is kept, though nothing else is left in
            // it: a write of its own (§5.6)
            Fragment::Map(Map { entries, .. }) => entries.retain(|id, en| {
                en.remove_writes(&id.dot, pred);
                en.holds()
            }),
            Fragment::Seq(s) => seq::remove_writes(s, pred),
            Fragment::Register(_) | Fragment::Slots(_) => {}
        }
    }

    /// Whether the fragment holds a write or record `remove_writes(pred)` would remove or change.
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
    #[cfg(test)]
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
    #[cfg(test)]
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
#[cfg(test)]
struct HoldsWrite<'a>(&'a Dot);

#[cfg(test)]
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
#[cfg(test)]
struct HoldsStamp<'a>(&'a Stamp);

#[cfg(test)]
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

/// `Fragment::each_valued` in a keyed map record: the origin dot of every write.
struct EachWrite<'a>(&'a mut dyn FnMut(&Dot));

impl Visit for EachWrite<'_> {
    fn stamp(&mut self, s: &Stamp) -> bool {
        (self.0)(s.dot.origin());
        false
    }
    fn rec(&mut self, r: Rec<'_>) -> Next {
        match r {
            Rec::Entry(id, e) if e.created.is_some() => (self.0)(id.dot.origin()),
            Rec::Seq(d, el) => {
                if el.created.is_some() {
                    (0..el.span).for_each(|k| (self.0)(crate::seq_span::nth(d, k).origin()));
                }
                el.pos.iter().for_each(|p| (self.0)(p.0.dot.origin()));
                if let Some((st, _)) = &el.deleted {
                    (self.0)(st.dot.origin());
                }
            }
            _ => {}
        }
        Next::On
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

fn remove_reg_writes(r: &mut Register, pred: &dyn Fn(&Dot) -> bool) {
    if r.reset.as_ref().is_some_and(|x| pred(x.dot.origin())) {
        r.reset = None;
    }
    if r.write.as_ref().is_some_and(|w| pred(w.stamp.dot.origin())) {
        r.write = None;
    }
}

fn remove_writes_elems(elems: &mut BTreeMap<Dot, Elem>, pred: &dyn Fn(&Dot) -> bool) {
    elems.retain(|_, el| {
        if el.reset.as_ref().is_some_and(|r| pred(r.dot.origin())) {
            el.reset = None;
        }
        if el.gone.as_ref().is_some_and(|g| pred(g.stamp.dot.origin())) {
            el.gone = None;
        }
        if let Some(f) = &mut el.frag {
            f.remove_writes(pred);
            if f.is_empty() {
                el.frag = None;
            }
        }
        el.holds()
    });
}

/// The embedding of register `r` into slot encoding `enc`, pruned (§7); `None` for the register.
fn embedding(r: &Register, enc: crate::fragment::Encoding) -> Option<Fragment> {
    crate::state::embed(r, enc).map(|mut t| {
        t.prune(None, &mut Changes::new());
        t
    })
}

/// What `Fragment::filter_by` keeps of a fragment against another.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keep {
    /// The writes the other holds a copy of at their position and stamp.
    Held,
    /// The writes the other holds none of at their position and stamp.
    NotHeld,
}

impl Keep {
    /// Whether a write stays: `held`, the other holds a write of that stamp there.
    pub(crate) fn stays(self, held: bool) -> bool {
        match self {
            Keep::Held => held,
            Keep::NotHeld => !held,
        }
    }
}
