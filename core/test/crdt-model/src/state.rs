//! The abstract lattice (spec §4, §5): fragments with resolved stamps, join, prune, presence, read, un-merge.
use crate::seq::linearize;
use crate::stamp::{max_opt, survives, Dot, Source, Stamp};
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BagKind {
    Counter,
    Max,
    Min,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Composite {
    pub reset: Option<Stamp>,
    /// Explicit presence write `W` (§4.3). The presence stamp is computed: see `Frag::written`.
    pub w: Option<Stamp>,
    /// The `W` is held value-less (§4.7): it writes the value "an empty composite".
    pub w_valueless: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Elem {
    pub reset: Option<Stamp>,
    pub frag: Option<Box<Frag>>,
}

/// A map entry record's identity (§5.6): the entry's dot and key; no key for the dot's key-erased record (§4.7).
pub type Eid = (Dot, Option<Value>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub reset: Option<Stamp>,
    pub frag: Option<Box<Frag>>,
    /// The creation write's stamp (dot = the entry's), while it survives pruning (§5.6); the record reads only
    /// while it holds it.
    pub created: Option<Stamp>,
}

/// The records of map `entries` that are live, with what each reads as (§5.6): a keyed record whose dot's creation
/// is held (in it, valued, or value-less in the dot's key-erased record), whose content (its fragment joined with
/// the key-erased record's) is present and, but under its own valued creation, holds a live value.
pub fn live_records(entries: &BTreeMap<Eid, Entry>) -> Vec<(Eid, Frag)> {
    let mut out = Vec::new();
    for ((d, k), en) in entries {
        let (Some(_), Some(f)) = (k, &en.frag) else { continue };
        let erased = entries.get(&(d.clone(), None));
        if en.created.is_none() && erased.map_or(true, |e| e.created.is_none()) {
            continue;
        }
        let f = match erased.and_then(|e| e.frag.as_deref()) {
            Some(x) => {
                let mut j = join_any((**f).clone(), x.clone());
                j.prune(None);
                j
            }
            None => (**f).clone(),
        };
        if !f.present() || (en.created.is_none() && !f.live_value()) {
            continue;
        }
        out.push(((d.clone(), k.clone()), f));
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Anchor {
    Head,
    Dot(Dot),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    None,
    Char(char),
    Frag(Box<Frag>),
}

/// A position write `(stamp, anchor, sibling key)`; no key: the stamp is the sibling key (§5.7).
pub type Pos = (Stamp, Anchor, Option<Stamp>);

/// The sibling key of a position write (§5.7, §6.1).
pub fn sib_key(p: &Pos) -> &Stamp {
    p.2.as_ref().unwrap_or(&p.0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqElem {
    /// The creation write: stamp (ts, element dot) and initial anchor. Text content lives and dies with it.
    pub created: Option<(Stamp, Anchor)>,
    pub content: Content,
    /// Position writes (the creation write included), greatest first, at most two (§5.7).
    pub pos: Vec<Pos>,
    /// Text: the deleted flag (LWW bool). List: the element reset `R_elem`, always `true`; the element's content
    /// fragment is pruned under it and the element is deleted iff that fragment is absent (§5.7).
    pub deleted: Option<(Stamp, bool)>,
    /// Text: the char the surviving `deleted` write carries (an undelete's own value, §5.7); never with a `true`
    /// flag. What an undeleted element shows.
    pub undel: Option<char>,
    /// List: the creation is held value-less (§4.7). A text creation's value is its char.
    pub valueless: bool,
}

impl SeqElem {
    pub fn new(created: Stamp, anchor: Anchor, content: Content) -> SeqElem {
        SeqElem { created: Some((created.clone(), anchor.clone())), content, pos: vec![(created, anchor, None)], deleted: None, undel: None, valueless: false }
    }
    pub fn write(content: Content, pos: Vec<Pos>, deleted: Option<(Stamp, bool)>) -> SeqElem {
        SeqElem { created: None, content, pos, deleted, undel: None, valueless: false }
    }
    /// A text flag write: a delete, or an undelete carrying `undel` (§5.7).
    pub fn flag(s: Stamp, deleted: bool, undel: Option<char>) -> SeqElem {
        SeqElem { created: None, content: Content::None, pos: vec![], deleted: Some((s, deleted)), undel: undel.filter(|_| !deleted), valueless: false }
    }
    /// A text element's char as it reads (§5.7): one register over the creation and the flag writes, by stamp, a
    /// flag winning a tie. The creation winning: its char; an undelete: the undelete's own; a delete: none. None
    /// without a creation.
    pub fn char(&self) -> Option<char> {
        let (c, _) = self.created.as_ref()?;
        match &self.deleted {
            Some((f, false)) if f >= c => self.undel,
            Some((f, true)) if f >= c => None,
            _ => if let Content::Char(c) = self.content { Some(c) } else { None },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frag {
    /// A write without a value is value-less (§4.7).
    Register { reset: Option<Stamp>, write: Option<(Stamp, Option<Value>)> },
    Bag { kind: BagKind, c: Composite, elems: BTreeMap<Dot, Elem> },
    Struct { c: Composite, fields: BTreeMap<u64, Frag> },
    Enum { c: Composite, case: Option<(Stamp, Option<u64>)>, payloads: BTreeMap<u64, Frag> },
    Set { c: Composite, elems: BTreeMap<Dot, Elem> },
    Map { c: Composite, entries: BTreeMap<Eid, Entry> },
    Seq { text: bool, c: Composite, elems: BTreeMap<Dot, SeqElem> },
    /// Several encodings at one position (§7): the register slot plus non-register slots keyed by encoding, joined
    /// pointwise. Every slot already holds the embedding of the register slot. Never produced by a writer; appears in
    /// states and snapshots. Always at least two slots (`assemble` collapses fewer).
    Slots { reg: Option<Box<Frag>>, slots: BTreeMap<u8, Frag> },
}

/// Later wins; of two copies of one write (equal stamps) the greater payload (§4.1 copy order).
pub fn max_pair<T: Ord>(a: Option<(Stamp, T)>, b: Option<(Stamp, T)>) -> Option<(Stamp, T)> {
    a.max(b)
}

/// Register join: greater stamp wins; of copies of one write the valued one (§4.7), then the greater value (canonical
/// bytes, §4.1 copy order).
pub fn max_valued<T: Ord>(a: Option<(Stamp, Option<T>)>, b: Option<(Stamp, Option<T>)>) -> Option<(Stamp, Option<T>)> {
    a.max(b)
}

/// The non-`Derived` dot whose commit carries writes under `d` (§2.1, §4.7).
pub fn origin(d: &Dot) -> &Dot {
    match &d.source {
        Source::Derived(x) => origin(x),
        _ => d,
    }
}

impl SeqElem {
    /// Whether the creation write counts toward presence (§4.3): a valued one (text: its char held; list: not held
    /// value-less), or one under a flag write (text) or element reset (list).
    fn creation_counts(&self, text: bool) -> bool {
        if text {
            matches!(self.content, Content::Char(_)) || self.deleted.is_some()
        } else {
            !self.valueless || self.deleted.as_ref().map_or(false, |d| d.1)
        }
    }
    /// Not live (§5.7 Live). Text: no char to show. List: no creation held, the creation at or below the element's
    /// reset, or content that is not present or, under a value-less creation, holds no live value.
    pub fn is_deleted(&self, text: bool) -> bool {
        if text {
            return self.char().is_none();
        }
        let Some((c, _)) = &self.created else { return true };
        if self.deleted.as_ref().is_some_and(|(r, _)| *c <= *r) {
            return true;
        }
        !matches!(&self.content, Content::Frag(f) if f.present() && (!self.valueless || f.live_value()))
    }
    /// Whether the element reads (§5.7 Live).
    pub fn shows(&self, text: bool) -> bool {
        !self.is_deleted(text)
    }
    /// Whether the record holds a write, and so stays in the state (§4.2): one with none goes, and what anchors at its
    /// dot is placed at a virtual anchor (§6.1), as at a node that never held it.
    fn is_record(&self) -> bool {
        self.created.is_some() || !self.pos.is_empty() || self.deleted.is_some() || matches!(self.content, Content::Frag(_))
    }
}

fn top2(mut v: Vec<Pos>) -> Vec<Pos> {
    // greatest first; of copies of one write the greater anchor, then the greater sibling key, none below any
    // (§4.1 copy order)
    v.sort_by(|a, b| b.cmp(a));
    v.dedup_by(|a, b| a.0 == b.0);
    v.truncate(2);
    v
}

impl Frag {
    pub fn enc(&self) -> u8 {
        match self {
            Frag::Register { .. } => 0,
            Frag::Bag { kind: BagKind::Counter, .. } => 1,
            Frag::Bag { kind: BagKind::Max, .. } => 2,
            Frag::Bag { kind: BagKind::Min, .. } => 3,
            Frag::Struct { .. } => 4,
            Frag::Enum { .. } => 5,
            Frag::Set { .. } => 6,
            Frag::Map { .. } => 7,
            Frag::Seq { text: false, .. } => 8,
            Frag::Seq { text: true, .. } => 9,
            Frag::Slots { .. } => 10,
        }
    }

    /// Slots of a `Slots` position (the register slot first), or the fragment itself.
    pub fn slots(&self) -> Vec<&Frag> {
        match self {
            Frag::Slots { reg, slots } => reg.iter().map(|r| &**r).chain(slots.values()).collect(),
            f => vec![f],
        }
    }

    /// The slot of encoding `enc` at this position, if any (§7: ops address the slot of their schema's encoding).
    pub fn slot(&self, enc: u8) -> Option<&Frag> {
        match self {
            Frag::Slots { reg, slots } => {
                if enc == 0 {
                    reg.as_deref()
                } else {
                    slots.get(&enc)
                }
            }
            f if f.enc() == enc => Some(f),
            _ => None,
        }
    }

    /// The slot a `Slots` position reads as: greatest `all_max`, ties by greater encoding id (§7).
    pub fn chosen(&self) -> &Frag {
        match self {
            Frag::Slots { .. } => self.slots().into_iter().max_by(|a, b| a.all_max().cmp(&b.all_max()).then(a.enc().cmp(&b.enc()))).unwrap(),
            f => f,
        }
    }

    pub fn empty(enc: u8) -> Frag {
        let c = Composite::default();
        match enc {
            0 => Frag::Register { reset: None, write: None },
            1 => Frag::Bag { kind: BagKind::Counter, c, elems: BTreeMap::new() },
            2 => Frag::Bag { kind: BagKind::Max, c, elems: BTreeMap::new() },
            3 => Frag::Bag { kind: BagKind::Min, c, elems: BTreeMap::new() },
            4 => Frag::Struct { c, fields: BTreeMap::new() },
            5 => Frag::Enum { c, case: None, payloads: BTreeMap::new() },
            6 => Frag::Set { c, elems: BTreeMap::new() },
            7 => Frag::Map { c, entries: BTreeMap::new() },
            8 => Frag::Seq { text: false, c, elems: BTreeMap::new() },
            9 => Frag::Seq { text: true, c, elems: BTreeMap::new() },
            _ => panic!("unknown encoding"),
        }
    }

    /// Own reset; for `Slots` the greatest slot reset (one position, one effective reset, §7).
    pub fn reset(&self) -> Option<Stamp> {
        match self {
            Frag::Register { reset, .. } => reset.clone(),
            Frag::Slots { .. } => self.slots().into_iter().fold(None, |m, f| max_opt(m, f.reset())),
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => c.reset.clone(),
        }
    }
    pub fn set_reset(&mut self, r: Option<Stamp>) {
        match self {
            Frag::Register { reset, .. } => *reset = r,
            Frag::Slots { .. } => panic!("writers never produce slots"),
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => c.reset = r,
        }
    }
    pub fn composite(&self) -> Option<&Composite> {
        match self {
            Frag::Register { .. } | Frag::Slots { .. } => None,
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => Some(c),
        }
    }
    pub fn composite_mut(&mut self) -> Option<&mut Composite> {
        match self {
            Frag::Register { .. } | Frag::Slots { .. } => None,
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => Some(c),
        }
    }

    /// Presence stamp (§4.3): a register's valued write, or a composite's explicit `W` joined with every
    /// presence-counting write inside.
    pub fn written(&self) -> Option<Stamp> {
        match self {
            Frag::Register { write, .. } => write.as_ref().filter(|w| w.1.is_some()).map(|w| w.0.clone()),
            Frag::Slots { .. } => self.chosen().written(),
            f => max_opt(f.composite().unwrap().w.clone().filter(|_| !f.composite().unwrap().w_valueless), f.inner_max(true)),
        }
    }

    /// Greatest stamp carried inside (writes of children, elements, case, pos, flags), excluding own reset and own
    /// explicit `W`. With `valued`, value-less writes are skipped (§4.3, §4.7); used for presence and the canonical
    /// `W` rule (§3.3 rule 4).
    pub fn inner_max(&self, valued: bool) -> Option<Stamp> {
        let child = |f: &Frag| if valued { max_opt(f.written(), f.reset()) } else { f.all_max() };
        let elems_max = |elems: &BTreeMap<Dot, Elem>| elems.values().fold(None, |m, e| max_opt(max_opt(m, e.reset.clone()), e.frag.as_deref().and_then(child)));
        match self {
            Frag::Register { write, .. } => write.as_ref().filter(|w| !valued || w.1.is_some()).map(|w| w.0.clone()),
            Frag::Slots { .. } => self.slots().into_iter().fold(None, |m, f| max_opt(m, child(f))),
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems_max(elems),
            Frag::Struct { fields, .. } => fields.values().fold(None, |m, f| max_opt(m, child(f))),
            Frag::Enum { case, payloads, .. } => {
                let k = case.as_ref().filter(|k| !valued || k.1.is_some()).map(|k| k.0.clone());
                payloads.values().fold(k, |m, f| max_opt(m, child(f)))
            }
            // a keyed record's creation counts (§4.3); a key-erased record's is value-less
            Frag::Map { entries, .. } => entries.iter().fold(None, |m, ((_, k), e)| {
                let c = e.created.clone().filter(|_| !valued || k.is_some());
                max_opt(max_opt(max_opt(m, c), e.reset.clone()), e.frag.as_deref().and_then(child))
            }),
            Frag::Seq { elems, text, .. } => elems.iter().fold(None, |m, (d, e)| {
                let creation = !valued || e.creation_counts(*text);
                let m = if creation { max_opt(m, e.created.as_ref().map(|c| c.0.clone())) } else { m };
                // the creation write sits in `pos` too
                let m = e.pos.iter().filter(|p| creation || p.0.dot != *d).fold(m, |m, p| max_opt(m, Some(p.0.clone())));
                let m = max_opt(m, e.deleted.as_ref().map(|d| d.0.clone()));
                match &e.content {
                    // a list element's fragment survives its reset only with newer writes, which are on the wire
                    Content::Frag(f) => max_opt(m, child(f)),
                    _ => m,
                }
            }),
        }
    }

    /// Greatest stamp of anything in this fragment including its own reset, `W` and value-less writes (§7, Read).
    pub fn all_max(&self) -> Option<Stamp> {
        let w = self.composite().and_then(|c| c.w.clone());
        max_opt(max_opt(self.inner_max(false), self.reset()), w)
    }

    /// No surviving write at any depth (§4.2): after pruning every record holds one.
    pub fn is_empty(&self) -> bool {
        self.all_max().is_none() && match self {
            Frag::Register { .. } => true,
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.is_empty(),
            Frag::Struct { fields, .. } => fields.is_empty(),
            Frag::Enum { payloads, .. } => payloads.is_empty(),
            Frag::Map { entries, .. } => entries.is_empty(),
            Frag::Seq { elems, .. } => elems.is_empty(),
            Frag::Slots { .. } => self.slots().iter().all(|f| f.is_empty()),
        }
    }

    // ---------------------------------------------------------------- join

    /// Join (§4.1, §7). `other` may be any encoding.
    pub fn join(&mut self, other: Frag) {
        let a = std::mem::replace(self, Frag::empty(0));
        *self = join_any(a, other);
        self.prune(None);
    }

    /// Raw union of writes, same encoding, no pruning.
    pub fn join_raw(self, o: Frag) -> Frag {
        assert_eq!(self.enc(), o.enc());
        fn jc(a: Composite, b: Composite) -> Composite {
            // later wins; of copies of one `W` the valued one (§4.1 copy order)
            let w_valueless = match a.w.cmp(&b.w) {
                std::cmp::Ordering::Less => b.w_valueless,
                std::cmp::Ordering::Greater => a.w_valueless,
                std::cmp::Ordering::Equal => a.w_valueless && b.w_valueless,
            };
            Composite { reset: max_opt(a.reset, b.reset), w: max_opt(a.w, b.w), w_valueless }
        }
        fn jopt(a: Option<Box<Frag>>, b: Option<Box<Frag>>) -> Option<Box<Frag>> {
            match (a, b) {
                (None, x) | (x, None) => x,
                (Some(a), Some(b)) => Some(Box::new(join_any(*a, *b))),
            }
        }
        fn jelems(mut a: BTreeMap<Dot, Elem>, b: BTreeMap<Dot, Elem>) -> BTreeMap<Dot, Elem> {
            for (d, eb) in b {
                match a.remove(&d) {
                    None => {
                        a.insert(d, eb);
                    }
                    Some(ea) => {
                        a.insert(d, Elem { reset: max_opt(ea.reset, eb.reset), frag: jopt(ea.frag, eb.frag) });
                    }
                }
            }
            a
        }
        fn jfrags(mut a: BTreeMap<u64, Frag>, b: BTreeMap<u64, Frag>) -> BTreeMap<u64, Frag> {
            for (k, fb) in b {
                match a.remove(&k) {
                    None => {
                        a.insert(k, fb);
                    }
                    Some(fa) => {
                        a.insert(k, join_any(fa, fb));
                    }
                }
            }
            a
        }
        match (self, o) {
            (Frag::Register { reset: ra, write: wa }, Frag::Register { reset: rb, write: wb }) => Frag::Register { reset: max_opt(ra, rb), write: max_valued(wa, wb) },
            (Frag::Bag { kind, c: ca, elems: ea }, Frag::Bag { c: cb, elems: eb, .. }) => Frag::Bag { kind, c: jc(ca, cb), elems: jelems(ea, eb) },
            (Frag::Set { c: ca, elems: ea }, Frag::Set { c: cb, elems: eb }) => Frag::Set { c: jc(ca, cb), elems: jelems(ea, eb) },
            (Frag::Struct { c: ca, fields: fa }, Frag::Struct { c: cb, fields: fb }) => Frag::Struct { c: jc(ca, cb), fields: jfrags(fa, fb) },
            (Frag::Enum { c: ca, case: ka, payloads: pa }, Frag::Enum { c: cb, case: kb, payloads: pb }) => Frag::Enum { c: jc(ca, cb), case: max_valued(ka, kb), payloads: jfrags(pa, pb) },
            (Frag::Map { c: ca, entries: mut ea }, Frag::Map { c: cb, entries: eb }) => {
                for (id, nb) in eb {
                    match ea.remove(&id) {
                        None => {
                            ea.insert(id, nb);
                        }
                        Some(na) => {
                            ea.insert(id, Entry { reset: max_opt(na.reset, nb.reset), frag: jopt(na.frag, nb.frag), created: max_opt(na.created, nb.created) });
                        }
                    }
                }
                Frag::Map { c: jc(ca, cb), entries: ea }
            }
            (Frag::Seq { text, c: ca, elems: mut ea }, Frag::Seq { c: cb, elems: eb, .. }) => {
                for (d, nb) in eb {
                    match ea.remove(&d) {
                        None => {
                            ea.insert(d, nb);
                        }
                        Some(mut na) => {
                            let mut nb = nb;
                            // a text char without a creation is no one's payload (§5.7)
                            for x in [&mut na, &mut nb] {
                                if text && x.created.is_none() {
                                    x.content = Content::None;
                                }
                            }
                            // one creation per dot: copies under other stamps are one write, the greater stamp wins
                            // whole (anchor and char) and the lesser goes, as a position write too (§5.7 Join)
                            if let (Some(a), Some(b)) = (&na.created, &nb.created) {
                                if a.0 != b.0 {
                                    let lost = a.clone().min(b.clone());
                                    let loser = if a.0 < b.0 { &mut na } else { &mut nb };
                                    loser.pos.retain(|p| p.2.is_some() || p.0 != lost.0 || p.1 != lost.1);
                                    loser.created = None;
                                    if text {
                                        loser.content = Content::None;
                                    }
                                }
                            }
                            // of two copies of one creation the greater anchor and the greater char (§4.1 copy order)
                            let content = match (na.content, nb.content) {
                                (Content::None, x) | (x, Content::None) => x,
                                (Content::Char(a), Content::Char(b)) => Content::Char(a.max(b)),
                                (Content::Frag(a), Content::Frag(b)) => Content::Frag(Box::new(join_any(*a, *b))),
                                (a, _) => a,
                            };
                            // the flag: later wins; of copies of one write `true` over `false`, then a char over
                            // none, then the greater char (§4.1 copy order)
                            let (deleted, undel) = match (na.deleted, nb.deleted) {
                                (None, d) => (d, nb.undel),
                                (d, None) => (d, na.undel),
                                (Some(a), Some(b)) => {
                                    if (a.0.clone(), a.1, na.undel) < (b.0.clone(), b.1, nb.undel) { (Some(b), nb.undel) } else { (Some(a), na.undel) }
                                }
                            };
                            let mut pos = na.pos;
                            pos.extend(nb.pos);
                            // a list creation's valued copy over its value-less one (§4.1 copy order)
                            let valueless = match (&na.created, &nb.created) {
                                (Some(_), Some(_)) => na.valueless && nb.valueless,
                                (Some(_), None) => na.valueless,
                                (None, _) => nb.valueless,
                            };
                            let created = na.created.max(nb.created);
                            ea.insert(d, SeqElem { created, content, pos: top2(pos), deleted, undel, valueless });
                        }
                    }
                }
                Frag::Seq { text, c: jc(ca, cb), elems: ea }
            }
            _ => unreachable!(),
        }
    }

    // --------------------------------------------------------------- prune

    /// Drop every write below the effective reset (§4.2). `e_parent` is the parent's effective reset.
    pub fn prune(&mut self, e_parent: Option<&Stamp>) {
        let own = self.reset();
        let e = max_opt(e_parent.cloned(), own);
        let e = e.as_ref();
        if let Frag::Slots { .. } = self {
            // one effective reset for every slot (§7): each slot is pruned with it like any nested fragment (an
            // own reset below it goes); slots left empty or below the register's embedding go, fewer than two
            // collapse
            let (reg, mut slots) = parts(std::mem::replace(self, Frag::empty(0)));
            // every slot holds the register's embedding, however the slots arrived
            if let Some(r) = &reg {
                for (k, f) in slots.iter_mut() {
                    // a text slot's embedded records are the embedding of the register's winning copy (§7)
                    if let (Frag::Seq { elems, .. }, Frag::Register { write: Some(w), .. }) = (&mut *f, r) {
                        elems.retain(|d, e| {
                            if matches!(&d.source, Source::Derived(x) if **x == w.0.dot) {
                                e.created = None;
                                if matches!(e.content, Content::Char(_)) {
                                    e.content = Content::None;
                                }
                                e.pos.retain(|p| p.0.dot != *d);
                            }
                            e.is_record()
                        });
                    }
                    let e = crate::embed::embed(r, *k).expect("embedding is total from a register");
                    *f = std::mem::replace(f, Frag::empty(0)).join_raw(e);
                }
            }
            let fix = |mut f: Frag| {
                f.prune(e);
                f
            };
            let reg = reg.map(fix);
            let slots = slots.into_iter().map(|(k, f)| (k, fix(f))).collect();
            *self = assemble(reg, slots);
            return;
        }
        // a nested reset below the parent's effective reset is itself a pruned write (§4.2)
        if let (Some(r), Some(p)) = (self.reset(), e_parent) {
            if !survives(&r, Some(p)) {
                self.set_reset(None);
            }
        }
        fn prune_elems(elems: &mut BTreeMap<Dot, Elem>, e: Option<&Stamp>) {
            elems.retain(|_, el| {
                if !el.reset.as_ref().map_or(true, |r| survives(r, e)) {
                    el.reset = None;
                }
                let ee = max_opt(e.cloned(), el.reset.clone());
                if let Some(f) = &mut el.frag {
                    f.prune(ee.as_ref());
                    if f.is_empty() {
                        el.frag = None;
                    }
                }
                el.reset.is_some() || el.frag.is_some()
            });
        }
        match self {
            Frag::Register { write, reset } => {
                if let Some(w) = write {
                    if !survives(&w.0, e) {
                        *write = None;
                    }
                }
                // a reset below the register's own write is implied by it (the write resets everything older at
                // the position, §7), so it goes
                if let (Some(w), Some(r)) = (write.as_ref(), reset.as_ref()) {
                    if w.0 > *r {
                        *reset = None;
                    }
                }
            }
            Frag::Bag { c, elems, .. } | Frag::Set { c, elems } => {
                prune_written(c, e);
                prune_elems(elems, e);
            }
            Frag::Struct { c, fields } => {
                prune_written(c, e);
                fields.retain(|_, f| {
                    f.prune(e);
                    !f.is_empty()
                });
            }
            Frag::Enum { c, case, payloads } => {
                prune_written(c, e);
                if let Some(k) = case {
                    if !survives(&k.0, e) {
                        *case = None;
                    }
                }
                payloads.retain(|_, f| {
                    f.prune(e);
                    !f.is_empty()
                });
            }
            Frag::Map { c, entries } => {
                prune_written(c, e);
                for en in entries.values_mut() {
                    if !en.reset.as_ref().map_or(true, |r| survives(r, e)) {
                        en.reset = None;
                    }
                }
                // the records of a dot are one entry (§5.6): every reset of the dot reaches each of them, and each write
                // of the dot's join sits in the record carrying the greatest key of its copies (the key-erased record's
                // lowest), as the join of every copy (§4.1 copy order: the key is a part of its own)
                let dots: Vec<Dot> = entries.keys().map(|(d, _)| d.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                for d in dots {
                    let ids: Vec<Eid> = entries.keys().filter(|(x, _)| *x == d).cloned().collect();
                    let r = ids.iter().fold(None, |m, id| max_opt(m, entries[id].reset.clone()));
                    let ee = max_opt(e.cloned(), r.clone());
                    let mut recs: BTreeMap<Eid, Entry> = ids.iter().map(|id| (id.clone(), entries.remove(id).unwrap())).collect();
                    for en in recs.values_mut() {
                        if let Some(f) = &mut en.frag {
                            f.prune(ee.as_ref());
                        }
                        if !en.created.as_ref().map_or(true, |c| survives(c, ee.as_ref())) {
                            en.created = None;
                        }
                    }
                    let c = recs.values().fold(None, |m, en| max_opt(m, en.created.clone()));
                    // every write once, under the greatest key holding a copy of it, as the join of its copies
                    let mut at: BTreeMap<crate::writes::Name, (Eid, Frag)> = BTreeMap::new();
                    for (id, en) in recs.iter().rev() {
                        for (n, w) in en.frag.as_deref().map(crate::writes::writes).unwrap_or_default() {
                            match at.entry(n) {
                                std::collections::btree_map::Entry::Vacant(v) => {
                                    v.insert((id.clone(), w));
                                }
                                std::collections::btree_map::Entry::Occupied(mut o) => {
                                    let x = &mut o.get_mut().1;
                                    *x = join_any(x.clone(), w);
                                }
                            }
                        }
                    }
                    // of those, the ones the dot's join holds, as the join holds them (a creation pushed out of the
                    // dot's top-2 positions keeps no position write, §5.7)
                    let held = crate::writes::join_all(at.values().map(|x| x.1.clone())).map(|mut j| {
                        j.prune(ee.as_ref());
                        crate::writes::by_name(&j)
                    });
                    let held = held.unwrap_or_default();
                    let reset_at = recs.iter().rev().find(|(_, en)| r.is_some() && en.reset == r).map(|x| x.0.clone());
                    let created_at = recs.iter().rev().find(|(_, en)| c.is_some() && en.created == c).map(|x| x.0.clone());
                    for id in recs.into_keys() {
                        let frag = crate::writes::join_all(at.iter().filter(|(_, (k, _))| *k == id).filter_map(|(n, _)| held.get(n).cloned())).map(|mut f| {
                            f.prune(ee.as_ref());
                            f
                        });
                        let en = Entry {
                            reset: if reset_at.as_ref() == Some(&id) { r.clone() } else { None },
                            frag: frag.filter(|f| !f.is_empty()).map(Box::new),
                            created: if created_at.as_ref() == Some(&id) { c.clone() } else { None },
                        };
                        // a creation is a write of its own: it may be left alone (its content un-merged)
                        if en.holds() {
                            entries.insert(id, en);
                        }
                    }
                }
            }
            Frag::Slots { .. } => unreachable!(),
            Frag::Seq { c, elems, text } => {
                prune_written(c, e);
                elems.retain(|_, el| {
                    el.pos.retain(|p| survives(&p.0, e));
                    if el.created.as_ref().map_or(false, |c| !survives(&c.0, e)) {
                        el.created = None;
                        el.valueless = false;
                    }
                    // a text flag write below the creation loses the char register to it (§5.7 Join)
                    let floor = if *text { max_opt(e.cloned(), el.created.as_ref().map(|c| c.0.clone())) } else { e.cloned() };
                    if let Some(d) = &el.deleted {
                        if !survives(&d.0, floor.as_ref()) {
                            el.deleted = None;
                            el.undel = None;
                        }
                    }
                    // a list element's content is pruned under its own reset as well (§5.7)
                    let ee = if *text { e.cloned() } else { max_opt(e.cloned(), el.deleted.as_ref().map(|d| d.0.clone())) };
                    let mut keep_content = true;
                    if let Content::Frag(f) = &mut el.content {
                        f.prune(ee.as_ref());
                        keep_content = !f.is_empty();
                    }
                    if !keep_content {
                        el.content = Content::None;
                    }
                    // Text content has no stamp of its own: it lives and dies with the creation write (§5.7).
                    if el.created.is_none() && matches!(el.content, Content::Char(_)) {
                        el.content = Content::None;
                    }
                    el.is_record()
                });
            }
        }
    }

    // --------------------------------------------------------------- read

    pub fn present(&self) -> bool {
        self.written().is_some()
    }

    /// Whether the fragment holds a live value (§4.3): a valued register or case winner, a `W`, a live element or
    /// record, or a field holding one. Removals, positions and value-less writes are none.
    pub fn live_value(&self) -> bool {
        match self {
            Frag::Register { write, .. } => write.as_ref().is_some_and(|w| w.1.is_some()),
            Frag::Slots { .. } => self.chosen().live_value(),
            f if f.composite().is_some_and(|c| c.w.is_some() && !c.w_valueless) => true,
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.values().any(|e| e.frag.as_ref().is_some_and(|f| f.present())),
            Frag::Struct { fields, .. } => fields.values().any(|f| f.live_value()),
            Frag::Enum { case, .. } => case.as_ref().is_some_and(|k| k.1.is_some()),
            Frag::Map { entries, .. } => !live_records(entries).is_empty(),
            Frag::Seq { text, elems, .. } => elems.values().any(|e| e.shows(*text)),
        }
    }

    /// Read (§4.4, §5). `None` = absent.
    pub fn read(&self) -> Option<Value> {
        if !self.present() {
            return None;
        }
        Some(match self {
            Frag::Slots { .. } => return self.chosen().read(),
            Frag::Register { write, .. } => write.as_ref().unwrap().1.clone().unwrap(),
            Frag::Bag { kind, elems, .. } => {
                let vals: Vec<Value> = elems.values().filter_map(|e| e.frag.as_ref().and_then(|f| f.read())).collect();
                match kind {
                    BagKind::Counter => {
                        // §5.2: ints summed exactly (i128) and clamped to i64; floats summed as f64 in dot order
                        // (`vals` is in dot order), so the read is the same on every node.
                        let mut si: i128 = 0;
                        let mut sf: f64 = 0.0;
                        let mut is_f = false;
                        for v in &vals {
                            match v {
                                Value::Int(i) => si += *i as i128,
                                Value::Float(b) => {
                                    is_f = true;
                                    sf += f64::from_bits(*b)
                                }
                                _ => {}
                            }
                        }
                        let si = si.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
                        if is_f {
                            Value::float(sf + si as f64)
                        } else {
                            Value::Int(si)
                        }
                    }
                    BagKind::Max | BagKind::Min => {
                        let mut it = vals.into_iter().filter(|v| matches!(v, Value::Int(_) | Value::Float(_)));
                        let first = it.next()?;
                        it.fold(first, |a, b| {
                            let ord = num_cmp(&a, &b);
                            let pick_b = if *kind == BagKind::Max { ord.is_lt() } else { ord.is_gt() };
                            if pick_b { b } else { a }
                        })
                    }
                }
            }
            Frag::Struct { fields, .. } => Value::fields(fields.iter().filter_map(|(k, f)| f.read().map(|v| (*k, v))).collect()),
            Frag::Enum { case, payloads, .. } => {
                let (_, Some(id)) = case.as_ref()? else { return None };
                Value::Enum(*id, payloads.get(id).and_then(|f| f.read()).map(Box::new))
            }
            Frag::Set { elems, .. } => Value::set(elems.values().filter_map(|e| e.frag.as_ref().and_then(|f| f.read())).collect()),
            Frag::Map { entries, .. } => {
                let mut by_key: BTreeMap<Value, Frag> = BTreeMap::new();
                for ((_, k), f) in live_records(entries) {
                    let k = k.expect("live records are keyed");
                    match by_key.remove(&k) {
                        None => {
                            by_key.insert(k, f);
                        }
                        Some(g) => {
                            let mut j = join_any(g, f);
                            j.prune(None);
                            by_key.insert(k, j);
                        }
                    }
                }
                Value::map(by_key.into_iter().filter_map(|(k, f)| f.read().map(|v| (k, v))).collect())
            }
            Frag::Seq { text, elems, .. } => {
                let order = linearize(elems, *text);
                if *text {
                    Value::Str(order.iter().filter_map(|d| elems[d].char()).collect())
                } else {
                    Value::List(order.iter().filter_map(|d| match &elems[d].content {
                        Content::Frag(f) => f.read(),
                        _ => None,
                    }).collect())
                }
            }
        })
    }

    // ------------------------------------------------------------ un-merge

    /// Remove the writes of invalid deltas (§4.6): every write whose origin dot `bad` names, and the records such
    /// a dot created with others' writes nested in them, but for a record whose dot `held` names (a valid snapshot
    /// holds a record of that dot, at any key or position: `held_records`): it stays with the valid writes nested in
    /// it. `bad` is asked about origin dots (never `Derived`).
    pub fn unmerge(&mut self, bad: &dyn Fn(&Dot) -> bool, held: &dyn Fn(&Dot) -> bool) {
        if let Frag::Slots { .. } = self {
            let (reg, slots) = parts(std::mem::replace(self, Frag::empty(0)));
            let reg = reg.map(|mut r| {
                r.unmerge(bad, held);
                r
            });
            let slots = slots
                .into_iter()
                .map(|(k, mut f)| {
                    f.unmerge(bad, held);
                    (k, f)
                })
                .collect();
            *self = assemble(reg, slots);
            return;
        }
        let is_bad = |s: &Stamp| bad(origin(&s.dot));
        let child = |f: &mut Frag| {
            f.unmerge(bad, held);
            !f.is_empty()
        };
        fn fix_elems(elems: &mut BTreeMap<Dot, Elem>, bad: &dyn Fn(&Dot) -> bool, held: &dyn Fn(&Dot) -> bool) {
            elems.retain(|d, el| {
                if el.reset.as_ref().is_some_and(|r| bad(origin(&r.dot))) {
                    el.reset = None;
                }
                if bad(origin(d)) && !held(d) {
                    el.frag = None;
                } else if let Some(f) = &mut el.frag {
                    f.unmerge(bad, held);
                    if f.is_empty() {
                        el.frag = None;
                    }
                }
                el.reset.is_some() || el.frag.is_some()
            });
        }
        if let Some(c) = self.composite_mut() {
            if c.reset.as_ref().is_some_and(|r| is_bad(r)) {
                c.reset = None;
            }
            if c.w.as_ref().is_some_and(|r| is_bad(r)) {
                c.w = None;
                c.w_valueless = false;
            }
        }
        match self {
            Frag::Slots { .. } => unreachable!(),
            Frag::Register { reset, write } => {
                if reset.as_ref().is_some_and(|r| is_bad(r)) {
                    *reset = None;
                }
                if write.as_ref().is_some_and(|w| is_bad(&w.0)) {
                    *write = None;
                }
            }
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => fix_elems(elems, bad, held),
            Frag::Struct { fields, .. } => fields.retain(|_, f| child(f)),
            Frag::Enum { case, payloads, .. } => {
                if case.as_ref().is_some_and(|k| is_bad(&k.0)) {
                    *case = None;
                }
                payloads.retain(|_, f| child(f));
            }
            Frag::Map { entries, .. } => entries.retain(|(d, _), en| {
                if en.reset.as_ref().is_some_and(|r| is_bad(r)) {
                    en.reset = None;
                }
                if bad(origin(d)) {
                    en.created = None;
                    if !held(d) {
                        en.frag = None;
                    }
                }
                if let Some(f) = &mut en.frag {
                    f.unmerge(bad, held);
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                en.holds()
            }),
            Frag::Seq { elems, .. } => {
                elems.retain(|d, el| {
                    el.pos.retain(|p| !is_bad(&p.0));
                    if el.deleted.as_ref().is_some_and(|x| is_bad(&x.0)) {
                        el.deleted = None;
                        el.undel = None;
                    }
                    if bad(origin(d)) {
                        // the creation goes (§6.1 places what anchors at it) with its char; its list content too
                        // unless a valid snapshot holds the element; an undelete's char is its own writer's (§4.7)
                        el.created = None;
                        el.valueless = false;
                        if !held(d) || matches!(el.content, Content::Char(_)) {
                            el.content = Content::None;
                        }
                    }
                    if let Content::Frag(f) = &mut el.content {
                        f.unmerge(bad, held);
                        if f.is_empty() {
                            el.content = Content::None;
                        }
                    }
                    // a record of theirs goes where no write is left
                    el.is_record()
                });
            }
        }
    }

    /// The dots of every record (map entry, any key or key-erased; set, bag or sequence element) at any depth: what
    /// a valid snapshot holds for un-merge (§4.6: a record is held by its dot, wherever it sits).
    pub fn held_records(&self, out: &mut BTreeSet<Dot>) {
        for f in self.slots() {
            match f {
                Frag::Bag { elems, .. } | Frag::Set { elems, .. } => {
                    for (d, el) in elems {
                        out.insert(d.clone());
                        if let Some(f) = &el.frag {
                            f.held_records(out);
                        }
                    }
                }
                Frag::Struct { fields, .. } => fields.values().for_each(|f| f.held_records(out)),
                Frag::Enum { payloads, .. } => payloads.values().for_each(|f| f.held_records(out)),
                Frag::Map { entries, .. } => {
                    for ((d, _), en) in entries {
                        out.insert(d.clone());
                        if let Some(f) = &en.frag {
                            f.held_records(out);
                        }
                    }
                }
                Frag::Seq { elems, .. } => {
                    for (d, el) in elems {
                        out.insert(d.clone());
                        if let Content::Frag(f) = &el.content {
                            f.held_records(out);
                        }
                    }
                }
                Frag::Register { .. } | Frag::Slots { .. } => {}
            }
        }
    }

    // -------------------------------------------------------------- expiry

    /// Hold every value-carrying write owned by an expired commit value-less (§4.7). `expired` is asked about origin
    /// dots (never `Derived`). Commutes with join; applied after every join on a node past the commit's T, and what a
    /// snapshot carries of an expiring delta.
    pub fn strip(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_values(expired);
        // the moved map writes meet their dot's records; `Derived` records left without a write go
        self.prune(None);
    }

    fn strip_values(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        let exp = |d: &Dot| expired(origin(d));
        // `W` writes the value "an empty composite"
        if let Some(c) = self.composite_mut() {
            if c.w.as_ref().is_some_and(|w| exp(&w.dot)) {
                c.w_valueless = true;
            }
        }
        match self {
            Frag::Slots { reg, slots } => {
                reg.iter_mut().for_each(|r| r.strip_values(expired));
                slots.values_mut().for_each(|f| f.strip_values(expired));
            }
            Frag::Register { write, .. } => {
                if let Some(w) = write {
                    if exp(&w.0.dot) {
                        w.1 = None;
                    }
                }
            }
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.values_mut().filter_map(|e| e.frag.as_mut()).for_each(|f| f.strip_values(expired)),
            Frag::Struct { fields, .. } => fields.values_mut().for_each(|f| f.strip_values(expired)),
            Frag::Enum { case, payloads, .. } => {
                if let Some(k) = case {
                    if exp(&k.0.dot) {
                        k.1 = None;
                    }
                }
                payloads.values_mut().for_each(|f| f.strip_values(expired));
            }
            Frag::Map { entries, .. } => {
                // each write repeats its record's key as its own value: the expired ones move, value-less, to their
                // dot's key-erased record
                let keyed: Vec<Eid> = entries.keys().filter(|(_, k)| k.is_some()).cloned().collect();
                for id in keyed {
                    let en = entries.remove(&id).unwrap();
                    let mut mine = en.clone();
                    mine.keep_writes(&id.0, &|d| exp(d));
                    let mut rest = en;
                    rest.keep_writes(&id.0, &|d| !exp(d));
                    if rest.holds() {
                        entries.insert(id.clone(), rest);
                    }
                    if mine.holds() {
                        let er = (id.0.clone(), None);
                        let en = match entries.remove(&er) {
                            None => mine,
                            Some(o) => Entry { reset: max_opt(o.reset, mine.reset), frag: jopt_any(o.frag, mine.frag), created: max_opt(o.created, mine.created) },
                        };
                        entries.insert(er, en);
                    }
                }
                for f in entries.values_mut().filter_map(|en| en.frag.as_mut()) {
                    f.strip_values(expired);
                }
            }
            Frag::Seq { text, elems, .. } => {
                let text = *text;
                for (d, el) in elems.iter_mut() {
                    // an undelete's char is its flag write's own value
                    if el.deleted.as_ref().is_some_and(|x| exp(&x.0.dot)) {
                        el.undel = None;
                    }
                    if !text && exp(d) && el.created.is_some() {
                        el.valueless = true;
                    }
                    match &mut el.content {
                        Content::Frag(f) => f.strip_values(expired),
                        _ if exp(d) => {
                            el.content = Content::None;
                            if matches!(d.source, Source::Derived(_)) {
                                // an embedded character's creation is known only from the value (§7): it goes entirely
                                el.created = None;
                                el.pos.retain(|p| p.0.dot != *d);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Keeps only the writes whose origin dot `keep` accepts, with the records holding them; others' writes nested in
    /// a record go with theirs, but the record stays where a kept write is in it.
    pub fn keep_writes(&mut self, keep: &dyn Fn(&Dot) -> bool) {
        let k = |s: &Option<Stamp>| s.as_ref().is_some_and(|s| keep(origin(&s.dot)));
        if let Frag::Slots { .. } = self {
            let (reg, slots) = parts(std::mem::replace(self, Frag::empty(0)));
            let reg = reg.map(|mut r| {
                r.keep_writes(keep);
                r
            });
            let slots = slots.into_iter().map(|(e, mut f)| {
                f.keep_writes(keep);
                (e, f)
            });
            *self = assemble(reg, slots.collect());
            return;
        }
        if let Some(c) = self.composite_mut() {
            if !k(&c.reset) {
                c.reset = None;
            }
            if !k(&c.w) {
                c.w = None;
                c.w_valueless = false;
            }
        }
        match self {
            Frag::Slots { .. } => unreachable!(),
            Frag::Register { reset, write } => {
                if !k(reset) {
                    *reset = None;
                }
                if !write.as_ref().is_some_and(|w| keep(origin(&w.0.dot))) {
                    *write = None;
                }
            }
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.retain(|_, el| {
                if !k(&el.reset) {
                    el.reset = None;
                }
                keep_in(&mut el.frag, keep);
                el.reset.is_some() || el.frag.is_some()
            }),
            Frag::Struct { fields: m, .. } => m.retain(|_, f| {
                f.keep_writes(keep);
                !f.is_empty()
            }),
            Frag::Enum { case, payloads, .. } => {
                if !case.as_ref().is_some_and(|c| keep(origin(&c.0.dot))) {
                    *case = None;
                }
                payloads.retain(|_, f| {
                    f.keep_writes(keep);
                    !f.is_empty()
                });
            }
            Frag::Map { entries, .. } => entries.retain(|(d, _), en| {
                en.keep_writes(d, keep);
                en.holds()
            }),
            Frag::Seq { elems, .. } => elems.retain(|d, el| {
                if !keep(origin(d)) {
                    el.created = None;
                    el.valueless = false;
                    if matches!(el.content, Content::Char(_)) {
                        el.content = Content::None;
                    }
                }
                el.pos.retain(|p| keep(origin(&p.0.dot)));
                if !el.deleted.as_ref().is_some_and(|x| keep(origin(&x.0.dot))) {
                    el.deleted = None;
                    el.undel = None;
                }
                if let Content::Frag(f) = &mut el.content {
                    f.keep_writes(keep);
                    if f.is_empty() {
                        el.content = Content::None;
                    }
                }
                el.is_record()
            }),
        }
    }
}

impl Entry {
    /// Whether the record holds a write (§4.2).
    pub fn holds(&self) -> bool {
        self.reset.is_some() || self.frag.is_some() || self.created.is_some()
    }
    /// `Frag::keep_writes` of record `dot`'s writes: its reset, its creation (the dot's) and its content.
    pub fn keep_writes(&mut self, dot: &Dot, keep: &dyn Fn(&Dot) -> bool) {
        if !self.reset.as_ref().is_some_and(|r| keep(origin(&r.dot))) {
            self.reset = None;
        }
        if !keep(origin(dot)) {
            self.created = None;
        }
        keep_in(&mut self.frag, keep);
    }
}

fn keep_in(f: &mut Option<Box<Frag>>, keep: &dyn Fn(&Dot) -> bool) {
    if let Some(x) = f {
        x.keep_writes(keep);
        if x.is_empty() {
            *f = None;
        }
    }
}

fn prune_written(c: &mut Composite, e: Option<&Stamp>) {
    if let Some(w) = &c.w {
        if !survives(w, e) {
            c.w = None;
            c.w_valueless = false;
        }
    }
}

/// §5.2 order for max/min: ints by value; anything involving a float by IEEE 754 totalOrder on f64
/// (-0.0 < 0.0, the canonical NaN is greatest), so the result never depends on iteration order.
pub fn num_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let f = |v: &Value| match v {
        Value::Int(i) => *i as f64,
        Value::Float(b) => f64::from_bits(*b),
        _ => f64::NAN,
    };
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        _ => f(a).total_cmp(&f(b)),
    }
}

/// Drops the chars of deleted text elements at any depth: what the wire carries (§3.3 rule 5).
pub fn drop_deleted_chars(f: &mut Frag) {
    match f {
        Frag::Seq { elems, .. } => {
            for e in elems.values_mut() {
                match &mut e.content {
                    Content::Char(_) if e.deleted.as_ref().map_or(false, |d| d.1) => e.content = Content::None,
                    Content::Frag(x) => drop_deleted_chars(x),
                    _ => {}
                }
            }
        }
        Frag::Struct { fields: m, .. } | Frag::Enum { payloads: m, .. } => m.values_mut().for_each(drop_deleted_chars),
        Frag::Map { entries, .. } => entries.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(drop_deleted_chars),
        Frag::Set { elems, .. } | Frag::Bag { elems, .. } => elems.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(drop_deleted_chars),
        Frag::Slots { slots, .. } => slots.values_mut().for_each(drop_deleted_chars),
        Frag::Register { .. } => {}
    }
}

/// Split a fragment into its register slot and non-register slots.
pub(crate) fn parts(f: Frag) -> (Option<Frag>, BTreeMap<u8, Frag>) {
    match f {
        Frag::Slots { reg, slots } => (reg.map(|r| *r), slots),
        Frag::Register { .. } => (Some(f), BTreeMap::new()),
        f => {
            let mut m = BTreeMap::new();
            m.insert(f.enc(), f);
            (None, m)
        }
    }
}

/// Canonical position from its slots: a lone slot stands alone, nothing is an empty register.
pub(crate) fn assemble(reg: Option<Frag>, mut slots: BTreeMap<u8, Frag>) -> Frag {
    let reg = reg.filter(|r| !r.is_empty());
    // a slot that adds nothing to the register's embedding is not kept (§7 Canonical form)
    slots.retain(|_, f| !f.is_empty() && !reg.as_ref().map_or(false, |r| below_embedding(f, r)));
    match (reg, slots.len()) {
        (None, 0) => Frag::Register { reset: None, write: None },
        (Some(r), 0) => r,
        (None, 1) => slots.into_iter().next().unwrap().1,
        (reg, _) => Frag::Slots { reg: reg.map(Box::new), slots },
    }
}

/// Whether `f` adds nothing to the embedding of register `r` into its encoding: `f ⊔ embed(r) = embed(r)`.
fn below_embedding(f: &Frag, r: &Frag) -> bool {
    let Some(mut e) = crate::embed::embed(r, f.enc()) else { return false };
    e.prune(None);
    let mut j = f.clone().join_raw(e.clone());
    j.prune(None);
    j == e
}

/// `join_any` of optional fragments.
pub fn jopt_any(a: Option<Box<Frag>>, b: Option<Box<Frag>>) -> Option<Box<Frag>> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(Box::new(join_any(*a, *b))),
    }
}

/// Join of two fragments of possibly different encodings (§7), unpruned: pointwise per encoding, with the register
/// slot embedded into every non-register slot.
pub fn join_any(a: Frag, b: Frag) -> Frag {
    if a.enc() == b.enc() && a.enc() != 10 {
        return a.join_raw(b);
    }
    let (ra, sa) = parts(a);
    let (rb, sb) = parts(b);
    let reg = match (ra, rb) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(x.join_raw(y)),
    };
    let mut slots = sa;
    for (k, fb) in sb {
        let f = match slots.remove(&k) {
            None => fb,
            Some(fa) => fa.join_raw(fb),
        };
        slots.insert(k, f);
    }
    if let Some(r) = &reg {
        for (k, f) in slots.iter_mut() {
            let e = crate::embed::embed(r, *k).expect("embedding is total from a register");
            *f = std::mem::replace(f, Frag::empty(0)).join_raw(e);
        }
    }
    assemble(reg, slots)
}
