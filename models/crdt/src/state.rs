//! The abstract lattice (spec §4, §5): fragments with resolved stamps, join, prune, presence, read, un-merge.
use crate::seq::linearize;
use crate::stamp::{max_opt, survives, Dot, Source, Stamp};
use crate::value::Value;
use std::collections::BTreeMap;

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
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Elem {
    pub reset: Option<Stamp>,
    pub frag: Option<Box<Frag>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub reset: Option<Stamp>,
    /// `None` for tombstones and entries whose creation is value-less (§4.7, §5.6).
    pub key: Option<Value>,
    pub frag: Option<Box<Frag>>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqElem {
    /// The creation write: stamp (ts, element dot) and initial anchor. Text content lives and dies with it.
    pub created: Option<(Stamp, Anchor)>,
    pub content: Content,
    /// Position writes (the creation write included), greatest first, at most two (§5.7).
    pub pos: Vec<(Stamp, Anchor)>,
    /// Text: the deleted flag (LWW bool). List: the element reset `R_elem`, always `true`; the element's content
    /// fragment is pruned under it and the element is deleted iff that fragment is absent (§5.7).
    pub deleted: Option<(Stamp, bool)>,
}

impl SeqElem {
    pub fn new(created: Stamp, anchor: Anchor, content: Content) -> SeqElem {
        SeqElem { created: Some((created.clone(), anchor.clone())), content, pos: vec![(created, anchor)], deleted: None }
    }
    pub fn write(content: Content, pos: Vec<(Stamp, Anchor)>, deleted: Option<(Stamp, bool)>) -> SeqElem {
        SeqElem { created: None, content, pos, deleted }
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
    Map { c: Composite, entries: BTreeMap<Dot, Entry> },
    Seq { text: bool, c: Composite, elems: BTreeMap<Dot, SeqElem> },
    /// Several encodings at one position (§7): the register slot plus non-register slots keyed by encoding, joined
    /// pointwise. Every slot already holds the embedding of the register slot. Never produced by a writer; appears in
    /// states and snapshots. Always at least two members (`assemble` collapses fewer).
    Slots { reg: Option<Box<Frag>>, slots: BTreeMap<u8, Frag> },
}

pub fn max_pair<T>(a: Option<(Stamp, T)>, b: Option<(Stamp, T)>) -> Option<(Stamp, T)> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(if a.0 >= b.0 { a } else { b }),
    }
}

/// Register join: greater stamp wins; copies of one write prefer the one with the value (§4.7).
pub fn max_valued<T>(a: Option<(Stamp, Option<T>)>, b: Option<(Stamp, Option<T>)>) -> Option<(Stamp, Option<T>)> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(if a.0 > b.0 || (a.0 == b.0 && a.1.is_some()) { a } else { b }),
    }
}

/// The non-`Derived` dot whose commit owns writes under `d` (§2.1, §4.7).
pub fn owner(d: &Dot) -> &Dot {
    match &d.source {
        Source::Derived(x) => owner(x),
        _ => d,
    }
}

impl SeqElem {
    /// Whether the creation write counts toward presence: value-less creations (no content, not deleted or reset) do not.
    fn creation_counts(&self) -> bool {
        !matches!(self.content, Content::None) || self.deleted.as_ref().map_or(false, |d| d.1)
    }
    /// Text: the deleted flag. List: no present content fragment (reset, value-less or never had one).
    pub fn is_deleted(&self, text: bool) -> bool {
        if text {
            self.deleted.as_ref().map_or(false, |d| d.1)
        } else {
            !matches!(&self.content, Content::Frag(f) if f.present())
        }
    }
    fn is_record(&self) -> bool {
        self.created.is_some() || !self.pos.is_empty() || self.deleted.is_some() || matches!(self.content, Content::Frag(_))
    }
    /// Whether the record stays in the state (§4.2, §5.7): Node/Commit records are never dropped (a record with no
    /// surviving write is a bare anchor); a `Derived` record exists only while it carries a write, since a node that
    /// only ever saw the value-less register has none (§4.7, §6.1).
    fn keeps_record(&self, d: &Dot) -> bool {
        !matches!(d.source, Source::Derived(_)) || self.is_record()
    }
}

fn top2(mut v: Vec<(Stamp, Anchor)>) -> Vec<(Stamp, Anchor)> {
    v.sort_by(|a, b| b.0.cmp(&a.0));
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

    /// Members of a `Slots` position (the register slot first), or the fragment itself.
    pub fn members(&self) -> Vec<&Frag> {
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

    /// The member a `Slots` position reads as: greatest `all_max`, ties by greater encoding id (§7).
    pub fn chosen(&self) -> &Frag {
        match self {
            Frag::Slots { .. } => self.members().into_iter().max_by(|a, b| a.all_max().cmp(&b.all_max()).then(a.enc().cmp(&b.enc()))).unwrap(),
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

    /// Own reset; for `Slots` the greatest member reset (one position, one effective reset, §7).
    pub fn reset(&self) -> Option<Stamp> {
        match self {
            Frag::Register { reset, .. } => reset.clone(),
            Frag::Slots { .. } => self.members().into_iter().fold(None, |m, f| max_opt(m, f.reset())),
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
            f => max_opt(f.composite().unwrap().w.clone(), f.inner_max(true)),
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
            Frag::Slots { .. } => self.members().into_iter().fold(None, |m, f| max_opt(m, child(f))),
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems_max(elems),
            Frag::Struct { fields, .. } => fields.values().fold(None, |m, f| max_opt(m, child(f))),
            Frag::Enum { case, payloads, .. } => {
                let k = case.as_ref().filter(|k| !valued || k.1.is_some()).map(|k| k.0.clone());
                payloads.values().fold(k, |m, f| max_opt(m, child(f)))
            }
            Frag::Map { entries, .. } => entries.values().fold(None, |m, e| max_opt(max_opt(m, e.reset.clone()), e.frag.as_deref().and_then(child))),
            Frag::Seq { elems, .. } => elems.iter().fold(None, |m, (d, e)| {
                let creation = !valued || e.creation_counts();
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

    /// No surviving write and no record at any depth. Records (sequence anchors, and the element, entry or
    /// field records holding them) are grow-only, so a fragment that still holds one is not empty even without a
    /// stamp (§4.2).
    pub fn is_empty(&self) -> bool {
        self.all_max().is_none() && match self {
            Frag::Register { .. } => true,
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.is_empty(),
            Frag::Struct { fields, .. } => fields.is_empty(),
            Frag::Enum { payloads, .. } => payloads.is_empty(),
            Frag::Map { entries, .. } => entries.is_empty(),
            Frag::Seq { elems, .. } => elems.is_empty(),
            Frag::Slots { .. } => self.members().iter().all(|f| f.is_empty()),
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
            Composite { reset: max_opt(a.reset, b.reset), w: max_opt(a.w, b.w) }
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
                for (d, nb) in eb {
                    match ea.remove(&d) {
                        None => {
                            ea.insert(d, nb);
                        }
                        Some(na) => {
                            // Keys of one dot are equal by construction; keep whichever is present.
                            ea.insert(d, Entry { reset: max_opt(na.reset, nb.reset), key: na.key.or(nb.key), frag: jopt(na.frag, nb.frag) });
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
                        Some(na) => {
                            let content = match (na.content, nb.content) {
                                (Content::None, x) | (x, Content::None) => x,
                                (Content::Char(a), Content::Char(_)) => Content::Char(a),
                                (Content::Frag(a), Content::Frag(b)) => Content::Frag(Box::new(join_any(*a, *b))),
                                (a, _) => a,
                            };
                            let mut pos = na.pos;
                            pos.extend(nb.pos);
                            let created = na.created.or(nb.created);
                            ea.insert(d, SeqElem { created, content, pos: top2(pos), deleted: max_pair(na.deleted, nb.deleted) });
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
            // one effective reset for every member (§7): each member is pruned with it like any nested fragment (an
            // own reset below it goes); members left empty or below the register's embedding go, fewer than two
            // collapse
            let (reg, mut slots) = parts(std::mem::replace(self, Frag::empty(0)));
            // every member holds the register's embedding, however the members arrived
            if let Some(r) = &reg {
                for (k, f) in slots.iter_mut() {
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
                entries.retain(|_, en| {
                    if !en.reset.as_ref().map_or(true, |r| survives(r, e)) {
                        en.reset = None;
                    }
                    let ee = max_opt(e.cloned(), en.reset.clone());
                    if let Some(f) = &mut en.frag {
                        f.prune(ee.as_ref());
                        if f.is_empty() {
                            en.frag = None;
                        }
                    }
                    // content-free tombstone: the key goes with the content
                    if en.frag.is_none() {
                        en.key = None;
                    }
                    en.reset.is_some() || en.frag.is_some()
                });
            }
            Frag::Slots { .. } => unreachable!(),
            Frag::Seq { c, elems, text } => {
                prune_written(c, e);
                elems.retain(|d, el| {
                    el.pos.retain(|p| survives(&p.0, e));
                    if el.created.as_ref().map_or(false, |c| !survives(&c.0, e)) {
                        el.created = None;
                    }
                    if let Some(d) = &el.deleted {
                        if !survives(&d.0, e) {
                            el.deleted = None;
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
                    el.keeps_record(d)
                });
            }
        }
    }

    // --------------------------------------------------------------- read

    pub fn present(&self) -> bool {
        self.written().is_some()
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
                for en in entries.values() {
                    if let (Some(k), Some(f)) = (&en.key, &en.frag) {
                        if f.present() {
                            match by_key.remove(k) {
                                None => {
                                    by_key.insert(k.clone(), (**f).clone());
                                }
                                Some(g) => {
                                    let mut j = join_any(g, (**f).clone());
                                    j.prune(None);
                                    by_key.insert(k.clone(), j);
                                }
                            }
                        }
                    }
                }
                Value::map(by_key.into_iter().filter_map(|(k, f)| f.read().map(|v| (k, v))).collect())
            }
            Frag::Seq { text, elems, .. } => {
                let order = linearize(elems, *text);
                if *text {
                    Value::Str(order.iter().filter_map(|d| match &elems[d].content {
                        Content::Char(c) => Some(*c),
                        _ => None,
                    }).collect())
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

    /// Remove every write authored by a source matching `bad` (§4.6).
    pub fn unmerge(&mut self, bad: &dyn Fn(&Source) -> bool) {
        if let Frag::Slots { .. } = self {
            let (reg, slots) = parts(std::mem::replace(self, Frag::empty(0)));
            let reg = reg.map(|mut r| {
                r.unmerge(bad);
                r
            });
            let slots = slots
                .into_iter()
                .map(|(k, mut f)| {
                    f.unmerge(bad);
                    (k, f)
                })
                .collect();
            *self = assemble(reg, slots);
            return;
        }
        let is_bad = |s: &Stamp| bad(s.dot.source.author());
        fn fix_elems(elems: &mut BTreeMap<Dot, Elem>, is_bad: &dyn Fn(&Stamp) -> bool, bad: &dyn Fn(&Source) -> bool) {
            elems.retain(|d, el| {
                if el.reset.as_ref().map_or(false, |r| is_bad(r)) {
                    el.reset = None;
                }
                if bad(d.source.author()) {
                    el.frag = None;
                } else if let Some(f) = &mut el.frag {
                    f.unmerge(bad);
                    if f.is_empty() {
                        el.frag = None;
                    }
                }
                el.reset.is_some() || el.frag.is_some()
            });
        }
        if let Some(c) = self.composite_mut() {
            if c.reset.as_ref().map_or(false, |r| is_bad(r)) {
                c.reset = None;
            }
            if c.w.as_ref().map_or(false, |r| is_bad(r)) {
                c.w = None;
            }
        }
        match self {
            Frag::Slots { .. } => unreachable!(),
            Frag::Register { reset, write } => {
                if reset.as_ref().map_or(false, |r| is_bad(r)) {
                    *reset = None;
                }
                if write.as_ref().map_or(false, |w| is_bad(&w.0)) {
                    *write = None;
                }
            }
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => fix_elems(elems, &is_bad, bad),
            Frag::Struct { fields, .. } => fields.retain(|_, f| {
                f.unmerge(bad);
                !f.is_empty()
            }),
            Frag::Enum { case, payloads, .. } => {
                if case.as_ref().map_or(false, |k| is_bad(&k.0)) {
                    *case = None;
                }
                payloads.retain(|_, f| {
                    f.unmerge(bad);
                    !f.is_empty()
                });
            }
            Frag::Map { entries, .. } => entries.retain(|d, en| {
                if en.reset.as_ref().map_or(false, |r| is_bad(r)) {
                    en.reset = None;
                }
                if bad(d.source.author()) {
                    en.frag = None;
                } else if let Some(f) = &mut en.frag {
                    f.unmerge(bad);
                    if f.is_empty() {
                        en.frag = None;
                    }
                }
                if en.frag.is_none() {
                    en.key = None;
                }
                en.reset.is_some() || en.frag.is_some()
            }),
            Frag::Seq { elems, .. } => {
                for (d, el) in elems.iter_mut() {
                    let created_by_bad = bad(d.source.author());
                    // Keep the creation write of an invalid insert so the element stays a hidden anchor.
                    el.pos.retain(|p| !is_bad(&p.0) || p.0.dot == *d);
                    if el.deleted.as_ref().map_or(false, |x| is_bad(&x.0)) {
                        el.deleted = None;
                    }
                    if created_by_bad {
                        el.content = Content::None;
                    } else if let Content::Frag(f) = &mut el.content {
                        f.unmerge(bad);
                        if f.is_empty() {
                            el.content = Content::None;
                        }
                    }
                }
                elems.retain(|d, el| el.keeps_record(d));
            }
        }
    }

    // -------------------------------------------------------------- expiry

    /// Hold every value-carrying write owned by an expired commit value-less (§4.7). `expired` is asked about owner
    /// dots (never `Derived`). Commutes with join; applied after every join on a node past the commit's T.
    pub fn strip(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        self.strip_values(expired);
        // drop `Derived` records left without a write (their creation was known only from the value)
        self.prune(None);
    }

    fn strip_values(&mut self, expired: &dyn Fn(&Dot) -> bool) {
        let exp = |d: &Dot| expired(owner(d));
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
                for (d, en) in entries.iter_mut() {
                    // the key is the creation's value; a key repeated by another record is ignored
                    if exp(d) {
                        en.key = None;
                    }
                    if let Some(f) = &mut en.frag {
                        f.strip_values(expired);
                    }
                }
            }
            Frag::Seq { elems, .. } => {
                for (d, el) in elems.iter_mut() {
                    match &mut el.content {
                        // a list element loses only the content writes of the expiring delta; others' nested
                        // writes survive and show (§4.7; spec/requirements.md, Data model)
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
}

fn prune_written(c: &mut Composite, e: Option<&Stamp>) {
    if let Some(w) = &c.w {
        if !survives(w, e) {
            c.w = None;
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

/// Split a fragment into its register slot and non-register slots.
fn parts(f: Frag) -> (Option<Frag>, BTreeMap<u8, Frag>) {
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

/// Canonical position from its members: a lone member stands alone, nothing is an empty register.
fn assemble(reg: Option<Frag>, mut slots: BTreeMap<u8, Frag>) -> Frag {
    let reg = reg.filter(|r| !r.is_empty());
    // a member that adds nothing to the register's embedding is not kept (§7 Canonical form)
    slots.retain(|_, f| !f.is_empty() && !reg.as_ref().map_or(false, |r| below_embedding(f, r)));
    match (reg, slots.len()) {
        (None, 0) => Frag::Register { reset: None, write: None },
        (Some(r), 0) => r,
        (None, 1) => slots.into_iter().next().unwrap().1,
        (reg, _) => Frag::Slots { reg: reg.map(Box::new), slots },
    }
}

/// Whether `f` adds nothing to the embedding of register `r` into its encoding: `f ⊔ embed(r) = embed(r)`.
pub(crate) fn below_embedding(f: &Frag, r: &Frag) -> bool {
    let Some(mut e) = crate::embed::embed(r, f.enc()) else { return false };
    e.prune(None);
    let mut j = f.clone().join_raw(e.clone());
    j.prune(None);
    j == e
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
