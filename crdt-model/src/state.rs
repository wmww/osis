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
    /// Presence stamp (§4.3): greatest stamp of any write inside, plus explicit W writes.
    pub written: Option<Stamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Elem {
    pub reset: Option<Stamp>,
    pub frag: Option<Box<Frag>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub reset: Option<Stamp>,
    pub key: Value,
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
    Register { reset: Option<Stamp>, write: Option<(Stamp, Value)> },
    Bag { kind: BagKind, c: Composite, elems: BTreeMap<Dot, Elem> },
    Struct { c: Composite, fields: BTreeMap<u64, Frag> },
    Enum { c: Composite, case: Option<(Stamp, u64)>, payloads: BTreeMap<u64, Frag> },
    Set { c: Composite, elems: BTreeMap<Dot, Elem> },
    Map { c: Composite, entries: BTreeMap<Dot, Entry> },
    Seq { text: bool, c: Composite, elems: BTreeMap<Dot, SeqElem> },
}

pub fn max_pair<T>(a: Option<(Stamp, T)>, b: Option<(Stamp, T)>) -> Option<(Stamp, T)> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(if a.0 >= b.0 { a } else { b }),
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

    pub fn reset(&self) -> Option<&Stamp> {
        match self {
            Frag::Register { reset, .. } => reset.as_ref(),
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => c.reset.as_ref(),
        }
    }
    pub fn set_reset(&mut self, r: Option<Stamp>) {
        match self {
            Frag::Register { reset, .. } => *reset = r,
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => c.reset = r,
        }
    }
    pub fn composite(&self) -> Option<&Composite> {
        match self {
            Frag::Register { .. } => None,
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => Some(c),
        }
    }
    pub fn composite_mut(&mut self) -> Option<&mut Composite> {
        match self {
            Frag::Register { .. } => None,
            Frag::Bag { c, .. } | Frag::Struct { c, .. } | Frag::Enum { c, .. } | Frag::Set { c, .. } | Frag::Map { c, .. } | Frag::Seq { c, .. } => Some(c),
        }
    }

    /// Presence stamp: register write stamp, or the composite's `written`.
    pub fn written(&self) -> Option<Stamp> {
        match self {
            Frag::Register { write, .. } => write.as_ref().map(|w| w.0.clone()),
            f => f.composite().unwrap().written.clone(),
        }
    }

    /// Greatest stamp carried inside (writes of children, elements, case, pos, flags), excluding own reset and
    /// excluding explicit presence writes. Used for canonical `W` encoding (§3.3 rule 4).
    pub fn inner_max(&self) -> Option<Stamp> {
        fn elems_max(elems: &BTreeMap<Dot, Elem>) -> Option<Stamp> {
            elems.values().fold(None, |m, e| max_opt(max_opt(m, e.reset.clone()), e.frag.as_ref().and_then(|f| f.all_max())))
        }
        match self {
            Frag::Register { write, .. } => write.as_ref().map(|w| w.0.clone()),
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems_max(elems),
            Frag::Struct { fields, .. } => fields.values().fold(None, |m, f| max_opt(m, f.all_max())),
            Frag::Enum { case, payloads, .. } => payloads.values().fold(case.as_ref().map(|c| c.0.clone()), |m, f| max_opt(m, f.all_max())),
            Frag::Map { entries, .. } => entries.values().fold(None, |m, e| max_opt(max_opt(m, e.reset.clone()), e.frag.as_ref().and_then(|f| f.all_max()))),
            Frag::Seq { elems, .. } => elems.values().fold(None, |m, e| {
                let m = max_opt(m, e.created.as_ref().map(|c| c.0.clone()));
                let m = e.pos.iter().fold(m, |m, p| max_opt(m, Some(p.0.clone())));
                let m = max_opt(m, e.deleted.as_ref().map(|d| d.0.clone()));
                match &e.content {
                    Content::Frag(f) => max_opt(m, f.all_max()),
                    _ => m,
                }
            }),
        }
    }

    /// Greatest stamp of anything in this fragment including its own reset and presence (§7 rule 2).
    pub fn all_max(&self) -> Option<Stamp> {
        max_opt(max_opt(self.inner_max(), self.reset().cloned()), self.written())
    }

    /// Recompute `written` bottom-up as max(explicit, inner). Used after constructing deltas and after decoding.
    pub fn fix_written(&mut self) {
        match self {
            Frag::Register { .. } => {}
            Frag::Struct { fields, .. } => fields.values_mut().for_each(|f| f.fix_written()),
            Frag::Enum { payloads, .. } => payloads.values_mut().for_each(|f| f.fix_written()),
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.values_mut().for_each(|e| {
                if let Some(f) = &mut e.frag {
                    f.fix_written()
                }
            }),
            Frag::Map { entries, .. } => entries.values_mut().for_each(|e| {
                if let Some(f) = &mut e.frag {
                    f.fix_written()
                }
            }),
            Frag::Seq { elems, .. } => elems.values_mut().for_each(|e| {
                if let Content::Frag(f) = &mut e.content {
                    f.fix_written()
                }
            }),
        }
        let inner = self.inner_max();
        if let Some(c) = self.composite_mut() {
            c.written = max_opt(c.written.clone(), inner);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.reset().is_none() && self.written().is_none() && self.inner_max().is_none() && match self {
            Frag::Seq { elems, .. } => elems.is_empty(),
            _ => true,
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
            Composite { reset: max_opt(a.reset, b.reset), written: max_opt(a.written, b.written) }
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
            (Frag::Register { reset: ra, write: wa }, Frag::Register { reset: rb, write: wb }) => Frag::Register { reset: max_opt(ra, rb), write: max_pair(wa, wb) },
            (Frag::Bag { kind, c: ca, elems: ea }, Frag::Bag { c: cb, elems: eb, .. }) => Frag::Bag { kind, c: jc(ca, cb), elems: jelems(ea, eb) },
            (Frag::Set { c: ca, elems: ea }, Frag::Set { c: cb, elems: eb }) => Frag::Set { c: jc(ca, cb), elems: jelems(ea, eb) },
            (Frag::Struct { c: ca, fields: fa }, Frag::Struct { c: cb, fields: fb }) => Frag::Struct { c: jc(ca, cb), fields: jfrags(fa, fb) },
            (Frag::Enum { c: ca, case: ka, payloads: pa }, Frag::Enum { c: cb, case: kb, payloads: pb }) => Frag::Enum { c: jc(ca, cb), case: max_pair(ka, kb), payloads: jfrags(pa, pb) },
            (Frag::Map { c: ca, entries: mut ea }, Frag::Map { c: cb, entries: eb }) => {
                for (d, nb) in eb {
                    match ea.remove(&d) {
                        None => {
                            ea.insert(d, nb);
                        }
                        Some(na) => {
                            // Keys of one dot are equal by construction; keep whichever is present.
                            ea.insert(d, Entry { reset: max_opt(na.reset, nb.reset), key: na.key, frag: jopt(na.frag, nb.frag) });
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
        let own = self.reset().cloned();
        let e = max_opt(e_parent.cloned(), own);
        let e = e.as_ref();
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
            Frag::Register { write, .. } => {
                if let Some(w) = write {
                    if !survives(&w.0, e) {
                        *write = None;
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
                    en.reset.is_some() || en.frag.is_some()
                });
            }
            Frag::Seq { c, elems, .. } => {
                prune_written(c, e);
                elems.retain(|_, el| {
                    el.pos.retain(|p| survives(&p.0, e));
                    if el.created.as_ref().map_or(false, |c| !survives(&c.0, e)) {
                        el.created = None;
                    }
                    if let Some(d) = &el.deleted {
                        if !survives(&d.0, e) {
                            el.deleted = None;
                        }
                    }
                    let mut keep_content = true;
                    if let Content::Frag(f) = &mut el.content {
                        f.prune(e);
                        keep_content = !f.is_empty();
                    }
                    if !keep_content {
                        el.content = Content::None;
                    }
                    // Text content has no stamp of its own: it lives and dies with the creation write (§4.2).
                    if el.created.is_none() && matches!(el.content, Content::Char(_)) {
                        el.content = Content::None;
                    }
                    // A record survives while any creation, position or flag write survives.
                    el.created.is_some() || !el.pos.is_empty() || el.deleted.is_some() || matches!(el.content, Content::Frag(_))
                });
            }
        }
    }

    // --------------------------------------------------------------- read

    pub fn present(&self) -> bool {
        match self {
            Frag::Register { write, .. } => write.is_some(),
            f => f.composite().unwrap().written.is_some(),
        }
    }

    /// Read (§4.4, §5). `None` = absent.
    pub fn read(&self) -> Option<Value> {
        if !self.present() {
            return None;
        }
        Some(match self {
            Frag::Register { write, .. } => write.as_ref().unwrap().1.clone(),
            Frag::Bag { kind, elems, .. } => {
                let vals: Vec<Value> = elems.values().filter_map(|e| e.frag.as_ref().and_then(|f| f.read())).collect();
                match kind {
                    BagKind::Counter => {
                        let mut si: i64 = 0;
                        let mut sf: f64 = 0.0;
                        let mut is_f = false;
                        for v in &vals {
                            match v {
                                Value::Int(i) => si = si.saturating_add(*i),
                                Value::Float(b) => {
                                    is_f = true;
                                    sf += f64::from_bits(*b)
                                }
                                _ => {}
                            }
                        }
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
                let (_, id) = case.as_ref()?;
                Value::Enum(*id, payloads.get(id).and_then(|f| f.read()).map(Box::new))
            }
            Frag::Set { elems, .. } => Value::set(elems.values().filter_map(|e| e.frag.as_ref().and_then(|f| f.read())).collect()),
            Frag::Map { entries, .. } => {
                let mut by_key: BTreeMap<Value, Frag> = BTreeMap::new();
                for en in entries.values() {
                    if let Some(f) = &en.frag {
                        if f.present() {
                            match by_key.remove(&en.key) {
                                None => {
                                    by_key.insert(en.key.clone(), (**f).clone());
                                }
                                Some(g) => {
                                    let mut j = join_any(g, (**f).clone());
                                    j.prune(None);
                                    by_key.insert(en.key.clone(), j);
                                }
                            }
                        }
                    }
                }
                Value::map(by_key.into_iter().filter_map(|(k, f)| f.read().map(|v| (k, v))).collect())
            }
            Frag::Seq { text, elems, .. } => {
                let order = linearize(elems);
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
            c.written = None; // recomputed below
        }
        match self {
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
                elems.retain(|_, el| el.created.is_some() || !el.pos.is_empty() || el.deleted.is_some() || matches!(el.content, Content::Frag(_)));
            }
        }
        self.fix_written();
    }
}

fn prune_written(c: &mut Composite, e: Option<&Stamp>) {
    if let Some(w) = &c.written {
        if !survives(w, e) {
            c.written = None;
        }
    }
}

pub fn num_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let f = |v: &Value| match v {
        Value::Int(i) => *i as f64,
        Value::Float(b) => f64::from_bits(*b),
        _ => f64::NAN,
    };
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        _ => f(a).partial_cmp(&f(b)).unwrap_or(std::cmp::Ordering::Equal),
    }
}

/// Join of two fragments of possibly different encodings (§7), unpruned.
pub fn join_any(a: Frag, b: Frag) -> Frag {
    if a.enc() == b.enc() {
        return a.join_raw(b);
    }
    if let Some(ea) = crate::embed::embed(&a, b.enc()) {
        return ea.join_raw(b);
    }
    if let Some(eb) = crate::embed::embed(&b, a.enc()) {
        return a.join_raw(eb);
    }
    // No edge: the side with the greater stamp is kept, the other becomes a reset at its greatest stamp.
    let (wa, wb) = (a.all_max(), b.all_max());
    let (mut keep, loser) = if wa >= wb { (a, wb) } else { (b, wa) };
    let r = max_opt(keep.reset().cloned(), loser);
    keep.set_reset(r);
    keep
}
