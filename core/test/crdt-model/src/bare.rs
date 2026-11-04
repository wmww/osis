//! §5.6 Bare anchors: a keyed record holds only its writes and the records on their paths; every record of the
//! dot holding no write at or below it is held by the dot's key-erased record, which drops one a keyed record holds.

use crate::state::{Content, Entry, Frag, SeqElem, assemble, parts};
use std::collections::BTreeMap;

fn own(e: &SeqElem) -> bool {
    e.created.is_some() || !e.pos.is_empty() || e.deleted.is_some()
}

/// `f` split into what holds a write (with the records on its paths) and the records holding none (with theirs).
pub fn split(f: Frag) -> (Frag, Frag) {
    let enc = f.enc();
    let mut bare = Frag::empty(if enc == 10 { 0 } else { enc });
    let mut f = f;
    match &mut f {
        Frag::Register { .. } | Frag::Bag { .. } | Frag::Set { .. } => {}
        Frag::Struct { fields: m, .. } | Frag::Enum { payloads: m, .. } => {
            let mut out = BTreeMap::new();
            for (k, x) in std::mem::take(m) {
                let (a, b) = split(x);
                if !a.is_empty() {
                    m.insert(k, a);
                }
                if !b.is_empty() {
                    out.insert(k, b);
                }
            }
            match &mut bare {
                Frag::Struct { fields, .. } => *fields = out,
                Frag::Enum { payloads, .. } => *payloads = out,
                _ => unreachable!(),
            }
        }
        Frag::Map { entries, .. } => {
            let mut out = BTreeMap::new();
            for (id, mut en) in std::mem::take(entries) {
                if let Some(x) = en.frag.take() {
                    let (a, b) = split(*x);
                    en.frag = (!a.is_empty()).then(|| Box::new(a));
                    if !b.is_empty() {
                        out.insert(id.clone(), Entry { reset: None, frag: Some(Box::new(b)), created: None });
                    }
                }
                if en.reset.is_some() || en.frag.is_some() || en.created.is_some() {
                    entries.insert(id, en);
                }
            }
            if let Frag::Map { entries, .. } = &mut bare {
                *entries = out;
            }
        }
        Frag::Seq { elems, .. } => {
            let mut out = BTreeMap::new();
            for (d, mut el) in std::mem::take(elems) {
                if matches!(el.content, Content::Frag(_)) {
                    let Content::Frag(x) = std::mem::replace(&mut el.content, Content::None) else { unreachable!() };
                    let (a, b) = split(*x);
                    if !a.is_empty() {
                        el.content = Content::Frag(Box::new(a));
                    }
                    if !b.is_empty() {
                        out.insert(d.clone(), SeqElem { content: Content::Frag(Box::new(b)), ..SeqElem::write(Content::None, vec![], None) });
                    }
                } else if !own(&el) {
                    out.insert(d, el);
                    continue;
                }
                if own(&el) || !matches!(el.content, Content::None) {
                    elems.insert(d, el);
                }
            }
            if let Frag::Seq { elems, .. } = &mut bare {
                *elems = out;
            }
        }
        Frag::Slots { .. } => {
            let (reg, slots) = parts(f);
            let (mut keep, mut out) = (BTreeMap::new(), BTreeMap::new());
            for (k, x) in slots {
                let (a, b) = split(x);
                keep.insert(k, a);
                out.insert(k, b);
            }
            return (assemble(reg, keep), assemble(None, out));
        }
    }
    (f, bare)
}

/// `f` without the records holding no write at or below them that `by` holds.
pub fn drop_held(f: Frag, by: &Frag) -> Frag {
    if let Frag::Slots { .. } = f {
        let (reg, slots) = parts(f);
        let slots = slots.into_iter().map(|(k, x)| (k, if let Some(g) = by.slot(k) { drop_held(x, g) } else { x })).collect();
        return assemble(reg, slots);
    }
    let Some(by) = by.slot(f.enc()) else { return f };
    let mut f = f;
    match (&mut f, by) {
        (Frag::Struct { fields: m, .. }, Frag::Struct { fields: b, .. }) | (Frag::Enum { payloads: m, .. }, Frag::Enum { payloads: b, .. }) => {
            *m = std::mem::take(m).into_iter().map(|(k, x)| (k, if let Some(g) = b.get(&k) { drop_held(x, g) } else { x })).filter(|(_, x)| !x.is_empty()).collect();
        }
        (Frag::Map { entries, .. }, Frag::Map { entries: b, .. }) => {
            for (id, mut en) in std::mem::take(entries) {
                // the records of one dot are one entry: any of them holding a record holds it
                for g in b.iter().filter(|((d, _), _)| *d == id.0).filter_map(|(_, e)| e.frag.as_deref()) {
                    if let Some(x) = en.frag.take() {
                        let x = drop_held(*x, g);
                        en.frag = (!x.is_empty()).then(|| Box::new(x));
                    }
                }
                entries.insert(id, en);
            }
            entries.retain(|_, en| en.reset.is_some() || en.frag.is_some() || en.created.is_some());
        }
        (Frag::Seq { elems, .. }, Frag::Seq { elems: b, .. }) => {
            for (d, el) in std::mem::take(elems) {
                let mut el = el;
                if let Some(g) = b.get(&d).filter(|_| !own(&el)) {
                    if let Content::Frag(x) = std::mem::replace(&mut el.content, Content::None) {
                        let x = match &g.content {
                            Content::Frag(g) => drop_held(*x, g),
                            _ => *x,
                        };
                        if !x.is_empty() {
                            el.content = Content::Frag(Box::new(x));
                        }
                    }
                    if matches!(el.content, Content::None) {
                        continue;
                    }
                }
                elems.insert(d, el);
            }
        }
        _ => {}
    }
    f
}
