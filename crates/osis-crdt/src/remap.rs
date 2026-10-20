//! Re-sourcing for imports (spec/permissions.md §7): every dot of a fragment (write stamps,
//! element identities, anchors, resets) mapped by a function; `ts` is kept. `Derived` dots map
//! through their underlying dot.

use crate::fragment::{Bag, Elem, Entry, Enum, Fragment, Meta, Register, Set, Slots, Struct};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Source, SourceKind, Stamp};
use std::collections::BTreeMap;

type DotFn<'a> = &'a dyn Fn(&Dot) -> Option<Dot>;

fn dot(d: &Dot, f: DotFn<'_>) -> Dot {
    match d.src.kind() {
        SourceKind::Derived(inner) => match Source::derived(dot(inner, f)) {
            Some(s) => Dot::new(s, d.ctr),
            None => d.clone(),
        },
        _ => f(d).unwrap_or_else(|| d.clone()),
    }
}

fn stamp(s: &mut Stamp, f: DotFn<'_>) {
    s.dot = dot(&s.dot, f);
}

fn opt(s: &mut Option<Stamp>, f: DotFn<'_>) {
    if let Some(s) = s {
        stamp(s, f);
    }
}

fn meta(m: &mut Meta, f: DotFn<'_>) {
    opt(&mut m.reset, f);
    opt(&mut m.w, f);
}

fn register(r: &mut Register, f: DotFn<'_>) {
    opt(&mut r.reset, f);
    if let Some(w) = &mut r.write {
        stamp(&mut w.stamp, f);
    }
}

fn elems(m: &mut BTreeMap<Dot, Elem>, f: DotFn<'_>) {
    *m = std::mem::take(m)
        .into_iter()
        .map(|(d, mut e)| {
            opt(&mut e.reset, f);
            if let Some(x) = &mut e.frag {
                x.map_dots(f);
            }
            (dot(&d, f), e)
        })
        .collect();
}

fn anchor(a: &mut Anchor, f: DotFn<'_>) {
    if let Anchor::Dot(d) = a {
        *d = dot(d, f);
    }
}

fn seq(s: &mut Seq, f: DotFn<'_>) {
    meta(&mut s.meta, f);
    s.elems = std::mem::take(&mut s.elems)
        .into_iter()
        .map(|(d, mut e): (Dot, SeqElem)| {
            if let Some((st, a)) = &mut e.created {
                stamp(st, f);
                anchor(a, f);
            }
            for (st, a) in &mut e.pos {
                stamp(st, f);
                anchor(a, f);
            }
            if let Some((st, _)) = &mut e.deleted {
                stamp(st, f);
            }
            if let SeqContent::Frag(x) = &mut e.content {
                x.map_dots(f);
            }
            (dot(&d, f), e)
        })
        .collect();
}

impl Fragment {
    /// Maps every dot (`f` sees non-`Derived` dots; `None` keeps the dot).
    pub fn map_dots(&mut self, f: &dyn Fn(&Dot) -> Option<Dot>) {
        match self {
            Fragment::Register(r) => register(r, f),
            Fragment::Bag(Bag { meta: m, elems: e, .. }) | Fragment::Set(Set { meta: m, elems: e }) => {
                meta(m, f);
                elems(e, f);
            }
            Fragment::Struct(Struct { meta: m, fields }) => {
                meta(m, f);
                for x in fields.values_mut() {
                    x.map_dots(f);
                }
            }
            Fragment::Enum(Enum { meta: m, case, payloads }) => {
                meta(m, f);
                if let Some(c) = case {
                    stamp(&mut c.stamp, f);
                }
                for x in payloads.values_mut() {
                    x.map_dots(f);
                }
            }
            Fragment::Map(mp) => {
                meta(&mut mp.meta, f);
                mp.entries = std::mem::take(&mut mp.entries)
                    .into_iter()
                    .map(|(d, mut e): (Dot, Entry)| {
                        opt(&mut e.reset, f);
                        if let Some(x) = &mut e.frag {
                            x.map_dots(f);
                        }
                        (dot(&d, f), e)
                    })
                    .collect();
                mp.reindex();
            }
            Fragment::Seq(s) => seq(s, f),
            Fragment::Slots(Slots { reg, members }) => {
                if let Some(r) = reg {
                    register(r, f);
                }
                for x in members.values_mut() {
                    x.map_dots(f);
                }
            }
        }
    }
}
