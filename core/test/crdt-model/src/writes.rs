//! A fragment as the set of its writes (spec §4.1, §4.8): each write alone, as a fragment holding it and nothing else,
//! named by its place and stamp. Copies of one write share a name; joining every write of a fragment gives it back.
use crate::stamp::{Dot, Stamp};
use crate::state::{join_any, Composite, Content, Elem, Entry, Frag, SeqElem};
use crate::value::Value;
use std::collections::BTreeMap;

/// One step of a write's name: where it sits, then what it is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// The slot of this encoding at the position (§7).
    Enc(u8),
    Field(u64),
    Elem(Dot),
    Record(Dot, Option<Value>),
    Reset(Stamp),
    W(Stamp),
    Write(Stamp),
    Case(Stamp),
    Created(Stamp),
    Pos(Stamp),
    Flag(Stamp),
}

/// A write's name: copies of one write have the same.
pub type Name = Vec<Step>;

/// Every write of `f`, each alone in a fragment of its own. A `Slots` position leaves out what its register's
/// embedding writes into a slot (§7): those are the register write's, not the slot's.
pub fn writes(f: &Frag) -> Vec<(Name, Frag)> {
    match f {
        Frag::Slots { reg, slots } => {
            let mut out: Vec<(Name, Frag)> = reg.as_deref().map(writes).unwrap_or_default();
            for (k, s) in slots {
                let embedded = reg.as_deref().and_then(|r| crate::embed::embed(r, *k)).map(|mut e| {
                    e.prune(None);
                    writes(&e)
                });
                out.extend(writes(s).into_iter().filter(|w| !embedded.as_ref().is_some_and(|e| e.contains(w))));
            }
            out
        }
        f => {
            let enc = f.enc();
            let mut out = Vec::new();
            let mut put = |name: Vec<Step>, w: Frag| {
                let mut n = vec![Step::Enc(enc)];
                n.extend(name);
                out.push((n, w));
            };
            let bare = || Frag::empty(enc);
            if let Some(c) = f.composite() {
                if let Some(r) = &c.reset {
                    let mut w = bare();
                    w.composite_mut().unwrap().reset = Some(r.clone());
                    put(vec![Step::Reset(r.clone())], w);
                }
                if let Some(s) = &c.w {
                    let mut w = bare();
                    *w.composite_mut().unwrap() = Composite { reset: None, w: Some(s.clone()), w_valueless: c.w_valueless };
                    put(vec![Step::W(s.clone())], w);
                }
            }
            match f {
                Frag::Register { reset, write } => {
                    if let Some(r) = reset {
                        put(vec![Step::Reset(r.clone())], Frag::Register { reset: Some(r.clone()), write: None });
                    }
                    if let Some(x) = write {
                        put(vec![Step::Write(x.0.clone())], Frag::Register { reset: None, write: Some(x.clone()) });
                    }
                }
                Frag::Bag { elems, .. } | Frag::Set { elems, .. } => {
                    for (d, el) in elems {
                        let one = |el: Elem| {
                            let mut w = bare();
                            if let Frag::Bag { elems, .. } | Frag::Set { elems, .. } = &mut w {
                                elems.insert(d.clone(), el);
                            }
                            w
                        };
                        if let Some(r) = &el.reset {
                            put(vec![Step::Elem(d.clone()), Step::Reset(r.clone())], one(Elem { reset: Some(r.clone()), frag: None }));
                        }
                        for (n, x) in el.frag.as_deref().map(writes).unwrap_or_default() {
                            put(prefixed(Step::Elem(d.clone()), n), one(Elem { reset: None, frag: Some(Box::new(x)) }));
                        }
                    }
                }
                Frag::Struct { fields, .. } | Frag::Enum { payloads: fields, .. } => {
                    for (k, x) in fields {
                        for (n, x) in writes(x) {
                            let mut w = bare();
                            if let Frag::Struct { fields, .. } | Frag::Enum { payloads: fields, .. } = &mut w {
                                fields.insert(*k, x);
                            }
                            put(prefixed(Step::Field(*k), n), w);
                        }
                    }
                    if let Frag::Enum { case: Some(k), .. } = f {
                        let mut w = bare();
                        if let Frag::Enum { case, .. } = &mut w {
                            *case = Some(k.clone());
                        }
                        put(vec![Step::Case(k.0.clone())], w);
                    }
                }
                Frag::Map { entries, .. } => {
                    for (id, en) in entries {
                        let one = |en: Entry| {
                            let mut w = bare();
                            if let Frag::Map { entries, .. } = &mut w {
                                entries.insert(id.clone(), en);
                            }
                            w
                        };
                        let at = Step::Record(id.0.clone(), id.1.clone());
                        if let Some(r) = &en.reset {
                            put(vec![at.clone(), Step::Reset(r.clone())], one(Entry { reset: Some(r.clone()), frag: None, created: None }));
                        }
                        if let Some(c) = &en.created {
                            put(vec![at.clone(), Step::Created(c.clone())], one(Entry { reset: None, frag: None, created: Some(c.clone()) }));
                        }
                        for (n, x) in en.frag.as_deref().map(writes).unwrap_or_default() {
                            put(prefixed(at.clone(), n), one(Entry { reset: None, frag: Some(Box::new(x)), created: None }));
                        }
                    }
                }
                Frag::Seq { elems, .. } => {
                    for (d, el) in elems {
                        let one = |el: SeqElem| {
                            let mut w = bare();
                            if let Frag::Seq { elems, .. } = &mut w {
                                elems.insert(d.clone(), el);
                            }
                            w
                        };
                        let at = Step::Elem(d.clone());
                        let none = SeqElem::write(Content::None, vec![], None);
                        // a text char is its creation's payload, and its position write is the creation's own (§5.7)
                        let own = |p: &crate::state::Pos| el.created.as_ref().is_some_and(|c| p.0 == c.0 && p.1 == c.1 && p.2.is_none());
                        if let Some(c) = &el.created {
                            let content = if let Content::Char(x) = el.content { Content::Char(x) } else { Content::None };
                            let pos = el.pos.iter().filter(|p| own(p)).cloned().collect();
                            put(vec![at.clone(), Step::Created(c.0.clone())], one(SeqElem { created: Some(c.clone()), content, pos, valueless: el.valueless, ..none.clone() }));
                        }
                        for p in el.pos.iter().filter(|p| !own(p)) {
                            put(vec![at.clone(), Step::Pos(p.0.clone())], one(SeqElem { pos: vec![p.clone()], ..none.clone() }));
                        }
                        if let Some(x) = &el.deleted {
                            put(vec![at.clone(), Step::Flag(x.0.clone())], one(SeqElem { deleted: Some(x.clone()), undel: el.undel, ..none.clone() }));
                        }
                        if let Content::Frag(x) = &el.content {
                            for (n, x) in writes(x) {
                                put(prefixed(at.clone(), n), one(SeqElem { content: Content::Frag(Box::new(x)), ..none.clone() }));
                            }
                        }
                    }
                }
                Frag::Slots { .. } => unreachable!(),
            }
            out
        }
    }
}

fn prefixed(s: Step, n: Name) -> Name {
    let mut out = vec![s];
    out.extend(n);
    out
}

/// The join of `ws`, unpruned; `None` for no write.
pub fn join_all(ws: impl IntoIterator<Item = Frag>) -> Option<Frag> {
    ws.into_iter().reduce(join_any)
}

/// The writes of `f` by name: one per name (a fragment holds one copy of each write).
pub fn by_name(f: &Frag) -> BTreeMap<Name, Frag> {
    writes(f).into_iter().collect()
}
