//! Death of a write (§4.8), the writes a state holds and covering (spec/commits.md §5), value-less writes (§4.7).
//! Each is stated over `writes::writes` (a fragment as the set of its writes) and join.
use crate::stamp::{Source, Stamp};
use crate::state::{drop_deleted_chars, Content, Frag};
use crate::writes::{writes, Name, Step};
use std::collections::BTreeSet;

/// A write's identity (§4.8): its position, kind and stamp; a map entry is its dot, whichever of the dot's records
/// (§5.6) holds the copy.
pub fn key(n: &Name) -> Name {
    n.iter().map(|s| if let Step::Record(d, _) = s { Step::Record(d.clone(), None) } else { s.clone() }).collect()
}

/// The stamp of a write by name.
pub fn stamp(n: &Name) -> &Stamp {
    match n.last() {
        Some(Step::Reset(s) | Step::W(s) | Step::Write(s) | Step::Case(s) | Step::Created(s) | Step::Pos(s) | Step::Flag(s)) => s,
        _ => panic!("a write's name ends with its stamp"),
    }
}

/// Every write of `f` by `key`.
pub fn keys(f: &Frag) -> BTreeSet<Name> {
    writes(f).iter().map(|(n, _)| key(n)).collect()
}

/// The winning writes of `f` (§4.8) by `key`: what it holds after pruning but a sequence element's position writes
/// other than `cur` (when that is not the creation's own) and a text element's creation (not an embedded char's)
/// while its winning flag is a delete. Of a map dot's records pruning keeps the writes of their join.
pub fn winning(f: &Frag) -> BTreeSet<Name> {
    fn only(f: &mut Frag) {
        match f {
            Frag::Register { .. } => {}
            Frag::Slots { reg, slots } => {
                reg.iter_mut().for_each(|r| only(r));
                slots.values_mut().for_each(only);
            }
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(only),
            Frag::Struct { fields, .. } | Frag::Enum { payloads: fields, .. } => fields.values_mut().for_each(only),
            Frag::Map { entries, .. } => entries.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(only),
            Frag::Seq { text, elems, .. } => {
                for (d, el) in elems.iter_mut() {
                    el.pos.truncate(1);
                    let deleted = matches!((&el.deleted, &el.created), (Some((s, true)), Some((c, _))) if s >= c);
                    if *text && deleted && !matches!(d.source, Source::Derived(_)) {
                        el.created = None;
                        el.pos.retain(|p| p.0.dot != *d);
                        if matches!(el.content, Content::Char(_)) {
                            el.content = Content::None;
                        }
                    }
                    if let Content::Frag(x) = &mut el.content {
                        only(x);
                    }
                }
            }
        }
    }
    let mut g = f.clone();
    g.prune(None);
    only(&mut g);
    keys(&g)
}

/// Whether write `s` supersedes write `w` (§4.8): `w` wins alone and not in `w ⊔ s`. Both are single writes
/// (`writes::writes`).
pub fn supersedes(s: &Frag, w: &Frag) -> bool {
    let Some(n) = winning(w).into_iter().next() else { return false };
    let mut j = w.clone();
    j.join(s.clone());
    !winning(&j).contains(&n)
}

/// Whether a state holds write `n` by dot (spec/commits.md §5 live write), given the state's `keys`: the write
/// itself, or for a sequence element's creation the element's record (also one holding only others' writes).
pub fn holds(state_keys: &BTreeSet<Name>, n: &Name) -> bool {
    let k = key(n);
    if state_keys.contains(&k) {
        return true;
    }
    match k.as_slice() {
        [.., Step::Elem(_), Step::Created(_)] => {
            let rec = &k[..k.len() - 1];
            state_keys.iter().any(|m| m.starts_with(rec))
        }
        _ => false,
    }
}

/// Canonical bytes of a fragment (§3.3): its wire encoding, deleted chars dropped.
pub fn canonical(f: &Frag) -> Vec<u8> {
    let mut g = f.clone();
    drop_deleted_chars(&mut g);
    crate::wire::encode_delta(&g, [0; 16], &mut crate::wire::Ctx::new(0, Source::session(0, 0), 1))
}

/// spec/commits.md §5 Covered: joining `body` into `snap` leaves `snap`'s canonical bytes unchanged.
pub fn covers(snap: &Frag, body: &Frag) -> bool {
    let mut a = snap.clone();
    a.prune(None);
    let mut j = a.clone();
    j.join(body.clone());
    canonical(&a) == canonical(&j)
}

/// Whether single write `w` carries a value (§4.7): stripping it changes it.
pub fn valued(w: &Frag) -> bool {
    let mut s = w.clone();
    s.strip(&|_| true);
    s != *w
}

/// The stamps of the value-carrying writes `f` holds value-less (§4.7): a register, case or `W` without its value,
/// a creation in a map dot's key-erased record, a list creation held value-less, a text undelete without its char,
/// and a text creation without its char unless its element is deleted in `f` or something in `f` anchors at it (a
/// deleted element's char is never on the wire, §3.3 rule 5, §4.5). Embedded chars are their register's.
pub fn valueless(f: &Frag) -> Vec<Stamp> {
    fn go(f: &Frag, out: &mut Vec<Stamp>) {
        if let Some(c) = f.composite() {
            if let (Some(w), true) = (&c.w, c.w_valueless) {
                out.push(w.clone());
            }
        }
        match f {
            Frag::Register { write: Some((s, None)), .. } => out.push(s.clone()),
            Frag::Register { .. } => {}
            Frag::Slots { reg, slots } => {
                reg.iter().for_each(|r| go(r, out));
                slots.values().for_each(|s| go(s, out));
            }
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => elems.values().filter_map(|e| e.frag.as_deref()).for_each(|x| go(x, out)),
            Frag::Struct { fields, .. } => fields.values().for_each(|x| go(x, out)),
            Frag::Enum { case, payloads, .. } => {
                if let Some((s, None)) = case {
                    out.push(s.clone());
                }
                payloads.values().for_each(|x| go(x, out));
            }
            Frag::Map { entries, .. } => {
                for ((_, k), en) in entries {
                    // a key-erased record's reset is a removal (§5.6), no value-less write
                    if k.is_none() {
                        out.extend(en.created.iter().cloned());
                    }
                    if let Some(x) = &en.frag {
                        go(x, out);
                    }
                }
            }
            Frag::Seq { text, elems, .. } => {
                let anchored: BTreeSet<_> = elems.values().flat_map(|e| e.pos.iter()).filter_map(|p| if let crate::state::Anchor::Dot(d) = &p.1 { Some(d.clone()) } else { None }).collect();
                for (d, el) in elems {
                    let derived = matches!(d.source, Source::Derived(_));
                    if let Some((c, _)) = &el.created {
                        let deleted = el.deleted.as_ref().is_some_and(|x| x.1);
                        if *text && !derived && !matches!(el.content, Content::Char(_)) && !deleted && !anchored.contains(d) {
                            out.push(c.clone());
                        }
                        if !*text && el.valueless {
                            out.push(c.clone());
                        }
                    }
                    if let (true, false, Some((s, false)), None) = (*text, derived, &el.deleted, el.undel) {
                        out.push(s.clone());
                    }
                    if let Content::Frag(x) = &el.content {
                        go(x, out);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    go(f, &mut out);
    out
}
