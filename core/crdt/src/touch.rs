//! The positions a fragment writes, as undo reads the state before a commit there (spec/crdt.md
//! §4.6; the engine's undo index). A position is a path from the aspect root through struct
//! fields and enum cases to the first collection element (a sequence, set or bag element by its
//! dot, a map record by its dot and, keyed, under its key too) or to a composite's own writes
//! (its reset, `W` or case write), a register or a `Slots` position: what lies below one is
//! that position's. Undo of a delta reads the state before it only at the delta's positions
//! and the presence of the composites above them (`undo::undo_at`).

use crate::fragment::{Fragment, Key};
use crate::stamp::Dot;

/// One step of a position's path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Seg {
    Field(u64),
    Case(u64),
    /// A map key: below it, `Dot` of each record carrying it.
    Key(Key),
    Dot(Dot),
}

/// A position: its path from the aspect root (empty: the root itself).
pub type Pos = Vec<Seg>;

/// Every position `f` writes (unsorted; duplicates possible). A map record keyed `k` of dot `d`
/// gives `[.., Dot(d)]` and `[.., Key(k), Dot(d)]`, so a key's positions name its records' dots.
pub fn touches(f: &Fragment) -> Vec<Pos> {
    let mut out = Vec::new();
    walk(f, &mut Vec::new(), &mut out);
    out
}

fn walk(f: &Fragment, at: &mut Pos, out: &mut Vec<Pos>) {
    if f.meta().is_some_and(|m| m.reset.is_some() || m.w.is_some()) {
        out.push(at.clone());
    }
    let under = |s: Seg, out: &mut Vec<Pos>| {
        let mut p = at.clone();
        p.push(s);
        out.push(p);
    };
    match f {
        Fragment::Register(_) | Fragment::Slots(_) => out.push(at.clone()),
        Fragment::Bag(x) => x.elems.keys().for_each(|d| under(Seg::Dot(d.clone()), out)),
        Fragment::Set(x) => x.elems.keys().for_each(|d| under(Seg::Dot(d.clone()), out)),
        Fragment::Map(m) => {
            for id in m.entries.keys() {
                under(Seg::Dot(id.dot.clone()), out);
                if let Some(k) = &id.key {
                    let mut p = at.clone();
                    p.extend([Seg::Key(k.clone()), Seg::Dot(id.dot.clone())]);
                    out.push(p);
                }
            }
        }
        Fragment::Seq(s) => {
            for (d, e) in s.elems() {
                (0..e.span).for_each(|i| under(Seg::Dot(crate::seq_span::nth(d, i)), out));
            }
        }
        Fragment::Struct(x) => {
            for (id, c) in &x.fields {
                at.push(Seg::Field(*id));
                walk(c, at, out);
                at.pop();
            }
        }
        Fragment::Enum(x) => {
            if x.case.is_some() {
                out.push(at.clone());
            }
            for (id, c) in &x.payloads {
                at.push(Seg::Case(*id));
                walk(c, at, out);
                at.pop();
            }
        }
    }
}

/// Whether `f` is present (§4.3) at `path`, a path of struct fields and enum cases: `false`
/// where nothing is there; `None` where a step meets another encoding (a `Slots` position, a
/// conflicting write), which only the whole state answers.
pub fn present_at(f: &Fragment, path: &[Seg]) -> Option<bool> {
    let mut f = f;
    for s in path {
        let next = match (f, s) {
            (Fragment::Struct(x), Seg::Field(id)) => x.fields.get(id),
            (Fragment::Enum(x), Seg::Case(id)) => x.payloads.get(id),
            _ if f.is_empty() => return Some(false),
            _ => return None,
        };
        let Some(n) = next else { return Some(false) };
        f = n;
    }
    Some(f.present())
}
