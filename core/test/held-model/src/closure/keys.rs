//! Holder access (notes/holder-access-study.md, The direction): the holders a node holds for
//! keys (spec/sync-set.md §2 Held for keys). A grant is its target's data, so a node finds its
//! keys from the things it reads up: the holders their grants name, and those the grants of such
//! a holder name in turn, each one it opens and does not read. Properties in
//! tests/it/spec_holders.rs.
//!
//! Abstracted: a node opens a holder where its own things' roles read it (`Closure::keys`: in the
//! engine, where it holds a read secret a box gave); grants sit on independent things. Left out:
//! how a node first learns a thing's sync ID and box (an offer, or a holder's key part).
use super::{closure, Closure, Edges, NodeView, Role, Set, Walk, World, T};
use std::collections::BTreeMap;

/// The best role any of `own` holds on each thing over `w`'s grants.
pub fn roles_of(w: &World, own: &Set) -> BTreeMap<T, Role> {
    let mut out = BTreeMap::new();
    for &a in own {
        for (t, r) in w.roles_from(a) {
            let e = out.entry(t).or_insert(r);
            *e = (*e).max(r);
        }
    }
    out
}

/// Whether the node holds `h` for keys once named: no own thing, not read in the node closure,
/// and opened (its roles read it).
fn holdable(c: &Closure, n: &NodeView, h: T) -> bool {
    !n.own.contains(&h) && !c.read.contains(&h) && c.keys.contains(&h)
}

/// The holders held for keys: the walk up from each thing the node syncs (read or kept unread) through the
/// holders its grants name with key access (any role on a read thing; read or above on a holder
/// in turn, whose keys the hop opens), each one `holdable`.
pub fn for_keys(w: &World, e: &Edges, n: &NodeView) -> Set {
    let c = closure(w, e, n, Walk::Units);
    let mut out = Set::new();
    let mut todo: Vec<(T, bool)> = c.read.iter().chain(&c.stored).map(|&x| (x, true)).collect();
    while let Some((x, read)) = todo.pop() {
        for (&(h, t), &r) in &w.grants {
            let hop = !w.keyless.contains(&(h, t)) && (read || r >= Role::Read);
            if t == x && hop && holdable(&c, n, h) && out.insert(h) {
                todo.push((h, false));
            }
        }
    }
    out
}

/// The oracle, by paths: every holder on a path of grants from an own thing to a thing the node
/// syncs along which the node can act, other than an own thing or a thing read. Such a
/// path runs by hops with key access, each giving read or above (it opens the next thing's keys)
/// but the last, any role on the read thing, through no second own thing.
/// Enumerated as simple paths from each own thing, apart from `for_keys`'s walk.
pub fn on_paths(w: &World, e: &Edges, n: &NodeView) -> Set {
    let c = closure(w, e, n, Walk::Units);
    let mut out = Set::new();
    for &a in &n.own {
        extend(w, n, &c, &mut vec![a], &mut out);
    }
    out
}

fn extend(w: &World, n: &NodeView, c: &Closure, path: &mut Vec<T>, out: &mut Set) {
    let Some(&at) = path.last() else { return };
    for (&(h, t), &r) in &w.grants {
        if h != at || path.contains(&t) || w.keyless.contains(&(h, t)) {
            continue;
        }
        if c.read.contains(&t) || c.stored.contains(&t) {
            // a path ends at the first read thing it meets: its holders since the last own thing
            // or read thing are the ones acted through
            out.extend(path.iter().copied().filter(|x| !n.own.contains(x) && !c.read.contains(x)));
        }
        if r >= Role::Read && !n.own.contains(&t) {
            path.push(t);
            extend(w, n, c, path, out);
            path.pop();
        }
    }
}
