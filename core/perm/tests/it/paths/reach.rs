//! The walk by reach reads exactly as the whole walk (`Paths::whole`: every part of a component
//! after an update's earliest change walked again): a part is walked again only where something its
//! step reads changed (notes/perm-paths.md, Reach). Compared update by update (each `Changed` and
//! the work, never more than the whole walk's) on every differential world kind and on part
//! soups, from scratch, on arrival in a shuffled order, on forgetting half one commit at a time and
//! on trust switched on and off, with the dispute set at the end.
//! spec/permissions.md §5.1, §5.2 (draft: notes/a1-spec/permissions.md §5.1, §5.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::single::{differs, run};
use crate::common::{seeded, sharded};
use osis_base::Tid;
use osis_perm::paths::{Changed, Commit, Paths};
use osis_perm::WriteId;
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};

/// One update applied to both walks: where their `Changed` differ, what.
fn both(d: &mut Paths, w: &mut Paths, what: &str, f: &dyn Fn(&mut Paths) -> Changed) -> Option<String> {
    let (a, b) = (f(d), f(w));
    (a != b).then(|| format!("{what}: Changed {a:?} / {b:?}"))
}

/// `commits` read by the walk by reach and the whole walk: from scratch, arriving one at a time
/// in a shuffled order, half forgotten one at a time, an edge write trusted and put aside again;
/// the first difference, or the walk by reach doing more steps than the whole walk.
pub(super) fn alike(records: &BTreeMap<Tid, Tid>, trust: &BTreeSet<WriteId>, commits: &[Commit], seed: u64, disputes: bool) -> Option<String> {
    let mut d = Paths::new(records, trust.clone());
    let mut w = Paths::whole(records, trust.clone());
    if let Some(x) = both(&mut d, &mut w, "from scratch", &|p| p.add(commits)) {
        return Some(x);
    }
    if let Some(x) = differs(&mut d, &mut w, false) {
        return Some(format!("from scratch: {x}"));
    }
    let mut rng = Rng(seed);
    let order = rng.perm(commits.len());
    let mut d = Paths::new(records, trust.clone());
    let mut w = Paths::whole(records, trust.clone());
    for &k in &order {
        if let Some(x) = both(&mut d, &mut w, &format!("arrival {order:?} at {k}"), &|p| p.add(std::slice::from_ref(&commits[k]))) {
            return Some(x);
        }
    }
    if let Some(x) = differs(&mut d, &mut w, false) {
        return Some(format!("arrival {order:?}: {x}"));
    }
    for &k in order.iter().filter(|&&k| k % 2 == seed as usize % 2) {
        if let Some(x) = both(&mut d, &mut w, &format!("forgetting {k} after arrival {order:?}"), &|p| p.forget(&[commits[k].id])) {
            return Some(x);
        }
    }
    if let Some(x) = differs(&mut d, &mut w, false) {
        return Some(format!("forgetting half after arrival {order:?}: {x}"));
    }
    // an edge write held now trusted, then the trust set as it was
    if let Some(id) = d.statuses().into_keys().nth(rng.below(4)) {
        let mut more = trust.clone();
        more.insert(id);
        if let Some(x) = both(&mut d, &mut w, &format!("trusting {id:?}"), &|p| p.set_trust(more.clone())) {
            return Some(x);
        }
        if let Some(x) = both(&mut d, &mut w, &format!("untrusting {id:?}"), &|p| p.set_trust(trust.clone())) {
            return Some(x);
        }
    }
    if let Some(x) = differs(&mut d, &mut w, disputes) {
        return Some(format!("at the end: {x}"));
    }
    (d.counts().steps > w.counts().steps).then(|| format!("{} steps by reach, {} whole", d.counts().steps, w.counts().steps))
}

// notes/perm-paths.md, Reach: a part's step reads only the edges it touches, its path's last edge
// and its own verdict and drop, so walking again only the parts whose reads changed reads every
// world as the whole walk does, update by update.
#[test]
#[ignore = "property"]
fn paths_reach_agree_plain() {
    let f = run(0, 60, alike);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// As above, more worlds (a property).
#[test]
#[ignore]
fn paths_reach_agree_large() {
    let f: Vec<String> = sharded(100_000, 0x5eed_4eac, |n, seed| run(seeded(seed) % (1 << 40), n.div_ceil(9), alike)).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}
