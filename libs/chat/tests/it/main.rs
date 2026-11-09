//! End to end on the sim (notes/chat.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod flows;
mod thin;

use osis::{HolderKind, Osis, Result, Role, Tid};
use std::collections::BTreeMap;

/// The holders a share view shows: direct actors (accounts, teams), and link joiners at the link's
/// role. `HolderKind` tells them apart (spec/permissions.md §7).
pub fn participants(db: &Osis, c: Tid) -> Result<BTreeMap<Tid, Role>> {
    let ways = db.holders(c)?;
    let is_link = |k: &Tid| ways.iter().any(|h| h.actor == *k && h.kind == HolderKind::Link && h.through.is_empty());
    let mut out = BTreeMap::new();
    for h in ways.iter().filter(|h| h.kind == HolderKind::Actor && (h.through.is_empty() || matches!(h.through.as_slice(), [k] if is_link(k)))) {
        let r = out.entry(h.actor).or_insert(h.role);
        *r = h.role.max(*r);
    }
    Ok(out)
}

/// The links on `c` that work: a link's key still holds its actor.
pub fn link_actors(db: &Osis, c: Tid) -> Result<BTreeMap<Tid, Role>> {
    let ways = db.holders(c)?;
    Ok(ways.iter().filter(|h| h.kind == HolderKind::Link && h.through.is_empty() && ways.iter().any(|x| x.kind == HolderKind::Key && x.through == [h.actor])).map(|h| (h.actor, h.role)).collect())
}

/// This account leaves `c`.
pub fn leave(db: &Osis, c: Tid) -> Result<()> {
    db.leave(db.me(), c)
}
