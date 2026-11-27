//! The local part's log (spec/sync-set.md §2 The local part's log): the local part is a unit like
//! any other, and what it carries of things outside it is what this node logged there. The node
//! logs thing X when an edge of the local part carries a vertex of X (a dependent it opens there
//! too, so one made independent stays logged), judged while it
//! held X's role entries by another route (`founded_otherwise`); the row stays while some edge of
//! the local part still carries X, whatever became of that route, and goes with the last. The
//! local part's carriage reads the grants on a thing only where it is an own thing, logged, or
//! founded otherwise (`counts`): grants held as evidence, or handed over with no route, carry
//! nothing there.
//!
//! Who writes each input: the rows are this node's own, written from its closure; a peer moves
//! them only by what it may already move (the strongs and grants the walk reads).

use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::Tid;
use osis_store::Shred;

/// `ll/` + thing: the local part carries thing X (`Indexes::local_log`).
pub(crate) const LOCAL_LOG: &[u8] = b"ll/";

/// Loads the local part's log (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let rows = tx.scan_keys(LOCAL_LOG, "local log row", Tid::from_bytes)?;
    tx.core.ix.local_log.extend(rows);
    Ok(())
}

/// Whether the local part's carriage reads the grants on `y` (`y`'s independent's): the node root
/// or a thing the local part holds whole (its own data), an own thing, one logged in the local
/// part, or one whose role entries the node holds by another route.
pub(crate) fn counts(core: &Core, y: &Tid) -> bool {
    // the local part's own things: the node root and what it holds whole
    if core.node_root == Some(*y) || core.ix.closure.local_holds(y) {
        return true;
    }
    let a = core.secret_actor(y).unwrap_or(*y);
    core.is_own(&a) || core.ix.local_log.contains(&a) || founded_otherwise(core, &a)
}

/// Whether the node holds independent `a`'s role entries by a route other than the local part's
/// carriage of it: a link it redeems or a grant signal it follows naming `a` (a share link's K,
/// its record naming `a` the link's target, holding a role on it, spec/permissions.md §7), its own
/// commits minting `a` or giving it a keyset in the running transaction (`Core::made`), or a
/// vertex of `a` that an edge of another unit gives on a path avoiding `a` (a unit it syncs
/// carrying `a` whole or as a stub).
fn founded_otherwise(core: &Core, a: &Tid) -> bool {
    let fl = &core.followed_links;
    fl.contains(a) || core.made.contains(a) || core.roster_of(a).keys().any(|k| fl.contains(k) && core.created(k).is_some_and(|r| r.link == Some(*a))) || crate::sync::units::given_elsewhere(core, a)
}

/// The local part's log brought up to its edges as they stand (a settle's end): each thing an edge
/// from the local part was linked to or unlinked from is logged while one carries it, and goes
/// with the last. Whether a row moved.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<bool> {
    let moved = tx.core.ix.closure.take_local_moved();
    let mut any = false;
    for x in moved {
        let carried = tx.core.ix.closure.local_carries(&x) && !tx.core.is_own(&x);
        let logged = tx.core.ix.local_log.contains(&x);
        let key = [LOCAL_LOG, x.as_bytes().as_slice()].concat();
        if carried && !logged {
            tx.txn.put_local(&key, &[], Shred::No)?;
            tx.core.ix.local_log.insert(x);
            any = true;
        } else if !carried && logged {
            tx.txn.remove_local(&key, Shred::No)?;
            tx.core.ix.local_log.remove(&x);
            any = true;
        }
    }
    Ok(any)
}
