//! Release (spec/sync-set.md §3): a thing leaving the node closure is dropped once the sync pass
//! in flight with the connected peers has ended, never waiting for an absent peer. Leaving is the
//! node closure's (`sync::units`, which notes what left and the sync units it was in); when to
//! drop is sync's (`osis_sync::leave`); dropping is here.

use crate::engine::Engine;
use crate::error::Result;
use osis_base::{BlobId, Tid};
use std::collections::{BTreeMap, BTreeSet};

impl Engine {
    /// The things that left the node closure and are not released yet, each with the sync units
    /// that held it when it left (none: it left the local part): what sync drops once its pass
    /// in flight ends (spec/sync-set.md §3). A stamped read.
    pub fn left_closure(&self) -> BTreeMap<Tid, BTreeSet<Tid>> {
        let units = |cs: &BTreeSet<crate::sync::units::Ctx>| cs.iter().filter_map(|c| if let crate::sync::units::Ctx::Read(u) | crate::sync::units::Ctx::Unread(u) | crate::sync::units::Ctx::Ticket(u) = c { Some(*u) } else { None }).collect();
        self.core.ix.closure.left().iter().map(|(t, cs)| (*t, units(cs))).collect()
    }

    /// Drops what `ts` left behind here, those still outside the node closure (spec/sync-set.md
    /// §3): the content of each and of each thing whose secrets are one of theirs, but those the
    /// node closure holds; what arrives again counts as never received. The blobs of the commits
    /// it deleted whole.
    pub fn released(&mut self, ts: &BTreeSet<Tid>) -> Result<BTreeSet<BlobId>> {
        let out: BTreeSet<Tid> = ts.iter().filter(|t| !self.core.ix.closure.holds(t)).copied().collect();
        if out.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut things = crate::retention::forget::under(&self.core, &out);
        things.extend(out.iter().copied());
        let cl = &self.core.ix.closure;
        things.retain(|x| !cl.holds(x));
        let f = self.run(|tx| {
            for t in &out {
                tx.core.ix.closure.released(t);
            }
            crate::flows::inbox::drop_account_tickets(tx, &out)?;
            // what stays of them (records, role-class state) only while a held thing needs it
            tx.core.needs_due.extend(things.iter().copied());
            crate::retention::forget::forget(tx, crate::retention::forget::Scope::Local(&things), &BTreeMap::new())
        })?;
        Ok(f.blobs)
    }
}
