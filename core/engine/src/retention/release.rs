//! Release (spec/sync-set.md §3): a thing leaving the node closure is dropped once the sync pass
//! in flight with the connected peers has ended, never waiting for an absent peer. Leaving is the
//! node closure's (`sync::units`, which notes what left and the sync units it was in); when to
//! drop is sync's (`osis_sync::leave`); dropping is here.

use crate::engine::Engine;
use crate::error::Result;
use osis_base::Tid;
use std::collections::{BTreeMap, BTreeSet};

impl Engine {
    /// The things that left the node closure and are not released yet, each with the sync units
    /// that held it when it left (none: it left the local part): what sync drops once its pass
    /// in flight ends (spec/sync-set.md §3). A stamped read.
    pub fn left_closure(&self) -> BTreeMap<Tid, BTreeSet<Tid>> {
        let units = |cs: &BTreeSet<crate::sync::units::Ctx>| cs.iter().filter_map(|c| if let crate::sync::units::Ctx::Read(u) | crate::sync::units::Ctx::Unread(u) | crate::sync::units::Ctx::Stub(u) = c { Some(*u) } else { None }).collect();
        self.core.ix.closure.left().iter().map(|(t, cs)| (*t, units(cs))).collect()
    }

    /// Releases each of `ts` still outside the node closure (spec/sync-set.md §3; one a unit it
    /// reads carries as a stub is held as that stub from then on): it and what
    /// it was named holder on are judged in the same transaction by what the node holds of a
    /// thing outside its node closure (`retention::needed::Holding`): its content goes as never
    /// received, its certificates stay while a held thing needs them, and the store's own
    /// entries of the commits it deleted whole go (`sync::bodies::forget`).
    pub fn released(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        let out: BTreeSet<Tid> = ts.iter().filter(|t| !self.core.ix.closure.holds(t)).copied().collect();
        if out.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            for t in &out {
                tx.core.ix.closure.released(t);
            }
            tx.core.needs_due.extend(out.iter().copied());
            // and what each was named holder on: needed by it only while it was in the closure
            let named: Vec<Tid> = out.iter().flat_map(|t| tx.core.ix.held.named_on(t).copied().collect::<Vec<_>>()).collect();
            tx.core.needs_due.extend(named);
            Ok(())
        })
    }
}
