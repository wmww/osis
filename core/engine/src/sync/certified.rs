//! Which commits each read thing's certificates name, per commit (`Certified`): `sync_bodies`
//! reads one commit's row, so a change of one thing's certificates moves the bodies of the
//! commits it named or names and no other. A thing's certificates (`Engine::sync_certificates`)
//! read its whole component's timeline, which moves at nearly every role event; followed here
//! through `Effects`, a recomputation that names the same commits moves nothing.

use super::ThingSync;
use crate::Engine;
use crate::error::Result;
use crate::labeling::{Certs, Parts};
use osis_base::memo::{Effects, Stamped, Unrecorded};
use osis_base::{CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What one thing's certificates name of a commit: parts to carry, and whether its header goes
/// alone (a minting or request, `Certs::headers`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Named {
    pub parts: Parts,
    pub header: bool,
}

/// The certificates of the things this node reads, followed, and indexed by commit.
#[derive(Clone)]
pub(crate) struct Certified {
    /// The things read here (a read sync ID of the sync set): whose certificates are followed.
    things: Effects<(), Arc<BTreeSet<Tid>>>,
    /// Each followed thing's certificates, as last indexed.
    certs: Effects<Tid, Arc<Certs>>,
    /// Per commit, each followed thing whose certificates name it.
    of: Stamped<CommitId, Arc<BTreeMap<Tid, Named>>>,
}

impl Default for Certified {
    fn default() -> Self {
        Certified { things: Effects::new("sync: certified things"), certs: Effects::new("sync: certified"), of: Stamped::default() }
    }
}

fn named(certs: &Certs, c: &CommitId) -> Option<Named> {
    let parts = certs.commits.get(c).cloned().unwrap_or_default();
    let header = certs.headers.contains(c);
    (header || !parts.is_empty()).then_some(Named { parts, header })
}

impl Certified {
    /// `t`'s certificates moved from `was` to `now`: the rows of the commits either names.
    /// Whether a row moved.
    fn index(&mut self, t: &Tid, was: &Certs, now: &Certs) -> bool {
        let mut moved = false;
        let commits: BTreeSet<&CommitId> = was.commits.keys().chain(&was.headers).chain(now.commits.keys()).chain(&now.headers).collect();
        for c in commits {
            let n = named(now, c);
            if named(was, c) == n {
                continue;
            }
            moved = true;
            let mut row = self.of.get(c).map(|r| (**r).clone()).unwrap_or_default();
            match n {
                Some(n) => row.insert(*t, n),
                None => row.remove(t),
            };
            if row.is_empty() {
                self.of.remove(c);
            } else {
                self.of.insert(*c, Arc::new(row));
            }
        }
        moved
    }
}

impl Engine {
    /// The things whose certificates `Certified` follows: those holding a read sync ID.
    fn read_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        let set = self.sync_set()?;
        Ok(Arc::new(set.ids.values().filter(|(_, h)| *h == super::Holding::Read).map(|(t, _)| *t).collect()))
    }

    /// Brings `Certified` up to date with what moved since the last call: work in proportion to
    /// the things whose certificates' reads moved. Read by no caller: what a caller reads is the
    /// rows (`certified`). Whether a row moved.
    pub(crate) fn follow_certificates(&mut self) -> Result<bool> {
        let _u = Unrecorded::start();
        let mut things = std::mem::replace(&mut self.core.certified.things, Effects::new("sync: certified things"));
        let mut certs = std::mem::replace(&mut self.core.certified.certs, Effects::new("sync: certified"));
        let r = self.follow_with(&mut things, &mut certs);
        self.core.certified.things = things;
        self.core.certified.certs = certs;
        r
    }

    fn follow_with(&mut self, things: &mut Effects<(), Arc<BTreeSet<Tid>>>, certs: &mut Effects<Tid, Arc<Certs>>) -> Result<bool> {
        let mut moved = false;
        if !things.wants(&()) {
            things.want(());
        }
        let mut gone = Vec::new();
        for k in things.due() {
            let Some((was, now)) = things.try_settle(&k, || self.read_things())? else { continue };
            let was = was.unwrap_or_default();
            for t in now.difference(&was) {
                certs.want(*t);
            }
            gone.extend(was.difference(&now).copied());
        }
        for t in gone {
            if let Some((Some(was), _)) = certs.settle(&t, || Arc::new(Certs::default())) {
                moved |= self.core.certified.index(&t, &was, &Certs::default());
            }
            certs.unwant(&t);
        }
        for t in certs.due() {
            let Some((was, now)) = certs.settle(&t, || self.sync_certificates(&t)) else { continue };
            moved |= self.core.certified.index(&t, &was.unwrap_or_default(), &now);
        }
        Ok(moved)
    }

    /// Per thing read here whose certificates name commit `c`, what they name of it, and the
    /// thing's read sync IDs (spec/permissions.md §4): a read of `c`'s row alone.
    pub(crate) fn certified(&mut self, c: &CommitId) -> Result<Vec<(Tid, Named, Vec<osis_base::SyncId>)>> {
        self.follow_certificates()?;
        let Some(row) = self.core.certified.of.get(c).cloned() else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for (t, n) in row.iter() {
            if let ThingSync::Read(ids) = self.thing_sync(t)? {
                out.push((*t, n.clone(), ids));
            }
        }
        Ok(out)
    }
}
