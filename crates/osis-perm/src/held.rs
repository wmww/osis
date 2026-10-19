//! The held-set queries perm needs (notes/architecture.md §2): the node implements `HeldSet`
//! over its store; `MemoryHeldSet` serves tests. perm holds no state between calls.

use crate::types::{MembershipCommit, RosterSnapshot};
use osis_core::{CreationRecord, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What the node holds that layer 1 needs. Applied, verified commits only (pending ones are not
/// held, spec/commits.md §4); duplicates are harmless.
pub trait HeldSet {
    /// Things with a held edge write, roster snapshot or `/created` record.
    fn things(&self) -> Vec<Tid>;
    /// Membership commits with an edge write on `thing` (roster snapshots excluded).
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<MembershipCommit>>;
    /// Roster snapshots of `thing`.
    fn roster_snapshots(&self, thing: &Tid) -> Vec<Arc<RosterSnapshot>>;
    /// The `/created` record of `thing`, if held.
    fn created(&self, thing: &Tid) -> Option<CreationRecord>;
}

/// In-memory held set.
#[derive(Clone, Debug, Default)]
pub struct MemoryHeldSet {
    pub commits: BTreeMap<Tid, Vec<Arc<MembershipCommit>>>,
    pub snapshots: BTreeMap<Tid, Vec<Arc<RosterSnapshot>>>,
    pub created: BTreeMap<Tid, CreationRecord>,
}

impl MemoryHeldSet {
    pub fn new() -> Self {
        Self::default()
    }
    /// Adds a creation record under its tid; returns the tid.
    pub fn create(&mut self, record: CreationRecord) -> Tid {
        let tid = record.tid();
        self.created.insert(tid, record);
        tid
    }
    pub fn add_commit(&mut self, c: MembershipCommit) {
        let c = Arc::new(c);
        let targets: BTreeSet<Tid> = c.ops.iter().map(|o| o.target).collect();
        for t in targets {
            self.commits.entry(t).or_default().push(c.clone());
        }
    }
    pub fn add_snapshot(&mut self, s: RosterSnapshot) {
        self.snapshots.entry(s.thing).or_default().push(Arc::new(s));
    }
    /// Drops every held commit and snapshot with this ID (as a compacted node would).
    pub fn remove(&mut self, id: &osis_core::CommitId) {
        for v in self.commits.values_mut() {
            v.retain(|c| c.id != *id);
        }
        for v in self.snapshots.values_mut() {
            v.retain(|s| s.id != *id);
        }
    }
}

impl HeldSet for MemoryHeldSet {
    fn things(&self) -> Vec<Tid> {
        let mut s: BTreeSet<Tid> = self.commits.keys().copied().collect();
        s.extend(self.snapshots.keys().copied());
        s.extend(self.created.keys().copied());
        s.into_iter().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<MembershipCommit>> {
        self.commits.get(thing).cloned().unwrap_or_default()
    }
    fn roster_snapshots(&self, thing: &Tid) -> Vec<Arc<RosterSnapshot>> {
        self.snapshots.get(thing).cloned().unwrap_or_default()
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        self.created.get(thing).cloned()
    }
}
