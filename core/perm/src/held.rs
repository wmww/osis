//! The held-set queries perm needs (notes/architecture.md §2): the node implements `HeldSet`
//! over its store; `MemoryHeldSet` serves tests. perm holds no state between calls.

use crate::types::RoleCommit;
use crate::vouch::{RoleParts, Vouch};
use osis_base::{CommitId, CreationRecord, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What the node holds that layer 1 needs. Applied, verified commits only (pending ones are not
/// held, spec/commits.md §4); duplicates are harmless. A record's frontiers are fixed by its
/// commit ID (the node's are inline in the signed header or linked by content hash): a saved
/// walk is matched to its input by everything else in full, frontiers by their sizes.
pub trait HeldSet {
    /// Things with a held edge write, `created.0` record or vouch.
    fn things(&self) -> Vec<Tid>;
    /// Role commits with an edge write on `thing`.
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<RoleCommit>>;
    /// The `created.0` record of `thing`, if held.
    fn created(&self, thing: &Tid) -> Option<CreationRecord>;
    /// The vouches held on `thing` (spec/permissions.md §5.1 Vouches), in a fixed order. Every
    /// held set answers it: one that leaves vouches out judges role writes vouch-blind.
    fn vouches(&self, thing: &Tid) -> Vec<Arc<Vouch>>;
    /// The role-class parts other than edge writes of held role commit `id` (`RoleParts`);
    /// `None` when not held or it has none.
    fn role_parts(&self, id: &CommitId) -> Option<Arc<RoleParts>>;
}

/// In-memory held set.
#[derive(Clone, Debug, Default)]
pub struct MemoryHeldSet {
    pub commits: BTreeMap<Tid, Vec<Arc<RoleCommit>>>,
    pub created: BTreeMap<Tid, CreationRecord>,
    pub vouches: BTreeMap<Tid, Vec<Arc<Vouch>>>,
    pub parts: BTreeMap<CommitId, Arc<RoleParts>>,
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
    pub fn add_commit(&mut self, c: RoleCommit) {
        let c = Arc::new(c);
        let targets: BTreeSet<Tid> = c.ops.iter().map(|o| o.target).collect();
        for t in targets {
            self.commits.entry(t).or_default().push(c.clone());
        }
    }
    /// Adds a vouch on its thing.
    pub fn add_vouch(&mut self, v: Vouch) {
        self.vouches.entry(v.thing).or_default().push(Arc::new(v));
    }
    /// Notes a held role commit's role-class parts that are not edge writes.
    pub fn add_parts(&mut self, p: RoleParts) {
        self.parts.insert(p.id, Arc::new(p));
    }
    /// Drops every held commit with this ID (as a compacted node would).
    pub fn remove(&mut self, id: &osis_base::CommitId) {
        for v in self.commits.values_mut() {
            v.retain(|c| c.id != *id);
        }
        for v in self.vouches.values_mut() {
            v.retain(|x| x.id != *id);
        }
        self.parts.remove(id);
    }
}

impl HeldSet for MemoryHeldSet {
    fn things(&self) -> Vec<Tid> {
        let mut s: BTreeSet<Tid> = self.commits.keys().copied().collect();
        s.extend(self.created.keys().copied());
        s.extend(self.vouches.keys().copied());
        s.into_iter().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<RoleCommit>> {
        self.commits.get(thing).cloned().unwrap_or_default()
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        self.created.get(thing).cloned()
    }
    fn vouches(&self, thing: &Tid) -> Vec<Arc<Vouch>> {
        self.vouches.get(thing).cloned().unwrap_or_default()
    }
    fn role_parts(&self, id: &CommitId) -> Option<Arc<RoleParts>> {
        self.parts.get(id).cloned()
    }
}
