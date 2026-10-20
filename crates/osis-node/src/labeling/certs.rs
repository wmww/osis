//! Certificate blobs (spec/permissions.md §4; spec/sync.md §3): this node's chain certificates
//! for a group and its node card as (commit, aspects) to place, and partial bodies of a commit.
//! Labels and steps are membership flows' (`Engine::create_label`, `Engine::issue_step`).

use super::blobs::Body;
use crate::engine::Engine;
use crate::error::Result;
use osis_core::{Ak, CommitId, CreationRecord, Tid};
use osis_perm::Point;
use std::collections::{BTreeMap, BTreeSet};

/// Aspects a node card holds (each its own commit, spec/permissions.md §4).
const CARD: [&str; 3] = ["/keys", "/node", "/reach"];


impl Engine {
    /// The newest held commit touching `(tid, ak)`.
    fn latest_on(&self, tid: &Tid, ak: &str) -> Option<CommitId> {
        let ak = Ak::new(ak).ok()?;
        self.core.by_aspect.get(&(*tid, ak)).and_then(|s| s.iter().next_back()).map(|(_, c)| *c)
    }

    /// Aspect indexes of commit `c` on `(tid, ak)` for any of `aks`.
    fn aspects_of(&self, c: &CommitId, tids: &BTreeSet<Tid>, aks: &[&str]) -> Vec<usize> {
        let Some(h) = self.header(c) else { return Vec::new() };
        h.aspects.iter().enumerate().filter(|(_, a)| tids.contains(&a.tid) && aks.contains(&a.ak.as_str())).map(|(i, _)| i).collect()
    }

    /// This node's chain certificates for `g` and its node card (spec/permissions.md §4), as
    /// commits with the aspect indexes to carry.
    pub fn certificates(&self, g: &Tid) -> BTreeMap<CommitId, BTreeSet<usize>> {
        let me = self.tid();
        let mut out: BTreeMap<CommitId, BTreeSet<usize>> = BTreeMap::new();
        let mut add = |c: CommitId, ais: Vec<usize>| {
            if !ais.is_empty() {
                out.entry(c).or_default().extend(ais);
            }
        };
        let mine = BTreeSet::from([me]);
        for ak in CARD.iter().chain(["/created"].iter()) {
            if let Some(c) = self.latest_on(&me, ak) {
                add(c, self.aspects_of(&c, &mine, &[ak]));
            }
        }
        let mut created: BTreeSet<Tid> = BTreeSet::new();
        let mut keys: BTreeSet<Tid> = BTreeSet::new();
        let mut cur = Some(*g);
        while let Some(t) = cur {
            if !created.insert(t) {
                break;
            }
            cur = match self.core.created(&t) {
                Some(CreationRecord::Thing { owner, .. }) => Some(*owner),
                _ => None,
            };
        }
        if let Some(tl) = self.core.timelines.get(g) {
            let ts = osis_core::Ts::make(self.now(), 0xffff).unwrap_or_default();
            let certs = tl.certificates(&me, g, Point { ts, node: me, commit: CommitId([0xff; 32]) });
            created.extend(certs.created.iter().copied());
            keys.extend(certs.keys.iter().copied());
            let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
            for c in certs.commits.iter().chain(certs.snapshots.keys()) {
                add(*c, self.aspects_of(c, &all, &["/members", "/tenures"]));
            }
        }
        for t in &created {
            if let Some(c) = self.latest_on(t, "/created") {
                add(c, self.aspects_of(&c, &BTreeSet::from([*t]), &["/created"]));
            }
        }
        for t in &keys {
            if let Some(c) = self.latest_on(t, "/keys") {
                add(c, self.aspects_of(&c, &BTreeSet::from([*t]), &["/keys"]));
            }
        }
        out
    }

    /// The bodies of commit `c` restricted to aspects `ais` (one per retention class): a
    /// certificate copy.
    pub fn partial_bodies(&mut self, c: &CommitId, ais: &BTreeSet<usize>) -> Result<Vec<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        let cut = osis_commit::rewrite(&blob, |ai, _| !ais.contains(&ai));
        if cut.parts.is_empty() {
            return Ok(Vec::new());
        }
        let membership = cut.header.kind.is_membership();
        let resolved = match self.core.commits.get(&id) {
            Some(m) if !cut.header.is_resolved() => m.header.clone(),
            _ => std::sync::Arc::new(cut.header.clone()),
        };
        let ps = osis_commit::project_resolved(&cut, &resolved, |_| ())?;
        Ok(ps.into_iter().map(|p| Body { commit: id, reader: self.tid(), parts: p.parts, expires: p.expires, tokens: p.tokens, plaintext: p.plaintext, membership }).collect())
    }
}
