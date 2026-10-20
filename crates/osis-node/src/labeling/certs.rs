//! Certificate blobs (spec/permissions.md §4; spec/sync.md §3): this node's chain certificates
//! for a group and its node card as (commit, parts) to place, a roster snapshot projected to the
//! deltas of the chain's members, partial bodies of a commit and the blobs its parts link.
//! Labels and steps are membership flows' (`Engine::create_label`, `Engine::issue_step`).

use super::blobs::Body;
use crate::engine::Engine;
use crate::error::Result;
use osis_commit::Decoded;
use osis_core::{Ak, BlobId, CommitId, CreationRecord, Tid};
use osis_perm::Point;
use std::collections::{BTreeMap, BTreeSet};

/// Aspects a node card holds (each its own commit, spec/permissions.md §4).
const CARD: [&str; 3] = ["/keys", "/node", "/reach"];

/// Parts of a commit: (aspect index, delta index).
pub type Parts = BTreeSet<(usize, usize)>;

impl Engine {
    /// The newest held commit touching `(tid, ak)`.
    fn latest_on(&self, tid: &Tid, ak: &str) -> Option<CommitId> {
        let ak = Ak::new(ak).ok()?;
        self.core.by_aspect.get(&(*tid, ak)).and_then(|s| s.iter().next_back()).map(|(_, c)| *c)
    }

    /// Every delta of commit `c` on `(tid, ak)` for any of `aks`.
    fn parts_of(&self, c: &CommitId, tids: &BTreeSet<Tid>, aks: &[&str]) -> Parts {
        let Some(h) = self.header(c) else { return Parts::new() };
        h.aspects
            .iter()
            .enumerate()
            .filter(|(_, a)| tids.contains(&a.tid) && aks.contains(&a.ak.as_str()))
            .flat_map(|(i, a)| (0..a.hashes.len()).map(move |d| (i, d)))
            .collect()
    }

    /// The deltas of roster snapshot `c` on `things` a chain needs (spec/permissions.md §6):
    /// those naming one of `members`, and those naming nobody (a reset alone). Every delta of
    /// those aspects when the commit cannot be read here.
    fn snapshot_parts(&mut self, c: &CommitId, things: &BTreeSet<Tid>, members: &BTreeSet<Tid>) -> Parts {
        let all = self.parts_of(c, things, &["/members", "/tenures"]);
        let ais: BTreeSet<usize> = all.iter().map(|x| x.0).collect();
        let Some(h) = self.header(c) else { return all };
        let id = *c;
        let Ok(parts) = self.run(|tx| crate::apply::held_parts_at(tx, &id, &|ai| ais.contains(&ai))) else { return all };
        let mut out = Parts::new();
        for (ai, di, d) in parts {
            let (Some(a), Decoded::Delta(d)) = (h.aspects.get(ai), &d) else { continue };
            let named = crate::apply::validity::named_members(a.ak.as_str(), &d.fragment);
            if named.is_empty() || named.iter().any(|m| members.contains(m)) {
                out.insert((ai, di));
            }
        }
        out
    }

    /// This node's chain certificates for `g` and its node card (spec/permissions.md §4), as
    /// commits with the parts to carry; a roster snapshot projected to the chain's members.
    pub fn certificates(&mut self, g: &Tid) -> BTreeMap<CommitId, Parts> {
        let me = self.tid();
        let mut out: BTreeMap<CommitId, Parts> = BTreeMap::new();
        let mut add = |c: CommitId, parts: Parts| {
            if !parts.is_empty() {
                out.entry(c).or_default().extend(parts);
            }
        };
        let mine = BTreeSet::from([me]);
        for ak in CARD.iter().chain(["/created"].iter()) {
            if let Some(c) = self.latest_on(&me, ak) {
                add(c, self.parts_of(&c, &mine, &[ak]));
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
            for c in &certs.commits {
                add(*c, self.parts_of(c, &all, &["/members", "/tenures"]));
            }
            for (c, members) in &certs.snapshots {
                add(*c, self.snapshot_parts(c, &all, members));
            }
        }
        for t in &created {
            if let Some(c) = self.latest_on(t, "/created") {
                add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["/created"]));
            }
        }
        for t in &keys {
            if let Some(c) = self.latest_on(t, "/keys") {
                add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["/keys"]));
            }
        }
        out
    }

    /// The bodies of commit `c` restricted to aspects `ais` (one per retention class): a
    /// certificate copy.
    pub fn partial_bodies(&mut self, c: &CommitId, ais: &BTreeSet<usize>) -> Result<Vec<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        let parts: Parts = blob.parts.iter().filter(|p| ais.contains(&p.ai)).map(|p| (p.ai, p.di)).collect();
        self.part_bodies(c, &parts)
    }

    /// The bodies of commit `c` restricted to `parts` (one per retention class): a certificate
    /// copy.
    pub fn part_bodies(&mut self, c: &CommitId, parts: &Parts) -> Result<Vec<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        let cut = osis_commit::rewrite(&blob, |ai, di| !parts.contains(&(ai, di)));
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

    /// Blobs a certificate copy of `parts` of commit `c` needs beside its body (spec/sync.md
    /// §3): the trees of the header's linked lists (a demotion's frontier among them) and of the
    /// large values its deltas link (a roster snapshot's linked frontiers), as far as held.
    pub fn linked_blobs(&mut self, c: &CommitId, parts: &Parts) -> Result<BTreeSet<BlobId>> {
        let mut out = BTreeSet::new();
        let Some(h) = self.header(c) else { return Ok(out) };
        let lists: Vec<osis_core::Link> = osis_commit::ListField::ALL.iter().filter_map(|f| h.links.get(*f).copied()).collect();
        for l in &lists {
            self.tree_blobs(l, &h.actor, &mut out)?;
        }
        let id = *c;
        let found = self.run(|tx| {
            let mut found = BTreeSet::new();
            for (ai, di, d) in crate::apply::held_parts_at(tx, &id, &|ai| parts.iter().any(|p| p.0 == ai))? {
                let (Some(a), Decoded::Delta(d)) = (h.aspects.get(ai), &d) else { continue };
                if !parts.contains(&(ai, di)) {
                    continue;
                }
                let mut roots = Vec::new();
                if let Some(v) = d.fragment.read() {
                    crate::engine::large::links_in(&v, &mut roots);
                }
                let Some(dedup) = tx.core.dedup(&a.tid) else { continue };
                let mut trees = crate::engine::large::LiveTrees::default();
                crate::engine::large::tree_blobs(tx, &dedup, &roots, &mut trees)?;
                found.extend(trees.blobs);
            }
            Ok(found)
        })?;
        out.extend(found);
        Ok(out)
    }
}
