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
    /// The newest applied commit whose delta on `(tid, ak)` is valid here: `ts` is the author's
    /// to choose, so an invalid write (anyone's commit on another's card) never stands for the
    /// current one.
    fn latest_on(&self, tid: &Tid, ak: &str) -> Option<CommitId> {
        self.latest_by(tid, ak, None)
    }

    /// `latest_on`, written by `author` when given.
    pub(crate) fn latest_by(&self, tid: &Tid, ak: &str, author: Option<&Tid>) -> Option<CommitId> {
        let k = Ak::new(ak).ok()?;
        let held = self.core.by_aspect.get(&(*tid, k))?;
        held.iter().rev().map(|(_, c)| *c).find(|c| {
            let Some(m) = self.core.commits.get(c) else { return false };
            !self.core.pending.contains_key(c)
                && author.is_none_or(|a| m.header.author == *a)
                && m.header.aspects.iter().enumerate().any(|(i, a)| a.tid == *tid && a.ak.as_str() == ak && m.valid.get(i).copied().unwrap_or(false))
        })
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

    /// The newest held commit writing `(tid, ak)` with the indexes of its deltas on it (a
    /// grantee's certificate copy names a thing's `/label` and `/created`, spec/sync.md §3).
    pub(crate) fn aspect_commit(&self, tid: &Tid, ak: &str) -> Option<(CommitId, BTreeSet<usize>)> {
        let c = self.latest_on(tid, ak)?;
        let h = self.header(&c)?;
        let ais: BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *tid && a.ak.as_str() == ak).map(|(i, _)| i).collect();
        Some((c, ais))
    }

    /// The deltas of roster snapshot `c` on `things` a chain needs (spec/permissions.md §6):
    /// those naming one of `members`, and those naming nobody (the reset alone). None when the
    /// commit cannot be read here (diagnostic): never the whole roster.
    pub(crate) fn snapshot_parts(&mut self, c: &CommitId, things: &BTreeSet<Tid>, members: &BTreeSet<Tid>) -> Parts {
        let all = self.parts_of(c, things, &["/members", "/tenures"]);
        let ais: BTreeSet<usize> = all.iter().map(|x| x.0).collect();
        let id = *c;
        let read = match self.header(c) {
            Some(h) => self.run(|tx| crate::apply::held_parts_at(tx, &id, &|ai| ais.contains(&ai))).ok().map(|p| (h, p)),
            None => None,
        };
        let Some((h, parts)) = read else {
            let now = self.now();
            self.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::BadInput, tids: things.iter().copied().collect(), commit: Some(id), peer: None, detail: "a roster snapshot certificate does not read: not placed".into() }, now);
            return Parts::new();
        };
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
        // the owner chain's `/created` records
        let mut cur = Some(*g);
        let mut seen = BTreeSet::new();
        while let Some(t) = cur {
            if !seen.insert(t) {
                break;
            }
            if let Some(c) = self.latest_on(&t, "/created") {
                add(c, self.parts_of(&c, &BTreeSet::from([t]), &["/created"]));
            }
            cur = match self.core.created(&t) {
                Some(CreationRecord::Thing { owner, .. }) => Some(*owner),
                _ => None,
            };
        }
        if let Some(tl) = self.core.timelines.get(g) {
            let ts = osis_core::Ts::make(self.now(), 0xffff).unwrap_or_default();
            let certs = tl.certificates(&me, g, Point { ts, node: me, commit: CommitId([0xff; 32]) });
            self.cert_parts(&certs, &mut out);
        }
        out
    }

    /// The commits and parts certificates `certs` name (spec/permissions.md §4), added to `out`:
    /// edge writes projected to their edge deltas on the chain's things, roster snapshots to
    /// their members' entries, the newest `/created` of each thing and `/keys` of each actor.
    fn cert_parts(&mut self, certs: &osis_perm::Certificates, out: &mut BTreeMap<CommitId, Parts>) {
        let mut add = |c: CommitId, parts: Parts| {
            if !parts.is_empty() {
                out.entry(c).or_default().extend(parts);
            }
        };
        let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
        for c in &certs.commits {
            add(*c, self.parts_of(c, &all, &["/members", "/tenures"]));
        }
        for (c, members) in &certs.snapshots {
            add(*c, self.snapshot_parts(c, &all, members));
        }
        for t in &certs.created {
            if let Some(c) = self.latest_on(t, "/created") {
                add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["/created"]));
            }
        }
        for t in &certs.keys {
            if let Some(c) = self.latest_on(t, "/keys") {
                add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["/keys"]));
            }
        }
    }

    /// Revokes of departures inside members of `actor` (a member M with secrets of its own,
    /// outside `closure`: an applied write lowering an edge on M), with what judges them: the
    /// ones that keep `actor`'s epoch uncovered, the only certificates a node that may not rotate
    /// places under such an epoch (spec/permissions.md §4).
    pub fn inside_member_revokes(&mut self, actor: &Tid, closure: &BTreeSet<Tid>) -> BTreeMap<CommitId, Parts> {
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        let mut whole: Vec<(CommitId, Tid)> = Vec::new();
        let members: Vec<Tid> = self.core.current_members(actor).into_iter().map(|x| x.0).filter(|m| self.core.has_own_secrets(m) && !closure.contains(m)).collect();
        for m in members {
            let Some(tl) = self.core.timelines.get(&m) else { continue };
            for wid in tl.applied().keys() {
                let osis_perm::WriteId::Op(c, i) = wid else { continue };
                let Some(mc) = tl.membership_commit(c) else { continue };
                let Some(op) = mc.ops.get(*i as usize) else { continue };
                if op.target != m {
                    continue;
                }
                let old = tl.edges_at(Some(mc.point())).get(&op.member, &op.target).map(|e| e.role);
                let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                if new < old
                    && let Some(cs) = tl.write_certificates(wid)
                {
                    found.push(cs);
                    whole.push((*c, m));
                }
            }
        }
        let mut out = BTreeMap::new();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        // the whole write on M (its rotation's `/keys` and `/secrets` too: boxes sealed to M's
        // members): a reader that syncs M waits for every delta of it (spec/commits.md §4)
        for (c, m) in whole {
            let p = self.parts_of(&c, &BTreeSet::from([m]), &["/members", "/tenures", "/keys", "/secrets"]);
            if !p.is_empty() {
                out.entry(c).or_default().extend(p);
            }
        }
        out
    }

    /// Revokes and roster snapshots about `authors` (of entries seen under a label), with what
    /// a verifier needs to judge them as this node does (their own authors' chain certificates;
    /// spec/permissions.md §4): applied edge writes lowering an author's edge on a thing outside
    /// `closure` (inside it they are closure bodies), and roster snapshots of such things naming
    /// an author, projected to the authors.
    pub fn revoke_certificates(&mut self, authors: &BTreeSet<Tid>, closure: &BTreeSet<Tid>) -> BTreeMap<CommitId, Parts> {
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        for m in authors {
            let Some(tl) = self.core.timelines.get(m) else { continue };
            for wid in tl.applied().keys() {
                let about = match wid {
                    osis_perm::WriteId::Op(c, i) => {
                        let Some(mc) = tl.membership_commit(c) else { continue };
                        let Some(op) = mc.ops.get(*i as usize) else { continue };
                        if op.member != *m || closure.contains(&op.target) {
                            continue;
                        }
                        let old = tl.edges_at(Some(mc.point())).get(&op.member, &op.target).map(|e| e.role);
                        let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                        new < old
                    }
                    osis_perm::WriteId::Snapshot(c) => tl.roster_snapshot(c).is_some_and(|s| !closure.contains(&s.thing) && (s.roster.contains_key(m) || s.ledger.iter().any(|t| t.member == *m))),
                };
                if !about {
                    continue;
                }
                if let Some(mut cs) = tl.write_certificates(wid) {
                    for members in cs.snapshots.values_mut() {
                        members.retain(|x| authors.contains(x));
                    }
                    found.push(cs);
                }
            }
        }
        let mut out = BTreeMap::new();
        for cs in &found {
            self.cert_parts(cs, &mut out);
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_core::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/permissions.md §4 (certificates and cards are the current valid writes), §5.2: a
    // later write by a node without the role (here a reader; anyone's on another node's card)
    // is invalid and never stands for the newest commit on the aspect: admins would otherwise
    // delete the real one as superseded.
    #[test]
    fn invalid_later_write_never_newest_spec_permissions_4() {
        let mut lp = LocalPeer::new(3, 921, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        let ak = Ak::new("/x/a").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let good = lp.peers[0].commit(m).unwrap().unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync_all().unwrap();
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(2)).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let bad = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync(1, 2).unwrap();
        let e = &lp.peers[2].engine;
        assert!(e.header(&bad).is_some_and(|h| h.ts > e.header(&good).unwrap().ts), "the reader's write is held, later");
        assert_eq!(e.latest_by(&t, "/x/a", None), Some(good));
        assert_eq!(e.latest_by(&t, "/x/a", Some(&b)), None);
    }
}
