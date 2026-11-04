//! Certificate blobs (spec/permissions.md §4; spec/sync.md §3): this node's chain certificates
//! for a group and its node card as (commit, parts) to place, a roster snapshot projected to the
//! deltas of the chain's holders, partial bodies of a commit and the blobs its parts link.
//! Labels and steps are role flows' (`Engine::create_label`, `Engine::issue_step`).

use super::blobs::Body;
use crate::engine::Engine;
use crate::error::Result;
use osis_commit::Decoded;
use osis_base::{Ak, BlobId, ChainStep, CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Aspects a node card holds (each its own commit, spec/permissions.md §4).
const CARD: [&str; 3] = ["keys.0", "node.0", "reach.0"];

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
    pub fn latest_by(&self, tid: &Tid, ak: &str, author: Option<&Tid>) -> Option<CommitId> {
        let k = Ak::new(ak).ok()?;
        let held = self.core.ix.by_aspect.get(&(*tid, k))?;
        held.iter().rev().map(|(_, c)| *c).find(|c| {
            let Some(m) = self.core.ix.commits.get(c) else { return false };
            !self.core.ix.pending.contains_key(c)
                && author.is_none_or(|a| m.header.author == *a)
                && m.header.aspects.iter().enumerate().any(|(i, a)| a.tid == *tid && a.ak.as_str() == ak && m.valid_at(i))
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
    /// grantee's certificate copy names a thing's `label.0` and `created.0`, spec/sync.md §3).
    pub fn aspect_commit(&self, tid: &Tid, ak: &str) -> Option<(CommitId, BTreeSet<usize>)> {
        let c = self.latest_on(tid, ak)?;
        let h = self.header(&c)?;
        let ais: BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *tid && a.ak.as_str() == ak).map(|(i, _)| i).collect();
        Some((c, ais))
    }

    /// Every applied commit with a valid delta on `(tid, ak)`, with its aspects there.
    pub fn aspect_commits(&self, tid: &Tid, ak: &str) -> Vec<(CommitId, BTreeSet<usize>)> {
        let Some(held) = Ak::new(ak).ok().and_then(|k| self.core.ix.by_aspect.get(&(*tid, k))) else { return Vec::new() };
        let mut out = Vec::new();
        for (_, c) in held {
            let Some(m) = self.core.ix.commits.get(c).filter(|_| !self.core.ix.pending.contains_key(c)) else { continue };
            let ais: BTreeSet<usize> = m.header.aspects.iter().enumerate().filter(|(i, a)| a.tid == *tid && a.ak.as_str() == ak && m.valid_at(*i)).map(|(i, _)| i).collect();
            if !ais.is_empty() {
                out.push((*c, ais));
            }
        }
        out
    }

    /// The holders each `roles.0` or `secrets.0` aspect of applied role commit `c` is
    /// about (spec/sync.md §3): those whose edge a `roles.0` delta writes, those a `secrets.0`
    /// delta boxes. Empty for any other commit kind.
    pub fn holders_named(&mut self, c: &CommitId) -> Arc<BTreeMap<usize, BTreeSet<Tid>>> {
        if let Some(n) = self.core.holders_named.get(c).cloned() {
            #[cfg(debug_assertions)]
            if self.recheck(format!("holders_named {c:?}")) {
                assert_eq!(*n, self.holders_named_read(c), "holders_named of {c:?} went stale");
            }
            return n;
        }
        let _s = crate::costs::span("holders named: read");
        let n = Arc::new(self.holders_named_read(c));
        self.core.holders_named.insert(*c, n.clone());
        n
    }

    fn holders_named_read(&mut self, c: &CommitId) -> BTreeMap<usize, BTreeSet<Tid>> {
        let mut out: BTreeMap<usize, BTreeSet<Tid>> = BTreeMap::new();
        let Some(h) = self.header(c) else { return out };
        if !h.kind.is_role() {
            return out;
        }
        let id = *c;
        let keep = |ai: usize| h.aspects.get(ai).is_some_and(|a| matches!(a.ak.as_str(), "roles.0" | "secrets.0"));
        let Ok(parts) = self.run(|tx| crate::apply::held_parts_at(tx, &id, &keep)) else { return out };
        for (ai, _, d) in parts {
            let (Some(a), Decoded::Delta(d)) = (h.aspects.get(ai), &d) else { continue };
            let named: Vec<Tid> = match a.ak.as_str() {
                "roles.0" => crate::apply::validity::edge_holders(&self.core, &a.tid, &d.fragment),
                _ => crate::apply::keys::secrets_write(&d.fragment).boxes.into_keys().map(|k| k.holder).collect(),
            };
            out.entry(ai).or_default().extend(named);
        }
        out
    }

    /// Whether commit `c` gave this node a read secret of `t` (an inbox payload's label is
    /// followed only for such a thing, spec/sync.md §3): applied with a valid `secrets.0` delta
    /// on `t`, or held pending with a reading-only read candidate from it (its box opened).
    pub fn boxed_by(&self, c: &CommitId, t: &Tid) -> bool {
        if let Some(m) = self.core.ix.commits.get(c) {
            return m.header.aspects.iter().enumerate().any(|(i, a)| a.tid == *t && a.ak.as_str() == "secrets.0" && m.valid_at(i));
        }
        self.core.ix.pending.contains_key(c)
            && self.core.ix.secrets.get(t).is_some_and(|e| e.role(osis_base::Role::Read).epochs().any(|(_, i)| i.reading.iter().any(|u| u.commit == *c)))
    }

    /// The deltas of roster snapshot `c` on `things` a chain needs (spec/permissions.md §6):
    /// those naming one of `holders`, and those naming nobody (the reset alone). None when the
    /// commit cannot be read here (diagnostic): never the whole roster.
    pub(crate) fn snapshot_parts(&mut self, c: &CommitId, things: &BTreeSet<Tid>, holders: &BTreeSet<Tid>) -> Parts {
        let all = self.parts_of(c, things, &["roles.0", "tenures.0"]);
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
            let named = crate::apply::validity::named_holders(a.ak.as_str(), &d.fragment);
            if named.is_empty() || named.iter().any(|m| holders.contains(m)) {
                out.insert((ai, di));
            }
        }
        out
    }

    /// This node's chain certificates for `g` and its node card (spec/permissions.md §4), as
    /// commits with the parts to carry; a roster snapshot projected to the chain's holders.
    pub fn certificates(&mut self, g: &Tid) -> BTreeMap<CommitId, Parts> {
        let me = self.tid();
        let mut out: BTreeMap<CommitId, Parts> = BTreeMap::new();
        let mut add = |c: CommitId, parts: Parts| {
            if !parts.is_empty() {
                out.entry(c).or_default().extend(parts);
            }
        };
        let mine = BTreeSet::from([me]);
        for ak in CARD.iter().chain(["created.0"].iter()) {
            if let Some(c) = self.latest_on(&me, ak) {
                add(c, self.parts_of(&c, &mine, &[ak]));
            }
        }
        // the owner chain's `created.0` records
        for t in self.core.owner_chain(g).filter_map(|s| s.thing()) {
            if let Some(c) = self.latest_on(&t, "created.0") {
                add(c, self.parts_of(&c, &BTreeSet::from([t]), &["created.0"]));
            }
        }
        if let Some(tl) = self.core.timelines.get(g) {
            let certs = tl.certificates(&me, g);
            self.cert_parts(&certs, &mut out);
        }
        // and to each actor it has acted for (`validity::acts_for`): usually on the chain to
        // `g` already, the node reaching `g` through it
        for a in self.core.acting().iter() {
            let certs = self.chain_to(&me, a);
            self.cert_parts(&certs, &mut out);
        }
        out
    }

    /// The commits of `t`'s current `keys.0` (spec/permissions.md §4): the newest, and the rotation
    /// commits of its newest keyset per role, forks included. The newest may be an inbox write
    /// carrying no keyset, and a rotation of what `t` holds names `t`'s keyset (spec/crypto.md §4).
    pub fn current_keys(&self, t: &Tid) -> BTreeSet<CommitId> {
        let mut newest: BTreeMap<osis_base::Role, (u64, BTreeSet<CommitId>)> = BTreeMap::new();
        for (r, e) in self.core.ix.keyset_epochs.get(t).into_iter().flatten() {
            let Some((_, c)) = self.core.ix.epoch_intro.get(&(*t, *r, *e)) else { continue };
            let n = newest.entry(*r).or_default();
            if e.n() > n.0 {
                *n = (e.n(), BTreeSet::new());
            }
            if e.n() == n.0 {
                n.1.insert(*c);
            }
        }
        newest.into_values().flat_map(|(_, c)| c).chain(self.latest_on(t, "keys.0")).collect()
    }

    /// `node`'s chain certificates for `t` with the owner chains of both up to their key
    /// actors or ownerless things, timeline or not.
    fn chain_to(&self, node: &Tid, t: &Tid) -> osis_perm::Certificates {
        let mut cs = match self.core.timelines.get(t) {
            Some(tl) => tl.certificates(node, t),
            None => osis_perm::Certificates::default(),
        };
        for x in [t, node] {
            for step in self.core.owner_chain(x) {
                match step {
                    ChainStep::Up { thing, .. } | ChainStep::Ownerless { thing, .. } => {
                        cs.created.insert(thing);
                        cs.keys.insert(thing);
                    }
                    ChainStep::Key(y) | ChainStep::Unknown(y) => {
                        cs.created.insert(y);
                    }
                    ChainStep::TooDeep => {}
                }
            }
        }
        cs
    }

    /// What a verifier needs beside `parts` of commit `c` to judge them (spec/permissions.md
    /// §4): its author's chain certificates to each thing the parts touch and to its actor
    /// (`validity::acts_for`), minus `parts` themselves. `None` when `c` is not applied here: a
    /// node that cannot verify it cannot tell.
    pub fn author_chain(&mut self, c: &CommitId, parts: &Parts) -> Option<BTreeMap<CommitId, Parts>> {
        if self.core.ix.pending.contains_key(c) {
            return None;
        }
        let h = self.core.ix.commits.get(c)?.header.clone();
        let mut things: BTreeSet<Tid> = parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| a.tid).collect();
        things.insert(h.actor);
        let found: Vec<osis_perm::Certificates> = things.iter().chain([&h.author]).map(|t| self.chain_to(&h.author, t)).collect();
        let mut out = BTreeMap::new();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        if let Some(p) = out.get_mut(c) {
            p.retain(|x| !parts.contains(x));
        }
        out.retain(|_, p| !p.is_empty());
        Some(out)
    }

    /// The commits and parts certificates `certs` name (spec/permissions.md §4), added to `out`:
    /// edge writes projected to their edge deltas on the chain's things, roster snapshots to
    /// their holders' entries, the newest `created.0` of each thing and the current `keys.0` of each actor.
    fn cert_parts(&mut self, certs: &osis_perm::Certificates, out: &mut BTreeMap<CommitId, Parts>) {
        let mut add = |c: CommitId, parts: Parts| {
            if !parts.is_empty() {
                out.entry(c).or_default().extend(parts);
            }
        };
        let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
        for c in &certs.commits {
            add(*c, self.parts_of(c, &all, &["roles.0", "tenures.0"]));
        }
        for (c, holders) in &certs.snapshots {
            add(*c, self.snapshot_parts(c, &all, holders));
        }
        for t in &certs.created {
            if let Some(c) = self.latest_on(t, "created.0") {
                add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["created.0"]));
            }
        }
        for t in &certs.keys {
            for c in self.current_keys(t) {
                add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["keys.0"]));
            }
        }
    }

    /// Revokes of the departures inside holders of `actor` that leave its epochs uncovered now
    /// (`rotation::uncovered_departures`: a departure from M, the last actor on its chain, with
    /// secrets of its own and outside `closure`; the newest applied write lowering the departed
    /// holder's edge on M), each the whole write on M with what judges it, and the current `keys.0`
    /// commits of each actor on the chain, projected to that `keys.0`, with its author's chain: the only
    /// certificates a node that may not rotate places under such an epoch (spec/permissions.md
    /// §4). A departure by `until` has no write and places only the keysets.
    pub fn inside_holder_revokes(&mut self, actor: &Tid, closure: &BTreeSet<Tid>) -> BTreeMap<CommitId, Parts> {
        let a = *actor;
        let deps = self.run(|tx| crate::rotation::uncovered_departures(tx, &a)).unwrap_or_default();
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        let mut whole: Vec<(CommitId, Tid)> = Vec::new();
        let mut keyed: BTreeSet<Tid> = BTreeSet::new();
        for d in deps {
            // the actor left: the last on the chain (A's holder via[0] is the first)
            let Some(m) = d.via.last().copied() else { continue };
            let leaver = d.holder;
            if closure.contains(&m) || !self.core.has_own_secrets(&m) {
                continue;
            }
            // each actor on the chain's newest keyset: a rotator holding none of its secrets seals
            // to it, and one rotated apart from the departure write is known only from its `keys.0`
            keyed.extend(d.via.iter().filter(|t| !closure.contains(t)).copied());
            let Some(tl) = self.core.timelines.get(&m) else { continue };
            let mut newest: Option<(osis_base::Ts, osis_perm::WriteId, CommitId)> = None;
            for wid in tl.applied().keys() {
                let osis_perm::WriteId::Op(c, i) = wid else { continue };
                let Some(mc) = tl.role_commit(c) else { continue };
                let Some(op) = mc.ops.get(*i as usize) else { continue };
                if op.target != m || op.holder != leaver {
                    continue;
                }
                let old = tl.edges_at(Some(mc.point())).get(&op.holder, &op.target).map(|e| e.role);
                let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                if new < old && newest.as_ref().is_none_or(|(t, _, _)| mc.ts > *t) {
                    newest = Some((mc.ts, *wid, *c));
                }
            }
            if let Some((_, wid, c)) = newest
                && let Some(cs) = tl.write_certificates(&wid)
                && !whole.contains(&(c, m))
            {
                found.push(cs);
                whole.push((c, m));
            }
        }
        let mut out = BTreeMap::new();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        for t in keyed {
            for c in self.current_keys(&t) {
                if whole.contains(&(c, t)) {
                    continue;
                }
                // its `keys.0` delta, like a chain certificate's (not its boxes: a covered removal
                // that rotated it stays unplaced as a whole write)
                let p = self.parts_of(&c, &BTreeSet::from([t]), &["keys.0"]);
                for (x, q) in self.author_chain(&c, &p).unwrap_or_default() {
                    out.entry(x).or_default().extend(q);
                }
                out.entry(c).or_default().extend(p);
            }
        }
        // the whole write on M (its rotation's `keys.0` and `secrets.0` too: boxes sealed to M's
        // holders): a reader that syncs M waits for every delta of it (spec/commits.md §4)
        for (c, m) in whole {
            let p = self.parts_of(&c, &BTreeSet::from([m]), &["roles.0", "tenures.0", "keys.0", "secrets.0"]);
            if !p.is_empty() {
                out.entry(c).or_default().extend(p);
            }
        }
        out
    }

    /// Whether this node judges the parts `parts` of commit `c` valid (spec/permissions.md
    /// §5): applied, not pending, each aspect valid, and, for a role commit, each of its
    /// edge ops applied (an aspect is valid while any op on it is: the loser of a single-use
    /// redemption race keeps its valid removal of L beside its void grant).
    pub fn judged_valid(&self, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        if self.core.ix.pending.contains_key(c) || parts.iter().any(|(ai, _)| !m.valid_at(*ai)) {
            return false;
        }
        if !m.header.kind.is_role() {
            return true;
        }
        let targets: BTreeSet<Tid> = m.header.aspects.iter().filter(|a| crate::apply::validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect();
        targets.iter().all(|t| {
            let Some(tl) = self.core.timelines.get(t) else { return true };
            let Some(mc) = tl.role_commit(c) else { return true };
            mc.ops.iter().enumerate().filter(|(_, op)| op.target == *t).all(|(i, _)| u32::try_from(i).is_ok_and(|i| tl.is_applied(&osis_perm::WriteId::Op(*c, i))))
        })
    }

    /// Revokes and roster snapshots about `authors` (of entries seen under a label), with what
    /// a verifier needs to judge them as this node does (their own authors' chain certificates;
    /// spec/permissions.md §4): applied edge writes lowering an author's edge on a thing outside
    /// `closure` (inside it they are closure bodies), and roster snapshots of such things naming
    /// an author, projected to the authors. Keysets only of actors reading `actor`, the label's:
    /// its rotators seal to those; a verifier needs none, and a thing the author left has a fresh
    /// deposit seed that is not for the label's readers.
    pub fn revoke_certificates(&mut self, authors: &BTreeSet<Tid>, closure: &BTreeSet<Tid>, actor: &Tid) -> BTreeMap<CommitId, Parts> {
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        for m in authors {
            let Some(tl) = self.core.timelines.get(m) else { continue };
            for wid in tl.applied().keys() {
                let about = match wid {
                    osis_perm::WriteId::Op(c, i) => {
                        let Some(mc) = tl.role_commit(c) else { continue };
                        let Some(op) = mc.ops.get(*i as usize) else { continue };
                        if op.holder != *m || closure.contains(&op.target) {
                            continue;
                        }
                        let old = tl.edges_at(Some(mc.point())).get(&op.holder, &op.target).map(|e| e.role);
                        let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                        new < old
                    }
                    osis_perm::WriteId::Snapshot(c) => tl.roster_snapshot(c).is_some_and(|s| !closure.contains(&s.thing) && (s.roster.contains_key(m) || s.ledger.iter().any(|t| t.holder == *m))),
                };
                if !about {
                    continue;
                }
                if let Some(mut cs) = tl.write_certificates(wid) {
                    for holders in cs.snapshots.values_mut() {
                        holders.retain(|x| authors.contains(x));
                    }
                    cs.keys.retain(|t| self.core.may_read(t, actor));
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

    /// Applied writes lowering `x`'s edge on a thing inside `closure` (`x`'s label's closure)
    /// that `x`'s edge there has not been raised again since, with what judges them
    /// (spec/permissions.md §2, §4): `x`'s holders still holding the edge would re-upload the
    /// thing's bodies its delete-key holders drop. Also the commits whose own parts these are:
    /// placed though inside the closure (the label no longer carries them as bodies). Never a
    /// `secrets.0` or `keys.0` delta of such a commit (`cert_parts` takes its `roles.0` and
    /// `tenures.0`).
    pub fn removal_certificates(&mut self, x: &Tid, closure: &BTreeSet<Tid>) -> (BTreeMap<CommitId, Parts>, BTreeSet<CommitId>) {
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        let mut own = BTreeSet::new();
        if let Some(tl) = self.core.timelines.get(x) {
            let current = tl.edges_at(None);
            for wid in tl.applied().keys() {
                let osis_perm::WriteId::Op(c, i) = wid else { continue };
                let Some(mc) = tl.role_commit(c) else { continue };
                let Some(op) = mc.ops.get(*i as usize) else { continue };
                if op.holder != *x || !closure.contains(&op.target) {
                    continue;
                }
                let old = tl.edges_at(Some(mc.point())).get(&op.holder, &op.target).map(|e| e.role);
                let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                let now = current.get(&op.holder, &op.target).map(|e| e.role);
                if new < old && now <= new
                    && let Some(cs) = tl.write_certificates(wid)
                {
                    own.insert(*c);
                    found.push(cs);
                }
            }
        }
        let mut out = BTreeMap::new();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        // the thing's newest `keys.0` is often the removal's own (its fresh deposit seed)
        for c in &own {
            let Some(h) = self.header(c) else { continue };
            if let Some(p) = out.get_mut(c) {
                p.retain(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| crate::apply::validity::edge_ak(a.ak.as_str())));
            }
        }
        (out, own)
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
        let role_commit = cut.header.kind.is_role();
        let resolved = match self.core.ix.commits.get(&id) {
            Some(m) if !cut.header.is_resolved() => m.header.arc(),
            _ => std::sync::Arc::new(cut.header.clone()),
        };
        let order = super::fetch_order(&resolved);
        let ps = osis_commit::project_resolved(&cut, &resolved, |_| ())?;
        Ok(ps.into_iter().map(|p| Body { commit: id, reader: self.tid(), parts: p.parts, expires: p.expires, keys: p.keys, blind: cut.header.blind, plaintext: p.plaintext, role_commit, order }).collect())
    }

    /// Blobs a certificate copy of `parts` of commit `c` needs beside its body (spec/sync.md
    /// §3): the trees of the header's linked lists (a demotion's frontier among them) and of the
    /// large values its deltas link (a roster snapshot's linked frontiers), as far as held.
    pub fn linked_blobs(&mut self, c: &CommitId, parts: &Parts) -> Result<BTreeSet<BlobId>> {
        let mut out = BTreeSet::new();
        let Some(h) = self.header(c) else { return Ok(out) };
        let lists: Vec<osis_base::Link> = osis_commit::ListField::ALL.iter().filter_map(|f| h.links.get(*f).copied()).collect();
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
                d.fragment.values(&mut |v| crate::engine::large::links_in(v, &mut roots));
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
    use osis_base::{Ak, Role, Value, WallMs};
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
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let good = lp.peers[0].commit(m).unwrap().unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None, tied: None, keyset: None };
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
        assert_eq!(e.latest_by(&t, "x:a.0", None), Some(good));
        assert_eq!(e.latest_by(&t, "x:a.0", Some(&b)), None);
    }
}
