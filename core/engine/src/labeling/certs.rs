//! Certificate blobs (spec/permissions.md §4; spec/sync.md §3): this node's chain certificates
//! for a group and its node card as (commit, parts) to place, partial bodies of a commit and the
//! blobs its parts link.
//! Labels and steps are role flows' (`Engine::create_label`, `Engine::issue_step`).

use super::blobs::Body;
use crate::engine::memo::Memo;
use crate::engine::Engine;
use crate::error::Result;
use osis_commit::Decoded;
use osis_base::{Ak, BlobId, ChainStep, CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Aspects a node card holds (each its own commit, spec/permissions.md §4).
const CARD: [&str; 3] = ["keys.0", "node.0", "reach.0"];

/// Parts of a commit, by aspect index.
pub type Parts = BTreeSet<usize>;

/// Chain material a verifier needs (spec/permissions.md §4): parts of commits to copy, commits
/// to copy as headers alone (an ended actor's mintings), and raw creation records (a record
/// blob's), which outlive the commits that minted them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Certs {
    pub commits: BTreeMap<CommitId, Parts>,
    pub headers: BTreeSet<CommitId>,
    pub records: BTreeSet<Tid>,
}

impl Certs {
    fn add(&mut self, c: CommitId, parts: Parts) {
        if !parts.is_empty() {
            self.commits.entry(c).or_default().extend(parts);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.headers.is_empty() && self.records.is_empty()
    }

    /// Adds `other`'s commits, headers and records.
    pub fn extend(&mut self, other: Certs) {
        for (c, p) in other.commits {
            self.add(c, p);
        }
        self.headers.extend(other.headers);
        self.records.extend(other.records);
    }
}

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

    /// The parts of commit `c` on `(tid, ak)` for any of `aks`.
    fn parts_of(&self, c: &CommitId, tids: &BTreeSet<Tid>, aks: &[&str]) -> Parts {
        let Some(h) = self.header(c) else { return Parts::new() };
        h.aspects
            .iter()
            .enumerate()
            .filter(|(_, a)| tids.contains(&a.tid) && aks.contains(&a.ak.as_str()))
            .map(|(i, _)| i)
            .collect()
    }

    /// The newest held commit writing `(tid, ak)` with its aspect indexes there (a
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
        // parts the store refused to read name nobody now, and are read again at the next ask
        Memo::get_in(self, |e| &e.core.holders_named, c, |e| e.holders_named_read(c).map(Arc::new)).unwrap_or_default()
    }

    fn holders_named_read(&mut self, c: &CommitId) -> Result<BTreeMap<usize, BTreeSet<Tid>>> {
        let mut out: BTreeMap<usize, BTreeSet<Tid>> = BTreeMap::new();
        let Some(h) = self.header(c) else { return Ok(out) };
        if !h.kind.is_role() {
            return Ok(out);
        }
        let id = *c;
        let keep = |ai: usize| h.aspects.get(ai).is_some_and(|a| matches!(a.ak.as_str(), "roles.0" | "secrets.0"));
        let parts = self.run(|tx| crate::apply::held_parts_at(tx, &id, &keep))?;
        for (ai, d) in parts {
            let (Some(a), Decoded::Delta(d)) = (h.aspects.get(ai), &d) else { continue };
            let named: Vec<Tid> = match a.ak.as_str() {
                "roles.0" => crate::apply::validity::edge_holders(&self.core, &a.tid, &d.fragment),
                _ => crate::apply::keys::secrets_write(&d.fragment).boxes.into_keys().map(|k| k.holder).collect(),
            };
            out.entry(ai).or_default().extend(named);
        }
        Ok(out)
    }

    /// Whether commit `c` gave this node a read secret of `t` (an inbox payload's label is
    /// followed only for such a thing, spec/sync.md §3): applied with a valid `secrets.0` delta
    /// on `t`, or a reading-only read candidate from it (its box opened).
    pub fn boxed_by(&self, c: &CommitId, t: &Tid) -> bool {
        if let Some(m) = self.core.ix.commits.get(c) {
            return m.header.aspects.iter().enumerate().any(|(i, a)| a.tid == *t && a.ak.as_str() == "secrets.0" && m.valid_at(i));
        }
        self.core.ix.secrets.get(t).is_some_and(|e| e.role(osis_base::Role::Read).epochs().any(|(_, i)| i.reading.iter().any(|u| u.commit == *c)))
    }

    /// This node's chain certificates for `g`, its node card and the cards of the key actors
    /// holding `g` (spec/permissions.md §4): the commits with the parts to carry, and the records.
    pub fn certificates(&mut self, g: &Tid) -> Certs {
        let Some(me) = self.core.me() else { return Certs::default() };
        let mut out = Certs::default();
        // the account's card (the author of every commit but the node's own) and the node's
        for who in [me, self.tid()] {
            let mine = BTreeSet::from([who]);
            out.records.insert(who);
            for ak in CARD {
                if let Some(c) = self.latest_on(&who, ak) {
                    out.add(c, self.parts_of(&c, &mine, &[ak]));
                }
            }
        }
        // the account's signing chain, every line (spec/permissions.md §5.5, Chains travel)
        if self.core.is_account(&me)
            && let Ok(keys) = osis_base::Ak::new("keys.0")
        {
            let rots: Vec<CommitId> = self.core.ix.by_aspect.get(&(me, keys)).into_iter().flatten().map(|(_, c)| *c).filter(|c| self.core.ix.commits.get(c).is_some_and(|m| m.view.author == me && m.view.epoch.is_some()) && self.header(c).is_some_and(|h| h.rotation.is_some())).collect();
            let mine = BTreeSet::from([me]);
            for c in rots {
                out.add(c, self.parts_of(&c, &mine, &["keys.0"]));
            }
        }
        // the record chain's records
        out.records.extend(self.core.record_chain(g).filter_map(|s| s.thing()));
        // the ended things the label's closure needs told ended: on an authority path into it,
        // or listed or referenced there; their records and frozen permission history, which no
        // body under the label carries once their ending dropped their own (spec/permissions.md
        // §4, spec/commits.md §5 Ending)
        let needed = self.ended_needed(g).unwrap_or_else(|_| self.ended_upstream(g));
        for e in needed {
            out.records.insert(e);
            out.records.extend(self.core.record_chain(&e).filter_map(|s| s.thing()));
            let certs = self.history_certificates(&e);
            self.cert_parts(&certs, &mut out);
        }
        // the cards of the key actors holding `g` that are no node (a link key: its writes
        // under the label verify by its card, which no chain of this node's carries; a node
        // places its own)
        let keys: Vec<Tid> = self.core.roster_of(g).into_keys().filter(|k| *k != me && self.core.is_key_actor(k)).collect();
        for k in keys.into_iter().filter(|k| self.latest_on(k, "node.0").is_none()) {
            out.records.insert(k);
            if let Some(c) = self.latest_on(&k, "keys.0") {
                out.add(c, self.parts_of(&c, &BTreeSet::from([k]), &["keys.0"]));
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
        // every ended thing whose record goes, with what tells it ended
        let ended: Vec<Tid> = out.records.iter().filter(|t| self.core.ended(t)).copied().collect();
        for t in ended {
            self.ending_evidence(&t, &mut out);
        }
        out.records.retain(|t| self.core.created(t).is_some());
        out
    }

    /// The ended actors held here on an authority path into `g`'s closure (spec/commits.md §5
    /// Ending): named first admin or holder on a live thing of the closure, or on such an ended
    /// actor. A walk of the held holders, few beside the closure's things, and up from the
    /// ended ones among them.
    pub fn ended_upstream(&self, g: &Tid) -> BTreeSet<Tid> {
        let closure = self.closure(g);
        let held = &self.core.ix.held;
        let ended: Vec<Tid> = held.holders().filter(|e| self.core.ended(e)).copied().collect();
        let mut out = BTreeSet::new();
        // to a fixpoint: an ended actor counts once it is named on a live closure thing or on one counted
        loop {
            let more: Vec<Tid> = ended.iter().filter(|e| !out.contains(*e) && held.named_on(e).any(|x| x != *e && (closure.contains(x) && !self.core.ended(x) || out.contains(x)))).copied().collect();
            if more.is_empty() {
                return out;
            }
            out.extend(more);
        }
    }

    /// The ended things held here whose evidence the closure of `g` needs (spec/commits.md §5
    /// Ending, issues/thing-lifetimes.md What is kept): on an authority path into it
    /// (`ended_upstream`), or listed in `retainers^.0` or referenced in a live durable value by
    /// a live thing of it. O(kept ended things something needs and the reference rows naming
    /// them): bounded by live things, not by what ended.
    pub fn ended_needed(&mut self, g: &Tid) -> Result<BTreeSet<Tid>> {
        let mut out = self.ended_upstream(g);
        let closure = self.closure(g);
        for x in self.core.ended_kept() {
            crate::costs::count("ended needed: candidates", 1);
            if out.contains(&x) {
                continue;
            }
            let rows: Vec<_> = self.references_to(&x)?.into_iter().filter(|r| r.source != x && !r.ephemeral()).collect();
            if rows.iter().any(|r| closure.contains(&r.source) && self.core.exists(&r.source)) {
                out.insert(x);
            } else if rows.is_empty() && !crate::retention::end::dependents(&self.core, &x) {
                // needed by nothing held: no candidate until a reference to it comes (`end_ended`)
                self.core.note_ended_kept(&x, false);
            }
        }
        Ok(out)
    }

    /// What tells ended actor `t` ended, added to `out` (spec/commits.md §5 Ending): whatever
    /// lets a node judge `t`'s frozen history also tells it the ending (`cert_parts` adds it
    /// for every ended thing whose record goes). Each held minting and each held request
    /// dropping one, as a header alone: a minting's `expires` dates an expiry (a value-less part
    /// is never uploaded), a request's header names what it ends (`Header::requests`; `t`'s frozen
    /// history judges its right), and a header-only blob has no prefix expiry, so a release's
    /// copy outlives the request's own blobs (spec/sync.md §1). Each with its author's chains to
    /// `t` and to its actor. Once per `out`: its mintings among `out`'s headers.
    fn ending_evidence(&mut self, t: &Tid, out: &mut Certs) {
        let mintings: Vec<CommitId> = self.core.mintings(t).map(|(c, _)| c).collect();
        if mintings.iter().all(|c| out.headers.contains(c)) {
            return;
        }
        out.headers.extend(mintings.iter().copied());
        let requests = crate::retention::end::ending_requests(&self.core, t);
        out.headers.extend(requests.iter().copied());
        for c in mintings.iter().chain(&requests) {
            let Some(h) = self.header(c) else { continue };
            for x in [*t, h.actor, h.author] {
                let cs = self.chain_to(&h.author, &x);
                self.cert_parts(&cs, out);
            }
        }
    }

    /// What judges ended actor `t`'s permission history (spec/permissions.md §4): every held
    /// edge write on `t` with its write certificates (its author's chains, its holder's).
    fn history_certificates(&self, t: &Tid) -> osis_perm::Certificates {
        let mut out = osis_perm::Certificates::default();
        let Some(tl) = self.core.timelines.get(t) else { return out };
        for cm in self.core.ix.held.commits_on(t) {
            for (i, _) in cm.ops.iter().enumerate().filter(|(_, o)| o.target == *t) {
                let Some(cs) = u32::try_from(i).ok().and_then(|i| tl.write_certificates(&osis_perm::WriteId(cm.id, i))) else { continue };
                out.created.extend(cs.created);
                out.commits.extend(cs.commits);
                out.keys.extend(cs.keys);
            }
        }
        out
    }

    /// The commits of `t`'s current `keys.0` (spec/permissions.md §4): the newest, and the rotation
    /// commits of its newest keyset per role, forks included. The newest may be an inbox write
    /// carrying no keyset, and a rotation of what `t` holds names `t`'s keyset (spec/crypto.md §4).
    pub fn current_keys(&self, t: &Tid) -> BTreeSet<CommitId> {
        let mut newest: BTreeMap<osis_base::Role, (u64, BTreeSet<CommitId>)> = BTreeMap::new();
        for (r, e, _) in self.core.keysets_of(t) {
            let (r, e) = (&r, &e);
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

    /// `node`'s chain certificates for `t` with the record chains of both up to their key
    /// actors, timeline or not.
    pub(super) fn chain_to(&self, node: &Tid, t: &Tid) -> osis_perm::Certificates {
        let mut cs = match self.core.timelines.get(t) {
            Some(tl) => tl.certificates(node, t),
            None => osis_perm::Certificates::default(),
        };
        for x in [t, node] {
            for step in self.core.record_chain(x) {
                match step {
                    ChainStep::Up { thing, .. } => {
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
    pub fn author_chain(&mut self, c: &CommitId, parts: &Parts) -> Option<Certs> {
        if self.core.ix.pending.contains_key(c) {
            return None;
        }
        let h = self.core.ix.commits.get(c)?.header.clone();
        let mut things: BTreeSet<Tid> = parts.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| a.tid).collect();
        things.insert(h.actor);
        let found: Vec<osis_perm::Certificates> = things.iter().chain([&h.author]).map(|t| self.chain_to(&h.author, t)).collect();
        let mut out = Certs::default();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        if let Some(p) = out.commits.get_mut(c) {
            p.retain(|x| !parts.contains(x));
        }
        out.commits.retain(|_, p| !p.is_empty());
        out.records.retain(|t| self.core.created(t).is_some());
        Some(out)
    }

    /// The commits, parts and records certificates `certs` name (spec/permissions.md §4), added to
    /// `out`: edge writes projected to their edge deltas on the chain's things, the record of
    /// each thing and the current `keys.0` of each actor.
    pub(super) fn cert_parts(&mut self, certs: &osis_perm::Certificates, out: &mut Certs) {
        let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
        for c in &certs.commits {
            out.add(*c, self.parts_of(c, &all, &["roles.0"]));
        }
        out.records.extend(certs.created.iter().copied());
        for t in &certs.keys {
            for c in self.current_keys(t) {
                out.add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["keys.0"]));
            }
        }
        let ended: Vec<Tid> = certs.created.iter().filter(|t| self.core.ended(t)).copied().collect();
        for t in ended {
            self.ending_evidence(&t, out);
        }
    }

    /// Whether this node judges the parts `parts` of commit `c` valid (spec/permissions.md
    /// §5): applied, not pending, each aspect valid, and, for a role commit, each of its
    /// edge ops applied (an aspect is valid while any op on it is: the loser of a single-use
    /// redemption race keeps its valid removal of L beside its void grant).
    /// The parts of applied, not pending commit `c` valid here (`None`: not applied or pending).
    pub fn valid_parts(&self, c: &CommitId) -> Option<BTreeSet<usize>> {
        let m = self.core.ix.commits.get(c).filter(|_| !self.core.ix.pending.contains_key(c))?;
        Some((0..m.header.aspects.len()).filter(|ai| m.valid_at(*ai)).collect())
    }

    pub fn judged_valid(&self, c: &CommitId, parts: &[usize]) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        if self.core.ix.pending.contains_key(c) || parts.iter().any(|ai| !m.valid_at(*ai)) {
            return false;
        }
        if !m.header.kind.is_role() {
            return true;
        }
        let targets: BTreeSet<Tid> = m.header.aspects.iter().filter(|a| crate::apply::validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect();
        targets.iter().all(|t| {
            let Some(tl) = self.core.timelines.get(t) else { return true };
            let Some(mc) = tl.role_commit(c) else { return true };
            mc.ops.iter().enumerate().filter(|(_, op)| op.target == *t).all(|(i, _)| u32::try_from(i).is_ok_and(|i| tl.is_applied(&osis_perm::WriteId(*c, i))))
        })
    }

    /// Revokes about `authors` (of entries seen under a label), with what a verifier needs to judge
    /// them as this node does (their own authors' chain certificates; spec/permissions.md §4):
    /// applied edge writes lowering an author's edge on a thing outside `closure` (inside it they
    /// are closure bodies). Keysets only of actors reading `actor`, the label's:
    /// its rotators seal to those; a verifier needs none, and a thing the author left has a fresh
    /// deposit seed that is not for the label's readers.
    pub fn revoke_certificates(&mut self, authors: &BTreeSet<Tid>, closure: &BTreeSet<Tid>, actor: &Tid) -> Certs {
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        for m in authors {
            let Some(tl) = self.core.timelines.get(m) else { continue };
            for wid in tl.applied().keys() {
                let Some(mc) = tl.role_commit(&wid.0) else { continue };
                let Some(op) = mc.ops.get(wid.1 as usize) else { continue };
                if op.holder != *m || closure.contains(&op.target) {
                    continue;
                }
                let old = tl.edges_at(Some(mc.point())).get(&op.holder, &op.target).map(|e| e.role);
                let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                if new >= old {
                    continue;
                }
                if let Some(mut cs) = tl.write_certificates(wid) {
                    cs.keys.retain(|t| self.core.may_read(t, actor));
                    found.push(cs);
                }
            }
        }
        let mut out = Certs::default();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        out.records.retain(|t| self.core.created(t).is_some());
        out
    }

    /// Applied writes lowering `x`'s edge on a thing inside `closure` (`x`'s label's closure)
    /// that `x`'s edge there has not been raised again since, with what judges them
    /// (spec/permissions.md §2, §4): `x`'s holders still holding the edge would re-upload the
    /// thing's bodies its delete-key holders drop. Also the commits whose own parts these are:
    /// placed though inside the closure (the label no longer carries them as bodies). Never a
    /// `secrets.0` or `keys.0` delta of such a commit (`cert_parts` takes its `roles.0`).
    pub fn removal_certificates(&mut self, x: &Tid, closure: &BTreeSet<Tid>) -> (Certs, BTreeSet<CommitId>) {
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        let mut own = BTreeSet::new();
        if let Some(tl) = self.core.timelines.get(x) {
            let current = tl.edges_at(None);
            for wid in tl.applied().keys() {
                let Some(mc) = tl.role_commit(&wid.0) else { continue };
                let Some(op) = mc.ops.get(wid.1 as usize) else { continue };
                if op.holder != *x || !closure.contains(&op.target) {
                    continue;
                }
                let old = tl.edges_at(Some(mc.point())).get(&op.holder, &op.target).map(|e| e.role);
                let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
                let now = current.get(&op.holder, &op.target).map(|e| e.role);
                if new < old && now <= new
                    && let Some(cs) = tl.write_certificates(wid)
                {
                    own.insert(wid.0);
                    found.push(cs);
                }
            }
        }
        let mut out = Certs::default();
        for cs in &found {
            self.cert_parts(cs, &mut out);
        }
        out.records.retain(|t| self.core.created(t).is_some());
        // the thing's newest `keys.0` is often the removal's own (its fresh deposit seed)
        for c in &own {
            let Some(h) = self.header(c) else { continue };
            if let Some(p) = out.commits.get_mut(c) {
                p.retain(|ai| h.aspects.get(*ai).is_some_and(|a| crate::apply::validity::edge_ak(a.ak.as_str())));
            }
        }
        (out, own)
    }

    /// The body of commit `c` restricted to `parts` (its plaintext holds those alone): a
    /// certificate copy. `None`: none of them held.
    pub fn part_body(&mut self, c: &CommitId, parts: &Parts) -> Result<Option<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let cut = osis_commit::rewrite(&blob, |ai| !parts.contains(&ai));
        if cut.parts.is_empty() {
            return Ok(None);
        }
        let resolved = self.resolved_header(&cut);
        Ok(Some(Body {
            commit: id,
            parts: cut.parts.iter().map(|p| p.ai).collect(),
            expires: osis_commit::blob_expiry(&resolved),
            blind: cut.header.blind,
            plaintext: cut.encode(),
            role_commit: cut.header.kind.is_role(),
            order: super::fetch_order(&resolved),
            to_label: false,
        }))
    }

    /// A header-only copy of held commit `c` (an ended actor's minting, `ending_evidence`): no
    /// part, so no expiry or commitments in its prefix (spec/sync.md §1), ordered by its `ts`
    /// (spec/crypto.md §5).
    pub fn header_body(&self, c: &CommitId) -> Option<Body> {
        let h = self.core.ix.commits.get(c).map(|m| m.header.clone())?;
        Some(Body { commit: *c, parts: Vec::new(), expires: None, blind: h.blind, plaintext: Vec::new(), role_commit: h.kind.is_role(), order: h.ts.to_u64().max(1), to_label: false })
    }

    /// Blobs a certificate copy of `parts` of commit `c` needs beside its body (spec/sync.md
    /// §3): the trees of the header's linked lists (a demotion's frontier among them) and of the
    /// large values its deltas link, as far as held.
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
            for (ai, d) in crate::apply::held_parts_at(tx, &id, &|ai| parts.contains(&ai))? {
                let (Some(a), Decoded::Delta(d)) = (h.aspects.get(ai), &d) else { continue };
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
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let b = lp.peers[1].engine.me();
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let good = lp.peers[0].commit(m).unwrap().unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
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
