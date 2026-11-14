//! Certificate blobs (spec/permissions.md §4; spec/sync-judgement.md §1): this node's chain certificates
//! for a group and its node card as (commit, parts) to place, partial bodies of a commit and the
//! blobs its parts link.
//! Labels come with secrets of their own (`rotation::own_secrets`), steps by sync once their rotations are logged (`Engine::due_step`, `issue_due_step`).

use super::blobs::Body;
use osis_base::memo::Memo;
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
/// to copy as headers alone (the mintings of things whose records go), and raw creation records (a record
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
        self.latest_where(tid, ak, |c| author.is_none_or(|a| self.core.ix.commits.get(c).is_some_and(|m| m.header.author == *a)))
    }

    /// `latest_on` among the commits `keep` passes.
    fn latest_where(&self, tid: &Tid, ak: &str, keep: impl Fn(&CommitId) -> bool) -> Option<CommitId> {
        let k = Ak::new(ak).ok()?;
        let held = self.core.ix.by_aspect.get(&(*tid, k))?;
        held.iter().rev().map(|(_, c)| *c).find(|c| {
            let Some(m) = self.core.ix.commits.get(c) else { return false };
            !self.core.ix.pending.contains_key(c) && keep(c) && m.view.aspect(tid, ak).is_some_and(|i| m.valid_at(i))
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
    /// grantee's certificate copy names a thing's `label.0` and `created.0`, spec/sync-inbox.md §5).
    pub fn aspect_commit(&self, tid: &Tid, ak: &str) -> Option<(CommitId, BTreeSet<usize>)> {
        let c = self.latest_on(tid, ak)?;
        let h = self.header(&c)?;
        let ais: BTreeSet<usize> = h.aspect_index(tid, ak).into_iter().collect();
        Some((c, ais))
    }

    /// Every applied commit with a valid delta on `(tid, ak)`, with its aspects there.
    pub fn aspect_commits(&self, tid: &Tid, ak: &str) -> Vec<(CommitId, BTreeSet<usize>)> {
        let Some(held) = Ak::new(ak).ok().and_then(|k| self.core.ix.by_aspect.get(&(*tid, k))) else { return Vec::new() };
        let mut out = Vec::new();
        for (_, c) in held {
            let Some(m) = self.core.ix.commits.get(c).filter(|_| !self.core.ix.pending.contains_key(c)) else { continue };
            let ais: BTreeSet<usize> = m.view.aspect(tid, ak).filter(|i| m.valid_at(*i)).into_iter().collect();
            if !ais.is_empty() {
                out.push((*c, ais));
            }
        }
        out
    }

    /// The holders each `roles.0` or `secrets.0` aspect of applied role commit `c` is
    /// about (spec/sync-inbox.md §5): those whose edge a `roles.0` delta writes, those a `secrets.0`
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
        let parts = self.read(|tx| crate::apply::held_parts_at(tx, &id, &keep))?;
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

    /// This node's chain certificates for `g`, its node card and the cards of the key actors
    /// holding `g` (spec/permissions.md §4): the commits with the parts to carry, and the records.
    pub fn certificates(&mut self, g: &Tid) -> Certs {
        let Some(me) = self.core.me() else { return Certs::default() };
        let mut out = Certs::default();
        // the account's card (the author of every commit but the node's own) and, under D's
        // home alone, the node's (nothing of a node goes under another sync ID)
        let under_d = self.core.account_devices().is_some_and(|(_, d)| d == *g);
        for who in std::iter::once(me).chain(under_d.then(|| self.tid())) {
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
        // the destroyed things the label's closure needs told destroyed: on an authority path into it,
        // or listed or referenced there; their records and frozen permission history, which no
        // body under the label carries once their destruction dropped their own (spec/permissions.md
        // §4, spec/commits.md §5 Destruction)
        let needed = self.destroyed_needed(g).unwrap_or_else(|_| self.destroyed_upstream(g));
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
        let certs = self.core.timelines.certificates(&me, g);
        self.cert_parts(&certs, &mut out);
        // and to each actor it has acted for (`validity::acts_for`): usually on the chain to
        // `g` already, the node reaching `g` through it
        for a in self.core.acting().iter() {
            let certs = self.chain_to(&me, a);
            self.cert_parts(&certs, &mut out);
        }
        // every thing whose record goes, with its mintings (and a destroyed one's destruction)
        let records: Vec<Tid> = out.records.iter().copied().collect();
        for t in records {
            self.minting_evidence(&t, &mut out);
        }
        out.records.retain(|t| self.core.created(t).is_some());
        out
    }

    /// What a sync ID of `g` holds as certificates, whoever logs them (spec/permissions.md §4,
    /// spec/sync-judgement.md §2): the union of `g`'s pieces (`Piece`): `g`'s own
    /// (`own_piece`); the author's chain of each held commit on a thing of `g`'s closure its actor
    /// may read, which goes with the commit (`certificate_authors`, `chain_piece`); and under an
    /// actor's inbox its grant copies (`grant_copy`, one per thing it is named on). Nothing else:
    /// a chain into an item of the closure that no write there needs (a private group's roster
    /// holding a role on an item under S) is none of S's readers'. Parts the closure's bodies carry
    /// are `sync_bodies`' to leave out. Derived whole, O(all of it): what sync reads is
    /// `sync::certified`, kept per piece; this is what it is checked against.
    #[cfg(test)]
    pub(crate) fn sync_certificates(&mut self, g: &Tid) -> Certs {
        let mut out = self.own_piece(g);
        for (a, x) in self.certificate_authors(g) {
            out.extend(self.chain_piece(&a, &x));
        }
        for a in self.inbox_actors_of(g) {
            let things: Vec<Tid> = self.core.ix.held.named_on(&a).filter(|t| **t != a).copied().collect();
            for t in things {
                out.extend(self.grant_copy(&a, &t));
            }
        }
        out
    }

    /// `g`'s own certificates as a read thing (`sync_certificates`): this node's own
    /// (`certificates`); every node's chain certificates for `g`, which each node syncing it logs
    /// (`Timelines::certificates_into` `g`: what ever reaches it); and under D's home every card
    /// commit of D's other nodes. Reads role commits, records and cards, never content.
    pub(crate) fn own_piece(&mut self, g: &Tid) -> Certs {
        let mut out = self.certificates(g);
        let found = self.core.timelines.certificates_into(g);
        self.cert_parts(&found, &mut out);
        if self.core.account_devices().is_some_and(|(_, d)| d == *g) {
            let me = self.tid();
            for (n, _) in self.core.key_holders(g) {
                if n == me || !self.is_node(&n).unwrap_or(false) {
                    continue;
                }
                for ak in CARD {
                    let Ok(k) = Ak::new(ak) else { continue };
                    let held: Vec<CommitId> = self.core.ix.by_aspect.get(&(n, k)).into_iter().flatten().map(|x| x.1).collect();
                    for c in held {
                        let Some(h) = self.header(&c) else { continue };
                        if h.author == n && h.aspects.iter().all(|a| a.tid == n && CARD.contains(&a.ak.as_str())) {
                            out.add(c, (0..h.aspects.len()).collect());
                        }
                    }
                }
            }
        }
        out
    }

    /// Author `a`'s chain certificates for `x` (spec/permissions.md §4, a commit's author's
    /// chain), the parts and records they name: read from the paths into `x` alone
    /// (`Timelines::certificates`).
    pub(crate) fn chain_piece(&mut self, a: &Tid, x: &Tid) -> Certs {
        let mut out = Certs::default();
        let found = self.core.timelines.certificates(a, x);
        self.cert_parts(&found, &mut out);
        out
    }

    /// The (author, thing) pairs whose author's chain goes under a sync ID of `g` with the
    /// author's writes (spec/permissions.md §4, a commit's author's chain): each author of a held
    /// commit on a thing of `g`'s closure its actor may read (`Indexes::authors_on`). A commit
    /// acting for another actor needs no more: the author's chain to the thing runs through it.
    /// A node author's chain (its card) goes under D's home alone, with D's nodes' cards.
    #[cfg(test)]
    fn certificate_authors(&mut self, g: &Tid) -> Vec<(Tid, Tid)> {
        let ctx = self.body_ctx(g);
        let things: Vec<Tid> = ctx.closure.iter().filter(|t| self.reads(&ctx, t)).copied().collect();
        let pairs: Vec<(Tid, Tid)> = things.into_iter().flat_map(|x| self.core.ix.authors_on.get(&x).into_iter().flatten().map(move |a| (*a, x)).collect::<Vec<_>>()).collect();
        pairs.into_iter().filter(|(a, _)| !self.is_node(a).unwrap_or(false)).collect()
    }

    /// The actors whose inbox (spec/sync-inbox.md §1) is a sync ID `g` owns.
    pub(crate) fn inbox_actors_of(&mut self, g: &Tid) -> Vec<Tid> {
        let Ok(owned) = self.owned_sync_ids(g) else { return Vec::new() };
        let mut out: Vec<Tid> = owned.iter().flat_map(|o| self.inbox_actors_at(&o.id)).collect();
        out.sort();
        out.dedup();
        out
    }

    /// Actor `a`'s grant copy for thing `t` (spec/sync-inbox.md §5), logged under `a`'s inbox: the
    /// newest edge write naming `a` on `t` the timeline applies (a removal included: it tells `a`'s
    /// other nodes the grant ended), projected as the grant's inbox blob projects it (spec/sync-
    /// inbox.md §2, `inbox_blob`): one boxing `a` gives its `secrets.0` part on `t`, with its
    /// `roles.0` part while `a` reads `t`; one not boxing `a` (a removal or lowering) its `roles.0`
    /// part, none when `a`'s edge was below read before it and `a` reads `t` neither now (a sync
    /// holder's). While `a` reads `t`, also what the blob carries beside it (`carried_chain`),
    /// every commit writing `t`'s `sync.0` with its author's chain, and `t`'s records with their
    /// mintings; below read, nothing more (a sync holder learns none of them, spec/sync-ids.md
    /// §2). Nothing for a commit not applied here. One per (actor, thing), read from `t`'s edges
    /// alone (`Timelines::on`): a newer write replaces it, and the older copy leaves the required
    /// set. Nothing unless its author held write on `a` at its `ts` (`posts_to`): a reader's grant
    /// to `a` reaches `a`'s holders by its inbox blob alone.
    pub fn grant_copy(&mut self, a: &Tid, t: &Tid) -> Certs {
        let mut out = Certs::default();
        // the newest applied edge write naming `a` on `t`, and whether `a` read `t` just before it
        let Some((c, read_before)) = self.core.timelines.on(t).and_then(|on| {
            let (_, c, _) = on.held().filter(|(w, _, o)| o.holder == *a && on.is_applied(w)).max_by_key(|(_, c, _)| c.point())?;
            Some((c.id, on.edge_at(a, Some(c.point())).is_some_and(|e| e.role >= osis_base::Role::Read)))
        }) else {
            return out;
        };
        if self.core.ix.pending.contains_key(&c) || !self.core.ix.commits.contains_key(&c) || !self.posts_to(&c, a) {
            return out;
        }
        let on = BTreeSet::from([*t]);
        let boxes = {
            let named = self.holders_named(&c);
            self.parts_of(&c, &on, &["secrets.0"]).iter().any(|ai| named.get(ai).is_some_and(|hs| hs.contains(a)))
        };
        let reads = self.core.role_now(a, t) >= Some(osis_base::Role::Read);
        let aks: &[&str] = match (boxes, reads) {
            // a lowering or removal of a reader; a sync holder's is sent none
            (false, _) if read_before || reads => &["roles.0"],
            (false, _) => return out,
            (true, true) => &["roles.0", "secrets.0"],
            (true, false) => &["secrets.0"],
        };
        let parts = self.parts_of(&c, &on, aks);
        if !reads {
            out.add(c, parts);
            return out;
        }
        let boxed = if boxes { on.clone() } else { BTreeSet::new() };
        let Some(chain) = self.carried_chain(&c, &parts, &boxed) else { return out };
        out.extend(chain);
        out.add(c, parts);
        for (x, ais) in self.aspect_commits(t, "sync.0") {
            if let Some(chain) = self.carried_chain(&x, &ais, &BTreeSet::new()) {
                out.extend(chain);
            }
            out.add(x, ais);
        }
        out.records.extend(self.core.record_chain(t).filter_map(|s| s.thing()));
        let records: Vec<Tid> = out.records.iter().copied().collect();
        for x in records {
            self.minting_evidence(&x, &mut out);
        }
        out.records.retain(|x| self.core.created(x).is_some());
        out
    }

    /// Whether commit `c` may post into actor `a`'s space (spec/requirements.md: posting into a
    /// shared space needs write on its actor): its author held write on `a` at `c`'s `ts`, as this
    /// node judges it, as promotion judges its author (spec/sync-inbox.md §4).
    fn posts_to(&self, c: &CommitId, a: &Tid) -> bool {
        self.header(c).is_some_and(|h| crate::engine::write::role_of(&self.core, &h.author, a, h.ts) >= Some(osis_base::Role::Write))
    }

    /// The author's chain an inbox blob of commit `c` carries for its `parts` (spec/wire.md §9
    /// position 2), and a grant copy with it (spec/sync-inbox.md §5): `author_chain` without any
    /// `keys.0` but the author's own, plus the current `keys.0` commits of each thing in `boxed`
    /// (those it boxes the recipient on), each projected to that delta, with their records.
    /// `None` while `c` is pending.
    pub(crate) fn carried_chain(&mut self, c: &CommitId, parts: &Parts, boxed: &BTreeSet<Tid>) -> Option<Certs> {
        let author = self.header(c)?.author;
        let mut certs = self.author_chain(c, parts)?;
        for (x, ps) in certs.commits.iter_mut() {
            let Some(h) = self.header(x) else { continue };
            ps.retain(|ai| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() != "keys.0" || a.tid == author));
        }
        certs.commits.retain(|_, p| !p.is_empty());
        for t in boxed {
            for k in self.current_keys(t) {
                if let Some(ai) = self.header(&k).and_then(|h| h.aspect_index(t, "keys.0")) {
                    certs.commits.entry(k).or_default().insert(ai);
                }
            }
            certs.records.insert(*t);
        }
        Some(certs)
    }

    /// The destroyed actors held here on an authority path into `g`'s closure (spec/commits.md §5
    /// Destruction): named first admin or holder on a live thing of the closure, or on such a destroyed
    /// actor. A walk of the held holders, few beside the closure's things, and up from the
    /// destroyed ones among them.
    pub fn destroyed_upstream(&self, g: &Tid) -> BTreeSet<Tid> {
        let closure = self.closure(g);
        let held = &self.core.ix.held;
        let destroyed: Vec<Tid> = held.holders().filter(|e| self.core.destroyed(e)).copied().collect();
        let mut out = BTreeSet::new();
        // to a fixpoint: a destroyed actor counts once it is named on a live closure thing or on one counted
        loop {
            let more: Vec<Tid> = destroyed.iter().filter(|e| !out.contains(*e) && held.named_on(e).any(|x| x != *e && (closure.contains(x) && !self.core.destroyed(x) || out.contains(x)))).copied().collect();
            if more.is_empty() {
                return out;
            }
            out.extend(more);
        }
    }

    /// The destroyed things held here whose evidence the closure of `g` needs (spec/commits.md §5
    /// Destruction, notes/lifetimes.md What is kept): on an authority path into it
    /// (`destroyed_upstream`), or listed in `retainers^.0` or referenced in a live durable value by
    /// a live thing of it. O(kept destroyed things something needs and the reference rows naming
    /// them): bounded by live things, not by what was destroyed.
    pub fn destroyed_needed(&mut self, g: &Tid) -> Result<BTreeSet<Tid>> {
        let mut out = self.destroyed_upstream(g);
        let closure = self.closure(g);
        for x in self.core.destroyed_kept() {
            osis_base::costs::count("destroyed needed: candidates", 1);
            if out.contains(&x) {
                continue;
            }
            let rows: Vec<_> = self.references_to(&x)?.into_iter().filter(|r| r.source != x && crate::retention::destroy::needs_from(&r.ak)).collect();
            if rows.iter().any(|r| closure.contains(&r.source) && self.core.exists(&r.source)) {
                out.insert(x);
            } else if rows.is_empty() && !crate::retention::destroy::dependents(&self.core, &x) {
                // needed by nothing held: no candidate until a reference to it comes (`apply_destructions`)
                self.core.note_destroyed_kept(&x, false);
            }
        }
        Ok(out)
    }

    /// What goes with `t`'s record, added to `out` (spec/commits.md §5, A thing's mintings travel
    /// with its record; `cert_parts` adds it for every thing whose record goes): its witness
    /// (`witness`) as a header alone and, destroyed, each held request destroying it. A node
    /// knowing `t` by its record so judges it live or destroyed, and when, as one holding every
    /// minting does: a minting again travels only while it is the witness, and only a right
    /// holder makes a request, so what a reader mints adds nothing. A minting's `expires` dates an
    /// expiry (a value-less part is never uploaded), a request's header names what it destroys
    /// (`Header::requests`; `t`'s frozen history judges its right), and a header-only blob has no
    /// prefix expiry, so a release's copy outlives the request's own blobs (spec/sync-ids.md §1).
    /// Each with its author's chains to `t` and to its actor. Once per `out`: its witness among
    /// `out`'s headers.
    pub fn minting_evidence(&mut self, t: &Tid, out: &mut Certs) {
        let Some(w) = self.witness(t) else { return };
        if out.headers.contains(&w.commit) {
            return;
        }
        let requests = if w.standing.valued { BTreeSet::new() } else { crate::retention::destroy::destroying_requests(&self.core, t) };
        let evidence: Vec<CommitId> = std::iter::once(w.commit).chain(requests).collect();
        out.headers.extend(evidence.iter().copied());
        for c in &evidence {
            let Some(h) = self.header(c) else { continue };
            for x in [*t, h.actor, h.author] {
                // a header is judged by its author's edges and records; no keyset judges it
                let mut cs = self.chain_to(&h.author, &x);
                cs.keys.clear();
                self.cert_parts(&cs, out);
            }
        }
    }

    /// `t`'s witness (spec/commits.md §5, A thing's mintings travel with its record): its held
    /// minting destroyed last, valued ones last of all, ties by the lowest commit ID.
    pub fn witness(&self, t: &Tid) -> Option<crate::retention::Minting> {
        crate::retention::destroy::witness(&self.core, t)
    }

    /// Every held minting of `t` with its standing (`witness` is the highest).
    pub fn mintings_of(&self, t: &Tid) -> Vec<crate::retention::Minting> {
        crate::retention::destroy::mintings(&self.core, t)
    }

    /// What judges destroyed actor `t`'s permission history (spec/permissions.md §4): every held
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

    /// The commits of `t`'s current `keys.0` (spec/permissions.md §4): the newest, the rotation
    /// commits of its newest keyset per role, forks included, and the commits recording boxes
    /// at those keysets' epochs (spec/crypto.md §4, Stale: a grant's or re-seal's to a holder
    /// actor). The newest may be an inbox write carrying no keyset, and a rotation of what `t`
    /// holds names `t`'s keyset (spec/crypto.md §4).
    pub fn current_keys(&self, t: &Tid) -> BTreeSet<CommitId> {
        // per role: the newest n, its keysets' rotation commits, the commits recording boxes there
        let mut newest: BTreeMap<osis_base::Role, (u64, BTreeSet<CommitId>, BTreeSet<CommitId>)> = BTreeMap::new();
        let mut intros = BTreeSet::new();
        for (r, e, _) in self.core.keysets_of(t) {
            let (r, e) = (&r, &e);
            let Some((_, c)) = self.core.ix.epoch_intro.get(&(*t, *r, *e)) else { continue };
            intros.insert(*c);
            let n = newest.entry(*r).or_default();
            if e.n() > n.0 {
                *n = (e.n(), BTreeSet::new(), BTreeSet::new());
            }
            if e.n() == n.0 {
                n.1.insert(*c);
                n.2.extend(self.core.ix.sealed.get(&(*t, *r, *e)).into_iter().flat_map(|x| x.by.iter().copied()));
            }
        }
        let rotations: BTreeSet<CommitId> = newest.values().flat_map(|x| x.1.iter().copied()).collect();
        let records: BTreeSet<CommitId> = newest.values().flat_map(|x| x.2.iter().copied()).collect();
        // the newest but one writing only box records (a grant's or re-seal's, at any epoch): what
        // carries the inbox and deposit seed
        let recorders: BTreeSet<CommitId> = self.core.sealed_noted(t).flat_map(|x| x.2.by.iter().copied()).collect();
        let card = self.latest_where(t, "keys.0", |c| intros.contains(c) || !recorders.contains(c));
        rotations.iter().chain(&records).copied().chain(card).collect()
    }

    /// `node`'s chain certificates for `t` with the record chains of both up to their key
    /// actors, timeline or not.
    pub(super) fn chain_to(&self, node: &Tid, t: &Tid) -> osis_perm::Certificates {
        let mut cs = self.core.timelines.certificates(node, t);
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
        // a keyset is held only with the demotions it carries (spec/crypto.md §4, Carried
        // demotions)
        for t in parts.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.ak.as_str() == "keys.0").map(|a| a.tid).collect::<Vec<_>>() {
            self.carried_demotions(&t, c, &mut out);
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
    /// each thing and the current `keys.0` of each actor, with the demotions its keysets carry.
    pub(super) fn cert_parts(&mut self, certs: &osis_perm::Certificates, out: &mut Certs) {
        let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
        for c in &certs.commits {
            out.add(*c, self.parts_of(c, &all, &["roles.0"]));
        }
        out.records.extend(certs.created.iter().copied());
        for t in &certs.keys {
            for c in self.current_keys(t) {
                out.add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["keys.0"]));
                self.carried_demotions(t, &c, out);
            }
        }
        for t in &certs.created {
            self.minting_evidence(t, out);
        }
    }

    /// The demotions the keysets of `t` that commit `c` introduces carry (spec/crypto.md §4,
    /// Carried demotions): each listed commit's `roles.0` parts with its author's chains, and
    /// `c`'s own `roles.0` parts where a keyset says `c` demotes, added to `out`: a receiver holds
    /// those keysets only with them. Each demotion's chain once per `out` (a chain may name a
    /// keyset carrying it back: holder actors may form a cycle).
    fn carried_demotions(&mut self, t: &Tid, c: &CommitId, out: &mut Certs) {
        let mut carried: BTreeSet<CommitId> = BTreeSet::new();
        for (r, e, x) in self.core.keysets_noted(t) {
            if self.core.ix.epoch_intro.get(&(*t, r, e)).is_some_and(|i| i.1 == *c) {
                carried.extend(x.demotions.iter().copied());
                if x.demotes {
                    carried.insert(*c);
                }
            }
        }
        for d in carried {
            let Some(h) = self.header(&d) else { continue };
            let things: BTreeSet<Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "roles.0").map(|a| a.tid).collect();
            let parts = self.parts_of(&d, &things, &["roles.0"]);
            let fresh = !out.commits.get(&d).is_some_and(|p| parts.is_subset(p));
            out.add(d, parts);
            if !fresh {
                continue;
            }
            for x in things.into_iter().chain([h.actor]) {
                let cs = self.chain_to(&h.author, &x);
                self.cert_parts(&cs, out);
            }
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
        judged_valid(&self.core, c, parts)
    }

    /// Revokes about `authors` (of entries seen under a label of `ctx`'s group), with what a
    /// verifier needs to judge them as this node does (their own authors' chain certificates;
    /// spec/permissions.md §4): applied edge writes lowering an author's edge on a thing whose
    /// parts the label's bodies do not carry (`body_carried`). Keysets only of actors reading the
    /// label's actor: its rotators seal to those; a verifier needs none, and a thing the author
    /// left has a fresh deposit seed that is not for the label's readers.
    pub fn revoke_certificates(&mut self, authors: &BTreeSet<Tid>, ctx: &super::BodyCtx) -> Certs {
        let actor = &ctx.actor;
        let mut found: Vec<osis_perm::Certificates> = Vec::new();
        for m in authors {
            let Some(tl) = self.core.timelines.get(m) else { continue };
            for wid in tl.applied().keys() {
                let Some(mc) = tl.role_commit(&wid.0) else { continue };
                let Some(op) = mc.ops.get(wid.1 as usize) else { continue };
                if op.holder != *m || ctx.closure.contains(&op.target) && self.reads(ctx, &op.target) {
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
    /// thing's bodies its delete-key holders drop. Never a `secrets.0` or `keys.0` delta of such
    /// a removal's own commit (`cert_parts` takes its `roles.0`).
    pub fn removal_certificates(&mut self, x: &Tid, closure: &BTreeSet<Tid>) -> Certs {
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
        out
    }

    /// The body of commit `c` restricted to `parts` (its plaintext holds those alone): a
    /// certificate copy. `None`: none of them held.
    pub fn part_body(&mut self, c: &CommitId, parts: &Parts) -> Result<Option<Body>> {
        let id = *c;
        let Some(blob) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
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

    /// A header-only copy of held commit `c` (a minting or a destroying request, `minting_evidence`): no
    /// part, so no expiry or commitments in its prefix (spec/sync-ids.md §1), ordered by its `ts`
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
        let found = self.read(|tx| {
            let mut found = BTreeSet::new();
            for (ai, d) in crate::apply::held_parts_at(tx, &id, &|ai| parts.contains(&ai))? {
                let (Some(a), Decoded::Delta(d)) = (h.aspects.get(ai), &d) else { continue };
                let mut roots = Vec::new();
                d.fragment.values(&mut |v| crate::engine::large::links_in(v, &mut roots));
                let Some(dedup) = tx.core.dedup(&a.tid) else { continue };
                let mut trees = crate::engine::large::Trees::default();
                crate::engine::large::tree_blobs(tx, &dedup, &roots, &mut trees)?;
                found.extend(trees.blobs);
            }
            Ok(found)
        })?;
        out.extend(found);
        Ok(out)
    }
}

/// `Engine::judged_valid`: parts `parts` of `c` are valid here and, for a role commit, every edge
/// write it makes is applied.
pub(crate) fn judged_valid(core: &crate::engine::Core, c: &CommitId, parts: &[usize]) -> bool {
    let Some(m) = core.ix.commits.get(c) else { return false };
    if core.ix.pending.contains_key(c) || parts.iter().any(|ai| !m.valid_at(*ai)) {
        return false;
    }
    if !m.header.kind.is_role() {
        return true;
    }
    let targets: BTreeSet<Tid> = m.header.aspects.iter().filter(|a| crate::apply::validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect();
    targets.iter().all(|t| {
        let Some(tl) = core.timelines.get(t) else { return true };
        let Some(mc) = tl.role_commit(c) else { return true };
        mc.ops.iter().enumerate().filter(|(_, op)| op.target == *t).all(|(i, _)| u32::try_from(i).is_ok_and(|i| tl.is_applied(&osis_perm::WriteId(*c, i))))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/permissions.md §4 (current `keys.0` commits; holder card): certificates and cards are the current valid writes, §5.2: a
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
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None, floor: None };
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
