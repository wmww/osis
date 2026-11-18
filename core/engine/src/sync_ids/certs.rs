//! Certificate blobs (spec/permissions.md §4; spec/sync-judgement.md §1): this node's chain certificates
//! for a thing with own keys and its node card as (commit, parts) to place, partial bodies of a commit and the
//! blobs its parts link.
//! Sync IDs come with secrets of their own (`rotation::own_secrets`), steps by sync once their rotations are logged (`Engine::due_step`, `issue_due_step`).

use super::blobs::Body;
use osis_base::memo::Memo;
use crate::engine::Engine;
use crate::error::Result;
use osis_commit::Decoded;
use osis_base::{Ak, ChainStep, CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Aspects a node card holds (each its own commit, spec/permissions.md §4).
const CARD: [&str; 3] = ["keys.0", "node.0", "reach.0"];

/// Parts of a commit, by aspect index.
pub type Parts = BTreeSet<usize>;

/// Chain material a verifier needs (spec/permissions.md §4): parts of commits to copy, commits
/// to copy as headers alone (the requests destroying things whose records go, an account's
/// rotations but its current `keys.0` commits), the held
/// mintings of things whose records go (each with those things: a header-only copy of each is
/// judged by its standing, spec/commits.md §5), and raw creation records (a record blob's),
/// which outlive the commits that minted them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Certs {
    pub commits: BTreeMap<CommitId, Parts>,
    pub headers: BTreeSet<CommitId>,
    pub mintings: BTreeMap<CommitId, BTreeSet<Tid>>,
    pub records: BTreeSet<Tid>,
    /// `Some` in a `sync::certified` piece (`Certs::deferring`): the accounts whose record, card
    /// and signing chain go too, not added here, each account's chain being one piece of its own
    /// (`account_piece`), so a rotation re-derives that piece alone. `None` in every other value:
    /// each account's chain is in it (`cert_parts`).
    pub accounts: Option<BTreeSet<Tid>>,
}

impl Certs {
    /// An empty value naming accounts rather than holding their chains (`accounts`).
    pub(crate) fn deferring() -> Certs {
        Certs { accounts: Some(BTreeSet::new()), ..Certs::default() }
    }

    /// Whether `t` is an account this value names rather than holds (`accounts`).
    fn defers(&self, t: &Tid) -> bool {
        self.accounts.as_ref().is_some_and(|a| a.contains(t))
    }

    fn add(&mut self, c: CommitId, parts: Parts) {
        if !parts.is_empty() {
            self.commits.entry(c).or_default().extend(parts);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.headers.is_empty() && self.mintings.is_empty() && self.records.is_empty() && self.accounts.as_ref().is_none_or(BTreeSet::is_empty)
    }

    /// Adds `other`'s commits, headers, mintings and records.
    pub fn extend(&mut self, other: Certs) {
        for (c, p) in other.commits {
            self.add(c, p);
        }
        self.headers.extend(other.headers);
        for (c, ts) in other.mintings {
            self.mintings.entry(c).or_default().extend(ts);
        }
        self.records.extend(other.records);
        match (&mut self.accounts, other.accounts) {
            (Some(a), Some(b)) => a.extend(b),
            (a @ None, Some(b)) => *a = Some(b),
            _ => {}
        }
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
                _ => crate::apply::keys::secrets_write(&d.fragment).boxes.into_keys().map(|k| k.holder.0).collect(),
            };
            out.entry(ai).or_default().extend(named);
        }
        Ok(out)
    }

    /// This node's chain certificates for `g`, its node card and the cards of the key actors
    /// holding `g` (spec/permissions.md §4): the commits with the parts to carry, and the records.
    /// What pairing hands a new node of the account; S's required set is `own_piece`.
    pub fn certificates(&mut self, g: &Tid) -> Certs {
        let Some(me) = self.core.me() else { return Certs::default() };
        let mut out = Certs::default();
        self.shared_certificates(g, &mut out);
        // the account's card (the author of every commit but the node's own) and, under D's
        // sync ID alone, the node's (nothing of a node goes under another sync ID)
        let under_d = self.core.account_and_root().is_some_and(|(_, d)| d == *g);
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
        self.account_chain(&me, &mut out);
        let certs = self.core.timelines.certificates(&me, g);
        self.cert_parts(&certs, &mut out);
        // and to each actor it has acted for (`validity::acts_for`): usually on the chain to
        // `g` already, the node reaching `g` through it
        for a in self.core.acting().iter() {
            let certs = self.chain_to(&me, a);
            self.cert_parts(&certs, &mut out);
        }
        self.close_records(&mut out);
        out
    }

    /// What any node logs under `g` beside chains (spec/permissions.md §4): the records up `g`'s
    /// record chain, the destroyed things its closure needs with their frozen permission history,
    /// and the cards of the key actors holding `g` that are no node. Nothing here depends on which
    /// node asks. Added to `out`.
    fn shared_certificates(&mut self, g: &Tid, out: &mut Certs) {
        // the record chain's records
        out.records.extend(self.core.record_chain(g).filter_map(|s| s.thing()));
        // the destroyed things the sync ID's closure needs told destroyed: on an authority path into it,
        // or listed or referenced there; their records and frozen permission history, which no
        // body under the sync ID carries once their destruction dropped their own (spec/permissions.md
        // §4, spec/commits.md §5 Destruction)
        let needed = self.destroyed_upstream(g);
        for e in needed {
            out.records.insert(e);
            out.records.extend(self.core.record_chain(&e).filter_map(|s| s.thing()));
            let certs = self.history_certificates(&e);
            self.cert_parts(&certs, out);
        }
        // the cards of the key actors holding `g` that are neither node nor account (a link key:
        // its writes under the sync ID verify by its card, which no chain carries; a node places
        // its own under D's sync ID alone; an account's goes with its signing chain)
        let keys: Vec<Tid> = self.core.roster_of(g).into_keys().filter(|k| self.core.is_key_actor(k) && !self.core.is_account(k)).collect();
        for k in keys.into_iter().filter(|k| self.latest_on(k, "node.0").is_none()) {
            out.records.insert(k);
            if let Some(c) = self.latest_on(&k, "keys.0") {
                out.add(c, self.parts_of(&c, &BTreeSet::from([k]), &["keys.0"]));
            }
        }
    }

    /// Every thing whose record `out` carries gets its mintings (and a destroyed one's
    /// destruction), but an account it defers (whose piece carries them); records not held leave.
    fn close_records(&mut self, out: &mut Certs) {
        let records: Vec<Tid> = out.records.iter().copied().filter(|t| !out.defers(t)).collect();
        for t in records {
            self.minting_evidence(&t, out);
        }
        out.records.retain(|t| self.core.created(t).is_some());
    }

    /// Account `p`'s record, current `keys.0` commits and signing chain, every line held
    /// (spec/permissions.md §4, §5.5 Chains travel), added to `out`: the current `keys.0` commits
    /// projected to `keys.0` (`current_keys`), every other held rotation as a header-only copy
    /// (`Certs::headers`): a commit at an old epoch verifies by the key its rotation's header
    /// carries, and the rotation's `keys.0` part is the readers' for nothing; and its inbox's
    /// record and current `keys.0` commits (its public record, spec/sync-inbox.md §1). Nothing
    /// for an actor that is no account.
    pub(crate) fn account_chain(&mut self, p: &Tid, out: &mut Certs) {
        if !self.core.is_account(p) {
            return;
        }
        out.records.insert(*p);
        let current = self.current_keys(p);
        self.current_keys_into(p, out);
        let Ok(keys) = osis_base::Ak::new("keys.0") else { return };
        let rots: Vec<CommitId> = self.core.ix.by_aspect.get(&(*p, keys)).into_iter().flatten().map(|(_, c)| *c).filter(|c| !current.contains(c) && self.core.ix.commits.get(c).is_some_and(|m| m.view.author == *p && m.view.epoch.is_some()) && self.header(c).is_some_and(|h| h.rotation.is_some())).collect();
        out.headers.extend(rots);
        // and its inbox's public key record (spec/sync-inbox.md §1)
        if let Some(i) = self.inbox_thing(p).filter(|i| self.core.created(i).is_some()) {
            out.records.insert(i);
            self.current_keys_into(&i, out);
        }
    }

    /// What a sync ID of `g` holds as certificates, whoever logs them (spec/permissions.md §4,
    /// spec/sync-judgement.md §2): the union of `g`'s pieces (`Piece`): `g`'s own
    /// (`own_piece`); the author's chain of each held commit on a thing of `g`'s closure its actor
    /// may read, which goes with the commit (`certificate_chains`, `chain_piece`); `g`'s own chain
    /// to each thing an edge write names it holder on, with that thing's boxes to `g` and sync
    /// record (`holder_piece`: role changes travel); the chain of each holder `g`'s keys open to
    /// each thing it is named holder on (`openers`). Nothing else:
    /// a chain into an item of the closure that no write there needs (the roster of a holder
    /// private to others holding a role on an item under S) is none of S's readers'. Parts the closure's bodies carry
    /// are `sync_bodies`' to leave out. Derived whole, O(all of it): what sync reads is
    /// `sync::certified`, kept per piece; this is what it is checked against.
    #[cfg(test)]
    pub(crate) fn sync_certificates(&mut self, g: &Tid) -> Certs {
        let mut out = self.own_piece(g);
        let mut held_on: Vec<(Tid, Tid)> = self.core.ix.held.named_on(g).filter(|x| *x != g && self.core.ix.held.is_holder_by_write(g, x)).map(|x| (*g, *x)).collect();
        // an account root's, for its account held here, on the things it reaches by strongs
        if let Some(p) = self.core.account_of_root(g).filter(|p| self.core.accounts.get(p).is_some_and(|a| a.root == *g)) {
            held_on.extend(self.core.ix.held.named_on(&p).filter(|x| **x != p && self.core.ix.held.is_holder_by_write(&p, x) && self.core.ix.closure.reaches_from(g, x)).map(|x| (p, *x)));
        }
        for (a, x) in self.certificate_chains(g) {
            out.extend(self.chain_piece(&a, &x));
        }
        for (t, x) in held_on {
            out.extend(self.holder_piece(&t, &x));
        }
        // the chain to each thing a holder `g`'s keys open is named on, an account root's to the
        // things it reaches by strongs
        let holders: Vec<Tid> = self.core.ix.held.holders().copied().filter(|t| self.openers(t).contains(g)).collect();
        for t in holders {
            let on: Vec<Tid> = self.core.ix.held.named_on(&t).copied().filter(|x| *x != t && self.core.ix.held.is_holder_by_write(&t, x) && (self.core.account_of_root(g).is_none() || self.core.ix.closure.reaches_from(g, x))).collect();
            for x in on {
                out.extend(self.chain_piece(&t, &x));
            }
        }
        self.expand_accounts(&mut out);
        out
    }

    /// `g`'s own certificates as a read thing (`sync_certificates`): `shared_certificates`, every
    /// actor's chain certificates for `g` (`Timelines::certificates_into`: what reaches it over
    /// chained writes, each account with its signing chain), and under D's sync ID every node's card
    /// commits (each node of D logs its own there). The same at every node judging `g`: what this
    /// node logs of its own (`certificates`) decides nothing of S's required set, else two honest
    /// nodes would delete each other's copies (spec/sync-judgement.md §2). Reads role commits,
    /// records and cards, never content.
    pub(crate) fn own_piece(&mut self, g: &Tid) -> Certs {
        // any account root, whichever node judges it
        let under_d = self.core.account_of_root(g).is_some();
        let mut out = Certs::deferring();
        self.shared_certificates(g, &mut out);
        let found = self.core.timelines.certificates_into(g);
        self.cert_parts(&found, &mut out);
        if under_d {
            // D's holders, and every node its account's chain names (a rotation's minter or
            // certifier, a device added or removed): each rotation is read by its minter's card
            let mut nodes: BTreeSet<Tid> = self.core.key_holders(g).into_iter().map(|(n, _)| n).collect();
            nodes.extend(self.core.account_of_root(g).map(|p| self.core.chain_nodes(&p)).unwrap_or_default());
            for n in nodes {
                if !self.is_node(&n).unwrap_or(false) {
                    continue;
                }
                out.records.insert(n);
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
        self.close_records(&mut out);
        out
    }

    /// Author `a`'s chain certificates for `x` (spec/permissions.md §4, a commit's author's
    /// chain), the parts and records they name: read from the paths into `x` alone
    /// (`Timelines::certificates`).
    pub(crate) fn chain_piece(&mut self, a: &Tid, x: &Tid) -> Certs {
        let mut out = Certs::deferring();
        let found = self.core.timelines.certificates(a, x);
        self.cert_parts(&found, &mut out);
        out
    }

    /// What holder `t`'s readers need of `x` an edge write names `t` holder on (spec/sync-judgement.md
    /// §2 role commits naming an actor): `t`'s chain to `x` (`chain_piece`), the `secrets.0` parts
    /// on `x` boxing a secret to `t`, and `x`'s `sync.0` parts, so a reader of
    /// `t` holds the grant and `x`'s sync ID with no ticket (the chain carries `x`'s keys). An
    /// account's, under its root, is the boxes and `sync.0` alone: its nodes read `x`'s chain
    /// under `x`'s own sync ID once the boxes' history opens it, and a chain named under the root
    /// only while the thing is held left its copies there carrying more than the root names after.
    /// Each valid part held, O(`x`'s held `secrets.0` and `sync.0` commits).
    pub(crate) fn holder_piece(&mut self, t: &Tid, x: &Tid) -> Certs {
        let mut out = if self.core.is_account(t) { Certs::default() } else { self.chain_piece(t, x) };
        let on = BTreeSet::from([*x]);
        for ak in ["secrets.0", "sync.0"] {
            let Ok(k) = Ak::new(ak) else { continue };
            let held: Vec<CommitId> = self.core.ix.by_aspect.get(&(*x, k.clone())).into_iter().flatten().map(|v| v.1).collect();
            for c in held {
                let Some(ai) = self.core.ix.commits.get(&c).filter(|_| !self.core.ix.pending.contains_key(&c)).and_then(|m| m.aspect(x, &k).filter(|ai| m.valid_at(*ai))) else { continue };
                if ak == "secrets.0" && !self.holders_named(&c).get(&ai).is_some_and(|h| h.contains(t)) {
                    continue;
                }
                out.add(c, self.parts_of(&c, &on, &[ak]));
            }
        }
        out
    }

    /// Account `p`'s record, card and signing chain (`account_chain`) with its mintings: one
    /// piece wherever a piece names `p` (`Certs::accounts`), naming no account.
    pub(crate) fn account_piece(&mut self, p: &Tid) -> Certs {
        let mut out = Certs::default();
        self.account_chain(p, &mut out);
        self.close_records(&mut out);
        out
    }

    /// `out` with each account it names (`Certs::accounts`) brought in whole (`account_piece`).
    #[cfg(test)]
    pub(crate) fn expand_accounts(&mut self, out: &mut Certs) {
        for p in out.accounts.take().unwrap_or_default() {
            let a = self.account_piece(&p);
            out.extend(a);
        }
    }

    /// The (author, target) chains that go under a sync ID of `g` with the author's writes
    /// (spec/permissions.md §4, a commit's author's chain: everything the commit's validity reads):
    /// of each held commit on a thing of `g`'s closure its actor may read, its author's chain to
    /// that thing and, acting for another actor, to that actor (`Indexes::chains_on`). A node
    /// author's chain (its card) goes under D's sync ID alone, with D's nodes' cards.
    #[cfg(test)]
    fn certificate_chains(&mut self, g: &Tid) -> Vec<(Tid, Tid)> {
        let things: Vec<Tid> = self.sync_unit(g).iter().filter(|t| self.cert_reads_in(g, t)).copied().collect();
        let pairs: Vec<(Tid, Tid)> = things.into_iter().flat_map(|x| self.core.ix.chains_on.get(&x).into_iter().flatten().copied().collect::<Vec<_>>()).collect();
        pairs.into_iter().filter(|(a, _)| !self.is_node(a).unwrap_or(false)).collect()
    }

    /// The destroyed actors held here on an authority path into `g`'s sync unit (spec/commits.md
    /// §5 Destruction): named first admin or holder on a live thing of the unit, or on such a
    /// destroyed actor. A walk of the destroyed things held (`Indexes::destroyed`), never of every
    /// holder.
    pub fn destroyed_upstream(&self, g: &Tid) -> BTreeSet<Tid> {
        let held = &self.core.ix.held;
        let destroyed: Vec<Tid> = self.core.ix.destroyed.iter().copied().collect();
        osis_base::costs::count("destroyed upstream: actors examined", destroyed.len() as u64);
        let mut out = BTreeSet::new();
        // to a fixpoint: a destroyed actor counts once it is named on a live closure thing or on one counted
        loop {
            let more: Vec<Tid> = destroyed.iter().filter(|e| !out.contains(*e) && held.named_on(e).any(|x| x != *e && (self.core.ix.closure.unit_holds(g, x) && !self.core.destroyed(x) || out.contains(x)))).copied().collect();
            if more.is_empty() {
                return out;
            }
            out.extend(more);
        }
    }

    /// What goes with `t`'s record, added to `out` (spec/commits.md §5, A thing's mintings travel
    /// with its record; `cert_parts` adds it for every thing whose record goes): each held minting
    /// of `t` (`out.mintings`: sync judges each header-only copy by its standing, logging the
    /// witness, `witness`) and, destroyed, each held request destroying it as a header alone. A
    /// node knowing `t` by its record so judges it live or destroyed, and when, as one holding
    /// every minting does: a minting again travels only while it is the witness, and only a right
    /// holder makes a request, so what a reader mints adds nothing. A minting's `expires` dates an
    /// expiry (a value-less part is never logged), a request's header names what it destroys
    /// (`Header::requests`; `t`'s frozen history judges its right), and a header-only blob has no
    /// prefix expiry, so a release's copy outlives the request's own blobs (spec/sync-ids.md §1).
    /// The witness and the requests each with its author's chains to `t` and to its actor. Once
    /// per `out`: `t` among its witness's things in `out.mintings`.
    pub fn minting_evidence(&mut self, t: &Tid, out: &mut Certs) {
        let all = self.mintings_of(t);
        let Some(w) = crate::retention::destroy::highest(&all) else { return };
        if out.mintings.get(&w.commit).is_some_and(|x| x.contains(t)) {
            return;
        }
        for m in &all {
            out.mintings.entry(m.commit).or_default().insert(*t);
        }
        let requests = if w.standing.valued { BTreeSet::new() } else { crate::retention::destroy::destroying_requests(&self.core, t) };
        out.headers.extend(requests.iter().copied());
        let evidence: Vec<CommitId> = std::iter::once(w.commit).chain(requests).collect();
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
    /// each thing and the current `keys.0` of each actor, with the demotions its keysets carry,
    /// and each account's on the chain or at the root of a record chain on it (`account_chain`;
    /// named in `out.accounts` instead where `out` defers them).
    pub(super) fn cert_parts(&mut self, certs: &osis_perm::Certificates, out: &mut Certs) {
        let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
        for c in &certs.commits {
            out.add(*c, self.parts_of(c, &all, &["roles.0"]));
        }
        out.records.extend(certs.created.iter().copied());
        // each account on the chain or at the root of a record chain on it: its record, card and
        // signing chain, every line (spec/permissions.md §4)
        let accounts: BTreeSet<Tid> = certs.created.iter().flat_map(|t| std::iter::once(*t).chain(self.core.record_chain(t).filter_map(|s| match s {
            ChainStep::Key(y) => Some(y),
            _ => None,
        }))).filter(|t| self.core.is_account(t)).collect();
        match &mut out.accounts {
            Some(named) => named.extend(accounts),
            None => {
                for p in &accounts {
                    self.account_chain(p, out);
                }
            }
        }
        for t in &certs.keys {
            if !out.defers(t) {
                self.current_keys_into(t, out);
            }
        }
        for t in &certs.created {
            if !out.defers(t) {
                self.minting_evidence(t, out);
            }
        }
    }

    /// Actor `t`'s current `keys.0` commits projected to `keys.0`, with the demotions its keysets
    /// carry (spec/permissions.md §4), added to `out`.
    fn current_keys_into(&mut self, t: &Tid, out: &mut Certs) {
        for c in self.current_keys(t) {
            out.add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["keys.0"]));
            self.carried_demotions(t, &c, out);
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
    pub fn judged_valid(&self, c: &CommitId, parts: &[usize]) -> bool {
        judged_valid(&self.core, c, parts)
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
            to_sync_id: false,
        }))
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
        lp.hold(t);
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        let c = lp.peers[2].engine.me();
        lp.peers[0].engine.grant(&t, &c, &edge).unwrap();
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
