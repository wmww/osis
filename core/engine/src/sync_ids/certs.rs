//! Certificates (spec/permissions.md §4; spec/sync-judgement.md §1): what a read thing's sync IDs
//! carry beside bodies, as (commit, parts) to log, from the evidence derivation over the held
//! set (`evidence::held`); partial bodies of a commit and the blobs its parts link.
//! Sync IDs come with secrets of their own (`rotation::own_secrets`), steps by sync once their rotations are logged (`Engine::due_step`, `issue_due_step`).

use super::blobs::Body;
use crate::evidence::held::Ev;
use osis_base::memo::Memo;
use crate::engine::Engine;
use crate::error::Result;
use osis_commit::Decoded;
use osis_base::{Ak, CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Parts of a commit, by aspect index.
pub type Parts = BTreeSet<usize>;

/// Chain material a verifier needs (spec/permissions.md §4): parts of commits to copy, commits
/// to copy as headers alone (the requests destroying things whose records go), the held
/// mintings of things whose records go (each with those things: a header-only copy of each is
/// judged by its standing, spec/commits.md §5), and raw creation records (a record blob's),
/// which outlive the commits that minted them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Certs {
    pub commits: BTreeMap<CommitId, Parts>,
    pub headers: BTreeSet<CommitId>,
    pub mintings: BTreeMap<CommitId, BTreeSet<Tid>>,
    pub records: BTreeSet<Tid>,
}

impl Certs {
    fn add(&mut self, c: CommitId, parts: Parts) {
        if !parts.is_empty() {
            self.commits.entry(c).or_default().extend(parts);
        }
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
        self.latest_where(tid, ak, |c| author.is_none_or(|a| self.core.ix.commits.get(c).is_some_and(|m| m.header.signer == *a)))
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
                // a key's grant names no holder with a key part (nothing is sealed to a key)
                "roles.0" => crate::apply::validity::edge_holders(&self.core, &a.tid, crate::apply::validity::Grants::Things, &d.fragment).into_iter().filter_map(|h| h.thing()).collect(),
                _ => crate::apply::keys::secrets_write(&d.fragment).boxes.into_keys().map(|k| k.holder.0).collect(),
            };
            out.entry(ai).or_default().extend(named);
        }
        Ok(out)
    }

    /// The evidence derivation over the held set (`evidence::kept`): what `closure_of` reads.
    pub(crate) fn evidence_now(&mut self) -> Result<Arc<Ev>> {
        self.kept_evidence()
    }

    /// What read thing `g`'s sync IDs carry beside bodies (spec/permissions.md §4 Evidence of a
    /// sync ID, Key part), from `ev` holding `g` as a sync ID: its required copies; the records of
    /// both ends of each edge its evidence reads; the records, cards and mintings `shared` adds;
    /// the current `keys.0` commits of `g`'s holders; and `g`'s key part, with their evidence.
    pub(crate) fn sync_certificates(&mut self, ev: &Ev, g: &Tid) -> Certs {
        let mut out = Certs::default();
        let req: BTreeSet<(CommitId, Tid)> = ev.required(g).map(|r| r.keys().copied().collect()).unwrap_or_default();
        for (c, x) in &req {
            self.add_copy(c, x, &mut out);
        }
        // a key has no record: its edge's target's is the one read
        for (a, b) in ev.edges(g).into_iter().flatten() {
            out.records.extend(a.thing());
            out.records.insert(*b);
        }
        self.shared_certificates(ev, g, &mut out);
        let holders: Vec<Tid> = self.core.roster_of(g).into_keys().collect();
        for h in &holders {
            self.current_keys_into(ev, h, &mut out);
        }
        // a holder of sync alone on a target gets that target's boxes and `sync.0` parts and
        // nothing else of it: no roster, no edge write, no evidence of either (spec/permissions.md
        // §4 Key part)
        let mut key_part = BTreeSet::new();
        for (c, x) in self.key_part(g) {
            if self.core.roster_of(&x).get(g).is_some_and(|e| e.role == osis_base::Role::Sync) {
                out.add(c, self.parts_of(&c, &BTreeSet::from([x]), &["secrets.0", "sync.0"]));
                out.records.insert(x);
            } else {
                key_part.insert((c, x));
            }
        }
        for (c, x) in &key_part {
            self.add_copy(c, x, &mut out);
        }
        self.add_closure(ev, &key_part, &mut out);
        self.close_records(ev, &mut out);
        out
    }

    /// What `g`'s sync IDs carry beside bodies (`sync_certificates`), whether or not this node
    /// reads `g` as a sync ID.
    pub fn certificates(&mut self, g: &Tid) -> Result<Certs> {
        let mut ev = self.kept_evidence()?;
        // a thing this node does not read as a sync ID: with its unit, on a copy
        if !ev.sids().any(|s| s == *g) {
            let unit = self.sync_unit(g);
            let e = Arc::make_mut(&mut ev);
            e.add_sid(*g, *g);
            for t in unit.iter() {
                e.join(g, *t);
            }
        }
        Ok(self.sync_certificates(&ev, g))
    }

    /// `g`'s key part (spec/permissions.md §4 Key part), as copies: per thing `x` an edge write
    /// names `g` holder on, each commit writing such an edge, boxing `g` in `x`'s `secrets.0`, or
    /// writing `x`'s `sync.0`. A creation record naming `g` mint admin names it as an edge write
    /// does (`Held::named_on`), so a thing `g` minted is among them.
    pub(crate) fn key_part(&mut self, g: &Tid) -> BTreeSet<(CommitId, Tid)> {
        let on: Vec<Tid> = self.core.ix.held.named_on(g).filter(|x| *x != g).copied().collect();
        let mut out = BTreeSet::new();
        for x in on {
            for ak in ["roles.0", "secrets.0", "sync.0"] {
                let Ok(k) = osis_base::Ak::new(ak) else { continue };
                let cs: Vec<CommitId> = self.core.ix.by_aspect.get(&(x, k)).into_iter().flatten().map(|(_, c)| *c).collect();
                for c in cs {
                    let named = ak == "sync.0" || {
                        let Some(ai) = self.header(&c).and_then(|h| h.aspect_index(&x, ak)) else { continue };
                        self.holders_named(&c).get(&ai).is_some_and(|hs| hs.contains(g))
                    };
                    if named {
                        out.insert((c, x));
                    }
                }
            }
        }
        out
    }

    /// The evidence of parts `parts` of commit `c` (spec/permissions.md §4 Evidence of a commit):
    /// the copies the derivation closes them over, the demotions a `keys.0` part's keysets carry,
    /// and the records `close_records` brings; `c` itself not among them.
    pub(crate) fn evidence_of(&mut self, c: &CommitId, parts: &Parts) -> Result<Certs> {
        let ev = self.evidence_now()?;
        let mut out = Certs::default();
        let Some(h) = self.header(c) else { return Ok(out) };
        out.records.insert(h.signer);
        let on: Vec<_> = parts.iter().filter_map(|ai| h.aspects.get(*ai)).collect();
        let seeds: BTreeSet<(CommitId, Tid)> = on.iter().map(|a| (*c, a.tid)).collect();
        self.add_closure(&ev, &seeds, &mut out);
        for a in on.iter().filter(|a| a.ak.as_str() == "keys.0") {
            self.carried_demotions(&ev, &a.tid, c, &mut out);
        }
        self.close_records(&ev, &mut out);
        Ok(out)
    }

    /// Copy (`c`, `x`): `c`'s role-class parts on `x` (spec/permissions.md §4 Copies), with the
    /// records of `x` and of `c`'s signer, added to `out`.
    fn add_copy(&mut self, c: &CommitId, x: &Tid, out: &mut Certs) {
        let Some(h) = self.header(c) else { return };
        out.add(*c, self.parts_of(c, &BTreeSet::from([*x]), &osis_schema::core_types::ROLE_CLASS));
        out.records.insert(*x);
        out.records.insert(h.signer);
    }

    /// The copies `ev` closes `seeds` over (`Evidence::closure_of`, seeds not included), added
    /// to `out`.
    pub(crate) fn add_closure(&mut self, ev: &Ev, seeds: &BTreeSet<(CommitId, Tid)>, out: &mut Certs) {
        if seeds.is_empty() {
            return;
        }
        let closure: Vec<(CommitId, Tid)> = ev.closure_of(seeds).into_keys().collect();
        for (c, x) in &closure {
            self.add_copy(c, x, out);
        }
    }

    /// What any node logs under `g` beside its evidence (spec/permissions.md §4): the records up
    /// `g`'s record chain, the destroyed things its closure needs with their frozen permission
    /// history, and the public key records of the key actors holding `g`. Nothing here depends
    /// on which node asks. Added to `out`.
    fn shared_certificates(&mut self, ev: &Ev, g: &Tid, out: &mut Certs) {
        out.records.extend(self.core.record_chain(g).filter_map(|s| s.thing()));
        // the destroyed things the sync ID's closure needs told destroyed: on an authority path into it,
        // or listed or referenced there; their records and frozen permission history, which no
        // body under the sync ID carries once their destruction dropped their own (spec/permissions.md
        // §4, spec/commits.md §5 Destruction)
        let needed = self.destroyed_upstream(g);
        for e in needed {
            out.records.insert(e);
            let frozen: BTreeSet<(CommitId, Tid)> = ["roles.0", "signers.0"].into_iter().filter_map(|k| osis_base::Ak::new(k).ok()).flat_map(|k| self.core.ix.by_aspect.get(&(e, k)).into_iter().flatten().map(|(_, c)| (*c, e)).collect::<Vec<_>>()).collect();
            for (c, x) in &frozen {
                self.add_copy(c, x, out);
            }
            self.add_closure(ev, &frozen, out);
        }
        // the public key records of the key actors holding `g` (spec/permissions.md §4: keys, not
        // evidence)
        let keys: Vec<Tid> = self.core.roster_of(g).into_keys().filter(|k| self.core.is_key_actor(k)).collect();
        for k in keys {
            out.records.insert(k);
            if let Some(c) = self.latest_on(&k, "keys.0") {
                out.add(c, self.parts_of(&c, &BTreeSet::from([k]), &["keys.0"]));
            }
        }
    }

    /// To a fixed point, every thing whose record `out` carries gets the records up its record
    /// chain and its mintings (`minting_evidence`); records not held leave.
    pub(crate) fn close_records(&mut self, ev: &Ev, out: &mut Certs) {
        let mut done = BTreeSet::new();
        loop {
            let fresh: Vec<Tid> = out.records.iter().filter(|t| !done.contains(*t)).copied().collect();
            if fresh.is_empty() {
                break;
            }
            for t in fresh {
                done.insert(t);
                out.records.extend(self.core.record_chain(&t).filter_map(|s| s.thing()));
                self.minting_evidence(ev, &t, out);
            }
        }
        out.records.retain(|t| self.core.created(t).is_some());
    }

    /// The destroyed actors held here on an authority path into `g`'s sync unit (spec/commits.md
    /// §5 Destruction): named mint admin or holder on a live thing of the unit, or on such a
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
    /// with its record; `close_records` adds it for every thing whose record goes): each held
    /// minting of `t` (`out.mintings`: sync judges each header-only copy by its standing, logging
    /// the witness, `witness`) and, destroyed, each held request destroying it as a header alone.
    /// A node knowing `t` by its record so judges it live or destroyed, and when, as one holding
    /// every minting does: a minting again travels only while it is the witness, and only a right
    /// holder makes a request, so what a reader mints adds nothing. A minting's `expires` dates an
    /// expiry (a gone part is never logged), a request's header names what it destroys
    /// (`Header::purge`; `t`'s frozen history judges its right), and a header-only blob has no
    /// prefix expiry, so a release's copy outlives the request's own blobs (spec/sync-ids.md §1).
    /// The witness and the requests each with the evidence of their parts. Once per `out`: `t`
    /// among its witness's things in `out.mintings`.
    pub fn minting_evidence(&mut self, ev: &Ev, t: &Tid, out: &mut Certs) {
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
        let mut seeds = BTreeSet::new();
        for c in std::iter::once(w.commit).chain(requests) {
            let Some(h) = self.header(&c) else { continue };
            let things = h.aspects.iter().map(|a| a.tid).chain(h.purge.iter().map(|i| *crate::retention::purge::item_names(i).0));
            seeds.extend(things.map(|x| (c, x)));
        }
        self.add_closure(ev, &seeds, out);
    }

    /// Every held minting of `t` with its standing (`witness` is the highest).
    pub fn mintings_of(&self, t: &Tid) -> Vec<crate::retention::Minting> {
        crate::retention::destroy::mintings(&self.core, t)
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

    /// Actor `t`'s current `keys.0` commits projected to `keys.0`, with the demotions its keysets
    /// carry (spec/permissions.md §4), added to `out`.
    fn current_keys_into(&mut self, ev: &Ev, t: &Tid, out: &mut Certs) {
        for c in self.current_keys(t) {
            out.add(c, self.parts_of(&c, &BTreeSet::from([*t]), &["keys.0"]));
            self.carried_demotions(ev, t, &c, out);
        }
    }

    /// The demotions the keysets of `t` that commit `c` introduces carry (spec/crypto.md §4,
    /// Carried demotions): each carried commit's `roles.0` parts (`c`'s own among them where a
    /// keyset says `c` demotes) with their evidence, added to `out`: a receiver holds those
    /// keysets only with them.
    fn carried_demotions(&mut self, ev: &Ev, t: &Tid, c: &CommitId, out: &mut Certs) {
        let mut carried: BTreeSet<CommitId> = BTreeSet::new();
        for (r, e, x) in self.core.keysets_noted(t) {
            if self.core.ix.epoch_intro.get(&(*t, r, e)).is_some_and(|i| i.1 == *c) {
                carried.extend(x.demotions.iter().copied());
            }
        }
        for d in carried {
            let Some(h) = self.header(&d) else { continue };
            let things: BTreeSet<Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "roles.0").map(|a| a.tid).collect();
            let parts = self.parts_of(&d, &things, &["roles.0"]);
            out.add(d, parts);
            let seeds: BTreeSet<(CommitId, Tid)> = things.into_iter().map(|x| (d, x)).collect();
            self.add_closure(ev, &seeds, out);
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
        let Some(tl) = core.timelines().get(t) else { return true };
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

    // spec/permissions.md §4 (current `keys.0` commits): certificates and cards are the current valid writes, §5.2: a
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
        let edge = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
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
