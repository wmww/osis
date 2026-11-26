//! Certificates (spec/permissions.md §4; spec/sync-judgement.md §1): what a read thing's sync IDs
//! carry beside bodies, as (commit, parts) to log, from the evidence derivation over the held
//! set (`evidence::held`); partial bodies of a commit and the blobs its parts link.
//! Sync IDs come with secrets of their own (`rotation::own_secrets`), steps by sync once their rotations are logged (`Engine::due_step`, `issue_due_step`).

use super::blobs::Body;
use crate::evidence::held::Ev;
use osis_base::memo::Memo;
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Parts of a commit, by part index.
pub type Parts = BTreeSet<usize>;

/// What a certificate copy's cut is for (spec/permissions.md §4 Copies): what S carries names
/// the parts S's readers read there (`Engine::cut_parts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cut {
    /// S's evidence; `step`: the copy records a step placing a listed key.
    Evidence { step: bool },
    /// Keys: a public key record, a carried cause, holder keys.
    Keys,
}

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
    /// Sync copies (spec/wire.md §4), as (commit, thing, holder): no header, record or evidence
    /// goes with them; a stub's sync-only cut (spec/permissions.md §4 Stub).
    pub sync_copies: BTreeSet<(CommitId, Tid, Tid)>,
}

impl Certs {
    fn add(&mut self, c: CommitId, parts: Parts) {
        if !parts.is_empty() {
            self.commits.entry(c).or_default().extend(parts);
        }
    }

    /// Adds `other`'s commits, headers, mintings and records, by reference.
    pub fn extend_from(&mut self, other: &Certs) {
        for (c, p) in &other.commits {
            if !p.is_empty() {
                self.commits.entry(*c).or_default().extend(p.iter().copied());
            }
        }
        self.headers.extend(other.headers.iter().copied());
        for (c, ts) in &other.mintings {
            self.mintings.entry(*c).or_default().extend(ts.iter().copied());
        }
        self.records.extend(other.records.iter().copied());
        self.sync_copies.extend(other.sync_copies.iter().copied());
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
        self.sync_copies.extend(other.sync_copies);
    }
}

impl Engine {
    /// The parts of commit `c` on `(tid, ak)` for any of `aks`.
    pub(crate) fn parts_of(&self, c: &CommitId, tids: &BTreeSet<Tid>, aks: &[&str]) -> Parts {
        let Some(h) = self.header(c) else { return Parts::new() };
        h.aspects
            .iter()
            .enumerate()
            .filter(|(_, a)| tids.contains(&a.tid) && aks.contains(&a.ak.as_str()))
            .map(|(i, _)| i)
            .collect()
    }

    /// The holders each `roles.0` or `secrets.0` part of applied role commit `c` is about
    /// (spec/sync-inbox.md §5), by part index: those whose edge a `roles.0` delta writes, those a
    /// `secrets.0` piece's box records are keyed with (one per piece, none for the rest). Empty
    /// for any other commit kind.
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
            let Some(a) = h.aspects.get(ai) else { continue };
            let f = d.fragment();
            let named: Vec<Tid> = match a.ak.as_str() {
                // a key's grant names no holder (nothing is sealed to a key)
                "roles.0" => crate::apply::validity::edge_holders(&self.core, &a.tid, crate::apply::validity::Grants::Things, f).into_iter().filter_map(|h| h.thing()).collect(),
                // the holders its records are keyed with, puts and removals: of a piece, its
                // holder (spec/wire.md §4 Pieces)
                _ => f.field_keys(0).into_iter().filter_map(osis_commit::box_holder).collect(),
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
    /// sync ID), from `ev` holding `g` as a sync ID: its required copies; the records of both ends
    /// of each edge its evidence reads; the records and mintings `shared` adds; and the public
    /// key records of `g`'s holders, with their evidence; and the stubs `g`'s unit carries, each
    /// cut to its readers (`stub_certificates`).
    pub(crate) fn sync_certificates(&mut self, ev: &Ev, g: &Tid) -> Certs {
        let mut out = Certs::default();
        let req: BTreeSet<(CommitId, Tid)> = ev.required(g).map(|r| r.keys().copied().collect()).unwrap_or_default();
        let stepped = ev.stepped(g).cloned().unwrap_or_default();
        for (c, x) in &req {
            self.add_cut(c, x, Cut::Evidence { step: stepped.contains(&(*c, *x)) }, &mut out);
        }
        // a key has no record: its edge's target's is the one read
        for (a, b) in ev.edges(g).into_iter().flatten() {
            out.records.extend(a.thing());
            out.records.insert(*b);
        }
        self.shared_certificates(ev, g, &mut out);
        // the public key records of `g`'s holders (spec/permissions.md §4): every admin can seal
        // to and list them; a link key's redeemer, holding its seed alone, learns its record and
        // keysets from `g`'s sync ID; its mint admin among them by its record edge while that
        // stands: a removed holder's keys go nowhere
        let holders: BTreeSet<Tid> = self.core.roster_of(g).into_keys().collect();
        for h in &holders {
            self.public_key_record_into(ev, h, &mut out);
        }
        self.stub_certificates(ev, g, &mut out);
        self.close_records(ev, &mut out);
        out
    }

    /// The stubs `g`'s unit carries as this node holds their role entries (spec/permissions.md
    /// §4 Stub; spec/sync-set.md §2 Stubs, Carriers), added to `out`: of each independent thing
    /// X the walk gives from `g`'s unit, outside it. Where `g`'s keys open X: each held commit
    /// with a role-class part on X, cut to the stub (`stub_parts`: the pieces boxing `g`, the
    /// holders on its chains to X or the public), with its evidence, and X's public key record
    /// (its sync ID and step keys); else, `g` holding sync on X, the sync copies for holder `g`.
    fn stub_certificates(&mut self, ev: &Ev, g: &Tid, out: &mut Certs) {
        for x in self.core.ix.closure.unit_stubs(g) {
            let role = |ak: &str| matches!(ak, "roles.0" | "signers.0" | "secrets.0" | "sync.0");
            let cs: BTreeSet<CommitId> = self.core.aspects_of(&x).filter(|((_, ak), _)| role(ak.as_str())).flat_map(|(_, cs)| cs.iter().map(|(_, c)| *c).collect::<Vec<_>>()).collect();
            if self.core.keys_open(g, &x) {
                let mut open = crate::sync::units::chain_holders(&self.core, g, &x);
                open.extend([*g, Tid::PUBLIC]);
                let mut seeds = BTreeSet::new();
                for c in cs {
                    let parts = self.stub_parts(&c, &x, &open);
                    if !parts.is_empty() {
                        out.add(c, parts);
                        out.records.insert(x);
                        out.records.extend(self.header(&c).map(|h| h.signer));
                        seeds.insert((c, x));
                    }
                }
                self.add_closure(ev, &seeds, out);
                self.public_key_record_into(ev, &x, out);
            } else if self.core.keyed_role_now(g, &x) >= Some(osis_base::Role::Sync) {
                for c in cs {
                    let boxes = self.header(&c).map(|h| h.aspect_parts(&x, "secrets.0")).unwrap_or_default();
                    let named = self.holders_named(&c);
                    let steps = self.header(&c).is_some_and(|h| !h.aspect_parts(&x, "sync.0").is_empty());
                    if steps || boxes.into_iter().any(|ai| named.get(&ai).is_some_and(|hs| hs.contains(g))) {
                        out.sync_copies.insert((c, x, *g));
                    }
                }
            }
        }
    }

    /// The stub cut of commit `c` on `x` for readers opening `open`: its
    /// edge-class and `sync.0` parts, its `secrets.0` pieces naming a holder of `open` or none
    /// (the rest piece). Invariant (security): nothing outside `x`; a box part only beside its
    /// edge-class parts.
    fn stub_parts(&mut self, c: &CommitId, x: &Tid, open: &BTreeSet<Tid>) -> Parts {
        let Some(h) = self.header(c) else { return Parts::new() };
        let named = self.holders_named(c);
        let edge = |ak: &str| crate::apply::validity::edge_ak(ak);
        let mut out = Parts::new();
        for (i, a) in h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *x) {
            let take = match a.ak.as_str() {
                "secrets.0" => named.get(&i).is_none_or(|hs| hs.is_empty() || hs.iter().any(|h| open.contains(h))),
                ak => edge(ak) || ak == "sync.0",
            };
            if take {
                out.insert(i);
            }
        }
        if !out.is_empty() {
            out.extend(h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *x && edge(a.ak.as_str())).map(|(i, _)| i));
        }
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
            e.add_sid(*g);
            for t in unit.iter() {
                e.join(g, *t);
            }
        }
        Ok(self.sync_certificates(&ev, g))
    }

    /// The commits writing `g`'s edge on `x` or boxing `g` there, while `g` is named on `x`.
    pub(crate) fn edge_on(&mut self, g: &Tid, x: &Tid) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        if !self.core.ix.held.is_named(g, x) {
            return out;
        }
        for ak in ["roles.0", "secrets.0"] {
            let Ok(k) = osis_base::Ak::new(ak) else { continue };
            let cs: Vec<CommitId> = self.core.ix.by_aspect.get(&(*x, k)).into_iter().flatten().map(|(_, c)| *c).collect();
            for c in cs {
                let named = {
                    let parts = self.header(&c).map(|h| h.aspect_parts(x, ak)).unwrap_or_default();
                    let named = self.holders_named(&c);
                    parts.into_iter().any(|ai| named.get(&ai).is_some_and(|hs| hs.contains(g)))
                };
                if named {
                    out.insert(c);
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

    /// `cut`'s parts of commit `c` on thing `x` (spec/permissions.md §4 Copies: S's cut, each
    /// part whole): evidence, its edge-class parts and, recording a step placing a listed key, its
    /// `sync.0`; keys, its `keys.0`. Beside a `keys.0` part, the commit's edge-class parts on
    /// `x`: they carry the edge writes its rotation makes (a removal: a public link's redeemer
    /// learns the public's removal so).
    /// Invariant (security): nothing outside `x`; a box part only beside its edge-class parts.
    /// A stub's cut: `stub_parts`.
    pub(crate) fn cut_parts(&mut self, c: &CommitId, x: &Tid, cut: Cut) -> Parts {
        let Some(h) = self.header(c) else { return Parts::new() };
        let edge = |ak: &str| crate::apply::validity::edge_ak(ak);
        let mut out = Parts::new();
        let mut boxes = false;
        for (i, a) in h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *x) {
            let ak = a.ak.as_str();
            let take = match cut {
                Cut::Evidence { step } => edge(ak) || (step && ak == "sync.0"),
                Cut::Keys => ak == "keys.0",
            };
            if take {
                boxes |= matches!(ak, "secrets.0" | "keys.0");
                out.insert(i);
            }
        }
        if boxes {
            out.extend(h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *x && edge(a.ak.as_str())).map(|(i, _)| i));
        }
        out
    }

    /// `cut`'s parts of `c` on `x` (`cut_parts`), with the records of `x` and of `c`'s signer,
    /// added to `out`.
    pub(crate) fn add_cut(&mut self, c: &CommitId, x: &Tid, cut: Cut, out: &mut Certs) {
        let Some(h) = self.header(c) else { return };
        out.add(*c, self.cut_parts(c, x, cut));
        out.records.insert(*x);
        out.records.insert(h.signer);
    }

    /// The evidence `ev` closes `seeds` over (`Evidence::closure_of`, seeds not included), each
    /// copy cut to evidence, added to `out`; a seed recording a step another places gets its
    /// `sync.0` part too.
    pub(crate) fn add_closure(&mut self, ev: &Ev, seeds: &BTreeSet<(CommitId, Tid)>, out: &mut Certs) {
        if seeds.is_empty() {
            return;
        }
        let (members, stepped) = ev.closure_of(seeds);
        for (c, x) in members.keys() {
            self.add_cut(c, x, Cut::Evidence { step: stepped.contains(&(*c, *x)) }, out);
        }
        for (c, x) in stepped.iter().filter(|s| seeds.contains(*s)) {
            out.add(*c, self.parts_of(c, &BTreeSet::from([*x]), &["sync.0"]));
        }
    }

    /// What any node logs under `g` beside its evidence (spec/permissions.md §4): the records up
    /// `g`'s record chain and the destroyed things its closure needs with their frozen permission
    /// history. Nothing here depends on which node asks. Added to `out`.
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
                self.add_cut(c, x, Cut::Evidence { step: false }, out);
            }
            self.add_closure(ev, &frozen, out);
        }
    }

    /// To a fixed point, every thing whose record `out` carries brings what its record's going
    /// brings (`record_certificates`); records not held leave.
    pub(crate) fn close_records(&mut self, ev: &Ev, out: &mut Certs) {
        let mut done = BTreeSet::new();
        loop {
            let fresh: Vec<Tid> = out.records.iter().filter(|t| !done.contains(*t)).copied().collect();
            if fresh.is_empty() {
                break;
            }
            for t in fresh {
                done.insert(t);
                let c = self.record_certificates(ev, &t);
                out.extend_from(&c);
            }
        }
        out.records.retain(|t| self.core.created(t).is_some());
    }

    /// What `t`'s record going brings (`close_records`): the records up its record chain and
    /// its mintings with their evidence (`minting_evidence`). A function of the held set and
    /// the derivation's rows alone, kept per record (`Core::record_certs`), so a follow derives
    /// the records whose inputs moved. An answer read on a copy of the derivation (a thing not
    /// read, `certificates`) is the kept one's (no closure reads a sync ID), and one derived on
    /// the copy moves once the copy's stamps go with it.
    fn record_certificates(&mut self, ev: &Ev, t: &Tid) -> Arc<Certs> {
        let r: std::result::Result<_, std::convert::Infallible> = Memo::get_in(self, |e| &e.core.record_certs, t, |e| {
            // counted: a make derives the contributions of the records it changed
            osis_base::costs::count("certificates: record contributions derived", 1);
            let mut out = Certs::default();
            out.records.extend(e.core.record_chain(t).filter_map(|s| s.thing()));
            e.minting_evidence(ev, t, &mut out);
            Ok(Arc::new(out))
        });
        match r {
            Ok(c) => c,
            Err(e) => match e {},
        }
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

    /// `t`'s current `keys.0` commits (spec/permissions.md §4): every held commit whose `keys.0`
    /// body on `t` has a write live in `t`'s state, a compaction snapshot among them. So they rebuild
    /// the state whole: the newest keyset per role (forks included) with its box records, and
    /// whichever commits last wrote the other fields (`sync_id`, `deposit_seed`, `step`).
    pub fn current_keys(&mut self, t: &Tid) -> Result<BTreeSet<CommitId>> {
        let t = *t;
        self.read(|tx| current_keys_in(tx, &t))
    }

    /// `t`'s public key record (spec/sync-inbox.md §1): its record and current `keys.0` commits
    /// projected to `keys.0`, each a certificate copy with its evidence (the steps placing the
    /// keys it lists among them: a reader judges it) and the demotions its keysets carry
    /// (spec/permissions.md §4), added to `out`.
    fn public_key_record_into(&mut self, ev: &Ev, t: &Tid, out: &mut Certs) {
        out.records.insert(*t);
        let mut seeds = BTreeSet::new();
        for c in self.current_keys(t).unwrap_or_default() {
            out.add(c, self.cut_parts(&c, t, Cut::Keys));
            self.carried_demotions(ev, t, &c, out);
            seeds.insert((c, *t));
        }
        self.add_closure(ev, &seeds, out);
    }

    /// The demotions the keysets of `t` that commit `c` introduces carry (spec/crypto.md §4,
    /// Carried demotions) and the left-out causes they record (Carried): each carried commit's
    /// `roles.0` parts (`c`'s own among them where a keyset says `c` demotes) with their
    /// evidence, a cause's `keys.0` parts beside them (a rotation commit making a box stale),
    /// added to `out`: a receiver holds those keysets only with them.
    fn carried_demotions(&mut self, ev: &Ev, t: &Tid, c: &CommitId, out: &mut Certs) {
        let mut carried: BTreeSet<CommitId> = BTreeSet::new();
        let mut causes: BTreeSet<CommitId> = BTreeSet::new();
        for (r, e, x) in self.core.keysets_noted(t) {
            if self.core.ix.epoch_intro.get(&(*t, r, e)).is_some_and(|i| i.1 == *c) {
                carried.extend(x.demotions.iter().copied());
                causes.extend(x.left_out.values().flat_map(|xs| xs.values().flatten().copied()));
            }
        }
        for d in carried.iter().chain(&causes) {
            let Some(h) = self.header(d) else { continue };
            let aks: &[&str] = if causes.contains(d) { &["roles.0", "keys.0"] } else { &["roles.0"] };
            let things: BTreeSet<Tid> = h.aspects.iter().filter(|a| aks.contains(&a.ak.as_str())).map(|a| a.tid).collect();
            for x in &things {
                let mut parts = self.cut_parts(d, x, Cut::Evidence { step: false });
                if causes.contains(d) {
                    parts.extend(self.cut_parts(d, x, Cut::Keys));
                }
                out.add(*d, parts);
            }
            let seeds: BTreeSet<(CommitId, Tid)> = things.into_iter().map(|x| (*d, x)).collect();
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
/// `Engine::current_keys` in `tx`.
pub(crate) fn current_keys_in(tx: &mut crate::engine::Tx<'_>, t: &Tid) -> Result<BTreeSet<CommitId>> {
    let ak = Ak::new("keys.0").map_err(|_| crate::Error::Misuse("ak"))?;
    let Some(dots) = tx.state(t, &ak)?.map(|f| f.live_writes().into_iter().map(|(d, _)| d).collect::<BTreeSet<_>>()) else { return Ok(BTreeSet::new()) };
    let live: BTreeSet<CommitId> = dots.iter().filter_map(|d| match d.src.kind() {
        osis_crdt::SourceKind::Commit(c) => Some(*c),
        _ => None,
    }).collect();
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*t, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let mut out: BTreeSet<CommitId> = held.iter().copied().filter(|c| live.contains(c) && tx.core.ix.commits.contains_key(c)).collect();
    // a compaction snapshot holds its writes by their own stamps: current where its body holds one
    for c in held {
        let Some(m) = tx.core.ix.commits.get(&c).cloned() else { continue };
        if m.header.kind != osis_commit::Kind::RoleSnapshot {
            continue;
        }
        for ai in m.view.aspect_parts(t, "keys.0").collect::<Vec<_>>() {
            let Some(f) = crate::apply::held_fragment(tx, &c, ai)? else { continue };
            if f.live_writes().into_iter().any(|(d, _)| dots.contains(&d)) {
                out.insert(c);
            }
        }
    }
    Ok(out)
}

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
    use osis_base::{Ak, Role, Tid, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/permissions.md §4 (current `keys.0` commits): certificates and cards are the current valid writes, §5.2: a
    // later write by a node without the role (here a reader; anyone's on another node's card)
    // is invalid and never stands for the newest commit on the aspect: admins would otherwise
    // delete the real one as superseded.
    #[test]
    fn invalid_later_write_never_newest_spec_permissions_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let good = lp.peers[0].commit(m).unwrap().unwrap();
        lp.hold(t);
        let edge = ct::Edge { role: Role::Read, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        let c = lp.peers[2].engine.tid();
        lp.peers[0].engine.grant(&t, &c, &edge).unwrap();
        lp.sync_all().unwrap();
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(2)).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let bad = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync(1, 2).unwrap();
        let e = &mut lp.peers[2].engine;
        assert!(e.header(&bad).is_some_and(|h| h.ts > e.header(&good).unwrap().ts), "the reader's write is held, later");
        assert_eq!(e.get(&t, &ak).unwrap(), Some(Value::Int(1)), "the valid write stands");
    }

    /// The keyset of `m` that `t`'s box to `m` at read epoch `e` names, at peer `i`.
    fn boxed_at(lp: &mut LocalPeer, i: usize, t: Tid, e: osis_crypto::Epoch, m: Tid) -> Option<osis_crypto::Epoch> {
        let s = lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap()?;
        s.boxes.iter().find(|(k, _)| k.holder == osis_base::Weak(m) && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).and_then(|(_, b)| osis_keys::box_keysets(b).into_iter().next())
    }

    /// Peer 0 mints A, grants peer 1 admin on it; peer 1 rotates A to keyset k; peer 0 mints T
    /// with admin A and makes it independent. Returns the peers, A, T, k and the rotation.
    fn under_a_rotated_by_another() -> (LocalPeer, Tid, Tid, osis_crypto::Epoch, osis_base::CommitId) {
        use crate::rotation::tests::{edge, independent_thing, synced};
        let mut lp = synced(3);
        let p1 = lp.peers[1].engine.tid();
        let a = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&a, &p1, &edge(Role::Admin)).unwrap();
        lp.sync(0, 1).unwrap();
        let rot = lp.peers[1].engine.rotate_leaving_out(&a, &Role::ALL, &[]).unwrap().unwrap();
        let k = lp.peers[1].engine.epochs(&a).unwrap().read.newest_held().unwrap().0;
        lp.sync(1, 0).unwrap();
        // T under A: its record edge makes A its mint admin
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        lp.takes_grants(0, t);
        lp.peers[0].engine.make_independent(&t).unwrap();
        (lp, a, t, k, rot)
    }

    /// Whether `t`'s certificates at peer `i` carry `rot`'s `keys.0` part on `a`.
    fn carries_keys_of(lp: &mut LocalPeer, i: usize, t: &Tid, a: &Tid, rot: &osis_base::CommitId) -> bool {
        let e = &mut lp.peers[i].engine;
        let certs = e.certificates(t).unwrap();
        let ai = e.header(rot).unwrap().aspect_index(a, "keys.0").unwrap();
        certs.commits.get(rot).is_some_and(|ps| ps.contains(&ai))
    }

    // held-model copy_cut `hand(true)` (spec/permissions.md §4 Copies: keys and the evidence of
    // their parts): peer 1, granted admin on A by peer 0, rotates A to keyset k. T, minted with
    // admin A, made independent, is granted write to peer 2, which reads nothing of A and holds
    // only T's bodies and T's certificates (each copy cut). Peer 2 rotates T and boxes A at k, as
    // a node holding every copy whole does: A's keys copy is judged by peer 1's grant, its
    // evidence. Fails with no evidence closed over the keys copies (the rotation unjudgeable: A
    // boxed at the older keyset).
    #[test]
    fn a_cut_holder_keyset_is_sealed_to_as_whole_spec_permissions_4() {
        use crate::rotation::tests::edge;
        use std::collections::BTreeSet;
        let (mut lp, a, t, k, _) = under_a_rotated_by_another();
        let p2 = lp.peers[2].engine.tid();
        lp.hold_at(2, t);
        lp.peers[0].engine.grant(&t, &p2, &edge(Role::Write)).unwrap();
        let e0 = lp.peers[0].engine.epochs(&t).unwrap().read.newest_held().unwrap().0;
        assert_eq!(boxed_at(&mut lp, 0, t, e0, a), Some(k), "T's admin boxes A at k");
        let on_t: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t))).collect();
        for c in on_t {
            let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
            lp.deliver(2, &pk).unwrap();
        }
        lp.send_certificates(0, 2, &t).unwrap();
        // A's record, as the record blob under T carries it
        let p0 = &mut lp.peers[0].engine;
        let minting = p0.mintings_of(&a)[0].commit;
        let created = p0.header(&minting).unwrap().aspect_index(&a, "created.0").unwrap();
        let pk = p0.package_of_parts(&minting, &BTreeSet::from([created])).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
        assert!(lp.peers[2].engine.get_typed(&a, &ct::SECRETS).unwrap().is_none(), "peer 2 holds no box of A");
        assert!(lp.peers[2].engine.rotate_leaving_out(&t, &[Role::Read], &[]).unwrap().is_some(), "peer 2 rotates T");
        let e2 = lp.peers[2].engine.epochs(&t).unwrap().read.newest_held().unwrap().0;
        assert_ne!(e2, e0);
        assert_eq!(boxed_at(&mut lp, 2, t, e2, a), Some(k), "peer 2 boxes A at k, as from whole copies");
    }

    // spec/permissions.md §4 (the public key record of a current holder; the mint admin holds by
    // its record edge while it stands, §1): T, minted with admin A, carries A's keys while A
    // holds, by its record edge alone and beside a grant; once peer 1 removes A's record edge,
    // T's certificates carry none of A's keys. Fails with the mint admin's record carried
    // whatever its edge.
    #[test]
    fn a_removed_mint_admins_keys_leave_the_certificates_spec_permissions_4() {
        use crate::rotation::tests::edge;
        let (mut lp, a, t, _, rot) = under_a_rotated_by_another();
        assert!(carries_keys_of(&mut lp, 0, &t, &a, &rot), "A's keys under T, no edge write on T");
        let p1 = lp.peers[1].engine.tid();
        lp.peers[0].engine.grant(&t, &p1, &edge(Role::Admin)).unwrap();
        assert!(carries_keys_of(&mut lp, 0, &t, &a, &rot), "A's keys under T beside a grant");
        lp.sync(0, 1).unwrap();
        lp.peers[1].engine.demote(&t, &crate::flows::Demotion { holder: a, new: None, retain: None }).unwrap();
        lp.sync(1, 0).unwrap();
        assert!(!lp.peers[0].engine.core.current_holders(&t).iter().any(|(h, ..)| *h == a), "A removed from T");
        assert!(!carries_keys_of(&mut lp, 0, &t, &a, &rot), "none of A's keys under T once removed");
    }
}
