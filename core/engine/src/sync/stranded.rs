//! Stranded reports (spec/permissions.md §4 Stranded, spec/wire.md §11.2
//! Stranded): what a stranded node tells, and what an admin does with a report.
//!
//! Principle: a report asks only for the re-seal any node that may rotate owes a current holder
//! anyway (spec/permissions.md §3 Re-seal); the receiver judges it from what it holds, never
//! from the sender. So a report brings nothing but the named holder's keys, taken only along that
//! holder's authority chain and only where judged valid, and records one ask per (actor, holder),
//! met at the end of the next complete pass of the actor's sync IDs like the re-seal trigger.
//!
//! - Sending side: `stranded(s)` (S read here, a current read epoch of its thing known and none
//!   held), or `stranding(s, step)` where sync judged it (a walk stopped), with the holder this
//!   node reads the actor through, its current `keys.0` commits and the step's sync key; `holder_keys(holder)` (the report's keys); `writer_of(s, proven)` (who a Stranded message goes to).
//! - Receiving side: `take_stranded(s, holder, keys)` (a Stranded message): the keys taken (`take_holder_keys`) and the ask recorded
//!   (rows `rs/`, durable), keyed by the holder's current `keys.0` commits as held after taking:
//!   a report again with nothing new asks nothing (a notice taken again as its reads move, a
//!   peer repeating a message). `passes_wanted` wants a pass of the actor's sync IDs from an
//!   unmet ask on; `pass_end` re-seals each asked holder (`rotation::Reseal::Asked`: every
//!   current epoch held, only where a box differs from the one Seal gives now) and marks the ask
//!   met; one refused stays unmet, tried again at the actor's next pass end. An ask goes, met or
//!   not, once its holder is no longer current (at a pass's end, which a role commit of the actor
//!   begins) or this node loses or destroys the actor.
//!
//! Bounds: an ask per current holder of an actor this node may rotate (a report naming anything
//! else records nothing; a holder that leaves is dropped at the next pass end); a report's work is O(its bytes): each commit it carries is judged and
//! ingested at most once per pass of the chain loop, and the loop runs at most once per thing
//! the chain gains.

use crate::apply::carriers::Carrier;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::sync_ids::Certs;
use osis_base::{CommitId, CreationRecord, Role, SyncId, Tid, Value};
use osis_commit::CommitBlob;
use osis_blob::HolderKeys;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `rs/` + actor + holder: a re-seal a stranded report asked for (`Ask`).
const ASKS: &[u8] = b"rs/";

/// A re-seal asked for by a stranded report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    /// The pass place it was taken at (`Core::place`): a complete pass begun after it meets it.
    pub at: u64,
    /// A digest of the holder's current `keys.0` commits held when it was taken.
    pub keys: [u8; 32],
    /// Met at a pass's end: kept so the same report asks nothing more.
    pub met: bool,
}

impl Ask {
    fn encode(&self) -> Vec<u8> {
        [&self.at.to_be_bytes()[..], &self.keys, &[u8::from(self.met)]].concat()
    }
    fn decode(v: &[u8]) -> Option<Ask> {
        Some(Ask { at: u64::from_be_bytes(v.get(..8)?.try_into().ok()?), keys: v.get(8..40)?.try_into().ok()?, met: *v.get(40)? == 1 })
    }
}

/// This node stranded on a sync ID it reads (spec/permissions.md §4): what its report names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stranding {
    /// The sync ID's actor (its thing's independent).
    pub actor: Tid,
    /// The holder this node reads the actor through, as it judges it.
    pub holder: Tid,
    /// The sync key of the newest step it reached (its recorded head; zeros recording none).
    pub step: [u8; 32],
    /// The holder's current `keys.0` commits: a report goes again when they move
    /// (spec/sync-status.md §3 Stranded).
    pub keys: BTreeSet<CommitId>,
    /// The actor's admins other than this node's account: where a stranded notice goes.
    pub admins: Vec<Tid>,
}

fn ask_key(a: &Tid, m: &Tid) -> Vec<u8> {
    [ASKS, a.as_bytes(), m.as_bytes()].concat()
}

/// Loads the asks (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("re-seal ask");
    let mut rows = Vec::new();
    tx.scan(ASKS, |k, v| {
        let a = Tid::from_bytes(k.get(..15).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let m = Tid::from_bytes(k.get(15..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        rows.push(((a, m), Ask::decode(&v).ok_or_else(bad)?));
        Ok(())
    })?;
    // the pass place goes on from the highest stored (`sync::held::load`)
    let top = rows.iter().map(|(_, k)| k.at).max().unwrap_or(0);
    tx.core.place = tx.core.place.max(top);
    tx.core.ix.reseal_asks.extend(rows);
    Ok(())
}

/// The holders of `a` with an unmet ask.
pub(crate) fn asked(tx: &Tx<'_>, a: &Tid) -> Vec<Tid> {
    of_actor(tx, a).filter(|(_, k)| !k.met).map(|(m, _)| m).collect()
}

/// `a`'s asks, by holder.
fn of_actor<'a>(tx: &'a Tx<'_>, a: &Tid) -> impl Iterator<Item = (Tid, Ask)> + 'a {
    let a = *a;
    tx.core.ix.reseal_asks.iter().filter(move |((x, _), _)| *x == a).map(|((_, m), k)| (*m, *k))
}

/// The ask for (`a`, `m`) met: kept, so the same report asks nothing more.
pub(crate) fn meet(tx: &mut Tx<'_>, a: &Tid, m: &Tid) -> Result<()> {
    let Some(k) = tx.core.ix.reseal_asks.get(&(*a, *m)).copied() else { return Ok(()) };
    let k = Ask { met: true, ..k };
    tx.txn.put_local(&ask_key(a, m), &k.encode(), Shred::No)?;
    tx.core.ix.reseal_asks.insert((*a, *m), k);
    Ok(())
}

/// Drops `a`'s asks, met or not, and its reports, of holders `keep` refuses (a holder no longer
/// current at a pass's end; every one when this node loses the actor).
pub(crate) fn drop_asks(tx: &mut Tx<'_>, a: &Tid, keep: impl Fn(&Tid) -> bool) -> Result<()> {
    // the reports naming them carry nothing more (spec/commits.md §4 Pending storage)
    crate::apply::carriers::reports_gone(tx, a, &keep)?;
    let gone: Vec<Tid> = of_actor(tx, a).map(|(m, _)| m).filter(|m| !keep(m)).collect();
    for m in gone {
        tx.txn.remove_local(&ask_key(a, &m), Shred::No)?;
        tx.core.ix.reseal_asks.remove(&(*a, m));
    }
    Ok(())
}

fn keys_digest(keys: &BTreeSet<CommitId>) -> [u8; 32] {
    let mut h = osis_base::hash::Hasher::new();
    for k in keys {
        h.update(&k.0);
    }
    h.finalize()
}

impl Engine {
    /// Whether this node is stranded on read sync ID `s` as its keys tell (spec/permissions.md §4,
    /// spec/crypto.md §4: a node holding no current read secret of the actor): a current read
    /// epoch of S's thing is known here and none is held. `None` otherwise, or for a sync ID not
    /// read here. Whether a complete pass came first is sync's (it reads this at a heard-out S).
    pub fn stranded(&mut self, s: &SyncId) -> Result<Option<Stranding>> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(None) };
        let Some(e) = self.core.epochs(&t) else { return Ok(None) };
        let read = e.role(Role::Read);
        let current = read.current();
        if current.is_empty() || current.iter().any(|ep| read.secret(ep).is_some()) {
            return Ok(None);
        }
        self.stranding(s, None)
    }

    /// The report of this node stranded on read sync ID `s` where sync judged it (spec/permissions.md
    /// §4: a walk stopped at a store source, spec/sync-ids.md §6 Walk), naming `step`, the sync key
    /// of the step it stopped at (none: its recorded head). `None` for a sync ID not read here.
    pub fn stranding(&mut self, s: &SyncId, step: Option<[u8; 32]>) -> Result<Option<Stranding>> {
        let Some((t, o)) = self.read_sync_id(s)? else { return Ok(None) };
        let actor = self.core.reader_of(&t);
        let holder = self.own_holder(&actor);
        let step = step.unwrap_or_else(|| o.path.steps.last().map_or([0; 32], |(st, _)| st.keys.sync.to_bytes()));
        let me = self.core.account.get();
        let admins = self.core.key_holders(&actor).into_iter().filter(|(m, r)| *r == Role::Admin && Some(*m) != me).map(|(m, _)| m).collect();
        Ok(Some(Stranding { actor, holder, step, keys: self.current_keys(&holder), admins }))
    }

    /// The holder of `a` this node reads it through, as it judges it (spec/permissions.md §4):
    /// its account when that holds `a`, else a holder of `a` that is no key actor and that its
    /// account holds a role on (a team); its account when it judges none.
    fn own_holder(&self, a: &Tid) -> Tid {
        let me = self.core.account.get().unwrap_or_else(|| self.core.id.tid());
        let holders: Vec<Tid> = self.core.key_holders(a).into_iter().map(|x| x.0).collect();
        if holders.contains(&me) {
            return me;
        }
        holders.into_iter().find(|h| !self.core.is_key_actor(h) && self.core.role_now(&me, h).is_some()).unwrap_or(me)
    }

    /// A stranded report's holder keys of `holder` (spec/wire.md §11.2 Stranded): its current
    /// `keys.0` commits each projected to that delta, with their authors' chain certificates for
    /// it (projected, no `keys.0` but the author's own), and that chain's records.
    pub fn holder_keys(&mut self, holder: &Tid) -> Result<HolderKeys> {
        let mut certs = Certs::default();
        for k in self.current_keys(holder) {
            let Some(h) = self.header(&k) else { continue };
            let Some(ai) = h.aspect_index(holder, "keys.0") else { continue };
            certs.commits.entry(k).or_default().insert(ai);
            let Some(mut chain) = self.author_chain(&k, &BTreeSet::from([ai])) else { continue };
            for (x, ps) in chain.commits.iter_mut() {
                let Some(hx) = self.header(x) else { continue };
                ps.retain(|i| hx.aspects.get(*i).is_some_and(|a| a.ak.as_str() != "keys.0" || a.tid == hx.author));
            }
            chain.commits.retain(|_, p| !p.is_empty());
            certs.extend(chain);
        }
        certs.records.insert(*holder);
        let (commits, records) = self.certs_values(&certs)?;
        Ok(HolderKeys { commits, records })
    }

    /// The account among `proven` holding write or above on read sync ID `s`'s actor, as this
    /// node judges it (spec/permissions.md §4: who a Stranded message goes to).
    pub fn writer_of(&mut self, s: &SyncId, proven: &[Tid]) -> Result<Option<Tid>> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(None) };
        let a = self.core.reader_of(&t);
        Ok(proven.iter().find(|x| self.core.is_account(x) && self.core.role_now(x, &a) >= Some(Role::Write)).copied())
    }

    /// The account among `proven` that may read read sync ID `s`'s thing (`Core::may_read`, the
    /// one access form), as this node judges it: whom a suspect list is judged for
    /// (`repair_suspect`).
    pub fn reader_account(&mut self, s: &SyncId, proven: &[Tid]) -> Result<Option<Tid>> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(None) };
        Ok(proven.iter().find(|x| self.core.is_account(x) && self.core.may_read(x, &t)).copied())
    }

    /// A stranded report (a Stranded message, or a stranded notice taken from this node's inbox):
    /// `holder` is stranded on `s`. Judged from what this node holds alone (spec/permissions.md
    /// §4): only for a sync ID read here whose actor `holder` is a current holder of and that this
    /// node may rotate a role of at or below the holder's; then the keys are taken
    /// (`take_holder_keys`) and the re-seal asked for, met at the end of the actor's next complete
    /// pass (`pass_end`). Returns whether the ask is new.
    pub fn take_stranded(&mut self, s: &SyncId, holder: &Tid, keys: &HolderKeys) -> Result<bool> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(false) };
        let actor = self.core.reader_of(&t);
        self.take_stranded_from(s, holder, keys, Carrier::Report { actor, sync_id: *s, holder: *holder })
    }

    /// `take_stranded` of a report carried by `from`: a Stranded message's report itself (the
    /// newest on its sync ID replacing the one before, `carriers::report_taken`), or the fire of a
    /// stranded notice.
    pub(crate) fn take_stranded_from(&mut self, s: &SyncId, holder: &Tid, keys: &HolderKeys, from: Carrier) -> Result<bool> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(false) };
        let a = self.core.reader_of(&t);
        if !self.may_reseal(&a, holder) {
            return Ok(false);
        }
        self.take_holder_keys(holder, keys, Some(from))?;
        if matches!(from, Carrier::Report { .. }) {
            let ids: BTreeSet<CommitId> = keys.commits.iter().filter_map(|v| CommitBlob::decode(&osis_base::encode(v)).ok()).map(|b| b.id()).collect();
            self.run(|tx| crate::apply::carriers::report_taken(tx, &from, &ids))?;
        }
        let m = *holder;
        if !self.may_reseal(&a, &m) {
            return Ok(false);
        }
        let digest = keys_digest(&self.current_keys(&m));
        if self.core.ix.reseal_asks.get(&(a, m)).is_some_and(|k| k.keys == digest) {
            return Ok(false);
        }
        // the next pass place, as a role commit's arrival takes (`sync::held`)
        self.core.place += 1;
        let k = Ask { at: self.core.place, keys: digest, met: false };
        self.run(|tx| {
            tx.txn.put_local(&ask_key(&a, &m), &k.encode(), Shred::No)?;
            tx.core.ix.reseal_asks.insert((a, m), k);
            Ok(true)
        })
    }

    /// `m` is a current holder of `a` and this node may rotate a role of `a` at or below `m`'s.
    fn may_reseal(&self, a: &Tid, m: &Tid) -> bool {
        let Some(role) = self.core.key_holders(a).into_iter().find(|(x, _)| x == m).map(|x| x.1) else { return false };
        let Ok(me) = self.core.writer() else { return false };
        crate::rotation::may_rotate(&self.core, &me, a).iter().any(|r| *r <= role)
    }

    /// Takes a report's holder keys of `holder` (spec/permissions.md §4, spec/wire.md §11.2): only
    /// what is on the holder's authority chain as judged while taking them (the holder, then
    /// each one's mint admin and current holders, transitively, judged again as what is taken
    /// extends it): records of chain things, `keys.0` deltas on the holder and on the authors of
    /// the holder's `keys.0` commits carried (their cards), `roles.0` deltas on chain things; each
    /// commit, projected to those deltas, kept only if judged valid with every edge write it makes
    /// applied (`ingest_valid`), carried by `from` while it pends. Everything else is ignored.
    /// Returns the commits taken.
    pub fn take_holder_keys(&mut self, holder: &Tid, keys: &HolderKeys, from: Option<Carrier>) -> Result<usize> {
        let blobs: Vec<CommitBlob> = keys.commits.iter().filter_map(|v| CommitBlob::decode(&osis_base::encode(v)).ok()).collect();
        let records: BTreeMap<Tid, CreationRecord> = keys.records.iter().map(|r| (r.tid(), r.clone())).collect();
        // the authors of the holder's `keys.0` deltas carried: their cards are on the chain
        let cards: BTreeSet<Tid> = blobs.iter().filter(|b| b.parts.iter().any(|p| b.header.aspects.get(p.ai).is_some_and(|a| a.tid == *holder && a.ak.as_str() == "keys.0"))).map(|b| b.header.author).collect();
        let mut done: BTreeSet<usize> = BTreeSet::new();
        let mut learned: BTreeSet<Tid> = BTreeSet::new();
        let mut taken = 0;
        loop {
            let chain = self.authority_chain(holder);
            let mut moved = false;
            let recs: Vec<CreationRecord> = records.iter().filter(|(t, _)| chain.contains(*t) && !learned.contains(*t) && self.core.created(t).is_none()).map(|(_, r)| r.clone()).collect();
            if !recs.is_empty() {
                learned.extend(recs.iter().map(CreationRecord::tid));
                moved |= self.learn_records(recs)? > 0;
            }
            for (i, b) in blobs.iter().enumerate() {
                if done.contains(&i) {
                    continue;
                }
                let on = |ai: usize| {
                    b.header.aspects.get(ai).is_some_and(|a| match a.ak.as_str() {
                        "keys.0" => a.tid == *holder || chain.contains(&a.tid) && cards.contains(&a.tid),
                        "roles.0" => chain.contains(&a.tid),
                        _ => false,
                    })
                };
                if !b.parts.iter().any(|x| on(x.ai)) {
                    continue;
                }
                let mut p = b.clone();
                p.parts.retain(|x| on(x.ai));
                done.insert(i);
                osis_base::costs::count("stranded: holder keys judged", 1);
                if self.ingest_valid(&p.encode(), from)?.is_some() {
                    taken += 1;
                    moved = true;
                }
            }
            if !moved {
                return Ok(taken);
            }
        }
    }

    /// The authority chain of `holder` (spec/permissions.md §4): the holder, then each one's
    /// mint admin and current holders, transitively, as held here.
    fn authority_chain(&self, holder: &Tid) -> BTreeSet<Tid> {
        let mut out = BTreeSet::from([*holder]);
        let mut todo = vec![*holder];
        while let Some(x) = todo.pop() {
            let up = self.core.created(&x).and_then(CreationRecord::mint_admin).into_iter().chain(self.core.key_holders(&x).into_iter().map(|h| h.0));
            for y in up {
                if out.insert(y) {
                    todo.push(y);
                }
            }
        }
        out
    }

    /// `certs` as `CommitBlobPlaintext` values projected to their parts and creation records
    /// (spec/wire.md §11.2 Stranded).
    pub(crate) fn certs_values(&mut self, certs: &Certs) -> Result<(Vec<Value>, Vec<CreationRecord>)> {
        let mut out = Vec::new();
        for (x, ps) in &certs.commits {
            let id = *x;
            let Some(full) = self.read(|tx| tx.get_commit(&id))? else { continue };
            let mut b = Arc::unwrap_or_clone(full);
            b.parts.retain(|p| ps.contains(&p.ai));
            if b.parts.is_empty() {
                continue;
            }
            out.extend(osis_base::decode(&b.encode(), &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB)).ok());
        }
        let records = certs.records.iter().filter_map(|t| self.core.created(t).cloned()).collect();
        Ok((out, records))
    }
}
