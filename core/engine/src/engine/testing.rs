//! Test hooks: `#[doc(hidden)] pub` because the crate's `tests/it` calls them.

use super::index::*;
use super::Engine;
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// One row of `Engine::body_page`.
#[doc(hidden)]
pub struct HeldBody {
    pub id: CommitId,
    /// Its commit's purge author (`View::purge_author`).
    pub purge_author: Option<Tid>,
    pub ts: osis_base::Ts,
    pub valid: bool,
    pub value: Option<osis_base::Value>,
}

/// The family of local key `k`: up to its first `/`, else 3 bytes (`Engine::local_census`,
/// `Engine::rows`).
pub(crate) fn family(k: &[u8]) -> &[u8] {
    let end = k.iter().position(|b| *b == b'/').map_or(3.min(k.len()), |p| (p + 1).min(k.len()));
    k.get(..end).unwrap_or(k)
}

impl Engine {
    /// How many actors `flows::retake` lists (`Waits::untaken`): each entry is owned by its
    /// actor's `secrets.0` state, so none outlives it.
    #[doc(hidden)]
    pub fn retake_listed(&self) -> usize {
        self.core.waits.untaken_len()
    }

    /// The grant writes held role commit `id` makes, whatever the delete keys it lists (none while
    /// a reset names a write not held, `validity::edge_writes_of`, nor for a split commit): the
    /// applied ones (`ix.held`) less a miskeyed commit's left out.
    #[doc(hidden)]
    pub fn edge_writes(&mut self, id: &CommitId) -> Result<Vec<osis_perm::GrantOp>> {
        let id = *id;
        self.read(|tx| {
            let Some(v) = tx.core.ix.commits.get(&id).filter(|m| matches!(m.header.path, osis_commit::Paths::One(_))).map(|m| m.view.clone()) else { return Ok(Vec::new()) };
            let parts = crate::apply::perm_parts(tx, &id)?;
            let per = crate::apply::validity::edge_writes_of(tx.core, &v, &id, &parts);
            Ok(if per.iter().all(|x| x.2) { per.into_iter().flat_map(|x| x.1).collect() } else { Vec::new() })
        })
    }

    /// Tests only: rotates `roles` of `a` boxing every holder this node would but `skip`, as a
    /// rotation that left them out (a holder left out of a rotation, spec/permissions.md §4
    /// Stranded). The commit made.
    #[doc(hidden)]
    pub fn rotate_leaving_out(&mut self, a: &Tid, roles: &[osis_base::Role], skip: &[Tid]) -> Result<Option<CommitId>> {
        let (a, roles): (Tid, BTreeSet<osis_base::Role>) = (*a, roles.iter().copied().collect());
        let skip: Vec<(Tid, Option<osis_base::Role>)> = skip.iter().map(|t| (*t, None)).collect();
        self.run(|tx| {
            let held = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
            let me = tx.core.tid();
            let holders = crate::rotation::recipients(tx, &me, &a, &skip)?;
            let mut m = crate::Mutation::new();
            let r = crate::rotation::rotation_into(tx, &mut m, a, &roles, &held, &holders, crate::rotation::Departs::No)?;
            let c = Engine::commit_tx(tx, m)?;
            crate::rotation::recorded(tx, a, c, &r, &mut crate::flows::Done::default())?;
            Ok(c)
        })
    }

    /// Tests only: an exact copy of this engine as it stands, on `clock`, sharing no mutable
    /// state with it (notes/test-harnesses.md, Copied worlds): its store over test copies of the backend
    /// and root (`osis_store::Store::test_copy`), its indexes, caches and memos, its rngs
    /// continuing the same streams (`NodeRng::test_copy`). It goes on exactly as this one would.
    /// Not copied: event subscribers and commit listeners (their owner subscribes and listens
    /// again). Never in a product: the copy is the same node, its identity, session and rng
    /// stream twice, so the two would reuse nonces, counters and commit IDs. Called inside a
    /// world copy (`osis_base::copying`) to copy several nodes and what they share as one.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: std::sync::Arc<dyn osis_base::Clock>) -> Result<Engine> {
        osis_base::copying::copying(|| {
            Ok(Engine {
                instance: self.instance,
                store: self.store.test_copy()?,
                blobs: self.blobs.clone().test_copy(clock.clone())?,
                blob_stamps: self.blob_stamps.clone(),
                blob_seq: self.blob_seq,
                blobs_unsettled: self.blobs_unsettled,
                failed_seen: self.failed_seen,
                taken_failed: self.taken_failed,
                loads: self.loads,
                store_rng: self.store_rng.test_copy(),
                rng: self.rng.test_copy(),
                core: self.core.test_copy(clock.clone()),
                eph: self.eph.clone(),
                clock,
                cfg: self.cfg.clone(),
                // the original checks their shared past
                #[cfg(debug_assertions)]
                index_unchecked: false,
                #[cfg(debug_assertions)]
                verdicts_unchecked: false,
                #[cfg(debug_assertions)]
                last_tx_wall: self.last_tx_wall,
                #[cfg(debug_assertions)]
                loading: self.loading,
                #[cfg(test)]
                index_poked: self.index_poked,
                #[cfg(test)]
                check_every_tx: self.check_every_tx,
            })
        })
    }

    /// Per held snapshot of `(tid, ak)`, the runs of counters of the writes it carries
    /// (`retention::snapshot::Carried`).
    #[doc(hidden)]
    pub fn carried_bounds(&self, tid: &Tid, ak: &Ak) -> Vec<usize> {
        self.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|s| s.4.len()).collect()
    }

    /// Commits `m` past the writer's rules, as a hostile node would: its role check, commit
    /// shape rules and refusal to emit a delta it judges invalid. A receiver's judgment of what
    /// no writer makes can be tested so.
    #[doc(hidden)]
    pub fn commit_hostile(&mut self, mut m: crate::Mutation) -> Result<Option<CommitId>> {
        m.unchecked();
        self.core.forged.clear();
        let was = std::mem::replace(&mut self.core.skip_writer_rules, true);
        let r = self.commit(m);
        self.core.skip_writer_rules = was;
        r
    }

    /// Commit `id` as sent, built while `skip_writer_rules` or `forge_bad` was set (tests: what
    /// this node's own copy may have dropped of it); since the last `commit_hostile` began.
    #[doc(hidden)]
    pub fn take_forged(&mut self, id: &CommitId) -> Option<Vec<u8>> {
        self.core.forged.remove(id)
    }

    /// `commit_hostile` with every delta on the aspects `bad` replaced by bytes that do not decode
    /// (the header hashing them), and the blob as sent: this node's own copy drops them.
    #[doc(hidden)]
    pub fn commit_forged(&mut self, m: crate::Mutation, bad: std::collections::BTreeSet<(osis_base::Tid, osis_base::Ak)>) -> Result<Option<(CommitId, Vec<u8>)>> {
        self.core.forge_bad = bad;
        let r = self.commit_hostile(m);
        self.core.forge_bad = Default::default();
        Ok(r?.and_then(|id| Some((id, self.take_forged(&id)?))))
    }

    /// Rotates `roles` of each of `actors` in one commit as a hostile writer would: boxing only
    /// those of its current holders in `boxed` (itself alone locks out the rest: notes/keys.md,
    /// Lockouts).
    #[doc(hidden)]
    pub fn rotate_boxing_only(&mut self, actors: &[Tid], roles: &[osis_base::Role], boxed: &[Tid]) -> Result<Option<CommitId>> {
        let roles = roles.iter().copied().collect();
        self.run(|tx| {
            let mut m = crate::Mutation::new();
            let mut rots = Vec::new();
            for a in actors {
                let held = tx.core.epochs(a).ok_or(Error::Misuse("no secrets held for the actor"))?;
                let mut holders = crate::rotation::recipients(tx, &tx.core.tid(), a, &[])?;
                holders.holders.retain(|r| boxed.contains(&r.holder));
                rots.push((*a, crate::rotation::rotation_into(tx, &mut m, *a, &roles, &held, &holders, crate::rotation::Departs::No)?));
            }
            let c = Engine::commit_tx(tx, m)?;
            for (a, rot) in &rots {
                crate::rotation::record(tx, *a, rot)?;
            }
            Ok(c)
        })
    }

    /// Tests only: fires external signal `ak` on `thing` with `value` as any fire goes
    /// (`flows::inbox::fire`): written where this node reads the thing, refused where its setting
    /// does not take it, else owed sealed.
    #[doc(hidden)]
    pub fn fire_open(&mut self, thing: &Tid, ak: &str, value: osis_base::Value) -> Result<()> {
        let t = *thing;
        self.run(|tx| crate::flows::inbox::fire(tx, t, ak, value, std::collections::BTreeSet::new()))
    }

    /// Tests only: what `LocalPeer`'s plaintext delivery stands for. A package stands for an
    /// entry sealed under the newest read epoch of each of its things whose secret is held here,
    /// established or not (its writer sealed under its newest; a newer one here is only
    /// stricter): each part is noted opened under it (`sync_ids::opened`), as `open_commit` notes
    /// a section's. Nothing is noted for a thing with no read secret held.
    #[doc(hidden)]
    pub fn note_delivered(&mut self, b: &osis_commit::CommitBlob) {
        let mut by: std::collections::BTreeMap<Tid, Vec<&osis_commit::Part>> = std::collections::BTreeMap::new();
        for p in &b.parts {
            if let Some(a) = b.header.aspects.get(p.ai) {
                by.entry(a.tid).or_default().push(p);
            }
        }
        let under: Vec<_> = by.into_iter().filter_map(|(t, ps)| Some((t, self.epochs(&t)?.read.held_newest_first().first()?.0, ps))).collect();
        self.note_opened(&b.header, &under);
    }

    /// `(tid, ak)`'s state encoded as a snapshot fragment with its pages (empty: no state):
    /// nodes holding the same bodies hold the same bytes (tests comparing nodes' states).
    #[doc(hidden)]
    pub fn state_bytes(&mut self, tid: &Tid, ak: &Ak) -> Result<Vec<u8>> {
        Ok(self.read(|tx| tx.state(tid, ak)?.map(crate::engine::state::encode).transpose())?.unwrap_or_default())
    }

    /// The store's local rows and blobs by kind (a row's key up to its first `/`, else 3 bytes;
    /// node sync's `y/` rows by their next byte too): count and key plus value bytes. Tests
    /// counting what grows (notes/growth.md).
    #[doc(hidden)]
    pub fn local_census(&mut self) -> Result<std::collections::BTreeMap<String, (usize, usize)>> {
        let rows = self.read(|tx| Ok(tx.txn.scan_local(b"", b"", usize::MAX)?))?;
        let mut out = std::collections::BTreeMap::<String, (usize, usize)>::new();
        for (k, v) in rows {
            let e = out.entry(String::from_utf8_lossy(family(&k)).into_owned()).or_default();
            e.0 += 1;
            e.1 += k.len() + v.len();
        }
        Ok(out)
    }

    /// Every logical store row by family (`Transaction::census`): count and key plus value
    /// bytes. Tests counting what a thing costs (notes/thing-cost.md).
    #[doc(hidden)]
    pub fn census(&mut self) -> Result<std::collections::BTreeMap<String, (usize, usize)>> {
        self.read(|tx| Ok(tx.txn.census()?))
    }

    /// The KEM key of held keyset `e` of role `r` of `m`, as sealing reads it
    /// (`apply::keys::keyset_kem`).
    #[cfg(test)]
    pub(crate) fn keyset_kem(&mut self, m: &Tid, r: osis_base::Role, e: &osis_crypto::Epoch) -> Result<Option<osis_crypto::KemPublicKey>> {
        self.read(|tx| crate::apply::keys::keyset_kem(tx, m, r, e))
    }

    /// What the store holds, decrypted (`Store::dump`): tests compare two nodes' stores.
    #[doc(hidden)]
    pub fn store_dump(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(self.store.dump()?)
    }

    /// What an attacker holding this node's device recovers from everything `backend` (the
    /// engine's store) and `blobs` (its ciphertext store's) recorded (`osis_store::attack`): the
    /// current tree's keys, the sync ID read secrets this node's code computes now, blobs and wraps
    /// opened as osis-blob does. Shredding tests.
    #[doc(hidden)]
    pub fn forensic(&mut self, backend: &osis_store::MemoryBackend, blobs: &osis_store::MemoryBackend) -> Result<Vec<osis_store::Recovered>> {
        // the one store: the engine's and its ciphertext store's (the hub's, its entry rows)
        let mut keys = self.store.forensic_keys()?;
        keys.extend(self.blobs.begin().forensic_keys()?);
        let mut ev = osis_store::Evidence::of(keys, backend);
        ev.rows.extend(blobs.history());
        ev.blobs.extend(blobs.blob_history());
        ev.sealed.extend(blobs.sealed());
        let tids: std::collections::BTreeSet<Tid> = self.all_aspects()?.into_iter().map(|(t, _)| t).collect();
        for t in tids {
            ev.secrets.extend(self.read_secrets(&t).iter().map(|s| *s.expose()));
        }
        Ok(osis_store::attack(&ev, Some(&FORENSIC_CIPHERS)))
    }

    /// How many parts of commit `id` are gone while they wait (`retention::strip_purged`).
    #[doc(hidden)]
    pub fn stripped_count(&mut self, id: &osis_base::CommitId) -> Result<usize> {
        let id = *id;
        self.read(|tx| {
            let Some(b) = tx.txn.get_pending(&id)?.and_then(|p| osis_commit::CommitBlob::decode_stored(&p.bytes).ok()) else { return Ok(0) };
            let mut n = 0;
            for ai in 0..b.header.aspects.len() {
                if crate::retention::waiting_stripped(tx, &b, &id, ai)? {
                    n += 1;
                }
            }
            Ok(n)
        })
    }

    /// Keeps every body: no purge-on-replace cover or drop (tests: an oracle for the earliest
    /// superseder of each write, spec/crdt.md §4.8).
    #[doc(hidden)]
    pub fn keep_bodies(&mut self, on: bool) {
        self.core.keep_bodies = on;
    }

    /// Whether this node answers removals with addenda (spec/permissions.md §5.2): off for an
    /// oracle checking that reads are a function of the received commits alone (a witness's
    /// addendum depends on what it had received when the removal came).
    #[doc(hidden)]
    pub fn write_addenda(&mut self, on: bool) {
        self.core.addenda_on = on;
    }


    /// The list bound in place of `MAX_LIST_BYTES` (tests: frontiers, thing lists and listings
    /// fit end to end).
    #[cfg(test)]
    pub(crate) fn list_bound(&mut self, bytes: usize) {
        self.core.list_bound = bytes;
    }

    /// Whether the delta of `(tid, ak)` in `c` is valid here (`None`: no such delta). Tests: the
    /// order harness reads an invalid body's facts.
    #[doc(hidden)]
    pub fn body_valid(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<bool> {
        let m = self.core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak)?;
        self.part_valid(c, ai)
    }

    /// Whether part `ai` of `c` is valid here (a piece of a `secrets.0` judged alone,
    /// spec/wire.md §4 Pieces).
    #[doc(hidden)]
    pub fn part_valid(&self, c: &CommitId, ai: usize) -> Option<bool> {
        let m = self.core.ix.commits.get(c)?;
        Some(m.valid().get(ai).copied().unwrap_or(true))
    }

    /// Removes `holders` from `target` in one commit under one rotation (spec/commits.md §2), as
    /// a link revocation does (tests: an explicit removal of several holders).
    #[doc(hidden)]
    pub fn remove_holders(&mut self, target: &Tid, first: &Tid, others: &[Tid]) -> Result<crate::flows::Done> {
        self.remove_signed(None, target, &crate::flows::Demotion { holder: *first, new: None, retain: None }, others)
    }

    /// Whether held commit `c` is a role commit whose removal resets an entry of unknown
    /// creation, so none of its grant writes applies (`apply::validity::add_role_commit`; tests).
    #[doc(hidden)]
    pub fn unresolved(&self, c: &CommitId) -> bool {
        self.core.ix.unresolved.contains(c)
    }

    /// The (target, AK) of each strong `source`'s held history holds (`refs::kept`; tests: the
    /// reference index property).
    #[doc(hidden)]
    pub fn history_strongs_from(&mut self, source: &Tid) -> Result<Vec<(Tid, Ak)>> {
        let s = *source;
        self.read(|tx| Ok(super::refs::kept::from(tx, &s)?.into_iter().filter(|r| r.1 == osis_base::RefKind::Strong).map(|r| (r.0, r.2)).collect()))
    }

    /// How many bodies of `(tid, ak)` are held.
    #[doc(hidden)]
    pub fn held_bodies(&self, tid: &Tid, ak: &Ak) -> usize {
        self.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter(|(_, c)| crate::retention::held_part(&self.core, c, tid, ak).is_some()).count()
    }

    /// A page of `n` held bodies of `(tid, ak)` by `(ts, ID)`, read as a history read would:
    /// `skip` from the newest or the oldest end, each with its author, its `ts`, its validity
    /// and its value (tests).
    #[doc(hidden)]
    pub fn body_page(&mut self, tid: &Tid, ak: &Ak, newest: bool, skip: usize, n: usize) -> Result<Vec<HeldBody>> {
        let k = (*tid, ak.clone());
        let set = self.core.ix.by_aspect.get(&k);
        let page: Vec<(osis_base::Ts, CommitId)> = match set {
            Some(s) if newest => s.iter().rev().skip(skip).take(n).copied().collect(),
            Some(s) => s.iter().skip(skip).take(n).copied().collect(),
            None => Vec::new(),
        };
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| {
            let mut out = Vec::new();
            for (ts, c) in &page {
                let Some(m) = tx.core.ix.commits.get(c) else { continue };
                let Some(ai) = m.aspect(&tid, &ak) else { continue };
                let (purge_author, valid) = (Some(m.view.purge_author), m.valid_at(ai));
                let mut v = None;
                crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
                    v = f.read();
                    Ok(())
                })?;
                out.push(HeldBody { id: *c, purge_author, ts: *ts, valid, value: v });
            }
            Ok(out)
        })
    }

    /// The held body of `c` on `(tid, ak)`, its pieces joined (diagnosis: what a commit carries,
    /// gone writes and copies included, where `body_page` gives only its read).
    #[doc(hidden)]
    pub fn body_fragment(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<osis_crdt::Fragment>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| {
            let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(&tid, &ak)) else { return Ok(None) };
            let mut out: Option<osis_crdt::Fragment> = None;
            crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
                match &mut out {
                    Some(o) => {
                        o.join(f);
                    }
                    None => out = Some(f),
                }
                Ok(())
            })?;
            Ok(out)
        })
    }

    /// Where a value the delta of `c` on `(tid, ak)` wrote is still held, in the state or in a held
    /// body of the aspect, as a word for a message (tests: `order::value_past_end`).
    #[doc(hidden)]
    pub fn value_held_of(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<String>> {
        let Some((h, ai)) = self.core.ix.commits.get(c).and_then(|m| Some((m.header.clone(), m.aspect(tid, ak)?))) else { return Ok(None) };
        let owned = crate::retention::writes_of(&h, c, ai);
        let carries = |f: &osis_crdt::Fragment| {
            let mut g = f.clone();
            g.remove_gone(&|d| owned.iter().any(|o| o.owns(d)));
            g != *f
        };
        if self.state(tid, ak)?.is_some_and(|f| carries(&f)) {
            return Ok(Some("the state".into()));
        }
        let bodies: Vec<CommitId> = self.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
        for b in bodies {
            if self.body_fragment(&b, tid, ak)?.is_some_and(|f| carries(&f)) {
                return Ok(Some(format!("body {b:?}")));
            }
        }
        Ok(None)
    }

    /// The part indexes of the parts waiting commit `c`'s stored copy holds, gone ones
    /// included (`None`: not waiting). Tests: the held-model adapter (`tests/it/held.rs`).
    #[doc(hidden)]
    pub fn pending_parts(&mut self, c: &CommitId) -> Result<Option<std::collections::BTreeSet<usize>>> {
        let c = *c;
        self.read(|tx| {
            let Some(osis_store::Pending { bytes, .. }) = tx.txn.get_pending(&c)? else { return Ok(None) };
            let Ok(blob) = osis_commit::CommitBlob::decode_stored(&bytes) else { return Ok(None) };
            Ok(Some(blob.parts.iter().map(|p| p.ai).collect()))
        })
    }

    /// A part of waiting commit `c` whose stored copy still holds a value past its expiry at `now`,
    /// or that a held purge request drops, its thing's record held so it could be stripped (tests:
    /// `order::value_past_end`; spec/commits.md §5).
    #[doc(hidden)]
    pub fn pending_value_past_end(&mut self, c: &CommitId, now: osis_base::Time) -> Result<Option<String>> {
        let c = *c;
        self.read(|tx| {
            let Some(osis_store::Pending { bytes, .. }) = tx.txn.get_pending(&c)? else { return Ok(None) };
            let Ok(blob) = osis_commit::CommitBlob::decode_stored(&bytes) else { return Ok(None) };
            let emptied = crate::retention::emptied();
            for p in blob.parts.iter().filter(|p| p.delta != emptied) {
                let Some(a) = blob.header.aspects.get(p.ai) else { continue };
                if blob.header.expires.is_some_and(|t| t <= now.0) {
                    return Ok(Some(format!("part {} on {:?} {} past its expiry", p.ai, a.tid, a.ak.as_str())));
                }
                if tx.core.dedup(&a.tid).is_some() && crate::retention::known_purged(tx, &blob.header, &c, p.ai)? {
                    return Ok(Some(format!("part {} on {:?} {} purged", p.ai, a.tid, a.ak.as_str())));
                }
            }
            Ok(None)
        })
    }

    /// Writes the stored pages of `(tid, ak)` hold that their skeleton prunes
    /// (`pages::stale_in_pages`; 0 unpaged). Tests: a join that skipped a page write.
    #[cfg(test)]
    pub fn stale_page_writes(&mut self, tid: &Tid, ak: &Ak) -> Result<usize> {
        let k = (*tid, ak.clone());
        self.read(|tx| {
            tx.load_lazy(&k.0, &k.1)?;
            match (tx.core.pages.get(&k), tx.core.states.get(&k)) {
                (Some(idx), Some(Some(f))) => super::pages::stale_in_pages(&mut tx.txn, &k.0, &k.1, idx, f),
                _ => Ok(0),
            }
        })
    }

    /// Whether held commit `c` introduces a keyset of `t` (its rotation, `Indexes::epoch_intro`):
    /// not merely a `keys.0` part (a deposit seed or step write is one too). Tests: delivering the
    /// keyset commits apart.
    pub fn writes_keyset(&self, t: &Tid, c: &CommitId) -> bool {
        self.core.ix.epoch_intro.iter().any(|(k, v)| k.0 == *t && v.1 == *c)
    }

    /// Drops the cached state of `(tid, ak)` and its loaded pages: a new session holds neither.
    /// Tests of what an operation loads, each in a new session without a restart (each restart
    /// is an end of history, checked whole).
    #[doc(hidden)]
    pub fn forget_cached(&mut self, tid: &Tid, ak: &Ak) {
        let k = (*tid, ak.clone());
        self.core.states.remove(&k);
        self.core.pages.remove(&k);
    }

    /// The state of `(tid, ak)` loaded afresh from the store, the cache left as it was. Tests:
    /// a cached state the store does not hold.
    #[cfg(test)]
    pub fn stored_state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<osis_crdt::Fragment>> {
        let k = (*tid, ak.clone());
        let (st, idx) = (self.core.states.remove(&k), self.core.pages.remove(&k));
        let out = self.state(tid, ak);
        self.core.states.remove(&k);
        self.core.pages.remove(&k);
        if let Some(st) = st {
            self.core.states.insert(k.clone(), st);
        }
        if let Some(idx) = idx {
            self.core.pages.insert(k, idx);
        }
        out
    }

    /// Bodies judged so far for when they were replaced (keep bounds). Tests: a judgment's cost
    /// grows with the parts judged, not their square.
    #[doc(hidden)]
    pub fn replaced_reads(&self) -> u64 {
        self.core.replaced_reads
    }

    /// Held parts walked for their winners judging deaths. Tests: a few per part judged,
    /// whatever the deaths.
    #[doc(hidden)]
    pub fn death_walks(&self) -> u64 {
        self.core.death_walks
    }


    /// Aspect rebuilds run so far. Tests: a validity change on a signal rebuilds nothing.
    #[doc(hidden)]
    pub fn rebuilds(&self) -> u64 {
        self.core.rebuilds
    }

    /// How many held `retention^.0` parts are invalid.
    #[doc(hidden)]
    pub fn fallen_settings(&self) -> usize {
        self.core.ix.commits.values().map(|m| m.header.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == osis_commit::retention::RETENTION && !m.valid_at(*ai)).count()).sum()
    }

    /// Every applied durable commit with its parts not received here (`commit_ids` with
    /// `Hold::Missing`): two nodes holding one commit may hold different parts of it.
    #[doc(hidden)]
    pub fn commit_parts_missing(&self) -> BTreeMap<CommitId, std::collections::BTreeSet<usize>> {
        self.core.ix.commits.iter().filter(|(_, m)| !m.view.memory).map(|(id, m)| (*id, m.missing_parts().collect())).collect()
    }

    /// The indexes open rebuilds, field by field (tests: a load from the persisted index equals a
    /// rebuild from the commit records; harnesses compare with `IndexDigest::diff`).
    #[doc(hidden)]
    pub fn index_digest(&self) -> IndexDigest {
        self.core.index_digest()
    }

    /// Damages the persisted index (tests): `garble` a commit's parts row, else mislabel its tag.
    #[doc(hidden)]
    pub fn damage_index(&mut self, garble: bool) -> Result<()> {
        if !garble {
            // another build's rules judged differently: every part valid, and the states
            // joined so
            return self.run(|tx| {
                #[cfg(debug_assertions)]
                {
                    tx.core.unchecked_tx = true;
                }
                let aspects: Vec<(Tid, osis_base::Ak)> = tx.core.ix.invalid.keys().cloned().collect();
                for (tid, ak) in aspects {
                    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
                    let mut st = osis_crdt::Fragment::default();
                    for c in held {
                        let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(&tid, &ak)) else { continue };
                        crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
                            st.join(f);
                            Ok(())
                        })?;
                    }
                    tx.set_state(&tid, &ak, (!st.is_empty()).then_some(st), Shred::No)?;
                }
                let t = tx.txn.index(METAS)?;
                let rows: Vec<(CommitId, Vec<u8>)> = tx.core.ix.commits.iter().map(|(id, m)| {
                    let mut row = meta_row(tx.core, id, m);
                    // every part valid, nothing else needed
                    row.iter_mut().skip(4).take(m.parts()).for_each(|p| *p = 1);
                    (*id, row)
                }).collect();
                for (id, row) in rows {
                    tx.txn.table_put(t, &id.0, row, Shred::No)?;
                }
                tx.txn.put_local(VERSION_KEY, b"another build", Shred::No).map_err(Error::from)
            });
        }
        self.run(|tx| {
            let Some(id) = tx.core.ix.commits.keys().next().copied() else { return Ok(()) };
            let t = tx.txn.index(METAS)?;
            tx.txn.table_put(t, &id.0, vec![1; 300], Shred::No)?;
            Ok(())
        })
    }

    /// The role timelines' verdicts per thing (rosters, applied and dropped grant writes): of the components as held (`false`) or of one from-scratch
    /// evaluation of the held set (tests: restored walks equal a from-scratch evaluation).
    #[doc(hidden)]
    pub fn perm_digest(&self, from_scratch: bool) -> String {
        self.core.perm_digest(from_scratch)
    }

    /// Whether a grant write of commit `c` on `t` applies in the settled walk (tests).
    #[doc(hidden)]
    pub fn edge_write_applied(&self, t: &Tid, c: &CommitId) -> bool {
        self.core.timelines().get(t).is_some_and(|tl| tl.held_on(t).any(|(w, mc, _)| mc.id == *c && tl.is_applied(&w)))
    }

    /// Damages the role commits' `PERM_PARTS` rows (tests): 0 truncates one, 1 garbles one,
    /// 2 removes one. Returns how many rows there were.
    #[doc(hidden)]
    pub fn damage_perm_rows(&mut self, how: u8) -> Result<usize> {
        self.run(|tx| {
            let t = tx.txn.index(PERM_PARTS)?;
            let rows = tx.txn.table_range(t, &[], None, 1 << 20)?;
            if let Some((k, v)) = rows.iter().max_by_key(|(_, v)| v.len()) {
                match how {
                    0 => tx.txn.table_put(t, k, v.get(..v.len() / 2).unwrap_or_default().to_vec(), Shred::No).map(|_| ())?,
                    1 => tx.txn.table_put(t, k, vec![0xff; v.len()], Shred::No).map(|_| ())?,
                    _ => tx.txn.table_remove(t, k, Shred::No).map(|_| ())?,
                }
            }
            Ok(rows.len())
        })
    }

    /// The `PERM_PARTS` rows as stored (tests: what a rebuild writes equals what the writes kept).
    #[doc(hidden)]
    pub fn perm_rows(&mut self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.read(|tx| {
            let t = tx.txn.index(PERM_PARTS)?;
            Ok(tx.txn.table_range(t, &[], None, 1 << 20)?)
        })
    }

    /// The first held commit whose flags differ from what judging it now gives (tests: after an
    /// open from the persisted index, every judgment input a body gave is there). Decodes every
    /// header.
    #[doc(hidden)]
    pub fn misjudged(&self) -> Option<String> {
        crate::apply::validity::misjudged(&self.core)
    }

    /// Whether the persisted index is tagged as this build's (tests).
    #[doc(hidden)]
    pub fn index_current(&mut self) -> Result<bool> {
        self.run(current)
    }

    /// Every known commit naming `(tid, ak)` with its part's status (dropped, missing, valid,
    /// covered by), then the aspect's state. Failure detail (the sim's divergence dump).
    #[doc(hidden)]
    pub fn aspect_dump(&mut self, tid: &Tid, ak: &Ak) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for (c, m) in self.core.ix.commits.iter() {
            let Some(ai) = m.aspect(tid, ak) else { continue };
            let h = &m.header;
            let dropped = m.dropped(ai);
            let missing = m.missing(ai);
            let valid = m.valid().get(ai).copied().unwrap_or(true);
            let _ = writeln!(out, "  {c:?} {:?} by {} ts {:?}: dropped {:?} missing {missing} valid {valid} covered by {:?}", h.kind, h.signer, h.ts, dropped.is_some(), dropped.map(|d| &d.covered_by));
        }
        let state = self.state(tid, ak).map(|s| format!("{s:?}")).unwrap_or_else(|e| format!("error {e}"));
        let _ = writeln!(out, "  state {state}");
        out
    }

    /// Rebuilds the state of `(tid, ak)` from its held bodies and current state, as a validity
    /// flip does (tests: equals the state kept incrementally).
    #[doc(hidden)]
    pub fn rebuild_state(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        self.run(|tx| crate::apply::rebuild(tx, tid, ak))
    }

    /// Rebuilds the in-memory indexes from the commit records (and the persisted index), as a
    /// store written by another build would (tests).
    #[doc(hidden)]
    pub fn rebuild_index(&mut self) -> Result<()> {
        self.run(invalidate)?;
        self.reload()
    }
}

/// One index of `IndexDigest::tables`: compared typed (`Core::same_index`), shown entry by entry.
trait Table {
    fn same(&self, o: &dyn Table) -> bool;
    fn any(&self) -> &dyn std::any::Any;
    /// Each entry in key order as text: its key's `Debug`, and its value's (empty for a set).
    fn entries(&self) -> Vec<(String, String)>;
}

impl<K: std::fmt::Debug + PartialEq + 'static, V: std::fmt::Debug + PartialEq + 'static> Table for BTreeMap<K, V> {
    fn same(&self, o: &dyn Table) -> bool {
        o.any().downcast_ref::<Self>().is_some_and(|o| self == o)
    }
    fn any(&self) -> &dyn std::any::Any {
        self
    }
    fn entries(&self) -> Vec<(String, String)> {
        self.iter().map(|(k, v)| (format!("{k:?}"), format!("{v:?}"))).collect()
    }
}

impl<T: std::fmt::Debug + PartialEq + 'static> Table for BTreeSet<T> {
    fn same(&self, o: &dyn Table) -> bool {
        o.any().downcast_ref::<Self>().is_some_and(|o| self == o)
    }
    fn any(&self) -> &dyn std::any::Any {
        self
    }
    fn entries(&self) -> Vec<(String, String)> {
        self.iter().map(|t| (format!("{t:?}"), String::new())).collect()
    }
}

/// The indexes `IndexDigest::tables` holds as entries, by name (a list, no count to keep in step).
fn tables(ix: &super::Indexes) -> Vec<(&'static str, &dyn Table)> {
    vec![
        ("by_thing", &*ix.by_thing),
        ("paths_unknown", &*ix.paths_unknown),
        ("by_actor", &*ix.by_actor),
        ("purges_on", &*ix.purges_on),
        ("by_aspect", &*ix.by_aspect),
        ("aspect_things", &*ix.aspect_things),
        ("originals", &*ix.originals),
        ("versions", &*ix.versions),
        ("invalid", &*ix.invalid),
        ("missing", &*ix.missing),
        ("missing_things", &*ix.missing_things),
        ("ranges", &*ix.ranges),
        ("rotation_role", &*ix.rotation_role),
        ("overreach", &*ix.overreach),
        ("retention", &*ix.retention),
        ("addenda", &*ix.addenda),
        ("addenda_keyed", &*ix.addenda_keyed),
        ("boxes_to", &*ix.boxes_to),
        ("epoch_intro", &*ix.epoch_intro),
        ("keysets", &*ix.keysets),
        ("keysets_invalid", &*ix.keysets_invalid),
        ("independent", &*ix.independent),
        ("destroyed", &*ix.destroyed),
        ("keyset_parts", &*ix.keyset_parts),
        ("holder_keys", &*ix.holder_keys),
        ("unresolved", &*ix.unresolved),
        ("secrets", &*ix.secrets),
        ("void", &*ix.void),
        ("held_wait", &*ix.held_wait),
        ("opened_under", &*ix.opened_under),
        ("blob_parts", &*ix.blob_parts),
        ("commit_blobs", &*ix.commit_blobs),
        ("cert_blobs", &*ix.cert_blobs),
        ("sync_cuts", &*ix.sync_cuts),
        ("sync_cuts_under", &*ix.sync_cuts_under),
        ("sync_cuts_of", &*ix.sync_cuts_of),
        ("sync_cut_ids", &*ix.sync_cut_ids),
        ("sync_cut_things", &*ix.sync_cut_things),
        ("claim_syncs", &*ix.claim_syncs),
        ("keys_sync_id", &*ix.keys_sync_id),
        ("gone", &*ix.gone),
        ("sync_recorded", &*ix.sync_recorded),
        ("sync_recorders", &*ix.sync_recorders),
        ("sync_recorded_ids", &*ix.sync_recorded_ids),
        ("steps", &*ix.steps),
        ("miskeyed", &*ix.miskeyed),
        ("covered_under", &*ix.covered_under),
        ("handed", &*ix.handed),
        ("handed_under", &*ix.handed_under),
        ("forgotten_names", &*ix.forgotten_names),
        ("own_held", &*ix.own_held),
        ("own_replaces", &*ix.own_replaces),
        ("sealed", &*ix.sealed),
        ("boxed", &*ix.boxed),
        ("leaving", &*ix.leaving),
        ("dated", &*ix.dated),
        ("leave_from", &*ix.leave_from),
        ("leave_due", &*ix.leave_due),
        ("resnapshots_owed", &*ix.resnapshots_owed),
        ("freed", &*ix.freed),
        ("kept", &*ix.kept),
        ("timed_lost", &*ix.timed_lost),
        ("fires", &*ix.fires),
        ("fires_on", &*ix.fires_on),
    ]
}

/// `Indexes::derived_written` as an open loads it: an emptied entry stays in memory until then.
fn derived_written(ix: &super::Indexes) -> BTreeMap<Tid, std::collections::BTreeSet<osis_crypto::Epoch>> {
    ix.derived_written.iter().filter(|(_, s)| !s.is_empty()).map(|(t, s)| (*t, s.clone())).collect()
}

/// A commit's `CommitDigest`, its `rest` empty, and what `rest` shows.
fn commit_digest(m: &super::Meta) -> (CommitDigest, (&osis_base::Time, &crate::events::Origin, &super::View)) {
    let n = m.parts();
    let d = CommitDigest { kind: m.view.kind, valid: m.valid().to_vec(), dropped: m.dropped_parts().map(|x| x.0).collect(), stripped: m.stripped_parts().collect(), own_live: (0..n).filter(|ai| m.own_live(*ai)).collect(), missing: m.missing_parts().collect(), whole: (0..n).filter(|ai| m.whole(*ai)).collect(), rest: String::new() };
    (d, (&m.received, &m.origin, &*m.view))
}

/// The role timelines' verdicts `Core::perm_digest` shows: per held thing its roster (`None`: no
/// timeline), then every applied grant write and every held one not applied, and the keyless actor
/// grants.
type PermParts = (Vec<(Tid, Option<BTreeMap<Tid, osis_perm::Grant>>)>, BTreeMap<osis_perm::WriteId, osis_perm::paths::Applied>, BTreeSet<osis_perm::WriteId>, BTreeSet<(Tid, Tid)>);

impl super::Core {
    /// `Engine::index_digest`.
    pub(crate) fn index_digest(&self) -> IndexDigest {
        let ix = &self.ix;
        let commits = ix.commits.iter().map(|(id, m)| {
            let (mut d, rest) = commit_digest(m);
            d.rest = format!("{:?} {:?} {:?}", rest.0, rest.1, rest.2);
            (*id, d)
        }).collect();
        let mut snapshots: BTreeMap<CommitId, Vec<(Tid, Ak, String)>> = BTreeMap::new();
        for ((t, a), v) in ix.snapshots.iter() {
            for s in v {
                snapshots.entry(s.1).or_default().push((*t, a.clone(), format!("{s:?}")));
            }
        }
        let mut tables: BTreeMap<&'static str, Vec<(String, String)>> = tables(ix).into_iter().map(|(n, t)| (n, t.entries())).collect();
        tables.insert("derived_written", derived_written(ix).entries());
        IndexDigest { commits, held: self.held_digest(), snapshots, tables }
    }

    /// `IndexDigest::held`.
    fn held_digest(&self) -> BTreeMap<Tid, (Vec<CommitId>, bool)> {
        let ix = &self.ix;
        ix.held.all_things().into_iter().map(|t| {
            // sorted: the held set keeps arrival order, which nothing it answers depends on
            let mut cs: Vec<CommitId> = ix.held.edge_commits(&t).iter().map(|x| x.id).collect();
            cs.sort();
            (t, (cs, ix.held.created(&t).is_some()))
        }).collect()
    }

    /// Whether `index_digest` and `perm_digest(false)` of `self` and `o` are equal, compared
    /// without text (`Engine::check_index`; its failure message shows the digests). At least as
    /// strict as the digests: snapshots compared in their held order.
    pub(crate) fn same_index(&self, o: &Self) -> bool {
        let (a, b) = (&self.ix, &o.ix);
        a.commits.len() == b.commits.len()
            && a.commits.iter().zip(b.commits.iter()).all(|((x, m), (y, n))| x == y && commit_digest(m) == commit_digest(n))
            && self.held_digest() == o.held_digest()
            && *a.snapshots == *b.snapshots
            && tables(a).iter().zip(tables(b).iter()).all(|((_, x), (_, y))| x.same(*y))
            && derived_written(a) == derived_written(b)
            && self.perm_parts(false) == o.perm_parts(false)
    }

    /// `PermParts` of the components as held (`false`) or of one from-scratch evaluation.
    fn perm_parts(&self, from_scratch: bool) -> PermParts {
        let held = &self.ix.held;
        // from scratch: one update over every held commit and record, under the same trust set
        let full = from_scratch.then(|| {
            let mut tl = self.timelines().emptied();
            let commits: BTreeSet<CommitId> = self.ix.commits.keys().copied().collect();
            let things: BTreeSet<Tid> = held.all_things().into_iter().collect();
            tl.update(self, &commits, &things);
            tl
        });
        let get = |t: &Tid| full.as_ref().or_else(|| self.timelines().get(t));
        let (mut rosters, mut applied, mut dropped) = (Vec::new(), BTreeMap::new(), BTreeSet::new());
        for t in held.all_things() {
            let Some(tl) = get(&t) else {
                rosters.push((t, None));
                continue;
            };
            rosters.push((t, Some(tl.roster(&t, osis_perm::At::END))));
            for (w, _, _) in tl.held_on(&t) {
                match tl.applied(&w) {
                    Some(a) => drop(applied.insert(w, a)),
                    None => drop(dropped.insert(w)),
                }
            }
        }
        let keyless = match &full {
            Some(tl) => crate::rotation::members::keyless_in(tl),
            None => (*self.timelines().keyless()).clone(),
        };
        (rosters, applied, dropped, keyless)
    }

    /// `Engine::perm_digest`.
    pub(crate) fn perm_digest(&self, from_scratch: bool) -> String {
        use std::fmt::Write;
        let (rosters, applied, dropped, keyless) = self.perm_parts(from_scratch);
        let mut out = String::new();
        for (t, r) in rosters {
            let _ = match r {
                Some(r) => writeln!(out, "{t:?} {r:?}"),
                None => writeln!(out, "{t:?} no timeline"),
            };
        }
        let _ = writeln!(out, "applied {applied:?}\nnot applied {dropped:?}\nkeyless {keyless:?}");
        out
    }
}

/// The indexes open rebuilds (`Engine::index_digest`): the parts harnesses tell apart typed,
/// keyed by commit, snapshot or thing; every other index by name, as its entries in key order
/// (each its key's and its value's `Debug` text, `Table::entries`).
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexDigest {
    pub commits: BTreeMap<CommitId, CommitDigest>,
    /// Per thing perm's held set reads: its edge commits, sorted, and whether its creation record
    /// is held.
    pub held: BTreeMap<Tid, (Vec<CommitId>, bool)>,
    /// Per compaction snapshot: its `snapshots` entries, with their aspect.
    pub snapshots: BTreeMap<CommitId, Vec<(Tid, Ak, String)>>,
    pub tables: BTreeMap<&'static str, Vec<(String, String)>>,
}

/// One commit of `IndexDigest::commits`.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDigest {
    pub kind: osis_commit::Kind,
    pub valid: Vec<bool>,
    /// Aspects whose deltas were all dropped.
    pub dropped: std::collections::BTreeSet<usize>,
    /// Aspects held as their leftover (`Hold::Leftover`), those none of whose own writes are gone (`Hold::Leftover::own_live`).
    pub stripped: std::collections::BTreeSet<usize>,
    pub own_live: std::collections::BTreeSet<usize>,
    pub missing: std::collections::BTreeSet<usize>,
    /// Held parts standing as whole replaces (`Hold::Body::whole`).
    pub whole: std::collections::BTreeSet<usize>,
    /// Received time, origin and view, as text.
    pub rest: String,
}

/// Where two `IndexDigest`s differ: one entry per commit, thing, snapshot, or key of a named
/// index (its `Debug` text).
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexField {
    Commit(CommitId),
    Held(Tid),
    Snapshots(CommitId),
    Table(&'static str, String),
}

impl IndexDigest {
    /// Every field where `self` and `other` differ, in field order.
    pub fn diff(&self, other: &Self) -> Vec<IndexField> {
        // destructured: a new field fails to compile until it is compared
        let IndexDigest { commits, held, snapshots, tables } = self;
        let mut out = Vec::new();
        keyed(commits, &other.commits, IndexField::Commit, &mut out);
        keyed(held, &other.held, IndexField::Held, &mut out);
        keyed(snapshots, &other.snapshots, IndexField::Snapshots, &mut out);
        let names: BTreeSet<&'static str> = tables.keys().chain(other.tables.keys()).copied().collect();
        for n in names {
            let (a, b) = (table_entries(tables.get(n)), table_entries(other.tables.get(n)));
            keyed(&a, &b, |k: &str| IndexField::Table(n, k.to_string()), &mut out);
        }
        out
    }

    /// Field `f` of this digest as text (`None`: absent), for a failure message: a table's field
    /// is its key's whole entry.
    pub fn show(&self, f: &IndexField) -> Option<String> {
        let s = |x: Option<&dyn std::fmt::Debug>| x.map(|x| format!("{x:?}"));
        match f {
            IndexField::Commit(c) => s(self.commits.get(c).map(|x| x as _)),
            IndexField::Held(t) => s(self.held.get(t).map(|x| x as _)),
            IndexField::Snapshots(c) => s(self.snapshots.get(c).map(|x| x as _)),
            IndexField::Table(n, k) => table_entries(self.tables.get(n)).get(k.as_str()).map(|v| v.join(", ")),
        }
    }

    /// The first difference from `other` (`None`: equal), described: the field's whole entry on
    /// each side (a table's: its key's).
    pub fn first_diff(&self, other: &Self) -> Option<String> {
        let f = self.diff(other).into_iter().next()?;
        let (want, got) = (self.show(&f).unwrap_or("<none>".into()), other.show(&f).unwrap_or("<none>".into()));
        Some(format!("index {f:?}:\n  want {want}\n  got  {got}"))
    }

    /// Without the held set (`held`): what validity tests compare.
    pub fn without_held(mut self) -> Self {
        self.held.clear();
        self
    }
}

/// How blobs, wraps and sections open, as osis-blob and osis-commit open them (`Engine::forensic`).
const FORENSIC_CIPHERS: osis_store::Ciphers = osis_store::Ciphers {
    prefix: |blob| osis_blob::blob::Prefix::parse(blob).ok().map(|p| p.len()),
    open: |blob, key| osis_blob::open(blob, &osis_crypto::Secret32::from_bytes(*key)).ok().map(|(_, p)| p),
    sections: |plain| {
        let Ok(env) = osis_commit::Envelope::decode(plain) else { return Vec::new() };
        let id = env.id();
        env.sections.into_iter().map(|s| Box::new(ForensicSection { bytes: [&id.0[..], &s.nonce, &s.ciphertext].concat(), id, s }) as Box<dyn osis_store::Section>).collect()
    },
};

/// A section of a commit blob as the forensic attack tries it (`osis_store::Section`): its
/// bytes are the commit ID, the nonce and the ciphertext, all `open` reads (the ID and the nonce
/// of fixed length, `Envelope::decode` checks, so no two sections join to the same bytes).
struct ForensicSection {
    id: CommitId,
    s: osis_commit::Section,
    bytes: Vec<u8>,
}

impl osis_store::Section for ForensicSection {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    // as its read secret or as the key itself, each key only if its first plaintext bytes can
    // begin a section (either `Contents` form: a commit stating one path, or the split form)
    fn open(&self, t: &osis_crypto::Trial) -> Option<Vec<u8>> {
        let may = |z: &osis_crypto::aead::Keystream| self.s.may_open_with(z, false) || self.s.may_open_with(z, true);
        let open = |k: &osis_crypto::Secret32| osis_crypto::open_section(&self.id, k, &self.s.ciphertext).ok();
        let derived = t.section_key(&self.id, &self.s.nonce);
        let dz = osis_crypto::aead::Keystream::new(derived.expose(), &osis_crypto::aead::ZERO_NONCE);
        may(&dz).then(|| open(&derived)).flatten().or_else(|| may(t.zero()).then(|| open(t.key())).flatten())
    }
}

/// A table's entries by key text: the values of every key whose `Debug` reads alike (one,
/// unless two keys print alike), so a difference is found whatever the keys print.
fn table_entries(t: Option<&Vec<(String, String)>>) -> BTreeMap<&str, Vec<&str>> {
    let mut out: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (k, v) in t.into_iter().flatten() {
        out.entry(k.as_str()).or_default().push(v.as_str());
    }
    out
}

/// The keys of `a` and `b` whose values differ (or that one lacks), as fields.
fn keyed<K: Ord + Clone, V: PartialEq>(a: &BTreeMap<K, V>, b: &BTreeMap<K, V>, f: impl Fn(K) -> IndexField, out: &mut Vec<IndexField>) {
    let keys: std::collections::BTreeSet<&K> = a.keys().chain(b.keys()).collect();
    out.extend(keys.into_iter().filter(|k| a.get(*k) != b.get(*k)).map(|k| f(k.clone())));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec: none (test support): every index the check compares is named once, so none is
    // shadowed in `IndexDigest::tables` by a twin a merge left behind.
    #[test]
    fn index_tables_named_once() {
        let ix = super::super::Indexes::default();
        let names: Vec<_> = tables(&ix).into_iter().map(|(n, _)| n).collect();
        let set: BTreeSet<_> = names.iter().collect();
        assert_eq!(set.len(), names.len(), "{names:?}");
    }

    // spec: none (test support): the index check's message names the differing table key and
    // shows that key's whole entry on each side, however long, and no other entry.
    #[test]
    fn first_diff_shows_the_differing_keys_whole_entry() {
        let long = "x".repeat(5_000);
        let table = |v: &str| IndexDigest { tables: [("versions", vec![("a".into(), "same".into()), ("b".into(), format!("{long}{v}")), ("c".into(), "same".into())])].into(), ..Default::default() };
        let d = table("1").first_diff(&table("2")).unwrap();
        assert!(d.starts_with("index Table(\"versions\", \"b\"):"), "{d}");
        assert!(d.contains(&format!("want {long}1\n")) && d.ends_with(&format!("got  {long}2")), "{d}");
        assert!(!d.contains("same"), "{d}");
        let gone = IndexDigest { tables: [("versions", vec![("a".into(), "same".into())])].into(), ..Default::default() };
        let d = table("1").first_diff(&gone).unwrap();
        assert!(d.starts_with("index Table(\"versions\", \"b\"):") && d.ends_with("got  <none>"), "{d}");
    }

    // spec: none (test support): every index is in `tables`, compared on its own in
    // `index_digest`, or listed here as left out of the check, so a new index is placed on purpose.
    #[test]
    fn every_index_is_placed_in_the_check() {
        const OWN: &[&str] = &["held", "commits", "snapshots", "derived_written"];
        // node-local or re-derived by an open, so they differ from a fresh load by design: a
        // transaction's work queues (`rekeyed`, `cover_waits`); what an open parks anew (`pending`, `pend_on`,
        // `pend_keys`, `pend_by`, `pend_needs`, `pend_opened`, `pend_openers`: each examined again); rows not persisted for ephemeral aspects
        // (`forgotten`); events, not the held set (`falls`, `passes`, `role_arrivals`,
        // `cause_at`, `reseal_asks`, `carriers`, `carrying`, `local_log`); the node closure, built again after an open (`closure`);
        // the removals to judge for addenda, all of them again at an open (`addenda_due`,
        // `addenda_gathered`, `addenda_wake`).
        const LEFT_OUT: &[&str] = &["rekeyed", "keys_due", "fires_due", "cards_due", "cards_stale", "forgotten", "pending", "pend_on", "pend_keys", "pend_by", "pend_needs", "pend_opened", "pend_openers", "falls", "passes", "role_arrivals", "cause_at", "setting_waits", "reseal_asks", "carriers", "carrying", "local_log", "cover_waits", "closure", "addenda_due", "addenda_gathered", "addenda_wake"];
        let ix = super::super::Indexes::default();
        let compared: BTreeSet<&str> = tables(&ix).into_iter().map(|(n, _)| n).collect();
        for n in super::super::INDEX_NAMES {
            let places = [compared.contains(n), OWN.contains(n), LEFT_OUT.contains(n)].into_iter().filter(|x| *x).count();
            assert_eq!(places, 1, "index {n}: in tables, compared on its own, or left out: exactly one");
        }
        assert_eq!(compared.len() + OWN.len() + LEFT_OUT.len(), super::super::INDEX_NAMES.len(), "a listed name that is no index");
    }

    // spec: none (forensic test support): a section key planted on the device opens its section
    // in the attack (`Section::may_open_with` never rules out a real one), for sections of two
    // parts and of more parts than one CBOR head byte counts; without the key it stays shut.
    #[test]
    fn forensic_opens_a_section_by_its_planted_key() {
        use osis_base::{Value, Time};
        let mut lp = crate::local_peer::LocalPeer::fresh(1, Time(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = crate::Mutation::new();
        let (one, many) = (e.new_thing(&mut m, me), e.new_thing(&mut m, me));
        m.set(one, &Ak::new("x:a.0").unwrap(), &Value::Str("PLANTED-ONE".into())).unwrap();
        for i in 0..30 {
            m.set(many, &Ak::new(format!("x:a{i:02}.0")).unwrap(), &Value::Str(format!("PLANTED-MANY-{i}"))).unwrap();
        }
        let id = e.commit(m).unwrap().unwrap();
        // the commit blob as sync IDs carry it: its key planted, no wrap or read secret on the device
        let body = e.body(&id).unwrap().unwrap();
        let sealed = e.seal(&body, osis_blob::Class::Durable, &[], &mut osis_crypto::SeededRng::from_u64(0)).unwrap().unwrap();
        let env = osis_commit::Envelope::decode(&osis_blob::open(&sealed.blob, &sealed.key).unwrap().1).unwrap();
        let bk = sealed.key;
        let framed = sealed.blob;
        let reads: Vec<_> = [one, many].iter().flat_map(|t| e.read_secrets(t)).collect();
        let attack = |secrets: Vec<[u8; 32]>| {
            let ev = osis_store::Evidence { secrets, blobs: vec![(sealed.id, Some(framed.clone()))], ..Default::default() };
            osis_store::attack(&ev, Some(&FORENSIC_CIPHERS)).into_iter().map(|r| r.plain).collect::<Vec<_>>()
        };
        let has = |found: &[Vec<u8>], marker: &[u8]| found.iter().any(|x| x.windows(marker.len()).any(|w| w == marker));
        assert!(!has(&attack(vec![*bk.expose()]), b"PLANTED"), "shut without its key");
        let mut tried = Vec::new();
        for s in &env.sections {
            let Some(key) = reads.iter().find(|r| s.opens_under(&env.id(), r)).map(|r| osis_crypto::section_key(r, &env.id(), &s.nonce)) else { continue };
            let found = attack(vec![*bk.expose(), *key.expose()]);
            let marker: &[u8] = if s.ais.len() >= 24 { b"PLANTED-MANY-29" } else { b"PLANTED-ONE" };
            assert!(has(&found, marker), "{} parts", s.ais.len());
            tried.push(s.ais.len());
        }
        tried.sort();
        assert_eq!(tried, [2, 31], "each thing's creation and its aspects");
    }

    // spec: none (forensic test support): a key that failed on a section in one attack still
    // opens a section of the same commit at the same place in a later attack when that one was
    // sealed again under it (the attack's memo of failed tries is by a section's bytes).
    #[test]
    fn forensic_retries_a_resealed_section() {
        use osis_base::{Value, Time};
        let mut lp = crate::local_peer::LocalPeer::fresh(1, Time(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = crate::Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Str("RESEALED".into())).unwrap();
        let id = e.commit(m).unwrap().unwrap();
        let body = e.body(&id).unwrap().unwrap();
        let reads = e.read_secrets(&t);
        let mut seal = |seed| {
            let sealed = e.seal(&body, osis_blob::Class::Durable, &[], &mut osis_crypto::SeededRng::from_u64(seed)).unwrap().unwrap();
            let env = osis_commit::Envelope::decode(&osis_blob::open(&sealed.blob, &sealed.key).unwrap().1).unwrap();
            let keys: Vec<[u8; 32]> = env.sections.iter().filter_map(|s| reads.iter().find(|r| s.opens_under(&env.id(), r)).map(|r| osis_crypto::section_key(r, &env.id(), &s.nonce))).map(|k| *k.expose()).collect();
            (sealed, env, keys)
        };
        let (a, env_a, keys_a) = seal(0);
        let (b, env_b, keys_b) = seal(1);
        assert_eq!(env_a.id(), env_b.id(), "one commit");
        assert!(!keys_b.is_empty() && keys_b.iter().all(|k| !keys_a.contains(k)), "sealed again under other keys");
        let attack = |s: &crate::sync_ids::Sealed, keys: &[[u8; 32]]| {
            let secrets = [&[*s.key.expose()][..], keys].concat();
            let ev = osis_store::Evidence { secrets, blobs: vec![(s.id, Some(s.blob.clone()))], ..Default::default() };
            osis_store::attack(&ev, Some(&FORENSIC_CIPHERS)).into_iter().any(|r| r.plain.windows(8).any(|w| w == b"RESEALED"))
        };
        assert!(!attack(&a, &keys_b), "b's keys fail on a's sections");
        assert!(attack(&b, &keys_b), "and open b's");
    }
}
