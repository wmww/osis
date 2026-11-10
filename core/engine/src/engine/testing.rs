//! Test hooks: `#[doc(hidden)] pub` because osis-node's `tests/it` calls them.

use super::index::*;
use super::Engine;
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeMap;

/// One row of `Engine::body_page`.
#[doc(hidden)]
pub struct HeldBody {
    pub id: CommitId,
    pub author: Tid,
    pub ts: osis_base::Ts,
    pub valid: bool,
    pub value: Option<osis_base::Value>,
}

impl Engine {
    /// Commits `m` past the writer's rules, as a hostile node would: its role check, commit
    /// shape rules and refusal to emit a delta it judges invalid. A receiver's judgment of what
    /// no writer makes can be tested so.
    #[doc(hidden)]
    pub fn commit_hostile(&mut self, mut m: crate::Mutation) -> Result<Option<CommitId>> {
        m.unchecked();
        let was = std::mem::replace(&mut self.core.skip_writer_rules, true);
        let r = self.commit(m);
        self.core.skip_writer_rules = was;
        r
    }

    /// `commit_hostile` as a memory commit (`Engine::commit_in_memory`): a forged ephemeral
    /// write, to test receivers.
    #[doc(hidden)]
    pub fn commit_in_memory_hostile(&mut self, mut m: crate::Mutation) -> Result<Option<CommitId>> {
        m.unchecked();
        let was = std::mem::replace(&mut self.core.skip_writer_rules, true);
        let r = self.commit_in_memory(m);
        self.core.skip_writer_rules = was;
        r
    }

    /// The last commit built while `skip_writer_rules` or `forge_bad` was set, as sent (tests:
    /// what this node's own copy may have dropped of it).
    #[doc(hidden)]
    pub fn take_forged(&mut self) -> Option<Vec<u8>> {
        self.core.forged.take()
    }

    /// `commit_hostile` with every delta on the aspects `bad` replaced by bytes that do not decode
    /// (the header hashing them), and the blob as sent: this node's own copy drops them.
    #[doc(hidden)]
    pub fn commit_forged(&mut self, m: crate::Mutation, bad: std::collections::BTreeSet<(osis_base::Tid, osis_base::Ak)>) -> Result<Option<(CommitId, Vec<u8>)>> {
        self.core.forge_bad = bad;
        let r = self.commit_hostile(m);
        self.core.forge_bad = Default::default();
        let forged = self.core.forged.take();
        Ok(r?.zip(forged))
    }

    /// Rotates `roles` of each of `actors` in one commit as a hostile writer would: boxing only
    /// those of its current holders in `boxed` (itself alone locks out the rest: notes/crypto.md,
    /// Lockouts).
    #[doc(hidden)]
    pub fn rotate_boxing_only(&mut self, actors: &[Tid], roles: &[osis_base::Role], boxed: &[Tid]) -> Result<Option<CommitId>> {
        let roles = roles.iter().copied().collect();
        self.run(|tx| {
            let mut m = crate::Mutation::new();
            let mut rots = Vec::new();
            for a in actors {
                let held = tx.core.epochs(a).ok_or(Error::Misuse("no secrets held for the actor"))?;
                let mut holders = crate::rotation::recipients(tx, &tx.core.writer()?, a, &[])?.ok_or(crate::rotation::SEAL_WAITS)?;
                holders.retain(|r| boxed.contains(&r.holder));
                rots.push((*a, crate::rotation::rotation_into(tx, &mut m, *a, &roles, &held, &holders, false)?));
            }
            let c = Engine::commit_tx(tx, m)?;
            for (a, rot) in &rots {
                crate::rotation::record(tx, *a, rot)?;
            }
            Ok(c)
        })
    }

    /// Flags an aspect suspect (tests: what a suspect node does, however it became one).
    #[doc(hidden)]
    pub fn flag_suspect(&mut self, t: &Tid, a: &Ak, why: crate::retention::suspect::Why, bodies: &[(CommitId, usize)]) -> Result<()> {
        self.run(|tx| crate::retention::suspect::raise(tx, t, a, why, bodies))
    }

    /// The store's local rows and blobs by kind (a row's key up to its first `/`, else 3 bytes):
    /// count and key plus value bytes. Tests counting what grows (notes/growth.md).
    #[doc(hidden)]
    pub fn local_census(&mut self) -> Result<std::collections::BTreeMap<String, (usize, usize)>> {
        let rows = self.run(|tx| Ok(tx.txn.scan_local(b"", b"", usize::MAX)?))?;
        let mut out = std::collections::BTreeMap::<String, (usize, usize)>::new();
        for (k, v) in rows {
            let end = k.iter().position(|b| *b == b'/').map_or(3.min(k.len()), |p| (p + 1).min(k.len()));
            let e = out.entry(String::from_utf8_lossy(k.get(..end).unwrap_or(&k)).into_owned()).or_default();
            e.0 += 1;
            e.1 += k.len() + v.len();
        }
        Ok(out)
    }

    /// What the store holds, decrypted (`Store::dump`): tests compare two nodes' stores.
    #[doc(hidden)]
    pub fn store_dump(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(self.store.dump()?)
    }

    /// Every key the store's current tree yields: what an attacker holding the device starts
    /// from. Shredding tests.
    #[doc(hidden)]
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>> {
        Ok(self.store.forensic_keys()?)
    }

    /// What an attacker holding this node's device recovers from everything `backend` recorded
    /// (`osis_store::attack`): the current tree's keys, the label read secrets this node's code
    /// computes now, blobs and wraps opened as osis-label does. Shredding tests.
    #[doc(hidden)]
    pub fn forensic(&mut self, backend: &osis_store::MemoryBackend) -> Result<Vec<osis_store::Recovered>> {
        let mut ev = osis_store::Evidence::of(self.store.forensic_keys()?, backend);
        let tids: std::collections::BTreeSet<Tid> = self.all_aspects()?.into_iter().map(|(t, _)| t).collect();
        for t in tids {
            ev.secrets.extend(self.read_secrets(&t).iter().map(|s| *s.expose()));
        }
        Ok(osis_store::attack(&ev, Some(&FORENSIC_CIPHERS)))
    }

    /// How many parts of commit `id` are held value-less while they wait (`retention::strip_purged`).
    #[doc(hidden)]
    pub fn stripped_count(&mut self, id: &osis_base::CommitId) -> Result<usize> {
        let id = *id;
        self.run(|tx| {
            let Some(b) = tx.txn.get_pending(&id)?.and_then(|(_, b)| osis_commit::CommitBlob::decode_stored(&b).ok()) else { return Ok(0) };
            let mut n = 0;
            for ai in 0..b.header.aspects.len() {
                if crate::retention::waiting_stripped(tx, &b, &id, ai)? {
                    n += 1;
                }
            }
            Ok(n)
        })
    }

    /// How many purge requests' dropped-a-permanent-delta notes are kept (`retention::lasting`).
    #[doc(hidden)]
    pub fn named_permanent_count(&mut self) -> Result<usize> {
        self.run(|tx| {
            let mut n = 0;
            tx.scan(crate::engine::records::NAMED_PERMANENT, |_, _| {
                n += 1;
                Ok(())
            })?;
            Ok(n)
        })
    }

    /// The origin dots of the writes of `(tid, ak)` held valid snapshots carry whose own delta
    /// was never received, read from their bodies (tests: a recompute plays them at their
    /// snapshot, not at their own `ts`; an invalid snapshot gives nothing, spec/permissions.md
    /// §5.2). A record carrying no `ts` (a tombstone) carries no write.
    #[doc(hidden)]
    pub fn carried_dots(&mut self, tid: &Tid, ak: &osis_base::Ak) -> Vec<osis_crdt::Dot> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| {
            let snaps: Vec<(CommitId, usize)> = tx.core.ix.snapshots.get(&(tid, ak.clone())).into_iter().flatten().filter_map(|s| tx.core.ix.commits.get(&s.1).and_then(|m| m.aspect(&tid, &ak)).map(|ai| (s.1, ai))).collect();
            let mut out = std::collections::BTreeSet::new();
            for (s, ai) in snaps {
                if !crate::apply::copies::snapshot_valid(tx.core, &s, &tid, &ak) {
                    continue;
                }
                crate::apply::each_held_piece(tx, &s, ai, &mut |tx, f| {
                    out.extend(f.writes().into_iter().filter(|(d, ts)| ts.is_some() && !d.src.is_derived() && !crate::apply::copies::delta_received(tx.core, &tid, &ak, d)).map(|(d, _)| d));
                    Ok(())
                })?;
            }
            Ok(out.into_iter().collect())
        })
        .unwrap_or_default()
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

    /// What a demotion's frontier is fit to in place of `MAX_LIST_BYTES` (tests: `receipt::fit` end to end).
    #[doc(hidden)]
    pub fn list_bound(&mut self, bytes: usize) {
        self.core.list_bound = bytes;
    }

    /// Whether the delta of `(tid, ak)` in `c` is valid here (`None`: no such delta). Tests: the
    /// order harness reads an invalid body's facts.
    #[doc(hidden)]
    pub fn body_valid(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<bool> {
        let m = self.core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak)?;
        Some(m.valid.get(ai).copied().unwrap_or(true))
    }

    /// The held deltas of `(tid, ak)` judged invalid here, with their `ts`. Tests: the order
    /// harness tells the documented keep-at-most difference apart.
    #[doc(hidden)]
    pub fn invalid_writes(&self, tid: &Tid, ak: &Ak) -> Vec<(CommitId, osis_base::Ts)> {
        let k = (*tid, ak.clone());
        self.core.ix.by_aspect.get(&k).into_iter().flatten().filter(|(_, c)| self.body_valid(c, tid, ak) == Some(false)).map(|(ts, c)| (*c, *ts)).collect()
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
                let (author, valid) = (m.header.actor, m.valid_at(ai));
                let mut v = None;
                crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
                    v = f.read();
                    Ok(())
                })?;
                out.push(HeldBody { id: *c, author, ts: *ts, valid, value: v });
            }
            Ok(out)
        })
    }

    /// The held body of `c` on `(tid, ak)`, its pieces joined (diagnosis: what a commit carries,
    /// value-less writes and copies included, where `body_page` gives only its read).
    #[doc(hidden)]
    pub fn body_fragment(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<osis_crdt::Fragment>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
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
            g.strip(&|d| owned.iter().any(|o| o.owns(d)));
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

    /// The aspect indexes of the parts waiting commit `c`'s stored copy holds, value-less ones
    /// included (`None`: not waiting). Tests: the held-model adapter (`tests/it/held.rs`).
    #[doc(hidden)]
    pub fn pending_parts(&mut self, c: &CommitId) -> Result<Option<std::collections::BTreeSet<usize>>> {
        let c = *c;
        self.run(|tx| {
            let Some((_, bytes)) = tx.txn.get_pending(&c)? else { return Ok(None) };
            let Ok(blob) = osis_commit::CommitBlob::decode_stored(&bytes) else { return Ok(None) };
            Ok(Some(blob.parts.iter().map(|p| p.ai).collect()))
        })
    }

    /// A part of waiting commit `c` whose stored copy still holds a value past its expiry at `now`,
    /// or that a held purge request drops, its thing's record held so it could be stripped (tests:
    /// `order::value_past_end`; spec/commits.md §5).
    #[doc(hidden)]
    pub fn pending_value_past_end(&mut self, c: &CommitId, now: osis_base::WallMs) -> Result<Option<String>> {
        let c = *c;
        self.run(|tx| {
            let Some((_, bytes)) = tx.txn.get_pending(&c)? else { return Ok(None) };
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
        self.run(|tx| {
            tx.load_lazy(&k.0, &k.1)?;
            match (tx.core.pages.get(&k), tx.core.states.get(&k)) {
                (Some(idx), Some(Some(f))) => super::pages::stale_in_pages(&mut tx.txn, &k.0, &k.1, idx, f),
                _ => Ok(0),
            }
        })
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

    /// Commits with a dropped part, commits with an invalid part, and snapshots kept for their
    /// dropped parts standing in (`Dropped::stands_in`). Tests: what a random history reached.
    #[doc(hidden)]
    pub fn drop_counts(&self) -> [usize; 3] {
        let ms = || self.core.ix.commits.values();
        [ms().filter(|m| !m.dropped.is_empty()).count(), ms().filter(|m| m.valid.contains(&false)).count(), self.core.ix.dropped_snapshots.values().map(|v| v.len()).sum()]
    }

    /// How many held commits' parts break their thing's required retention.
    #[doc(hidden)]
    pub fn broken_parts(&self) -> usize {
        self.core.ix.commits.iter().map(|(id, m)| (0..m.header.aspects.len()).filter(|ai| crate::apply::validity::broken_by(&self.core, &m.header, id, *ai).is_some()).count()).sum()
    }

    /// How many held `required^.0` parts are invalid.
    #[doc(hidden)]
    pub fn fallen_required(&self) -> usize {
        self.core.ix.commits.values().map(|m| m.header.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == osis_commit::retention::REQUIRED && !m.valid_at(*ai)).count()).sum()
    }

    /// Every applied durable commit with its parts not received here (`commit_ids` with
    /// `Meta::missing`): two nodes holding one commit may hold different parts of it.
    #[doc(hidden)]
    pub fn commit_parts_missing(&self) -> BTreeMap<CommitId, std::collections::BTreeSet<usize>> {
        self.core.ix.commits.iter().filter(|(_, m)| !m.view.memory).map(|(id, m)| (*id, m.missing.clone())).collect()
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
                    row.iter_mut().skip(5).take(m.valid.len()).for_each(|p| *p = 1);
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

    /// The role timelines' verdicts per thing (rosters, applied and dropped edge writes): of the components as held (`false`) or of one from-scratch
    /// evaluation of the held set (tests: restored walks equal a from-scratch evaluation).
    #[doc(hidden)]
    pub fn perm_digest(&self, from_scratch: bool) -> String {
        self.core.perm_digest(from_scratch)
    }

    /// The drop set D of every held thing's timeline (spec/permissions.md §5.1): each dropped
    /// write with the point of the demotion whose audit dropped it and the edge it writes
    /// (target, holder). Tests: judgment vectors.
    #[doc(hidden)]
    pub fn drop_set(&self) -> Vec<DropEntry> {
        let mut out = BTreeMap::new();
        for t in osis_perm::HeldSet::things(&self.core.ix.held) {
            let Some(tl) = self.core.timelines.get(&t) else { continue };
            for (w, p) in tl.dropped() {
                if let Some(o) = tl.role_commit(&w.0).and_then(|rc| rc.ops.get(w.1 as usize)) {
                    out.insert(*w, (*p, (o.target, o.holder)));
                }
            }
        }
        out.into_iter().map(|(w, (p, e))| (w, p, e)).collect()
    }

    /// Whether an edge write of commit `c` applies in `t`'s timeline (tests).
    #[doc(hidden)]
    pub fn edge_applied(&self, t: &Tid, c: &CommitId) -> bool {
        self.core.timelines.get(t).is_some_and(|tl| tl.applied().keys().any(|w| w.0 == *c))
    }

    /// Whether an edge write of commit `c` on `t` applies in the settled walk (tests).
    #[doc(hidden)]
    pub fn edge_write_applied(&self, t: &Tid, c: &CommitId) -> bool {
        self.core.timelines.get(t).is_some_and(|tl| tl.applied().iter().any(|(w, a)| w.commit() == *c && a.target == *t))
    }

    /// Sets the least component saved (`WALK_CACHE_MIN`) for this session (tests).
    #[doc(hidden)]
    pub fn set_walk_cache_min(&mut self, n: usize) {
        self.core.walk_cache_min = n;
    }

    /// Role components the last open restored from their saved walks (tests).
    #[doc(hidden)]
    pub fn walks_restored(&self) -> usize {
        self.core.timelines.restored()
    }

    /// Damages every saved walk (tests): 0 truncates, 1 flips a bit, 2 saves it again under
    /// other rules.
    #[doc(hidden)]
    pub fn damage_walks(&mut self, how: u8) -> Result<usize> {
        self.run(|tx| {
            let t = tx.txn.index(WALKS)?;
            let rows = tx.txn.table_range(t, &[], None, 1 << 20)?;
            let other = tx.core.timelines.to_save(b"another build", 1, true);
            for (k, mut v) in rows.iter().cloned() {
                match how {
                    0 => v.truncate(v.len() / 2),
                    1 => {
                        let i = v.len() / 2;
                        if let Some(b) = v.get_mut(i) {
                            *b ^= 4;
                        }
                    }
                    _ => match other.put.iter().find(|(r, _)| r.as_bytes()[..] == k[..]) {
                        Some((_, b)) => v = b.clone(),
                        None => continue,
                    },
                }
                tx.txn.table_put(t, &k, v, Shred::Yes)?;
            }
            Ok(rows.len())
        })
    }

    /// Damages the role commits' `EDGES` rows (tests): 0 truncates one, 1 garbles one,
    /// 2 removes one. Returns how many rows there were.
    #[doc(hidden)]
    pub fn damage_edges(&mut self, how: u8) -> Result<usize> {
        self.run(|tx| {
            let t = tx.txn.index(EDGES)?;
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

    /// The `EDGES` rows as stored (tests: what a rebuild writes equals what the writes kept).
    #[doc(hidden)]
    pub fn edges_rows(&mut self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.run(|tx| {
            let t = tx.txn.index(EDGES)?;
            Ok(tx.txn.table_range(t, &[], None, 1 << 20)?)
        })
    }

    /// Headers decoded so far of commits without a list by link (tests: an open from the index
    /// decodes none; those with one are resolved from blobs at open).
    #[doc(hidden)]
    pub fn headers_decoded(&self) -> usize {
        self.core.ix.commits.values().filter(|m| !m.view.linked && m.header.is_decoded()).count()
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
            let dropped = m.dropped.get(&ai);
            let missing = m.missing.contains(&ai);
            let valid = m.valid.get(ai).copied().unwrap_or(true);
            let _ = writeln!(out, "  {c:?} {:?} by {} ts {:?}: dropped {:?} missing {missing} valid {valid} covered by {:?}", h.kind, h.author, h.ts, dropped.is_some(), dropped.map(|d| &d.covered_by));
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

/// One index of `IndexDigest::tables`: compared typed (`Core::same_index`), shown as its `Debug`
/// text.
trait Table: std::fmt::Debug {
    fn same(&self, o: &dyn Table) -> bool;
    fn any(&self) -> &dyn std::any::Any;
}

impl<T: std::fmt::Debug + PartialEq + 'static> Table for T {
    fn same(&self, o: &dyn Table) -> bool {
        o.any().downcast_ref::<T>().is_some_and(|o| self == o)
    }
    fn any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The indexes `IndexDigest::tables` holds as text, by name.
fn tables(ix: &super::Indexes) -> [(&'static str, &dyn Table); 26] {
    [
        ("by_thing", &*ix.by_thing),
        ("by_actor", &*ix.by_actor),
        ("by_aspect", &*ix.by_aspect),
        ("originals", &*ix.originals),
        ("versions", &*ix.versions),
        ("bounded_held", &*ix.bounded_held),
        ("invalid", &*ix.invalid),
        ("ranges", &*ix.ranges),
        ("rotation_role", &*ix.rotation_role),
        ("grant_overreach", &*ix.grant_overreach),
        ("required", &*ix.required),
        ("addenda", &*ix.addenda),
        ("boxes_to", &*ix.boxes_to),
        ("epoch_intro", &*ix.epoch_intro),
        ("keysets", &*ix.keysets),
        ("own_keys", &*ix.own_keys),
        ("keyset_parts", &*ix.keyset_parts),
        ("holder_keys", &*ix.holder_keys),
        ("unresolved", &*ix.unresolved),
        ("groups", &ix.groups.of),
        ("secrets", &*ix.secrets),
        ("void", &*ix.void),
        ("valueless", &*ix.valueless),
        ("labeled", &*ix.labeled),
        ("epochs", &*ix.epochs),
        ("by_epoch", &*ix.by_epoch),
    ]
}

/// A commit's `CommitDigest`, its `rest` empty, and what `rest` shows.
fn commit_digest(m: &super::Meta) -> (CommitDigest, (&osis_base::WallMs, &crate::events::Origin, &super::View)) {
    let stands_in = m.dropped.iter().filter(|(_, d)| d.stands_in).map(|(ai, _)| *ai).collect();
    let d = CommitDigest { kind: m.view.kind, valid: m.valid.clone(), dropped: m.dropped.keys().copied().collect(), stands_in, stripped: m.stripped.clone(), valued: m.valued.clone(), missing: m.missing.clone(), rest: String::new() };
    (d, (&m.received, &m.origin, &*m.view))
}

/// The role timelines' verdicts `Core::perm_digest` shows: per held thing its roster (`None`: no
/// timeline), then every applied and dropped edge write.
type PermParts = (Vec<(Tid, Option<BTreeMap<Tid, osis_perm::Edge>>)>, BTreeMap<osis_perm::WriteId, osis_perm::Applied>, BTreeMap<osis_perm::WriteId, osis_perm::Point>);

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
        let mut dropped_snapshots: BTreeMap<CommitId, Vec<(Tid, Ak)>> = BTreeMap::new();
        for ((t, a), v) in ix.dropped_snapshots.iter() {
            for c in v {
                dropped_snapshots.entry(*c).or_default().push((*t, a.clone()));
            }
        }
        let tables = tables(ix).into_iter().map(|(n, t)| (n, format!("{t:?}"))).collect();
        IndexDigest { commits, held: self.held_digest(), by_chunk: (*ix.by_chunk).clone(), snapshots, dropped_snapshots, tables }
    }

    /// `IndexDigest::held`.
    fn held_digest(&self) -> BTreeMap<Tid, (Vec<CommitId>, bool)> {
        let ix = &self.ix;
        osis_perm::HeldSet::things(&ix.held).into_iter().map(|t| {
            // sorted: the held set keeps arrival order, which nothing it answers depends on
            let mut cs: Vec<CommitId> = osis_perm::HeldSet::edge_commits(&ix.held, &t).iter().map(|x| x.id).collect();
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
            && *a.by_chunk == *b.by_chunk
            && *a.snapshots == *b.snapshots
            && *a.dropped_snapshots == *b.dropped_snapshots
            && tables(a).iter().zip(tables(b).iter()).all(|((_, x), (_, y))| x.same(*y))
            && self.perm_parts(false) == o.perm_parts(false)
    }

    /// `PermParts` of the components as held (`false`) or of one from-scratch evaluation.
    fn perm_parts(&self, from_scratch: bool) -> PermParts {
        let held = &self.ix.held;
        let full = from_scratch.then(|| osis_perm::Timeline::evaluate(held));
        let get = |t: &Tid| full.as_ref().or_else(|| self.timelines.get(t));
        let (mut rosters, mut applied, mut dropped) = (Vec::new(), BTreeMap::new(), BTreeMap::new());
        for t in osis_perm::HeldSet::things(held) {
            let Some(tl) = get(&t) else {
                rosters.push((t, None));
                continue;
            };
            rosters.push((t, Some(tl.roster(&t, osis_perm::At::END))));
            applied.extend(tl.applied().iter().map(|(k, v)| (*k, *v)));
            dropped.extend(tl.dropped().iter().map(|(k, v)| (*k, *v)));
        }
        (rosters, applied, dropped)
    }

    /// `Engine::perm_digest`.
    pub(crate) fn perm_digest(&self, from_scratch: bool) -> String {
        use std::fmt::Write;
        let (rosters, applied, dropped) = self.perm_parts(from_scratch);
        let mut out = String::new();
        for (t, r) in rosters {
            let _ = match r {
                Some(r) => writeln!(out, "{t:?} {r:?}"),
                None => writeln!(out, "{t:?} no timeline"),
            };
        }
        let _ = writeln!(out, "applied {applied:?}\ndropped {dropped:?}");
        out
    }
}

/// The indexes open rebuilds (`Engine::index_digest`): the parts harnesses tell apart typed,
/// keyed by commit, snapshot or thing; every other index as its `Debug` text, by name.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexDigest {
    pub commits: BTreeMap<CommitId, CommitDigest>,
    /// Per held thing: its edge commits, sorted, and whether its creation
    /// record is held.
    pub held: BTreeMap<Tid, (Vec<CommitId>, bool)>,
    pub by_chunk: BTreeMap<osis_base::BlobId, std::collections::BTreeSet<CommitId>>,
    /// Per compaction snapshot: its `snapshots` entries, with their aspect.
    pub snapshots: BTreeMap<CommitId, Vec<(Tid, Ak, String)>>,
    /// Per snapshot: the aspects listing it in `dropped_snapshots`.
    pub dropped_snapshots: BTreeMap<CommitId, Vec<(Tid, Ak)>>,
    pub tables: BTreeMap<&'static str, String>,
}

/// One commit of `IndexDigest::commits`.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDigest {
    pub kind: osis_commit::Kind,
    pub valid: Vec<bool>,
    /// Aspects whose deltas were all dropped, and those of them standing in
    /// (`Dropped::stands_in`).
    pub dropped: std::collections::BTreeSet<usize>,
    pub stands_in: std::collections::BTreeSet<usize>,
    /// Aspects held as their leftover (`Meta::stripped`), those holding values (`Meta::valued`).
    pub stripped: std::collections::BTreeSet<usize>,
    pub valued: std::collections::BTreeSet<usize>,
    pub missing: std::collections::BTreeSet<usize>,
    /// Received time, origin and view, as text.
    pub rest: String,
}

#[doc(hidden)]
/// A write of the drop set D, the point of the demotion that dropped it, and for an edge op
/// its edge (target, holder) (`Engine::drop_set`).
pub type DropEntry = (osis_perm::WriteId, osis_perm::Point, (Tid, Tid));

/// Where two `IndexDigest`s differ: one entry per commit, thing, snapshot or named index.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexField {
    Commit(CommitId),
    Held(Tid),
    ByChunk,
    Snapshots(CommitId),
    DroppedSnapshots(CommitId),
    Table(&'static str),
}

impl IndexDigest {
    /// Every field where `self` and `other` differ, in field order.
    pub fn diff(&self, other: &Self) -> Vec<IndexField> {
        // destructured: a new field fails to compile until it is compared
        let IndexDigest { commits, held, by_chunk, snapshots, dropped_snapshots, tables } = self;
        let mut out = Vec::new();
        keyed(commits, &other.commits, IndexField::Commit, &mut out);
        keyed(held, &other.held, IndexField::Held, &mut out);
        if *by_chunk != other.by_chunk {
            out.push(IndexField::ByChunk);
        }
        keyed(snapshots, &other.snapshots, IndexField::Snapshots, &mut out);
        keyed(dropped_snapshots, &other.dropped_snapshots, IndexField::DroppedSnapshots, &mut out);
        keyed(tables, &other.tables, IndexField::Table, &mut out);
        out
    }

    /// Field `f` of this digest as text (`None`: absent), for a failure message.
    pub fn show(&self, f: &IndexField) -> Option<String> {
        let s = |x: Option<&dyn std::fmt::Debug>| x.map(|x| format!("{x:?}"));
        match f {
            IndexField::Commit(c) => s(self.commits.get(c).map(|x| x as _)),
            IndexField::Held(t) => s(self.held.get(t).map(|x| x as _)),
            IndexField::ByChunk => s(Some(&self.by_chunk)),
            IndexField::Snapshots(c) => s(self.snapshots.get(c).map(|x| x as _)),
            IndexField::DroppedSnapshots(c) => s(self.dropped_snapshots.get(c).map(|x| x as _)),
            IndexField::Table(n) => self.tables.get(n).cloned(),
        }
    }

    /// The first difference from `other` (`None`: equal), described.
    pub fn first_diff(&self, other: &Self) -> Option<String> {
        let f = self.diff(other).into_iter().next()?;
        Some(format!("index {f:?}:\n  want {}\n  got  {}", self.show(&f).unwrap_or("<none>".into()), other.show(&f).unwrap_or("<none>".into())))
    }

    /// Without the held set (`held`): what validity tests compare.
    pub fn without_held(mut self) -> Self {
        self.held.clear();
        self
    }
}

/// How blobs, wraps and sections open, as osis-label and osis-commit open them (`Engine::forensic`).
const FORENSIC_CIPHERS: osis_store::Ciphers = osis_store::Ciphers {
    // a padded blob ends in 0x80 or 0x00 (`osis_crypto::unpad`): another last byte rules the
    // key out without the whole AEAD pass (tens of thousands of candidates per blob)
    open: |blob, key| {
        let ct = osis_label::blob::Prefix::parse(blob).ok().and_then(|p| blob.get(p.len()..))?;
        matches!(osis_crypto::aead::last_plain_byte(key, &osis_crypto::aead::ZERO_NONCE, ct), Some(0 | 0x80)).then_some(())?;
        osis_label::open(blob, &osis_crypto::Secret32::from_bytes(*key)).ok().map(|(_, p)| p)
    },
    unwrap: |secret, blob, wrap| osis_crypto::unwrap(&osis_crypto::Secret32::from_bytes(*secret), blob, wrap).ok().map(|k| *k.expose()),
    wrap_len: osis_crypto::WRAP_LEN,
    // a section opens under a candidate as its wrap's read secret, or as its key
    sections: |plain, keys, opened| {
        let Ok(env) = osis_commit::Envelope::decode(plain) else { return Vec::new() };
        let id = env.id();
        env.sections
            .iter()
            .enumerate()
            .filter(|(i, _)| !opened.contains(i))
            .filter_map(|(i, s)| {
                keys.iter().find_map(|key| {
                    let k = osis_crypto::Secret32::from_bytes(*key);
                    // as the key itself, only if its first plaintext bytes can begin a section
                    let sk = match osis_crypto::unwrap_section(&k, &id, &s.wrap) {
                        Ok(sk) => sk,
                        Err(_) if s.may_open_with(key) => k,
                        Err(_) => return None,
                    };
                    osis_crypto::open_section(&id, &sk, &s.ciphertext).ok().map(|p| (i, p))
                })
            })
            .collect()
    },
};

/// The keys of `a` and `b` whose values differ (or that one lacks), as fields.
fn keyed<K: Ord + Clone, V: PartialEq>(a: &BTreeMap<K, V>, b: &BTreeMap<K, V>, f: impl Fn(K) -> IndexField, out: &mut Vec<IndexField>) {
    let keys: std::collections::BTreeSet<&K> = a.keys().chain(b.keys()).collect();
    out.extend(keys.into_iter().filter(|k| a.get(*k) != b.get(*k)).map(|k| f(k.clone())));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec: none (forensic test support): a section key planted on the device opens its section
    // in the attack (`Section::may_open_with` never rules out a real one), for sections of two
    // parts and of more parts than one CBOR head byte counts; without the key it stays shut.
    #[test]
    fn forensic_opens_a_section_by_its_planted_key() {
        use osis_base::{Value, WallMs};
        let mut lp = crate::local_peer::LocalPeer::new(1, 944, WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = crate::Mutation::new();
        let (one, many) = (e.new_thing(&mut m, me), e.new_thing(&mut m, me));
        m.set(one, &Ak::new("x:a.0").unwrap(), &Value::Str("PLANTED-ONE".into())).unwrap();
        for i in 0..30 {
            m.set(many, &Ak::new(format!("x:a{i:02}.0")).unwrap(), &Value::Str(format!("PLANTED-MANY-{i}"))).unwrap();
        }
        let id = e.commit(m).unwrap().unwrap();
        // the commit blob as labels carry it: its key planted, no wrap or read secret on the device
        let body = e.body(&id).unwrap().unwrap();
        let sealed = e.seal(&body, osis_label::Class::Durable, &[], &mut osis_crypto::SeededRng::from_u64(1)).unwrap().unwrap();
        let env = osis_commit::Envelope::decode(&osis_label::open(&sealed.blob, &sealed.key).unwrap().1).unwrap();
        let bk = sealed.key;
        let framed = sealed.blob;
        let reads: Vec<_> = [one, many].iter().flat_map(|t| e.read_secrets(t)).collect();
        let attack = |secrets: Vec<[u8; 32]>| {
            let ev = osis_store::Evidence { store_keys: Vec::new(), secrets, rows: Vec::new(), blobs: vec![(sealed.id, Some(framed.clone()))] };
            osis_store::attack(&ev, Some(&FORENSIC_CIPHERS)).into_iter().map(|r| r.plain).collect::<Vec<_>>()
        };
        let has = |found: &[Vec<u8>], marker: &[u8]| found.iter().any(|x| x.windows(marker.len()).any(|w| w == marker));
        assert!(!has(&attack(vec![*bk.expose()]), b"PLANTED"), "shut without its key");
        let mut tried = Vec::new();
        for s in &env.sections {
            let Some(key) = reads.iter().find_map(|r| osis_crypto::unwrap_section(r, &env.id(), &s.wrap).ok()) else { continue };
            let found = attack(vec![*bk.expose(), *key.expose()]);
            let marker: &[u8] = if s.ais.len() >= 24 { b"PLANTED-MANY-29" } else { b"PLANTED-ONE" };
            assert!(has(&found, marker), "{} parts", s.ais.len());
            tried.push(s.ais.len());
        }
        tried.sort();
        assert_eq!(tried, [2, 31], "each thing's creation and its aspects");
    }
}
