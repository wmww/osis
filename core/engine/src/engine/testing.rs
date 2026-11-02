//! Test hooks: `#[doc(hidden)] pub` because osis-node's `tests/it` calls them (retention's
//! death-row hooks live in `retention::deaths`).

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
    /// those of its current holders in `boxed` (itself alone locks out the rest,
    /// spec/permissions.md §3, Lockout recovery).
    #[doc(hidden)]
    pub fn rotate_boxing_only(&mut self, actors: &[Tid], roles: &[osis_base::Role], boxed: &[Tid]) -> Result<Option<CommitId>> {
        let roles = roles.iter().copied().collect();
        self.run(|tx| {
            let mut m = crate::Mutation::new();
            let mut rots = Vec::new();
            for a in actors {
                let held = tx.core.epochs(a).ok_or(Error::Misuse("no secrets held for the actor"))?;
                let mut holders = crate::rotation::recipients(tx, a, &[])?;
                holders.retain(|r| boxed.contains(&r.holder));
                rots.push((*a, crate::rotation::rotation_into(tx, &mut m, *a, &roles, &held, &holders, &[])?));
            }
            let c = Engine::commit_tx(tx, m)?;
            for (a, rot) in &rots {
                crate::rotation::record(tx, *a, rot)?;
            }
            Ok(c)
        })
    }

    /// Stops `reexamine` here, so what pends stays pending whatever else happens. For what a
    /// pending commit does to the rest of the node: the only wait a role commit's one part has
    /// once its author and thing are known is the clock's (spec/commits.md §4).
    #[doc(hidden)]
    pub fn freeze_pending(&mut self) {
        self.core.frozen_pending = true;
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
        let ciphers = osis_store::Ciphers {
            open: |blob, key| osis_label::open(blob, &osis_crypto::Secret32::from_bytes(*key)).ok().map(|(_, p)| p),
            unwrap: |secret, blob, wrap| osis_crypto::unwrap(&osis_crypto::Secret32::from_bytes(*secret), blob, wrap).ok().map(|k| *k.expose()),
            wrap_len: osis_crypto::WRAP_LEN,
        };
        Ok(osis_store::attack(&ev, Some(&ciphers)))
    }

    /// How many stripped deltas are kept for commit `id` (`retention::strip_purged`).
    #[doc(hidden)]
    pub fn stripped_count(&mut self, id: &osis_base::CommitId) -> Result<usize> {
        let id = *id;
        self.run(|tx| Ok(crate::retention::stripped_of(tx, &id)?.len()))
    }

    /// About the bytes the pending commits' kept examinations hold (`apply::waits`).
    #[doc(hidden)]
    pub fn waits_bytes(&self) -> usize {
        self.core.waits.bytes()
    }

    /// Recomputes the deaths of `(tid, ak)` from the held bodies and the state, as a validity
    /// flip does (tests: on a node keeping every body, `keep_bodies`, it gives each write its
    /// earliest superseder).
    #[doc(hidden)]
    pub fn replay_deaths(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        self.settle_deaths()?;
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| crate::retention::rejudge_deaths(tx, &tid, &ak))
    }

    /// The owner dots of the writes of `(tid, ak)` held valid snapshots carry whose own delta
    /// was never received (tests: a recompute plays them at their snapshot, not at their own
    /// `ts`; an invalid snapshot gives nothing, spec/permissions.md §5.2).
    #[doc(hidden)]
    pub fn carried_dots(&self, tid: &Tid, ak: &osis_base::Ak) -> Vec<osis_crdt::Dot> {
        let groups = self.core.ix.carried.get(&(*tid, ak.clone())).into_iter().flatten();
        groups.filter(|g| !crate::apply::validity::invalid_snapshot(&self.core, &g.snap, tid, ak)).flat_map(|g| g.ctrs.iter().map(|x| osis_crdt::Dot::new(g.src.clone(), *x))).collect()
    }

    /// Keeps every body past its keep-at-most bound (tests: an oracle for the earliest
    /// superseder of each write, spec/crdt.md §4.8).
    #[doc(hidden)]
    pub fn keep_bodies(&mut self, on: bool) {
        self.core.keep_bodies = on;
    }

    /// Whether the delta of `(tid, ak)` in `c` is valid here (`None`: no such delta). Tests: the
    /// order harness tells the documented keep-at-most difference apart.
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
    /// and its value (benches: there is no history API yet, `scale::long_aspect`).
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

    /// Commits with a dropped part, commits with an invalid part, and snapshots kept for their
    /// dropped parts' frontiers (`Dropped::gives`). Tests: what a random history reached.
    #[doc(hidden)]
    pub fn drop_counts(&self) -> [usize; 3] {
        let ms = || self.core.ix.commits.values();
        [ms().filter(|m| !m.dropped.is_empty()).count(), ms().filter(|m| m.valid.contains(&false)).count(), self.core.ix.dropped_snapshots.values().map(|v| v.len()).sum()]
    }

    /// The indexes open rebuilds, field by field (tests: a load from the persisted index equals a
    /// rebuild from the commit records; harnesses compare with `IndexDigest::diff`).
    #[doc(hidden)]
    pub fn index_digest(&self) -> IndexDigest {
        let ix = &self.core.ix;
        let commits = ix.commits.iter().map(|(id, m)| {
            let gives = m.dropped.iter().filter_map(|(ai, d)| Some((*ai, format!("{:?}", d.gives.as_ref()?)))).collect();
            let rest = format!("{:?} {:?} {:?}", m.received, m.origin, m.view);
            (*id, CommitDigest { kind: m.view.kind, valid: m.valid.clone(), dropped: m.dropped.keys().copied().collect(), gives, missing: m.missing.clone(), rest })
        }).collect();
        let held = osis_perm::HeldSet::things(&ix.held).into_iter().map(|t| {
            // sorted: the held set keeps arrival order, which nothing it answers depends on
            let mut cs: Vec<CommitId> = osis_perm::HeldSet::edge_commits(&ix.held, &t).iter().map(|x| x.id).collect();
            let mut ss: Vec<CommitId> = osis_perm::HeldSet::roster_snapshots(&ix.held, &t).iter().map(|x| x.id).collect();
            cs.sort();
            ss.sort();
            (t, (cs, ss, ix.held.created(&t).is_some()))
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
        let mut carried: BTreeMap<CommitId, Vec<Carry>> = BTreeMap::new();
        for ((t, a), v) in ix.carried.iter() {
            for g in v {
                carried.entry(g.snap).or_default().push(Carry { tid: *t, ak: a.clone(), src: g.src.clone(), ctrs: g.ctrs.clone() });
            }
        }
        let tables = [
            ("by_thing", format!("{:?}", *ix.by_thing)),
            ("by_actor", format!("{:?}", *ix.by_actor)),
            ("by_aspect", format!("{:?}", *ix.by_aspect)),
            ("bounded_held", format!("{:?}", *ix.bounded_held)),
            ("invalid", format!("{:?}", *ix.invalid)),
            ("ranges", format!("{:?}", *ix.ranges)),
            ("rotation_role", format!("{:?}", *ix.rotation_role)),
            ("grant_overreach", format!("{:?}", *ix.grant_overreach)),
            ("boxes_to", format!("{:?}", *ix.boxes_to)),
            ("epoch_intro", format!("{:?}", *ix.epoch_intro)),
            ("keyset_epochs", format!("{:?}", *ix.keyset_epochs)),
            ("own_keys", format!("{:?}", *ix.own_keys)),
            ("keyset_parts", format!("{:?}", *ix.keyset_parts)),
            ("holder_keys", format!("{:?}", *ix.holder_keys)),
            ("unresolved", format!("{:?}", *ix.unresolved)),
            ("was", format!("{:?}", *ix.was)),
            ("moved", format!("{:?}", *ix.moved)),
            ("groups", format!("{:?}", ix.groups.of)),
            ("secrets", format!("{:?}", *ix.secrets)),
            ("void", format!("{:?}", *ix.void)),
            ("valueless", format!("{:?}", *ix.valueless)),
            ("imports", format!("{:?}", *ix.imports)),
            ("undone_by", format!("{:?}", *ix.undone_by)),
        ].into_iter().collect();
        IndexDigest { commits, held, by_chunk: (*ix.by_chunk).clone(), snapshots, dropped_snapshots, carried, tables }
    }

    /// Damages the persisted index (tests): `garble` a commit's parts row, else mislabel its tag.
    #[doc(hidden)]
    pub fn damage_index(&mut self, garble: bool) -> Result<()> {
        if !garble {
            // another build's rules judged differently: every part valid, nothing carried, and
            // the states joined so
            return self.run(|tx| {
                let aspects: Vec<(Tid, osis_base::Ak)> = tx.core.ix.invalid.keys().cloned().chain(tx.core.ix.carried.keys().cloned()).collect();
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
                    tx.set_state(&tid, &ak, (!st.is_empty()).then_some(st), Shred::No, false)?;
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
                let t = tx.txn.index(CARRIED)?;
                let keys: Vec<(Tid, osis_base::Ak)> = tx.core.ix.carried.keys().cloned().collect();
                for k in keys {
                    tx.txn.table_remove(t, &enc(&k), Shred::No)?;
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

    /// The role timelines' verdicts per thing (rosters, ledgers, epoch starts, applied and
    /// dropped edge writes): of the components as held (`false`) or of one from-scratch
    /// evaluation of the held set (tests: restored walks equal a from-scratch evaluation).
    #[doc(hidden)]
    pub fn perm_digest(&self, from_scratch: bool) -> String {
        use std::fmt::Write;
        let held = &self.core.ix.held;
        let full = from_scratch.then(|| osis_perm::Timeline::evaluate(held));
        let get = |t: &Tid| full.as_ref().or_else(|| self.core.timelines.get(t));
        let mut out = String::new();
        let mut applied = BTreeMap::new();
        let mut dropped = BTreeMap::new();
        for t in osis_perm::HeldSet::things(held) {
            let Some(tl) = get(&t) else {
                let _ = writeln!(out, "{t:?} no timeline");
                continue;
            };
            let _ = writeln!(out, "{t:?} {:?} {:?} {:?}", tl.roster(&t, osis_perm::At::END), tl.roster_state(&t), tl.epoch_start(&t));
            applied.extend(tl.applied().iter().map(|(k, v)| (*k, *v)));
            dropped.extend(tl.dropped().iter().map(|(k, v)| (*k, *v)));
        }
        let _ = writeln!(out, "applied {applied:?}\ndropped {dropped:?}");
        out
    }

    /// The epoch start of `thing` in its role timeline (spec/permissions.md §6; tests: judgment
    /// vectors).
    #[doc(hidden)]
    pub fn epoch_start(&self, thing: &Tid) -> Option<CommitId> {
        self.core.timelines.get(thing).and_then(|tl| tl.epoch_start(thing))
    }

    /// The drop set D of every held thing's timeline (spec/permissions.md §5.1): each dropped
    /// write with the point of the demotion whose audit dropped it and, for an edge op, the
    /// edge it writes (target, holder). Tests: judgment vectors.
    #[doc(hidden)]
    pub fn drop_set(&self) -> Vec<DropEntry> {
        let mut out = BTreeMap::new();
        for t in osis_perm::HeldSet::things(&self.core.ix.held) {
            let Some(tl) = self.core.timelines.get(&t) else { continue };
            for (w, p) in tl.dropped() {
                let edge = match w {
                    osis_perm::WriteId::Op(c, i) => tl.role_commit(c).and_then(|rc| rc.ops.get(*i as usize)).map(|o| (o.target, o.holder)),
                    osis_perm::WriteId::Snapshot(_) => None,
                };
                out.insert(*w, (*p, edge));
            }
        }
        out.into_iter().map(|(w, (p, e))| (w, p, e)).collect()
    }

    /// Whether an edge write of commit `c` applies in `t`'s timeline (tests).
    #[doc(hidden)]
    pub fn edge_applied(&self, t: &Tid, c: &CommitId) -> bool {
        self.core.timelines.get(t).is_some_and(|tl| tl.applied().keys().any(|w| matches!(w, osis_perm::WriteId::Op(x, _) if x == c)))
    }

    /// Whether an edge write of commit `c` on `t` applies in the settled walk, or a roster
    /// snapshot of `t` applied at its position, its start or not (spec/permissions.md §6) (tests).
    #[doc(hidden)]
    pub fn edge_write_applied(&self, t: &Tid, c: &CommitId) -> bool {
        self.core.timelines.get(t).is_some_and(|tl| tl.snapshot_applied(c).is_some_and(|a| a.target == *t) || tl.applied().iter().any(|(w, a)| w.commit() == *c && a.target == *t))
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

/// The indexes open rebuilds (`Engine::index_digest`): the parts harnesses tell apart typed,
/// keyed by commit, snapshot or thing; every other index as its `Debug` text, by name.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexDigest {
    pub commits: BTreeMap<CommitId, CommitDigest>,
    /// Per held thing: its edge commits and roster snapshots, sorted, and whether its creation
    /// record is held.
    pub held: BTreeMap<Tid, (Vec<CommitId>, Vec<CommitId>, bool)>,
    pub by_chunk: BTreeMap<osis_base::BlobId, std::collections::BTreeSet<CommitId>>,
    /// Per compaction snapshot: its `snapshots` entries, with their aspect.
    pub snapshots: BTreeMap<CommitId, Vec<(Tid, Ak, String)>>,
    /// Per snapshot: the aspects listing it in `dropped_snapshots`.
    pub dropped_snapshots: BTreeMap<CommitId, Vec<(Tid, Ak)>>,
    /// Per carrying snapshot: its `carried` groups.
    pub carried: BTreeMap<CommitId, Vec<Carry>>,
    pub tables: BTreeMap<&'static str, String>,
}

/// One commit of `IndexDigest::commits`.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDigest {
    pub kind: osis_commit::Kind,
    pub valid: Vec<bool>,
    /// Aspects whose deltas were all dropped, and the kept frontiers of those that keep them
    /// (`Dropped::gives`, as text).
    pub dropped: std::collections::BTreeSet<usize>,
    pub gives: BTreeMap<usize, String>,
    pub missing: std::collections::BTreeSet<usize>,
    /// Received time, origin and view, as text.
    pub rest: String,
}

#[doc(hidden)]
/// A write of the drop set D, the point of the demotion that dropped it, and for an edge op
/// its edge (target, holder) (`Engine::drop_set`).
pub type DropEntry = (osis_perm::WriteId, osis_perm::Point, Option<(Tid, Tid)>);

/// One `carried` group of `IndexDigest::carried`.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carry {
    pub tid: Tid,
    pub ak: Ak,
    pub src: osis_crdt::Source,
    pub ctrs: Vec<u64>,
}

/// Where two `IndexDigest`s differ: one entry per commit, thing, snapshot or named index.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndexField {
    Commit(CommitId),
    Held(Tid),
    ByChunk,
    Snapshots(CommitId),
    DroppedSnapshots(CommitId),
    Carried(CommitId),
    Table(&'static str),
}

impl IndexDigest {
    /// Every field where `self` and `other` differ, in field order.
    pub fn diff(&self, other: &Self) -> Vec<IndexField> {
        // destructured: a new field fails to compile until it is compared
        let IndexDigest { commits, held, by_chunk, snapshots, dropped_snapshots, carried, tables } = self;
        let mut out = Vec::new();
        keyed(commits, &other.commits, IndexField::Commit, &mut out);
        keyed(held, &other.held, IndexField::Held, &mut out);
        if *by_chunk != other.by_chunk {
            out.push(IndexField::ByChunk);
        }
        keyed(snapshots, &other.snapshots, IndexField::Snapshots, &mut out);
        keyed(dropped_snapshots, &other.dropped_snapshots, IndexField::DroppedSnapshots, &mut out);
        keyed(carried, &other.carried, IndexField::Carried, &mut out);
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
            IndexField::Carried(c) => s(self.carried.get(c).map(|x| x as _)),
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

/// The keys of `a` and `b` whose values differ (or that one lacks), as fields.
fn keyed<K: Ord + Clone, V: PartialEq>(a: &BTreeMap<K, V>, b: &BTreeMap<K, V>, f: impl Fn(K) -> IndexField, out: &mut Vec<IndexField>) {
    let keys: std::collections::BTreeSet<&K> = a.keys().chain(b.keys()).collect();
    out.extend(keys.into_iter().filter(|k| a.get(*k) != b.get(*k)).map(|k| f(k.clone())));
}
