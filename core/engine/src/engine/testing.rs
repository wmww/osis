//! Test hooks: `#[doc(hidden)] pub` because osis-node's `tests/it` calls them (retention's
//! death-row hooks live in `retention::deaths`).

use super::index::*;
use super::Engine;
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeMap;

impl Engine {
    /// Every key the store's current tree yields: what an attacker holding the device starts
    /// from. Shredding tests.
    #[doc(hidden)]
    pub fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>> {
        Ok(self.store.forensic_keys()?)
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

    /// The writes of `(tid, ak)` held snapshots carry whose own commit is not held, as (author
    /// node, `ts`) (tests: a recompute plays them at their snapshot, not at their own `ts`).
    #[doc(hidden)]
    pub fn carried_writes(&self, tid: &Tid, ak: &osis_base::Ak) -> Vec<(Tid, osis_base::Ts)> {
        self.core.ix.carried.get(&(*tid, ak.clone())).into_iter().flatten().map(|g| (g.node, g.ts)).collect()
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
        let ai = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)?;
        Some(m.valid.get(ai).copied().unwrap_or(true))
    }

    /// The writes of `(tid, ak)` judged invalid here: per held invalid delta its commit and `ts`,
    /// per snapshot carrying invalid writes of a commit it lacks the snapshot and their `ts`.
    /// Tests: the order harness tells the documented keep-at-most difference apart.
    #[doc(hidden)]
    pub fn invalid_writes(&self, tid: &Tid, ak: &Ak) -> Vec<(CommitId, osis_base::Ts)> {
        let k = (*tid, ak.clone());
        let mut out: Vec<(CommitId, osis_base::Ts)> = self.core.ix.by_aspect.get(&k).into_iter().flatten().filter(|(_, c)| self.body_valid(c, tid, ak) == Some(false)).map(|(ts, c)| (*c, *ts)).collect();
        out.extend(self.core.ix.carried.get(&k).into_iter().flatten().filter(|c| !c.invalid.is_empty()).map(|c| (c.snap, c.ts)));
        out
    }

    /// A dump of the indexes open rebuilds (tests: a load from the persisted index equals a
    /// rebuild from the commit records).
    #[doc(hidden)]
    pub fn index_digest(&self) -> String {
        use std::fmt::Write;
        let c = &self.core;
        let mut out = String::new();
        for (id, m) in c.ix.commits.iter() {
            let _ = writeln!(out, "commit {id:?} {:?} {:?} {:?} {:?} {:?} missing {:?}", m.valid, m.dropped, m.received, m.origin, m.view, m.missing);
        }
        let held = osis_perm::HeldSet::things(&c.ix.held);
        for t in held {
            // sorted: the held set keeps arrival order, which nothing it answers depends on
            let mut cs: Vec<CommitId> = osis_perm::HeldSet::edge_commits(&c.ix.held, &t).iter().map(|x| x.id).collect();
            let mut ss: Vec<CommitId> = osis_perm::HeldSet::roster_snapshots(&c.ix.held, &t).iter().map(|x| x.id).collect();
            cs.sort();
            ss.sort();
            let _ = writeln!(out, "held {t:?} {cs:?} {ss:?} {:?}", c.ix.held.created(&t).is_some());
        }
        let _ = writeln!(out, "by_thing {:?}\nby_chunk {:?}", *c.ix.by_thing, *c.ix.by_chunk);
        let _ = writeln!(out, "by_aspect {:?}\ninvalid {:?}\nranges {:?}", *c.ix.by_aspect, *c.ix.invalid, *c.ix.ranges);
        let _ = writeln!(out, "rotation_role {:?}\ngrant_overreach {:?}\nbox_keys {:?}\nboxes_to {:?}", *c.ix.rotation_role, *c.ix.grant_overreach, *c.ix.box_keys, *c.ix.boxes_to);
        let _ = writeln!(out, "epoch_intro {:?}\nbox_written {:?}\nown_keys {:?}", *c.ix.epoch_intro, *c.ix.box_written, *c.ix.own_keys);
        let _ = writeln!(out, "member_keys {:?}\nunresolved {:?}\nwas {:?}\nmoved {:?}\ngroups {:?}", *c.ix.member_keys, *c.ix.unresolved, *c.ix.was, *c.ix.moved, c.ix.groups.of);
        let _ = writeln!(out, "secrets {:?}\nvoid {:?}\nvalueless {:?}\nsnapshots {:?}\ncarried {:?}\nauthors {:?}\nimports {:?}", *c.ix.secrets, *c.ix.void, *c.ix.valueless, *c.ix.snapshots, *c.ix.carried, *c.ix.authors, *c.ix.imports);
        out
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
                        let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.header.aspects.iter().position(|a| a.tid == tid && a.ak == ak)) else { continue };
                        for d in crate::apply::held_parts(tx, &c, ai)? {
                            st.join(d.into_fragment());
                        }
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

    /// The membership timelines' verdicts per thing (rosters, ledgers, epoch starts, applied and
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

    /// Sets the least component saved (`WALK_CACHE_MIN`) for this session (tests).
    #[doc(hidden)]
    pub fn set_walk_cache_min(&mut self, n: usize) {
        self.core.walk_cache_min = n;
    }

    /// Membership components the last open restored from their saved walks (tests).
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

    /// Damages the membership commits' `EDGES` rows (tests): 0 truncates one, 1 garbles one,
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

    /// Rebuilds the in-memory indexes from the commit records (and the persisted index), as a
    /// store written by another build would (tests).
    #[doc(hidden)]
    pub fn rebuild_index(&mut self) -> Result<()> {
        self.run(invalidate)?;
        self.reload()
    }

}
