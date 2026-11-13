//! Forgetting a commit (memory: expired, superseded, covered; durable: covered, purged or invalid,
//! `Engine::forgettable`): `unindex_commit`, the mirror of
//! what applying a commit indexes (`tests::forget_equals_never_indexed`).

use crate::engine::records;
use crate::engine::Tx;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;

/// Removes commit `id` from every index applying it added to and its records from the store:
/// the mirror of `index_commit` and the rest of `apply_verified`.
pub(crate) fn unindex_commit(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    hand_down(tx, id)?;
    // a memory commit's held parts go with it: what they link joins the freed sets
    // (`retention::freed`), memory rows; node-sync deletes the pieces as durable ones
    let held: Vec<usize> = tx.core.ix.commits.get(id).filter(|m| m.view.memory).map(|m| (0..m.header.aspects.len()).filter(|ai| m.holds(*ai)).collect()).unwrap_or_default();
    for ai in held {
        crate::retention::freed::free_part(tx, id, ai)?;
    }
    let core = &mut *tx.core;
    let Some(m) = core.take_meta(id) else { return Ok(()) };
    let v = &m.view;
    // reported to the ephemeral lane with why, from what its dropped parts record: superseded
    // if a part was (its author's to delete), else covered, else gone
    if v.memory {
        let superseders: BTreeSet<CommitId> = m.dropped_parts().flat_map(|(_, d)| d.superseded_by.iter().copied()).collect();
        let mut by: BTreeSet<CommitId> = m.dropped_parts().map(|(_, d)| d).filter(|d| d.why == crate::engine::DropFor::Cover).flat_map(|d| d.covered_by.iter().copied()).collect();
        let why = if !superseders.is_empty() {
            by.extend(superseders);
            crate::engine::MemoryDrop::Superseded { by }
        } else if by.is_empty() {
            crate::engine::MemoryDrop::Gone
        } else {
            crate::engine::MemoryDrop::Covered { by }
        };
        core.memory.dropped.push((*id, m.header.arc(), why));
    }
    for (ai, a) in v.aspects.iter().enumerate() {
        let k = (a.tid, a.ak.clone());
        core.ix.by_aspect.remove(&k, &(v.ts, *id));
        core.ix.invalid.remove(&k, id);
        core.ix.by_thing.remove(&(a.tid, v.author), id);
        core.ix.dropped_snapshots.remove(&k, id);
        if v.form.counted() && v.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.remove(&(a.tid, a.ak.clone(), v.form.own_source(v.author, *id)), &(a.lo, *id));
        }
        super::atomic::forget_snapshot(core, &a.tid, &a.ak, id);
        // a memory commit's aspect holds no durable one (ephemeral aspects): one row per aspect;
        // an invalid part replaced nothing (`undo::parts_before` skips it), so it stands for none
        if m.valid_at(ai) && core.ix.forgotten.get(&k).is_none_or(|t| *t < v.ts) {
            if !v.memory {
                tx.txn.put_local(&records::aspect_key(records::FORGOTTEN, &a.tid, &a.ak), &v.ts.to_u64().to_be_bytes(), Shred::No)?;
            }
            core.ix.forgotten.insert(k, v.ts);
        }
    }
    if v.actor != v.author {
        core.ix.by_actor.remove(&(v.actor, v.author), id);
    }
    if let Some(e) = v.epoch {
        core.ix.rotation_sigs.remove(id);
        core.ix.by_epoch.remove(&(v.author, e), id);
        if let Some(j) = core.ix.epochs.get(&v.author).and_then(|j| j.unnamed(id)) {
            core.ix.epochs.insert(v.author, std::sync::Arc::new(j));
        }
        core.ix.names_due.remove(id);
    }
    super::validity::forget_addenda(core, id, &v.aspects);
    core.ix.void.remove(id);
    core.ix.pending.remove(id);
    core.stale_commits.remove(id);
    // its retention timers (memory rows: an expiry's per part, no keep bound's)
    if let Some(t) = m.header.expires {
        for ai in 0..m.header.aspects.len() {
            tx.txn.remove_local(&records::timer_key(t, id, ai), Shred::No)?;
        }
    }
    // its writes off the value-less list: a copy arriving again applies as new (a batched
    // rebuild still to run strips their values first, `apply::run_batched`)
    for (ai, a) in m.header.aspects.iter().enumerate() {
        let owned = crate::retention::writes_of(&m.header, id, ai);
        if owned.is_empty() {
            continue;
        }
        match &mut tx.core.batched {
            Some(b) => {
                // a memory aspect's rebuild: in the memory class however it was asked
                let e = b.entry((a.tid, a.ak.clone())).or_default();
                e.unlist.extend(owned);
                e.memory |= v.memory;
            }
            None => crate::retention::off_valueless(tx, &a.tid, &a.ak, &owned),
        }
    }
    tx.remove_commit(id)
}

/// Coverer `id` forgotten: each part dropped under it is dropped from then on under what `id`'s
/// part on that aspect dropped under, so its chain of covers (`retention::coverers`) runs past
/// `id` as it did while `id` was known (spec/permissions.md §5.2). O(the commits naming `id`,
/// `Indexes::covered_under`).
fn hand_down(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let Some(sm) = tx.core.ix.commits.get(id) else { return Ok(()) };
    let up: Vec<(Tid, Ak, BTreeSet<CommitId>)> = sm.view.aspects.iter().enumerate().map(|(ai, a)| (a.tid, a.ak.clone(), sm.dropped(ai).map(|d| d.covered_by.clone()).unwrap_or_default())).collect();
    let under: Vec<CommitId> = tx.core.ix.covered_under.get(id).into_iter().flatten().copied().collect();
    for c in under {
        let Some(mut m) = tx.core.ix.commits.get(&c).cloned() else { continue };
        for ai in 0..m.view.aspects.len() {
            let Some(a) = m.view.aspects.get(ai).map(|a| (a.tid, a.ak.clone())) else { continue };
            let Some(d) = m.dropped_mut(ai) else { continue };
            if d.covered_by.remove(id) {
                // counted: tests read how many parts a forget hands down to
                crate::costs::count("forget: handed down", 1);
                let by = up.iter().filter(|x| (x.0, &x.1) == (a.0, &a.1)).flat_map(|x| x.2.iter().copied());
                d.covered_by.extend(by.filter(|x| *x != c));
            }
        }
        tx.in_class(m.view.memory, |tx| {
            if let Some(blob) = tx.get_commit(&c)? {
                tx.put_commit(&c, &blob, &m, Shred::No, None)?;
            }
            tx.core.put_meta(c, m);
            Ok(())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::engine::journal::Journaled;
    use crate::local_peer::LocalPeer;
    use crate::{Engine, Mutation};
    use osis_base::{Ak, Value, WallMs};

    /// Every journaled index but `forgotten`, which keeps what forgetting leaves on purpose, and
    /// perm's view.
    fn digest(e: &Engine) -> String {
        e.core.ix.commits.values().for_each(|m| drop(m.header.decoded()));
        let ix: Vec<String> = e.core.ix.contents().lines().filter(|l| !l.starts_with("forgotten ")).map(String::from).collect();
        format!("{}\n{}", ix.join("\n"), e.perm_digest(false))
    }

    fn ak(s: &str) -> Ak {
        Ak::new(s).unwrap()
    }

    // issues/session-sources.md rule 8 (memory half): memory commits on a durable thing that
    // are superseded, or dropped with the thing's ephemeral state (a delete here), are
    // forgotten: every journaled index (and perm's view) as if they had never applied, the
    // state too, but for the newest forgotten `ts` per aspect. spec: none (internal)
    #[test]
    fn forget_equals_never_indexed() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        let before = digest(e);
        let key = Value::Str("k".into());
        for i in 0..3 {
            let mut m = Mutation::new();
            m.op(g, &ak("t:m+.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(key.clone())], op: osis_crdt::Op::Put(Value::Str(format!("v{i}"))) }).unwrap();
            m.expires(g, &ak("t:m+.0"), WallMs(e.now().0 + 1000)).unwrap();
            e.commit_in_memory(m).unwrap().unwrap();
        }
        assert_eq!(e.core.ix.commits.values().filter(|m| m.view.memory).count(), 1, "superseded moves are forgotten");
        e.run(|tx| crate::retention::memory::drop_things(tx, &[g].into())).unwrap();
        assert_eq!(digest(e), before);
        assert_eq!(e.get(&g, &ak("t:m+.0")).unwrap(), None);
        assert!(e.core.ix.forgotten.get(&(g, ak("t:m+.0"))).is_some(), "an undo still counts them (`undo::replaced_kept`)");
    }

    // spec/commits.md §6: an HLC ahead of the clock (a peer's fast clock read, here the clock set
    // back) has passed a short expiry: the write goes through, expiring just after its `ts`.
    #[test]
    fn short_expiry_behind_hlc_is_raised_spec_commits_6() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        lp.peers[0].clock.set(WallMs(1_700_000_000_000 - 60_000));
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        m.set(g, &ak("t:m.0"), &Value::Str("typing".into())).unwrap();
        m.expires(g, &ak("t:m.0"), WallMs(e.now().0 + 5_000)).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        let h = e.header(&c).unwrap();
        assert_eq!(h.expires, Some(h.ts.wall_ms().0 + 1));
        assert_eq!(e.get(&g, &ak("t:m.0")).unwrap(), Some(Value::Str("typing".into())));
        lp.advance(60_002);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&g, &ak("t:m.0")).unwrap(), None);
    }

    // spec/commits.md §5 Purge on replace, notes/ephemeral.md Principle: a memory aspect under
    // purge on replace drops a replaced part at once under the replacer's cover, while the
    // commit's live part on another aspect stays held, and at its expiry is held as its leftover,
    // value-less (spec/crdt.md §4.7).
    #[test]
    fn memory_purge_on_replace_drops_the_replaced_part_spec_commits_5() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(ak("t:r+.0"), osis_schema::History::PurgeOnReplace)).unwrap();
        e.commit(m).unwrap();
        let t = WallMs(e.now().0 + 2 * 3_600_000);
        let mut m = Mutation::new();
        for (k, v) in [("t:r+.0", "v"), ("t:s+.0", "live")] {
            m.set(g, &ak(k), &Value::Str(v.into())).unwrap();
            m.expires(g, &ak(k), t).unwrap();
        }
        let c = e.commit_in_memory(m).unwrap().unwrap();
        lp.advance(10);
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        m.set(g, &ak("t:r+.0"), &Value::Str("w".into())).unwrap();
        e.commit_in_memory(m).unwrap().unwrap();
        let r = e.core.ix.commits.get(&c).and_then(|m| m.aspect(&g, &ak("t:r+.0"))).unwrap();
        assert!(e.core.ix.commits.get(&c).is_some_and(|m| m.dropped_parts().count() == 1 && m.is_dropped(r)), "the replaced part goes");
        assert_eq!(e.get(&g, &ak("t:r+.0")).unwrap(), Some(Value::Str("w".into())));
        assert_eq!(e.get(&g, &ak("t:s+.0")).unwrap(), Some(Value::Str("live".into())));
        lp.advance(2 * 3_600_000);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&g, &ak("t:s+.0")).unwrap(), None, "value-less at its expiry");
        assert!(e.core.ix.commits.get(&c).is_some_and(|m| m.stripped_parts().count() == 1), "held as its leftover");
    }

    // eph-unify-a review (item 216): a memory aspect's state written by a durable transaction
    // lists the aspect in memory (`records::ASPECTS` routed by the key's marker), so nothing
    // durable names a memory aspect. spec: none (internal)
    #[test]
    fn memory_state_row_follows_key() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        let f = osis_crdt::Fragment::default();
        let rows = e
            .run(|tx| {
                // a state no body gives (`apply::check_rebuilt` would refuse it)
                #[cfg(debug_assertions)]
                {
                    tx.core.unchecked_tx = true;
                }
                tx.set_state(&g, &ak("t:a+.0"), Some(f.clone()), osis_store::Shred::No)?;
                Ok(tx.txn.memory_local_keys(crate::engine::records::ASPECTS))
            })
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
    }
}
