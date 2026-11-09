//! Forgetting a commit (memory: expired, superseded, covered; durable: its author's own cover,
//! `Engine::forgettable`): `unindex_commit`, the mirror of
//! what applying a commit indexes (`tests::forget_equals_never_indexed`).

use crate::engine::records;
use crate::engine::Tx;
use crate::error::Result;
use osis_base::CommitId;
use osis_store::Shred;
use std::collections::BTreeSet;

/// Removes commit `id` from every index applying it added to and its records from the store:
/// the mirror of `index_commit` and the rest of `apply_verified` for a memory commit.
pub(crate) fn unindex_commit(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let core = &mut *tx.core;
    let Some(m) = core.take_meta(id) else { return Ok(()) };
    let v = &m.view;
    // reported to the ephemeral lane with why (`MemorySync::reasons`, else covered by what
    // the dropped parts record, else gone)
    if v.memory {
        let why = core.memory.reasons.remove(id).unwrap_or_else(|| {
            let by: BTreeSet<CommitId> = m.dropped.values().filter(|d| d.why == crate::engine::DropFor::Cover).flat_map(|d| d.covered_by.iter().copied()).collect();
            if by.is_empty() { crate::engine::MemoryDrop::Gone } else { crate::engine::MemoryDrop::Covered { by } }
        });
        core.memory.dropped.push((*id, m.header.arc(), why));
        core.memory.dirty.extend(v.aspects.iter().map(|a| (a.tid, a.ak.clone())));
    }
    for a in &v.aspects {
        let k = (a.tid, a.ak.clone());
        core.ix.by_aspect.remove(&k, &(v.ts, *id));
        core.ix.invalid.remove(&k, id);
        core.ix.by_thing.remove(&(a.tid, v.author), id);
        core.ix.dropped_snapshots.remove(&k, id);
        if v.form.counted() && v.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.remove(&(a.tid, a.ak.clone(), v.form.own_source(v.author, *id)), &(a.lo, *id));
        }
        super::atomic::forget_snapshot(core, &a.tid, &a.ak, id);
        if core.ix.forgotten.get(&k).is_none_or(|t| *t < v.ts) {
            core.ix.forgotten.insert(k, v.ts);
        }
    }
    if v.actor != v.author {
        core.ix.by_actor.remove(&(v.actor, v.author), id);
    }
    if let Some(e) = v.epoch {
        core.ix.by_epoch.remove(&(v.author, e), id);
    }
    super::validity::forget_addenda(core, id, &v.aspects);
    for b in &v.chunks {
        core.ix.by_chunk.remove(b, id);
    }
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
    if v.memory {
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
                    e.memory = true;
                }
                None => crate::retention::off_valueless(tx, &a.tid, &a.ak, &owned),
            }
        }
    }
    tx.remove_commit(id)
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
        let mut lp = LocalPeer::new(1, 953, WallMs(1_700_000_000_000)).unwrap();
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
        let mut lp = LocalPeer::new(1, 955, WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        e.set_clock_offset(-60_000);
        let mut m = Mutation::new();
        m.set(g, &ak("t:m.0"), &Value::Str("typing".into())).unwrap();
        m.expires(g, &ak("t:m.0"), WallMs(e.now().0 + 5_000)).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        let h = e.header(&c).unwrap();
        assert_eq!(h.expires, Some(h.ts.wall_ms().0 + 1));
        assert_eq!(e.get(&g, &ak("t:m.0")).unwrap(), Some(Value::Str("typing".into())));
        lp.advance(60_002);
        let e = &mut lp.peers[0].engine;
        e.tick().unwrap();
        assert_eq!(e.get(&g, &ak("t:m.0")).unwrap(), None);
    }

    // review (eph-unify-a): a memory body is never dropped for a keep bound, so its
    // header (and expiry timer) is never forgotten while its live writes stay in the state; at
    // its expiry it is held as its leftover, value-less (spec/crdt.md §4.7). spec: none (internal)
    #[test]
    fn memory_purge_on_replace_ignored() {
        let mut lp = LocalPeer::new(1, 954, WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        let ret = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, history: Some(osis_schema::History::PurgeOnReplace) };
        let t = WallMs(e.now().0 + 2 * 3_600_000);
        let mut m = Mutation::new();
        for (k, v) in [("t:r+.0", "v"), ("t:s+.0", "live")] {
            m.retention(g, &ak(k), ret).unwrap();
            m.set(g, &ak(k), &Value::Str(v.into())).unwrap();
            m.expires(g, &ak(k), t).unwrap();
        }
        let c = e.commit_in_memory(m).unwrap().unwrap();
        lp.advance(10);
        let e = &mut lp.peers[0].engine;
        // kills `r`'s write: a memory body ignores keep bounds (`s` live)
        let mut m = Mutation::new();
        m.retention(g, &ak("t:r+.0"), ret).unwrap();
        m.set(g, &ak("t:r+.0"), &Value::Str("w".into())).unwrap();
        e.commit_in_memory(m).unwrap().unwrap();
        lp.advance(2000 + 3_600_000);
        let e = &mut lp.peers[0].engine;
        e.tick().unwrap();
        assert!(e.core.ix.commits.get(&c).is_some_and(|m| m.dropped.is_empty()));
        assert_eq!(e.get(&g, &ak("t:s+.0")).unwrap(), Some(Value::Str("live".into())));
        lp.advance(2 * 3_600_000);
        let e = &mut lp.peers[0].engine;
        e.tick().unwrap();
        assert_eq!(e.get(&g, &ak("t:s+.0")).unwrap(), None, "value-less at its expiry");
        assert!(e.core.ix.commits.get(&c).is_some_and(|m| m.dropped.is_empty() && m.stripped.len() == 2), "held as its leftover");
    }

    // eph-unify-a review (item 216): a memory aspect's state written by a durable transaction
    // lists the aspect in memory (`records::ASPECTS` routed by the key's marker), so nothing
    // durable names a memory aspect. spec: none (internal)
    #[test]
    fn memory_state_row_follows_key() {
        let mut lp = LocalPeer::new(1, 955, WallMs(1_700_000_000_000)).unwrap();
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
