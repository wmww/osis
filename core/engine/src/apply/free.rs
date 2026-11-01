//! Freeing memory things (issues/eph-unify.md step 3): an ephemeral thing nobody here needs any
//! more goes with its memory-class record, the memory commits every thing of which is freed
//! (`unindex_commit`, the mirror of what applying a commit indexes) and its aspects' memory rows
//! (one store call). Freeing leaves the indexes as if those commits had never applied
//! (`tests::free_equals_never_indexed`); a commit that also touches a thing not freed stays, and
//! so does every thing it is on, whole, until all of them are freed; so does the owner of a held
//! thing not freed. A memory commit that also touches a durable thing (an item's writes with its
//! `placed.0~` add into a durable group) keeps its things until it goes by retention.

use crate::engine::records;
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;

/// Local records keyed by aspect (`records::aspect_key`) a memory aspect may hold.
const ASPECT_RECORDS: [&[u8]; 5] = [records::ASPECTS, records::RECEIPT, records::VALUELESS, records::PURGES, records::DEATHS_DUE];

/// Frees the memory things among `things` and those freed before but still in use (`freeing`):
/// a thing stays (in `freeing`) while a commit on it touches a thing not freed or it owns a held
/// thing not freed; the others go with their records, aspects and every commit on them.
pub(crate) fn free(tx: &mut Tx<'_>, things: &BTreeSet<Tid>) -> Result<()> {
    let mut freed: BTreeSet<Tid> = things.iter().filter(|t| tx.core.ix.held.is_memory(t)).copied().collect();
    if freed.is_empty() {
        return Ok(());
    }
    tx.core.touch();
    // a thing waiting in `freeing` may have persisted since
    let waiting: Vec<Tid> = tx.core.ix.freeing.iter().copied().collect();
    for t in waiting {
        if tx.core.ix.held.is_memory(&t) {
            freed.insert(t);
        } else {
            tx.core.ix.freeing.remove(&t);
        }
    }
    // what stays, to a fixpoint: a thing a commit is on that also touches a thing not freed (or
    // a durable commit, defensively), and the owner of a held thing not freed (its chain)
    loop {
        let core = &*tx.core;
        let stays: Vec<Tid> = freed
            .iter()
            .filter(|t| {
                core.ix.held.owned(t).any(|x| !freed.contains(x))
                    || core.ix.by_thing.get(t).into_iter().flatten().any(|c| core.ix.commits.get(c).is_some_and(|m| !m.view.memory || m.view.aspects.iter().any(|a| !freed.contains(&a.tid))))
            })
            .copied()
            .collect();
        if stays.is_empty() {
            break;
        }
        for t in stays {
            freed.remove(&t);
            tx.core.ix.freeing.insert(t);
        }
    }
    // a pending memory commit all of whose things are freed goes too (its records ride in it,
    // so it would bring them back when it applied)
    for (c, bytes) in tx.txn.memory_pending()? {
        let Ok(b) = osis_commit::CommitBlob::decode(&bytes) else { continue };
        if !b.header.aspects.is_empty() && b.header.aspects.iter().all(|a| freed.contains(&a.tid)) {
            tx.txn.remove_pending(&c, Shred::No)?;
            tx.core.ix.pending.remove(&c);
            tx.core.waits.unpended(&c);
        }
    }
    let cands: BTreeSet<CommitId> = freed.iter().flat_map(|t| tx.core.ix.by_thing.get(t).into_iter().flatten().copied()).collect();
    for c in cands {
        unindex_commit(tx, &c)?;
    }
    for t in &freed {
        tx.core.ix.freeing.remove(t);
        tx.core.ix.held.free(t);
        tx.txn.remove_local(&[records::CREATED, t.as_bytes()].concat(), Shred::No)?;
        let aks = tx.txn.drop_memory_thing(t, |ak| ASPECT_RECORDS.iter().map(|p| records::aspect_key(p, t, ak)).collect())?;
        for ak in aks {
            unindex_aspect(tx.core, t, &ak);
        }
        if tx.core.ix.groups.defs.contains_key(t) {
            tx.core.ix.groups.set(*t, None);
        }
        tx.core.ix.syncing.remove(t);
    }
    tx.core.update_timelines();
    let flipped = super::validity::rejudge_all(tx, true)?;
    for (t, ak) in &flipped {
        super::atomic::observe_state(tx, t, ak)?;
    }
    if !flipped.is_empty() {
        tx.core.events.queue(crate::events::Event::Changed { cause: crate::events::Cause::Validity, changed: flipped });
    }
    Ok(())
}

/// Removes commit `id` from every index applying it added to and its records from the store:
/// the mirror of `index_commit` and the rest of `apply_verified` for a memory commit.
pub(crate) fn unindex_commit(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let core = &mut *tx.core;
    let Some(m) = core.ix.commits.remove(id) else { return Ok(()) };
    let v = &m.view;
    for a in &v.aspects {
        let k = (a.tid, a.ak.clone());
        core.ix.by_aspect.remove(&k, &(v.ts, *id));
        core.ix.invalid.remove(&k, id);
        core.ix.by_thing.remove(&a.tid, id);
        core.ix.dropped_snapshots.remove(&k, id);
        if v.form.counted() && v.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.remove(&(a.tid, a.ak.clone(), v.form.own_source(v.author, *id)), &a.lo);
        }
        super::atomic::forget_snapshot(core, &a.tid, &a.ak, id);
    }
    for b in &v.chunks {
        core.ix.by_chunk.remove(b, id);
    }
    core.ix.void.remove(id);
    core.ix.pending.remove(id);
    core.stale_commits.remove(id);
    // its retention timers (memory rows)
    let timers: Vec<Vec<u8>> = tx.txn.memory_local_keys(records::TIMER).into_iter().filter(|k| records::parse_timer(k.get(records::TIMER.len()..).unwrap_or_default()).is_ok_and(|(_, c, _)| c == *id)).collect();
    for k in timers {
        tx.txn.remove_local(&k, Shred::No)?;
    }
    tx.remove_commit(id)
}

/// Drops what the indexes and caches keep per aspect of `(tid, ak)` (no commit is on it).
fn unindex_aspect(core: &mut Core, tid: &Tid, ak: &Ak) {
    let k = (*tid, ak.clone());
    core.ix.snapshots.remove(&k);
    core.ix.carried.remove(&k);
    core.ix.valueless.remove(&k);
    core.ix.deaths_due.remove(&k);
    core.states.remove(&k);
    core.pages.remove(&k);
}

#[cfg(test)]
mod tests {
    use crate::engine::journal::Journaled;
    use crate::local_peer::LocalPeer;
    use crate::{Engine, Mutation};
    use osis_base::{Ak, Value, WallMs};
    use std::collections::BTreeSet;

    fn digest(e: &Engine) -> String {
        e.core.ix.commits.values().for_each(|m| drop(m.header.decoded()));
        format!("{}\n{}", e.core.ix.contents(), e.perm_digest(false))
    }

    fn ak(s: &str) -> Ak {
        Ak::new(s).unwrap()
    }

    // issues/eph-unify.md step 3 (freeing): memory commits applied on memory things, then those
    // things freed, leave every journaled index (and perm's view) as if the commits had never
    // applied, and no memory row but the session's counters: an index applying fills and
    // `unindex_commit` forgets fails here. spec: none (internal)
    #[test]
    fn free_equals_never_indexed() {
        let mut lp = LocalPeer::new(1, 952, WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        let before = digest(e);
        let rows = |e: &mut Engine| e.run(|tx| Ok(tx.txn.memory_local_keys(b""))).unwrap();
        assert!(rows(e).is_empty());
        let mut m = Mutation::new();
        let top = e.new_thing(&mut m, g);
        let leaf = e.new_thing(&mut m, top);
        m.set(leaf, &ak("t:a.0~"), &Value::Str("x".into())).unwrap();
        m.expires(leaf, &ak("t:a.0~"), WallMs(e.now().0 + 60_000)).unwrap();
        e.commit_in_memory(m).unwrap().unwrap();
        for i in 0..2 {
            let mut m = Mutation::new();
            m.set(leaf, &ak("t:a.0~"), &Value::Str(format!("y{i}"))).unwrap();
            m.set(top, &ak("t:b.0~"), &Value::Set([Value::Str(format!("z{i}"))].into())).unwrap();
            e.commit_in_memory(m).unwrap().unwrap();
        }
        // an owner no commit is on, of a thing one is on
        let mut m = Mutation::new();
        let boss = e.new_thing(&mut m, g);
        let kid = e.new_thing(&mut m, boss);
        m.set(kid, &ak("t:a.0~"), &Value::Str("k".into())).unwrap();
        e.commit_in_memory(m).unwrap().unwrap();
        // the first write expires: held value-less, its timer gone
        lp.advance(61_000);
        let e = &mut lp.peers[0].engine;
        e.tick().unwrap();
        assert!(e.core.ix.valueless.keys().any(|(t, _)| *t == leaf));
        assert_ne!(digest(e), before);
        assert!(!rows(e).is_empty());
        e.free_memory(&BTreeSet::from([boss])).unwrap();
        assert!(e.core.created(&boss).is_some(), "the owner of a held thing stays");
        e.free_memory(&BTreeSet::from([kid])).unwrap();
        assert!(e.core.created(&boss).is_none() && e.core.created(&kid).is_none());
        e.free_memory(&BTreeSet::from([top])).unwrap();
        assert!(e.core.created(&top).is_some() && e.core.created(&leaf).is_some(), "a commit on a thing not freed keeps its things");
        assert_eq!(e.get(&top, &ak("t:b.0~")).unwrap(), Some(Value::Set([Value::Str("z1".into())].into())));
        e.free_memory(&BTreeSet::from([leaf])).unwrap();
        assert_eq!(digest(e), before);
        assert!(rows(e).is_empty(), "{:?}", rows(e));
        assert!(e.core.states.keys().all(|(t, _)| *t != top && *t != leaf));
        // a durable thing is never freed
        e.free_memory(&BTreeSet::from([g])).unwrap();
        assert_eq!(digest(e), before);
    }
}
