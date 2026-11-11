//! Purge on replace (spec/commits.md §5): no bound of its own, only the principle's one drop. A
//! held purge-on-replace body a held valid snapshot covers, whose commit holds the right over it,
//! goes as covered at every node; a writer holding a replaced one that no such snapshot covers
//! writes one in the transaction it comes to hold one (the replacing write or the body applied, a
//! validity flip, a role change making it a writer), so the body goes there at once and
//! everywhere else when that snapshot arrives. A node without write writes none and drops only
//! under a writer's snapshot. Judged at the end of each transaction over the aspects whose
//! purge-on-replace bodies, snapshots or roles changed (`Core::none_due`), from what is held then.
//! "May write" is the snapshot's own check (`snapshot::snapshot_writer`: role and the thing's
//! delete keys), and a cover it refuses leaves the body, never fails the transaction. Limit: delete
//! keys arriving last are no trigger (issues/purge-cover-on-delete-keys.md).

use super::covered;
use crate::engine::{DropFor, Step, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use std::collections::BTreeSet;

/// The held valid snapshot of `(tid, ak)` holding the right over held body `c` that covers it,
/// latest first (spec/commits.md §5 Covered; of two covered-equal snapshots only the lower ID
/// covers, spec/sync.md §7).
fn coverer(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
    let mut snaps: Vec<(Ts, CommitId)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| (x.0, x.1)).filter(|x| x.1 != *c).collect();
    snaps.sort();
    let snapshot = tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction());
    for (_, s) in snaps.into_iter().rev() {
        if !super::purge::snapshot_right(tx.core, &s, c, tid, ak) || covered(tx, &s, c, tid, ak)? != Some(true) {
            continue;
        }
        if snapshot && *c < s && covered(tx, c, &s, tid, ak)? == Some(true) {
            continue;
        }
        return Ok(Some(s));
    }
    Ok(None)
}

/// Whether held valid body `c` on `(tid, ak)` (part `ai`) is replaced: joined into the state it
/// changes nothing (spec/crdt.md §3.3: what it holds that the state lacks is dead, not un-merged
/// with an invalid record it sits in, spec/crdt.md §4.6), and a write winning in it wins no
/// longer in the join (spec/crdt.md §4.8, `Fragment::winners`) or it holds a write
/// the state does not hold by dot. Judged a piece at a time against the state's part it meets. A
/// write is not identified by its stamp or dot (a map entry's creation and its values share one),
/// so dots alone miss an overwritten value. A write the state holds as it is (a root reset a later
/// write implies, kept by canonical form) wins in both, so a snapshot of the state is never
/// replaced by its own content and writers' covers do not chase each other. A delta with an
/// expiry held with its values is judged against the state with its values value-less, as a
/// snapshot carries them (spec/crdt.md §8): replaced only once no value of it lives, when a
/// snapshot of the state covers it (spec/commits.md §5).
fn replaced(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    if !m.valid_at(ai) {
        return Ok(false);
    }
    let own = (m.header.expires.is_some() && !super::valueless(tx.core, c, ai)).then(|| super::writes_of(&m.header, c, ai));
    let mut out = false;
    crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        if out {
            return Ok(());
        }
        let Some(mut st) = tx.state_at(tid, ak, &f)? else { return Ok(()) };
        if let Some(own) = &own {
            st.strip(&|d| own.iter().any(|o| o.owns(d)));
        }
        let mine: BTreeSet<osis_crdt::Dot> = f.live_writes().into_iter().map(|(d, _)| d).collect();
        let there: BTreeSet<osis_crdt::Dot> = st.live_writes().into_iter().map(|(d, _)| d).collect();
        let before = crate::engine::state::encode(&st)?;
        let own = f.winners();
        st.join(f);
        let died = !own.minus(&st.winners()).is_empty();
        out = (died || !mine.is_subset(&there)) && crate::engine::state::encode(&st)? == before;
        Ok(())
    })?;
    Ok(out)
}

/// Judges the purge-on-replace bodies of the aspects marked this transaction (`Core::none_due`):
/// a writer covers what is replaced and uncovered (one snapshot per aspect), then every covered
/// one drops (spec/commits.md §5). Durable aspects only: an ephemeral delta's retention is fixed
/// with no history promised (spec/commits.md §2).
pub(crate) fn settle_none(tx: &mut Tx<'_>) -> Result<()> {
    if tx.core.keep_bodies {
        return Ok(());
    }
    let mut written: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    while let Some(k) = tx.core.none_due.pop_first() {
        let (tid, ak) = k.clone();
        // a memory transaction writes no durable commit
        if tx.txn.is_memory() {
            continue;
        }
        let bodies: Vec<CommitId> = tx.core.ix.none_held.get(&k).into_iter().flatten().copied().collect();
        let mut held = Vec::new();
        for c in bodies {
            if let Some(ai) = super::held_part(tx.core, &c, &tid, &ak) {
                held.push((c, ai));
            }
        }
        if held.is_empty() {
            continue;
        }
        let mut uncovered = Vec::new();
        for (c, ai) in &held {
            if coverer(tx, c, &tid, &ak)?.is_none() {
                uncovered.push((*c, *ai));
            }
        }
        // a node that may write a snapshot (every writer holds the right over a `writer` body,
        // spec/permissions.md §6), judged at the stamp it would carry
        let mut owed = false;
        let ts = tx.core.hlc.peek();
        if !written.contains(&k) && !uncovered.is_empty() && super::snapshot::snapshot_writer(tx, &tid, &ak, false, ts)?.is_some() {
            for (c, ai) in &uncovered {
                if replaced(tx, c, *ai, &tid, &ak)? {
                    owed = true;
                    break;
                }
            }
        }
        if owed {
            written.insert(k.clone());
            // the write's own check has the last word (a removal sweep before it moves its stamp
            // on): a refusal leaves the body to the writers that may, never fails the transaction
            match tx.step(Step::Cover, |tx| super::snapshot::write_snapshot(tx, &tid, &ak, false)) {
                Ok(_) | Err(Error::Permission { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        for (c, ai) in held {
            if super::held_part(tx.core, &c, &tid, &ak) != Some(ai) || coverer(tx, &c, &tid, &ak)?.is_none() {
                continue;
            }
            // a commit carrying a purge request keeps its blobs to the floor (spec/commits.md §5)
            let floor = super::bounds::body_keep(tx, &c, &tid, &ak)?;
            if floor > tx.now().0 {
                tx.put_timer(floor, &c, ai, super::T_FLOOR)?;
                continue;
            }
            super::drop_part_for(tx, &c, ai, DropFor::Cover)?;
        }
    }
    Ok(())
}

/// Part `ai` of `c` reached its purge floor (`T_FLOOR`): its aspect is judged again at the end of
/// the transaction.
pub(super) fn floor_passed(tx: &mut Tx<'_>, c: &CommitId, ai: usize) {
    if let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)) {
        tx.core.none_due.insert((a.tid, a.ak.clone()));
    }
}
