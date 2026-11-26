//! Purge on replace (spec/commits.md §5): no bound of its own, only the principle's one drop. A
//! held body out of history (a purge-on-replace body once replaced) that a held valid snapshot
//! covers goes as covered at every node, the snapshot's writer holding the purge right over it or
//! not; a writer holding a replaced purge-on-replace body that no snapshot holding the right
//! covers writes one in the transaction it comes to hold one (the replacing write or the body
//! applied, a validity flip, a role change making it a writer, a setting arriving), unless its own
//! would hold no right either and another held cover already drops it, so the body
//! goes there at once and everywhere else when that snapshot arrives: the right holders' covers
//! keep the promise. A node without write writes none and drops only under a writer's snapshot. Judged at the end of each transaction over the aspects whose
//! purge-on-replace bodies, snapshots or roles changed (`Core::none_due`), from what is held then: a
//! function of the held set, whatever the order things arrived in. "May write" is the snapshot's
//! own check (`snapshot::may_snapshot`: role, the thing's minting, the epochs the writes it
//! carries were read under); a writer that may only later waits (`Indexes::cover_waits`) and is
//! judged again when what it waits for arrives (`wake_covers`), so the last to arrive of body,
//! replacement, role, minting and keys triggers the cover. A cover that fails leaves the body and never fails the transaction.

use crate::engine::write::{MayWrite, may_write_on};
use crate::engine::{Core, DropFor, Step, Tx};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use osis_base::{Ak, CommitId, Tid, Ts};
use std::collections::BTreeSet;

/// The held valid snapshot of `(tid, ak)` that covers held body `c`, holding the right over it
/// when `right`, latest first (spec/commits.md §5 Covered; of two covered-equal snapshots only the
/// lower ID covers, spec/sync-compaction.md §1), never another node's own cover at a removal
/// (`others_own_cover`: only its writer drops under it).
fn coverer(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, right: bool) -> Result<Option<CommitId>> {
    let mut snaps: Vec<(Ts, CommitId)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| (x.0, x.1)).filter(|x| x.1 != *c).collect();
    snaps.sort();
    for (_, s) in snaps.into_iter().rev() {
        if super::others_own_cover(tx.core, &s) {
            continue;
        }
        if (!right || super::purge::snapshot_right(tx.core, &s, c, tid, ak)) && super::snapshot::drops_under(tx, &s, c, tid, ak)? {
            return Ok(Some(s));
        }
    }
    Ok(None)
}

/// Whether held valid body `c` on `(tid, ak)` (part `ai`) is replaced (spec/commits.md §5
/// Bodies and deaths): a write of it is dead, superseded by a write lasting at least as long
/// (`bounds::dead`: the held writes, O(part)), and joined into the state it changes nothing
/// (spec/crdt.md §3.3: what it holds that the state lacks is dead, not un-merged with an invalid
/// record it sits in, spec/crdt.md §4.6). The state as it is, not without the writes ending
/// sooner (what a snapshot ending with the body carries, as the spec words it): such a write
/// can hold the body's writes from the state only where it supersedes them, and those it alone
/// supersedes are not dead for the body, so it is replaced in one exactly where it is in the
/// other (checked against that whole judging state in debug builds, `replaced_judged`). A write
/// the state holds as it is (a root reset a later write implies, kept by canonical form) wins in
/// both, so a snapshot of the state is never replaced by its own content and writers' covers do
/// not chase each other.
pub(super) fn replaced(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
    let out = replaced_read(tx, c, ai, tid, ak)?;
    #[cfg(debug_assertions)]
    {
        let whole = super::bounds::unseen(tx, |tx| replaced_judged(tx, c, ai, tid, ak))?;
        assert_eq!(out, whole, "replaced by the held writes vs the whole judging state");
    }
    Ok(out)
}

/// `replaced` by the spec's wording: judged against the state without the writes ending sooner
/// than the body (`snapshot::outlived`, O(state)): a write winning in it wins no longer in the
/// join, or it holds a write the state does not hold by dot, and the join changes nothing.
#[cfg(debug_assertions)]
fn replaced_judged(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    if !m.valid_at(ai) {
        return Ok(false);
    }
    let by = super::snapshot::outlived(tx, tid, ak, m.header.expires)?;
    let mut out = false;
    super::each_body_piece(tx, c, ai, &mut |tx, f| {
        if out {
            return Ok(());
        }
        let Some(mut st) = super::snapshot::judged_state(tx, tid, ak, &f, by.as_ref(), false)? else { return Ok(()) };
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

fn replaced_read(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
    if !tx.core.ix.commits.get(c).is_some_and(|m| m.valid_at(ai)) || !super::bounds::dead(tx, c, ai)? {
        return Ok(false);
    }
    let mut out = true;
    super::each_body_piece(tx, c, ai, &mut |tx, f| {
        if !out {
            return Ok(());
        }
        out = match tx.state_at(tid, ak, &f)? {
            Some(mut st) => {
                let before = crate::engine::state::encode(&st)?;
                st.join(f);
                crate::engine::state::encode(&st)? == before
            }
            None => false,
        };
        Ok(())
    })?;
    Ok(out)
}

/// Judges the purge-on-replace bodies of the aspects marked this transaction (`Core::none_due`):
/// a writer covers what is replaced and uncovered (one snapshot per aspect), then every covered
/// one drops (spec/commits.md §5). Either class: an ephemeral aspect's cover is a memory snapshot,
/// and its replaced bodies drop under any writer's cover, their author's own included (no
/// promise keeps them; notes/ephemeral.md (Own bodies under own covers) is for bodies nothing
/// purges), a commit so spent forgotten (`memory::forget_if_spent`).
pub(crate) fn settle_none(tx: &mut Tx<'_>) -> Result<()> {
    if tx.core.keep_bodies {
        return Ok(());
    }
    // the covers written this transaction, by aspect and end: at most one each
    let mut written: BTreeSet<(Tid, Ak, Option<u64>)> = BTreeSet::new();
    while let Some(k) = tx.core.none_due.pop_first() {
        let (tid, ak) = k.clone();
        // a memory transaction writes no durable commit
        let memory = ak.ephemeral();
        if tx.txn.is_memory() && !memory {
            continue;
        }
        let kept = super::history::of(tx.core, &tid, &ak);
        if !kept.purges() {
            continue;
        }
        let bodies: Vec<CommitId> = tx.core.ix.by_aspect.get(&k).into_iter().flatten().map(|x| x.1).collect();
        mark_strips(tx, &bodies)?;
        let mut held = Vec::new();
        for c in bodies {
            if let Some(ai) = super::held_part(tx.core, &c, &tid, &ak).filter(|ai| tx.core.ix.commits.get(&c).is_some_and(|m| !m.own_gone(*ai))) {
                held.push((c, ai));
            }
        }
        if held.is_empty() {
            continue;
        }
        let mut uncovered = Vec::new();
        for (c, ai) in &held {
            if coverer(tx, c, &tid, &ak, true)?.is_none() {
                uncovered.push((*c, *ai));
            }
        }
        // a node that may write a snapshot (every writer holds the right over a `writer` body,
        // spec/permissions.md §6), judged at the stamp it would carry; one that may later waits
        // for what moves that (`wake_covers`). One whose snapshot would hold no right over a body
        // another held cover already drops here owes none for it: its own would add nothing
        // (spec/commits.md §5 Purge on replace)
        let ts = tx.core.hlc.peek();
        let may = if !uncovered.is_empty() { super::snapshot::may_snapshot(tx, &tid, &ak, memory, ts)? } else { MayWrite::No };
        match may {
            MayWrite::Later => await_cover(tx.core, &tid),
            MayWrite::Yes if tx.core.ix.cover_waits.get(&tid).is_some_and(|w| w.contains(&tid)) => {
                end_wait(tx.core, &tid);
                tx.core.compaction.wake(&tid);
            }
            _ => {}
        }
        // a cover lasts as long as what it covers (spec/commits.md §5 Covered): one per end among
        // the owed bodies, from the state a write ending then dies in (`snapshot::write_cover`),
        // so it covers every owed body ending then. Latest first, each only while a body ending
        // then is still uncovered: a later one covers an earlier body no write ending between
        // keeps alive
        let mut owed: Vec<(Option<u64>, CommitId)> = Vec::new();
        if may == MayWrite::Yes {
            let me = tx.core.tid();
            for (c, ai) in &uncovered {
                if !under_purge(tx, c, *ai, &tid, &ak, &kept)? {
                    continue;
                }
                if !super::purge::would_hold_right(tx.core, &me, ts, c, &tid, &ak) && coverer(tx, c, &tid, &ak, false)?.is_some() {
                    continue;
                }
                let ends = tx.core.ix.commits.get(c).and_then(|m| m.header.expires);
                if !written.contains(&(tid, ak.clone(), ends)) {
                    owed.push((ends, *c));
                }
            }
        }
        owed.sort_by_key(|x| std::cmp::Reverse(x.0.unwrap_or(u64::MAX)));
        for (ends, c) in owed {
            if written.contains(&(tid, ak.clone(), ends)) || coverer(tx, &c, &tid, &ak, true)?.is_some() {
                continue;
            }
            written.insert((tid, ak.clone(), ends));
            // the write's own check has the last word (a removal sweep before it moves its stamp
            // on): a cover that fails leaves nothing and the body to the writers that may, and is
            // reported, never failing the transaction
            if let Err(e) = tx.step(Step::Cover, |tx| tx.in_class(memory, |tx| super::snapshot::write_cover(tx, &tid, &ak, memory, ends))) {
                tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: vec![tid], commit: None, peer: None, detail: e.to_string() }, tx.core.hlc.mono());
            }
        }
        for (c, ai) in held {
            if super::held_part(tx.core, &c, &tid, &ak) != Some(ai) || coverer(tx, &c, &tid, &ak, false)?.is_none() {
                continue;
            }
            // a live delta is no purge-on-replace body: it drops as any covered body does, by
            // node-sync (its author's own covers only there, spec/sync-compaction.md §1 own bodies). A memory
            // body only under purge on replace: any other (a snapshot carrying live writes, one
            // replaced under another setting) is node-sync's too, where its author keeps its own
            // (notes/ephemeral.md Own bodies under own covers)
            let gone = if memory {
                under_purge(tx, &c, ai, &tid, &ak, &kept)?
            } else {
                tx.core.ix.commits.get(&c).is_some_and(|m| m.view.kind.is_compaction()) || replaced(tx, &c, ai, &tid, &ak)?
            };
            if !gone {
                continue;
            }
            // kept while in history (a dated replacement ahead of the clock too), and a commit
            // carrying a purge request keeps its blobs to the floor (spec/commits.md §5): judged
            // again then; out of history any writer's cover drops it (as `Engine::drop_from`)
            let now = tx.now().0;
            let floor = super::bounds::part_keep(tx, &c, &tid, &ak)?;
            if floor > now {
                if floor < osis_commit::FOREVER {
                    tx.put_timer(floor, &c, ai, super::T_FLOOR)?;
                }
                continue;
            }
            tx.in_class(memory, |tx| {
                super::drop_part_for(tx, &c, ai, DropFor::Cover)?;
                super::memory::forget_if_spent(tx, &c)
            })?;
        }
    }
    Ok(())
}

/// Of `bodies` (the commits with a part on an aspect `settle_none` judges), each part dropped as
/// covered that strips now is marked so in its record (`sync::bodies::strip_due`,
/// `Dropped::strips`): its blobs drop it, and what this node keeps of it for them goes, in this
/// transaction. A drop as covered below puts its meta, so its aspect is judged again here.
fn mark_strips(tx: &mut Tx<'_>, bodies: &[CommitId]) -> Result<()> {
    for c in bodies {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        let due: Vec<usize> = (0..m.view.aspects.len()).filter(|ai| crate::sync::bodies::strip_due(tx.core, c, m, *ai)).collect();
        if due.is_empty() {
            continue;
        }
        let mut m = m.clone();
        for ai in due {
            if let Some(d) = m.dropped_mut(ai) {
                d.strips = true;
            }
        }
        tx.core.touch();
        tx.in_class(m.view.memory, |tx| tx.put_meta_record(c, m))?;
    }
    Ok(())
}

/// Whether held body `c` (part `ai`) of `(tid, ak)` is under purge on replace (spec/commits.md
/// §5): replaced, and the current setting's entry purges on replace or its floor is past the
/// body's oldest dead write (`bounds::written_of`).
fn under_purge(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, kept: &super::history::Kept) -> Result<bool> {
    if !replaced(tx, c, ai, tid, ak)? {
        return Ok(false);
    }
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(false) };
    let w = super::bounds::written_of(tx, &h, c, ai)?;
    Ok(kept.purge_on_replace(w))
}

/// `t` waits to be written on before this node covers its bodies or weighs them for the trigger
/// (`Indexes::cover_waits`).
pub(crate) fn await_cover(core: &mut Core, t: &Tid) {
    let chain: Vec<Tid> = core.record_chain(t).filter_map(|s| s.thing()).collect();
    for a in chain {
        core.ix.cover_waits.insert(a, *t);
    }
}

/// `t` waits no more (`Indexes::cover_waits`).
fn end_wait(core: &mut Core, t: &Tid) {
    let chain: Vec<Tid> = core.record_chain(t).filter_map(|s| s.thing()).collect();
    for a in chain {
        core.ix.cover_waits.remove(&a, t);
    }
}

/// The things waiting in `Indexes::cover_waits` that this transaction may have made writable here:
/// those with a thing on their record chain whose `created.0`, `keys.0` or `secrets.0` commits,
/// opened epochs or independence changed (the journals of what it changed: O(what
/// changed), nothing when nothing waits). Each that may be written on now leaves the waits with
/// its purge-on-replace aspects due (`settle_none`) and the trigger's owed weighings woken
/// (`compact::Trigger::wake`) and its owed re-snapshots due (`Indexes::resnapshots_owed`), so
/// whether a writer covers is a function of the held set, whatever came last
/// (spec/requirements.md Purge on replace).
pub(crate) fn wake_covers(tx: &mut Tx<'_>) -> Result<()> {
    let core = &*tx.core;
    let mut moved: BTreeSet<Tid> = core.ix.secrets.before().into_keys().copied().collect();
    moved.extend(core.ix.independent.logged());
    for (id, old) in core.ix.commits.before() {
        let Some(m) = core.ix.commits.get(id).or(old) else { continue };
        moved.extend(m.view.aspects.iter().filter(|a| matches!(a.ak.as_str(), "created.0" | "keys.0" | "secrets.0")).map(|a| a.tid));
    }
    let woken: BTreeSet<Tid> = moved.iter().filter_map(|a| core.ix.cover_waits.get(a)).flatten().copied().collect();
    for t in woken {
        let may = may_write_on(tx, &t)?;
        end_wait(tx.core, &t);
        // its owed re-snapshots are judged again (`Engine::purge_resnapshots`)
        if may != MayWrite::Later {
            let owed: Vec<Ak> = tx.core.ix.resnapshots_owed.get(&t).into_iter().flat_map(|m| m.keys().cloned()).collect();
            tx.core.resnapshots_due.extend(owed.into_iter().map(|a| (t, a)));
        }
        match may {
            // the chain may have grown (a record arrived): kept under all of it
            MayWrite::Later => await_cover(tx.core, &t),
            MayWrite::Yes => {
                tx.core.compaction.wake(&t);
                let on: Vec<Ak> = tx.core.aspects_of(&t).map(|((_, a), _)| a.clone()).collect();
                for ak in on {
                    if super::history::of(tx.core, &t, &ak).purges() {
                        tx.core.none_due.insert((t, ak));
                    }
                }
            }
            MayWrite::No => {}
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
