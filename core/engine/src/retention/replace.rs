//! Purge on replace (spec/commits.md §5): no bound of its own, only the principle's one drop. A
//! held body out of history (a purge-on-replace body once replaced) that a held valid snapshot
//! covers goes as covered at every node, the snapshot's writer holding the purge right over it or
//! not; a writer holding a replaced purge-on-replace body that no snapshot holding the right
//! covers writes one in the transaction it comes to hold one (the replacing write or the body
//! applied, a validity flip, a role change making it a writer, a setting arriving), so the body
//! goes there at once and everywhere else when that snapshot arrives: the right holders' covers
//! keep the promise. A node without write writes none and drops only under a writer's snapshot. Judged at the end of each transaction over the aspects whose
//! purge-on-replace bodies, snapshots or roles changed (`Core::none_due`), from what is held then: a
//! function of the held set, whatever the order things arrived in. "May write" is the snapshot's
//! own check (`snapshot::may_snapshot`: role, the thing's minting and delete keys); a writer that
//! may only later waits (`Indexes::cover_waits`) and is judged again when what it waits for
//! arrives (`wake_covers`), so the last to arrive of body, replacement, role and keys triggers the
//! cover. A cover that fails leaves the body and never fails the transaction.

use super::covered;
use crate::engine::write::{MayWrite, may_write_on};
use crate::engine::{Core, DropFor, Step, Tx};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use osis_base::{Ak, CommitId, Tid, Ts};
use std::collections::BTreeSet;

/// The held valid snapshot of `(tid, ak)` that covers held body `c`, holding the right over it
/// when `right`, latest first (spec/commits.md §5 Covered; of two covered-equal snapshots only the
/// lower ID covers, spec/sync.md §7).
fn coverer(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, right: bool) -> Result<Option<CommitId>> {
    let mut snaps: Vec<(Ts, CommitId)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| (x.0, x.1)).filter(|x| x.1 != *c).collect();
    snaps.sort();
    let snapshot = tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction());
    for (_, s) in snaps.into_iter().rev() {
        if (right && !super::purge::snapshot_right(tx.core, &s, c, tid, ak)) || covered(tx, &s, c, tid, ak)? != Some(true) {
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
pub(super) fn replaced(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
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
        let kept = super::history::of(tx.core, &tid, &ak);
        if !kept.purges() {
            continue;
        }
        let bodies: Vec<CommitId> = tx.core.ix.by_aspect.get(&k).into_iter().flatten().map(|x| x.1).collect();
        let mut held = Vec::new();
        for c in bodies {
            if let Some(ai) = super::held_part(tx.core, &c, &tid, &ak).filter(|ai| tx.core.ix.commits.get(&c).is_some_and(|m| !m.bare(*ai))) {
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
        // for what moves that (`wake_covers`)
        let mut owed = false;
        let ts = tx.core.hlc.peek();
        let may = if !written.contains(&k) && !uncovered.is_empty() { super::snapshot::may_snapshot(tx, &tid, &ak, false, ts)? } else { MayWrite::No };
        match may {
            MayWrite::Later => await_cover(tx.core, &tid),
            MayWrite::Yes if tx.core.ix.cover_waits.get(&tid).is_some_and(|w| w.contains(&tid)) => end_wait(tx.core, &tid),
            _ => {}
        }
        if may == MayWrite::Yes {
            for (c, ai) in &uncovered {
                if under_purge(tx, c, *ai, &tid, &ak, &kept)? {
                    owed = true;
                    break;
                }
            }
        }
        if owed {
            written.insert(k.clone());
            // the write's own check has the last word (a removal sweep before it moves its stamp
            // on): a cover that fails leaves nothing and the body to the writers that may, and is
            // reported, never failing the transaction
            if let Err(e) = tx.step(Step::Cover, |tx| super::snapshot::write_snapshot(tx, &tid, &ak, false)) {
                let now = tx.now();
                tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: vec![tid], commit: None, peer: None, detail: e.to_string() }, now);
            }
        }
        for (c, ai) in held {
            if super::held_part(tx.core, &c, &tid, &ak) != Some(ai) || coverer(tx, &c, &tid, &ak, false)?.is_none() {
                continue;
            }
            // kept while in history (a dated replacement ahead of the clock too), and a commit
            // carrying a purge request keeps its blobs to the floor (spec/commits.md §5): judged
            // again then; out of history any writer's cover drops it (as `bounds::drop_from`)
            let now = tx.now().0;
            let floor = super::bounds::body_keep(tx, &c, &tid, &ak)?;
            if floor > now {
                if floor < osis_commit::FOREVER {
                    tx.put_timer(floor, &c, ai, super::T_FLOOR)?;
                }
                continue;
            }
            // read on its own (a live delta): no cover drops it
            if super::bounds::read_alone(tx, &c, &tid, &ak)? {
                continue;
            }
            super::drop_part_for(tx, &c, ai, DropFor::Cover)?;
            // node-sync judges its delete at hosts (a snapshot's arrival judges only the
            // aspect's cover candidates, `Core::cover_judged_on`)
            tx.core.mark_changed(c);
        }
    }
    Ok(())
}

/// Whether held body `c` (part `ai`) of `(tid, ak)` is under purge on replace (spec/commits.md
/// §5): replaced, and the setting in force when it was replaced purges on replace. Dated only
/// when the timeline moved after the body was written (else in force then is in force at its
/// replacement).
fn under_purge(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, kept: &super::history::Kept) -> Result<bool> {
    if !replaced(tx, c, ai, tid, ak)? {
        return Ok(false);
    }
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(false) };
    let written = h.ts.wall_ms().0;
    if kept.settled_from(written) {
        return Ok(kept.purge_on_replace(written));
    }
    tx.core.replaced_reads += 1;
    Ok(super::bounds::dated_replaced_at(tx, &h, c, ai)?.is_some_and(|r| kept.purge_on_replace(r.wall_ms().0)))
}

/// `t` waits to be written on before this node covers its bodies (`Indexes::cover_waits`).
fn await_cover(core: &mut Core, t: &Tid) {
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
/// opened epochs, own keys or delete-key hints changed (the journals of what it changed: O(what
/// changed), nothing when nothing waits). Each that may be written on now leaves the waits with
/// its purge-on-replace aspects due (`settle_none`), so whether a writer covers is a function of
/// the held set, whatever came last (spec/requirements.md Purge on replace).
pub(crate) fn wake_covers(tx: &mut Tx<'_>) -> Result<()> {
    // an inbox hint is taken up once its commit applies (`Core::promote_hints`)
    tx.core.promote_hints();
    let core = &*tx.core;
    let mut moved: BTreeSet<Tid> = core.ix.secrets.before().into_keys().copied().collect();
    moved.extend(core.ix.own_keys.logged());
    moved.extend(core.ix.delete_hints.before().into_keys().copied());
    for (id, old) in core.ix.commits.before() {
        let Some(m) = core.ix.commits.get(id).or(old) else { continue };
        moved.extend(m.view.aspects.iter().filter(|a| matches!(a.ak.as_str(), "created.0" | "keys.0" | "secrets.0")).map(|a| a.tid));
    }
    let woken: BTreeSet<Tid> = moved.iter().filter_map(|a| core.ix.cover_waits.get(a)).flatten().copied().collect();
    for t in woken {
        let may = may_write_on(tx, &t)?;
        end_wait(tx.core, &t);
        match may {
            // the chain may have grown (a record arrived): kept under all of it
            MayWrite::Later => await_cover(tx.core, &t),
            MayWrite::Yes => {
                let on: Vec<Ak> = tx.core.ix.by_aspect.range((t, Ak::MIN)..).take_while(|((x, _), _)| *x == t).map(|((_, a), _)| a.clone()).collect();
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
