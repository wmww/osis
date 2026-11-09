//! Signal edits (spec/commits.md §5 Signals). A durable signal's part naming `replaces` is an
//! honored version of the named fire while that fire is listed, valid and unreplaced, by the same
//! verified actor, and sorts before it; the version then lists under the original.
//!
//! The rule, one derived state: `versions` is every valid claim (`index_commit`,
//! `index_validity`); `originals` is every fire's place but the honored versions'. A claim's status
//! depends only on its original and on itself, so `settle` recomputes the claims of each original
//! that changed and each claim that changed, from the state it finds, at the end of the transaction:
//! the same function whatever arrived first. The fire reads as its newest listed honored version,
//! found at read time (`newest_version`). An original leaving the listing by time alone (a purge
//! tombstone's end) is told by a timer (`time_passed`).

use super::listing::{CommitPos, Here, listed, purged_keep};
use super::{AspectView, Core, Tx, View};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use std::collections::BTreeSet;

/// What may carry `replaces` (spec/commits.md §5 Signals): a durable signal.
pub(crate) fn durable_signal(ak: &Ak) -> bool {
    ak.signal() && !ak.ephemeral()
}

/// The durable signal parts of commit view `v`.
fn signal_parts(v: &View) -> impl Iterator<Item = (usize, &AspectView)> + '_ {
    v.aspects.iter().enumerate().filter(move |(_, a)| !v.memory && durable_signal(&a.ak))
}

/// The `versions` key of `v`'s claim at `a`, if any.
fn claim(v: &View, a: &AspectView) -> Option<(Tid, Ak, CommitId, Tid)> {
    a.replaces.map(|o| (a.tid, a.ak.clone(), o, v.actor))
}

/// A held commit's claims join `versions` when indexed; `index_validity` takes the invalid out.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, v: &View) {
    for (_, a) in signal_parts(v) {
        if let Some(k) = claim(v, a) {
            core.ix.versions.insert(k, (v.ts, *id));
        }
    }
}

/// Validity moved `id`'s claims in or out of `versions`.
pub(crate) fn index_validity(core: &mut Core, id: &CommitId) {
    let Some(m) = core.ix.commits.get(id).filter(|m| m.view.aspects.iter().any(|a| a.replaces.is_some())) else { return };
    let v = m.view.clone();
    let valid = m.valid.clone();
    for (ai, a) in signal_parts(&v) {
        let Some(k) = claim(&v, a) else { continue };
        if valid.get(ai).copied().unwrap_or(false) {
            core.ix.versions.insert(k, (v.ts, *id));
        } else {
            core.ix.versions.remove(&k, &(v.ts, *id));
        }
    }
}

/// A keep bound of `c`'s part passed: its listing may have changed with no meta changing.
pub(crate) fn time_passed(tx: &mut Tx<'_>, c: &CommitId, ai: usize) {
    if let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)).filter(|a| durable_signal(&a.ak)) {
        let k = (a.tid, a.ak.clone(), *c);
        tx.core.refold.insert(k);
    }
}

/// Whether `c` is folded under its original (absent from `originals`, carrying a claim).
pub(crate) fn folded(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    if !durable_signal(ak) {
        return false;
    }
    let Some(m) = core.ix.commits.get(c) else { return false };
    let claims = m.view.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak && a.replaces.is_some());
    claims && !core.ix.originals.get(&(*tid, ak.clone())).is_some_and(|s| s.contains(&(m.view.ts, *c)))
}

/// Whether commit `o` can be replaced on `(tid, ak)`: it is held and listed there, valid, with no
/// `replaces` of its own (spec/commits.md §5 Signals).
fn original(tx: &mut Tx<'_>, o: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    let Some(ai) = tx.core.ix.commits.get(o).and_then(|m| m.aspect(tid, ak)) else { return Ok(false) };
    if tx.core.ix.commits.get(o).is_some_and(|m| m.view.aspects.get(ai).is_some_and(|a| a.replaces.is_some())) {
        return Ok(false);
    }
    Ok(listed(tx, o, ai)?.is_some_and(|(valid, _)| valid))
}

/// Puts claim `(ts, v)` where it belongs, the fold of its named commit judged as `fold` (`None`: it
/// is no valid claim under an actor's original, so it stands alone). Returns whether it moved.
fn place(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, ts: Ts, v: &CommitId, fold: Option<(Ts, CommitId, bool)>) -> bool {
    let at = (ts, *v);
    let folds = fold.is_some_and(|(ots, o, ok)| ok && (ots, o) < at);
    let k = (*tid, ak.clone());
    if folds { tx.core.ix.originals.remove(&k, &at) } else { tx.core.ix.originals.insert(k, at) }
}

/// Every claim under `o` re-placed; `o` told when its reading may have changed, its moved claims too.
fn refold(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, o: &CommitId) -> Result<()> {
    let Some((ots, actor)) = tx.core.ix.commits.get(o).map(|m| (m.view.ts, m.view.actor)) else { return Ok(()) };
    let k = (*tid, ak.clone(), *o, actor);
    let claims: Vec<(Ts, CommitId)> = tx.core.ix.versions.get(&k).map(|s| s.iter().copied().collect()).unwrap_or_default();
    if claims.is_empty() {
        return Ok(());
    }
    let ok = original(tx, o, tid, ak)?;
    for (ts, v) in claims {
        if place(tx, tid, ak, ts, &v, Some((ots, *o, ok))) {
            tx.core.commits_named(*tid, ak.clone(), v);
        }
    }
    tx.core.commits_named(*tid, ak.clone(), *o);
    Ok(())
}

/// Claim `v` on `(tid, ak)` naming `o` re-placed (`v` changed).
fn reclaim(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, o: &CommitId, v: &CommitId, ts: Ts) -> Result<()> {
    let actor = tx.core.ix.commits.get(v).map(|m| m.view.actor);
    let fold = match (tx.core.ix.commits.get(o).map(|m| (m.view.ts, m.view.actor)), actor) {
        (Some((ots, oa)), Some(va)) if oa == va && tx.core.ix.versions.get(&(*tid, ak.clone(), *o, va)).is_some_and(|s| s.contains(&(ts, *v))) => Some((ots, *o, original(tx, o, tid, ak)?)),
        _ => None,
    };
    place(tx, tid, ak, ts, v, fold);
    if tx.core.ix.commits.contains_key(o) {
        tx.core.commits_named(*tid, ak.clone(), *o);
    }
    Ok(())
}

/// At the end of a transaction: `originals` from the commits it changed (`Core::commit_changes`'s
/// journal), each claim's and each named original's fold judged again from what stands now; a
/// purge tombstone's end armed. O(changed commits), and the claims of the originals among them.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<()> {
    if tx.txn.is_memory() {
        return Ok(());
    }
    let mut whole: BTreeSet<(Tid, Ak, CommitId)> = std::mem::take(&mut tx.core.refold);
    let mut claims: BTreeSet<(Tid, Ak, CommitId, CommitId, Ts)> = BTreeSet::new();
    let changed: Vec<(CommitId, std::sync::Arc<View>, bool, bool)> = tx.core.ix.commits.before().iter().filter_map(|(id, old)| {
        let new = tx.core.ix.commits.get(*id);
        Some((**id, new.or(*old)?.view.clone(), old.is_none(), new.is_none()))
    }).collect();
    for (id, view, added, gone) in changed {
        for (_, a) in signal_parts(&view) {
            let k = (a.tid, a.ak.clone());
            if gone {
                tx.core.ix.originals.remove(&k, &(view.ts, id));
                continue;
            }
            if added {
                tx.core.ix.originals.insert(k, (view.ts, id));
            }
            whole.insert((a.tid, a.ak.clone(), id));
            if let Some(o) = a.replaces {
                claims.insert((a.tid, a.ak.clone(), o, id, view.ts));
            }
        }
    }
    for (tid, ak, c) in &whole {
        refold(tx, tid, ak, c)?;
        let Some((ai, named)) = tx.core.ix.commits.get(c).and_then(|m| Some((m.aspect(tid, ak)?, m.view.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak)?.replaces))) else { continue };
        // a claim's change (a bound passed: from the timer) changes its original's reading
        if let Some(o) = named.filter(|o| tx.core.ix.commits.contains_key(o)) {
            tx.core.commits_named(*tid, ak.clone(), o);
        }
        // a listed tombstone ends by time alone
        if let Some((_, Here::Purged(by))) = listed(tx, c, ai)? {
            let t = purged_keep(tx, c, ai, &by);
            if tx.now().0 < t && t < osis_commit::FOREVER {
                tx.put_timer(t, c, ai, crate::retention::T_KEPT)?;
            }
        }
    }
    for (tid, ak, o, v, ts) in &claims {
        reclaim(tx, tid, ak, o, v, *ts)?;
    }
    Ok(())
}

/// `originals` from nothing (a rebuild of the index from the commit records).
pub(crate) fn rebuild(tx: &mut Tx<'_>) -> Result<()> {
    let all: Vec<(Tid, Ak, CommitId, Ts, Option<CommitId>)> = tx.core.ix.commits.iter().flat_map(|(c, m)| signal_parts(&m.view).map(move |(_, a)| (a.tid, a.ak.clone(), *c, m.view.ts, a.replaces))).collect();
    for (t, ak, c, ts, _) in &all {
        tx.core.ix.originals.insert((*t, ak.clone()), (*ts, *c));
    }
    let named: BTreeSet<(Tid, Ak, CommitId)> = all.into_iter().filter_map(|(t, ak, _, _, o)| Some((t, ak, o?))).collect();
    for (t, ak, o) in &named {
        refold(tx, t, ak, o)?;
    }
    Ok(())
}

/// What original `c` part `ai` reads as: its newest listed honored version with its body here, as
/// `(commit, aspect index, place, what is here)`; `None`: no version, or `c` not one (invalid).
pub(super) fn newest_version(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, valid: bool) -> Result<Option<(CommitId, usize, CommitPos, Here)>> {
    if !valid || !durable_signal(ak) {
        return Ok(None);
    }
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let (place, actor, own) = ((m.view.ts, *c), m.view.actor, m.view.aspects.get(ai).and_then(|a| a.replaces));
    if own.is_some() {
        return Ok(None);
    }
    let key = (*tid, ak.clone(), *c, actor);
    let mut below = None;
    loop {
        let Some(set) = tx.core.ix.versions.get(&key) else { return Ok(None) };
        let upper = below.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let Some((ts, v)) = set.range((std::ops::Bound::Excluded(place), upper)).next_back().copied() else { return Ok(None) };
        below = Some((ts, v));
        drop(crate::costs::span("listing: version judged"));
        let Some(vai) = tx.core.ix.commits.get(&v).and_then(|m| m.aspect(tid, ak)) else { continue };
        match listed(tx, &v, vai)? {
            Some((true, Here::NotFetched)) | None => continue,
            Some((true, h)) => return Ok(Some((v, vai, CommitPos { ts, id: v }, h))),
            Some((false, _)) => continue,
        }
    }
}
