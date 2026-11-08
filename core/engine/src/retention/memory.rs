//! Memory-class retention: superseded memory commits vanish whole (spec/sync.md §9 Superseded
//! commits), as do a thing's memory parts at its delete here; an expired one is held as its
//! leftover like a durable one (spec/crdt.md §4.7) and drops once covered (`drop_covered`). A
//! memory commit no part of which is held any more is forgotten, header included
//! (`apply::unindex_commit`; issues/session-sources.md rule 8, memory half). Invariant: a memory
//! aspect's state is the join of the valid parts held of it, so two nodes holding the same
//! memory commits read alike whatever was superseded when.

use crate::engine::Tx;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::EphClass;
use osis_crdt::Fragment;
use std::collections::BTreeSet;

/// Delta `ai` of memory commit `c` vanishes whole: its body drops and the aspect is rebuilt
/// without its writes (resets and removals included), as at a node that never held it. The
/// aspect, when anything went.
pub(crate) fn vanish(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<(Tid, Ak)>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
    if m.dropped.contains_key(&ai) {
        return Ok(None);
    }
    let (tid, ak) = (a.tid, a.ak.clone());
    super::drop_part(tx, c, ai)?;
    crate::apply::rebuild(tx, &tid, &ak)?;
    Ok(Some((tid, ak)))
}

/// Forgets memory commit `c` once no part of it is held (each dropped or never received) and
/// none waits: as if it had never applied (`unindex_commit`), its receipt kept. A copy arriving
/// again applies again and goes again by the same rule.
pub(crate) fn forget_if_spent(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(()) };
    if !m.view.memory || m.dropped.is_empty() || (0..m.view.aspects.len()).any(|ai| m.holds(ai)) || tx.core.ix.pending.contains_key(c) {
        return Ok(());
    }
    crate::apply::unindex_commit(tx, c)
}

/// A delete's ephemeral side (spec/commits.md §2, notes/ephemeral.md Deletion): every held part
/// on an ephemeral aspect of `things` vanishes here (`vanish`) and the commits spent by it are
/// forgotten; nothing is written, so other holders keep their copies. The aspects changed.
pub(crate) fn drop_things(tx: &mut Tx<'_>, things: &BTreeSet<Tid>) -> Result<Vec<(Tid, Ak)>> {
    tx.in_class(true, |tx| {
        let mut changed = BTreeSet::new();
        let mut spent = BTreeSet::new();
        for t in things {
            let held: Vec<(Ak, CommitId)> = tx.core.aspects_of(t).filter(|((_, ak), _)| ak.ephemeral()).flat_map(|((_, ak), cs)| cs.iter().map(move |(_, c)| (ak.clone(), *c))).collect();
            for (ak, c) in held {
                let Some(ai) = tx.core.ix.commits.get(&c).filter(|m| m.view.memory).and_then(|m| m.aspect(t, &ak)) else { continue };
                changed.extend(vanish(tx, &c, ai)?);
                spent.insert(c);
            }
        }
        for c in &spent {
            forget_if_spent(tx, c)?;
        }
        Ok(changed.into_iter().collect())
    })
}

/// spec/sync.md §9 (Superseded expiring writes): on `aspects`, the held plain memory commits
/// each of whose held parts a valid held part of another commit of their author supersedes
/// (`supersedes`) vanish whole. Run when parts of a memory aspect turn valid (each commit judged
/// against every other: a cost per flip quadratic in the commits held on the aspect). The aspects
/// changed.
pub(crate) fn drop_superseded(tx: &mut Tx<'_>, aspects: &BTreeSet<(Tid, Ak)>) -> Result<BTreeSet<(Tid, Ak)>> {
    let mut cands: BTreeSet<CommitId> = BTreeSet::new();
    for k in aspects {
        for (_, c) in tx.core.ix.by_aspect.get(k).into_iter().flatten() {
            if tx.core.ix.commits.get(c).is_some_and(plain_memory) {
                cands.insert(*c);
            }
        }
    }
    drop_superseded_of(tx, cands, None)
}

/// `drop_superseded` on memory commit `id` applied: `id` itself, and the held commits of its
/// author a part of `id` supersedes, are judged. A function of the commits held, so convergent:
/// before `id` came no held commit was superseded, so only one `id` supersedes a part of can be
/// now. Cost: `id`'s parts decoded once, and on each of its aspects the author's held expiring
/// commits expiring no later decoded once (none unless `id` expires, carries no reset and is
/// no sequence or bag). Those vanished are forgotten (`forget_if_spent`), but `id` (its caller
/// forgets it once done). The aspects changed.
pub(crate) fn drop_superseded_by(tx: &mut Tx<'_>, id: &CommitId) -> Result<BTreeSet<(Tid, Ak)>> {
    let Some(m) = tx.core.ix.commits.get(id).filter(|m| plain_memory(m)).cloned() else { return Ok(BTreeSet::new()) };
    let mut cands: BTreeSet<CommitId> = [*id].into();
    if let Some(q_exp) = m.header.expires {
        for (ai, a) in m.header.aspects.iter().enumerate() {
            if !m.holds(ai) || !m.valid_at(ai) {
                continue;
            }
            let q = joined(tx, id, ai)?;
            if !may_supersede(&q) {
                continue;
            }
            let others: Vec<(CommitId, usize, Option<u64>)> = tx
                .core
                .ix
                .by_aspect
                .get(&(a.tid, a.ak.clone()))
                .into_iter()
                .flatten()
                .filter_map(|(_, x)| {
                    let xm = tx.core.ix.commits.get(x).filter(|xm| *x != *id && plain_memory(xm) && xm.view.author == m.view.author && xm.header.expires.is_some_and(|t| t <= q_exp))?;
                    let xai = xm.aspect(&a.tid, &a.ak).filter(|xai| xm.holds(*xai))?;
                    Some((*x, xai, xm.header.expires))
                })
                .collect();
            for (x, xai, x_exp) in others {
                if !cands.contains(&x) && supersedes(&q, Some(q_exp), &joined(tx, &x, xai)?, x_exp) {
                    cands.insert(x);
                }
            }
        }
    }
    drop_superseded_of(tx, cands, Some(id))
}

/// Of `cands`, those superseded (`superseded`) vanish whole and are forgotten, but `keep`. The
/// aspects changed.
fn drop_superseded_of(tx: &mut Tx<'_>, cands: BTreeSet<CommitId>, keep: Option<&CommitId>) -> Result<BTreeSet<(Tid, Ak)>> {
    let mut changed = BTreeSet::new();
    for c in cands {
        let Some(by) = superseded(tx, &c)? else { continue };
        let n = tx.core.ix.commits.get(&c).map_or(0, |m| m.view.aspects.len());
        for ai in 0..n {
            if tx.core.ix.commits.get(&c).is_some_and(|m| m.holds(ai)) {
                changed.extend(vanish(tx, &c, ai)?);
            }
        }
        // the lane deletes its entries once a superseder is held there (its author only)
        tx.core.memory.reasons.insert(c, crate::engine::MemoryDrop::Superseded { by });
        if keep != Some(&c) {
            forget_if_spent(tx, &c)?;
        }
    }
    Ok(changed)
}

/// spec/sync.md §9 (Compaction, memory class): on `aspects`, each held memory body a valid held
/// memory snapshot covers (`covered`, spec/commits.md §5) is dropped as covered at once, its keep
/// bounds aside (memory class keeps none), and its commit forgotten once spent (`keep` aside: the
/// commit being applied, its caller forgets it). Of covered-equal snapshots (equal `ts`) the higher commit ID
/// goes, as on the durable path. A function of the commits held, so holders of the same ones
/// keep the same bodies. Run when parts of a memory aspect turn valid, and for `new` alone when it
/// applies or goes value-less (a body judged against the held snapshots; a snapshot, every held
/// body against it and it against the others): whether one body is covered by one snapshot
/// depends on those two alone. The commits dropped from.
///
/// An author keeps its own bodies until one of its own snapshots covers them
/// (issues/eph-unify.md decision 1): a demotion's frontier lists no memory commit
/// (spec/permissions.md §5.2), so a compactor's demotion invalidates every snapshot it made and
/// what those covered is gone at every holder; each author then still holds its own writes and
/// uploads them again where the lane reconciles (`MemorySync::invalidated`).
pub(crate) fn drop_covered(tx: &mut Tx<'_>, aspects: &BTreeSet<(Tid, Ak)>, keep: Option<&CommitId>, new: Option<&CommitId>) -> Result<BTreeSet<CommitId>> {
    let mut dropped = BTreeSet::new();
    let me = tx.core.id.tid();
    let held_on = |tx: &Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak| -> Option<(usize, bool, Tid)> {
        let m = tx.core.ix.commits.get(c).filter(|m| m.view.memory)?;
        let ai = m.aspect(tid, ak).filter(|ai| m.holds(*ai))?;
        Some((ai, m.view.kind.is_compaction(), m.view.author))
    };
    for (tid, ak) in aspects {
        let snaps: Vec<(CommitId, Tid)> = tx
            .core
            .ix
            .snapshots
            .get(&(*tid, ak.clone()))
            .into_iter()
            .flatten()
            .filter_map(|x| {
                let (_, snap, author) = held_on(tx, &x.1, tid, ak)?;
                (snap && crate::apply::copies::snapshot_valid(tx.core, &x.1, tid, ak)).then_some((x.1, author))
            })
            .collect();
        if snaps.is_empty() {
            continue;
        }
        // a new body: judged alone against the snapshots; a new snapshot: every body against
        // it, it against the rest; else every body against every snapshot
        let new_snap = new.filter(|n| snaps.iter().any(|x| x.0 == **n));
        let bodies: Vec<CommitId> = match new {
            Some(n) if new_snap.is_none() => vec![*n],
            _ => tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect(),
        };
        let holds = |tx: &Tx<'_>, c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.holds(ai)));
        // a new snapshot judged against every body: its part read once
        if let Some(n) = new_snap
            && let Some((sai, _, _)) = held_on(tx, n, tid, ak)
        {
            let mut pieces = Vec::new();
            let gives = crate::apply::each_held_piece(tx, n, sai, &mut |_, p| {
                pieces.push(p);
                Ok(())
            })?;
            tx.core.cover_cache = Some((*n, sai, pieces, gives));
        }
        // the aspect rebuilt once for all the drops (a covered body's writes are in its coverer:
        // the state a drop reads is unchanged by the others)
        let r = crate::apply::run_batched(tx, |tx| {
            for c in bodies {
                let Some((ai, is_snapshot, author)) = held_on(tx, &c, tid, ak) else { continue };
                for (s, snap_author) in &snaps {
                    if new_snap.is_some_and(|n| *n != c && *n != *s) {
                        continue;
                    }
                    if *s == c || !holds(tx, s) || !holds(tx, &c) || (author == me && *snap_author != me) {
                        continue;
                    }
                    if super::covered(tx, s, &c, tid, ak)? != Some(true) {
                        continue;
                    }
                    // kept history stays to its keep bound (spec/commits.md §5)
                    if super::bounds::body_keep(tx, &c, tid, ak)? > tx.now().0 {
                        break;
                    }
                    if is_snapshot && c < *s && super::covered(tx, &c, s, tid, ak)? == Some(true) {
                        continue;
                    }
                    // a bare leftover not past its expiry (purged) stays (`drop_part_for`)
                    super::drop_part_for(tx, &c, ai, super::DropFor::Cover)?;
                    if !holds(tx, &c) {
                        dropped.insert(c);
                    }
                    break;
                }
            }
            Ok(())
        });
        tx.core.cover_cache = None;
        r?;
    }
    for c in &dropped {
        if keep != Some(c) {
            forget_if_spent(tx, c)?;
        }
    }
    Ok(dropped)
}

/// After a part of memory commit `c` went value-less at its expiry: `c` alone is judged again
/// (spec/sync.md §9: its leftover may be superseded whole now). Not forgotten here: its caller
/// does.
pub(crate) fn superseded_rest(tx: &mut Tx<'_>, c: &CommitId) -> Result<BTreeSet<(Tid, Ak)>> {
    if !tx.core.ix.commits.get(c).is_some_and(plain_memory) {
        return Ok(BTreeSet::new());
    }
    drop_superseded_of(tx, [*c].into(), Some(c))
}

/// A held plain memory commit (what the superseded rule judges).
fn plain_memory(m: &crate::engine::Meta) -> bool {
    m.view.memory && m.header.ephemeral == Some(EphClass::Plain)
}

/// Whether every held part of memory commit `c` (one at least, core aspects alike) expires, keeps
/// no history (a keep bound only limits drops, spec/commits.md §5) and is superseded by a valid
/// held part of another plain memory commit of its author on the aspect: those superseders.
fn superseded(tx: &mut Tx<'_>, c: &CommitId) -> Result<Option<BTreeSet<CommitId>>> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let held: Vec<usize> = (0..m.header.aspects.len()).filter(|ai| m.holds(*ai)).collect();
    let Some(p_exp) = m.header.expires else { return Ok(None) };
    if held.is_empty() || held.iter().any(|ai| m.header.aspects.get(*ai).is_some_and(|a| a.retention.history.is_some())) {
        return Ok(None);
    }
    let mut by = BTreeSet::new();
    for ai in held {
        let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
        let p = joined(tx, c, ai)?;
        if p.has_any_reset() {
            return Ok(None);
        }
        // newest first, one at a time: a later write of the author is the likely superseder
        let k = (a.tid, a.ak.clone());
        let mut next: Option<(osis_base::Ts, CommitId)> = None;
        let mut any = None;
        loop {
            let step = {
                let Some(set) = tx.core.ix.by_aspect.get(&k) else { break };
                match &next {
                    None => set.iter().next_back().copied(),
                    Some(x) => set.range(..*x).next_back().copied(),
                }
            };
            let Some(x) = step else { break };
            next = Some(x);
            let x = x.1;
            let Some((xai, x_exp)) = tx.core.ix.commits.get(&x).filter(|xm| x != *c && plain_memory(xm) && xm.view.author == m.view.author && xm.header.expires.is_some_and(|t| t >= p_exp)).and_then(|xm| {
                let xai = xm.aspect(&a.tid, &a.ak).filter(|xai| xm.holds(*xai) && xm.valid_at(*xai))?;
                Some((xai, xm.header.expires))
            }) else {
                continue;
            };
            if supersedes(&joined(tx, &x, xai)?, x_exp, &p, Some(p_exp)) {
                any = Some(x);
                break;
            }
        }
        let Some(x) = any else { return Ok(None) };
        by.insert(x);
    }
    Ok(Some(by))
}

/// Held part `ai` of `c` as one fragment.
fn joined(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Fragment> {
    let mut f = Fragment::default();
    if let Some(x) = crate::apply::held_fragment(tx, c, ai)? {
        f.join(x);
    }
    Ok(f)
}

/// What `supersedes` asks of `q` alone: no sequence or bag (every element shows in the read, none
/// shadows another's) and no reset.
fn may_supersede(q: &Fragment) -> bool {
    !matches!(q, Fragment::Seq(_) | Fragment::Bag(_)) && !q.has_any_reset()
}

/// Whether writes `q` of an author supersede its earlier writes `p` on one aspect (spec/sync.md
/// §9): `p` expires (`p_exp`), `q` too and no earlier (`q_exp`), neither carries a reset, every write of `q` is
/// later than every write of `p` and none is into a record it did not create (it would be
/// hidden with `p`'s), and `p` joined into `q` reads as `q` alone (a cursor's newer entry at
/// its key, a register's newer write). While `q` is held nothing reads `p`, and `p` goes first.
pub(crate) fn supersedes(q: &Fragment, q_exp: Option<u64>, p: &Fragment, p_exp: Option<u64>) -> bool {
    let Some(tp) = p_exp else { return false };
    // a superseder expires, no earlier than `p`: a plain one could be absorbed
    // by a cover that does not supersede `p`, and a node getting only the cover would hold `p`;
    // a reset in either part would make the relation intransitive or drop a tombstone, and the
    // drop order-dependent
    if q_exp.is_none_or(|t| t < tp) || !may_supersede(q) || p.has_any_reset() {
        return false;
    }
    let Some(newest_p) = p.writes().into_iter().filter_map(|(_, ts)| ts).max() else { return false };
    let qw = q.writes();
    if qw.is_empty() || !qw.iter().all(|(_, ts)| ts.is_some_and(|t| t > newest_p)) {
        return false;
    }
    let mut j = q.clone();
    j.join(p.clone());
    j.read() == q.read()
}

