//! Memory-class retention (issues/eph-unify.md step A): an expired or superseded memory delta
//! vanishes whole (spec/crdt.md §4.7 Ephemeral data, spec/sync.md §9 Superseded expiring
//! writes), never value-less as durable data goes; a memory commit no part of which is held any
//! more is forgotten, header included (`apply::unindex_commit`; issues/session-sources.md rule
//! 8, memory half). Invariant: a memory aspect's state is the join of the valid parts held of
//! it, so two nodes holding the same memory commits read alike whatever expired or was
//! superseded when.

use crate::engine::{Owned, Tx};
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
    let gone: Vec<Owned> = Owned::of(&m.header, c, ai).into_iter().collect();
    super::drop_part(tx, c, ai)?;
    crate::apply::rebuild_without(tx, &tid, &ak, &gone)?;
    super::mark_deaths_due(tx, &tid, &ak)?;
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

/// spec/sync.md §9 (Superseded expiring writes): on `aspects`, the held memory commits (of
/// `author` only, when given) each of whose held parts a valid held part of another commit of
/// their author supersedes (`supersedes`) vanish whole. A function of the commits held, so
/// convergent: run when a memory commit applies (on its aspects, for its author) and when parts
/// of a memory aspect turn valid. Those vanished are forgotten (`forget_if_spent`), but `keep`
/// (the commit being applied: its caller forgets it once done). The aspects changed.
pub(crate) fn drop_superseded(tx: &mut Tx<'_>, aspects: &BTreeSet<(Tid, Ak)>, author: Option<Tid>, keep: Option<&CommitId>) -> Result<BTreeSet<(Tid, Ak)>> {
    let mut changed = BTreeSet::new();
    let mut cands: BTreeSet<CommitId> = BTreeSet::new();
    for k in aspects {
        for (_, c) in tx.core.ix.by_aspect.get(k).into_iter().flatten() {
            if tx.core.ix.commits.get(c).is_some_and(|m| plain_memory(m) && author.is_none_or(|a| m.view.author == a)) {
                cands.insert(*c);
            }
        }
    }
    for c in cands {
        if !superseded(tx, &c)? {
            continue;
        }
        let n = tx.core.ix.commits.get(&c).map_or(0, |m| m.view.aspects.len());
        for ai in 0..n {
            if tx.core.ix.commits.get(&c).is_some_and(|m| m.holds(ai)) {
                changed.extend(vanish(tx, &c, ai)?);
            }
        }
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
/// keep the same bodies. Run when a memory commit applies and when parts of a memory aspect turn
/// valid. The commits dropped from.
pub(crate) fn drop_covered(tx: &mut Tx<'_>, aspects: &BTreeSet<(Tid, Ak)>, keep: Option<&CommitId>) -> Result<BTreeSet<CommitId>> {
    let mut dropped = BTreeSet::new();
    for (tid, ak) in aspects {
        let held: Vec<(CommitId, usize, bool)> = tx
            .core
            .ix
            .by_aspect
            .get(&(*tid, ak.clone()))
            .into_iter()
            .flatten()
            .filter_map(|(_, c)| {
                let m = tx.core.ix.commits.get(c).filter(|m| m.view.memory)?;
                let ai = m.aspect(tid, ak).filter(|ai| m.holds(*ai))?;
                Some((*c, ai, m.view.kind.is_compaction()))
            })
            .collect();
        let snaps: Vec<CommitId> = held.iter().filter(|x| x.2 && crate::apply::copies::snapshot_valid(tx.core, &x.0, tid, ak)).map(|x| x.0).collect();
        if snaps.is_empty() {
            continue;
        }
        let holds = |tx: &Tx<'_>, c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.holds(ai)));
        for (c, ai, is_snapshot) in held {
            for s in &snaps {
                if *s == c || !holds(tx, s) || !holds(tx, &c) {
                    continue;
                }
                if super::covered(tx, s, &c, tid, ak)? != Some(true) {
                    continue;
                }
                if is_snapshot && c < *s && super::covered(tx, &c, s, tid, ak)? == Some(true) {
                    continue;
                }
                super::drop_part_for(tx, &c, ai, super::DropFor::Cover)?;
                dropped.insert(c);
                break;
            }
        }
    }
    for c in &dropped {
        if keep != Some(c) {
            forget_if_spent(tx, c)?;
        }
    }
    Ok(dropped)
}

/// After a part of memory commit `c` vanished at its expiry: `c` vanishes whole when every part
/// it still holds is superseded (`drop_superseded` on its aspects; else a node that held it when
/// its superseders came keeps the rest, while one receiving it after the expiry drops it on
/// arrival). Not forgotten here: its caller does.
pub(crate) fn superseded_rest(tx: &mut Tx<'_>, c: &CommitId) -> Result<BTreeSet<(Tid, Ak)>> {
    let Some(m) = tx.core.ix.commits.get(c).filter(|m| plain_memory(m)) else { return Ok(BTreeSet::new()) };
    let author = m.view.author;
    let aspects = m.header.aspects.iter().enumerate().filter(|(ai, _)| m.holds(*ai)).map(|(_, a)| (a.tid, a.ak.clone())).collect();
    drop_superseded(tx, &aspects, Some(author), Some(c))
}

/// A held plain memory commit (what the superseded rule judges).
fn plain_memory(m: &crate::engine::Meta) -> bool {
    m.view.memory && m.header.ephemeral == Some(EphClass::Plain)
}

/// Whether every held part of memory commit `c` (one at least, core aspects alike) expires and
/// is superseded by a valid held part of another plain memory commit of its author on the aspect.
fn superseded(tx: &mut Tx<'_>, c: &CommitId) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(false) };
    let held: Vec<usize> = (0..m.header.aspects.len()).filter(|ai| m.holds(*ai)).collect();
    if held.is_empty() {
        return Ok(false);
    }
    for ai in held {
        let Some(a) = m.header.aspects.get(ai) else { return Ok(false) };
        if a.expires.is_none() {
            return Ok(false);
        }
        let others: Vec<(CommitId, usize, Option<u64>)> = tx
            .core
            .ix
            .by_aspect
            .get(&(a.tid, a.ak.clone()))
            .into_iter()
            .flatten()
            .filter_map(|(_, x)| {
                let xm = tx.core.ix.commits.get(x).filter(|xm| *x != *c && plain_memory(xm) && xm.view.author == m.view.author)?;
                let xai = xm.aspect(&a.tid, &a.ak).filter(|xai| xm.holds(*xai) && xm.valid_at(*xai))?;
                Some((*x, xai, xm.header.aspects.get(xai)?.expires))
            })
            .collect();
        if others.is_empty() {
            return Ok(false);
        }
        let p = joined(tx, c, ai)?;
        let mut any = false;
        for (x, xai, x_exp) in others {
            if supersedes(&joined(tx, &x, xai)?, x_exp, &p, a.expires) {
                any = true;
                break;
            }
        }
        if !any {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Held part `ai` of `c` as one fragment.
fn joined(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Fragment> {
    let mut f = Fragment::default();
    for x in crate::apply::held_fragments(tx, c, ai)? {
        f.join(x);
    }
    Ok(f)
}

/// Whether writes `q` of an author supersede its earlier writes `p` on one aspect (spec/sync.md
/// §9): `p` expires (`p_exp`), `q` too and no earlier (`q_exp`), neither carries a reset, every write of `q` is
/// later than every write of `p` and none is into a record it did not create (it would be
/// hidden with `p`'s), and `p` joined into `q` reads as `q` alone (a cursor's newer entry at
/// its key, a register's newer write). While `q` is held nothing reads `p`, and `p` goes first.
pub(crate) fn supersedes(q: &Fragment, q_exp: Option<u64>, p: &Fragment, p_exp: Option<u64>) -> bool {
    let Some(tp) = p_exp else { return false };
    // a sequence's or bag's elements all show in the read: none shadows another's (cheap out
    // for appended events)
    // a superseder expires, no earlier than `p`: a plain one could be absorbed
    // by a cover that does not supersede `p`, and a node getting only the cover would hold `p`;
    // a reset in either part would make the relation intransitive or drop a tombstone, and the
    // drop order-dependent
    if q_exp.is_none_or(|t| t < tp) || matches!(q, Fragment::Seq(_) | Fragment::Bag(_)) || q.has_any_reset() || p.has_any_reset() {
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

