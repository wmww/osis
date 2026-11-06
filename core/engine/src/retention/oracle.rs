//! The readers of held parts before they streamed (issues/durable-decode-bound.md step 4), each
//! part decoded whole, kept as the oracle of the streamed ones: in this crate's tests every
//! `covered`, `body_live` and `note_copies` is checked against them
//! (`tests_paged` runs random paged histories through them).

use crate::engine::Tx;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{Decoded, Header};
use osis_crdt::{Changes, Fragment};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let (Some(sai), Some(cai)) = (super::aspect_index(tx.core, s, tid, ak), super::aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    if !crate::apply::copies::snapshot_valid(tx.core, s, tid, ak) || super::snapshot::carrier_at(tx.core, s, sai) {
        return Ok(Some(false));
    }
    if super::snapshot::stamped_later(tx.core, c, s) {
        return Ok(Some(false));
    }
    if tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction() && m.missing.contains(&cai)) {
        return Ok(None);
    }
    let part = crate::apply::held_part(tx, s, sai)?;
    let held = crate::apply::held_fragment(tx, c, cai)?;
    if let (Some(m), Some(Decoded::Snapshot(sn))) = (tx.core.ix.commits.get(c), &part) {
        let h = &m.header;
        if held.is_none() && h.aspects.get(cai).is_some_and(|a| super::snapshot::unseen_by(&sn.frontiers, h, c, a.hi)) {
            return Ok(Some(false));
        }
        let untraced = match (h.form.counted() && h.kind.has_own_writes(), super::snapshot::by_id(h.kind, h.form)) {
            (true, _) => !sn.frontiers.lists(&h.form.own_source(h.author, *c)),
            (_, true) => !sn.absorbed.contains_key(c),
            _ => false,
        };
        if untraced && m.missing.contains(&cai) {
            return Ok(None);
        }
    }
    let Some(snap) = part.map(Decoded::into_fragment) else { return Ok(None) };
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    if m.header.aspects.get(cai).is_some_and(|_| m.header.expires.is_some()) {
        return Ok(Some(false));
    }
    let Some(mut body) = held else { return Ok(Some(true)) };
    let is_snapshot = m.header.kind.is_compaction();
    if is_snapshot && !crate::apply::copies::snapshot_valid(tx.core, c, tid, ak) {
        let core = &*tx.core;
        body.strip_copies(&|d| crate::apply::copies::any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && m.valid_at(ai)));
    }
    let before = crate::engine::state::encode(&snap)?;
    let mut j = snap.clone();
    j.join(body.clone());
    if crate::engine::state::encode(&j)? != before {
        return Ok(Some(false));
    }
    let mut ranges: Vec<(osis_crdt::Source, u64, u64)> = if is_snapshot {
        body.writes().into_iter().filter(|w| w.1.is_some()).map(|(d, _)| (d.src.clone(), d.ctr, d.ctr.saturating_add(1))).collect()
    } else {
        crate::apply::copies::owned_ranges(&m.header, c, cai)
    };
    ranges.sort();
    ranges.dedup();
    let ix = snap.copy_index();
    Ok(Some(ix.outside(&ranges, &osis_crdt::CopySet::of(&[&body])).is_empty()))
}

pub(crate) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let (_, holders) = super::body_class(tx.core, &h, c, ai);
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, &holders);
    }
    for x in holders {
        let Some(a) = h.aspects.get(x) else { continue };
        let own = super::writes_of(&h, c, x);
        if tx.state(&a.tid, &a.ak)?.is_some_and(|st| st.holds_owned_write(&|src, lo, hi| own.iter().any(|o| o.owns_range(src, lo, hi)))) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<bool> {
    let dropped: BTreeMap<usize, bool> = tx.core.ix.commits.get(c).map(|m| m.dropped.iter().map(|(ai, d)| (*ai, d.live)).collect()).unwrap_or_default();
    for x in holders {
        let Some(a) = h.aspects.get(*x) else { continue };
        let part = crate::apply::held_fragment(tx, c, *x)?;
        if part.is_none() && dropped.get(x) == Some(&false) {
            continue;
        }
        let Some(st) = tx.state(&a.tid, &a.ak)? else { continue };
        let writes = st.live_writes();
        let Some(f) = part else {
            let tsless = dropped.contains_key(x);
            if writes.iter().any(|(_, t)| t.map_or(tsless, |t| t <= h.ts)) {
                return Ok(true);
            }
            continue;
        };
        let live: BTreeSet<osis_crdt::Dot> = writes.into_iter().map(|(d, _)| d).collect();
        if f.live_writes().into_iter().any(|(d, _)| live.contains(&d)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The dates `deaths::body_deaths` gives: the part whole against the whole state.
pub(crate) fn body_deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, ts: Ts) -> Result<BTreeSet<Ts>> {
    let mut out = BTreeSet::new();
    let (Some(f), Some(mut st)) = (crate::apply::held_fragment(tx, c, ai)?, tx.state(tid, ak)?.cloned()) else { return Ok(out) };
    let mut ch = Changes::new();
    st.join_into(f.clone(), None, &mut ch);
    let invalid = crate::apply::invalid_of(tx.core, tid, ak);
    for d in ch.into_deaths().into_iter().filter(|d| super::deaths::dies_in(&f, d)) {
        let mut at = d.at;
        if invalid.iter().any(|o| o.owns(d.by.owner())) {
            let k = super::deaths::killer(&d);
            let mut snaps: Vec<(Ts, CommitId)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| !crate::apply::copies::invalid_snapshot(tx.core, &x.1, tid, ak)).map(|x| (x.0, x.1)).collect();
            snaps.sort();
            for (sts, s) in snaps {
                if sts > at && let Some(sai) = super::held_part(tx.core, &s, tid, ak) && crate::apply::held_fragment(tx, &s, sai)?.is_some_and(|g| g.holds_stamp(&k)) {
                    at = sts;
                    break;
                }
            }
        }
        out.insert(at.max(ts));
    }
    Ok(out)
}
