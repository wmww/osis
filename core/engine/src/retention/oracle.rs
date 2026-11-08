//! The readers of held parts before they streamed (issues/durable-decode-bound.md step 4), each
//! part decoded whole, kept as the oracle of the streamed ones: in this crate's tests every
//! `covered` and `body_live` is checked against them, and `bounds::deaths` (the part joined
//! into the state's pages at its positions) against the part joined into the whole state
//! (`tests_paged` runs random paged histories through them).

use crate::engine::Tx;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{Decoded, Header};
use osis_crdt::Changes;
use std::collections::BTreeSet;

pub(crate) fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let (Some(sai), Some(cai)) = (super::aspect_index(tx.core, s, tid, ak), super::aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    if !crate::apply::copies::snapshot_valid(tx.core, s, tid, ak) || super::snapshot::cannot_keep(tx, s, sai, c, cai, tid, ak)? {
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
    let Some(mut body) = held else {
        return Ok(Some(m.header.aspects.get(cai).is_none_or(|_| m.header.expires.is_none() || super::valueless(tx.core, c, cai))));
    };
    let is_snapshot = m.header.kind.is_compaction();
    if is_snapshot && !crate::apply::copies::snapshot_valid(tx.core, c, tid, ak) {
        let core = &*tx.core;
        body.remove_writes(&|d| crate::apply::copies::any_delta(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && m.valid_at(ai)));
    }
    let before = crate::engine::state::encode(&snap)?;
    let mut j = snap.clone();
    j.join(body);
    Ok(Some(crate::engine::state::encode(&j)? == before))
}

pub(crate) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let holders = super::body_class(tx.core, &h, ai);
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
    for x in holders {
        let Some(a) = h.aspects.get(*x) else { continue };
        let part = crate::apply::held_fragment(tx, c, *x)?;
        let Some(st) = tx.state(&a.tid, &a.ak)? else { continue };
        let writes = st.live_writes();
        let Some(f) = part else {
            if writes.iter().any(|(_, t)| t.is_none_or(|t| t <= h.ts)) {
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

/// What `bounds::deaths` gives, sorted: the held part whole joined into the whole state.
pub(crate) fn deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<Vec<(osis_crdt::Stamp, osis_base::Ts, osis_crdt::Dot, bool)>> {
    let (Some(f), Some(mut st)) = (crate::apply::held_fragment(tx, c, ai)?, tx.state(tid, ak)?.cloned()) else { return Ok(Vec::new()) };
    let held = f.stamps();
    let mut ch = Changes::new();
    st.join_into(f, None, &mut ch);
    let mut out: Vec<_> = ch.into_deaths().into_iter().filter(|d| super::bounds::dies_in(&held, d)).map(|d| (d.stamp, d.at, d.by, d.element)).collect();
    out.sort();
    Ok(out)
}
