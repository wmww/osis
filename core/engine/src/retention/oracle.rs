//! The readers of held parts before they streamed (issues/durable-decode-bound.md step 4), each
//! part decoded whole, kept as the oracle of the streamed ones: in this crate's tests every
//! `covered`, `body_live`, `note_copies`, `Parts::kills` and `make_valueless`'s residue is
//! checked against them (`tests_paged` runs random paged histories through them).

use crate::engine::{Owned, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{Decoded, Header};
use osis_crdt::{Changes, Fragment, Stamp};
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
    let parts = crate::apply::held_parts(tx, s, sai)?;
    if let (Some(m), [Decoded::Snapshot(sn)]) = (tx.core.ix.commits.get(c), parts.as_slice()) {
        let h = &m.header;
        if h.aspects.get(cai).is_some_and(|a| super::snapshot::unseen_by(&sn.frontiers, h, c, a.hi)) {
            return Ok(Some(false));
        }
        let untraced = match (h.form.counted() && h.kind.has_own_writes(), super::snapshot::by_id(h.kind, h.form)) {
            (true, _) => !sn.frontiers.lists(&h.form.own_source(h.author, *c)),
            (_, true) => !sn.absorbed.contains_key(c),
            _ => h.kind == osis_commit::Kind::Import,
        };
        if untraced && m.missing.contains(&cai) {
            return Ok(None);
        }
    }
    let held = crate::apply::held_parts(tx, c, cai)?;
    if let ([Decoded::Snapshot(sn)], [Decoded::Snapshot(other)]) = (parts.as_slice(), held.as_slice())
        && other.frontiers.sources().any(|(s, f)| sn.frontiers.lists(&s) && sn.frontiers.of(&s) < f)
    {
        return Ok(Some(false));
    }
    let snap: Vec<Fragment> = parts.into_iter().map(Decoded::into_fragment).collect();
    let [snap] = snap.as_slice() else { return Ok(None) };
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    if m.header.aspects.get(cai).is_some_and(|a| a.expires.is_some()) {
        return Ok(Some(false));
    }
    if held.is_empty() {
        return Ok(Some(true));
    }
    let is_snapshot = m.header.kind.is_compaction();
    let mut body: Vec<Fragment> = held.into_iter().map(Decoded::into_fragment).collect();
    if is_snapshot && !crate::apply::copies::snapshot_valid(tx.core, c, tid, ak) {
        let core = &*tx.core;
        for b in &mut body {
            b.strip_copies(&|d| crate::apply::copies::any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && m.valid_at(ai)));
        }
    }
    let before = crate::engine::state::encode(snap)?;
    let mut j = snap.clone();
    for b in &body {
        j.join(b.clone());
    }
    if crate::engine::state::encode(&j)? != before {
        return Ok(Some(false));
    }
    let mut ranges: Vec<(osis_crdt::Source, u64, u64)> = if is_snapshot {
        body.iter().flat_map(|b| b.writes()).filter(|w| w.1.is_some()).map(|(d, _)| (d.src.clone(), d.ctr, d.ctr.saturating_add(1))).collect()
    } else {
        crate::apply::copies::owned_ranges(&m.header, c, cai)
    };
    ranges.sort();
    ranges.dedup();
    let body: Vec<&Fragment> = body.iter().collect();
    let ix = snap.copy_index();
    Ok(Some(ix.outside(&ranges, &osis_crdt::CopySet::of(&body)).is_empty()))
}

pub(crate) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let (_, holders) = super::body_class(tx.core, &h, c, ai);
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, &holders);
    }
    for x in holders {
        let Some(a) = h.aspects.get(x) else { continue };
        let Some(o) = Owned::of(&h, c, x) else { return Ok(true) };
        if tx.state(&a.tid, &a.ak)?.is_some_and(|st| st.holds_owned_write(&|src, lo, hi| o.owns_range(src, lo, hi))) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<bool> {
    let dropped: BTreeMap<usize, bool> = tx.core.ix.commits.get(c).map(|m| m.dropped.iter().map(|(ai, d)| (*ai, d.live)).collect()).unwrap_or_default();
    for x in holders {
        let Some(a) = h.aspects.get(*x) else { continue };
        let parts = crate::apply::held_fragments(tx, c, *x)?;
        if parts.is_empty() && dropped.get(x) == Some(&false) {
            continue;
        }
        let Some(st) = tx.state(&a.tid, &a.ak)? else { continue };
        let writes = st.live_writes();
        if parts.is_empty() {
            let tsless = dropped.contains_key(x);
            if writes.iter().any(|(_, t)| t.map_or(tsless, |t| t <= h.ts)) {
                return Ok(true);
            }
            continue;
        }
        let live: BTreeSet<osis_crdt::Dot> = writes.into_iter().map(|(d, _)| d).collect();
        for f in parts {
            if f.live_writes().into_iter().any(|(d, _)| live.contains(&d)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The dates `note_copies` gives, sorted, each once.
pub(crate) fn copies_deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, ts: Ts, saw: &dyn Fn(&osis_crdt::Death) -> bool) -> Result<Vec<Ts>> {
    let Some(st) = tx.state(tid, ak)?.cloned() else { return Ok(Vec::new()) };
    let mut deaths = Vec::new();
    let fs = crate::apply::held_fragments(tx, c, ai)?;
    for f in fs {
        let mut st = st.clone();
        let mut ch = Changes::new();
        st.join_into(f.clone(), None, &mut ch);
        deaths.extend(ch.into_deaths().into_iter().filter(|d| f.holds_stamp(&d.stamp) && (d.at > ts || !saw(d) && super::deaths::dies_in(&f, d))).map(|d| d.at.max(ts)));
    }
    deaths.sort();
    deaths.dedup();
    Ok(deaths)
}

/// `Parts::kills`' set.
pub(crate) fn kills(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, (c, ai): (&CommitId, usize), src: Option<(CommitId, usize)>) -> Result<BTreeSet<(Stamp, Stamp)>> {
    let mut dead = BTreeSet::new();
    let fs = crate::apply::held_fragments(tx, c, ai)?;
    let mut keep = |f: &Fragment, ch: Changes| dead.extend(ch.into_deaths().into_iter().filter(|d| super::deaths::dies_in(f, d)).map(|d| (d.stamp.clone(), super::deaths::killer(&d))));
    if let Some((k, kai)) = src {
        let ks = crate::apply::held_fragments(tx, &k, kai)?;
        for f in &fs {
            let (mut g, mut ch) = (f.clone(), Changes::new());
            for x in &ks {
                g.join_into(x.clone(), None, &mut ch);
            }
            keep(f, ch);
        }
    } else if let Some(st) = tx.state(tid, ak)?.cloned() {
        for f in &fs {
            let (mut st, mut ch) = (st.clone(), Changes::new());
            st.join_into(f.clone(), None, &mut ch);
            keep(f, ch);
        }
    }
    Ok(dead)
}

/// `make_valueless`'s residue: the body and `kept` (or, dropped as covered, its held valid coverers'
/// copies of its writes) joined, then stripped.
pub(crate) fn residue(tx: &mut Tx<'_>, m: &crate::engine::Meta, c: &CommitId, ai: usize, o: &[Owned], all: &[Owned], kept: &[Fragment]) -> Result<Option<Fragment>> {
    let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
    let mut bodies = crate::apply::held_fragments(tx, c, ai)?;
    bodies.extend(kept.iter().cloned());
    if bodies.is_empty() && m.dropped.get(&ai).is_some_and(|d| d.as_cover()) {
        for s in super::coverers(tx.core, c, ai) {
            let Some(sai) = super::held_part(tx.core, &s, &a.tid, &a.ak) else { continue };
            if !crate::apply::copies::snapshot_valid(tx.core, &s, &a.tid, &a.ak) {
                continue;
            }
            for mut f in crate::apply::held_fragments(tx, &s, sai)? {
                f.remove_writes(&|d| !o.iter().any(|x| x.owns(d)));
                if f != Fragment::default() {
                    bodies.push(f);
                }
            }
        }
    }
    if bodies.is_empty() {
        return Ok(None);
    }
    let mut r = Fragment::default();
    for b in bodies {
        r.join(b);
    }
    r.strip(&|d| all.iter().any(|x| x.owns(d)));
    Ok(Some(r))
}
