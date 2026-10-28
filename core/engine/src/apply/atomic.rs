//! Atomic apply (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its membership records reach perm, records deaths, receipts, expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::validity;
use crate::engine::{Core, Meta, Owned, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Cause, Event, Origin};
use osis_commit::{CommitBlob, Decoded, Form, Header};
use osis_base::{Ak, CommitId, CreationRecord, Tid, Value, WallMs};
use osis_crdt::{Changes, Fragment};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn fragment(d: Decoded) -> (Fragment, Option<osis_crdt::Frontiers>) {
    match d {
        Decoded::Delta(x) => (x.fragment, None),
        Decoded::Snapshot(x) => (x.fragment, Some(x.frontiers)),
    }
}

/// Notes a held compaction snapshot of `(tid, ak)` with its frontiers.
pub(crate) fn note_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, ts: osis_base::Ts, id: &CommitId, fr: osis_crdt::Frontiers) {
    // kept in (`ts`, ID) order, so arrival order (a rebuild's is the store's) does not show
    let v = core.snapshots.entry_or_default((*tid, ak.clone()));
    if !v.iter().any(|x| x.1 == *id) {
        let at = v.partition_point(|x| (x.0, x.1) < (ts, *id));
        v.insert(at, (ts, *id, fr));
    }
}

/// Forgets snapshot `id` of `(tid, ak)` when its body drops: its frontiers and carried writes
/// are index entries derived from the body (spec/commits.md §5), which a rebuild cannot read.
pub(crate) fn forget_snapshot(core: &mut Core, tid: &Tid, ak: &Ak, id: &CommitId) {
    let k = (*tid, ak.clone());
    if let Some(mut v) = core.snapshots.get(&k).cloned()
        && v.iter().any(|x| x.1 == *id)
    {
        v.retain(|x| x.1 != *id);
        if v.is_empty() {
            core.snapshots.remove(&k);
        } else {
            core.snapshots.insert(k.clone(), v);
        }
    }
    if let Some(mut v) = core.carried.get(&k).cloned()
        && v.iter().any(|c| c.snap == *id)
    {
        v.retain(|c| c.snap != *id);
        if v.is_empty() {
            core.carried.remove(&k);
        } else {
            core.carried.insert(k, v);
        }
    }
}

/// Adds a commit to the per-aspect and node-form range indexes.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    for a in &h.aspects {
        core.by_aspect.insert((a.tid, a.ak.clone()), (h.ts, *id));
        if a.ak.as_str() == "/label" {
            core.labeled.insert(a.tid);
        }
        if !h.kind.has_own_writes() {
            core.copies.insert((a.tid, a.ak.clone()), (h.ts, *id));
        }
        core.by_thing.insert(a.tid, *id);
        if h.form == Form::Node && h.kind.has_own_writes() && a.lo < a.hi {
            core.ranges.insert((a.tid, a.ak.clone(), h.author), a.lo, (a.hi, *id));
        }
    }
    for b in &h.chunks {
        core.by_chunk.insert(*b, *id);
    }
    crate::retention::note_indexed(core, id, h);
}

/// Commits by the same node whose node-form ranges on one aspect overlap this one's
/// (spec/commits.md §4: all are invalid).
fn overlaps(core: &Core, id: &CommitId, h: &Header) -> BTreeSet<CommitId> {
    let mut out = BTreeSet::new();
    if h.form != Form::Node || !h.kind.has_own_writes() {
        return out;
    }
    for a in &h.aspects {
        if let Some(m) = core.ranges.get(&(a.tid, a.ak.clone(), h.author)) {
            for (lo, (hi, c)) in m.range(..a.hi) {
                if *hi > a.lo && *lo < a.hi && c != id {
                    out.insert(*c);
                }
            }
        }
    }
    out
}

/// Joins `delta` into the state of `(tid, ak)`, holding value-less what must be.
pub(crate) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment) -> Result<Changes> {
    let _s = crate::costs::span("apply: join");
    tx.load_lazy(tid, ak)?;
    // writes owned by deltas invalid here go from every body before it joins (un-merge is a
    // function of the held set: another's nested write under an invalid creation goes too)
    let invalid = invalid_of(tx.core, tid, ak);
    if !invalid.is_empty() {
        delta.remove_dots(&|d| invalid.iter().any(|o| o.owns(d)));
    }
    // the state is held stripped and stripping commutes with join (spec/crdt.md §4.7)
    strip_valueless(tx.core, tid, ak, &mut delta);
    // a paged state loads only the pages the join touches
    let touch = crate::engine::pages::touch_of(&delta, tx.core.pages.get(&(*tid, ak.clone())));
    tx.ensure_touch(tid, ak, &touch)?;
    // joined in place (evicted on rollback), so a join costs O(delta), not a copy of the state
    let k = (*tid, ak.clone());
    tx.core.touch();
    tx.core.wrote(k.clone());
    let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
    let ch = st.join(delta);
    let st = (!st.is_empty()).then_some(st);
    if ch.is_changed() || !ch.deaths().is_empty() {
        tx.set_state_touched(tid, ak, st, &touch, Shred::No)?;
    } else {
        tx.core.states.insert(k, st);
    }
    Ok(ch)
}

/// The owners of writes of the held deltas on `(tid, ak)` that are invalid here.
pub(crate) fn invalid_of(core: &Core, tid: &Tid, ak: &Ak) -> Vec<Owned> {
    let mut out = Vec::new();
    for c in core.invalid.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = core.commits.get(c) else { continue };
        let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { continue };
        if m.valid.get(ai).copied().unwrap_or(false) {
            continue;
        }
        if m.header.kind.has_own_writes() {
            out.extend(Owned::of(&m.header, c, ai));
        } else if m.header.kind == osis_commit::Kind::Import {
            out.extend(m.header.origins.iter().map(|o| Owned::Commit(o.commit)));
        }
    }
    // writes snapshots carry without their commit, invalid as their author's
    for c in core.carried.get(&(*tid, ak.clone())).into_iter().flatten() {
        if !c.invalid.is_empty() {
            out.push(Owned::Dots { src: c.src.clone(), ctrs: c.invalid.clone() });
        }
    }
    out
}

pub(crate) fn strip_valueless(core: &Core, tid: &Tid, ak: &Ak, st: &mut Fragment) {
    if let Some(v) = core.valueless.get(&(*tid, ak.clone()))
        && !v.is_empty()
    {
        st.strip(&|d| v.iter().any(|o| o.owns(d)));
    }
}

/// Records the creation records `parts` carry that are not held yet; whether any was new.
fn note_created(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)]) -> Result<bool> {
    let mut any = false;
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != osis_commit::retention::CREATED || tx.core.created(&a.tid).is_some() {
            continue;
        }
        let rec = match d {
            Decoded::Delta(x) => x.fragment.read(),
            Decoded::Snapshot(x) => x.fragment.read(),
        }
        .as_ref()
        .and_then(CreationRecord::from_value)
        .ok_or(Error::BadInput("/created"))?;
        if rec.tid() == a.tid {
            tx.txn.put_local(&[records::CREATED, a.tid.as_bytes()].concat(), &osis_base::encode(&rec.to_value()), Shred::No)?;
            tx.core.held.create(rec);
            // the reader actor of the thing's deltas is known now
            let touching: Vec<CommitId> = tx.core.aspects_of(&a.tid).flat_map(|(_, s)| s.iter().map(|x| x.1)).collect();
            for c in touching {
                tx.core.bodies.remove(&c);
                tx.core.mark_changed(c);
            }
            any = true;
        }
    }
    Ok(any)
}

/// Applies a verified commit (`parts` decoded) in this transaction.
pub(crate) fn apply_verified(tx: &mut Tx<'_>, blob: &CommitBlob, parts: Vec<(usize, usize, Decoded)>, origin: Origin, received: WallMs) -> Result<()> {
    let _s = crate::costs::span("apply");
    tx.core.touch();
    let id = blob.id();
    let h = Arc::new(blob.header.clone());
    tx.core.hlc.observe(h.ts);
    tx.txn.put_local(records::HLC, &tx.core.hlc.last().to_u64().to_be_bytes(), Shred::No)?;

    // creation records first: perm and dedup secrets need them
    let mut held_changed = note_created(tx, &h, &parts)?;
    validity::note_authors(tx.core, &id, &h, &parts)?;
    let view = Arc::new(crate::engine::View::of(&h));
    if h.kind.is_membership() {
        validity::note_required(tx.core, &h, &id, &parts);
        validity::add_membership(tx, &view, Some(&h), &id, &validity::EdgeParts::of(&h, &parts))?;
        held_changed = true;
    }
    if held_changed {
        tx.core.update_timelines();
    }

    // overlapping node-form counters void both commits
    let ov = overlaps(tx.core, &id, &h);
    if !ov.is_empty() {
        held_changed = true;
        for c in ov.iter().chain(std::iter::once(&id)) {
            tx.core.void.insert(*c);
            tx.core.stale_commits.insert(*c);
            tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
        }
        let now = tx.now();
        tx.core.events.diagnostic(
            crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OverlappingCounters, tids: vec![h.author], commit: Some(id), peer: Some(h.author), detail: String::new() },
            now,
        );
    }
    index_commit(tx.core, &id, &view);
    validity::uncarry(tx.core, &id, &h);
    let valid: Vec<bool> = (0..h.aspects.len()).map(|ai| validity::part_valid(tx.core, &h, &id, ai)).collect();
    let meta = Meta { view, header: crate::engine::LazyHeader::ready(h.clone()), received, origin, valid: valid.clone(), dropped: BTreeSet::new() };
    tx.core.commits.insert(id, meta.clone());
    tx.core.index_validity(&id);

    // receipt record (spec/permissions.md §5.1; spec/crdt.md §8)
    {
        let _s = crate::costs::span("apply: receipt");
        super::receipt::record(tx, &h, &id, &parts, received)?;
    }

    if origin == Origin::Local && h.kind == osis_commit::Kind::Content {
        let mut by_aspect: BTreeMap<usize, Vec<&Fragment>> = BTreeMap::new();
        for (ai, _, d) in &parts {
            by_aspect.entry(*ai).or_default().push(match d {
                Decoded::Delta(x) => &x.fragment,
                Decoded::Snapshot(x) => &x.fragment,
            });
        }
        for (ai, a) in h.aspects.iter().enumerate() {
            // one delta: keep only what undoing it reads
            let delta = match by_aspect.get(&ai).map(Vec::as_slice) {
                Some([d]) => Some(*d),
                _ => None,
            };
            crate::undo::remember(tx, &id, &a.tid, &a.ak, delta)?;
        }
    }
    let pend = super::keys::before_join(tx, &h, &parts, &valid)?;
    let mut changed: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut touched = Touched::default();
    let mut unmerge: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // deaths after the commit's record: they may drop its own body (dead on arrival)
    let mut joined: Vec<(Tid, Ak, bool, Vec<osis_crdt::Death>)> = Vec::new();
    for (ai, _, d) in &parts {
        let (ai, d) = (*ai, d.clone());
        let Some(a) = h.aspects.get(ai) else { continue };
        let (f, fr) = fragment(d);
        // every held snapshot's frontiers and carried writes, whatever its validity
        if let Some(fr) = fr {
            note_snapshot(tx.core, &a.tid, &a.ak, h.ts, &id, fr);
            validity::note_carried(tx.core, &a.tid, &a.ak, &id, &f);
            if validity::carries_invalid(tx.core, &a.tid, &a.ak, &id) {
                unmerge.insert((a.tid, a.ak.clone()));
            }
        }
        if !valid.get(ai).copied().unwrap_or(false) {
            arrived_invalid(tx, &a.tid, &a.ak, Some(f), &mut changed, &mut touched)?;
            continue;
        }
        touched.note(&a.tid, &a.ak, &f);
        let replay = crate::retention::replays(tx.core, &id, &h, &a.tid, &a.ak);
        let ch = join_into_state(tx, &a.tid, &a.ak, f)?;
        if ch.is_changed() {
            changed.insert((a.tid, a.ak.clone()));
        }
        joined.push((a.tid, a.ak.clone(), replay, ch.into_deaths()));
    }
    // an invalid aspect whose part is not held: others' writes under its creations go too (the
    // part may never come, or come late)
    for (ai, a) in h.aspects.iter().enumerate() {
        if !valid.get(ai).copied().unwrap_or(false) && !parts.iter().any(|p| p.0 == ai) {
            arrived_invalid(tx, &a.tid, &a.ak, None, &mut changed, &mut touched)?;
        }
    }
    {
        let _s = crate::costs::span("apply: put_commit");
        tx.put_commit(&id, blob, &meta, Shred::No, None)?;
    }
    unmerge_carried(tx, &unmerge, &mut changed, &mut touched, true)?;
    for (tid, ak, replay, deaths) in &joined {
        if *replay {
            crate::retention::mark_late(tx, &id, &h, tid, ak, deaths)?;
        } else {
            crate::retention::note_deaths(tx, tid, ak, deaths)?;
        }
    }
    {
        let _s = crate::costs::span("apply: retention");
        crate::retention::on_apply(tx, &id, &mut changed)?;
    }

    {
        let _s = crate::costs::span("apply: observe");
        for (tid, ak) in &changed {
            observe_touched(tx, tid, ak, &touched)?;
        }
    }
    super::keys::after_join(tx, &h, &parts, &valid, pend)?;
    let mut flipped = Vec::new();
    if held_changed || tx.core.stale() {
        flipped = validity::rejudge_all(tx, true)?;
        for (tid, ak) in &flipped {
            observe_state(tx, tid, ak)?;
        }
    }
    let rosters: BTreeSet<Tid> = if h.kind.is_membership() { h.aspects.iter().filter(|a| a.ak.as_str() == "/members" || a.ak.as_str() == "/tenures").map(|a| a.tid).collect() } else { BTreeSet::new() };
    // a received roster change may end this node's read access (spec/permissions.md §3); its own
    // self-removals drop what they lost once uploaded (`Done::drop_lost`)
    if origin != Origin::Local {
        crate::rotation::mark_lost_due(tx, rosters.iter().copied())?;
    }
    tx.core.events.queue(Event::Applied { id, origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect() });
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    for thing in rosters {
        tx.core.events.queue(Event::Roster { thing });
    }
    Ok(())
}

/// A delta invalid on arrival (`f`; `None`: its part is not held), on apply or late: others'
/// writes already joined may sit under its creations, so the aspect un-merges as on a flip;
/// its sequence records stay as hidden anchors (what un-merging it gives, spec/crdt.md §4.6).
/// Edge and creation aspects reach perm instead.
fn arrived_invalid(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, f: Option<Fragment>, changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched) -> Result<()> {
    if matches!(ak.as_str(), "/members" | "/tenures" | "/created") {
        return Ok(());
    }
    let held = f.is_some();
    if let Some(f) = &f {
        join_into_state(tx, tid, ak, f.clone())?;
    }
    if !unmerge_fell(tx, tid, ak, f)? && !held {
        return Ok(());
    }
    // the writes it un-merged may have superseded others (spec/crdt.md §4.8)
    crate::retention::mark_if_bounded(tx, tid, ak)?;
    // others' writes went: what waits on the aspect's state is judged again
    tx.core.mark_aspect_changed(tid, ak);
    changed.insert((*tid, ak.clone()));
    touched.whole(tid, ak);
    Ok(())
}

/// Un-merges the aspects a snapshot just held carries invalid writes on (`carries_invalid`),
/// once the commit is stored so its own body joins too: in place for a snapshot new here
/// (`fresh`: its carried judgments only add invalid writes), else rebuilt.
fn unmerge_carried(tx: &mut Tx<'_>, unmerge: &BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>, touched: &mut Touched, fresh: bool) -> Result<()> {
    for (tid, ak) in unmerge {
        if fresh {
            unmerge_fell(tx, tid, ak, None)?;
        } else {
            rebuild(tx, tid, ak)?;
        }
        crate::retention::mark_deaths_due(tx, tid, ak)?;
        tx.core.mark_aspect_changed(tid, ak);
        changed.insert((*tid, ak.clone()));
        touched.whole(tid, ak);
    }
    Ok(())
}

/// Joins deltas of an applied commit that arrived later (spec/commits.md §4). Late creation
/// records and edge writes reach perm as on apply (a certificate copy may bring a commit's
/// `/members` delta after its `/created` one), and held deltas are re-judged.
pub(crate) fn join_late(tx: &mut Tx<'_>, id: &CommitId, merged: &CommitBlob, parts: Vec<(usize, usize, Decoded)>) -> Result<()> {
    tx.core.touch();
    let mut meta = tx.core.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    let received = tx.now();
    super::receipt::record(tx, &h, id, &parts, received)?;
    let mut held_changed = note_created(tx, &h, &parts)?;
    validity::note_authors(tx.core, id, &h, &parts)?;
    let edges = h.kind.is_membership() && parts.iter().any(|(ai, _, _)| h.aspects.get(*ai).is_some_and(|a| matches!(a.ak.as_str(), "/members" | "/tenures")));
    if h.kind.is_membership() {
        // judged with the parts held before (a grant's `/members` part names what its
        // `/secrets` part may box)
        let mut all = parts.clone();
        all.extend(super::held_parts_at(tx, id, &|ai| !parts.iter().any(|(x, _, _)| *x == ai))?);
        validity::note_required(tx.core, &h, id, &all);
        // what that judged (an overreaching late `/secrets` part) holds for the late parts'
        // join below; other aspects' flips go through the re-judge (`invalidated`, `revalidated`)
        let late: BTreeSet<usize> = parts.iter().map(|p| p.0).collect();
        let mut flipped = false;
        for ai in late {
            let v = validity::part_valid(tx.core, &h, id, ai);
            if let Some(x) = meta.valid.get_mut(ai)
                && *x != v
            {
                *x = v;
                flipped = true;
            }
        }
        if flipped {
            if let Some(m) = tx.core.commits.get_mut(id) {
                m.valid = meta.valid.clone();
            }
            tx.core.index_validity(id);
            held_changed = true;
        }
    }
    // late `/secrets` parts establish epochs like the first ones, with the commit's `/keys`
    // (held parts). The keysets "before" are the current `/keys` state, which already holds this
    // commit's `/keys` when that part joined earlier: an approximation like `revalidated`'s (a
    // keyset the commit replaced is no longer known; its removed keys come from the index of
    // held keyed entries, and a write whose removed keys are unknown waits as usual).
    let mut with_keys = parts.clone();
    if h.kind == osis_commit::Kind::Membership && parts.iter().any(|(ai, _, _)| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "/secrets")) {
        for (ai, a) in h.aspects.iter().enumerate() {
            if a.ak.as_str() == "/keys" && !parts.iter().any(|(x, _, _)| *x == ai) {
                with_keys.extend(super::held_parts(tx, id, ai)?.into_iter().map(|d| (ai, 0, d)));
            }
        }
    }
    let pend = super::keys::before_join(tx, &h, &with_keys, &meta.valid)?;
    let mut changed = BTreeSet::new();
    let mut touched = Touched::default();
    let mut unmerge: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // deaths after the commit's record: they may drop its own body (dead on arrival)
    let mut joined: Vec<(Tid, Ak, bool, Vec<osis_crdt::Death>)> = Vec::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(ai) else { continue };
        let (f, fr) = fragment(d);
        if let Some(fr) = fr {
            note_snapshot(tx.core, &a.tid, &a.ak, h.ts, id, fr);
            validity::note_carried(tx.core, &a.tid, &a.ak, id, &f);
            if validity::carries_invalid(tx.core, &a.tid, &a.ak, id) {
                unmerge.insert((a.tid, a.ak.clone()));
            }
        }
        if !meta.valid.get(ai).copied().unwrap_or(false) {
            arrived_invalid(tx, &a.tid, &a.ak, Some(f), &mut changed, &mut touched)?;
            continue;
        }
        touched.note(&a.tid, &a.ak, &f);
        let replay = crate::retention::replays(tx.core, id, &h, &a.tid, &a.ak);
        let ch = join_into_state(tx, &a.tid, &a.ak, f)?;
        if ch.is_changed() {
            changed.insert((a.tid, a.ak.clone()));
        }
        joined.push((a.tid, a.ak.clone(), replay, ch.into_deaths()));
    }
    // the record's `node/edges` row, read once: it is also the commit's edge writes again
    let all = if h.kind.is_membership() { Some(super::edge_parts_of(tx, id, &h, merged.clone())?) } else { None };
    tx.put_commit(id, merged, &meta, Shred::No, all.as_ref())?;
    unmerge_carried(tx, &unmerge, &mut changed, &mut touched, false)?;
    for (tid, ak, replay, deaths) in &joined {
        if *replay {
            crate::retention::mark_late(tx, id, &h, tid, ak, deaths)?;
        } else {
            crate::retention::note_deaths(tx, tid, ak, deaths)?;
        }
    }
    if edges && let Some(all) = &all {
        tx.core.held.remove(id);
        validity::add_membership(tx, &meta.view, Some(&h), id, all)?;
        held_changed = true;
    }
    if held_changed {
        tx.core.update_timelines();
    }
    for (tid, ak) in &changed {
        observe_touched(tx, tid, ak, &touched)?;
    }
    super::keys::after_join(tx, &h, &with_keys, &meta.valid, pend)?;
    let mut flipped = Vec::new();
    if held_changed || tx.core.stale() {
        flipped = validity::rejudge_all(tx, true)?;
        for (tid, ak) in &flipped {
            observe_state(tx, tid, ak)?;
        }
    }
    if edges && meta.origin != Origin::Local {
        crate::rotation::mark_lost_due(tx, h.aspects.iter().filter(|a| matches!(a.ak.as_str(), "/members" | "/tenures")).map(|a| a.tid))?;
    }
    if edges {
        for thing in h.aspects.iter().filter(|a| matches!(a.ak.as_str(), "/members" | "/tenures")).map(|a| a.tid).collect::<BTreeSet<_>>() {
            tx.core.events.queue(Event::Roster { thing });
        }
    }
    tx.core.events.queue(Event::Joined { id: *id });
    for (t, a) in &changed {
        tx.core.mark_aspect_changed(t, a);
    }
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LateDelta, changed: changed.into_iter().collect() });
    }
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    Ok(())
}

/// The `/secrets` entries a commit's joins touched, per aspect (`None`: anything may have
/// changed, read the whole state).
#[derive(Default)]
struct Touched(std::collections::BTreeMap<(Tid, Ak), Option<SecretsKeys>>);

/// Keys of the box and history-box entries a change touched.
type SecretsKeys = (Vec<Value>, Vec<Value>);

impl Touched {
    fn note(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) {
        if ak.as_str() != "/secrets" {
            return;
        }
        let keys = crate::engine::secrets::touched_keys(f);
        match (self.0.entry((*tid, ak.clone())).or_insert_with(|| Some((Vec::new(), Vec::new()))), keys) {
            (Some(acc), Some((b, h))) => {
                acc.0.extend(b);
                acc.1.extend(h);
            }
            (slot, _) => *slot = None,
        }
    }
    fn whole(&mut self, tid: &Tid, ak: &Ak) {
        self.0.insert((*tid, ak.clone()), None);
    }
}

/// `observe_state`, reading only the touched `/secrets` entries where known.
fn observe_touched(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, touched: &Touched) -> Result<()> {
    match touched.0.get(&(*tid, ak.clone())) {
        Some(Some((boxes, history))) => observe_secrets_keys(tx, tid, boxes, history),
        _ => observe_state(tx, tid, ak),
    }
}

/// What the `/secrets` entries keyed `boxes` and `history` of `actor` hold (and the history chain
/// they reach) teaches this node: O(those entries), not O(boxes). Whether anything was learned.
pub(crate) fn ingest_secrets_keys(tx: &mut Tx<'_>, actor: &Tid, boxes: &[Value], history: &[Value]) -> Result<bool> {
    let ak = Ak::new("/secrets").map_err(|_| Error::Misuse("ak"))?;
    // the boxes keyed so, and the history boxes (their chain is followed in memory)
    use osis_crdt::PathSeg;
    let mut paths: Vec<Vec<PathSeg>> = boxes.iter().map(|k| vec![PathSeg::Field(0), PathSeg::Key(k.clone())]).collect();
    paths.push(vec![PathSeg::Field(1)]);
    tx.ensure_paths(actor, &ak, &paths)?;
    let k = (*actor, ak);
    // taken out of the cache while the core learns from it, then put back
    let Some(st) = tx.core.states.get_mut(&k).and_then(Option::take) else { return Ok(false) };
    tx.core.touch();
    let learned = tx.core.ingest_keyed(actor, &st, boxes, history);
    tx.core.states.insert(k, Some(st));
    Ok(learned)
}

/// `ingest_secrets_keys`, persisting what was learned and reopening the boxes sealed to `actor`.
fn observe_secrets_keys(tx: &mut Tx<'_>, actor: &Tid, boxes: &[Value], history: &[Value]) -> Result<()> {
    if ingest_secrets_keys(tx, actor, boxes, history)? && let Some(e) = tx.core.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
        // boxes sealed to this actor elsewhere open now (membership flows hook)
        crate::flows::reopen_dependents(tx, *actor)?;
    }
    #[cfg(test)]
    if tx.core.check_ingest {
        // the whole state's ingestion learns nothing the entries' did not
        let ak = Ak::new("/secrets").map_err(|_| Error::Misuse("ak"))?;
        let before = tx.core.secrets.get(actor).cloned();
        let st = tx.state(actor, &ak)?.cloned();
        let alts = st.as_ref().map(crate::engine::secrets::history_alts).unwrap_or_default();
        if let Some(s) = st.as_ref().and_then(Fragment::read).as_ref().and_then(crate::engine::secrets::secrets_value)
            && tx.core.ingest_secrets(actor, &s, None, &alts, None)
        {

            match before {
                Some(b) => tx.core.secrets.insert(*actor, b),
                None => tx.core.secrets.remove(actor),
            };
            return Err(Error::Misuse("per-entry /secrets ingestion missed what the whole state holds"));
        }
    }
    Ok(())
}

/// Keeps the indexes derived from states current: secrets opened from `/secrets`, own keys
/// from `/keys`, the `/was` and `/moved` indexes, group definitions.
pub(crate) fn observe_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !matches!(ak.as_str(), "/secrets" | "/keys" | "/was" | "/moved" | "/group") {
        return Ok(());
    }
    let v = tx.state(tid, ak)?.and_then(Fragment::read);
    match ak.as_str() {
        "/secrets" => {
            let alts = tx.state(tid, ak)?.map(crate::engine::secrets::history_alts).unwrap_or_default();
            if let Some(s) = v.as_ref().and_then(crate::engine::secrets::secrets_value)
                && tx.core.ingest_secrets(tid, &s, None, &alts, None)
                && let Some(e) = tx.core.secrets.get(tid)
            {
                let b = crate::engine::secrets::encode_epochs(e);
                tx.txn.put_local(&[b"k/".as_slice(), tid.as_bytes()].concat(), &b, Shred::Yes)?;
                // boxes sealed to this actor elsewhere open now (membership flows hook)
                crate::flows::reopen_dependents(tx, *tid)?;
            }
        }
        "/keys" => {
            if let Some(k) = v.as_ref().and_then(crate::engine::secrets::keys_value) {
                tx.core.observe_keys(tid, &k);
                // reading-only candidates the published keysets contradict go
                if let Some(e) = tx.core.secrets.get_mut(tid)
                    && osis_keys::prune_reading(e, &k)
                {
                    crate::flows::save_epochs(tx, tid)?;
                }
            }
        }
        "/was" => {
            if let Some(old) = tx.core.was_of.remove(tid) {
                tx.core.was.remove(&old, tid);
            }
            if let Some(Value::Tid(t)) = v {
                tx.core.was.insert(t, *tid);
                tx.core.was_of.insert(*tid, t);
            }
        }
        "/moved" => match v {
            Some(Value::Tid(t)) => {
                tx.core.moved.insert(*tid, t);
            }
            _ => {
                tx.core.moved.remove(tid);
            }
        },
        // every path that changes a `/group` (late deltas, re-judging) updates `/groups`
        "/group" => tx.core.groups.set(*tid, group_def(v)),
        _ => {}
    }
    Ok(())
}

/// A `/group` value's (items, subgroups).
pub(crate) fn group_def(v: Option<Value>) -> Option<(BTreeSet<Tid>, BTreeSet<Tid>)> {
    v.and_then(|v| osis_schema::AspectKey::decode(&osis_schema::core_types::GROUP, &v).ok()).map(|g| (g.items, g.subgroups))
}

/// Un-merges `(tid, ak)` after validity only fell (deltas or carried writes newly invalid, none
/// valid again): the state without the writes of every delta invalid here, in place, when that
/// is what `rebuild` gives (none of them supersedes a write in the state, spec/crdt.md §4.6);
/// else `rebuild`. `fell`: the bodies of what fell, when known: a paged state then loads and
/// rewrites only the pages holding their dots (else the whole state). No other body is read.
/// Whether the state may have changed.
pub(crate) fn unmerge_fell(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, fell: Option<Fragment>) -> Result<bool> {
    let invalid = invalid_of(tx.core, tid, ak);
    let bad = |d: &osis_crdt::Dot| invalid.iter().any(|o| o.owns(d));
    tx.load_lazy(tid, ak)?;
    let k = (*tid, ak.clone());
    let touch = fell.as_ref().and_then(|f| crate::engine::pages::touch_of(f, tx.core.pages.get(&k)));
    tx.ensure_touch(tid, ak, &touch)?;
    let in_place = match tx.core.states.get(&k).and_then(Option::as_ref) {
        None => None,
        Some(cur) if cur.dots_supersede(&bad) => return rebuild(tx, tid, ak).map(|()| true),
        Some(cur) => Some(cur.holds_dots(&bad)),
    };
    if in_place == Some(true) {
        let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
        st.remove_dots(&bad);
        st.prune(None, &mut Changes::new());
        let st = (!st.is_empty()).then_some(st);
        tx.core.touch();
        tx.core.wrote(k);
        tx.set_state_touched(tid, ak, st, &touch, Shred::Yes)?;
    }
    // in place is what rebuilding gives
    #[cfg(debug_assertions)]
    {
        let want = rebuilt(tx, tid, ak)?;
        debug_assert!(tx.state(tid, ak)? == want.as_ref(), "in-place un-merge of {tid:?} {ak:?} differs from a rebuild");
    }
    Ok(in_place == Some(true))
}

/// Rebuilds `(tid, ak)` after validity changed (spec/crdt.md §4.6, spec/permissions.md §5.2):
/// the join of the current state (a snapshot this node holds) and every held body, each first
/// stripped of the writes of the deltas now invalid here (by counter range or commit ID, so the
/// author's valid deltas, dropped bodies included, keep theirs).
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let st = rebuilt(tx, tid, ak)?;
    tx.set_state(tid, ak, st, Shred::Yes, false)
}

/// What `rebuild` writes.
fn rebuilt(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
    let held: Vec<(osis_base::Ts, CommitId)> = tx.core.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().copied().collect()).unwrap_or_default();
    let invalid = invalid_of(tx.core, tid, ak);
    let mut bodies: Vec<Fragment> = Vec::new();
    for (_, c) in held {
        let Some(m) = tx.core.commits.get(&c).cloned() else { continue };
        let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { continue };
        for d in super::held_parts(tx, &c, ai)? {
            bodies.push(fragment(d).0);
        }
    }
    tx.load(tid, ak)?;
    let current = tx.core.states.get(&(*tid, ak.clone())).cloned().flatten();
    let bad = |d: &osis_crdt::Dot| invalid.iter().any(|o| o.owns(d));
    let mut st = Fragment::default();
    let mut ch = Changes::new();
    for mut b in current.into_iter().chain(bodies) {
        b.remove_dots(&bad);
        st.join_into(b, None, &mut ch);
    }
    strip_valueless(tx.core, tid, ak, &mut st);
    Ok((!st.is_empty()).then_some(st))
}
