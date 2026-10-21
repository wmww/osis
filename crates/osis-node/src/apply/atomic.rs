//! Atomic apply (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its membership records reach perm, records deaths, receipts, expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::validity;
use crate::engine::{Core, Meta, Owned, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Cause, Event, Origin};
use osis_commit::{CommitBlob, Decoded, Form, Header};
use osis_core::{Ak, CommitId, CreationRecord, Tid, Value, WallMs};
use osis_crdt::{Changes, Fragment};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

fn fragment(d: Decoded) -> (Fragment, Option<osis_crdt::Frontiers>) {
    match d {
        Decoded::Delta(x) => (x.fragment, None),
        Decoded::Snapshot(x) => (x.fragment, Some(x.frontiers)),
    }
}

/// Adds a commit to the per-aspect and node-form range indexes.
pub(crate) fn index_commit(core: &mut Core, id: &CommitId, h: &Header) {
    for a in &h.aspects {
        core.by_aspect.insert((a.tid, a.ak.clone()), (h.ts, *id));
        core.by_thing.insert(a.tid, *id);
        if h.form == Form::Node && h.kind.has_own_writes() && a.lo < a.hi {
            core.ranges.insert((a.tid, a.ak.clone(), h.author), a.lo, (a.hi, *id));
        }
    }
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
    tx.core.written.push(k.clone());
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
            tx.txn.put_local(&[records::CREATED, a.tid.as_bytes()].concat(), &osis_core::encode(&rec.to_value()), Shred::No)?;
            tx.core.held.create(rec);
            any = true;
        }
    }
    Ok(any)
}

/// Applies a verified commit (`parts` decoded) in this transaction.
pub(crate) fn apply_verified(tx: &mut Tx<'_>, blob: &CommitBlob, parts: Vec<(usize, usize, Decoded)>, origin: Origin, received: WallMs) -> Result<()> {
    tx.core.touch();
    let id = blob.id();
    let h = Arc::new(blob.header.clone());
    tx.core.hlc.observe(h.ts);
    tx.txn.put_local(records::HLC, &tx.core.hlc.last().to_u64().to_be_bytes(), Shred::No)?;

    // creation records first: perm and dedup secrets need them
    let mut held_changed = note_created(tx, &h, &parts)?;
    if h.kind.is_membership() {
        validity::note_required(tx.core, &h, &id, &parts);
        validity::add_membership(tx, &h, &id, &parts)?;
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
            tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
            if let Some(m) = tx.core.commits.get(c) {
                let things: Vec<Tid> = m.header.aspects.iter().map(|a| a.tid).collect();
                tx.core.rejudge.extend(things);
            }
        }
        let now = tx.now();
        tx.core.events.diagnostic(
            crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OverlappingCounters, tids: vec![h.author], commit: Some(id), peer: Some(h.author), detail: String::new() },
            now,
        );
    }
    index_commit(tx.core, &id, &h);
    let valid: Vec<bool> = (0..h.aspects.len()).map(|ai| validity::part_valid(tx.core, &h, &id, ai)).collect();
    let meta = Meta { header: h.clone(), received, origin, valid: valid.clone(), dropped: BTreeSet::new() };
    tx.core.commits.insert(id, meta.clone());
    tx.core.index_validity(&id);

    // receipt record (spec/permissions.md §5.1; spec/crdt.md §8)
    super::receipt::record(tx, &h, &id, &parts, received)?;

    if origin == Origin::Local && h.kind == osis_commit::Kind::Content {
        for (ai, a) in h.aspects.iter().enumerate() {
            let mut mine = parts.iter().filter(|(x, _, _)| *x == ai).map(|(_, _, d)| match d {
                Decoded::Delta(x) => &x.fragment,
                Decoded::Snapshot(x) => &x.fragment,
            });
            // one delta: keep only what undoing it reads
            let delta = match (mine.next(), mine.next()) {
                (Some(d), None) => Some(d),
                _ => None,
            };
            crate::undo::remember(tx, &id, &a.tid, &a.ak, delta)?;
        }
    }
    let pend = super::keys::before_join(tx, &h, &parts, &valid)?;
    let mut changed: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut touched = Touched::default();
    for (ai, _, d) in &parts {
        let (ai, d) = (*ai, d.clone());
        let Some(a) = h.aspects.get(ai) else { continue };
        if !valid.get(ai).copied().unwrap_or(false) {
            // others' writes already joined may sit under its creations
            if !matches!(a.ak.as_str(), "/members" | "/tenures" | "/created") {
                rebuild(tx, &a.tid, &a.ak)?;
                changed.insert((a.tid, a.ak.clone()));
                touched.whole(&a.tid, &a.ak);
            }
            continue;
        }
        let (f, _) = fragment(d);
        touched.note(&a.tid, &a.ak, &f);
        let ch = join_into_state(tx, &a.tid, &a.ak, f)?;
        if ch.is_changed() {
            changed.insert((a.tid, a.ak.clone()));
        }
        crate::retention::note_deaths(tx, &a.tid, &a.ak, ch.deaths())?;
    }
    tx.put_commit(&id, blob, &meta, Shred::No)?;
    crate::retention::on_apply(tx, &id, &mut changed)?;

    for (tid, ak) in &changed {
        observe_touched(tx, tid, ak, &touched)?;
    }
    super::keys::after_join(tx, &h, &parts, &valid, pend)?;
    let mut flipped = Vec::new();
    if held_changed {
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

/// Joins deltas of an applied commit that arrived later (spec/commits.md §4). Late creation
/// records and edge writes reach perm as on apply (a certificate copy may bring a commit's
/// `/members` delta after its `/created` one), and held deltas are re-judged.
pub(crate) fn join_late(tx: &mut Tx<'_>, id: &CommitId, merged: &CommitBlob, parts: Vec<(usize, usize, Decoded)>) -> Result<()> {
    tx.core.touch();
    let meta = tx.core.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    let received = tx.now();
    super::receipt::record(tx, &h, id, &parts, received)?;
    let mut held_changed = note_created(tx, &h, &parts)?;
    let edges = h.kind.is_membership() && parts.iter().any(|(ai, _, _)| h.aspects.get(*ai).is_some_and(|a| matches!(a.ak.as_str(), "/members" | "/tenures")));
    if h.kind.is_membership() {
        validity::note_required(tx.core, &h, id, &parts);
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
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(ai) else { continue };
        if !meta.valid.get(ai).copied().unwrap_or(false) {
            continue;
        }
        let (f, _) = fragment(d);
        touched.note(&a.tid, &a.ak, &f);
        let ch = join_into_state(tx, &a.tid, &a.ak, f)?;
        if ch.is_changed() {
            changed.insert((a.tid, a.ak.clone()));
        }
        crate::retention::note_deaths(tx, &a.tid, &a.ak, ch.deaths())?;
    }
    tx.put_commit(id, merged, &meta, Shred::No)?;
    if edges {
        // the commit's edge writes again, from every held part
        tx.core.held.remove(id);
        let mut all = Vec::new();
        for (ai, a) in h.aspects.iter().enumerate() {
            if matches!(a.ak.as_str(), "/members" | "/tenures") {
                all.extend(super::held_parts(tx, id, ai)?.into_iter().map(|d| (ai, 0, d)));
            }
        }
        validity::add_membership(tx, &h, id, &all)?;
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
    if held_changed {
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
struct Touched(std::collections::BTreeMap<(Tid, Ak), Option<(Vec<Value>, Vec<Value>)>>);

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

/// Rebuilds `(tid, ak)` after validity changed (spec/crdt.md §4.6, spec/permissions.md §5.2):
/// the join of the current state (a snapshot this node holds) and every held body, each first
/// stripped of the writes of the deltas now invalid here (by counter range or commit ID, so the
/// author's valid deltas, dropped bodies included, keep theirs).
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<(osis_core::Ts, CommitId)> = tx.core.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().copied().collect()).unwrap_or_default();
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
    let st = (!st.is_empty()).then_some(st);
    tx.set_state(tid, ak, st, Shred::Yes, false)
}
