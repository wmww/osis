//! Atomic apply (spec/commits.md §4): one store transaction joins every valid delta of a commit
//! after its membership records reach perm, records deaths, receipts, expiry and purges, and
//! re-judges held deltas when the held set changed; events go out after it is durable.

use super::validity;
use crate::engine::{Core, Meta, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Cause, Event, Origin};
use osis_commit::{CommitBlob, Decoded, Form, Header};
use osis_core::{Ak, CommitId, CreationRecord, Tid, Value, WallMs};
use osis_crdt::{Changes, Fragment, Source};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
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
        core.by_aspect.entry((a.tid, a.ak.clone())).or_default().insert((h.ts, *id));
        if h.form == Form::Node && h.kind.has_own_writes() && a.lo < a.hi {
            core.ranges.entry((a.tid, a.ak.clone(), h.author)).or_default().insert(a.lo, (a.hi, *id));
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
pub(crate) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, delta: Fragment) -> Result<Changes> {
    tx.load(tid, ak)?;
    let mut st = tx.core.states.get(&(*tid, ak.clone())).cloned().flatten().unwrap_or_default();
    let ch = st.join(delta);
    strip_valueless(tx.core, tid, ak, &mut st);
    if ch.is_changed() || !ch.deaths().is_empty() {
        tx.set_state(tid, ak, Some(st), Shred::No, false)?;
    }
    Ok(ch)
}

pub(crate) fn strip_valueless(core: &Core, tid: &Tid, ak: &Ak, st: &mut Fragment) {
    if let Some(v) = core.valueless.get(&(*tid, ak.clone()))
        && !v.is_empty()
    {
        st.strip(&|d| v.iter().any(|o| o.owns(d)));
    }
}

/// Applies a verified commit (`parts` decoded) in this transaction.
pub(crate) fn apply_verified(tx: &mut Tx<'_>, blob: &CommitBlob, parts: Vec<(usize, usize, Decoded)>, origin: Origin, received: WallMs) -> Result<()> {
    let id = blob.id();
    let h = Arc::new(blob.header.clone());
    tx.core.hlc.observe(h.ts);
    tx.txn.put_local(records::HLC, &tx.core.hlc.last().to_u64().to_be_bytes(), Shred::No)?;

    // creation records first: perm and dedup secrets need them
    let mut held_changed = false;
    for (ai, _, d) in &parts {
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
            held_changed = true;
        }
    }
    if h.kind.is_membership() {
        validity::add_membership(tx.core, &h, &id, &parts);
        held_changed = true;
    }
    if held_changed {
        tx.core.timelines.update(&tx.core.held);
    }

    // overlapping node-form counters void both commits
    let ov = overlaps(tx.core, &id, &h);
    if !ov.is_empty() {
        for c in ov.iter().chain(std::iter::once(&id)) {
            tx.core.void.insert(*c);
            tx.txn.put_local(&[records::VOID, &c.0[..]].concat(), &[], Shred::No)?;
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

    // receipt record (spec/permissions.md §5.1; spec/crdt.md §8)
    super::receipt::record(tx, &h, &id, &parts, received)?;

    if origin == Origin::Local && h.kind == osis_commit::Kind::Content {
        for a in h.aspects.iter() {
            crate::undo::remember(tx, &id, &a.tid, &a.ak)?;
        }
    }
    let mut changed: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(ai) else { continue };
        if !valid.get(ai).copied().unwrap_or(false) {
            continue;
        }
        let (f, _) = fragment(d);
        let ch = join_into_state(tx, &a.tid, &a.ak, f)?;
        if ch.is_changed() {
            changed.insert((a.tid, a.ak.clone()));
        }
        crate::retention::note_deaths(tx, &a.tid, &a.ak, ch.deaths())?;
    }
    tx.put_commit(&id, blob, &meta, Shred::No)?;
    crate::retention::on_apply(tx, &id, &mut changed)?;

    for (tid, ak) in &changed {
        observe_state(tx, tid, ak)?;
    }
    if changed.iter().any(|(_, ak)| ak.as_str() == "/group") {
        recompute_groups(tx.core);
    }
    let mut flipped = Vec::new();
    if held_changed {
        flipped = validity::rejudge_all(tx, true)?;
        for (tid, ak) in &flipped {
            observe_state(tx, tid, ak)?;
        }
    }
    let rosters: BTreeSet<Tid> = if h.kind.is_membership() { h.aspects.iter().filter(|a| a.ak.as_str() == "/members" || a.ak.as_str() == "/tenures").map(|a| a.tid).collect() } else { BTreeSet::new() };
    tx.core.events.queue(Event::Applied { id, origin, author: h.author, actor: h.actor, ts: h.ts, received, changed: changed.into_iter().collect() });
    if !flipped.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Validity, changed: flipped });
    }
    for thing in rosters {
        tx.core.events.queue(Event::Roster { thing });
    }
    Ok(())
}

/// Joins deltas of an applied commit that arrived later (spec/commits.md §4).
pub(crate) fn join_late(tx: &mut Tx<'_>, id: &CommitId, merged: &CommitBlob, parts: Vec<(usize, usize, Decoded)>) -> Result<()> {
    let meta = tx.core.commits.get(id).cloned().ok_or(Error::Corrupt("commit index"))?;
    let h = meta.header.clone();
    let mut changed = BTreeSet::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(ai) else { continue };
        if !meta.valid.get(ai).copied().unwrap_or(false) {
            continue;
        }
        let (f, _) = fragment(d);
        let ch = join_into_state(tx, &a.tid, &a.ak, f)?;
        if ch.is_changed() {
            changed.insert((a.tid, a.ak.clone()));
        }
        crate::retention::note_deaths(tx, &a.tid, &a.ak, ch.deaths())?;
    }
    tx.put_commit(id, merged, &meta, Shred::No)?;
    for (tid, ak) in &changed {
        observe_state(tx, tid, ak)?;
    }
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LateDelta, changed: changed.into_iter().collect() });
    }
    Ok(())
}

/// Keeps the indexes derived from states current: secrets opened from `/secrets`, own keys
/// from `/keys`, the `/was` and `/moved` indexes, group definitions.
pub(crate) fn observe_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let v = tx.state(tid, ak)?.and_then(Fragment::read);
    match ak.as_str() {
        "/secrets" => {
            if let Some(s) = v.as_ref().and_then(crate::engine::secrets::secrets_value)
                && tx.core.ingest_secrets(tid, &s)
                && let Some(e) = tx.core.secrets.get(tid)
            {
                let b = crate::engine::secrets::encode_epochs(e);
                tx.txn.put_local(&[b"k/".as_slice(), tid.as_bytes()].concat(), &b, Shred::Yes)?;
            }
        }
        "/keys" => {
            if let Some(k) = v.as_ref().and_then(crate::engine::secrets::keys_value) {
                tx.core.observe_keys(tid, &k);
            }
        }
        "/was" => {
            for s in tx.core.was.values_mut() {
                s.remove(tid);
            }
            if let Some(Value::Tid(t)) = v {
                tx.core.was.entry(t).or_default().insert(*tid);
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
        "/group" => {
            let g = v.and_then(|v| osis_schema::AspectKey::decode(&osis_schema::core_types::GROUP, &v).ok());
            match g {
                Some(g) => {
                    tx.core.group_defs.insert(*tid, (g.items, g.subgroups));
                }
                None => {
                    tx.core.group_defs.remove(tid);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `/groups` (spec/data-model.md §8): every group whose items, directly or through
/// subgroups (cycles allowed), contain the thing.
pub(crate) fn recompute_groups(core: &mut Core) {
    let mut out: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
    for g in core.group_defs.keys() {
        let mut seen: BTreeSet<Tid> = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some((items, subs)) = core.group_defs.get(&x) {
                for i in items {
                    out.entry(*i).or_default().insert(*g);
                }
                stack.extend(subs.iter().copied());
            }
        }
    }
    core.groups = out;
}

/// Rebuilds `(tid, ak)` from its held bodies after validity changed (spec/crdt.md §4.6): the
/// join of every held body and the current state (a snapshot it holds) without the writes of
/// sources with an invalid delta here, then those sources' valid deltas joined back.
pub(crate) fn rebuild(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<(osis_core::Ts, CommitId)> = tx.core.by_aspect.get(&(*tid, ak.clone())).map(|s| s.iter().copied().collect()).unwrap_or_default();
    let mut bodies: Vec<(bool, Option<Source>, Fragment)> = Vec::new();
    let mut bad: BTreeSet<Source> = BTreeSet::new();
    for (_, c) in held {
        let Some(m) = tx.core.commits.get(&c).cloned() else { continue };
        let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { continue };
        let ok = m.valid.get(ai).copied().unwrap_or(false);
        let own = m.header.kind.has_own_writes().then(|| match m.header.form {
            Form::Node => Source::node(m.header.author),
            Form::Commit => Source::commit(c),
        });
        if !ok && let Some(s) = &own {
            bad.insert(s.clone());
        }
        for d in super::held_parts(tx, &c, ai)? {
            bodies.push((ok, own.clone(), fragment(d).0));
        }
    }
    tx.load(tid, ak)?;
    let current = tx.core.states.get(&(*tid, ak.clone())).cloned().flatten();
    let is_bad = |s: &Source| bad.contains(s.author());
    let mut all: Vec<Fragment> = current.into_iter().collect();
    all.extend(bodies.iter().filter(|b| b.0 || b.1.is_none()).map(|b| b.2.clone()));
    let mut st = osis_crdt::unmerge(all, &is_bad);
    for (ok, own, f) in bodies {
        if ok && own.as_ref().is_some_and(|s| bad.contains(s)) {
            st.join(f);
        }
    }
    strip_valueless(tx.core, tid, ak, &mut st);
    tx.set_state(tid, ak, Some(st), Shred::Yes, false)
}
