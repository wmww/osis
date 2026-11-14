//! Retention (spec/commits.md §5–§6; spec/crdt.md §4.7, §4.8, §8). Principle: every drop that
//! is not expiry or purge is a right holder's valid covering compaction snapshot; a node without
//! write drops nothing on its own but expired content. Here: when a body was replaced, judged from
//! the held set when asked (for keep-for-D, `bounds`), purge on replace (`replace`: the replacing writer's cover, covered
//! bodies dropped at every node), expiry at T (the body kept as its leftover), purge requests
//! judged by perm at the request's time (also against deltas arriving later), compaction
//! snapshots and the covered test. node-sync judges what to delete at hosts and what to re-snapshot from the commit
//! index (parts with no body, `Meta::body_gone`, `covered`), so no queue is kept here.
//!
//! Here: bodies dropping and coming back, leftovers, what runs on apply and by timer.
//! `purge`: purge requests. `pending`: parts held while their commit waits. `snapshot`: compaction.
//! `history`: the one door to what history keeps of a body. `bounds`: a body's keep bound, when
//! it was replaced, and liveness. `replace`: purge on
//! replace. `leftover`: the rows.
//!
//! Each part of a body is judged on its own: its keep bound by its own aspect (`bounds::part_keep`),
//! whether it is live by its own writes (`replace::replaced`, `bounds::live_keep`); a part drops alone, and the blob is
//! rewritten without it (`drop_part_for`).

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Core, DropFor, Dropped, Engine, Hold, Missing, Owned, Tx};
use crate::error::{Error, Result};
use crate::events::{Cause, Event};
use osis_commit::{Header, Kind};
use osis_base::{Ak, CommitId, Tid};
use osis_crdt::Fragment;
use osis_schema::core_types::is_role_class;
use osis_store::Shred;
use std::collections::BTreeSet;

pub(crate) mod bounds;
pub mod compact;
pub(crate) mod history;
pub(crate) mod leaving;
pub(crate) mod leftover;
mod pending;
mod purge;
pub(crate) mod replace;
pub(crate) mod snapshot;
#[cfg(test)]
mod oracle;
pub(crate) mod destroy;
pub use destroy::{End, Minting, Standing};
pub mod lifetimes;
pub(crate) mod forget;
pub mod freed;
pub(crate) mod memory;
pub(crate) use snapshot::{reaches, snapshot_state};
#[cfg(test)]
pub(crate) use snapshot::write_snapshot;
pub mod suspect;

pub(crate) use replace::settle_none;
pub(crate) use pending::{emptied, forget_joined_leftovers, forget_waiting_leftovers, pending_drops, pending_expired, stripped_joined, waiting_stripped};
use pending::{purge_pending, strip_pending};
pub(crate) use purge::{check_request, known_purged, lasting, load_owed, note_requests, purged_aspects, purged_by, rejudge_purges, requests_resting_on};
pub(crate) use snapshot::covered;
pub(crate) use bounds::{Killed, mark_killed, mark_bounded};

const T_EXPIRY: u8 = 1;
/// A purge-on-replace body kept to its commit's purge floor: judged again then (`replace`).
const T_FLOOR: u8 = 2;
/// A part kept by a purge request's header (its commit's purge floor, a purged fire's tombstone):
/// a signal's body goes then (`signal_bound`); a value part is told at its floor, armed when it
/// arrives (`listing::kept_passed`). Leaving history by the timeline alone is `leaving`'s one
/// timer per aspect.
pub(crate) const T_KEPT: u8 = 3;

/// A signal delta's keep bound, wall ms (spec/commits.md §5 Signals): any body's keep at least
/// (`bounds::part_keep`), replaced when written; `None`: kept for good.
pub(crate) fn signal_bound(core: &Core, h: &Header, a: &osis_commit::AspectEntry) -> Option<u64> {
    let t = bounds::kept_until(core, h, a, Some(h.ts.wall_ms().0));
    (t < osis_commit::FOREVER).then_some(t)
}

/// Whether part `ai` of `h` is a signal's past its keep bound at wall ms `now` (spec/commits.md §5
/// Signals): past every bound, so no read shows it, no copy of it is taken and nothing makes it
/// missing again (fetched, or a suspect flag for it).
pub(crate) fn past_signal_bound(core: &Core, h: &Header, ai: usize, now: u64) -> bool {
    h.aspects.get(ai).filter(|a| a.ak.signal()).and_then(|a| signal_bound(core, h, a)).is_some_and(|t| t <= now)
}

/// A non-`Derived` source's bytes (its length tells the kind).
fn source_bytes(src: &osis_crdt::Source) -> Vec<u8> {
    match src.kind() {
        osis_crdt::SourceKind::Session(s) => s.to_bytes().to_vec(),
        osis_crdt::SourceKind::Commit(c) => c.0.to_vec(),
        osis_crdt::SourceKind::Derived(_) => Vec::new(),
    }
}

pub(crate) fn read_source(r: &mut Rd<'_>) -> Result<osis_crdt::Source> {
    Ok(match r.u8()? {
        31 => osis_crdt::Source::session(osis_crdt::Session::from_bytes(&r.arr()?)),
        32 => osis_crdt::Source::commit(CommitId(r.arr()?)),
        _ => return Err(crate::error::Error::Corrupt("owned source")),
    })
}

/// `src` (non-`Derived`) as its length and bytes.
pub(crate) fn write_source(w: Wr, src: &osis_crdt::Source) -> Wr {
    let b = source_bytes(src);
    w.u8(b.len() as u8).raw(&b)
}

pub(crate) fn encode_owned(v: &[Owned]) -> Vec<u8> {
    let mut w = Wr::new().u32(v.len() as u32);
    for o in v {
        w = match o {
            Owned::Range { src, lo, hi } => write_source(w.u8(0), src).u64(*lo).u64(*hi),
            Owned::Commit(c) => w.u8(1).raw(&c.0),
            Owned::Dots { src, ctrs } => {
                let mut w = write_source(w.u8(2), src).u32(ctrs.len() as u32);
                for c in ctrs {
                    w = w.u64(*c);
                }
                w
            }
        };
    }
    w.take()
}

pub(crate) fn decode_owned(b: &[u8]) -> Result<Vec<Owned>> {
    let mut r = Rd::new(b);
    let mut out = Vec::new();
    for _ in 0..r.u32()? {
        out.push(match r.u8()? {
            0 => Owned::Range { src: read_source(&mut r)?, lo: r.u64()?, hi: r.u64()? },
            1 => Owned::Commit(CommitId(r.arr()?)),
            _ => {
                let src = read_source(&mut r)?;
                let mut ctrs = Vec::new();
                for _ in 0..r.u32()? {
                    ctrs.push(r.u64()?);
                }
                Owned::Dots { src, ctrs }
            }
        });
    }
    r.end()?;
    Ok(out)
}

/// The aspect index of `(tid, ak)` in known commit `c`.
fn aspect_index(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    core.ix.commits.get(c)?.aspect(tid, ak)
}

/// The aspect index of `(tid, ak)` in known commit `c` and its header (`UnknownCommit`: not
/// known with that aspect).
fn known_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<(usize, crate::engine::LazyHeader)> {
    let m = core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?;
    Ok((m.aspect(tid, ak).ok_or(Error::UnknownCommit(*c))?, m.header.clone()))
}

/// Whether the bodies of `(tid, ak)` have a relative keep bound (spec/commits.md §5): only then is
/// when a body was replaced asked (`bounds::part_replaced_at`).
pub(crate) fn bounded(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    history::of(core, tid, ak).dated()
}

/// The aspect index of `(tid, ak)` in held commit `c`, if that part is held (`Meta::holds`: a
/// late part still to arrive is not).
pub(crate) fn held_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    let m = core.ix.commits.get(c)?;
    m.aspect(tid, ak).filter(|ai| m.holds(*ai))
}

/// Drops the delta of aspect `ai` of `c` from its body (spec/commits.md §5): the commit is kept
/// without it (same header), the aspect rebuilt
/// shredded (node-sync deletes it at hosts, judged from
/// `Meta::body_gone`). A bare leftover stays for un-merge (spec/crdt.md §4.6) but past its
/// expiry, when a held snapshot covers it (`drops_as_covered`); one holding values
/// (`Hold::Leftover::valued`) is dropped as a whole body.
pub(crate) fn drop_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    drop_part_for(tx, c, ai, DropFor::Other)
}

/// Whether a cover may drop part `ai` of `m` (spec/commits.md §5): not dropped, and a body, a
/// leftover holding values (`Hold::Leftover::valued`) or a bare leftover past its expiry (value-less for
/// good, its writes in the coverer). A purge's bare leftover stays: the purge may fall and its
/// values come back. The one judgment of which parts a cover drops: the drop (`drop_part_for`,
/// `Engine::droppable_if_covered`) and the compaction trigger's count (`compact::candidates`)
/// both ask it, so the trigger never counts a body its own snapshot leaves.
pub(crate) fn drops_as_covered(m: &crate::engine::Meta, ai: usize, now: u64) -> bool {
    !m.is_dropped(ai) && (!m.bare(ai) || m.header.expires.is_some_and(|t| t <= now))
}

/// Whether this node keeps held part `(tid, ak)` of `c` under cover `s` though `s` covers it
/// (spec/sync-compaction.md §1 own bodies): a delta it wrote none of whose writes is dead drops only under
/// a cover it wrote. The one judgment: node-sync's covered drops and the compaction trigger's
/// count (`compact::covered_already`) both ask it.
pub(crate) fn own_kept_under(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    let own = |x: &CommitId| tx.core.ix.commits.get(x).is_some_and(|m| m.origin == crate::events::Origin::Local);
    if !own(c) || own(s) || tx.core.ix.commits.get(c).is_none_or(|m| m.view.kind.is_compaction()) {
        return Ok(false);
    }
    // as `Engine::replaced`: a part not held, or bare, is never replaced
    let Some(ai) = held_part(tx.core, c, tid, ak) else { return Ok(true) };
    if tx.core.ix.commits.get(c).is_none_or(|m| m.bare(ai)) {
        return Ok(true);
    }
    Ok(!replace::replaced(tx, c, ai, tid, ak)?)
}

/// `drop_part`, saying why.
fn drop_part_for(tx: &mut Tx<'_>, c: &CommitId, ai: usize, why: DropFor) -> Result<()> {
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    // a part judged invalid drops as invalid, whatever else asks (spec/permissions.md §6): it
    // stays at hosts and comes back once valid. As covered, a memory one would be forgotten,
    // and a holder judging it valid again would find it gone for good
    let why = if why == DropFor::Cover && goes_invalid(tx.core, &m, ai) { DropFor::Invalid } else { why };
    let invalid = why == DropFor::Invalid;
    // a bare leftover stays but past its expiry under a cover, or while invalid: then it gives
    // nothing; a signal's gives nothing ever, and goes at its keep bound
    let leftover = invalid || why == DropFor::Destroyed || why == DropFor::Cover && drops_as_covered(&m, ai, tx.now().0) || a.ak.signal();
    if m.is_dropped(ai) || (m.bare(ai) && !leftover) {
        return Ok(());
    }
    // its keep-at-least bound, judged while it is held: hosts delete it `MAX_DRIFT` past
    let keep = if why == DropFor::Cover { bounds::part_keep(tx, c, &a.tid, &a.ak)? } else { 0 };
    let hosts_from = if keep == 0 { 0 } else { keep.saturating_add(osis_base::format::MAX_DRIFT_MS) };
    // a setting not held is in no timeline (spec/commits.md §5 In force)
    if a.ak.as_str() == osis_commit::retention::RETENTION {
        let mut settings = tx.core.ix.retention.get(&a.tid).cloned().unwrap_or_default();
        settings.retain(|x| x.0.commit != *c);
        if settings.is_empty() {
            tx.core.ix.retention.remove(&a.tid);
        } else {
            tx.core.ix.retention.insert(a.tid, settings);
        }
        tx.core.settings_due.insert(a.tid);
    }
    let k = (a.tid, a.ak.clone());
    // a stripped part's body is its leftover: read below as the held body, forgotten after
    let stripped = m.stripped(ai);
    let snapshot = m.header.kind.is_compaction();
    // the held valid snapshots covering it: their copies of its writes stay its writes
    // (an invalid body's writes are none of the state's, whatever carries copies of them)
    // (a plain commit counts only as its author's own whole replace: `snapshot::own_covers`)
    let snaps: Vec<CommitId> = if invalid || why == DropFor::Destroyed { Vec::new() } else { tx.core.ix.snapshots.get(&k).into_iter().flatten().map(|x| x.1).chain(snapshot::own_covers(tx.core, c, &a.tid, &a.ak)).filter(|s| s != c).collect() };
    let mut covered_by = BTreeSet::new();
    let own_cover = m.whole(ai);
    for s in snaps {
        if covered(tx, &s, c, &a.tid, &a.ak)? == Some(true) {
            covered_by.insert(s);
        }
    }
    // as covered only under a coverer, which carries its writes (an expired leftover too)
    if why == DropFor::Cover && covered_by.is_empty() {
        return Ok(());
    }
    // a snapshot dropped other than as covered still settles suspect flags of what it was stamped
    // after (`receipt::settled`), held when it dropped or not (a part missing, as after a purge
    // fell, needs no body for that: its header says it all); a coverer, stamped no earlier,
    // does for a covered one; an invalid one settles nothing
    let stands_in = snapshot && why == DropFor::Other;
    let (role, overreach) = (tx.core.ix.rotation_role.get(&(*c, ai)).copied(), tx.core.ix.grant_overreach.contains(&(*c, ai)));
    // a role-class body whole: what keys noted from it (`keys::keysets_of`, `forget_dropped`)
    let role_bodies: Vec<Fragment> = if is_role_class(a.ak.as_str()) { crate::apply::held_fragment(tx, c, ai)?.into_iter().collect() } else { Vec::new() };
    let keysets = crate::apply::keys::keysets_of(&m.header, ai, &role_bodies);
    let shown = tx.core.ix.shown.get(&(*c, ai)).cloned();
    // what it links joins its thing's freed set first; an invalid body's stays at hosts with its
    // pieces, a refetch source (spec/permissions.md §6)
    if !invalid {
        freed::free_part(tx, c, ai)?;
    }
    if stripped {
        leftover::remove(tx, &a.tid, &a.ak, c, ai)?;
    }
    // a part missing (again, `uncover`) and dropped is dropped, as an open reads it: received
    m.set_hold(ai, Hold::Dropped(Dropped { covered_by, why, hosts_from, stands_in, role, overreach, keysets, shown, superseded_by: BTreeSet::new() }));
    if osis_schema::core_types::is_addenda(a.ak.as_str()) {
        crate::apply::validity::forget_addendum_body(tx.core, c, &a.tid);
    }
    if let Some(blob) = tx.get_commit(c)? {
        let rest = osis_commit::rewrite(&blob, |x| x == ai);
        tx.put_commit(c, &rest, &m, Shred::Yes, None)?;
    }
    let header = m.header.clone();
    tx.core.put_meta(*c, m);
    // a part not held is no cover candidate (`Core::cover_judged_on`)
    if let Some(s) = tx.core.cover_candidates.get_mut(&k) {
        s.remove(c);
    }
    // a role commit's `keys.0` part on the thing, kept for good while this part was held
    // (`bounds::judged_by_held`), has its own bound again: a cover candidate again
    if header.kind == osis_commit::Kind::Role && a.ak.as_str() == "secrets.0" {
        let keys = osis_schema::core_types::KEYS.name();
        if held_part(tx.core, c, &a.tid, &keys).is_some() {
            tx.core.cover_candidates.entry((a.tid, keys)).or_default().insert(*c);
        }
    }
    crate::apply::note_stands_in(tx.core, c);
    crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, c);
    crate::apply::keys::forget_dropped(tx, &header, ai, &role_bodies)?;
    // a snapshot dropped other than as covered carries nothing: the parts dropped under its
    // cover alone are missing again
    let uncovered = (stands_in || (own_cover && why != DropFor::Cover)) && uncover(tx, &a.tid, &a.ak)?;
    // the one path (issues/drop-rejoin-robust.md item 1): the aspect is rebuilt from what is
    // held now, shredded (every local copy of the body goes,
    // spec/commits.md §5). A valid snapshot dropped vouches no more for invalid deltas' writes
    // it carried (spec/permissions.md §5.2). A destroyed thing's aspects rebuild once, after its last part (`retention::destroy`).
    // An invalid part gave nothing (`apply::rebuilt`): its drop leaves the state as it is
    // unless it uncovered a part.
    if why == DropFor::Destroyed || (invalid && !uncovered) {
        return Ok(());
    }
    crate::apply::rebuild(tx, &a.tid, &a.ak)
}

/// The snapshots that covered dropped part `ai` of `c` when it dropped, or covered such a
/// coverer dropped in turn, and so on (`Dropped::covered_by`).
pub(crate) fn coverers(core: &Core, c: &CommitId, ai: usize) -> Vec<CommitId> {
    let Some(a) = core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)) else { return Vec::new() };
    let (tid, ak) = (a.tid, a.ak.clone());
    let direct = |x: &CommitId| -> Vec<CommitId> {
        let Some(m) = core.ix.commits.get(x) else { return Vec::new() };
        m.aspect(&tid, &ak).and_then(|xai| m.dropped(xai)).map(|d| d.covered_by.iter().copied().collect()).unwrap_or_default()
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut todo = direct(c);
    while let Some(x) = todo.pop() {
        out.push(x);
        if seen.insert(x) {
            todo.extend(direct(&x));
        }
    }
    out
}

/// Parts on `(tid, ak)` dropped as covered that no coverer carries any more (no coverer, or
/// one covering a coverer and so on, is held and valid: each turned invalid, went missing or was
/// dropped other than as covered, by a purge) are missing again (spec/permissions.md §5.2): they
/// give nothing, as at a node that never held them, until the body arrives again (a node still
/// holding it finds it uncovered and re-uploads it, spec/sync-judgement.md §2; sync fetches it again). The caller rebuilds the aspect. Whether any part went missing.
pub(crate) fn uncover(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<bool> {
    let core = &*tx.core;
    let carries = |s: &CommitId| {
        let Some(m) = core.ix.commits.get(s) else { return false };
        let Some(ai) = m.aspect(tid, ak) else { return false };
        m.valid_at(ai) && !m.is_dropped(ai) && !m.missing(ai)
    };
    // the cover test that dropped it (`snapshot::covered`), on what is held now: a carrying
    // snapshot, or two valid held own replaces later than it (any two, recorded or not)
    let still = |c: &CommitId, ai: usize| {
        let snapshot = coverers(core, c, ai).iter().any(|s| carries(s) && core.ix.commits.get(s).is_some_and(|m| m.view.kind.is_compaction()));
        snapshot || snapshot::own_covers(core, c, tid, ak).len() >= 2
    };
    let mut lost = Vec::new();
    for (_, c) in core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        if m.dropped(ai).is_some_and(|d| d.as_cover()) && !still(c, ai) {
            lost.push((*c, ai));
        }
    }
    let any = !lost.is_empty();
    if any {
        // until each comes back, this node may read less than one that kept it
        suspect::raise(tx, tid, ak, suspect::Why::Uncovered, &lost)?;
    }
    for (c, ai) in lost {
        // dropped as covered: nothing in `dropped_snapshots` (`Dropped::stands_in`);
        // the epochs it introduced or held go too (`keys::rebuild_keysets` below)
        reopen_to_fetch(tx, &c, ai)?;
    }
    if any && ak.as_str() == "keys.0" {
        crate::apply::keys::rebuild_keysets(tx, &BTreeSet::from([*tid]))?;
    }
    Ok(any)
}

/// Whether held part `ai` of `m` goes once judged invalid (spec/permissions.md §6): any but a
/// role commit's (the role timeline and the possible holders read every held edge write, of any
/// validity, spec/permissions.md §5.1, spec/commits.md §4; a label holds and promotes the commit
/// whole, spec/sync-inbox.md §4) and a part of this node's own commit (its user is told the write was
/// refused and may write it again from it, `DiagnosticKind::OwnWriteInvalid`). A memory part
/// goes as a durable one: its commit stays known while an entry of it is (`forgettable`).
fn goes_invalid(core: &Core, m: &crate::engine::Meta, ai: usize) -> bool {
    !m.valid_at(ai) && m.holds(ai) && Some(m.view.author) != core.me() && !m.view.kind.is_role()
}

/// Whether commit `m` holds no part and is known only for a part dropped while invalid (its
/// header, so a copy is not taken while it stays invalid and valid again it is fetched,
/// `valid_again`) or, memory class, one reopened to be fetched (`Missing::ToFetch`): durable and
/// memory alike, node-sync forgets it once it knows no entry of it (`Engine::forgettable`,
/// spec/permissions.md §6).
pub(crate) fn kept_invalid(m: &crate::engine::Meta) -> bool {
    (0..m.view.aspects.len()).all(|ai| !m.holds(ai)) && (0..m.view.aspects.len()).any(|ai| m.missing_as(ai) == Some(Missing::ToFetch) || m.dropped_invalid(ai))
}

/// Whether content commit `c` holds nothing but purged leftovers, one at least (each held
/// value-less for a purge request, `held_purged`), no permanent delta (a lasting header stays,
/// spec/commits.md §5) and no `created.0` delta (a thing's first commit stays): kept only so that
/// a fall of the request finds its writes again (`unstrip`) and a copy is fetched, as one
/// `kept_invalid` is. Either class: node-sync forgets it by the same rule
/// (`Engine::forgettable`); a memory one is charged its own bytes until then.
pub(crate) fn kept_purged(core: &Core, c: &CommitId, m: &crate::engine::Meta, now: u64) -> bool {
    if m.stripped_parts().next().is_none() || m.view.purges || m.view.kind != Kind::Content || core.ix.pending.contains_key(c) {
        return false;
    }
    let purged = |ai: usize| m.bare(ai) && m.header.aspects.get(ai).is_some_and(|a| held_purged(core, c, &a.tid, &a.ak, ai, now));
    let n = m.view.aspects.len();
    // a thing's first commit stays (its `created.0` part never drops)
    let kept = |a: &osis_commit::AspectEntry| a.ak.as_str() == osis_commit::retention::CREATED || history::permanent(core, &m.header, a, now);
    (0..n).any(purged) && (0..n).all(|ai| !m.holds(ai) || purged(ai)) && !m.header.aspects.iter().any(kept)
}

/// Drops every held part judged invalid in this transaction (`Core::drop_due`) but those
/// `goes_invalid` keeps: its writes are none of the state's, so no read changes and no aspect is
/// rebuilt (spec/crdt.md §4.6, spec/permissions.md §5.2). Run at the transaction's end, after
/// this node's addenda (a witness lists what it received, `flows::addenda`). A memory
/// transaction writes no durable row: it drops memory parts only.
pub(crate) fn drop_invalid(tx: &mut Tx<'_>) -> Result<()> {
    let memory_only = tx.txn.is_memory();
    while !tx.core.drop_due.is_empty() {
        let mut due = std::mem::take(&mut tx.core.drop_due);
        if memory_only {
            due.retain(|c| tx.core.ix.commits.get(c).is_some_and(|m| m.view.memory));
        }
        crate::apply::run_batched(tx, |tx| {
            for c in &due {
                let Some(m) = tx.core.ix.commits.get(c) else { continue };
                let parts: Vec<usize> = (0..m.view.aspects.len()).filter(|ai| goes_invalid(tx.core, m, *ai)).collect();
                let memory = m.view.memory;
                tx.in_class(memory, |tx| {
                    for ai in parts {
                        drop_part_for(tx, c, ai, DropFor::Invalid)?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        // a judgment the dropped body fed is kept with it (`Dropped`), but a keyset rebuild
        // marks its commits for judging again: nothing flips, yet it is judged
        crate::apply::rejudged(tx, false)?;
    }
    Ok(())
}

/// The things whose `retention^.0` settings arrived, flipped or dropped this transaction
/// (`Core::settings_due`): what their timelines judge is judged again (spec/commits.md §5
/// Convergence), from what is held, per aspect of the thing: the bodies that leave history or come
/// back by the new timeline are told and marked (`leaving::settings_changed`: O(those bodies), no
/// body read), and purge on replace is settled where some setting asks for it (`settle_none`: a
/// setting arriving can make a writer owe a cover).
pub(crate) fn settings_changed(tx: &mut Tx<'_>) -> Result<()> {
    while let Some(t) = tx.core.settings_due.pop_first() {
        let aspects: Vec<Ak> = tx.core.ix.by_aspect.range((t, Ak::MIN)..).take_while(|((x, _), _)| *x == t).map(|((_, a), _)| a.clone()).collect();
        for ak in aspects {
            if osis_commit::retention::fixed_retention(ak.as_str()).is_some() {
                continue;
            }
            let kept = history::of(tx.core, &t, &ak);
            if kept.purges() {
                tx.core.none_due.insert((t, ak.clone()));
            }
            // a live body kept for good may not be now (spec/commits.md §5 Kept while live): the
            // aspect's held deltas are cover candidates again, and the trigger weighs it
            let live = kept.live_until();
            if live > tx.now().0 {
                crate::retention::compact::Trigger::live_until(tx, (t, ak.clone()), live);
            }
            if live != osis_commit::retention::NEVER {
                let k = (t, ak.clone());
                let on: Vec<CommitId> = tx.core.durable_on(&k).filter(|c| tx.core.ix.commits.get(c).is_some_and(|m| !m.view.kind.is_compaction())).collect();
                if !on.is_empty() {
                    tx.core.cover_candidates.entry(k.clone()).or_default().extend(on);
                }
                tx.core.compaction.weigh(k);
            }
            leaving::settings_changed(tx, &t, &ak)?;
        }
    }
    Ok(())
}

/// The parts `parts` dropped while invalid that are valid now are missing again (spec/permissions.md
/// §6): they give nothing until the body arrives again, as at a node that never received it
/// (sync fetches it from any holder; with none it stays gone at every
/// node alike). Until then this node may read less than one that kept it (its author). A signal's
/// past its keep bound stays dropped (`past_signal_bound`).
pub(crate) fn valid_again(tx: &mut Tx<'_>, parts: &[(CommitId, usize)]) -> Result<()> {
    let now = tx.now().0;
    let mut by_aspect: std::collections::BTreeMap<(Tid, Ak), Vec<(CommitId, usize)>> = std::collections::BTreeMap::new();
    for (c, ai) in parts {
        if let Some(a) = tx.core.ix.commits.get(c).filter(|m| m.dropped_invalid(*ai) && m.valid_at(*ai) && !past_signal_bound(tx.core, &m.header, *ai, now)).and_then(|m| m.view.aspects.get(*ai)) {
            by_aspect.entry((a.tid, a.ak.clone())).or_default().push((*c, *ai));
        }
    }
    for ((tid, ak), back) in by_aspect {
        suspect::raise(tx, &tid, &ak, suspect::Why::Uncovered, &back)?;
        for (c, ai) in back {
            reopen_to_fetch(tx, &c, ai)?;
        }
    }
    Ok(())
}

/// Makes dropped part `ai` of `c` missing, as at a node that never received it: what its body
/// judged or gave goes too (`Dropped::role`; the header's one-delta rule for `secrets.0` stays,
/// `validity::note_required`). Its meta after.
fn reopen(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<crate::engine::Meta>> {
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    reopen_in(tx, c, &mut m, ai);
    tx.in_class(m.view.memory, |tx| {
        if let Some(blob) = tx.get_commit(c)? {
            tx.put_commit(c, &blob, &m, Shred::No, None)?;
        }
        Ok(())
    })?;
    tx.core.put_meta(*c, m.clone());
    Ok(Some(m))
}

/// `reopen` on `m`, the caller writing it.
pub(super) fn reopen_in(tx: &mut Tx<'_>, c: &CommitId, m: &mut crate::engine::Meta, ai: usize) {
    tx.core.touch();
    // missing again, a dropped snapshot stands in no more (`Dropped::stands_in`)
    if m.dropped(ai).is_some_and(|d| d.stands_in)
        && let Some(a) = m.view.aspects.get(ai)
    {
        tx.core.ix.dropped_snapshots.remove(&(a.tid, a.ak.clone()), c);
    }
    m.set_hold(ai, Hold::Missing(Missing::Plain));
    crate::apply::unjudge_part(tx.core, c, ai);
    // those are inputs of its judgment (`validity::rejudge_all` judges it again)
    tx.core.stale_commits.insert(*c);
}

/// `reopen`, and sync fetches it again. A memory commit stays known
/// while the part is to come (`Missing::ToFetch`).
fn reopen_to_fetch(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<crate::engine::Meta>> {
    let mut m = reopen(tx, c, ai)?;
    if let Some(m) = m.as_mut().filter(|m| m.view.memory) {
        m.set_hold(ai, Hold::Missing(Missing::ToFetch));
        tx.core.put_meta(*c, m.clone());
    }
    Ok(m)
}

/// Whether a late copy of part `ai` of `c`, dropped or stripped, joins (`reopen_late` makes
/// way for it). A body dropped other than as covered (one missing when purged) counts as never
/// received (spec/commits.md §5): its copy joins and is judged again (`on_late`: stripped if
/// expired or purged), so nodes holding the same bodies read alike. A leftover is replaced only by a valued copy: one of a delta no longer held
/// value-less here (an expired delta's never comes back; its purge's fall made it missing
/// already, `rejudge_purges`); else the copy is the leftover and brings nothing. One dropped
/// as covered joins only once no cover carries it
/// (`uncover` makes it missing), one dropped while invalid only once valid (`valid_again`). A memory part dropped other than as covered and held value-less by
/// no request (superseded, its thing deleted here) vanished whole and stays gone
/// (`memory::forget_if_spent` forgets a spent commit); one missing when purged is a durable one's
/// case. A signal's part past its keep bound is past every bound: no copy is taken
/// (spec/commits.md §5 Signals), so a peer still holding it resends nothing that sticks.
pub(crate) fn takes_late(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    if past_signal_bound(tx.core, &m.header, ai, tx.now().0) {
        return Ok(false);
    }
    if m.stripped(ai) {
        return Ok(gone_of(tx.core, &m.header, c, ai).is_empty());
    }
    let gone = m.dropped(ai).is_some_and(|d| matches!(d.why, DropFor::Other | DropFor::Destroyed));
    Ok(gone && (!m.view.memory || valueless(tx.core, c, ai)))
}

/// Whether the value-carrying writes of delta `ai` of `c` are held value-less here
/// (`make_leftover`, or missing past its expiry or under a standing request).
pub(crate) fn valueless(core: &Core, c: &CommitId, ai: usize) -> bool {
    core.ix.commits.get(c).is_some_and(|m| !gone_of(core, &m.header, c, ai).is_empty())
}

/// Whether part `ai` of `c` on `(tid, ak)` is held value-less for a purge request: its own writes
/// on the value-less list, not past its expiry (an expired one is value-less for good).
pub(crate) fn held_purged(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak, ai: usize, now: u64) -> bool {
    if !core.ix.valueless.contains_key(&(*tid, ak.clone())) {
        return false;
    }
    core.ix.commits.get(c).is_some_and(|m| m.header.expires.is_none_or(|t| t > now)) && valueless(core, c, ai)
}

/// The writes delta `ai` of `id` holds as its own: its counters or commit ID, a
/// snapshot's none (it copies). What invalidity, expiry and purge of the delta take.
pub(crate) fn writes_of(h: &Header, id: &CommitId, ai: usize) -> Vec<Owned> {
    if h.aspects.get(ai).is_some() && h.kind.has_own_writes() { Owned::of(h, id, ai).into_iter().collect() } else { Vec::new() }
}

/// `writes_of` the value-less list of the aspect names.
pub(crate) fn gone_of(core: &Core, h: &Header, id: &CommitId, ai: usize) -> Vec<Owned> {
    let Some(v) = h.aspects.get(ai).and_then(|a| core.ix.valueless.get(&(a.tid, a.ak.clone()))) else { return Vec::new() };
    // sorted (`list_valueless`)
    writes_of(h, id, ai).into_iter().filter(|o| v.binary_search(o).is_ok()).collect()
}

/// Whether a write of value-less list `list` (sorted, `list_valueless`) owns `d`: O(log its
/// length) but for exact-dot entries of `d`'s source. A source's ranges are disjoint (a counter
/// is one delta's), so the last starting at or below `d`'s counter is the only one that can.
pub(crate) fn sorted_owns(list: &[Owned], d: &osis_crdt::Dot) -> bool {
    if let osis_crdt::SourceKind::Commit(c) = d.src.kind()
        && list.binary_search(&Owned::Commit(*c)).is_ok()
    {
        return true;
    }
    // `Owned`'s order: ranges by source and start, then commits, then exact dots by source
    let i = list.partition_point(|x| matches!(x, Owned::Range { src, lo, .. } if (src, *lo) <= (&d.src, d.ctr)));
    if i > 0 && list.get(i - 1).is_some_and(|x| x.owns(d)) {
        return true;
    }
    let j = list.partition_point(|x| !matches!(x, Owned::Dots { src, .. } if *src >= d.src));
    list.get(j..).unwrap_or_default().iter().take_while(|x| matches!(x, Owned::Dots { src, .. } if *src == d.src)).any(|x| x.owns(d))
}

/// Takes `gone` off the value-less list of `(tid, ak)`.
pub(crate) fn off_valueless(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned]) {
    let k = (*tid, ak.clone());
    let Some(list) = tx.core.ix.valueless.get(&k) else { return };
    if !gone.iter().any(|o| list.binary_search(o).is_ok()) {
        return;
    }
    tx.core.touch();
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    list.retain(|x| !gone.contains(x));
    if list.is_empty() {
        tx.core.ix.valueless.remove(&k);
    }
    tx.core.valueless_dirty.insert(k);
}

/// Puts `o` on the value-less list of `(tid, ak)` (spec/crdt.md §4.7): the join-time predicate
/// that strips those writes' values from every body joined and holds the list elements they
/// created ended (`apply::strip_valueless`). Sorted: what the node holds, not the order it
/// learned it in. Whether any was new.
fn list_valueless(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, o: &[Owned]) -> bool {
    let k = (*tid, ak.clone());
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    let mut new = false;
    for x in o {
        if let Err(i) = list.binary_search(x) {
            list.insert(i, x.clone());
            new = true;
        }
    }
    if new {
        tx.core.touch();
        tx.core.valueless_dirty.insert(k);
    }
    new
}

/// Makes way for the late copies of parts `ais` of `c` (`takes_late`): a dropped part is
/// reopened, a stripped one gives up its leftover (`unstrip`).
pub(crate) fn reopen_late(tx: &mut Tx<'_>, c: &CommitId, ais: &BTreeSet<usize>) -> Result<()> {
    for ai in ais {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        if m.stripped(*ai) {
            unstrip(tx, c, *ai, false)?;
        } else if m.is_dropped(*ai) {
            reopen(tx, c, *ai)?;
        }
    }
    Ok(())
}

/// Holds delta `ai` of `c` as its leftover from now on (spec/crdt.md §4.7): its own writes `o`
/// (`writes_of`) go on the value-less list, and their values go from its body and the aspect's
/// state, shredded (`strip_leftover`). `in_place` (an expiry) while no held snapshot may carry a
/// value of `o` (`snapshot::carried_meets`): the state is stripped in place, O(the delta)
/// (`apply::strip_state`); else rebuilt (`apply::rebuild`), which also holds each snapshot
/// carrying such a value as its leftover. A copy of a write listed later goes on its join.
///
/// The leftover is the body as held (whole, or a leftover already), `extra` (what a waiting part
/// was stripped to, `pending::strip_purged`) or, dropped as covered, its held valid coverers'
/// copies of its writes, stripped (`Fragment::strip`: the value-less copy, spec/crdt.md §4.7); a
/// snapshot's keeps its frontiers and `Absorbed`. A part missing or dropped other than as covered has
/// none: the list alone holds it value-less, and a copy joins stripped (`takes_late`,
/// `drop_gone`); one missing is dropped (a tombstone for a new node).
///
/// Invariant: every write a node holds of a delta it holds value-less is in a held body, whole
/// or leftover, never in the state alone (the leftover is stored before the state changes), so
/// an un-merge of a later write that superseded it gives it back
/// (`apply::rebuilt`), whatever order the expiry, that write and its revocation came in.
/// The aspect, when anything changed.
fn make_leftover(tx: &mut Tx<'_>, c: &CommitId, ai: usize, o: &[Owned], extra: &[Fragment], in_place: bool) -> Result<Option<(Tid, Ak)>> {
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(None) };
    if o.is_empty() {
        return Ok(None);
    }
    tx.core.touch();
    let k = (a.tid, a.ak.clone());
    list_valueless(tx, &a.tid, &a.ak, o);
    let all = writes_of(&m.header, c, ai);
    let mut body: Option<Fragment> = None;
    let gives = crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        body.get_or_insert_default().join(f);
        Ok(())
    })?
    .flatten();
    for f in extra {
        body.get_or_insert_default().join(f.clone());
    }
    if body.is_none() && m.dropped(ai).is_some_and(|d| d.as_cover()) {
        // a covered body's live writes are in its coverers (a purge strips them next)
        for s in coverers(tx.core, c, ai) {
            let Some(sai) = held_part(tx.core, &s, &a.tid, &a.ak) else { continue };
            if !crate::apply::copies::snapshot_valid(tx.core, &s, &a.tid, &a.ak) {
                continue;
            }
            crate::apply::each_held_piece(tx, &s, sai, &mut |_, mut f| {
                f.remove_writes(&|d| !all.iter().any(|x| x.owns(d)));
                if f != Fragment::default() {
                    body.get_or_insert_default().join(f);
                }
                Ok(())
            })?;
        }
    }
    let Some(mut body) = body else {
        // nothing held of it: a leftover set aside at a fall (`unstrip`) is its body again;
        // else the list alone holds it value-less, a copy joins stripped. A part missing when
        // purged counts as received and dropped (a new node's tombstone, spec/commits.md §5:
        // `purged_on`, `body_gone`); one dropped already stays so.
        if m.missing(ai)
            && let Some(l) = leftover::get(tx, &a.tid, &a.ak, c, ai)?
        {
            // as bare as `unstrip` left it; a whole replace by the leftover, as a load reads it
            let whole = l.gives.is_none() && snapshot::whole_replace(&m, &a.ak, &l.fragment);
            m.set_hold(ai, Hold::Leftover { whole, valued: false });
            if let Some(blob) = tx.get_commit(c)? {
                tx.put_commit(c, &blob, &m, Shred::No, None)?;
            }
            tx.core.put_meta(*c, m);
            crate::apply::rebuild(tx, &a.tid, &a.ak)?;
        } else if m.missing(ai) {
            drop_part_for(tx, c, ai, DropFor::Other)?;
        } else {
            crate::apply::rebuild(tx, &a.tid, &a.ak)?;
        }
        return Ok(Some(k));
    };
    let mut at = (in_place && !snapshot::carried_meets(tx.core, &a.tid, &a.ak, o)).then(|| body.clone());
    strip_leftover(tx.core, &m.header, ai, &mut body);
    if let Some(at) = &mut at {
        at.join(body.clone());
    }
    put_leftover(tx, c, ai, m, body, gives)?;
    match at {
        // an expiry: the state stripped in place, the delta's body and leftover saying where
        Some(at) => {
            crate::apply::strip_state(tx, &a.tid, &a.ak, &at, o)?;
            if !tx.is_memory_commit(c) {
                tx.core.cover_candidates.entry(k.clone()).or_default().insert(*c);
            }
        }
        // the one path (item 1): the state from the held bodies, the leftover among them,
        // stripped by the list, shredded (every local copy of the values goes)
        None => crate::apply::rebuild(tx, &a.tid, &a.ak)?,
    }
    Ok(Some(k))
}

/// Snapshot part `ai` of `c` carries a copy of a value of a write on its aspect's value-less list
/// (spec/crdt.md §4.7 Copies, spec/commits.md §5): held as its leftover from now on, those copies
/// value-less. Store only: the state took the copies stripped (`apply::join_into_state`), or the
/// caller rebuilds the aspect.
pub(crate) fn strip_carried(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let mut body: Option<Fragment> = None;
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        body.get_or_insert_default().join(f);
        Ok(())
    })?;
    let Some(body) = body else { return Ok(()) };
    hold_carrier(tx, c, ai, body, held.flatten())
}

/// Snapshot part `ai` of applied commit `c` joined as its leftover `body` (stripped while it
/// waited, `pending::strip_carried_waiting`): held so, as `strip_carried` holds an applied one.
pub(crate) fn hold_carrier(tx: &mut Tx<'_>, c: &CommitId, ai: usize, mut body: Fragment, gives: Option<crate::engine::Gives>) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    tx.core.touch();
    strip_leftover(tx.core, &m.header, ai, &mut body);
    put_leftover(tx, c, ai, m, body, gives)
}

/// The leftover of `body`, held part `ai` (spec/crdt.md §4.7), the one strip of purge, expiry
/// and arrival. Invariant: no held body holds the value of a write the node holds value-less
/// (purged, expired), its own or a snapshot's copy under its dot; no body loses a value of a write
/// not held value-less, but a carrier held through its purge's fall (`purge::rejudge_purges`).
/// So every listed write loses its value (`Fragment::strip`), and a rebuild reads the same with it.
fn strip_leftover(core: &Core, h: &Header, ai: usize, body: &mut Fragment) {
    let Some(list) = h.aspects.get(ai).and_then(|a| core.ix.valueless.get(&(a.tid, a.ak.clone()))) else { return };
    body.strip(&|d| sorted_owns(list, d));
}

/// Stores `body` as the leftover of part `ai` of `c` (meta `m`): a part held whole loses its body
/// (the blob without the slot, shredded); one dropped as covered is held again, as its leftover.
/// It holds values while its own writes are off the value-less list (`Hold::Leftover::valued`; a snapshot
/// always): a body for keep bounds.
fn put_leftover(tx: &mut Tx<'_>, c: &CommitId, ai: usize, mut m: crate::engine::Meta, body: Fragment, gives: Option<crate::engine::Gives>) -> Result<()> {
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    if gives.is_some() {
        let mut carried = snapshot::Carried::default();
        carried.add(&body);
        crate::apply::note_carried(tx.core, &a.tid, &a.ak, c, carried);
    }
    // a held body keeps what it was judged; one held again (dropped as covered, missing) is a
    // whole replace by its leftover, as a load from the commit records reads it
    let whole_replace = m.whole(ai) || !m.holds(ai) && gives.is_none() && snapshot::whole_replace(&m, &a.ak, &body);
    leftover::put(tx, &a.tid, &a.ak, c, ai, &leftover::Leftover { fragment: body, gives })?;
    let valued = gone_of(tx.core, &m.header, c, ai).is_empty();
    if m.stripped(ai) && m.valued(ai) == valued {
        return Ok(());
    }
    let fresh = !m.stripped(ai);
    m.set_hold(ai, Hold::Leftover { whole: whole_replace, valued });
    // a leftover says no entries (spec/permissions.md §5.2, Addenda: a list counts while its
    // body is held)
    if osis_schema::core_types::is_addenda(a.ak.as_str()) {
        crate::apply::validity::forget_addendum_body(tx.core, c, &a.tid);
    }
    // its delta's links join the freed set: the leftover still links what it keeps
    if fresh {
        freed::free_part(tx, c, ai)?;
    }
    if let Some(blob) = tx.get_commit(c)? {
        // its body goes: the blob without the slot, shredded
        let (rest, shred) = if fresh { (osis_commit::rewrite(&blob, |x| x == ai), Shred::Yes) } else { (std::sync::Arc::unwrap_or_clone(blob), Shred::No) };
        tx.put_commit(c, &rest, &m, shred, None)?;
    }
    tx.core.put_meta(*c, m);
    Ok(())
}

/// Part `ai` of `c`, held as its leftover, gives it up: the part is missing (counts as never
/// received), its writes leave the state (`apply::rebuild`). For the valued copy
/// arriving (`takes_late`), whose join brings them back valued; or on its purge's fall
/// (`rejudge_purges`), a delta's leftover then `kept` aside for a rise before a copy comes (held
/// value-less again, it holds what it left, as at a node that never saw the fall:
/// `make_leftover` adopts it). A whole replace missing at the fall is no own replace: the
/// bodies dropped under it alone are missing again (`uncover`), as `drop_part_for` judges an own
/// cover dropped; for a joining copy the replace stays one.
fn unstrip(tx: &mut Tx<'_>, c: &CommitId, ai: usize, kept: bool) -> Result<()> {
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    if !m.stripped(ai) {
        return Ok(());
    }
    let own_cover = kept && m.whole(ai);
    tx.core.touch();
    if !kept {
        leftover::remove(tx, &a.tid, &a.ak, c, ai)?;
    }
    // a memory commit stays known while the part is to come back (`reopen_to_fetch`); a copy
    // joining makes way itself (`kept` false)
    m.set_hold(ai, Hold::Missing(if kept && m.view.memory { Missing::ToFetch } else { Missing::Plain }));
    tx.core.stale_commits.insert(*c);
    if let Some(blob) = tx.get_commit(c)? {
        tx.put_commit(c, &blob, &m, Shred::No, None)?;
    }
    // a snapshot missing indexes nothing, as an open reads it
    crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, c);
    tx.core.put_meta(*c, m);
    if own_cover {
        uncover(tx, &a.tid, &a.ak)?;
    }
    crate::apply::rebuild(tx, &a.tid, &a.ak)
}

/// Holds delta `ai` of `c` value-less (`make_leftover`): at expiry, or `purged`. A snapshot has
/// no values of its own: one a request names stays held, its copies of what the request takes
/// stripped by the rebuild that request runs (spec/commits.md §5), so a purge never drops a
/// cover. A part of
/// it waiting in the stored pending copy goes at expiry (`strip_pending`); purged, it is held
/// value-less there too, as `pending_drops` holds it (`purge_pending`). A part missing is held
/// value-less by the list alone (a copy joins stripped).
fn hold_valueless(tx: &mut Tx<'_>, c: &CommitId, ai: usize, purged: bool, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    if purged {
        purge_pending(tx, c, ai)?;
    } else {
        strip_pending(tx, c, ai)?;
    }
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let own = writes_of(&m.header, c, ai);
    if let Some(k) = make_leftover(tx, c, ai, &own, &[], !purged)? {
        changed.insert(k);
    }
    // a memory commit's leftover may be superseded now (spec/sync-compaction.md §2), or covered by a
    // held snapshot (spec/commits.md §5); its caller forgets it
    changed.extend(memory::superseded_rest(tx, c)?);
    if let Some(a) = m.header.aspects.get(ai) {
        let k = (a.tid, a.ak.clone());
        if tx.is_memory_commit(c) && tx.core.ix.commits.get(c).is_some_and(|m| m.holds(ai)) {
            memory::drop_covered(tx, &[k.clone()].into(), Some(c), Some(c))?;
        }
        // the compaction trigger counts leftovers (`retention::compact`), and covers them once
        // the aspect is quiet
        crate::retention::compact::Trigger::stirred(tx, &k);
        tx.core.compaction.weigh(k);
    }
    Ok(())
}

/// Part `ai` of `c` just joined, carrying a value of a write the value-less list names (spec/crdt.md
/// §4.7: joined stripped): a late copy of an expired or purged delta is held as its leftover
/// (`make_leftover`); so is a snapshot carrying a copy of such a value (`strip_carried`).
fn drop_gone(tx: &mut Tx<'_>, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).filter(|m| m.holds(ai) && !m.stripped(ai)) else { return Ok(()) };
    let gone = gone_of(tx.core, &m.header, c, ai);
    if gone.is_empty() {
        let Some(k) = m.header.aspects.get(ai).map(|a| (a.tid, a.ak.clone())) else { return Ok(()) };
        let Some(list) = tx.core.ix.valueless.get(&k).filter(|l| !l.is_empty() && m.header.kind.is_compaction()).cloned() else { return Ok(()) };
        // the state took it stripped (`apply::join_into_state`): only the stored body changes
        if crate::apply::carries_any(tx, c, ai, &list)? {
            strip_carried(tx, c, ai)?;
            changed.insert(k);
        }
        return Ok(());
    }
    strip_pending(tx, c, ai)?;
    if let Some(k) = make_leftover(tx, c, ai, &gone, &[], false)? {
        changed.insert(k);
    }
    Ok(())
}

/// Writes the value-less lists changed in this transaction, each once however many parts joined it.
pub(crate) fn persist_valueless(tx: &mut Tx<'_>) -> Result<()> {
    for (tid, ak) in std::mem::take(&mut tx.core.valueless_dirty) {
        match tx.core.ix.valueless.get(&(tid, ak.clone())) {
            Some(list) => {
                let enc = encode_owned(list);
                tx.put_aspect_local(records::VALUELESS, &tid, &ak, &enc)?;
            }
            None => {
                tx.txn.remove_local(&records::aspect_key(records::VALUELESS, &tid, &ak), Shred::No)?;
            }
        }
    }
    Ok(())
}

/// After a commit applied: its expiry (now or by timer), its purge request against held
/// deltas, and earlier purge requests against its deltas.
pub(crate) fn on_apply(tx: &mut Tx<'_>, id: &CommitId, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    on_late(tx, id, None, changed)
}

/// After late parts `ais` of applied commit `id` joined: `on_apply` for them (`None`: the commit
/// applied, every part and its request).
pub(crate) fn on_late(tx: &mut Tx<'_>, id: &CommitId, ais: Option<&BTreeSet<usize>>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, ais.cloned().unwrap_or_else(|| (0..h.aspects.len()).collect()), &mut purged, changed)?;
    if ais.is_none() {
        purge::apply_request(tx, id, &h, &mut purged)?;
        // a further minting of a held thing may bring it back after its expiry (`destroy::apply_destructions`)
        for a in h.aspects.iter().filter(|a| a.ak.as_str() == osis_commit::retention::CREATED) {
            if tx.core.mintings(&a.tid).nth(1).is_some() {
                tx.core.valueless_dirty.insert((a.tid, a.ak.clone()));
            }
        }
    }
    purged_changed(tx, purged, changed);
    Ok(())
}

/// Parts `ais` of applied commit `id`: expiry (now or by timer), held purge requests naming
/// them, held snapshots' parts carrying purged values, and on a memory commit what it supersedes
/// or covers. One held value-less (a copy of an expired or purged delta, joined stripped) is held
/// as its leftover: the list holds only what is past its expiry or a standing purge drops
/// (`rejudge_purges` takes the rest out; `drop_gone`).
fn on_parts(tx: &mut Tx<'_>, id: &CommitId, h: &Header, ais: BTreeSet<usize>, purged: &mut BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    for &ai in &ais {
        if h.aspects.get(ai).is_none() {
            continue;
        }
        if let Some(t) = h.expires {
            if t <= tx.now().0 {
                hold_valueless(tx, id, ai, false, purged)?;
            } else {
                tx.put_timer(t, id, ai, T_EXPIRY)?;
            }
        }
        purge::purge_arrived(tx, id, h, ai, purged)?;
        // a snapshot's copies of commits not held here, judged by its facts
        if h.kind.is_compaction()
            && let Some(a) = h.aspects.get(ai)
        {
            purge::rejudge_carried(tx, &a.tid, &a.ak, purged)?;
        }
        drop_gone(tx, id, ai, purged)?;
        // a value part a purge request's header keeps listed to its floor, replaced or not by then,
        // whatever its aspect keeps: told when the floor passes (`listing::kept_passed`)
        if let Some(t) = osis_commit::retention::purge_keep_until(h).filter(|t| *t > tx.now().0 && *t < osis_commit::FOREVER)
            && h.aspects.get(ai).is_some_and(|a| !a.ak.signal())
        {
            tx.put_timer(t, id, ai, T_KEPT)?;
        }
        // a signal body goes at its keep bound, whole or as its leftover: by its aspect's walk
        // while its timeline keeps it (`leaving`), then by its commit's purge floor if later
        if let Some(a) = h.aspects.get(ai).filter(|a| a.ak.signal()) {
            let now = tx.now().0;
            if history::of(tx.core, &a.tid, &a.ak).leaves_at(Some(h.ts.wall_ms().0)) > now {
                leaving::fire_held(tx, &a.tid, &a.ak, (h.ts, *id))?;
            } else {
                match signal_bound(tx.core, h, a) {
                    Some(t) if t <= now => drop_part(tx, id, ai)?,
                    Some(t) => tx.put_timer(t, id, ai, T_KEPT)?,
                    None => {}
                }
            }
        }
    }
    if h.ephemeral.is_some() {
        let aspects = ais.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        changed.extend(memory::drop_superseded_by(tx, id)?);
        memory::drop_covered(tx, &aspects, Some(id), Some(id))?;
    }
    Ok(())
}

fn purged_changed(tx: &mut Tx<'_>, purged: BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>) {
    if !purged.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Purge, changed: purged.iter().cloned().collect() });
        changed.extend(purged);
    }
}

/// A due timer: its store key, commit, aspect index and kind (`T_EXPIRY`, `T_FLOOR`, `T_KEPT`).
type Due = (Vec<u8>, CommitId, usize, u8);

/// The timers due by the wall clock, and when the first of the others is (`u64::MAX`: none).
fn due_timers(tx: &mut Tx<'_>) -> Result<(Vec<Due>, u64)> {
    let now = tx.now().0;
    let mut due = Vec::new();
    // keys sort by time: read up to the first not due
    let mut from: Vec<u8> = Vec::new();
    loop {
        let page = tx.txn.scan_local(records::TIMER, &from, 64)?;
        let n = page.len();
        for (k, v) in page {
            let tail = k.get(records::TIMER.len()..).unwrap_or_default();
            let (t, c, ai) = records::parse_timer(tail)?;
            if t > now {
                return Ok((due, t));
            }
            from = [tail, &[0]].concat();
            due.push((tail.to_vec(), c, ai, v.first().copied().unwrap_or(0)));
        }
        if n < 64 {
            return Ok((due, u64::MAX));
        }
    }
}

/// Runs due timer `key` (`records::timer_key`) of part `ai` of `c`, of `kind`; the
/// aspects it changed go to `changed`.
fn run_timer(tx: &mut Tx<'_>, key: &[u8], c: &CommitId, ai: usize, kind: u8, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    tx.txn.remove_local(key, Shred::No)?;
    // a request's floor is its window on a thing it destroyed (`destroy::in_force`): its keep is
    // judged again
    if kind == T_KEPT
        && let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)).filter(|a| osis_commit::retention::destroying_request(a.ak.as_str()))
    {
        tx.core.destroyed_due.insert(a.tid);
    }
    // a value part's keep bound changes nothing held, only its listing
    if kind == T_KEPT && tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)).is_some_and(|a| !a.ak.signal()) {
        return crate::engine::listing::kept_passed(tx, c, ai);
    }
    // judged again by node-sync whatever the timer did
    let mut ch = BTreeSet::new();
    if kind == T_FLOOR {
        replace::floor_passed(tx, c, ai);
    } else if kind == T_KEPT {
        // a setting since may have moved the bound: judged by the timeline now
        let now = tx.now().0;
        let bound = tx.core.ix.commits.get(c).map(|m| m.header.clone()).and_then(|h| Some(signal_bound(tx.core, &h, h.aspects.get(ai)?)));
        match bound {
            Some(Some(t)) if t > now => tx.put_timer(t, c, ai, T_KEPT)?,
            Some(None) => {}
            _ => {
                drop_part(tx, c, ai)?;
                crate::engine::edits::time_passed(tx, c, ai);
            }
        }
    } else {
        hold_valueless(tx, c, ai, false, &mut ch)?;
    }
    // the bound may have ended the part's listing with nothing held changing (a purge
    // tombstone's): its fold under its original judged again, and told (an event repeating a
    // page is harmless)
    if !crate::engine::listing::is_listed(tx, c, ai)?
        && let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai))
    {
        let (tid, ak) = (a.tid, a.ak.clone());
        tx.core.commits_named(tid, ak, *c);
        crate::engine::edits::time_passed(tx, c, ai);
    }
    memory::forget_if_spent(tx, c)?;
    changed.extend(ch);
    Ok(())
}

/// The parts of commit `id`'s stored pending copy (header `h`, resolved) past their expiry go as
/// their expiry timers take them (`Engine::tick`), before anything reads the copy to apply it: a
/// part waiting when its expiry passes counts as never received (spec/commits.md §5), whenever
/// ticks run.
pub(crate) fn expire_waiting(tx: &mut Tx<'_>, id: &CommitId, pending: &osis_commit::CommitBlob, h: &Header) -> Result<()> {
    let Some(t) = h.expires.filter(|t| *t <= tx.now().0) else { return Ok(()) };
    let ais: BTreeSet<usize> = pending.parts.iter().map(|p| p.ai).filter(|ai| h.aspects.get(*ai).is_some()).collect();
    if ais.is_empty() {
        return Ok(());
    }
    let mut changed = BTreeSet::new();
    for ai in ais {
        run_timer(tx, &records::timer_key(t, id, ai), id, ai, T_EXPIRY, &mut changed)?;
    }
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
    }
    Ok(())
}

impl Engine {
    /// Whether part `ai` of `c` was dropped here while invalid and no right took it since (not
    /// purged, not expired): no right deletes its blobs at hosts, which keep the copy fetched
    /// again if it turns valid (spec/permissions.md §6, spec/sync-judgement.md §2).
    pub fn left_at_hosts(&self, c: &CommitId, ai: usize) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.dropped_invalid(ai) && !valueless(&self.core, c, ai))
    }

    /// Runs what is due by the wall clock: expiries, purge floors (`T_FLOOR`, `T_KEPT`), bodies
    /// leaving history (`leaving`), live bounds and quiet times the compaction trigger waits for
    /// (`compact::Trigger::passed`, `quiet_passed`) and commits parked for drift.
    pub fn tick(&mut self) -> Result<()> {
        let r = self.run(|tx| {
            let mut changed = BTreeSet::new();
            let (due, next) = due_timers(tx)?;
            let (leave, next_leave) = leaving::due(tx.core, tx.now().0);
            // live bounds passed: the trigger weighs those aspects
            let now = tx.now().0;
            tx.core.compaction.passed(now);
            // the timers these put lower it again
            tx.core.timer_floor = next.min(next_leave).min(tx.core.compaction.next_at());
            // their rebuilds once per aspect (`run_batched`); an expiry strips a state in place
            // only while no rebuild of it is asked (`apply::strip_state`)
            crate::apply::run_batched(tx, |tx| {
                for (k, c, ai, kind) in due {
                    // a memory commit's timer is memory work: what it writes stays in memory
                    let memory = tx.is_memory_commit(&c);
                    tx.in_class(memory, |tx| run_timer(tx, &[records::TIMER, &k].concat(), &c, ai, kind, &mut changed))?;
                }
                for (tid, ak) in leave {
                    let memory = ak.ephemeral();
                    tx.in_class(memory, |tx| leaving::passed(tx, &tid, &ak))?;
                }
                Ok(())
            })?;
            if !changed.is_empty() {
                tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            }
            // quiet times passed: after the expiries, which end an aspect's quiet time
            tx.core.compaction.quiet_passed(now);
            tx.core.timer_floor = tx.core.timer_floor.min(tx.core.compaction.next_at());
            Ok(())
        });
        if r.is_err() {
            // the timers stay: due again
            self.core.timer_floor = 0;
        }
        r?;
        self.reexamine()
    }

    /// Whether a retention timer, durable or memory, is due by the wall
    /// clock: in memory, no store read (a timer removed without running may leave a false
    /// `true`, which the next `tick` clears).
    pub fn timers_due(&self) -> bool {
        self.core.timer_floor <= self.now().0
    }

    /// When the next retention timer is due (wall ms).
    pub fn next_timer(&mut self) -> Result<Option<u64>> {
        self.read(|tx| {
            let first = tx.txn.scan_local(records::TIMER, &[], 1)?;
            let part = first.first().and_then(|(k, _)| k.get(records::TIMER.len()..)).and_then(|k| records::parse_timer(k).ok()).map(|(t, _, _)| t);
            let aspect = tx.core.ix.leave_due.keys().next().copied();
            let live = Some(tx.core.compaction.next_at()).filter(|t| *t != u64::MAX);
            Ok(part.into_iter().chain(aspect).chain(live).min())
        })
    }

    /// Whether held commit `c` is an own replace of `(tid, ak)` (`snapshot::covered`).
    pub fn own_replace(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        snapshot::own_replace(&self.core, c, tid, ak)
    }

    /// The held commits own replaces `qs` of one author newly let go (`snapshot::own_newly_covered`).
    pub fn own_newly_covered(&self, qs: &[CommitId], tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        snapshot::own_newly_covered(&self.core, qs, tid, ak)
    }

    /// Whether `c` is a held commit of `s`'s author on `(tid, ak)` stamped before `s`.
    pub fn own_older(&self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let (Some(sm), Some(cm)) = (self.core.ix.commits.get(s), self.core.ix.commits.get(c)) else { return false };
        self.core.ix.own_held.get(&(*tid, ak.clone(), sm.view.author)).is_some_and(|x| x.contains(&(cm.view.ts, *c))) && cm.view.ts < sm.view.ts
    }

    /// `s`'s author's held commits on `(tid, ak)` stamped before `s` (`Indexes::own_held`).
    pub fn own_held_before(&self, s: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        let Some(m) = self.core.ix.commits.get(s) else { return Vec::new() };
        let ts = m.view.ts;
        self.core.ix.own_held.get(&(*tid, ak.clone(), m.view.author)).into_iter().flatten().take_while(|x| x.0 < ts).map(|x| x.1).collect()
    }

    /// The own replaces that may cover `c` on `(tid, ak)` (`snapshot::own_covers`).
    pub fn own_covers(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        snapshot::own_covers(&self.core, c, tid, ak)
    }

    /// Whether part `ai` of commit `c` is held.
    pub fn part_held(&self, c: &CommitId, ai: usize) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.holds(ai))
    }

    /// Whether commit `c` is known with no part held, only for a part dropped while invalid
    /// (`kept_invalid`): sync keeps of it its header, charged to its source like input not
    /// judged yet.
    pub fn kept_invalid(&self, c: &CommitId) -> bool {
        self.core.ix.commits.get(c).is_some_and(kept_invalid)
    }

    /// Whether commit `c` is held only as purged leftovers (`kept_purged`): a memory one is
    /// charged its own bytes against its labels' caps until it is forgotten, not through its
    /// entries, which the purger deletes at hosts.
    pub fn kept_purged(&self, c: &CommitId) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| kept_purged(&self.core, c, m, self.now().0))
    }

    /// Whether commit `c` may be forgotten, ID included, once node-sync knows no entry of it
    /// (spec/commits.md §5, Forgetting): nothing waiting, and either holding no part, known only
    /// for a part dropped while invalid (`kept_invalid`, either class: spec/permissions.md §6),
    /// holding only purged leftovers (`kept_purged`, either class: a fall then has nothing to fetch), or
    /// a durable content commit or content snapshot every part of which dropped as covered, by
    /// any writer's cover, no purge request (else each write another writer compacts, and each
    /// snapshot under a later one, would leave a header for good: `growth::several_writers_grow_nothing`).
    pub fn forgettable(&self, c: &CommitId) -> bool {
        // counted: tests read how many commits forgetting looks at
        let _s = osis_base::costs::span("forgettable");
        let core = &self.core;
        let Some(m) = core.ix.commits.get(c) else { return false };
        if core.ix.pending.contains_key(c) {
            return false;
        }
        if kept_invalid(m) || kept_purged(core, c, m, self.now().0) {
            return true;
        }
        if m.view.memory {
            return false;
        }
        matches!(m.view.kind, Kind::Content | Kind::ContentSnapshot) && !m.view.purges && m.dropped_parts().count() == m.view.aspects.len() && m.dropped_parts().all(|(_, d)| d.why == DropFor::Cover)
    }

    /// Every commit `forgettable` holds true of (the first tick after an open: forgetting
    /// is otherwise by events).
    pub fn all_forgettable(&self) -> Vec<CommitId> {
        self.core.ix.commits.keys().copied().filter(|c| self.forgettable(c)).collect()
    }

    /// Forgets commits `cs`, IDs included: as if they had never applied (`apply::unindex_commit`).
    /// Their leftovers held (`kept_purged`) go first, their aspects rebuilt once at the end
    /// without their value-less writes, as at a node that never received them (one rebuild per
    /// commit made forgetting an aspect's `n` leftovers quadratic).
    pub fn forget_commits(&mut self, cs: &[CommitId]) -> Result<()> {
        self.run(|tx| {
            crate::apply::run_batched(tx, |tx| {
                let mut aspects = BTreeSet::new();
                for c in cs {
                    // a memory commit's is memory work (`forgettable`: one kept for an invalid part)
                    let memory = tx.is_memory_commit(c);
                    tx.in_class(memory, |tx| {
                        let Some(m) = tx.core.ix.commits.get(c) else { return Ok(()) };
                        aspects.extend(m.header.aspects.iter().map(|a| (memory, a.tid, a.ak.clone())));
                        let held: Vec<(usize, Tid, Ak)> = m.stripped_parts().filter_map(|ai| m.header.aspects.get(ai).map(|a| (ai, a.tid, a.ak.clone()))).collect();
                        for (ai, tid, ak) in held {
                            drop_part_for(tx, c, ai, DropFor::Destroyed)?;
                            crate::apply::rebuild(tx, &tid, &ak)?;
                        }
                        crate::apply::unindex_commit(tx, c)
                    })?;
                }
                // its copies a held snapshot carries are judged as a commit not held from now on
                let mut changed = BTreeSet::new();
                for (memory, tid, ak) in aspects {
                    tx.in_class(memory, |tx| purge::rejudge_carried(tx, &tid, &ak, &mut changed))?;
                }
                purged_changed(tx, changed, &mut BTreeSet::new());
                Ok(())
            })
        })
    }

    /// Drops a body as covered (compaction, executed by node-sync): aspect `ak` of commit `c`.
    /// Refused unless a held valid snapshot covers it (every drop but expiry and purge is one
    /// as covered, spec/commits.md §5).
    pub fn drop_body(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx.core, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            drop_part_for(tx, &c, ai, DropFor::Cover)?;
            // a judgment the dropped body fed is kept with it (`Dropped`), but a keyset rebuild
            // marks its commits for judging again (as `drop_invalid`)
            crate::apply::rejudged(tx, false)?;
            match tx.core.ix.commits.get(&c) {
                Some(m) if !m.holds(ai) || m.bare(ai) => Ok(()),
                _ => Err(Error::Misuse("no held valid snapshot covers the body")),
            }
        })
    }
}

#[cfg(test)]
mod tests_own;
#[cfg(test)]
mod tests_carried;
#[cfg(test)]
mod tests_resnapshot;
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::engine::{Hold, Missing};
    use crate::flows::Demotion;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, CommitId, Role, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::Codec;
    use osis_schema::core_types as ct;

    // spec/commits.md §5 (replaced), scale: a reset killing every write of a filled map judges
    // the fill and a snapshot of it walking each held part a few times for its winners, never
    // once per death: the same count for 10 times the writes.
    #[test]
    fn reset_judged_walks_parts_once_spec_commits_5() {
        let walks = |n: usize| {
            let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
            let a = lp.peers[0].engine.me();
            let x = Ak::new("x:m.0").unwrap();
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, a);
            m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(x.clone(), osis_schema::History::Keep { until: None, after: Some(3_600_000) })).unwrap();
            lp.peers[0].commit(m).unwrap();
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Map((0..n).map(|i| (Value::Str(format!("k{i}")), Value::Int(i as i64))).collect())).unwrap();
            let fill = lp.peers[0].commit(m).unwrap().unwrap();
            lp.advance(10);
            let snap = lp.peers[0].engine.snapshot(&t, &x).unwrap().unwrap();
            lp.advance(10);
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Int(0)).unwrap();
            let reset = lp.peers[0].commit(m).unwrap().unwrap();
            let e = &mut lp.peers[0].engine;
            let at = Some(e.header(&reset).unwrap().ts);
            let w0 = e.death_walks();
            assert_eq!([e.replaced_at(&fill, &t, &x).unwrap(), e.replaced_at(&snap, &t, &x).unwrap()], [at, at]);
            e.death_walks() - w0
        };
        let w = walks(20);
        assert!(w > 0);
        assert_eq!(walks(200), w, "walks per judgment grow with the deaths");
    }

    // spec/commits.md §5 (replaced), issues/derived-state-recomputed.md: a replaced body's keep
    // bound is judged once per change of what it reads (its aspect's held bodies and state): asked
    // again, or after writes on another aspect, it judges nothing.
    #[test]
    fn replaced_bound_judged_once_per_change_of_its_aspect_spec_commits_5() {
        let mut lp = LocalPeer::new(1, 954, WallMs(1_700_000_000_000)).unwrap();
        let a = lp.peers[0].engine.me();
        let (x, y) = (Ak::new("x:m.0").unwrap(), Ak::new("x:n.0").unwrap());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(x.clone(), osis_schema::History::Keep { until: None, after: Some(3_600_000) })).unwrap();
        lp.peers[0].commit(m).unwrap();
        let write = |lp: &mut LocalPeer, ak: &Ak, v: i64| {
            let mut m = Mutation::new();
            m.set(t, ak, &Value::Int(v)).unwrap();
            lp.advance(10);
            lp.peers[0].commit(m).unwrap().unwrap()
        };
        let first = write(&mut lp, &x, 1);
        write(&mut lp, &x, 2);
        let judged = |lp: &mut LocalPeer| {
            osis_base::costs::take();
            let k = lp.peers[0].engine.part_keeps(&first).unwrap();
            let n = |name: &str, c: &[(&str, std::time::Duration, u64)]| c.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
            let c = osis_base::costs::take();
            (k, n("part bounds", &c) + n("replaced at", &c) + n("held writes", &c) + n("deaths: a body", &c))
        };
        let (k, n) = judged(&mut lp);
        assert!(n > 0 && k.iter().any(|k| *k > 0), "judged: {k:?}");
        assert_eq!(judged(&mut lp), (k.clone(), 0), "asked again");
        write(&mut lp, &y, 1);
        write(&mut lp, &y, 2);
        assert_eq!(judged(&mut lp), (k.clone(), 0), "writes on another aspect");
        write(&mut lp, &x, 3);
        assert!(judged(&mut lp).1 > 0, "a write on its aspect");
    }

    /// One peer, a thing whose `x:m.0` keeps history an hour (so replaced bodies are dated), and
    /// a write of `x:m.0` 10 ms after the last.
    fn kept_register(seed: u64) -> (LocalPeer, osis_base::Tid, Ak) {
        let mut lp = LocalPeer::new(1, seed, WallMs(1_700_000_000_000)).unwrap();
        let a = lp.peers[0].engine.me();
        let x = Ak::new("x:m.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(x.clone(), osis_schema::History::Keep { until: None, after: Some(3_600_000) })).unwrap();
        lp.peers[0].commit(m).unwrap();
        (lp, t, x)
    }

    fn write_x(lp: &mut LocalPeer, t: osis_base::Tid, x: &Ak, v: i64) -> CommitId {
        let mut m = Mutation::new();
        m.set(t, x, &Value::Int(v)).unwrap();
        lp.advance(10);
        lp.peers[0].commit(m).unwrap().unwrap()
    }

    // spec: none (internal: issues/derived-state-recomputed.md step 4). Dating a replaced body
    // reads its aspect's held writes, amended by each join: a write decodes its own body however
    // many the aspect holds (read anew, the aspect's every body: n at n, 10n at 10n).
    #[test]
    fn a_join_decodes_its_own_body_not_the_aspects() {
        let per_join = |n: i64| {
            let (mut lp, t, x) = kept_register(957);
            let mut prev = write_x(&mut lp, t, &x, 0);
            for v in 1..=n {
                let c = write_x(&mut lp, t, &x, v);
                lp.peers[0].engine.part_keeps(&prev).unwrap();
                prev = c;
            }
            osis_base::costs::take();
            write_x(&mut lp, t, &x, n + 1);
            assert!(lp.peers[0].engine.part_keeps(&prev).unwrap().iter().any(|k| *k > 0), "dated");
            let c = osis_base::costs::take();
            let count = |name: &str| c.iter().filter(|s| s.0 == name).map(|s| s.2).sum::<u64>();
            (count("deaths: a body"), count("held writes"))
        };
        assert_eq!(per_join(8), (1, 0), "at 8 bodies");
        assert_eq!(per_join(80), (1, 0), "at 80 bodies");
    }

    // spec: none (internal: notes/engine.md, Derived values). The aspect's held writes, amended or
    // read anew, are what a fresh read gives: after a join, a snapshot's join, a join undone by a
    // failed transaction that asked for them, and a body dropped as covered.
    #[test]
    fn held_writes_kept_are_a_fresh_reads() {
        use crate::error::Error;
        let (mut lp, t, x) = kept_register(958);
        let check = |lp: &mut LocalPeer, what: &str| {
            lp.peers[0]
                .engine
                .run(|tx| {
                    let kept = super::bounds::held_writes(tx, &t, &x)?;
                    assert_eq!(*kept, super::bounds::read_held_writes(tx, &t, &x)?, "{what}");
                    Ok(())
                })
                .unwrap();
        };
        let first = write_x(&mut lp, t, &x, 0);
        check(&mut lp, "read anew");
        write_x(&mut lp, t, &x, 1);
        check(&mut lp, "a join");
        lp.advance(10);
        let snap = lp.peers[0].engine.snapshot(&t, &x).unwrap().unwrap();
        check(&mut lp, "a snapshot's join");
        let r = lp.peers[0].engine.run(|tx| {
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Int(2)).unwrap();
            crate::engine::write::commit_in(tx, m)?;
            super::bounds::held_writes(tx, &t, &x)?;
            Err::<(), _>(Error::Misuse("test: undo"))
        });
        assert!(r.is_err());
        check(&mut lp, "a join undone after it was amended");
        write_x(&mut lp, t, &x, 3);
        check(&mut lp, "a join after the undone one");
        lp.advance(3_600_000);
        lp.peers[0].engine.drop_body(&first, &t, &x).unwrap();
        check(&mut lp, "a body dropped");
        assert!(lp.peers[0].engine.core.ix.commits.get(&snap).is_some());
    }

    // spec: none (internal: notes/engine.md, Derived values). The aspect's held writes kept are
    // what a fresh read gives when a part invalid here joins (un-merged: it gives nothing), and
    // when a valid one joins inside its record.
    #[test]
    fn held_writes_over_an_invalid_part_are_a_fresh_reads() {
        let mut lp = LocalPeer::new(4, 959, WallMs(1_700_000_000_000)).unwrap();
        let a = lp.peers[0].engine.me();
        let x = Ak::new("x:m.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(x.clone(), osis_schema::History::Keep { until: None, after: Some(3_600_000) })).unwrap();
        lp.peers[0].commit(m).unwrap();
        for w in [1, 2] {
            let w = lp.peers[w].engine.me();
            let mut m = Mutation::new();
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(w))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, tied: None }.to_value()) }).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
        lp.sync_all().unwrap();
        let check = |lp: &mut LocalPeer, what: &str| {
            lp.peers[3]
                .engine
                .run(|tx| {
                    let kept = super::bounds::held_writes(tx, &t, &x)?;
                    assert_eq!(*kept, super::bounds::read_held_writes(tx, &t, &x)?, "{what}");
                    Ok(())
                })
                .unwrap();
        };
        // node 2 puts a map at `a`, node 1 writes inside it; node 0 removes node 2 before seeing it
        let mut m = Mutation::new();
        m.set(t, &x, &Value::Map(osis_base::ValueMap::from([(Value::Str("a".into()), Value::Map(osis_base::ValueMap::from([(Value::Str("b".into()), Value::Int(1))])))]))).unwrap();
        lp.advance(10);
        let rogue = lp.peers[2].commit(m).unwrap().unwrap();
        let rogue = lp.peers[2].engine.package(&rogue).unwrap().unwrap();
        lp.deliver(1, &rogue).unwrap();
        let mut m = Mutation::new();
        m.op(t, &x, PathOp { path: vec![PathSeg::Key(Value::Str("a".into())), PathSeg::Key(Value::Str("c".into()))], op: Op::Set(Value::Int(2)) }).unwrap();
        lp.advance(10);
        let inside = lp.peers[1].commit(m).unwrap().unwrap();
        let inside = lp.peers[1].engine.package(&inside).unwrap().unwrap();
        let r = lp.peers[2].engine.me();
        use std::collections::{BTreeMap, BTreeSet};
        let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(r, BTreeSet::from([t]))]), content: BTreeMap::from([(r, BTreeSet::from([t]))]) };
        let f = lp.peers[0].engine.frontier(&scope, WallMs(1_700_000_000_000)).unwrap();
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(r)) }).unwrap();
        m.frontier(f.to_value());
        lp.advance(10);
        let demote = lp.peers[0].commit(m).unwrap().unwrap();
        let demote = lp.peers[0].engine.package(&demote).unwrap().unwrap();
        check(&mut lp, "every part valid");
        lp.deliver(3, &demote).unwrap();
        lp.deliver(3, &rogue).unwrap();
        assert!(lp.peers[3].engine.core.ix.invalid.get(&(t, x.clone())).is_some_and(|s| !s.is_empty()));
        check(&mut lp, "an invalid part joined");
        lp.deliver(3, &inside).unwrap();
        check(&mut lp, "a join inside the invalid part's record");
        // with the invalid part held, a join amends them: it reads its own body alone
        let mut m = Mutation::new();
        m.op(t, &x, PathOp { path: vec![PathSeg::Key(Value::Str("d".into()))], op: Op::Set(Value::Int(3)) }).unwrap();
        lp.advance(10);
        let more = lp.peers[1].commit(m).unwrap().unwrap();
        let more = lp.peers[1].engine.package(&more).unwrap().unwrap();
        osis_base::costs::take();
        lp.deliver(3, &more).unwrap();
        lp.peers[3].engine.run(|tx| super::bounds::held_writes(tx, &t, &x).map(drop)).unwrap();
        let c = osis_base::costs::take();
        let count = |name: &str| c.iter().filter(|s| s.0 == name).map(|s| s.2).sum::<u64>();
        assert_eq!((count("deaths: a body"), count("held writes")), (1, 0), "a join beside an invalid part");
        check(&mut lp, "a join beside an invalid part");
    }

    // spec: none (internal: notes/engine.md, Derived values). A memo reading a commit's leftover
    // runs again when the record is written, and again when a failed transaction undoes that
    // write.
    #[test]
    fn memos_follow_leftovers_through_writes_and_undo() {
        use crate::engine::Tx;
        use osis_base::memo::Memo;
        use crate::error::Error;
        let mut lp = LocalPeer::new(1, 956, WallMs(1_700_000_000_000)).unwrap();
        let a = lp.peers[0].engine.me();
        let x = Ak::new("x:m.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &x, &Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        let ai = e.core.ix.commits.get(&c).unwrap().aspect(&t, &x).unwrap();
        let runs = |name: &str| osis_base::costs::take().iter().filter(|s| s.0 == name).map(|s| s.2).sum::<u64>();
        let undo = || Err::<(), _>(Error::Misuse("test: undo"));

        // leaked: `Memo::get_in` finds its memo through the transaction's borrow
        let memo: &'static Memo<u8, String> = Box::leak(Box::new(Memo::new("test record")));
        let left = |tx: &mut Tx<'_>| Memo::get_in(tx, |_| memo, &0, |tx| Ok::<_, Error>(format!("{:?}", super::leftover::get(tx, &t, &x, &c, ai)?.map(|l| l.fragment))));
        let put = |tx: &mut Tx<'_>, f: osis_crdt::Fragment| super::leftover::put(tx, &t, &x, &c, ai, &super::leftover::Leftover { fragment: f, gives: None });
        e.run(|tx| {
            let f = crate::apply::held_fragment(tx, &c, ai)?.unwrap();
            put(tx, f)
        })
        .unwrap();
        osis_base::costs::take();
        let one = e.run(left).unwrap();
        assert_eq!((e.run(left).unwrap(), runs("test record")), (one.clone(), 1), "asked again");
        e.run(|tx| put(tx, osis_crdt::Fragment::default())).unwrap();
        let two = e.run(left).unwrap();
        assert_ne!(two, one, "a leftover written");
        let r = e.run(|tx| {
            let f = crate::apply::held_fragment(tx, &c, ai)?.unwrap();
            put(tx, f)?;
            assert_eq!(left(tx).unwrap(), one, "written in the transaction");
            undo()
        });
        assert!(r.is_err());
        assert_eq!(e.run(left).unwrap(), two, "the write undone");
    }

    // spec/commits.md §5, spec/crypto.md §7, spec/requirements.md Purge on replace: a writer whose
    // delete keys of the thing are not here writes nothing on it, so the replacement applies there
    // (no refused own snapshot fails the receive) and the replaced body stays; once the keys come it
    // covers it, so the end is the one of the keys coming first: whatever arrives last of body,
    // replacement, role and keys triggers the cover
    #[test]
    fn writer_covers_once_its_delete_keys_come_in_any_order_spec_commits_5() {
        let end = |keys_first: bool| {
            let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let (alice, bob, carol) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
            let (x, keys) = (Ak::new("x:v.0").unwrap(), Ak::new("keys.0").unwrap());
            let none = osis_schema::Retention { by: osis_schema::PurgeBy::Writer };
            let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
            // bob writes `t` by a raw edge write: `t` keeps its first admin's secrets
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, alice);
            m.op(t, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(bob))], op: Op::Set(edge(Role::Write).to_value()) }).unwrap();
            lp.peers[0].commit(m).unwrap();
            let mut m = Mutation::new();
            m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(x.clone(), osis_schema::History::PurgeOnReplace)).unwrap();
            lp.peers[0].commit(m).unwrap();
            lp.sync(0, 1).unwrap();
            assert!(lp.peers[1].engine.holds_delete_keys(&t).unwrap());
            // alice keeps both bodies uncovered (as when her cover is still on its way)
            lp.peers[0].engine.keep_bodies(true);
            let mut puts = Vec::new();
            for v in [1, 2] {
                lp.advance(1000);
                let mut m = Mutation::new();
                m.set(t, &x, &Value::Int(v)).unwrap().retention(t, &x, none).unwrap();
                puts.push(lp.peers[0].commit(m).unwrap().unwrap());
            }
            // a first holder by the flow gives `t` secrets of its own, its `keys.0` in that
            // commit: bob gets the rest, then the two puts and the keys in either order
            lp.peers[0].engine.grant(&t, &carol, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
            let pks = lp.packages(0).unwrap();
            let carries = |id: &CommitId| lp.peers[0].engine.header(id).unwrap().aspects.iter().any(|a| a.tid == t && a.ak == keys);
            let (key_pks, other): (Vec<_>, Vec<_>) = pks.into_iter().partition(|pk| carries(&pk.id));
            let (put_pks, rest): (Vec<_>, Vec<_>) = other.into_iter().partition(|pk| puts.contains(&pk.id));
            for pk in &rest {
                lp.deliver(1, pk).unwrap();
            }
            let (first, last) = if keys_first { (&key_pks, &put_pks) } else { (&put_pks, &key_pks) };
            for pk in first {
                lp.deliver(1, pk).unwrap();
            }
            if !keys_first {
                let e = &mut lp.peers[1].engine;
                assert!(!e.holds_delete_keys(&t).unwrap(), "bob's write is here, t's delete keys are not");
                assert_eq!(e.get(&t, &x).unwrap(), Some(Value::Int(2)));
                assert!(super::held_part(&e.core, &puts[0], &t, &x).is_some(), "no cover yet: the replaced body stays");
            }
            for pk in last {
                lp.deliver(1, pk).unwrap();
            }
            let e = &mut lp.peers[1].engine;
            let held: Vec<bool> = puts.iter().map(|c| super::held_part(&e.core, c, &t, &x).is_some()).collect();
            let own = e.core.ix.snapshots.get(&(t, x.clone())).into_iter().flatten().filter(|s| e.core.ix.commits.get(&s.1).is_some_and(|m| m.view.author == bob)).count();
            (e.get(&t, &x).unwrap(), held, own)
        };
        let keys_first = end(true);
        // the live put is no purge-on-replace body: only the replaced one goes here (the live one
        // is the compaction trigger's, node-sync's)
        assert_eq!(keys_first, (Some(Value::Int(2)), vec![false, true], 1), "bob covers on the replacement");
        assert_eq!(end(false), keys_first, "bob covers once the keys come");
    }

    // spec/sync-judgement.md §1 entitlement: a thing's reader actor is the nearest actor up its record
    // chain with secrets of its own, through first-admin links: a plain thing's is its first
    // admin's, and so is that of a thing below it; once a grant
    // gives it secrets of its own, its own.
    #[test]
    fn reader_actor_up_the_record_chain_spec_sync_3() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let e = &mut lp.peers[0].engine;
        let p = e.create_with_admin(&a).unwrap().0;
        let r = e.create_with_admin(&p).unwrap().0;
        let mut m = Mutation::new();
        let q = e.new_thing(&mut m, p);
        let s = e.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap().unwrap();
        let readers = |e: &crate::Engine| [p, q, r, s].map(|t| e.core.reader_of(&t));
        assert_eq!(readers(&lp.peers[0].engine), [a; 4], "plain: every reader actor is A");
        let e = &mut lp.peers[0].engine;
        e.grant(&p, &b, &ct::Edge { role: Role::Read, until: None, invite: None, tied: None }).unwrap();
        assert!(e.core.ix.own_keys.contains(&p), "the grant gave P secrets of its own");
        assert_eq!(readers(&lp.peers[0].engine), [p, p, p, a], "P's own, S still A's");
    }

    // spec/sync-compaction.md §1 (carriers): a body with live writes needs a carrier, spec/permissions.md §5.2: a
    // write made invalid (its author's removal by an admin that had not received it) counts
    // dead; a re-grant that makes it valid again counts it live again.
    #[test]
    fn delta_live_follows_validity_spec_sync_7() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, w, x) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(0)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
        let admin = ct::Edge { role: Role::Admin, ..write.clone() };
        lp.peers[0].engine.grant(&t, &w, &write).unwrap();
        lp.peers[0].engine.grant(&t, &x, &admin).unwrap();
        lp.sync_all().unwrap();
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync(1, 0).unwrap();
        assert!(lp.peers[0].engine.delta_live(&c, &t, &ak).unwrap(), "W's write is the value");
        // no addendum of A's would list it
        lp.peers[0].engine.core.addenda_on = false;
        lp.advance(1_000);
        lp.peers[2].engine.demote(&t, &Demotion { holder: w, new: None, retain: None }).unwrap();
        lp.sync(2, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(!e.delta_live(&c, &t, &ak).unwrap(), "invalid after a removal not listing it: dead");
        assert!(!e.core.ix.commits[&c].holds(0), "dropped while invalid");
        e.grant(&t, &w, &write).unwrap();
        assert!(e.core.ix.commits[&c].missing(0), "valid again after the re-grant: missing, fetched");
        lp.sync(1, 0).unwrap();
        assert!(lp.peers[0].engine.delta_live(&c, &t, &ak).unwrap(), "fetched from its author: live");
    }

    // spec/commits.md §5 live writes, by dot, and a delta stamp marks many positions: C's snapshot,
    // invalid at C after A's demotion, holds A's write to field 0 (dead here), and of field 1 only
    // C's reset of it (invalid too), so field 1's entry, under the same stamp, is live here at a
    // position the snapshot does not hold.
    #[test]
    fn invalid_snapshot_is_live_by_dot_spec_commits_5() {
        static TS: osis_schema::StaticSchema = osis_schema::StaticSchema::new("t.osis", "revision 1; aspect k:s.0: struct { 0 a: int, 1 m: map<string, int> };\n");
        let key: osis_schema::Aspect<Value> = osis_schema::Aspect::new("k:s.0", &TS);
        let ak = Ak::new("k:s.0").unwrap();
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let [a, c] = [0, 1].map(|i| lp.peers[i].engine.me());
        let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
        lp.peers[0].engine.grant(&t, &c, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        use osis_crdt::{Op, PathOp, PathSeg};
        let mut m = Mutation::new();
        m.op(t, &key, PathOp { path: vec![PathSeg::Field(0)], op: Op::Set(Value::Int(1)) }).unwrap();
        m.op(t, &key, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(Value::Str("x".into()))], op: Op::Put(Value::Int(2)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        m.op(t, &key, PathOp { path: vec![PathSeg::Field(1)], op: Op::Replace(Value::Map(Default::default())) }).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(10);
        let snap = lp.peers[1].engine.snapshot(&t, &ak).unwrap().unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        m.op(t, &key, PathOp { path: vec![PathSeg::Field(0)], op: Op::Set(Value::Int(3)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].engine.demote(&t, &Demotion { holder: c, new: None, retain: None }).unwrap();
        lp.sync(0, 1).unwrap();
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.body_valid(&snap, &t, &ak), Some(false), "the snapshot is invalid here");
        assert!(e.delta_live(&snap, &t, &ak).unwrap(), "its stamp is live at field 1");
    }

    // spec/crdt.md §4.6 Un-merge, §4.7, issues/drop-rejoin-robust.md item 2 (leftovers are
    // bodies): every write a node holds of a delta it holds value-less is in a held body, never
    // in the state alone (`make_leftover`), so after an expiry and after a purge the state is
    // the join of the held bodies (`apply::check_rebuilt` checks every transaction), and reads
    // as the value-less winner (absent), not the older value. Were the leftover not stored (the
    // state stripped alone), the bodies would lack the expired stamp and the join would show
    // "old".
    #[test]
    fn leftover_is_a_held_body_spec_crdt_4_7() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.me();
        let (reg, other) = (Ak::new("x:a.0").unwrap(), Ak::new("x:b.0").unwrap());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &reg, &Value::Str("old".into())).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.advance(10);
        let now = lp.peers[0].engine.now();
        let mut m = Mutation::new();
        m.set(t, &reg, &Value::Str("brief".into())).unwrap();
        m.expires(t, &reg, WallMs(now.0 + 1000)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(2000);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&t, &reg).unwrap(), None, "the value-less winner reads absent");
        lp.advance(10);
        let mut m = Mutation::new();
        m.set(t, &reg, &Value::Str("secret".into())).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        m.purge_commit(c, t, reg.clone());
        m.set(t, &other, &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&t, &reg).unwrap(), None, "purged: the value-less winner reads absent");
        assert!(e.core.ix.commits.get(&c).unwrap().stripped(0), "the purged part is held as its leftover");
    }

    // spec/commits.md §5 (Own replaces, Purge): a whole replace held as its leftover stays one
    // through a fall and a rise of its purge. The fall makes the part missing (its leftover set
    // aside), and a missing part says nothing of `whole` (`Hold::Missing`); the rise adopts the
    // leftover and judges the replace on it, as a load from the commit records does
    // (`check_index` compares them).
    #[test]
    fn whole_replace_through_a_purges_fall_and_rise_spec_commits_5() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, x, w) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let (reg, other) = (Ak::new("x:a.0").unwrap(), Ak::new("x:b.0").unwrap());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &other, &Value::Int(0)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &x, &ct::Edge { role: Role::Admin, ..write.clone() }).unwrap();
        lp.peers[0].engine.grant(&t, &w, &write).unwrap();
        lp.sync_all().unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        m.set(t, &reg, &Value::Str("secret".into())).unwrap();
        let c = lp.peers[2].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        let hold = |lp: &LocalPeer| lp.peers[2].engine.core.ix.commits[&c].hold[0].clone();
        let own = |lp: &LocalPeer| lp.peers[2].engine.core.ix.own_replaces.get(&(t, reg.clone(), w)).is_some_and(|s| s.iter().any(|x| x.1 == c));
        assert_eq!(hold(&lp), Hold::Body { whole: true });
        // x purges it; the owner removes x before hearing of it, so the purge falls
        lp.advance(10);
        let mut m = Mutation::new();
        m.purge_commit(c, t, reg.clone());
        m.set(t, &other, &Value::Int(1)).unwrap();
        let p1 = lp.peers[1].commit(m).unwrap().unwrap();
        let p1 = lp.peers[1].engine.package(&p1).unwrap().unwrap();
        lp.advance(10);
        let d = lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap();
        let ds: Vec<_> = d.commits.iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap()).collect();
        lp.deliver(2, &p1).unwrap();
        assert_eq!(hold(&lp), Hold::Leftover { whole: true, valued: false }, "purged");
        assert!(own(&lp));
        for d in &ds {
            lp.deliver(2, d).unwrap();
        }
        assert_eq!(hold(&lp), Hold::Missing(Missing::Plain), "fallen: never received");
        assert!(!own(&lp));
        // the owner purges it: the leftover set aside is its body again, a whole replace
        lp.advance(10);
        let mut m = Mutation::new();
        m.purge_commit(c, t, reg.clone());
        m.set(t, &other, &Value::Int(2)).unwrap();
        let p2 = lp.peers[0].commit(m).unwrap().unwrap();
        let p2 = lp.peers[0].engine.package(&p2).unwrap().unwrap();
        lp.deliver(2, &p2).unwrap();
        assert_eq!(hold(&lp), Hold::Leftover { whole: true, valued: false }, "purged again");
        assert!(own(&lp));
        lp.peers[2].engine.check_index();
    }

    // spec/commits.md §5 (Own replaces, Purge): an own replace gone missing at its purge's fall
    // is no cover: a body dropped under it and one other own replace is missing again, as at a
    // node that holds the same commits and never saw the fall. W writes C0, then whole replaces
    // C2, C3; C0 is dropped as covered; the admin X purges C2; the owner removes X before hearing
    // of it, so the purge falls and C2 is missing.
    #[test]
    fn own_replace_missing_at_a_fall_uncovers_spec_commits_5() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, x, w) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let (reg, other) = (Ak::new("x:a.0").unwrap(), Ak::new("x:b.0").unwrap());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &other, &Value::Int(0)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &x, &ct::Edge { role: Role::Admin, ..write.clone() }).unwrap();
        lp.peers[0].engine.grant(&t, &w, &write).unwrap();
        lp.sync_all().unwrap();
        let cs: Vec<CommitId> = (0..3)
            .map(|v| {
                lp.advance(10);
                let mut m = Mutation::new();
                m.set(t, &reg, &Value::Int(v)).unwrap();
                lp.peers[2].commit(m).unwrap().unwrap()
            })
            .collect();
        let (c0, c2) = (cs[0], cs[1]);
        lp.sync_all().unwrap();
        lp.peers[2].engine.drop_body(&c0, &t, &reg).unwrap();
        let hold = |lp: &LocalPeer, c: &CommitId| lp.peers[2].engine.core.ix.commits[c].hold[0].clone();
        assert!(matches!(hold(&lp, &c0), Hold::Dropped(_)), "covered by C2, C3");
        lp.advance(10);
        let mut m = Mutation::new();
        m.purge_commit(c2, t, reg.clone());
        m.set(t, &other, &Value::Int(1)).unwrap();
        let p = lp.peers[1].commit(m).unwrap().unwrap();
        let p = lp.peers[1].engine.package(&p).unwrap().unwrap();
        lp.advance(10);
        let d = lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap();
        let ds: Vec<_> = d.commits.iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap()).collect();
        lp.deliver(2, &p).unwrap();
        assert!(matches!(hold(&lp, &c0), Hold::Dropped(_)), "C2 purged is still an own replace");
        for d in &ds {
            lp.deliver(2, d).unwrap();
        }
        assert_eq!(hold(&lp, &c2), Hold::Missing(Missing::Plain), "fallen: never received");
        assert_eq!(hold(&lp, &c0), Hold::Missing(Missing::Plain), "C0 is missing again: one own replace covers nothing");
        assert_eq!(lp.peers[2].engine.get(&t, &reg).unwrap(), Some(Value::Int(2)));
        lp.peers[2].engine.check_index();
        // the cycle ends: C2 and C0 fetched back, C0 drops again under C2, C3 and stays dropped
        lp.sync_all().unwrap();
        assert!(matches!(hold(&lp, &c2), Hold::Body { whole: true }), "C2 back whole");
        lp.peers[2].engine.drop_body(&c0, &t, &reg).unwrap();
        assert!(matches!(hold(&lp, &c0), Hold::Dropped(_)), "covered by C2, C3 again");
        lp.sync_all().unwrap();
        assert!(matches!(hold(&lp, &c0), Hold::Dropped(_)), "nothing fetches it back");
        assert_eq!(lp.peers[2].engine.get(&t, &reg).unwrap(), Some(Value::Int(2)));
        lp.peers[2].engine.check_index();
    }

    // spec/permissions.md §5.2, spec/commits.md §5 Forgetting: a coverer forgotten while a body
    // dropped under it is still known (its entries not deleted yet) leaves that body under the
    // covers it dropped under: a snapshot falling invalid later uncovers nothing a held valid one
    // still carries. Reader R drops W's C under A's S1, S1 under A's S2, forgets S1; W's
    // snapshot falls invalid at R (A removed W not having heard of it): C stays dropped,
    // nothing is fetched, no flag.
    #[test]
    fn forgotten_coverer_hands_down_its_covers_spec_permissions_5_2() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (a, w, r) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let reg = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&t, &r, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let set = |lp: &mut LocalPeer, p: usize, v: i64| {
            lp.advance(10);
            let mut m = Mutation::new();
            m.set(t, &reg, &Value::Int(v)).unwrap();
            lp.peers[p].commit(m).unwrap().unwrap()
        };
        let c = set(&mut lp, 1, 1);
        lp.sync_all().unwrap();
        lp.advance(10);
        let s1 = lp.peers[0].engine.snapshot(&t, &reg).unwrap().unwrap();
        lp.sync_all().unwrap();
        lp.peers[2].engine.drop_body(&c, &t, &reg).unwrap();
        set(&mut lp, 0, 2);
        lp.advance(10);
        lp.peers[0].engine.snapshot(&t, &reg).unwrap().unwrap();
        lp.sync_all().unwrap();
        let e = &mut lp.peers[2].engine;
        e.drop_body(&s1, &t, &reg).unwrap();
        assert!(e.forgettable(&s1));
        e.forget_commits(&[s1]).unwrap();
        // what S1 handed down is stored: the same after a restart
        lp.peers[2].restart(0).unwrap();
        lp.peers[2].engine.check_index();
        lp.advance(10);
        let sw = lp.peers[1].engine.snapshot(&t, &reg).unwrap().unwrap();
        let sw = lp.peers[1].engine.package(&sw).unwrap().unwrap();
        lp.advance(10);
        let d = lp.peers[0].engine.demote(&t, &Demotion { holder: w, new: None, retain: None }).unwrap();
        let ds: Vec<_> = d.commits.iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap()).collect();
        lp.deliver(2, &sw).unwrap();
        for d in &ds {
            lp.deliver(2, d).unwrap();
        }
        let e = &mut lp.peers[2].engine;
        assert!(!e.core.ix.commits[&sw.id].valid_at(0), "W's snapshot fell");
        assert!(matches!(e.core.ix.commits[&c].hold[0], Hold::Dropped(_)), "S2 carries C");
        assert!(e.suspects().unwrap().is_empty(), "no flag");
        assert_eq!(e.get(&t, &reg).unwrap(), Some(Value::Int(2)));
        e.check_index();
    }

    // spec/permissions.md §5.2, scale: a body dropped under a snapshot that drops under the next
    // and is forgotten, n times over, names the newest alone: each forget hands down to what
    // dropped under it, O(1) here, and the chain `uncover` walks stays one link, at n and 10n.
    #[test]
    fn forgotten_coverers_keep_the_chain_short_spec_permissions_5_2() {
        let work = |n: i64| {
            let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
            let e = &mut lp.peers[0].engine;
            let me = e.me();
            let reg = Ak::new("x:a.0").unwrap();
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, me);
            m.set(t, &reg, &Value::Int(0)).unwrap();
            let c = e.commit(m).unwrap().unwrap();
            let mut last: Option<CommitId> = None;
            osis_base::costs::take();
            for v in 1..=n {
                lp.advance(10);
                let e = &mut lp.peers[0].engine;
                let mut m = Mutation::new();
                m.set(t, &reg, &Value::Int(v)).unwrap();
                e.commit(m).unwrap();
                let s = e.snapshot(&t, &reg).unwrap().unwrap();
                match last {
                    None => e.drop_body(&c, &t, &reg).unwrap(),
                    Some(p) => {
                        e.drop_body(&p, &t, &reg).unwrap();
                        e.forget_commits(&[p]).unwrap();
                    }
                }
                last = Some(s);
            }
            let handed = osis_base::costs::take().iter().find(|x| x.0 == "forget: handed down").map_or(0, |x| x.2);
            let e = &mut lp.peers[0].engine;
            assert_eq!(e.coverers_of(&c, &t, &reg), vec![last.unwrap()], "the newest alone");
            e.check_index();
            handed
        };
        assert_eq!((work(4), work(40)), (3, 39), "one hand-down per forget");
    }
}
