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
//! A body here is one retention class of a commit (`body_class`): it is judged over the class,
//! and a part drops with the rest of its class. The class depends on what is held (`reader`), so
//! nothing kept may be keyed by it.

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Core, DropFor, Dropped, Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::events::{Cause, Event};
use osis_commit::{Header, Kind};
use osis_base::{Ak, CommitId, Tid};
use osis_crdt::Fragment;
use osis_schema::core_types::is_role_class;
use osis_store::Shred;
use std::collections::BTreeSet;

pub(crate) mod bounds;
pub(crate) mod history;
pub(crate) mod leftover;
mod pending;
mod purge;
mod replace;
pub(crate) mod snapshot;
#[cfg(test)]
mod oracle;
pub(crate) mod end;
pub(crate) mod forget;
pub(crate) mod memory;
pub(crate) use snapshot::{frontiers_now, reaches, snapshot_state};
#[cfg(test)]
pub(crate) use snapshot::write_snapshot;
pub mod suspect;

pub(crate) use replace::settle_none;
pub(crate) use pending::{emptied, fetch_fallen, forget_joined_leftovers, forget_waiting_leftovers, pending_drops, pending_expired, stripped_joined, waiting_stripped};
use pending::{purge_pending, strip_pending};
pub(crate) use purge::{check_request, counts_as_purged, known_purged, lasting, note_requests, purged_aspects, purged_by, rejudge_purges, requests_resting_on};
pub(crate) use snapshot::covered;
pub(crate) use bounds::{Killed, any_bounded, mark_killed, mark_bounded};

const T_EXPIRY: u8 = 1;
/// A purge-on-replace body kept to its commit's purge floor: judged again then (`replace`).
const T_FLOOR: u8 = 2;
/// A body's keep bound: a signal's body goes then (`signal_bound`); a listed value part leaves
/// the listing then (`listing::kept_passed`).
pub(crate) const T_KEPT: u8 = 3;

/// A signal delta's keep bound, wall ms (spec/commits.md §5 Signals): any body's keep at least
/// (`body_keep`), replaced when written; `None`: kept for good.
pub(crate) fn signal_bound(h: &Header, a: &osis_commit::AspectEntry) -> Option<u64> {
    let t = bounds::kept_until(h, a, Some(h.ts.wall_ms().0));
    (t < osis_commit::FOREVER).then_some(t)
}

/// Whether part `ai` of `h` is a signal's past its keep bound at wall ms `now` (spec/commits.md §5
/// Signals): past every bound, so no read shows it, no copy of it is taken and nothing makes it
/// missing again (fetched, or a suspect flag for it).
pub(crate) fn past_signal_bound(h: &Header, ai: usize, now: u64) -> bool {
    h.aspects.get(ai).filter(|a| a.ak.signal()).and_then(|a| signal_bound(h, a)).is_some_and(|t| t <= now)
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

/// The aspects of the retention class holding aspect `ai` of a commit (spec/commits.md §5: reader
/// actor and retention class). A class moves as records and keys arrive (the reader actor,
/// `Core::reader_of`), so nothing kept may be keyed by it.
pub(crate) fn body_class(core: &Core, h: &Header, ai: usize) -> Vec<usize> {
    let Some(me) = h.aspects.get(ai) else { return vec![ai] };
    let k = class_key(core, me);
    h.aspects.iter().enumerate().filter(|(_, a)| class_key(core, a) == k).map(|(i, _)| i).collect()
}

/// What groups a commit's deltas into bodies (`body_class`).
fn class_key(core: &Core, a: &osis_commit::AspectEntry) -> (Tid, osis_schema::Retention, Vec<usize>, bool) {
    // a signal's body is replaced when written, the others' when their writes die: never one class
    (core.reader_of(&a.tid), a.retention, a.keys.clone(), a.ak.signal())
}

/// Every retention class of header `h` (`body_class`), as the aspect indexes each holds, keyed
/// once per aspect: grouping all of a commit's parts costs O(parts), not O(parts²).
pub(crate) fn body_classes(core: &Core, h: &Header) -> Vec<Vec<usize>> {
    let mut at: std::collections::HashMap<_, usize> = std::collections::HashMap::new();
    let mut out: Vec<Vec<usize>> = Vec::new();
    for (i, a) in h.aspects.iter().enumerate() {
        let n = *at.entry(class_key(core, a)).or_insert_with(|| {
            out.push(Vec::new());
            out.len() - 1
        });
        if let Some(v) = out.get_mut(n) {
            v.push(i);
        }
    }
    out
}

/// Whether a delta's body has a relative keep bound (spec/commits.md §5): only it asks when the body
/// was replaced (`bounds::replaced_at`).
pub(crate) fn bounded(a: &osis_commit::AspectEntry) -> bool {
    history::of(a).dated()
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
/// expiry, when a held snapshot covers it (`expired_leftover`); one holding values
/// (`Meta::valued`) is dropped as a whole body.
pub(crate) fn drop_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    drop_part_for(tx, c, ai, DropFor::Other)
}

/// Whether part `ai` of `m` is a bare leftover past its expiry (spec/commits.md §5): value-less
/// for good, so it drops as covered like any body, its writes in the coverer (a purge's leftover
/// stays: the purge may fall and its values come back).
pub(crate) fn expired_leftover(m: &crate::engine::Meta, ai: usize, now: u64) -> bool {
    m.bare(ai) && m.header.expires.is_some_and(|t| t <= now)
}

/// `drop_part`, saying why.
fn drop_part_for(tx: &mut Tx<'_>, c: &CommitId, ai: usize, why: DropFor) -> Result<()> {
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    let invalid = why == DropFor::Invalid;
    // a bare leftover stays but past its expiry under a cover, or while invalid: then it gives
    // nothing; a signal's gives nothing ever, and goes at its keep bound
    let leftover = invalid || why == DropFor::Ended || why == DropFor::Cover && expired_leftover(&m, ai, tx.now().0) || a.ak.signal();
    if m.dropped.contains_key(&ai) || (m.bare(ai) && !leftover) {
        return Ok(());
    }
    // a setting not held binds nothing (spec/commits.md §5 Required retention); an invalid one
    // bound nothing already
    if a.ak.as_str() == osis_commit::retention::REQUIRED {
        let mut settings = tx.core.ix.required.get(&a.tid).cloned().unwrap_or_default();
        settings.retain(|x| x.0.commit != *c);
        if settings.is_empty() {
            tx.core.ix.required.remove(&a.tid);
        } else {
            tx.core.ix.required.insert(a.tid, settings);
        }
    }
    let k = (a.tid, a.ak.clone());
    // a stripped part's body is its leftover: read below as the held body, forgotten after
    let stripped = m.stripped.remove(&ai);
    m.valued.remove(&ai);
    let snapshot = m.header.kind.is_compaction();
    // the held valid snapshots covering it: their copies of its writes stay its writes
    // (an invalid body's writes are none of the state's, whatever carries copies of them)
    // (a plain commit counts only as its author's own whole replace: `snapshot::own_covers`)
    let snaps: Vec<CommitId> = if invalid || why == DropFor::Ended { Vec::new() } else { tx.core.ix.snapshots.get(&k).into_iter().flatten().map(|x| x.1).chain(snapshot::own_covers(tx.core, c, &a.tid, &a.ak)).filter(|s| s != c).collect() };
    let mut covered_by = BTreeSet::new();
    let own_cover = m.whole.remove(&ai);
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
    if stripped {
        leftover::remove(tx, &a.tid, &a.ak, c, ai)?;
    }
    m.dropped.insert(ai, Dropped { covered_by, why, stands_in, role, overreach, keysets, shown, superseded_by: BTreeSet::new() });
    if osis_schema::core_types::is_addenda(a.ak.as_str()) {
        crate::apply::validity::forget_addendum_body(tx.core, c, &a.tid);
    }
    // a part missing (again, `uncover`) and dropped is dropped, as an open reads it: received
    m.missing.remove(&ai);
    if let Some(blob) = tx.get_commit(c)? {
        let rest = osis_commit::rewrite(&blob, |x| x == ai);
        tx.put_commit(c, &rest, &m, Shred::Yes, None)?;
    }
    let header = m.header.clone();
    tx.core.put_meta(*c, m);
    crate::apply::note_stands_in(tx.core, c);
    crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, c);
    crate::apply::keys::forget_dropped(tx, &header, ai, &role_bodies)?;
    // a snapshot dropped other than as covered carries nothing: the parts dropped under its
    // cover alone are missing again
    if stands_in || (own_cover && why != DropFor::Cover) {
        uncover(tx, &a.tid, &a.ak)?;
    }
    // the one path (issues/drop-rejoin-robust.md item 1): the aspect is rebuilt from what is
    // held now, shredded (every local copy of the body goes,
    // spec/commits.md §5). A valid snapshot dropped vouches no more for invalid deltas' writes
    // it carried (spec/permissions.md §5.2). An ended thing's aspects rebuild once, after its last part (`retention::end`).
    if why == DropFor::Ended {
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
        m.aspect(&tid, &ak).and_then(|xai| m.dropped.get(&xai)).map(|d| d.covered_by.iter().copied().collect()).unwrap_or_default()
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
/// holding it finds it uncovered and re-uploads it, spec/sync.md §6; node-sync fetches it again,
/// `Changed::undropped`). The caller rebuilds the aspect.
pub(crate) fn uncover(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let core = &*tx.core;
    let carries = |s: &CommitId| {
        let Some(m) = core.ix.commits.get(s) else { return false };
        let Some(ai) = m.aspect(tid, ak) else { return false };
        m.valid_at(ai) && !m.dropped.contains_key(&ai) && !m.missing.contains(&ai)
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
        if m.dropped.get(&ai).is_some_and(|d| d.as_cover()) && !still(c, ai) {
            lost.push((*c, ai));
        }
    }
    let any = !lost.is_empty();
    if any {
        tx.core.forget_live(tid, ak);
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
    Ok(())
}

/// Whether held part `ai` of `m` goes once judged invalid (spec/permissions.md §6): any but a
/// role commit's (the role timeline and the possible holders read every held edge write, of any
/// validity, spec/permissions.md §5.1, spec/commits.md §4; a label holds and promotes the commit
/// whole, spec/sync.md §5), a part of this node's own commit (its user is
/// told the write was refused and may write it again from it, `DiagnosticKind::OwnWriteInvalid`)
/// and a memory part (forgotten with its commit once nothing of it is held, spec/sync.md §9, so it
/// could not come back: notes/ephemeral.md Divergences left).
fn goes_invalid(core: &Core, m: &crate::engine::Meta, ai: usize) -> bool {
    !m.valid_at(ai) && m.holds(ai) && !m.view.memory && Some(m.view.author) != core.me() && !m.view.kind.is_role()
}

/// Drops every held part judged invalid in this transaction (`Core::drop_due`) but those
/// `goes_invalid` keeps, each aspect rebuilt once (the one path: a record an invalid body left
/// with no write goes with it): its writes are none of the state's, so no read changes
/// (spec/permissions.md §5.2). Run at the transaction's end, after
/// this node's addenda (a witness lists what it received, `flows::addenda`).
pub(crate) fn drop_invalid(tx: &mut Tx<'_>) -> Result<()> {
    while !tx.core.drop_due.is_empty() {
        let due = std::mem::take(&mut tx.core.drop_due);
        crate::apply::run_batched(tx, |tx| {
            for c in &due {
                let Some(m) = tx.core.ix.commits.get(c) else { continue };
                let parts: Vec<usize> = (0..m.view.aspects.len()).filter(|ai| goes_invalid(tx.core, m, *ai)).collect();
                for ai in parts {
                    drop_part_for(tx, c, ai, DropFor::Invalid)?;
                }
            }
            Ok(())
        })?;
        // a judgment the dropped body fed is kept with it (`Dropped`), but a keyset rebuild
        // marks its commits for judging again: nothing flips, yet it is judged
        crate::apply::rejudged(tx, false)?;
    }
    Ok(())
}

/// The parts `parts` dropped while invalid that are valid now are missing again (spec/permissions.md
/// §6): they give nothing until the body arrives again, as at a node that never received it
/// (node-sync fetches it, `Changed::undropped`, from any holder; with none it stays gone at every
/// node alike). Until then this node may read less than one that kept it (its author). A signal's
/// past its keep bound stays dropped (`past_signal_bound`).
pub(crate) fn valid_again(tx: &mut Tx<'_>, parts: &[(CommitId, usize)]) -> Result<()> {
    let now = tx.now().0;
    let mut by_aspect: std::collections::BTreeMap<(Tid, Ak), Vec<(CommitId, usize)>> = std::collections::BTreeMap::new();
    for (c, ai) in parts {
        if let Some(a) = tx.core.ix.commits.get(c).filter(|m| m.dropped_invalid(*ai) && m.valid_at(*ai) && !past_signal_bound(&m.header, *ai, now)).and_then(|m| m.view.aspects.get(*ai)) {
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
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    // missing again, a dropped snapshot stands in no more (`Dropped::stands_in`)
    if m.dropped.remove(&ai).is_some_and(|d| d.stands_in)
        && let Some(a) = m.view.aspects.get(ai)
    {
        tx.core.ix.dropped_snapshots.remove(&(a.tid, a.ak.clone()), c);
    }
    m.missing.insert(ai);
    tx.core.ix.rotation_role.remove(&(*c, ai));
    tx.core.ix.shown.remove(&(*c, ai));
    tx.core.ix.grant_overreach.remove(&(*c, ai));
    // those are inputs of its judgment (`validity::rejudge_all` judges it again)
    tx.core.stale_commits.insert(*c);
    if let Some(blob) = tx.get_commit(c)? {
        tx.put_commit(c, &blob, &m, Shred::No, None)?;
    }
    tx.core.put_meta(*c, m.clone());
    Ok(Some(m))
}

/// node-sync fetches commit `c` again (`Changed::undropped`): a part held as its leftover or
/// missing whose purge fell.
fn refetch(tx: &mut Tx<'_>, c: &CommitId) {
    if let Some(ch) = &mut tx.core.changed {
        ch.undropped.insert(*c);
    }
}

/// `reopen`, and node-sync fetches it again (`Changed::undropped`).
fn reopen_to_fetch(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<crate::engine::Meta>> {
    let m = reopen(tx, c, ai)?;
    if let Some(ch) = &mut tx.core.changed {
        ch.undropped.insert(*c);
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
/// (`uncover` makes it missing), one dropped while invalid only once valid (`valid_again`). A memory part dropped other than as covered vanished whole
/// (superseded, its thing deleted here) and stays gone (`memory::forget_if_spent` forgets a
/// spent commit). A signal's part past its keep bound is past every bound: no copy is taken
/// (spec/commits.md §5 Signals), so a peer still holding it resends nothing that sticks.
pub(crate) fn takes_late(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    if past_signal_bound(&m.header, ai, tx.now().0) {
        return Ok(false);
    }
    if m.stripped.contains(&ai) {
        return Ok(gone_of(tx.core, &m.header, c, ai).is_empty());
    }
    Ok(!m.view.memory && m.dropped.get(&ai).is_some_and(|d| matches!(d.why, DropFor::Other | DropFor::Ended)))
}

/// Whether the value-carrying writes of delta `ai` of `c` are held value-less here
/// (`make_leftover`, or missing past its expiry or under a standing request).
pub(crate) fn valueless(core: &Core, c: &CommitId, ai: usize) -> bool {
    core.ix.commits.get(c).is_some_and(|m| !gone_of(core, &m.header, c, ai).is_empty())
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
        if m.stripped.contains(ai) {
            unstrip(tx, c, *ai, false)?;
        } else if m.dropped.contains_key(ai) {
            reopen(tx, c, *ai)?;
        }
    }
    Ok(())
}

/// Holds delta `ai` of `c` as its leftover from now on (spec/crdt.md §4.7): its own writes `o`
/// (`writes_of`) go on the value-less list, and their values go from its body and the aspect's
/// state, shredded (`strip_leftover`). A copy of a write listed later goes then
/// (`apply::rebuild`).
///
/// The leftover is the body as held (whole, or a leftover already), `extra` (what a waiting part
/// was stripped to, `pending::strip_purged`) or, dropped as covered, its held valid coverers'
/// copies of its writes, stripped (`Fragment::strip`: the value-less copy, spec/crdt.md §4.7); a
/// snapshot's keeps its frontiers and `Absorbed`. A part missing or dropped other than as covered has
/// none: the list alone holds it value-less, and a copy joins stripped (`takes_late`,
/// `drop_gone`); one missing is dropped (a tombstone for a new node).
///
/// Invariant: every write a node holds of a delta it holds value-less is in a held body, whole
/// or leftover, never in the state alone (the leftover is stored before the state is rebuilt
/// from the bodies), so an un-merge of a later write that superseded it gives it back
/// (`apply::rebuilt`), whatever order the expiry, that write and its revocation came in.
/// The aspect, when anything changed.
fn make_leftover(tx: &mut Tx<'_>, c: &CommitId, ai: usize, o: &[Owned], extra: &[Fragment]) -> Result<Option<(Tid, Ak)>> {
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
    let mut gives: Option<crate::engine::Gives> = None;
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        body.get_or_insert_default().join(f);
        Ok(())
    })?;
    gives = held.flatten().or(gives);
    for f in extra {
        body.get_or_insert_default().join(f.clone());
    }
    if body.is_none() && m.dropped.get(&ai).is_some_and(|d| d.as_cover()) {
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
        if m.missing.contains(&ai) && leftover::has(tx, &a.tid, &a.ak, c, ai)? {
            m.missing.remove(&ai);
            m.stripped.insert(ai);
            if let Some(blob) = tx.get_commit(c)? {
                tx.put_commit(c, &blob, &m, Shred::No, None)?;
            }
            tx.core.put_meta(*c, m);
            tx.core.mark_changed(*c);
            if let Some(ch) = &mut tx.core.changed {
                ch.undropped.remove(c);
            }
            crate::apply::rebuild(tx, &a.tid, &a.ak)?;
        } else if m.missing.contains(&ai) {
            drop_part_for(tx, c, ai, DropFor::Other)?;
        } else {
            crate::apply::rebuild(tx, &a.tid, &a.ak)?;
        }
        return Ok(Some(k));
    };
    strip_leftover(tx.core, &m.header, ai, &mut body);
    put_leftover(tx, c, ai, m, body, gives)?;
    // the one path (item 1): the state from the held bodies, the leftover among them, stripped
    // by the list, shredded (every local copy of the values goes)
    crate::apply::rebuild(tx, &a.tid, &a.ak)?;
    Ok(Some(k))
}

/// Snapshot part `ai` of `c` carries a copy of a value of a write on its aspect's value-less list
/// (spec/crdt.md §4.7 Copies, spec/commits.md §5): held as its leftover from now on, those copies
/// value-less. Store only: the caller rebuilds the aspect.
pub(crate) fn strip_carried(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let mut body: Option<Fragment> = None;
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        body.get_or_insert_default().join(f);
        Ok(())
    })?;
    let Some(mut body) = body else { return Ok(()) };
    tx.core.touch();
    strip_leftover(tx.core, &m.header, ai, &mut body);
    put_leftover(tx, c, ai, m, body, held.flatten())
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
/// It holds values while its own writes are off the value-less list (`Meta::valued`; a snapshot
/// always): a body for keep bounds.
fn put_leftover(tx: &mut Tx<'_>, c: &CommitId, ai: usize, mut m: crate::engine::Meta, body: Fragment, gives: Option<crate::engine::Gives>) -> Result<()> {
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    leftover::put(tx, &a.tid, &a.ak, c, ai, &leftover::Leftover { fragment: body, gives })?;
    let valued = gone_of(tx.core, &m.header, c, ai).is_empty();
    if m.stripped.contains(&ai) && m.valued.contains(&ai) == valued {
        return Ok(());
    }
    let whole = m.stripped.insert(ai);
    // a leftover says no entries (spec/permissions.md §5.2, Addenda: a list counts while its
    // body is held)
    if osis_schema::core_types::is_addenda(a.ak.as_str()) {
        crate::apply::validity::forget_addendum_body(tx.core, c, &a.tid);
    }
    if valued {
        m.valued.insert(ai);
    } else {
        m.valued.remove(&ai);
    }
    if whole {
        m.dropped.remove(&ai);
        m.missing.remove(&ai);
    }
    if let Some(blob) = tx.get_commit(c)? {
        // its body goes: the blob without the slot, shredded
        let (rest, shred) = if whole { (osis_commit::rewrite(&blob, |x| x == ai), Shred::Yes) } else { (std::sync::Arc::unwrap_or_clone(blob), Shred::No) };
        tx.put_commit(c, &rest, &m, shred, None)?;
    }
    tx.core.put_meta(*c, m);
    if whole {
        tx.core.mark_changed(*c);
        if let Some(ch) = &mut tx.core.changed {
            ch.undropped.remove(c);
        }
    }
    Ok(())
}

/// Part `ai` of `c`, held as its leftover, gives it up: the part is missing (counts as never
/// received), its writes leave the state (`apply::rebuild`). For the valued copy
/// arriving (`takes_late`), whose join brings them back valued; or on its purge's fall
/// (`rejudge_purges`), a delta's leftover then `kept` aside for a rise before a copy comes (held
/// value-less again, it holds what it left, as at a node that never saw the fall:
/// `make_leftover` adopts it).
fn unstrip(tx: &mut Tx<'_>, c: &CommitId, ai: usize, kept: bool) -> Result<()> {
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    if !m.stripped.remove(&ai) {
        return Ok(());
    }
    m.valued.remove(&ai);
    tx.core.touch();
    if !kept {
        leftover::remove(tx, &a.tid, &a.ak, c, ai)?;
    }
    m.missing.insert(ai);
    tx.core.stale_commits.insert(*c);
    if let Some(blob) = tx.get_commit(c)? {
        tx.put_commit(c, &blob, &m, Shred::No, None)?;
    }
    // a snapshot missing indexes nothing, as an open reads it
    crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, c);
    tx.core.put_meta(*c, m);
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
        strip_pending(tx, c, ai, true)?;
    }
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let own = writes_of(&m.header, c, ai);
    if let Some(k) = make_leftover(tx, c, ai, &own, &[])? {
        changed.insert(k);
    }
    // a memory commit's leftover may be superseded now (spec/sync.md §9), or covered by a
    // held snapshot (spec/commits.md §5); its caller forgets it
    changed.extend(memory::superseded_rest(tx, c)?);
    if tx.is_memory_commit(c)
        && let Some(a) = m.header.aspects.get(ai)
    {
        let k = (a.tid, a.ak.clone());
        if tx.core.ix.commits.get(c).is_some_and(|m| m.holds(ai)) {
            memory::drop_covered(tx, &[k.clone()].into(), Some(c), Some(c))?;
        }
        // the compaction trigger weighs leftovers (`Engine::memory_compactions`)
        tx.core.memory.dirty.insert(k);
    }
    Ok(())
}

/// Part `ai` of `c` just joined, carrying a value of a write the value-less list names (spec/crdt.md
/// §4.7: joined stripped): a late copy of an expired or purged delta is held as its leftover
/// (`make_leftover`); so is a snapshot carrying a copy of such a value (`strip_carried`).
fn drop_gone(tx: &mut Tx<'_>, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).filter(|m| m.holds(ai) && !m.stripped.contains(&ai)) else { return Ok(()) };
    let gone = gone_of(tx.core, &m.header, c, ai);
    if gone.is_empty() {
        let Some(k) = m.header.aspects.get(ai).map(|a| (a.tid, a.ak.clone())) else { return Ok(()) };
        let Some(list) = tx.core.ix.valueless.get(&k).filter(|l| !l.is_empty() && m.header.kind.is_compaction()).cloned() else { return Ok(()) };
        if crate::apply::carries_any(tx, c, ai, &list)? {
            strip_carried(tx, c, ai)?;
            crate::apply::rebuild(tx, &k.0, &k.1)?;
            changed.insert(k);
        }
        return Ok(());
    }
    strip_pending(tx, c, ai, true)?;
    if let Some(k) = make_leftover(tx, c, ai, &gone, &[])? {
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
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, &(0..h.aspects.len()).collect(), &mut purged, changed)?;
    purge::apply_request(tx, id, &h, &mut purged)?;
    // a further minting of a held thing may bring it back after its expiry (`end::end_ended`)
    for a in h.aspects.iter().filter(|a| a.ak.as_str() == osis_commit::retention::CREATED) {
        if tx.core.mintings(&a.tid).nth(1).is_some() {
            tx.core.valueless_dirty.insert((a.tid, a.ak.clone()));
        }
    }
    purged_changed(tx, purged, changed);
    Ok(())
}

/// After late parts `ais` of applied commit `id` joined: `on_apply` for them.
pub(crate) fn on_late(tx: &mut Tx<'_>, id: &CommitId, ais: &BTreeSet<usize>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, ais, &mut purged, changed)?;
    purged_changed(tx, purged, changed);
    Ok(())
}

/// Parts `ais` of applied commit `id`: expiry (now or by timer), held purge requests naming
/// them, held snapshots' parts carrying purged values, and on a memory commit what it supersedes
/// or covers. One held value-less (a copy of an expired or purged delta, joined stripped) is held
/// as its leftover: the list holds only what is past its expiry or a standing purge drops
/// (`rejudge_purges` takes the rest out; `drop_gone`).
fn on_parts(tx: &mut Tx<'_>, id: &CommitId, h: &Header, ais: &BTreeSet<usize>, purged: &mut BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    for ai in ais.iter().copied() {
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
        drop_gone(tx, id, ai, purged)?;
        // a signal body goes at its keep bound, whole or as its leftover
        if let Some(a) = h.aspects.get(ai).filter(|a| a.ak.signal())
            && let Some(t) = signal_bound(h, a)
        {
            if t <= tx.now().0 {
                drop_part(tx, id, ai)?;
            } else {
                tx.put_timer(t, id, ai, T_KEPT)?;
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
    for (t, a) in &purged {
        tx.core.mark_aspect_changed(t, a);
    }
    if !purged.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Purge, changed: purged.iter().cloned().collect() });
        changed.extend(purged);
    }
}

/// A due timer: its store key, commit, aspect index and kind (`T_EXPIRY`, `T_FLOOR`, `T_KEPT`).
type Due = (Vec<u8>, CommitId, usize, u8);

/// The timers due by the corrected clock, and when the first of the others is (`u64::MAX`: none).
fn due_timers(tx: &mut Tx<'_>) -> Result<(Vec<Due>, u64)> {
    let now = tx.now().0;
    let mut due = Vec::new();
    let mut next = u64::MAX;
    tx.scan(records::TIMER, |k, v| {
        let (t, c, ai) = records::parse_timer(k)?;
        if t <= now {
            due.push((k.to_vec(), c, ai, v.first().copied().unwrap_or(0)));
        } else {
            next = next.min(t);
        }
        Ok(())
    })?;
    Ok((due, next))
}

/// Runs due timer `key` (`records::timer_key`) of part `ai` of `c`, of `kind`; the
/// aspects it changed go to `changed`.
fn run_timer(tx: &mut Tx<'_>, key: &[u8], c: &CommitId, ai: usize, kind: u8, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    tx.txn.remove_local(key, Shred::No)?;
    // a value part's keep bound changes nothing held, only its listing
    if kind == T_KEPT && tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)).is_some_and(|a| !a.ak.signal()) {
        return crate::engine::listing::kept_passed(tx, c, ai);
    }
    // judged again by node-sync whatever the timer did
    tx.core.mark_changed(*c);
    let mut ch = BTreeSet::new();
    if kind == T_FLOOR {
        replace::floor_passed(tx, c, ai);
    } else if kind == T_KEPT {
        drop_part(tx, c, ai)?;
        crate::engine::edits::time_passed(tx, c, ai);
    } else {
        hold_valueless(tx, c, ai, false, &mut ch)?;
    }
    memory::forget_if_spent(tx, c)?;
    for (t, a) in &ch {
        tx.core.mark_aspect_changed(t, a);
    }
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
    /// again if it turns valid (spec/permissions.md §6, spec/sync.md §6).
    pub fn left_at_hosts(&self, c: &CommitId, ai: usize) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.dropped_invalid(ai) && !valueless(&self.core, c, ai))
    }

    /// Runs what is due by the corrected clock: expiries, purge floors (`T_FLOOR`), signal keep
    /// bounds (`T_KEPT`) and commits
    /// parked for drift. The
    /// commits whose timers fired are marked changed (`Core::changed`).
    pub fn tick(&mut self) -> Result<()> {
        let r = self.run(|tx| {
            let mut changed = BTreeSet::new();
            let (due, next) = due_timers(tx)?;
            // the timers these put lower it again
            tx.core.timer_floor = next;
            // their rebuilds once per aspect (`run_batched`: an expiry reads no state)
            crate::apply::run_batched(tx, |tx| {
                for (k, c, ai, kind) in due {
                    // a memory commit's timer is memory work: what it writes stays in memory
                    let memory = tx.is_memory_commit(&c);
                    tx.in_class(memory, |tx| run_timer(tx, &[records::TIMER, &k].concat(), &c, ai, kind, &mut changed))?;
                }
                Ok(())
            })?;
            if !changed.is_empty() {
                tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            }
            Ok(())
        });
        if r.is_err() {
            // the timers stay: due again
            self.core.timer_floor = 0;
        }
        r?;
        self.reexamine()
    }

    /// Whether a retention timer, durable or memory, is due by the corrected
    /// clock: in memory, no store read (a timer removed without running may leave a false
    /// `true`, which the next `tick` clears).
    pub fn timers_due(&self) -> bool {
        self.core.timer_floor <= self.now().0
    }

    /// When the next retention timer is due (corrected wall ms).
    pub fn next_timer(&mut self) -> Result<Option<u64>> {
        self.run(|tx| {
            let first = tx.txn.scan_local(records::TIMER, &[], 1)?;
            Ok(first.first().and_then(|(k, _)| k.get(records::TIMER.len()..)).and_then(|k| records::parse_timer(k).ok()).map(|(t, _, _)| t))
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

    /// Whether commit `c` may be forgotten, ID included (spec/commits.md §5, Forgetting): a
    /// content commit, every part dropped as covered by a cover of its own author, no purge
    /// request, nothing waiting.
    pub fn forgettable(&self, c: &CommitId) -> bool {
        // counted: tests read how many commits forgetting looks at
        let _s = crate::costs::span("forgettable");
        let core = &self.core;
        let Some(m) = core.ix.commits.get(c) else { return false };
        let own_cover = |d: &Dropped| d.why == DropFor::Cover && d.covered_by.iter().any(|x| core.ix.commits.get(x).is_none_or(|s| s.view.author == m.view.author));
        !m.view.memory && m.view.kind == Kind::Content && !m.view.purges && m.dropped.len() == m.view.aspects.len() && m.dropped.values().all(own_cover) && !core.ix.pending.contains_key(c)
    }

    /// Every commit `forgettable` holds true of (the first tick after an open: forgetting
    /// is otherwise by events).
    pub fn all_forgettable(&self) -> Vec<CommitId> {
        self.core.ix.commits.keys().copied().filter(|c| self.forgettable(c)).collect()
    }

    /// Forgets commit `c`, ID included: as if it had never applied (`apply::unindex_commit`).
    pub fn forget_commit(&mut self, c: &CommitId) -> Result<()> {
        let c = *c;
        self.run(|tx| crate::apply::unindex_commit(tx, &c))
    }

    /// Drops a body as covered (compaction, executed by node-sync): aspect `ak` of commit `c`.
    /// Refused unless a held valid snapshot covers it (every drop but expiry and purge is one
    /// as covered, spec/commits.md §5).
    pub fn drop_body(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx.core, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            drop_part_for(tx, &c, ai, DropFor::Cover)?;
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
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::flows::Demotion;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/commits.md §5 (replaced), scale: a reset killing every write of a filled map judges
    // the fill and a snapshot of it walking each held part a few times for its winners, never
    // once per death: the same count for 10 times the writes.
    #[test]
    fn reset_judged_walks_parts_once_spec_commits_5() {
        let walks = |n: usize| {
            let mut lp = LocalPeer::new(1, 953, WallMs(1_700_000_000_000)).unwrap();
            let a = lp.peers[0].engine.me();
            let x = Ak::new("x:m.0").unwrap();
            let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, history: Some(osis_schema::History::Keep { until: None, after: Some(3_600_000) }) };
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, a);
            lp.peers[0].commit(m).unwrap();
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Map((0..n).map(|i| (Value::Str(format!("k{i}")), Value::Int(i as i64))).collect())).unwrap().retention(t, &x, keep).unwrap();
            let fill = lp.peers[0].commit(m).unwrap().unwrap();
            lp.advance(10);
            let snap = lp.peers[0].engine.snapshot(&t, &x).unwrap().unwrap();
            lp.advance(10);
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Int(0)).unwrap().retention(t, &x, keep).unwrap();
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

    // spec/sync.md §3 Entitlement: a thing's reader actor is the nearest actor up its record
    // chain with secrets of its own, through first-admin links: a plain thing's is its first
    // admin's, and so is that of a thing below it; once a grant
    // gives it secrets of its own, its own.
    #[test]
    fn reader_actor_up_the_record_chain_spec_sync_3() {
        let mut lp = LocalPeer::new(2, 952, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let x = Ak::new("x:a.0").unwrap();
        let e = &mut lp.peers[0].engine;
        let p = e.create_with_admin(&a).unwrap().0;
        let r = e.create_with_admin(&p).unwrap().0;
        let mut m = Mutation::new();
        let q = e.new_thing(&mut m, p);
        let s = e.new_thing(&mut m, a);
        for t in [p, q, r, s] {
            m.set(t, &x, &Value::Int(1)).unwrap();
        }
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        // the things whose write of `x` in `c` is in the body class of its write on P
        let class = |e: &crate::Engine| {
            let h = e.core.ix.commits.get(&c).unwrap().header.clone();
            let ai = h.aspects.iter().position(|y| y.tid == p && y.ak == x).unwrap();
            let mut ts: Vec<_> = super::body_class(&e.core, &h, ai).iter().map(|i| &h.aspects[*i]).filter(|y| y.ak == x).map(|y| y.tid).collect();
            ts.sort();
            ts
        };
        let mut all = vec![p, q, r, s];
        all.sort();
        assert_eq!(class(&lp.peers[0].engine), all, "plain: every reader actor is A");
        let e = &mut lp.peers[0].engine;
        e.grant(&p, &b, &ct::Edge { role: Role::Read, until: None, invite: None, tied: None }).unwrap();
        assert!(e.core.ix.own_keys.contains(&p), "the grant gave P secrets of its own");
        let mut own = vec![p, q, r];
        own.sort();
        assert_eq!(class(&lp.peers[0].engine), own, "P's own, S still A's");
    }

    // spec/sync.md §7 (a body with live writes needs a carrier), spec/permissions.md §5.2: a
    // write made invalid (its author's removal by an admin that had not received it) counts
    // dead; a re-grant that makes it valid again counts it live again.
    #[test]
    fn body_live_follows_validity_spec_sync_7() {
        let mut lp = LocalPeer::new(3, 951, WallMs(1_700_000_000_000)).unwrap();
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
        assert!(lp.peers[0].engine.body_live(&c, &t, &ak).unwrap(), "W's write is the value");
        // no addendum of A's would list it
        lp.peers[0].engine.core.addenda_on = false;
        lp.advance(1_000);
        lp.peers[2].engine.demote(&t, &Demotion { holder: w, new: None, retain: None }).unwrap();
        lp.sync(2, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(!e.body_live(&c, &t, &ak).unwrap(), "invalid after a removal not listing it: dead");
        assert!(!e.core.ix.commits[&c].holds(0), "dropped while invalid");
        e.grant(&t, &w, &write).unwrap();
        assert!(e.core.ix.commits[&c].missing.contains(&0), "valid again after the re-grant: missing, fetched");
        lp.sync(1, 0).unwrap();
        assert!(lp.peers[0].engine.body_live(&c, &t, &ak).unwrap(), "fetched from its author: live");
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
        let mut lp = LocalPeer::new(2, 955, WallMs(1_700_000_000_000)).unwrap();
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
        assert!(e.body_live(&snap, &t, &ak).unwrap(), "its stamp is live at field 1");
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
        let mut lp = LocalPeer::new(1, 953, WallMs(1_700_000_000_000)).unwrap();
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
        m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: reg.clone() });
        m.set(t, &other, &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&t, &reg).unwrap(), None, "purged: the value-less winner reads absent");
        assert!(e.core.ix.commits.get(&c).unwrap().stripped.contains(&0), "the purged part is held as its leftover");
    }

    // spec/sync.md §6 (work sets): node-sync's change hook marks a commit whose validity flipped
    // (its author's removal by an admin that had not received it), and one whose body was
    // dropped; nothing is kept until node-sync asks.
    #[test]
    fn changed_marks_flips_and_drops_spec_sync_6() {
        let mut lp = LocalPeer::new(3, 952, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, w, x) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(0)).unwrap();
        let first = lp.peers[0].commit(m).unwrap().unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
        let admin = ct::Edge { role: Role::Admin, ..write.clone() };
        lp.peers[0].engine.grant(&t, &w, &write).unwrap();
        lp.peers[0].engine.grant(&t, &x, &admin).unwrap();
        lp.sync_all().unwrap();
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        e.take_changed();
        lp.sync(1, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(e.take_changed().commits.contains(&c), "applied");
        lp.peers[2].engine.demote(&t, &Demotion { holder: w, new: None, retain: None }).unwrap();
        lp.sync(2, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        let got = e.take_changed();
        assert!(got.commits.contains(&c), "the flipped commit");
        assert!(!got.commits.contains(&first), "not every commit on the flipped aspect");
        assert!(got.aspects.contains(&(t, ak.clone())), "the flipped aspect's state");
        e.snapshot(&t, &ak).unwrap().unwrap();
        e.take_changed();
        e.drop_body(&first, &t, &ak).unwrap();
        assert!(e.take_changed().commits.contains(&first), "dropped");
    }
}
