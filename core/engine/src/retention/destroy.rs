//! Destroying a thing (spec/commits.md §5 Destruction): purging or expiring its creation. A thing
//! exists while a creation of it is held live; once every held creation of it is value-less the
//! thing goes in the transaction that made it so: its parts as bodies dropped (node-sync then
//! deletes them at peers by the dropped-body path), its states and per-aspect rows, but what
//! judges its destruction (`judges_destruction`: its record, its value-less mintings, its role-class
//! parts, the destroying requests' parts). Records are identity, `created.0` is existence: authority
//! that passed through it stands as its held edge writes say. What stays is
//! held by the ordinary rules, never its own: while the thing is in the node closure or a held thing
//! needs it (`retention::needed`), released whole as any thing; the requests are commits carrying a
//! purge request, kept as any (spec/commits.md §5 Forgetting, lasting). So a minting arriving later
//! falls under a held request as any named delta does. What a dependent needs travels with the
//! dependent: its holders place the record and frozen history under its sync IDs
//! (`Engine::destroyed_upstream`). `Core::exists` says the thing is gone all the same. A later write
//! on it is a write on an unknown thing, but an edge write: the walk reads every held edge write
//! whatever its stamp, so a destruction's right is judged as any request's (`kept_whole`).

use crate::engine::records;
use crate::engine::{Core, DropFor, Tx};
use crate::error::Result;
use crate::events::{Cause, Event};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::Header;
use osis_perm::Point;
use osis_store::Shred;
use std::collections::BTreeSet;

const CREATED: &str = osis_commit::retention::CREATED;
const ROLES: &str = "roles.0";

/// Aspects whose parts a destroyed thing keeps and still takes (`thing_wait`), so its destruction is
/// judged alike: its mintings, its role-class aspects (no content: its frozen edges, its keys and
/// sync IDs, as role history always stays) and the destroying requests' parts on it.
pub(crate) fn judges_destruction(ak: &str) -> bool {
    ak == CREATED || osis_schema::core_types::is_role_class(ak) || osis_commit::retention::destroying_request(ak)
}

/// Aspects a destroyed thing keeps whatever their stamp: its mintings, and its edge writes (the
/// walk's input, taken whatever their stamp, `thing_wait`): its destruction's right is judged as
/// any request's, by every held edge write (spec/commits.md §5 Destruction), so a removal stamped
/// after it reads the same in every arrival order.
pub(crate) fn kept_whole(ak: &str) -> bool {
    ak == CREATED || ak == ROLES
}

/// When a held minting is destroyed (spec/commits.md §5 Destruction): at its expiry `At(T, None)`,
/// after a request `At(wall_ms(ts), Some(point))`, or `Never`, whichever comes first. In this order
/// a part written after a later end is written after every earlier one: an expiry at `T` is
/// reached by every `ts` past a request stamped before `T`, a request stamped at or after `T` only
/// by `ts` past `T`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum End {
    At(u64, Option<Point>),
    Never,
}

impl End {
    /// Whether a part of a commit with header `h` is written after this end.
    fn after(&self, h: &Header) -> bool {
        match self {
            End::At(x, None) => *x <= h.ts.wall_ms().0,
            // stamped after the request: one at its `ts` is concurrent with it (spec/crdt.md §2.2)
            End::At(_, Some(p)) => p.ts < h.ts,
            End::Never => false,
        }
    }
}

/// A held minting's standing (spec/commits.md §5, A thing's mintings travel with its record):
/// valued ones after every value-less one, then by end. A thing is destroyed when its highest
/// held standing is value-less, and then at that end, so the highest minting is its witness: it
/// alone judges the thing as all of them do.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Standing {
    pub valued: bool,
    pub end: End,
}

/// A held minting of a thing: its commit and its standing. Every minting carries the thing's
/// record, so its expiry, and is purgeable by admins alone (spec/commits.md §5 Destruction): a
/// node holds its mintings at one standing, but for the transaction one arrives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Minting {
    pub commit: CommitId,
    pub standing: Standing,
}

/// `t`'s destruction (spec/commits.md §5 Destruction): the end of its witness, the point by which
/// every minting of it is dropped.
pub(crate) struct Destruction(End);

impl Destruction {
    /// `t`'s destruction, `None` while it is not destroyed.
    pub(crate) fn of(core: &Core, t: &Tid) -> Option<Destruction> {
        if !core.destroyed(t) {
            return None;
        }
        witness(core, t).map(|w| Destruction(w.standing.end))
    }

    /// Whether a part of a commit with header `h` is written after the destruction: nobody writes a
    /// thing after its destruction, so such a part is a part on an unknown thing, whatever its aspect.
    pub(crate) fn after(&self, h: &Header) -> bool {
        self.0.after(h)
    }
}

/// A held minting of `t` as `per_minting` reads it: `(commit, delta index)`, its expiry and the
/// held requests standing over it.
struct Held {
    at: (CommitId, usize),
    expires: Option<u64>,
    by: Vec<Point>,
}

/// The held requests with an item on `t`'s `created.0`, found among the requests with a delta
/// on `t` (`Indexes::purges_on`: a request has one on each thing it names), with their headers.
/// Held whether or not `t` keeps its mintings: a destroyed thing keeping nothing still holds them.
fn creation_requests<'a>(core: &'a Core, t: &'a Tid) -> impl Iterator<Item = (CommitId, &'a Header)> + 'a {
    let on_t = move |p: &Header| p.purge.iter().any(|i| i.tid() == t && i.ak().as_str() == CREATED);
    core.ix.purges_on.get(t).into_iter().flatten().filter_map(move |pc| core.ix.commits.get(pc).filter(|m| on_t(&m.header)).map(|m| (*pc, &*m.header)))
}

/// Each held minting of `t` (`Held`; its requests each a request with an item on `t`'s
/// `created.0`, `creation_requests`).
fn per_minting(core: &Core, t: &Tid) -> Vec<Held> {
    let requests: Vec<(CommitId, &Header)> = creation_requests(core, t).collect();
    // `Core::mintings` lists held commits alone: each has its header
    let held = core.mintings(t).filter_map(|(c, ai)| {
        let m = core.ix.commits.get(&c)?;
        let a = m.header.aspects.get(ai)?;
        let by = requests.iter().filter(|(pc, p)| super::purge::stands(core, p, pc, a, &m.header, &c)).map(|(pc, p)| Point { ts: p.ts, node: p.signer, commit: *pc }).collect();
        Some(Held { at: (c, ai), expires: m.header.expires, by })
    });
    held.collect()
}

/// Every held minting of `t` with its standing (`Standing`). Costs the held mintings times the
/// held requests on `t`'s creation.
pub fn mintings(core: &Core, t: &Tid) -> Vec<Minting> {
    let per = per_minting(core, t);
    per.into_iter()
        .map(|Held { at: (commit, ai), expires, by }| {
            let expiry = expires.map_or(End::Never, |x| End::At(x, None));
            let request = by.into_iter().min().map_or(End::Never, |p| End::At(p.ts.wall_ms().0, Some(p)));
            Minting { commit, standing: Standing { valued: !core.minting_gone(&commit, ai), end: expiry.min(request) } }
        })
        .collect()
}

/// `t`'s witness: its highest held minting (`Standing`), ties by the lowest commit ID. What
/// goes with `t`'s record (`Engine::minting_evidence`): its header and, destroyed, the requests
/// destroying it (`destroying_requests`). A node holding them judges `t` live or destroyed, and
/// when, as one holding every minting does.
pub fn witness(core: &Core, t: &Tid) -> Option<Minting> {
    highest(&mintings(core, t))
}

/// The witness among `ms` (a thing's held mintings): the highest standing, ties by the lowest
/// commit ID.
pub fn highest(ms: &[Minting]) -> Option<Minting> {
    ms.iter().copied().max_by(|a, b| a.standing.cmp(&b.standing).then(b.commit.cmp(&a.commit)))
}

/// The held requests standing over a minting of `t` (spec/commits.md §5 Destruction): with its
/// witness, what tells another node `t` was destroyed, a node holding an earlier witness too. Only
/// a right holder makes one: an admin.
pub(crate) fn destroying_requests(core: &Core, t: &Tid) -> BTreeSet<CommitId> {
    per_minting(core, t).into_iter().flat_map(|h| h.by).map(|p| p.commit).collect()
}

/// Ends the things a value-less list changed on in this transaction (`Core::valueless_dirty`,
/// taken at the end of the transaction, so any arrival order lands here).
pub(crate) fn apply_destructions(tx: &mut Tx<'_>) -> Result<()> {
    unnamed(tx.core);
    let dirty: BTreeSet<Tid> = tx.core.valueless_dirty.iter().filter(|(_, ak)| ak.as_str() == CREATED).map(|(t, _)| *t).collect();
    let (due, fell): (BTreeSet<Tid>, BTreeSet<Tid>) = dirty.into_iter().partition(|t| tx.core.destroyed(t));
    for t in &due {
        note(tx, t, true)?;
    }
    for t in &fell {
        note(tx, t, false)?;
    }
    if due.is_empty() && fell.is_empty() {
        return Ok(());
    }
    let mut changed = BTreeSet::new();
    for t in &fell {
        reopen_fallen(tx, t)?;
        reads_again(t, &mut changed);
    }
    for t in &due {
        destroy_thing(tx, t, &mut changed)?;
    }
    crate::apply::rejudged(tx, false)?;
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
    }
    Ok(())
}

/// Notes `t` held destroyed or not (`Indexes::destroyed`, rows `records::DESTROYED`).
pub(crate) fn note(tx: &mut Tx<'_>, t: &Tid, destroyed: bool) -> Result<()> {
    let key = [records::DESTROYED, t.as_bytes()].concat();
    if destroyed {
        if tx.core.ix.destroyed.insert(*t) {
            tx.txn.put_local(&key, &[], Shred::No)?;
        }
    } else if tx.core.ix.destroyed.remove(t) {
        tx.txn.remove_local(&key, Shred::Yes)?;
    }
    Ok(())
}

/// The things held destroyed at open: from their rows, or rebuilding, from their mintings (the
/// rows written again).
pub(crate) fn load(tx: &mut Tx<'_>, fast: bool) -> Result<()> {
    let rows = tx.scan_keys(records::DESTROYED, "destroyed", Tid::from_bytes)?;
    if fast {
        tx.core.ix.destroyed.extend(rows);
        return Ok(());
    }
    let things: Vec<Tid> = tx.core.ix.held.things().copied().collect();
    for t in rows {
        tx.txn.remove_local(&[records::DESTROYED, t.as_bytes()].concat(), Shred::Yes)?;
    }
    for t in things.iter().filter(|t| tx.core.destroyed(t)).copied().collect::<Vec<_>>() {
        note(tx, &t, true)?;
    }
    Ok(())
}

/// The holders some thing stopped naming since the last call (`Held::take_unnamed`): each is
/// judged for whether anything held still needs it (`retention::needed`).
fn unnamed(core: &mut Core) {
    for t in core.ix.held.take_unnamed() {
        core.note_lost(t);
    }
}

/// `t`'s destruction fell: the parts it dropped are fetched again (spec/commits.md §5 Destruction).
fn reopen_fallen(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    // a dropped keys.0 part's keysets left with it
    if reopen_destroyed(tx, t)? {
        crate::apply::keys::rebuild_keysets(tx, &BTreeSet::from([*t]))?;
    }
    // reads of the thing and its roles move, and whatever waited on the thing is judged again
    tx.core.ix.held.record_back(*t);
    Ok(())
}

/// The parts on `t` that `t`'s destruction dropped count as never received and are fetched again.
/// Whether one was a `keys.0` part.
fn reopen_destroyed(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    let commits: Vec<CommitId> = tx.core.on_thing(t).collect();
    let mut keys = false;
    for c in commits {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let destroyed: Vec<(usize, bool)> = m.dropped_parts().filter(|(_, d)| d.why == DropFor::Destroyed).filter_map(|(ai, _)| m.header.aspects.get(ai).filter(|a| a.tid == *t).map(|a| (ai, a.ak.as_str() == "keys.0"))).collect();
        for (ai, is_keys) in destroyed {
            keys |= is_keys;
            super::reopen_to_fetch(tx, &c, ai)?;
        }
    }
    Ok(keys)
}

/// What reads differently once `t` reads as gone or back while its record stays held.
fn reads_again(t: &Tid, changed: &mut BTreeSet<(Tid, Ak)>) {
    for ak in [CREATED, ROLES] {
        if let Ok(ak) = Ak::new(ak) {
            changed.insert((*t, ak));
        }
    }
}

/// Drops everything of `t` (`apply_destructions`) but what judges its destruction
/// (`judges_destruction`) written before it, and its edge writes whatever their stamp (the module
/// doc).
fn destroy_thing(tx: &mut Tx<'_>, t: &Tid, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    // what stays still reads as gone (`Core::exists`): observers hear it
    reads_again(t, changed);
    let destruction = Destruction::of(tx.core, t);
    let late = |core: &Core, id: &CommitId| destruction.as_ref().is_some_and(|e| core.ix.commits.get(id).is_some_and(|m| e.after(&m.header)));
    let aspects: Vec<(Ak, Vec<CommitId>)> = tx.core.aspects_of(t).filter(|((_, ak), _)| !judges_destruction(ak.as_str())).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).collect())).collect();
    // what it keeps but for its parts written after the destruction
    let partly: Vec<(Ak, Vec<CommitId>)> = tx.core.aspects_of(t).filter(|((_, ak), _)| judges_destruction(ak.as_str()) && !kept_whole(ak.as_str())).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).filter(|c| late(tx.core, c)).collect::<Vec<_>>())).filter(|(_, cs)| !cs.is_empty()).collect();
    for (ak, commits) in aspects.iter().chain(&partly) {
        for c in commits {
            if let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(t, ak)) {
                super::drop_part_for(tx, c, ai, DropFor::Destroyed)?;
            }
        }
    }
    for (ak, _) in &partly {
        crate::apply::rebuild(tx, t, ak)?;
        changed.insert((*t, ak.clone()));
    }
    for (ak, _) in &aspects {
        let k = (*t, ak.clone());
        crate::apply::rebuild(tx, t, ak)?;
        crate::engine::refs::clear(tx, t, ak)?;
        tx.txn.drop_aspect(t, ak)?;
        for p in [records::ASPECTS, records::FORGOTTEN, records::RESNAPSHOTS_OWED] {
            tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
        }
        super::suspect::forget(tx, t, ak, Shred::Yes)?;
        // as a node that never held it (spec/commits.md §5 Forgetting); no write on it is owed
        super::names::forget_aspect(tx, t, ak)?;
        tx.core.ix.forgotten.remove(&k);
        tx.core.ix.resnapshots_owed.remove(t, ak);
        if tx.core.ix.valueless.get(&k).is_some() {
            tx.core.touch();
            tx.core.ix.valueless.remove(&k);
        }
        tx.core.valueless_dirty.insert(k.clone());
        changed.insert(k);
    }
    Ok(())
}

/// Every per-aspect row of `(t, ak)` goes, as on a node that never held a part of it.
pub(super) fn forget_aspect_rows(tx: &mut Tx<'_>, t: &Tid, ak: &Ak) -> Result<()> {
    super::names::forget_aspect(tx, t, ak)?;
    let k = (*t, ak.clone());
    tx.core.ix.forgotten.remove(&k);
    tx.core.ix.resnapshots_owed.remove(t, ak);
    if tx.core.ix.valueless.remove(&k).is_some() {
        tx.core.touch();
    }
    for p in [records::ASPECTS, records::VALUELESS, records::PURGES, records::FORGOTTEN, records::RESNAPSHOTS_OWED] {
        tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
    }
    super::suspect::forget(tx, t, ak, Shred::Yes)?;
    crate::sync::falls::forget(tx, t, ak)?;
    for p in [records::LEFTOVER, records::PURGES_NAMED] {
        tx.remove_scanned(&records::aspect_key(p, t, ak), |_| Ok(true))?;
    }
    Ok(())
}

