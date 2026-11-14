//! Destroying a thing (spec/commits.md §5 Destruction; notes/expiry-creation-design.md §3): purging or
//! expiring its creation. A thing exists while a creation of it is held live; once every held
//! creation of it is value-less the thing goes in the transaction that made it so: its parts as
//! bodies dropped (node-sync then deletes them at hosts by the dropped-body path), its states and
//! per-aspect rows. Records are identity, `created.0` is existence: what the thing created lives
//! on: authority that passed through it stands as its frozen history says. Its record, its
//! value-less mintings, its `roles.0` parts (no content) and the destroying requests' parts stay
//! while it **keeps** (`keeps`), by one rule: while something held needs them. A held thing it is
//! on an authority path of (`dependents`: a held record naming it first admin, a held edge
//! write naming it holder, whose verdicts climb its record edge and frozen edges; for a key actor
//! a held commit it signed or acted in with a part held on another thing, which its record
//! verifies), a held thing listing or referencing it (`needs_evidence`), or a held request
//! destroying it while it may be judged again (`in_force`: `ROLE_KEEP` after it or to its expiry, as role history
//! is kept; a removal ordered before it may make it fall, `reopen_fallen`). It is judged again
//! whenever one of those lets go, however: a reference or list going (`refs::note`), a record or
//! edge naming it going (`Held::take_unnamed`), a key actor's last commit held elsewhere going
//! (`Indexes::signed`), a request's window ending (its part's `T_KEPT` timer, or its part expiring). A
//! destroyed thing that keeps nothing leaves only the commits' headers and, once a purge request
//! destroying it is past its window, the verdict alone (`keeps`: destroyed for good). Its own
//! secrets, if it had any, stay only while node-sync may still delete an entry of its commits
//! (`hold_secrets`).
//! What a dependent needs travels with the dependent: its holders place the record and frozen
//! history under its labels (`Engine::destroyed_upstream`), and a node that kept nothing takes them
//! again when it opens them (`takes_late`), so it judges a dependent reaching it later as the
//! others do: the keep is per node, but no verdict depends on it.
//! `Core::exists` says the thing is gone all the same. A later write on it is a write on an
//! unknown thing.

use crate::engine::records;
use crate::engine::{Core, DropFor, Hold, Missing, Tx};
use crate::error::Result;
use crate::events::{Cause, Event};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::Header;
use osis_perm::Point;
use osis_store::Shred;
use std::collections::BTreeSet;

const CREATED: &str = osis_commit::retention::CREATED;
const ROLES: &str = "roles.0";

/// Aspects whose parts a destroyed thing still takes (`thing_wait`), so its destruction is judged alike:
/// its mintings, its frozen edges and the destroying requests' parts on it.
pub(crate) fn judges_destruction(ak: &str) -> bool {
    matches!(ak, CREATED | ROLES) || osis_commit::retention::destroying_request(ak)
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
    /// Whether a part of commit `id` (header `h`) is written after this end.
    fn after(&self, h: &Header, id: &CommitId) -> bool {
        match self {
            End::At(x, None) => *x <= h.ts.wall_ms().0,
            End::At(_, Some(p)) => *p < Point { ts: h.ts, node: h.author, commit: *id },
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

/// A held minting of a thing: its commit and its standing.
#[derive(Clone, Copy, Debug)]
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

    /// Whether a part of commit `id` (header `h`) is written after the destruction: nobody writes a
    /// thing after its destruction, so such a part is a part on an unknown thing, whatever its aspect.
    pub(crate) fn after(&self, h: &Header, id: &CommitId) -> bool {
        self.0.after(h, id)
    }
}

/// A held minting of `t` as `per_minting` reads it: `(commit, delta index)`, its expiry and the
/// held requests standing over it.
struct Held {
    at: (CommitId, usize),
    expires: Option<u64>,
    by: Vec<Point>,
}

/// Each held minting of `t` (`Held`; its requests each a request with an item on `t`'s
/// `created.0`, found among the commits on `t`: a request has a delta on each thing it names).
fn per_minting(core: &Core, t: &Tid) -> Vec<Held> {
    let on_t = |p: &Header| p.requests().iter().any(|i| i.tid() == t && i.ak().as_str() == CREATED);
    let requests: Vec<(CommitId, &Header)> = core.on_thing(t).filter_map(|pc| core.ix.commits.get(&pc).filter(|m| m.view.purges && on_t(&m.header)).map(|m| (pc, &*m.header))).collect();
    let held = core.mintings(t).map(|(c, ai)| {
        let none = Held { at: (c, ai), expires: None, by: Vec::new() };
        let Some(m) = core.ix.commits.get(&c) else { return none };
        let Some(a) = m.header.aspects.get(ai) else { return none };
        let by = requests.iter().filter(|(pc, p)| super::purge::stands(core, p, pc, a, &m.header, &c)).map(|(pc, p)| Point { ts: p.ts, node: p.author, commit: *pc }).collect();
        Held { at: (c, ai), expires: m.header.expires, by }
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
    mintings(core, t).into_iter().max_by(|a, b| a.standing.cmp(&b.standing).then(b.commit.cmp(&a.commit)))
}

/// The held requests standing over a minting of `t` (spec/commits.md §5 Destruction): with its
/// witness, what tells another node `t` was destroyed, a node holding an earlier witness too. Only
/// a right holder makes one: an admin, or a writer for its own minting or for one of class `writer`.
pub(crate) fn destroying_requests(core: &Core, t: &Tid) -> BTreeSet<CommitId> {
    per_minting(core, t).into_iter().flat_map(|h| h.by).map(|p| p.commit).collect()
}

/// How `t` was destroyed, read at wall ms `now`: by release alone (storage reclaim, never erasure:
/// every held minting dropped by a standing release request, none by a purge or its own
/// expiry), and then whether every such request is past its expiry (spec/commits.md §5
/// Destruction, Forgetting). `None`: not destroyed by release alone.
fn release_state(core: &Core, t: &Tid, now: u64) -> Option<bool> {
    let per = per_minting(core, t);
    let mut spent = true;
    for Held { expires: x, by, .. } in &per {
        if by.is_empty() || x.is_some_and(|x| x <= now) {
            return None;
        }
        for p in by {
            let m = core.ix.commits.get(&p.commit)?;
            if !m.header.is_release() {
                return None;
            }
            spent &= m.header.expires.is_some_and(|x| x <= now);
        }
    }
    (!per.is_empty()).then_some(spent)
}

/// Whether `t` was destroyed by release alone (`release_state`): nothing of it is erasure's, so no
/// header of it lasts (`purge::lasting`).
pub(crate) fn released(core: &Core, t: &Tid, now: u64) -> bool {
    release_state(core, t, now).is_some()
}

/// Whether something held here needs the evidence that `t` was destroyed (notes/lifetimes.md,
/// What is kept): a dependent (`dependents`), or another held thing listing it in
/// `retainers^.0` or referencing it in a live durable value other than `group.0` (the
/// reference index, `needs_from`). One rule
/// for every destruction: while it holds, `t`'s record, value-less creation, `roles.0` and destruction
/// request parts stay and travel under that thing's labels (`Engine::certificates`).
pub(crate) fn needs_evidence(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    if dependents(tx.core, t) {
        return Ok(true);
    }
    Ok(crate::engine::refs::to(tx, t)?.iter().any(|r| r.source != *t && needs_from(&r.ak)))
}

/// Whether a reference row in aspect `ak` makes its source need the evidence that its target
/// destroyed: a live durable value, but not `group.0` (a group contains its members, it does not
/// depend on them: readers show nothing for an unknown member; it still keeps a member alive
/// for the lifetime judgment).
pub(crate) fn needs_from(ak: &Ak) -> bool {
    !ak.ephemeral() && ak.as_str() != osis_schema::RawKey::ak(&osis_schema::core_types::GROUP)
}

/// Whether a request destroying `t` is in force here: until the latest held request standing
/// over a minting of it passes `wall_ms(ts) + ROLE_KEEP` or its `expires`, the earlier (a release's
/// `expires`; a purge's floor, `purge_keep_until`: while its blobs are kept for nodes that have not
/// seen it, and a role write ordered before it may make it fall). Judging it reads `t`'s record and
/// frozen edges. Judged again at that end: the request's part on `t` going value-less, or its floor's
/// timer (`T_KEPT`). Not for a thing whose every creation is past its expiry: nothing can make that
/// fall.
fn in_force(tx: &Tx<'_>, t: &Tid) -> bool {
    if every_creation_expired(tx, t) {
        return false;
    }
    let now = tx.now().0;
    destroying_requests(tx.core, t).iter().filter_map(|pc| tx.core.ix.commits.get(pc)).any(|m| {
        let end = osis_commit::retention::release_expires(m.view.ts).min(m.header.expires.unwrap_or(u64::MAX));
        end > now
    })
}

/// Whether destroyed `t` keeps its record and what tells it was destroyed: while a held thing needs
/// it (`needs_evidence`, noted in `Core::destroyed_kept`) or a request destroying it is in force
/// (`in_force`). A purge request standing past its window cannot fall here any more: `t` is
/// marked destroyed for good (`Indexes::destroyed_for_good`), the verdict kept without its
/// evidence, so no minting of it arriving later is taken (`apply::thing_wait`). Erasure's tombstone
/// (notes/deletion.md); a release leaves none, an expiry needs none (a copy carries its `expires`).
fn keeps(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    let needs = needs_evidence(tx, t)?;
    tx.core.note_destroyed_kept(t, needs);
    if in_force(tx, t) {
        return Ok(true);
    }
    let purged = destroying_requests(tx.core, t).iter().any(|pc| tx.core.ix.commits.get(pc).is_some_and(|m| !m.header.is_release()));
    if purged && tx.core.ix.destroyed_for_good.insert(*t) {
        tx.txn.put_local(&[records::DESTROYED, t.as_bytes()].concat(), &[], Shred::No)?;
    }
    Ok(needs)
}

/// Ends the things a value-less list changed on in this transaction (`Core::valueless_dirty`,
/// taken at the end of the transaction, so any arrival order lands here).
pub(crate) fn apply_destructions(tx: &mut Tx<'_>) -> Result<()> {
    let dirty: BTreeSet<Tid> = tx.core.valueless_dirty.iter().filter(|(_, ak)| ak.as_str() == CREATED).map(|(t, _)| *t).collect();
    let (due, fell): (BTreeSet<Tid>, BTreeSet<Tid>) = dirty.into_iter().partition(|t| tx.core.destroyed(t));
    // destroyed things whose keep may have gone: a destroying request's part on it expired, its
    // window ended, or something that needed it let go of it (`Core::destroyed_due`: a reference
    // or list went, a key actor's last commit held elsewhere; `Held::take_unnamed`: a record or
    // edge naming it went)
    let mut again: BTreeSet<Tid> = tx.core.valueless_dirty.iter().filter(|(_, ak)| osis_commit::retention::destroying_request(ak.as_str())).map(|(t, _)| *t).collect();
    again.extend(std::mem::take(&mut tx.core.destroyed_due));
    again.extend(tx.core.ix.held.take_unnamed());
    again.retain(|t| !due.contains(t) && !fell.contains(t) && tx.core.created(t).is_some() && tx.core.destroyed(t));
    if due.is_empty() && fell.is_empty() && again.is_empty() {
        return Ok(());
    }
    // the things whose holders for keys these were (named on them, or on a destroyed actor so
    // named): possession counts their frozen holders in their place (spec/crypto.md §4, Holder
    // actors, Destroyed), so their verdicts are judged again
    let mut seen: BTreeSet<Tid> = due.union(&fell).copied().collect();
    let mut work: Vec<Tid> = seen.iter().copied().collect();
    while let Some(t) = work.pop() {
        let on: Vec<Tid> = tx.core.ix.held.named_on(&t).copied().filter(|x| *x != t).collect();
        for x in on {
            tx.core.stale_things.insert(x);
            if tx.core.destroyed_actor(&x) && seen.insert(x) {
                work.push(x);
            }
        }
    }
    // known again or destroyed: judged, with what lists it
    for t in due.iter().chain(&fell) {
        super::lifetimes::queue_with_listers(tx, t)?;
    }
    let mut changed = BTreeSet::new();
    for t in &fell {
        reopen_fallen(tx, t)?;
        reads_again(t, &mut changed);
    }
    let mut held_changed = false;
    for t in &due {
        held_changed |= destroy_thing(tx, t, &mut changed)?;
    }
    // a kept destroyed thing goes once nothing keeps it (what that drops may let more go)
    loop {
        again.extend(std::mem::take(&mut tx.core.destroyed_due));
        again.extend(tx.core.ix.held.take_unnamed());
        let Some(t) = again.pop_first() else { break };
        if tx.core.destroyed(&t) && tx.core.created(&t).is_some() && !keeps(tx, &t)? {
            held_changed |= destroy_thing(tx, &t, &mut changed)?;
        }
    }
    if held_changed {
        tx.core.update_timelines();
    }
    crate::apply::rejudged(tx, held_changed)?;
    if !changed.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
    }
    Ok(())
}

/// `t`'s destruction fell: the parts it dropped are fetched again (spec/commits.md §5 Destruction).
fn reopen_fallen(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    // a keys.0 part's keysets left with its dropped record
    if reopen_destroyed(tx, t, |_| true)? {
        crate::apply::keys::rebuild_keysets(tx, &BTreeSet::from([*t]))?;
    }
    unhold_secrets(tx, t)?;
    // reads of the thing and its roles move, and whatever waited on the thing is judged again
    tx.core.role_changed();
    tx.core.ix.held.record_back(*t);
    Ok(())
}

/// `t`'s record is held again after its destruction here kept nothing of it (a dependent reached this
/// node later): what that drop took of its frozen history (`judges_destruction` but its mintings,
/// which stay destroyed) counts as never received and is fetched again (spec/commits.md §5 Destruction).
pub(crate) fn record_back(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    reopen_destroyed(tx, t, |ak| judges_destruction(ak) && ak != CREATED)?;
    Ok(())
}

/// The parts on `t` of the aspects `on` names that `t`'s destruction dropped count as never
/// received and are fetched again. Whether one was a `keys.0` part.
fn reopen_destroyed(tx: &mut Tx<'_>, t: &Tid, on: impl Fn(&str) -> bool) -> Result<bool> {
    let commits: Vec<CommitId> = tx.core.on_thing(t).collect();
    let mut keys = false;
    for c in commits {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let destroyed: Vec<(usize, bool)> = m.dropped_parts().filter(|(_, d)| d.why == DropFor::Destroyed).filter_map(|(ai, _)| m.header.aspects.get(ai).filter(|a| a.tid == *t && on(a.ak.as_str())).map(|a| (ai, a.ak.as_str() == "keys.0"))).collect();
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

/// Whether `t`'s every creation is past its expiry: a destruction nothing can make fall, whatever
/// purge requests it also holds.
fn every_creation_expired(tx: &Tx<'_>, t: &Tid) -> bool {
    let now = tx.now().0;
    tx.core.mintings(t).all(|(c, _)| tx.core.ix.commits.get(&c).is_some_and(|m| m.header.expires.is_some_and(|x| x <= now)))
}

/// Whether something held here depends on `t` (the module doc): `t` is on an authority path of
/// another held thing (a held record names it first admin, or a held edge write names it
/// holder), or for a key actor a held durable commit it signed or acted in has a part held on
/// another thing (`Indexes::signed`).
pub(crate) fn dependents(core: &crate::engine::Core, t: &Tid) -> bool {
    let key = core.is_key_actor(t);
    let signed = key && core.ix.signed.get(t).is_some_and(|n| *n > 0);
    // checked on every key actor judged, named or not
    debug_assert!(!key || signed == core.ix.commits.values().any(|m| !m.view.memory && (m.view.author == *t || m.view.actor == *t) && m.view.aspects.iter().enumerate().any(|(ai, a)| a.tid != *t && !m.is_dropped(ai))), "Indexes::signed of {t}");
    signed || core.ix.held.named_on(t).any(|x| x != t)
}

/// Drops everything of `t` (`apply_destructions`) but what it keeps (the module doc). Whether the role
/// timelines' inputs changed: they do when it keeps nothing.
fn destroy_thing(tx: &mut Tx<'_>, t: &Tid, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<bool> {
    let keep = keeps(tx, t)?;
    // released, every request past its expiry: with what it drops the node forgets it
    let forget = !keep && release_state(tx.core, t, tx.now().0) == Some(true);
    if keep {
        // what stays still reads as gone (`Core::exists`): observers hear it
        reads_again(t, changed);
    }
    // the holders its `roles.0` entries keyed go with the entries: read while the parts are held
    // kept or not, an edge write on it stamped after its destruction goes (`Destruction::after`), judged
    // once while the late writes are still held
    let destruction = Destruction::of(tx.core, t);
    let late = |core: &Core, id: &CommitId| destruction.as_ref().is_some_and(|e| core.ix.commits.get(id).is_some_and(|m| e.after(&m.header, id)));
    let edge_commits: Vec<CommitId> = tx.core.ix.held.commits_on(t).iter().map(|c| c.id).filter(|c| !keep || late(tx.core, c)).collect();
    for id in &edge_commits {
        let parts = crate::apply::edge_parts(tx, id)?;
        let view = tx.core.ix.commits.get(id).map(|m| m.view.clone());
        for (ai, es) in &parts.0 {
            let Some(v) = view.as_ref().filter(|v| v.aspects.get(*ai).is_some_and(|a| a.tid == *t)) else { continue };
            // the entries it created (a reset of another's entry keys nothing: that one's commit
            // may stay)
            let own = crate::engine::Owned::of_view(v, id, *ai);
            for (d, _, _) in es.iter().filter(|(d, _, _)| own.as_ref().is_some_and(|o| o.owns(d.origin()))) {
                tx.core.ix.holder_keys.remove(&(*t, d.clone()));
            }
        }
    }
    let aspects: Vec<(Ak, Vec<CommitId>)> = tx.core.aspects_of(t).filter(|((_, ak), _)| !keep || !judges_destruction(ak.as_str())).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).collect())).collect();
    // what it keeps but for its parts written after the destruction
    let partly: Vec<(Ak, Vec<CommitId>)> = if keep {
        tx.core.aspects_of(t).filter(|((_, ak), _)| judges_destruction(ak.as_str()) && ak.as_str() != CREATED).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).filter(|c| late(tx.core, c)).collect::<Vec<_>>())).filter(|(_, cs)| !cs.is_empty()).collect()
    } else {
        Vec::new()
    };
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
    let held_changed = !edge_commits.is_empty();
    for id in edge_commits {
        // a role commit keeps its row and its place, empty once its last edge goes: as an open reads it
        let mut parts = crate::apply::edge_parts(tx, &id)?;
        let Some((view, m)) = tx.core.ix.commits.get(&id).map(|m| (m.view.clone(), m.clone())) else { continue };
        // the parts it dropped are not held (a role commit's record keeps them)
        parts.0.retain(|(ai, _)| m.holds(*ai));
        tx.core.ix.held.remove(&id);
        crate::apply::validity::add_role_commit(tx.core, &view, &id, &parts);
        crate::engine::index::put_edges(tx, &id, &parts, Shred::Yes)?;
    }
    for (ak, _) in &aspects {
        let k = (*t, ak.clone());
        crate::apply::rebuild(tx, t, ak)?;
        crate::engine::refs::clear(tx, t, ak)?;
        tx.txn.drop_aspect(t, ak)?;
        for p in [records::ASPECTS, records::SUSPECT, records::FORGOTTEN] {
            tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
        }
        // as a node that never held it (spec/commits.md §5 Forgetting)
        tx.core.ix.forgotten.remove(&k);
        if tx.core.ix.valueless.get(&k).is_some() {
            tx.core.touch();
            tx.core.ix.valueless.remove(&k);
        }
        tx.core.valueless_dirty.insert(k.clone());
        changed.insert(k);
    }
    if keep {
        unhold_secrets(tx, t)?;
    } else {
        hold_secrets(tx, t)?;
        tx.txn.remove_local(&[records::CREATED, t.as_bytes()].concat(), Shred::Yes)?;
        tx.core.ix.held.forget_record(t);
        tx.core.tree_reach.remove(t);
        crate::rotation::merge::forget(tx, t)?;
        if forget {
            forget_released(tx, t)?;
        }
        // the destroyed actors on its authority paths, kept for it alone, go in
        // `apply_destructions`'s loop: its record and edges going unname them (`Held::take_unnamed`)
    }
    tx.core.role_changed();
    Ok(held_changed || !keep)
}

/// Forgets released `t` once its release requests are past their expiry and nothing keeps it
/// (spec/commits.md §5 Forgetting; `destroy_thing` dropped every part of it and its record). Of each
/// commit on `t`, a part elsewhere is marked forgotten (`Missing::Forgot`: on a released thing
/// forgotten here before, this transaction's included, whose record is not held again), missing on a thing whose record is not
/// held (unknown here, maybe alive elsewhere), or other (on a thing held here):
/// - all marked: it goes whole, header and ID included; node-sync deletes its entries where it
///   may, then forgets them (`MemoryDrop::Gone`);
/// - none other, some unknown: it goes here alone, as a commit thrown out awaiting records; its
///   entries stay at hosts, node-sync skipping them until one of those records arrives
///   (`MemoryDrop::Awaits`);
/// - else it keeps its header, its parts on `t` counting as never received, marked forgotten:
///   not fetched, joined (the mark going) if a copy comes (spec/commits.md §5 Never received).
///
/// `t` is then unknown here, as on a node that never held it.
fn forget_released(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let aks: Vec<Ak> = tx.core.aspects_of(t).map(|((_, ak), _)| ak.clone()).collect();
    let commits: Vec<CommitId> = tx.core.on_thing(t).collect();
    // aspects elsewhere of commits that went: unindexing marked them forgotten
    let mut others: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    for c in commits {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let aspects = &m.header.aspects;
        let on_t: Vec<usize> = m.view.aspects_on(t).collect();
        // not held (missing, or dropped) on a thing whose record is not held
        let unknown = |ai: &usize| !m.holds(*ai) && aspects.get(*ai).is_some_and(|a| tx.core.created(&a.tid).is_none());
        // a marked part whose thing's record came back is live again until its copy joins
        let elsewhere = (0..aspects.len()).filter(|ai| !on_t.contains(ai) && !(m.missing_as(*ai) == Some(Missing::Forgot) && unknown(ai)));
        let (mut awaited, mut held) = (Vec::new(), false);
        for ai in elsewhere {
            if unknown(&ai) {
                awaited.extend(aspects.get(ai).map(|a| a.tid));
            } else {
                held = true;
            }
        }
        if !held {
            others.extend(aspects.iter().filter(|a| a.tid != *t).map(|a| (a.tid, a.ak.clone())));
            let header = m.header.arc();
            crate::apply::unindex_commit(tx, &c)?;
            // as a node that never held it: no purge list names it (one on a thing never held)
            super::purge::unnote_requests(tx, &c, &header)?;
            // node-sync deletes its entries at hosts where it may and forgets them once gone, as
            // a memory commit's gone whole (`take_memory_drops`), or skips them awaiting a record
            let why = if awaited.is_empty() { crate::engine::MemoryDrop::Gone } else { crate::engine::MemoryDrop::Awaits { things: awaited } };
            tx.core.memory.dropped.push((c, header, why));
            continue;
        }
        let mut m = m.clone();
        for ai in on_t.iter().copied().filter(|ai| m.is_dropped(*ai)).collect::<Vec<_>>() {
            super::reopen_in(tx, &c, &mut m, ai);
        }
        // dead at every node: one to be fetched is not (`Missing::ToFetch` goes)
        for ai in on_t.into_iter().filter(|ai| m.missing(*ai)).collect::<Vec<_>>() {
            m.set_hold(ai, Hold::Missing(Missing::Forgot));
        }
        if let Some(blob) = tx.get_commit(&c)? {
            tx.put_commit(&c, &blob, &m, Shred::No, None)?;
        }
        tx.core.put_meta(c, m);
        tx.core.mark_changed(c);
    }
    // as a node that never held it: no per-aspect row of it stays
    for ak in &aks {
        forget_aspect_rows(tx, t, ak)?;
    }
    // with no held part left on one, as a node that never held it: of a thing whose record is
    // not held, every per-aspect row (a request's purge items and value-less list on a thing never
    // held here); of a held one, the FORGOTTEN row unindexing wrote
    for (u, ak) in others {
        if tx.core.ix.by_aspect.get(&(u, ak.clone())).is_some_and(|s| !s.is_empty()) {
            continue;
        }
        if tx.core.created(&u).is_none() {
            forget_aspect_rows(tx, &u, &ak)?;
        } else {
            tx.core.ix.forgotten.remove(&(u, ak.clone()));
            tx.txn.remove_local(&records::aspect_key(records::FORGOTTEN, &u, &ak), Shred::Yes)?;
        }
    }
    super::leaving::forget_things(tx, &BTreeSet::from([*t]))?;
    Ok(())
}

/// Destroyed `t` keeps nothing here (its record goes): its own secrets, if held, are noted as
/// held for node-sync alone (`Indexes::destroyed_secrets`, `records::DESTROYED_SECRETS`).
///
/// Invariant: a destroyed thing's own secrets (`Indexes::secrets`, its `k/` row) are held while it
/// keeps (`keeps`: a dependent's content may be keyed by its epochs, reached up its record chain)
/// and, once it keeps nothing, exactly while this node may still delete something by the delete
/// keys `Core::delete_chain` derives from them, of a commit **keyed by it** (a part on it: levels 1
/// and 3; acting for it: level 2, the author chain, spec/crypto.md §7): a freed link of its thing
/// or author (judged here), or, under a label node-sync syncs, an entry of such a commit whose
/// sections list a part on it (any, of one acting for it) or a delete of one within its tombstone
/// (judged by node-sync, `SyncEngine::drop_destroyed_secrets`, when the thing is noted here, after
/// each start, and when such an entry, delete or freed link goes). Nothing else needs them: the
/// thing reads as absent, nothing is written on it or for it (a valid write acting for it is on a
/// thing that needs it), and a dependent reaching this node later brings what reads its parts
/// (spec/commits.md §5 Destruction). Limit: an entry left awaiting a record (`Kind::Awaits`) keeps
/// no header to tell, so one of a commit keyed by it stays at hosts once the secrets went.
fn hold_secrets(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    if tx.core.ix.secrets.get(t).is_none() || tx.core.ix.destroyed_secrets.contains(t) {
        return Ok(());
    }
    tx.core.ix.destroyed_secrets.insert(*t);
    tx.core.destroyed_secrets_due.insert(*t);
    tx.txn.put_local(&[records::DESTROYED_SECRETS, t.as_bytes()].concat(), &[], Shred::No)?;
    Ok(())
}

/// `t` keeps again, or its destruction fell: its secrets are its own again, not node-sync's.
fn unhold_secrets(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    if tx.core.ix.destroyed_secrets.remove(t) {
        tx.txn.remove_local(&[records::DESTROYED_SECRETS, t.as_bytes()].concat(), Shred::No)?;
    }
    Ok(())
}

impl crate::engine::Engine {
    /// The destroyed things whose own secrets are held for node-sync's deletes alone (`hold_secrets`)
    /// to judge again since the last call: node-sync drops each (`drop_destroyed_secrets`) once it
    /// knows no entry of a commit keyed by it.
    pub fn take_destroyed_secrets_due(&mut self) -> BTreeSet<Tid> {
        let due = std::mem::take(&mut self.core.destroyed_secrets_due);
        due.into_iter().filter(|t| self.core.ix.destroyed_secrets.contains(t)).collect()
    }

    /// The held commits keyed by destroyed `t` (`hold_secrets`): with a part on it or acting for it.
    pub fn commits_keyed_by(&self, t: &Tid) -> BTreeSet<CommitId> {
        self.core.on_thing(t).chain(self.core.acting_for(t)).collect()
    }

    /// Drops the secrets of each of `ts` held for node-sync alone (`hold_secrets`), node-sync
    /// knowing no entry of a commit keyed by it: its `k/` row and `Indexes::secrets` entry go.
    /// One with a freed link left (`retention::freed`) stays: `freed_done` hands it back. One whose
    /// record is held again keeps them as its own.
    pub fn drop_destroyed_secrets(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        let ts: Vec<Tid> = ts.iter().copied().filter(|t| self.core.ix.destroyed_secrets.contains(t)).collect();
        if ts.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            let freed = super::freed::things_with_links(tx)?;
            for t in ts.into_iter().filter(|t| !freed.contains(t)) {
                unhold_secrets(tx, &t)?;
                // its record back for a dependent (`record_back`): it keeps, so its secrets are its own
                if tx.core.created(&t).is_some() {
                    continue;
                }
                if tx.core.ix.secrets.remove(&t).is_some() {
                    tx.core.touch();
                    tx.core.role_changed();
                }
                tx.txn.remove_local(&[b"k/".as_slice(), t.as_bytes()].concat(), Shred::Yes)?;
            }
            Ok(())
        })
    }
}

/// Every per-aspect row of `(t, ak)` goes, as on a node that never held a part of it.
pub(super) fn forget_aspect_rows(tx: &mut Tx<'_>, t: &Tid, ak: &Ak) -> Result<()> {
    let k = (*t, ak.clone());
    tx.core.ix.forgotten.remove(&k);
    if tx.core.ix.valueless.remove(&k).is_some() {
        tx.core.touch();
    }
    for p in [records::ASPECTS, records::VALUELESS, records::PURGES, records::SUSPECT, records::FORGOTTEN] {
        tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
    }
    for p in [records::LEFTOVER, records::PURGES_NAMED] {
        tx.remove_scanned(&records::aspect_key(p, t, ak), |_| Ok(true))?;
    }
    Ok(())
}

