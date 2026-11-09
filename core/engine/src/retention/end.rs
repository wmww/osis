//! Ending a thing (spec/commits.md §5 Ending; notes/expiry-creation-design.md §3): purging or
//! expiring its creation. A thing exists while a creation of it is held live; once every held
//! creation of it is value-less the thing goes whole in the transaction that made it so: its
//! parts as bodies dropped (node-sync then deletes them at hosts by the dropped-body path), its
//! states and per-aspect rows, its record and edges. A later write on it is a write on an unknown
//! thing. An ending by purge keeps what judges it, for good since nothing drops a request: the
//! request's own `purge.0` part, so it still reaches the nodes that have not heard, and the
//! thing's record, its value-less creation and `roles.0` parts (no content), since the right to
//! purge is read from them and a removal arriving later may make it fall; a fall reopens what the
//! ending dropped to be fetched again (`reopen_fallen`). `Core::exists` says the thing is gone all the
//! same. An ending by expiry needs no right: it keeps nothing but the commits' headers.

use crate::engine::records;
use crate::engine::{DropFor, Tx};
use crate::error::Result;
use crate::events::{Cause, Event};
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;

const CREATED: &str = osis_commit::retention::CREATED;
const PURGE: &str = osis_commit::retention::PURGE;
const ROLES: &str = "roles.0";

/// Aspects whose parts an ended thing still takes (`thing_wait`), so its ending is judged alike.
pub(crate) fn judges_ending(ak: &str) -> bool {
    matches!(ak, CREATED | PURGE | ROLES)
}

/// Ends the things a value-less list changed on in this transaction (`Core::valueless_dirty`,
/// taken at the end of the transaction, so any arrival order lands here).
pub(crate) fn end_ended(tx: &mut Tx<'_>) -> Result<()> {
    let dirty: BTreeSet<Tid> = tx.core.valueless_dirty.iter().filter(|(_, ak)| ak.as_str() == CREATED).map(|(t, _)| *t).collect();
    let (due, fell): (BTreeSet<Tid>, BTreeSet<Tid>) = dirty.into_iter().partition(|t| tx.core.ended(t));
    if due.is_empty() && fell.is_empty() {
        return Ok(());
    }
    let mut changed = BTreeSet::new();
    for t in &fell {
        reopen_fallen(tx, t)?;
        reads_again(t, &mut changed);
    }
    let mut held_changed = false;
    for t in &due {
        held_changed |= end_thing(tx, t, &mut changed)?;
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

/// `t`'s ending fell: the parts it dropped are fetched again (spec/commits.md §5 Ending).
fn reopen_fallen(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let commits: Vec<CommitId> = tx.core.on_thing(t).collect();
    // a keys.0 part's keysets left with its dropped record
    let mut keysets = false;
    for c in commits {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let ended: Vec<(usize, bool)> = m.dropped.iter().filter(|(_, d)| d.why == DropFor::Ended).filter_map(|(ai, _)| m.header.aspects.get(*ai).filter(|a| a.tid == *t).map(|a| (*ai, a.ak.as_str() == "keys.0"))).collect();
        for (ai, is_keys) in ended {
            keysets |= is_keys;
            super::reopen_to_fetch(tx, &c, ai)?;
        }
    }
    if keysets {
        crate::apply::keys::rebuild_keysets(tx, &BTreeSet::from([*t]))?;
    }
    // reads of the thing and its roles move, and whatever waited on the thing is judged again
    tx.core.role_changed();
    tx.core.ix.held.record_back(*t);
    Ok(())
}

/// What reads differently once `t` reads as gone or back while its record stays held.
fn reads_again(t: &Tid, changed: &mut BTreeSet<(Tid, Ak)>) {
    for ak in [CREATED, ROLES] {
        if let Ok(ak) = Ak::new(ak) {
            changed.insert((*t, ak));
        }
    }
}

/// Whether `t`'s every creation is past its expiry: an ending nothing can make fall, whatever
/// purge requests it also holds.
fn every_creation_expired(tx: &Tx<'_>, t: &Tid) -> bool {
    let now = tx.now().0;
    tx.core.aspects_of(t).filter(|((_, ak), _)| ak.as_str() == CREATED).flat_map(|(_, s)| s.iter()).all(|(_, c)| tx.core.ix.commits.get(c).is_some_and(|m| m.header.expires.is_some_and(|x| x <= now)))
}

/// Drops everything of `t` (`end_ended`) but what judges a purge's ending. Whether the role
/// timelines' inputs changed: an ending by purge keeps them.
fn end_thing(tx: &mut Tx<'_>, t: &Tid, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<bool> {
    let by_purge = !every_creation_expired(tx, t);
    if by_purge {
        // what stays still reads as gone (`Core::exists`): observers hear it
        reads_again(t, changed);
    }
    // the holders its `roles.0` entries keyed go with the entries: read while the parts are held
    let edge_commits: Vec<CommitId> = if by_purge { Vec::new() } else { tx.core.ix.held.commits_on(t).iter().map(|c| c.id).collect() };
    for id in &edge_commits {
        let parts = crate::apply::edge_parts(tx, id)?;
        let view = tx.core.ix.commits.get(id).map(|m| m.view.clone());
        for (ai, es) in &parts.0 {
            if view.as_ref().and_then(|v| v.aspects.get(*ai)).is_some_and(|a| a.tid == *t) {
                for (d, _, _) in es {
                    tx.core.ix.holder_keys.remove(&(*t, d.clone()));
                }
            }
        }
    }
    let aspects: Vec<(Ak, Vec<CommitId>)> = tx.core.aspects_of(t).filter(|((_, ak), _)| !by_purge || !judges_ending(ak.as_str())).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).collect())).collect();
    for (ak, commits) in &aspects {
        for c in commits {
            if let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(t, ak)) {
                super::drop_part_for(tx, c, ai, DropFor::Ended)?;
            }
        }
    }
    for id in edge_commits {
        // a role commit keeps its row and its place, empty once its last edge goes: as an open reads it
        let parts = crate::apply::edge_parts(tx, &id)?;
        let Some(view) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
        tx.core.ix.held.remove(&id);
        crate::apply::validity::add_role_commit(tx.core, &view, &id, &parts);
        crate::engine::index::put_edges(tx, &id, &parts, Shred::Yes)?;
    }
    for (ak, _) in &aspects {
        let k = (*t, ak.clone());
        crate::apply::rebuild(tx, t, ak)?;
        tx.txn.drop_aspect(t, ak)?;
        tx.core.forget_live(t, ak);
        for p in [records::ASPECTS, records::SUSPECT] {
            tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
        }
        if tx.core.ix.valueless.get(&k).is_some() {
            tx.core.touch();
            tx.core.ix.valueless.remove(&k);
        }
        tx.core.valueless_dirty.insert(k.clone());
        changed.insert(k);
    }
    if !by_purge {
        tx.txn.remove_local(&[records::CREATED, t.as_bytes()].concat(), Shred::Yes)?;
        tx.core.ix.held.forget_record(t);
    }
    tx.core.role_changed();
    Ok(!by_purge)
}
