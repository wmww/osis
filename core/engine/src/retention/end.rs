//! Ending a thing (spec/commits.md §5 Ending; notes/expiry-creation-design.md §3): purging or
//! expiring its creation. A thing exists while a creation of it is held live; once every held
//! creation of it is value-less the thing goes whole in the transaction that made it so: its
//! parts as bodies dropped (node-sync then deletes them at hosts by the dropped-body path), its
//! states and per-aspect rows, its record and edges. A later write on it is a write on an unknown
//! thing. Nothing is kept per ended thing but what any purge leaves: the commits' headers, and
//! the request. A request's own `purge.0` part stays held, with the thing's record to place it
//! by, so the request still reaches the nodes that have not heard; `Core::ended` then says the
//! thing is gone, and an expiry leaves not even that.

use crate::engine::records;
use crate::engine::{DropFor, Tx};
use crate::error::Result;
use crate::events::{Cause, Event};
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;

const CREATED: &str = osis_commit::retention::CREATED;
const PURGE: &str = osis_commit::retention::PURGE;

/// Whether every held creation of `t` is value-less: `t` is ended. A thing with no creation held
/// is unknown, not ended.
fn ended(tx: &Tx<'_>, t: &Tid) -> bool {
    let Ok(ak) = Ak::new(CREATED) else { return false };
    let Some(held) = tx.core.ix.by_aspect.get(&(*t, ak.clone())) else { return false };
    let mut any = false;
    for (_, c) in held.iter() {
        let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(t, &ak)) else { continue };
        if !tx.core.ix.commits.get(c).is_some_and(|m| m.holds(ai) || m.stripped.contains(&ai)) {
            continue;
        }
        any = true;
        if !super::valueless(tx.core, c, ai) {
            return false;
        }
    }
    any
}

/// Ends the things a value-less list changed on in this transaction (`Core::valueless_dirty`,
/// taken at the end of the transaction, so any arrival order lands here).
pub(crate) fn end_ended(tx: &mut Tx<'_>) -> Result<()> {
    let due: BTreeSet<Tid> = tx.core.valueless_dirty.iter().filter(|(_, ak)| ak.as_str() == CREATED).map(|(t, _)| *t).filter(|t| ended(tx, t)).collect();
    if due.is_empty() {
        return Ok(());
    }
    let mut changed = BTreeSet::new();
    for t in &due {
        end_thing(tx, t, &mut changed)?;
    }
    tx.core.update_timelines();
    crate::apply::rejudged(tx, true)?;
    tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
    Ok(())
}

/// Drops everything of `t` (`end_ended`).
fn end_thing(tx: &mut Tx<'_>, t: &Tid, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let aspects: Vec<(Ak, Vec<CommitId>)> = tx.core.aspects_of(t).filter(|((_, ak), _)| ak.as_str() != PURGE).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).collect())).collect();
    for (ak, commits) in &aspects {
        for c in commits {
            if let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(t, ak)) {
                super::drop_part_for(tx, c, ai, DropFor::Ended)?;
            }
        }
    }
    let edge_commits: Vec<CommitId> = tx.core.ix.held.commits_on(t).iter().map(|c| c.id).collect();
    for id in edge_commits {
        let parts = crate::apply::edge_parts(tx, &id)?;
        tx.core.ix.held.remove(&id);
        if parts.0.is_empty() {
            crate::engine::index::remove_edges(tx, &id)?;
        } else {
            let Some(view) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
            crate::apply::validity::add_role_commit(tx.core, &view, &id, &parts);
            crate::engine::index::put_edges(tx, &id, &parts, Shred::Yes)?;
        }
    }
    for (ak, _) in &aspects {
        let k = (*t, ak.clone());
        tx.txn.drop_aspect(t, ak)?;
        tx.core.forget_live(t, ak);
        for p in [records::ASPECTS, records::RECEIPT, records::SUSPECT] {
            tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
        }
        if tx.core.ix.valueless.get(&k).is_some() {
            tx.core.touch();
            tx.core.ix.valueless.remove(&k);
        }
        tx.core.valueless_dirty.insert(k.clone());
        changed.insert(k);
    }
    if tx.core.aspects_of(t).all(|((_, ak), _)| ak.as_str() != PURGE) {
        tx.txn.remove_local(&[records::CREATED, t.as_bytes()].concat(), Shred::Yes)?;
        tx.core.ix.held.forget_record(t);
    }
    tx.core.role_changed();
    Ok(())
}
