//! Ending a thing (spec/commits.md §5 Ending; notes/expiry-creation-design.md §3): purging or
//! expiring its creation. A thing exists while a creation of it is held live; once every held
//! creation of it is value-less the thing goes whole in the transaction that made it so: its
//! parts as bodies dropped (node-sync then deletes them at hosts by the dropped-body path), its
//! states and per-aspect rows, its record and edges. A later write on it is a write on an unknown
//! thing. Nothing is kept per ended thing but what any purge leaves: the commits' headers, and
//! the request. A request's own `purge.0` part stays held, with the thing's record to place it
//! by, so the request still reaches the nodes that have not heard; `Core::exists` then says the
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

/// Ends the things a value-less list changed on in this transaction (`Core::valueless_dirty`,
/// taken at the end of the transaction, so any arrival order lands here).
pub(crate) fn end_ended(tx: &mut Tx<'_>) -> Result<()> {
    let due: BTreeSet<Tid> = tx.core.valueless_dirty.iter().filter(|(_, ak)| ak.as_str() == CREATED).map(|(t, _)| *t).filter(|t| tx.core.ended(t)).collect();
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
    // the holders its `roles.0` entries keyed go with the entries: read while the parts are held
    let edge_commits: Vec<CommitId> = tx.core.ix.held.commits_on(t).iter().map(|c| c.id).collect();
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
    let aspects: Vec<(Ak, Vec<CommitId>)> = tx.core.aspects_of(t).filter(|((_, ak), _)| ak.as_str() != PURGE).map(|((_, ak), s)| (ak.clone(), s.iter().map(|x| x.1).collect())).collect();
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
