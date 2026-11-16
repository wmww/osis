//! What stays of a thing only while something held needs it (spec/commits.md §5 Forgetting,
//! spec/permissions.md §4): another account's chain (its record, its `keys.0` commits, its
//! inbox's), and a released thing's record and role-class state. A thing outside the node closure
//! is kept while a thing that needs it is kept: one whose record names it first admin, one whose
//! held edge write names it holder (`Held::named_on`), one a held commit it authored or acted in
//! is on (body held or not). A thing is rooted, kept for itself: in the node closure or leaving it,
//! this node's account's or the node's own (its record chain's key actor), a key actor that is
//! no account (a node, a link key), one a key actor held here is named on (a link being
//! redeemed, a bearer), a kept copy, destroyed (`retention::destroy` keeps it), or a
//! thing an own self-removal still waits to seal under. Everything else goes whole, as never
//! received, in the transaction its last need went (`settle`).
//!
//! Interim (issues/needed-interim-roots.md): a thing this node may read, or of whose content (any
//! aspect but the role-class ones, `forget::content`) it holds a part, is rooted too, but in the
//! transaction that releases it: engine tests hand peers things no strong holds there.
//!
//! Judged again when a need goes: a signer's commit dropping a part or forgotten
//! (`Core::note_signed`, `Core::take_meta`), a holder unnamed (`Held::take_unnamed`), a thing
//! released (`Engine::released`), at the end of the transaction (`Engine::run`, in turn with
//! destructions, on the node closure settled). The judgement
//! walks the needs up from the thing (`needed`) and stops at the first rooted one, so it costs
//! O(1) while the thing is needed and the unrooted things reached when it is not, which go
//! together: needs may form cycles (holder actors granted on each other).

use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{ChainStep, Tid};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Whether `t` is kept for itself (the module doc).
fn rooted(core: &Core, t: &Tid) -> bool {
    let cl = &core.ix.closure;
    // Interim (issues/needed-interim-roots.md): readable or holding content, not released now
    if !core.released_now.contains(t) && (super::forget::read_path(core, t) || holds_content(core, t)) {
        return true;
    }
    if cl.holds(t) || cl.left().contains_key(t) || core.ix.kept.contains_key(t) || super::forget::copy_of(core, t).is_some() || core.destroyed(t) {
        return true;
    }
    if core.is_key_actor(t) && !core.is_account(t) {
        return true;
    }
    // the key actor its record chain climbs to; an unknown link reads as another's
    let top = match core.record_chain(t).last() {
        Some(ChainStep::Key(y)) => Some(y),
        Some(ChainStep::Unknown(_)) | None => None,
        Some(ChainStep::Up { .. }) | Some(ChainStep::TooDeep) => return true,
    };
    if top.is_some_and(|y| y == core.id.tid() || core.account.get() == Some(y) || core.accounts.contains_key(&y) || core.key_actors.contains_key(&y) || core.ix.bearers.contains(&y)) {
        return true;
    }
    // a key actor held here (a link being redeemed, a bearer) is named on it
    if core.ix.held.holders_of(t).any(|h| core.key_actors.contains_key(h) || core.ix.bearers.contains(h)) {
        return true;
    }
    // an own self-removal from it waits to be sealed under its sync IDs (`sync::held::wait_if_own`)
    core.ix.held_wait.iter().any(|c| core.ix.commits.get(c).is_some_and(|m| m.view.aspect(t, "roles.0").is_some()))
}

/// Interim (issues/needed-interim-roots.md): whether a held commit holds a part on
/// content of `t` (`forget::content`).
fn holds_content(core: &Core, t: &Tid) -> bool {
    core.aspects_of(t).filter(|((_, ak), _)| super::forget::content(ak)).any(|((_, ak), cs)| cs.iter().any(|(_, c)| core.ix.commits.get(c).is_some_and(|m| m.aspect(t, ak).is_some_and(|ai| m.holds(ai)))))
}

/// The things that need `t` held (the module doc), but `t`: those naming it, and those a held
/// commit it authored (an account's: `Indexes::by_epoch`) or acted in (`Indexes::by_actor`) has
/// an aspect on, its parts held or not (a header alone is judged by its author's chain).
fn needers<'a>(core: &'a Core, t: &'a Tid) -> impl Iterator<Item = Tid> + 'a {
    let lo = osis_base::CommitId([0; 32]);
    let authored = core.ix.by_epoch.range((*t, lo)..).take_while(move |((a, _), _)| a == t).flat_map(|(_, cs)| cs.iter());
    let acted = core.ix.by_actor.range((*t, Tid::from_bytes([0; 15]))..).take_while(move |((a, _), _)| a == t).flat_map(|(_, cs)| cs.iter());
    let signed = authored.chain(acted).flat_map(move |c| core.ix.commits.get(c).into_iter().flat_map(|m| m.view.aspects.iter().map(|a| a.tid).collect::<Vec<_>>()));
    core.ix.held.named_on(t).copied().chain(signed).filter(move |x| x != t)
}

/// Whether something rooted needs `t`, through any chain of needs; when not, `reached` holds `t`
/// and every thing needing it, none rooted.
fn needed(core: &Core, t: &Tid, reached: &mut BTreeSet<Tid>) -> bool {
    reached.insert(*t);
    let mut todo = vec![*t];
    while let Some(x) = todo.pop() {
        if rooted(core, &x) {
            return true;
        }
        for y in needers(core, &x) {
            if reached.insert(y) {
                todo.push(y);
            }
        }
    }
    false
}

/// Whether anything of `t` is held: its record, a commit on it, or its secrets.
fn holds_any(core: &Core, t: &Tid) -> bool {
    core.created(t).is_some() || core.on_thing(t).next().is_some() || core.ix.secrets.get(t).is_some()
}

/// Judges the things due (`Core::needs_due`) and drops every one nothing rooted needs, with what
/// only it kept: each goes whole, as never received (`forget::Scope::Whole`), its secrets, record
/// and role arrival with it. Whether anything went: what it named and signed is due in turn.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<bool> {
    let due = std::mem::take(&mut tx.core.needs_due);
    let mut gone: BTreeSet<Tid> = BTreeSet::new();
    for t in due {
        if gone.contains(&t) || !holds_any(tx.core, &t) {
            continue;
        }
        let mut reached = BTreeSet::new();
        if needed(tx.core, &t, &mut reached) {
            continue;
        }
        gone.extend(reached);
    }
    gone.retain(|t| holds_any(tx.core, t));
    if gone.is_empty() {
        return Ok(false);
    }
    osis_base::costs::count("needed: things dropped", gone.len() as u64);
    // the role commits with a part on them
    let core = &*tx.core;
    let roles: BTreeSet<osis_base::CommitId> = gone.iter().flat_map(|t| core.ix.held.commits_on(t).iter().map(|c| c.id).chain(core.on_thing(t).filter(|c| core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_role())))).collect();
    // what they noted of each such commit's parts on them goes with the parts: the holders their
    // `roles.0` entries keyed (as a destruction's, `destroy::destroy_thing`), the boxes their
    // `secrets.0` bodies wrote (`Indexes::boxes_to`, `keys::forget_dropped`)
    let mut boxes = Vec::new();
    for id in &roles {
        let Some(m) = tx.core.ix.commits.get(id).cloned() else { continue };
        let parts = crate::apply::edge_parts(tx, id)?;
        for (ai, es) in &parts.0 {
            let Some(t) = m.view.aspects.get(*ai).map(|a| a.tid).filter(|t| gone.contains(t)) else { continue };
            let own = crate::engine::Owned::of_view(&m.view, id, *ai);
            for (d, _, _) in es.iter().filter(|(d, _, _)| own.as_ref().is_some_and(|o| o.owns(d.origin()))) {
                tx.core.ix.holder_keys.remove(&(t, d.clone()));
            }
        }
        for (ai, a) in m.header.aspects.iter().enumerate() {
            if a.ak.as_str() == "secrets.0" && gone.contains(&a.tid) && m.holds(ai) {
                let body = crate::apply::held_fragment(tx, id, ai)?;
                boxes.push((m.header.arc(), ai, body.into_iter().collect::<Vec<_>>()));
            }
        }
    }
    super::forget::forget(tx, super::forget::Scope::Whole(&gone), &BTreeMap::new())?;
    for (h, ai, bodies) in boxes {
        crate::apply::keys::forget_dropped(tx, &h, ai, &bodies)?;
    }
    // perm's held set reads each such commit left without its edge writes on them
    for id in roles {
        tx.core.ix.held.remove(&id);
        let Some(view) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
        let parts = crate::apply::edge_parts(tx, &id)?;
        crate::apply::validity::add_role_commit(tx.core, &view, &id, &parts);
        crate::engine::index::put_edges(tx, &id, &parts, Shred::Yes)?;
    }
    for t in &gone {
        if tx.core.ix.secrets.remove(t).is_some() {
            tx.txn.remove_local(&[crate::engine::records::SECRETS, t.as_bytes()].concat(), Shred::Yes)?;
        }
        crate::sync::stranded::drop_asks(tx, t, |_| false)?;
        crate::sync::held::forget_actor(tx, t)?;
        if tx.core.created(t).is_some() {
            tx.txn.remove_local(&[crate::engine::records::CREATED, t.as_bytes()].concat(), Shred::Yes)?;
            tx.core.ix.held.forget_record(t);
            tx.core.tree_reach.remove(t);
            crate::rotation::merge::forget(tx, t)?;
        }
    }
    tx.core.update_timelines();
    crate::apply::rejudged(tx, true)?;
    Ok(true)
}

