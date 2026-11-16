//! What stays of a thing only while something held needs it (spec/commits.md §5 Forgetting,
//! spec/permissions.md §4): another account's chain (its record, its `keys.0` commits, its
//! inbox's), and a released thing's record and role-class state, whoever's it is. A thing outside
//! the node closure is kept while a thing that needs it is kept: one in the node closure whose
//! durable state holds a strong to it (`refs::to`; a weak or ticket only points and needs
//! nothing), an account by its `keys.0` (its inbox), one whose record names it first admin, one
//! whose held edge write names it holder (`Held::named_on`), one a held or pending commit it
//! authored or acted in is on (body held or not; a pending one by the things it writes on,
//! `Indexes::pend_by`), one a pending commit awaiting its record writes on (`Wake::Record`), one a
//! held commit on it has a part missing on (`Meta::missing_parts`). A thing is rooted, kept for
//! itself: in the node closure or leaving it, reached by a held strong with a ticket for it held
//! (`Closure::accepted`: what judges the ticket stays, spec/sync-set.md §2), a key actor that is
//! no account (a node, a link key), the K of a followed link, one a key actor held here is named
//! on (a link being redeemed, a bearer), a kept copy, or a thing an own self-removal still waits
//! to seal under. Nothing is rooted by whose it is: this node's account is needed by its root
//! (D's record names it), and a thing made under the node or the account goes as any once
//! released. A pairing node takes the account up (`Engine::paired`) in the hold of the engine
//! that applied what pairing sent, before any pass ends. Everything else goes whole, as never
//! received, when the pass that brought it ends or its last need went (`settle`).
//!
//! Judged once the pass in flight ends (`Engine::settle_needs`): a thing arrived (a record
//! learned, `apply::atomic::learn_record`, or awaited by a commit that pends, `apply::set_pending`)
//! or lost a need (a strong row or an account's `keys.0` row gone, `refs::note`; a signer's commit dropping a part or
//! forgotten, `Core::note_signed`, `Core::take_meta`, or leaving pending; a commit's part no longer missing,
//! `Core::note_on`; a holder unnamed,
//! `Held::take_unnamed`) is noted in `Core::pass_due` until then, so a parent's record arriving
//! before what needs it stays. A release judges what it released in its own transaction
//! (`Engine::released`). Either way at the end of a transaction (`Engine::run`, in turn with
//! destructions, on the node closure settled). The judgement walks the needs up from the thing
//! (`needed`) and stops at the first rooted one, so it costs O(1) while the thing is needed and
//! the unrooted things reached when it is not, which go together: needs may form cycles (holder
//! actors granted on each other).

use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::Tid;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

impl Engine {
    /// A pass ended (sync: every connected peer's pass in flight; a test: a delivery batch): what
    /// arrived outside the node closure since the last call and nothing held needs goes
    /// (spec/commits.md §5 What a held thing needs), as at a release. The first call after an
    /// open judges every held record and every record a pending commit awaits, as an open keeps
    /// no list of what arrived. O(what arrived).
    pub fn settle_needs(&mut self) -> Result<()> {
        let due: BTreeSet<Tid> = match self.core.pass_due.replace(BTreeSet::new()) {
            Some(a) => a,
            None => {
                let awaited = self.core.ix.pend_on.keys().filter_map(|w| if let crate::apply::Wake::Record(t) = w { Some(*t) } else { None });
                self.core.ix.held.things().copied().chain(awaited).collect()
            }
        };
        let cl = &self.core.ix.closure;
        let due: Vec<Tid> = due.into_iter().filter(|t| !cl.holds(t)).collect();
        if due.is_empty() {
            return Ok(());
        }
        // judged in a read first: a pass that leaves everything needed writes nothing
        let goes = self.read(|tx| {
            for t in &due {
                if holds_any(tx.core, t) && !needed(tx, t, &mut BTreeSet::new())? {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if !goes {
            return Ok(());
        }
        let r = self.run(|tx| {
            tx.core.needs_due.extend(due.iter().copied());
            Ok(())
        });
        // judged again at the next pass's end
        if r.is_err() {
            for t in due {
                self.core.note_pass_due(t);
            }
        }
        r
    }
}

/// Whether `t` is kept for itself (the module doc).
fn rooted(core: &Core, t: &Tid) -> bool {
    let cl = &core.ix.closure;
    if cl.holds(t) || cl.left().contains_key(t) || cl.accepted(t) || core.ix.kept.contains_key(t) || super::forget::copy_of(core, t).is_some() {
        return true;
    }
    // a key actor that is no account, or the K of a link this node follows
    if (core.is_key_actor(t) && !core.is_account(t)) || core.followed_links.contains(t) {
        return true;
    }
    // a key actor held here (a link being redeemed, a bearer) is named on it
    if core.ix.held.holders_of(t).any(|h| core.key_actors.contains_key(h) || core.ix.bearers.contains(h)) {
        return true;
    }
    // an own self-removal from it waits to be sealed under its sync IDs (`sync::held::wait_if_own`)
    core.ix.held_wait.iter().any(|c| core.ix.commits.get(c).is_some_and(|m| m.view.aspect(t, "roles.0").is_some()))
}

/// The things that need `t` held (the module doc), but `t`: those naming it, those in the node
/// closure whose state holds a strong to it (`refs::to`, durable aspects; an account's `keys.0`
/// naming its inbox too), those a held commit it
/// authored (an account's: `Indexes::by_epoch`) or acted in (`Indexes::by_actor`) has an aspect
/// on, its parts held or not (a header alone is judged by its author's chain), those a pending
/// commit it signed (`Indexes::pend_by`) or awaiting its record (`Wake::Record`) writes on, and
/// those a held commit on it has a part missing on.
fn needers(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeSet<Tid>> {
    let core = &*tx.core;
    let lo = osis_base::CommitId([0; 32]);
    let authored = core.ix.by_epoch.range((*t, lo)..).take_while(|((a, _), _)| a == t).flat_map(|(_, cs)| cs.iter());
    let acted = core.ix.by_actor.range((*t, Tid::from_bytes([0; 15]))..).take_while(|((a, _), _)| a == t).flat_map(|(_, cs)| cs.iter());
    let signed = authored.chain(acted).flat_map(|c| core.ix.commits.get(c).into_iter().flat_map(|m| m.view.aspects.iter().map(|a| a.tid)));
    // a pending commit it signed or whose record it awaits (`Wake::Record`), on the things it
    // writes on (`Wake::Thing`), as if held
    let awaiting = core.ix.pend_on.get(&crate::apply::Wake::Record(*t)).into_iter().flatten();
    let pending = core.ix.pend_by.get(t).into_iter().flatten().chain(awaiting).flat_map(|c| core.ix.pend_keys.get(c).into_iter().flat_map(|ws| ws.iter()).filter_map(|w| if let crate::apply::Wake::Thing(x) = w { Some(*x) } else { None }));
    // a held commit on it still waiting for a part (counted missing), by the things those parts
    // are on: what arrives there may reference it, and the commit stays whole for it
    let waiting = core.on_thing(t).flat_map(|c| core.ix.commits.get(&c).into_iter().flat_map(|m| m.missing_parts().filter_map(|ai| m.view.aspects.get(ai).map(|a| a.tid))));
    let mut out: BTreeSet<Tid> = core.ix.held.named_on(t).copied().chain(signed).chain(pending).chain(waiting).collect();
    // a strong from a thing the node closure holds (a weak or ticket only points; one kept only
    // as a certificate needs nothing by what its state names), and an account's reference from
    // its `keys.0` (its inbox, part of its chain)
    let refs = crate::engine::refs::to(tx, t)?;
    let core = &*tx.core;
    out.extend(refs.into_iter().filter(|r| (r.kind == osis_base::RefKind::Strong && core.ix.closure.holds(&r.source)) || (r.ak.as_str() == "keys.0" && core.is_account(&r.source))).map(|r| r.source));
    // an account root and an account's profile: needed by the account (its chain is the root's
    // roster)
    out.extend(core.account_of_root(t));
    if let Some(a) = core.first_admin(t).filter(|a| core.is_account(a)) {
        let inbox = crate::flows::inbox::inbox_in(tx, &a)?;
        if tx.core.profile_of(&a, inbox) == Some(*t) {
            out.insert(a);
        }
    }
    out.remove(t);
    Ok(out)
}

/// Whether something rooted needs `t`, through any chain of needs; when not, `reached` holds `t`
/// and every thing needing it, none rooted.
fn needed(tx: &mut Tx<'_>, t: &Tid, reached: &mut BTreeSet<Tid>) -> Result<bool> {
    reached.insert(*t);
    let mut todo = vec![*t];
    while let Some(x) = todo.pop() {
        if rooted(tx.core, &x) {
            return Ok(true);
        }
        for y in needers(tx, &x)? {
            if reached.insert(y) {
                todo.push(y);
            }
        }
    }
    Ok(false)
}

/// Whether anything of `t` is held: its record, a commit on it, its secrets, or a pending commit
/// awaiting its record.
fn holds_any(core: &Core, t: &Tid) -> bool {
    core.created(t).is_some() || core.on_thing(t).next().is_some() || core.ix.secrets.get(t).is_some() || core.ix.pend_on.contains_key(&crate::apply::Wake::Record(*t))
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
        if needed(tx, &t, &mut reached)? {
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

