//! What stays of a thing only while something held needs it (spec/commits.md §5 Forgetting,
//! spec/permissions.md §4): another account's chain (its record, its `keys.0` commits, its
//! inbox's), and a released thing's record and role-class state, whoever's it is. A thing outside
//! the node closure is kept while a thing that needs it is kept: one in the node closure whose
//! durable state holds a strong to it (`refs::to`; a weak or ticket only points and needs
//! nothing), an account by its `keys.0` (its inbox), one whose record names it first admin, one
//! whose held edge write names it holder (`Held::named_on`), one a held or pending commit it
//! authored or acted in is on (body held or not; a pending one by the things it writes on,
//! `Indexes::pend_by`), one a pending commit awaiting its record writes on (`Wake::Record`), one in
//! the node closure a held commit on it has a part missing on (`Meta::missing_parts`: a part the
//! node fetches again), one in the node closure an edge write on it names holder (not by its
//! record: the holder's sync ID carries the grant with its chain, spec/sync-judgement.md §2 A
//! grant naming a holder). A thing is rooted, kept for
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
//! An arrival is judged once the pass in flight ends (`Engine::settle_needs`): a thing whose
//! record was learned (`apply::atomic::learn_record`) or that a commit that pends awaits
//! (`apply::set_pending`) is noted in `Core::pass_due` until then, so a parent's record arriving
//! before what needs it stays. A lost need waits for nothing but a pass in flight: a thing that
//! lost one (a strong row or an account's `keys.0` row gone, `refs::note`; a signer's commit
//! dropping a part or forgotten, `Core::note_signed`, `Core::take_meta`, or leaving pending; a
//! commit's part no longer missing, `Core::note_on`; a holder unnamed, `Held::take_unnamed`; an
//! accepted ticket's strong gone) is noted in `Core::lost_due`, judged at a pass's end or, with
//! none in flight, at once (`Engine::settle_lost`). A release judges what it released, and what
//! each was named holder on, in its own transaction
//! (`Engine::released`). Either way at the end of a transaction (`Engine::run`, in turn with
//! destructions, on the node closure settled). The judgement walks the needs up from the thing
//! (`search`) and stops at the first rooted one, so it costs O(1) while the thing is needed and
//! the unrooted things reached when it is not, which go together: needs may form cycles (holder
//! actors granted on each other).

use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::Tid;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

impl Engine {
    /// A pass ended (sync: every connected peer's pass in flight; a test: a delivery batch): what
    /// arrived outside the node closure or lost a need since the last call and nothing held needs
    /// goes (spec/commits.md §5 What a held thing needs), as at a release. The first call after an
    /// open judges every held record and every record a pending commit awaits, as an open keeps
    /// no list of what arrived. O(what arrived).
    pub fn settle_needs(&mut self) -> Result<()> {
        let mut due: BTreeSet<Tid> = match self.core.pass_due.replace(BTreeSet::new()) {
            Some(a) => a,
            None => {
                let awaited = self.core.ix.pend_on.keys().filter_map(|w| if let crate::apply::Wake::Record(t) = w { Some(*t) } else { None });
                self.core.ix.held.things().copied().chain(awaited).collect()
            }
        };
        due.append(&mut self.core.lost_due);
        let r = self.settle_due(&due);
        // judged again at the next pass's end
        if r.is_err() {
            for t in due {
                self.core.note_pass_due(t);
            }
        }
        r
    }

    /// No pass is in flight (sync: none begun and not ended): what lost a need since the last
    /// judgement and nothing held needs goes, as at a pass end. A lost need waits for nothing;
    /// an arrival waits for the pass that brought it (a parent's record before what needs it),
    /// so one also arrived since (`Core::pass_due`; every held record after an open) waits for
    /// that pass. O(what lost a need).
    pub fn settle_lost(&mut self) -> Result<()> {
        let Some(arrived) = &self.core.pass_due else { return Ok(()) };
        let due: BTreeSet<Tid> = self.core.lost_due.difference(arrived).copied().collect();
        if due.is_empty() {
            return Ok(());
        }
        self.core.lost_due.retain(|t| !due.contains(t));
        let r = self.settle_due(&due);
        if r.is_err() {
            self.core.lost_due.extend(due);
        }
        r
    }

    /// `due` judged: those outside the node closure nothing held needs go.
    fn settle_due(&mut self, due: &BTreeSet<Tid>) -> Result<()> {
        let cl = &self.core.ix.closure;
        let due: Vec<Tid> = due.iter().filter(|t| !cl.holds(t)).copied().collect();
        if due.is_empty() {
            return Ok(());
        }
        // judged in a read first: a pass that leaves everything needed writes nothing
        let goes = self.read(|tx| {
            for t in &due {
                if holds_any(tx.core, t) && !needed(tx, t, &mut Reached::new())? {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if !goes {
            return Ok(());
        }
        self.run(|tx| {
            tx.core.needs_due.extend(due.iter().copied());
            Ok(())
        })
    }
}

/// Why a thing is kept for itself (the module doc, `rooted`).
#[derive(Clone, Debug)]
pub(crate) enum Root {
    /// In the node closure.
    Closure,
    /// Leaving the node closure, not released yet.
    Leaving,
    /// Reached by a held strong with a ticket for it held (`Closure::accepted`).
    Accepted,
    /// A kept copy (`rotation::lost`).
    Kept,
    /// A secret actor whose kept copy is this one (`forget::copy_of`).
    CopyOf(Tid),
    /// A key actor that is no account (a node, a link key).
    KeyActor,
    /// The K of a link this node follows.
    FollowedLink,
    /// A key actor held here (a link being redeemed, a bearer) is named holder on it.
    HeldKeyActor(Tid),
    /// An own self-removal from it waits to be sealed under its sync IDs.
    SelfRemoval(osis_base::CommitId),
}

/// Why `x` needs `t` held (the module doc, `needs`).
#[derive(Clone, Debug)]
pub(crate) enum Need {
    /// `t` is named holder on `x` by a held edge write (`Held::named_on`).
    Holder,
    /// A held commit `t` authored or acted in has an aspect on `x`.
    Signed(osis_base::CommitId),
    /// A pending commit `t` signed, or one awaiting `t`'s record, writes on `x`.
    Pending(osis_base::CommitId),
    /// `x` is in the node closure and a held commit on `t` has a part missing on it.
    Missing(osis_base::CommitId),
    /// `x` is in the node closure and an edge write on `t` names it holder.
    Holding,
    /// `x` is in the node closure and its durable aspect holds a strong to `t`.
    Strong(osis_base::Ak),
    /// Account `x`'s `keys.0` names `t` (its inbox).
    Inbox,
    /// `t` is account `x`'s profile.
    Profile,
}

/// Why `t` is kept for itself (the module doc), if it is.
pub(crate) fn rooted(core: &Core, t: &Tid) -> Option<Root> {
    let cl = &core.ix.closure;
    if cl.holds(t) {
        return Some(Root::Closure);
    }
    if cl.left().contains_key(t) {
        return Some(Root::Leaving);
    }
    if cl.accepted(t) {
        return Some(Root::Accepted);
    }
    if core.ix.kept.contains_key(t) {
        return Some(Root::Kept);
    }
    if let Some(a) = super::forget::copy_of(core, t) {
        return Some(Root::CopyOf(a));
    }
    // a key actor that is no account, or the K of a link this node follows
    if core.is_key_actor(t) && !core.is_account(t) {
        return Some(Root::KeyActor);
    }
    if core.followed_links.contains(t) {
        return Some(Root::FollowedLink);
    }
    // a key actor held here (a link being redeemed, a bearer) is named on it
    if let Some(h) = core.ix.held.holders_of(t).find(|h| core.key_actors.contains_key(h) || core.ix.bearers.contains(h)) {
        return Some(Root::HeldKeyActor(*h));
    }
    // an own self-removal from it waits to be sealed under its sync IDs (`sync::held::wait_if_own`)
    core.ix.held_wait.iter().find(|c| core.ix.commits.get(c).is_some_and(|m| m.view.aspect(t, "roles.0").is_some())).map(|c| Root::SelfRemoval(*c))
}

/// The things that need `t` held (the module doc), but `t`, each with why (one thing may come
/// more than once): those naming it, those in the node closure whose state holds a strong to it
/// (`refs::to`, durable aspects; an account's `keys.0` naming its inbox too), those a held commit
/// it authored (an account's: `Indexes::by_epoch`) or acted in (`Indexes::by_actor`) has an
/// aspect on, its parts held or not (a header alone is judged by its author's chain), those a
/// pending commit it signed (`Indexes::pend_by`) or awaiting its record (`Wake::Record`) writes
/// on, and, in the node closure, those a held commit on it has a part missing on and those an
/// edge write on it names holder. The rule (`needed`) and the explainer (`Engine::why_kept`)
/// both read it.
pub(crate) fn needs(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<(Tid, Need)>> {
    let core = &*tx.core;
    let lo = osis_base::CommitId([0; 32]);
    let authored = core.ix.by_epoch.range((*t, lo)..).take_while(|((a, _), _)| a == t).flat_map(|(_, cs)| cs.iter());
    let acted = core.ix.by_actor.range((*t, Tid::from_bytes([0; 15]))..).take_while(|((a, _), _)| a == t).flat_map(|(_, cs)| cs.iter());
    let signed = authored.chain(acted).flat_map(|c| core.ix.commits.get(c).into_iter().flat_map(move |m| m.view.aspects.iter().map(move |a| (a.tid, Need::Signed(*c)))));
    // a pending commit it signed or whose record it awaits (`Wake::Record`), on the things it
    // writes on (`Wake::Thing`), as if held
    let awaiting = core.ix.pend_on.get(&crate::apply::Wake::Record(*t)).into_iter().flatten();
    let pending = core.ix.pend_by.get(t).into_iter().flatten().chain(awaiting).flat_map(|c| core.ix.pend_keys.get(c).into_iter().flat_map(|ws| ws.iter()).filter_map(move |w| if let crate::apply::Wake::Thing(x) = w { Some((*x, Need::Pending(*c))) } else { None }));
    // a held commit on it still waiting for a part (counted missing), by the things the node
    // closure holds those parts are on (spec/commits.md §5: one the node fetches again): what
    // arrives there may reference it, and the commit stays whole for it
    let waiting = core.on_thing(t).flat_map(|c| core.ix.commits.get(&c).into_iter().flat_map(move |m| m.missing_parts().filter_map(move |ai| m.view.aspects.get(ai).map(|a| (a.tid, Need::Missing(c)))))).filter(|(x, _)| core.ix.closure.holds(x));
    // a thing in the node closure an edge write on it names holder (not by its record): the
    // holder's sync ID carries the grant with its chain (spec/sync-judgement.md §2 A grant naming
    // a holder), so its readers read it through the holder
    let holding = core.ix.held.holders_of(t).filter(|h| core.ix.closure.holds(h) && core.first_admin(t) != Some(**h)).map(|h| (*h, Need::Holding));
    let mut out: Vec<(Tid, Need)> = core.ix.held.named_on(t).map(|x| (*x, Need::Holder)).chain(signed).chain(pending).chain(waiting).chain(holding).collect();
    // a strong from a thing the node closure holds (a weak or ticket only points; one kept only
    // as a certificate needs nothing by what its state names), and an account's reference from
    // its `keys.0` (its inbox, part of its chain)
    let refs = crate::engine::refs::to(tx, t)?;
    // a strong in a held body of a thing whose history holds its targets (`refs::kept`)
    let kept = crate::engine::refs::kept::to(tx, t)?;
    let core = &*tx.core;
    out.extend(kept.into_iter().filter(|(s, _)| core.ix.closure.holds(s)).map(|(s, ak)| (s, Need::Strong(ak))));
    for r in refs {
        if r.kind == osis_base::RefKind::Strong && core.ix.closure.holds(&r.source) {
            out.push((r.source, Need::Strong(r.ak)));
        } else if r.ak.as_str() == "keys.0" && core.is_account(&r.source) {
            out.push((r.source, Need::Inbox));
        }
    }
    // an account's profile: needed by the account
    if let Some(a) = core.first_admin(t).filter(|a| core.is_account(a)) {
        let inbox = crate::flows::inbox::inbox_in(tx, &a)?;
        if tx.core.profile_of(&a, inbox) == Some(*t) {
            out.push((a, Need::Profile));
        }
    }
    out.retain(|(x, _)| x != t);
    Ok(out)
}

/// What `search` reached: each thing with the thing it needs and why (`None` for the start).
pub(crate) type Reached = BTreeMap<Tid, Option<(Tid, Need)>>;

/// Walks the needs up from `t` (`needs`), breadth first, to the first rooted thing: that thing
/// and why it is rooted, its chain to `t` in `reached`. `None` when nothing rooted needs `t`,
/// through any chain of needs: `reached` then holds `t` and every thing needing it, none rooted.
pub(crate) fn search(tx: &mut Tx<'_>, t: &Tid, reached: &mut Reached) -> Result<Option<(Tid, Root)>> {
    reached.insert(*t, None);
    let mut todo = std::collections::VecDeque::from([*t]);
    while let Some(x) = todo.pop_front() {
        if let Some(r) = rooted(tx.core, &x) {
            return Ok(Some((x, r)));
        }
        for (y, why) in needs(tx, &x)? {
            if let std::collections::btree_map::Entry::Vacant(e) = reached.entry(y) {
                e.insert(Some((x, why)));
                todo.push_back(y);
            }
        }
    }
    Ok(None)
}

/// Whether something rooted needs `t` (`search`); when not, `reached` holds `t` and every
/// thing needing it, none rooted.
fn needed(tx: &mut Tx<'_>, t: &Tid, reached: &mut Reached) -> Result<bool> {
    Ok(search(tx, t, reached)?.is_some())
}

/// Whether anything of `t` is held: its record, a commit on it, its secrets, or a pending commit
/// awaiting its record.
pub(crate) fn holds_any(core: &Core, t: &Tid) -> bool {
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
        let mut reached = Reached::new();
        if needed(tx, &t, &mut reached)? {
            continue;
        }
        gone.extend(reached.into_keys());
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
        crate::sync_ids::opened::forget_thing(tx, t)?;
        // its keyset notes go with it, though a held commit keeps its other parts
        let keyed: Vec<osis_base::CommitId> = tx.core.ix.keyset_parts.get(t).into_iter().flatten().copied().collect();
        for id in keyed {
            tx.core.ix.keyset_parts.remove(t, &id);
            tx.txn.remove_local(&crate::engine::records::own_keys_key(t, &id), Shred::Yes)?;
        }
        tx.core.ix.own_keys.remove(t);
        tx.core.ix.secrets.remove(t);
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
