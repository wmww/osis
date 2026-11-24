//! Edge writes (spec/permissions.md §2, §3, §5.3): grants with the grantee's boxes, changes,
//! removals and demotions carrying the target's rotation, may-grant grants and self-removals,
//! the frontier, inbox delivery and acceptance
//! (spec/sync-inbox.md §2, spec/crypto.md §5).

use super::{Done, now_ts, put_edge, put_secrets};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::apply::validity::perm_edge;
use crate::rotation;
use crate::Mutation;
use osis_base::{CommitId, Role, Tid, WallMs};
use osis_keys::{Departure, ROLES, box_holder, roles_up_to};

use osis_perm::{At, Edge as PermEdge};
use osis_schema::core_types::{self as ct, Edge};
use std::collections::BTreeSet;

/// A role-lowering edge write: `holder`'s new edge on the target (`None` removes it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demotion {
    pub holder: Tid,
    pub new: Option<Edge>,
    /// A removal's word (`new` `None`): retain or erase; `None`: the thing's default in force
    /// (spec/permissions.md §3, Retain).
    pub retain: Option<bool>,
}

/// What `d` writes on the holder's edge on `target`, standing at `old`: `d.new`, or for a removal
/// saying retain the value that says so (spec/permissions.md §3, Retain).
fn written(core: &crate::engine::Core, target: &Tid, old: Option<&PermEdge>, d: &Demotion) -> Result<Option<Edge>> {
    if d.new.is_some() {
        return match d.retain.is_some() || d.new.as_ref().is_some_and(|n| n.until == Some(osis_base::WallMs(0))) {
            true => Err(Error::Misuse("only a removal says retain or erase, by `retain`")),
            false => Ok(d.new.clone()),
        };
    }
    let retain = old.is_some() && d.retain.unwrap_or_else(|| crate::apply::validity::retain_default(core, target));
    Ok(retain.then_some(Edge { role: Role::Read, until: Some(osis_base::WallMs(0)), may_grant: false, retain: false, floor: None }))
}

/// A grant or a raise of `holder`'s edge on `target` by `who` (this node, or a held key actor
/// signing), with the grantee's boxes for every granted role at each current epoch
/// (spec/crypto.md §4). An admin's grant, or a may-grant grant (spec/permissions.md §2) where
/// `who`'s effective may-grant allows it and the holder has no current edge. `leave`: the signer's
/// own edge removed in the same commit (a single-use redemption, spec/permissions.md §7).
/// `frontier`: the one a grant that audits carries (`Engine::grant_signed`).
pub(crate) fn grant_in(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, holder: Tid, edge: &Edge, leave: bool, frontier: Option<osis_perm::Frontier>) -> Result<Done> {
    grant_history(tx, signer, target, holder, edge, leave, frontier, History::All)
}

/// What a grant hands its holder of what was written before it (spec/crypto.md §4, Floors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum History {
    /// Everything this node holds (the history boxes of each epoch it boxes).
    All,
    /// Nothing: the grant's commit is a cut, a read rotation whose history box carries no earlier
    /// secret, and the edge's floor is the cut's n.
    None,
}

/// `grant_in`, handing `history`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn grant_history(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, holder: Tid, edge: &Edge, leave: bool, frontier: Option<osis_perm::Frontier>, history: History) -> Result<Done> {
    let who = signer.unwrap_or(tx.core.me());
    if edge.until == Some(osis_base::WallMs(0)) {
        return Err(Error::Misuse("`until` 0 is a removal's saying retain"));
    }
    let role = tx.core.role_now(&who, &target);
    let admin = crate::engine::secrets::usable_role(tx, &target, role)? == Some(Role::Admin);
    // a non-writer of the target's sync ID deposits its may-grant grant (spec/sync-judgement.md §1)
    let ts = now_ts(tx.core);
    let old = tx.core.timelines().get(&target).and_then(|tl| tl.roster(&target, At::now(ts)).get(&holder).copied());
    let may_grant = tx.core.timelines().get(&target).and_then(|tl| tl.may_grant(&who, &target, At::now(ts)));
    // below the holder's edge for keys (one past its `until` included, still in the state) a
    // grant would be the holder's departure, whose rotation it does not carry (spec/permissions.md
    // §3): a demotion makes it
    let below = tx.core.timelines().get(&target).is_some_and(|tl| rotation::key_role(tl.edges_at(None).get(&holder, &target)) > Some(edge.role));
    if admin && below {
        return Err(Error::Misuse("a grant below the holder's edge lowers it (use demote)"));
    }
    if !admin {
        let ok = old.is_none() && may_grant.is_some_and(|i| edge.role <= i);
        if !ok || below || history == History::None {
            return Err(Error::Permission { tid: target, needs: Role::Admin });
        }
    }
    // a holder reading the target already holds its history: a cut gives it nothing to withhold
    if history == History::None && tx.core.key_holders(&target).iter().any(|(m, _)| *m == holder) {
        return Err(Error::Misuse("a grant without history is for a holder that holds no role on the target"));
    }
    let mut done = Done::default();
    // a thing is made a holder only once independent; a target gets them on its first
    // holder other than its mint admin (spec/permissions.md §3)
    if !tx.core.is_key_actor(&holder) && !tx.core.is_independent(&holder) {
        rotation::own_secrets(tx, holder, &mut done)?;
    }
    if !tx.core.is_independent(&target) && !tx.core.is_key_actor(&target) {
        if !admin {
            return Err(Error::Permission { tid: target, needs: Role::Admin });
        }
        rotation::own_secrets(tx, target, &mut done)?;
    }
    // rotate first where due (a holder actor's own epochs too, by this node where it may), then
    // box the holder at the current epochs held, blocked ones included: a box carrying a secret
    // is encrypted under its recipient's key, not under that epoch (spec/crypto.md §4,
    // Encrypting under; `rotation::reseal_one` alike)
    if !tx.core.is_key_actor(&holder) {
        let me = tx.core.me();
        rotation::ensure_rotated(tx, me, holder, &mut done)?;
    }
    let mut roles = roles_up_to(edge.role);
    // a renewal of an ended edge is not finalized first: the grant writes it anew
    rotation::ensure_rotated_but(tx, who, target, &[holder], &BTreeSet::new(), &mut done)?;
    let epochs = tx.core.epochs(&target).ok_or(Error::Misuse("no secrets held for the target"))?;
    let keyless = rotation::grant_keyless(tx.core, &target, &holder);
    // a holder actor is boxed at the keyset Seal gives, per role (spec/crypto.md §4); one whose
    // grant would close a key cycle is keyless and boxed nothing; one this node can seal to no
    // keyset is not granted (its boxes would say nothing)
    let rcpt = match keyless {
        true => None,
        false => match rotation::sealed_granted(tx, &who, &target, &holder, edge.role)? {
            // boxed at the floor this grant gives (spec/crypto.md §4, A party's floor): its own
            // (a change keeping it), at least its author's
            rotation::Sealed::Boxed(r) => Some(osis_keys::Recipient { floor: edge.floor.unwrap_or(0).max(rotation::floors::holder_floor(tx.core, &target, &who)), ..r }),
            rotation::Sealed::Out => return Err(Error::Misuse("the holder has no keyset this node may seal it to")),
        },
    };
    let mut m = Mutation::new();
    reset_current(tx, &mut m, target, holder)?;
    // a grant without history: the cut, a read rotation boxing every current holder and the
    // grantee, carrying no earlier secret; the edge's floor is its n (spec/crypto.md §4, Floors)
    let mut edge = edge.clone();
    let cut = match history {
        History::All => None,
        History::None => {
            if let Some(s) = signer {
                m.sign_as(s);
            }
            let mut boxing = rotation::recipients(tx, &who, &target, &[])?;
            boxing.holders.extend(rcpt.clone());
            if !rotation::may_rotate(tx.core, &who, &target).contains(&Role::Read) {
                return Err(Error::Misuse("this node may not rotate the target's read role now"));
            }
            let rotated = BTreeSet::from([Role::Read]);
            let rot = rotation::cut_into(tx, &mut m, target, &rotated, &epochs, &boxing, rotation::Departs::No, true)?;
            edge.floor = rot.role(Role::Read).map(|x| x.epoch.n());
            // a re-add: boxes at each epoch the holder's removal's rotation listed that this node
            // holds (what its earlier nodes read before it left), below its floor; a holder that
            // holds the rest boxes them (the tip add)
            let listed = rotation::floors::removal_listed(tx.core, &target, &holder, &epochs, None);
            let held: BTreeSet<osis_crypto::Epoch> = listed.into_iter().filter(|e| epochs.read.is_established(e) && epochs.read.secret(e).is_some()).collect();
            if let Some(r) = rcpt.clone().filter(|_| !held.is_empty()) {
                let w = osis_keys::box_dropped(&target, &epochs, &osis_keys::Recipient { floor: 0, ..r }, &held, &mut *tx.rng)?.ok_or(Error::Misuse("the holder's keyset is unknown"))?;
                put_secrets(&mut m, target, &w, false)?;
            }
            roles.retain(|r| !rotated.contains(r));
            Some(rot)
        }
    };
    let boxes = match rcpt {
        Some(rcpt) if !roles.is_empty() => {
            let hist = rotation::history_boxes(tx, &who, &target)?;
            Some(box_holder(&target, &epochs, &hist, &rcpt, &roles, &mut *tx.rng)?.ok_or(Error::Misuse("the holder's keyset is unknown"))?)
        }
        _ => None,
    };
    let unreached = match &cut {
        Some(rot) => rotation::unreached(tx, &target, rot)?.into_iter().filter(|x| *x != holder).collect(),
        None => Vec::new(),
    };
    let edge = &edge;
    put_edge(&mut m, target, holder, edge)?;
    if leave {
        removal(tx, &mut m, target, who)?;
    }
    if let Some(w) = &boxes {
        put_secrets(&mut m, target, w, !admin)?;
    }
    if let Some(s) = signer.filter(|_| cut.is_none()) {
        m.sign_as(s);
    }
    if let Some(f) = frontier {
        m.frontier(f);
    }
    if !admin {
        m.unchecked();
    }
    let c = Engine::commit_tx(tx, m)?;
    if let Some(rot) = &cut {
        rotation::recorded(tx, target, c, rot, &unreached, &mut done)?;
        // the current state under the cut: a snapshot owed of each aspect holding content from
        // before it (spec/crypto.md §4, State at a cut), written right after this transaction
        rotation::floors::owe_state(tx, &target)?;
    }
    // the current history setting, written again under the cut: the holder opens no earlier one
    // (spec/crypto.md §4, Floors)
    let setting = match cut {
        Some(_) => crate::apply::validity::setting_now(tx.core, &target).map(|s| (*s).clone()),
        None => None,
    };
    done.add(c);
    if let Some(c) = c {
        super::inbox::deliver_copy(tx, holder, c, target)?;
    }
    if let Some(s) = setting {
        let mut m = Mutation::new();
        m.set(target, &ct::RETENTION, &s)?;
        done.add(Engine::commit_tx(tx, m)?);
    }
    Ok(done)
}

/// `holder`'s current entry on `target`: the one the edge write in force there in this node's
/// walk created (spec/permissions.md §2), whatever the `roles.0` state says of it (a void
/// finalize resets it in the state while the edge stands). At most one: a role commit creates
/// one entry per holder.
fn current_entry(tx: &Tx<'_>, target: &Tid, holder: &Tid) -> Option<(osis_crdt::Dot, osis_base::Value)> {
    let c = tx.core.timelines().get(target)?.in_force(holder, target)?;
    let view = &tx.core.ix.commits.get(&c)?.view;
    let ai = view.aspect(target, "roles.0")?;
    let own = crate::engine::Owned::of_view(view, &c, ai)?;
    tx.core.ix.holder_keys.iter().find(|((t, d), m)| t == target && *m == holder && own.owns(d.origin())).map(|((_, d), m)| (d.clone(), osis_base::Value::Weak(*m)))
}

/// Resets `holder`'s current entry on `target` in `m`, if it has one (spec/permissions.md §2):
/// every edge write does, so a holder's k-th write carries one reset, not k.
pub(crate) fn reset_current(tx: &Tx<'_>, m: &mut Mutation, target: Tid, holder: Tid) -> Result<bool> {
    let Some(e) = current_entry(tx, &target, &holder) else { return Ok(false) };
    m.dead_resets.entry((target, super::ak("roles.0")?)).or_default().push(e);
    Ok(true)
}

/// The removal of `holder`'s edge on `target` in `m`: a reset of its current entry. A holder
/// with none (a mint admin's record edge, stored nowhere, or an edge already removed) gets an
/// entry of this delta reset in it: a removal naming the holder whose creation every reader
/// holds (spec/permissions.md §2), so it applies in any arrival order.
pub(crate) fn removal(tx: &Tx<'_>, m: &mut Mutation, target: Tid, holder: Tid) -> Result<()> {
    if !reset_current(tx, m, target, holder)? {
        m.fresh_resets.entry((target, super::ak("roles.0")?)).or_default().push(osis_base::Value::Weak(holder));
    }
    Ok(())
}

/// A removal or demotion (or a self-removal) of `d.holder` on `target` by `who`: an explicit
/// demotion carries the frontier and the target's rotation of the roles the holder left in the
/// same commit (spec/permissions.md §3), after the cascade on the target, where `who` may rotate
/// those roles, else goes alone (its departure uncovered, the rotation due); no secret of the
/// target is needed
/// (the rotation supersedes every current epoch, held or not; a holder of one it lacks adds it
/// to the history). A self-removal carries no frontier and no rotation (the next node that may
/// rotate does), and the leaver drops what it lost. An explicit removal of an absent edge resets
/// its dead entries (spec/permissions.md §2). With `others`, an explicit removal of those
/// holders' edges too, under the same frontier and one rotation (spec/commits.md §2). Then the
/// inbox copy to each holder, logged before any other entry under every sync ID the removed
/// parties could read.
pub(crate) fn demote_in(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, d: &Demotion, others: &[Tid], frontier: Option<osis_perm::Frontier>) -> Result<Done> {
    let who = signer.unwrap_or(tx.core.me());
    let holder = d.holder;
    let ts = now_ts(tx.core);
    let tl = tx.core.timelines().get(&target).ok_or(Error::UnknownThing(target))?;
    let old = tl.edges_at(None).get(&holder, &target).copied();
    let new = written(tx.core, &target, old.as_ref(), d)?;
    let new_p = new.as_ref().map(perm_edge);
    if old.is_some() && !osis_perm::types::lowers(new_p.as_ref(), old.as_ref()) {
        return Err(Error::Misuse("not a lowering write (use grant)"));
    }
    // the other holders removed in the same commit: distinct present edges, not the author's
    let mut gone: Vec<(Tid, PermEdge)> = Vec::new();
    for o in others {
        let e = tl.edges_at(None).get(o, &target).copied().ok_or(Error::Misuse("no edge to remove"))?;
        if d.new.is_some() || *o == holder || *o == who || gone.iter().any(|(x, _)| x == o) {
            return Err(Error::Misuse("a removal of several holders removes distinct edges of others"));
        }
        gone.push((*o, e));
    }
    let selfr = old.is_some() && crate::apply::validity::self_removal(tx.core, &who, &target, &holder, ts);
    let admin = crate::engine::secrets::usable_role_now(tx, &who, &target)? == Some(Role::Admin);
    if !selfr && !admin || selfr && !gone.is_empty() {
        return Err(Error::Permission { tid: target, needs: Role::Admin });
    }
    let mut done = Done::default();
    let mut m = Mutation::new();
    // before the rotation: a departing commit's names carry its signer (`rotation_into`)
    if let Some(s) = signer {
        m.sign_as(s);
    }
    if old.is_none() && d.new.is_some() {
        return Err(Error::Misuse("no edge to lower"));
    }
    removal(tx, &mut m, target, holder)?;
    if let Some(n) = &new {
        put_edge(&mut m, target, holder, n)?;
    }
    for (o, _) in &gone {
        removal(tx, &mut m, target, *o)?;
    }
    if !selfr && let Some(f) = frontier {
        m.frontier(f);
    }
    // an explicit demotion carries the target's rotation of the roles the holders left
    let mut roles = BTreeSet::new();
    let mut departs = rotation::Departs::No;
    let mut skip = Vec::new();
    // departures for keys: roles with `until` disregarded (spec/crypto.md §4), so a removal of an
    // edge past its `until` is the departure and rotates
    let new_role = rotation::key_role(new_p.as_ref());
    let mut left: BTreeSet<Role> = BTreeSet::new();
    let mut pending = Vec::new();
    // an explicit lowering from write or above demotes a writer or admin (spec/permissions.md
    // §5.1 step 4): the target's keysets in this commit carry it (spec/crypto.md §4, Carried
    // demotions)
    let mut demotes = false;
    let removing: Vec<Tid> = std::iter::once(holder).chain(gone.iter().map(|(x, _)| *x)).collect();
    for (x, o, n) in std::iter::once((holder, old, new_role)).chain(gone.iter().map(|(x, e)| (*x, Some(*e), None))) {
        let held_role = rotation::key_role(o.as_ref());
        demotes |= !selfr && held_role >= Some(Role::Write) && n < held_role;
        if let Some(dep) = Departure::of_change(x, held_role, n) {
            left.extend(ROLES.into_iter().filter(|r| *r >= dep.from && Some(*r) <= held_role));
            pending.push(dep);
        }
    }
    if !selfr && !left.is_empty() && tx.core.is_independent(&target) {
        // boxing to the remaining holders encrypts under their keysets: the cascade first (no
        // finalize of an edge this commit removes; no rotation of a role of the target the
        // holders leave, which would box them at it: this commit rotates it)
        rotation::ensure_rotated_but(tx, who, target, &removing, &left, &mut done)?;
        let may = rotation::may_rotate(tx.core, &who, &target);
        roles = left.into_iter().filter(|r| may.contains(r)).collect();
        skip = std::iter::once((holder, new_role)).chain(gone.iter().map(|(x, _)| (*x, None))).collect();
        departs = match (pending.is_empty(), demotes) {
            (true, _) => rotation::Departs::No,
            (false, false) => rotation::Departs::Holder,
            (false, true) => rotation::Departs::Demoting,
        };
    }
    if selfr {
        m.unchecked();
    }
    let c = rotation::commit_rotating(tx, m, who, target, &roles, &skip, departs, &mut done)?;
    // a removed holder is opened the target's sync ID no more: its removal reaches it as a grant does
    if let (Some(c), false) = (c, selfr) {
        for x in &removing {
            super::inbox::deliver_copy(tx, *x, c, target)?;
        }
    }
    Ok(done)
}

/// The edges on `target` that `who` (this node, or a key actor it signs as) may finalize now
/// (spec/permissions.md §2), each with whether its finalize says retain: past their `until` by
/// this node's clock (an edge the timeline holds with every applied write in effect), of a role
/// at most `who`'s own there, `who` holding write; not its own (that is a self-removal).
pub(crate) fn finalizable(core: &crate::engine::Core, who: &Tid, target: &Tid) -> Vec<(Tid, PermEdge, bool)> {
    let ts = now_ts(core);
    // read by the edges into `target` and what reaches it (`Timelines::on`, `role`)
    let Some(on) = core.timelines().on(target) else { return Vec::new() };
    let role = core.timelines().role(who, target, At::now(ts));
    if role < Some(Role::Write) {
        return Vec::new();
    }
    let ended: Vec<(Tid, PermEdge)> = on.holders().into_iter().filter(|(m, e)| m != who && e.until.is_some() && !e.says_retain() && !e.alive_at(Some(ts)) && Some(e.role) <= role).collect();
    if ended.is_empty() {
        return Vec::new();
    }
    // it says what the expiry would (spec/permissions.md §3, Retain): what the grant was written
    // with
    ended.into_iter().map(|(m, e)| (m, e, e.retain)).collect()
}

/// A finalize by `who` of the edges `ended` on `target` (`finalizable`; spec/permissions.md §2):
/// their removal with no frontier, each saying retain or erase as its expiry would, and the
/// rotation of the roles they held that `who` may rotate, in one role commit, none of `kept`
/// (the roles a removal of the same act rotates, `rotation::Keep`). The cascade below
/// `target` is the caller's (`rotation::ensure_rotated`).
pub(crate) fn finalize_in(tx: &mut Tx<'_>, who: Tid, target: Tid, ended: &[(Tid, PermEdge, bool)], kept: &BTreeSet<Role>, done: &mut Done) -> Result<()> {
    let mut m = Mutation::new();
    if who != tx.core.me() {
        m.sign_as(who);
    }
    let mut left: BTreeSet<Role> = BTreeSet::new();
    let mut pending = Vec::new();
    for (x, e, keep) in ended {
        removal(tx, &mut m, target, *x)?;
        if *keep {
            put_edge(&mut m, target, *x, &Edge { role: Role::Read, until: Some(WallMs(0)), may_grant: false, retain: false, floor: None })?;
        }
        if let Some(dep) = Departure::of_change(*x, Some(e.role), None) {
            left.extend(ROLES.into_iter().filter(|r| *r <= e.role));
            pending.push(dep);
        }
    }
    let may = rotation::may_rotate(tx.core, &who, &target);
    let mut roles: BTreeSet<Role> = left.into_iter().filter(|r| may.contains(r) && !kept.contains(r)).collect();
    if !tx.core.is_independent(&target) {
        roles.clear();
    }
    let skip: Vec<(Tid, Option<Role>)> = ended.iter().map(|(x, _, _)| (*x, None)).collect();
    // a finalize demotes nobody (spec/permissions.md §5.1: it audits nothing)
    let departs = if pending.is_empty() { rotation::Departs::No } else { rotation::Departs::Holder };
    // a writer's write on `roles.0`: judged by the finalize authority, not an admin's
    m.unchecked();
    rotation::commit_rotating(tx, m, who, target, &roles, &skip, departs, done).map(|_| ())
}

impl Engine {
    /// Whether a removal from `t`, or a grant on it ending by `until`, retains a read-only copy
    /// unless its writer says otherwise: the `retain` of `t`'s current setting (spec/permissions.md
    /// §3, Retain). A timed grant carries what it was written with (`Edge::retain`).
    pub fn retains_by_default(&self, t: &Tid) -> bool {
        crate::apply::validity::retain_default(&self.core, t)
    }

    /// Grants `holder` the edge `edge` on `target`, or raises its edge (spec/permissions.md §2),
    /// as an admin of the target or by a may-grant. Gives the target (and a dependent holder) secrets of
    /// their own first where needed. Delivers the grant to the holder's inbox (a node: direct).
    pub fn grant(&mut self, target: &Tid, holder: &Tid, edge: &Edge) -> Result<Done> {
        self.grant_signed(None, *target, *holder, edge, false, History::All)
    }

    /// `grant` handing `history` of what was written before it (spec/crypto.md §4, Floors): a
    /// grant without it is a cut, so `holder` reads only what is written under its epoch and
    /// those after it. An admin's grant to a holder holding no role on the target.
    pub fn grant_with(&mut self, target: &Tid, holder: &Tid, edge: &Edge, history: History) -> Result<Done> {
        self.grant_signed(None, *target, *holder, edge, false, history)
    }

    /// `grant_in` with the frontier of what this node received when the grant audits: an admin's
    /// grant below the edge as restored (spec/permissions.md §5.1 step 4), such as a may-grant taken
    /// away or a role below one the holder lost with no explicit write on the edge since. Invariant: an
    /// explicit write that audits carries its author's frontier, else every write of the holder's
    /// it puts in question drops, received or not.
    pub(crate) fn grant_signed(&mut self, signer: Option<Tid>, target: Tid, holder: Tid, edge: &Edge, leave: bool, history: History) -> Result<Done> {
        self.grant_signed_then(signer, target, holder, edge, leave, history, |_| Ok(()))
    }

    /// `grant_signed`, then `then` in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn grant_signed_then(&mut self, signer: Option<Tid>, target: Tid, holder: Tid, edge: &Edge, leave: bool, history: History, then: impl FnOnce(&mut Tx<'_>) -> Result<()>) -> Result<Done> {
        let who = signer.unwrap_or(self.core.me());
        let new = Some(perm_edge(edge));
        let audits = self.core.role_now(&who, &target) == Some(Role::Admin) && self.needs_frontier(&target, &holder, Some(edge));
        let frontier = match audits {
            true => {
                let ops: Vec<osis_perm::EdgeOp> = std::iter::once((holder, new)).chain(leave.then_some((who, None))).map(|(holder, edge)| osis_perm::EdgeOp { target, holder: osis_base::Holder::Thing(holder), edge }).collect();
                self.demotion_frontier(target, ops)?
            }
            false => (None, Vec::new()),
        };
        let (frontier, covers) = frontier;
        let mut done = self.run(|tx| {
            let done = grant_history(tx, signer, target, holder, edge, leave, frontier, history)?;
            then(tx)?;
            Ok(done)
        })?;
        done.commits.splice(0..0, covers);
        // a cut's owed snapshots (the state it carries to the holder) go right after it
        if history == History::None {
            self.purge_resnapshots()?;
        }
        Ok(done)
    }

    /// Whether an explicit write of `edge` (`None`: a removal) on `holder`'s edge on `target`,
    /// stamped now, carries its author's frontier (spec/permissions.md §5.1 step 4): a removal
    /// always (without one it is a finalize), another write when the edge as restored exceeds it
    /// (an `until` alive then takes nothing). The writer rule refuses either way of getting it
    /// wrong (`check_content_rules`).
    pub fn needs_frontier(&self, target: &Tid, holder: &Tid, edge: Option<&Edge>) -> bool {
        let new = edge.map(perm_edge);
        new.is_none() || self.core.timelines().get(target).is_some_and(|tl| tl.audits(holder, target, new, self.core.hlc.peek()))
    }

    /// The role for keys of `holder`'s edge on `target` in the state (one past its `until`
    /// included): a grant below it would be the holder's departure, which only a demotion makes
    /// (spec/permissions.md §3).
    pub fn key_role(&self, target: &Tid, holder: &Tid) -> Option<Role> {
        rotation::key_role(self.core.timelines().get(target)?.edges_at(None).get(holder, target))
    }

    /// The things a demotion of `holder` on `target` puts in question (spec/permissions.md §5.1):
    /// every thing the demoted authority gave write or role authority on. What a caller syncs
    /// first when it wants the removal to keep more (spec/permissions.md §5.3).
    pub fn removal_scope(&self, target: &Tid, holder: &Tid, new: Option<&Edge>) -> BTreeSet<Tid> {
        let _ = new;
        let scope = crate::apply::receipt::scope_of(&self.core, &[(*holder, *target)]);
        scope.roles.values().chain(scope.content.values()).flatten().copied().collect()
    }

    /// The frontier edge writes `ops` on `target`, stamped now, carry (spec/permissions.md §5.1
    /// Frontier): what this node received of the commits resting on the edges they lower
    /// (`receipt::scope_of`), and its own cover of what it no longer holds the ID of
    /// (`own_cover`). Returns the frontier and the own covers, which the caller's `Done` carries
    /// before the lowering. `None`: an unknown target.
    fn demotion_frontier(&mut self, target: Tid, ops: Vec<osis_perm::EdgeOp>) -> Result<(Option<osis_perm::Frontier>, Vec<CommitId>)> {
        let as_of = self.now();
        if self.core.timelines().get(&target).is_none() {
            return Ok((None, Vec::new()));
        }
        let edges: Vec<(Tid, Tid)> = ops.iter().filter_map(|o| Some((o.holder.thing()?, o.target))).collect();
        let scope = crate::apply::receipt::scope_of(&self.core, &edges);
        let mut keep: BTreeSet<CommitId> = BTreeSet::new();
        let mut f = self.frontier_fitted(&scope, as_of, &keep)?;
        let named = self.own_cover(&scope)?;
        if !named.is_empty() {
            keep.extend(named.iter().copied());
            f = self.frontier_fitted(&scope, as_of, &keep)?;
        }
        Ok((Some(osis_perm::Frontier::new(f.commits)), named.into_iter().collect()))
    }

    /// Lowers or removes `d.holder`'s edge on `target` (spec/permissions.md §2, §3, §5): an
    /// explicit demotion by an admin (with the frontier of what this node had received of the
    /// demoted nodes), or a
    /// self-removal. The rotation of the roles the holder left goes in the same commit (while Seal
    /// waits, none: it stays due).
    pub fn demote(&mut self, target: &Tid, d: &Demotion) -> Result<Done> {
        self.remove_signed(None, target, d, &[])
    }

    /// Whether writing `new` (`None`: a removal) on `holder`'s edge on `target` would leave
    /// `target` with no standing admin here, so that it is refused unless marked
    /// (`leaving_adminless`): for a caller writing several commits that checks before the first.
    pub fn leaves_no_admin(&self, target: &Tid, holder: &Tid, new: Option<&Edge>) -> bool {
        crate::apply::validity::leaves_no_admin(&self.core, target, &[(*holder, new.map(perm_edge))])
    }

    /// `f` with the edge writes it signs allowed to leave a thing with no standing admin
    /// (spec/permissions.md §1, The last admin; otherwise `Error::LeavesNoAdmin`): each commit
    /// that does carries the adminless mark, and no other.
    pub fn leaving_adminless<R>(&mut self, f: impl FnOnce(&mut Engine) -> R) -> R {
        let was = std::mem::replace(&mut self.core.leave_adminless, true);
        let r = f(self);
        self.core.leave_adminless = was;
        r
    }

    /// `demote` that also removes `others` in the same commit under one rotation
    /// (spec/commits.md §2); `d.new` must then be `None`.
    pub(crate) fn remove_signed(&mut self, signer: Option<Tid>, target: &Tid, d: &Demotion, others: &[Tid]) -> Result<Done> {
        self.remove_signed_then(signer, target, d, others, |_| Ok(()))
    }

    /// `remove_signed`, then `then` in the same transaction.
    pub(crate) fn remove_signed_then(&mut self, signer: Option<Tid>, target: &Tid, d: &Demotion, others: &[Tid], then: impl FnOnce(&mut Tx<'_>) -> Result<()>) -> Result<Done> {
        let t = *target;
        let new = match self.core.timelines().get(&t) {
            Some(tl) => written(&self.core, &t, tl.edges_at(None).get(&d.holder, &t), d)?,
            None => None,
        };
        let audits = self.needs_frontier(&t, &d.holder, new.as_ref());
        let new = new.as_ref().map(perm_edge);
        let ops: Vec<osis_perm::EdgeOp> = std::iter::once((d.holder, new)).chain(others.iter().map(|x| (*x, None))).map(|(holder, edge)| osis_perm::EdgeOp { target: t, holder: osis_base::Holder::Thing(holder), edge }).collect();
        let (frontier, covers) = if audits { self.demotion_frontier(t, ops)? } else { (None, Vec::new()) };
        let d = d.clone();
        let mut done = self.run(|tx| {
            let done = demote_in(tx, signer, t, &d, others, frontier)?;
            then(tx)?;
            Ok(done)
        })?;
        done.commits.splice(0..0, covers);
        Ok(done)
    }
}

/// How this node may remove a holder's edge (`Engine::may_remove`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// A self-removal through admin on the holder: no frontier, no rotation, no pre-sync.
    SelfRemoval,
    /// An explicit demotion by an admin of the target: audited with this node's frontier.
    Explicit,
}

impl Engine {
    /// How this node may remove `holder`'s edge on `target` now, if at all: a self-removal
    /// (admin on the holder actor its only authority for it, spec/permissions.md §2), or an
    /// explicit demotion (admin on the target, `usable_role`). Reads the clock up to the next
    /// `until` or role commit of the target's and the holder's components (an authority ending by
    /// time alone moves it).
    pub fn may_remove(&mut self, target: &Tid, holder: &Tid) -> Result<Option<Removal>> {
        let me = self.core.me();
        let _horizon = self.core.bound_to_horizon([*target, *holder].into_iter());
        if crate::apply::validity::self_removal(&self.core, &me, target, holder, now_ts(&self.core)) {
            return Ok(Some(Removal::SelfRemoval));
        }
        Ok((self.usable_role(target, self.core.role_now(&me, target))? == Some(Role::Admin)).then_some(Removal::Explicit))
    }
}
