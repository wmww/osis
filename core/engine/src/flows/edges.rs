//! Edge writes (spec/permissions.md §2, §3, §5.3): grants with the grantee's boxes, changes,
//! removals and demotions carrying the target's rotation, invite grants and self-removals,
//! the pre-sync choice and the receipt-record frontier, inbox delivery and acceptance
//! (spec/sync.md §3, spec/crypto.md §5).

use super::{Delivery, Done, inbox_of, now_ts, own_label, put_edge, put_secrets, remove_edge, secrets_in};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::rotation;
use crate::Mutation;
use osis_commit::CommitBlob;
use osis_base::{CommitId, Role, Tid, WallMs};
use osis_keys::{Departure, ROLES, box_holder, roles_up_to};
use osis_label::{InboxLabel, InboxPayload, InboxThing, open_inbox_blob, seal_inbox_blob};
use osis_perm::{At, Edge as PermEdge};
use osis_schema::core_types::{self as ct, Edge};
use std::collections::BTreeSet;

/// Before stamping a role-lowering write (spec/permissions.md §5.3): what the caller did about
/// syncing the labels `Engine::presync_scope` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreSync {
    /// Every label was synced and what it downloaded applied.
    Synced,
    /// Some label could not be synced: stamp anyway (`proceed`; uncompacted writes by the
    /// demoted holder under those labels are lost) or fail.
    Unsynced { proceed: bool },
}

/// A role-lowering edge write: `holder`'s new edge on the target (`None` removes it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demotion {
    pub holder: Tid,
    pub new: Option<Edge>,
    pub presync: PreSync,
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
    let retain = old.is_some() && d.retain.unwrap_or_else(|| crate::apply::validity::retain_now(core, target));
    Ok(retain.then_some(Edge { role: Role::Read, until: Some(osis_base::WallMs(0)), invite: None, tied: None }))
}

fn perm_edge(e: &Edge) -> PermEdge {
    PermEdge { role: e.role, until: e.until, invite: e.invite, tied: e.tied.map(super::tied::tie_perm) }
}

/// Which parts of a commit an inbox blob carries.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Parts {
    /// Every part (a grant: the edge and the grantee's boxes; a re-seal).
    All,
    /// The `roles.0` parts only (a removal: the rotation's boxes are not about the holder).
    Edge,
}

/// The deliveries of a role commit about `holder` (spec/permissions.md §2): an inbox
/// blob for an actor, the commit itself over a direct connection for a node, nothing for a
/// recovery or link key (it reads its label by static entry).
pub(crate) fn deliver_to(tx: &mut Tx<'_>, holder: Tid, c: CommitId, things: &[Tid]) -> Result<Vec<Delivery>> {
    deliver_parts(tx, holder, c, things, Parts::All, Vec::new())
}

/// `deliver_to` with the carried `parts` and the author's `chain` for them (`CommitBlobPlaintext`
/// values, spec/wire.md §9). A flow seals with no chain: node-sync seals again from the record it
/// keeps (`SyncRecords::note_unsent`), with the chain, when it sends.
pub fn deliver_parts(tx: &mut Tx<'_>, holder: Tid, c: CommitId, things: &[Tid], parts: Parts, chain: Vec<osis_base::Value>) -> Result<Vec<Delivery>> {
    if tx.core.is_key_actor(&holder) {
        let is_node = super::super::flows::is_node(tx, &holder)?;
        return Ok(if is_node { vec![super::owe(tx, Delivery::Direct { to: holder, commits: vec![c] })?] } else { Vec::new() });
    }
    let Some((_, inbox)) = inbox_of(tx, &holder)? else { return Ok(Vec::new()) };
    // sealed to the holder's newest read keyset (its own, else the inbox actor's)
    let mut to = holder;
    let mut kem = None;
    let up: Vec<Tid> = tx.core.record_chain(&holder).filter_map(|s| s.thing()).collect();
    for cur in up {
        if let Some(ks) = super::Core::keys_in(tx, &cur)?.and_then(|k| k.read) {
            let ct::KemKey::X25519MlKem768(b) = &ks.kem_key;
            kem = Some(osis_crypto::KemPublicKey::from_slice(b)?);
            to = cur;
            break;
        }
    }
    let Some(kem) = kem else { return Ok(Vec::new()) };
    let mut blob = tx.get_commit(&c)?.ok_or(Error::UnknownCommit(c))?;
    if parts == Parts::Edge {
        let keep: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, a)| a.ak.as_str() == "roles.0").map(|(i, _)| i).collect();
        blob.parts.retain(|p| keep.contains(&p.ai));
    }
    let commit = osis_base::decode(&blob.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB })
        .map_err(|_| Error::Corrupt("commit blob"))?;
    let mut ts: Vec<InboxThing> = Vec::new();
    let mut seen = BTreeSet::new();
    for t in things {
        if seen.insert(*t) {
            let label = own_label(tx, t)?.map(|(id, index, hosts)| InboxLabel { id, index, hosts });
            let delete_keys = crate::engine::secrets::own_delete_keys(tx, t)?;
            ts.push(InboxThing { tid: *t, label, delete_keys });
        }
    }
    ts.sort_by_key(|t| t.tid);
    let payload = InboxPayload { commit, things: ts, chain };
    let now = tx.now();
    let blob = seal_inbox_blob(&to, &kem, &payload, now, &mut *tx.rng)?;
    let resend = super::Resend { holder, commit: c, things: things.to_vec(), edge_only: parts == Parts::Edge };
    // its record in the commit's own transaction: node-sync sends it from there, also after a
    // crash before `carry_out` (spec/sync.md §3, §5)
    if let Some(r) = tx.core.sync_records {
        r.note_unsent(tx, holder, c, things.to_vec(), parts == Parts::Edge)?;
    }
    Ok(vec![Delivery::Inbox { to, inbox, blob, resend }])
}

/// A grant or a raise of `holder`'s edge on `target` by `who` (this node, or a held key actor
/// signing), with the grantee's boxes for every granted role at each current epoch
/// (spec/crypto.md §4). An admin's grant, or an invite grant (spec/permissions.md §2) where
/// `who`'s effective invite allows it and the holder has no current edge. `leave`: the signer's
/// own edge removed in the same commit (a single-use redemption, spec/permissions.md §7).
pub(crate) fn grant_in(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, holder: Tid, edge: &Edge, leave: bool) -> Result<Done> {
    let who = signer.unwrap_or(tx.core.id.tid());
    if edge.invite.is_some_and(|i| i > edge.role) {
        return Err(Error::Misuse("invite above the edge's role"));
    }
    if edge.until == Some(osis_base::WallMs(0)) {
        return Err(Error::Misuse("`until` 0 is a removal's saying retain"));
    }
    let role = tx.core.role_now(&who, &target);
    let admin = role == Some(Role::Admin);
    // a non-writer of the target's label deposits its invite grant (spec/sync.md §5)
    let deposit = role < Some(Role::Write);
    let ts = now_ts(tx.core);
    let old = tx.core.timelines.get(&target).and_then(|tl| tl.roster(&target, At::now(ts)).get(&holder).copied());
    let invite = tx.core.timelines.get(&target).and_then(|tl| tl.invite(&who, &target, At::now(ts)));
    // below the holder's edge for keys (one past its `until` included, still in the state) a
    // grant would be a demotion with no frontier and no rotation: a demotion lowers it
    let below = tx.core.timelines.get(&target).is_some_and(|tl| rotation::key_role(tl.edges_at(None).get(&holder, &target)) > Some(edge.role));
    if admin && below {
        return Err(Error::Misuse("a grant below the holder's edge lowers it (use demote)"));
    }
    if !admin {
        let ok = old.is_none() && invite.is_some_and(|i| edge.role <= i && edge.invite.is_none_or(|x| x <= i));
        if !ok || below {
            return Err(Error::Permission { tid: target });
        }
    }
    let mut done = Done::default();
    // a thing is made a holder only with secrets of its own; a target gets them on its first
    // holder other than its first admin (spec/permissions.md §3)
    if !tx.core.is_key_actor(&holder) && !tx.core.has_own_secrets(&holder) {
        rotation::own_secrets(tx, holder, &mut done)?;
    }
    if !tx.core.has_own_secrets(&target) && !tx.core.is_key_actor(&target) {
        if !admin {
            return Err(Error::Permission { tid: target });
        }
        rotation::own_secrets(tx, target, &mut done)?;
    }
    // rotate first where due (a holder actor's own epochs too, by this node where it may), then
    // box the holder at the current epochs held, blocked ones included: a box carrying a secret
    // is encrypted under its recipient's key, not under that epoch (spec/crypto.md §4,
    // Encrypting under; `rotation::reseal_one` alike)
    if !tx.core.is_key_actor(&holder) {
        let me = tx.core.id.tid();
        rotation::ensure_rotated(tx, me, holder, &mut done)?;
    }
    let roles = roles_up_to(edge.role);
    // a renewal of an ended edge is not finalized first: the grant writes it anew
    rotation::ensure_rotated_but(tx, who, target, &[holder], &mut done)?;
    let epochs = tx.core.epochs(&target).ok_or(Error::Misuse("no secrets held for the target"))?;
    let secrets = secrets_in(tx, &target)?;
    // a holder actor is boxed at the keyset Seal gives, per role (spec/crypto.md §4); one whose
    // grant would close a key cycle is keyless and boxed nothing; one this node can seal to no
    // keyset is not granted (its boxes would say nothing)
    let boxes = if rotation::grant_keyless(tx.core, &target, &holder) {
        None
    } else {
        let rcpt = match rotation::sealed(tx, &who, &target, &holder, edge.role)? {
            rotation::Sealed::Boxed(r) => r,
            rotation::Sealed::Out => return Err(Error::Misuse("the holder has no keyset this node may seal it to")),
            rotation::Sealed::Wait => return Err(rotation::SEAL_WAITS),
        };
        Some(box_holder(&target, &epochs, &secrets, &rcpt, &roles, &mut *tx.rng)?.ok_or(Error::Misuse("the holder's keyset is unknown"))?)
    };
    // an edge past its `until` is out of the roster but still in the state: a set over it would
    // keep its fields the new edge leaves out (the `until` among them)
    let held = old.is_some() || tx.core.timelines.get(&target).is_some_and(|tl| tl.edges_at(None).get(&holder, &target).is_some());
    let mut m = Mutation::new();
    if held {
        remove_edge(&mut m, target, holder)?;
    }
    put_edge(&mut m, target, holder, edge)?;
    if leave {
        remove_edge(&mut m, target, who)?;
    }
    if let Some(w) = &boxes {
        put_secrets(&mut m, target, w, !admin)?;
    }
    if let Some(s) = signer {
        m.sign_as(s);
    }
    if !admin {
        m.unchecked();
    }
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        done.deliveries.extend(deliver_to(tx, holder, c, &[target])?);
        if deposit {
            done.deliveries.push(super::owe(tx, Delivery::Deposit { commit: c, under: target })?);
        }
        if let Some(w) = &boxes {
            rotation::carry(tx, target, w, &mut done)?;
        }
    }
    Ok(done)
}

/// The dots of `holder`'s `roles.0` entries on `target` this node has seen, live or dead.
fn entry_dots(tx: &Tx<'_>, target: &Tid, holder: &Tid) -> Vec<(osis_crdt::Dot, osis_base::Value)> {
    tx.core.ix.holder_keys.iter().filter(|((t, _), m)| t == target && *m == holder).map(|((_, d), m)| (d.clone(), osis_base::Value::Tid(*m))).collect()
}

/// The reset of `holder`'s edge on `target` in `m`: its live entry and every entry of it the node
/// saw, so it resets also an entry an earlier write reset in the state while applying nothing on
/// the timeline (a void finalize, spec/permissions.md §2), where the edge still stands. A holder
/// with no entry at all (a first admin's record edge, stored nowhere) gets an entry of this delta
/// reset in it: a removal naming the holder whose creation every reader holds (spec/permissions.md
/// §2), so it applies in any arrival order.
pub(crate) fn removal(tx: &Tx<'_>, m: &mut Mutation, target: Tid, holder: Tid) -> Result<()> {
    remove_edge(m, target, holder)?;
    let dots = entry_dots(tx, &target, &holder);
    let key = (target, super::ak("roles.0")?);
    if dots.is_empty() {
        m.fresh_resets.entry(key).or_default().push(osis_base::Value::Tid(holder));
    } else {
        m.dead_resets.entry(key).or_default().extend(dots);
    }
    Ok(())
}

/// Whether lowering `lowered` on plain `target` would leave it no admin (spec/permissions.md §1:
/// refused; signed anyway, the thing stays plain and nobody administers it).
fn leaves_no_admin(core: &crate::engine::Core, target: &Tid, lowered: &[(Tid, Option<Role>)]) -> bool {
    !core.key_holders(target).into_iter().any(|(m, r)| r == Role::Admin && lowered.iter().all(|(x, n)| *x != m || *n == Some(Role::Admin)))
}

/// A removal or demotion (or a self-removal) of `d.holder` on `target` by `who`: an explicit
/// demotion carries the frontier and the target's rotation of the roles the holder left in the
/// same commit (spec/permissions.md §3), after the cascade on the target, or no rotation while
/// Seal waits (its rotation stays due); a self-removal carries no frontier and no rotation (the
/// next node that may rotate does), and the leaver drops what it lost. An
/// explicit removal of an absent edge resets its dead entries (spec/permissions.md §2). With
/// `others`, an explicit removal of those holders' edges too, under the same frontier and one
/// rotation (spec/commits.md §2). Then the inbox copy to each holder, and placement before any
/// other upload under every label the removed parties could read. A rotated role whose current
/// secrets this node lacks rotates only when nodes holding no write once the removal applies
/// made every such epoch (`rotation::lacked_made_by`): the keyset lists them, so they are
/// superseded (lockout recovery, spec/permissions.md §3), and the things below it so locked
/// rotate next (`rotation::recover_reached`); else the removal goes alone.
pub(crate) fn demote_in(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, d: &Demotion, others: &[Tid], frontier: Option<osis_base::Value>) -> Result<Done> {
    let who = signer.unwrap_or(tx.core.id.tid());
    let holder = d.holder;
    let ts = now_ts(tx.core);
    let tl = tx.core.timelines.get(&target).ok_or(Error::UnknownThing(target))?;
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
    let admin = tx.core.role_now(&who, &target) == Some(Role::Admin);
    if !selfr && !admin || selfr && !gone.is_empty() {
        return Err(Error::Permission { tid: target });
    }
    if !selfr && let PreSync::Unsynced { proceed: false } = d.presync {
        return Err(Error::Misuse("labels not synced before a demotion; proceed to stamp anyway"));
    }
    // a plain thing's only holder for keys is its first admin (a grant gives it secrets
    // of its own first): lowering the first admin's edge would leave it no admin, refused
    // (spec/permissions.md §1)
    if !tx.core.has_own_secrets(&target) && !tx.core.is_key_actor(&target) {
        let lowered: Vec<(Tid, Option<Role>)> = std::iter::once((holder, rotation::key_role(new_p.as_ref()))).chain(gone.iter().map(|(x, _)| (*x, None))).collect();
        if leaves_no_admin(tx.core, &target, &lowered) && !tx.core.skip_writer_rules {
            return Err(Error::Misuse("this would leave a plain thing with no admin: grant another admin first"));
        }
    }
    let mut done = Done::default();
    let mut m = Mutation::new();
    // before the rotation: a departing commit's names carry its signer (`rotation_into`)
    if let Some(s) = signer {
        m.sign_as(s);
    }
    match old {
        Some(_) => removal(tx, &mut m, target, holder)?,
        None => {
            if d.new.is_some() {
                return Err(Error::Misuse("no edge to lower"));
            }
            let dots = entry_dots(tx, &target, &holder);
            if dots.is_empty() {
                return Err(Error::Misuse("no edge of that holder was ever seen"));
            }
            m.dead_resets.insert((target, super::ak("roles.0")?), dots);
        }
    }
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
    let mut rot = None;
    let mut unreached = Vec::new();
    // departures for keys: roles with `until` disregarded (spec/crypto.md §4), so a removal of an
    // edge past its `until` is the departure and rotates
    let new_role = rotation::key_role(new_p.as_ref());
    let mut left: BTreeSet<Role> = BTreeSet::new();
    let mut pending = Vec::new();
    let removing: Vec<Tid> = std::iter::once(holder).chain(gone.iter().map(|(x, _)| *x)).collect();
    for (x, o, n) in std::iter::once((holder, old, new_role)).chain(gone.iter().map(|(x, e)| (*x, Some(*e), None))) {
        let held_role = rotation::key_role(o.as_ref());
        if let Some(dep) = Departure::of_change(x, held_role, n) {
            left.extend(ROLES.into_iter().filter(|r| *r >= dep.from && Some(*r) <= held_role));
            pending.push(dep);
        }
    }
    if !selfr && !left.is_empty() && tx.core.has_own_secrets(&target) {
        // boxing to the remaining holders encrypts under their keysets: the cascade first (no
        // finalize of an edge this commit removes)
        rotation::ensure_rotated_but(tx, who, target, &removing, &mut done)?;
        let may = rotation::may_rotate(tx.core, &who, &target);
        let roles: BTreeSet<Role> = left.into_iter().filter(|r| may.contains(r)).collect();
        if !roles.is_empty() {
            let held = tx.core.epochs(&target).ok_or(Error::Misuse("no secrets held for the target"))?;
            // rotating a role without the secret of one of its current epochs would drop that
            // secret from the history boxes, unless every lacked epoch's maker holds no write once
            // this removal applies (spec/crypto.md §4, Boxes); else the removal goes alone, its
            // departure uncovered (spec/permissions.md §3, Lockout recovery)
            let after: Vec<(Tid, Tid, Option<PermEdge>)> = std::iter::once((holder, target, new_p)).chain(gone.iter().map(|(x, _)| (*x, target, None))).collect();
            let recovers = roles.iter().any(|r| !held.role(*r).holds_current());
            let rotates = roles.iter().all(|r| rotation::may_supersede(tx.core, &held, *r, &target, &after));
            let skip: Vec<(Tid, Option<Role>)> = std::iter::once((holder, new_role)).chain(gone.iter().map(|(x, _)| (*x, None))).collect();
            // while Seal waits the removal goes alone (spec/permissions.md §3), but a recovery
            // waits: only its own rotation may list the epochs it lacks
            let holders = if rotates { rotation::recipients(tx, &who, &target, &skip)? } else { None };
            if rotates && recovers && holders.is_none() {
                return Err(rotation::SEAL_WAITS);
            }
            if let Some(holders) = holders {
                let r = rotation::rotation_into(tx, &mut m, target, &roles, &held, &holders, !pending.is_empty())?;
                if rotation::refreshes_deposit(tx.core, &who, &target, &roles) {
                    rotation::fresh_deposit_seed(tx, &mut m, target)?;
                }
                unreached = rotation::unreached(tx, &target, &r)?;
                rot = Some(r);
            }
        }
    }
    if selfr {
        m.unchecked();
    }
    let c = Engine::commit_tx(tx, m)?;
    if let Some(r) = &rot {
        rotation::record(tx, target, r)?;
    }
    done.add(c);
    if let Some(c) = c {
        // a removal of another actor G's edge (explicit, or a self-removal by an admin of G,
        // lowering too) leaves G's closure bodies
        let gone_from = if new_role.is_none() || selfr { &removing[..] } else { removing.get(1..).unwrap_or_default() };
        lowered_deliveries(tx, who, target, c, rot.as_ref(), &unreached, &removing, gone_from, &mut done)?;
    }
    if rot.is_some() {
        rotation::recover_reached(tx, who, target, &removing, &mut done)?;
    }
    // the leaver drops what it lost once the removal is placed (`Done::drop_lost`): it must
    // still seal the removal under the labels it leaves
    done.drop_lost |= selfr;
    Ok(done)
}

/// The deliveries of role commit `c` by `who` lowering edges on `target` (spec/permissions.md §2,
/// §3): the inbox copy to each holder in `lowered`, the rotation `rot` by inbox to `unreached`,
/// placement before any other upload under every label the first lowered party could read (the
/// target and what its roles open), and, for each actor in `gone_from` (its edge removed, not the
/// author's own), under the labels holding it: it leaves its closure bodies (it reads the target
/// no more) and the target may have left it already (an unplace), so its holders learn it there
/// (its inbox reaches only its admins).
#[allow(clippy::too_many_arguments)]
fn lowered_deliveries(tx: &mut Tx<'_>, who: Tid, target: Tid, c: CommitId, rot: Option<&osis_keys::Rotation>, unreached: &[Tid], lowered: &[Tid], gone_from: &[Tid], done: &mut Done) -> Result<()> {
    let ts = now_ts(tx.core);
    for x in lowered {
        done.deliveries.extend(deliver_parts(tx, *x, c, &[target], Parts::Edge, Vec::new())?);
    }
    done.deliveries.extend(rotation::deliver_rotation(tx, target, Some(c), unreached)?);
    let graph = osis_keys::PermGraph { timeline: tx.core.timelines.get(&target).ok_or(Error::UnknownThing(target))?, at: At::now(ts) };
    let mut under: Vec<Tid> = lowered.first().map(|h| osis_keys::reached(&graph, target, *h).into_iter().collect()).unwrap_or_default();
    if let Err(i) = under.binary_search(&target) {
        under.insert(i, target);
    }
    done.deliveries.push(super::owe(tx, Delivery::First { commits: rotation::placed_with(c, rot.map(|r| &r.names)), under })?);
    for x in gone_from {
        if *x != who && !tx.core.is_key_actor(x) {
            done.deliveries.push(super::owe(tx, Delivery::Removal { commit: c, under: *x })?);
        }
    }
    Ok(())
}

/// The edges on `target` that `who` (this node, or a key actor it signs as) may finalize now
/// (spec/permissions.md §2), each with whether its finalize says retain: past their `until` by
/// this node's clock (an edge the timeline holds with every applied write in effect), of a role
/// at most `who`'s own there, `who` holding write; not its own (that is a self-removal).
pub(crate) fn finalizable(core: &crate::engine::Core, who: &Tid, target: &Tid) -> Vec<(Tid, PermEdge, bool)> {
    let ts = now_ts(core);
    let Some(tl) = core.timelines.get(target) else { return Vec::new() };
    let role = tl.role(who, target, At::now(ts));
    if role < Some(Role::Write) {
        return Vec::new();
    }
    let ended: Vec<(Tid, PermEdge)> = tl.edges_at(None).holders(target).filter(|(m, e)| *m != who && e.until.is_some() && !e.says_retain() && !e.alive_at(Some(ts)) && Some(e.role) <= role).map(|(m, e)| (*m, *e)).collect();
    if ended.is_empty() {
        return Vec::new();
    }
    // it says what the expiry would (spec/permissions.md §3, Retain): the default at its key
    let ends = tl.ended(target, ts);
    ended
        .into_iter()
        .map(|(m, e)| {
            let keep = match ends.get(&m).map(|x| x.0) {
                Some(osis_perm::EdgeEnd::Until(key)) => crate::apply::validity::retain_in_force(core, target, &key),
                _ => false,
            };
            (m, e, keep)
        })
        .collect()
}

/// A finalize by `who` of the edges `ended` on `target` (`finalizable`; spec/permissions.md §2):
/// their removal with no frontier, each saying retain or erase as its expiry would, and the
/// rotation of the roles they held that `who` may rotate, in one role commit, or alone while Seal
/// waits (its rotation then stays due). Not written when `who` may not supersede such a role
/// (`rotation::may_supersede`: it waits for the secret, spec/crypto.md §4): false then. The cascade below `target`
/// is the caller's (`rotation::ensure_rotated`).
pub(crate) fn finalize_in(tx: &mut Tx<'_>, who: Tid, target: Tid, ended: &[(Tid, PermEdge, bool)], done: &mut Done) -> Result<bool> {
    let mut m = Mutation::new();
    if who != tx.core.id.tid() {
        m.sign_as(who);
    }
    let mut left: BTreeSet<Role> = BTreeSet::new();
    let mut pending = Vec::new();
    for (x, e, keep) in ended {
        removal(tx, &mut m, target, *x)?;
        if *keep {
            put_edge(&mut m, target, *x, &Edge { role: Role::Read, until: Some(WallMs(0)), invite: None, tied: None })?;
        }
        if let Some(dep) = Departure::of_change(*x, Some(e.role), None) {
            left.extend(ROLES.into_iter().filter(|r| *r <= e.role));
            pending.push(dep);
        }
    }
    let mut rot = None;
    let mut unreached = Vec::new();
    let may = rotation::may_rotate(tx.core, &who, &target);
    let roles: BTreeSet<Role> = left.into_iter().filter(|r| may.contains(r)).collect();
    if !roles.is_empty() && tx.core.has_own_secrets(&target) {
        let after: Vec<(Tid, Tid, Option<PermEdge>)> = ended.iter().map(|(x, _, _)| (*x, target, None)).collect();
        let Some(held) = tx.core.epochs(&target).filter(|h| roles.iter().all(|r| rotation::may_supersede(tx.core, h, *r, &target, &after))) else { return Ok(false) };
        let skip: Vec<(Tid, Option<Role>)> = ended.iter().map(|(x, _, _)| (*x, None)).collect();
        // while Seal waits the finalize goes alone (spec/permissions.md §3)
        if let Some(holders) = rotation::recipients(tx, &who, &target, &skip)? {
            let r = rotation::rotation_into(tx, &mut m, target, &roles, &held, &holders, !pending.is_empty())?;
            if rotation::refreshes_deposit(tx.core, &who, &target, &roles) {
                rotation::fresh_deposit_seed(tx, &mut m, target)?;
            }
            unreached = rotation::unreached(tx, &target, &r)?;
            rot = Some(r);
        }
    }
    // a writer's write on `roles.0`: judged by the finalize authority, not an admin's
    m.unchecked();
    let c = Engine::commit_tx(tx, m)?;
    if let Some(r) = &rot {
        rotation::record(tx, target, r)?;
    }
    done.add(c);
    if let Some(c) = c {
        let removed: Vec<Tid> = ended.iter().map(|x| x.0).collect();
        lowered_deliveries(tx, who, target, c, rot.as_ref(), &unreached, &removed, &removed, done)?;
    }
    Ok(true)
}

impl Engine {
    /// Grants `holder` the edge `edge` on `target`, or raises its edge (spec/permissions.md §2),
    /// as an admin of the target or by invite. Gives the target (and a plain holder) secrets of
    /// their own first where needed. Delivers the grant to the holder's inbox (a node: direct).
    pub fn grant(&mut self, target: &Tid, holder: &Tid, edge: &Edge) -> Result<Done> {
        let (t, m, e) = (*target, *holder, edge.clone());
        self.run(|tx| grant_in(tx, None, t, m, &e, false))
    }

    /// `grant`, signed as a held key actor (a recovery key, a link key).
    pub fn grant_as(&mut self, signer: &Tid, target: &Tid, holder: &Tid, edge: &Edge) -> Result<Done> {
        let (s, t, m, e) = (*signer, *target, *holder, edge.clone());
        self.run(|tx| grant_in(tx, Some(s), t, m, &e, false))
    }

    /// The role `holder` lost on `target` with no explicit write on that edge since: an edge past
    /// its `until` (finalized or not), or one its holder removed. The next explicit write audits
    /// against it (spec/permissions.md §5.1 step 4), so one below it needs the frontier of a demotion.
    pub fn lost_role(&self, target: &Tid, holder: &Tid) -> Option<Role> {
        let tl = self.core.timelines.get(target)?;
        rotation::key_role(tl.edges_at(None).get(holder, target)).max(tl.role_lowered_unaudited(holder, target))
    }

    /// The things whose every label the caller should sync before stamping a demotion of
    /// `holder` on `target` (spec/permissions.md §5.3): every thing the demoted authority gave
    /// write or role authority on.
    pub fn presync_scope(&self, target: &Tid, holder: &Tid, new: Option<&Edge>) -> BTreeSet<Tid> {
        let Some(tl) = self.core.timelines.get(target) else { return BTreeSet::new() };
        // as if every held write had been received
        let ops = vec![osis_perm::EdgeOp { target: *target, holder: *holder, edge: new.map(perm_edge) }];
        let scope = tl.demotion_scope(self.demotion_probe(self.tid(), ops, tl.all_held()));
        scope.roles.values().chain(scope.content.values()).flatten().copied().collect()
    }

    /// A demotion by `who` with edge writes `ops` and frontier `f`, as `Timeline::demotion_scope`
    /// takes it: at the `ts` the next commit gets (after every held one); its ID is not known yet.
    fn demotion_probe(&self, who: Tid, mut ops: Vec<osis_perm::EdgeOp>, f: osis_perm::Frontier) -> osis_perm::RoleCommit {
        ops.sort_by_key(|o| (o.target, o.holder));
        let id = CommitId([0xff; 32]);
        osis_perm::RoleCommit { id, ts: self.core.hlc.peek(), author: who, actor: who, frontier: Some(std::sync::Arc::new(f)), ops }
    }

    /// Lowers or removes `d.holder`'s edge on `target` (spec/permissions.md §2, §3, §5): an
    /// explicit demotion by an admin (with the frontier of what this node had received of the
    /// demoted nodes, `d.presync` deciding whether to stamp without a pre-sync), or a
    /// self-removal. The rotation of the roles the holder left goes in the same commit (while Seal
    /// waits, none: it stays due).
    pub fn demote(&mut self, target: &Tid, d: &Demotion) -> Result<Done> {
        self.demote_signed(None, target, d)
    }

    /// `demote`, signed as a held key actor (a recovery key removing a stolen node, a sharer
    /// finalizing a link is the node itself).
    pub fn demote_as(&mut self, signer: &Tid, target: &Tid, d: &Demotion) -> Result<Done> {
        self.demote_signed(Some(*signer), target, d)
    }

    fn demote_signed(&mut self, signer: Option<Tid>, target: &Tid, d: &Demotion) -> Result<Done> {
        self.remove_signed(signer, target, d, &[])
    }

    /// `demote_signed` that also removes `others` in the same commit under one rotation
    /// (spec/commits.md §2); `d.new` must then be `None`.
    pub(crate) fn remove_signed(&mut self, signer: Option<Tid>, target: &Tid, d: &Demotion, others: &[Tid]) -> Result<Done> {
        let who = signer.unwrap_or(self.tid());
        let t = *target;
        let as_of = self.now();
        let frontier = match self.core.timelines.get(&t) {
            Some(tl) => {
                // this node's own chain counts only as listed: its chain certificates for the
                // target, by commit ID (spec/permissions.md §5.1, §4)
                let own = tl.certificates(&who, &t).commits;
                let new = written(&self.core, &t, tl.edges_at(None).get(&d.holder, &t), d)?;
                let ops: Vec<osis_perm::EdgeOp> = std::iter::once((d.holder, new.as_ref().map(perm_edge))).chain(others.iter().map(|x| (*x, None))).map(|(holder, edge)| osis_perm::EdgeOp { target: t, holder, edge }).collect();
                // what this node received on the aspects the demotion puts in question with
                // that frontier (`Timeline::demotion_scope`), from what it puts in question
                // with every held write received, until the scope stops growing
                let mut scope = tl.demotion_scope(self.demotion_probe(who, ops.clone(), tl.all_held()));
                loop {
                    let (mut f, requests) = self.frontier_and_requests(&scope, as_of)?;
                    f.commits.extend(own.iter().copied());
                    let requests: Vec<CommitId> = requests.into_iter().filter(|c| !own.contains(c)).collect();
                    crate::apply::receipt::fit_requests(&mut f, &requests, self.core.list_bound);
                    let pf = osis_perm::Frontier { commits: f.commits.clone() };
                    let probe = self.demotion_probe(who, ops.clone(), pf);
                    let s = self.core.timelines.get(&t).map(|tl| tl.demotion_scope(probe)).unwrap_or_default();
                    if scope.covers(&s) {
                        break Some(osis_schema::Codec::to_value(&f));
                    }
                    scope.join(s);
                }
            }
            None => None,
        };
        let d = d.clone();
        self.run(|tx| demote_in(tx, signer, t, &d, others, frontier))
    }

    /// Opens an inbox blob addressed to an actor this node holds the read secret of
    /// (spec/sync.md §3), applies the role commit it carries and returns the things it
    /// names with their labels, plus the certificate copy to place under that actor's home
    /// label (a grant this node accepts).
    pub fn accept_inbox(&mut self, blob: &[u8]) -> Result<(Vec<InboxThing>, Done)> {
        let mut candidates: Vec<(Tid, osis_crypto::KemSecret)> = Vec::new();
        for (a, e) in self.core.ix.secrets.iter() {
            for (_, s) in e.role(Role::Read).held_newest_first() {
                candidates.push((*a, osis_crypto::role_kem(s)));
            }
        }
        let mut opened = None;
        for (a, kem) in &candidates {
            if let Ok((_, p)) = open_inbox_blob(blob, a, kem) {
                opened = Some((*a, p));
                break;
            }
        }
        let (a, p) = opened.ok_or(Error::Misuse("no held read secret opens this inbox blob"))?;
        let (bytes, things, _) = p.split();
        let id = CommitBlob::decode(&bytes)?.id();
        self.ingest(&bytes, Vec::new())?;
        self.note_delete_hints(id, &things)?;
        let mut done = Done::default();
        if self.core.ix.commits.contains_key(&id) {
            done.deliveries.push(self.run(|tx| super::owe(tx, Delivery::Certificate { commits: vec![id], under: a }))?);
        }
        Ok((things, done))
    }
}

