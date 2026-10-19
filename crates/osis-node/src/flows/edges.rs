//! Edge writes (spec/permissions.md §2, §3, §5.3): grants with the grantee's boxes, changes,
//! removals and demotions carrying the target's rotation, invite grants and self-removals,
//! the pre-sync choice and the receipt-record frontier, inbox delivery and acceptance
//! (spec/sync.md §3, spec/crypto.md §5).

use super::{Delivery, Done, inbox_of, label_for, now_ts, put_edge, put_secrets, recipient, remove_edge, secrets_in};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::rotation;
use crate::Mutation;
use osis_commit::CommitBlob;
use osis_core::{CommitId, Role, Tid, WallMs};
use osis_keys::{Departure, ROLES, box_member, roles_up_to};
use osis_label::{InboxPayload, InboxThing, open_inbox_blob, seal_inbox_blob};
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
    /// demoted member under those labels are lost) or fail.
    Unsynced { proceed: bool },
    /// An explicitly backdated revoke: the frontier as of this time; no pre-sync.
    Backdated(WallMs),
}

/// A role-lowering edge write: `member`'s new edge on the target (`None` removes it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demotion {
    pub member: Tid,
    pub new: Option<Edge>,
    pub presync: PreSync,
}

fn perm_edge(e: &Edge) -> PermEdge {
    PermEdge { role: e.role, until: e.until, invite: e.invite, since: None }
}

/// Which parts of a commit an inbox blob carries.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Parts {
    /// Every part (a grant: the edge and the grantee's boxes; a re-seal).
    All,
    /// The `/members` parts only (a removal: the rotation's boxes are not about the member).
    Edge,
}

/// The deliveries of a membership commit about `member` (spec/permissions.md §2): an inbox
/// blob for an actor, the commit itself over a direct connection for a node, nothing for a
/// recovery or link key (it reads its label by static entry).
pub(crate) fn deliver_to(tx: &mut Tx<'_>, member: Tid, c: CommitId, things: &[Tid]) -> Result<Vec<Delivery>> {
    deliver_parts(tx, member, c, things, Parts::All)
}

pub(crate) fn deliver_parts(tx: &mut Tx<'_>, member: Tid, c: CommitId, things: &[Tid], parts: Parts) -> Result<Vec<Delivery>> {
    if tx.core.is_key_actor(&member) {
        let is_node = super::super::flows::is_node(tx, &member)?;
        return Ok(if is_node { vec![Delivery::Direct { to: member, commits: vec![c] }] } else { Vec::new() });
    }
    let Some((_, inbox)) = inbox_of(tx, &member)? else { return Ok(Vec::new()) };
    // sealed to the member's newest read keyset (its own, else the inbox actor's)
    let mut to = member;
    let mut kem = None;
    let mut cur = member;
    for _ in 0..64 {
        if let Some(ks) = super::Core::keys_in(tx, &cur)?.and_then(|k| k.read) {
            let ct::KemKey::X25519MlKem768(b) = &ks.kem_key;
            kem = Some(osis_crypto::KemPublicKey::from_slice(b)?);
            to = cur;
            break;
        }
        match tx.core.owner(&cur) {
            Some(o) => cur = o,
            None => break,
        }
    }
    let Some(kem) = kem else { return Ok(Vec::new()) };
    let mut blob = tx.get_commit(&c)?.ok_or(Error::UnknownCommit(c))?;
    if parts == Parts::Edge {
        let keep: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, a)| a.ak.as_str() == "/members").map(|(i, _)| i).collect();
        blob.parts.retain(|p| keep.contains(&p.ai));
    }
    let commit = osis_core::decode(&blob.encode(), &osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: osis_core::format::MAX_BLOB })
        .map_err(|_| Error::Corrupt("commit blob"))?;
    let mut ts: Vec<InboxThing> = Vec::new();
    let mut seen = BTreeSet::new();
    for t in things {
        if seen.insert(*t)
            && let Some((label, servers)) = label_for(tx, t)?
        {
            ts.push(InboxThing { tid: *t, label, servers });
        }
    }
    ts.sort_by_key(|t| t.tid);
    let payload = InboxPayload { commit, things: ts };
    let now = tx.now();
    let blob = seal_inbox_blob(&to, &kem, &payload, now, &mut *tx.rng)?;
    Ok(vec![Delivery::Inbox { to, inbox, blob }])
}

/// A grant or a raise of `member`'s edge on `target` by `who` (this node, or a held key actor
/// signing), with the grantee's boxes for every granted role at each current epoch
/// (spec/crypto.md §4). An admin's grant, or an invite grant (spec/permissions.md §2) where
/// `who`'s effective invite allows it and the member has no current edge. `leave`: the signer's
/// own edge removed in the same commit (a single-use redemption, spec/permissions.md §9).
pub(crate) fn grant_in(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, member: Tid, edge: &Edge, leave: bool) -> Result<Done> {
    let who = signer.unwrap_or(tx.core.id.tid());
    if edge.invite.is_some_and(|i| i > edge.role) {
        return Err(Error::Misuse("invite above the edge's role"));
    }
    let role = tx.core.role_now(&who, &target);
    let admin = role == Some(Role::Admin);
    // a non-writer of the target's label deposits its invite grant (spec/sync.md §5)
    let deposit = role < Some(Role::Write);
    let ts = now_ts(tx.core);
    let old = tx.core.timelines.get(&target).and_then(|tl| tl.roster(&target, At::now(ts)).get(&member).copied());
    let invite = tx.core.timelines.get(&target).and_then(|tl| tl.invite(&who, &target, At::now(ts)));
    if !admin {
        let ok = old.is_none() && invite.is_some_and(|i| edge.role <= i && edge.invite.is_none_or(|x| x <= i));
        if !ok {
            return Err(Error::Permission { tid: target });
        }
    }
    let mut done = Done::default();
    // a thing is made a member only with secrets of its own; a target gets them on its first
    // non-owner member (spec/permissions.md §3)
    if !tx.core.is_key_actor(&member) && !tx.core.has_own_secrets(&member) {
        rotation::own_secrets(tx, member, &mut done)?;
    }
    if !tx.core.has_own_secrets(&target) && !tx.core.is_key_actor(&target) {
        if !admin {
            return Err(Error::Permission { tid: target });
        }
        rotation::own_secrets(tx, target, &mut done)?;
    }
    // boxing is encrypting under: rotate first where a known departure is uncovered
    let roles = roles_up_to(edge.role);
    rotation::require_covered(tx, who, target, &roles, &mut done)?;
    let epochs = tx.core.epochs(&target).ok_or(Error::Misuse("no secrets held for the target"))?;
    let secrets = secrets_in(tx, &target)?;
    let rcpt = recipient(tx, member, edge.role)?;
    let boxes = box_member(&target, &epochs, &secrets, &rcpt, &roles, &mut *tx.rng)?.ok_or(Error::Misuse("the member's keyset is unknown"))?;
    let mut m = Mutation::new();
    if old.is_some() {
        remove_edge(&mut m, target, member)?;
    }
    put_edge(&mut m, target, member, edge)?;
    if leave {
        remove_edge(&mut m, target, who)?;
    }
    put_secrets(&mut m, target, &boxes)?;
    if let Some(s) = signer {
        m.sign_as(s);
    }
    if !admin {
        m.unchecked();
    }
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        if leave {
            done.departed.push(target);
        }
        done.deliveries.extend(deliver_to(tx, member, c, &[target])?);
        if deposit {
            done.deliveries.push(Delivery::Deposit { commit: c, under: target });
        }
    }
    Ok(done)
}

/// The dots of `member`'s `/members` entries on `target` this node has seen, live or dead.
fn entry_dots(tx: &Tx<'_>, target: &Tid, member: &Tid) -> Vec<osis_crdt::Dot> {
    tx.core.member_keys.iter().filter(|((t, _), (m, _))| t == target && m == member).map(|((_, d), _)| d.clone()).collect()
}

/// A removal or demotion (or a self-removal) of `d.member` on `target` by `who`: an explicit
/// demotion carries the frontier and the target's rotation of the roles the member left in the
/// same commit (spec/permissions.md §3), after the cascade on the target; a self-removal
/// carries neither (the next node that may rotate does), and the leaver drops what it lost. An
/// explicit removal of an absent edge resets its dead entries (spec/permissions.md §2). Then the
/// inbox copy to the member, and placement before any other upload under every label the
/// removed party could read.
pub(crate) fn demote_in(tx: &mut Tx<'_>, signer: Option<Tid>, target: Tid, d: &Demotion, frontier: Option<osis_core::Value>) -> Result<Done> {
    let who = signer.unwrap_or(tx.core.id.tid());
    let member = d.member;
    let ts = now_ts(tx.core);
    let tl = tx.core.timelines.get(&target).ok_or(Error::UnknownThing(target))?;
    let old = tl.edges_at(None).get(&member, &target).copied();
    let new_p = d.new.as_ref().map(perm_edge);
    if old.is_some() && !osis_perm::types::lowers(new_p.as_ref(), old.as_ref()) {
        return Err(Error::Misuse("not a lowering write (use grant)"));
    }
    let selfr = old.is_some() && crate::apply::validity::self_removal(tx.core, &who, &target, &member, ts);
    let admin = tx.core.role_now(&who, &target) == Some(Role::Admin);
    if !selfr && !admin {
        return Err(Error::Permission { tid: target });
    }
    if !selfr && let PreSync::Unsynced { proceed: false } = d.presync {
        return Err(Error::Misuse("labels not synced before a demotion; proceed to stamp anyway"));
    }
    let mut done = Done::default();
    let mut m = Mutation::new();
    match old {
        Some(_) => remove_edge(&mut m, target, member)?,
        None => {
            if d.new.is_some() {
                return Err(Error::Misuse("no edge to lower"));
            }
            let dots = entry_dots(tx, &target, &member);
            if dots.is_empty() {
                return Err(Error::Misuse("no edge of that member was ever seen"));
            }
            m.dead_resets.insert((target, super::ak("/members")?), dots);
        }
    }
    if let Some(n) = &d.new {
        put_edge(&mut m, target, member, n)?;
    }
    if !selfr && let Some(f) = frontier {
        m.frontier(f);
    }
    // an explicit demotion carries the target's rotation of the roles the member left
    let mut rot = None;
    let held_role = old.filter(|o| o.alive_at(Some(ts))).map(|o| o.role);
    if !selfr
        && let Some(dep) = Departure::of_change(member, held_role, d.new.as_ref().filter(|e| e.until.is_none_or(|u| u > ts.wall_ms())).map(|e| e.role))
        && tx.core.has_own_secrets(&target)
    {
        // boxing to the remaining members encrypts under their keysets: the cascade first
        rotation::ensure_rotated(tx, who, target, &mut Vec::new(), &mut done)?;
        let may = rotation::may_rotate(tx.core, &who, &target);
        let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r >= dep.from && Some(*r) <= held_role && may.contains(r)).collect();
        if !roles.is_empty() {
            let held = tx.core.epochs(&target).ok_or(Error::Misuse("no secrets held for the target"))?;
            let members = rotation::recipients(tx, &target, Some((member, d.new.as_ref().map(|e| e.role))))?;
            rot = Some(rotation::rotation_into(tx, &mut m, target, &roles, &held, &members)?);
        }
    }
    if let Some(s) = signer {
        m.sign_as(s);
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
        done.deliveries.extend(deliver_parts(tx, member, c, &[target], Parts::Edge)?);
        // every label the removed party could read: the target and what its roles open
        let graph = osis_keys::PermGraph { timeline: tx.core.timelines.get(&target).ok_or(Error::UnknownThing(target))?, at: At::now(ts), own_secrets: &|t: &Tid| tx.core.has_own_secrets(t) };
        let plan = osis_keys::plan_inside(&graph, target, ROLES.into_iter().collect(), Departure::member(member, Role::Read));
        let mut under: Vec<Tid> = plan.entries.keys().copied().collect();
        under.push(target);
        under.sort();
        under.dedup();
        done.deliveries.push(Delivery::First { commits: vec![c], under });
    }
    // the leaver drops what it lost once the removal is placed (`Done::drop_lost`): it must
    // still seal the removal under the labels it leaves
    done.drop_lost |= selfr;
    Ok(done)
}

impl Engine {
    /// Grants `member` the edge `edge` on `target`, or raises its edge (spec/permissions.md §2),
    /// as an admin of the target or by invite. Gives the target (and a plain member) secrets of
    /// their own first where needed. Delivers the grant to the member's inbox (a node: direct).
    pub fn grant(&mut self, target: &Tid, member: &Tid, edge: &Edge) -> Result<Done> {
        let (t, m, e) = (*target, *member, edge.clone());
        self.run(|tx| grant_in(tx, None, t, m, &e, false))
    }

    /// `grant`, signed as a held key actor (a recovery key, a link key).
    pub fn grant_as(&mut self, signer: &Tid, target: &Tid, member: &Tid, edge: &Edge) -> Result<Done> {
        let (s, t, m, e) = (*signer, *target, *member, edge.clone());
        self.run(|tx| grant_in(tx, Some(s), t, m, &e, false))
    }

    /// The things whose every label the caller should sync before stamping a demotion of
    /// `member` on `target` (spec/permissions.md §5.3): every thing the demoted authority gave
    /// write or membership authority on.
    pub fn presync_scope(&self, target: &Tid, member: &Tid, new: Option<&Edge>) -> BTreeSet<Tid> {
        let ts = now_ts(&self.core);
        let Some(tl) = self.core.timelines.get(target) else { return BTreeSet::new() };
        let scope = tl.demotion_scope(&self.tid(), member, target, new.map(perm_edge), ts);
        scope.membership.values().chain(scope.content.values()).flatten().copied().collect()
    }

    /// Lowers or removes `d.member`'s edge on `target` (spec/permissions.md §2, §3, §5): an
    /// explicit demotion by an admin (with the frontier of what this node had received of the
    /// demoted nodes, `d.presync` deciding whether to stamp without a pre-sync), or a
    /// self-removal. The rotation of the roles the member left goes in the same commit.
    pub fn demote(&mut self, target: &Tid, d: &Demotion) -> Result<Done> {
        self.demote_signed(None, target, d)
    }

    /// `demote`, signed as a held key actor (a recovery key removing a stolen device, a sharer
    /// finalizing a link is the node itself).
    pub fn demote_as(&mut self, signer: &Tid, target: &Tid, d: &Demotion) -> Result<Done> {
        self.demote_signed(Some(*signer), target, d)
    }

    fn demote_signed(&mut self, signer: Option<Tid>, target: &Tid, d: &Demotion) -> Result<Done> {
        let who = signer.unwrap_or(self.tid());
        let t = *target;
        let ts = now_ts(&self.core);
        let as_of = match d.presync {
            PreSync::Backdated(w) => w,
            _ => self.now(),
        };
        let frontier = match self.core.timelines.get(&t) {
            Some(tl) => {
                let scope = match tl.edges_at(None).get(&d.member, &t) {
                    Some(_) => tl.demotion_scope(&who, &d.member, &t, d.new.as_ref().map(perm_edge), ts),
                    // an absent edge (a used single-use link): audit the member's own writes on
                    // the target as if it still held its role (spec/permissions.md §5.1)
                    None => {
                        let things: std::collections::BTreeSet<Tid> = [t].into_iter().collect();
                        osis_perm::DemotionScope { membership: [(d.member, things.clone())].into_iter().collect(), content: [(d.member, things)].into_iter().collect() }
                    }
                };
                Some(osis_schema::Codec::to_value(&self.frontier(&scope, as_of)?))
            }
            None => None,
        };
        let d = d.clone();
        self.run(|tx| demote_in(tx, signer, t, &d, frontier))
    }

    /// Opens an inbox blob addressed to an actor this node holds the read secret of
    /// (spec/sync.md §3), applies the membership commit it carries and returns the things it
    /// names with their labels, plus the certificate copy to place under that actor's home
    /// label (a grant this device accepts).
    pub fn accept_inbox(&mut self, blob: &[u8]) -> Result<(Vec<InboxThing>, Done)> {
        let mut candidates: Vec<(Tid, osis_crypto::KemSecret)> = Vec::new();
        for (a, e) in &self.core.secrets {
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
        let bytes = osis_core::encode(&p.commit);
        let id = CommitBlob::decode(&bytes)?.id();
        self.ingest(&bytes, Vec::new())?;
        let mut done = Done::default();
        if self.core.commits.contains_key(&id) {
            done.deliveries.push(Delivery::Certificate { commits: vec![id], under: a });
        }
        Ok((p.things, done))
    }
}
