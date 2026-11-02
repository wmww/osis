//! A node acting as an actor it administers, confined to that actor's rights (notes/client-port.md
//! §3): receivers judge a commit by its author node's rights alone (spec/permissions.md §1; the
//! header's actor is attribution), and this node's are usually wider than the actor's, so only
//! this node can hold it to them. `Mutation::confine` asks for that check before a write;
//! `readable_by`, `actor_role` and `revert_as` are the same rule for reads and reverts.

use super::write::{check_authority, check_authority_with, check_role_with, role_with, Mutation, Records, Resolved};
use super::{Engine, Tx};
use crate::error::{Error, Result};
use crate::ephemeral::{gains, Reverted};
use crate::events::ChangeId;
use crate::flows::Done;
use crate::rotation;
use osis_base::{Ak, Role, Tid, Ts, Value};
use osis_crdt::Op;
use osis_perm::At;
use osis_schema::core_types::GROUP;
use osis_schema::AspectKey;
use std::collections::BTreeSet;

impl Engine {
    fn acting_ts(&self) -> Ts {
        Ts::make(self.now(), 0).unwrap_or_default()
    }

    /// The effective role of `actor` on `t` now; a thing ephemeral here takes its owner's
    /// (spec/permissions.md §1).
    pub fn actor_role(&self, actor: &Tid, t: &Tid) -> Option<Role> {
        let records: Records<'_> = &|x| self.ephemeral_thing(x).map(|e| &e.record);
        role_with(&self.core, *actor, records, t, self.acting_ts())
    }

    /// Whether a client of this node, `actor`, reads `t` here now: `entitled`, and this node's copy is current.
    pub fn readable_by(&self, actor: &Tid, t: &Tid) -> bool {
        // in a group read at another node or still catching up on its way home, or held only
        // through groups that stopped syncing here: stale here, and this node would serve it to a
        // client as if current (notes/client-port.md §6)
        if !self.core.receipts_only.is_empty() || !self.core.routed_away.is_empty() {
            // `placed.0~` too: as the owner's calls route (`Osis::route`)
            let gs = self.groups_of(t);
            if self.core.routed_away.contains(t) || gs.iter().any(|g| self.core.routed_away.contains(g)) {
                return false;
            }
            let out = |g: &Tid| self.core.receipts_only.contains(g);
            if (out(t) || gs.iter().any(out)) && !gs.iter().chain([t]).any(|g| !out(g) && self.core.ix.labeled.contains(g)) {
                return false;
            }
        }
        self.entitled(actor, t)
    }

    /// The permission model's entitlement (spec/sync.md §3); a thing ephemeral here by its owner
    /// chain. False for what this node does not know.
    pub fn entitled(&self, actor: &Tid, t: &Tid) -> bool {
        if self.ephemeral_thing(t).is_some() {
            return self.actor_role(actor, t) >= Some(Role::Read);
        }
        self.core.may_read(actor, t)
    }

    /// Fails `Permission` unless `actor` itself may do all of a confined `m`: every aspect's write,
    /// every creation (write on the owner), every thing it persists or frees. A purge names
    /// history whose right (spec/permissions.md §8) is judged at receivers by this node's rights:
    /// it needs admin, the one role that holds every such right. `group.0` gains only what it may
    /// read or this batch creates (`UnknownThing`, as for a tid nobody knows), by whatever op: else
    /// the answer would tell a hidden thing from an unknown one and its name would reach the
    /// group's readers (its data would not: spec/sync.md §3 entitlement judges the group's actor).
    pub(crate) fn check_confined(&self, m: &Mutation, actor: &Tid) -> Result<()> {
        let ts = self.acting_ts();
        let creates = &m.creates;
        let records: Records<'_> = &|t| creates.get(t).or_else(|| self.ephemeral_thing(t).map(|e| &e.record));
        let created = "created.0";
        for (t, ak) in m.aspects.keys() {
            check_authority_with(&self.core, *actor, records, t, ak.as_str(), ts)?;
        }
        for t in m.creates.keys().chain(&m.persist).chain(&m.free) {
            check_authority_with(&self.core, *actor, records, t, created, ts)?;
        }
        for p in &m.purge {
            check_role_with(&self.core, *actor, records, p.tid(), p.ak().as_str(), Role::Admin, ts)?;
        }
        for ((_, ak), a) in &m.aspects {
            if ak.as_str() != GROUP.ak() {
                continue;
            }
            for op in &a.ops {
                let added: &[Value] = match &op.op {
                    Op::Set(v) | Op::Replace(v) | Op::Put(v) | Op::Add(v) | Op::Edit { new: v, .. } => std::slice::from_ref(v),
                    Op::Insert { items, .. } | Op::InsertAfter { items, .. } => items,
                    _ => &[],
                };
                let hidden = |t: &Tid| !m.creates.contains_key(t) && !self.readable_by(actor, t);
                if let Some(t) = added.iter().find_map(|v| find_tid(v, &hidden)) {
                    return Err(Error::UnknownThing(t));
                }
            }
        }
        Ok(())
    }

    /// Reverts change `id` for `actor`, held to its rights: on everything the change touched,
    /// whether or not the revert still writes it (the answer tells nothing of what it may not
    /// read), and on every write the revert really makes (`undo_in`, `revert_inner`). An error
    /// names only what it reads. One bit stays: a deleted thing placed in a group the actor may
    /// not write is refused (issues/revert-tells-hidden-placement.md).
    pub fn revert_as(&mut self, id: ChangeId, actor: Tid) -> Result<Reverted> {
        let mut touched: BTreeSet<(Tid, Ak)> = self.ephemeral_log().into_iter().filter(|l| l.id == id).flat_map(|l| l.aspects).collect();
        if let ChangeId::Commit(c) = id
            && let Some(h) = self.header(&c)
        {
            touched.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
        }
        let shown = touched.iter().map(|(t, _)| *t).find(|t| self.readable_by(&actor, t));
        let ts = self.acting_ts();
        let records: Records<'_> = &|t| self.ephemeral_thing(t).map(|e| &e.record);
        let check = touched.iter().try_for_each(|(t, ak)| check_authority_with(&self.core, actor, records, t, ak.as_str(), ts));
        let r = check.and_then(|()| self.revert_inner(id, actor, true));
        r.map_err(|e| match (e, shown) {
            (Error::Permission { tid }, Some(s)) if !self.readable_by(&actor, &tid) => Error::Permission { tid: s },
            (e, _) => e,
        })
    }

    /// The things `actor` holds a current edge on.
    pub fn grants_of(&self, actor: &Tid) -> Vec<Tid> {
        let Some(tl) = self.core.timelines.get(actor) else { return Vec::new() };
        let ts = self.acting_ts();
        let edges = tl.edges_at(At::now(ts).point);
        let mut out: Vec<Tid> = edges.targets(actor).copied().collect();
        out.retain(|t| self.roster(t).contains_key(actor));
        out
    }

    /// Mints an actor owned by `owner` with secrets of its own (and `keys.0`), as a link's K is
    /// minted, and commits what `also` builds for it, all in one transaction: a crash or a
    /// failure leaves both or neither (`flows::links` shares the shape).
    pub fn mint_actor(&mut self, owner: &Tid, also: impl FnOnce(Tid) -> Result<Mutation>) -> Result<(Tid, Done)> {
        let owner = *owner;
        self.run(|tx| {
            let mut done = Done::default();
            let mut m = Mutation::new();
            let a = m.create(crate::identity::thing_record(owner, None, &mut *tx.rng));
            done.add(Engine::commit_tx(tx, m)?);
            rotation::own_secrets(tx, a, &mut done)?;
            done.add(Engine::commit_tx(tx, also(a)?)?);
            Ok((a, done))
        })
    }
}

/// A confined revert's durable writes, as `undo_in` is about to make them: `actor`'s rights on
/// each, and `group.0` gains only what it may read (a revert of an unplace puts a thing back).
pub(crate) fn check_undo(tx: &mut Tx<'_>, actor: Tid, deltas: &[Resolved], ts: Ts) -> Result<()> {
    for d in deltas {
        check_authority(tx.core, actor, &Default::default(), &d.tid, d.ak.as_str(), ts)?;
        if d.ak.as_str() == GROUP.ak() {
            let gained = gains(tx.state(&d.tid, &d.ak)?, &d.fragment);
            if let Some(t) = gained.iter().find(|t| !tx.core.may_read(&actor, t)) {
                return Err(Error::Permission { tid: *t });
            }
        }
    }
    Ok(())
}

/// The first tid inside `v` that `f` holds of.
fn find_tid(v: &Value, f: &dyn Fn(&Tid) -> bool) -> Option<Tid> {
    match v {
        Value::Tid(t) => f(t).then_some(*t),
        Value::List(l) => l.iter().find_map(|x| find_tid(x, f)),
        Value::Set(s) => s.iter().find_map(|x| find_tid(x, f)),
        Value::Map(m) => m.iter().find_map(|(k, x)| find_tid(k, f).or_else(|| find_tid(x, f))),
        Value::Enum(_, Some(p)) => find_tid(p, f),
        _ => None,
    }
}
