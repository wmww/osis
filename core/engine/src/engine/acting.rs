//! A node acting as an actor it administers, confined to that actor's rights (notes/client-port.md
//! §3): receivers judge a commit by its author node's rights alone (spec/permissions.md §1; the
//! header's actor is attribution), and this node's are usually wider than the actor's, so only
//! this node can hold it to them. `Mutation::confine` asks for that check before a write;
//! `readable_by`, `actor_role` and `check_revert_as` are the same rule for reads and reverts.

use super::write::{check_authority_with, check_role_with, role_with, Mutation, Records};
use super::Engine;
use crate::error::{Error, Result};
use crate::events::ChangeId;
use crate::flows::Done;
use crate::rotation;
use osis_base::{Ak, Role, Tid, Ts, Value};
use osis_crdt::Op;
use osis_perm::At;
use osis_schema::core_types::{CREATED, GROUP, is_role_class};
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

    /// Whether `actor` may read `t` now: the permission model's entitlement (spec/sync.md §3); a
    /// thing ephemeral here by its owner chain. False for what this node does not know.
    pub fn readable_by(&self, actor: &Tid, t: &Tid) -> bool {
        if self.ephemeral_thing(t).is_some() {
            return self.actor_role(actor, t) >= Some(Role::Read);
        }
        self.core.may_read(actor, t)
    }

    /// Fails `Permission` unless `actor` itself may do all of a confined `m`: every aspect's write,
    /// every creation (write on the owner), every thing it persists or frees. A purge names
    /// history whose right (spec/permissions.md §8) is judged at receivers by this node's rights:
    /// it needs admin, the one role that holds every such right. `group.0` gains only what it may
    /// read or this batch creates (`UnknownThing`, as for a tid nobody knows), by whatever op: a
    /// placement carries the thing's data under the group's labels.
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
                    Op::Insert { items, .. } => items,
                    _ => &[],
                };
                let mut bad = None;
                added.iter().for_each(|v| each_tid(v, &mut |t| {
                    if !m.creates.contains_key(t) && !self.readable_by(actor, t) {
                        bad = Some(*t);
                    }
                }));
                if let Some(t) = bad {
                    return Err(Error::UnknownThing(t));
                }
            }
        }
        Ok(())
    }

    /// What reverting change `id` writes: the aspects it touched; for a thing it created, which the
    /// revert deletes (`undo::unmake_ops`), every held aspect and its placements in every group
    /// this node may write. Things it saved as drafts are not deleted; they count anyway.
    fn revert_writes(&mut self, id: ChangeId) -> Result<BTreeSet<(Tid, Ak)>> {
        let mut out: BTreeSet<(Tid, Ak)> = self.ephemeral_log().into_iter().filter(|l| l.id == id).flat_map(|l| l.aspects).collect();
        if let ChangeId::Commit(c) = id
            && let Some(h) = self.header(&c)
        {
            out.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
        }
        let made: Vec<Tid> = out.iter().filter(|(_, a)| a.as_str() == CREATED.ak()).map(|(t, _)| *t).collect();
        let group = Ak::new(GROUP.ak()).map_err(|_| Error::Misuse("ak"))?;
        for t in made {
            out.extend(self.aspects(&t)?.into_iter().filter(|a| a.as_str() != CREATED.ak() && !is_role_class(a.as_str())).map(|a| (t, a)));
            let (items, subs) = self.listed_in(&t);
            out.extend(items.into_iter().chain(subs).filter(|g| *g != t && self.role_on(g) >= Some(Role::Write)).map(|g| (g, group.clone())));
        }
        Ok(out)
    }

    /// Fails `Permission` unless `actor` may make every write reverting change `id` makes; the
    /// error names only what it may read.
    pub fn check_revert_as(&mut self, actor: &Tid, id: ChangeId) -> Result<()> {
        let writes = self.revert_writes(id)?;
        let ts = self.acting_ts();
        let records: Records<'_> = &|t| self.ephemeral_thing(t).map(|e| &e.record);
        let shown = writes.iter().map(|(t, _)| *t).find(|t| self.readable_by(actor, t));
        for (t, ak) in &writes {
            check_authority_with(&self.core, *actor, records, t, ak.as_str(), ts).map_err(|e| match shown {
                Some(tid) if !self.readable_by(actor, t) => Error::Permission { tid },
                _ => e,
            })?;
        }
        Ok(())
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

/// Calls `f` with every tid inside `v`.
fn each_tid(v: &Value, f: &mut dyn FnMut(&Tid)) {
    match v {
        Value::Tid(t) => f(t),
        Value::List(l) => l.iter().for_each(|x| each_tid(x, f)),
        Value::Set(s) => s.iter().for_each(|x| each_tid(x, f)),
        Value::Map(m) => m.iter().for_each(|(k, x)| {
            each_tid(k, f);
            each_tid(x, f);
        }),
        Value::Enum(_, Some(p)) => each_tid(p, f),
        _ => {}
    }
}
