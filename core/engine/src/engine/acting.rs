//! A node acting as an actor it administers, confined to that actor's rights (notes/client-port.md
//! §3): receivers judge a commit by its author node's rights alone (spec/permissions.md §1; the
//! header's actor is attribution), and this node's are usually wider than the actor's, so only
//! this node can hold it to them. `Mutation::confine` asks for that check before a write;
//! `readable_by`, `actor_role` and `check_revert_as` are the same rule for reads and reverts.

use super::write::{check_authority_with, check_role_with, role_with, Mutation, Records};
use super::Engine;
use crate::error::Result;
use crate::events::ChangeId;
use crate::flows::Done;
use crate::rotation;
use osis_base::{Ak, Role, Tid, Ts};
use osis_perm::At;
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
    /// it needs admin, the one role that holds every such right.
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
        Ok(())
    }

    /// Fails `Permission` unless `actor` may write every aspect reverting change `id` writes.
    pub fn check_revert_as(&self, actor: &Tid, id: ChangeId) -> Result<()> {
        let ts = self.acting_ts();
        let records: Records<'_> = &|t| self.ephemeral_thing(t).map(|e| &e.record);
        let mut aspects: BTreeSet<(Tid, Ak)> = self.ephemeral_log().into_iter().filter(|l| l.id == id).flat_map(|l| l.aspects).collect();
        if let ChangeId::Commit(c) = id
            && let Some(h) = self.header(&c)
        {
            aspects.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
        }
        for (t, ak) in &aspects {
            check_authority_with(&self.core, *actor, records, t, ak.as_str(), ts)?;
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
