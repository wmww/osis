//! A node acting as an actor it administers, confined to that actor's rights (notes/client-port.md
//! §3): receivers judge a commit by its author node's rights (spec/permissions.md §1; of the
//! header's actor only that the node acts for it, §5.2), and this node's are usually wider than
//! the actor's, so only this node can hold it to them. `Mutation::confine` asks for that check before a write;
//! `readable_by`, `actor_role` and `revert_as` are the same rule for reads and reverts.

use super::write::{check_authority, check_authority_with, check_role_with, Mutation, Records, Resolved};
use super::{Engine, Tx};
use crate::error::{Error, Result};
use crate::undo::Reverted;
use crate::flows::Done;
use crate::rotation;
use osis_base::{Ak, CommitId, Role, Tid, Ts};
use osis_perm::At;
use std::collections::BTreeSet;

impl Engine {
    fn acting_ts(&self) -> Ts {
        Ts::make(self.now(), 0).unwrap_or_default()
    }

    /// The effective role of `actor` on `t` now (spec/permissions.md §1).
    pub fn actor_role(&self, actor: &Tid, t: &Tid) -> Option<Role> {
        self.core.role_now(actor, t)
    }

    /// Whether a client of this node, `actor`, reads `t` here now: `entitled` and this node's copy
    /// is current, or a kept copy it reads (`copy_readable_by`).
    pub fn readable_by(&self, actor: &Tid, t: &Tid) -> bool {
        // in a sync unit read at another node, or still catching up as it moves back: stale here,
        // and this node would serve it to a client as if current (notes/client-port.md §6)
        let away = &self.core.sourced_elsewhere;
        if !away.is_empty() && (away.contains(t) || self.units_holding(t).iter().any(|u| away.contains(u))) {
            return false;
        }
        self.entitled(actor, t) || self.copy_readable_by(actor, t)
    }

    /// The permission model's entitlement (spec/sync-judgement.md §1). False for what this node does not
    /// know.
    pub fn entitled(&self, actor: &Tid, t: &Tid) -> bool {
        self.core.may_read(actor, t)
    }

    /// Fails `Permission` unless `actor` itself may do all of a confined `m`: every aspect's write,
    /// every creation (write on the first admin). A purge needs write: what it drops receivers
    /// judge by this node's and the actor's rights together (spec/permissions.md §6).
    pub(crate) fn check_confined(&self, m: &Mutation, actor: &Tid) -> Result<()> {
        let ts = self.acting_ts();
        let creates = &m.creates;
        let records: Records<'_> = &|t| creates.get(t);
        let created = "created.0";
        for (t, ak) in m.aspects.keys() {
            check_authority_with(&self.core, *actor, records, t, ak.as_str(), ts)?;
        }
        for t in m.creates.keys() {
            check_authority_with(&self.core, *actor, records, t, created, ts)?;
        }
        for p in &m.purge {
            check_role_with(&self.core, *actor, records, p.tid(), p.ak().as_str(), Role::Write, ts)?;
        }
        Ok(())
    }

    /// Reverts change `id` for `actor`, held to its rights: on everything the change touched,
    /// whether or not the revert still writes it (the answer tells nothing of what it may not
    /// read), and on every write the revert really makes (`undo_in`, `revert_inner`). An error
    /// names only what it reads.
    pub fn revert_as(&mut self, id: CommitId, actor: Tid) -> Result<Reverted> {
        self.as_actor(id, actor, |e| e.revert_inner(id, actor, true))
    }

    /// What `revert_as` fails with before writing anything (`Permission`, then `NotKept`),
    /// named as it would, and whether it writes anything (`Engine::check_revertible`).
    pub fn check_revertible_as(&mut self, id: CommitId, actor: Tid) -> Result<bool> {
        self.as_actor(id, actor, |e| e.check_revert(id))
    }

    /// `f` once `actor` holds write on everything commit `id` touched; an error names only what
    /// `actor` reads.
    fn as_actor<T>(&mut self, id: CommitId, actor: Tid, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        let touched: BTreeSet<(Tid, Ak)> = self.header(&id).map(|h| h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect()).unwrap_or_default();
        let shown = touched.iter().map(|(t, _)| *t).find(|t| self.readable_by(&actor, t));
        let ts = self.acting_ts();
        let check = touched.iter().try_for_each(|(t, ak)| check_authority(&self.core, actor, &Default::default(), t, ak.as_str(), ts));
        let r = check.and_then(|()| f(self));
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

    /// Mints an actor whose first admin is `admin` with secrets of its own (and `keys.0`), as a link's K is
    /// minted, and commits what `also` builds for it, all in one transaction: a crash or a
    /// failure leaves both or neither (`flows::links` shares the shape).
    pub fn mint_actor(&mut self, admin: &Tid, also: impl FnOnce(Tid) -> Result<Mutation>) -> Result<(Tid, Done)> {
        let admin = *admin;
        self.run(|tx| {
            let mut done = Done::default();
            let rec = crate::identity::thing_record(admin, None, &mut *tx.rng);
            let a = rotation::own_secrets_new(tx, rec, &[], &mut done)?;
            done.add(Engine::commit_tx(tx, also(a)?)?);
            Ok((a, done))
        })
    }
}

/// A confined revert's durable writes, as `undo_in` is about to make them: `actor`'s rights on
/// each.
pub(crate) fn check_undo(tx: &mut Tx<'_>, actor: Tid, deltas: &[Resolved], ts: Ts) -> Result<()> {
    for d in deltas {
        check_authority(tx.core, actor, &Default::default(), &d.tid, d.ak.as_str(), ts)?;
    }
    Ok(())
}
