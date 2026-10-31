//! Moving a thing (spec/permissions.md §7): node-core's copy with import (`Engine::move_thing`,
//! which refuses a second import of a continued thing), then the roster re-granted on the copy
//! by its new owner's chain and `/moved` written on the old thing by its admins. `/keys`
//! writes an admin makes outside rotations (deposit-seed refresh, spec/crypto.md §3: MAY).

use super::Done;
use crate::engine::Engine;
use crate::error::Result;
use crate::Mutation;
use osis_base::{Role, Tid};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::Codec;
use osis_schema::core_types::{self as ct, Edge};

impl Engine {
    /// Moves `t` to `owner` (an actor this node is admin of): the copy with `t`'s history,
    /// each current member of `t` re-granted its edge on the copy (with boxes, by inbox), and
    /// `/moved` on `t` when this node is its admin. A labeled `t`'s copy gets secrets of its
    /// own and a label at `t`'s servers first. Returns the copy.
    pub fn move_to(&mut self, t: &Tid, owner: &Tid) -> Result<(Tid, Done)> {
        let ts = super::now_ts(&self.core);
        let roster: Vec<(Tid, Edge)> = self
            .roster(t)
            .into_iter()
            .filter(|(_, e)| e.alive_at(Some(ts)))
            .map(|(m, e)| (m, Edge { role: e.role, until: e.until, invite: e.invite, since: None, tied: e.tied }))
            .collect();
        let servers = self.group_labels(t)?.into_iter().find(|l| !l.replaced).map(|l| l.servers);
        let (copy, imports) = self.move_thing(t, *owner)?;
        let mut done = Done { commits: imports, ..Done::default() };
        // a labeled thing's copy gets a label at the same servers before the re-grants, so their
        // inbox payloads name it and its members sync and write it whatever else they read
        if let Some(servers) = servers {
            done.extend(self.give_own_secrets(&copy)?);
            let (_, d) = self.create_label(&copy, &servers)?;
            done.extend(d);
        }
        for (m, e) in roster {
            if m != *owner {
                done.extend(self.grant(&copy, &m, &e)?);
            }
        }
        if self.role_on(t) == Some(Role::Admin) {
            let mut m = Mutation::new();
            m.set(*t, &ct::MOVED, &copy)?;
            done.add(self.commit(m)?);
        }
        Ok((copy, done))
    }

    /// Refreshes `actor`'s deposit seed (spec/crypto.md §3, a MAY: a departed member can then no
    /// longer deposit under its labels, nor can a member that has not read the new `/keys`).
    pub fn refresh_deposit_seed(&mut self, actor: &Tid) -> Result<Done> {
        let a = *actor;
        let mut done = Done::default();
        let c = self.run(|tx| {
            let mut seed = [0u8; 32];
            tx.rng.fill_bytes(&mut seed);
            let mut m = Mutation::new();
            m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Set(Some(seed).to_value()) })?;
            Engine::commit_tx(tx, m)
        })?;
        done.add(c);
        Ok(done)
    }
}
