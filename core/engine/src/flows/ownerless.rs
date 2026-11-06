//! Ownerless things (spec/permissions.md §1, §3): no owner and no key; their record names the
//! first admin, which holds an admin edge on them from the start (stored nowhere). A plain one
//! derives its secrets from the first admin's (spec/crypto.md §3), like an owned plain thing.

use super::Done;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{CreationRecord, Role, Tid};

impl Engine {
    /// Creates an ownerless thing whose first admin is `admin` (this node, or an actor it holds
    /// write on): a commit carrying its `created.0` alone.
    pub fn create_ownerless(&mut self, admin: &Tid) -> Result<(Tid, Done)> {
        let a = *admin;
        if a != self.tid() && self.role_on(&a) < Some(Role::Write) {
            return Err(Error::Permission { tid: a });
        }
        let (t, c) = self.run(|tx| {
            let mut nonce = [0u8; 32];
            tx.rng.fill_bytes(&mut nonce);
            let mut m = Mutation::new();
            let t = m.create(CreationRecord::Ownerless { admin: a, nonce });
            Ok((t, Engine::commit_tx(tx, m)?))
        })?;
        let mut done = Done::default();
        done.add(c);
        Ok((t, done))
    }
}
