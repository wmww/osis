//! Creating a thing by its record alone (spec/permissions.md §1): a role commit carrying its
//! `created.0`, which names its first admin. A plain one derives its secrets from the first
//! admin's (spec/crypto.md §3).

use super::Done;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{CreationRecord, Role, Tid};

impl Engine {
    /// Creates a thing whose first admin is `admin` (this node, or an actor it holds write on):
    /// a commit carrying its `created.0` alone.
    pub fn create_with_admin(&mut self, admin: &Tid) -> Result<(Tid, Done)> {
        let a = *admin;
        if a != self.me() && self.role_on(&a) < Some(Role::Write) {
            return Err(Error::Permission { tid: a });
        }
        let (t, c) = self.run(|tx| {
            let mut nonce = [0u8; 32];
            tx.rng.fill_bytes(&mut nonce);
            let mut m = Mutation::new();
            let t = m.create(CreationRecord::Thing { admin: a, nonce, link: false });
            Ok((t, Engine::commit_tx(tx, m)?))
        })?;
        let mut done = Done::default();
        done.add(c);
        Ok((t, done))
    }
}
