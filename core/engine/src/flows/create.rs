//! Creating a thing (spec/permissions.md §1): its `created.0`, which names its mint admin, and
//! the strong that holds it (spec/sync-set.md §2 Minting a thing). A dependent one derives its secrets from the mint
//! admin's (spec/crypto.md §3).

use super::Done;
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{Role, Tid};

impl Engine {
    /// Creates a thing whose mint admin is `admin` (this node, or an actor it holds write on):
    /// a commit carrying its `created.0` and the strong that holds it (`hold_where_it_lives`).
    pub fn create_with_admin(&mut self, admin: &Tid) -> Result<(Tid, Done)> {
        let a = *admin;
        if a != self.core.tid() && self.role_on(&a) < Some(Role::Write) {
            return Err(Error::Permission { tid: a, needs: Role::Write });
        }
        let mut m = Mutation::new();
        let t = self.new_thing(&mut m, a);
        let c = self.commit(m)?;
        let mut done = Done::default();
        done.add(c);
        Ok((t, done))
    }
}
