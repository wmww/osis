//! Purge rights (spec/permissions.md §8), who may rotate (§3) and who may write the
//! membership-class aspects (§1).

use crate::timeline::{At, Timeline};
use osis_base::{Role, Tid};

/// Who may purge a delta (spec/commits.md §5; wire codes spec/wire.md §1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PurgeBy {
    Nobody,
    Admin,
    Author,
    Writer,
}

impl PurgeBy {
    pub fn from_code(c: u64) -> Option<PurgeBy> {
        [PurgeBy::Nobody, PurgeBy::Admin, PurgeBy::Author, PurgeBy::Writer].get(usize::try_from(c).ok()?).copied()
    }
    pub fn code(self) -> u64 {
        self as u64
    }
}

impl Timeline {
    /// §8: may `requester` purge a delta of `thing` with retention `by` at `at`? `actor` is the
    /// actor directly above the delta's author node: the actor its commit acted for (header
    /// field 2; an import's delta: its origin commit's). `admin`: the thing's current admins;
    /// `author`: also any node acting for `actor` (write on it) while `actor` holds write on
    /// the thing; `writer`: also any current writer.
    pub fn may_purge(&self, requester: &Tid, thing: &Tid, by: PurgeBy, actor: &Tid, at: At) -> bool {
        let role = self.role(requester, thing, at);
        let admin = role == Some(Role::Admin);
        let via_author = || self.role(requester, actor, at) >= Some(Role::Write) && self.role(actor, thing, at) >= Some(Role::Write);
        match by {
            PurgeBy::Nobody => false,
            PurgeBy::Admin => admin,
            PurgeBy::Author => admin || via_author(),
            PurgeBy::Writer => admin || role >= Some(Role::Write) || via_author(),
        }
    }

    /// §3: the roles of `actor` that `node` may rotate and re-seal at `at`: write or above
    /// rotates its roles and below.
    pub fn may_rotate(&self, node: &Tid, actor: &Tid, at: At) -> Vec<Role> {
        let r = self.role(node, actor, at);
        [Role::Read, Role::Write, Role::Admin].into_iter().filter(|x| r >= Some(Role::Write) && Some(*x) <= r).collect()
    }

    /// §1: may `node` write the membership-class aspects of `thing` (admins; invite grants,
    /// self-removals, rotations and re-seals follow their own rules)?
    pub fn may_write_membership(&self, node: &Tid, thing: &Tid, at: At) -> bool {
        self.role(node, thing, at) == Some(Role::Admin)
    }
}
