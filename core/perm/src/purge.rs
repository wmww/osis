//! Purge rights (spec/permissions.md §8) and who may rotate (§3).

use crate::timeline::{At, Timeline};
use osis_base::{PurgeBy, Role, Tid};

impl Timeline {
    /// §8: may `requester` purge a delta of `thing` with retention `by` at `at`? `actor` is the
    /// actor its commit acted for (`Header::purge_actor`: header field 2, checked by validity; an
    /// import's delta: its origin commit's, as its importer states it). Each member of the set
    /// `by` names gives the right alone: the thing's current admins; any node acting for `actor`
    /// (write on it) while `actor` holds write on the thing; any current writer.
    pub fn may_purge(&self, requester: &Tid, thing: &Tid, by: PurgeBy, actor: &Tid, at: At) -> bool {
        let role = self.role(requester, thing, at);
        (by.admin() && role == Some(Role::Admin))
            || (by.writer() && role >= Some(Role::Write))
            || (by.author() && self.role(requester, actor, at) >= Some(Role::Write) && self.role(actor, thing, at) >= Some(Role::Write))
    }

    /// §3: the roles of `actor` that `node` may rotate and re-seal at `at`: write or above
    /// rotates its roles and below.
    pub fn may_rotate(&self, node: &Tid, actor: &Tid, at: At) -> Vec<Role> {
        let r = self.role(node, actor, at);
        [Role::Read, Role::Write, Role::Admin].into_iter().filter(|x| r >= Some(Role::Write) && Some(*x) <= r).collect()
    }
}
