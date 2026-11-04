//! Purge rights (spec/permissions.md §7) and who may rotate (§3).

use crate::content::Validity;
use crate::timeline::{At, Timeline};
use crate::types::Point;
use osis_base::{PurgeBy, Role, Tid};

impl Timeline {
    /// §7: may `requester` purge a delta of `thing` with retention `by` at `at`? `actor` is the
    /// actor its commit acted for (header field 2, checked by validity). Each member of the set
    /// `by` names gives the right alone: the thing's current admins; any node acting for `actor`
    /// (write on it) while `actor` holds write on the thing; any current writer.
    pub fn may_purge(&self, requester: &Tid, thing: &Tid, by: PurgeBy, actor: &Tid, at: At) -> bool {
        let role = self.role(requester, thing, at);
        (by.admin() && role == Some(Role::Admin))
            || (by.writer() && role >= Some(Role::Write))
            || (by.author() && self.role(requester, actor, at) >= Some(Role::Write) && self.role(actor, thing, at) >= Some(Role::Write))
    }

    /// §7: whether the commit at `at` holds, for its signer `who`, what `may_purge` asks at its own
    /// key, each role it rests on valid there as a delta needing that role would be: a demotion
    /// whose frontier leaves the commit out takes the right however early its `ts`.
    pub fn purge_stands(&self, who: &Tid, thing: &Tid, by: PurgeBy, actor: &Tid, at: Point) -> bool {
        let holds = |x: &Tid, on: &Tid, need: Role| self.role(x, on, At::before(at)) >= Some(need) && self.delta_valid(Point { node: *x, ..at }, on, need) == Validity::Valid;
        (by.admin() && holds(who, thing, Role::Admin)) || (by.writer() && holds(who, thing, Role::Write)) || (by.author() && holds(who, actor, Role::Write) && holds(actor, thing, Role::Write))
    }

    /// §3: the roles of `actor` that `node` may rotate and re-seal at `at`: write or above
    /// rotates its roles and below.
    pub fn may_rotate(&self, node: &Tid, actor: &Tid, at: At) -> Vec<Role> {
        let r = self.role(node, actor, at);
        [Role::Read, Role::Write, Role::Admin].into_iter().filter(|x| r >= Some(Role::Write) && Some(*x) <= r).collect()
    }
}
