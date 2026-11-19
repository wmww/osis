//! Purge rights (spec/permissions.md §6) and who may rotate (§3).

use crate::content::Validity;
use crate::timeline::{At, Timeline};
use crate::types::Point;
use osis_base::{PurgeBy, Role, Tid};

impl Timeline {
    /// §6: may `requester` purge a delta of `thing` with retention `by` at `at`? `author` is the
    /// delta's purge author (its commit's path names it, checked by validity). Each member of the
    /// set `by` names gives the right alone: the thing's current admins; any node with write on
    /// `author` while `author` holds write on the thing; any current writer.
    pub fn may_purge(&self, requester: &Tid, thing: &Tid, by: PurgeBy, author: &Tid, at: At) -> bool {
        let role = self.role(requester, thing, at);
        role == Some(Role::Admin)
            || (by.writer() && role >= Some(Role::Write))
            || (by.author() && self.role(requester, author, at) >= Some(Role::Write) && self.role(author, thing, at) >= Some(Role::Write))
    }

    /// §6: whether the commit at `at` holds, for its signer `who`, what `may_purge` asks at its own
    /// key. Invariant: each role it rests on counts exactly when a delta of that node needing the
    /// role at that key is valid (§5.2), nothing more: a demotion whose frontier leaves the commit
    /// out takes the right however early its `ts`, and a re-grant gives back the right of a request
    /// made in the gap as it does that request's own writes.
    pub fn purge_stands(&self, who: &Tid, thing: &Tid, by: PurgeBy, author: &Tid, at: Point) -> bool {
        let holds = |x: &Tid, on: &Tid, need: Role| self.delta_valid(Point { node: *x, ..at }, on, need) == Validity::Valid;
        holds(who, thing, Role::Admin) || (by.writer() && holds(who, thing, Role::Write)) || (by.author() && holds(who, author, Role::Write) && holds(author, thing, Role::Write))
    }

    /// §3: the roles of `actor` that `node` may rotate and re-seal at `at`: write or above
    /// rotates its roles and below.
    pub fn may_rotate(&self, node: &Tid, actor: &Tid, at: At) -> Vec<Role> {
        let r = self.role(node, actor, at);
        Role::ALL.into_iter().filter(|x| r >= Some(Role::Write) && Some(*x) <= r).collect()
    }
}
