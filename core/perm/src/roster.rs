//! Roster snapshot production (spec/permissions.md §6): the roster with `since` and the tenure
//! ledger an owner-chain author writes, as its timeline computes them.
//!
//! Readings: tenures are per role level (a promotion ends a write tenure without a frontier
//! and starts an admin one); an edge that expires by `until` stays in the roster with its
//! `until` while it is current, and a tenure it ended inside the history gets the key
//! (first `ts` at `until`, the zero tid and commit ID), before every write at that `ts`. A tenure ended by an explicit write that audited
//! (lowered the edge as the walk restores it) carries that write's frontier (empty if it had
//! none); tenures ended without one stay without, and the next auditing write of that edge
//! that ends none of them is an entry of its own: `since` = `until` = its key, its frontier,
//! the highest role it audits. Read edges carry no `since`.

use crate::graph::Class;
use crate::timeline::{At, Timeline};
use crate::types::{Edge, Point, Tenure};
use osis_base::{Role, Tid, Ts};
use std::collections::BTreeMap;

/// The `/members` and `/tenures` state a roster snapshot of a thing carries.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RosterState {
    pub roster: BTreeMap<Tid, Edge>,
    pub ledger: Vec<Tenure>,
}

/// One write+ tenure being followed.
struct Open {
    role: Role,
    since: Option<Point>,
}

impl Timeline {
    /// May `node` write a roster snapshot of `thing` now (§6: owner-chain authority)?
    pub fn may_roster_snapshot(&self, node: &Tid, thing: &Tid, now: Ts) -> bool {
        self.class(node, thing, At::now(now)) == Class::Chain
    }

    /// The roster and ledger a roster snapshot of `thing` written after every held write
    /// carries: the epoch start's ledger carried forward whole, then every write+ tenure that
    /// ended since.
    pub fn roster_state(&self, thing: &Tid) -> RosterState {
        let start = self.epoch_start(thing).and_then(|id| self.roster_snapshot(&id));
        let from: Option<Point> = start.map(|s| s.point());
        let mut ledger: Vec<Tenure> = start.map(|s| s.ledger.clone()).unwrap_or_default();
        // Per member: changes after the epoch start, in order.
        let mut changes: BTreeMap<Tid, Vec<&crate::walk::Change>> = BTreeMap::new();
        for c in &self.walked.history {
            if c.target == *thing && from.is_none_or(|p| c.point > p) {
                changes.entry(c.member).or_default().push(c);
            }
        }
        let mut members: Vec<Tid> = changes.keys().copied().collect();
        if let Some(s) = start {
            members.extend(s.roster.keys().copied());
        }
        members.sort();
        members.dedup();
        let mut roster = BTreeMap::new();
        for m in members {
            let first = start.and_then(|s| s.roster.get(&m)).copied();
            let mut edge: Option<Edge> = first.map(|e| Edge { since: None, ..e });
            // Key of the write that set the current edge.
            let mut set_key: Option<Point> = first.and_then(|e| e.since);
            let mut open = first.filter(|e| e.role >= Role::Write).map(|e| Open { role: e.role, since: e.since });
            for c in changes.get(&m).map(|v| v.as_slice()).unwrap_or(&[]) {
                let key = c.point;
                // Expiry inside the history ends the tenure at the first ts at `until`.
                if let Some(u) = edge.and_then(|e| e.until).filter(|u| c.point.ts.wall_ms() >= *u)
                    && let Some(o) = open.take()
                {
                    let at = Ts::make(u, 0).unwrap_or(c.point.ts).min(c.point.ts);
                    ledger.push(Tenure { member: m, role: o.role, since: o.since, until: Point::expiry(at), frontier: None });
                }
                // An edge already expired when written grants nothing.
                let new_role = c.edge.filter(|e| e.alive_at(Some(c.point.ts))).map(|e| e.role).filter(|r| *r >= Role::Write);
                // An auditing write: its frontier (empty if it had none), the role it audited.
                let audit = c.audited.filter(|r| *r >= Role::Write).map(|r| (c.explicit.clone().flatten().unwrap_or_default(), r));
                let open_role = open.as_ref().map(|o| o.role);
                // A tenure ends at a role change, and at an audit from above its role (the
                // demoter's own standing, kept since an earlier demotion; it then goes on).
                let split = c.audited.is_some_and(|r| open_role.is_some_and(|o| o < r));
                if open_role != new_role || split {
                    if let Some(o) = open.take() {
                        ledger.push(Tenure { member: m, role: o.role, since: o.since, until: key, frontier: audit.as_ref().map(|a| a.0.clone()) });
                    }
                    open = new_role.map(|r| Open { role: r, since: Some(key) });
                }
                // An audit with no tenure in force before it (of tenures ended without one, or
                // of the demoter's own standing kept since an earlier demotion): an entry of its
                // own.
                if let Some((f, r)) = audit.filter(|_| open_role.is_none()) {
                    ledger.push(Tenure { member: m, role: r, since: Some(key), until: key, frontier: Some(f) });
                }
                edge = c.edge;
                set_key = Some(key);
            }
            if let Some(e) = edge {
                // The open tenure's start, else (an edge never in force) the write that set it.
                let since = open.as_ref().map_or(set_key, |o| o.since);
                roster.insert(m, Edge { since: if e.role >= Role::Write { since } else { None }, ..e });
            }
        }
        RosterState { roster, ledger }
    }
}
