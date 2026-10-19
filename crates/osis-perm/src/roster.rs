//! Roster snapshot production (spec/permissions.md §6): the roster with `since` and the tenure
//! ledger an owner-chain author writes, as its timeline computes them.
//!
//! Readings: tenures are per role level (a promotion ends a write tenure without a frontier
//! and starts an admin one); an edge that expires by `until` stays in the roster with its
//! `until` while it is current, and a tenure it ended inside the history gets the key
//! (first `ts` at `until`, the member); a tenure ended by `until` or self-removal takes the
//! frontier of the next explicit demotion of that edge, if any. Read edges carry no `since`.

use crate::graph::Class;
use crate::timeline::{At, Timeline};
use crate::types::{Edge, EdgeKey, Frontier, Point, Tenure};
use osis_core::{Role, Tid, Ts};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The `/members` and `/tenures` state a roster snapshot of a thing carries.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RosterState {
    pub roster: BTreeMap<Tid, Edge>,
    pub ledger: Vec<Tenure>,
    /// Tenures ended by `until` or self-removal whose frontier is a later demotion's: the
    /// ledger places that audit at the tenure's end (diagnostic; notes/permissions.md).
    pub late_audits: usize,
}

/// One write+ tenure being followed.
struct Open {
    role: Role,
    since: Option<EdgeKey>,
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
        let mut late = 0;
        for m in members {
            let first = start.and_then(|s| s.roster.get(&m)).copied();
            let mut edge: Option<Edge> = first.map(|e| Edge { since: None, ..e });
            // Key of the write that set the current edge.
            let mut set_key: Option<EdgeKey> = first.and_then(|e| e.since);
            let mut open = first.filter(|e| e.role >= Role::Write).map(|e| Open { role: e.role, since: e.since });
            // Tenures ended without a frontier since the last explicit demotion.
            let mut pending: Vec<usize> = Vec::new();
            let mut held = edge.map(|e| e.role);
            let close = |open: &mut Option<Open>, until: EdgeKey, ledger: &mut Vec<Tenure>, pending: &mut Vec<usize>, f: Option<Arc<Frontier>>| {
                if let Some(o) = open.take() {
                    if f.is_none() {
                        pending.push(ledger.len());
                    }
                    ledger.push(Tenure { member: m, role: o.role, since: o.since, until, frontier: f });
                }
            };
            for c in changes.get(&m).map(|v| v.as_slice()).unwrap_or(&[]) {
                let key = c.point.key();
                // Expiry inside the history ends the tenure at the first ts at `until`.
                if let Some(u) = edge.and_then(|e| e.until).filter(|u| c.point.ts.wall_ms() >= *u) {
                    let at = Ts::make(u, 0).unwrap_or(c.point.ts);
                    close(&mut open, EdgeKey { ts: at.min(c.point.ts), node: m }, &mut ledger, &mut pending, None);
                }
                // An edge already expired when written grants nothing.
                let new_role = c.edge.filter(|e| e.alive_at(Some(c.point.ts))).map(|e| e.role);
                // A node lowering its own edge is never its own demoter (§5.1 step 4).
                let demotes = c.explicit.is_some() && c.point.node != m && new_role < held;
                let f = if demotes { c.explicit.clone().flatten() } else { None };
                if demotes {
                    late += pending.len();
                    for &i in &pending {
                        if let Some(t) = ledger.get_mut(i) {
                            t.frontier = f.clone();
                        }
                    }
                    pending.clear();
                    held = new_role;
                } else {
                    held = held.max(new_role);
                }
                if open.as_ref().map(|o| o.role) != new_role.filter(|r| *r >= Role::Write) {
                    close(&mut open, key, &mut ledger, &mut pending, f);
                    if let Some(r) = new_role.filter(|r| *r >= Role::Write) {
                        open = Some(Open { role: r, since: Some(key) });
                    }
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
        RosterState { roster, ledger, late_audits: late }
    }
}
