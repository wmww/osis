//! Worlds for the external-fire rule (spec/permissions.md §5.2 External fires, spec/commits.md §5
//! The setting): thing 10 (mint admin node 0) with a second admin (node 2), a writer (node 1) and a
//! stranger (node 3) holding no role; settings enabling the external signal `EXT` or not, by
//! either admin; fires of it by the stranger, the writer and an admin, some stamped before the
//! settings around them; the writer's removal, listing some of its fires; the admins removing each
//! other at about the same time (a dispute: which setting stands differs by what a node holds).
//! Every subset of a world's events is a held set: a node holding part of it, so each arrival
//! order of the events passes through these sets.

use crate::gen::{creations, Rng, RECORDS};
use crate::types::*;

/// The external signal the worlds fire.
pub const EXT: Aspect = Aspect::external(14);
/// Another external signal: a setting naming only it enables `EXT` not.
pub const OTHER: Aspect = Aspect::external(15);
pub const THING: ThingId = 10;
pub const ADMIN: NodeId = 0;
pub const WRITER: NodeId = 1;
pub const ADMIN2: NodeId = 2;
pub const STRANGER: NodeId = 3;
/// Event commit IDs start here (creations are `gen::CREATION_ID` and up).
const FIRST: CommitId = 100;

/// A world: the commits every held set has (creations, the grants) and the events, of which any
/// subset is held.
#[derive(Clone, Debug)]
pub struct World {
    pub base: Vec<Commit>,
    pub events: Vec<Commit>,
    pub now: u64,
}

/// The `ts` of hour `h` after the generator's base.
fn hour(h: u64) -> u64 {
    (crate::gen::START + h * HOUR) * MS
}

fn content(id: CommitId, author: NodeId, ts: u64, aspect: Aspect, body: Delta) -> Commit {
    let part = Part { thing: THING, aspect, retention: Retention::ADMIN, body: Body::Held(body), stripped: Default::default(), replaces: None };
    Commit { id, signer: author, acting: author, ts, expires: None, kind: CommitKind::Content, parts: vec![part], purge: vec![], frontier: None, undoes: None, boxes: vec![] }
}

fn edge(id: CommitId, author: NodeId, ts: u64, holder: NodeId, role: Option<Role>, frontier: Option<Vec<CommitId>>) -> Commit {
    let part = Part { thing: THING, aspect: Aspect::ROLES, retention: Retention::ROLE, body: Body::Held(Delta::Edge(EdgeWrite::role(holder, role))), stripped: Default::default(), replaces: None };
    Commit { id, signer: author, acting: author, ts, expires: None, kind: CommitKind::Role, parts: vec![part], purge: vec![], frontier, undoes: None, boxes: vec![] }
}

/// A fire of `EXT` by `author` at `ts`.
pub fn fire(id: CommitId, author: NodeId, ts: u64) -> Commit {
    content(id, author, ts, EXT, Delta::Writes(crate::gen::set(ts, id, id as i64)))
}

/// A setting by `author` at `ts` with an entry of its own for each of `named`, and a keeping
/// default when `default`.
pub fn setting(id: CommitId, author: NodeId, ts: u64, named: &[Aspect], default: bool) -> Commit {
    let keep = SettingEntry { history: Opt::Keep { after: 0, until: NEVER }, expires: None, purge_before: 0 };
    let x = Setting { rules: named.iter().map(|a| (a.name, keep)).collect(), default: default.then_some(keep), written: None };
    content(id, author, ts, Aspect::RETENTION, Delta::Retention(x))
}

/// A random world of `seed`: two to six events.
pub fn world(seed: u64) -> World {
    let mut r = Rng::new(seed ^ 0xE47);
    let mut base = creations();
    base.push(edge(FIRST - 2, ADMIN, hour(0), ADMIN2, Some(Role::Admin), None));
    base.push(edge(FIRST - 1, ADMIN, hour(0), WRITER, Some(Role::Write), None));
    let n = 2 + r.below(5) as usize;
    let mut events: Vec<Commit> = Vec::new();
    while events.len() < n {
        let id = FIRST + events.len() as CommitId;
        let ts = hour(1 + r.below(12));
        match r.below(9) {
            0..=2 => {
                let named: &[Aspect] = match r.below(4) {
                    0 | 1 => &[EXT],
                    2 => &[OTHER],
                    _ => &[],
                };
                events.push(setting(id, r.pick(&[ADMIN, ADMIN2]), ts, named, r.chance(30)));
            }
            3..=5 => events.push(fire(id, r.pick(&[STRANGER, STRANGER, WRITER, ADMIN]), ts)),
            6 => {
                // the writer's removal, listing some of its fires so far
                let fires: Vec<CommitId> = events.iter().filter(|c| c.signer == WRITER && c.parts[0].aspect == EXT && r.chance(50)).map(|c| c.id).collect();
                events.push(edge(id, r.pick(&[ADMIN, ADMIN2]), ts, WRITER, None, Some(fires)));
            }
            _ => {
                // the admins remove each other about the same time (the second may not fit)
                let (a, b) = if r.chance(50) { (ADMIN, ADMIN2) } else { (ADMIN2, ADMIN) };
                events.push(edge(id, a, ts, b, None, Some(vec![])));
                if events.len() < n {
                    events.push(edge(id + 1, b, ts + r.below(2) * HOUR * MS, a, None, Some(vec![])));
                }
            }
        }
    }
    World { base, events, now: crate::gen::START + 14 * HOUR }
}

/// The admins' dispute, toggling forever: each removes the other at hour 5, then they write
/// settings enabling and disabling `EXT` in turn (the first admin enables at 6 and disables at 8,
/// the second disables at 7 and enables at 9); the stranger fires at 3 and at 10. Which admin
/// stands, and so which setting is current, differs by the held set.
pub fn dispute() -> World {
    let mut base = creations();
    base.push(edge(FIRST - 2, ADMIN, hour(0), ADMIN2, Some(Role::Admin), None));
    base.push(edge(FIRST - 1, ADMIN, hour(0), WRITER, Some(Role::Write), None));
    let events = vec![
        edge(FIRST, ADMIN, hour(5), ADMIN2, None, Some(vec![])),
        edge(FIRST + 1, ADMIN2, hour(5), ADMIN, None, Some(vec![])),
        setting(FIRST + 2, ADMIN, hour(6), &[EXT], false),
        setting(FIRST + 3, ADMIN2, hour(7), &[], true),
        setting(FIRST + 4, ADMIN, hour(8), &[OTHER], false),
        setting(FIRST + 5, ADMIN2, hour(9), &[EXT], false),
        fire(FIRST + 6, STRANGER, hour(3)),
        fire(FIRST + 7, STRANGER, hour(10)),
    ];
    World { base, events, now: crate::gen::START + 14 * HOUR }
}

impl World {
    /// What a node `me` holding the events `mask` names (bit k: event k) holds, judged by `rule`.
    pub fn held(&self, mask: u64, me: NodeId, rule: ExternalFires) -> Held {
        let mut commits = self.base.clone();
        commits.extend(self.events.iter().enumerate().filter(|(k, _)| mask >> k & 1 == 1).map(|(_, c)| c.clone()));
        Held { now: self.now, me, records: RECORDS.to_vec(), commits, dots: vec![], external_fires: rule }
    }
}
