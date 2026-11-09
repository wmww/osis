//! A small random history generator (for this crate's properties and for an engine adapter), and a
//! shuffle of a held set's order. Dependency-free PRNG so a seed means the same history everywhere.

use crate::model::{cover, evaluate, join, snapshot_retention, snapshot_state};
use crate::types::*;
use crdt_model::ops::{self, Ty, Writer};
use std::collections::BTreeSet;

/// xorshift64*.
#[derive(Clone, Debug)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    pub fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

pub const REG: Aspect = Aspect::plain(1);
pub const MAP: Aspect = Aspect::plain(2);
pub const TEXT: Aspect = Aspect::plain(3);
pub const ADM: Aspect = Aspect::admin(4);
pub const SET: Aspect = Aspect::plain(6);
pub const COUNT: Aspect = Aspect::plain(7);
pub const LIST: Aspect = Aspect::plain(11);
/// A struct of a register and a map (a nested map).
pub const REC: Aspect = Aspect::plain(12);
/// `purge.0`: what a purge request with nothing to reset writes.
pub const PURGE: Aspect = Aspect::plain(9);
/// What snapshots cover.
pub const ASPECTS: [Aspect; 8] = [REG, MAP, TEXT, ADM, SET, COUNT, LIST, REC];
/// A signal (never snapshotted).
pub const SIG: Aspect = Aspect::signal(5);
/// What content writes go to.
pub const WRITTEN: [Aspect; 9] = [REG, MAP, TEXT, ADM, SET, COUNT, LIST, REC, SIG];

/// The schema type of each aspect the generator writes (spec/crdt.md §5: its encodings).
pub fn ty(a: Aspect) -> Option<Ty> {
    let map = || Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register));
    Some(match a {
        REG | ADM | SIG | PURGE => Ty::Register,
        MAP => map(),
        TEXT => Ty::Text,
        SET => Ty::Set(Box::new(Ty::Register)),
        COUNT => Ty::Counter,
        LIST => Ty::List(Box::new(Ty::Register)),
        REC => Ty::Struct([(1, Ty::Register), (2, map())].into_iter().collect()),
        _ => return None,
    })
}

/// A register write of `v` by commit-form commit `id` at `ts`.
pub fn set(ts: u64, id: CommitId, v: i64) -> Frag {
    Frag::Register { reset: None, write: Some((stamp(ts, id, 1), Some(Value::Int(v)))) }
}

pub const NODES: u64 = 4;
/// An account actor whose first admin is node 2, the first admin of thing 12.
pub const ACCOUNT: ThingId = 20;
/// A link: K (an actor whose first admin is node 0, with an edge on thing 10) and L (a key actor).
pub const LINK_K: ThingId = 21;
pub const LINK_L: NodeId = 30;
/// The records held apart from creations: the nodes and L (key actors), and the account's (thing
/// 12's chain proof).
pub const RECORDS: [Record; 6] = [
    Record { id: 0, link: RecordLink::Key },
    Record { id: 1, link: RecordLink::Key },
    Record { id: 2, link: RecordLink::Key },
    Record { id: 3, link: RecordLink::Key },
    Record { id: LINK_L, link: RecordLink::Key },
    Record { id: ACCOUNT, link: RecordLink::Admin(2) },
];
/// The things made by a creation (thing, its first admin, the node creating it): with a node or
/// the account as first admin.
pub const CREATIONS: [(ThingId, RecordLink, NodeId); 6] = [
    (10, RecordLink::Admin(0), 0),
    (11, RecordLink::Admin(1), 1),
    (ACCOUNT, RecordLink::Admin(2), 2),
    (12, RecordLink::Admin(ACCOUNT), 2),
    (13, RecordLink::Admin(3), 3),
    (LINK_K, RecordLink::Admin(0), 0),
];
/// Commit IDs of creations: this plus the thing (the generator's others are below 1_000_001).
pub const CREATION_ID: CommitId = 2_000_000;

/// Thing `t`'s creation commit (one `created.0` part), by `author` at `ts`.
pub fn creation(t: ThingId, link: RecordLink, author: NodeId, ts: u64, retention: Retention, expires: Option<u64>) -> Commit {
    let part = Part { thing: t, aspect: Aspect::CREATED, retention, body: Body::Held(Delta::Created(link)), stripped: Default::default(), replaces: None };
    Commit { id: CREATION_ID + t, author, actor: author, ts, expires, kind: CommitKind::Content, parts: vec![part], purge: vec![], frontier: None, undoes: None , boxes: vec![] }
}

/// Every `CREATIONS` thing's creation, an hour before `START`, kept for good.
pub fn creations() -> Vec<Commit> {
    CREATIONS.iter().enumerate().map(|(k, &(t, link, author))| creation(t, link, author, (START - HOUR) * MS + k as u64, Retention::FIXED, None)).collect()
}

/// Whether `c` creates a thing.
pub fn creates(c: &Commit) -> bool {
    c.parts.iter().any(|p| p.aspect == Aspect::CREATED)
}
/// Things content is written on, and the node with authority on each by its record chain.
pub const CONTENT: [(ThingId, NodeId); 4] = [(10, 0), (11, 1), (12, 2), (13, 3)];
/// Things roles are written on, with that node.
pub const TARGETS: [(ThingId, NodeId); 6] = [(10, 0), (11, 1), (12, 2), (13, 3), (ACCOUNT, 2), (LINK_K, 0)];
pub const HOLDERS: [NodeId; 7] = [0, 1, 2, 3, ACCOUNT, LINK_K, LINK_L];
pub const START: u64 = 1_000_000_000;

/// Retention presets the generator draws from: convenient (`author_or_admin`, `writer`), kept
/// for good (`nobody`), gone once replaced, kept until an hour or two from now, kept an hour
/// after replaced, both.
pub fn retentions(wall_now: u64) -> [Retention; 8] {
    [
        Retention::PLAIN,
        Retention::WRITER,
        Retention::FIXED,
        Retention::PURGE_ON_REPLACE,
        Retention::PLAIN.until(wall_now + HOUR),
        Retention::PLAIN.with_by(PurgeBy::Admin).until(wall_now + 2 * HOUR),
        Retention::WRITER.after(HOUR),
        Retention::PLAIN.until(wall_now + HOUR).after(2 * HOUR),
    ]
}

/// The keep-history settings a signal declares (spec/commits.md §5 Signals): until an hour
/// from now, an hour after written, for good, both.
pub fn signal_retentions(wall_now: u64) -> [Retention; 4] {
    [
        Retention::WRITER.until(wall_now + HOUR),
        Retention::PLAIN.after(HOUR),
        Retention::PLAIN.until(FOREVER),
        Retention::PLAIN.with_by(PurgeBy::Admin).until(wall_now + HOUR).after(2 * HOUR),
    ]
}

fn role_part(thing: ThingId, e: EdgeWrite) -> Part {
    Part { thing, aspect: Aspect::ROLES, retention: Retention::ROLE, body: Body::Held(Delta::Edge(e)), stripped: Default::default(), replaces: None }
}

fn plain_part(thing: ThingId, aspect: Aspect, retention: Retention, d: Delta) -> Part {
    Part { thing, aspect, retention, body: Body::Held(d), stripped: Default::default(), replaces: None }
}

/// A random history of `n` commits on the `CREATIONS` things, after their creations (plus the
/// covering snapshots writers owe): content
/// under every history mode, signal writes, compaction snapshots, purges, undos, required retention, acting for
/// the account, edge writes (grants, `until`, invites, self-removals, finalizes, link
/// redemptions); creations kept for good or `admin` with no history, a few expiring, some
/// purged; every body held but about one in ten missing and a few parked (creations whole);
/// sometimes a creation or a key actor's record unknown; `now` up to six hours after the last
/// commit. Snapshots and undos are written from the author's model state.
pub fn history(seed: u64, n: usize) -> Held {
    let mut r = Rng::new(seed);
    let mut commits: Vec<Commit> = Vec::new();
    let mut ids: BTreeSet<CommitId> = BTreeSet::new();
    let mut w = START;
    let mut logical = 0u64;
    // the things' creations: an ending (expiry, purge) needs a purgeable one
    for (k, &(t, link, author)) in CREATIONS.iter().enumerate() {
        let ts = (START - HOUR) * MS + k as u64;
        let retention = if r.chance(50) { Retention::FIXED } else { Retention::ROLE };
        let expires = (retention.by != PurgeBy::Nobody && r.chance(4)).then(|| START + (2 + r.below(9)) * HOUR);
        commits.push(creation(t, link, author, ts, retention, expires));
    }
    let mut new_id = |r: &mut Rng| loop {
        let id = r.below(1_000_000) as CommitId + 1;
        if ids.insert(id) {
            break id;
        }
    };
    let base = |id, author, ts| Commit {
        id,
        author,
        actor: author,
        ts,
        expires: None,
        kind: CommitKind::Content,
        parts: vec![],
        purge: vec![],
        frontier: None,
        undoes: None,
        boxes: vec![],
    };
    // half the histories set a link up: K's edge on thing 10, L's (invite) edge on K
    if r.chance(50) {
        let ts = w * MS;
        let until = r.chance(50).then(|| w + (2 + r.below(8)) * HOUR);
        let k = EdgeWrite::role(LINK_K, Some(Role::Write));
        let l = EdgeWrite { holder: LINK_L, role: Some(Role::Write), invite: Some(Role::Write), until };
        let (a, b) = (new_id(&mut r), new_id(&mut r));
        commits.push(Commit { kind: CommitKind::Role, parts: vec![role_part(10, k)], ..base(a, 0, ts) });
        commits.push(Commit { kind: CommitKind::Role, parts: vec![role_part(LINK_K, l)], ..base(b, 0, ts + 1) });
        logical = 1;
    }
    for _ in 0..n {
        let step = r.below(4) * HOUR / 2;
        if step == 0 {
            logical += 1;
        } else {
            logical = 0;
        }
        w += step;
        let ts = w * MS + logical;
        let id = new_id(&mut r);
        let (thing, chief) = r.pick(&CONTENT);
        // chiefs write most of the time, so most histories have valid writes and rights (an author
        // nothing leads to the thing from waits)
        let named: Vec<NodeId> = commits
            .iter()
            .filter(|c| c.is_role())
            .flat_map(|c| c.parts.iter())
            .filter_map(|p| match &p.body {
                Body::Held(Delta::Edge(e)) if p.thing == thing && e.holder < NODES as NodeId => Some(e.holder),
                _ => None,
            })
            .collect();
        let author = if r.chance(70) {
            chief
        } else if !named.is_empty() && r.chance(60) {
            r.pick(&named)
        } else {
            r.below(NODES) as NodeId
        };
        let roll = r.below(100);
        let prefix = |me: NodeId| Held { now: w, me, records: RECORDS.to_vec(), commits: commits.clone(), dots: vec![] };
        let c = if roll < 15 {
            let (thing, chief) = r.pick(&TARGETS);
            let author = if r.chance(50) { chief } else { r.below(NODES) as NodeId };
            let sub = r.below(100);
            if sub < 55 {
                let holder = r.pick(&HOLDERS);
                let role = r.pick(&[None, Some(Role::Read), Some(Role::Write), Some(Role::Admin)]);
                let invite = role.filter(|_| r.chance(15));
                let until = (role.is_some() && r.chance(25)).then(|| w + r.below(4) * HOUR);
                let frontier = (role != Some(Role::Admin))
                    .then(|| commits.iter().filter(|c| c.author == holder && r.chance(60)).map(|c| c.id).collect());
                let e = EdgeWrite { holder, role, invite, until };
                Commit { kind: CommitKind::Role, frontier, parts: vec![role_part(thing, e)], ..base(id, author, ts) }
            } else if sub < 70 {
                // self-removal (or lowering) of the author's own edge
                let role = r.pick(&[None, Some(Role::Read)]);
                Commit { kind: CommitKind::Role, parts: vec![role_part(thing, EdgeWrite::role(author, role))], ..base(id, author, ts) }
            } else if sub < 80 {
                // finalize: another's edge (a timed one when held), no frontier
                let timed: Vec<NodeId> = commits
                    .iter()
                    .flat_map(|c| c.parts.iter())
                    .filter_map(|p| match &p.body {
                        Body::Held(Delta::Edge(e)) if p.thing == thing && e.until.is_some() => Some(e.holder),
                        _ => None,
                    })
                    .collect();
                let holder = if timed.is_empty() { r.pick(&HOLDERS) } else { r.pick(&timed) };
                Commit { kind: CommitKind::Role, parts: vec![role_part(thing, EdgeWrite::role(holder, None))], ..base(id, author, ts) }
            } else if sub < 87 {
                // a link redemption: L invite-grants a node on K, single use removing L's edge
                let holder = r.below(NODES) as NodeId;
                let mut parts = vec![role_part(LINK_K, EdgeWrite::role(holder, Some(r.pick(&[Role::Read, Role::Write]))))];
                if r.chance(50) {
                    parts.push(role_part(LINK_K, EdgeWrite::role(LINK_L, None)));
                }
                Commit { kind: CommitKind::Role, parts, ..base(id, LINK_L, ts) }
            } else {
                // a grant by the record chain's node
                let e = EdgeWrite::role(r.pick(&HOLDERS), Some(r.pick(&[Role::Read, Role::Write, Role::Admin])));
                Commit { kind: CommitKind::Role, parts: vec![role_part(thing, e)], ..base(id, chief, ts) }
            }
        } else if roll < 23 && !commits.is_empty() {
            let aspect = r.pick(&ASPECTS);
            let h = prefix(author);
            let o = evaluate(&h);
            // a snapshot carries writes of expiring deltas value-less (spec/crdt.md §8)
            let f = snapshot_state(&h, &o, thing, aspect);
            let retention = snapshot_retention(&h, thing, aspect, &f);
            Commit { kind: CommitKind::Snapshot, parts: vec![plain_part(thing, aspect, retention, Delta::Writes(f))], ..base(id, author, ts) }
        } else if roll < 31 && !commits.is_empty() {
            // a creation's purge ends the thing: drawn less often
            let mut target = commits[r.below(commits.len() as u64) as usize].clone();
            if creates(&target) && !r.chance(30) {
                target = commits[r.below(commits.len() as u64) as usize].clone();
            }
            let tp = target.parts[0].clone();
            let item = match r.below(3) {
                0 => PurgeItem::Commit { commit: target.id, thing: tp.thing, aspect: tp.aspect },
                1 => PurgeItem::Aspect { thing: tp.thing, aspect: tp.aspect },
                _ => PurgeItem::Author { thing: tp.thing, aspect: tp.aspect, author: target.actor },
            };
            let ws = set(ts, id, r.below(5) as i64);
            // the chief, else often a node an edge names on the thing: a grant or demotion between
            // the delta and the request decides its right (judged at the request, spec/permissions.md §6)
            let granted: Vec<NodeId> = commits
                .iter()
                .filter(|c| c.kind == CommitKind::Role && c.ts > target.ts)
                .flat_map(|c| c.parts.iter())
                .filter_map(|p| match &p.body {
                    Body::Held(Delta::Edge(e)) if p.thing == tp.thing && e.holder < NODES as NodeId => Some(e.holder),
                    _ => None,
                })
                .collect();
            let author = match CONTENT.iter().find(|x| x.0 == tp.thing) {
                Some(&(_, chief)) if r.chance(50) => chief,
                _ if !granted.is_empty() && r.chance(60) => r.pick(&granted),
                _ => author,
            };
            Commit { purge: vec![item], parts: vec![plain_part(tp.thing, PURGE, Retention::PLAIN, Delta::Writes(ws))], ..base(id, author, ts) }
        } else if roll < 34 {
            // a required retention setting for one aspect or every AK
            let aspect_ = r.pick(&[None, Some(REG.name), Some(MAP.name), Some(TEXT.name), Some(SET.name), Some(LIST.name), Some(SIG.name)]);
            let retention = r.pick(&retentions(w));
            let expiry = (retention.by != PurgeBy::Nobody && r.chance(20)).then(|| (1 + r.below(3)) * HOUR);
            let d = Delta::Required(vec![Rule { aspect: aspect_, retention, expiry, r#final: false }]);
            Commit { parts: vec![plain_part(thing, Aspect::REQUIRED, Retention::FIXED, d)], ..base(id, chief, ts) }
        } else {
            let undone = (roll < 44)
                .then(|| {
                    // a one-part signal commit has nothing to undo (spec/crdt.md §4.6)
                    let cands: Vec<CommitId> = commits.iter().filter(|c| c.kind == CommitKind::Content && c.purge.is_empty() && !creates(c) && !c.parts.iter().any(|p| p.aspect.signal)).map(|c| c.id).collect();
                    (!cands.is_empty()).then(|| r.pick(&cands)).and_then(|t| crate::undo::undo(&prefix(author), t, id, ts, author))
                })
                .flatten();
            match undone {
                Some(u) => u,
                None => {
                    let aspect = r.pick(&WRITTEN);
                    // the writer's view: every body written on the aspect so far
                    let prior = join(commits.iter().flat_map(|c| c.parts.iter()).filter(|p| p.thing == thing && p.aspect == aspect).filter_map(|p| match &p.body {
                        Body::Held(Delta::Writes(f)) => Some(f.clone()),
                        _ => None,
                    }));
                    let ws = if aspect.signal { set(ts, id, r.below(5) as i64) } else { content(&mut r, aspect, ts, id, &prior) };
                    let mut retention = if aspect.signal { r.pick(&signal_retentions(w)) } else { r.pick(&retentions(w)) };
                    let mut expires = (r.chance(15) && retention.by != PurgeBy::Nobody).then(|| w + (1 + r.below(4)) * HOUR);
                    // half the writers follow the required retention they hold
                    if r.chance(50) {
                        let req = commits.iter().filter(|c| c.ts < ts).flat_map(|c| c.parts.iter().map(move |p| (c, p))).filter_map(|(c, p)| match &p.body {
                            Body::Held(Delta::Required(rules)) if p.thing == thing => Some((c.ts, rules.clone())),
                            _ => None,
                        });
                        if let Some((_, rules)) = req.max_by_key(|x| x.0) {
                            let e = rules.iter().find(|x| x.aspect == Some(aspect.name)).or_else(|| rules.iter().find(|x| x.aspect.is_none()));
                            // a signal declares keep history
                            if let Some(e) = e.filter(|e| !aspect.signal || e.retention.keeps()) {
                                retention = e.retention;
                                expires = e.expiry.map(|d| w + d);
                            }
                        }
                    }
                    // node 2 acts for its account on the account's thing half the time
                    let actor = if thing == 12 && author == 2 && r.chance(50) { ACCOUNT } else { author };
                    Commit { expires, actor, parts: vec![plain_part(thing, aspect, retention, Delta::Writes(ws))], ..base(id, author, ts) }
                }
            }
        };
        let author = c.author;
        let content = c.kind == CommitKind::Content;
        commits.push(c);
        // a writer applying a kill of a purge-on-replace body it holds covers it in that transaction
        // (spec/commits.md §5): the author does so most of the time (a lapse leaves it to others)
        if content && r.chance(80) {
            let h = Held { now: w, me: author, records: RECORDS.to_vec(), commits: commits.clone(), dots: vec![] };
            let o = evaluate(&h);
            let owed: BTreeSet<(ThingId, Aspect)> = o.owed.iter().map(|&(c, i)| { let p = &h.commits.iter().find(|x| x.id == c).unwrap().parts[i]; (p.thing, p.aspect) }).collect();
            for (thing, aspect) in owed {
                logical += 1;
                let id = new_id(&mut r);
                commits.push(cover(&h, &o, thing, aspect, id, w * MS + logical));
            }
        }
    }
    for c in commits.iter_mut().filter(|c| !creates(c)) {
        for p in &mut c.parts {
            if r.chance(10) {
                p.body = Body::Missing;
            } else if r.chance(2) {
                p.body = Body::Parked;
            }
        }
    }
    let mut records = RECORDS.to_vec();
    if r.chance(5) {
        let gone = r.pick(&[3, ACCOUNT, 12, 13, LINK_K, LINK_L]);
        records.retain(|t| t.id != gone);
        commits.retain(|c| c.id != CREATION_ID + gone);
    }
    Held { now: w + r.below(13) * HOUR / 2, me: r.below(NODES) as NodeId, records, commits, dots: vec![] }
}

/// A random content write on `aspect` from the writer's view `prior` (crdt-model's ops, now and
/// then a root reset or a replace).
fn content(r: &mut Rng, aspect: Aspect, ts: u64, id: CommitId, prior: &Frag) -> Frag {
    let ty = ty(aspect).expect("a generated aspect");
    let mut w = Writer::new(commit_source(id), ts, 1);
    let mut cr = crdt_model::gen::Rng(r.next() | 1);
    match r.below(10) {
        0 => ops::remove(&mut w, ty.enc()),
        1 => ops::replace(&mut w, &ty, &crdt_model::gen::random_value(&mut cr, &ty, 0)),
        _ => crdt_model::gen::random_op(&mut cr, &mut w, &ty, Some(prior)).unwrap_or_else(|| ops::create(&mut w, &ty, &crdt_model::gen::random_value(&mut cr, &ty, 0))),
    }
}

/// The same held set in another order: commits, records, frontiers.
pub fn shuffle(h: &Held, seed: u64) -> Held {
    let mut r = Rng::new(seed);
    let mut n = h.clone();
    r.shuffle(&mut n.commits);
    r.shuffle(&mut n.records);
    for c in &mut n.commits {
        if let Some(f) = &mut c.frontier {
            r.shuffle(f);
        }
    }
    n
}
