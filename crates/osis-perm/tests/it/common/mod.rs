//! Test histories: nodes, things, commits with receipt times; frontiers derived from receipts
//! as the models do (a demoter at t covers what it received before t), commit-form dots.
#![allow(dead_code)]

use osis_core::{CommitId, CreationRecord, Role, Tid, Ts, WallMs};
use osis_perm::{Dots, Edge, EdgeOp, Frontier, MembershipCommit, MemoryHeldSet, RosterSnapshot, Tenure, WriteId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const LATE: u64 = 100_000;

pub fn ts(t: u64) -> Ts {
    Ts::make(WallMs(t), 0).unwrap()
}

pub fn cid(n: u32) -> CommitId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    b[31] = 1;
    CommitId(b)
}

pub fn edge(role: Role) -> Option<Edge> {
    Some(Edge::new(role))
}

pub fn edge_inv(role: Role, invite: Option<Role>, until: Option<u64>) -> Option<Edge> {
    Some(Edge { role, until: until.map(WallMs), invite, since: None })
}

/// `n` key-actor records whose tids sort in index order (models order authors by index).
pub fn key_actors(n: usize, salt: u8) -> Vec<(Tid, CreationRecord)> {
    let mut v: Vec<(Tid, CreationRecord)> = (0..n)
        .map(|i| {
            let mut nonce = [salt; 32];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let rec = CreationRecord::KeyActor { alg: 1, public_key: vec![i as u8; 32], nonce };
            (rec.tid(), rec)
        })
        .collect();
    v.sort_by_key(|(t, _)| *t);
    v
}

pub fn thing_record(owner: Tid, i: u64) -> (Tid, CreationRecord) {
    let mut nonce = [7u8; 32];
    nonce[..8].copy_from_slice(&i.to_be_bytes());
    let rec = CreationRecord::Thing { owner, nonce };
    (rec.tid(), rec)
}

#[derive(Clone, Debug)]
pub struct CSpec {
    pub id: CommitId,
    pub author: Tid,
    pub t: u64,
    pub ops: Vec<(Tid, Tid, Option<Edge>)>,
    pub recv: BTreeMap<Tid, u64>,
}

/// A ledger key (t, node, commit ID); `None`: the commit of that node at t (`World::key`).
pub type KeySpec = (u64, Tid, Option<CommitId>);
/// A ledger entry: (member, role, since, until, audited).
pub type LedgerSpec = (Tid, Role, Option<KeySpec>, KeySpec, bool);

#[derive(Clone, Debug)]
pub struct SSpec {
    pub id: CommitId,
    pub author: Tid,
    pub t: u64,
    pub thing: Tid,
    pub roster: BTreeMap<Tid, Edge>,
    /// (member, role, since, until); the tenure's frontier is the until node's receipts before
    /// the until time; `audited: false` leaves it without one.
    pub ledger: Vec<LedgerSpec>,
    pub recv: BTreeMap<Tid, u64>,
}

/// A history under construction.
#[derive(Clone, Debug, Default)]
pub struct World {
    pub created: BTreeMap<Tid, CreationRecord>,
    pub commits: Vec<CSpec>,
    pub snaps: Vec<SSpec>,
    /// Roster snapshots added verbatim (produced by perm).
    pub raw: Vec<RosterSnapshot>,
    next: u32,
}

impl World {
    pub fn new() -> World {
        World { next: 1000, ..Default::default() }
    }
    /// `n` nodes (key actors), tids in index order.
    pub fn nodes(&mut self, n: usize) -> Vec<Tid> {
        self.nodes_salted(n, 1)
    }
    /// Nodes distinct from those of another salt.
    pub fn nodes_salted(&mut self, n: usize, salt: u8) -> Vec<Tid> {
        key_actors(n, salt).into_iter().map(|(t, r)| {
            self.created.insert(t, r);
            t
        }).collect()
    }
    pub fn thing(&mut self, owner: Tid) -> Tid {
        let (t, r) = thing_record(owner, self.created.len() as u64 ^ u64::from(owner.as_bytes()[0]) << 32);
        self.created.insert(t, r);
        t
    }
    /// Both worlds' records in one (their tids and IDs must not collide).
    pub fn merge(&mut self, o: World) {
        self.created.extend(o.created);
        self.commits.extend(o.commits);
        self.snaps.extend(o.snaps);
        self.raw.extend(o.raw);
    }
    pub fn fresh_id(&mut self) -> CommitId {
        self.next += 1;
        cid(self.next)
    }
    /// A commit; `recv`: receipt times by node (author: its own t; others LATE).
    pub fn commit(&mut self, author: Tid, t: u64, ops: &[(Tid, Tid, Option<Edge>)], recv: &[(Tid, u64)]) -> CommitId {
        let id = self.fresh_id();
        let mut r: BTreeMap<Tid, u64> = recv.iter().copied().collect();
        r.insert(author, t);
        self.commits.push(CSpec { id, author, t, ops: ops.to_vec(), recv: r });
        id
    }
    /// A commit with a chosen ID.
    pub fn commit_id(&mut self, id: CommitId, author: Tid, t: u64, ops: &[(Tid, Tid, Option<Edge>)], recv: &[(Tid, u64)]) {
        let mut r: BTreeMap<Tid, u64> = recv.iter().copied().collect();
        r.insert(author, t);
        self.commits.push(CSpec { id, author, t, ops: ops.to_vec(), recv: r });
    }
    /// A content commit (no edge writes): only its receipts matter, for frontiers. Returns its
    /// point.
    pub fn content(&mut self, author: Tid, t: u64, recv: &[(Tid, u64)]) -> osis_perm::Point {
        let id = self.commit(author, t, &[], recv);
        osis_perm::Point { ts: ts(t), node: author, commit: id }
    }
    /// One edge write: `member`'s edge on `target`.
    pub fn set(&mut self, author: Tid, target: Tid, member: Tid, e: Option<Edge>, t: u64, recv: &[(Tid, u64)]) -> CommitId {
        self.commit(author, t, &[(target, member, e)], recv)
    }
    pub fn snapshot(&mut self, author: Tid, thing: Tid, roster: &[(Tid, Edge)], t: u64, recv: &[(Tid, u64)]) -> CommitId {
        self.snapshot_l(author, thing, roster, &[], t, recv)
    }
    pub fn snapshot_l(
        &mut self,
        author: Tid,
        thing: Tid,
        roster: &[(Tid, Edge)],
        ledger: &[LedgerSpec],
        t: u64,
        recv: &[(Tid, u64)],
    ) -> CommitId {
        let id = self.fresh_id();
        self.snapshot_id(id, author, thing, roster, ledger, t, recv)
    }
    /// A roster snapshot with a chosen ID.
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot_id(
        &mut self,
        id: CommitId,
        author: Tid,
        thing: Tid,
        roster: &[(Tid, Edge)],
        ledger: &[LedgerSpec],
        t: u64,
        recv: &[(Tid, u64)],
    ) -> CommitId {
        let mut r: BTreeMap<Tid, u64> = recv.iter().copied().collect();
        r.insert(author, t);
        self.snaps.push(SSpec { id, author, t, thing, roster: roster.iter().copied().collect(), ledger: ledger.to_vec(), recv: r });
        id
    }

    /// A roster snapshot carrying a produced state, received by everyone at once.
    pub fn snapshot_state(&mut self, author: Tid, thing: Tid, state: osis_perm::RosterState, t: u64) -> CommitId {
        let id = self.fresh_id();
        self.raw.push(RosterSnapshot { id, ts: ts(t), author, actor: author, thing, dots: Dots::Commit, roster: state.roster, ledger: state.ledger });
        id
    }

    /// Without `thing`'s edge writes and roster snapshots other than `keep` (a node that
    /// compacted `thing` at `keep`).
    /// A commit that also writes other things keeps those writes.
    pub fn compacted(&self, thing: Tid, keep: CommitId) -> MemoryHeldSet {
        let mut w = self.clone();
        for c in &mut w.commits {
            c.ops.retain(|o| o.0 != thing);
        }
        let mut skip: BTreeSet<CommitId> = self.commits.iter().filter(|c| c.ops.iter().all(|o| o.0 == thing) && !c.ops.is_empty()).map(|c| c.id).collect();
        skip.extend(self.snaps.iter().filter(|s| s.thing == thing && s.id != keep).map(|s| s.id));
        skip.extend(self.raw.iter().filter(|s| s.thing == thing && s.id != keep).map(|s| s.id));
        w.held_without(&skip)
    }

    fn recv_of(&self, id: &CommitId) -> Option<&BTreeMap<Tid, u64>> {
        self.commits.iter().find(|c| c.id == *id).map(|c| &c.recv).or_else(|| self.snaps.iter().find(|s| s.id == *id).map(|s| &s.recv))
    }

    /// Frontier of a demoter `node` at `t`: every commit it received before `t`.
    pub fn frontier(&self, node: Tid, t: u64) -> Frontier {
        let mut f = Frontier::default();
        for (id, r) in self.commits.iter().map(|c| (c.id, &c.recv)).chain(self.snaps.iter().map(|s| (s.id, &s.recv))) {
            if r.get(&node).copied().unwrap_or(LATE) < t {
                f.commits.insert(id);
            }
        }
        f
    }

    /// A ledger key; without a commit ID, that of `node`'s commit at `t` (the first by ID;
    /// the zero commit ID if none).
    pub fn key(&self, (t, node, commit): KeySpec) -> osis_perm::Point {
        let ids = self.commits.iter().map(|c| (c.id, c.author, c.t)).chain(self.snaps.iter().map(|s| (s.id, s.author, s.t)));
        let found = || ids.filter(|&(_, a, ct)| a == node && ct == t).map(|x| x.0).min().unwrap_or(CommitId([0; 32]));
        osis_perm::Point { ts: ts(t), node, commit: commit.unwrap_or_else(found) }
    }

    /// The held set, every commit carrying the frontier its receipts imply.
    pub fn held(&self) -> MemoryHeldSet {
        self.held_without(&BTreeSet::new())
    }

    pub fn held_without(&self, skip: &BTreeSet<CommitId>) -> MemoryHeldSet {
        let mut h = MemoryHeldSet::new();
        for (t, r) in &self.created {
            h.created.insert(*t, r.clone());
        }
        for c in self.commits.iter().filter(|c| !skip.contains(&c.id)) {
            h.add_commit(MembershipCommit {
                id: c.id,
                ts: ts(c.t),
                author: c.author,
                actor: c.author,
                frontier: Some(Arc::new(self.frontier(c.author, c.t))),
                ops: c.ops.iter().map(|&(target, member, edge)| EdgeOp { target, member, edge, dots: Dots::Commit }).collect(),
            });
        }
        for s in self.raw.iter().filter(|s| !skip.contains(&s.id)) {
            h.add_snapshot(s.clone());
        }
        for s in self.snaps.iter().filter(|s| !skip.contains(&s.id)) {
            let ledger = s
                .ledger
                .iter()
                .map(|&(member, role, since, until, audited)| Tenure {
                    member,
                    role,
                    since: since.map(|k| self.key(k)),
                    until: self.key(until),
                    frontier: audited.then(|| Arc::new(self.frontier(until.1, until.0))),
                })
                .collect();
            h.add_snapshot(RosterSnapshot { id: s.id, ts: ts(s.t), author: s.author, actor: s.author, thing: s.thing, dots: Dots::Commit, roster: s.roster.clone(), ledger });
        }
        h
    }
}

/// Sticky residue (notes/permissions.md, models/tla/membership M2): the drops whose cause R is
/// not, in the settled walk, an applied fall of the dropped write's author X on its target N
/// past the write's class (R was dropped, or with the write dropped R is no fall, or not
/// through that class). The write's class is X's class on N just before it in the settled
/// walk. They stay dropped since D only grows, so the answer depends on the order drops were
/// found, and a roster snapshot can repair them.
pub fn residue(tl: &osis_perm::Timeline) -> BTreeSet<WriteId> {
    let by = |w: &WriteId| match w {
        WriteId::Op(c, k) => tl.membership_commit(c).and_then(|m| Some((m.author, m.ops.get(usize::try_from(*k).ok()?)?.target, m.point()))),
        WriteId::Snapshot(c) => tl.roster_snapshot(c).map(|s| (s.author, s.thing, s.point())),
    };
    let audits = |w: &WriteId, p: &osis_perm::Point| {
        let Some((x, n, at)) = by(w) else { return false };
        let class = tl.class(&x, &n, osis_perm::At::before(at));
        tl.falls(&x, &n).iter().any(|f| f.point == *p && f.now < class && class <= f.held)
    };
    tl.dropped().iter().filter(|(w, p)| !audits(w, p)).map(|(w, _)| *w).collect()
}

/// Whether `tl` has sticky residue (`residue`).
pub fn sticky_residue(tl: &osis_perm::Timeline) -> bool {
    !residue(tl).is_empty()
}

/// The commit IDs of dropped writes.
pub fn dropped_commits(tl: &osis_perm::Timeline) -> BTreeSet<CommitId> {
    tl.dropped().keys().map(WriteId::commit).collect()
}

fn model_role(r: membership_model::Role) -> Option<Role> {
    match r {
        membership_model::Role::None => None,
        membership_model::Role::Read => Some(Role::Read),
        membership_model::Role::Write => Some(Role::Write),
        membership_model::Role::Admin => Some(Role::Admin),
    }
}

/// A joint-model history as a world (genesis: writes by the top key actor at t=0).
pub fn joint_world(h: &membership_model::joint::JHist, salt: u8) -> (World, Vec<Tid>, Vec<Tid>) {
    use membership_model::joint::Owner;
    let mut w = World::new();
    w.next = 1000 + u32::from(salt) * 100_000;
    let nodes = w.nodes_salted(h.nodes, salt);
    let (mut actors, mut top): (Vec<Tid>, Vec<Tid>) = (Vec::new(), Vec::new());
    for o in &h.owners {
        let (owner, tp) = match *o {
            Owner::Node(n) => (nodes[n], nodes[n]),
            Owner::Actor(y) => (actors[y], top[y]),
        };
        actors.push(w.thing(owner));
        top.push(tp);
    }
    let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    for (m, row) in h.genesis.iter().enumerate() {
        for (x, &r) in row.iter().enumerate() {
            if let Some(r) = model_role(r) {
                w.set(top[x], actors[x], ent(m), Some(Edge::new(r)), 0, &all0);
            }
        }
    }
    for (i, jw) in h.writes.iter().enumerate() {
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
        let mut id = cid(jw.id);
        id.0[30] = salt;
        w.commit_id(id, nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.member), model_role(jw.role).map(Edge::new))], &recv);
    }
    (w, nodes, actors)
}

/// An edges-model history as a world: node 0 owns the one target.
pub fn edges_world(h: &membership_model::edges::EHist, salt: u8) -> (World, Vec<Tid>, Tid) {
    use membership_model::edges::{Edge as MEdge, NEVER};
    let mut w = World::new();
    w.next = 1000 + u32::from(salt) * 100_000;
    let nodes = w.nodes_salted(h.n(), salt);
    let t = w.thing(nodes[0]);
    let me = |e: Option<MEdge>| {
        e.map(|e| Edge { role: model_role(e.role).unwrap_or(Role::Read), until: (e.until != NEVER).then_some(WallMs(e.until as u64)), invite: model_role(e.invite), since: None })
    };
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    for (x, e) in h.genesis.iter().enumerate().skip(1) {
        if e.is_some() {
            w.set(nodes[0], t, nodes[x], me(*e), 0, &all0);
        }
    }
    for (i, ew) in h.writes.iter().enumerate() {
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
        let ops: Vec<(Tid, Tid, Option<Edge>)> = ew.ops.iter().map(|&(x, e)| (t, nodes[x], me(e))).collect();
        let mut id = cid(ew.id);
        id.0[30] = salt;
        w.commit_id(id, nodes[ew.author], ew.t as u64, &ops, &recv);
    }
    (w, nodes, t)
}

pub fn gen_id(n: usize) -> CommitId {
    let mut c = cid(n as u32);
    c.0[31] = 2;
    c
}

/// A snapshot-model history: key actor K (node 0) owns P, P owns G; genesis edges are K's
/// writes at t=0; records (layer 2) are left out; writes on G for K are inert in the model and
/// left out too.
pub struct SnapWorld {
    pub w: World,
    pub nodes: Vec<Tid>,
    pub p: Tid,
    pub g: Tid,
    /// Model write index -> commit ID (None: left out).
    pub ids: Vec<Option<CommitId>>,
}

pub fn snap_world(h: &membership_model::snapshot::SHist) -> SnapWorld {
    use membership_model::snapshot::Thing;
    let mut w = World::new();
    let nodes = w.nodes(h.n());
    let k = nodes[0];
    let p = w.thing(k);
    let g = w.thing(p);
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    let mut gi = 0;
    for (thing, roles) in [(p, &h.gp), (g, &h.gg)] {
        for (x, &r) in roles.iter().enumerate().skip(1) {
            if let Some(r) = model_role(r) {
                gi += 1;
                w.commit_id(gen_id(gi), k, 0, &[(thing, nodes[x], Some(Edge::new(r)))], &all0);
            }
        }
    }
    // the model's write id stands for the commit ID (0: no write)
    let mid = |id: usize| if id == 0 { CommitId([0; 32]) } else { cid(id as u32) };
    let key = |k: (u32, usize, usize)| (k.0 as u64, nodes[k.1], Some(mid(k.2)));
    let mut ids = Vec::new();
    for (i, sw) in h.writes.iter().enumerate() {
        let thing = if sw.thing == Thing::P { p } else { g };
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
        if sw.rec || (sw.snap.is_none() && sw.target == 0) {
            ids.push(None);
            continue;
        }
        let author = nodes[sw.author];
        let id = match &sw.snap {
            None => {
                let id = mid(sw.id);
                w.commit_id(id, author, sw.t as u64, &[(thing, nodes[sw.target], model_role(sw.role).map(Edge::new))], &recv);
                id
            }
            Some(roster) => {
                let mut r: Vec<(Tid, Edge)> = Vec::new();
                for (x, &rl) in roster.iter().enumerate().skip(1) {
                    if let Some(rl) = model_role(rl) {
                        let open = sw.ledger.iter().find(|e| e.member == x && e.until.is_none());
                        let since = open.and_then(|e| e.since).map(|k| w.key(key(k)));
                        r.push((nodes[x], Edge { since: if rl == Role::Admin { since } else { None }, ..Edge::new(rl) }));
                    }
                }
                let ledger: Vec<_> = sw.ledger.iter().filter_map(|e| e.until.map(|u| (nodes[e.member], Role::Admin, e.since.map(key), key(u), true))).collect();
                w.snapshot_id(mid(sw.id), author, thing, &r, &ledger, sw.t as u64, &recv)
            }
        };
        ids.push(Some(id));
    }
    SnapWorld { w, nodes, p, g, ids }
}


/// A random run's seed: `seed`, or `seed` xor `OSIS_PERM_SEED` (decimal) to sample other
/// histories (`OSIS_PERM_SEED=1 cargo test --workspace -- --ignored`).
pub fn seeded(seed: u64) -> u64 {
    match std::env::var("OSIS_PERM_SEED") {
        Ok(v) => seed ^ v.parse::<u64>().unwrap_or_else(|_| panic!("OSIS_PERM_SEED={v:?} is not a decimal u64")),
        Err(_) => seed,
    }
}
