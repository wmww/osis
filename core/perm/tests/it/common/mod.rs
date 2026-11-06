//! Test histories: nodes, things, commits with receipt times; frontiers derived from receipts
//! as the models do (a demoter at t covers what it received before t), commit-form dots.
#![allow(dead_code)]

use osis_base::{CommitId, CreationRecord, Role, Tid, Ts, WallMs};
use osis_perm::{Edge, EdgeOp, Frontier, RoleCommit, MemoryHeldSet, WriteId};
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
    Some(Edge { role, until: until.map(WallMs), invite, tied: None })
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

pub fn thing_record(admin: Tid, i: u64) -> (Tid, CreationRecord) {
    let mut nonce = [7u8; 32];
    nonce[..8].copy_from_slice(&i.to_be_bytes());
    let rec = CreationRecord::Thing { admin, nonce };
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

/// A history under construction.
#[derive(Clone, Debug, Default)]
pub struct World {
    pub created: BTreeMap<Tid, CreationRecord>,
    pub commits: Vec<CSpec>,
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
    /// A thing whose first admin is `admin`.
    pub fn thing(&mut self, admin: Tid) -> Tid {
        let (t, r) = thing_record(admin, self.created.len() as u64 ^ u64::from(admin.as_bytes()[0]) << 32);
        self.created.insert(t, r);
        t
    }
    /// Both worlds' records in one (their tids and IDs must not collide).
    pub fn merge(&mut self, o: World) {
        self.created.extend(o.created);
        self.commits.extend(o.commits);
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
    /// One edge write: `holder`'s edge on `target`.
    pub fn set(&mut self, author: Tid, target: Tid, holder: Tid, e: Option<Edge>, t: u64, recv: &[(Tid, u64)]) -> CommitId {
        self.commit(author, t, &[(target, holder, e)], recv)
    }
    /// Frontier of a demoter `node` at `t`: every commit it received before `t`.
    pub fn frontier(&self, node: Tid, t: u64) -> Frontier {
        let mut f = Frontier::default();
        for c in &self.commits {
            if c.recv.get(&node).copied().unwrap_or(LATE) < t {
                f.commits.insert(c.id);
            }
        }
        f
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
            h.add_commit(RoleCommit {
                id: c.id,
                ts: ts(c.t),
                author: c.author,
                actor: c.author,
                frontier: Some(Arc::new(self.frontier(c.author, c.t))),
                ops: c.ops.iter().map(|&(target, holder, edge)| EdgeOp { target, holder, edge }).collect(),
            });
        }
        h
    }
}

/// Sticky residue (notes/permissions.md, core/test/tla/roles M2): the drops whose cause R is
/// not, in the settled walk, an applied fall of the dropped write's author X on its target N
/// past the write's class (R was dropped, or with the write dropped R is no fall, or not
/// through that class). The write's class is X's class on N just before it in the settled
/// walk; a self-removal through a holder (§2: X's admin on the holder is its only authority)
/// is audited on the holder, by X's class there (§5.1 step 3). They stay dropped since D only
/// grows, so the answer depends on the order drops were found.
pub fn residue(tl: &osis_perm::Timeline) -> BTreeSet<WriteId> {
    let by = |w: &WriteId| tl.role_commit(&w.0).and_then(|m| Some((m.author, m.ops.get(usize::try_from(w.1).ok()?)?.target, m.point())));
    // the thing whose class fall audits w: the holder for a self-removal through it
    let audited_on = |w: &WriteId, target: Tid| {
        let Some(m) = tl.role_commit(&w.0) else { return target };
        let Some(op) = m.ops.get(usize::try_from(w.1).unwrap_or(usize::MAX)) else { return target };
        let at = osis_perm::At::before(m.point());
        let old = tl.edges_at(Some(m.point())).get(&op.holder, &op.target).copied();
        let class = tl.class(&m.author, &op.target, at);
        let through = op.holder != m.author && osis_perm::types::lowers(op.edge.as_ref(), old.as_ref()) && tl.role(&m.author, &op.holder, at) == Some(Role::Admin) && class != osis_perm::Class::Edge;
        if through { op.holder } else { target }
    };
    let audits = |w: &WriteId, p: &osis_perm::Point| {
        let Some((x, t, at)) = by(w) else { return false };
        let n = audited_on(w, t);
        let class = tl.class(&x, &n, osis_perm::At::before(at));
        tl.falls(&x, &n).iter().any(|f| f.point == *p && f.now < class && class <= f.held)
    };
    tl.dropped().iter().filter(|(w, p)| !audits(w, p)).map(|(w, _)| *w).collect()
}

/// Whether `tl` has sticky residue (`residue`).
pub fn sticky_residue(tl: &osis_perm::Timeline) -> bool {
    !residue(tl).is_empty()
}

pub fn model_role(r: roles_model::Role) -> Option<Role> {
    match r {
        roles_model::Role::None => None,
        roles_model::Role::Read => Some(Role::Read),
        roles_model::Role::Write => Some(Role::Write),
        roles_model::Role::Admin => Some(Role::Admin),
    }
}

/// A joint-model history's actors in `w` (nodes `nodes`): their tids (each one's record names
/// its first admin, `JHist::admins`) and the key actor at the top of each one's record chain.
/// The model's other genesis edges are writes by that key actor at t=0 (`joint_genesis`, from
/// `ids` when given); the record edge is in force by the record alone.
pub fn joint_actors(w: &mut World, h: &roles_model::joint::JHist, nodes: &[Tid]) -> (Vec<Tid>, Vec<Tid>) {
    let (mut actors, mut top): (Vec<Tid>, Vec<Tid>) = (Vec::new(), Vec::new());
    for &a in &h.admins {
        let (t, tp) = if a < h.nodes { (w.thing(nodes[a]), nodes[a]) } else { (w.thing(actors[a - h.nodes]), top[a - h.nodes]) };
        actors.push(t);
        top.push(tp);
    }
    (actors, top)
}

/// The genesis edges of `h` but the record edges as writes by the top key actors at t=0
/// (`joint_actors`), commit IDs from `id` when given.
pub fn joint_genesis(w: &mut World, h: &roles_model::joint::JHist, nodes: &[Tid], actors: &[Tid], top: &[Tid], id: Option<&dyn Fn(usize) -> CommitId>) {
    let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    let mut g = 0;
    for (m, row) in h.genesis.iter().enumerate() {
        for (x, &r) in row.iter().enumerate() {
            if h.admins[x] == m {
                continue;
            }
            let (Some(r), tp) = (model_role(r), top[x]) else { continue };
            g += 1;
            match id {
                Some(f) => w.commit_id(f(g), tp, 0, &[(actors[x], ent(m), Some(Edge::new(r)))], &all0),
                None => {
                    w.set(tp, actors[x], ent(m), Some(Edge::new(r)), 0, &all0);
                }
            }
        }
    }
}

/// A joint-model history as a world (genesis: writes by the top key actor at t=0).
pub fn joint_world(h: &roles_model::joint::JHist, salt: u8) -> (World, Vec<Tid>, Vec<Tid>) {
    let mut w = World::new();
    w.next = 1000 + u32::from(salt) * 100_000;
    let nodes = w.nodes_salted(h.nodes, salt);
    let (actors, top) = joint_actors(&mut w, h, &nodes);
    joint_genesis(&mut w, h, &nodes, &actors, &top, None);
    let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
    for (i, jw) in h.writes.iter().enumerate() {
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
        let mut id = cid(jw.id);
        id.0[30] = salt;
        w.commit_id(id, nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.holder), model_role(jw.role).map(Edge::new))], &recv);
    }
    (w, nodes, actors)
}

/// An edges-model edge value (some marked tied: carried, never an authority).
pub fn model_edge(e: Option<roles_model::edges::Edge>) -> Option<Edge> {
    use roles_model::edges::NEVER;
    e.map(|e| Edge { role: model_role(e.role).unwrap_or(Role::Read), until: (e.until != NEVER).then_some(WallMs(e.until as u64)), invite: model_role(e.invite), tied: tie_if((e.until ^ e.role as u32 ^ e.invite as u32) & 1 == 1) })
}

/// An edges-model history as a world: node 0 is the one target's first admin; the other
/// genesis edges are its writes at t=0.
pub fn edges_world(h: &roles_model::edges::EHist, salt: u8) -> (World, Vec<Tid>, Tid) {
    let mut w = World::new();
    w.next = 1000 + u32::from(salt) * 100_000;
    let nodes = w.nodes_salted(h.n(), salt);
    let t = w.thing(nodes[0]);
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    for (x, e) in h.genesis.iter().enumerate().skip(1) {
        if e.is_some() {
            w.set(nodes[0], t, nodes[x], model_edge(*e), 0, &all0);
        }
    }
    for (i, ew) in h.writes.iter().enumerate() {
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
        let ops: Vec<(Tid, Tid, Option<Edge>)> = ew.ops.iter().map(|&(x, e)| (t, nodes[x], model_edge(e))).collect();
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

/// A random run's seed: `seed`, or `seed` xor `OSIS_PERM_SEED` (decimal) to sample other
/// histories (`OSIS_PERM_SEED=1 cargo test -p osis-perm -- --ignored`).
pub fn seeded(seed: u64) -> u64 {
    osis_base::testenv::u64_var("OSIS_PERM_SEED").map_or(seed, |v| seed ^ v)
}

/// Tier-2 random runs are split into this many shards, each with its own seed (`shard_seed`);
/// fixed, so a failure's seed is the same on every machine.
pub const SHARDS: u64 = 16;

/// Shards running at once across every `sharded` run in the process: a thread per core
/// (`OSIS_PERM_THREADS` overrides), so concurrent tests share the cores instead of each
/// starting 16 busy threads.
fn shard_permits() -> &'static (std::sync::Mutex<usize>, std::sync::Condvar) {
    static P: std::sync::OnceLock<(std::sync::Mutex<usize>, std::sync::Condvar)> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        let n = osis_base::testenv::u64_var("OSIS_PERM_THREADS").map_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()), |n| n as usize);
        (std::sync::Mutex::new(n.max(1)), std::sync::Condvar::new())
    })
}

/// A held shard permit, returned on drop (a panicking shard included).
struct Permit;

impl Permit {
    fn take() -> Permit {
        let (m, cv) = shard_permits();
        let mut free = cv.wait_while(m.lock().unwrap_or_else(|e| e.into_inner()), |n| *n == 0).unwrap_or_else(|e| e.into_inner());
        *free -= 1;
        Permit
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let (m, cv) = shard_permits();
        *m.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        cv.notify_one();
    }
}

/// The seed of shard `i` of a run seeded `seed` (before `seeded`).
pub fn shard_seed(seed: u64, i: u64) -> u64 {
    seed ^ (i << 40)
}

/// Runs `run(samples, seed)` as `SHARDS` shards of `samples / SHARDS` (at least one) on
/// scoped threads, each running once it holds a permit (`shard_permits`), shard i seeded
/// `shard_seed(seed, i)`; returns their results in shard order. A panicking shard panics the
/// run (its message is printed by the shard's thread).
pub fn sharded<T: Send>(samples: u64, seed: u64, run: impl Fn(u64, u64) -> T + Sync) -> Vec<T> {
    let per = (osis_base::testenv::large_n(samples) / SHARDS).max(1);
    let run = &run;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..SHARDS)
            .map(|i| {
                s.spawn(move || {
                    let _p = Permit::take();
                    run(per, shard_seed(seed, i))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| panic!("a shard of seed {seed:#x} failed (message above)"))).collect()
    })
}

/// A tie for an edge the generators mark tied (carried, never an authority).
pub fn tie_if(on: bool) -> Option<osis_perm::Tie> {
    on.then_some(osis_perm::Tie { ts: Ts::default(), src: osis_perm::TieSource::Commit(osis_base::CommitId([3; 32])), ctr: 2, subgroup: false })
}
