//! Joint walk over several actors (spec/permissions.md §5.1): one timeline over every edge
//! write of every actor, ordered by (t, author node, commit ID). Nodes are key actors; each
//! actor is owned by a node or another actor; an edge (member: node or actor, target actor,
//! role). Effective role: max over paths of the min along the path, paths climbing edges and
//! owner links, computed as a fixpoint so mutual membership is fine. Class of a node on an
//! actor: owner chain (admin of an actor strictly above it in its owner chain, or the node at
//! the top), else edge admin (admin by any path), else none.
//!
//! A write applies iff its author has admin on the target (attributed to its class there) or
//! it is a self-removal (lowers the edge of a member the author has admin on; never audited,
//! audits nothing). After each applied write by A on edge (M, T), every other node X reaching
//! M whose class on an actor N reachable from T fell below its class with the edge restored
//! as if the member still held its role (the highest role the edge had since the last
//! explicit write on it, self-removals and A's own writes auditing nothing) has its
//! earlier applied writes on N attributed to a class in (new, held] audited by A's frontier
//! (A's receipts before t; A's chain writes, those setting the admin edges on A's admin paths
//! to the target, and the write itself count), and the walk restarts on
//! any drop. Drops are sticky. No invites, `until` or snapshots here (edges.rs, snapshot.rs).
//!
//! Checked (`cargo run --release [samples] joint`, `cargo test`): termination, input-order
//! independence (with commit-ID ties), nothing dropped with nobody offline.

use crate::{Rng, Role};
use std::collections::HashSet;

const LATE: u32 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    Node(usize),
    Actor(usize),
}

#[derive(Clone, Debug)]
pub struct JWrite {
    pub author: usize,
    pub t: u32,
    pub id: u32,
    pub target: usize,
    /// Member entity: nodes 0..nodes, actors nodes..nodes+actors.
    pub member: usize,
    pub role: Role,
}

#[derive(Clone, Debug)]
pub struct JHist {
    pub nodes: usize,
    pub owners: Vec<Owner>,
    /// [member entity][target actor].
    pub genesis: Vec<Vec<Role>>,
    pub writes: Vec<JWrite>,
    /// [write][node] receipt time; author: its own t.
    pub recv: Vec<Vec<u32>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Class {
    None,
    Edge,
    Chain,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attr {
    Skipped,
    SelfOnly,
    By(Class),
}

#[derive(Clone, Debug, PartialEq)]
pub struct JOut {
    pub edges: Vec<Vec<Role>>,
    pub roles: Vec<Vec<Role>>,
    /// Writes applied in the final walk (bit per write index).
    pub applied: u64,
    pub dropped: u64,
    pub passes: usize,
}

impl JHist {
    fn actors(&self) -> usize {
        self.owners.len()
    }

    pub fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| (self.writes[i].t, self.writes[i].author, self.writes[i].id));
        o
    }

    /// Effective roles [node][actor] given the edges.
    fn roles(&self, edges: &[Vec<Role>]) -> Vec<Vec<Role>> {
        let (nn, na) = (self.nodes, self.actors());
        let mut r = vec![vec![Role::None; na]; nn];
        loop {
            let mut changed = false;
            for n in 0..nn {
                for x in 0..na {
                    let mut v = edges[n][x];
                    match self.owners[x] {
                        Owner::Node(o) if o == n => v = Role::Admin,
                        Owner::Actor(y) => v = v.max(r[n][y]),
                        _ => {}
                    }
                    for y in 0..na {
                        v = v.max(r[n][y].min(edges[nn + y][x]));
                    }
                    if v > r[n][x] {
                        r[n][x] = v;
                        changed = true;
                    }
                }
            }
            if !changed {
                return r;
            }
        }
    }

    fn class(&self, r: &[Vec<Role>], n: usize, x: usize) -> Class {
        let mut o = self.owners[x];
        let mut seen = 0;
        while let Owner::Actor(y) = o {
            if r[n][y] == Role::Admin {
                return Class::Chain;
            }
            o = self.owners[y];
            seen += 1;
            assert!(seen <= self.actors(), "owner cycle");
        }
        if o == Owner::Node(n) {
            return Class::Chain;
        }
        if r[n][x] == Role::Admin {
            Class::Edge
        } else {
            Class::None
        }
    }

    /// A's chain writes for a write on actor x: the writes that set the admin edges on A's
    /// admin paths to x (spec/permissions.md §5.1, "A's own chain writes").
    fn chain_writes(&self, edges: &[Vec<Role>], r: &[Vec<Role>], set_by: &[Vec<Option<usize>>], a: usize, x: usize) -> Vec<usize> {
        let (nn, na) = (self.nodes, self.actors());
        let mut to = vec![false; nn + na];
        to[nn + x] = true;
        loop {
            let mut changed = false;
            for e in 0..nn + na {
                if to[e] {
                    continue;
                }
                let owns = |y: usize| match self.owners[y] {
                    Owner::Node(o) => o == e,
                    Owner::Actor(z) => nn + z == e,
                };
                if (0..na).any(|y| to[nn + y] && (edges[e][y] == Role::Admin || owns(y))) {
                    to[e] = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut out = vec![];
        for m in 0..nn + na {
            let admin = m == a || m >= nn && r[a][m - nn] == Role::Admin;
            for y in 0..na {
                if admin && edges[m][y] == Role::Admin && to[nn + y] {
                    out.extend(set_by[m][y]);
                }
            }
        }
        out
    }

    /// Entities reaching `m` (included) by edges of any role and owner links.
    fn reaching(&self, edges: &[Vec<Role>], m: usize) -> Vec<bool> {
        let (nn, na) = (self.nodes, self.actors());
        let mut v = vec![false; nn + na];
        v[m] = true;
        loop {
            let mut changed = false;
            for e in 0..nn + na {
                if v[e] {
                    continue;
                }
                let via_owner = |x: usize| match self.owners[x] {
                    Owner::Node(o) => o == e,
                    Owner::Actor(y) => nn + y == e,
                };
                if (0..na).any(|x| v[nn + x] && (edges[e][x] > Role::None || via_owner(x))) {
                    v[e] = true;
                    changed = true;
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// Entities reachable from `t` (included) by edges of any role and owner links.
    fn reachable(&self, edges: &[Vec<Role>], t: usize) -> Vec<bool> {
        let (nn, na) = (self.nodes, self.actors());
        let mut v = vec![false; nn + na];
        v[t] = true;
        loop {
            let mut changed = false;
            for x in 0..na {
                if v[nn + x] {
                    continue;
                }
                let owner = match self.owners[x] {
                    Owner::Node(o) => o,
                    Owner::Actor(y) => nn + y,
                };
                if v[owner] || (0..nn + na).any(|e| v[e] && edges[e][x] > Role::None) {
                    v[nn + x] = true;
                    changed = true;
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// Whether node a has admin on member entity m.
    fn admin_of(&self, r: &[Vec<Role>], a: usize, m: usize) -> bool {
        m == a || m >= self.nodes && r[a][m - self.nodes] == Role::Admin
    }

    /// §5.1: step 1 orders the writes; each pass is step 2 (apply iff the author has the
    /// authority), step 3 (attribute by class) and step 4 (a class fall audits with the
    /// demoter's frontier and restarts); step 5 returns the first pass adding nothing to D.
    pub fn eval(&self, audit: bool) -> JOut {
        let (nn, na) = (self.nodes, self.actors());
        let order = self.order();
        let mut dropped = 0u64;
        let mut passes = 0;
        'walk: loop {
            passes += 1;
            let mut edges = self.genesis.clone();
            let mut r = self.roles(&edges);
            // prior[m][x]: the highest role m's edge on x had since the last explicit write on
            // it (self-removals audit nothing); prior_self[(m, x, a)]: the same for a node a
            // that lowered it by its own write (an author is never audited).
            let mut prior: Vec<Vec<Role>> = vec![vec![Role::None; na]; nn + na];
            let mut prior_self: std::collections::HashMap<(usize, usize, usize), Role> = Default::default();
            let mut attr = vec![Attr::Skipped; self.writes.len()];
            // set_by[m][x]: the applied write that set m's current edge on x.
            let mut set_by: Vec<Vec<Option<usize>>> = vec![vec![None; na]; nn + na];
            for &i in &order {
                let w = &self.writes[i];
                let a = w.author;
                // An edge for the target's owner (node or actor) is no write: the owner is
                // implicitly admin and cannot be removed (spec/permissions.md §1).
                let owner_member = match self.owners[w.target] {
                    Owner::Node(o) => w.member == o,
                    Owner::Actor(y) => w.member == nn + y,
                };
                if dropped >> i & 1 == 1 || owner_member {
                    continue;
                }
                let old = edges[w.member][w.target];
                attr[i] = if w.role <= old && self.admin_of(&r, a, w.member) {
                    Attr::SelfOnly
                } else {
                    match self.class(&r, a, w.target) {
                        Class::None => continue,
                        c => Attr::By(c),
                    }
                };
                let chain_a = self.chain_writes(&edges, &r, &set_by, a, w.target);
                let own = self.reaching(&edges, w.member)[a];
                edges[w.member][w.target] = w.role;
                set_by[w.member][w.target] = Some(i);
                r = self.roles(&edges);
                let mut grew = false;
                let (m, t) = (w.member, w.target);
                if attr[i] == Attr::SelfOnly {
                    prior[m][t] = prior[m][t].max(old);
                    continue;
                }
                // An explicit write demotes x on n when x's class is lower than with the edge
                // restored as if the member still held its role (spec/permissions.md §5.1).
                let base = prior[m][t].max(old);
                prior[m][t] = Role::None;
                let (up, down) = (self.reaching(&edges, m), self.reachable(&edges, nn + t));
                for x in 0..nn {
                    let restored = base.max(prior_self.remove(&(m, t, x)).unwrap_or(Role::None));
                    if x == a {
                        if own {
                            prior_self.insert((m, t, a), restored);
                        }
                        continue;
                    }
                    if !up[x] || !audit {
                        continue;
                    }
                    let mut was = edges.clone();
                    was[m][t] = restored;
                    let rw = self.roles(&was);
                    for n in 0..na {
                        let (now, before) = (self.class(&r, x, n), self.class(&rw, x, n));
                        if !down[nn + n] || now >= before {
                            continue;
                        }
                        for j in 0..self.writes.len() {
                            let wj = &self.writes[j];
                            if j == i || wj.author != x || wj.target != n {
                                continue;
                            }
                            let Attr::By(c) = attr[j] else { continue };
                            if !(now < c && c <= before) {
                                continue;
                            }
                            let covered = self.recv[j][a] < w.t || chain_a.contains(&j);
                            if !covered {
                                dropped |= 1 << j;
                                grew = true;
                            }
                        }
                    }
                }
                if grew {
                    continue 'walk;
                }
            }
            let applied = (0..self.writes.len()).filter(|&j| attr[j] != Attr::Skipped).fold(0u64, |m, j| m | 1 << j);
            return JOut { edges, roles: r, applied, dropped, passes };
        }
    }

    fn permute(&self, perm: &[usize]) -> JHist {
        JHist {
            nodes: self.nodes,
            owners: self.owners.clone(),
            genesis: self.genesis.clone(),
            writes: perm.iter().map(|&i| self.writes[i].clone()).collect(),
            recv: perm.iter().map(|&i| self.recv[i].clone()).collect(),
        }
    }

    /// The result as a function of the write set: edges, roles, and which writes dropped.
    fn result(&self, o: &JOut) -> (Vec<Vec<Role>>, Vec<Vec<Role>>, Vec<u32>) {
        let mut ids: Vec<u32> = (0..self.writes.len()).filter(|&j| o.dropped >> j & 1 == 1).map(|j| self.writes[j].id).collect();
        ids.sort();
        (o.edges.clone(), o.roles.clone(), ids)
    }
}

/// The timeline of §5.1 with audits on.
pub fn walk(h: &JHist) -> JOut {
    h.eval(true)
}

// ---------- search ----------

#[derive(Default)]
pub struct Stats {
    histories: u64,
    max_passes: usize,
    order_dep: u64,
    honest_mismatch: u64,
    with_cycle: u64,
    with_tie: u64,
    ex_order: Option<JHist>,
    ex_honest: Option<JHist>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.histories += o.histories;
        self.max_passes = self.max_passes.max(o.max_passes);
        self.order_dep += o.order_dep;
        self.honest_mismatch += o.honest_mismatch;
        self.with_cycle += o.with_cycle;
        self.with_tie += o.with_tie;
        if self.ex_order.is_none() {
            self.ex_order = o.ex_order;
        }
        if self.ex_honest.is_none() {
            self.ex_honest = o.ex_honest;
        }
    }

    pub fn print(&self) {
        println!(
            "joint: {} histories ({} with mutual membership, {} with a (t, author) tie) | max passes {} | order-dependent {} | drops with nobody offline {}",
            self.histories, self.with_cycle, self.with_tie, self.max_passes, self.order_dep, self.honest_mismatch
        );
        for (label, ex) in [("order dependence", &self.ex_order), ("drop with nobody offline", &self.ex_honest)] {
            if let Some(h) = ex {
                println!("  {label} example: {h:?}");
            }
        }
    }
}

pub fn random_hist(rng: &mut Rng) -> JHist {
    let nodes = 2 + rng.below(3);
    let na = 2 + rng.below(2);
    // Actor 0 owned by node 0; others by a node or a lower actor (no owner cycles).
    let owners: Vec<Owner> = (0..na).map(|x| if x == 0 || rng.below(2) == 0 { Owner::Node(rng.below(nodes)) } else { Owner::Actor(rng.below(x)) }).collect();
    let ents = nodes + na;
    let mut genesis = vec![vec![Role::None; na]; ents];
    for m in 0..ents {
        for x in 0..na {
            if m != nodes + x && rng.below(3) == 0 {
                genesis[m][x] = [Role::Write, Role::Admin, Role::Admin][rng.below(3)];
            }
        }
    }
    let k = 2 + rng.below(6);
    let mut h = JHist { nodes, owners, genesis, writes: vec![], recv: vec![] };
    while h.writes.len() < k {
        let author = rng.below(nodes);
        let t = 1 + rng.below(8) as u32;
        if rng.below(4) != 0 && h.writes.iter().any(|w| w.t == t && w.author == author) {
            continue;
        }
        let id = rng.next() as u32;
        if h.writes.iter().any(|w| w.id == id) {
            continue;
        }
        let target = rng.below(na);
        let member = loop {
            let m = rng.below(ents);
            if m != nodes + target {
                break m;
            }
        };
        let role = [Role::None, Role::None, Role::Write, Role::Admin][rng.below(4)];
        let mut r: Vec<u32> = (0..nodes).map(|_| if rng.below(3) == 0 { LATE } else { (t as i64 + rng.below(6) as i64 - 2).max(0) as u32 }).collect();
        r[author] = t;
        h.writes.push(JWrite { author, t, id, target, member, role });
        h.recv.push(r);
    }
    h
}

fn check(h: &JHist, st: &mut Stats, rng: &mut Rng) {
    st.histories += 1;
    let na = h.owners.len();
    let mutual = (0..na).any(|x| (0..na).any(|y| x != y && h.genesis[h.nodes + x][y] > Role::None && h.genesis[h.nodes + y][x] > Role::None));
    st.with_cycle += mutual as u64;
    let tie = (0..h.writes.len()).any(|i| (0..i).any(|j| (h.writes[i].t, h.writes[i].author) == (h.writes[j].t, h.writes[j].author)));
    st.with_tie += tie as u64;
    let o = h.eval(true);
    st.max_passes = st.max_passes.max(o.passes);
    let res = h.result(&o);
    let perm = rng.perm(h.writes.len());
    let ph = h.permute(&perm);
    if ph.result(&ph.eval(true)) != res {
        st.order_dep += 1;
        st.ex_order.get_or_insert_with(|| h.clone());
    }
    let distinct = h.writes.iter().map(|w| w.t).collect::<HashSet<_>>().len() == h.writes.len();
    if distinct {
        let mut honest = h.clone();
        for (i, r) in honest.recv.iter_mut().enumerate() {
            r.fill(h.writes[i].t);
        }
        let a = honest.eval(true);
        if a.dropped != 0 || a.edges != honest.eval(false).edges {
            st.honest_mismatch += 1;
            st.ex_honest.get_or_insert_with(|| honest.clone());
        }
    }
}

pub fn random(samples: u64, seed: u64) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut rng = Rng(seed ^ (th + 1).wrapping_mul(0x9E3779B97F4A7C15));
                    let mut st = Stats::default();
                    for _ in 0..samples / threads {
                        let h = random_hist(&mut rng);
                        check(&h, &mut st, &mut rng);
                    }
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

// ---------- scenarios ----------

#[cfg(test)]
mod tests {
    use super::*;
    use Role::{Admin, None};

    /// Nodes 0..5; actors A (owned by node 0) and B (owned by node 1), entities 5 and 6.
    const NODES: usize = 5;
    const A: usize = 0;
    const B: usize = 1;
    const EA: usize = NODES + A;
    const EB: usize = NODES + B;

    struct Jb(JHist);
    impl Jb {
        fn new(owners: Vec<Owner>, edges: &[(usize, usize, Role)]) -> Self {
            let na = owners.len();
            let mut genesis = vec![vec![None; na]; NODES + na];
            for &(m, x, r) in edges {
                genesis[m][x] = r;
            }
            Jb(JHist { nodes: NODES, owners, genesis, writes: vec![], recv: vec![] })
        }
        fn set(&mut self, author: usize, target: usize, member: usize, role: Role, t: u32, recv: &[(usize, u32)]) -> usize {
            let mut r = vec![LATE; NODES];
            r[author] = t;
            for &(m, tm) in recv {
                r[m] = tm;
            }
            let id = 100 + self.0.writes.len() as u32;
            self.0.writes.push(JWrite { author, t, id, target, member, role });
            self.0.recv.push(r);
            self.0.writes.len() - 1
        }
    }

    /// Every input order gives the same result.
    fn assert_order_independent(h: &JHist) {
        let res = h.result(&h.eval(true));
        let k = h.writes.len();
        let mut perm: Vec<usize> = (0..k).collect();
        // Heap's algorithm over all permutations (k is small).
        fn heap(n: usize, p: &mut Vec<usize>, f: &mut dyn FnMut(&[usize])) {
            if n <= 1 {
                f(p);
                return;
            }
            for i in 0..n {
                heap(n - 1, p, f);
                let j = if n % 2 == 0 { i } else { 0 };
                p.swap(j, n - 1);
            }
        }
        heap(k, &mut perm, &mut |p| {
            let ph = h.permute(p);
            assert_eq!(ph.result(&ph.eval(true)), res, "order {p:?}");
        });
    }

    fn mutual() -> Vec<(usize, usize, Role)> {
        vec![(EA, B, Admin), (EB, A, Admin)]
    }

    /// Mutual membership: A and B are admins of each other; node 2 is an admin of A, hence
    /// of B. 2 grants node 3 admin on B; A's owner removes 2 from A. The grant falls iff the
    /// owner had not received it; both walks terminate.
    #[test]
    fn mutual_membership() {
        for seen in [false, true] {
            let mut edges = mutual();
            edges.push((2, A, Admin));
            let mut b = Jb::new(vec![Owner::Node(0), Owner::Node(1)], &edges);
            b.set(2, B, 3, Admin, 2, if seen { &[(0, 3)] } else { &[] });
            b.set(0, A, 2, None, 4, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.roles[2], vec![None, None]);
            assert_eq!(o.roles[3][B], if seen { Admin } else { None }, "seen {seen}");
            assert!(o.passes <= 2);
            assert_order_independent(&b.0);
        }
    }

    /// Concurrent removals across mutual actors: x (admin of A) removes y from B at t=2, y
    /// (admin of B, so of A) removes x from A at t=3, neither having seen the other. The
    /// earlier wins: y has no authority left at t=3. If A's owner then removes x without
    /// having received x's removal of y, that removal falls, y's removal of x applies and the
    /// owner's removal finds x already gone.
    #[test]
    fn concurrent_cross_removals() {
        let (x, y) = (2, 3);
        let mut edges = mutual();
        edges.extend([(x, A, Admin), (y, B, Admin)]);
        let mut b = Jb::new(vec![Owner::Node(0), Owner::Node(1)], &edges);
        b.set(x, B, y, None, 2, &[]);
        b.set(y, A, x, None, 3, &[]);
        let o = b.0.eval(true);
        assert_eq!((o.roles[x][A], o.roles[y][B]), (Admin, None));
        assert_order_independent(&b.0);
        b.set(0, A, x, None, 5, &[]);
        let o = b.0.eval(true);
        assert_eq!((o.roles[x][A], o.roles[y][B], o.roles[y][A]), (None, Admin, Admin));
        assert_eq!(o.dropped, 0b001);
        assert_order_independent(&b.0);
        // Same t: the author node decides, then the commit ID.
        let mut b = Jb::new(vec![Owner::Node(0), Owner::Node(1)], &edges);
        b.set(x, B, y, None, 2, &[]);
        b.set(y, A, x, None, 2, &[]);
        let o = b.0.eval(true);
        assert_eq!((o.roles[x][A], o.roles[y][B]), (Admin, None));
        assert_order_independent(&b.0);
    }

    /// One node writing two commits at one t (a link key's two holders): the commit ID
    /// orders them. Node 2 (admin of A) grants 3 admin and removes it at t=2; which one
    /// stands depends on the IDs only.
    #[test]
    fn same_author_same_t_by_commit_id() {
        for (grant_id, removal_id, expect) in [(1, 2, None), (2, 1, Admin)] {
            let mut b = Jb::new(vec![Owner::Node(0), Owner::Node(1)], &[(2, A, Admin)]);
            let g = b.set(2, A, 3, Admin, 2, &[]);
            let r = b.set(2, A, 3, None, 2, &[]);
            b.0.writes[g].id = grant_id;
            b.0.writes[r].id = removal_id;
            assert_eq!(b.0.eval(true).roles[3][A], expect);
            assert_order_independent(&b.0);
        }
    }

    /// Two edge-admin paths to one doc D (actor 2, owned by node 0): node 3 is admin of teams
    /// T1 and T2 (actors 0 and 1), both admins of D. 3 grants node 4 admin on D at t=1, seen
    /// by nobody. Removing T1's path (t=3) leaves 3's class on D at edge admin: no audit.
    /// Removing T2's (t=4) drops the grant unless that remover had received it.
    #[test]
    fn two_edge_paths_class_attribution() {
        for seen in [false, true] {
            let (t1, t2, d) = (0, 1, 2);
            let owners = vec![Owner::Node(0), Owner::Node(1), Owner::Node(0)];
            let mut b = Jb::new(owners, &[(3, t1, Admin), (3, t2, Admin), (NODES + t1, d, Admin), (NODES + t2, d, Admin)]);
            b.set(3, d, 4, Admin, 1, if seen { &[(1, 2)] } else { &[] });
            b.set(0, t1, 3, None, 3, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.roles[4][d], Admin);
            b.set(1, t2, 3, None, 4, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.roles[4][d], if seen { Admin } else { None }, "seen {seen}");
            assert_order_independent(&b.0);
        }
    }

    /// Owner chain plus edge: actor P (owned by node 0) owns doc G (actor 1); node 3 has an
    /// admin edge on G and becomes a P admin at t=2. Its grant on G at t=1 is edge class.
    /// Edge removed first (t=3): 3 keeps the chain, no fall, no audit; the P removal (t=4)
    /// falls through edge admin too and audits it. P removal first: it audits only chain-class
    /// writes; the edge removal after audits the grant. Dropped either way.
    #[test]
    fn chain_and_edge_paths() {
        let (p, g) = (0, 1);
        for edge_first in [true, false] {
            let owners = vec![Owner::Node(0), Owner::Actor(p)];
            let mut b = Jb::new(owners, &[(3, g, Admin), (2, p, Admin)]);
            b.set(3, g, 4, Admin, 1, &[]);
            b.set(2, p, 3, Admin, 2, &[]);
            let (te, tp) = if edge_first { (3, 4) } else { (4, 3) };
            b.set(2, g, 3, None, te, &[]);
            b.set(0, p, 3, None, tp, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.roles[4][g], None, "edge first {edge_first}");
            assert_order_independent(&b.0);
        }
    }

    /// Self-removal through an actor: node 2, admin of A, removes A's edge on B (it is
    /// admin of the member). Never audited: B's owner removing 2's other rights later
    /// cannot hand A its edge back.
    #[test]
    fn self_removal_through_actor_never_dropped() {
        let mut b = Jb::new(vec![Owner::Node(0), Owner::Node(1)], &[(2, A, Admin), (EA, B, Admin)]);
        b.set(2, B, EA, None, 2, &[]);
        b.set(0, A, 2, None, 4, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.edges[EA][B], None);
        assert_eq!(o.dropped, 0);
    }

    /// Transitive ownership audit: P (owned by node 0) owns Q, Q owns D. Node 3 is admin of P,
    /// so of the chain above D, and grants node 4 admin on D at t=1, seen by nobody. Removing 3
    /// from P (t=3) drops the grant, two ownership levels below P; unless 3 keeps the chain
    /// on D by an admin edge on Q, where its class on D does not fall and nothing is audited.
    #[test]
    fn transitive_ownership_audit() {
        let (p, q, d) = (0, 1, 2);
        for keeps_q in [false, true] {
            let owners = vec![Owner::Node(0), Owner::Actor(p), Owner::Actor(q)];
            let mut edges = vec![(3, p, Admin)];
            if keeps_q {
                edges.push((3, q, Admin));
            }
            let mut b = Jb::new(owners, &edges);
            b.set(3, d, 4, Admin, 1, &[]);
            b.set(0, p, 3, None, 3, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.roles[4][d], if keeps_q { Admin } else { None }, "keeps Q {keeps_q}");
            assert_order_independent(&b.0);
        }
    }
}
