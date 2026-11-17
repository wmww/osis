//! Greenfield model of connection-lived things (issues/connection-lived-data.md), written from the
//! design before any code: a thing naming keeper accounts is held at a node only while that node
//! reaches, over current connections directly or through other nodes, a node of a keeper account.
//! Findings in issues/connection-lived-data.md (Model).
//!
//! Two readings of one history of connection events:
//! - `Oracle`: the rule applied to the connection graph alone, settled at once after each event: in
//!   each component, a thing lives where the component has a keeper's node, and copies flow along
//!   connections whose two ends both share the thing.
//! - `Net`: the protocol: an event-driven path-vector of reached accounts (a route is a path of
//!   nodes; one through the receiver is ignored), copies pushed and asked for over connections
//!   sharing the thing, a node dropping what no reached account keeps. Messages queue per directed
//!   connection and are delivered in random order between queues.
//!
//! Abstracted: a thing's content is one copy (held or not); keepers are fixed at creation; who
//! shares a thing (reads it, keeps it unread, or neither) is fixed per node; every node is honest.
use crate::gen::Rng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type N = usize;
pub type A = usize;
pub type T = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Share {
    /// The node's closure reaches the thing and it reads it: it judges keepers.
    Reads,
    /// The node keeps the thing's sync ID unread: it cannot read the keepers.
    Unread,
    No,
}

/// What a node keeping a thing unread does with its copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blind {
    /// Holds a copy until it restarts (it cannot judge keepers).
    Keeps,
    /// Holds nothing: passes a copy on to the connections sharing the thing, as a relay-only signal.
    Relays,
    /// Judges keepers like a reader (keepers readable to it, e.g. as opaque tokens per sync ID).
    Judges,
}

#[derive(Clone, Debug)]
pub struct World {
    pub account: Vec<A>,
    /// Per thing: its keeper accounts and its creator node.
    pub keepers: Vec<BTreeSet<A>>,
    pub creator: Vec<N>,
    /// `share[n][t]`.
    pub share: Vec<Vec<Share>>,
    pub blind: Blind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Connect(N, N),
    Disconnect(N, N),
    Restart(N),
    Create(T),
}

pub type Edges = BTreeSet<(N, N)>;

fn edge(a: N, b: N) -> (N, N) {
    (a.min(b), a.max(b))
}

/// The components of `nodes` over `edges` restricted to `keep` (both ends in it).
fn components(nodes: usize, edges: &Edges, keep: impl Fn(N) -> bool) -> Vec<usize> {
    let mut comp: Vec<usize> = (0..nodes).collect();
    fn find(c: &mut Vec<usize>, x: usize) -> usize {
        let mut r = x;
        while c[r] != r {
            r = c[r];
        }
        c[x] = r;
        r
    }
    for &(a, b) in edges {
        if keep(a) && keep(b) {
            let (ra, rb) = (find(&mut comp, a), find(&mut comp, b));
            comp[ra] = rb;
        }
    }
    (0..nodes).map(|x| find(&mut comp, x)).collect()
}

impl World {
    pub fn nodes(&self) -> usize {
        self.account.len()
    }
    pub fn things(&self) -> usize {
        self.keepers.len()
    }
    /// Whether node `n` holds a copy of `t` it got, given what it reaches.
    fn takes(&self, n: N, t: T, reach: &BTreeSet<A>) -> bool {
        let kept = self.keepers[t].iter().any(|a| reach.contains(a));
        match (self.share[n][t], self.blind) {
            (Share::No, _) => false,
            (Share::Reads, _) | (Share::Unread, Blind::Judges) => kept,
            (Share::Unread, Blind::Keeps) => true,
            (Share::Unread, Blind::Relays) => false,
        }
    }
}

/// The rule settled at once on the connection graph.
#[derive(Clone, Debug)]
pub struct Oracle {
    pub edges: Edges,
    pub has: Vec<BTreeSet<T>>,
    pub created: BTreeSet<T>,
}

impl Oracle {
    pub fn new(w: &World) -> Oracle {
        Oracle { edges: Edges::new(), has: vec![BTreeSet::new(); w.nodes()], created: BTreeSet::new() }
    }
    /// The accounts each node reaches.
    pub fn reach(&self, w: &World) -> Vec<BTreeSet<A>> {
        let comp = components(w.nodes(), &self.edges, |_| true);
        (0..w.nodes()).map(|n| (0..w.nodes()).filter(|&m| comp[m] == comp[n]).map(|m| w.account[m]).collect()).collect()
    }
    pub fn apply(&mut self, w: &World, e: Event) {
        match e {
            Event::Connect(a, b) => {
                self.edges.insert(edge(a, b));
            }
            Event::Disconnect(a, b) => {
                self.edges.remove(&edge(a, b));
            }
            Event::Restart(n) => {
                self.edges.retain(|&(a, b)| a != n && b != n);
                self.has[n].clear();
            }
            Event::Create(t) => {
                self.created.insert(t);
                self.has[w.creator[t]].insert(t);
            }
        }
        self.settle(w);
    }
    fn settle(&mut self, w: &World) {
        let reach = self.reach(w);
        for t in 0..w.things() {
            // Copies flow along connections both of whose ends share t, past any node that takes
            // it or (relaying) passes it on.
            let carries = |n: N| w.share[n][t] != Share::No;
            let flow = components(w.nodes(), &self.edges, carries);
            let seeded: BTreeSet<usize> = (0..w.nodes()).filter(|&n| self.has[n].contains(&t)).map(|n| flow[n]).collect();
            for n in 0..w.nodes() {
                // The rule: every node sharing t holds it while it reaches a keeper, readers and
                // nodes keeping it unread alike, whatever `w.blind` says the protocol does.
                let kept = w.keepers[t].iter().any(|a| reach[n].contains(a));
                match carries(n) && seeded.contains(&flow[n]) && kept {
                    true => self.has[n].insert(t),
                    false => self.has[n].remove(&t),
                };
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// The sender's whole table of reached accounts, each with its path (sender first).
    Routes(BTreeMap<A, Vec<N>>),
    Copy(T),
    Want(T),
}

/// Counters for scaling checks.
#[derive(Clone, Debug, Default)]
pub struct Work {
    pub route_msgs: usize,
    pub route_entries: usize,
    pub copies: usize,
    pub wants: usize,
    pub drops: usize,
    /// Things re-judged on a reach change.
    pub judged: usize,
}

#[derive(Clone, Debug)]
pub struct Net {
    pub edges: Edges,
    /// `rib[n][m]`: what neighbour `m` last told `n`.
    pub rib: Vec<BTreeMap<N, BTreeMap<A, Vec<N>>>>,
    /// What `n` last told each neighbour.
    pub told: Vec<BTreeMap<N, BTreeMap<A, Vec<N>>>>,
    pub has: Vec<BTreeSet<T>>,
    pub queues: BTreeMap<(N, N), VecDeque<Msg>>,
    /// What each relaying node passed on (taken once, until it restarts).
    pub passed: Vec<BTreeSet<T>>,
    /// Drop only once the routes have settled (`drain` judges at quiescence), not at each route
    /// change: an idealised hold-down.
    pub settled_drops: bool,
    /// Tell each neighbour the best route avoiding it (`told_to`).
    pub alternates: bool,
    pub work: Work,
}

impl Net {
    pub fn new(w: &World) -> Net {
        let n = w.nodes();
        Net { edges: Edges::new(), rib: vec![BTreeMap::new(); n], told: vec![BTreeMap::new(); n], has: vec![BTreeSet::new(); n], queues: BTreeMap::new(), passed: vec![BTreeSet::new(); n], settled_drops: false, alternates: false, work: Work::default() }
    }
    fn neighbours(&self, n: N) -> Vec<N> {
        self.edges.iter().filter_map(|&(a, b)| if a == n { Some(b) } else if b == n { Some(a) } else { None }).collect()
    }
    /// Best route per account from what the neighbours told: shortest, then least path; a path
    /// through `n` itself is ignored.
    pub fn table(&self, w: &World, n: N) -> BTreeMap<A, Vec<N>> {
        self.table_avoiding(w, n, None)
    }
    /// The table told to neighbour `m`: with `alternates`, the best route not through `m`, so
    /// `m` keeps an alternative to its own route through `n`; else the one best table.
    fn told_to(&self, w: &World, n: N, m: N) -> BTreeMap<A, Vec<N>> {
        self.table_avoiding(w, n, self.alternates.then_some(m))
    }
    fn table_avoiding(&self, w: &World, n: N, avoid: Option<N>) -> BTreeMap<A, Vec<N>> {
        let mut best: BTreeMap<A, Vec<N>> = BTreeMap::from([(w.account[n], vec![n])]);
        for routes in self.rib[n].values() {
            for (&a, p) in routes {
                if p.contains(&n) || avoid.is_some_and(|m| p.contains(&m)) {
                    continue;
                }
                let mut q = vec![n];
                q.extend(p);
                let better = best.get(&a).is_none_or(|o| (q.len(), &q) < (o.len(), o));
                if better {
                    best.insert(a, q);
                }
            }
        }
        best
    }
    pub fn reach(&self, w: &World, n: N) -> BTreeSet<A> {
        self.table(w, n).into_keys().collect()
    }
    fn send(&mut self, from: N, to: N, m: Msg) {
        match &m {
            Msg::Routes(r) => {
                self.work.route_msgs += 1;
                self.work.route_entries += r.len();
            }
            Msg::Copy(_) => self.work.copies += 1,
            Msg::Want(_) => self.work.wants += 1,
        }
        self.queues.entry((from, to)).or_default().push_back(m);
    }
    /// Tell each neighbour the table where it changed; then judge holdings by the new reach.
    fn routes_changed(&mut self, w: &World, n: N, before: &BTreeSet<A>) {
        for m in self.neighbours(n) {
            let table = self.told_to(w, n, m);
            if self.told[n].get(&m) != Some(&table) {
                self.told[n].insert(m, table.clone());
                self.send(n, m, Msg::Routes(table));
            }
        }
        let reach = self.reach(w, n);
        if &reach == before {
            return;
        }
        // Re-judge only the things whose keepers include an account that came or went.
        let moved: BTreeSet<A> = reach.symmetric_difference(before).copied().collect();
        for t in 0..w.things() {
            if !w.keepers[t].iter().any(|a| moved.contains(a)) {
                continue;
            }
            self.work.judged += 1;
            let kept = w.takes(n, t, &reach);
            if !kept && !self.settled_drops && self.has[n].remove(&t) {
                self.work.drops += 1;
            }
            if kept && !self.has[n].contains(&t) && w.share[n][t] != Share::No && w.takes(n, t, &reach) {
                for m in self.shared_neighbours(w, n, t) {
                    self.send(n, m, Msg::Want(t));
                }
            }
        }
    }
    fn shared_neighbours(&self, w: &World, n: N, t: T) -> Vec<N> {
        self.neighbours(n).into_iter().filter(|&m| w.share[m][t] != Share::No).collect()
    }
    pub fn apply(&mut self, w: &World, e: Event) {
        match e {
            Event::Connect(a, b) => {
                if self.edges.insert(edge(a, b)) {
                    for (x, y) in [(a, b), (b, a)] {
                        let table = self.told_to(w, x, y);
                        self.told[x].insert(y, table.clone());
                        self.send(x, y, Msg::Routes(table));
                        // A join lists what each side holds of what both share; ordinary sync.
                        for t in self.has[x].clone() {
                            if w.share[y][t] != Share::No {
                                self.send(x, y, Msg::Copy(t));
                            }
                        }
                    }
                }
            }
            Event::Disconnect(a, b) => self.close(w, a, b),
            Event::Restart(n) => {
                for m in self.neighbours(n) {
                    self.close(w, n, m);
                }
                self.has[n].clear();
                self.passed[n].clear();
            }
            Event::Create(t) => {
                let c = w.creator[t];
                self.has[c].insert(t);
                let reach = self.reach(w, c);
                if !w.keepers[t].iter().any(|a| reach.contains(a)) {
                    self.has[c].remove(&t);
                    return;
                }
                for m in self.shared_neighbours(w, c, t) {
                    self.send(c, m, Msg::Copy(t));
                }
            }
        }
    }
    fn close(&mut self, w: &World, a: N, b: N) {
        if !self.edges.remove(&edge(a, b)) {
            return;
        }
        self.queues.remove(&(a, b));
        self.queues.remove(&(b, a));
        for (x, y) in [(a, b), (b, a)] {
            let before = self.reach(w, x);
            self.rib[x].remove(&y);
            self.told[x].remove(&y);
            self.routes_changed(w, x, &before);
        }
    }
    /// Deliver one queued message, picked at random among the non-empty queues.
    pub fn step(&mut self, w: &World, r: &mut Rng) -> bool {
        let live: Vec<(N, N)> = self.queues.iter().filter(|(_, q)| !q.is_empty()).map(|(&k, _)| k).collect();
        if live.is_empty() {
            return false;
        }
        let (from, to) = live[r.below(live.len() as u64) as usize];
        let m = self.queues.get_mut(&(from, to)).unwrap().pop_front().unwrap();
        match m {
            Msg::Routes(routes) => {
                let before = self.reach(w, to);
                self.rib[to].insert(from, routes);
                self.routes_changed(w, to, &before);
            }
            Msg::Want(t) => {
                if self.has[to].contains(&t) {
                    self.send(to, from, Msg::Copy(t));
                }
            }
            Msg::Copy(t) => {
                if self.has[to].contains(&t) {
                    return true;
                }
                let reach = self.reach(w, to);
                let passes = w.share[to][t] == Share::Unread && w.blind == Blind::Relays && self.passed[to].insert(t);
                if w.takes(to, t, &reach) {
                    self.has[to].insert(t);
                }
                if self.has[to].contains(&t) || passes {
                    for m in self.shared_neighbours(w, to, t) {
                        if m != from {
                            self.send(to, m, Msg::Copy(t));
                        }
                    }
                }
            }
        }
        true
    }
    /// Deliver until no message is queued.
    pub fn drain(&mut self, w: &World, r: &mut Rng) {
        let mut steps = 0;
        while self.step(w, r) {
            steps += 1;
            assert!(steps < 1_000_000, "no quiescence");
        }
        if self.settled_drops {
            for n in 0..w.nodes() {
                let reach = self.reach(w, n);
                let before = self.has[n].len();
                self.has[n].retain(|&t| w.takes(n, t, &reach));
                self.work.drops += before - self.has[n].len();
            }
        }
    }
}

/// A random world: `nodes` nodes over `accounts` accounts, `things` things.
pub fn world(r: &mut Rng, nodes: usize, accounts: usize, things: usize, blind: Blind, unread_pct: u64) -> World {
    let account: Vec<A> = (0..nodes).map(|n| if n < accounts { n } else { r.below(accounts as u64) as usize }).collect();
    let mut keepers = Vec::new();
    let mut creator = Vec::new();
    let mut share = vec![vec![Share::No; things]; nodes];
    for t in 0..things {
        let c = r.below(nodes as u64) as usize;
        creator.push(c);
        let mut k = BTreeSet::from([account[c]]);
        if r.chance(30) {
            k.insert(r.below(accounts as u64) as usize);
        }
        keepers.push(k);
        for n in 0..nodes {
            share[n][t] = match (n == c, r.below(100)) {
                (true, _) => Share::Reads,
                (false, x) if x < unread_pct => Share::Unread,
                (false, x) if x < 70 => Share::Reads,
                _ => Share::No,
            };
        }
    }
    World { account, keepers, creator, share, blind }
}

/// A random history: connection churn, restarts and creations.
pub fn history(r: &mut Rng, w: &World, len: usize) -> Vec<Event> {
    let mut out = Vec::new();
    let mut edges = Edges::new();
    let mut made: Vec<T> = (0..w.things()).collect();
    r.shuffle(&mut made);
    for _ in 0..len {
        let x = r.below(100);
        let (a, b) = (r.below(w.nodes() as u64) as usize, r.below(w.nodes() as u64) as usize);
        if x < 10 && !made.is_empty() {
            out.push(Event::Create(made.pop().unwrap()));
        } else if x < 15 {
            out.push(Event::Restart(a));
            edges.retain(|&(p, q)| p != a && q != a);
        } else if a != b && edges.contains(&edge(a, b)) && x < 55 {
            edges.remove(&edge(a, b));
            out.push(Event::Disconnect(a, b));
        } else if a != b {
            edges.insert(edge(a, b));
            out.push(Event::Connect(a, b));
        }
    }
    out
}

/// One mismatch between the protocol at quiescence and the oracle.
#[derive(Clone, Debug)]
pub struct Diff {
    pub at: usize,
    pub node: N,
    pub thing: T,
    pub net: bool,
    pub oracle: bool,
}

/// Run `h` on both readings, the net drained after every event; the first mismatch of reach or
/// holdings, if any.
pub fn run(w: &World, h: &[Event], r: &mut Rng, settled_drops: bool, alternates: bool) -> Result<(), (Diff, &'static str)> {
    let (mut o, mut net) = (Oracle::new(w), Net::new(w));
    net.settled_drops = settled_drops;
    net.alternates = alternates;
    for (i, &e) in h.iter().enumerate() {
        o.apply(w, e);
        net.apply(w, e);
        net.drain(w, r);
        let reach = o.reach(w);
        for n in 0..w.nodes() {
            if net.reach(w, n) != reach[n] {
                return Err((Diff { at: i, node: n, thing: usize::MAX, net: false, oracle: false }, "reach"));
            }
            // What users observe: readers' holdings.
            for t in (0..w.things()).filter(|&t| w.share[n][t] == Share::Reads) {
                let (a, b) = (net.has[n].contains(&t), o.has[n].contains(&t));
                if a != b {
                    return Err((Diff { at: i, node: n, thing: t, net: a, oracle: b }, "holds"));
                }
            }
        }
    }
    Ok(())
}
