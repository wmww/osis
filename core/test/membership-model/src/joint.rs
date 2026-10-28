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
//! (A's receipts before t; nothing else counts, A's own chain writes included), and the walk
//! restarts on
//! any drop. Drops are sticky. No invites, `until` or snapshots here (edges.rs, snapshot.rs).
//!
//! Checked (`cargo run --bin membership-model [samples] joint`, `cargo test`): termination, input-order
//! independence (with commit-ID ties), nothing dropped with nobody offline.

use crate::{Rng, Role};
use std::collections::{HashMap, HashSet};

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

/// What the walk remembers per edge between explicit writes on it (§5.1 step 4, "the edge as
/// restored").
struct Restored {
    /// [member][target]: the join of the edge's values since the last explicit write on it,
    /// values taken away by self-removal included.
    since: Vec<Vec<Role>>,
    /// (member, target, author): the standing an author kept by its own explicit write on
    /// that edge ("R never demotes its own author"), until the next explicit write on it.
    kept: HashMap<(usize, usize, usize), Role>,
}

/// One walk under a fixed drop set (§5.1 steps 2-4).
struct Pass {
    edges: Vec<Vec<Role>>,
    roles: Vec<Vec<Role>>,
    attr: Vec<Attr>,
    /// Writes the walk added to D (it stops at the first write that adds any).
    added: u64,
}

impl JHist {
    fn actors(&self) -> usize {
        self.owners.len()
    }

    /// The owner entity of actor `x`.
    fn owner(&self, x: usize) -> usize {
        match self.owners[x] {
            Owner::Node(o) => o,
            Owner::Actor(y) => self.nodes + y,
        }
    }

    /// §5.1 step 1: order the edge writes by (ts, author node, commit ID).
    pub fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| (self.writes[i].t, self.writes[i].author, self.writes[i].id));
        o
    }

    /// §1 effective role [node][actor]: the maximum over paths of the minimum role along the
    /// path, paths climbing edges and owner links (an owner holds admin on what it owns).
    /// A fixpoint, so mutual membership is fine.
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

    /// §5.1 step 3: node n's authority class on actor x: owner chain (admin of an actor
    /// strictly above x in its owner chain, or the key actor at the top), else edge admin,
    /// else none (no invites here).
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

    /// Entities reaching `m` (included) by edges of any role and owner links.
    fn reaching(&self, edges: &[Vec<Role>], m: usize) -> Vec<bool> {
        let (nn, na) = (self.nodes, self.actors());
        let mut v = vec![false; nn + na];
        v[m] = true;
        loop {
            let mut changed = false;
            for e in 0..nn + na {
                if !v[e] && (0..na).any(|x| v[nn + x] && (edges[e][x] > Role::None || self.owner(x) == e)) {
                    v[e] = true;
                    changed = true;
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// Entities reachable from `t` (included) by edges of any role and owner links: where a
    /// fall on `t` can reach (§5.1 step 4, "everything below N").
    fn reachable(&self, edges: &[Vec<Role>], t: usize) -> Vec<bool> {
        let (nn, na) = (self.nodes, self.actors());
        let mut v = vec![false; nn + na];
        v[t] = true;
        loop {
            let mut changed = false;
            for x in 0..na {
                if !v[nn + x] && (v[self.owner(x)] || (0..nn + na).any(|e| v[e] && edges[e][x] > Role::None)) {
                    v[nn + x] = true;
                    changed = true;
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// Whether node a has admin on member entity m (a node is its own admin).
    fn admin_of(&self, r: &[Vec<Role>], a: usize, m: usize) -> bool {
        m == a || m >= self.nodes && r[a][m - self.nodes] == Role::Admin
    }

    /// §1: an edge for the target's owner is no write (the owner is implicitly admin and
    /// cannot be removed).
    fn is_owner_edge(&self, w: &JWrite) -> bool {
        w.member == self.owner(w.target)
    }

    /// §2 self-removal: lowers an edge whose member the author has admin on, and either lowers
    /// the author's own edge or the author has no owner-chain or edge-admin authority on the
    /// target at that point.
    fn is_self_removal(&self, edges: &[Vec<Role>], r: &[Vec<Role>], w: &JWrite) -> bool {
        let lowers = w.role <= edges[w.member][w.target];
        lowers && self.admin_of(r, w.author, w.member) && (w.member == w.author || self.class(r, w.author, w.target) == Class::None)
    }

    /// §5.1 steps 2-3: whether write `w` applies at this point, and its attribution: a
    /// self-removal, or the author's class on the target (admin needed: owner chain or edge).
    fn authority(&self, edges: &[Vec<Role>], r: &[Vec<Role>], w: &JWrite) -> Attr {
        if self.is_self_removal(edges, r, w) {
            return Attr::SelfOnly;
        }
        match self.class(r, w.author, w.target) {
            Class::None => Attr::Skipped,
            c => Attr::By(c),
        }
    }

    /// §5.1 frontier: write j is covered by write w's frontier when w's author had received
    /// it before w's time.
    fn covered(&self, j: usize, w: &JWrite) -> bool {
        self.recv[j][w.author] < w.t
    }

    /// §5.1 step 4 for the explicit write `i` (just applied: `edges`, `r` are after it; `old`
    /// the edge before it; `own`: its author reached the member before it): the writes it adds
    /// to D. Every other node x reaching the member whose class on an actor n below the target
    /// fell (against the edge as restored, x's kept standing included) has its earlier applied
    /// writes on n attributed to a class it fell through, and not covered by i's frontier,
    /// added to D. The author keeps its standing instead.
    #[allow(clippy::too_many_arguments)]
    fn audit(&self, i: usize, old: Role, own: bool, edges: &[Vec<Role>], r: &[Vec<Role>], attr: &[Attr], rest: &mut Restored, audit: bool) -> u64 {
        let (nn, na) = (self.nodes, self.actors());
        let w = &self.writes[i];
        let (a, m, t) = (w.author, w.member, w.target);
        let base = rest.since[m][t].max(old);
        rest.since[m][t] = Role::None;
        let (up, down) = (self.reaching(edges, m), self.reachable(edges, nn + t));
        let mut added = 0u64;
        for x in 0..nn {
            let restored = base.max(rest.kept.remove(&(m, t, x)).unwrap_or(Role::None));
            if x == a {
                if own {
                    rest.kept.insert((m, t, a), restored);
                }
                continue;
            }
            if !up[x] || !audit {
                continue;
            }
            let mut was = edges.to_vec();
            was[m][t] = restored;
            let rw = self.roles(&was);
            for n in 0..na {
                let (now, before) = (self.class(r, x, n), self.class(&rw, x, n));
                if !down[nn + n] || now >= before {
                    continue;
                }
                for (j, wj) in self.writes.iter().enumerate() {
                    if j == i || wj.author != x || wj.target != n {
                        continue;
                    }
                    let Attr::By(c) = attr[j] else { continue };
                    if now < c && c <= before && !self.covered(j, w) {
                        added |= 1 << j;
                    }
                }
            }
        }
        added
    }

    /// §5.1 steps 2-4: one walk skipping `dropped`, stopping after the first write that adds
    /// to D.
    fn pass(&self, order: &[usize], dropped: u64, audit: bool) -> Pass {
        let (nn, na) = (self.nodes, self.actors());
        let mut edges = self.genesis.clone();
        let mut r = self.roles(&edges);
        let mut rest = Restored { since: vec![vec![Role::None; na]; nn + na], kept: HashMap::new() };
        let mut attr = vec![Attr::Skipped; self.writes.len()];
        for &i in order {
            let w = &self.writes[i];
            if dropped >> i & 1 == 1 || self.is_owner_edge(w) {
                continue;
            }
            attr[i] = self.authority(&edges, &r, w);
            if attr[i] == Attr::Skipped {
                continue;
            }
            let old = edges[w.member][w.target];
            let own = self.reaching(&edges, w.member)[w.author];
            edges[w.member][w.target] = w.role;
            r = self.roles(&edges);
            if attr[i] == Attr::SelfOnly {
                // Never audited, audits nothing; the next explicit write restores `old`.
                let s = &mut rest.since[w.member][w.target];
                *s = (*s).max(old);
                continue;
            }
            let added = self.audit(i, old, own, &edges, &r, &attr, &mut rest, audit);
            if added != 0 {
                return Pass { edges, roles: r, attr, added };
            }
        }
        Pass { edges, roles: r, attr, added: 0 }
    }

    /// The timeline (§5.1): walks from scratch, each walk restarting with the writes the last
    /// one added to D (sticky within the evaluation), until a walk adds nothing (step 5).
    /// `audit = false` never drops (the reference for the nobody-offline check).
    pub fn eval(&self, audit: bool) -> JOut {
        let order = self.order();
        let mut dropped = 0u64;
        let mut passes = 0;
        loop {
            passes += 1;
            let p = self.pass(&order, dropped, audit);
            if p.added == 0 {
                let applied = (0..self.writes.len()).filter(|&j| p.attr[j] != Attr::Skipped).fold(0u64, |m, j| m | 1 << j);
                return JOut { edges: p.edges, roles: p.roles, applied, dropped, passes };
            }
            dropped |= p.added;
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

/// Quiescence: after every delivery, every node agrees. Each node's walk over the writes in
/// the order it received them (its own at their time, never-received ones last) gives the
/// result of the canonical walk. Returns the first node that disagrees.
pub fn quiescent(h: &JHist) -> Result<(), usize> {
    let res = h.result(&walk(h));
    for n in 0..h.nodes {
        let ph = h.permute(&crate::delivery_order(&h.recv, n));
        if ph.result(&walk(&ph)) != res {
            return Err(n);
        }
    }
    Ok(())
}

fn ent_name(nodes: usize, e: usize) -> String {
    if e < nodes {
        format!("n{e}")
    } else {
        format!("A{}", e - nodes)
    }
}

/// A trace: actors with owners, genesis edges, then each write in walk order with its index,
/// author, commit ID and who received it when.
impl std::fmt::Display for JHist {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let nm = |e: usize| ent_name(self.nodes, e);
        let owners: Vec<String> = (0..self.actors()).map(|x| format!("A{x} owned by {}", nm(self.owner(x)))).collect();
        writeln!(f, "nodes n0..n{}; {}", self.nodes - 1, owners.join(", "))?;
        for (m, row) in self.genesis.iter().enumerate() {
            for (x, r) in row.iter().enumerate().filter(|(_, r)| **r != Role::None) {
                writeln!(f, "  genesis: {} {r:?} on A{x}", nm(m))?;
            }
        }
        for i in self.order() {
            let w = &self.writes[i];
            writeln!(f, "  w{i}: t={} {} (id {}) sets {} on A{} := {:?} | {}", w.t, nm(w.author), w.id, nm(w.member), w.target, w.role, crate::fmt_recv(&self.recv[i], w.author))?;
        }
        Ok(())
    }
}

impl crate::shrink::Shrink for JHist {
    fn smaller(&self) -> Vec<JHist> {
        use crate::shrink::{compact_ids, compact_times, without, LATE};
        let mut out = Vec::new();
        let (nn, na) = (self.nodes, self.actors());
        for i in 0..self.writes.len() {
            out.push(JHist { writes: without(&self.writes, i), recv: without(&self.recv, i), ..self.clone() });
        }
        // An unused node or actor.
        for k in (0..nn).filter(|_| nn > 1) {
            let used = self.writes.iter().any(|w| w.author == k || w.member == k) || self.genesis[k].iter().any(|&r| r != Role::None) || self.owners.contains(&Owner::Node(k));
            if !used {
                let mut h = self.clone();
                h.nodes -= 1;
                h.genesis.remove(k);
                for r in &mut h.recv {
                    r.remove(k);
                }
                for w in &mut h.writes {
                    w.author -= usize::from(w.author > k);
                    w.member -= usize::from(w.member > k);
                }
                h.owners.iter_mut().for_each(|o| if let Owner::Node(n) = o { *n -= usize::from(*n > k) });
                out.push(h);
            }
        }
        for x in (0..na).filter(|_| na > 1) {
            let e = nn + x;
            let used = self.writes.iter().any(|w| w.target == x || w.member == e) || self.genesis[e].iter().any(|&r| r != Role::None) || self.genesis.iter().any(|row| row[x] != Role::None) || self.owners.contains(&Owner::Actor(x));
            if !used {
                let mut h = self.clone();
                h.owners.remove(x);
                h.genesis.remove(e);
                for row in &mut h.genesis {
                    row.remove(x);
                }
                for w in &mut h.writes {
                    w.target -= usize::from(w.target > x);
                    w.member -= usize::from(w.member > e);
                }
                h.owners.iter_mut().for_each(|o| if let Owner::Actor(y) = o { *y -= usize::from(*y > x) });
                out.push(h);
            }
        }
        for m in 0..self.genesis.len() {
            for x in 0..na {
                if self.genesis[m][x] > Role::None {
                    let mut h = self.clone();
                    h.genesis[m][x] = Role::None;
                    out.push(h);
                    if self.genesis[m][x] == Role::Admin {
                        let mut h = self.clone();
                        h.genesis[m][x] = Role::Write;
                        out.push(h);
                    }
                }
            }
        }
        for i in 0..self.writes.len() {
            for r in [Role::None, Role::Write].into_iter().filter(|&r| r < self.writes[i].role) {
                let mut h = self.clone();
                h.writes[i].role = r;
                out.push(h);
            }
            for n in (0..nn).filter(|&n| n != self.writes[i].author && self.recv[i][n] < LATE) {
                let mut h = self.clone();
                h.recv[i][n] = LATE;
                out.push(h);
            }
        }
        let times: Vec<u32> = self.writes.iter().map(|w| w.t).chain(self.recv.iter().flatten().copied()).collect();
        if let Some(map) = compact_times(&times) {
            let mut h = self.clone();
            h.writes.iter_mut().for_each(|w| w.t = map(w.t));
            h.recv.iter_mut().flatten().for_each(|v| *v = map(*v));
            out.push(h);
        }
        if let Some(ids) = compact_ids(&self.writes.iter().map(|w| w.id).collect::<Vec<_>>()) {
            let mut h = self.clone();
            h.writes.iter_mut().zip(ids).for_each(|(w, id)| w.id = id);
            out.push(h);
        }
        out
    }
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
    disagree: u64,
    ex_order: Option<JHist>,
    ex_honest: Option<JHist>,
    ex_disagree: Option<JHist>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.histories += o.histories;
        self.max_passes = self.max_passes.max(o.max_passes);
        self.order_dep += o.order_dep;
        self.honest_mismatch += o.honest_mismatch;
        self.with_cycle += o.with_cycle;
        self.with_tie += o.with_tie;
        self.disagree += o.disagree;
        self.ex_order = self.ex_order.take().or(o.ex_order);
        self.ex_honest = self.ex_honest.take().or(o.ex_honest);
        self.ex_disagree = self.ex_disagree.take().or(o.ex_disagree);
    }

    pub fn print(&self) {
        println!(
            "joint: {} histories ({} with mutual membership, {} with a (t, author) tie) | max passes {} | order-dependent {} | drops with nobody offline {} | nodes disagreeing after every delivery {}",
            self.histories, self.with_cycle, self.with_tie, self.max_passes, self.order_dep, self.honest_mismatch, self.disagree
        );
        // Shrunk while they still fail the same check.
        let examples = [
            ("order dependence", &self.ex_order, &(|h: &JHist| quiescent(h).is_err()) as &dyn Fn(&JHist) -> bool),
            ("drop with nobody offline", &self.ex_honest, &|h: &JHist| honest(h).map_or(false, |h| honest_drops(&h))),
            ("disagreement after every delivery", &self.ex_disagree, &|h: &JHist| quiescent(h).is_err()),
        ];
        for (label, ex, fails) in examples {
            if let Some(h) = ex {
                let mut h = if fails(h) { crate::shrink::shrink(h.clone(), fails) } else { h.clone() };
                if label == "drop with nobody offline" {
                    h = honest(&h).unwrap_or(h);
                }
                println!("  {label} example:\n{h}");
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
    // Entities each node may reach (any edge ever, owner links), for honest receipts.
    let reach: Vec<Vec<bool>> = (0..nodes)
        .map(|y| {
            let mut v = vec![false; ents];
            v[y] = true;
            loop {
                let mut changed = false;
                for x in 0..na {
                    if v[nodes + x] {
                        continue;
                    }
                    let owner = match h.owners[x] {
                        Owner::Node(o) => o,
                        Owner::Actor(z) => nodes + z,
                    };
                    let edge = (0..ents).any(|m| v[m] && (h.genesis[m][x] > Role::None || h.writes.iter().any(|w| w.member == m && w.target == x)));
                    if v[owner] || edge {
                        v[nodes + x] = true;
                        changed = true;
                    }
                }
                if !changed {
                    return v;
                }
            }
        })
        .collect();
    let ws: Vec<(usize, u32)> = h.writes.iter().map(|w| (w.author, w.t)).collect();
    let members: Vec<usize> = h.writes.iter().map(|w| w.member).collect();
    let eligible: Vec<bool> = h.writes.iter().map(|w| w.role < Role::Admin).collect();
    let late = crate::late_writes(rng, &eligible);
    crate::hold_chains(&ws, &late, |j, x| reach[x][members[j]], &mut h.recv);
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
    if let Some(honest) = honest(h) {
        if honest_drops(&honest) {
            st.honest_mismatch += 1;
            st.ex_honest.get_or_insert(honest);
        }
    }
    if quiescent(h).is_err() {
        st.disagree += 1;
        st.ex_disagree.get_or_insert_with(|| h.clone());
    }
}

/// `h` with nobody offline: every write received by everyone at its time (None when two
/// writes share a time, where receipts cannot all be simultaneous).
fn honest(h: &JHist) -> Option<JHist> {
    let distinct = h.writes.iter().map(|w| w.t).collect::<HashSet<_>>().len() == h.writes.len();
    distinct.then(|| {
        let mut honest = h.clone();
        for (i, r) in honest.recv.iter_mut().enumerate() {
            r.fill(h.writes[i].t);
        }
        honest
    })
}

/// With nobody offline nothing is dropped, and the walk equals the one without audits.
fn honest_drops(h: &JHist) -> bool {
    let a = h.eval(true);
    a.dropped != 0 || a.edges != h.eval(false).edges
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

    /// A owns group G and doc T; X is admin of G, G admin of T. X grants Y admin on T, unseen
    /// by A. A, admin of G as its owner but also owner of T, removes G from T: an explicit
    /// demotion (not a self-removal), so X's unseen grant is dropped.
    #[test]
    fn group_removal_by_owner_of_both() {
        let (g, t) = (0, 1);
        let mut b = Jb::new(vec![Owner::Node(0), Owner::Node(0)], &[(1, g, Admin), (NODES + g, t, Admin)]);
        let grant = b.set(1, t, 2, Admin, 3, &[]);
        b.set(0, t, NODES + g, None, 10, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.dropped >> grant & 1, 1);
        assert_eq!(o.roles[2][t], None);
        assert_order_independent(&b.0);
    }
}
