//! Joint walk over several actors (spec/permissions.md §5.1): one timeline over every edge
//! write of every actor, ordered by (t, author node, commit ID). Nodes are key actors; each
//! actor's record names its first admin (a node or a lower actor), whose record edge (admin)
//! is in the genesis edges before every write and removable like any edge
//! (spec/permissions.md §1); an edge (holder: node or actor, target actor, role). Effective
//! role: max over paths of the min along the path, paths climbing edges, computed as a
//! fixpoint so mutual role is fine. Class of a node on an actor: edge admin (admin by any
//! path), else none.
//!
//! A write applies iff its author has admin on the target (attributed to its class there) or
//! it is a self-removal (lowers the edge of a holder the author has admin on; attributed to
//! its class on that holder, or on the target for its own edge; audits nothing). After each applied write by A on edge (M, T), every other node X reaching
//! M whose class on an actor N reachable from T fell below its class with the edge restored
//! as if the holder still held its role (the highest role the edge had since the last
//! explicit write on it, self-removals and A's own writes auditing nothing) has its
//! earlier applied writes on N attributed to a class in (new, held] audited by A's frontier
//! (A's receipts before t; nothing else counts, A's own chain writes included), and the walk
//! restarts on
//! any drop. Drops are sticky. No invites, `until` or snapshots here (edges.rs, snapshot.rs).
//!
//! Checked (`cargo run --bin roles-model [samples] joint`, `cargo test`): termination, input-order
//! independence (with commit-ID ties), nothing dropped with nobody offline.

use crate::{Rng, Role};
use std::collections::{HashMap, HashSet};

const LATE: u32 = 1000;

#[derive(Clone, Debug)]
pub struct JWrite {
    pub author: usize,
    pub t: u32,
    pub id: u32,
    pub target: usize,
    /// Holder entity: nodes 0..nodes, actors nodes..nodes+actors.
    pub holder: usize,
    pub role: Role,
}

#[derive(Clone, Debug)]
pub struct JHist {
    pub nodes: usize,
    /// Each actor's first admin entity (a node, or a lower actor): `genesis[admins[x]][x]` is
    /// its record edge, admin.
    pub admins: Vec<usize>,
    /// [holder entity][target actor].
    pub genesis: Vec<Vec<Role>>,
    pub writes: Vec<JWrite>,
    /// [write][node] receipt time; author: its own t.
    pub recv: Vec<Vec<u32>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Class {
    None,
    Edge,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attr {
    Skipped,
    /// A self-removal, attributed to the author's class on an actor (the holder it is admin
    /// of, or the target for its own edge) and audited when that falls.
    SelfOnly(Class, usize),
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

/// The settled walk as layer 2 reads it (`JHist::steps`).
#[derive(Clone, Debug)]
pub struct Steps {
    /// Roles [node][actor] before every write.
    pub genesis: Vec<Vec<Role>>,
    /// Each applied write in walk order, with the roles just after it.
    pub after: Vec<(usize, Vec<Vec<Role>>)>,
    /// (write, node, actor): explicit demotions below write.
    pub demotions: Vec<(usize, usize, usize)>,
}

/// What the walk remembers per edge between explicit writes on it (§5.1 step 4, "the edge as
/// restored").
struct Restored {
    /// [holder][target]: the join of the edge's values since the last explicit write on it,
    /// values taken away by self-removal included.
    since: Vec<Vec<Role>>,
    /// (holder, target, author): the standing an author kept by its own explicit write on
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
    /// Explicit writes that lowered another holder's edge.
    demoting: u64,
}

impl JHist {
    fn actors(&self) -> usize {
        self.admins.len()
    }

    /// §5.1 step 1: order the edge writes by (ts, author node, commit ID).
    pub fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| (self.writes[i].t, self.writes[i].author, self.writes[i].id));
        o
    }

    /// §1 effective role [node][actor]: the maximum over paths of the minimum role along the
    /// path, paths climbing edges. A fixpoint, so mutual role is fine.
    fn roles(&self, edges: &[Vec<Role>]) -> Vec<Vec<Role>> {
        let (nn, na) = (self.nodes, self.actors());
        let mut r = vec![vec![Role::None; na]; nn];
        loop {
            let mut changed = false;
            for n in 0..nn {
                for x in 0..na {
                    let mut v = edges[n][x];
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

    /// §5.1 step 3: node n's authority class on actor x: edge admin (admin by any path), else
    /// none (no invites here).
    fn class(&self, r: &[Vec<Role>], n: usize, x: usize) -> Class {
        if r[n][x] == Role::Admin { Class::Edge } else { Class::None }
    }

    /// Entities reaching `m` (included) by edges of any role.
    fn reaching(&self, edges: &[Vec<Role>], m: usize) -> Vec<bool> {
        let (nn, na) = (self.nodes, self.actors());
        let mut v = vec![false; nn + na];
        v[m] = true;
        loop {
            let mut changed = false;
            for e in 0..nn + na {
                if !v[e] && (0..na).any(|x| v[nn + x] && edges[e][x] > Role::None) {
                    v[e] = true;
                    changed = true;
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// Entities reachable from `t` (included) by edges of any role: where a fall on `t` can
    /// reach (§5.1 step 4, "everything N reaches by edges").
    fn reachable(&self, edges: &[Vec<Role>], t: usize) -> Vec<bool> {
        let (nn, na) = (self.nodes, self.actors());
        let mut v = vec![false; nn + na];
        v[t] = true;
        loop {
            let mut changed = false;
            for x in 0..na {
                if !v[nn + x] && (0..nn + na).any(|e| v[e] && edges[e][x] > Role::None) {
                    v[nn + x] = true;
                    changed = true;
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// Whether node a has admin on holder entity m (a node is its own admin).
    fn admin_of(&self, r: &[Vec<Role>], a: usize, m: usize) -> bool {
        m == a || m >= self.nodes && r[a][m - self.nodes] == Role::Admin
    }

    /// §2 self-removal: lowers an edge whose holder the author has admin on, and either lowers
    /// the author's own edge or the author has no edge-admin authority on the target at that
    /// point with the holder's edge there disregarded (authority through the holder does not
    /// count).
    fn is_self_removal(&self, edges: &[Vec<Role>], r: &[Vec<Role>], w: &JWrite) -> bool {
        let lowers = w.role <= edges[w.holder][w.target];
        if !lowers || !self.admin_of(r, w.author, w.holder) {
            return false;
        }
        if w.holder == w.author {
            return true;
        }
        let mut without = edges.to_vec();
        without[w.holder][w.target] = Role::None;
        self.class(&self.roles(&without), w.author, w.target) == Class::None
    }

    /// §5.1 steps 2-3: whether write `w` applies at this point, and its attribution: a
    /// self-removal, or the author's class on the target (admin needed).
    fn authority(&self, edges: &[Vec<Role>], r: &[Vec<Role>], w: &JWrite) -> Attr {
        if self.is_self_removal(edges, r, w) {
            let on = if w.holder == w.author { w.target } else { w.holder - self.nodes };
            return Attr::SelfOnly(self.class(r, w.author, on), on);
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
    /// the edge before it; `own`: its author reached the holder before it): the writes it adds
    /// to D. Every other node x reaching the holder whose class on an actor n below the target
    /// fell (against the edge as restored, x's kept standing included) has its earlier applied
    /// writes on n attributed to a class it fell through, and not covered by i's frontier,
    /// added to D. The author keeps its standing instead.
    #[allow(clippy::too_many_arguments)]
    fn audit(&self, i: usize, old: Role, own: bool, edges: &[Vec<Role>], r: &[Vec<Role>], attr: &[Attr], rest: &mut Restored, audit: bool) -> u64 {
        let (nn, na) = (self.nodes, self.actors());
        let w = &self.writes[i];
        let (a, m, t) = (w.author, w.holder, w.target);
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
                    let (c, on) = match attr[j] {
                        Attr::By(c) => (c, wj.target),
                        Attr::SelfOnly(c, on) => (c, on),
                        Attr::Skipped => continue,
                    };
                    if j == i || wj.author != x || on != n {
                        continue;
                    }
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
        let mut demoting = 0u64;
        for &i in order {
            let w = &self.writes[i];
            if dropped >> i & 1 == 1 {
                continue;
            }
            attr[i] = self.authority(&edges, &r, w);
            if attr[i] == Attr::Skipped {
                continue;
            }
            let old = edges[w.holder][w.target];
            let own = self.reaching(&edges, w.holder)[w.author];
            edges[w.holder][w.target] = w.role;
            r = self.roles(&edges);
            if let Attr::SelfOnly(..) = attr[i] {
                // Audits nothing; the next explicit write restores `old`.
                let s = &mut rest.since[w.holder][w.target];
                *s = (*s).max(old);
                continue;
            }
            if w.role < old && w.holder != w.author {
                demoting |= 1 << i;
            }
            let added = self.audit(i, old, own, &edges, &r, &attr, &mut rest, audit);
            if added != 0 {
                return Pass { edges, roles: r, attr, added, demoting };
            }
        }
        Pass { edges, roles: r, attr, added: 0, demoting }
    }

    /// The timeline (§5.1): walks from scratch, each walk restarting with the writes the last
    /// one added to D (sticky within the evaluation), until a walk adds nothing (step 5).
    /// `audit = false` never drops (the reference for the nobody-offline check).
    pub fn eval(&self, audit: bool) -> JOut {
        self.eval_from(audit, 0).0
    }

    /// The timeline with D starting at `d0` (a trust set's seeds, `crate::trust`), and the
    /// explicit writes the settled walk applied lowering another holder's edge.
    pub fn eval_from(&self, audit: bool, d0: u64) -> (JOut, u64) {
        let order = self.order();
        let mut dropped = d0;
        let mut passes = 0;
        loop {
            passes += 1;
            let p = self.pass(&order, dropped, audit);
            if p.added == 0 {
                let applied = (0..self.writes.len()).filter(|&j| p.attr[j] != Attr::Skipped).fold(0u64, |m, j| m | 1 << j);
                return (JOut { edges: p.edges, roles: p.roles, applied, dropped, passes }, p.demoting);
            }
            dropped |= p.added;
        }
    }
    /// For layer 2 (`crate::addenda`): the settled walk replayed, with the roles after each
    /// applied write and every explicit demotion below write (§5.2): an applied explicit write
    /// by another author that demotes node x on actor n (§5.1 step 4: x reaches the holder, n
    /// below the target) and takes x's role on n, with the edge as restored, from write or
    /// above to below write. Reads the walk; changes nothing in it.
    pub fn steps(&self) -> Steps {
        let dropped = self.eval(true).dropped;
        let (nn, na) = (self.nodes, self.actors());
        let mut edges = self.genesis.clone();
        let mut r = self.roles(&edges);
        let mut st = Steps { genesis: r.clone(), after: vec![], demotions: vec![] };
        let mut rest = Restored { since: vec![vec![Role::None; na]; nn + na], kept: HashMap::new() };
        let mut attr = vec![Attr::Skipped; self.writes.len()];
        for i in self.order() {
            let w = &self.writes[i];
            if dropped >> i & 1 == 1 {
                continue;
            }
            attr[i] = self.authority(&edges, &r, w);
            if attr[i] == Attr::Skipped {
                continue;
            }
            let (a, m, t) = (w.author, w.holder, w.target);
            let old = edges[m][t];
            let own = self.reaching(&edges, m)[a];
            edges[m][t] = w.role;
            r = self.roles(&edges);
            if let Attr::SelfOnly(..) = attr[i] {
                let s = &mut rest.since[m][t];
                *s = (*s).max(old);
                st.after.push((i, r.clone()));
                continue;
            }
            let base = rest.since[m][t].max(old);
            let (up, down) = (self.reaching(&edges, m), self.reachable(&edges, nn + t));
            for x in (0..nn).filter(|&x| x != a && up[x]) {
                let mut was = edges.clone();
                was[m][t] = base.max(rest.kept.get(&(m, t, x)).copied().unwrap_or(Role::None));
                let rw = self.roles(&was);
                for n in (0..na).filter(|&n| down[nn + n] && rw[x][n] >= Role::Write && r[x][n] < Role::Write) {
                    st.demotions.push((i, x, n));
                }
            }
            let added = self.audit(i, old, own, &edges, &r, &attr, &mut rest, true);
            debug_assert_eq!(added, 0, "the settled walk adds nothing");
            st.after.push((i, r.clone()));
        }
        st
    }

    fn permute(&self, perm: &[usize]) -> JHist {
        JHist {
            nodes: self.nodes,
            admins: self.admins.clone(),
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

/// A trace: actors with their first admins, genesis edges, then each write in walk order with
/// its index, author, commit ID and who received it when.
impl std::fmt::Display for JHist {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let nm = |e: usize| ent_name(self.nodes, e);
        let admins: Vec<String> = (0..self.actors()).map(|x| format!("A{x} first admin {}", nm(self.admins[x]))).collect();
        writeln!(f, "nodes n0..n{}; {}", self.nodes - 1, admins.join(", "))?;
        for (m, row) in self.genesis.iter().enumerate() {
            for (x, r) in row.iter().enumerate().filter(|(_, r)| **r != Role::None) {
                writeln!(f, "  genesis: {} {r:?} on A{x}", nm(m))?;
            }
        }
        for i in self.order() {
            let w = &self.writes[i];
            writeln!(f, "  w{i}: t={} {} (id {}) sets {} on A{} := {:?} | {}", w.t, nm(w.author), w.id, nm(w.holder), w.target, w.role, crate::fmt_recv(&self.recv[i], w.author))?;
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
            let used = self.writes.iter().any(|w| w.author == k || w.holder == k) || self.genesis[k].iter().any(|&r| r != Role::None) || self.admins.contains(&k);
            if !used {
                let mut h = self.clone();
                h.nodes -= 1;
                h.genesis.remove(k);
                for r in &mut h.recv {
                    r.remove(k);
                }
                for w in &mut h.writes {
                    w.author -= usize::from(w.author > k);
                    w.holder -= usize::from(w.holder > k);
                }
                h.admins.iter_mut().for_each(|a| *a -= usize::from(*a > k));
                out.push(h);
            }
        }
        for x in (0..na).filter(|_| na > 1) {
            let e = nn + x;
            let used = self.writes.iter().any(|w| w.target == x || w.holder == e) || self.genesis[e].iter().any(|&r| r != Role::None) || self.genesis.iter().enumerate().any(|(m, row)| row[x] != Role::None && m != e) || self.admins.contains(&e);
            if !used {
                let mut h = self.clone();
                h.admins.remove(x);
                h.genesis.remove(e);
                for row in &mut h.genesis {
                    row.remove(x);
                }
                for w in &mut h.writes {
                    w.target -= usize::from(w.target > x);
                    w.holder -= usize::from(w.holder > e);
                }
                h.admins.iter_mut().for_each(|a| *a -= usize::from(*a > e));
                out.push(h);
            }
        }
        for m in 0..self.genesis.len() {
            // an actor keeps its record edge
            for x in (0..na).filter(|&x| self.admins[x] != m) {
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

// ---------- disputes (crate::trust) ----------

impl JHist {
    /// Every edge ever held: genesis or written with a role.
    fn ever(&self) -> Vec<Vec<Role>> {
        let mut e = self.genesis.clone();
        for w in &self.writes {
            e[w.holder][w.target] = e[w.holder][w.target].max(w.role);
        }
        e
    }

    /// Actors reachable from actor `n` by edges ever held: what a demotion on `n` puts in
    /// question.
    pub fn reach(&self, n: usize) -> Vec<bool> {
        let v = self.reachable(&self.ever(), self.nodes + n);
        (0..self.actors()).map(|x| v[self.nodes + x]).collect()
    }

    /// Whether write `j` lowers its author's own edge: below the value the last held write on
    /// that edge ordered before it set (else genesis). Static: a function of the history, not
    /// of any walk.
    fn lowers_own(&self, j: usize) -> bool {
        let w = &self.writes[j];
        if w.holder != w.author {
            return false;
        }
        let key = |i: usize| (self.writes[i].t, self.writes[i].author, self.writes[i].id);
        let prev = (0..self.writes.len()).filter(|&i| i != j && self.writes[i].holder == w.holder && self.writes[i].target == w.target && key(i) < key(j)).max_by_key(|&i| key(i));
        w.role < prev.map_or(self.genesis[w.holder][w.target], |i| self.writes[i].role)
    }
}

impl crate::trust::Trusting for JHist {
    type Res = (Vec<Vec<Role>>, Vec<Vec<Role>>, Vec<u32>);
    fn n_ops(&self) -> usize {
        self.writes.len()
    }
    fn n_writes(&self) -> usize {
        self.writes.len()
    }
    fn walk_from(&self, d0: u64) -> crate::trust::Walked<Self::Res> {
        let (o, demoting) = self.eval_from(true, d0);
        crate::trust::Walked { res: self.result(&o), applied: o.applied, demoting }
    }
    fn plain(&self) -> Self::Res {
        self.result(&walk(self))
    }
    fn victim(&self, i: usize) -> Option<usize> {
        let w = &self.writes[i];
        (w.holder != w.author).then_some(w.holder)
    }
    /// The writes ordered before R, on its target and below it, by nodes other than the
    /// demoter that ever reach the holder by admin edges, that the demoter had not received
    /// before `t`, but their writes lowering their own edges (`lowers_own`: a self-grant is a
    /// seed, a self-removal not).
    fn seeds(&self, i: usize) -> u64 {
        let Some(m) = self.victim(i) else { return 0 };
        let r = &self.writes[i];
        let admins: Vec<Vec<Role>> = self.ever().iter().map(|row| row.iter().map(|&r| if r == Role::Admin { r } else { Role::None }).collect()).collect();
        let up = self.reaching(&admins, m);
        let below = self.reach(r.target);
        let in_question = |w: &JWrite| below[w.target] || w.holder >= self.nodes && below[w.holder - self.nodes];
        (0..self.writes.len())
            .filter(|&j| j != i && up[self.writes[j].author] && self.writes[j].author != r.author && !self.lowers_own(j) && in_question(&self.writes[j]) && self.recv[j][r.author] >= r.t && (self.writes[j].t, self.writes[j].author, self.writes[j].id) < (r.t, r.author, r.id))
            .fold(0, |m, j| m | 1 << j)
    }
    fn key(&self, i: usize) -> (u32, usize) {
        (self.writes[i].id, 0)
    }
    fn permute(&self, perm: &[usize]) -> Self {
        JHist::permute(self, perm)
    }
    fn honest(&self) -> Option<Self> {
        honest(self)
    }
    fn mutual(&self) -> bool {
        let ever = self.ever();
        let up: Vec<Vec<bool>> = (0..self.nodes + self.actors()).map(|m| self.reaching(&ever, m)).collect();
        let lowers = |w: &JWrite, x: usize| w.role < Role::Admin && w.holder != w.author && up[w.holder][x];
        let unlisted = |i: usize, j: usize| self.recv[j][self.writes[i].author] >= self.writes[i].t;
        let n = self.writes.len();
        // node g granted node a something: wrote a role on an edge a reaches through.
        let granted = |g: usize, a: usize| self.writes.iter().any(|w| w.author == g && w.role > Role::None && up[w.holder][a]);
        (0..n).any(|i| (0..n).any(|j| {
            let (a, x) = (self.writes[i].author, self.writes[j].author);
            let hits = |b: usize| b != x && lowers(&self.writes[j], b);
            a != x && lowers(&self.writes[i], x) && (hits(a) || (0..self.nodes).any(|g| granted(g, a) && hits(g))) && unlisted(i, j)
        }))
    }
    fn same_state(&self, a: &Self::Res, b: &Self::Res) -> bool {
        a.0 == b.0 && a.1 == b.1
    }
    fn outside_equal(&self, i: usize, a: &Self::Res, b: &Self::Res) -> bool {
        let below = self.reach(self.writes[i].target);
        (0..self.actors()).filter(|&u| !below[u]).all(|u| a.0.iter().zip(&b.0).all(|(ra, rb)| ra[u] == rb[u]) && a.1.iter().zip(&b.1).all(|(ra, rb)| ra[u] == rb[u]))
    }
}

/// A random history: every actor's first admin a node or a lower actor, holding the record
/// edge (admin) in genesis before every write, removable; other edges start at random
/// (earlier history every node saw); writes by any node, many lowering admins; a third of the
/// receipts never happen, and a quarter of the writes that grant no admin are late
/// (`crate::hold_chains`).
pub fn random_hist(rng: &mut Rng) -> JHist {
    let nodes = 2 + rng.below(3);
    let na = 2 + rng.below(2);
    let ents = nodes + na;
    let mut genesis = vec![vec![Role::None; na]; ents];
    for m in 0..ents {
        for x in 0..na {
            if m != nodes + x && rng.below(3) == 0 {
                genesis[m][x] = [Role::Read, Role::Write, Role::Admin, Role::Admin][rng.below(4)];
            }
        }
    }
    let admins: Vec<usize> = (0..na).map(|x| rng.below(nodes + x)).collect();
    for x in 0..na {
        genesis[admins[x]][x] = Role::Admin;
    }
    let k = 2 + rng.below(7);
    let mut h = JHist { nodes, admins, genesis, writes: vec![], recv: vec![] };
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
        let holder = loop {
            let m = rng.below(ents);
            if m != nodes + target {
                break m;
            }
        };
        let role = [Role::None, Role::None, Role::None, Role::Read, Role::Write, Role::Admin][rng.below(6)];
        let mut r: Vec<u32> = (0..nodes).map(|_| if rng.below(3) == 0 { LATE } else { (t as i64 + rng.below(6) as i64 - 2).max(0) as u32 }).collect();
        r[author] = t;
        h.writes.push(JWrite { author, t, id, target, holder, role });
        h.recv.push(r);
    }
    let ever = h.ever();
    let reach: Vec<Vec<bool>> = (0..nodes).map(|y| h.reachable(&ever, y)).collect();
    let ws: Vec<(usize, u32)> = h.writes.iter().map(|w| (w.author, w.t)).collect();
    let holders: Vec<usize> = h.writes.iter().map(|w| w.holder).collect();
    let eligible: Vec<bool> = h.writes.iter().map(|w| w.role < Role::Admin).collect();
    let late = crate::late_writes(rng, &eligible);
    crate::hold_chains(&ws, &late, |j, x| reach[x][holders[j]], &mut h.recv);
    h
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
            "joint: {} histories ({} with mutual roles, {} with a (t, author) tie) | max passes {} | order-dependent {} | drops with nobody offline {} | nodes disagreeing after every delivery {}",
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

fn check(h: &JHist, st: &mut Stats, rng: &mut Rng) {
    st.histories += 1;
    let na = h.admins.len();
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

    /// Nodes 0..5; actors A (first admin node 0) and B (first admin node 1), entities 5 and 6.
    const NODES: usize = 5;
    const A: usize = 0;
    const B: usize = 1;
    const EA: usize = NODES + A;
    const EB: usize = NODES + B;

    struct Jb(JHist);
    impl Jb {
        /// Actors with their first admin entities (record edges in genesis) and more genesis
        /// edges.
        fn new(admins: Vec<usize>, edges: &[(usize, usize, Role)]) -> Self {
            let na = admins.len();
            let mut genesis = vec![vec![None; na]; NODES + na];
            for (x, &a) in admins.iter().enumerate() {
                genesis[a][x] = Admin;
            }
            for &(m, x, r) in edges {
                genesis[m][x] = r;
            }
            Jb(JHist { nodes: NODES, admins, genesis, writes: vec![], recv: vec![] })
        }
        fn set(&mut self, author: usize, target: usize, holder: usize, role: Role, t: u32, recv: &[(usize, u32)]) -> usize {
            let mut r = vec![LATE; NODES];
            r[author] = t;
            for &(m, tm) in recv {
                r[m] = tm;
            }
            let id = 100 + self.0.writes.len() as u32;
            self.0.writes.push(JWrite { author, t, id, target, holder, role });
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

    /// Mutual roles: A and B are admins of each other; node 2 is an admin of A, hence
    /// of B. 2 grants node 3 admin on B; A's first admin removes 2 from A. The grant falls iff
    /// the first admin had not received it; both walks terminate.
    #[test]
    fn mutual_roles() {
        for seen in [false, true] {
            let mut edges = mutual();
            edges.push((2, A, Admin));
            let mut b = Jb::new(vec![0, 1], &edges);
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
    /// earlier wins: y has no authority left at t=3. If A's first admin then removes x without
    /// having received x's removal of y, that removal falls, y's removal of x applies and the
    /// first admin's removal finds x already gone.
    #[test]
    fn concurrent_cross_removals() {
        let (x, y) = (2, 3);
        let mut edges = mutual();
        edges.extend([(x, A, Admin), (y, B, Admin)]);
        let mut b = Jb::new(vec![0, 1], &edges);
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
        let mut b = Jb::new(vec![0, 1], &edges);
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
            let mut b = Jb::new(vec![0, 1], &[(2, A, Admin)]);
            let g = b.set(2, A, 3, Admin, 2, &[]);
            let r = b.set(2, A, 3, None, 2, &[]);
            b.0.writes[g].id = grant_id;
            b.0.writes[r].id = removal_id;
            assert_eq!(b.0.eval(true).roles[3][A], expect);
            assert_order_independent(&b.0);
        }
    }

    /// Two edge-admin paths to one doc D (actor 2, first admin node 0): node 3 is admin of
    /// teams T1 and T2 (actors 0 and 1), both admins of D. 3 grants node 4 admin on D at t=1,
    /// seen by nobody. Removing T1's path (t=3) leaves 3's class on D at edge admin: no audit.
    /// Removing T2's (t=4) drops the grant unless that remover had received it.
    #[test]
    fn two_edge_paths_class_attribution() {
        for seen in [false, true] {
            let (t1, t2, d) = (0, 1, 2);
            let mut b = Jb::new(vec![0, 1, 0], &[(3, t1, Admin), (3, t2, Admin), (NODES + t1, d, Admin), (NODES + t2, d, Admin)]);
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

    /// A record edge path plus an edge: actor P (first admin node 0) is the first admin of doc
    /// G (actor 1); node 3 has an admin edge on G and becomes a P admin at t=2. Its grant on G
    /// at t=1 is edge class. Edge removed first (t=3): 3 keeps admin on G through P's record
    /// edge, no fall, no audit; the P removal (t=4) takes it and audits the grant. P removal
    /// first (t=3): 3's class on G stands by its edge; the edge removal (t=4) audits the grant.
    /// Dropped either way.
    #[test]
    fn record_edge_and_edge_paths() {
        let (p, g) = (0, 1);
        for edge_first in [true, false] {
            let mut b = Jb::new(vec![0, NODES + p], &[(3, g, Admin), (2, p, Admin)]);
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

    /// Self-removal through an actor: node 2, admin of A, removes A's write edge on B (admin
    /// of the holder is its only authority). Audited like a write on A: A's first admin
    /// removing 2 from A without having seen it hands A its edge back; having seen it, the
    /// removal stands.
    #[test]
    fn self_removal_through_actor_audited() {
        for seen in [false, true] {
            let mut b = Jb::new(vec![0, 1], &[(2, A, Admin), (EA, B, Role::Write)]);
            b.set(2, B, EA, None, 2, if seen { &[(0, 3)] } else { &[] });
            b.set(0, A, 2, None, 4, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.edges[EA][B], if seen { None } else { Role::Write }, "seen {seen}");
            assert_eq!(o.dropped != 0, !seen);
            assert_order_independent(&b.0);
        }
    }

    /// Transitive record-edge audit: P (first admin node 0) is the first admin of Q, Q of D.
    /// Node 3 is admin of P, so of D through the record edges, and grants node 4 admin on D at
    /// t=1, seen by nobody. Removing 3 from P (t=3) drops the grant, two record edges below P;
    /// unless 3 keeps admin on D by an admin edge on Q, where its class on D does not fall and
    /// nothing is audited.
    #[test]
    fn transitive_record_edge_audit() {
        let (p, q, d) = (0, 1, 2);
        for keeps_q in [false, true] {
            let mut edges = vec![(3, p, Admin)];
            if keeps_q {
                edges.push((3, q, Admin));
            }
            let mut b = Jb::new(vec![0, NODES + p, NODES + q], &edges);
            b.set(3, d, 4, Admin, 1, &[]);
            b.set(0, p, 3, None, 3, &[]);
            let o = b.0.eval(true);
            assert_eq!(o.roles[4][d], if keeps_q { Admin } else { None }, "keeps Q {keeps_q}");
            assert_order_independent(&b.0);
        }
    }

    /// Node 0 is first admin of group G and doc T; X is admin of G, G admin of T. X grants Y
    /// admin on T, unseen by 0. Node 0, admin of G by G's record edge but also admin of T by
    /// T's, removes G from T: an explicit demotion (not a self-removal), so X's unseen grant is
    /// dropped.
    #[test]
    fn group_removal_by_first_admin_of_both() {
        let (g, t) = (0, 1);
        let mut b = Jb::new(vec![0, 0], &[(1, g, Admin), (NODES + g, t, Admin)]);
        let grant = b.set(1, t, 2, Admin, 3, &[]);
        b.set(0, t, NODES + g, None, 10, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.dropped >> grant & 1, 1);
        assert_eq!(o.roles[2][t], None);
        assert_order_independent(&b.0);
    }

    /// A first admin is an ordinary admin (spec/permissions.md §1): node 0, first admin of A,
    /// grants node 2 admin at t=1; 2 removes 0's record edge at t=3 without having received
    /// 0's grant of node 3 at t=2. The removal applies, 0 holds nothing on A, its unseen grant
    /// drops, and its later grant of itself (t=4) is no write (no authority left).
    #[test]
    fn first_admin_removed_by_another_admin() {
        let mut b = Jb::new(vec![0, 1], &[]);
        b.set(0, A, 2, Admin, 1, &[(2, 1)]);
        let grant = b.set(0, A, 3, Admin, 2, &[]);
        let removal = b.set(2, A, 0, None, 3, &[]);
        let back = b.set(0, A, 0, Admin, 4, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.applied >> removal & 1, 1);
        assert_eq!(o.dropped >> grant & 1, 1);
        assert_eq!(o.applied >> back & 1, 0);
        assert_eq!((o.roles[0][A], o.roles[2][A], o.roles[3][A]), (None, Admin, None));
        assert_order_independent(&b.0);
    }
}
