//! Two-level model of roster snapshots (spec/permissions.md §6). Key actor
//! K (node 0) owns person actor P, whose admins are devices; P owns G. Membership writes
//! target P or G; a write on G by a P-admin acts through the owner chain. A **snapshot** of a
//! thing is a write by its owner chain (P: K; G: K or a P-admin at that time) carrying the
//! thing's whole roster. The timeline of a thing starts at its newest *applied* owner-chain
//! snapshot: author had chain authority at its time by the chain's timeline, and no later
//! demotion of the author dropped it. That roster also stands for every earlier time.
//! Without one the node walks everything it holds (a compacted node: from an empty roster).
//! Snapshots by edge-admins are ignored. Everything else is the demoter-frontier rule; a
//! P-demotion audits the device's writes made as P-admin (on P and on G), a G-demotion
//! only writes made by edge authority, so edge-admins never touch snapshots.
//!
//! Checked (`cargo run --release [samples] snapshot`, `cargo test`): compaction, that is
//! removing every write of a thing before any applied snapshot of it, never changes the
//! result; nothing is dropped when nobody is offline; input order independence; bounded
//! passes. A compaction point that a later backdated removal un-applies diverges from the
//! full history until a fresh snapshot follows the removal (`compaction_at_unapplied`).

use crate::Role;
use std::collections::HashSet;

pub const K: usize = 0;
const LATE: u32 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Thing {
    P,
    G,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SWrite {
    pub author: usize,
    pub thing: Thing,
    /// Ignored for snapshots.
    pub target: usize,
    pub role: Role,
    pub t: u32,
    /// Full roster of `thing` over all nodes (K's entry ignored).
    pub snap: Option<Vec<Role>>,
}

#[derive(Clone, Debug)]
pub struct SHist {
    pub gp: Vec<Role>,
    pub gg: Vec<Role>,
    pub writes: Vec<SWrite>,
    /// [write][node] receipt time on the receiver's clock; author: its own `t`.
    pub recv: Vec<Vec<u32>>,
}

#[derive(Clone, Debug)]
pub struct ThingOut {
    /// roles_after[k]: roles after processing the first k positions of the global order
    /// (the start roster for every position before the epoch start).
    pub roles_after: Vec<Vec<Role>>,
    pub roles: Vec<Role>,
    pub applied: u64,
    pub dropped: u64,
    /// Applied writes that took their target from effective admin to below: (write, target).
    pub demotions: Vec<(usize, usize)>,
    pub passes: usize,
    pub start: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Out {
    pub p: ThingOut,
    pub g: ThingOut,
}

fn max_role(a: Role, b: Role) -> Role {
    if a >= b {
        a
    } else {
        b
    }
}

impl SHist {
    pub fn n(&self) -> usize {
        self.gp.len()
    }

    pub fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| (self.writes[i].t, self.writes[i].author));
        o
    }

    /// `audit = false` evaluates without frontiers (nothing is ever dropped), the reference
    /// for the nobody-offline check.
    pub fn eval(&self, audit: bool) -> Out {
        let order = self.order();
        let p = self.walk(Thing::P, &order, &self.gp, &|a, _| if a == K { Role::Admin } else { Role::None }, 0, audit);
        // A device demoted from P: its writes on G that the demoter had not received are dropped.
        let mut dropped_g = 0u64;
        if audit {
            let pos_of = pos_of(&order);
            for &(r, z) in &p.demotions {
                let rw = &self.writes[r];
                for (j, w) in self.writes.iter().enumerate() {
                    let as_device = p.roles_after[pos_of[j]][z] == Role::Admin;
                    if w.thing == Thing::G && w.author == z && as_device && pos_of[j] < pos_of[r] && !(self.recv[j][rw.author] < rw.t) {
                        dropped_g |= 1 << j;
                    }
                }
            }
        }
        let chain = |a: usize, pos: usize| if a == K { Role::Admin } else { p.roles_after[pos][a] };
        let g = self.walk(Thing::G, &order, &self.gg, &chain, dropped_g, audit);
        Out { p, g }
    }

    fn walk(
        &self,
        thing: Thing,
        order: &[usize],
        genesis: &[Role],
        chain: &dyn Fn(usize, usize) -> Role,
        mut dropped: u64,
        audit: bool,
    ) -> ThingOut {
        let n = self.n();
        let pos_of = pos_of(order);
        // Epoch start: newest applied owner-chain snapshot of this thing. Only a demotion in
        // the chain can drop one, and those drops are known before this walk.
        let start = (0..self.writes.len())
            .filter(|&i| {
                let w = &self.writes[i];
                w.thing == thing && w.snap.is_some() && chain(w.author, pos_of[i]) == Role::Admin && dropped >> i & 1 == 0
            })
            .max_by_key(|&i| pos_of[i]);
        let mut passes = 0;
        'walk: loop {
            passes += 1;
            let (mut roles, start_pos) = match start {
                Some(s) => (self.writes[s].snap.clone().unwrap(), pos_of[s] + 1),
                None => (genesis.to_vec(), 0),
            };
            roles[K] = Role::Admin;
            let mut applied = 0u64;
            if let Some(s) = start {
                applied |= 1 << s;
            }
            let mut demotions = Vec::new();
            let mut chain_of: Vec<Option<usize>> = vec![None; n];
            let mut roles_after = vec![roles.clone(); start_pos.min(order.len()) + 1];
            for pos in start_pos..order.len() {
                let i = order[pos];
                let w = &self.writes[i];
                if w.thing != thing || dropped >> i & 1 == 1 || w.target == K || w.snap.is_some() {
                    // A snapshot here is inapplicable or dropped (an applied one would be the start).
                    roles_after.push(roles.clone());
                    continue;
                }
                let a = w.author;
                let is_admin = |x: usize, roles: &[Role]| x == K || roles[x] == Role::Admin || chain(x, pos) == Role::Admin;
                if !is_admin(a, &roles) {
                    roles_after.push(roles.clone());
                    continue;
                }
                let old = max_role(roles[w.target], chain(w.target, pos));
                roles[w.target] = w.role;
                applied |= 1 << i;
                let new = max_role(w.role, chain(w.target, pos));
                if old == Role::Admin && new < Role::Admin {
                    demotions.push((i, w.target));
                    if audit {
                        let mut grew = false;
                        for j in 0..self.writes.len() {
                            if applied >> j & 1 == 0 || self.writes[j].author != w.target || j == i {
                                continue;
                            }
                            if chain(w.target, pos_of[j]) == Role::Admin {
                                continue; // made by chain authority, audited by the chain's demotions
                            }
                            let covered = self.recv[j][a] < w.t || chain_of[a] == Some(j);
                            if !covered {
                                dropped |= 1 << j;
                                grew = true;
                            }
                        }
                        if grew {
                            continue 'walk;
                        }
                    }
                }
                chain_of[w.target] = Some(i);
                roles_after.push(roles.clone());
            }
            debug_assert_eq!(roles_after.len(), order.len() + 1);
            return ThingOut { roles_after, roles, applied, dropped, demotions, passes, start };
        }
    }

    /// Snapshots of `thing` whose author had chain authority at their time. `applied` further
    /// requires that no demotion dropped them; those are the compaction points whose result
    /// must equal the full history's. The others were compaction points at some node only
    /// if a backdated removal arrived after it compacted.
    pub fn snapshots(&self, thing: Thing, out: &Out, applied: bool) -> Vec<usize> {
        let order = self.order();
        let pos_of = pos_of(&order);
        let t = if thing == Thing::P { &out.p } else { &out.g };
        (0..self.writes.len())
            .filter(|&i| {
                let w = &self.writes[i];
                let chain_admin = w.author == K || (thing == Thing::G && out.p.roles_after[pos_of[i]][w.author] == Role::Admin);
                w.thing == thing && w.snap.is_some() && chain_admin && (!applied || t.dropped >> i & 1 == 0)
            })
            .collect()
    }

    /// The history as held by a node that compacted `thing` at snapshot `s`: every write of
    /// `thing` ordered before `s` is gone, and so is the genesis (nothing before `s` exists).
    pub fn compacted(&self, thing: Thing, s: usize) -> (SHist, Vec<usize>) {
        let order = self.order();
        let pos_of = pos_of(&order);
        let keep: Vec<usize> = (0..self.writes.len())
            .filter(|&i| !(self.writes[i].thing == thing && pos_of[i] < pos_of[s]))
            .collect();
        let empty = vec![Role::None; self.n()];
        let h = SHist {
            gp: if thing == Thing::P { empty.clone() } else { self.gp.clone() },
            gg: if thing == Thing::G { empty } else { self.gg.clone() },
            writes: keep.iter().map(|&i| self.writes[i].clone()).collect(),
            recv: keep.iter().map(|&i| self.recv[i].clone()).collect(),
        };
        (h, keep)
    }

    fn permute(&self, perm: &[usize]) -> SHist {
        SHist {
            gp: self.gp.clone(),
            gg: self.gg.clone(),
            writes: perm.iter().map(|&i| self.writes[i].clone()).collect(),
            recv: perm.iter().map(|&i| self.recv[i].clone()).collect(),
        }
    }
}

fn pos_of(order: &[usize]) -> Vec<usize> {
    let mut p = vec![0; order.len()];
    for (pos, &i) in order.iter().enumerate() {
        p[i] = pos;
    }
    p
}

/// Applied set of `h` restricted to the kept writes, in `h`'s indexing.
fn applied_kept(applied: u64, keep: &[usize]) -> u64 {
    let mut m = 0u64;
    for (new, &old) in keep.iter().enumerate() {
        if applied >> old & 1 == 1 {
            m |= 1 << new;
        }
    }
    m
}

// ---------- search ----------

#[derive(Default)]
pub struct Stats {
    histories: u64,
    with_snapshot_start: u64,
    compactions: u64,
    compaction_mismatch: u64,
    unapplied_points: u64,
    unapplied_diverge: u64,
    order_dep: u64,
    honest_mismatch: u64,
    max_passes: usize,
    ex_compaction: Option<SHist>,
    ex_order: Option<SHist>,
    ex_honest: Option<SHist>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.histories += o.histories;
        self.with_snapshot_start += o.with_snapshot_start;
        self.compactions += o.compactions;
        self.compaction_mismatch += o.compaction_mismatch;
        self.unapplied_points += o.unapplied_points;
        self.unapplied_diverge += o.unapplied_diverge;
        self.order_dep += o.order_dep;
        self.honest_mismatch += o.honest_mismatch;
        self.max_passes = self.max_passes.max(o.max_passes);
        fn pick(a: &mut Option<SHist>, b: Option<SHist>) {
            if let Some(b) = b {
                if a.as_ref().map_or(true, |a| b.writes.len() < a.writes.len()) {
                    *a = Some(b);
                }
            }
        }
        pick(&mut self.ex_compaction, o.ex_compaction);
        pick(&mut self.ex_order, o.ex_order);
        pick(&mut self.ex_honest, o.ex_honest);
    }

    pub fn print(&self) {
        println!(
            "snapshot: {} histories | G starts at a snapshot {} | compactions at applied snapshots {} mismatches {} | compactions at since-unapplied snapshots {} diverging {} | order-dependent {} | drops with nobody offline {} | max passes {}",
            self.histories, self.with_snapshot_start, self.compactions, self.compaction_mismatch, self.unapplied_points, self.unapplied_diverge, self.order_dep, self.honest_mismatch, self.max_passes
        );
        for (label, ex) in [("compaction mismatch", &self.ex_compaction), ("order dependence", &self.ex_order), ("drop with nobody offline", &self.ex_honest)] {
            if let Some(h) = ex {
                println!("  smallest {label} example:");
                print_hist(h);
            }
        }
    }
}

pub fn print_hist(h: &SHist) {
    println!("    genesis P {:?} G {:?}", h.gp, h.gg);
    for i in h.order() {
        let w = &h.writes[i];
        match &w.snap {
            Some(r) => println!("    w{i}: {} snapshots {:?} := {:?} at t={} | recv {:?}", w.author, w.thing, r, w.t, h.recv[i]),
            None => println!("    w{i}: {} sets {:?}[{}] := {:?} at t={} | recv {:?}", w.author, w.thing, w.target, w.role, w.t, h.recv[i]),
        }
    }
    let o = h.eval(true);
    println!(
        "    -> P roles {:?} start {:?} | G roles {:?} start {:?} applied {:#b} dropped {:#b} ({} passes)",
        o.p.roles, o.p.start, o.g.roles, o.g.start, o.g.applied, o.g.dropped, o.g.passes
    );
}

fn check(h: &SHist, st: &mut Stats, rng: &mut crate::Rng) {
    st.histories += 1;
    let o = h.eval(true);
    st.max_passes = st.max_passes.max(o.p.passes.max(o.g.passes));
    if o.g.start.is_some() {
        st.with_snapshot_start += 1;
    }
    for thing in [Thing::P, Thing::G] {
        let applied = h.snapshots(thing, &o, true);
        for s in h.snapshots(thing, &o, false) {
            let (c, keep) = h.compacted(thing, s);
            let oc = c.eval(true);
            let same = oc.p.roles == o.p.roles
                && oc.g.roles == o.g.roles
                && oc.p.applied == applied_kept(o.p.applied, &keep)
                && oc.g.applied == applied_kept(o.g.applied, &keep);
            if applied.contains(&s) {
                st.compactions += 1;
                if !same {
                    st.compaction_mismatch += 1;
                    st.ex_compaction.get_or_insert_with(|| h.clone());
                }
            } else {
                st.unapplied_points += 1;
                if !same {
                    st.unapplied_diverge += 1;
                }
            }
        }
    }
    let perm = rng.perm(h.writes.len());
    let op = h.permute(&perm).eval(true);
    if op.p.roles != o.p.roles || op.g.roles != o.g.roles {
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
        let b = honest.eval(false);
        if a.p.roles != b.p.roles || a.g.roles != b.g.roles || a.p.dropped != 0 || a.g.dropped != 0 {
            st.honest_mismatch += 1;
            st.ex_honest.get_or_insert_with(|| honest.clone());
        }
    }
}

fn random_hist(rng: &mut crate::Rng) -> SHist {
    let devices = 1 + rng.below(2);
    let gnodes = 1 + rng.below(3);
    let n = 1 + devices + gnodes;
    let mut gp = vec![Role::None; n];
    let mut gg = vec![Role::None; n];
    for d in 1..=devices {
        gp[d] = Role::Admin;
    }
    for x in 1 + devices..n {
        gg[x] = [Role::None, Role::Write, Role::Admin, Role::Admin][rng.below(4)];
    }
    let k = 2 + rng.below(7);
    let mut writes = Vec::new();
    let mut recv = Vec::new();
    let rt = |rng: &mut crate::Rng, t: u32| -> u32 {
        if rng.below(3) == 0 {
            LATE
        } else {
            (t as i64 + rng.below(6) as i64 - 2).max(0) as u32
        }
    };
    while writes.len() < k {
        let thing = if rng.below(4) == 0 { Thing::P } else { Thing::G };
        let author = if rng.below(8) == 0 {
            rng.below(n)
        } else if thing == Thing::P || rng.below(2) == 0 {
            rng.below(1 + devices)
        } else {
            1 + devices + rng.below(gnodes)
        };
        let t = 1 + rng.below(10) as u32;
        if writes.iter().any(|w: &SWrite| w.t == t && w.author == author) {
            continue;
        }
        let snap = if rng.below(4) == 0 {
            let roles: Vec<Role> = (0..n)
                .map(|_| match thing {
                    Thing::P => [Role::None, Role::Admin][rng.below(2)],
                    Thing::G => [Role::None, Role::Write, Role::Admin][rng.below(3)],
                })
                .collect();
            Some(roles)
        } else {
            None
        };
        let target = 1 + rng.below(n - 1);
        let role = match thing {
            Thing::P => [Role::None, Role::Admin][rng.below(2)],
            Thing::G => [Role::None, Role::None, Role::Write, Role::Admin][rng.below(4)],
        };
        let mut r: Vec<u32> = (0..n).map(|_| rt(rng, t)).collect();
        r[author] = t;
        writes.push(SWrite { author, thing, target, role, t, snap });
        recv.push(r);
    }
    SHist { gp, gg, writes, recv }
}

pub fn random(samples: u64, seed: u64) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut rng = crate::Rng(seed ^ (th + 1).wrapping_mul(0x9E3779B97F4A7C15));
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
    use Role::*;
    use Thing::*;

    // Nodes: K=0, devices D1=1, D2=2, G members A=3 (admin), B=4 (writer), Z=5 (nobody).
    const D1: usize = 1;
    const D2: usize = 2;
    const A: usize = 3;
    const B: usize = 4;
    const Z: usize = 5;
    const GP: [Role; 6] = [None, Admin, Admin, None, None, None];
    const GG: [Role; 6] = [None, None, None, Admin, Write, None];

    struct B6(SHist);
    impl B6 {
        fn new() -> Self {
            B6(SHist { gp: GP.to_vec(), gg: GG.to_vec(), writes: vec![], recv: vec![] })
        }
        fn push(&mut self, w: SWrite, recv: &[(usize, u32)]) -> usize {
            let mut r = vec![LATE; 6];
            r[w.author] = w.t;
            for &(m, tm) in recv {
                r[m] = tm;
            }
            self.0.writes.push(w);
            self.0.recv.push(r);
            self.0.writes.len() - 1
        }
        fn set(&mut self, author: usize, thing: Thing, target: usize, role: Role, t: u32, recv: &[(usize, u32)]) -> usize {
            self.push(SWrite { author, thing, target, role, t, snap: Option::None }, recv)
        }
        fn snap(&mut self, author: usize, thing: Thing, roster: [Role; 6], t: u32, recv: &[(usize, u32)]) -> usize {
            self.push(SWrite { author, thing, target: 0, role: None, t, snap: Some(roster.to_vec()) }, recv)
        }
    }

    fn g(h: &SHist) -> Vec<Role> {
        h.eval(true).g.roles
    }

    /// Compacting at every applied snapshot gives the full result.
    fn assert_compaction_invariant(h: &SHist) {
        let o = h.eval(true);
        for thing in [P, G] {
            for s in h.snapshots(thing, &o, true) {
                let (c, _) = h.compacted(thing, s);
                let oc = c.eval(true);
                assert_eq!((oc.p.roles, oc.g.roles), (o.p.roles.clone(), o.g.roles.clone()), "compacted {thing:?} at w{s}");
            }
        }
    }

    /// Owner snapshot then churn: the key actor snapshots G, later writes apply on top, a
    /// post-snapshot demotion audits only post-snapshot writes, and a verifier holding only
    /// the snapshot and later writes agrees.
    #[test]
    fn owner_snapshot_then_churn() {
        let mut b = B6::new();
        b.set(A, G, Z, Admin, 2, &[]); // pre-snapshot grant, nobody else saw it
        b.snap(K, G, [None, None, None, Admin, Write, Admin], 5, &[]);
        b.set(Z, G, B, Admin, 6, &[]); // Z admin by the snapshot
        b.set(A, G, Z, None, 8, &[]); // A demotes Z without having received w2: dropped
        let h = b.0;
        assert_eq!(g(&h), vec![Admin, None, None, Admin, Write, None]);
        let o = h.eval(true);
        assert_eq!(o.g.dropped, 0b100);
        assert_compaction_invariant(&h);
        let (c, _) = h.compacted(G, 1);
        assert_eq!(c.writes.len(), 3);
    }

    /// A grant with a pre-snapshot timestamp arriving after the snapshot is ignored
    /// everywhere, whether or not the pre-snapshot history is still held.
    #[test]
    fn late_pre_snapshot_grant() {
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, None], 5, &[(K, 5), (D2, 5), (A, 5), (B, 5)]);
        b.set(A, G, Z, Admin, 4, &[]); // in flight while D1 snapshotted
        let h = b.0;
        assert_eq!(g(&h), vec![Admin, None, None, Admin, Write, None]);
        assert_compaction_invariant(&h);
    }

    /// Stolen device D1 snapshots G at t=5 granting Z admin. D2 removes D1 from P backdated
    /// to t=3: the snapshot no longer applies. A node holding the full history falls back to
    /// it (Z gone, A and B as before); a node that compacted at the snapshot holds nothing
    /// before it and sees an empty roster: they diverge until D2's fresh snapshot, which
    /// both start from. Removal at t=7 by a node that received the snapshot at t=6 leaves
    /// it standing; at t=7 without having received it, the snapshot is dropped, same
    /// divergence, same remedy.
    #[test]
    fn stolen_device_snapshot_undone_by_backdated_removal() {
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, Admin], 5, &[(D2, 6), (A, 5), (Z, 5)]);
        b.set(D2, P, D1, None, 3, &[]);
        let h = b.0.clone();
        let o = h.eval(true);
        assert_eq!(o.p.roles, vec![Admin, None, Admin, None, None, None]);
        assert_eq!(o.g.start, Option::None);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert!(h.snapshots(G, &o, true).is_empty());
        let (c, _) = h.compacted(G, 0);
        assert_eq!(g(&c), vec![Admin, None, None, None, None, None]);
        // Recourse: D2 re-snapshots after the removal; full and compacted agree again.
        b.snap(D2, G, [None, None, None, Admin, Write, None], 7, &[]);
        let h2 = b.0;
        assert_eq!(g(&h2), vec![Admin, None, None, Admin, Write, None]);
        let (c2, _) = h2.compacted(G, 0);
        assert_eq!(g(&c2), g(&h2));
        assert_compaction_invariant(&h2);
        // Removal at t=7 with the snapshot received at t=6: covered, it stands.
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, Admin], 5, &[(D2, 6), (A, 5), (Z, 5)]);
        b.set(D2, P, D1, None, 7, &[]);
        assert_eq!(g(&b.0), vec![Admin, None, None, Admin, Write, Admin]);
        assert_compaction_invariant(&b.0);
        // Removal at t=7 by a remover that never received it: dropped.
        let mut b = B6::new();
        let s = b.snap(D1, G, [None, None, None, Admin, Write, Admin], 5, &[(A, 5), (Z, 5)]);
        b.set(D2, P, D1, None, 7, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.dropped >> s & 1, 1);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
    }

    /// A device removed from P cannot mint an epoch start: a snapshot claimed after its
    /// removal is inapplicable, one backdated into its tenure is dropped by the removal's
    /// frontier. Neither is ever the start, so nobody compacts at it and nothing diverges.
    #[test]
    fn forged_snapshot_by_removed_device() {
        let mut b = B6::new();
        b.set(D2, P, D1, None, 4, &[(K, 4), (A, 4)]);
        b.snap(D1, G, [None, None, None, None, None, Admin], 8, &[]); // after removal
        b.snap(D1, G, [None, None, None, None, None, Admin], 3, &[]); // backdated into tenure
        let h = b.0.clone();
        let o = h.eval(true);
        assert_eq!(o.g.start, Option::None);
        assert_eq!(o.g.dropped, 0b100);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert!(h.snapshots(G, &o, true).is_empty());
        b.snap(D2, G, [None, None, None, Admin, Write, None], 6, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.g.start, Some(3));
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
        assert_compaction_invariant(&b.0);
    }

    /// An edge-admin of G demoting an ex-device's edge role audits only the writes it made
    /// by edge authority, never its snapshot.
    #[test]
    fn edge_demotion_never_audits_chain_writes() {
        let mut b = B6::new();
        b.set(A, G, D1, Admin, 1, &[(D1, 1)]); // D1 also edge-admin of G
        let s = b.snap(D1, G, [None, Admin, None, Admin, Write, Admin], 5, &[(D2, 5), (A, 5)]);
        b.set(D2, P, D1, None, 7, &[]); // covered: D2 received the snapshot
        b.set(A, G, D1, None, 9, &[]); // A never received the snapshot; irrelevant
        let o = b.0.eval(true);
        assert_eq!(o.g.dropped >> s & 1, 0);
        assert_eq!(o.g.start, Some(s));
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, Admin]);
        assert_compaction_invariant(&b.0);
    }

    /// A snapshot by an edge-admin of G is not an epoch start and is ignored.
    #[test]
    fn edge_admin_snapshot_ignored() {
        let mut b = B6::new();
        b.snap(A, G, [None, None, None, Admin, Admin, Admin], 5, &[]);
        let h = b.0;
        let o = h.eval(true);
        assert_eq!(o.g.start, Option::None);
        assert_eq!(o.g.roles, vec![Admin, None, None, Admin, Write, None]);
    }

    /// A demotion in P audits the device's ordinary writes on G too.
    #[test]
    fn p_demotion_audits_g_writes() {
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[]);
        b.set(D2, P, D1, None, 5, &[]);
        assert_eq!(g(&b.0)[Z], None);
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[(D2, 3)]);
        b.set(D2, P, D1, None, 5, &[]);
        assert_eq!(g(&b.0)[Z], Admin);
    }

    /// The key actor's snapshot of P: its roster stands for all earlier time, so a device
    /// it omits never had authority on G, and compaction of P changes nothing.
    #[test]
    fn owner_snapshot_of_p_governs_earlier_time() {
        let mut b = B6::new();
        b.set(D1, G, Z, Admin, 2, &[(D2, 2), (A, 2)]);
        b.snap(K, P, [None, None, Admin, None, None, None], 6, &[]);
        let h = b.0;
        let o = h.eval(true);
        assert_eq!(o.p.roles, vec![Admin, None, Admin, None, None, None]);
        assert_eq!(o.g.roles[Z], None);
        assert_eq!(o.g.applied, 0);
        assert_compaction_invariant(&h);
    }

    /// Two owner-chain snapshots: the newer applicable one wins, and compacting at the
    /// older one still agrees.
    #[test]
    fn newest_applicable_snapshot_wins() {
        let mut b = B6::new();
        b.snap(D1, G, [None, None, None, Admin, Write, Admin], 3, &[]);
        b.set(A, G, B, Admin, 4, &[]);
        b.snap(D2, G, [None, None, None, Admin, None, None], 6, &[]);
        b.set(A, G, Z, Write, 7, &[]);
        let h = b.0;
        assert_eq!(g(&h), vec![Admin, None, None, Admin, None, Write]);
        assert_eq!(h.eval(true).g.start, Some(2));
        assert_compaction_invariant(&h);
    }
}
