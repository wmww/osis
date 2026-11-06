//! Differential tests against core/test/roles-model (notes/testing.md): random histories from
//! the model, evaluated by both; equal rosters, roles, applied and dropped sets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::needless_range_loop)]

use crate::common;

use common::*;
use roles_model::shrink::{shrink, Shrink};
use roles_model::{edges, joint, Rng};
use osis_base::{CommitId, Role, Tid};
use osis_perm::{At, Edge, Timeline, WriteId};

/// A joint-model history as a world: node i is the i-th smallest key-actor tid, genesis edges
/// but the record edges are writes by the key actor at the top of the target's record chain at
/// t=0.
struct JointWorld {
    w: World,
    nodes: Vec<Tid>,
    actors: Vec<Tid>,
    ids: Vec<CommitId>,
}

fn joint_world(h: &joint::JHist) -> JointWorld {
    let mut w = World::new();
    let nodes = w.nodes(h.nodes);
    let (actors, top) = joint_actors(&mut w, h, &nodes);
    joint_genesis(&mut w, h, &nodes, &actors, &top, Some(&gen_id));
    let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
    let mut ids = Vec::new();
    for (i, jw) in h.writes.iter().enumerate() {
        let id = cid(jw.id);
        ids.push(id);
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
        w.commit_id(id, nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.holder), model_role(jw.role).map(Edge::new))], &recv);
    }
    JointWorld { w, nodes, actors, ids }
}

/// Compares perm with the joint model on one history; returns a description of the first
/// difference.
fn joint_diff(h: &joint::JHist) -> Option<String> {
    let jw = joint_world(h);
    let o = joint::walk(h);
    let tl = Timeline::evaluate(&jw.w.held());
    joint_check(h, &jw, &tl, &o.roles, &o.edges, o.applied, o.dropped)
}

/// Compares `tl` with a joint-model result (roles, edges, applied and dropped writes by index).
fn joint_check(h: &joint::JHist, jw: &JointWorld, tl: &Timeline, roles: &[Vec<roles_model::Role>], edges: &[Vec<roles_model::Role>], applied: u64, dropped: u64) -> Option<String> {
    for n in 0..h.nodes {
        for x in 0..h.admins.len() {
            let (m, p) = (model_role(roles[n][x]), tl.role(&jw.nodes[n], &jw.actors[x], At::END));
            if m != p {
                return Some(format!("role of node {n} on actor {x}: model {m:?} perm {p:?}"));
            }
        }
    }
    let ents = h.nodes + h.admins.len();
    for m in 0..ents {
        for x in 0..h.admins.len() {
            if m == h.nodes + x {
                continue;
            }
            let holder = if m < h.nodes { jw.nodes[m] } else { jw.actors[m - h.nodes] };
            let pe = tl.roster(&jw.actors[x], At::END).get(&holder).map(|e| e.role);
            if model_role(edges[m][x]) != pe {
                return Some(format!("edge {m} on {x}: model {:?} perm {pe:?}", edges[m][x]));
            }
        }
    }
    for i in 0..h.writes.len() {
        let id = WriteId(jw.ids[i], 0);
        let (ma, md) = (applied >> i & 1 == 1, dropped >> i & 1 == 1);
        let (pa, pd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
        if (ma, md) != (pa, pd) {
            return Some(format!("write {i}: model applied {ma} dropped {md}, perm applied {pa} dropped {pd}"));
        }
    }
    None
}

/// Runs `samples` histories from `history` through `diff`, calling `each` on every one. A
/// mismatching history is reported as a trace (`OSIS_PERM_SHRINK=1`: shrunk while it still
/// mismatches); the run fails after three.
fn model_run<H: Shrink + Clone + std::fmt::Display>(samples: u64, seed: u64, history: impl Fn(&mut Rng) -> H, diff: impl Fn(&H) -> Option<String>, mut each: impl FnMut(&H)) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let mut fails = Vec::new();
    for s in 0..samples {
        let h = history(&mut rng);
        each(&h);
        if diff(&h).is_some() {
            let shrunk = osis_base::testenv::u64_var("OSIS_PERM_SHRINK").is_some_and(|n| n != 0);
            let (m, what) = if shrunk { (shrink(h.clone(), |c| diff(c).is_some()), "shrunk") } else { (h, "as made; OSIS_PERM_SHRINK=1 shrinks it") };
            let d = diff(&m).unwrap_or_default();
            fails.push(format!("seed {seed:#x} sample {s} ({what}): {d}\n{m}"));
            if fails.len() >= 3 {
                break;
            }
        }
    }
    assert!(fails.is_empty(), "{} mismatches:\n{}", fails.len(), fails.join("\n"));
}

fn joint_run(samples: u64, seed: u64) {
    let mut with_drops = 0u64;
    // histories where an audit dropped something (late forgeries, unseen writes)
    model_run(samples, seed, joint::random_hist, joint_diff, |h| with_drops += u64::from(joint::walk(h).dropped != 0));
    eprintln!("joint model: {samples} histories, {with_drops} with drops");
}

/// spec/permissions.md §5.1: the joint walk agrees with core/test/roles-model `joint`.
#[test]
fn joint_model_agrees() {
    joint_run(300, 0x5eed_0001);
}

/// spec/permissions.md §5.1: as above, more samples (tier 2).
#[test]
#[ignore]
fn joint_model_agrees_large() {
    sharded(100_000, 0x5eed_0002, joint_run);
}

/// spec/permissions.md §5.1, shrunk from OSIS_PERM_SEED=1303000: n1 removes A1's admin edge on A0 (explicit, n1 also has
/// its own admin edge there), removes the now absent edge again, then removes itself; n0 (who
/// received none of it) removes A1's edge. The second removal keeps n1's standing from the
/// first (§5.1 "R never demotes its own author"), so n0's write audits both against it and
/// drops them, and n1's unseen self-removal with them (perm lost the standing at the write on
/// the absent edge).
#[test]
fn joint_kept_standing_survives_absent_edge_removal() {
    let h = absent_edge_removal_hist();
    let o = joint::walk(&h);
    assert_eq!(o.dropped, 0b1101, "model drops both of n1's explicit removals and its leave");
    assert_eq!(joint_diff(&h), None);
}

/// The history of `joint_kept_standing_survives_absent_edge_removal`.
fn absent_edge_removal_hist() -> joint::JHist {
    use joint::{JHist, JWrite};
    use roles_model::Role::{Admin, None as Gone};
    const LATE: u32 = roles_model::shrink::LATE;
    let w = |author, t, id, holder| JWrite { author, t, id, target: 0, holder, role: Gone };
    // entities: n0, n1, A0, A1; n0 is A0's first admin, n1 A1's
    let mut genesis = vec![vec![Gone; 2]; 4];
    genesis[0][0] = Admin;
    genesis[1][1] = Admin;
    genesis[1][0] = Admin;
    genesis[3][0] = Admin;
    JHist {
        nodes: 2,
        admins: vec![0, 1],
        genesis,
        writes: vec![w(1, 1, 4, 3), w(0, 3, 2, 3), w(1, 2, 1, 1), w(1, 1, 3, 3)],
        recv: vec![vec![LATE, 1], vec![3, LATE], vec![LATE, 2], vec![LATE, 1]],
    }
}

/// spec/permissions.md §5.1: `joint_kept_standing_survives_absent_edge_removal` spread out
/// for incremental placement (`incremental::kept_standing_absent_edge_every_order`): n0 grants
/// n2 read on A0 between n1's removals and n1's self-removal, so the removal of the absent edge
/// can arrive late and be inserted before it.
pub(crate) fn absent_edge_removal_spread_hist() -> joint::JHist {
    use joint::{JHist, JWrite};
    use roles_model::Role::{Admin, None as Gone, Read};
    const LATE: u32 = roles_model::shrink::LATE;
    let w = |author, t, id, holder, role| JWrite { author, t, id, target: 0, holder, role };
    // entities: n0, n1, n2, A0, A1; n0 is A0's first admin, n1 A1's
    let mut genesis = vec![vec![Gone; 2]; 5];
    genesis[0][0] = Admin;
    genesis[1][1] = Admin;
    genesis[1][0] = Admin;
    genesis[4][0] = Admin;
    JHist {
        nodes: 3,
        admins: vec![0, 1],
        genesis,
        writes: vec![w(1, 1, 3, 4, Gone), w(1, 1, 4, 4, Gone), w(0, 5, 5, 2, Read), w(1, 6, 1, 1, Gone), w(0, 7, 2, 4, Gone)],
        recv: vec![vec![LATE, 1, LATE], vec![LATE, 1, LATE], vec![5, LATE, LATE], vec![LATE, 6, LATE], vec![7, LATE, LATE]],
    }
}

/// spec/permissions.md §5.1: perm agrees with the model on `absent_edge_removal_spread_hist`.
#[test]
fn joint_kept_standing_spread_agrees() {
    let h = absent_edge_removal_spread_hist();
    assert_eq!(joint::walk(&h).dropped, 0b1011, "model drops both of n1's explicit removals and its leave");
    assert_eq!(joint_diff(&h), None);
}

/// An edges-model history: node 0 is first admin of the one target T; genesis edges are its writes at t=0.
struct EdgesWorld {
    w: World,
    nodes: Vec<Tid>,
    t: Tid,
    ids: Vec<CommitId>,
}

fn edges_world(h: &edges::EHist) -> EdgesWorld {
    let mut w = World::new();
    let nodes = w.nodes(h.n());
    let t = w.thing(nodes[0]);
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    for (x, e) in h.genesis.iter().enumerate().skip(1) {
        if e.is_some() {
            w.commit_id(gen_id(x), nodes[0], 0, &[(t, nodes[x], model_edge(*e))], &all0);
        }
    }
    let mut ids = Vec::new();
    for (i, ew) in h.writes.iter().enumerate() {
        let id = cid(ew.id);
        ids.push(id);
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
        let ops: Vec<(Tid, Tid, Option<Edge>)> = ew.ops.iter().map(|&(x, e)| (t, nodes[x], model_edge(e))).collect();
        w.commit_spec(id, nodes[ew.author], ew.t as u64, &ops, &recv, ew.fin);
    }
    EdgesWorld { w, nodes, t, ids }
}

/// (role, invite) of x's edge on T at the model's NOW.
fn auth_of(tl: &Timeline, ew: &EdgesWorld, x: usize) -> (Option<Role>, Option<Role>) {
    tl.roster(&ew.t, At::now(ts(500))).get(&ew.nodes[x]).map_or((None, None), |e| (Some(e.role), e.invite))
}

/// Compares `tl` with an edges-model result (authorities, applied and dropped ops by flat index).
fn edges_check(h: &edges::EHist, ew: &EdgesWorld, tl: &Timeline, auth: &[(roles_model::Role, roles_model::Role)], applied: u64, dropped: u64) -> Option<String> {
    for x in 1..h.n() {
        let (mr, mi) = auth[x];
        let m = (model_role(mr), model_role(mi));
        let p = auth_of(tl, ew, x);
        if m != p {
            return Some(format!("auth of {x}: model {m:?} perm {p:?}"));
        }
    }
    let mut op = 0;
    for (i, w) in h.writes.iter().enumerate() {
        for (k, &(x, _)) in w.ops.iter().enumerate() {
            let q = op + k;
            if x == edges::O {
                continue;
            }
            let (ma, md) = (applied >> q & 1 == 1, dropped >> q & 1 == 1);
            let id = WriteId(ew.ids[i], k as u32);
            let (pa, pd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
            if (ma, md) != (pa, pd) {
                return Some(format!("write {i} op {k}: model applied {ma} dropped {md}, perm applied {pa} dropped {pd}"));
            }
        }
        op += w.ops.len();
    }
    None
}

fn edges_diff(h: &edges::EHist) -> Option<String> {
    let ew = edges_world(h);
    let o = edges::walk(h);
    let tl = Timeline::evaluate(&ew.w.held());
    let applied = (0..o.attr.len()).filter(|&j| o.attr[j] != edges::Attr::Skipped).fold(0u64, |m, j| m | 1 << j);
    let auth: Vec<_> = (0..h.n()).map(|x| o.auth(x)).collect();
    if let Some(d) = edges_check(h, &ew, &tl, &auth, applied, o.dropped) {
        return Some(d);
    }
    // Projection agreement (spec/permissions.md §4): a node holding one holder's certificate
    // closure computes that holder's authority as the full node does.
    for z in 1..h.n() {
        let pw = edges_world(&h.projected(z));
        let ptl = Timeline::evaluate(&pw.w.held());
        if auth_of(&ptl, &pw, z) != auth_of(&tl, &ew, z) {
            return Some(format!("projection for {z} differs"));
        }
    }
    None
}

fn edges_run(samples: u64, seed: u64) {
    model_run(samples, seed, edges::random_hist, edges_diff, |_| {});
}

/// spec/permissions.md §2, §5.1, §7: `until`, invite power, self-removal and links agree with
/// core/test/roles-model `edges`, projections included.
#[test]
fn edges_model_agrees() {
    edges_run(300, 0x5eed_0003);
}

/// spec/permissions.md §2, §5.1, §7: as above, more samples (tier 2).
#[test]
#[ignore]
fn edges_model_agrees_large() {
    sharded(100_000, 0x5eed_0004, edges_run);
}

// ---------- trust sets and disputes (spec/permissions.md §5.1 Trust; core/test/roles-model `trust`) ----------

use roles_model::trust::{pick_all, side, Side, Trusting};
use osis_perm::{Dispute, Timelines, Trust};

/// Model trust set `bits` (ops) as perm's.
fn trust_of<H: Trusting>(h: &H, bits: u64) -> Trust {
    let ops = (0..h.n_ops()).filter(|&op| bits >> op & 1 == 1).map(|op| {
        let (id, k) = h.key(op);
        WriteId(cid(id), k as u32)
    });
    Trust { ops: ops.collect() }
}

/// Perm's disputes and active ops against the model side's, `ent` mapping a victim entity to
/// its tid.
fn side_check<H: Trusting, R>(h: &H, s: &Side<R>, tl: &Timeline, ent: impl Fn(usize) -> Tid) -> Option<String> {
    let active = trust_of(h, s.active);
    if *tl.trusted_active() != active.ops {
        return Some(format!("active: model {:?} perm {:?}", active.ops, tl.trusted_active()));
    }
    let mut md: Vec<Dispute> = s.disputes.iter().map(|&(r, x)| Dispute { op: trust_of(h, 1 << r).ops.into_iter().next().unwrap(), holder: ent(x) }).collect();
    md.sort();
    let mut pd = tl.disputes().to_vec();
    pd.sort();
    (md != pd).then(|| format!("disputes: model {md:?} perm {pd:?}"))
}

/// The trust sets a history is checked under: none, each open dispute's R alone, and the set
/// a node picking each new dispute at random ends with.
fn trust_sets<H: Trusting>(h: &H) -> Vec<u64> {
    let s0 = side(h, 0);
    let mut out = vec![0];
    out.extend(s0.disputes.iter().map(|d| 1u64 << d.0));
    let (t, _, _) = pick_all(h, &mut Rng(h.n_writes() as u64 + 1));
    if !out.contains(&t) {
        out.push(t);
    }
    out
}

/// A `Timelines` taken through `set_trust` with `a`, `b`, then `a` again reads as a fresh
/// evaluation under `a` (switching is a pure function; the component is evaluated from
/// scratch each time): roles and rosters on `things`, applied and dropped ops of `ids`,
/// active ops and disputes over every component.
fn switching_check(held: &osis_perm::MemoryHeldSet, a: &Trust, b: &Trust, things: &[Tid], nodes: &[Tid], ids: &[CommitId]) -> Option<String> {
    let want = Timeline::evaluate_with(held, a);
    let mut tls = Timelines::new();
    tls.update(held);
    tls.set_trust(held, a.clone());
    tls.set_trust(held, b.clone());
    tls.set_trust(held, a.clone());
    let (mut disputes, mut active) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
    let mut seen: Vec<*const Timeline> = Vec::new();
    for t in things {
        let Some(tl) = tls.get(t) else { continue };
        for n in nodes {
            if tl.role(n, t, At::END) != want.role(n, t, At::END) {
                return Some(format!("after switching: role of {n:?} on {t:?}: {:?} against {:?} fresh", tl.role(n, t, At::END), want.role(n, t, At::END)));
            }
        }
        if tl.roster(t, At::END) != want.roster(t, At::END) {
            return Some(format!("after switching: roster of {t:?} differs"));
        }
        if !seen.contains(&(tl as *const Timeline)) {
            seen.push(tl);
            disputes.extend(tl.disputes().iter().copied());
            active.extend(tl.trusted_active().iter().copied());
        }
    }
    for id in ids {
        let Some(c) = want.role_commit(id) else { continue };
        for (k, op) in c.ops.iter().enumerate() {
            let w = WriteId(*id, k as u32);
            let Some(tl) = tls.get(&op.target) else { return Some(format!("after switching: no timeline for {:?}", op.target)) };
            if (tl.is_applied(&w), tl.dropped().contains_key(&w)) != (want.is_applied(&w), want.dropped().contains_key(&w)) {
                return Some(format!("after switching: write {w:?} applied {} dropped {} against fresh {} {}", tl.is_applied(&w), tl.dropped().contains_key(&w), want.is_applied(&w), want.dropped().contains_key(&w)));
            }
        }
    }
    let wd: std::collections::BTreeSet<Dispute> = want.disputes().iter().copied().collect();
    if disputes != wd {
        return Some(format!("after switching: disputes {disputes:?} against fresh {wd:?}"));
    }
    (active != *want.trusted_active()).then(|| format!("after switching: active {active:?} against fresh {:?}", want.trusted_active()))
}

fn joint_trust_diff(h: &joint::JHist) -> Option<String> {
    let jw = joint_world(h);
    let held = jw.w.held();
    let ent = |e: usize| if e < h.nodes { jw.nodes[e] } else { jw.actors[e - h.nodes] };
    let sets = trust_sets(h);
    let mut first: Option<Trust> = None;
    for bits in &sets {
        let s = side(h, *bits);
        let trust = trust_of(h, *bits);
        let check = |tl: &Timeline| joint_check(h, &jw, tl, &s.res.1, &s.res.0, s.applied, dropped_bits(h, &s.res.2)).or_else(|| side_check(h, &s, tl, ent));
        let tl = Timeline::evaluate_with(&held, &trust);
        if let Some(d) = check(&tl) {
            return Some(format!("trust {bits:#b}: {d}"));
        }
        match &first {
            None => first = Some(trust),
            Some(a) if *bits != 0 => {
                if let Some(d) = switching_check(&held, &trust, a, &jw.actors, &jw.nodes, &jw.ids) {
                    return Some(format!("trust {bits:#b}: {d}"));
                }
            }
            _ => {}
        }
    }
    None
}

/// Dropped commit IDs as write bits (one write per commit in the joint model).
fn dropped_bits(h: &joint::JHist, ids: &[u32]) -> u64 {
    (0..h.writes.len()).filter(|&i| ids.contains(&h.writes[i].id)).fold(0, |m, i| m | 1 << i)
}

fn edges_trust_diff(h: &edges::EHist) -> Option<String> {
    let ew = edges_world(h);
    let held = ew.w.held();
    let sets = trust_sets(h);
    let mut first: Option<Trust> = None;
    for bits in &sets {
        let s = side(h, *bits);
        let trust = trust_of(h, *bits);
        // the settled walk again, for its dropped ops (the side's result lists commits)
        let dropped = h.eval_from(edges::Drops::Sticky, s.d0).0.dropped;
        let check = |tl: &Timeline| edges_check(h, &ew, tl, &s.res.0, s.applied, dropped).or_else(|| side_check(h, &s, tl, |x| ew.nodes[x]));
        let tl = Timeline::evaluate_with(&held, &trust);
        if let Some(d) = check(&tl) {
            return Some(format!("trust {bits:#b}: {d}"));
        }
        match &first {
            None => first = Some(trust),
            Some(a) if *bits != 0 => {
                if let Some(d) = switching_check(&held, &trust, a, &[ew.t], &ew.nodes, &ew.ids) {
                    return Some(format!("trust {bits:#b}: {d}"));
                }
            }
            _ => {}
        }
    }
    None
}

/// Histories from `gen` with an open dispute (one in 200-500 has one): up to 4000 tries each,
/// else the last.
fn disputed<H: Trusting>(make: impl Fn(&mut Rng) -> H) -> impl Fn(&mut Rng) -> H {
    move |rng| {
        let mut h = make(rng);
        for _ in 0..4000 {
            if !side(&h, 0).disputes.is_empty() {
                break;
            }
            h = make(rng);
        }
        h
    }
}

fn trust_run(samples: u64, seed: u64) {
    use edges::{Net, Who};
    let mut disputed_n = 0u64;
    let mut count = |h: &dyn Fn() -> bool| disputed_n += u64::from(h());
    model_run(samples / 2, seed, joint::random_hist, joint_trust_diff, |h| count(&|| !side(h, 0).disputes.is_empty()));
    model_run(samples / 2, seed ^ 0x77, disputed(joint::random_hist), joint_trust_diff, |h| count(&|| !side(h, 0).disputes.is_empty()));
    for (i, who) in [Who::OneRemover, Who::Rank, Who::RankFreeGrants, Who::Anyone].into_iter().enumerate() {
        for (j, net) in [Net::Online, Net::Offline].into_iter().enumerate() {
            let n = samples / (1 + 3 * (i != 3) as u64);
            let s = seed ^ (i as u64 * 2 + j as u64 + 1) << 8;
            model_run(n, s, |rng| edges::random_shaped(rng, who, net), edges_trust_diff, |h| count(&|| !side(h, 0).disputes.is_empty()));
            if who == Who::Anyone && net == Net::Offline {
                model_run(n / 2, s ^ 0x77, disputed(|rng| edges::random_shaped(rng, who, net)), edges_trust_diff, |h| count(&|| !side(h, 0).disputes.is_empty()));
            }
        }
    }
    eprintln!("trust: {samples} joint histories and the edges shapes (half of the joint and Anyone-offline ones picked with a dispute), {disputed_n} with a dispute");
}

/// spec/permissions.md §5.1 Trust: perm's walk under a trust set, its active ops and open
/// disputes agree with core/test/roles-model `trust` (`side`) on joint and shaped edges
/// histories, under no trust, each dispute's R alone and a node's random picks; switching
/// trust sets through `Timelines` reads as a fresh evaluation.
#[test]
fn trust_model_agrees() {
    trust_run(300, 0x5eed_0005);
}

/// spec/permissions.md §5.1 Trust: as above, more samples (tier 2).
#[test]
#[ignore]
fn trust_model_agrees_large() {
    sharded(30_000, 0x5eed_0006, trust_run);
}
