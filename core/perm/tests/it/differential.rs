//! Differential tests against core/test/roles-model (notes/testing.md): random histories from
//! the model, evaluated by both; equal rosters, roles, applied and dropped sets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use roles_model::shrink::{shrink, Shrink};
use roles_model::{edges, joint, Rng};
use osis_base::{CommitId, Role, Tid};
use osis_perm::{At, Edge, Timeline, WriteId};

/// A joint-model history as a world: node i is the i-th smallest key-actor tid, genesis edges
/// are writes by the key actor at the top of the target's chain at t=0.
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
    let owner_of = |x: usize| h.owner(x);
    for n in 0..h.nodes {
        for x in 0..h.owners.len() {
            let (m, p) = (model_role(o.roles[n][x]), tl.role(&jw.nodes[n], &jw.actors[x], At::END));
            if m != p {
                return Some(format!("role of node {n} on actor {x}: model {m:?} perm {p:?}"));
            }
        }
    }
    let ents = h.nodes + h.owners.len();
    for m in 0..ents {
        for x in 0..h.owners.len() {
            if owner_of(x) == Some(m) || m == h.nodes + x {
                continue;
            }
            let holder = if m < h.nodes { jw.nodes[m] } else { jw.actors[m - h.nodes] };
            let pe = tl.roster(&jw.actors[x], At::END).get(&holder).map(|e| e.role);
            if model_role(o.edges[m][x]) != pe {
                return Some(format!("edge {m} on {x}: model {:?} perm {pe:?}", o.edges[m][x]));
            }
        }
    }
    for (i, jwr) in h.writes.iter().enumerate() {
        if owner_of(jwr.target) == Some(jwr.holder) {
            continue;
        }
        let id = WriteId(jw.ids[i], 0);
        let (ma, md) = (o.applied >> i & 1 == 1, o.dropped >> i & 1 == 1);
        let (pa, pd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
        if (ma, md) != (pa, pd) {
            return Some(format!("write {i}: model applied {ma} dropped {md}, perm applied {pa} dropped {pd}"));
        }
    }
    None
}

/// Runs `samples` histories from `history` through `diff`, calling `each` on every one. A
/// mismatching history is shrunk while it still mismatches and reported as a trace; the run
/// fails after three.
fn model_run<H: Shrink + Clone + std::fmt::Display>(samples: u64, seed: u64, history: impl Fn(&mut Rng) -> H, diff: impl Fn(&H) -> Option<String>, mut each: impl FnMut(&H)) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let mut fails = Vec::new();
    for s in 0..samples {
        let h = history(&mut rng);
        each(&h);
        if diff(&h).is_some() {
            let m = shrink(h.clone(), |c| diff(c).is_some());
            let d = diff(&m).unwrap_or_default();
            fails.push(format!("seed {seed:#x} sample {s} (shrunk): {d}\n{m}"));
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
    use joint::{JHist, JWrite, Owner};
    use roles_model::Role::{Admin, None as Gone};
    const LATE: u32 = roles_model::shrink::LATE;
    let w = |author, t, id, holder| JWrite { author, t, id, target: 0, holder, role: Gone };
    // entities: n0, n1, A0, A1
    let mut genesis = vec![vec![Gone; 2]; 4];
    genesis[1][0] = Admin;
    genesis[3][0] = Admin;
    JHist {
        nodes: 2,
        owners: vec![Owner::Node(0), Owner::Node(1)],
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
    use joint::{JHist, JWrite, Owner};
    use roles_model::Role::{Admin, None as Gone, Read};
    const LATE: u32 = roles_model::shrink::LATE;
    let w = |author, t, id, holder, role| JWrite { author, t, id, target: 0, holder, role };
    // entities: n0, n1, n2, A0, A1
    let mut genesis = vec![vec![Gone; 2]; 5];
    genesis[1][0] = Admin;
    genesis[4][0] = Admin;
    JHist {
        nodes: 3,
        owners: vec![Owner::Node(0), Owner::Node(1)],
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

/// An edges-model history: node 0 owns the one target T; genesis edges are its writes at t=0.
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
        w.commit_id(id, nodes[ew.author], ew.t as u64, &ops, &recv);
    }
    EdgesWorld { w, nodes, t, ids }
}

/// (role, invite) of x's edge on T at the model's NOW.
fn auth_of(tl: &Timeline, ew: &EdgesWorld, x: usize) -> (Option<Role>, Option<Role>) {
    tl.roster(&ew.t, At::now(ts(500))).get(&ew.nodes[x]).map_or((None, None), |e| (Some(e.role), e.invite))
}

fn edges_diff(h: &edges::EHist) -> Option<String> {
    let ew = edges_world(h);
    let o = edges::walk(h);
    let tl = Timeline::evaluate(&ew.w.held());
    for x in 1..h.n() {
        let (mr, mi) = o.auth(x);
        let m = (model_role(mr), model_role(mi));
        let p = auth_of(&tl, &ew, x);
        if m != p {
            return Some(format!("auth of {x}: model {m:?} perm {p:?}"));
        }
    }
    for (i, w) in h.writes.iter().enumerate() {
        for (k, &(x, _)) in w.ops.iter().enumerate() {
            if x == edges::O {
                continue;
            }
            let op = o.base[i] + k;
            let ma = o.attr[op] != edges::Attr::Skipped;
            let md = o.dropped >> op & 1 == 1;
            let id = WriteId(ew.ids[i], k as u32);
            let (pa, pd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
            if (ma, md) != (pa, pd) {
                return Some(format!("write {i} op {k}: model applied {ma} dropped {md}, perm applied {pa} dropped {pd}"));
            }
        }
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
