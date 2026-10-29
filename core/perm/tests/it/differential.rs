//! Differential tests against core/test/membership-model (notes/testing.md): random histories from
//! the model, evaluated by both; equal rosters, roles, applied and dropped sets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use membership_model::shrink::{shrink, Shrink};
use membership_model::{edges, joint, snapshot, Rng};
use osis_base::{CommitId, Role, Tid};
use osis_perm::{At, Edge, Timeline, WriteId};

fn role(r: membership_model::Role) -> Option<Role> {
    match r {
        membership_model::Role::None => None,
        membership_model::Role::Read => Some(Role::Read),
        membership_model::Role::Write => Some(Role::Write),
        membership_model::Role::Admin => Some(Role::Admin),
    }
}


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
    let mut actors: Vec<Tid> = Vec::new();
    let mut top: Vec<Tid> = Vec::new();
    for o in &h.owners {
        let (owner, tp) = match *o {
            joint::Owner::Node(n) => (nodes[n], nodes[n]),
            joint::Owner::Actor(y) => (actors[y], top[y]),
        };
        actors.push(w.thing(owner));
        top.push(tp);
    }
    let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
    let mut g = 0;
    for (m, row) in h.genesis.iter().enumerate() {
        for (x, &r) in row.iter().enumerate() {
            if let Some(r) = role(r) {
                g += 1;
                let recv: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
                w.commit_id(gen_id(g), top[x], 0, &[(actors[x], ent(m), Some(Edge::new(r)))], &recv);
            }
        }
    }
    let mut ids = Vec::new();
    for (i, jw) in h.writes.iter().enumerate() {
        let id = cid(jw.id);
        ids.push(id);
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
        w.commit_id(id, nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.member), role(jw.role).map(Edge::new))], &recv);
    }
    JointWorld { w, nodes, actors, ids }
}

/// Compares perm with the joint model on one history; returns a description of the first
/// difference.
fn joint_diff(h: &joint::JHist) -> Option<String> {
    let jw = joint_world(h);
    let o = joint::walk(h);
    let tl = Timeline::evaluate(&jw.w.held());
    let owner_of = |x: usize| match h.owners[x] {
        joint::Owner::Node(n) => n,
        joint::Owner::Actor(y) => h.nodes + y,
    };
    for n in 0..h.nodes {
        for x in 0..h.owners.len() {
            let (m, p) = (role(o.roles[n][x]), tl.role(&jw.nodes[n], &jw.actors[x], At::END));
            if m != p {
                return Some(format!("role of node {n} on actor {x}: model {m:?} perm {p:?}"));
            }
        }
    }
    let ents = h.nodes + h.owners.len();
    for m in 0..ents {
        for x in 0..h.owners.len() {
            if m == owner_of(x) || m == h.nodes + x {
                continue;
            }
            let member = if m < h.nodes { jw.nodes[m] } else { jw.actors[m - h.nodes] };
            let pe = tl.roster(&jw.actors[x], At::END).get(&member).map(|e| e.role);
            if role(o.edges[m][x]) != pe {
                return Some(format!("edge {m} on {x}: model {:?} perm {pe:?}", o.edges[m][x]));
            }
        }
    }
    for (i, jwr) in h.writes.iter().enumerate() {
        if jwr.member == owner_of(jwr.target) {
            continue;
        }
        let id = WriteId::Op(jw.ids[i], 0);
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

/// spec/permissions.md §5.1: the joint walk agrees with core/test/membership-model `joint`.
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
/// drops them (perm lost the standing at the write on the absent edge).
#[test]
fn joint_kept_standing_survives_absent_edge_removal() {
    let h = absent_edge_removal_hist();
    let o = joint::walk(&h);
    assert_eq!(o.dropped, 0b1001, "model drops both of n1's explicit removals");
    assert_eq!(joint_diff(&h), None);
}

/// The history of `joint_kept_standing_survives_absent_edge_removal`.
fn absent_edge_removal_hist() -> joint::JHist {
    use joint::{JHist, JWrite, Owner};
    use membership_model::Role::{Admin, None as Gone};
    const LATE: u32 = membership_model::shrink::LATE;
    let w = |author, t, id, member| JWrite { author, t, id, target: 0, member, role: Gone };
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
    use membership_model::Role::{Admin, None as Gone, Read};
    const LATE: u32 = membership_model::shrink::LATE;
    let w = |author, t, id, member, role| JWrite { author, t, id, target: 0, member, role };
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
    assert_eq!(joint::walk(&h).dropped, 0b11, "model drops both of n1's explicit removals");
    assert_eq!(joint_diff(&h), None);
}

/// An edges-model history: node 0 owns the one target T; genesis edges are its writes at t=0.
struct EdgesWorld {
    w: World,
    nodes: Vec<Tid>,
    t: Tid,
    ids: Vec<CommitId>,
}

fn medge(e: Option<edges::Edge>) -> Option<Edge> {
    e.map(|e| Edge {
        role: role(e.role).unwrap_or(Role::Read),
        until: (e.until != edges::NEVER).then_some(osis_base::WallMs(e.until as u64)),
        invite: role(e.invite),
        since: None,
    })
}

fn edges_world(h: &edges::EHist) -> EdgesWorld {
    let mut w = World::new();
    let nodes = w.nodes(h.n());
    let t = w.thing(nodes[0]);
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    for (x, e) in h.genesis.iter().enumerate().skip(1) {
        if e.is_some() {
            w.commit_id(gen_id(x), nodes[0], 0, &[(t, nodes[x], medge(*e))], &all0);
        }
    }
    let mut ids = Vec::new();
    for (i, ew) in h.writes.iter().enumerate() {
        let id = cid(ew.id);
        ids.push(id);
        let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
        let ops: Vec<(Tid, Tid, Option<Edge>)> = ew.ops.iter().map(|&(x, e)| (t, nodes[x], medge(e))).collect();
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
        let m = (role(mr), role(mi));
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
            let id = WriteId::Op(ew.ids[i], k as u32);
            let (pa, pd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
            if (ma, md) != (pa, pd) {
                return Some(format!("write {i} op {k}: model applied {ma} dropped {md}, perm applied {pa} dropped {pd}"));
            }
        }
    }
    // Projection agreement (spec/permissions.md §4): a node holding one member's certificate
    // closure computes that member's authority as the full node does.
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

/// spec/permissions.md §2, §5.1, §9: `until`, invite power, self-removal and links agree with
/// core/test/membership-model `edges`, projections included.
#[test]
fn edges_model_agrees() {
    edges_run(300, 0x5eed_0003);
}

/// spec/permissions.md §2, §5.1, §9: as above, more samples (tier 2).
#[test]
#[ignore]
fn edges_model_agrees_large() {
    sharded(100_000, 0x5eed_0004, edges_run);
}

fn snap_diff(h: &snapshot::SHist) -> Option<String> {
    let sw = snap_world(h);
    let o = snapshot::walk(h);
    let tl = Timeline::evaluate(&sw.w.held());
    if residue(&tl) {
        RESIDUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    for (name, thing, out) in [("P", sw.p, &o.p), ("G", sw.g, &o.g)] {
        let roster = tl.roster(&thing, At::END);
        for x in 1..h.n() {
            let (m, p) = (role(out.roles[x]), roster.get(&sw.nodes[x]).map(|e| e.role));
            if m != p {
                return Some(format!("{name} edge of {x}: model {m:?} perm {p:?}"));
            }
        }
        let start = out.start.and_then(|s| sw.ids[s]);
        if start != tl.epoch_start(&thing) {
            return Some(format!("{name} epoch start: model {:?} perm {:?}", out.start, tl.epoch_start(&thing)));
        }
        for (i, wr) in h.writes.iter().enumerate() {
            let Some(id) = sw.ids[i] else { continue };
            if (wr.thing == snapshot::Thing::P) != (name == "P") {
                continue;
            }
            let pid = if wr.snap.is_some() { WriteId::Snapshot(id) } else { WriteId::Op(id, 0) };
            let (ma, pa) = (out.applied >> i & 1 == 1, tl.is_applied(&pid));
            if ma != pa {
                return Some(format!("{name} write {i}: model applied {ma}, perm {pa}"));
            }
        }
    }
    None
}

/// Sticky residue (`common::sticky_residue`): the two-level model, which settles P before
/// walking G, may discover drops in another order than the joint walk the spec prescribes.
static RESIDUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn residue(tl: &Timeline) -> bool {
    sticky_residue(tl)
}

/// A snapshot-model history without self-removal: no writes of an author's own edge, and
/// ledger entries ended by the member's own node given another ending node (that end is a
/// self-removal, spec/permissions.md §2, never an audited end, §6; read as one, its author
/// keeps its standing, §5.1 step 4). The snapshot model has no self-removal.
fn snap_hist(rng: &mut Rng) -> snapshot::SHist {
    let mut h = snapshot::random_hist(rng);
    let keep: Vec<usize> = (0..h.writes.len()).filter(|&i| h.writes[i].snap.is_some() || h.writes[i].rec || h.writes[i].author != h.writes[i].target).collect();
    h.writes = keep.iter().map(|&i| h.writes[i].clone()).collect();
    h.recv = keep.iter().map(|&i| h.recv[i].clone()).collect();
    let n = h.n();
    for e in h.writes.iter_mut().flat_map(|w| w.ledger.iter_mut()) {
        if let Some(u) = e.until.as_mut().filter(|u| u.1 == e.member) {
            u.1 = (e.member + 1) % n;
        }
    }
    h
}

/// The full history, compacted at every applied snapshot, and projected for every actor.
fn snap_cases(h: &snapshot::SHist) -> Option<String> {
    let o = snapshot::walk(h);
    let mut cases = vec![("full".to_string(), h.clone())];
    for thing in [snapshot::Thing::P, snapshot::Thing::G] {
        for sn in h.snapshots(thing, &o, true) {
            cases.push((format!("compacted {thing:?} at {sn}"), h.compacted(thing, sn).0));
        }
    }
    for z in 1..h.n() {
        cases.push((format!("projected {z}"), h.projected(z).0));
    }
    cases.into_iter().find_map(|(name, c)| snap_diff(&c).map(|d| format!("({name}) {d}")))
}

fn snap_run(samples: u64, seed: u64) {
    model_run(samples, seed, snap_hist, snap_cases, |_| {});
    eprintln!("snapshot model: {samples} histories, {} cases skipped as sticky residue", RESIDUE.load(std::sync::atomic::Ordering::Relaxed));
}

/// spec/permissions.md §6: epoch starts, ledgers, compaction and projections agree with
/// core/test/membership-model `snapshot`.
#[test]
fn snapshot_model_agrees() {
    snap_run(300, 0x5eed_0005);
}

/// spec/permissions.md §6: as above, more samples (tier 2).
#[test]
#[ignore]
fn snapshot_model_agrees_large() {
    sharded(50_000, 0x5eed_0006, snap_run);
}
