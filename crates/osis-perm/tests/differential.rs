//! Differential tests against models/membership (notes/testing.md): random histories from
//! the model, evaluated by both; equal rosters, roles, applied and dropped sets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use membership_model::{edges, joint, snapshot, Rng};
use osis_core::{CommitId, Role, Tid};
use osis_perm::{At, Edge, Timeline, WriteId};
use std::collections::BTreeSet;

fn role(r: membership_model::Role) -> Option<Role> {
    match r {
        membership_model::Role::None => None,
        membership_model::Role::Read => Some(Role::Read),
        membership_model::Role::Write => Some(Role::Write),
        membership_model::Role::Admin => Some(Role::Admin),
    }
}

fn gen_id(n: usize) -> CommitId {
    let mut c = cid(n as u32);
    c.0[31] = 2;
    c
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

fn joint_run(samples: u64, seed: u64) {
    let mut rng = Rng(seed);
    let mut fails = Vec::new();
    for s in 0..samples {
        let h = joint::random_hist(&mut rng);
        if let Some(d) = joint_diff(&h) {
            fails.push(format!("sample {s}: {d}\n{h:?}"));
            if fails.len() >= 3 {
                break;
            }
        }
    }
    assert!(fails.is_empty(), "{} mismatches:\n{}", fails.len(), fails.join("\n"));
}

/// spec/permissions.md §5.1: the joint walk agrees with models/membership `joint`.
#[test]
fn joint_model_agrees() {
    joint_run(300, 0x5eed_0001);
}

/// spec/permissions.md §5.1: as above, more samples (tier 2).
#[test]
#[ignore]
fn joint_model_agrees_large() {
    joint_run(100_000, 0x5eed_0002);
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
        until: (e.until != edges::NEVER).then_some(osis_core::WallMs(e.until as u64)),
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
    let mut rng = Rng(seed);
    let mut fails = Vec::new();
    for s in 0..samples {
        let h = edges::random_hist(&mut rng);
        if let Some(d) = edges_diff(&h) {
            fails.push(format!("sample {s}: {d}\n{h:?}"));
            if fails.len() >= 3 {
                break;
            }
        }
    }
    assert!(fails.is_empty(), "{} mismatches:\n{}", fails.len(), fails.join("\n"));
}

/// spec/permissions.md §2, §5.1, §9: `until`, invite power, self-removal and links agree with
/// models/membership `edges`, projections included.
#[test]
fn edges_model_agrees() {
    edges_run(300, 0x5eed_0003);
}

/// spec/permissions.md §2, §5.1, §9: as above, more samples (tier 2).
#[test]
#[ignore]
fn edges_model_agrees_large() {
    edges_run(100_000, 0x5eed_0004);
}

/// A snapshot-model history: key actor K (node 0) owns P, P owns G; genesis edges are K's
/// writes at t=0; records (layer 2) are left out; writes on G for K are inert in the model and
/// left out too.
struct SnapWorld {
    w: World,
    nodes: Vec<Tid>,
    p: Tid,
    g: Tid,
    /// Model write index -> commit ID (None: left out).
    ids: Vec<Option<CommitId>>,
}

fn snap_world(h: &snapshot::SHist) -> SnapWorld {
    use snapshot::Thing;
    let mut w = World::new();
    let nodes = w.nodes(h.n());
    let k = nodes[0];
    let p = w.thing(k);
    let g = w.thing(p);
    let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
    let mut gi = 0;
    for (thing, roles) in [(p, &h.gp), (g, &h.gg)] {
        for (x, &r) in roles.iter().enumerate().skip(1) {
            if let Some(r) = role(r) {
                gi += 1;
                w.commit_id(gen_id(gi), k, 0, &[(thing, nodes[x], Some(Edge::new(r)))], &all0);
            }
        }
    }
    let key = |k: (u32, usize)| (k.0 as u64, nodes[k.1]);
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
                let id = cid(i as u32 + 1);
                w.commit_id(id, author, sw.t as u64, &[(thing, nodes[sw.target], role(sw.role).map(Edge::new))], &recv);
                id
            }
            Some(roster) => {
                let mut r: Vec<(Tid, Edge)> = Vec::new();
                for (x, &rl) in roster.iter().enumerate().skip(1) {
                    if let Some(rl) = role(rl) {
                        let open = sw.ledger.iter().find(|e| e.member == x && e.until.is_none());
                        let since = open.and_then(|e| e.since).map(|k| {
                            let (t, n) = key(k);
                            osis_perm::EdgeKey { ts: ts(t), node: n }
                        });
                        r.push((nodes[x], Edge { since: if rl == Role::Admin { since } else { None }, ..Edge::new(rl) }));
                    }
                }
                let ledger: Vec<_> = sw.ledger.iter().filter_map(|e| e.until.map(|u| (nodes[e.member], Role::Admin, e.since.map(key), key(u), true))).collect();
                w.snapshot_l(author, thing, &r, &ledger, sw.t as u64, &recv)
            }
        };
        ids.push(Some(id));
    }
    SnapWorld { w, nodes, p, g, ids }
}

fn snap_diff(h: &snapshot::SHist) -> Option<String> {
    let sw = snap_world(h);
    let o = h.eval(true);
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

/// A drop whose cause was dropped too: sticky residue (notes/permissions.md), where the
/// two-level model, which settles P before walking G, may discover drops in another order than
/// the joint walk the spec prescribes.
static RESIDUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn residue(tl: &Timeline) -> bool {
    let dropped: BTreeSet<CommitId> = tl.dropped().keys().map(WriteId::commit).collect();
    tl.dropped().values().any(|p| dropped.contains(&p.commit))
}

fn snap_run(samples: u64, seed: u64) {
    let mut rng = Rng(seed);
    let mut fails = Vec::new();
    for s in 0..samples {
        // The snapshot model has no self-removal: leave out writes of an author's own edge.
        let mut h = snapshot::random_hist(&mut rng);
        let keep: Vec<usize> = (0..h.writes.len()).filter(|&i| h.writes[i].snap.is_some() || h.writes[i].rec || h.writes[i].author != h.writes[i].target).collect();
        h.writes = keep.iter().map(|&i| h.writes[i].clone()).collect();
        h.recv = keep.iter().map(|&i| h.recv[i].clone()).collect();
        let o = h.eval(true);
        let mut cases = vec![("full".to_string(), h.clone())];
        // Compaction at every applied snapshot, and projections.
        for thing in [snapshot::Thing::P, snapshot::Thing::G] {
            for sn in h.snapshots(thing, &o, true) {
                cases.push((format!("compacted {thing:?} at {sn}"), h.compacted(thing, sn).0));
            }
        }
        for z in 1..h.n() {
            cases.push((format!("projected {z}"), h.projected(z).0));
        }
        for (name, c) in cases {
            if let Some(d) = snap_diff(&c) {
                fails.push(format!("sample {s} ({name}): {d}\n{c:?}"));
                break;
            }
        }
        if fails.len() >= 3 {
            break;
        }
    }
    assert!(fails.is_empty(), "{} mismatches:\n{}", fails.len(), fails.join("\n"));
    eprintln!("snapshot model: {samples} histories, {} cases skipped as sticky residue", RESIDUE.load(std::sync::atomic::Ordering::Relaxed));
}

/// spec/permissions.md §6: epoch starts, ledgers, compaction and projections agree with
/// models/membership `snapshot`.
#[test]
fn snapshot_model_agrees() {
    snap_run(300, 0x5eed_0005);
}

/// spec/permissions.md §6: as above, more samples (tier 2).
#[test]
#[ignore]
fn snapshot_model_agrees_large() {
    snap_run(50_000, 0x5eed_0006);
}
