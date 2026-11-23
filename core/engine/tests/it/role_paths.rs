#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Role commits state real paths (notes/a1-spec/README.md step 3, Role paths; notes/a1-spec/
//! permissions.md §1 Path, §2): each role commit the engine writes states the path by which its
//! signer reaches what it writes, and the old walk, which reads the signer alone, judges every
//! edge write as it did when role commits stated the Interim empty path.

use crate::common;
use crate::flows::{edge_of, follow, people, spread, thing_of};
use common::*;
use osis_base::{Role, Tid};
use osis_engine::flows::{Demotion, LinkSpec};
use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;
use osis_perm::{At, Point};
use osis_schema::core_types as ct;
use std::collections::BTreeMap;

/// The representative world's peers (accounts `pa`..`pd`, written as their accounts) and things.
pub(crate) struct World {
    pub lp: LocalPeer,
}

fn grant(lp: &mut LocalPeer, by: usize, t: Tid, to: Tid, e: ct::Edge) {
    lp.peers[by].engine.grant(&t, &to, &e).unwrap();
    lp.advance(1000);
    spread(lp);
}

fn remove(lp: &mut LocalPeer, by: usize, t: Tid, holder: Tid) {
    lp.peers[by].engine.demote(&t, &Demotion { holder, new: None, retain: None }).unwrap();
    lp.advance(1000);
    spread(lp);
}

fn may_grant(role: Role) -> ct::Edge {
    ct::Edge { may_grant: true, ..edge_of(role) }
}

/// Four accounts A (0), B (1), C (2), D (3). B grants through one holder (H1 on T1) and through
/// three (K1, K2, K3 on T3) and removes D through the three (the removal rotates T3); B, admin of
/// H5, takes H5 off T5 (a self-removal through a holder: B's only role there is through H5); C
/// leaves T1 itself; B invites D to T4 by H4's invite and C invites B by its own; a timed grant
/// on T1 ends and B finalizes it; C redeems a single-use link to T7; on T6, B grants D write and
/// writes content only C receives, A removes B (the grant falls), and C writes an addendum for the
/// content, then leaves T6 itself (an admin's leave); A removes
/// C from T8, which A reaches by a descent of two steps.
pub(crate) fn world() -> World {
    let (mut lp, ps) = people(4);
    let (pa, pb, pc, pd) = (ps[0], ps[1], ps[2], ps[3]);
    let mut things: Vec<Tid> = (0..13).map(|_| thing_of(&mut lp, 0, pa)).collect();
    let &[t1, h1, t3, k1, k2, k3, t5, h5, t4, h4, t6, t7, g8] = &things[..] else { unreachable!() };
    let t8 = thing_of(&mut lp, 0, g8);
    things.push(t8);
    spread(&mut lp);
    // through one holder
    grant(&mut lp, 0, t1, h1, edge_of(Role::Admin));
    grant(&mut lp, 0, h1, pb, edge_of(Role::Admin));
    grant(&mut lp, 1, t1, pc, edge_of(Role::Write));
    // through three, and a removal with its rotation
    grant(&mut lp, 0, t3, k3, edge_of(Role::Admin));
    grant(&mut lp, 0, k3, k2, edge_of(Role::Admin));
    grant(&mut lp, 0, k2, k1, edge_of(Role::Admin));
    grant(&mut lp, 0, k1, pb, edge_of(Role::Admin));
    grant(&mut lp, 1, t3, pd, edge_of(Role::Read));
    remove(&mut lp, 1, t3, pd);
    // a leave through a holder, and one by the holder itself
    grant(&mut lp, 0, t5, h5, edge_of(Role::Write));
    grant(&mut lp, 0, h5, pb, edge_of(Role::Admin));
    remove(&mut lp, 1, t5, h5);
    remove(&mut lp, 2, t1, pc);
    // may-grant grants: by a holder's flag and by one's own
    grant(&mut lp, 0, t4, h4, may_grant(Role::Write));
    grant(&mut lp, 0, h4, pb, edge_of(Role::Write));
    grant(&mut lp, 1, t4, pd, edge_of(Role::Read));
    grant(&mut lp, 0, t4, pc, may_grant(Role::Write));
    grant(&mut lp, 2, t4, pb, edge_of(Role::Read));
    // a finalize of an ended grant
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 500);
    grant(&mut lp, 0, t1, pd, ct::Edge { until: Some(until), ..edge_of(Role::Read) });
    lp.advance(2000);
    lp.peers[1].engine.ensure_rotated(&t1).unwrap();
    spread(&mut lp);
    // a single-use link redemption
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &LinkSpec { target: t7, role: Role::Read, until: None, peers: Vec::new(), single_use: true }).unwrap();
    follow(&mut lp, &link);
    spread(&mut lp);
    lp.peers[2].engine.redeem(&link, &pc, true).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    // an addendum for what A's removal of B left out, then C's own leave
    grant(&mut lp, 0, t6, pb, edge_of(Role::Admin));
    grant(&mut lp, 0, t6, pc, edge_of(Role::Admin));
    lp.peers[1].engine.grant(&t6, &pd, &edge_of(Role::Write)).unwrap();
    let mut m = Mutation::new();
    m.set(t6, &REG, &s("by b")).unwrap();
    lp.peers[1].engine.commit(m).unwrap();
    lp.sync(1, 2).unwrap();
    lp.advance(1000);
    remove(&mut lp, 0, t6, pb);
    spread(&mut lp);
    remove(&mut lp, 2, t6, pc);
    // a removal by a descent of two steps
    grant(&mut lp, 0, t8, pc, edge_of(Role::Admin));
    remove(&mut lp, 0, t8, pc);
    World { lp }
}

/// Whether `p` is on `q`'s record chain (above `q`).
fn above(e: &osis_engine::Engine, p: Tid, q: Tid) -> bool {
    std::iter::successors(e.core.created(&q).and_then(|r| r.mint_admin()), |y| e.core.created(y).and_then(|r| r.mint_admin())).take(70).any(|x| x == p)
}

/// The role and invite hop `p` to `q` gives just before `point`: admin for a descent, else `p`'s
/// direct edge on `q` (`None`: no edge held).
fn hop(e: &osis_engine::Engine, p: Tid, q: Tid, marked: bool, point: Point) -> Option<(Role, Option<Role>)> {
    // a hop marked direct reads the direct edge, and only off a descent of two steps or more
    if marked {
        assert!(above(e, p, q) && e.core.created(&q).and_then(|r| r.mint_admin()) != Some(p), "a mark off a descent of two steps: {p:?} {q:?}");
    } else if above(e, p, q) {
        return Some((Role::Admin, Some(Role::Admin)));
    }
    let tl = e.core.timelines.get(&q)?;
    let edges = tl.edges_at(Some(point));
    let x = edges.get(&p, &q).filter(|x| x.alive_at(Some(point.ts)))?;
    Some((x.role, if x.role == Role::Admin { Some(Role::Admin) } else { x.may_grant.then_some(x.role) }))
}

// spec/permissions.md §1 Path, §2 Self-removal and Invite grant, spec/wire.md §4 field 2:
// every role commit states a real path. Over the representative world, each role commit A holds
// states one path, purge index 0, whose hops from its signer to each thing it writes (to the
// holder, for a self-removal) are held edges or descents just before its key, giving what the
// commit needs there: the signer's role on the thing (admin for an admin's edge write, its role
// for a rotation), admin up to the holder for a self-removal, the granted role as an
// invite on the last edge for an invite grant. Every kind the table names is met.
#[test]
fn every_stated_role_path_is_a_chain_of_held_edges_spec_wire_4() {
    let w = world();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lens: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, id) in (0..4).flat_map(|i| w.lp.peers[i].engine.commit_ids().into_iter().map(move |id| (i, id))) {
        let e = &w.lp.peers[i].engine;
        let Some(h) = e.header(&id) else { continue };
        if !h.kind.is_role() {
            continue;
        }
        let osis_commit::Paths::One(p) = &h.path else { panic!("{id:?}: a role commit states one path") };
        assert_eq!(p.purge, 0, "{id:?}");
        if h.rotation.is_some() || h.reseal.is_some() {
            assert!(p.things.is_empty());
            continue;
        }
        let point = Point { ts: h.ts, node: h.signer, commit: id };
        *lens.entry(p.things.len()).or_default() += 1;
        // judged where its things' records are held: each node checks what it reads
        if h.things().iter().any(|t| *t != h.signer && e.core.created(t).is_none()) {
            continue;
        }
        for t in h.things() {
            let listed = p.to(&t).to_vec();
            let end = listed.last().copied().unwrap_or(h.signer);
            let tl = e.core.timelines.get(&t);
            let ops: Vec<(Tid, Option<osis_perm::Edge>)> = tl.map(|tl| tl.held_on(&t).filter(|(w, _, _)| w.0 == id).map(|(_, _, op)| (op.holder, op.edge)).collect()).unwrap_or_default();
            let leave = !ops.is_empty() && ops.iter().any(|(m, _)| *m == end);
            // a key actor writing itself: [S] (spec/permissions.md §1 Path)
            let members: Vec<Tid> = std::iter::once(h.signer).chain(listed.iter().copied()).chain((!leave && t != h.signer).then_some(t)).collect();
            let hops: Vec<(Role, Option<Role>)> = members.windows(2).enumerate().map(|(j, x)| hop(e, x[0], x[1], p.direct >> j & 1 == 1, point).unwrap_or_else(|| panic!("{id:?}: {:?} holds nothing on {:?} (path to {t:?}: {listed:?}; {:?}, effective {:?}, record {:?})", x[0], x[1], h.aspects.iter().map(|a| (a.tid, a.ak.as_str().to_string())).collect::<Vec<_>>(), e.core.timelines.role(&h.signer, &t, At::before(point)), e.core.created(&t)))).collect();
            let role = hops.iter().map(|x| x.0).min().unwrap_or(Role::Admin);
            let has = |ak: &str| h.aspects.iter().any(|a| a.tid == t && a.ak.as_str() == ak);
            let effective = e.core.timelines.role(&h.signer, &t, At::before(point));
            if leave {
                assert_eq!(role, Role::Admin, "{id:?}: a self-removal's path gives admin up to its holder");
                *seen.entry(if listed.is_empty() { "leave" } else { "leave through a holder" }).or_default() += 1;
                if ops.len() == 2 {
                    *seen.entry("redemption").or_default() += 1;
                }
            } else if has("roles.0") && effective < Some(Role::Admin) && ops.iter().any(|(_, v)| v.is_some_and(|v| v.until.is_none())) {
                let granted = ops.iter().filter_map(|(_, v)| v.map(|v| v.role)).max().unwrap();
                let (last, rest) = hops.split_last().unwrap();
                assert!(rest.iter().all(|x| x.0 >= granted) && last.1 >= Some(granted), "{id:?}: an invite grant's path gives {granted:?} as an invite: {hops:?}");
                *seen.entry("invite").or_default() += 1;
            } else {
                assert!(Some(role) >= effective, "{id:?}: the path gives {role:?}, the signer's role there is {effective:?}");
                let kind = if has("roles.0") && h.frontier.is_none() && ops.iter().all(|(_, v)| v.is_none()) {
                    "finalize"
                } else if has("roles.0") {
                    "admin edge write"
                } else if has("keys.0") {
                    "rotation"
                } else {
                    "other"
                };
                *seen.entry(kind).or_default() += 1;
            }
        }
    }
    for k in ["leave", "leave through a holder", "redemption", "invite", "finalize", "admin edge write", "rotation"] {
        assert!(seen.contains_key(k), "no {k}: {seen:?}");
    }
    assert!(lens.contains_key(&1) && lens.contains_key(&3), "paths through one and three holders: {lens:?}");
    // the addendum: a content commit on T6 writing `addenda.0`, stating its real path
    let e = &w.lp.peers[0].engine;
    let addenda = e.commit_ids().into_iter().filter_map(|id| e.header(&id)).filter(|h| h.kind == osis_commit::Kind::Content && h.aspects.iter().any(|a| a.ak.as_str() == "addenda.0")).count();
    assert!(addenda >= 1, "an addendum is written");
}

/// The new walk (`osis_perm::paths`, notes/perm-paths.md) over the role commits engine `e` holds
/// as it holds them: each edge write a part along the path its commit states for its target (the
/// old walk's own reading of its value and frontier);
/// `e`'s trust set; records for every thing named. With each edge part's
/// old-walk ID and target.
pub(crate) fn new_walk(e: &osis_engine::Engine) -> (osis_perm::paths::Paths, BTreeMap<osis_perm::WriteId, (osis_perm::WriteId, Tid)>) {
    use osis_perm::paths::{Commit, EdgeWrite, Part, PartKind};
    let mut commits = Vec::new();
    let mut ids = BTreeMap::new();
    let mut named: std::collections::BTreeSet<Tid> = std::collections::BTreeSet::new();
    let mut trust = std::collections::BTreeSet::new();
    for id in e.commit_ids() {
        let Some(h) = e.header(&id) else { continue };
        if h.kind != osis_commit::Kind::Role {
            continue;
        }
        let osis_commit::Paths::One(p) = &h.path else { panic!("a role commit states one path") };
        let mut parts = Vec::new();
        named.insert(h.signer);
        named.extend(p.things.iter().copied());
        let things: std::collections::BTreeSet<Tid> = h.aspects.iter().map(|a| a.tid).collect();
        for t in things {
            named.insert(t);
            let path = p.to(&t).to_vec();
            if let Some(tl) = e.core.timelines.get(&t) {
                let mut ops: Vec<_> = tl.held_on(&t).filter(|(w, _, _)| w.0 == id).collect();
                ops.sort_by_key(|(_, _, op)| op.holder);
                for (w, c, op) in ops {
                    named.insert(op.holder);
                    let nid = osis_perm::WriteId(id, parts.len() as u32);
                    if tl.trust().contains(&w) {
                        trust.insert(nid);
                    }
                    ids.insert(nid, (w, t));
                    // A1's single list: each commit in the leaf of every thing it writes
                    let frontier = c.frontier.as_ref().map(|f| {
                        let things = |x: &osis_base::CommitId| e.header(x).map(|lh| lh.aspects.iter().map(|a| a.tid).collect::<Vec<Tid>>()).unwrap_or_default();
                        std::sync::Arc::new(osis_perm::paths::List::new(f.commits().iter().flat_map(|x| things(x).into_iter().map(move |t| (t, *x))).collect::<Vec<_>>()))
                    });
                    parts.push(Part { on: t, path: path.clone(), direct: p.direct, kind: PartKind::Edge(EdgeWrite { holder: op.holder, value: op.edge, frontier }) });
                }
            }
        }
        if !parts.is_empty() {
            commits.push(Commit { id, ts: h.ts, signer: h.signer, parts });
        }
    }
    // every record up each named thing's chain
    let mut records = BTreeMap::new();
    let mut todo: Vec<Tid> = named.into_iter().collect();
    while let Some(t) = todo.pop() {
        if let Some(a) = e.core.created(&t).and_then(|r| r.mint_admin())
            && records.insert(t, a).is_none()
        {
            todo.push(a);
        }
    }
    (osis_perm::paths::Paths::evaluate(&records, trust, &commits), ids)
}

/// Where the new walk judging the stated paths differs from the old walk at engine `e`: each edge
/// write whose applied/not differs, and each edge whose final role differs (every `until` counted
/// removed).
pub(crate) fn walks_differ(e: &osis_engine::Engine) -> Vec<String> {
    let (paths, ids) = new_walk(e);
    let mut out = Vec::new();
    for (nid, (w, t)) in &ids {
        let tl = e.core.timelines.get(t).unwrap();
        let old = tl.is_applied(w);
        let new = matches!(paths.status(nid), Some(osis_perm::paths::Status::Applied | osis_perm::paths::Status::MayGrant));
        if old != new {
            let (signer, holder, _) = tl.edge_op(w).unwrap();
            out.push(format!("edge write {:?} by {signer:?} on ({holder:?}, {t:?}): old {old}, new {:?}", w.0, paths.status(nid)));
        }
    }
    let finals = paths.finals();
    let mut targets: std::collections::BTreeSet<Tid> = finals.keys().map(|k| k.1).collect();
    targets.extend(ids.values().map(|x| x.1));
    for t in targets {
        let Some(tl) = e.core.timelines.get(&t) else { continue };
        let edges = tl.edges_at(None);
        let old: BTreeMap<Tid, Role> = edges.holders(&t).filter(|(_, x)| x.until.is_none()).map(|(m, x)| (*m, x.role)).collect();
        let new: BTreeMap<Tid, Role> = finals.iter().filter(|(k, v)| k.1 == t && v.0.is_some()).map(|(k, v)| (k.0, v.0.unwrap())).collect();
        if old != new {
            out.push(format!("roles on {t:?}: old {old:?}, new {new:?}"));
        }
    }
    out
}

// notes/a1-spec/README.md step 3 (For the wiring): the new walk judging the paths role commits
// state gives every edge write the old walk's verdict (spec/permissions.md §5.1) and every edge
// the old walk's final role, at every node of the representative world.
#[test]
fn the_new_walk_judges_the_stated_role_paths_as_the_old_walk_does() {
    let w = world();
    for i in 0..4 {
        assert_eq!(walks_differ(&w.lp.peers[i].engine), Vec::<String>::new(), "peer {i}");
    }
}

/// The newest role commit at peer `i` writing `holder`'s edge on `t`: its header, and the new
/// walk's status of that edge write.
fn newest_write(lp: &LocalPeer, i: usize, t: Tid, holder: Tid) -> (std::sync::Arc<osis_commit::Header>, Option<osis_perm::paths::Status>) {
    let e = &lp.peers[i].engine;
    let tl = e.core.timelines.get(&t).unwrap();
    let (w, _, _) = tl.held_on(&t).filter(|(_, _, op)| op.holder == holder).max_by_key(|(_, c, _)| c.ts).unwrap();
    let (paths, ids) = new_walk(e);
    let nid = ids.iter().find(|(_, (x, _))| *x == w).map(|(n, _)| *n).unwrap();
    (e.header(&w.0).unwrap(), paths.status(&nid))
}

fn one_path(h: &osis_commit::Header) -> Vec<Tid> {
    let osis_commit::Paths::One(p) = &h.path else { panic!("one path") };
    p.things.clone()
}

// spec/permissions.md §1 Path, §2 Self-removal: B, admin of holder H, removes H from T, where
// B's only admin on T is through H: a self-removal (its path, [H], ends at the holder), carrying
// no frontier (roles-model `an_honest_holder_leave_is_no_dispute`: K makes A2 leave T1 by [A2]).
// With a direct admin grant of its own on T, the same removal is explicit: the empty path, a
// frontier, and B's own edge the last edge.
#[test]
fn removing_the_holder_one_acts_through_is_a_self_removal_spec_permissions_2() {
    for direct in [false, true] {
        let (mut lp, ps) = people(2);
        let (pa, pb) = (ps[0], ps[1]);
        let t = thing_of(&mut lp, 0, pa);
        let h = thing_of(&mut lp, 0, pa);
        spread(&mut lp);
        grant(&mut lp, 0, t, h, edge_of(Role::Admin));
        grant(&mut lp, 0, h, pb, edge_of(Role::Admin));
        if direct {
            grant(&mut lp, 0, t, pb, edge_of(Role::Admin));
        }
        remove(&mut lp, 1, t, h);
        for i in 0..2 {
            let (hd, st) = newest_write(&lp, i, t, h);
            if direct {
                assert!(one_path(&hd).is_empty() && hd.frontier.is_some(), "peer {i}: {:?}", hd.path);
            } else {
                assert!(one_path(&hd) == [h] && hd.frontier.is_none(), "peer {i}: {:?}", hd.path);
            }
            assert_eq!(st, Some(osis_perm::paths::Status::Applied), "peer {i} direct {direct}");
            assert!(walks_differ(&lp.peers[i].engine).is_empty(), "peer {i}: {:?}", walks_differ(&lp.peers[i].engine));
            assert_eq!(lp.peers[i].engine.roster(&t).get(&h), None);
        }
    }
}

// spec/commits.md §2: a role commit changes at most one grant, a shape rule binding the writer
// alone; a receiver judges each edge write on its own. B, admin of T1 by its own grant and
// of T2 only through H, writes past the writer's rules one role commit granting C write on both.
// No one path serves both things, so it states the Interim one; it is written, and a receiver
// judges T1's edge write on its own. Fails where the writer asserts one path for every role
// commit, shape rules skipped or not.
#[test]
fn a_hostile_role_commit_on_things_reached_apart_is_written_spec_commits_2() {
    let (mut lp, ps) = people(3);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let t1 = thing_of(&mut lp, 0, pa);
    let t2 = thing_of(&mut lp, 0, pa);
    let h = thing_of(&mut lp, 0, pa);
    spread(&mut lp);
    grant(&mut lp, 0, t1, pb, edge_of(Role::Admin));
    grant(&mut lp, 0, t2, h, edge_of(Role::Admin));
    grant(&mut lp, 0, h, pb, edge_of(Role::Admin));
    let mut m = Mutation::new();
    for t in [t1, t2] {
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::Weak(pc))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge_of(Role::Write))) }).unwrap();
    }
    lp.peers[1].engine.commit_hostile(m).unwrap().expect("the commit writes");
    lp.advance(1000);
    spread(&mut lp);
    assert_eq!(lp.peers[0].engine.roster(&t1).get(&pc).map(|e| e.role), Some(Role::Write));
}

// spec/permissions.md §2 May-grant grant ("an edge write whose path gives admin on T is
// explicit, whatever it sets"): B holds admin on T through H and a direct write grant with the
// may-grant flag; its grant of read to C states the admin path [H], not its own flag's (the empty
// path), and applies as an explicit grant, not a may-grant grant.
#[test]
fn an_admin_holding_the_may_grant_flag_grants_by_its_admin_path_spec_permissions_2() {
    let (mut lp, ps) = people(3);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 0, pa);
    let h = thing_of(&mut lp, 0, pa);
    spread(&mut lp);
    grant(&mut lp, 0, t, h, edge_of(Role::Admin));
    grant(&mut lp, 0, h, pb, edge_of(Role::Admin));
    grant(&mut lp, 0, t, pb, may_grant(Role::Write));
    grant(&mut lp, 1, t, pc, edge_of(Role::Read));
    for i in 0..3 {
        let (hd, st) = newest_write(&lp, i, t, pc);
        assert_eq!(one_path(&hd), [h], "peer {i}");
        assert_eq!(st, Some(osis_perm::paths::Status::Applied), "peer {i}");
        assert!(walks_differ(&lp.peers[i].engine).is_empty(), "peer {i}");
    }
}

/// One world of `new_walk_differs_only_by_design`: its name, the class its differences show (or
/// none), and its peers.
type ClassWorld = (&'static str, Option<&'static str>, LocalPeer);

/// The classes' worlds this binary builds (notes/a1-spec/README.md step 3, For the wiring).
fn class_worlds() -> Vec<ClassWorld> {
    let mut out: Vec<ClassWorld> = vec![("representative", None, world().lp)];
    // A, T's mint admin, and B, granted admin, leave at once: no reader judges a last admin
    // (spec/permissions.md §1, The last admin), so both walks apply both leaves
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    grant(&mut lp, 0, t, ps[1], edge_of(Role::Admin));
    for (p, holder) in lp.peers.iter_mut().zip(&ps) {
        p.engine.demote(&t, &Demotion { holder: *holder, new: None, retain: None }).unwrap();
    }
    lp.advance(1000);
    spread(&mut lp);
    out.push(("concurrent leaves", None, lp));
    // a single-use link redeemed by a forger first, unseen by the sharer, then by P1, whom the
    // sharer saw; the sharer's removal of L lists P1's redemption alone: the forger's grant falls
    // and its leave with it, P1 is in (notes/a1-spec/README.md Open 23)
    // (roles-model `a_single_use_link_redeemed_twice_stays_with_the_redemption_the_sharer_listed`:
    // its worlds `unseen`, `later` (P1 first, the forger later and unseen), `both` and `neither`
    // (the sharer saw both, or none))
    // The forger later: its grant finds the link spent and its leave is a no-op; the sharer's
    // finalize drops the grant and, in the new walk, the leave with it: no role differs.
    let later = Some("a no-op leave falls with its commit's dropped grant");
    for (name, class, thief_first, seen) in [("single-use link redeemed twice", None, true, &[1][..]), ("single-use link, the forger later", later, false, &[1]), ("single-use link, both seen", None, true, &[1, 2]), ("single-use link, none seen", None, true, &[])] {
        let (mut lp, ps) = people(3);
        let d = thing_of(&mut lp, 0, ps[0]);
        let (link, _, _) = lp.peers[0].engine.create_link(&ps[0], &LinkSpec { target: d, role: Role::Read, until: None, peers: Vec::new(), single_use: true }).unwrap();
        follow(&mut lp, &link);
        spread(&mut lp);
        let l = osis_engine::identity::Identity::from_seed(link.seed.clone()).tid();
        for (k, i) in (if thief_first { [2, 1] } else { [1, 2] }).into_iter().enumerate() {
            lp.peers[i].clock.advance(1000 * k as u64);
            lp.peers[i].engine.redeem(&link, &ps[i], true).unwrap();
        }
        for &i in seen {
            lp.sync(i, 0).unwrap();
        }
        lp.peers[0].clock.advance(3000);
        lp.peers[0].engine.finalize_link(&link.k, &l).unwrap();
        spread(&mut lp);
        out.push((name, class, lp));
    }
    // a key actor's edge write on itself, made anyway: both walks apply it nowhere
    let (mut lp, ps) = people(3);
    let holder = lp.peers[2].engine.me();
    let mut m = Mutation::new();
    m.op(holder, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::Weak(ps[1]))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge_of(Role::Write))) }).unwrap();
    lp.peers[2].engine.core.skip_writer_rules = true;
    lp.peers[2].engine.commit(m).unwrap().unwrap();
    lp.peers[2].engine.core.skip_writer_rules = false;
    lp.advance(1000);
    spread(&mut lp);
    out.push(("a key actor's roster", None, lp));
    // a thing detached from its folder: A makes G and T under G, takes admin on T and removes G's
    // record edge there, then grants B write on T along its hop marked direct (Open 21): alike
    let (mut lp, ps) = people(2);
    let g = thing_of(&mut lp, 0, ps[0]);
    let t = thing_of(&mut lp, 0, g);
    spread(&mut lp);
    grant(&mut lp, 0, t, ps[0], edge_of(Role::Admin));
    remove(&mut lp, 0, t, g);
    grant(&mut lp, 0, t, ps[1], edge_of(Role::Write));
    out.push(("a detached thing", None, lp));
    // a writer's commit of two may-grant grants on T (read to C, write to D), unseen by A, who then
    // lowers the writer to read, flag kept: both grants fall under both walks (C's by Open 23's rule)
    let (mut lp, ps) = people(4);
    let t = thing_of(&mut lp, 0, ps[0]);
    spread(&mut lp);
    grant(&mut lp, 0, t, ps[1], may_grant(Role::Write));
    let mut m = Mutation::new();
    for (to, r) in [(ps[2], Role::Read), (ps[3], Role::Write)] {
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::Weak(to))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge_of(r))) }).unwrap();
    }
    // this engine's writer refuses it (a writer's raw role write needs admin): another one's
    lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1000);
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: Some(may_grant(Role::Read)), retain: None }).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    out.push(("a writer's two invites in one commit", None, lp));
    out
}

// spec/permissions.md §5.1, notes/a1-spec/README.md step 3 (For the wiring): the new walk over
// the paths role commits state against today's walk, per world of a listed class: each world shows differences, and
// only those of its class; a world of no class shows none. By hand: a measure for the wiring,
// which extends it as it moves the engine to the walk (the full sweep, at every engine drop of
// the engine suites, is the README's probe).
#[test]
#[ignore = "by hand: the wiring's measure of the new walk against today's"]
fn new_walk_differs_only_by_design() {
    let mut bad = Vec::new();
    for (name, class, lp) in class_worlds() {
        for (i, p) in lp.peers.iter().enumerate() {
            let d = walks_differ(&p.engine);
            println!("{name} (peer {i}, class {class:?}): {} differences", d.len());
            for x in &d {
                println!("  {x}");
            }
            let fits = match class {
                None => d.is_empty(),
                Some(c) if c.starts_with("a no-op leave") =>!d.is_empty() && d.iter().all(|x| x.contains("old true, new Some(Dropped)")),
                Some(c) => panic!("no rule for class {c}"),
            };
            let shown = class.is_none() || lp.peers.iter().any(|p| !walks_differ(&p.engine).is_empty());
            if !fits || !shown {
                bad.push(format!("{name} peer {i}: {d:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "differences outside their class: {bad:#?}");
}

// notes/principles.md Check scaling, spec/permissions.md §2 Path's may-grant: finding an
// invite grant's path (`Need::Invite`: the role on every edge but the last, as an invite on the
// last) walks the things reaching its target, as many at 10n unrelated role commits held as at n.
#[test]
fn finding_an_invite_grants_path_does_not_grow_with_history_spec_wire_4() {
    let walked = |n: usize| {
        let (mut lp, ps) = people(3);
        let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
        let t = thing_of(&mut lp, 0, pa);
        let h = thing_of(&mut lp, 0, pa);
        spread(&mut lp);
        grant(&mut lp, 0, t, h, may_grant(Role::Write));
        grant(&mut lp, 0, h, pb, edge_of(Role::Write));
        for _ in 0..n {
            let x = thing_of(&mut lp, 0, pa);
            lp.peers[0].engine.grant(&x, &pb, &edge_of(Role::Read)).unwrap();
        }
        spread(&mut lp);
        osis_base::costs::take();
        lp.peers[1].engine.grant(&t, &pc, &edge_of(Role::Read)).unwrap();
        let c = osis_base::costs::take().iter().find(|x| x.0 == "perm: ways walked").map_or(0, |x| x.2);
        let h_path = one_path(&lp.peers[1].engine.header(&lp.peers[1].engine.commit_ids().into_iter().max_by_key(|id| lp.peers[1].engine.header(id).map(|h| h.ts)).unwrap()).unwrap());
        (c, h_path == [h])
    };
    let (small, large) = (walked(1), walked(10));
    assert!(small.1 && large.1, "the invite grant states [H]");
    assert!(small.0 > 0 && small == large, "ways walked at n {small:?} and 10n {large:?}");
}

// spec/permissions.md §1 Path, Direct mark; spec/wire.md §4 `marks` (README Open 21): A
// makes G and T under G, takes admin on T by its own grant and removes G's record edge there
// (detaching T from its folder). A's later content and role writes on T state the empty path with
// its one hop marked direct (A's own grant: the descent is cut, so no unmarked path gives the
// role), and are applied by today's walk and by the new walk alike: B, granted write, reads A's
// value; no edge write's verdict or final role differs. Before its own grant, A's writes state the
// descent, unmarked; once it holds the grant, the marked hop (the fewest edges), before the detach
// too.
#[test]
fn a_detached_things_owner_states_a_marked_hop_both_walks_apply_spec_wire_4() {
    let (mut lp, ps) = people(2);
    let g = thing_of(&mut lp, 0, ps[0]);
    let t = thing_of(&mut lp, 0, g);
    spread(&mut lp);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("before")).unwrap();
    let before = lp.peers[0].commit(m).unwrap().unwrap();
    grant(&mut lp, 0, t, ps[0], edge_of(Role::Admin));
    let mut m = Mutation::new();
    m.set(t, &REG, &s("both routes")).unwrap();
    let both = lp.peers[0].commit(m).unwrap().unwrap();
    remove(&mut lp, 0, t, g);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("detached")).unwrap();
    let content = lp.peers[0].commit(m).unwrap().unwrap();
    let role = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Write)).unwrap().commits;
    lp.advance(1000);
    spread(&mut lp);
    let e = &lp.peers[0].engine;
    let path = |id| match &e.header(&id).unwrap().path {
        osis_commit::Paths::One(p) => p.clone(),
        x => panic!("{x:?}"),
    };
    assert_eq!(path(before), osis_commit::Path::default(), "the descent, unmarked");
    let marked = osis_commit::Path { purge: 0, things: vec![], direct: 1 };
    assert_eq!(path(content), marked);
    assert_eq!(path(both), marked, "the direct edge, fewer edges than the descent");
    assert!(!role.is_empty() && role.iter().all(|id| path(*id) == marked), "{role:?}");
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("detached")), "B reads A's write");
    assert_eq!(lp.peers[1].engine.core.timelines.role(&ps[1], &t, At::END), Some(Role::Write));
    for p in &lp.peers {
        let d = walks_differ(&p.engine);
        assert!(d.is_empty(), "{d:?}");
        let (paths, ids) = new_walk(&p.engine);
        let applied = ids.iter().filter(|(nid, (w, _))| role.contains(&w.0) && matches!(paths.status(nid), Some(osis_perm::paths::Status::Applied))).count();
        assert_eq!(applied, 1, "the new walk applies A's grant along the marked hop");
    }
}

// notes/principles.md Check scaling, spec/permissions.md §1 Path, Direct mark: finding
// a detached thing's path (A's direct edge, marked) walks the things reaching it, as many at 10n
// unrelated role commits held as at n.
#[test]
fn finding_a_marked_path_does_not_grow_with_history_spec_wire_4() {
    let walked = |n: usize| {
        let (mut lp, ps) = people(2);
        let g = thing_of(&mut lp, 0, ps[0]);
        let t = thing_of(&mut lp, 0, g);
        spread(&mut lp);
        grant(&mut lp, 0, t, ps[0], edge_of(Role::Admin));
        remove(&mut lp, 0, t, g);
        for _ in 0..n {
            let x = thing_of(&mut lp, 0, g);
            lp.peers[0].engine.grant(&x, &ps[1], &edge_of(Role::Read)).unwrap();
        }
        spread(&mut lp);
        osis_base::costs::take();
        let mut m = Mutation::new();
        m.set(t, &REG, &s("x")).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let c = osis_base::costs::take().iter().find(|x| x.0 == "perm: ways walked").map_or(0, |x| x.2);
        let osis_commit::Paths::One(p) = lp.peers[0].engine.header(&id).unwrap().path.clone() else { panic!("one path") };
        (c, p.direct)
    };
    let (small, large) = (walked(1), walked(10));
    assert!(small.1 == 1 && large.1 == 1, "the marked hop: {small:?} {large:?}");
    assert!(small.0 > 0 && small == large, "ways walked at n {small:?} and 10n {large:?}");
}
