#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Role commits state real paths (notes/a1-spec/README.md step 3, Role paths; notes/a1-spec/
//! permissions.md §1 Path, §2): each role commit the engine writes states the path by which its
//! signer reaches what it writes, and the old walk, which reads the signer alone, judges every
//! edge write as it did when role commits stated the Interim empty path.

use crate::common;
use crate::flows::{edge_of, follow, people, spread, thing_of};
use common::*;
use osis_base::{Role, Tid, Ts};
use osis_engine::flows::{Demotion, LinkSpec};
use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;
use osis_perm::{At, Point};
use osis_schema::core_types as ct;
use std::collections::BTreeMap;

/// The representative world's peers (accounts `pa`..`pd`, written as their accounts) and things.
pub(crate) struct World {
    pub lp: LocalPeer,
    pub things: Vec<Tid>,
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

fn invite(role: Role, invite: Role) -> ct::Edge {
    ct::Edge { invite: Some(invite), ..edge_of(role) }
}

/// Four accounts A (0), B (1), C (2), D (3). B grants through one holder (H1 on T1) and through
/// three (K1, K2, K3 on T3) and removes D through the three (the removal rotates T3); B, admin of
/// H5, takes H5 off T5 (a self-removal through a holder: B's only role there is through H5); C
/// leaves T1 itself; B invites D to T4 by H4's invite and C invites B by its own; a timed grant
/// on T1 ends and B finalizes it; C redeems a single-use link to T7; on T6, B grants D write and
/// writes content only C receives, A removes B, and C vouches for the grant and writes an addendum
/// for the content, then leaves T6 itself (an admin's leave, naming a remaining admin); A removes
/// C from T8, which A reaches by a descent of two steps (naming a remaining admin). With
/// `interim`, every node's role commits state the Interim empty path.
pub(crate) fn world(interim: bool) -> World {
    let (mut lp, ps) = people(4);
    for p in &mut lp.peers {
        p.engine.interim_role_paths(interim);
    }
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
    // invites: by a holder's invite and by one's own
    grant(&mut lp, 0, t4, h4, invite(Role::Write, Role::Read));
    grant(&mut lp, 0, h4, pb, edge_of(Role::Write));
    grant(&mut lp, 1, t4, pd, edge_of(Role::Read));
    grant(&mut lp, 0, t4, pc, invite(Role::Write, Role::Read));
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
    // a vouch and an addendum for what A's removal of B left out, then C's own leave
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
    World { lp, things }
}

/// Every role commit's edge writes at peer `i`, by (ts, signer, target, holder): whether the
/// old walk applies it; and every thing's roster.
type Verdicts = (BTreeMap<(Ts, Tid, Tid, Tid), bool>, BTreeMap<Tid, BTreeMap<Tid, osis_perm::Edge>>);

fn verdicts(w: &World, i: usize) -> Verdicts {
    let e = &w.lp.peers[i].engine;
    let mut out = BTreeMap::new();
    let mut rosters = BTreeMap::new();
    for t in &w.things {
        if let Some(tl) = e.core.timelines.get(t) {
            for (wid, c, op) in tl.held_on(t) {
                out.insert((c.ts, c.signer, op.target, op.holder), tl.is_applied(&wid));
            }
        }
        rosters.insert(*t, e.roster(t));
    }
    (out, rosters)
}

// notes/a1-spec/README.md step 3 (Role paths), spec/permissions.md §5.2 Interim: stating real
// paths on role commits changes no verdict of the old walk: every node's verdict on every edge
// write, and every thing's roster, equal those of the same world with every role commit stating
// the Interim empty path.
#[test]
fn role_paths_change_no_verdict_of_the_old_walk_spec_permissions_5_2() {
    let (real, interim) = (world(false), world(true));
    for i in 0..4 {
        let (a, b) = (verdicts(&real, i), verdicts(&interim, i));
        assert!(a.0.len() >= 20, "peer {i}: {} edge writes", a.0.len());
        assert_eq!(a, b, "peer {i}");
    }
}

/// Whether `p` is on `q`'s record chain (above `q`).
fn above(e: &osis_engine::Engine, p: Tid, q: Tid) -> bool {
    std::iter::successors(e.core.created(&q).and_then(|r| r.mint_admin()), |y| e.core.created(y).and_then(|r| r.mint_admin())).take(70).any(|x| x == p)
}

/// The role and invite hop `p` to `q` gives just before `point`: admin for a descent, else `p`'s
/// direct edge on `q` (`None`: no edge held).
fn hop(e: &osis_engine::Engine, p: Tid, q: Tid, point: Point) -> Option<(Role, Option<Role>)> {
    if above(e, p, q) {
        return Some((Role::Admin, Some(Role::Admin)));
    }
    let tl = e.core.timelines.get(&q)?;
    let edges = tl.edges_at(Some(point));
    let x = edges.get(&p, &q).filter(|x| x.alive_at(Some(point.ts)))?;
    Some((x.role, if x.role == Role::Admin { Some(Role::Admin) } else { x.invite.map(|i| i.min(x.role)) }))
}

// notes/a1-spec/permissions.md §1 Path, §2 Self-removal and Invite grant, spec/wire.md §4 field 2:
// every role commit states a real path. Over the representative world, each role commit A holds
// states one path, purge index 0, whose hops from its signer to each thing it writes (to the
// holder, for a self-removal) are held edges or descents just before its key, giving what the
// commit needs there: the signer's role on the thing (admin for an admin's edge write, its role
// for a rotation or a vouch), admin up to the holder for a self-removal, the granted role as an
// invite on the last edge for an invite grant. Every kind the table names is met.
#[test]
fn every_stated_role_path_is_a_chain_of_held_edges_spec_wire_4() {
    let w = world(false);
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
            // a key actor writing itself: [S] (notes/a1-spec/permissions.md §1 Path)
            let members: Vec<Tid> = std::iter::once(h.signer).chain(listed.iter().copied()).chain((!leave && t != h.signer).then_some(t)).collect();
            let hops: Vec<(Role, Option<Role>)> = members.windows(2).map(|x| hop(e, x[0], x[1], point).unwrap_or_else(|| panic!("{id:?}: {:?} holds nothing on {:?} (path to {t:?}: {listed:?}; {:?}, effective {:?}, record {:?})", x[0], x[1], h.aspects.iter().map(|a| (a.tid, a.ak.as_str().to_string())).collect::<Vec<_>>(), e.core.timelines.role(&h.signer, &t, At::before(point)), e.core.created(&t)))).collect();
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
                let kind = if has("vouches.0") {
                    "vouch"
                } else if has("roles.0") && h.frontier.is_none() && ops.iter().all(|(_, v)| v.is_none()) {
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
            if h.remains.is_some() {
                *seen.entry("remains").or_default() += 1;
            }
        }
    }
    for k in ["leave", "leave through a holder", "redemption", "invite", "vouch", "finalize", "admin edge write", "rotation", "remains"] {
        assert!(seen.contains_key(k), "no {k}: {seen:?}");
    }
    assert!(lens.contains_key(&1) && lens.contains_key(&3), "paths through one and three holders: {lens:?}");
    // the addendum: a content commit on T6 writing `addenda.0`, stating its real path
    let e = &w.lp.peers[0].engine;
    let addenda = e.commit_ids().into_iter().filter_map(|id| e.header(&id)).filter(|h| h.kind == osis_commit::Kind::Content && h.aspects.iter().any(|a| a.ak.as_str() == "addenda.0")).count();
    assert!(addenda >= 1, "an addendum is written");
}
