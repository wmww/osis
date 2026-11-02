//! Certificates (spec/permissions.md §4), purge rights (§8), rotation (§3), move resolution
//! (§7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use roles_model::{edges, joint, Rng};
use osis_base::Role::{Admin, Read, Write};
use osis_base::{Role, Tid};
use osis_perm::{verify, At, Edge, HeldSet, MoveIndex, Point, PurgeBy, Timeline, WriteId};
use std::collections::BTreeMap;

/// §4: a stolen device's grant verifies from certificates until the removal that drops it is
/// among them; the certificates of the grantee's chain include that removal.
#[test]
fn certificates_carry_demotions() {
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, d1, d2, z) = (n[0], n[1], n[2], n[3]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, d1, edge(Admin), 0, &all);
    w.set(k, p, d2, edge(Admin), 0, &all);
    let grant = w.set(d1, g, z, edge(Write), 3, &[]);
    let rm = w.set(d2, p, d1, None, 5, &[]);
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let at = Point { ts: ts(9), node: z, commit: cid(1) };
    let certs = tl.certificates(&z, &g);
    assert!(certs.commits.contains(&grant) && certs.commits.contains(&rm), "{certs:?}");
    assert!(certs.created.contains(&g) && certs.created.contains(&p) && certs.created.contains(&k));
    let set = tl.certificate_set(&certs, &held);
    assert!(!verify(&set, &z, &g, at, Write));
    let before = Point { ts: ts(4), node: z, commit: cid(1) };
    let mut set2 = set.clone();
    set2.remove(&rm);
    assert!(verify(&set2, &z, &g, before, Write));
}

/// §4: a demotion goes along with its demoted author's other paths. X writes on G by
/// its admin edge; a later grant makes X an admin of G's owner P; removing X's G edge after
/// that is no fall, so X's write unseen by the remover stands from certificates too.
#[test]
fn certificates_carry_chain_at_demotion_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(4);
    let (x, a, k) = (n[0], n[1], n[2]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(k, g, x, edge(Admin), 0, &all);
    w.set(k, p, a, edge(Admin), 0, &all);
    w.set(x, g, n[3], edge(Write), 2, &[]);
    w.set(a, p, x, edge(Admin), 2, &[(x, 2), (k, 2)]);
    w.set(k, g, x, None, 6, &[]);
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let id = WriteId::Op(w.commits[2].id, 0);
    assert!(tl.is_applied(&id) && tl.dropped().is_empty());
    let ct = Timeline::evaluate(&tl.certificate_set(&tl.write_certificates(&id).unwrap(), &held));
    assert!(ct.is_applied(&id) && !ct.dropped().contains_key(&id));
}

/// §4: as above, but the removal is by an admin d whose own later removal drops it: a demotion
/// dropped later still drops in a projection that lacks X's other path, so its chain goes along
/// though it is not applied in the final walk.
#[test]
fn certificates_carry_chain_at_dropped_demotion_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(5);
    let (x, a, k, d) = (n[0], n[1], n[2], n[4]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(k, g, x, edge(Admin), 0, &all);
    w.set(k, p, a, edge(Admin), 0, &all);
    w.set(k, g, d, edge(Admin), 0, &all);
    w.set(x, g, n[3], edge(Write), 2, &[]);
    w.set(a, p, x, edge(Admin), 2, &[(x, 2), (k, 2)]);
    let r = w.set(d, g, x, None, 6, &[]);
    w.set(k, g, d, None, 8, &[]);
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let id = WriteId::Op(w.commits[3].id, 0);
    assert!(tl.is_applied(&id) && tl.dropped().contains_key(&WriteId::Op(r, 0)));
    let ct = Timeline::evaluate(&tl.certificate_set(&tl.write_certificates(&id).unwrap(), &held));
    assert!(ct.is_applied(&id) && !ct.dropped().contains_key(&id));
}

/// §4, §6: a ledger entry with a frontier is a demotion at its own key, before its snapshot:
/// X's chain goes along at that key. X writes on H (owned by G) through its G edge; A then
/// makes X an admin of P (G's owner) and removes it at 8, covering the write; G's snapshot at
/// 10 ends X's G tenure at 6 with a frontier missing the write, while P still held X.
#[test]
fn certificates_carry_chain_at_ledger_end_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(4);
    let (x, a, k) = (n[0], n[1], n[2]);
    let p = w.thing(k);
    let g = w.thing(p);
    let h = w.thing(g);
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(k, g, x, edge(Admin), 0, &all);
    w.set(k, p, a, edge(Admin), 0, &all);
    let wr = w.set(x, h, n[3], edge(Write), 2, &[(a, 3)]);
    w.set(a, p, x, edge(Admin), 2, &[(x, 2), (k, 2)]);
    w.set(a, p, x, None, 8, &[]);
    w.snapshot_l(k, g, &[], &[(x, Admin, Some((0, k, None)), (6, k, None), true)], 10, &all);
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let id = WriteId::Op(wr, 0);
    assert!(tl.is_applied(&id) && !tl.dropped().contains_key(&id), "{:?}", tl.dropped());
    let ct = Timeline::evaluate(&tl.certificate_set(&tl.write_certificates(&id).unwrap(), &held));
    assert!(ct.is_applied(&id) && !ct.dropped().contains_key(&id), "{:?}", ct.dropped());
}

/// §4 projection: for every write of random joint and edges histories, its author's
/// certificates plus the write give the write the timeline's outcome (applied, dropped) and
/// the author its standing at the write.
fn cert_run_joint(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let h = joint::random_hist(&mut rng);
        let mut w = World::new();
        let nodes = w.nodes(h.nodes);
        let (actors, top) = joint_actors(&mut w, &h, &nodes);
        joint_genesis(&mut w, &h, &nodes, &actors, &top, None);
        let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
        for (i, jw) in h.writes.iter().enumerate() {
            let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
            let e = match jw.role {
                roles_model::Role::None => None,
                roles_model::Role::Admin => edge(Admin),
                _ => edge(Write),
            };
            w.commit_id(cid(jw.id), nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.holder), e)], &recv);
        }
        if let Some(d) = cert_check(&w) {
            panic!("seed {seed:#x} sample {s}: {d}\n{h}");
        }
        // one actor compacted at a roster snapshot of the end: its history held only as
        // roster and ledger tenures
        // (an ownerless actor and those below it have no key actor at the top to write one)
        let x = actors[s as usize % actors.len()];
        let Some(tp) = top[s as usize % actors.len()] else { continue };
        let tl = Timeline::evaluate(&w.held());
        let mut w2 = w.clone();
        let snap = w2.snapshot_state(tp, x, tl.roster_state(&x), LATE / 2);
        if let Some(d) = cert_check_held(&w2.compacted(x, snap)) {
            panic!("seed {seed:#x} sample {s}, {x:?} compacted: {d}\n{h}");
        }
    }
}

fn cert_check(w: &World) -> Option<String> {
    cert_check_held(&w.held())
}

/// Every edge write and roster snapshot of `held`, judged from its certificates as from
/// `held`.
fn cert_check_held(held: &osis_perm::MemoryHeldSet) -> Option<String> {
    let tl = Timeline::evaluate(held);
    // drops found in another order on a projection (sticky residue) need not agree
    if sticky_residue(&tl) {
        return None;
    }
    let mut writes: BTreeMap<WriteId, (Point, Tid, Tid)> = BTreeMap::new();
    for c in held.commits.values().flatten() {
        for (k, op) in c.ops.iter().enumerate() {
            writes.insert(WriteId::Op(c.id, k as u32), (c.point(), c.author, op.target));
        }
    }
    for s in held.snapshots.values().flatten() {
        writes.insert(WriteId::Snapshot(s.id), (s.point(), s.author, s.thing));
    }
    // node cards: each node's certificates for a thing give its role there at every write's
    // point and at the end
    let mut ats: Vec<At> = writes.values().map(|(p, _, _)| At::before(*p)).collect();
    ats.push(At::now(ts(LATE * 4)));
    let things = held.things();
    for n in things.iter().filter(|n| tl.owners().is_key(n)) {
        for t in &things {
            let ct = Timeline::evaluate(&tl.certificate_set(&tl.certificates(n, t), held));
            for at in &ats {
                let (f, c) = (tl.role(n, t, *at), ct.role(n, t, *at));
                if f != c {
                    return Some(format!("node {n:?} on {t:?} at {at:?}: full {f:?}, certificates {c:?}"));
                }
            }
        }
    }
    for (id, (at, author, target)) in writes {
        let certs = tl.write_certificates(&id).unwrap();
        let set = tl.certificate_set(&certs, held);
        let ct = Timeline::evaluate(&set);
        let (fa, fd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
        let (ca, cd) = (ct.is_applied(&id), ct.dropped().contains_key(&id));
        let (fs, cs) = (tl.standing(&author, &target, At::before(at)), ct.standing(&author, &target, At::before(at)));
        if (fa, fd, fs) != (ca, cd, cs) {
            return Some(format!("write {id:?}: full applied {fa} dropped {fd} {fs:?}, certificates applied {ca} dropped {cd} {cs:?}"));
        }
    }
    None
}

/// §4: a demotion along a path the author gained after its write goes along. n0 writes on A2
/// at 4 by its admin edge (w6), which n2 then removes; at 5 n1 makes n0 an admin of A1, an
/// admin of A2; removing A1 from A2 at 7 without having seen w6 drops it. A1 was on no path
/// of n0's at 4 (OSIS_PERM_SEED=90731).
#[test]
fn certificates_carry_demotion_on_later_path_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(3);
    let a0 = w.thing(n[0]);
    let a1 = w.thing(n[1]);
    let a2 = w.thing(n[1]);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], a0, n[0], edge(Write), 0, &all0);
    w.set(n[0], a0, n[2], edge(Admin), 0, &all0);
    w.set(n[1], a1, n[2], edge(Write), 0, &all0);
    w.set(n[1], a2, n[2], edge(Admin), 0, &all0);
    w.set(n[1], a2, a1, edge(Admin), 0, &all0);
    let r = |a: u64, b: u64, c: u64| vec![(n[0], a), (n[1], b), (n[2], c)];
    w.commit_id(cid(2782044695), n[1], 2, &[(a2, n[0], edge(Admin))], &r(1, 2, 1));
    w.commit_id(cid(3096925279), n[2], 2, &[(a0, a2, edge(Write))], &r(1, 1, 2));
    w.commit_id(cid(1778379934), n[0], 4, &[(a2, n[2], edge(Admin))], &r(4, LATE, 3));
    w.commit_id(cid(527979467), n[2], 4, &[(a2, n[0], None)], &r(3, LATE, 4));
    w.commit_id(cid(2288976456), n[1], 5, &[(a1, n[0], edge(Admin))], &r(LATE, 5, 7));
    w.commit_id(cid(2482343703), n[1], 7, &[(a2, a1, None)], &r(5, 7, 6));
    w.commit_id(cid(1006705973), n[2], 8, &[(a2, a0, None)], &r(LATE, LATE, 8));
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let id = WriteId::Op(cid(1778379934), 0);
    assert!(tl.dropped().contains_key(&id) && !sticky_residue(&tl), "{:?}", tl.dropped());
    assert_eq!(cert_check(&w), None);
}

/// As above, n0's later admin edge on A1 held only as a ledger tenure of a roster snapshot of
/// A1 (its commit compacted away): the later path runs over ledger edges too.
#[test]
fn certificates_carry_demotion_on_later_ledger_path_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(3);
    let a0 = w.thing(n[0]);
    let a1 = w.thing(n[1]);
    let a2 = w.thing(n[1]);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], a0, n[0], edge(Write), 0, &all0);
    w.set(n[0], a0, n[2], edge(Admin), 0, &all0);
    w.set(n[1], a1, n[2], edge(Write), 0, &all0);
    w.set(n[1], a2, n[2], edge(Admin), 0, &all0);
    w.set(n[1], a2, a1, edge(Admin), 0, &all0);
    let r = |a: u64, b: u64, c: u64| vec![(n[0], a), (n[1], b), (n[2], c)];
    w.commit_id(cid(2782044695), n[1], 2, &[(a2, n[0], edge(Admin))], &r(1, 2, 1));
    w.commit_id(cid(3096925279), n[2], 2, &[(a0, a2, edge(Write))], &r(1, 1, 2));
    w.commit_id(cid(1778379934), n[0], 4, &[(a2, n[2], edge(Admin))], &r(4, LATE, 3));
    w.commit_id(cid(527979467), n[2], 4, &[(a2, n[0], None)], &r(3, LATE, 4));
    w.commit_id(cid(2482343703), n[1], 7, &[(a2, a1, None)], &r(5, 7, 6));
    w.commit_id(cid(1006705973), n[2], 8, &[(a2, a0, None)], &r(LATE, LATE, 8));
    w.snapshot_l(n[1], a1, &[(n[2], edge(Write).unwrap())], &[(n[0], Admin, Some((5, n[1], None)), (9, n[1], None), false)], 10, &r(10, 10, 10));
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let id = WriteId::Op(cid(1778379934), 0);
    assert!(tl.dropped().contains_key(&id) && !sticky_residue(&tl), "{:?}", tl.dropped());
    assert_eq!(cert_check(&w), None);
}

/// OSIS_PERM_SEED=115000: n0 lowers itself on A1 to Write at 2 (w0); n1 makes n0 an admin
/// of A0 (an admin of A1 through A2) at 4 and removes n0 from A1 at 6; n2 removes n1 from A0
/// at 7, unseen by n1.
#[test]
fn certificates_self_demotion_regained_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(3);
    let a0 = w.thing(n[2]);
    let a1 = w.thing(a0);
    let a2 = w.thing(n[2]);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[2], a1, n[0], edge(Admin), 0, &all0);
    w.set(n[2], a0, n[1], edge(Admin), 0, &all0);
    w.set(n[2], a1, n[1], edge(Admin), 0, &all0);
    w.set(n[2], a2, n[2], edge(Write), 0, &all0);
    w.set(n[2], a2, a0, edge(Admin), 0, &all0);
    w.set(n[2], a0, a2, edge(Admin), 0, &all0);
    w.set(n[2], a1, a2, edge(Admin), 0, &all0);
    let r = |a: u64, b: u64, c: u64| vec![(n[0], a), (n[1], b), (n[2], c)];
    w.commit_id(cid(2921343996), n[0], 2, &[(a1, n[0], edge(Write))], &r(2, LATE, 1));
    w.commit_id(cid(3991304582), n[1], 4, &[(a0, n[0], edge(Admin))], &r(2, 4, LATE));
    w.commit_id(cid(2543417714), n[1], 6, &[(a1, n[0], None)], &r(LATE, 6, LATE));
    w.commit_id(cid(1791504058), n[2], 7, &[(a0, n[1], None)], &r(LATE, LATE, 7));
    assert_eq!(cert_check(&w), None);
}

/// As above, but n0's admin edge on A0 comes from n3 (at 4), made an admin of A0 by n1 at 3.
/// Dropping n1's grant leaves n3's without authority: in no walk's D, yet the first walk
/// applied it, and that walk kept n0's class when n1 removed n0 from A1.
#[test]
fn certificates_self_demotion_regained_indirect_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(4);
    let a0 = w.thing(n[2]);
    let a1 = w.thing(a0);
    let a2 = w.thing(n[2]);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[2], a1, n[0], edge(Admin), 0, &all0);
    w.set(n[2], a0, n[1], edge(Admin), 0, &all0);
    w.set(n[2], a1, n[1], edge(Admin), 0, &all0);
    w.set(n[2], a2, n[2], edge(Write), 0, &all0);
    w.set(n[2], a2, a0, edge(Admin), 0, &all0);
    w.set(n[2], a0, a2, edge(Admin), 0, &all0);
    w.set(n[2], a1, a2, edge(Admin), 0, &all0);
    let r = |a: u64, b: u64, c: u64, d: u64| vec![(n[0], a), (n[1], b), (n[2], c), (n[3], d)];
    w.set(n[0], a1, n[0], edge(Write), 2, &r(2, LATE, 1, 2));
    w.set(n[1], a0, n[3], edge(Admin), 3, &r(3, 3, LATE, 3));
    w.set(n[3], a0, n[0], edge(Admin), 4, &r(4, 4, LATE, 4));
    w.set(n[1], a1, n[0], None, 6, &r(LATE, 6, LATE, LATE));
    w.set(n[2], a0, n[1], None, 7, &r(LATE, LATE, 7, LATE));
    let tl = Timeline::evaluate(&w.held());
    assert_eq!(tl.dropped().len(), 2);
    assert_eq!(cert_check(&w), None);
}

/// OSIS_PERM_SEED=116000: n1 leaves A0 at 1 and A1 at 3 (unseen by n0) and again at 4; n0
/// removes n1 from A0 at 7, which restores n1's own earlier admin edge there, so n1's class on
/// A1 below A0 falls and its unseen leave at 3 drops. A0 is on no path of n1's at 7.
#[test]
fn certificates_carry_demotion_of_left_edge_spec_permissions_4() {
    let mut w = World::new();
    let n = w.nodes(2);
    let a0 = w.thing(n[0]);
    let a1 = w.thing(a0);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], a0, n[1], edge(Admin), 0, &all0);
    w.set(n[0], a1, n[1], edge(Admin), 0, &all0);
    w.commit_id(cid(3067972474), n[1], 1, &[(a0, n[1], None)], &[(n[0], 0)]);
    w.commit_id(cid(3117608188), n[1], 3, &[(a1, n[1], None)], &[(n[0], LATE)]);
    w.commit_id(cid(738872167), n[1], 4, &[(a1, n[1], None)], &[(n[0], 3)]);
    w.commit_id(cid(4081336266), n[0], 6, &[(a1, a0, None)], &[(n[1], LATE)]);
    w.commit_id(cid(393771808), n[0], 7, &[(a0, n[1], None)], &[(n[1], LATE)]);
    assert_eq!(cert_check(&w), None);
}

#[test]
fn certificates_project_joint() {
    cert_run_joint(80, 0x5eed_0201);
}

/// 64k samples, each also with one actor compacted at a roster snapshot.
#[test]
#[ignore]
fn certificates_project_joint_large() {
    sharded(64_000, 0x5eed_0202, cert_run_joint);
}

fn cert_run_edges(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let h = edges::random_hist(&mut rng);
        let mut w = World::new();
        let nodes = w.nodes(h.n());
        let t = w.thing(nodes[0]);
        let me = |e: Option<edges::Edge>| {
            e.map(|e| Edge {
                role: match e.role {
                    roles_model::Role::Admin => Admin,
                    roles_model::Role::Write => Write,
                    _ => Read,
                },
                until: (e.until != edges::NEVER).then_some(osis_base::WallMs(e.until as u64)),
                invite: match e.invite {
                    roles_model::Role::None => None,
                    roles_model::Role::Read => Some(Read),
                    roles_model::Role::Write => Some(Write),
                    roles_model::Role::Admin => Some(Admin),
                },
                since: None, tied: crate::common::tie_if((e.until ^ e.role as u32 ^ e.invite as u32) & 1 == 1), keyset: None,
            })
        };
        let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
        for (x, e) in h.genesis.iter().enumerate().skip(1) {
            if e.is_some() {
                w.set(nodes[0], t, nodes[x], me(*e), 0, &all0);
            }
        }
        for (i, ew) in h.writes.iter().enumerate() {
            let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
            let ops: Vec<(Tid, Tid, Option<Edge>)> = ew.ops.iter().map(|&(x, e)| (t, nodes[x], me(e))).collect();
            w.commit_id(cid(ew.id), nodes[ew.author], ew.t as u64, &ops, &recv);
        }
        if let Some(d) = cert_check(&w) {
            panic!("seed {seed:#x} sample {s}: {d}\n{h}");
        }
    }
}

#[test]
fn certificates_project_edges() {
    cert_run_edges(80, 0x5eed_0203);
}

#[test]
#[ignore]
fn certificates_project_edges_large() {
    sharded(20_000, 0x5eed_0204, cert_run_edges);
}

/// §8: purge rights by retention, judged at the request's time.
#[test]
fn purge_rights() {
    let mut w = World::new();
    let n = w.nodes(5);
    let (o, a, wr, dev, other) = (n[0], n[1], n[2], n[3], n[4]);
    let person = w.thing(o);
    let doc = w.thing(o);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(o, doc, a, edge(Admin), 0, &all);
    w.set(o, doc, wr, edge(Write), 0, &all);
    w.set(o, person, dev, edge(Admin), 0, &all);
    w.set(o, doc, person, edge(Write), 0, &all);
    let tl = Timeline::evaluate(&w.held());
    let now = At::now(ts(10));
    for (by, who, expect) in [
        (PurgeBy::Nobody, a, false),
        (PurgeBy::Admin, a, true),
        (PurgeBy::Admin, wr, false),
        (PurgeBy::Admin, dev, false),
        (PurgeBy::Author, dev, true),
        (PurgeBy::Author, person, true),
        (PurgeBy::Author, a, false),
        (PurgeBy::Author, o, true), // owns the person, so acts for it
        (PurgeBy::Author, wr, false),
        (PurgeBy::AuthorOrAdmin, a, true),
        (PurgeBy::AuthorOrAdmin, dev, true),
        (PurgeBy::AuthorOrAdmin, wr, false),
        (PurgeBy::Writer, wr, true),
        (PurgeBy::Writer, other, false),
    ] {
        assert_eq!(tl.may_purge(&who, &doc, by, &person, now), expect, "{by:?} by {who:?}");
    }
    // The author's actor lost write on the doc: its nodes lose the `author` right.
    w.set(o, doc, person, edge(Read), 5, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert!(!tl.may_purge(&dev, &doc, PurgeBy::AuthorOrAdmin, &person, now));
    // ... and under `author` nobody holds a right to its deltas
    for who in [dev, person, a, o, wr] {
        assert!(!tl.may_purge(&who, &doc, PurgeBy::Author, &person, now), "{who:?}");
    }
    // an admin who is the author holds the right as the author
    assert!(tl.may_purge(&a, &doc, PurgeBy::Author, &a, now));
    assert_eq!(PurgeBy::from_id(2), Some(PurgeBy::AuthorOrAdmin));
    assert_eq!(PurgeBy::from_id(5), None);
}

/// §3: write or above rotates its roles and below; readers rotate nothing.
// spec/permissions.md §1 (role-class by admins)
#[test]
fn rotation_rights() {
    let mut w = World::new();
    let n = w.nodes(4);
    let x = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(n[0], x, n[1], edge(Admin), 0, &all);
    w.set(n[0], x, n[2], edge(Write), 0, &all);
    w.set(n[0], x, n[3], edge(Read), 0, &all);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!(tl.may_rotate(&n[1], &x, At::END), vec![Read, Write, Admin]);
    assert_eq!(tl.may_rotate(&n[2], &x, At::END), vec![Read, Write]);
    assert_eq!(tl.may_rotate(&n[3], &x, At::END), Vec::<Role>::new());
}

struct Moves {
    was: BTreeMap<Tid, Vec<Tid>>,
    moved: BTreeMap<Tid, Tid>,
}

impl MoveIndex for Moves {
    fn continued_by(&self, t: &Tid) -> Vec<Tid> {
        self.was.get(t).cloned().unwrap_or_default()
    }
    fn moved(&self, t: &Tid) -> Option<Tid> {
        self.moved.get(t).copied()
    }
}

/// §7: a `was.0` claim with standing wins, else `moved.0`, else the tid itself; two claims with
/// standing fall back to `moved.0`; hops are bounded.
#[test]
fn move_resolution() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (x, y, z) = (n[0], n[1], n[2]);
    let r = w.thing(x); // the referencing thing, owned by X
    let t = w.thing(y); // the moved thing, owned by Y
    let m = w.thing(x); // X's copy
    let f = w.thing(z); // a fake claim by Z
    let g = w.thing(z); // a fake Z granted X an edge on
    w.set(z, g, x, edge(Read), 1, &[]);
    let tl = Timeline::evaluate(&w.held());
    let now = At::now(ts(5));
    assert!(tl.has_standing(&r, &m, now) && !tl.has_standing(&r, &f, now) && tl.has_standing(&r, &g, now));
    let idx = Moves { was: BTreeMap::from([(t, vec![m, f])]), moved: BTreeMap::new() };
    assert_eq!(tl.resolve(&idx, &r, &t, now), m);
    let idx = Moves { was: BTreeMap::from([(t, vec![f])]), moved: BTreeMap::from([(t, m)]) };
    assert_eq!(tl.resolve(&idx, &r, &t, now), m);
    let idx = Moves { was: BTreeMap::from([(t, vec![m, g])]), moved: BTreeMap::from([(t, f)]) };
    assert_eq!(tl.resolve(&idx, &r, &t, now), f, "two claims with standing: moved.0");
    let idx = Moves { was: BTreeMap::new(), moved: BTreeMap::new() };
    assert_eq!(tl.resolve(&idx, &r, &t, now), t);
    let idx = Moves { was: BTreeMap::new(), moved: BTreeMap::from([(t, m), (m, t)]) };
    assert_eq!(tl.resolve(&idx, &r, &t, now), t, "a cycle stops after RESOLUTION_HOPS (even)");
}

/// `Timeline::demotion_scope` of `author` setting `holder`'s edge on `target` to `new` at `t`,
/// with an empty frontier.
fn scope_of(tl: &Timeline, author: Tid, holder: Tid, target: Tid, new: Option<Edge>, t: u64) -> osis_perm::DemotionScope {
    let ops = vec![osis_perm::EdgeOp { target, holder, edge: new }];
    let frontier = Some(std::sync::Arc::new(osis_perm::Frontier::default()));
    tl.demotion_scope(osis_perm::RoleCommit { id: osis_base::CommitId([0xee; 32]), ts: ts(t), author, actor: author, frontier, ops })
}

/// §5.1 "Frontier": removing a device from P puts in question its writes on P and on G below
/// (every aspect: it falls below write); lowering an admin to write only the role-class
/// aspects; a grant nothing.
#[test]
fn demotion_scope() {
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, d1, d2, x) = (n[0], n[1], n[2], n[3]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(k, p, d1, edge(Admin), 0, &all);
    w.set(k, p, d2, edge(Admin), 0, &all);
    let tl = Timeline::evaluate(&w.held());
    let both: std::collections::BTreeSet<Tid> = [p, g].into_iter().collect();
    let s = scope_of(&tl, d2, d1, p, None, 5);
    assert_eq!((s.content.get(&d1), s.roles.get(&d1)), (Some(&both), Some(&both)));
    let s = scope_of(&tl, d2, d1, p, edge(Write), 5);
    assert!(s.content.is_empty());
    assert_eq!(s.roles.get(&d1), Some(&both));
    assert!(scope_of(&tl, d2, x, g, edge(Write), 5).is_empty());
    assert!(scope_of(&tl, d1, d1, p, None, 5).is_empty(), "never its own subject");
}

/// spec/permissions.md §5.1 step 4 ("as restored"), §5.1 "Frontier": after x removed its own
/// write edge (no audit), the next explicit write on that edge audits against the edge as
/// restored, so its scope puts x's writes on P and G in question though the edge is gone.
#[test]
fn demotion_scope_as_restored_spec_permissions_5_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (k, a, x) = (n[0], n[1], n[2]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(k, p, a, edge(Admin), 0, &all);
    w.set(k, p, x, edge(Write), 0, &all);
    w.set(x, p, x, None, 1, &all);
    let tl = Timeline::evaluate(&w.held());
    let both: std::collections::BTreeSet<Tid> = [p, g].into_iter().collect();
    let s = scope_of(&tl, a, x, p, None, 5);
    assert_eq!(s.content.get(&x), Some(&both));
}

/// spec/permissions.md §1: an owner chain reaches its key actor within `MAX_OWNER_DEPTH` owner
/// links; a deeper thing has none, and a chain query walks at most that far.
#[test]
fn owner_chain_capped_spec_permissions_1() {
    use osis_base::format::MAX_OWNER_DEPTH;
    let (key, rec) = key_actors(1, 9).remove(0);
    let mut o = osis_perm::Owners::default();
    o.insert(key, &rec);
    let mut chain = Vec::new();
    let mut top = key;
    for i in 0..=MAX_OWNER_DEPTH as u64 {
        let (t, r) = thing_record(top, i);
        o.insert(t, &r);
        chain.push(t);
        top = t;
    }
    // chain[i] is i + 1 links below the key actor; `up` ends with the key actor
    let at_cap = chain[MAX_OWNER_DEPTH - 1];
    let (up, k) = o.chain(&at_cap);
    assert_eq!((up.len(), up.last(), k), (MAX_OWNER_DEPTH, Some(&key), Some(key)));
    let (up, k) = o.chain(chain.last().unwrap());
    assert_eq!(k, None, "one link deeper: no owner chain");
    assert!(up.len() <= MAX_OWNER_DEPTH + 1);
}

/// A `View` with one edge patched answers every authority query as the edge state cloned with
/// that edge set (random owner trees, edges with `until` and invites, patches that add, change
/// or remove an edge).
#[test]
fn patched_view_equals_cloned_edges() {
    use osis_perm::graph::View;
    use osis_perm::{Edges, Owners};
    let mut rng = Rng(0x5eed_0301);
    let pick = |rng: &mut Rng| -> Option<Edge> {
        let role = [Read, Write, Admin][rng.below(3)];
        let invite = [None, Some(Read), Some(Write), Some(Admin)][rng.below(4)].map(|i: Role| i.min(role));
        let until = (rng.below(3) == 0).then(|| osis_base::WallMs(rng.below(10) as u64));
        (rng.below(4) != 0).then_some(Edge { role, until, invite, since: None, tied: crate::common::tie_if(until.is_some() != invite.is_some()), keyset: None })
    };
    for _ in 0..2000 {
        let keys = key_actors(3, 11);
        let mut o = Owners::default();
        let mut ents: Vec<Tid> = Vec::new();
        for (t, r) in &keys {
            o.insert(*t, r);
            ents.push(*t);
        }
        for i in 0..5u64 {
            let (t, r) = thing_record(ents[rng.below(ents.len())], i);
            o.insert(t, &r);
            ents.push(t);
        }
        let mut edges = Edges::default();
        for _ in 0..rng.below(12) {
            let (m, t) = (ents[rng.below(ents.len())], ents[3 + rng.below(5)]);
            if m != t {
                edges.set(m, t, pick(&mut rng));
            }
        }
        let (m, t) = (ents[rng.below(ents.len())], ents[3 + rng.below(5)]);
        let patch = pick(&mut rng);
        let mut cloned = edges.clone();
        cloned.set(m, t, patch);
        let at = (rng.below(2) == 0).then(|| ts(rng.below(10) as u64));
        let a = View::new(&o, &edges, at).patched(m, t, patch);
        let b = View::new(&o, &cloned, at);
        // the patch at least as wide as the edge it replaces: raising the old roles is exact
        let alive = |e: Option<Edge>| e.filter(|e| e.alive_at(at));
        let wider = alive(patch).is_some() && alive(edges.get(&m, &t).copied()).is_none_or(|o| Some(o.role) <= patch.map(|p| p.role));
        for x in &ents {
            let (ra, rb) = (a.roles_from(x), b.roles_from(x));
            assert_eq!(ra, rb);
            for y in &ents {
                assert_eq!(a.roles_to(y).get(x), ra.get(y));
            }
            if wider {
                let mut r = View::new(&o, &edges, at).roles_from(x);
                r.extend(a.roles_raised(&r, &[m]));
                assert_eq!(r, rb);
            }
            assert_eq!(a.reach_forward(x), b.reach_forward(x));
            assert_eq!(a.reach_backward(x), b.reach_backward(x));
            for n in &ents {
                assert_eq!(a.standing(x, &ra, n), b.standing(x, &rb, n));
            }
        }
    }
}

/// §5.1 "Frontier" against step 4: an explicit write R appended after a random history, by an
/// author that had received a random part of it, with the frontier a demoter builds (what it
/// received of each demoted node's writes on the things `demotion_scope` gives, plus its chain
/// certificates): R's audit drops no write the author had received, and each fall below a role
/// it records is in the scope (`roles`; below write also `content`). R's audit can drop a write
/// that held up another standing, widening the fall (notes/permissions.md, Readings of §5.1).
fn scope_check(w: &World, nodes: &[Tid], things: &[Tid], rng: &mut Rng) -> Option<String> {
    use osis_perm::{EdgeOp, Frontier, RoleCommit};
    use std::collections::BTreeSet;
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let ents: Vec<Tid> = nodes.iter().chain(things).copied().collect();
    let author = nodes[rng.below(nodes.len())];
    let target = things[rng.below(things.len())];
    let holder = ents[rng.below(ents.len())];
    let new = [None, edge(Read), edge(Write), edge_inv(Read, Some(Write), None)][rng.below(4)];
    let t = 500;
    // what the author had received: everything, nothing, or about half
    let mode = rng.below(3);
    let writes: Vec<(osis_base::CommitId, Tid, Vec<Tid>)> = w.commits.iter().map(|c| (c.id, c.author, c.ops.iter().map(|o| o.0).collect())).chain(w.snaps.iter().map(|s| (s.id, s.author, vec![s.thing]))).collect();
    let received: BTreeSet<osis_base::CommitId> = writes.iter().filter(|_| mode == 0 || (mode == 2 && rng.below(2) == 0)).map(|c| c.0).collect();
    let certs = tl.certificates(&author, &target);
    let own: BTreeSet<osis_base::CommitId> = certs.commits.into_iter().chain(certs.snapshots.into_keys()).filter(|c| received.contains(c)).collect();
    let frontier = |s: &osis_perm::DemotionScope| {
        let mut f = Frontier { commits: own.clone() };
        for (id, by, on) in &writes {
            let listed = |m: &BTreeMap<Tid, BTreeSet<Tid>>| m.get(by).is_some_and(|ts| on.iter().any(|t| ts.contains(t)));
            if received.contains(id) && (listed(&s.roles) || listed(&s.content)) {
                f.commits.insert(*id);
            }
        }
        f
    };
    let id = osis_base::CommitId([0xee; 32]);
    let r = |f: Frontier| RoleCommit { id, ts: ts(t), author, actor: author, frontier: Some(std::sync::Arc::new(f)), ops: vec![EdgeOp { target, holder, edge: new }] };
    // as a demoter builds it: from the scope with every held write received, until the scope
    // for the frontier is inside the scope it was built from
    let mut scope = tl.demotion_scope(r(tl.all_held()));
    let f = loop {
        let f = frontier(&scope);
        let s = tl.demotion_scope(r(f.clone()));
        if scope.covers(&s) {
            break f;
        }
        scope.join(s);
    };
    let mut held = held;
    held.add_commit(r(f));
    let tl2 = Timeline::evaluate(&held);
    if !tl2.is_applied(&WriteId::Op(id, 0)) || !residue(&tl2).is_empty() {
        return None;
    }
    let p = Point { ts: ts(t), node: author, commit: id };
    let name = |x: &Tid| nodes.iter().position(|y| y == x).map(|i| format!("n{i}")).or_else(|| things.iter().position(|y| y == x).map(|i| format!("A{i}"))).unwrap_or_default();
    let names = |m: &BTreeMap<Tid, BTreeSet<Tid>>| m.iter().map(|(x, s)| format!("{}: {:?}", name(x), s.iter().map(name).collect::<Vec<_>>())).collect::<Vec<_>>().join(", ");
    let what = format!("R: {} sets {} on {} := {new:?}, received {mode}; scope roles {{{}}} content {{{}}}", name(&author), name(&holder), name(&target), names(&scope.roles), names(&scope.content));
    for (d, at) in tl2.dropped() {
        if *at == p && received.contains(&d.commit()) {
            return Some(format!("R drops received write {d:?}; {what}"));
        }
    }
    for x in nodes {
        for n in &ents {
            for d in tl2.demotions(x, n).iter().filter(|d| d.point == p) {
                if !scope.roles.get(x).is_some_and(|s| s.contains(n)) || (d.below == Write && !scope.content.get(x).is_some_and(|s| s.contains(n))) {
                    return Some(format!("demotion below {:?} of {} on {} outside the scope; {what}", d.below, name(x), name(n)));
                }
            }
        }
    }
    None
}

fn scope_run(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let fail = if s % 2 == 0 {
            let h = edges::random_hist(&mut rng);
            let (w, nodes, t) = edges_world(&h, 1);
            scope_check(&w, &nodes, &[t], &mut rng).map(|d| format!("{d}\n{h}"))
        } else {
            let h = joint::random_hist(&mut rng);
            let (w, nodes, actors) = joint_world(&h, 1);
            scope_check(&w, &nodes, &actors, &mut rng).map(|d| format!("{d}\n{h}"))
        };
        if let Some(d) = fail {
            panic!("seed {seed:#x} sample {s}: {d}");
        }
    }
}

#[test]
fn demotion_scope_covers_audits_spec_permissions_5_1() {
    scope_run(4000, 0x5eed_0301);
}

#[test]
#[ignore]
fn demotion_scope_covers_audits_large_spec_permissions_5_1() {
    sharded(64_000, 0x5eed_0302, scope_run);
}
