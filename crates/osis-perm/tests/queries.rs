//! Certificates (spec/permissions.md §4), purge rights (§8), rotation (§3), move resolution
//! (§7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use membership_model::{edges, joint, Rng};
use osis_core::Role::{Admin, Read, Write};
use osis_core::{Role, Tid};
use osis_perm::{verify, At, Edge, MoveIndex, Point, PurgeBy, Timeline, WriteId};
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
    let certs = tl.certificates(&z, &g, at);
    assert!(certs.commits.contains(&grant) && certs.commits.contains(&rm), "{certs:?}");
    assert!(certs.created.contains(&g) && certs.created.contains(&p) && certs.created.contains(&k));
    let set = tl.certificate_set(&certs, &held);
    assert!(!verify(&set, &z, &g, at, Write));
    let before = Point { ts: ts(4), node: z, commit: cid(1) };
    let mut set2 = set.clone();
    set2.remove(&rm);
    assert!(verify(&set2, &z, &g, before, Write));
}

/// §4 projection: for every write of random joint and edges histories, its author's
/// certificates plus the write give the write the timeline's outcome (applied, dropped) and
/// the author its standing at the write.
fn cert_run_joint(samples: u64, seed: u64) {
    let mut rng = Rng(seeded(seed));
    for s in 0..samples {
        let h = joint::random_hist(&mut rng);
        let mut w = World::new();
        let nodes = w.nodes(h.nodes);
        let (mut actors, mut top) = (Vec::new(), Vec::new());
        for o in &h.owners {
            let (owner, tp) = match *o {
                joint::Owner::Node(n) => (nodes[n], nodes[n]),
                joint::Owner::Actor(y) => (actors[y], top[y]),
            };
            actors.push(w.thing(owner));
            top.push(tp);
        }
        let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
        let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
        for (m, row) in h.genesis.iter().enumerate() {
            for (x, &r) in row.iter().enumerate() {
                if r != membership_model::Role::None {
                    let role = if r == membership_model::Role::Admin { Admin } else { Write };
                    w.set(top[x], actors[x], ent(m), edge(role), 0, &all0);
                }
            }
        }
        for (i, jw) in h.writes.iter().enumerate() {
            let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
            let e = match jw.role {
                membership_model::Role::None => None,
                membership_model::Role::Admin => edge(Admin),
                _ => edge(Write),
            };
            w.commit_id(cid(jw.id), nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.member), e)], &recv);
        }
        if let Some(d) = cert_check(&w) {
            panic!("sample {s}: {d}\n{h:?}");
        }
    }
}

fn cert_check(w: &World) -> Option<String> {
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    // drops found in another order on a projection (sticky residue) need not agree
    if sticky_residue(&tl) {
        return None;
    }
    for c in &w.commits {
        for (k, op) in c.ops.iter().enumerate() {
            let id = WriteId::Op(c.id, k as u32);
            let at = Point { ts: ts(c.t), node: c.author, commit: c.id };
            let certs = tl.write_certificates(&id).unwrap();
            let set = tl.certificate_set(&certs, &held);
            let ct = Timeline::evaluate(&set);
            let (fa, fd) = (tl.is_applied(&id), tl.dropped().contains_key(&id));
            let (ca, cd) = (ct.is_applied(&id), ct.dropped().contains_key(&id));
            let (fs, cs) = (tl.standing(&c.author, &op.0, At::before(at)), ct.standing(&c.author, &op.0, At::before(at)));
            if (fa, fd, fs) != (ca, cd, cs) {
                return Some(format!("write {id:?}: full applied {fa} dropped {fd} {fs:?}, certificates applied {ca} dropped {cd} {cs:?}"));
            }
        }
    }
    None
}

#[test]
fn certificates_project_joint() {
    cert_run_joint(80, 0x5eed_0201);
}

#[test]
#[ignore]
fn certificates_project_joint_large() {
    cert_run_joint(20_000, 0x5eed_0202);
}

fn cert_run_edges(samples: u64, seed: u64) {
    let mut rng = Rng(seeded(seed));
    for s in 0..samples {
        let h = edges::random_hist(&mut rng);
        let mut w = World::new();
        let nodes = w.nodes(h.n());
        let t = w.thing(nodes[0]);
        let me = |e: Option<edges::Edge>| {
            e.map(|e| Edge {
                role: match e.role {
                    membership_model::Role::Admin => Admin,
                    membership_model::Role::Write => Write,
                    _ => Read,
                },
                until: (e.until != edges::NEVER).then_some(osis_core::WallMs(e.until as u64)),
                invite: match e.invite {
                    membership_model::Role::None => None,
                    membership_model::Role::Read => Some(Read),
                    membership_model::Role::Write => Some(Write),
                    membership_model::Role::Admin => Some(Admin),
                },
                since: None,
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
            panic!("sample {s}: {d}\n{h:?}");
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
    cert_run_edges(20_000, 0x5eed_0204);
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
        (PurgeBy::Author, dev, true),
        (PurgeBy::Author, wr, false),
        (PurgeBy::Writer, wr, true),
        (PurgeBy::Writer, other, false),
    ] {
        assert_eq!(tl.may_purge(&who, &doc, by, &person, now), expect, "{by:?} by {who:?}");
    }
    // The author's actor lost write on the doc: its nodes lose the `author` right.
    w.set(o, doc, person, edge(Read), 5, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert!(!tl.may_purge(&dev, &doc, PurgeBy::Author, &person, now));
    assert_eq!(PurgeBy::from_code(2), Some(PurgeBy::Author));
    assert_eq!(PurgeBy::from_code(4), None);
}

/// §3: write or above rotates its roles and below; readers rotate nothing.
// spec/permissions.md §1 (membership-class by admins)
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
    assert!(tl.may_write_membership(&n[1], &x, At::END) && !tl.may_write_membership(&n[2], &x, At::END));
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

/// §7: a `/was` claim with standing wins, else `/moved`, else the tid itself; two claims with
/// standing fall back to `/moved`; hops are bounded.
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
    assert_eq!(tl.resolve(&idx, &r, &t, now), f, "two claims with standing: /moved");
    let idx = Moves { was: BTreeMap::new(), moved: BTreeMap::new() };
    assert_eq!(tl.resolve(&idx, &r, &t, now), t);
    let idx = Moves { was: BTreeMap::new(), moved: BTreeMap::from([(t, m), (m, t)]) };
    assert_eq!(tl.resolve(&idx, &r, &t, now), t, "a cycle stops after RESOLUTION_HOPS (even)");
}

/// §5.1 "Frontier": removing a device from P puts in question its writes on P and on G below
/// (every aspect: it falls below write); lowering an admin to write only the membership-class
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
    let s = tl.demotion_scope(&d2, &d1, &p, None, ts(5));
    assert_eq!((s.content.get(&d1), s.membership.get(&d1)), (Some(&both), Some(&both)));
    let s = tl.demotion_scope(&d2, &d1, &p, edge(Write), ts(5));
    assert!(s.content.is_empty());
    assert_eq!(s.membership.get(&d1), Some(&both));
    assert!(tl.demotion_scope(&d2, &x, &g, edge(Write), ts(5)).is_empty());
    assert!(tl.demotion_scope(&d1, &d1, &p, None, ts(5)).is_empty(), "never its own subject");
}

/// spec/permissions.md §1: an owner chain reaches its key actor within `MAX_OWNER_DEPTH` owner
/// links; a deeper thing has none, and a chain query walks at most that far.
#[test]
fn owner_chain_capped_spec_permissions_1() {
    use osis_core::format::MAX_OWNER_DEPTH;
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
        let until = (rng.below(3) == 0).then(|| osis_core::WallMs(rng.below(10) as u64));
        (rng.below(4) != 0).then_some(Edge { role, until, invite, since: None })
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
            assert_eq!(a.admin_reaching(x), b.admin_reaching(x));
            for n in &ents {
                assert_eq!(a.standing(x, &ra, n), b.standing(x, &rb, n));
            }
        }
    }
}
