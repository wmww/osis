//! Making an account (spec/permissions.md §8): A minted with the node thing as mint admin and
//! independent at once, its inbox and profile minted with admin A, the node entering all three.

use crate::common::T0;
use osis_base::Role;
use osis_engine::local_peer::Peer;
use osis_schema::core_types as ct;

// spec/permissions.md §8 Making, spec/sync-inbox.md §1: A is minted with the node thing as mint
// admin, independent; its inbox and profile are minted with admin A, independent, held by strongs
// from A; A's `keys.0` names the inbox, whose setting takes both inbox signals; the node holds A
// (a strong from its root) and reads all three, the inbox and profile in A's sync unit, with
// admin on each by A's record edge.
#[test]
fn making_an_account_spec_permissions_8() {
    let mut p = Peer::new(1, T0).unwrap();
    let (acc, _) = p.engine.make_account().unwrap();
    let e = &mut p.engine;
    let me = e.me();
    assert_eq!(e.mint_admin(&acc.thing), Some(me));
    for t in [acc.inbox, acc.profile] {
        assert_eq!(e.mint_admin(&t), Some(acc.thing));
        assert!(e.closure_holds(&t) && e.sync_unit(&acc.thing).contains(&t), "in A's sync unit");
        assert_eq!(e.role_on(&t), Some(Role::Admin));
    }
    for t in [acc.thing, acc.inbox, acc.profile] {
        assert!(e.sync_id_of(&t).unwrap().is_some(), "independent: a sync ID of its own");
    }
    assert!(e.closure_holds(&acc.thing));
    assert_eq!(e.role_on(&acc.thing), Some(Role::Admin));
    assert_eq!(e.inbox_thing(&acc.thing), Some(acc.inbox));
    let x = e.get_typed(&acc.inbox, &ct::RETENTION).unwrap().unwrap();
    for s in ct::INBOX_SIGNALS {
        assert!(x.rules.contains_key(&osis_base::Ak::new(s).unwrap()), "{s} enabled");
    }
    e.check_closure();
}

/// A thing peer 0 mints with its node thing, held from its own root alone, made independent.
fn independent_of_0(lp: &mut osis_engine::local_peer::LocalPeer) -> osis_base::Tid {
    let e = &mut lp.peers[0].engine;
    let me = e.me();
    let (t, _) = e.create_with_admin(&me).unwrap();
    e.make_independent(&t).unwrap();
    t
}

// spec/sync-set.md §2 First entry: peer 1 reads X only through G (peer 1 read on G, G read on
// X). Its root's strong to X alone enters nothing: no unit it syncs carries X, and no key part of
// an own or read thing holds a piece on X (G is held for no reading of peer 1's). Once its root
// strongs G too, G is entered (its node thing's piece) and read, and G's piece on X carries it.
#[test]
fn a_strong_enters_only_what_a_unit_piece_or_offer_carries_spec_sync_set_2() {
    let mut lp = crate::common::net(2, 0);
    let (g, x) = (independent_of_0(&mut lp), independent_of_0(&mut lp));
    let n1 = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&g, &n1, &crate::common::edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &g, &crate::common::edge(Role::Read)).unwrap();
    lp.hold_at(1, x);
    lp.sync_all().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(!e.closure_holds(&x), "a role through G and a strong: nothing carries X");
    assert_eq!(e.role_on(&x), None, "X's grants count only where X is carried");
    e.check_closure();
    lp.hold_at(1, g);
    lp.sync_all().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.closure_holds(&g), "G: the node thing's piece");
    assert!(e.closure_holds(&x), "X: G's piece, G read");
    e.check_closure();
}

// spec/sync-set.md §2 First entry: an edge piece carries its target while its edge is current or
// while a loss is not carried out yet. Peer 1 reads X by its own grant and holds sync on X through
// G (peer 1 read on G, G sync on X; G held for keys alone, no strong to it). Once its grant is
// removed and the loss carried out (read secrets dropped, sync kept), the removal's piece carries
// nothing and G's key part carries nothing: X leaves, though peer 1 keeps the sync secrets.
#[test]
fn a_removals_piece_carries_nothing_once_the_loss_is_carried_out_spec_sync_set_2() {
    let mut lp = crate::common::net(2, 0);
    let (g, x) = (independent_of_0(&mut lp), independent_of_0(&mut lp));
    let n1 = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&g, &n1, &crate::common::edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &g, &crate::common::edge(Role::Sync)).unwrap();
    lp.peers[0].engine.grant(&x, &n1, &crate::common::edge(Role::Read)).unwrap();
    lp.hold_at(1, x);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.closure_holds(&x), "X: its own grant's piece");
    crate::common::set_edge(&mut lp.peers[0].engine, x, n1, None, None);
    lp.sync_all().unwrap();
    lp.peers[1].engine.drop_lost_secrets().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(!e.closure_holds(&x), "the removal's piece carries nothing once the loss is carried out");
    e.check_closure();
}

// spec/sync-set.md §2 First entry: entry is founded. Peer 1 reads Y through G (held for keys
// alone, no strong to it) and holds Y by its root's strong, carried first by U's piece (U read).
// Y's unit strongs H (Y read on H), and H holds an edge on Y: H is read only through Y's unit, so
// once U's edge goes, H's piece would carry Y only by Y itself: the loss is carried out, and
// neither is held then.
#[test]
fn a_read_things_piece_carries_nothing_it_is_read_only_through_spec_sync_set_2() {
    use crate::common::edge;
    let mut lp = crate::common::net(2, 0);
    let [u, y, h, g] = [(); 4].map(|_| independent_of_0(&mut lp));
    let n1 = lp.peers[1].engine.me();
    let e0 = &mut lp.peers[0].engine;
    for (t, holder) in [(u, n1), (g, n1), (y, g), (y, u), (h, y), (y, h)] {
        e0.grant(&t, &holder, &edge(Role::Read)).unwrap();
    }
    let mut m = osis_engine::Mutation::new();
    m.op(y, &osis_schema::core_types::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(h)) }).unwrap();
    e0.commit(m).unwrap();
    lp.hold_at(1, u);
    lp.hold_at(1, y);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.closure_holds(&y) && lp.peers[1].engine.closure_holds(&h), "Y by U's piece, H in Y's unit");
    crate::common::set_edge(&mut lp.peers[0].engine, y, u, None, None);
    lp.sync_all().unwrap();
    lp.peers[1].engine.drop_lost_secrets().unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.role_on(&y), None, "Y's grants count nowhere Y is carried");
    assert!(!e.closure_holds(&y) && !e.closure_holds(&h), "H's piece carries Y only through Y");
    e.check_closure();
}

// spec/sync-set.md §1, spec/permissions.md §8 Making: a node's settings are its node thing's
// entries on the thing its root's `settings^.0` names, A from its making. A sibling holding admin
// on A writes the node's caps entry there and the node applies it; one holding write on A cannot
// (`caps^.0` is admin-only: its commit, sent past its own rules, is invalid at the node); and no
// sibling signs as the node: only a key holding a grant on the node thing does.
#[test]
fn a_sibling_writes_a_nodes_settings_and_cannot_sign_as_it_spec_sync_set_1() {
    use crate::common::edge;
    use osis_schema::Codec;
    let mut lp = crate::common::net(3, 0);
    let (acc, _) = lp.peers[0].engine.make_account().unwrap();
    let a = acc.thing;
    let [n0, n1, n2] = [0, 1, 2].map(|i| lp.peers[i].engine.me());
    lp.peers[0].engine.grant(&a, &n1, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&a, &n2, &edge(Role::Write)).unwrap();
    lp.hold_at(1, a);
    lp.hold_at(2, a);
    lp.sync_all().unwrap();
    let entry = |n: osis_base::Tid, entries: u64| {
        let caps = ct::Caps { policy: [("entries".to_string(), entries)].into(), things: Default::default() };
        let mut m = osis_engine::Mutation::new();
        let path = vec![osis_crdt::PathSeg::Key(osis_base::Weak(n).to_value())];
        m.op(a, &ct::CAPS, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(caps.to_value()) }).unwrap();
        m
    };
    let entries = |lp: &mut osis_engine::local_peer::LocalPeer| lp.peers[0].engine.caps().unwrap().policy.get("entries").copied();
    assert_eq!(entries(&mut lp), None, "no entry: the defaults");
    lp.peers[1].commit(entry(n0, 7)).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(entries(&mut lp), Some(7), "an admin sibling's entry for node 0 applies there");
    let c = lp.peers[2].engine.commit_hostile(entry(n0, 1)).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[0].engine.header(&c).is_some(), "held at node 0");
    assert_eq!(entries(&mut lp), Some(7), "a writer of A sets no node's settings");
    let mut m = entry(n0, 2);
    m.sign_as(n0);
    assert!(lp.peers[1].commit(m).is_err(), "no key of node 1's holds a grant on node 0's thing");
    lp.peers[0].engine.check_closure();
}

// spec/sync-set.md §2 Stub, spec/sync-judgement.md §1 Certificate blobs: G's sync unit strongs X,
// which G holds sync on and whose keys G's do not open: G's sync ID carries X's stub, its
// role-class parts as copies, and none of X's content: a grant on X to another holder Z among
// them, which no rule naming G carries. Granted nothing on X, G carries none of it.
#[test]
fn a_units_stub_is_carried_as_certificate_copies_spec_sync_set_2() {
    use crate::common::edge;
    let mut lp = crate::common::net(1, 0);
    let [g, x, z] = [(); 3].map(|_| independent_of_0(&mut lp));
    let e = &mut lp.peers[0].engine;
    let mut m = osis_engine::Mutation::new();
    m.set(x, &crate::common::REG, &crate::common::s("x")).unwrap();
    let content = e.commit(m).unwrap().unwrap();
    let mut m = osis_engine::Mutation::new();
    m.op(g, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(x)) }).unwrap();
    e.commit(m).unwrap();
    let on_x = |e: &mut osis_engine::Engine| -> Vec<(osis_base::CommitId, Vec<String>)> {
        let c = e.certificates(&g).unwrap();
        c.commits.iter().filter_map(|(id, parts)| {
            let h = e.header(id)?;
            let aks: Vec<String> = parts.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.tid == x).map(|a| a.ak.as_str().to_string()).collect();
            (!aks.is_empty()).then_some((*id, aks))
        }).collect()
    };
    let other = e.grant(&x, &z, &edge(Role::Read)).unwrap().commits;
    assert_eq!(on_x(e), vec![], "no role on X: no stub");
    e.grant(&x, &g, &edge(Role::Sync)).unwrap();
    let stub = on_x(e);
    assert!(other.iter().any(|c| stub.iter().any(|(s, aks)| s == c && aks.iter().any(|a| a == "roles.0"))), "Z's grant: {stub:?}");
    assert!(stub.iter().all(|(c, aks)| *c != content && aks.iter().all(|a| ct::ROLE_CLASS.contains(&a.as_str()))), "role-class parts alone: {stub:?}");
}
