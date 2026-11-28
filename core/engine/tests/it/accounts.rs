//! Minting an account (spec/permissions.md §8): A minted with the node thing as mint admin and
//! independent at once, its inbox and profile minted with admin A, the node entering all three.

use crate::common::T0;
use osis_base::Role;
use osis_engine::local_peer::Peer;
use osis_schema::core_types as ct;

// spec/permissions.md §8 Minting, spec/sync-inbox.md §1: A is minted with the node thing as mint
// admin, independent; its inbox and profile are minted with admin A, independent, held by strongs
// from A; A's `keys.0` names the inbox, whose setting takes both inbox signals, and A's card is on
// the profile; the node holds A
// (a strong from its root) and reads all three, the inbox and profile in A's sync unit, with
// admin on each by A's record edge.
#[test]
fn minting_an_account_spec_permissions_8() {
    let mut p = Peer::new(1, T0).unwrap();
    let (acc, _) = osis_engine::local_peer::make_account(&mut p.engine).unwrap();
    let e = &mut p.engine;
    let me = e.tid();
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
    assert_eq!(e.inbox_of(&acc.thing).unwrap(), Some(acc.inbox));
    let x = e.get_typed(&acc.inbox, &ct::RETENTION).unwrap().unwrap();
    for s in ct::INBOX_SIGNALS {
        assert!(x.rules.contains_key(&osis_base::Ak::new(s).unwrap()), "{s} enabled");
    }
    e.check_closure();
}

/// A thing peer 0 mints with its node thing, held from its own root alone, made independent.
fn independent_of_0(lp: &mut osis_engine::local_peer::LocalPeer) -> osis_base::Tid {
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let (t, _) = e.create_with_admin(&me).unwrap();
    e.make_independent(&t).unwrap();
    t
}

// spec/sync-set.md §1, spec/permissions.md §8 Minting: a node's settings are its node thing's
// entries on the thing its root's `settings^.0` names, A from its minting. A sibling holding admin
// on A writes the node's caps entry there and the node applies it; one holding write on A cannot
// (`caps^.0` is admin-only: its commit, sent past its own rules, is invalid at the node); and no
// sibling signs as the node: only a key holding a grant on the node thing does.
#[test]
fn a_sibling_writes_a_nodes_settings_and_cannot_sign_as_it_spec_sync_set_1() {
    use crate::common::edge;
    use osis_schema::Codec;
    let mut lp = crate::common::net(3, 0);
    let (acc, _) = osis_engine::local_peer::make_account(&mut lp.peers[0].engine).unwrap();
    let a = acc.thing;
    let [n0, n1, n2] = [0, 1, 2].map(|i| lp.peers[i].engine.tid());
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

// spec/sync-set.md §2 Stub, spec/permissions.md §4 Stub, Copies, spec/wire.md §4 Sync-only cut:
// G's sync unit strongs X, which G holds only sync on and whose keys G's do not open: G's sync ID
// carries X's stub as its sync-only cut (X's sync ID alone: no certificate copy of any part on
// X), none of X's content, nor anything of a grant on X to another holder Z. Granted nothing on
// X, G carries none of it. Fails with G's grant travelling as a certificate copy.
#[test]
fn a_units_stub_is_carried_as_its_sync_only_cut_spec_sync_set_2() {
    use crate::common::edge;
    use std::collections::BTreeSet;
    let mut lp = crate::common::net(1, 0);
    let [g, x, z] = [(); 3].map(|_| independent_of_0(&mut lp));
    let e = &mut lp.peers[0].engine;
    let mut m = osis_engine::Mutation::new();
    m.set(x, &crate::common::REG, &crate::common::s("x")).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut m = osis_engine::Mutation::new();
    m.op(g, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(x)) }).unwrap();
    e.commit(m).unwrap();
    // (the aspects on X of certificate copies, whether X's sync-only cut goes)
    let on_x = |e: &mut osis_engine::Engine| {
        let c = e.certificates(&g).unwrap();
        let aks: BTreeSet<String> = c.commits.iter().filter_map(|(id, parts)| Some((e.header(id)?, parts))).flat_map(|(h, parts)| parts.iter().filter_map(|ai| h.aspects.get(*ai)).filter(|a| a.tid == x).map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>()).collect();
        (aks, c.sync_cuts.contains_key(&x))
    };
    e.grant(&x, &z, &edge(Role::Read)).unwrap();
    assert_eq!(on_x(e), (BTreeSet::new(), false), "no role on X: no stub");
    e.grant(&x, &g, &edge(Role::Sync)).unwrap();
    assert_eq!(on_x(e), (BTreeSet::new(), true), "X's sync-only cut, no header of a commit on X");
}
