#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Key grants (spec/permissions.md §1 Key grant, Key hop; §2 Key grants; spec/wire.md §4 field
//! 1): a key granted on a thing signs as it, the header naming the key in its second form, and
//! the walk rests what it signs on that grant as on any edge.

use crate::common::*;
use crate::flows::{edge_of, people, spread, thing_of};
use osis_base::{Role, SignKey, Tid};
use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;

fn key_of(lp: &LocalPeer, i: usize) -> SignKey {
    SignKey(lp.peers[i].engine.identity().signing().verifying_key().to_bytes())
}

fn reg(lp: &mut LocalPeer, i: usize, t: Tid) -> Option<osis_base::Value> {
    lp.peers[i].engine.get(&t, &ak("t:reg.0")).unwrap()
}

/// Peer 1 writes `v` on `t` signed as `t` by its own key, unsent.
fn write_as(lp: &mut LocalPeer, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.sign_as(t);
    m.set(t, &REG, &s(v)).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap()
}

/// Peer 0's thing T, with peer 1's node a reader (it holds T's secrets to write with) and peer
/// 1's key granted write on T: (peers, T, peer 1's key).
fn granted() -> (LocalPeer, Tid, SignKey) {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let k = key_of(&lp, 1);
    lp.peers[0].engine.grant_key(&t, &k, Some(&edge_of(Role::Write))).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    (lp, t, k)
}

// spec/permissions.md §1 Key hop, spec/wire.md §4 field 1: a commit signed as T by a key granted
// write on T names that key and holds its right by the grant alone (peer 1's node reads T only);
// the grant reads back as T's `signers.0` beside T's roster
#[test]
fn a_key_granted_on_a_thing_signs_as_it_spec_permissions_1() {
    let (mut lp, t, k) = granted();
    let c = write_as(&mut lp, t, "by key");
    let h = lp.peers[1].engine.header(&c).unwrap();
    assert_eq!((h.signer, h.key), (t, Some(k)), "signed as T, the key named");
    lp.advance(1000);
    spread(&mut lp);
    assert_eq!(reg(&mut lp, 0, t), Some(s("by key")), "valid at T's admin");
    let signers = lp.peers[0].engine.get(&t, &ak("signers.0")).unwrap().expect("T's key grants");
    let osis_base::Value::Map(m) = signers else { panic!("{signers:?}") };
    assert_eq!(m.keys().cloned().collect::<Vec<_>>(), vec![k.to_value()]);
}

// spec/permissions.md §2 Key grants, §5.1: removing a key's grant is the ordinary lowering, its
// frontier naming what its writer received; a commit the key signed as T that the removal did not
// list falls, one it listed stands
#[test]
fn a_keys_removed_grant_holds_up_only_what_its_remover_received_spec_permissions_2() {
    let (mut lp, t, k) = granted();
    write_as(&mut lp, t, "seen");
    lp.advance(1000);
    spread(&mut lp);
    // concurrent: peer 1 writes as T again, unseen, while peer 0 removes the key's grant
    let late = write_as(&mut lp, t, "unseen");
    lp.peers[0].engine.grant_key(&t, &k, None).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    for i in 0..2 {
        assert_eq!(reg(&mut lp, i, t), Some(s("seen")), "peer {i}: the unlisted write falls");
    }
    assert!(lp.peers[0].engine.header(&late).is_some(), "held at T's admin");
    // and with no grant left the key signs as T no more here
    let mut m = Mutation::new();
    m.sign_as(t);
    m.set(t, &REG, &s("after")).unwrap();
    assert!(lp.peers[1].commit(m).is_err(), "no key held with a grant on T");
}

// spec/permissions.md §1 Key hop: the key hop gives what its grant gives and no more
#[test]
fn a_key_granted_read_writes_nothing_spec_permissions_1() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let k = key_of(&lp, 1);
    lp.peers[0].engine.grant_key(&t, &k, Some(&edge_of(Role::Read))).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    // a read grant: the key signs as T, but what it writes there needs write (a writer past
    // its own rules sends it anyway)
    let mut m = Mutation::new();
    m.sign_as(t);
    m.set(t, &REG, &s("by a reader's key")).unwrap();
    let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1000);
    spread(&mut lp);
    assert!(lp.peers[0].engine.header(&c).is_some(), "held at T's admin");
    assert_eq!(reg(&mut lp, 0, t), Some(s("new")), "the key hop gives read only");
}

// spec/permissions.md §2 Key grants: a key's grant is written by T's admins alone; a reader of T
// may not grant a key on it
#[test]
fn only_an_admin_grants_a_key_spec_permissions_2() {
    let (mut lp, t, k) = granted();
    let other = SignKey([9; 32]);
    let e = lp.peers[1].engine.grant_key(&t, &other, Some(&edge_of(Role::Read)));
    assert!(matches!(e, Err(osis_engine::Error::Permission { .. })), "{e:?}");
    // a key's grant carries nothing a key cannot hold
    let e = lp.peers[0].engine.grant_key(&t, &k, Some(&osis_schema::core_types::Grant { floor: Some(1), ..edge_of(Role::Read) }));
    assert!(matches!(e, Err(osis_engine::Error::Misuse(_))), "{e:?}");
}

// spec/wire.md §4 field 1, spec/permissions.md §1: the key a part's right is judged by is the key
// its signature verified with. A copy of a key-signed commit naming another key granted on T (one
// holding admin there) carries a signature that key never made: refused whole
#[test]
fn a_header_naming_a_key_it_was_not_signed_by_is_refused_spec_wire_4() {
    let (mut lp, t, k) = granted();
    let admin_key = SignKey([7; 32]);
    lp.peers[0].engine.grant_key(&t, &admin_key, Some(&edge_of(Role::Admin))).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    let c = write_as(&mut lp, t, "by key");
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    assert_eq!(blob.header.key, Some(k));
    blob.header.key = Some(admin_key);
    let forged = osis_engine::local_peer::Package { id: blob.header.id(), bytes: blob.encode(), blobs: pk.blobs.clone() };
    assert!(lp.deliver(0, &forged).is_err(), "a signature not by the key named");
    assert!(lp.peers[0].engine.header(&forged.id).is_none());
    assert_eq!(reg(&mut lp, 0, t), Some(s("new")));
}

// spec/data-model.md §9 `signers.0`: a key grant carrying a `floor` (or `retain`, or `until` 0)
// is bad by itself; a reader applies none of it
#[test]
fn a_key_grant_holding_a_floor_grants_nothing_spec_data_model_9() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    lp.advance(1000);
    spread(&mut lp);
    let k = key_of(&lp, 1);
    let mut m = Mutation::new();
    let e = osis_schema::core_types::Grant { floor: Some(1), ..edge_of(Role::Write) };
    m.op(t, &osis_schema::core_types::SIGNERS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(k.to_value())], op: osis_crdt::Op::Put(osis_schema::Codec::to_value(&e)) }).unwrap();
    let c = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(lp.deliver(1, &pk).is_err(), "bad input");
    assert_eq!(lp.peers[1].engine.get(&t, &ak("signers.0")).unwrap(), None);
    let mut m = Mutation::new();
    m.sign_as(t);
    m.set(t, &REG, &s("by key")).unwrap();
    assert!(lp.peers[1].commit(m).is_err(), "no grant");
}

// spec/permissions.md §4 Evidence of a commit: a commit signed by a granted key states its key
// hop first; the grant writes on it (the `signers.0` write granting the key) are evidence of the
// commit wherever it is held, here a sync ID whose unit is D alone (D minted with T as admin, written
// as T by the key, so T's grant to the key is outside the unit)
#[test]
fn a_key_hops_grant_is_evidence_of_what_the_key_signs_spec_permissions_4() {
    use osis_engine::evidence::Reason;
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    let d = thing_of(&mut lp, 0, t);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let k = key_of(&lp, 1);
    let grant = lp.peers[0].engine.grant_key(&t, &k, Some(&edge_of(Role::Write))).unwrap().commits[0];
    lp.advance(1000);
    spread(&mut lp);
    let mut m = Mutation::new();
    m.sign_as(t);
    m.set(d, &REG, &s("on D by key")).unwrap();
    let w = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1000);
    spread(&mut lp);
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("on D by key")));
    let e = &mut lp.peers[0].engine;
    let copies = e.evidence_copies().unwrap();
    assert_eq!(copies[&(w, d)][0].hops.as_ref().and_then(|h| h.first().copied()), Some((osis_base::Holder::Key(k), t)), "the key hop first");
    let ev = osis_engine::evidence::held::derive(&copies, &[(d, vec![d])]);
    assert_eq!(ev.required(&d).unwrap().get(&(grant, t)), Some(&Reason::Edge((osis_base::Holder::Key(k), t))), "the key's grant");
}
