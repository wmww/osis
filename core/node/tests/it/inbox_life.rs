#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! An inbox blob's life (spec/sync.md §3): the grantee's certificate copy, re-sending after
//! `INBOX_LIFETIME`; direct packages kept until the app takes them.

use crate::net;
use net::*;
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{LabelId, Role, Tid};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

/// Alice (node `a`) and Bob (node `b`) as persons on one server; Alice holds Bob's card and a
/// group `g` with a label. Returns (net, sv, a, b, Alice's person, Bob's person, g, Bob's home).
fn alice_and_bob() -> (Net, usize, usize, usize, Tid, Tid, Tid, LabelId) {
    alice_and_bob_at(Vec::new())
}

/// `alice_and_bob` with `extra` addresses in g's label server list.
fn alice_and_bob_at(extra: Vec<osis_label::Address>) -> (Net, usize, usize, usize, Tid, Tid, Tid, LabelId) {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let addr = net.address(sv);
    let (alice, done) = net.engine(a).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_person(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.person);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let mut at = vec![addr];
    at.extend(extra);
    let (_, done) = net.engine(a).create_label(&g, &at).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob.person).unwrap().1.id;
    (net, sv, a, b, alice.person, bob.person, g, home)
}

fn grant(net: &mut Net, a: usize, g: Tid, to: Tid) {
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &to, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
}

/// Inbox entries a node knows present at the server under `l`.
fn inbox_at(net: &mut Net, n: usize, sv: usize, l: &LabelId) -> usize {
    let ids = net.server_ids(sv, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| matches!(k, EntryKind::Inbox(_)) && ids.contains(id)).count()
}

// spec/sync.md §3: the grantee's device places a certificate copy of the grant under its home
// label (the inbox), with the `/label` and `/created` commits of the group it names.
#[test]
fn grantee_copy_placed_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")));
    let ids = net.server_ids(sv, &home);
    let copies: Vec<(osis_base::BlobId, EntryKind)> = net.sync(b).entries(&home).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Commit { .. })).collect();
    let grant: Vec<osis_base::CommitId> = net.engine(b).commit_ids().into_iter().filter(|c| net.engine(b).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == g && x.ak.as_str() == "/members"))).collect();
    assert!(copies.iter().any(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if grant.contains(commit))), "the grant's copy is under Bob's home label");
    let label = copies.iter().any(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if net.engine(b).header(commit).is_some_and(|h| h.aspects.iter().any(|x| x.tid == g && x.ak.as_str() == "/label"))));
    assert!(label, "the group's /label commit is copied too");
    assert_eq!(inbox_at(&mut net, b, sv, &home), 1, "the inbox blob stays until it expires");
}

// spec/sync.md §3: an inbox blob nobody acts on expires at the server after `INBOX_LIFETIME`;
// the sender seals the commit again and re-sends it, and the member, back online, reads.
#[test]
fn unanswered_inbox_blob_resent_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    net.run();
    let first = net.server_ids(sv, &home);
    net.advance(INBOX_LIFETIME_MS + 1_000);
    let now = net.server_ids(sv, &home);
    assert!(now.iter().any(|x| !first.contains(x)), "a fresh inbox blob went up");
    assert!(first.iter().any(|x| !now.contains(x)), "the first one expired");
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
    assert_eq!(net.read(b, t), Some(s("for bob")));
}

// spec/permissions.md §1 (pairing), spec/sync.md §2: the commits for a node over a direct
// connection stay until the app takes them, across a restart.
#[test]
fn direct_packages_survive_restart_spec_sync_2() {
    let (mut net, _, a, _, alice, _, _, _) = alice_and_bob();
    let c = net.node(3, &[]);
    net.pair(c, a);
    let ct_ = net.tid(c);
    let done = net.engine(a).pair(&alice, &ct_).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.restart(a, 11);
    let pks = net.sync(a).take_direct_for(&ct_);
    assert!(!pks.is_empty(), "kept across the restart");
    assert!(net.sync(a).take_direct_for(&ct_).is_empty(), "taken once");
}

/// Entries present at the server under `l`, as node `n` knows them, of commits touching
/// `(t, ak)`.
fn under(net: &mut Net, n: usize, sv: usize, l: &LabelId, t: Tid, ak: &str) -> usize {
    let ids = net.server_ids(sv, l);
    let mut k = 0;
    for (id, e) in net.sync(n).entries(l) {
        let EntryKind::Commit { commit, .. } = e else { continue };
        if ids.contains(&id) && net.engine(n).header(&commit).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == ak)) {
            k += 1;
        }
    }
    k
}

// spec/sync.md §3 (the grantee's copy goes under the actor's HOME label): an actor whose inbox
// is another group's label gets no copy there (that group's readers would see its edges,
// labels and box keys).
#[test]
fn inbox_at_another_group_gets_no_copy_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, _) = alice_and_bob();
    let addr = net.address(sv);
    let e = net.engine(b);
    let mut m = Mutation::new();
    let h = e.new_thing(&mut m, bob);
    m.set(h, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    // a plain group of Bob's person: its label's deposit key derives from Bob's deposit seed
    let (hl, acts) = net.sync(b).create_label(&h, vec![addr.clone()]).unwrap();
    net.actions(b, acts);
    let mut m = Mutation::new();
    let inbox = ct::Inbox { label: hl, servers: vec![addr] };
    m.op(bob, &ct::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(4)], op: osis_crdt::Op::Replace(osis_schema::Codec::to_value(&Some(inbox))) }).unwrap();
    net.engine(b).commit(m).unwrap();
    net.run();
    net.pair(b, a);
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read), "the grant arrived through H's label");
    assert!(net.sync(b).entries(&hl).iter().any(|(_, k)| matches!(k, EntryKind::Inbox(Some(_)))));
    assert_eq!(under(&mut net, b, sv, &hl, g, "/members"), 0, "no copy of the grant under another group's label");
}

// spec/sync.md §3: an inbox payload's things are the sender's word; a copy carries the
// `/label` and `/created` only of things its commit touches, never of another thing this
// device holds that a hostile sender names.
#[test]
fn inbox_copy_names_only_touched_things_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")));
    // a private thing of Bob's
    let e = net.engine(b);
    let mut m = Mutation::new();
    let p = e.new_thing(&mut m, bob);
    e.commit(m).unwrap();
    net.run();
    // Alice pairs her item commit with `things = [p]`, sealed to Bob, deposited in his inbox
    let c = net.engine(a).commit_ids().into_iter().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "/created"))).unwrap();
    let bytes = net.engine(a).commit_bytes(&c).unwrap().unwrap();
    let commit = osis_base::decode(&bytes, &osis_base::Limits { max_depth: 64, max_bytes: bytes.len() }).unwrap();
    let keys = net.engine(a).get_typed(&bob, &ct::KEYS).unwrap().unwrap();
    let ct::KemKey::X25519MlKem768(kb) = &keys.read.unwrap().kem_key;
    let kem = osis_crypto::KemPublicKey::from_slice(kb).unwrap();
    let payload = osis_label::InboxPayload { commit, things: vec![osis_label::InboxThing { tid: p, label: home, index: 0, servers: vec![net.address(sv)], delete_keys: None }] };
    let now = osis_base::WallMs(net.now());
    let blob = osis_label::seal_inbox_blob(&bob, &kem, &payload, now, &mut osis_crypto::SeededRng::from_u64(5)).unwrap();
    let id = osis_label::blob_id(&blob);
    net.set_online(b, false);
    let put = osis_proto::Put { blob_id: id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: Some(now.0 + osis_base::format::INBOX_LIFETIME_MS), ephemeral: false, presence: false, tie: 0, replaces: &[], now: 0 };
    osis_proto::LabelStore::put(net.servers[sv].hub.store_mut(), &home, put).unwrap();
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).entries(&home).iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(Some(_)))), "Bob opened it");
    assert_eq!(under(&mut net, b, sv, &home, p, "/created"), 0, "the named private thing's /created is not copied");
}

// spec/sync.md §3 (re-send if the recipient has not acted), spec/permissions.md §3: a grant
// is not re-sent to a member removed since: after the lifetime only the removal notice goes
// again, never the grant with the target's current label.
#[test]
fn removed_member_gets_no_resent_grant_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.run();
    let done = net.engine(a).demote(&g, &osis_node::flows::Demotion { member: bob, new: None, presync: osis_node::flows::PreSync::Synced }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let first = net.server_ids(sv, &home);
    net.advance(INBOX_LIFETIME_MS + 1_000);
    let now = net.server_ids(sv, &home);
    let fresh = now.iter().filter(|x| !first.contains(x)).count();
    assert_eq!(fresh, 1, "only the removal notice is sent again");
}

// spec/sync.md §3 (an inbox blob's label hints are the sender's word), spec/permissions.md §9
// (only a followed link names a node to dial): a `peer://` address in a granted label's server
// list is never dialed by the grantee, neither from the inbox hint nor from the `/label`.
#[test]
fn inbox_hint_never_dials_peer_spec_sync_3() {
    let node = osis_label::Address { url: "peer://".into(), key: [0x99; 32] };
    let (mut net, _, a, b, _, bob, g, _) = alice_and_bob_at(vec![node.clone()]);
    let t = net.item(a, g, g, "for bob");
    grant(&mut net, a, g, bob);
    net.run();
    net.advance(61_000);
    assert_eq!(net.read(b, t), Some(s("for bob")), "the grant went through");
    assert!(!net.dialed.iter().any(|(n, x)| *n == b && x.key == node.key), "{:?}", net.dialed);
}

/// Seals commit `c` (held by node `from`) with `things` to `to` and puts it under `l` at server
/// `sv` with prefix expiry `expiry`, as a stranger holding the deposit seed could. Returns the
/// blob's ID.
fn plant_inbox(net: &mut Net, from: usize, (sv, l): (usize, &LabelId), to: Tid, c: &osis_base::CommitId, things: Vec<osis_label::InboxThing>, expiry: u64) -> osis_base::BlobId {
    let bytes = net.engine(from).commit_bytes(c).unwrap().unwrap();
    let commit = osis_base::decode(&bytes, &osis_base::Limits { max_depth: 64, max_bytes: bytes.len() }).unwrap();
    let keys = net.engine(from).get_typed(&to, &ct::KEYS).unwrap().unwrap();
    let ct::KemKey::X25519MlKem768(kb) = &keys.read.unwrap().kem_key;
    let kem = osis_crypto::KemPublicKey::from_slice(kb).unwrap();
    let payload = osis_label::InboxPayload { commit, things };
    // the prefix carries `now + INBOX_LIFETIME`: seal "earlier" for a shorter expiry
    let blob = osis_label::seal_inbox_blob(&to, &kem, &payload, osis_base::WallMs(expiry - INBOX_LIFETIME_MS), &mut osis_crypto::SeededRng::from_u64(9)).unwrap();
    let id = osis_label::blob_id(&blob);
    let put = osis_proto::Put { blob_id: id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: Some(expiry), ephemeral: false, presence: false, tie: 0, replaces: &[], now: 0 };
    osis_proto::LabelStore::put(net.servers[sv].hub.store_mut(), l, put).unwrap();
    id
}

// spec/sync.md §3, spec/requirements.md (read access never stores arbitrary content): a valid
// commit an inbox blob carries that is no membership commit about the actor is applied but
// never copied under its home label; nor are its things' labels followed (no box to the actor):
// their servers are never dialed.
#[test]
fn stranger_inbox_commit_not_copied_nor_dialed_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let t = net.item(a, g, g, "big content");
    net.run();
    let c = net.engine(a).commit_ids().into_iter().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "/created"))).unwrap();
    let rogue = osis_label::Address { url: "quic://rogue".into(), key: [0x77; 32] };
    let things = vec![osis_label::InboxThing { tid: t, label: LabelId([0x55; 16]), index: 0, servers: vec![rogue.clone()], delete_keys: None }];
    let exp = net.now() + INBOX_LIFETIME_MS;
    net.set_online(b, false);
    let id = plant_inbox(&mut net, a, (sv, &home), bob, &c, things, exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).entries(&home).iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(Some(_)))), "Bob opened it");
    assert!(net.engine(b).commit_ids().contains(&c), "the commit applied");
    let copied = net.sync(b).entries(&home).into_iter().any(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if commit == c));
    assert!(!copied, "no copy of a commit not about Bob");
    assert_eq!(under(&mut net, b, sv, &home, t, "/created"), 0);
    assert!(!net.dialed.iter().any(|(_, x)| x.key == rogue.key), "an unvetted hint is never dialed");
}

/// Alice's grant on `g` to `bob` (node `b` offline), its inbox blob deleted at the server;
/// returns the grant commit and the inbox thing a genuine delivery names.
fn grant_undelivered(net: &mut Net, a: usize, b: usize, sv: usize, home: &LabelId, g: Tid, bob: Tid) -> (osis_base::CommitId, osis_label::InboxThing) {
    use osis_node::flows::Delivery;
    net.set_online(b, false);
    let before = net.server_ids(sv, home);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
    let done = net.engine(a).grant(&g, &bob, &edge).unwrap();
    let c = done.deliveries.iter().find_map(|d| if let Delivery::Inbox { resend, .. } = d { Some(resend.commit) } else { None }).expect("an inbox delivery");
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let fresh: Vec<osis_base::BlobId> = net.server_ids(sv, home).into_iter().filter(|x| !before.contains(x)).collect();
    assert_eq!(fresh.len(), 1, "the genuine inbox blob");
    let now = net.now();
    osis_proto::LabelStore::delete(net.servers[sv].hub.store_mut(), home, &fresh[0], now).unwrap();
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    (c, osis_label::InboxThing { tid: g, label: gl.id, index: gl.index, servers: gl.servers.clone(), delete_keys: None })
}

// spec/sync.md §3: an inbox blob whose expiry is far below `INBOX_LIFETIME` gets no copy (its
// sender would get the deposit budget back for the next one); the grant it carries still
// applies, its label followed by the vetted hint (the grant boxes Bob on g).
#[test]
fn short_lived_inbox_blob_not_copied_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    let t = net.item(a, g, g, "for bob");
    let (c, thing) = grant_undelivered(&mut net, a, b, sv, &home, g, bob);
    let exp = net.now() + 10 * 60_000;
    plant_inbox(&mut net, a, (sv, &home), bob, &c, vec![thing], exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")), "the grant applied, g's label reached by its hint");
    assert_eq!(under(&mut net, b, sv, &home, g, "/members"), 0, "no copy from a short-lived blob");
}

// spec/sync.md §3: a vetted inbox hint (the grant boxes Bob on g) goes with its blob: once the
// blob expired, the server it named is dialed no more, though its label never opened.
#[test]
fn inbox_hint_goes_with_its_blob_spec_sync_3() {
    let (mut net, sv, a, b, _, bob, g, home) = alice_and_bob();
    let (c, mut thing) = grant_undelivered(&mut net, a, b, sv, &home, g, bob);
    let rogue = osis_label::Address { url: "quic://rogue".into(), key: [0x77; 32] };
    thing.label = LabelId([0x55; 16]);
    thing.servers = vec![rogue.clone()];
    let ttl = 10 * 60_000;
    let exp = net.now() + ttl;
    plant_inbox(&mut net, a, (sv, &home), bob, &c, vec![thing], exp);
    net.set_online(b, true);
    net.advance(60_000);
    assert!(net.dialed.iter().any(|(n, x)| *n == b && x.key == rogue.key), "the vetted hint is followed while the blob lives");
    net.advance(ttl);
    net.advance(60_000);
    let n = net.dialed.len();
    for _ in 0..6 {
        net.advance(30 * 60_000);
    }
    assert!(!net.dialed[n..].iter().any(|(n, x)| *n == b && x.key == rogue.key), "dialed no more after the blob expired");
}
