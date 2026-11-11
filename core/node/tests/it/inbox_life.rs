#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! An inbox blob's life (spec/sync.md §3): the grantee's certificate copy, re-sending after
//! `INBOX_LIFETIME`; direct packages kept until the app takes them.

use crate::net::hosted_nodes;
use crate::net;
use net::*;
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{LabelId, Role, Tid};
use osis_node::Mutation;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

/// Alice (node `a`) and Bob (node `b`) as accounts at one peer; Alice holds Bob's card and a
/// group `g` with a label. Returns (net, host, a, b, Alice's account, Bob's account, g, Bob's home).
fn alice_and_bob() -> (Net, usize, usize, usize, Tid, Tid, Tid, LabelId) {
    alice_and_bob_at(Vec::new())
}

/// `alice_and_bob` with `extra` addresses in g's label host list.
fn alice_and_bob_at(extra: Vec<osis_label::Address>) -> (Net, usize, usize, usize, Tid, Tid, Tid, LabelId) {
    let (net, (host, a, b, alice, bob, g, home)) = Net::cached(&format!("inbox_life::alice_and_bob_at/{extra:?}"), || {
        let (mut net, host, [a, b]) = hosted_nodes::<2>();
        let (a, b, alice, bob, g, home) = alice_and_bob_on(&mut net, host, a, b, extra);
        (net, (host, a, b, alice, bob, g, home))
    });
    (net, host, a, b, alice, bob, g, home)
}

/// `alice_and_bob_at` on nodes and a host already made: (a, b, Alice's account, Bob's account, g, home).
fn alice_and_bob_on(net: &mut Net, host: usize, a: usize, b: usize, extra: Vec<osis_label::Address>) -> (usize, usize, Tid, Tid, Tid, LabelId) {
    let addr = net.address(host);
    let (alice, done) = net.engine(a).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (bob, done) = net.engine(b).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g = e.new_thing(&mut m, alice.account);
    m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let mut at = vec![addr];
    at.extend(extra);
    let (_, done) = net.engine(a).create_label(&g, &at).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == bob.devices).unwrap().1.id;
    (a, b, alice.account, bob.account, g, home)
}

fn grant(net: &mut Net, a: usize, g: Tid, to: Tid) {
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &to, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
}

/// Inbox entries a node knows present at the host under `l`.
fn inbox_at(net: &mut Net, n: usize, host: usize, l: &LabelId) -> usize {
    let ids = net.host_ids(host, l);
    net.sync(n).entries(l).into_iter().filter(|(id, k)| matches!(k, EntryKind::Inbox(_)) && ids.contains(id)).count()
}

// spec/sync.md §3: the grantee's node places a certificate copy of the grant under its home
// label (the inbox), with the `label.0` and `created.0` commits of the group it names.
#[test]
fn grantee_copy_placed_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")));
    let ids = net.host_ids(host, &home);
    let copies: Vec<(osis_base::BlobId, EntryKind)> = net.sync(b).entries(&home).into_iter().filter(|(id, k)| ids.contains(id) && matches!(k, osis_node::sync::EntryKind::Commit { .. })).collect();
    let grant: Vec<osis_base::CommitId> = net.engine(b).commit_ids().into_iter().filter(|c| net.engine(b).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == g && x.ak.as_str() == "roles.0"))).collect();
    assert!(copies.iter().any(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if grant.contains(commit))), "the grant's copy is under Bob's home label");
    let label = copies.iter().any(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if net.engine(b).header(commit).is_some_and(|h| h.aspects.iter().any(|x| x.tid == g && x.ak.as_str() == "label.0"))));
    assert!(label, "the group's label.0 commit is copied too");
    assert_eq!(inbox_at(&mut net, b, host, &home), 1, "the inbox blob stays until it expires");
}

// spec/sync.md §3: an inbox blob nobody acts on expires at the host after `INBOX_LIFETIME`;
// the sender seals the commit again and re-sends it, and the holder, back online, reads.
#[test]
fn unanswered_inbox_blob_resent_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    net.run();
    let first = net.host_ids(host, &home);
    net.advance(INBOX_LIFETIME_MS + 1_000);
    let now = net.host_ids(host, &home);
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
    let (mut net, _, a, _, _alice, _, _, _) = alice_and_bob();
    let c = net.joining_node(3, &[]);
    net.pair(c, a);
    let ct_ = net.node_tid(c);
    let done = net.engine(a).pair(&ct_).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.restart(a, 11);
    let pks = net.sync(a).take_direct_for(&ct_);
    assert!(!pks.is_empty(), "kept across the restart");
    assert!(net.sync(a).take_direct_for(&ct_).is_empty(), "taken once");
}

/// Entries present at the host under `l`, as node `n` knows them, of commits touching
/// `(t, ak)`.
fn under(net: &mut Net, n: usize, host: usize, l: &LabelId, t: Tid, ak: &str) -> usize {
    let ids = net.host_ids(host, l);
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
    let (mut net, host, a, b, _, bob, g, _) = alice_and_bob();
    let addr = net.address(host);
    let e = net.engine(b);
    let mut m = Mutation::new();
    let h = e.new_thing(&mut m, bob);
    m.set(h, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    // a plain group of Bob's account: its label's deposit key derives from Bob's deposit seed
    let (hl, acts) = net.sync(b).create_label(&h, vec![addr.clone()]).unwrap();
    net.actions(b, acts);
    let mut m = Mutation::new();
    let inbox = ct::Inbox { label: hl, hosts: vec![addr] };
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
    assert_eq!(under(&mut net, b, host, &hl, g, "roles.0"), 0, "no copy of the grant under another group's label");
}

// spec/sync.md §3: an inbox payload's things are the sender's word; a copy carries the
// `label.0` and `created.0` only of things its commit touches, never of another thing this
// node holds that a hostile sender names.
#[test]
fn inbox_copy_names_only_touched_things_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
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
    let c = net.engine(a).commit_ids().into_iter().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "created.0"))).unwrap();
    let bytes = net.engine(a).commit_bytes(&c).unwrap().unwrap();
    let commit = osis_base::decode(&bytes, &osis_base::Limits { max_depth: 64, max_bytes: bytes.len() }).unwrap();
    let keys = net.engine(a).get_typed(&bob, &ct::KEYS).unwrap().unwrap();
    let ct::KemKey::X25519MlKem768(kb) = &keys.key.or(keys.read.map(|k| k.kem_key)).unwrap();
    let kem = osis_crypto::KemPublicKey::from_slice(kb).unwrap();
    let payload = osis_label::InboxPayload { chain: Vec::new(), records: Vec::new(), commit, things: vec![osis_label::InboxThing { tid: p, label: Some(osis_label::InboxLabel { id: home, index: 0, hosts: vec![net.address(host)] }), delete_keys: None }] };
    let now = osis_base::WallMs(net.now());
    let blob = osis_label::seal_inbox_blob(&bob, &kem, &payload, now, &mut osis_crypto::SeededRng::from_u64(5)).unwrap();
    let id = osis_label::blob_id(&blob);
    net.set_online(b, false);
    let put = osis_proto::Put { blob_id: id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: Some(now.0 + osis_base::format::INBOX_LIFETIME_MS), ephemeral: false, replaces: &[], now: 0 };
    osis_proto::LabelStore::put(&mut *net.hosts[host].hub.store(), &home, put).unwrap();
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).entries(&home).iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(Some(_)))), "Bob opened it");
    assert_eq!(under(&mut net, b, host, &home, p, "created.0"), 0, "the named private thing's created.0 is not copied");
}

// spec/sync.md §3 (re-send if the recipient has not acted), spec/permissions.md §3: a grant
// is not re-sent to a holder removed since: after the lifetime only the removal notice goes
// again, never the grant with the target's current label.
#[test]
fn removed_holder_gets_no_resent_grant_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.run();
    let done = net.engine(a).demote(&g, &osis_node::flows::Demotion { holder: bob, new: None, retain: None }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let first = net.host_ids(host, &home);
    net.advance(INBOX_LIFETIME_MS + 1_000);
    let now = net.host_ids(host, &home);
    let fresh = now.iter().filter(|x| !first.contains(x)).count();
    assert_eq!(fresh, 1, "only the removal notice is sent again");
}

/// Seals commit `c` (held by node `from`) with `things` to `to` and puts it under `l` at host
/// `host` with prefix expiry `expiry`, as a stranger holding the deposit seed could. Returns the
/// blob's ID.
fn plant_inbox(net: &mut Net, from: usize, at: (usize, &LabelId), to: Tid, c: &osis_base::CommitId, things: Vec<osis_label::InboxThing>, expiry: u64) -> osis_base::BlobId {
    let bytes = net.engine(from).commit_bytes(c).unwrap().unwrap();
    plant_bytes(net, from, at, to, &bytes, things, expiry)
}

/// `plant_inbox` of a commit's encoded bytes.
fn plant_bytes(net: &mut Net, from: usize, (host, l): (usize, &LabelId), to: Tid, bytes: &[u8], things: Vec<osis_label::InboxThing>, expiry: u64) -> osis_base::BlobId {
    let commit = osis_base::decode(bytes, &osis_base::Limits { max_depth: 64, max_bytes: bytes.len() }).unwrap();
    let keys = net.engine(from).get_typed(&to, &ct::KEYS).unwrap().unwrap();
    let ct::KemKey::X25519MlKem768(kb) = &keys.key.or(keys.read.map(|k| k.kem_key)).unwrap();
    let kem = osis_crypto::KemPublicKey::from_slice(kb).unwrap();
    let payload = osis_label::InboxPayload { commit, things, chain: Vec::new(), records: Vec::new() };
    // the prefix carries `now + INBOX_LIFETIME`: seal "earlier" for a shorter expiry
    let blob = osis_label::seal_inbox_blob(&to, &kem, &payload, osis_base::WallMs(expiry - INBOX_LIFETIME_MS), &mut osis_crypto::SeededRng::from_u64(9)).unwrap();
    let id = osis_label::blob_id(&blob);
    let put = osis_proto::Put { blob_id: id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: Some(expiry), ephemeral: false, replaces: &[], now: 0 };
    osis_proto::LabelStore::put(&mut *net.hosts[host].hub.store(), l, put).unwrap();
    id
}

// spec/sync.md §3, spec/requirements.md (read access never stores arbitrary content): a valid
// commit an inbox blob carries that is no role commit about the actor is applied but
// never copied under its home label; nor are its things' labels followed (no box to the actor):
// their hosts are never dialed.
#[test]
fn stranger_inbox_commit_not_copied_nor_dialed_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let t = net.item(a, g, g, "big content");
    net.run();
    let c = net.engine(a).commit_ids().into_iter().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "created.0"))).unwrap();
    let rogue = osis_label::Address { url: "quic://rogue".into(), key: [0x77; 32] };
    let things = vec![osis_label::InboxThing { tid: t, label: Some(osis_label::InboxLabel { id: LabelId([0x55; 16]), index: 0, hosts: vec![rogue.clone()] }), delete_keys: None }];
    let exp = net.now() + INBOX_LIFETIME_MS;
    net.set_online(b, false);
    let id = plant_inbox(&mut net, a, (host, &home), bob, &c, things, exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).entries(&home).iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(Some(_)))), "Bob opened it");
    assert!(net.engine(b).commit_ids().contains(&c), "the commit applied");
    let copied = net.sync(b).entries(&home).into_iter().any(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c));
    assert!(!copied, "no copy of a commit not about Bob");
    assert_eq!(under(&mut net, b, host, &home, t, "created.0"), 0);
    assert!(!net.dialed.iter().any(|(_, x)| x.key == rogue.key), "an unvetted hint is never dialed");
}

/// Alice's grant on `g` to `bob` (node `b` offline), its inbox blob deleted at the host;
/// returns the grant commit and the inbox thing a genuine delivery names.
fn grant_undelivered(net: &mut Net, a: usize, b: usize, host: usize, home: &LabelId, g: Tid, bob: Tid) -> (osis_base::CommitId, osis_label::InboxThing) {
    use osis_node::flows::Delivery;
    net.set_online(b, false);
    let before = net.host_ids(host, home);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &bob, &edge).unwrap();
    let c = done.deliveries.iter().find_map(|d| if let Delivery::Inbox { resend, .. } = d { Some(resend.commit) } else { None }).expect("an inbox delivery");
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let fresh: Vec<osis_base::BlobId> = net.host_ids(host, home).into_iter().filter(|x| !before.contains(x)).collect();
    assert_eq!(fresh.len(), 1, "the genuine inbox blob");
    let now = net.now();
    osis_proto::LabelStore::delete(&mut *net.hosts[host].hub.store(), home, &fresh[0], now).unwrap();
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    (c, osis_label::InboxThing { tid: g, label: Some(osis_label::InboxLabel { id: gl.id, index: gl.index, hosts: gl.hosts.clone() }), delete_keys: None })
}

// spec/sync.md §3: an inbox blob whose expiry is far below `INBOX_LIFETIME` gets no copy (its
// sender would get the deposit budget back for the next one); the grant it carries still
// applies, its label followed by the vetted hint (the grant boxes Bob on g).
#[test]
fn short_lived_inbox_blob_not_copied_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    let t = net.item(a, g, g, "for bob");
    let (c, thing) = grant_undelivered(&mut net, a, b, host, &home, g, bob);
    let exp = net.now() + 10 * 60_000;
    plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing], exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")), "the grant applied, g's label reached by its hint");
    assert_eq!(under(&mut net, b, host, &home, g, "roles.0"), 0, "no copy from a short-lived blob");
}

// spec/sync.md §3: a vetted inbox hint (the grant boxes Bob on g) goes with its blob: once the
// blob expired, the host it named is dialed no more, though its label never opened.
#[test]
fn inbox_hint_goes_with_its_blob_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    let (c, mut thing) = grant_undelivered(&mut net, a, b, host, &home, g, bob);
    let rogue = osis_label::Address { url: "quic://rogue".into(), key: [0x77; 32] };
    thing.label = Some(osis_label::InboxLabel { id: LabelId([0x55; 16]), index: 0, hosts: vec![rogue.clone()] });
    let ttl = 10 * 60_000;
    let exp = net.now() + ttl;
    plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing], exp);
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

/// The invite requests node `n` lists, by commit.
fn requests(net: &mut Net, n: usize) -> Vec<osis_base::CommitId> {
    net.sync(n).invite_requests().unwrap()
}

/// Whether node `n` holds commit `c`, applied or pending.
fn holds(net: &mut Net, n: usize, c: &osis_base::CommitId) -> bool {
    net.engine(n).commit_ids().contains(c) || net.engine(n).pending().iter().any(|(x, _)| x == c)
}

/// Alice's grant on `g` to `bob`; the grant commit.
fn grant_commit(net: &mut Net, a: usize, g: Tid, bob: Tid) -> osis_base::CommitId {
    use osis_node::flows::Delivery;
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &bob, &edge).unwrap();
    let c = done.deliveries.iter().find_map(|d| if let Delivery::Inbox { resend, .. } = d { Some(resend.commit) } else { None }).expect("an inbox delivery");
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    c
}

// spec/sync.md §3, §5: Bob knows nothing of Alice when her grant reaches him and the label's head has
// moved past the epoch boxed in it (Carol's removal): his account's claim key on the head opens the
// label, Alice's chain comes under it, and the grant applies. A commit released from an invite request
// that cannot be judged yet waits for what it needs like any other.
#[test]
fn grant_reaches_a_grantee_new_to_the_granter_past_a_rotation_spec_sync_5() {
    let (mut net, host, a, b, _, bob, g, _) = alice_and_bob_at(Vec::new());
    let c = net.node(3, &[host]);
    let addr = net.address(host);
    let (carol, done) = net.engine(c).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(c).carry_out(done).unwrap();
    net.actions(c, acts);
    net.run();
    net.pair(c, a);
    grant(&mut net, a, g, carol.account);
    net.run();
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.run();
    let d = osis_node::flows::Demotion { holder: carol.account, new: None, retain: None };
    let done = net.engine(a).demote(&g, &d).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert!(net.engine(b).roster(&g).contains_key(&bob), "the grant applied at Bob: pending {:?}", net.engine(b).pending());
    assert!(net.engine(b).role_on(&g).is_some(), "Bob holds g");
}

// spec/permissions.md §1, spec/crypto.md §2-§3: what Bob, outside Alice's account, holds after their
// exchange opens none of her account's secrets: her devices actor's seeds are not readable to him, and
// a commit of hers shows the account as author with the node sealed.
#[test]
fn an_outsider_reads_no_secret_of_the_account_spec_permissions_1() {
    let (mut net, _, a, b, alice, bob, g, _) = alice_and_bob_at(Vec::new());
    let devices = net.engine(a).account().unwrap().unwrap().1;
    grant(&mut net, a, g, bob);
    let t = net.item(a, g, g, "for bob");
    net.run();
    assert!(net.read(b, t).is_some(), "Bob reads the item");
    let e = net.engine(b);
    assert_eq!(e.get_typed(&devices, &ct::ACCOUNT).unwrap(), None, "D's seeds");
    assert!(e.account_kems(&alice).is_empty(), "the account's KEM secrets");
    assert!(e.epochs(&devices).is_none_or(|x| !x.read.holds_any()), "D's epochs");
    let id = e.commit_ids().into_iter().find(|c| e.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t))).unwrap();
    assert_eq!(e.header(&id).map(|h| h.author), Some(alice), "the account is the author");
}

// spec/sync.md §3 (invite requests): Bob shares nothing with Alice, so her invite is a request:
// its commit is not applied and g's hosts are never dialed until Bob accepts; accepting
// applies it, dials them and joins g.
#[test]
fn stranger_invite_waits_for_accept_spec_sync_3() {
    let rogue = osis_label::Address { url: "quic://g-only".into(), key: [0x78; 32] };
    let (mut net, _, a, b, _, bob, g, _) = alice_and_bob_at(vec![rogue.clone()]);
    net.nodes[b].accepts = false;
    let t = net.item(a, g, g, "for bob");
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(requests(&mut net, b), vec![c], "one request");
    assert!(!holds(&mut net, b, &c), "not applied before accept");
    assert!(!net.dialed.iter().any(|(n, x)| *n == b && x.key == rogue.key), "g's hosts not dialed before accept");
    assert_eq!(net.read(b, t), None);
    let (found, acts) = net.sync(b).accept_invite(c).unwrap();
    assert!(found);
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(requests(&mut net, b).is_empty(), "accepted: no request left");
    assert!(net.dialed.iter().any(|(n, x)| *n == b && x.key == rogue.key), "accepting dials g's hosts");
    assert_eq!(net.read(b, t), Some(s("for bob")), "and joins g");
}

// spec/wire.md §9: an inbox payload's chain gives only chain deltas and raw records: what else a commit in it carries (a box, a `label.0`, a group, a creation) is not applied
#[test]
fn an_inbox_chain_applies_only_chain_deltas_spec_wire_9() {
    let (mut net, host, a, b, alice, bob, g, home) = alice_and_bob();
    net.nodes[b].accepts = false;
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let (_, acts) = net.sync(b).accept_invite(c).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    net.set_online(b, false);
    let e = net.engine(a);
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, alice);
    m.set(x, &ct::GROUP, &ct::Group::default()).unwrap();
    let in_chain = e.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    let y = e.new_thing(&mut m, alice);
    m.set(y, &ct::GROUP, &ct::Group::default()).unwrap();
    let main = e.commit(m).unwrap().unwrap();
    let value = |net: &mut Net, c: &osis_base::CommitId| {
        let bytes = net.engine(a).commit_bytes(c).unwrap().unwrap();
        osis_base::decode(&bytes, &osis_base::Limits { max_depth: 64, max_bytes: bytes.len() }).unwrap()
    };
    let rec = net.engine(a).core.created(&x).cloned().unwrap();
    let payload = osis_label::InboxPayload { commit: value(&mut net, &main), things: Vec::new(), chain: vec![value(&mut net, &in_chain)], records: vec![rec] };
    let keys = net.engine(a).get_typed(&bob, &ct::KEYS).unwrap().unwrap();
    let ct::KemKey::X25519MlKem768(kb) = &keys.key.or(keys.read.map(|k| k.kem_key)).unwrap();
    let kem = osis_crypto::KemPublicKey::from_slice(kb).unwrap();
    let now = net.now();
    let blob = osis_label::seal_inbox_blob(&bob, &kem, &payload, osis_base::WallMs(now), &mut osis_crypto::SeededRng::from_u64(9)).unwrap();
    let put = osis_proto::Put { blob_id: osis_label::blob_id(&blob), blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry: Some(now + INBOX_LIFETIME_MS), ephemeral: false, replaces: &[], now: 0 };
    osis_proto::LabelStore::put(&mut *net.hosts[host].hub.store(), &home, put).unwrap();
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.engine(b).knows(&x), "its creation record, raw");
    assert!(!holds(&mut net, b, &in_chain), "a chain commit with no chain delta gives nothing");
    assert!(net.engine(b).get_typed(&x, &ct::GROUP).unwrap().is_none(), "and nothing but chain deltas");
}

// spec/sync.md §3: a declined request is forgotten: never listed again, its commit never
// applied, across a restart and the sender's re-send after `INBOX_LIFETIME`.
#[test]
fn declined_invite_forgotten_spec_sync_3() {
    let rogue = osis_label::Address { url: "quic://g-only".into(), key: [0x78; 32] };
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob_at(vec![rogue.clone()]);
    net.nodes[b].accepts = false;
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(requests(&mut net, b), vec![c]);
    assert!(net.sync(b).decline_invite(c).unwrap());
    assert!(!net.sync(b).decline_invite(c).unwrap(), "no request left to decline");
    assert!(!net.sync(b).accept_invite(c).unwrap().0, "nor to accept");
    net.restart(b, 2);
    net.nodes[b].accepts = false;
    let first = net.host_ids(host, &home);
    net.advance(INBOX_LIFETIME_MS + 1_000);
    assert!(net.host_ids(host, &home).iter().any(|x| !first.contains(x)), "Alice re-sent it");
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(requests(&mut net, b).is_empty(), "never listed again");
    assert!(!holds(&mut net, b, &c));
    assert!(!net.dialed.iter().any(|(n, x)| *n == b && x.key == rogue.key));
}

// spec/sync.md §3: once Bob shares g with Alice (he accepted), her next invite comes from a
// connected sender (her node is named on her account, g's first admin) and goes through directly.
#[test]
fn connected_sender_invite_goes_through_spec_sync_3() {
    let (mut net, _, a, b, alice, bob, g, _) = alice_and_bob();
    net.nodes[b].accepts = false;
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let (_, acts) = net.sync(b).accept_invite(c).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    // a second group of Alice's, with its own label
    let e = net.engine(a);
    let mut m = Mutation::new();
    let g2 = e.new_thing(&mut m, alice);
    m.set(g2, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let addr = net.address(0);
    let (_, done) = net.engine(a).create_label(&g2, &[addr]).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let t = net.item(a, g2, g2, "second");
    let c2 = grant_commit(&mut net, a, g2, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(requests(&mut net, b).is_empty(), "no request from a connected sender");
    assert!(holds(&mut net, b, &c2));
    assert_eq!(net.read(b, t), Some(s("second")), "joined directly");
}

/// Alice and Bob, Bob with a second node `b2` paired: (net, a, b, b2, bob, g), neither of
/// Bob's nodes accepting invites by itself.
fn bob_with_two_nodes() -> (Net, usize, usize, usize, Tid, Tid) {
    let (mut net, host, a, b, _, bob, g, _) = alice_and_bob();
    let b2 = net.joining_node(3, &[host]);
    net.pair(b2, b);
    let b2t = net.node_tid(b2);
    let done = net.engine(b).pair(&b2t).unwrap();
    let paired = done.commits[0];
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for (_, pks) in net.sync(b).take_direct() {
        for pk in pks {
            let _ = net.engine(b2).ingest(&pk.bytes, pk.blobs);
        }
    }
    let done = net.engine(b2).paired(&bob, &paired).unwrap();
    let acts = net.sync(b2).carry_out(done).unwrap();
    net.actions(b2, acts);
    net.nodes[b].accepts = false;
    net.nodes[b2].accepts = false;
    for _ in 0..3 {
        net.advance(70_000);
    }
    (net, a, b, b2, bob, g)
}

// spec/sync.md §3: a request accepted on one of Bob's nodes is admitted on his other one by
// the grant's copy under his home label (a commit blob of it under a synced label).
#[test]
fn invite_accepted_on_one_node_admitted_on_the_other_spec_sync_3() {
    let (mut net, a, b, b2, bob, g) = bob_with_two_nodes();
    let t = net.item(a, g, g, "for bob");
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(requests(&mut net, b), vec![c]);
    assert_eq!(requests(&mut net, b2), vec![c]);
    let (_, acts) = net.sync(b).accept_invite(c).unwrap();
    net.actions(b, acts);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, t), Some(s("for bob")));
    assert!(requests(&mut net, b2).is_empty(), "admitted on the other node");
    assert_eq!(net.read(b2, t), Some(s("for bob")));
}

// spec/sync.md §3 (a decline holds against inbox blobs only; a sibling's acceptance wins): Bob
// declines on b2, then accepts on b; b2 applies the grant from b's copy under the home label
#[test]
fn sibling_acceptance_wins_over_decline_spec_sync_3() {
    let (mut net, a, b, b2, bob, g) = bob_with_two_nodes();
    let t = net.item(a, g, g, "for bob");
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b2).decline_invite(c).unwrap());
    for _ in 0..2 {
        net.advance(70_000);
    }
    assert!(!holds(&mut net, b2, &c), "declined: not applied");
    let (_, acts) = net.sync(b).accept_invite(c).unwrap();
    net.actions(b, acts);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert!(holds(&mut net, b2, &c), "the sibling's acceptance applies it");
    assert_eq!(net.read(b2, t), Some(s("for bob")));
}

// spec/sync.md §3: a sender is connected by a current role only: Carol, removed from g (which
// Bob syncs), is a stranger to Bob again, and her invite is a request.
#[test]
fn removed_holder_invite_is_request_spec_sync_3() {
    use osis_node::flows::Demotion;
    let (mut net, host, a, b, _, bob, g, _) = alice_and_bob();
    let c = net.node(3, &[host]);
    let addr = net.address(host);
    let (carol, done) = net.engine(c).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(c).carry_out(done).unwrap();
    net.actions(c, acts);
    net.run();
    net.pair(c, a);
    net.pair(b, c);
    grant(&mut net, a, g, bob);
    grant(&mut net, a, g, carol.account);
    let _ = net.item(a, g, g, "for both");
    for _ in 0..3 {
        net.advance(70_000);
    }
    let done = net.engine(a).demote(&g, &Demotion { holder: carol.account, new: None, retain: None }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.engine(b).role_on(&g).is_some() && net.engine(b).roster(&g).keys().all(|m| *m != carol.account), "Bob syncs g and saw Carol leave it");
    net.nodes[b].accepts = false;
    let e = net.engine(c);
    let mut m = Mutation::new();
    let gc = e.new_thing(&mut m, carol.account);
    m.set(gc, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let (_, done) = net.engine(c).create_label(&gc, &[addr]).unwrap();
    let acts = net.sync(c).carry_out(done).unwrap();
    net.actions(c, acts);
    let x = grant_commit(&mut net, c, gc, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(requests(&mut net, b), vec![x], "a removed holder's invite waits");
    assert!(!holds(&mut net, b, &x));
}

// spec/sync.md §3 (direct packages kept until the app takes them): a crash between pairing's
// commit and carrying it out loses no direct package: the same commits wait for the new node
// after the restart.
#[test]
fn direct_packages_survive_a_crash_before_carry_out_spec_sync_3() {
    let (mut net, host, _, b, _, _bob, _, _) = alice_and_bob();
    let b2 = net.joining_node(3, &[host]);
    net.pair(b2, b);
    let b2t = net.node_tid(b2);
    let done = net.engine(b).pair(&b2t).unwrap();
    let want: Vec<osis_base::CommitId> = done.deliveries.iter().find_map(|d| if let osis_node::flows::Delivery::Direct { to, commits } = d { (*to == b2t).then(|| commits.clone()) } else { None }).unwrap();
    drop(done);
    net.restart(b, 77);
    net.run();
    let got: Vec<osis_base::CommitId> = net.sync(b).take_direct_for(&b2t).iter().map(|pk| osis_commit::CommitBlob::decode(&pk.bytes).unwrap().id()).collect();
    assert_eq!(got, want, "the pairing's direct packages after the restart");
}

/// Whether `n` has `g`'s one label open and idle, stranded on no connection.
fn settled(net: &mut Net, n: usize, g: Tid) -> bool {
    let st = net.sync(n).label_status();
    let of: Vec<_> = st.iter().filter(|s| s.group == g).collect();
    of.len() == 1 && !of[0].stranded && of[0].sources == 1 && of[0].idle == 1
}

/// Alice's item `t` of `g`, labeled by g alone.
fn item_in(net: &mut Net, a: usize, g: Tid) -> Tid {
    let t = net.item(a, g, g, "item");
    net.run();
    t
}

/// Handed off, then synced again, with nothing but settling in between (no time passes: a retry
/// timer cannot help).
fn toggle(net: &mut Net, n: usize, g: Tid) {
    let acts = net.sync(n).set_handed_off(g, true);
    net.actions(n, acts);
    net.run();
    let acts = net.sync(n).set_handed_off(g, false);
    net.actions(n, acts);
    net.run();
}

// spec/wire.md §9: a thing with no label of its own names none: a grant on an item of a group
// does not take the group's label away from the group when syncing it stops and resumes.
#[test]
fn item_grant_leaves_the_groups_label_alone_spec_wire_9() {
    let (mut net, _, a, b, _, bob, g, _) = alice_and_bob();
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    assert!(settled(&mut net, b, g));
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    assert!(net.engine(b).epochs(&t).is_some(), "bob took t's grant");
    toggle(&mut net, b, g);
    assert!(settled(&mut net, b, g), "{:?}", net.sync(b).label_status());
    net.write(a, t, "after");
    net.run();
    assert_eq!(net.read(b, t), Some(s("after")));
}

// spec/wire.md §9: an earlier grant on an item does not keep the grantee from its group's label
// (one hint per label, and the item's secrets open nothing under it).
#[test]
fn item_grant_then_group_grant_reaches_the_group_spec_wire_9() {
    let (mut net, _, a, b, _, bob, g, _) = alice_and_bob();
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    assert!(net.engine(b).epochs(&t).is_some(), "bob took t's grant");
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    assert!(settled(&mut net, b, g), "{:?}", net.sync(b).label_status());
    assert_eq!(net.read(b, t), Some(s("item")));
}

// spec/sync.md §3: a label a group here records is never a hint, whatever a blob calls it: not
// taken while the group is handed off here, nor in the way when it syncs again.
#[test]
fn inbox_blob_cannot_rename_a_groups_label_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let c = net.engine(a).commit_ids().into_iter().rev().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "secrets.0") && h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "roles.0"))).unwrap();
    let thing = osis_label::InboxThing { tid: t, label: Some(osis_label::InboxLabel { id: gl.id, index: gl.index, hosts: gl.hosts.clone() }), delete_keys: None };
    let exp = net.now() + INBOX_LIFETIME_MS;
    net.set_online(b, false);
    let id = plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing], exp);
    net.set_online(b, true);
    net.advance(61_000);
    let kinds = net.sync(b).entries(&home);
    assert!(kinds.iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(Some(_)))), "bob opened it: {kinds:?}");
    let acts = net.sync(b).set_handed_off(g, true);
    net.actions(b, acts);
    net.run();
    let acts = net.sync(b).set_handed_off(g, false);
    net.actions(b, acts);
    net.run();
    assert!(settled(&mut net, b, g), "{:?}", net.sync(b).label_status());
}

// spec/sync.md §3: a blob naming a group's label under an item, before the group is known, holds
// the label only while that hint stands: once it fails and the group's own grant names the label
// (or the blob expires), the label goes to the group on the same connection.
#[test]
fn hint_under_another_thing_gives_way_to_the_group_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let c = net.engine(a).commit_ids().into_iter().rev().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "secrets.0") && h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "roles.0"))).unwrap();
    let thing = osis_label::InboxThing { tid: t, label: Some(osis_label::InboxLabel { id: gl.id, index: gl.index, hosts: gl.hosts.clone() }), delete_keys: None };
    let exp = net.now() + INBOX_LIFETIME_MS;
    plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing], exp);
    net.advance(61_000);
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(INBOX_LIFETIME_MS / 2 + 1000);
    }
    assert!(settled(&mut net, b, g), "{:?}", net.sync(b).label_status());
    assert_eq!(net.read(b, t), Some(s("item")));
}

/// Bob's inbox holds a blob naming `g`'s label under item `t` (a thing the sender boxes to him),
/// sorted first, and the group's own grant: he reaches `g` at the next tries, long before the
/// blob expires. `hosts`: where the blob says the label is.
fn hint_first_then_group_grant(hosts: impl Fn(&[ct::Address]) -> Vec<ct::Address>) {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let c = boxing_grant(&mut net, a, t);
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    let first = net.host_ids(host, &home).into_iter().min().unwrap();
    let thing = osis_label::InboxThing { tid: t, label: Some(osis_label::InboxLabel { id: gl.id, index: gl.index, hosts: hosts(&gl.hosts) }), delete_keys: None };
    let mut exp = net.now() + INBOX_LIFETIME_MS;
    while plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing.clone()], exp) > first {
        exp -= 1;
    }
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(61_000);
    }
    assert!(settled(&mut net, b, g), "{:?}", net.sync(b).label_status());
    assert_eq!(net.read(b, t), Some(s("item")));
}

// spec/sync.md §3: blobs naming one label under different things: each thing is tried in turn, so
// a connected sender's word delays the label's own group by a few tries at most.
#[test]
fn hint_under_another_thing_does_not_hold_off_the_group_spec_sync_3() {
    hint_first_then_group_grant(|h| h.to_vec());
}

// spec/sync.md §3: nor by naming the label at a host that never answers: the label is tried at the
// hosts every blob names.
#[test]
fn hint_at_a_dead_host_does_not_hold_off_the_group_spec_sync_3() {
    hint_first_then_group_grant(|h| {
        let mut x = h[0].clone();
        x.key = [0xdd; 32];
        vec![x]
    });
}

/// The newest commit carrying `t`'s `roles.0` and `secrets.0`: its grant, with the boxes.
fn boxing_grant(net: &mut Net, a: usize, t: Tid) -> osis_base::CommitId {
    net.engine(a).commit_ids().into_iter().rev().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "secrets.0") && h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "roles.0"))).unwrap()
}

/// Everything queued delivered; a message loop panics here, not after minutes.
fn quiet(net: &mut Net, b: usize) {
    net.feed(b, osis_node::sync::Event::Local);
    net.settle(5_000);
}

// spec/sync.md §3: nor by naming the label at a host of its own that takes the open and never
// answers, on a connection older than the real host's: what the real host sends reads under the
// thing that opened there, not the one still opening elsewhere.
#[test]
fn hint_at_a_silent_host_does_not_hold_off_the_group_spec_sync_3() {
    let mut net = Net::new();
    let silent = net.add_host();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[silent, host]);
    let (a, b, _, bob, g, home) = alice_and_bob_on(&mut net, host, a, b, Vec::new());
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let c = boxing_grant(&mut net, a, t);
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    let first = net.host_ids(host, &home).into_iter().min().unwrap();
    let thing = osis_label::InboxThing { tid: t, label: Some(osis_label::InboxLabel { id: gl.id, index: gl.index, hosts: vec![net.address(silent)] }), delete_keys: None };
    let mut exp = net.now() + INBOX_LIFETIME_MS;
    while plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing.clone()], exp) > first {
        exp -= 1;
    }
    net.set_online(b, true);
    net.feed(b, osis_node::sync::Event::Tick);
    // both connections up, the silent host's the older; nothing it answers from here on
    for _ in 0..3 {
        net.round();
    }
    assert!(net.conn_to(b, silent).unwrap() < net.conn_to(b, host).unwrap());
    net.held_hosts.insert(silent);
    quiet(&mut net, b);
    quiet(&mut net, b);
    assert_eq!(net.read(b, t), Some(s("item")), "{:?}", net.sync(b).label_status());
    assert!(net.sync(b).labels().iter().any(|(x, l)| *x == g && l.id == gl.id), "{:?}", net.sync(b).label_status());
}

// spec/sync.md §3, §5: nor by naming it at a host of its own that holds the label's real path
// (a past reader's), answers the hinted open with a step and takes the claim, on a connection
// older than the real host's: the label is open under the hinted thing there, and what the real
// host sends still reads under the group that opened it there, with no message loop; once the
// group's `label.0` is held, the label leaves that connection.
#[test]
fn hint_at_a_claiming_host_does_not_hold_off_the_group_spec_sync_3() {
    let mut net = Net::new();
    let evil = net.add_host();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[evil, host]);
    let (a, b, _, bob, g, home) = alice_and_bob_on(&mut net, host, a, b, Vec::new());
    let t = item_in(&mut net, a, g);
    grant(&mut net, a, t, bob);
    net.advance(61_000);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    let c = boxing_grant(&mut net, a, t);
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    claiming_host(&mut net, evil, host, &gl.id);
    let first = net.host_ids(host, &home).into_iter().min().unwrap();
    let thing = osis_label::InboxThing { tid: t, label: Some(osis_label::InboxLabel { id: gl.id, index: gl.index, hosts: vec![net.address(evil)] }), delete_keys: None };
    let mut exp = net.now() + INBOX_LIFETIME_MS;
    while plant_inbox(&mut net, a, (host, &home), bob, &c, vec![thing.clone()], exp) > first {
        exp -= 1;
    }
    net.set_online(b, true);
    net.feed(b, osis_node::sync::Event::Tick);
    for _ in 0..3 {
        net.round();
    }
    assert!(net.conn_to(b, evil).unwrap() < net.conn_to(b, host).unwrap());
    for _ in 0..3 {
        quiet(&mut net, b);
        net.tick(61_000);
    }
    quiet(&mut net, b);
    assert_eq!(net.read(b, t), Some(s("item")), "{:?}", net.sync(b).label_status());
    assert!(net.sync(b).labels().iter().any(|(x, l)| *x == g && l.id == gl.id), "{:?}", net.sync(b).label_status());
    // the label left the claiming host's connection once its `label.0` was held: that host
    // (not one the group names) judges nothing more under the hinted thing
    assert_eq!(net.sync(b).conn_groups(&gl.id), vec![g]);
}

/// Host `evil` holds `l`'s path at `host` with its claim sets (a past reader's) and answers
/// every open of `l` by sync key with the head, so a hinted open walks there and claims.
fn claiming_host(net: &mut Net, evil: usize, host: usize, l: &LabelId) {
    let path = net.host_path(host, l);
    for st in &path {
        let set = osis_proto::LabelStore::claim_set(&*net.hosts[host].hub.store(), l, &st.id()).unwrap().map(|x| (*x).clone());
        osis_proto::LabelStore::push_step(&mut *net.hosts[evil].hub.store(), l, st.clone(), set).unwrap();
    }
    net.walk_to.insert(evil, (*l, path.last().unwrap().clone()));
}

/// One seed of `hint_turns`: blobs naming `g`'s label under other things (some at a wrong index),
/// at any of the real host, hosts that never answer, hosts that hold its real path, walk a hinted
/// open to its head and take the claim, and hosts without the label, in any order with the
/// group's own grant, while time passes and the real host's replies lag.
fn hint_turns_seed(seed: u64) {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rng = move |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x >> 8) % n
    };
    let mut net = Net::new();
    let silent: Vec<usize> = (0..rng(3)).map(|_| net.add_host()).collect();
    let claiming: Vec<usize> = (0..rng(3)).map(|_| net.add_host()).collect();
    let host = net.add_host();
    let empty: Vec<usize> = (0..rng(3)).map(|_| net.add_host()).collect();
    let a = net.node(1, &[host]);
    let at: Vec<usize> = silent.iter().chain(&claiming).copied().chain([host]).collect();
    let b = net.node(2, &at);
    let (a, b, _, bob, g, home) = alice_and_bob_on(&mut net, host, a, b, Vec::new());
    let things: Vec<Tid> = (0..1 + rng(3)).map(|_| item_in(&mut net, a, g)).collect();
    let mut planted = Vec::new();
    for t in &things {
        grant(&mut net, a, *t, bob);
        net.run();
        planted.push((*t, boxing_grant(&mut net, a, *t)));
    }
    net.advance(61_000);
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1;
    net.set_online(b, false);
    grant(&mut net, a, g, bob);
    net.advance(61_000);
    for e in &claiming {
        claiming_host(&mut net, *e, host, &gl.id);
    }
    let named: Vec<usize> = silent.iter().chain(&claiming).chain(&empty).copied().chain([host]).collect();
    let mut exp = net.now() + INBOX_LIFETIME_MS;
    for (t, c) in &planted {
        for _ in 0..1 + rng(2) {
            let hosts: Vec<_> = named.iter().filter(|_| rng(2) == 0).map(|h| net.address(*h)).collect();
            let index = gl.index + rng(2);
            let thing = osis_label::InboxThing { tid: *t, label: Some(osis_label::InboxLabel { id: gl.id, index, hosts }), delete_keys: None };
            plant_inbox(&mut net, a, (host, &home), bob, c, vec![thing], exp);
            exp -= 1;
        }
    }
    net.set_online(b, true);
    net.feed(b, osis_node::sync::Event::Tick);
    for _ in 0..3 {
        net.round();
    }
    net.held_hosts.extend(silent.iter().copied());
    for _ in 0..rng(6) {
        if rng(2) == 0 {
            net.held_hosts.insert(host);
        }
        net.tick(1_000 * (1 + rng(30)));
        quiet(&mut net, b);
        // only the real host's lag ends
        net.release_host(host);
        quiet(&mut net, b);
    }
    for _ in 0..things.len() as u64 + 4 {
        net.tick(61_000);
        quiet(&mut net, b);
        quiet(&mut net, b);
    }
    assert_eq!(net.read(b, things[0]), Some(s("item")), "seed {seed}: {:?}", net.sync(b).label_status());
    assert!(net.sync(b).labels().iter().any(|(x, l)| *x == g && l.id == gl.id), "seed {seed}: {:?}", net.sync(b).label_status());
    // once its `label.0` is held, no connection holds the label under a hint's thing
    let held = net.sync(b).conn_groups(&gl.id);
    assert!(held.iter().all(|x| *x == g), "seed {seed}: {held:?}");
}

fn hint_turns_replay(s: u64) -> String {
    format!("OSIS_HINTS_START={s} OSIS_HINTS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact inbox_life::hint_turns_reach_the_group_large_spec_sync_3")
}

// spec/sync.md §3: whatever other things blobs name a label under and whichever hosts they name it
// at, its own group reads it within a few retries, with no message loop on the way.
#[test]
fn hint_turns_reach_the_group_spec_sync_3() {
    osis_base::testenv::run_seeds("inbox_life::hint_turns_reach_the_group_spec_sync_3", &[0, 1, 2, 3], false, hint_turns_replay, hint_turns_seed);
}

#[test]
#[ignore]
fn hint_turns_reach_the_group_large_spec_sync_3() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_HINTS_START", "OSIS_HINTS_SEEDS", osis_base::testenv::large(0..60));
    seeds.run("inbox_life::hint_turns_reach_the_group_large_spec_sync_3", hint_turns_replay, hint_turns_seed);
}

// spec/wire.md §9: a grant's payload names a thing's own label, or none: never a group's holding it.
#[test]
fn grant_payload_names_only_the_things_own_label_spec_wire_9() {
    let (mut net, _, a, b, _, bob, g, _) = alice_and_bob();
    let t = item_in(&mut net, a, g);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let gl = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    let names = |on: Tid, net: &mut Net| {
        let done = net.engine(a).grant(&on, &bob, &edge).unwrap();
        let blob = done.deliveries.iter().find_map(|d| if let osis_node::flows::Delivery::Inbox { blob, .. } = d { Some(blob.clone()) } else { None }).expect("an inbox blob");
        let (things, _) = net.engine(b).accept_inbox(&blob).unwrap();
        things.into_iter().find(|x| x.tid == on).expect("the payload names it").label.map(|l| l.id)
    };
    let tl = names(t, &mut net).expect("the grant gave it a sync ID");
    assert_ne!(tl, gl, "its own, not the group's");
    assert_eq!(names(g, &mut net), Some(gl));
}

/// What is left of the deposit budget of `l` at the host, in entries.
fn budget_left(net: &mut Net, host: usize, l: &LabelId) -> u64 {
    osis_proto::LabelStore::budget(&*net.hosts[host].hub.store(), l).unwrap().entries_left
}

// spec/sync.md §5: a grant accepted on one node is stamped out of the deposit budget and stays at the host, readable by the sibling that was away
#[test]
fn stamped_inbox_blob_reaches_a_sibling_spec_sync_5() {
    let (mut net, a, b, b2, bob, g) = bob_with_two_nodes();
    let d = net.engine(b).account().unwrap().unwrap().1;
    let home = net.sync(b).labels().into_iter().find(|(x, _)| *x == d).unwrap().1.id;
    let left = budget_left(&mut net, 0, &home);
    let t = net.item(a, g, g, "for bob");
    net.set_online(b2, false);
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(budget_left(&mut net, 0, &home), left - 1, "a request holds its slot");
    let (_, acts) = net.sync(b).accept_invite(c).unwrap();
    net.actions(b, acts);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(budget_left(&mut net, 0, &home), left, "accepted: the slot is free");
    let id = net.sync(b).entries(&home).into_iter().find(|(_, k)| matches!(k, EntryKind::Inbox(Some(x)) if *x == c)).unwrap().0;
    assert!(net.host_ids(0, &home).contains(&id), "the blob stays");
    net.set_online(b2, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert!(net.sync(b2).entries(&home).iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(Some(x)) if *x == c)), "the sibling opened it");
    assert!(net.sync(b2).entry_meta(&home, &id).unwrap().1.is_some(), "stamped");
    assert_eq!(net.read(b2, t), Some(s("for bob")));
}

// spec/sync.md §5: a stranger's request holds its budget slot until the user answers it; declining frees the slot and the blob stays until it expires
#[test]
fn declined_request_leaves_the_budget_spec_sync_5() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    net.nodes[b].accepts = false;
    let left = budget_left(&mut net, host, &home);
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(requests(&mut net, b), vec![c]);
    assert_eq!(budget_left(&mut net, host, &home), left - 1, "unanswered: it holds its slot");
    assert!(net.sync(b).decline_invite(c).unwrap());
    let ids = net.host_ids(host, &home);
    for _ in 0..2 {
        net.advance(70_000);
    }
    assert_eq!(budget_left(&mut net, host, &home), left, "declined: the slot is free");
    assert_eq!(net.host_ids(host, &home), ids);
    assert!(!holds(&mut net, b, &c), "and its commit stays unapplied");
}

// spec/sync.md §5: a commit from a connected sender that applies and is judged invalid leaves its blob in the budget
#[test]
fn invalid_inbox_commit_keeps_its_slot_spec_sync_5() {
    let (mut net, host, a, b, alice, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    net.pair(a, b);
    // a thing of Bob's that Alice only reads
    let e = net.engine(b);
    let mut m = Mutation::new();
    let h = e.new_thing(&mut m, bob);
    m.set(h, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    grant(&mut net, b, h, alice);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read), "Alice is connected");
    assert_eq!(net.engine(a).role_on(&h), Some(Role::Read));
    let left = budget_left(&mut net, host, &home);
    let rec = net.engine(b).get_typed(&h, &ct::CREATED).unwrap().unwrap();
    let ak = osis_base::Ak::new("forged.0").unwrap();
    let bytes = crate::validity::forge_by(net.engine(a), rec, h, &ak, &osis_base::Value::Bytes(vec![1]), 1 << 32, osis_commit::Kind::Content);
    let c = osis_commit::CommitBlob::decode(&bytes).unwrap().id();
    let exp = net.now() + INBOX_LIFETIME_MS;
    net.set_online(b, false);
    plant_bytes(&mut net, a, (host, &home), bob, &bytes, Vec::new(), exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let valid = net.engine(b).core.ix.commits.get(&c).map(|m| m.valid.clone());
    assert_eq!(valid, Some(vec![false]), "applied, judged invalid; pending: {:?}", net.engine(b).pending());
    assert_eq!(budget_left(&mut net, host, &home), left - 1, "not stamped");
}

// spec/sync.md §3: a stranger holding a commit the actor applied or declined can seal it in many blobs: at most one leaves the budget, and a commit not about the actor none
#[test]
fn reseals_stay_in_the_budget_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    net.nodes[b].accepts = false;
    let left = budget_left(&mut net, host, &home);
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).decline_invite(c).unwrap());
    for _ in 0..2 {
        net.advance(70_000);
    }
    assert_eq!(budget_left(&mut net, host, &home), left, "the declined one is out");
    // his own card, which anyone with it holds; and the declined commit again
    let card = net.engine(b).aspect_commit(&bob, "keys.0").expect("Bob's keys.0").0;
    let exp = net.now() + INBOX_LIFETIME_MS;
    let t = |i: u64| vec![osis_label::InboxThing { tid: osis_base::Tid::from_bytes([i as u8; 15]), label: None, delete_keys: None }];
    net.set_online(b, false);
    for i in 0..3 {
        plant_inbox(&mut net, b, (host, &home), bob, &card, t(i), exp);
        plant_inbox(&mut net, a, (host, &home), bob, &c, t(i), exp);
    }
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(budget_left(&mut net, host, &home), left - 6, "not stamped");
}

// spec/sync.md §3: a copied grant's thing gets a new `label.0`: the copy under home gains it
#[test]
fn copied_grant_gains_a_new_label_spec_sync_3() {
    let (mut net, _, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
    let copies = |net: &mut Net, c: &osis_base::CommitId| net.sync(b).entries(&home).iter().any(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c));
    let first = net.engine(b).aspect_commit(&g, "label.0").expect("Bob holds the label").0;
    assert!(copies(&mut net, &first), "the first label's copy under home");
    let old = net.engine(a).labels_of(&g).iter().find(|l| !l.replaced).unwrap().id;
    let (_, acts) = net.sync(a).replace_label(&g, &old).unwrap();
    net.actions(a, acts);
    for _ in 0..4 {
        net.advance(70_000);
    }
    let next = net.engine(b).aspect_commit(&g, "label.0").expect("Bob holds the label").0;
    assert_ne!(first, next);
    assert!(copies(&mut net, &next), "the new label's copy under home");
}

// spec/sync.md §3: a blob expiring later than an honest sender's could is not stamped, its expiry being the sender's word; another blob of the commit is
#[test]
fn far_expiry_stays_in_the_budget_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    net.set_online(a, false);
    let c = grant_commit(&mut net, a, g, bob);
    let exp = net.now() + 2 * INBOX_LIFETIME_MS;
    net.set_online(b, false);
    let far = plant_inbox(&mut net, a, (host, &home), bob, &c, Vec::new(), exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.engine(b).core.ix.commits.contains_key(&c) && !net.engine(b).core.ix.pending.contains_key(&c), "applied");
    assert!(net.sync(b).entry_meta(&home, &far).unwrap().1.is_none());
    let exp = net.now() + INBOX_LIFETIME_MS;
    net.set_online(b, false);
    let near = plant_inbox(&mut net, a, (host, &home), bob, &c, vec![osis_label::InboxThing { tid: g, label: None, delete_keys: None }], exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).entry_meta(&home, &near).unwrap().1.is_some());
}

// spec/sync.md §3: a blob of the commit without the parts about the actor takes no stamp, and leaves it to the one with them
#[test]
fn partless_blob_takes_no_stamp_spec_sync_3() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    net.set_online(a, false);
    let c = grant_commit(&mut net, a, g, bob);
    let bytes = net.engine(a).commit_bytes(&c).unwrap().unwrap();
    let mut bare = osis_commit::CommitBlob::decode(&bytes).unwrap();
    bare.parts.clear();
    let exp = net.now() + INBOX_LIFETIME_MS;
    let t = |i: u64| vec![osis_label::InboxThing { tid: osis_base::Tid::from_bytes([i as u8; 15]), label: None, delete_keys: None }];
    net.set_online(b, false);
    let bares: Vec<_> = (0..4).map(|i| plant_bytes(&mut net, a, (host, &home), bob, &bare.encode(), t(i), exp)).collect();
    let whole = plant_inbox(&mut net, a, (host, &home), bob, &c, Vec::new(), exp);
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.sync(b).entry_meta(&home, &whole).unwrap().1.is_some());
    for x in bares {
        assert!(net.sync(b).entry_meta(&home, &x).unwrap().1.is_none());
    }
}

// spec/sync.md §5: a stranger's requests past the cap: those expiring too far ahead go first, then the earliest to expire, so a later request still reaches the user
#[test]
fn requests_past_the_cap_go_earliest_first_spec_sync_5() {
    let (mut net, host, a, b, _, bob, g, home) = alice_and_bob();
    net.nodes[b].accepts = false;
    let c = grant_commit(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(requests(&mut net, b), vec![c]);
    net.set_online(a, false);
    net.set_online(b, false);
    let now = net.now();
    let t = |i: u64| vec![osis_label::InboxThing { tid: osis_base::Tid::from_bytes([i as u8; 15]), label: None, delete_keys: None }];
    let n = osis_base::format::DEPOSITS_WAITING as u64;
    let far = plant_inbox(&mut net, a, (host, &home), bob, &c, t(0), now + 2 * INBOX_LIFETIME_MS);
    let plant = |net: &mut Net, i: u64| plant_inbox(net, a, (host, &home), bob, &c, t(i), now + INBOX_LIFETIME_MS - 1000 * (n + 8 - i));
    let ids: Vec<_> = (1..n + 8).map(|i| plant(&mut net, i)).collect();
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    let held = net.host_ids(host, &home);
    assert!(!held.contains(&far), "too far ahead goes first");
    let (early, late) = ids.split_at(ids.len() - osis_base::format::DEPOSITS_WAITING);
    assert!(early.iter().all(|x| !held.contains(x)), "then the earliest to expire");
    assert!(late.iter().all(|x| held.contains(x)), "the latest stay");
    assert!(net.sync(b).entries(&home).iter().all(|(x, _)| !early.contains(x)), "and are forgotten here");
    assert_eq!(requests(&mut net, b), vec![c], "the user still sees the invite");
}

// spec/sync.md §5: a burst of a connected sender's grants past the cap is stamped, none deleted while its stamp waits
#[test]
fn burst_of_grants_is_not_cleared_spec_sync_5() {
    let (mut net, host, a, b, alice, bob, g, home) = alice_and_bob();
    grant(&mut net, a, g, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read), "Alice is connected");
    net.nodes[b].accepts = false;
    net.set_online(b, false);
    let n = osis_base::format::DEPOSITS_WAITING + 8;
    let mut commits = Vec::new();
    for _ in 0..n {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, alice);
        m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        commits.push(grant_commit(&mut net, a, t, bob));
    }
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert!(requests(&mut net, b).is_empty(), "connected: no request");
    let held = net.host_ids(host, &home);
    let entries = net.sync(b).entries(&home);
    for c in &commits {
        let (id, _) = entries.iter().find(|(_, k)| matches!(k, EntryKind::Inbox(Some(x)) if x == c)).expect("its blob is kept");
        assert!(held.contains(id) && net.sync(b).entry_meta(&home, id).unwrap().1.is_some(), "stamped at the host");
    }
}

/// `n` real invites from Alice to Bob, a second apart, each on a new thing: their commits.
fn invites(net: &mut Net, a: usize, alice: Tid, bob: Tid, n: usize) -> Vec<osis_base::CommitId> {
    let mut commits = Vec::new();
    for _ in 0..n {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, alice);
        m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(m).unwrap();
        commits.push(grant_commit(net, a, t, bob));
        net.advance(1_000);
    }
    commits
}

/// Node `from` deposits at the host under `bob`'s inbox a blob that opens to nothing: `n` of them, while the budget takes them, expiring at `expiry`.
fn deposit_junk(net: &mut Net, from: usize, (host, l): (usize, &LabelId), bob: Tid, n: u64, expiry: u64) -> Vec<osis_base::BlobId> {
    let seed = net.engine(from).deposit_seed(&bob).unwrap().unwrap();
    let d = osis_crypto::deposit_key(&seed, l);
    let mut rng = osis_crypto::SeededRng::from_u64(expiry);
    let mut out = Vec::new();
    for _ in 0..n {
        let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(&mut rng), Some(osis_base::WallMs(expiry)), Vec::new()).unwrap();
        let (_, blob) = osis_label::frame(&prefix, b"junk", &mut rng).unwrap();
        let id = osis_label::blob_id(&blob);
        let wrap = osis_crypto::filler_wrap(&mut rng);
        let sig = osis_label::sign_deposit(&d, l, &id, &wrap);
        crate::wrap_poison::send(net, from, host, osis_proto::Message::Deposit { id: 0x4000_0001, label: *l, blob, wrap, sig });
        out.push(id);
    }
    assert!(out.iter().all(|x| net.host_ids(host, l).contains(x)), "the host took them");
    out
}

// spec/sync.md §5: a stranger's deposits that open to nothing, expiring after real requests, go before them: real deposits over the wire while Bob is away
#[test]
fn junk_goes_before_real_requests_spec_sync_5() {
    let (mut net, host, a, b, alice, bob, _, home) = alice_and_bob();
    net.nodes[b].accepts = false;
    net.set_online(b, false);
    let real = invites(&mut net, a, alice, bob, 10);
    let until = net.now() + INBOX_LIFETIME_MS;
    let junk = deposit_junk(&mut net, a, (host, &home), bob, 40, until);
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    let mut seen = requests(&mut net, b);
    seen.sort();
    let mut want = real.clone();
    want.sort();
    assert_eq!(seen, want, "every request stays");
    let held = net.host_ids(host, &home);
    assert_eq!(junk.iter().filter(|x| held.contains(x)).count(), osis_base::format::DEPOSITS_WAITING - real.len(), "the junk goes down to the cap");
}

// spec/sync.md §5: more real invites than the cap while their user is away: the latest stay, and the rest are lost to her until re-sent
#[test]
fn real_requests_past_the_cap_keep_the_latest_spec_sync_5() {
    let (mut net, _, a, b, alice, bob, _, _) = alice_and_bob();
    net.nodes[b].accepts = false;
    net.set_online(b, false);
    let n = osis_base::format::DEPOSITS_WAITING;
    let real = invites(&mut net, a, alice, bob, n + 8);
    net.set_online(b, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    let mut seen = requests(&mut net, b);
    seen.sort();
    let mut want = real[8..].to_vec();
    want.sort();
    assert_eq!(seen, want);
}

// spec/sync.md §5: an account's new node clears as the old one would, once its first sync is whole: requests stay, junk goes
#[test]
fn fresh_node_keeps_requests_over_junk_spec_sync_5() {
    let (mut net, host, a, b, alice, bob, _, home) = alice_and_bob();
    net.nodes[b].accepts = false;
    let real = invites(&mut net, a, alice, bob, 10);
    for _ in 0..2 {
        net.advance(70_000);
    }
    let until = net.now() + INBOX_LIFETIME_MS;
    net.set_online(b, false);
    let junk = deposit_junk(&mut net, a, (host, &home), bob, 40, until);
    let b2 = net.joining_node(3, &[host]);
    net.nodes[b2].accepts = false;
    net.pair(b2, b);
    let b2t = net.node_tid(b2);
    let done = net.engine(b).pair(&b2t).unwrap();
    let paired = done.commits[0];
    for (_, pks) in net.sync(b).take_direct() {
        for pk in pks {
            let _ = net.engine(b2).ingest(&pk.bytes, pk.blobs);
        }
    }
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for (_, pks) in net.sync(b).take_direct() {
        for pk in pks {
            let _ = net.engine(b2).ingest(&pk.bytes, pk.blobs);
        }
    }
    let done = net.engine(b2).paired(&bob, &paired).unwrap();
    let acts = net.sync(b2).carry_out(done).unwrap();
    net.actions(b2, acts);
    for _ in 0..6 {
        net.advance(70_000);
    }
    let mut seen = requests(&mut net, b2);
    seen.sort();
    let mut want = real.clone();
    want.sort();
    assert_eq!(seen, want, "the new node sees every request");
    let held = net.host_ids(host, &home);
    assert!(junk.iter().filter(|x| held.contains(x)).count() <= osis_base::format::DEPOSITS_WAITING - real.len());
}

// spec/sync.md §5, §2: a shared group's label is its own inbox, and its readers' card changes are deposits past the cap: its admin keeps them all; the record blobs of their chains go up stamped with them
#[test]
fn readers_burst_under_a_group_inbox_stays_spec_sync_5() {
    let mut net = Net::bare();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let addr = net.address(host);
    let (alice, done) = net.engine(a).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (o, done) = net.engine(a).create_with_admin(&alice.account).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let (l, acts) = net.sync(a).create_label(&o, vec![addr.clone()]).unwrap();
    net.actions(a, acts);
    net.run();
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let mut readers = Vec::new();
    for i in 0..4 {
        let r = net.node(10 + i, &[host]);
        let (p, done) = net.engine(r).create_account(std::slice::from_ref(&addr)).unwrap();
        let acts = net.sync(r).carry_out(done).unwrap();
        net.actions(r, acts);
        net.run();
        net.pair(r, a);
        let done = net.engine(a).grant(&o, &p.account, &edge).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        net.run();
        readers.push(r);
    }
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(readers.iter().all(|r| net.engine(*r).role_on(&o) == Some(Role::Read)));
    let before: std::collections::BTreeSet<_> = net.host_ids(host, &l).into_iter().collect();
    // the readers' cards and the record blobs of their chains went up stamped
    let waiting = before.iter().filter(|b| osis_proto::LabelStore::entry(&*net.hosts[host].hub.store(), &l, b).unwrap().is_some_and(|m| m.stamp.is_none())).count();
    assert_eq!(waiting, 0, "nothing waits in the budget");
    net.set_online(a, false);
    let until = net.now() + INBOX_LIFETIME_MS;
    let junk = deposit_junk(&mut net, readers[0], (host, &l), o, 40, until);
    // what the readers placed since, each card counted though the next replaces it
    let mut placed = std::collections::BTreeSet::new();
    let mut last = std::collections::BTreeSet::new();
    for round in 0..3u8 {
        for (i, r) in readers.iter().enumerate() {
            let acts = net.sync(*r).publish_reach([round * 16 + i as u8 + 1; 32], vec![]).unwrap();
            net.actions(*r, acts);
        }
        net.advance(70_000);
        let now: std::collections::BTreeSet<_> = net.host_ids(host, &l).into_iter().filter(|x| !junk.contains(x) && !before.contains(x) && !placed.contains(x)).collect();
        placed.extend(now.iter().copied());
        last = now;
    }
    assert!(placed.len() >= osis_base::format::DEPOSITS_WAITING / 3, "readers placed: {}", placed.len());
    // all but the junk, less the cards a later one replaced (they go as replaced, not by the
    // clearing rule)
    let held: Vec<_> = net.host_ids(host, &l).into_iter().filter(|x| !junk.contains(x) && (last.contains(x) || !placed.contains(x))).collect();
    assert!(!last.is_empty() && last.iter().all(|x| held.contains(x)));
    net.set_online(a, true);
    for _ in 0..4 {
        net.advance(70_000);
    }
    let after = net.host_ids(host, &l);
    assert_eq!(held.iter().filter(|x| !after.contains(x)).count(), 0, "the readers' deposits stay");
    assert_eq!(junk.iter().filter(|x| after.contains(x)).count(), osis_base::format::DEPOSITS_WAITING, "the rule ran");
}

// Requirements: peer input never costs unbounded memory; spec/sync.md §3. A stranger needs only
// the public `keys.0` to deposit a blob a node opens and decodes, before admission or any
// signature (issue value-decode-memory, closed): a blob of `{0:0}` costs its reader under
// `INBOX_PEAK_MAX` per byte in all (blob copies, the payload's decode and the commit's). In a child
// process, as the peak is process-wide.
#[cfg(target_os = "linux")]
#[test]
fn hostile_inbox_blob_peak_is_bounded_spec_sync_3() {
    const CHILD: &str = "OSIS_INBOX_PEAK_CHILD";
    /// Blob size: enough that the decode dwarfs the rest of what a sync pass touches.
    const SIZE: usize = 4 << 20;
    /// `osis_base::decode`'s bound for this shape (38), plus what the path adds on top of one
    /// decode: the blob's copies and the plaintext. Two decoded copies held at once would exceed it.
    const INBOX_PEAK_MAX: usize = 64;
    if std::env::var(CHILD).is_err() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "inbox_life::hostile_inbox_blob_peak_is_bounded_spec_sync_3", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{text}{}", String::from_utf8_lossy(&out.stderr));
        let kib: usize = text.lines().find_map(|l| l.split("peak_kib=").nth(1)).unwrap_or_else(|| panic!("{text}")).trim().parse().unwrap();
        println!("{} B per byte", kib * 1024 / SIZE);
        assert!(kib * 1024 <= INBOX_PEAK_MAX * SIZE, "{} B per byte", kib * 1024 / SIZE);
        return;
    }
    let status = |field: &str| -> usize {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        s.lines().find(|l| l.starts_with(field)).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap()
    };
    let (mut net, host, a, b, _, bob, _, home) = alice_and_bob();
    let keys = net.engine(a).get_typed(&bob, &ct::KEYS).unwrap().unwrap();
    let ct::KemKey::X25519MlKem768(kb) = &keys.key.or(keys.read.map(|k| k.kem_key)).unwrap();
    let kem = osis_crypto::KemPublicKey::from_slice(kb).unwrap();
    // `InboxPayload := [commit, things, chain, records]`, by hand: values built here would leave
    // freed memory for the decode to reuse, and the peak would not see it
    let mut plain = Vec::with_capacity(SIZE + 32);
    plain.extend([0x84]);
    osis_base::cbor::head(&mut plain, osis_base::cbor::MAJOR_ARRAY, (SIZE / 3) as u64);
    for _ in 0..SIZE / 3 {
        plain.extend([0xa1, 0, 0]);
    }
    plain.extend([0x80, 0x80, 0x80]);
    let now = osis_base::WallMs(net.now());
    let mut rng = osis_crypto::SeededRng::from_u64(5);
    let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(&mut rng), Some(now.saturating_add(INBOX_LIFETIME_MS)), vec![]).unwrap();
    let blob = osis_crypto::seal_inbox(&prefix.to_bytes(), &bob, &kem, &plain, &mut rng).unwrap();
    drop(plain);
    let id = osis_label::blob_id(&blob);
    net.set_online(b, false);
    // the label's host lists it with a stamp nobody signed: an honest host's deposit budget would
    // stop a stranger at about 2 MiB (spec/sync.md §5), the host of an inbox label has no such limit
    let stamp = Some(osis_crypto::Signature([0; 64]));
    let put = osis_proto::Put { blob_id: id, blob: &blob, wrap: [7; osis_crypto::WRAP_LEN], stamp, expiry: Some(now.0 + osis_base::format::INBOX_LIFETIME_MS), ephemeral: false, replaces: &[], now: 0 };
    assert_eq!(osis_proto::LabelStore::put(&mut *net.hosts[host].hub.store(), &home, put).unwrap(), osis_proto::Code::OK);
    drop(blob);
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let rss0 = status("VmRSS");
    net.set_online(b, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let peak = status("VmHWM").saturating_sub(rss0);
    // opened and its commit refused as undecodable: the decodes ran, and nothing else came of it
    assert!(net.sync(b).entries(&home).iter().any(|(x, k)| *x == id && matches!(k, EntryKind::Inbox(None))), "Bob opened it: {:?}", net.sync(b).entries(&home));
    println!("peak_kib={peak}");
}

// spec/sync.md §2: an actor's home label is the inbox its `keys.0` names, from the commit that
// makes the label: a sender holding only the actor's `keys.0` finds it there. A plain group's
// label is no inbox until the group is shared (secrets of its own).
#[test]
fn a_home_label_is_named_the_inbox_spec_sync_2() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    let l = net.engine(a).labels_of(&g).iter().find(|x| !x.replaced).unwrap().id;
    let c0 = net.engine(a).aspect_commit(&g, "keys.0").unwrap().0;
    assert_eq!(net.engine(a).aspect_commit(&g, "label.0").map(|x| x.0), Some(c0), "one commit");
    for n in [a, c] {
        assert_eq!(net.engine(n).inbox_of_actor(&g).unwrap().map(|(o, i)| (o, i.label)), Some((g, l)), "node {n}");
    }
    let (mut net, _, a, _, _, bob, plain, _) = alice_and_bob();
    assert_eq!(net.engine(a).get_typed(&plain, &ct::KEYS).unwrap().and_then(|k| k.inbox), None, "a plain group names none");
    assert_eq!(net.engine(a).inbox(&plain), None, "and has no inbox: no fallback to its first admin's");
    // shared, it gets secrets of its own, and its label is named in the same commit
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&plain, &bob, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let pl = net.engine(a).labels_of(&plain).iter().find(|x| !x.replaced).unwrap().id;
    let c0 = net.engine(a).aspect_commit(&plain, "keys.0").unwrap().0;
    assert_eq!(net.engine(a).get_typed(&plain, &ct::KEYS).unwrap().and_then(|k| k.inbox).map(|i| i.label), Some(pl));
    assert!(net.engine(a).header(&c0).unwrap().aspects.iter().any(|x| x.tid == plain && x.ak.as_str() == "secrets.0"), "with its secrets");
    assert_eq!(net.engine(a).inbox(&plain), Some(pl));
}

// spec/sync.md §2: replacing the label an actor's `keys.0` names as its inbox names the new one
// in the same commit, so grants reach it there (a replaced label is not synced).
#[test]
fn a_replaced_inbox_is_named_again_spec_sync_2() {
    let (mut net, _, a, b, _, bob, g, home) = alice_and_bob();
    let d = net.engine(b).account().unwrap().unwrap().1;
    let (new, acts) = net.sync(b).replace_label(&d, &home).unwrap();
    net.actions(b, acts);
    net.run();
    net.pair(b, a);
    for n in [a, b] {
        assert_eq!(net.engine(n).inbox_of_actor(&bob).unwrap().map(|(_, i)| i.label), Some(new), "node {n}");
    }
    grant(&mut net, a, g, bob);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
}

// spec/sync.md §2 (one sync ID per actor): a shared thing costs one sync ID and one commit of about
// the same size, however many this node already has.
#[test]
fn a_sync_id_costs_the_same_at_any_count_spec_sync_2() {
    let (mut net, _, a, _, alice, bob, _, _) = alice_and_bob();
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let per = |net: &mut Net, n: usize| {
        let before = net.sync(a).labels().len();
        let mut bytes = 0usize;
        for _ in 0..n {
            let e = net.engine(a);
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, alice);
            m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
            e.commit(m).unwrap();
            e.grant(&t, &bob, &edge).unwrap();
            let c = e.aspect_commit(&t, "label.0").unwrap().0;
            assert_eq!(e.aspect_commit(&t, "keys.0").map(|x| x.0), Some(c), "secrets and sync ID in one commit");
            bytes += e.commit_bytes(&c).unwrap().unwrap().len();
        }
        assert_eq!(net.sync(a).labels().len() - before, n, "one sync ID per thing shared");
        bytes / n
    };
    let small = per(&mut net, 4);
    let large = per(&mut net, 40);
    assert!(large <= small + small / 5, "per sync ID {small} B at 4, {large} B at 40");
}

// spec/sync.md §2 (inbox): an admin of another actor may write any sync ID as its inbox. Alice's
// group M, which Bob reads, names Bob's inbox; a blob sealed to Bob under his inbox still opens
// for him.
#[test]
fn an_actor_naming_someone_elses_inbox_hides_nothing_spec_sync_2() {
    let (mut net, _, a, b, alice, bob, _, _) = alice_and_bob();
    let m = loop {
        let e = net.engine(a);
        let mut w = Mutation::new();
        let m = e.new_thing(&mut w, alice);
        w.set(m, &ct::GROUP, &ct::Group::default()).unwrap();
        e.commit(w).unwrap();
        if m > bob {
            break m;
        }
    };
    grant(&mut net, a, m, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&m), Some(Role::Read));
    let inbox = net.engine(b).get_typed(&bob, &ct::KEYS).unwrap().and_then(|k| k.inbox).unwrap();
    let mut w = Mutation::new();
    w.op(m, &ct::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(4)], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&Some(inbox.clone()))) }).unwrap();
    net.engine(a).commit(w).unwrap();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).inbox(&m), Some(inbox.label), "Bob holds M's new inbox");
    let e = net.engine(a);
    let mut w = Mutation::new();
    let t = e.new_thing(&mut w, alice);
    w.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(w).unwrap();
    grant(&mut net, a, t, bob);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&t), Some(Role::Read), "his inbox still opens for him");
}

// spec/sync.md §3: a grant deposited under Bob's inbox after he replaced it, by a sender still
// holding his earlier `keys.0`, is read by nobody there: once the sender sees the new inbox it
// sends again at once (one re-send per replacement it sees, none for another `keys.0` change),
// not after `INBOX_LIFETIME`.
#[test]
fn a_delivery_under_a_replaced_inbox_is_sent_again_spec_sync_3() {
    let (mut net, _, a, b, _, bob, g, home) = alice_and_bob();
    let d = net.engine(b).account().unwrap().unwrap().1;
    let (new, acts) = net.sync(b).replace_label(&d, &home).unwrap();
    net.actions(b, acts);
    net.run();
    grant(&mut net, a, g, bob);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), None, "nobody reads the replaced inbox");
    let sent = net.sync(a).inbox_deliveries(&bob);
    assert!(matches!(sent.as_slice(), [(_, 0, Some(l))] if *l == home), "{sent:?}");
    net.pair(b, a);
    for _ in 0..4 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).role_on(&g), Some(Role::Read));
    let sent = net.sync(a).inbox_deliveries(&bob);
    assert!(matches!(sent.as_slice(), [(_, 1, Some(l))] if *l == new), "one re-send: {sent:?}");
    // a start looks at every holder: one still under its inbox is not sent again
    net.restart(a, 7);
    net.advance(70_000);
    let sent = net.sync(a).inbox_deliveries(&bob);
    assert!(matches!(sent.as_slice(), [(_, 1, Some(l))] if *l == new), "no re-send at a start: {sent:?}");
    // churn: each replacement the sender sees costs one re-send, within `MAX_INBOX_RESENDS` in all
    let mut l = new;
    for n in 2..=4u32 {
        let (next, acts) = net.sync(b).replace_label(&d, &l).unwrap();
        net.actions(b, acts);
        net.run();
        net.pair(b, a);
        for _ in 0..2 {
            net.advance(70_000);
        }
        l = next;
        let sent = net.sync(a).inbox_deliveries(&bob);
        let want = if n <= 3 { vec![(n, Some(l))] } else { Vec::new() };
        assert_eq!(sent.iter().map(|x| (x.1, x.2)).collect::<Vec<_>>(), want, "replacement {n}");
    }
}
