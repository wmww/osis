#![allow(clippy::unwrap_used)]
//! Accounts signing and being sealed to (spec/crypto.md §3, §4, spec/wire.md §4).

use super::members::keysets_of;
use crate::flows::CreatedAccount;
use crate::local_peer::LocalPeer;
use crate::Ingested;
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Ts, WallMs};
use osis_commit::{AccountSigner, AspectWrite, CommitBlob, CommitBuilder, FIRST_EPOCH, Form, Kind, MemoryBlobs, RotationHeader, writer_ctx};
use osis_crdt::{Delta, Source, Writer, create, encode_delta};
use osis_crypto::{AccountEpochKeys, Secret32};
use osis_keys::{account_epoch, stale};
use osis_schema::Codec;
use std::collections::BTreeSet;

/// `n` fresh peers (`LocalPeer::new`, seed 0), not synced: built once per test process, each
/// caller handed a copy.
fn peers(n: usize) -> LocalPeer {
    LocalPeer::cached(&format!("rotation::tests_account::peers/{n}"), || (LocalPeer::new(n, 0, super::tests::T0).unwrap(), ())).0
}

fn created(lp: &mut LocalPeer) -> (CreatedAccount, Vec<u8>) {
    let (a, done) = lp.peers[0].engine.create_account().unwrap();
    let bytes = lp.peers[0].engine.commit_bytes(&done.commits[0]).unwrap().unwrap();
    (a, bytes)
}

// spec/wire.md §4, spec/crypto.md §3: the commit creating an account names it as author and verifies at an outsider, who cannot open the inner signature
#[test]
fn account_created_commit_verifies_at_an_outsider_spec_wire_4() {
    let mut lp = peers(2);
    let me = lp.peers[0].engine.tid();
    let (a, bytes) = created(&mut lp);
    let blob = CommitBlob::decode(&bytes).unwrap();
    assert_eq!((blob.header.author, blob.header.epoch), (a.account, Some(FIRST_EPOCH)));
    assert_eq!(lp.peers[0].engine.open_inner(&blob), Some(me), "the creator opens its own");
    assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(lp.peers[1].engine.open_inner(&blob), None);
}

// spec/crypto.md §3, spec/data-model.md §9: a sibling granted on D takes the seed from `account.0`, opens the inner signature and signs as the account; an outsider opens neither
#[test]
fn sibling_opens_the_inner_signature_spec_crypto_3() {
    let mut lp = peers(3);
    let (me, sib) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let (a, bytes) = created(&mut lp);
    let blob = CommitBlob::decode(&bytes).unwrap();
    let both = |lp: &mut LocalPeer| {
        lp.sync(0, 1).unwrap();
        lp.sync(1, 0).unwrap();
    };
    both(&mut lp);
    let edge = osis_schema::core_types::Edge { role: Role::Admin, until: None, invite: None, tied: None, floor: None };
    lp.peers[0].engine.grant_as(&a.account, &a.devices, &sib, &edge).unwrap();
    both(&mut lp);
    lp.peers[1].engine.hold_account(&a.account, &a.devices).unwrap();
    assert_eq!(lp.peers[1].engine.open_inner(&blob), Some(me));
    let mut m = crate::Mutation::new();
    m.sign_as(a.account);
    m.set(a.profile, &osis_schema::core_types::GROUP, &Default::default()).unwrap();
    let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
    let b = CommitBlob::decode(&lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap()).unwrap();
    assert_eq!(b.header.author, a.account);
    both(&mut lp);
    assert_eq!(lp.peers[0].engine.open_inner(&b), Some(sib));
    assert_eq!(lp.peers[2].engine.open_inner(&b), None);
    // the node signing is not in what any reader of the commit gets: only sealed in `inner`
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let clear = lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap();
    assert!(!contains(&clear, sib.as_bytes()), "a commit as a node holds it names no node");
    // an outsider receives what labels carry: the creation commit sealed, D's seed under D's read secret
    let creation = blob.header.id();
    let sealed = lp.sealed(0, &[creation]).unwrap();
    assert!(!sealed.is_empty());
    let seed = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().keys.values().next().unwrap().seed().expose().to_owned();
    for (_, b) in sealed.iter().flat_map(|p| &p.blobs) {
        assert!(!contains(b, &seed), "the seed is sealed");
        assert!(!contains(b, me.as_bytes()), "the node is sealed");
    }
    let unopened = lp.deliver_sealed(2, &sealed).unwrap();
    assert_eq!(unopened, vec![creation], "no section opens for an outsider");
    assert!(lp.peers[2].engine.get_typed(&a.devices, &osis_schema::core_types::ACCOUNT).unwrap().is_none());
    assert!(lp.peers[2].engine.hold_account(&a.account, &a.devices).is_err(), "an outsider reads no seed");
}

struct Dedup(CreationRecord, osis_crypto::VerifyingKey);
impl osis_commit::Secrets for Dedup {
    fn dedup(&self, t: &Tid) -> Option<Secret32> {
        (self.0.tid() == *t).then(|| osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(self.1)
    }
    fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(self.1)
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(self.1)
    }
}

/// A rotation of the account of record `rec` from its first epoch to `next`, superseding that
/// epoch alone: what a node removed at the first epoch can make after every merge.
pub(super) fn rotation(rec: CreationRecord, first: &AccountEpochKeys, next: &AccountEpochKeys, ts: Ts) -> Vec<u8> {
    let header = RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![FIRST_EPOCH], names: Vec::new(), takes: Vec::new(), removals: Vec::new(), list_root: [0; 32] };
    rotation_at(rec, (FIRST_EPOCH, first), &[], next, header, ts)
}

/// A rotation of the account of record `rec` to `next`, signed at epoch `at` (its keys) and at
/// each fork of `forks` (named in `header`, in its order), sealed as a key actor made up.
pub(super) fn rotation_at(rec: CreationRecord, at: (CommitId, &AccountEpochKeys), forks: &[&AccountEpochKeys], next: &AccountEpochKeys, header: RotationHeader, ts: Ts) -> Vec<u8> {
    let (epoch, first) = at;
    let p = rec.tid();
    let ak = Ak::new("keys.0").unwrap();
    let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, p, p, Form::Commit);
    let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1);
    let f = create(&mut w, &view, &osis_keys::aspects::account_keys(next).to_value()).unwrap();
    let r = w.range();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Form::Commit, Kind::Role, ts, p, r.lo, r.hi), None).unwrap();
    let mut aw = AspectWrite::new(p, ak.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
    cb.aspects.push(aw);
    let node = osis_crypto::KeyActorKeys::from_seed(&Secret32::from_bytes([9; 32]));
    cb.account = Some(AccountSigner { epoch, inner: first.inner.clone(), node: Tid::from_bytes([9; 15]), node_key: node.signing });
    cb.rotation = Some((header, forks.iter().map(|k| k.signing.clone()).collect()));
    cb.build(&first.signing, &Dedup(rec, first.signing.verifying_key()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit.encode()
}

// spec/crypto.md §4 (Account keysets): at an outsider holding the rotation, a box naming the closed first epoch reads stale and the new epoch does not; the keyset rule reads the public name alone
#[test]
fn box_to_a_closed_epoch_reads_stale_spec_crypto_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    let rec = e.core.created(&a.account).unwrap().clone();
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([77; 32]));
    let first_name = account_epoch(0, &first.signing.verifying_key()).unwrap();
    let next_name = account_epoch(1, &next.signing.verifying_key()).unwrap();
    let none = BTreeSet::new();
    let e = &mut lp.peers[1].engine;
    let ks = e.run(|tx| keysets_of(tx, &a.account, Role::Read, None)).unwrap();
    assert!(!stale(&first_name, &ks, &none), "open before the rotation");
    let ts = Ts::make(e.now(), 0).unwrap();
    assert!(matches!(e.ingest(&rotation(rec, &first, &next, ts), Vec::new()).unwrap(), Ingested::Applied(_)));
    let ks = e.run(|tx| keysets_of(tx, &a.account, Role::Read, None)).unwrap();
    assert!(stale(&first_name, &ks, &none));
    assert!(!stale(&next_name, &ks, &none));
    assert_eq!(osis_keys::seal_keyset(&ks, &[first_name].into(), &none, &Default::default()), osis_keys::Seal::At([next_name].into()), "sealed at the open epoch");
}

// spec/sync-opens.md §2: an account's proof counts at an open epoch only: its first key alone while no
// rotation is held, the rotation's key and no longer the first once it is
#[test]
fn account_key_open_follows_the_rotations_held_spec_sync_10() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let record = lp.peers[0].engine.core.created(&a.account).cloned().unwrap();
    let CreationRecord::KeyActor { public_key, .. } = &record else { panic!("a key actor") };
    let first: [u8; 32] = public_key.as_slice().try_into().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.account_key_open(&record, &first), "an account not held: its first key");
    assert!(!e.account_key_open(&record, &[9; 32]), "any other key not");
    e.ingest(&bytes, Vec::new()).unwrap();
    assert!(e.account_key_open(&record, &first), "held: still open");
    let seed = Secret32::from_bytes([3; 32]);
    let (first_keys, next) = (AccountEpochKeys::from_seed(lp.peers[0].engine.core.accounts[&a.account].keys[&osis_crypto::VerifyingKey::from_bytes(&first).unwrap()].seed()), AccountEpochKeys::from_seed(&seed));
    let rot = rotation(record.clone(), &first_keys, &next, Ts::make(WallMs(1_700_000_000_100), 0).unwrap());
    let e = &mut lp.peers[1].engine;
    e.ingest(&rot, Vec::new()).unwrap();
    assert!(!e.account_key_open(&record, &first), "a rotation closes the first");
    assert!(e.account_key_open(&record, &next.signing.verifying_key().to_bytes()), "the new epoch");
}

// spec/permissions.md §5.4, spec/crypto.md §4 (Account keysets), §7: a reader outside the
// account holding two rotations of one epoch follows the one it came to hold first (received in
// one millisecond: the lower ID): it alone is open, a box to the account is sealed at it, the
// first epoch's box and the other fork's are stale, the delete key is its; a fork nothing
// rejects tells nothing
#[test]
fn forked_account_reads_the_head_held_first_spec_permissions_5_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let (x, y) = (AccountEpochKeys::from_seed(&Secret32::from_bytes([70; 32])), AccountEpochKeys::from_seed(&Secret32::from_bytes([71; 32])));
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    let mut ids = Vec::new();
    for k in [&x, &y] {
        let r = rotation(rec.clone(), &first, k, ts);
        ids.push(CommitBlob::decode(&r).unwrap().id());
        assert!(matches!(e.ingest(&r, Vec::new()).unwrap(), Ingested::Applied(_)));
    }
    let v = e.core.account_view(&a.account).unwrap();
    let preferred = v.preferred();
    assert_eq!(preferred, *ids.iter().min().unwrap());
    assert_eq!(v.heads(), vec![preferred]);
    assert!(ids.iter().all(|h| v.is_open(h) == (*h == preferred)), "the other fork is closed");
    let (keys, other) = if preferred == ids[0] { (&x, &y) } else { (&y, &x) };
    let name = |k: &AccountEpochKeys, h: u64| account_epoch(h, &k.signing.verifying_key()).unwrap();
    let (none, ks) = (BTreeSet::new(), e.run(|tx| keysets_of(tx, &a.account, Role::Read, None)).unwrap());
    assert_eq!(osis_keys::seal_keyset(&ks, &none, &none, &Default::default()), osis_keys::Seal::At([name(keys, 1)].into()), "sealed at the head followed");
    assert!(stale(&name(&first, 0), &ks, &none) && !stale(&name(keys, 1), &ks, &none) && stale(&name(other, 1), &ks, &none));
    assert_eq!(e.core.account_delete_key(&a.account).unwrap(), keys.signing.verifying_key());
    assert!(e.account_disputes().is_empty(), "a fork nothing rejects tells nothing");
}

fn edge(r: Role) -> osis_schema::core_types::Edge {
    osis_schema::core_types::Edge { role: r, until: None, invite: None, tied: None, floor: None }
}

/// An actor of peer 1 with secrets of its own.
fn actor_of(lp: &mut LocalPeer, a: &Tid) -> Tid {
    let e = &mut lp.peers[1].engine;
    let me = e.me();
    let mut m = crate::Mutation::new();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    let keep = edge(Role::Read);
    e.grant(&t, a, &keep).unwrap();
    t
}

// spec/crypto.md §4 (Seal), §3: a grant to an account is boxed at its open epoch by that epoch's public keys, not its first
#[test]
fn grant_boxes_at_the_open_epoch_spec_crypto_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([77; 32]));
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    assert!(matches!(e.ingest(&rotation(rec, &first, &next, ts), Vec::new()).unwrap(), Ingested::Applied(_)));
    let t = actor_of(&mut lp, &a.account);
    let e = &mut lp.peers[1].engine;
    let name = account_epoch(1, &next.signing.verifying_key()).unwrap();
    let s = e.run(|tx| crate::flows::secrets_in(tx, &t)).unwrap();
    let named: Vec<_> = s.boxes.iter().filter(|(k, _)| k.holder == a.account).map(|(_, b)| osis_keys::box_keysets(b)).collect();
    assert!(!named.is_empty() && named.iter().all(|x| *x == [name]), "{named:?}");
    let key = e.run(|tx| crate::flows::sync_ids::reader_key(tx, &a.account)).unwrap();
    match key {
        Some(crate::flows::sync_ids::ReaderKey::Dh(x)) => assert_eq!(x, next.kem.public().x25519(), "the open epoch's key"),
        _ => panic!("a claim key"),
    }
}

// spec/crdt.md §2.2: one node signing as two accounts writes under nonces no reader can link
#[test]
fn two_accounts_of_one_node_have_unlinked_sessions_spec_crdt_2() {
    let mut lp = peers(1);
    let write = |lp: &mut LocalPeer, a: &CreatedAccount, v: i64| {
        let mut m = crate::Mutation::new();
        m.sign_as(a.account);
        m.set(a.profile, &Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(v)).unwrap();
        let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
        lp.peers[0].engine.header(&c).unwrap().form
    };
    let (x, _) = lp.peers[0].engine.create_account().unwrap();
    let (y, _) = lp.peers[0].engine.create_account().unwrap();
    let (fx, fy) = (write(&mut lp, &x, 1), write(&mut lp, &y, 1));
    let own = lp.peers[0].engine.core.session.nonce;
    let (Form::Session(nx), Form::Session(ny)) = (fx, fy) else { panic!("session form") };
    assert_ne!(nx, ny);
    assert_ne!(nx, own);
    assert_ne!(nx[8..], ny[8..], "no half of the nonce is shared between accounts");
    assert_ne!(nx[8..], own[8..], "nor with the node's own session");
    assert_eq!(write(&mut lp, &x, 2), Form::Session(nx), "one session per account and open");
    // a session of this open stays recognised through the steps of `fresh_session`, per signer
    let core = &mut lp.peers[0].engine.core;
    assert!(core.own_plain(&x.account, &nx) && !core.own_plain(&y.account, &nx));
    core.fresh_session();
    let next = core.nonce_as(&x.account, core.session.nonce);
    assert_ne!(next, nx);
    assert!(core.own_plain(&x.account, &nx) && core.own_plain(&x.account, &next));
    // what an account's fallen write starts anew: its session is among the current ones, a stepped one's is not
    assert!(core.current_sessions().contains(&next) && !core.current_sessions().contains(&nx));
}

// spec/crdt.md §2.2: every start of a node draws new sessions, so no account's nonce (dots, counters) is reused across a restart
#[test]
fn account_session_nonce_is_new_after_a_restart_spec_crdt_2() {
    let mut lp = peers(1);
    let (a, _) = lp.peers[0].engine.create_account().unwrap();
    let nonce = |lp: &LocalPeer| {
        let c = &lp.peers[0].engine.core;
        c.nonce_as(&a.account, c.session.nonce)
    };
    let before = nonce(&lp);
    lp.peers[0].restart(0).unwrap();
    assert_ne!(nonce(&lp), before);
}

// spec/crypto.md §4 (Carried): a box at an account's new epoch carries that epoch's rotation
#[test]
fn a_box_at_an_account_epoch_carries_its_rotation_spec_crypto_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([80; 32]));
    let e = &mut lp.peers[1].engine;
    e.ingest(&bytes, Vec::new()).unwrap();
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    let rot = rotation(rec, &first, &next, ts);
    let id = CommitBlob::decode(&rot).unwrap().header.id();
    e.ingest(&rot, Vec::new()).unwrap();
    let t = actor_of(&mut lp, &a.account);
    let e = &mut lp.peers[1].engine;
    let s = e.run(|tx| crate::flows::secrets_in(tx, &t)).unwrap();
    let w = osis_keys::SecretsWrite { boxes: s.boxes.iter().filter(|(k, _)| k.holder == a.account).map(|(k, b)| (k.clone(), b.clone())).collect(), removed: Default::default(), history: Default::default(), sealed: Default::default() };
    assert_eq!(crate::rotation::members::carried(&e.core, &w, None), vec![id], "the box's epoch travels with it");
}

// the signing chain is built once per change of what it is built from (the rotations, the seeds
// held, the roster), whatever the writes between
#[test]
fn account_view_is_built_once_per_rotation() {
    let mut lp = peers(1);
    let (a, _) = lp.peers[0].engine.create_account().unwrap();
    let write = |lp: &mut LocalPeer| {
        let mut m = crate::Mutation::new();
        m.sign_as(a.account);
        m.set(a.profile, &osis_schema::core_types::GROUP, &Default::default()).unwrap();
        lp.peers[0].engine.commit(m).unwrap();
    };
    write(&mut lp);
    let builds = || osis_base::costs::take().into_iter().filter(|x| x.0 == "account view").map(|x| x.2).sum::<u64>();
    builds();
    for _ in 0..50 {
        write(&mut lp);
    }
    assert_eq!(builds(), 0, "no write rebuilds it");
    // a rotation builds it once (the epoch rule judges it on arrival), however many reads follow
    let e = &mut lp.peers[0].engine;
    let held = e.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([81; 32]));
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    builds();
    e.ingest(&rotation(rec, &first, &next, ts), Vec::new()).unwrap();
    // minted by no node of the account (no inner signature): the node disregards it
    assert!(e.core.accounts.contains_key(&a.account), "a rotation no node of the account made moves nothing");
    for _ in 0..5 {
        assert_eq!(e.core.account_delete_key(&a.account).unwrap(), first.signing.verifying_key());
    }
    assert_eq!(builds(), 2, "once for the rotation, once as the judgment it moved is read");
}

// spec/sync-inbox.md §2 (invite request): the request gate reads an author's signature at the header's epoch: a commit signed at the first epoch verifies only there
#[test]
fn request_gate_reads_the_header_epoch_spec_sync_3() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([79; 32]));
    let e = &mut lp.peers[1].engine;
    e.ingest(&bytes, Vec::new()).unwrap();
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    let rot = rotation(rec, &first, &next, ts);
    e.ingest(&rot, Vec::new()).unwrap();
    let blob = CommitBlob::decode(&rot).unwrap();
    let id = blob.header.id();
    let core = &e.core;
    assert!(crate::apply::signed_at(core, &id, &a.account, Some(FIRST_EPOCH), &blob.sigs));
    assert!(!crate::apply::signed_at(core, &id, &a.account, Some(id), &blob.sigs), "not at the epoch it mints");
    assert!(!crate::apply::signed_at(core, &id, &a.account, None, &blob.sigs), "an account's commit names its epoch");
}

// spec/crdt.md §2.2: a commit more than `MAX_DRIFT` ahead waits, also when its author is this
// node's own account: only what this node itself writes is exempt
#[test]
fn a_siblings_far_future_commit_waits_spec_crdt_2_2() {
    let mut lp = peers(2);
    let sib = lp.peers[1].engine.tid();
    let (a, _) = created(&mut lp);
    let both = |lp: &mut LocalPeer| {
        lp.sync(0, 1).unwrap();
        lp.sync(1, 0).unwrap();
    };
    both(&mut lp);
    let edge = osis_schema::core_types::Edge { role: Role::Admin, until: None, invite: None, tied: None, floor: None };
    lp.peers[0].engine.grant_as(&a.account, &a.devices, &sib, &edge).unwrap();
    both(&mut lp);
    lp.peers[1].engine.hold_account(&a.account, &a.devices).unwrap();
    lp.peers[1].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let mut m = crate::Mutation::new();
    m.sign_as(a.account);
    m.set(a.profile, &osis_schema::core_types::GROUP, &Default::default()).unwrap();
    let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[1].engine.header(&c).unwrap().author, a.account);
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    assert!(matches!(lp.deliver(0, &pk).unwrap(), Ingested::Pending(_, crate::apply::Reason::Drift)));
    lp.peers[0].clock.advance(osis_base::format::MAX_DRIFT_MS + 1);
    lp.peers[0].tick().unwrap();
    assert!(lp.peers[0].engine.pending().is_empty(), "it applies once within the bound");
}

/// `peers(3)` synced; peer 1 makes thing `t` (`x:a.0` = 0) and grants peer 0's account admin;
/// peer 0's account writes `x:a.0` = 1 there (`c`) and grants peer 2's account write (`g`);
/// all synced. Returns (lp, account, t, c, g) and the rotation of the account closing its first
/// epoch, as peer 1 would receive it.
fn closed_world() -> (LocalPeer, Tid, Tid, CommitId, CommitId, Vec<u8>) {
    let (lp, (a, t, c, g, rot)) = LocalPeer::cached("rotation::tests_account::closed_world", || {
        let mut lp = peers(3);
        // the addenda here are the tests' own
        for p in &mut lp.peers {
            p.engine.core.addenda_on = false;
        }
        lp.sync_all().unwrap();
        let (a, z) = (lp.peers[0].engine.me(), lp.peers[2].engine.me());
        let me = lp.peers[1].engine.me();
        let mut m = crate::Mutation::new();
        let t = lp.peers[1].engine.new_thing(&mut m, me);
        m.set(t, &Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(0)).unwrap();
        lp.peers[1].commit(m).unwrap();
        lp.peers[1].engine.grant(&t, &a, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        let mut m = crate::Mutation::new();
        m.set(t, &Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let g = *lp.peers[0].engine.grant(&t, &z, &edge(Role::Write)).unwrap().commits.last().unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        let e = &lp.peers[0].engine;
        let first = AccountEpochKeys::from_seed(e.core.accounts[&a].keys.values().next().unwrap().seed());
        let rot = rotation(e.core.created(&a).unwrap().clone(), &first, &AccountEpochKeys::from_seed(&Secret32::from_bytes([90; 32])), Ts::make(e.now(), 0).unwrap());
        (lp, (a, t, c, g, rot))
    });
    (lp, a, t, c, g, rot)
}

/// An addendum on `t` by `peer` against rotation `r` listing `lists`.
fn addendum(lp: &mut LocalPeer, peer: usize, t: Tid, r: CommitId, lists: &[CommitId]) {
    let mut mu = crate::Mutation::new();
    let f = osis_schema::core_types::Frontier { commits: lists.iter().copied().collect() };
    mu.op(t, &osis_schema::core_types::ADDENDA, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::bytes(&r.0))], op: osis_crdt::Op::Put(f.to_value()) }).unwrap();
    lp.peers[peer].commit(mu).unwrap();
}

// spec/permissions.md §5.5 (epoch rule; addenda against a rotation): once an outsider holds a
// rotation closing an account's epoch, the account's write there reads as absent and its grant
// gives nothing; a writer's addendum against the rotation listing both brings the write back,
// never the grant; a restart reads the same
#[test]
fn closed_epoch_write_falls_and_a_witness_saves_it_spec_permissions_5_5() {
    let (mut lp, a, t, c, g, rot) = closed_world();
    let r = CommitBlob::decode(&rot).unwrap().header.id();
    let z = lp.peers[2].engine.me();
    let x = Ak::new("x:a.0").unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.get(&t, &x).unwrap(), Some(osis_base::Value::Int(1)));
    assert_eq!(e.core.role_now(&z, &t), Some(Role::Write));
    assert!(matches!(e.ingest(&rot, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(e.get(&t, &x).unwrap(), Some(osis_base::Value::Int(0)), "the account's write at the closed epoch reads as absent");
    assert_eq!(e.core.role_now(&z, &t), None, "its grant there gives nothing");
    assert_eq!(e.core.role_now(&a, &t), Some(Role::Admin), "another's grant to the account stands");
    let d0 = e.index_digest();
    e.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&e.index_digest()), None, "rebuilt");
    addendum(&mut lp, 1, t, r, &[c, g]);
    // the write's body went with its fall; valid again, it is fetched again
    lp.sync(0, 1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.get(&t, &x).unwrap(), Some(osis_base::Value::Int(1)), "the witness's addendum saves the write");
    assert_eq!(e.core.role_now(&z, &t), None, "an addendum saves plain content only");
    lp.peers[1].restart(0).unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!((e.get(&t, &x).unwrap(), e.core.role_now(&z, &t)), (Some(osis_base::Value::Int(1)), None));
}

// spec/permissions.md §5.5: an addendum against a rotation that closes nothing the commit is
// signed at, or by a reader of the thing, saves nothing
#[test]
fn addendum_saves_only_against_a_closer_by_a_writer_spec_permissions_5_5() {
    let (mut lp, _, t, c, _, rot) = closed_world();
    let x = Ak::new("x:a.0").unwrap();
    assert!(matches!(lp.peers[1].engine.ingest(&rot, Vec::new()).unwrap(), Ingested::Applied(_)));
    addendum(&mut lp, 1, t, CommitId([3; 32]), &[c]);
    assert_eq!(lp.peers[1].engine.get(&t, &x).unwrap(), Some(osis_base::Value::Int(0)), "keyed by no closer");
    // peer 2 holds write on `t` only through the account's grant, which falls at peer 1
    let r = CommitBlob::decode(&rot).unwrap().header.id();
    addendum(&mut lp, 2, t, r, &[c]);
    lp.sync(2, 1).unwrap();
    lp.sync(0, 1).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &x).unwrap(), Some(osis_base::Value::Int(0)), "no writer's word");
}

// spec/permissions.md §5.5, notes/api-design.md (Fast by construction): a rotation re-judges the
// commits signed at the epochs it moved, once; a later write by anyone re-judges none of the
// account's history and builds no signing chain
#[test]
fn rotation_judges_its_epochs_once_and_writes_stay_flat() {
    let count = |n: usize| {
        let (mut lp, _, t, _, _, rot) = closed_world();
        for i in 0..n {
            let mut m = crate::Mutation::new();
            m.set(t, &Ak::new("x:b.0").unwrap(), &osis_base::Value::Int(i as i64)).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
        lp.sync_all().unwrap();
        let e = &mut lp.peers[1].engine;
        osis_base::costs::take();
        e.ingest(&rot, Vec::new()).unwrap();
        let judged = |c: Vec<(&'static str, std::time::Duration, u64)>| c.into_iter().find(|x| x.0 == "rejudge: a commit").map_or(0, |x| x.2);
        let on_rotation = judged(osis_base::costs::take());
        let mut m = crate::Mutation::new();
        m.set(t, &Ak::new("x:c.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
        lp.peers[1].commit(m).unwrap();
        let costs = osis_base::costs::take();
        (on_rotation, judged(costs.clone()), costs.iter().filter(|x| x.0 == "account view").map(|x| x.2).sum::<u64>())
    };
    let (small, large) = (count(5), count(50));
    assert!(large.0 >= 45 && large.0 <= small.0 + 50, "a rotation judges its epoch's commits: {small:?} {large:?}");
    assert_eq!((small.1, small.2), (large.1, large.2), "a write after it is flat in the account's history");
    assert_eq!(large.2, 0, "and builds no signing chain");
}

// spec/permissions.md §5.5 (addenda against a rotation): every arrival order: a witness's addendum held before the rotation
// it is keyed by saves the write as one held after it does; reopened and rebuilt, the index
// reads the same
#[test]
fn witness_before_its_rotation_saves_alike_and_reopens_alike_spec_permissions_5_5() {
    let (mut lp, _, t, c, _, rot) = closed_world();
    let r = CommitBlob::decode(&rot).unwrap().header.id();
    let x = Ak::new("x:a.0").unwrap();
    addendum(&mut lp, 1, t, r, &[c]);
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&rot, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(e.get(&t, &x).unwrap(), Some(osis_base::Value::Int(1)), "saved by the addendum held first");
    let d0 = e.index_digest();
    e.reload().unwrap();
    assert_eq!(d0.first_diff(&e.index_digest()), None, "reopened");
    e.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&e.index_digest()), None, "rebuilt");
    assert_eq!(e.get(&t, &x).unwrap(), Some(osis_base::Value::Int(1)));
}

// spec/permissions.md §5.5 (a commit that does not count is invalid whole), spec/sync-compaction.md §2: a
// signal the account fired at an epoch closed where it arrives is not delivered there
#[test]
fn signal_at_a_closed_epoch_is_not_delivered_spec_permissions_5_5() {
    let (mut lp, _, t, _, _, rot) = closed_world();
    let ring = |lp: &mut LocalPeer| {
        let e = &mut lp.peers[0].engine;
        let ts = e.core.hlc.next();
        let f = crate::engine::write::run_ops(&osis_crdt::Fragment::default(), Writer::new(ts, Source::session(e.core.session), 1), &[osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Set(osis_base::Value::Int(1)) }], &osis_crdt::AnyView).unwrap().unwrap().0;
        e.build_relay(e.me(), ts, vec![(t, Ak::new("x:ring+~0").unwrap(), f)]).unwrap()
    };
    let mut cs = vec![ring(&mut lp), ring(&mut lp)];
    let e = &mut lp.peers[1].engine;
    e.watch_commits();
    let fired = |lp: &LocalPeer| lp.peers[1].drain_events().into_iter().filter(|v| matches!(v, crate::events::Event::Commits(cs) if cs.iter().any(|c| c.fired.is_some()))).count();
    lp.peers[1].drain_events();
    assert!(lp.peers[1].engine.ingest_relay_blob(cs.remove(0).blob).unwrap());
    assert_eq!(fired(&lp), 1, "delivered at the open epoch");
    assert!(matches!(lp.peers[1].engine.ingest(&rot, Vec::new()).unwrap(), Ingested::Applied(_)));
    lp.peers[1].drain_events();
    lp.peers[1].engine.ingest_relay_blob(cs.remove(0).blob).unwrap();
    assert_eq!(fired(&lp), 0, "not once the epoch is closed");
}

// spec/sync-opens.md §2 (its account by a signature at an epoch), spec/wire.md §11.2 (Prove): a
// node of an account gives every held rotation as a header-only copy, each epoch's minting
// rotation first; a verifier holding the account's record takes them, its new key open there; one taken without
// the rotation minting the epoch it is signed at keeps nothing (nothing carries it).
#[test]
fn prove_rotations_are_taken_by_a_verifier_spec_sync_opens_2() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let p = a.account;
    let r1 = lp.peers[0].engine.rotate_account(&p).unwrap().unwrap();
    let r2 = lp.peers[0].engine.rotate_account(&p).unwrap().unwrap();
    let given = lp.peers[0].engine.prove_rotations().unwrap();
    let ids: Vec<CommitId> = given.iter().map(|v| CommitBlob::decode(&osis_base::cbor::encode(v)).unwrap()).inspect(|c| assert!(c.parts.is_empty(), "a header-only copy")).map(|c| c.id()).collect();
    assert_eq!(ids, vec![r1, r2], "each minting rotation first");
    let record = lp.peers[0].engine.core.created(&p).cloned().unwrap();
    let key = lp.peers[0].engine.account_open_key().unwrap();
    let e = &mut lp.peers[1].engine;
    e.ingest(&bytes, Vec::new()).unwrap();
    e.take_rotations(vec![given[1].clone()]).unwrap();
    assert!(!e.pends(&r2) && e.header(&r2).is_none(), "one whose minting rotation is not held keeps nothing");
    assert!(!e.key_open(&record, &key));
    e.take_rotations(given).unwrap();
    assert!(e.header(&r1).is_some() && e.header(&r2).is_some(), "both taken");
    assert!(e.key_open(&record, &key), "the account's new key open at the verifier");
}

// spec/permissions.md §5.5 (Waiting): a node of the account holding a sibling's rotation
// without its thing list for D keeps every commit of the account on D at the closed epoch (D's
// roster, so it stays a node of the account); once that list arrives, the lists judge: what
// the rotator held stands, a write it never held falls.
#[test]
fn a_node_of_the_account_waits_for_d_s_list_spec_permissions_5_5() {
    let mut lp = peers(2);
    let sib = lp.peers[1].engine.tid();
    let (a, _) = created(&mut lp);
    let (p, d) = (a.account, a.devices);
    let both = |lp: &mut LocalPeer| {
        lp.sync(0, 1).unwrap();
        lp.sync(1, 0).unwrap();
    };
    both(&mut lp);
    let g = *lp.peers[0].engine.grant_as(&p, &d, &sib, &edge(Role::Admin)).unwrap().commits.last().unwrap();
    both(&mut lp);
    lp.peers[1].engine.hold_account(&p, &d).unwrap();
    // a write on D the rotator never holds
    let mut m = crate::Mutation::new();
    m.sign_as(p);
    m.set(d, &Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
    let x = lp.peers[1].engine.commit(m).unwrap().unwrap();
    let r = lp.peers[0].engine.rotate_account(&p).unwrap().unwrap();
    let lists = lp.peers[0].engine.list_blob(&r, Some(&[d].into())).unwrap().unwrap();
    let rots = lp.peers[0].engine.prove_rotations().unwrap();
    let e = &mut lp.peers[1].engine;
    e.take_rotations(rots).unwrap();
    assert!(e.header(&r).is_some(), "the rotation held");
    let counts = |e: &crate::Engine, c: &CommitId| e.core.counts_at_epoch(c, &p, e.header(c).and_then(|h| h.epoch));
    assert!(counts(e, &g) && counts(e, &x), "waiting for D's list: both stand");
    assert!(e.roster(&d).contains_key(&sib), "still a node of the account");
    assert_eq!(e.hold_lists(&lists).unwrap(), crate::flows::lists::ListsHeld::Held);
    assert!(counts(e, &g), "the list names the grant");
    assert!(!counts(e, &x), "the write the rotator never held falls");
    assert!(e.roster(&d).contains_key(&sib));
}

// spec/crypto.md §5 (Who wraps under what): an account rotation's own sections go under the
// epoch it supersedes, never the one it mints, so a sibling opens its keys.0 part from the
// blob that carries the new seed, before holding that seed
#[test]
fn a_sibling_opens_the_rotation_s_keys_before_its_seed_spec_crypto_5() {
    let mut lp = peers(2);
    let sib = lp.peers[1].engine.tid();
    let (a, _) = created(&mut lp);
    let (p, d) = (a.account, a.devices);
    let both = |lp: &mut LocalPeer| {
        lp.sync(0, 1).unwrap();
        lp.sync(1, 0).unwrap();
    };
    both(&mut lp);
    lp.peers[0].engine.grant_as(&p, &d, &sib, &edge(Role::Admin)).unwrap();
    both(&mut lp);
    lp.peers[1].engine.hold_account(&p, &d).unwrap();
    let r = lp.peers[0].engine.rotate_account(&p).unwrap().unwrap();
    let pks = lp.sealed(0, &[r]).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.account_open_key().is_some_and(|k| Some(k) != lp.peers[0].engine.account_open_key()), "the new seed not held");
    let e = &mut lp.peers[1].engine;
    for pk in &pks {
        e.open_package(pk).unwrap();
    }
    assert_eq!(e.commit_parts_missing().get(&r).map(|m| m.len()), Some(0), "both parts opened at once");
}
