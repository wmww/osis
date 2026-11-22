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
use super::tests::edge;

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
    assert_eq!((blob.header.signer, blob.header.epoch), (a.account, Some(FIRST_EPOCH)));
    assert_eq!(lp.peers[0].engine.open_inner(&blob), Some(me), "the creator opens its own");
    assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(lp.peers[1].engine.open_inner(&blob), None);
}

struct Dedup(CreationRecord, osis_crypto::VerifyingKey);
impl osis_commit::Secrets for Dedup {
    fn dedup(&self, t: &Tid) -> Option<Secret32> {
        (self.0.tid() == *t).then(|| osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(self.1)
    }
    fn purge_author_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(self.1)
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(self.1)
    }
}

/// A rotation of the account of record `rec` from its first epoch to `next`, superseding that
/// epoch alone: what a node removed at the first epoch can make after every merge.
pub(super) fn rotation(rec: CreationRecord, first: &AccountEpochKeys, next: &AccountEpochKeys, ts: Ts) -> Vec<u8> {
    let header = RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![FIRST_EPOCH], names: Vec::new(), takes: Vec::new(), revokes: false, devices: Vec::new(), list_root: [0; 32], seeds: Vec::new() };
    rotation_at(rec, (FIRST_EPOCH, first), &[], next, header, ts)
}

/// `rotation`, its header naming a removal no outsider holds: at an outsider it revokes the
/// first epoch (spec/permissions.md §5.5 Revoked), as the rotation removing a node does.
pub(super) fn revoking_rotation(rec: CreationRecord, first: &AccountEpochKeys, next: &AccountEpochKeys, ts: Ts) -> Vec<u8> {
    let header = RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![FIRST_EPOCH], names: Vec::new(), takes: Vec::new(), revokes: true, devices: Vec::new(), list_root: [0; 32], seeds: Vec::new() };
    rotation_at(rec, (FIRST_EPOCH, first), &[], next, header, ts)
}

/// A rotation of the account of record `rec` to `next`, signed at epoch `at` (its keys) and at
/// each fork of `forks` (named in `header`, in its order), sealed as a key actor made up.
pub(super) fn rotation_at(rec: CreationRecord, at: (CommitId, &AccountEpochKeys), forks: &[&AccountEpochKeys], next: &AccountEpochKeys, header: RotationHeader, ts: Ts) -> Vec<u8> {
    let (epoch, first) = at;
    let p = rec.tid();
    let ak = Ak::new("keys.0").unwrap();
    let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, p, osis_commit::Path::default(), Form::Commit);
    let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1);
    let f = create(&mut w, &view, &osis_keys::aspects::account_keys(next).to_value()).unwrap();
    let r = w.range();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Form::Commit, Kind::Role, ts, p, r.lo, r.hi), None).unwrap();
    let mut aw = AspectWrite::new(p, ak.clone(), r.lo, r.hi, bytes);
    aw.purge_by = osis_commit::retention::write_purge_by(ak.as_str(), None, None).unwrap();
    cb.aspects.push(aw);
    let node = osis_crypto::KeyActorKeys::from_seed(&Secret32::from_bytes([9; 32]));
    let more = forks.iter().map(|k| k.inner.clone()).chain([next.inner.clone()]).collect();
    cb.account = Some(AccountSigner { epoch, inner: first.inner.clone(), node: Tid::from_bytes([9; 15]), node_key: node.signing, more });
    cb.rotation = Some((header, forks.iter().map(|k| k.signing.clone()).collect()));
    cb.build(&first.signing, &Dedup(rec, first.signing.verifying_key()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit.encode()
}

/// Blob `b` (signed at the epoch keyed `at`) with its inner signature sealed as node `node`
/// (signing with `key`): under `at`, and a rotation's again under each of `more` (`Sigs::more`);
/// the account's signature over it again.
pub(super) fn seal_inner_as(b: &mut CommitBlob, at: &AccountEpochKeys, more: &[&Secret32], node: &Tid, key: &osis_crypto::SigningSecret) {
    let id = b.header.id();
    let inner = osis_crypto::seal_inner(&at.inner, &id.0, node, key);
    let more = more.iter().map(|k| osis_crypto::seal_inner(k, &id.0, node, key)).collect();
    b.sigs = osis_commit::Sigs::signed(&id, &at.signing, Some(inner), more, b.sigs.merge.clone());
}

// spec/crypto.md §4 (Account keysets), spec/permissions.md §5.5 (Revoked): at an outsider, a box
// naming the first epoch a plain rotation closed is not stale (no one left), one naming the
// epoch a revocation closed is, and the open epoch's is not; the seal goes at the open epoch.
// The keyset rule reads the public name and the header alone
#[test]
fn box_to_a_revoked_epoch_reads_stale_spec_crypto_4() {
    let none = BTreeSet::new();
    for revoking in [false, true] {
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
        let e = &mut lp.peers[1].engine;
        let ks = e.run(|tx| keysets_of(tx, &a.account, Role::Read, None)).unwrap();
        assert!(!stale(&first_name, &ks, &none), "open before the rotation");
        let ts = Ts::make(e.now(), 0).unwrap();
        let rot = if revoking { revoking_rotation(rec, &first, &next, ts) } else { rotation(rec, &first, &next, ts) };
        assert!(matches!(e.ingest(&rot, Vec::new()).unwrap(), Ingested::Applied(_)));
        let ks = e.run(|tx| keysets_of(tx, &a.account, Role::Read, None)).unwrap();
        assert_eq!(stale(&first_name, &ks, &none), revoking, "revoking {revoking}");
        assert!(!stale(&next_name, &ks, &none));
        assert_eq!(osis_keys::seal_keyset(&ks, &[first_name].into(), &none, &Default::default()), osis_keys::Seal::At([next_name].into()), "sealed at the open epoch");
    }
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
// account holding two revocations of one epoch follows the one it came to hold first (received in
// one millisecond: the lower ID): it alone is open, a box to the account is sealed at it, the
// first epoch's box (revoked) and the other fork's (not counting) are stale, the delete key is its; a fork nothing
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
        let r = revoking_rotation(rec.clone(), &first, k, ts);
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

/// An outsider holding a line of `n` rotations of an account from its first epoch, each removing
/// a device: the bytes of its judgment of the account as persisted (`node/epochs`), which every
/// rotation writes again.
fn judged_bytes(n: u8) -> usize {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    let rec = e.core.created(&a.account).unwrap().clone();
    let mut prev = (FIRST_EPOCH, AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed()));
    for i in 0..n {
        let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([i; 32]));
        let header = RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![prev.0], names: Vec::new(), takes: Vec::new(), revokes: true, devices: Vec::new(), list_root: [0; 32], seeds: Vec::new() };
        lp.advance(1);
        let e = &mut lp.peers[1].engine;
        let r = rotation_at(rec.clone(), (prev.0, &prev.1), &[], &next, header, Ts::make(e.now(), 0).unwrap());
        let id = CommitBlob::decode(&r).unwrap().id();
        assert!(matches!(e.ingest(&r, Vec::new()).unwrap(), Ingested::Applied(_)));
        prev = (id, next);
    }
    let e = &lp.peers[1].engine;
    assert_eq!(e.core.account_view(&a.account).unwrap().preferred(), prev.0, "the line counts");
    osis_base::encode(&e.core.ix.epochs.get(&a.account).unwrap().to_value()).len()
}

// spec/requirements.md Scale (no operation O(history)): what a rotation writes of an account's
// judgment grows with its rotations, not their square: at 10n revoking rotations it is near 10
// times that at n (each revoked epoch's standing is a fact of its own, never a list of the
// rotations closing it)
#[test]
fn a_rotations_judgment_grows_with_the_rotations_spec_permissions_5_5() {
    let (small, large) = (judged_bytes(8), judged_bytes(80));
    assert!(large <= 13 * small, "bytes at 10n: {large}, at n: {small}");
}

/// An independent actor of peer 1.
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
    let named: Vec<_> = s.boxes.iter().filter(|(k, _)| k.holder == osis_base::Weak(a.account)).map(|(_, b)| osis_keys::box_keysets(b)).collect();
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
    let w = osis_keys::SecretsWrite { boxes: s.boxes.iter().filter(|(k, _)| k.holder == osis_base::Weak(a.account)).map(|(k, b)| (k.clone(), b.clone())).collect(), removed: Default::default(), history: Default::default(), sealed: Default::default() };
    assert_eq!(crate::rotation::members::carried(&e.core, &w, None), vec![id], "the box's epoch travels with it");
}

// spec/wire.md §4 (the epoch an account signer signs at): the request gate reads a signer's signature at the header's epoch: a commit signed at the first epoch verifies only there
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

/// `peers(3)` synced; peer 1 makes thing `t` (`x:a.0` = 0) and grants peer 0's account admin;
/// peer 0's account writes `x:a.0` = 1 there (`c`) and grants peer 2's account write (`g`);
/// all synced. Returns (lp, account, t, c, g) and a rotation of the account revoking its first
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
        lp.hold(t);
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
        let rot = revoking_rotation(e.core.created(&a).unwrap().clone(), &first, &AccountEpochKeys::from_seed(&Secret32::from_bytes([90; 32])), Ts::make(e.now(), 0).unwrap());
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
// the rotation minting the epoch it is signed at keeps nothing and writes nothing (nothing carries it).
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
    let writes = e.store_writes().committed;
    e.take_rotations(vec![given[1].clone()]).unwrap();
    assert!(!e.pends(&r2) && e.header(&r2).is_none(), "one whose minting rotation is not held keeps nothing");
    assert_eq!(e.store_writes().committed, writes, "and writes nothing");
    assert!(!e.key_open(&record, &key));
    e.take_rotations(given).unwrap();
    assert!(e.header(&r1).is_some() && e.header(&r2).is_some(), "both taken");
    assert!(e.key_open(&record, &key), "the account's new key open at the verifier");
}

/// Rotation blob `bytes` as a Prove carries it: a header-only copy.
fn header_only(bytes: &[u8]) -> osis_base::Value {
    let pt = osis_commit::rewrite(&CommitBlob::decode(bytes).unwrap(), |_| true).encode();
    osis_base::cbor::decode(&pt, &osis_base::cbor::Limits::DEFAULT).unwrap()
}

fn rotation_to(next: &AccountEpochKeys, mut supersedes: Vec<CommitId>) -> RotationHeader {
    supersedes.sort();
    RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes, names: Vec::new(), takes: Vec::new(), revokes: false, devices: Vec::new(), list_root: [0; 32], seeds: Vec::new() }
}

/// A verifier holding account A's record and its rotation r1 (taken from A's Prove), and a
/// removed node X holding A's first epoch, which proves to it `n` times: each Prove a plain fork
/// beside r1, then a line of two whose tip rejects r1 (signed at the fork's epoch, superseding
/// r1). What the verifier holds after: its local rows by kind, the held rotations of A, and the
/// ones kept from X's Proves.
fn forks_proved(n: usize) -> (std::collections::BTreeMap<String, (usize, usize)>, usize, Vec<CommitId>) {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let p = a.account;
    let held = lp.peers[0].engine.core.accounts.get(&p).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let r1 = lp.peers[0].engine.rotate_account(&p).unwrap().unwrap();
    let given = lp.peers[0].engine.prove_rotations().unwrap();
    lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap();
    lp.peers[1].engine.take_rotations(given).unwrap();
    // held first: a later millisecond
    lp.peers[1].clock.advance(5);
    let e = &mut lp.peers[1].engine;
    assert!(e.core.account_view(&p).unwrap().rotation_counts(&r1));
    let rec = e.core.created(&p).unwrap().clone();
    let mut sent = Vec::new();
    for i in 0..n {
        let seed = |j: u8| AccountEpochKeys::from_seed(&Secret32::from_bytes([(i % 200) as u8, (i / 200) as u8, j, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]));
        let (k1, k2, k3) = (seed(1), seed(2), seed(3));
        let ts = Ts::make(e.now(), 0).unwrap();
        let plain = rotation_at(rec.clone(), (FIRST_EPOCH, &first), &[], &k1, rotation_to(&k1, vec![FIRST_EPOCH]), ts);
        e.take_rotations(vec![header_only(&plain)]).unwrap();
        let f = rotation_at(rec.clone(), (FIRST_EPOCH, &first), &[], &k2, rotation_to(&k2, vec![FIRST_EPOCH]), ts);
        let fid = CommitBlob::decode(&f).unwrap().id();
        let g = rotation_at(rec.clone(), (fid, &k2), &[], &k3, rotation_to(&k3, vec![fid, r1]), ts);
        e.take_rotations(vec![header_only(&f), header_only(&g)]).unwrap();
        sent.extend([&plain, &f, &g].map(|b| CommitBlob::decode(b).unwrap().id()));
    }
    let v = e.core.account_view(&p).unwrap();
    assert!(v.rotation_counts(&r1), "the honest rotation still counts");
    let kept = sent.into_iter().filter(|c| e.header(c).is_some()).collect();
    (e.local_census().unwrap(), v.rotation_ids().len(), kept)
}

// spec/sync-opens.md §2 (a verifier takes those rotations as received commits),
// spec/permissions.md §5.4 (Warning): a removed node holding an old epoch proves forks at every
// reconnection; the verifier keeps of them only what the Warning's first rise needs (one line
// whose tip rejects the followed rotation, with what it needs), never a plain fork beside the
// line it follows, so what it stores is the same at 10 and 100 Proves.
#[test]
fn a_removed_nodes_proved_forks_are_bounded_at_n_and_10n_spec_sync_opens_2() {
    let (c10, n10, k10) = forks_proved(10);
    let (c100, n100, k100) = forks_proved(100);
    assert_eq!(k10.len(), 2, "the first rejecting line alone is kept");
    assert_eq!(k10, k100);
    assert_eq!((n10, n100), (3, 3), "r1 and that line");
    assert_eq!(c10, c100, "local rows by kind");
}

// spec/permissions.md §5.4 (Warning), spec/sync-opens.md §2: a verifier that followed a removed
// node's fork F (first seen) is told the account forked when an honest node's Prove carries the
// line answering F (r1 beside F, s signed at r1's epoch superseding F unnamed): the verifier
// keeps that line, lists the dispute, and its user may choose it, which it then follows.
#[test]
fn a_proved_answer_warns_and_can_be_chosen_spec_permissions_5_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let p = a.account;
    let held = lp.peers[0].engine.core.accounts.get(&p).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
    let (kf, k1, k2) = (AccountEpochKeys::from_seed(&Secret32::from_bytes([81; 32])), AccountEpochKeys::from_seed(&Secret32::from_bytes([82; 32])), AccountEpochKeys::from_seed(&Secret32::from_bytes([83; 32])));
    let e = &mut lp.peers[1].engine;
    e.ingest(&bytes, Vec::new()).unwrap();
    let rec = e.core.created(&p).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    let f = rotation_at(rec.clone(), (FIRST_EPOCH, &first), &[], &kf, rotation_to(&kf, vec![FIRST_EPOCH]), ts);
    let fid = CommitBlob::decode(&f).unwrap().id();
    e.take_rotations(vec![header_only(&f)]).unwrap();
    assert!(e.core.account_view(&p).unwrap().rotation_counts(&fid), "F followed, held first");
    lp.peers[1].clock.advance(5);
    let e = &mut lp.peers[1].engine;
    let r1 = rotation_at(rec.clone(), (FIRST_EPOCH, &first), &[], &k1, rotation_to(&k1, vec![FIRST_EPOCH]), ts);
    let r1id = CommitBlob::decode(&r1).unwrap().id();
    let s = rotation_at(rec, (r1id, &k1), &[], &k2, rotation_to(&k2, vec![r1id, fid]), ts);
    let sid = CommitBlob::decode(&s).unwrap().id();
    e.take_rotations(vec![header_only(&r1), header_only(&s)]).unwrap();
    assert!(e.header(&r1id).is_some() && e.header(&sid).is_some(), "the answering line kept");
    let ds = e.account_disputes();
    assert_eq!(ds.len(), 1, "told the account forked");
    e.choose_line(p, sid).unwrap();
    let v = e.core.account_view(&p).unwrap();
    assert!(v.rotation_counts(&sid) && v.rotation_counts(&r1id) && !v.rotation_counts(&fid), "the chosen line followed");
}

// spec/permissions.md §5.5 (Revoked: a record of a node of another account A proved at epoch E is
// waited for no more once a rotation of A's chain as this node follows it, past E, carries a
// removal): at an outsider, a rotation whose header says it removes no one revokes nothing; one
// saying it removes revokes every epoch it descends from, never its own (its header's word,
// spec/permissions.md §5.5 Revoked); a fork this node does not follow revokes nothing; a removal
// deeper in the chain revokes the epochs below it.
#[test]
fn a_rotation_carrying_a_removal_revokes_the_epochs_below_it_spec_permissions_5_5() {
    let ts_of = |e: &crate::Engine| Ts::make(e.now(), 0).unwrap();
    let key = |k: &AccountEpochKeys| k.signing.verifying_key().to_bytes();
    let header = |next: &AccountEpochKeys, sup: CommitId, revokes: bool| RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![sup], names: Vec::new(), takes: Vec::new(), revokes, devices: Vec::new(), list_root: [0; 32], seeds: Vec::new() };
    let setup = || {
        let mut lp = peers(2);
        let (a, bytes) = created(&mut lp);
        let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
        let first = AccountEpochKeys::from_seed(held.keys.values().next().unwrap().seed());
        let e = &mut lp.peers[1].engine;
        assert!(matches!(e.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
        (lp, a, first)
    };
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([77; 32]));
    for (what, revoked) in [("no removal", false), ("a removal", true)] {
        let (mut lp, a, first) = setup();
        let e = &mut lp.peers[1].engine;
        let rec = e.core.created(&a.account).unwrap().clone();
        let r = rotation_at(rec, (FIRST_EPOCH, &first), &[], &next, header(&next, FIRST_EPOCH, revoked), ts_of(e));
        assert!(matches!(e.ingest(&r, Vec::new()).unwrap(), Ingested::Applied(_)));
        assert_eq!(e.account_key_revoked(&a.account, &key(&first)), revoked, "{what}");
        assert!(!e.account_key_revoked(&a.account, &key(&next)), "{what}: the rotation's own epoch is not");
    }
    // a fork not followed: the rotation held first (an earlier millisecond) names no removal
    let (mut lp, a, first) = setup();
    let fork = AccountEpochKeys::from_seed(&Secret32::from_bytes([78; 32]));
    let rec = lp.peers[1].engine.core.created(&a.account).unwrap().clone();
    let r = rotation_at(rec.clone(), (FIRST_EPOCH, &first), &[], &next, header(&next, FIRST_EPOCH, false), ts_of(&lp.peers[1].engine));
    assert!(matches!(lp.peers[1].engine.ingest(&r, Vec::new()).unwrap(), Ingested::Applied(_)));
    lp.peers[1].clock.advance(5);
    let f = rotation_at(rec.clone(), (FIRST_EPOCH, &first), &[], &fork, header(&fork, FIRST_EPOCH, true), ts_of(&lp.peers[1].engine));
    assert!(matches!(lp.peers[1].engine.ingest(&f, Vec::new()).unwrap(), Ingested::Applied(_)));
    let e = &mut lp.peers[1].engine;
    assert!(!e.core.account_view(&a.account).unwrap().rotation_counts(&CommitBlob::decode(&f).unwrap().id()), "the fork is not followed");
    assert!(!e.account_key_revoked(&a.account, &key(&first)), "a fork not followed revokes nothing");
    // deeper: a plain rotation, then one past it carrying a removal
    let third = AccountEpochKeys::from_seed(&Secret32::from_bytes([79; 32]));
    let r1 = CommitBlob::decode(&r).unwrap().id();
    let r2 = rotation_at(rec, (r1, &next), &[], &third, header(&third, r1, true), ts_of(e));
    assert!(matches!(e.ingest(&r2, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert!(e.account_key_revoked(&a.account, &key(&first)) && e.account_key_revoked(&a.account, &key(&next)), "every epoch below the carrier");
    assert!(!e.account_key_revoked(&a.account, &key(&third)), "its own epoch is not");
}
