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

fn peers(n: usize) -> LocalPeer {
    LocalPeer::new(n, 1601, WallMs(1_700_000_000_000)).unwrap()
}

fn created(lp: &mut LocalPeer) -> (CreatedAccount, Vec<u8>) {
    let (a, done) = lp.peers[0].engine.create_account(&[]).unwrap();
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
    let edge = osis_schema::core_types::Edge { role: Role::Admin, until: None, invite: None, tied: None };
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
    let seed = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().seeds.values().next().unwrap().expose().to_owned();
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

/// A rotation of the account of record `rec` from its first epoch to `next`.
fn rotation(rec: CreationRecord, first: &AccountEpochKeys, next: &AccountEpochKeys, ts: Ts) -> Vec<u8> {
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
    cb.account = Some(AccountSigner { epoch: FIRST_EPOCH, inner: first.inner.clone(), node: Tid::from_bytes([9; 15]), node_key: node.signing });
    cb.rotation = Some((RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![FIRST_EPOCH], names: Vec::new(), list_root: [0; 32] }, Vec::new()));
    cb.build(&first.signing, &Dedup(rec, first.signing.verifying_key()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
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
    let first = AccountEpochKeys::from_seed(held.seeds.values().next().unwrap());
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
    assert_eq!(osis_keys::seal_keyset(&ks, &[first_name].into(), &none), osis_keys::Seal::At(next_name), "sealed at the open epoch");
}

// spec/crypto.md §4 (Account keysets), §7: concurrent rotations close each other's epochs, so at a
// reader holding both no box is sealed to the account and every earlier box is stale; the account
// still has a delete key, of an epoch that counts
#[test]
fn forked_account_has_no_open_epoch_spec_crypto_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.seeds.values().next().unwrap());
    let (x, y) = (AccountEpochKeys::from_seed(&Secret32::from_bytes([70; 32])), AccountEpochKeys::from_seed(&Secret32::from_bytes([71; 32])));
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    for k in [&x, &y] {
        assert!(matches!(e.ingest(&rotation(rec.clone(), &first, k, ts), Vec::new()).unwrap(), Ingested::Applied(_)));
    }
    let (none, ks) = (BTreeSet::new(), e.run(|tx| keysets_of(tx, &a.account, Role::Read, None)).unwrap());
    let unknown = account_epoch(2, &AccountEpochKeys::from_seed(&Secret32::from_bytes([72; 32])).signing.verifying_key()).unwrap();
    for k in [&first, &x, &y] {
        assert!(stale(&account_epoch(u64::from(k.signing.verifying_key() != first.signing.verifying_key()), &k.signing.verifying_key()).unwrap(), &ks, &none));
    }
    assert!(!stale(&unknown, &ks, &none), "an epoch not received yet is not stale");
    assert_eq!(osis_keys::seal_keyset(&ks, &none, &none), osis_keys::Seal::Out);
    assert!(e.run(|tx| crate::flows::account::holder_keys(tx, &a.account)).is_err());
    let want = [x.signing.verifying_key().to_bytes(), y.signing.verifying_key().to_bytes()].into_iter().max().unwrap();
    assert_eq!(e.core.account_delete_key(&a.account).unwrap().to_bytes(), want);
}

fn edge(r: Role) -> osis_schema::core_types::Edge {
    osis_schema::core_types::Edge { role: r, until: None, invite: None, tied: None }
}

/// An actor of peer 1 with secrets of its own.
fn actor_of(lp: &mut LocalPeer, a: &Tid) -> Tid {
    let e = &mut lp.peers[1].engine;
    let me = e.tid();
    let mut m = crate::Mutation::new();
    let t = e.new_thing(&mut m, me);
    e.commit(m).unwrap();
    let keep = edge(Role::Read);
    e.grant(&t, a, &keep).unwrap();
    t
}

// spec/crypto.md §4 (Seal), §3: a grant to an account is boxed at its newest open epoch by that epoch's public keys, not its first
#[test]
fn grant_boxes_at_the_open_epoch_spec_crypto_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.seeds.values().next().unwrap());
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
    let named: Vec<_> = s.boxes.iter().filter(|(k, _)| k.holder == a.account).map(|(_, b)| osis_keys::box_epoch(b)).collect();
    assert_eq!(named, vec![Some(name)]);
    let key = e.run(|tx| crate::flows::labels::reader_key(tx, &a.account)).unwrap();
    match key {
        Some(crate::flows::labels::ReaderKey::Static(vk, kem)) => assert_eq!((vk, kem), (next.signing.verifying_key(), next.kem.public().clone()), "one epoch's keys"),
        _ => panic!("a static entry"),
    }
}

// spec/crypto.md §4 (Possession key): an account's possession key at an epoch is that epoch's signing key, and it counts only for a commit ordered after the epoch's rotation
#[test]
fn possession_key_is_the_epochs_signing_key_spec_crypto_4() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.seeds.values().next().unwrap());
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([78; 32]));
    let e = &mut lp.peers[1].engine;
    e.ingest(&bytes, Vec::new()).unwrap();
    let rec = e.core.created(&a.account).unwrap().clone();
    let ts = Ts::make(e.now(), 0).unwrap();
    e.ingest(&rotation(rec, &first, &next, ts), Vec::new()).unwrap();
    let v = e.core.account_view(&a.account).unwrap();
    let point = |t: Ts, c: u8| osis_perm::Point { ts: t, node: a.account, commit: CommitId([c; 32]) };
    let (before, after) = (point(Ts::make(WallMs(ts.wall_ms().0 - 1), 0).unwrap(), 0), point(Ts::make(WallMs(ts.wall_ms().0 + 1), 0).unwrap(), 0));
    let name = account_epoch(1, &next.signing.verifying_key()).unwrap();
    assert_eq!(v.possession_key(&name, &after), Some(next.signing.verifying_key()));
    assert_eq!(v.possession_key(&name, &before), None, "before its rotation it shows nothing");
    let first_name = account_epoch(0, &first.signing.verifying_key()).unwrap();
    assert_eq!(v.possession_key(&first_name, &before), Some(first.signing.verifying_key()));
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
    let (x, _) = lp.peers[0].engine.create_account(&[]).unwrap();
    let (y, _) = lp.peers[0].engine.create_account(&[]).unwrap();
    let (fx, fy) = (write(&mut lp, &x, 1), write(&mut lp, &y, 1));
    let own = lp.peers[0].engine.core.session.nonce;
    let (Form::Session(nx), Form::Session(ny)) = (fx, fy) else { panic!("session form") };
    assert_ne!(nx, ny);
    assert_ne!(nx, own);
    assert_eq!(write(&mut lp, &x, 2), Form::Session(nx), "one session per account and open");
}

// the signing chain is built once per rotation it holds, whatever the writes between
#[test]
fn account_view_is_built_once_per_rotation() {
    let mut lp = peers(1);
    let (a, _) = lp.peers[0].engine.create_account(&[]).unwrap();
    let write = |lp: &mut LocalPeer| {
        let mut m = crate::Mutation::new();
        m.sign_as(a.account);
        m.set(a.profile, &osis_schema::core_types::GROUP, &Default::default()).unwrap();
        lp.peers[0].engine.commit(m).unwrap();
    };
    write(&mut lp);
    let before = lp.peers[0].engine.core.account_view_builds.get();
    for _ in 0..50 {
        write(&mut lp);
    }
    assert_eq!(lp.peers[0].engine.core.account_view_builds.get(), before, "no write rebuilds it");
}

// spec/sync.md §3 (invite requests): the request gate reads an author's signature at the header's epoch: a commit signed at the first epoch verifies only there
#[test]
fn request_gate_reads_the_header_epoch_spec_sync_3() {
    let mut lp = peers(2);
    let (a, bytes) = created(&mut lp);
    let held = lp.peers[0].engine.core.accounts.get(&a.account).unwrap().clone();
    let first = AccountEpochKeys::from_seed(held.seeds.values().next().unwrap());
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
