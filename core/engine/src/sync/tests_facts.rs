//! The judgement facts per blob and per card (spec/sync-judgement.md §2-§3), each against a
//! party that would make an honest node drop data: what a blob carries is what this node opened
//! or sealed of it (`note_blob`, here standing in for an entry opened), never a peer's word.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::bodies::note_blob;
use super::{MustNot, PartSet};
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, BlobId, CommitId, Tid, Value};
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
    for id in ids {
        let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
        lp.deliver(to, &pk).unwrap();
    }
}

/// Peer `i` notes blob `b` of `c` holding `parts` as opened (a shared blob unless `copy`).
fn opened(lp: &mut LocalPeer, i: usize, b: u8, c: &CommitId, parts: &[usize], copy: bool) -> BlobId {
    let (id, c, ps) = (BlobId([b; 32]), *c, parts.iter().copied().collect::<PartSet>());
    lp.peers[i].engine.run(|tx| note_blob(tx, &id, super::BlobOf { commit: c, parts: ps, sealed: Default::default(), copy, unchecked: false, salt: [0; 16], ais: Default::default() })).unwrap();
    id
}

/// Peer 0's account with peer 1 paired as its second node; D.
fn two_nodes() -> (LocalPeer, Tid) {
    LocalPeer::cached("sync::tests_facts::two_nodes", || {
        let mut lp = LocalPeer::new_bare(2, 0, T0).unwrap();
        let p = lp.peers[0].engine.create_account().unwrap().0;
        let n = lp.peers[1].engine.tid();
        let card = lp.peers[1].engine.commit_ids();
        send(&mut lp, 1, 0, &card);
        let (_, out) = lp.peers[0].engine.pair(&n).unwrap();
        send(&mut lp, 0, 1, &out);
        lp.peers[1].engine.paired(&p.account).unwrap();
        (lp, p.devices)
    })
}

/// Peer `i`'s node writes its own `reach.0` a second later, sent to the other peer.
fn reach(lp: &mut LocalPeer, i: usize, k: u8) -> CommitId {
    lp.advance(1000);
    let n = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    m.set(n, &ct::REACH, &ct::Reach { dialable: [k; 32], items: Vec::new(), account: None }).unwrap();
    let c = lp.peers[i].engine.commit(m).unwrap().unwrap();
    send(lp, i, 1 - i, &[c]);
    c
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit once a later valid card
// commit of that node writing the same aspect is under the sync ID, an entry of it this node
// opened and checked against its header): it goes once an entry of the later card is opened
// here; a header-only entry of it holds no part of the aspect and supersedes nothing.
#[test]
fn a_card_goes_once_a_later_one_is_opened_spec_sync_judgement_2() {
    let (mut lp, d) = two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let old = reach(&mut lp, 1, 1);
    let new = reach(&mut lp, 1, 2);
    opened(&mut lp, 0, 1, &new, &[], true);
    assert_eq!(lp.peers[0].engine.read_facts(&home, &old).unwrap().must_not, None, "a header only: kept");
    opened(&mut lp, 0, 2, &new, &[0], true);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&home, &old).unwrap().must_not, Some(MustNot::CardSuperseded));
    assert_eq!(e.read_facts(&home, &new).unwrap().must_not, None, "the newest stays");
    let own = reach(&mut lp, 0, 3);
    let later = reach(&mut lp, 0, 4);
    opened(&mut lp, 0, 3, &later, &[0], true);
    assert_eq!(lp.peers[0].engine.read_facts(&home, &own).unwrap().must_not, None, "its own card: never by this rule");
}

// spec/sync-ids.md §1 (Prefix of a commit encryption: a node opening a blob refuses one whose
// prefix expiry is not the commit's): a blob of an expiring commit framed again under a later
// expiry, or none, is refused; framed again under the commit's own it opens.
#[test]
fn a_blob_under_another_expiry_is_refused_spec_sync_ids_1() {
    let mut lp = LocalPeer::new_bare(1, 0, T0).unwrap();
    let d = lp.peers[0].engine.create_account().unwrap().0.devices;
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, d);
    e.commit(m).unwrap().unwrap();
    let expires = osis_base::WallMs(e.now().0 + 60_000);
    let mut m = Mutation::new();
    m.set(t, &ak("x:a.0"), &Value::Int(1)).unwrap();
    m.expires(t, &ak("x:a.0"), expires).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let body = e.body(&c).unwrap().expect("a body");
    let rng = &mut osis_crypto::SeededRng::from_u64(7);
    let sealed = e.seal(&body, osis_blob::Class::Durable, &[], rng).unwrap().expect("sealed");
    let (prefix, pt) = osis_blob::open(&sealed.blob, &sealed.key).unwrap();
    assert_eq!(prefix.expiry(), Some(expires));
    let env = osis_commit::Envelope::decode(&pt).unwrap();
    let groups = osis_commit::prefix_groups(&env.header, env.ais().iter().copied()).unwrap();
    let mut framed = |at: Option<osis_base::WallMs>| {
        let p = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(rng), &env.header.blind, at, &groups).unwrap().with_class(osis_blob::Class::Durable);
        let (key, blob) = osis_blob::frame(&p, &pt, rng).unwrap();
        e.open_commit(&blob, &key)
    };
    assert!(framed(Some(osis_base::WallMs(expires.0 + 1))).is_err(), "a later expiry");
    assert!(framed(None).is_err(), "no expiry");
    assert!(framed(Some(expires)).is_ok(), "the commit's own");
}
