//! The judgement facts per blob and per card (spec/sync-judgement.md §2-§3), each against a
//! party that would make an honest node drop data: what a blob carries is what this node opened
//! or sealed of it (`note_blob`, here standing in for an entry opened), never a peer's word.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::bodies::note_blob;
use super::PartSet;
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
    lp.peers[i].engine.run(|tx| note_blob(tx, &id, super::BlobOf { commit: c, parts: ps, sealed: Default::default(), copy, unchecked: false, salt: [0; 16], ais: Default::default(), seal: None })).unwrap();
    id
}

/// A thing D peer 0 makes and shares with peer 1, both syncing it; D.
fn two_nodes() -> (LocalPeer, Tid) {
    LocalPeer::cached("sync::tests_facts::two_nodes", || {
        let mut lp = LocalPeer::new(2, 0, T0).unwrap();
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let d = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        // each node learns the other's node thing by syncing it
        lp.sync_all().unwrap();
        lp.share(0, d);
        lp.sync_all().unwrap();
        (lp, d)
    })
}

// spec/sync-ids.md §1 (Prefix of a commit encryption: a node opening a blob refuses one whose
// prefix expiry is not the commit's): a blob of an expiring commit framed again under a later
// expiry, or none, is refused; framed again under the commit's own it opens.
#[test]
fn a_blob_under_another_expiry_is_refused_spec_sync_ids_1() {
    let mut lp = LocalPeer::new(1, 0, T0).unwrap();
    let d = lp.peers[0].engine.tid();
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

// spec/sync-judgement.md §1 (Certificate blobs; spec/wire.md §4: a header-only copy has no
// section): a blob of no section, a header alone, holds a header-only body whichever kind it was
// noted as. Opening it again (a peer relaying it under another sync ID, where nothing in its
// bytes says copy) leaves it the body, so the node logs no fresh encryption of it each time.
#[test]
#[ignore = "stub rewrite: a unit's stubs, cut and logged (R2)"]
fn a_header_alone_holds_a_header_only_body_of_either_kind_spec_sync_judgement_1() {
    let (mut lp, _) = two_nodes();
    let e = &mut lp.peers[0].engine;
    let ids: Vec<osis_base::SyncId> = e.sync_set().unwrap().ids.keys().copied().collect();
    let mut found = None;
    for c in e.commit_ids() {
        for s in &ids {
            if e.sync_body(s, &crate::sync::BodyId::unit(c)).unwrap().is_some_and(|m| m.header_only && m.copy) {
                found = found.or(Some((*s, c)));
            }
        }
    }
    let (s, c) = found.expect("a header-only certificate body under a held sync ID");
    for (b, copy) in [(7, true), (8, false)] {
        let id = opened(&mut lp, 0, b, &c, &[], copy);
        assert!(lp.peers[0].engine.holds_body(&s, &id).unwrap(), "a header alone noted as {}", if copy { "a copy" } else { "shared" });
    }
}

/// Peer 0 writes `n` aspects on a new thing minted with admin `d` in one commit (sent to peer 1 but for
/// the commit itself): enough that its aspect list goes by link (spec/wire.md §4).
fn wide_commit(lp: &mut LocalPeer, d: Tid, n: usize) -> (Tid, CommitId) {
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, d);
    let made = e.commit(m).unwrap().unwrap();
    send(lp, 0, 1, &[made]);
    let mut m = Mutation::new();
    for i in 0..n {
        m.set(t, &ak(&format!("x:a{i}.0")), &Value::Int(1)).unwrap();
    }
    (t, lp.peers[0].engine.commit(m).unwrap().unwrap())
}

/// Commit `c`'s blob as peer 0 seals it, framed again under `prefix` of its header (`None`: as
/// sealed), with its wrap under `s` for D (peer 1 reads D): (blob ID, wrap, bytes).
fn framed_entry(lp: &mut LocalPeer, d: Tid, c: &CommitId, junk: bool) -> (BlobId, crate::sync::Wrap, Vec<u8>) {
    let e = &mut lp.peers[0].engine;
    let body = e.body(c).unwrap().expect("a body");
    let rng = &mut osis_crypto::SeededRng::from_u64(9);
    let sealed = e.seal(&body, osis_blob::Class::Durable, &[], rng).unwrap().expect("sealed");
    let (key, bytes) = if junk {
        let (prefix, pt) = osis_blob::open(&sealed.blob, &sealed.key).unwrap();
        let mine = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([5; 32])).verifying_key();
        let p = osis_blob::Prefix::for_groups(*prefix.salt(), &body.blind, prefix.expiry(), &[vec![(1, mine)]]).unwrap().with_class(osis_blob::Class::Durable);
        osis_blob::frame(&p, &pt, rng).unwrap()
    } else {
        (sealed.key.clone(), sealed.blob.clone())
    };
    let id = osis_blob::blob_id(&bytes);
    let w = e.wrap_secret(&d, Some((c, &body.parts))).unwrap().expect("a wrap secret");
    (id, osis_crypto::wrap(&w, &id, &key, body.order).unwrap(), bytes)
}

// spec/commits.md §4 (a node holding a blob it opened before the header's lists resolved opens it again once they do),
// spec/sync-ids.md §1: a blob opened before its header lists resolve is checked once they do.
// A framer's blob of a genuine commit under commitments to a key of its own (so the thing's
// delete-key holders cannot delete it at a node keeping S unread) is opened again as the lists
// arrive and refused; the genuine blob opened alike is opened again and gives its parts.
// Fails if the blob is never opened again (it stays the commit's blob, kept and served as its
// body).
#[test]
fn a_blob_opened_before_its_lists_resolve_is_checked_once_they_do_spec_commits_4() {
    for junk in [true, false] {
        let (mut lp, d) = two_nodes();
        let (t, c) = wide_commit(&mut lp, d, 2500);
        assert!(!lp.peers[0].engine.header_list_blobs(&c).unwrap().is_empty(), "the aspect list goes by link");
        let s = lp.peers[1].engine.sync_id_of(&d).unwrap().unwrap();
        let (b, wrap, bytes) = framed_entry(&mut lp, d, &c, junk);
        let lists: Vec<(BlobId, Vec<u8>)> = {
            let e = &mut lp.peers[0].engine;
            e.header_list_blobs(&c).unwrap().into_iter().map(|x| (x, e.blob(&x).unwrap().unwrap())).collect()
        };
        let e = &mut lp.peers[1].engine;
        assert!(matches!(e.open_entry(&s, &b, &wrap, &bytes, u64::MAX).unwrap(), super::Opened::Commit(..)), "opened as a carrier");
        assert!(e.pends(&c), "waits for its lists");
        e.put_blobs(lists).unwrap();
        assert!(e.take_redeliver().contains(&c), "junk {junk}: its carriers open again once the lists resolve");
        let again = e.open_entry(&s, &b, &wrap, &bytes, u64::MAX).unwrap();
        e.redelivered(&c).unwrap();
        match junk {
            true => {
                assert!(matches!(again, super::Opened::Bad), "a framer's commitments: bad");
                assert_eq!(e.blob_commit(&b), None, "no blob of the commit");
            }
            false => {
                assert!(matches!(again, super::Opened::Commit(..)), "the genuine blob opens");
                assert_eq!(e.get(&t, &ak("x:a0.0")).unwrap(), Some(Value::Int(1)), "its parts taken");
            }
        }
    }
}

// spec/sync-judgement.md §2 (Per blob), spec/sync-compaction.md §1 (Duplicates): how one held
// blob of a commit loses to another, by what each carries as this node opened it. The same
// sections: the higher blob ID loses, or either where it may not stand. Unopened sections the
// other lacks: spare, unless the other lacks a part this one holds. A part only a blob carries
// that the other adds: needed, and not once that part is overwritten.
#[test]
fn a_blob_loses_to_another_by_what_each_carries_spec_sync_judgement_2() {
    use super::Loss::{Needed, Spare};
    let (mut lp, d) = two_nodes();
    let (t, c) = wide_commit(&mut lp, d, 2);
    let e = &mut lp.peers[0].engine;
    let s = e.sync_id_of(&d).unwrap().unwrap();
    let copy = e.sync_body(&s, &crate::sync::BodyId::unit(c)).unwrap().expect("a body under S").copy;
    let h = e.header(&c).unwrap();
    let on = |k: &str| h.aspects.iter().position(|a| a.tid == t && a.ak.as_str() == k).unwrap();
    let (p0, p1) = (on("x:a0.0"), on("x:a1.0"));
    let mut noted = |b: u8, parts: &[usize], sealed: &[u8]| {
        let (id, ps) = (BlobId([b; 32]), parts.iter().copied().collect::<PartSet>());
        let sealed = sealed.iter().map(|k| [*k; 32]).collect();
        e.run(|tx| note_blob(tx, &id, super::BlobOf { commit: c, parts: ps.clone(), sealed, copy, unchecked: false, salt: [0; 16], ais: ps, seal: None })).unwrap();
        id
    };
    let (b1, b2, b3, b4, b5, b6, b7, b8) = (noted(1, &[p0], &[]), noted(2, &[p0], &[]), noted(3, &[p0], &[9]), noted(4, &[p0], &[]), noted(5, &[p0, p1], &[9]), noted(6, &[p0], &[]), noted(7, &[p0], &[]), noted(8, &[p0, p1], &[]));
    let mut loses = |b: &BlobId, o: &BlobId, stands| lp.peers[0].engine.blob_loses(&s, b, o, stands).unwrap();
    assert_eq!(loses(&b2, &b1, (true, true)), Some(Spare), "the same sections: the higher ID loses");
    assert_eq!(loses(&b1, &b2, (true, true)), None);
    assert_eq!(loses(&b1, &b2, (false, true)), Some(Spare), "the lower ID loses where it may not stand");
    assert_eq!(loses(&b3, &b4, (true, true)), Some(Spare), "an unopened section the other lacks");
    assert_eq!(loses(&b5, &b6, (true, true)), None, "the other lacks a part held here");
    assert_eq!(loses(&b7, &b8, (true, true)), Some(Needed), "the other adds a part only a blob carries");
    let mut m = Mutation::new();
    m.set(t, &ak("x:a1.0"), &Value::Int(2)).unwrap();
    lp.peers[0].engine.commit(m).unwrap();
    assert_eq!(lp.peers[0].engine.blob_loses(&s, &b7, &b8, (true, true)).unwrap(), None, "the part it adds overwritten: no blob alone carries it");
}

// spec/sync-judgement.md §2 (Per blob: a strip), spec/sync-compaction.md §1 (Carriers): a blob
// stripping here is deleted at a peer only once each part of it held here (`live`) has another
// carrier there, and each part it strips as covered has a snapshot reaching it there (`covers`).
// A purged part strips with no cover; a part replaced under purge on replace strips covered.
#[test]
fn a_strip_names_its_live_parts_and_covers_spec_sync_judgement_2() {
    let (mut lp, d) = two_nodes();
    let (t, c) = wide_commit(&mut lp, d, 2);
    let e = &mut lp.peers[0].engine;
    let noted = |e: &mut crate::Engine, b: u8, c: CommitId, t: Tid| {
        let ps: PartSet = e.header(&c).unwrap().aspects.iter().enumerate().filter(|(_, a)| a.tid == t).map(|(i, _)| i).collect();
        let id = BlobId([b; 32]);
        e.run(|tx| note_blob(tx, &id, super::BlobOf { commit: c, parts: ps.clone(), sealed: Default::default(), copy: false, unchecked: false, salt: [0; 16], ais: ps, seal: None })).unwrap();
        id
    };
    let part = |e: &crate::Engine, c: &CommitId, t: Tid, k: &str| e.header(c).unwrap().aspects.iter().position(|a| a.tid == t && a.ak.as_str() == k).unwrap();
    let b = noted(e, 1, c, t);
    let mut m = Mutation::new();
    m.purge_commit(c, t, ak("x:a1.0"));
    m.set(t, &ak("x:a1.0"), &Value::Int(3)).unwrap();
    e.commit(m).unwrap();
    let st = e.strip_of(&b).expect("a purged part strips");
    assert_eq!((st.live, st.covers.len()), ([part(e, &c, t, "x:a0.0")].into(), 0), "purged: the rest live, no cover");
    let mut m = Mutation::new();
    let u = e.new_thing(&mut m, d);
    let x: ct::RetentionSetting = [(ak("x:v.0"), ct::RetentionEntry { history: Some(osis_schema::History::PurgeOnReplace), ..Default::default() })].into_iter().collect();
    m.set(u, &ct::RETENTION, &x).unwrap();
    e.commit(m).unwrap();
    let mut m = Mutation::new();
    m.set(u, &ak("x:v.0"), &Value::Int(1)).unwrap();
    m.set(u, &ak("x:w.0"), &Value::Int(1)).unwrap();
    let c1 = e.commit(m).unwrap().unwrap();
    let b1 = noted(e, 2, c1, u);
    let mut m = Mutation::new();
    m.set(u, &ak("x:v.0"), &Value::Int(2)).unwrap();
    e.commit(m).unwrap();
    let st = e.strip_of(&b1).expect("a part replaced under purge on replace strips");
    assert_eq!(st.live, [part(e, &c1, u, "x:w.0")].into(), "replaced: the rest live");
    assert!(st.covers.len() == 1 && !st.covers[0].is_empty(), "replaced: covered by what reaches it: {:?}", st.covers);
}


// spec/sync-judgement.md §3 (Dropped bodies: an entry that would leave again at once is not
// fetched while its body counts missing, but one carrying a part that counts missing gives it): a
// blob of a commit whose purged part strips here still gives its other part once that part counts
// missing; a blob of the purged part alone gives nothing. Fails if a stripping blob counts as
// giving nothing whatever it carries (its body's only copies stripping here, missing for good).
#[test]
fn a_stripping_blob_carrying_a_missing_part_gives_it_spec_sync_judgement_3() {
    let (mut lp, d) = two_nodes();
    let (t, c) = wide_commit(&mut lp, d, 2);
    let e = &mut lp.peers[0].engine;
    let h = e.header(&c).unwrap();
    let on = |k: &str| h.aspects.iter().position(|a| a.tid == t && a.ak.as_str() == k).unwrap();
    let (p0, p1) = (on("x:a0.0"), on("x:a1.0"));
    let noted = |e: &mut crate::Engine, b: u8, parts: &[usize]| {
        let (id, ps) = (BlobId([b; 32]), parts.iter().copied().collect::<PartSet>());
        e.run(|tx| note_blob(tx, &id, super::BlobOf { commit: c, parts: ps.clone(), sealed: Default::default(), copy: false, unchecked: false, salt: [0; 16], ais: ps, seal: None })).unwrap();
        id
    };
    let (both, purged) = (noted(e, 1, &[p0, p1]), noted(e, 2, &[p1]));
    let mut m = Mutation::new();
    m.purge_commit(c, t, ak("x:a1.0"));
    m.set(t, &ak("x:a1.0"), &Value::Int(3)).unwrap();
    e.commit(m).unwrap();
    assert!(e.strip_of(&both).is_some(), "the purged part strips");
    assert!(!e.blob_gives_missing(&both), "nothing counts missing yet");
    // part 0 counts never received, as once its cover fell
    e.run(|tx| {
        crate::retention::drop_part(tx, &c, p0)?;
        let mut m = tx.core.ix.commits.get(&c).cloned().unwrap();
        crate::retention::reopen_in(tx, &c, &mut m, p0);
        tx.in_class(m.view.memory, |tx| tx.put_meta_record(&c, m.clone()))
    })
    .unwrap();
    assert!(e.blob_gives_missing(&both), "it carries the missing part");
    assert!(!e.blob_gives_missing(&purged), "the purged part alone gives nothing");
}

// notes/slim-design.md B (one stored form per commit): a seal is kept only where it makes its
// blob again from the commit as held. Peer 0 seals a blob of its commit; the
// same opening noted for another blob of the commit (framed otherwise: other signatures, another
// prefix) keeps no seal, so its bytes stay; the seal of the true blob makes it byte for byte.
// Fails if a seal is noted for bytes it does not make (they would be dropped, and lost).
#[test]
fn a_seal_is_kept_only_for_the_blob_it_makes() {
    let (mut lp, d) = two_nodes();
    let mut m = Mutation::new();
    m.set(d, &ak("u:v.0"), &Value::Str("v".into())).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    let s = e.sync_id_of(&d).unwrap().unwrap();
    let mut rng = osis_crypto::SeededRng::from_u64(1);
    let (sealed, _) = e.seal_body(&s, &super::BodyId::unit(c), &[], &mut rng).unwrap().expect("sealed");
    let b = sealed.id;
    let row = (*e.blob_of(&b).expect("noted")).clone();
    assert!(row.seal.is_some(), "a fresh encryption keeps its seal");
    let made = e.regenerate(&b).unwrap().expect("made again");
    assert_eq!(osis_blob::blob_id(&made), b);
    let other = BlobId([0xA5; 32]);
    e.run(|tx| note_blob(tx, &other, row.clone())).unwrap();
    assert!(e.blob_of(&other).is_some_and(|r| r.seal.is_none()), "no seal for a blob it does not make");
    assert!(e.regenerate(&other).unwrap().is_none());
    assert_eq!(e.check_seals().1, Vec::<String>::new());
}
