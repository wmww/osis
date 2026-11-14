#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The engine's facade for sync (`osis_engine::sync`, notes/sync-facade.md): each call against
//! the spec rule it serves, over `LocalPeer` (commits and inbox blobs carried by hand).

use crate::common::{REG, s};
use crate::flows::{edge_of, people, spread, spread_sealed, thing_of};
use osis_base::{Ak, Role, Tid};
use osis_crypto::SeededRng;
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::{Holding, Taken, ThingSync};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Peer 0 grants peer 1's account `role` on a new thing of its own; the inbox blob of the grant.
fn granted(role: Role) -> (LocalPeer, Tid, Tid, osis_base::CommitId, Vec<u8>) {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(role)).unwrap();
    let g = *done.commits.last().unwrap();
    let blob = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).expect("an inbox blob to peer 1").1;
    (lp, t, ps[1], g, blob)
}

// spec/sync-set.md §1 (the first node: the commit creating D carries the synced group and the
// `synced^.0` entry), §2 (sync set: D read, a plain item of the closure has no sync ID of its own).
#[test]
fn account_has_a_synced_group_and_reads_home_spec_sync_set_1() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let synced = e.get_typed(&d, &ct::SYNCED).unwrap().expect("synced^.0 on D");
    let g = *synced.get(&e.tid()).expect("this node's synced group");
    assert!(e.closure(&g).contains(&d), "D under the synced group");
    let home = e.home_sync_id(&d).unwrap().unwrap();
    assert_eq!(e.thing_sync(&d).unwrap(), ThingSync::Read(vec![home]));
    assert_eq!(e.sync_set().unwrap().ids.get(&home), Some(&(d, Holding::Read)));
    assert_eq!(e.thing_sync(&g).unwrap(), ThingSync::Plain, "the synced group is plain");
    assert_eq!(e.sync_owner(&home).unwrap(), Some(d));
}

// spec/sync-ids.md §3 (claim key: a listed reader derives it from its own key and the step key),
// §4 (owner), spec/sync-opens.md §4 (admissible: read secrets at a current epoch, the head's sync
// proof).
#[test]
fn read_credentials_and_claim_key_spec_sync_ids_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let home = e.home_sync_id(&d).unwrap().unwrap();
    let ids = e.sync_ids(&d).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(!ids[0].hint);
    let head = ids[0].path.steps.last().unwrap().0.clone();
    head.verify_genesis().unwrap();
    let rc = e.read_credentials(&home).unwrap().expect("a reader of home");
    assert_eq!(rc.head.as_ref().map(|s| s.id()), Some(head.id()));
    assert!(!rc.read_secrets.is_empty(), "a current read secret");
    assert_eq!(rc.proofs.first().map(|p| p.0), Some(head.id()), "the head's sync proof first");
    assert_ne!(rc.roster, [0; 32]);
    let ck = e.claim_key(&home, &head.id()).unwrap().expect("this node is listed at genesis");
    let (_, Some(claims)) = &ids[0].path.steps[0] else { panic!("claim set held") };
    assert!(claims.claims.contains(&ck.verifying_key().to_bytes()));
}

// spec/sync-opens.md §4: the roster digest moves with a grant (no rotation needed).
#[test]
fn roster_digest_moves_with_a_grant_spec_sync_opens_4() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    // the thing in the synced group's closure: read here
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let before = lp.peers[0].engine.read_credentials(&s).unwrap().expect("read").roster;
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let after = lp.peers[0].engine.read_credentials(&s).unwrap().unwrap().roster;
    assert_ne!(before, after);
}

fn add_item(lp: &mut LocalPeer, i: usize, g: Tid, t: Tid) {
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap();
}

// spec/data-model.md §9 (`caps^.0`: on the node thing), spec/sync-ids.md §5 (caps).
#[test]
fn caps_read_from_the_node_spec_sync_ids_5() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    assert!(e.caps().unwrap().things.is_empty(), "absent: the defaults");
    let me = e.tid();
    let t = Tid::from_bytes([9; 15]);
    let mut m = Mutation::new();
    m.set(me, &ct::CAPS, &ct::Caps { policy: [("entries".to_string(), 7)].into(), things: [(t, ct::ThingCaps { entries: 3, bytes: 4 })].into() }).unwrap();
    e.commit(m).unwrap().unwrap();
    let c = e.caps().unwrap();
    assert_eq!(c.policy.get("entries"), Some(&7));
    assert_eq!(c.things.get(&t).map(|x| (x.entries, x.bytes)), Some((3, 4)));
}

// spec/sync-judgement.md §6 (kept unread: a sync record from a box sealed to its own key, no
// engine state of what S carries), spec/sync-inbox.md §2 (taking: the user accepted it).
#[test]
fn a_sync_grant_writes_a_sync_record_only_spec_sync_judgement_6() {
    let (mut lp, t, _, g, blob) = granted(Role::Sync);
    let e = &mut lp.peers[1].engine;
    let o = e.take_inbox_blob(&blob, true).unwrap().expect("opens");
    assert_eq!((o.commit, o.taken), (Some(g), Taken::Applied));
    let r = e.sync_record(&t).unwrap().expect("a sync record");
    assert_eq!(r.sync_ids.len(), 1, "the payload's sync ID");
    assert!(!r.secrets.is_empty());
    assert!(e.core.ix.commits.get(&g).is_none(), "the grant is not applied");
    assert!(e.epochs(&t).is_none(), "no engine state of the thing");
    assert!(o.hints.is_empty(), "a sync box gives no read hint");
    assert!(o.dial.is_none(), "the sender publishes no reach.0");
    // in the closure: kept unread
    let (_, d) = e.account().unwrap().unwrap();
    add_item(&mut lp, 1, d, t);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Unread(r.sync_ids.clone()));
}

// spec/sync-inbox.md §2 (invite request: an untaken blob, not applied, nothing followed),
// spec/sync-set.md §4 (invitations: listed untaken; accepting: takes it).
#[test]
fn an_untaken_grant_is_an_invitation_spec_sync_set_4() {
    let (mut lp, t, _, g, blob) = granted(Role::Read);
    let from = lp.peers[0].engine.me();
    let e = &mut lp.peers[1].engine;
    let o = e.take_inbox_blob(&blob, false).unwrap().expect("opens");
    assert_eq!(o.taken, Taken::Waiting, "the sender is not connected");
    assert!(e.core.ix.commits.get(&g).is_none());
    let inv = e.invitations().unwrap();
    let i = inv.iter().find(|i| i.thing == t).expect("listed");
    assert_eq!((i.role, i.from, i.taken), (Role::Read, from, false));
    let o = e.take_inbox_blob(&blob, true).unwrap().unwrap();
    assert_eq!(o.taken, Taken::Applied);
    assert!(!e.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken));
}

// spec/sync-judgement.md §6 Keeps: a box arriving after a new step (the rotation that
// stepped boxing the holder again) adds its epoch's sync secret to the record; nothing of the
// first is lost.
#[test]
fn a_box_after_a_new_step_extends_the_record_spec_sync_judgement_6() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == ps[1] {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    let first = lp.peers[1].engine.sync_record(&t).unwrap().unwrap();
    lp.peers[0].engine.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    // removing peer 2 rotates read and sync: the rotation boxes peer 1 at the new sync epoch
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap();
    let s = first.sync_ids[0];
    let ids = lp.peers[0].engine.sync_ids(&t).unwrap();
    let (_, step) = (ids[0].id, ids[0].path.steps.last().unwrap().0.clone());
    let _ = lp.peers[0].engine.issue_step(&t, &s, &step.id(), false).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == ps[1] {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    let after = lp.peers[1].engine.sync_record(&t).unwrap().unwrap();
    assert!(first.secrets.keys().all(|e| after.secrets.contains_key(e)), "nothing lost");
    assert!(after.secrets.len() > first.secrets.len(), "the new sync epoch's secret");
}

// spec/sync-inbox.md §2 (Re-send: until the sender has seen the recipient take it, a commit by
// the recipient writing a thing the blob names, opened under a current read epoch).
#[test]
fn a_delivery_is_owed_until_taken_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, blob) = granted(Role::Write);
    assert!(lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)));
    assert!(!lp.peers[0].engine.delivery_taken(&g, &pb).unwrap());
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    write_reg(&mut lp, 1, t, 1);
    spread_sealed(&mut lp);
    assert!(lp.peers[0].engine.delivery_taken(&g, &pb).unwrap());
    assert!(!lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)));
}

// spec/sync-inbox.md §2 (What it carries about G): a removal of a grant of read or above; G
// holding sync alone is sent none. Removing a sync holder owes it nothing, a reader is owed.
#[test]
fn a_removal_is_owed_to_a_reader_not_a_sync_holder_spec_sync_inbox_2() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    lp.peers[0].engine.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    let owed = |lp: &mut LocalPeer, c: osis_base::CommitId, h: Tid| lp.peers[0].engine.deliveries().unwrap().contains(&(c, h));
    let c = *lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits.last().unwrap();
    assert!(!owed(&mut lp, c, ps[1]), "a sync holder's removal");
    let c = *lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap().commits.last().unwrap();
    assert!(owed(&mut lp, c, ps[2]), "a reader's removal");
}

// spec/sync-inbox.md §2 (Re-send: a commit sealed under an older epoch shows nothing): a writer
// removed and granted write again, holding neither yet, writes under the epoch from before its
// removal; that write, stamped after the grant, leaves the grant owed; one written once it holds
// both, under the grant's epoch, shows it taken.
#[test]
fn a_write_under_an_older_epoch_shows_no_grant_again_taken_spec_sync_inbox_2() {
    let (mut lp, t, pb, _, blob) = granted(Role::Write);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let g = *lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Write)).unwrap().commits.last().unwrap();
    lp.advance(1_000);
    let stale = write_reg(&mut lp, 1, t, 2);
    let pks = lp.sealed(1, &[stale]).unwrap();
    lp.deliver_sealed(0, &pks).unwrap();
    assert!(lp.peers[0].engine.commit_bytes(&stale).unwrap().is_some(), "the stale write is held at the granter");
    assert!(!lp.peers[0].engine.delivery_taken(&g, &pb).unwrap(), "a write under the old epoch shows nothing");
    spread(&mut lp);
    let fresh = write_reg(&mut lp, 1, t, 3);
    let pks = lp.sealed(1, &[fresh]).unwrap();
    lp.deliver_sealed(0, &pks).unwrap();
    assert!(lp.peers[0].engine.delivery_taken(&g, &pb).unwrap(), "a write under the grant's epoch shows it taken");
}

/// Peer `i` writes `v` on `t`'s `t:reg.0`: the commit.
fn write_reg(lp: &mut LocalPeer, i: usize, t: Tid, v: i64) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(v)).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

// spec/permissions.md §3 (drops once that commit is held elsewhere: a self-remover keeps its
// secrets until then), spec/sync-status.md §2.
#[test]
fn a_self_removal_waits_to_be_held_elsewhere_spec_perm_3() {
    let (mut lp, t, pb, _, blob) = granted(Role::Write);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    let done = lp.peers[1].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let c = done.commits[0];
    let e = &mut lp.peers[1].engine;
    assert!(e.waiting_held_elsewhere().unwrap().contains(&c));
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "kept while it waits");
    e.held_elsewhere(&c).unwrap();
    assert!(e.waiting_held_elsewhere().unwrap().is_empty());
}

// spec/sync-judgement.md §1-§2: a commit's body under each read sync ID whose closure holds it,
// with its facts; this node's own commits under it.
#[test]
fn bodies_and_facts_under_home_spec_sync_judgement_1() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let home = e.home_sync_id(&d).unwrap().unwrap();
    let t = thing_of(&mut lp, 0, d);
    add_item(&mut lp, 0, d, t);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let b = e.sync_bodies(&c).unwrap();
    let meta = b.get(&home).expect("a body under home");
    assert!(!meta.parts.is_empty() && !meta.header_only && !meta.certificate);
    let f = e.body_facts(&home, &c).unwrap();
    assert!(f.required && f.closure && f.dropped.is_none());
    assert!(e.own_commits(&home).unwrap().contains(&c));
}

// spec/crypto.md §5 (passing on: a fresh encryption under the epoch each section was written
// under, refused where it is not established here): a held commit this node neither wrote nor opened from a blob is never sealed (its
// written epoch unknown); an own commit is sealed under the epoch it is written under, and the
// blob opens with its wrap under home's read secret.
#[test]
fn seal_body_never_guesses_a_section_epoch_spec_crypto_5() {
    let (mut lp, ps) = people(2);
    let (_, d0) = lp.peers[0].engine.account().unwrap().unwrap();
    let home = lp.peers[0].engine.home_sync_id(&d0).unwrap().unwrap();
    let t = thing_of(&mut lp, 0, d0);
    add_item(&mut lp, 0, d0, t);
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let mut rng = SeededRng::from_u64(3);
    let (sealed, wrap) = lp.peers[0].engine.seal_body(&home, &c, &mut rng).unwrap().expect("an own commit seals");
    assert_eq!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().map(|p| p.into_iter().collect::<Vec<_>>()), Some(sealed.parts.clone()));
    let rc = lp.peers[0].engine.read_credentials(&home).unwrap().unwrap();
    assert!(osis_label::unwrap_any(rc.read_secrets.iter().map(|x| &x.1), &sealed.id, &wrap).is_some(), "the wrap opens under home's read secret");
    let _ = ps;
}

/// The read epoch whose secret unwraps the section of `t` in sealed commit blob `bytes` (blob key
/// `key`), among `t`'s epochs held at peer `i`.
fn section_epoch_of(lp: &LocalPeer, i: usize, t: &Tid, c: &osis_base::CommitId, bytes: &[u8], key: &osis_crypto::Secret32) -> Option<osis_crypto::Epoch> {
    let (_, pt) = osis_label::open(bytes, key).unwrap();
    let env = osis_commit::Envelope::decode(&pt).unwrap();
    let ep = lp.peers[i].engine.epochs(t).unwrap();
    let found: Vec<_> = env.sections.iter().flat_map(|sec| ep.read.epochs().filter(|(e, _)| ep.read.secret(e).is_some_and(|s| osis_crypto::unwrap_section(s, c, &sec.wrap).is_ok())).map(|(e, _)| *e).collect::<Vec<_>>()).collect();
    assert!(found.len() <= 1, "one section of the thing");
    found.first().copied()
}

// spec/crypto.md §5 (passing on), spec/sync-judgement.md §4 (logs the body again once): a reader
// holding a newer read epoch seals another writer's section under the epoch it was written under
// (as it opened it), never under its newest; a body it holds but never opened from a blob is
// refused (its written epoch unknown).
#[test]
fn seal_body_keeps_another_writers_section_epoch_spec_crypto_5() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    for p in [ps[1], ps[2]] {
        let done = lp.peers[0].engine.grant(&t, &p, &edge_of(Role::Read)).unwrap();
        for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
            if let Some(i) = ps.iter().position(|x| *x == h) {
                lp.peers[i].engine.take_inbox_blob(&b, true).unwrap();
            }
        }
    }
    for i in 0..2 {
        let (_, d) = lp.peers[i].engine.account().unwrap().unwrap();
        add_item(&mut lp, i, d, t);
    }
    spread(&mut lp);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    // peer 0 writes c under epoch e1; peer 1 opens it from the blob peer 0 logged
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(7)).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let e1 = crate::flows::newest_read(&lp, 0, t).unwrap();
    let mut rng = SeededRng::from_u64(5);
    let (sealed, wrap) = lp.peers[0].engine.seal_body(&s, &c, &mut rng).unwrap().expect("peer 0 seals its own");
    assert!(matches!(lp.peers[1].engine.open_entry(&s, &sealed.id, &wrap, &sealed.blob).unwrap(), osis_engine::sync::Opened::Commit(x, _) if x == c));
    // removing peer 2 rotates read: peer 1 holds a newer epoch
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap();
    spread(&mut lp);
    let e2 = crate::flows::newest_read(&lp, 1, t).unwrap();
    assert_ne!(e1, e2, "peer 1 holds the rotation's epoch");
    let (again, _) = lp.peers[1].engine.seal_body(&s, &c, &mut rng).unwrap().expect("sealed under its written epoch");
    assert_eq!(section_epoch_of(&lp, 1, &t, &c, &again.blob, &again.key), Some(e1), "the section under the epoch it was written under, not the newest");
    // a body peer 1 holds but never opened from a blob: its written epoch is unknown here
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(8)).unwrap();
    let c2 = lp.peers[0].engine.commit(m).unwrap().unwrap();
    spread(&mut lp);
    assert!(lp.peers[1].engine.core.ix.commits.contains_key(&c2));
    assert!(lp.peers[1].engine.seal_body(&s, &c2, &mut rng).unwrap().is_none(), "refused: never guessed");
}

/// Commit `c` as peer `i` stores it.
fn commit_of(lp: &mut LocalPeer, i: usize, c: &osis_base::CommitId) -> osis_commit::CommitBlob {
    let pk = lp.peers[i].engine.package(c).unwrap().expect("held");
    osis_commit::CommitBlob::decode_stored(&pk.bytes).unwrap()
}

/// An inbox blob to peer `to`'s account carrying `commit` with `things`, sealed by hand (a
/// sender's own payload: its sync IDs and its commit's header are its word).
fn inbox_by_hand(lp: &mut LocalPeer, to: usize, commit: &osis_commit::CommitBlob, things: Vec<osis_label::InboxThing>) -> Vec<u8> {
    let e = &mut lp.peers[to].engine;
    let a = e.me();
    let Some(ct::KemKey::X25519MlKem768(k)) = e.get_typed(&a, &ct::KEYS).unwrap().and_then(|k| k.key) else { panic!("the account's KEM key") };
    let kem = osis_crypto::KemPublicKey::from_slice(&k).unwrap();
    let v = osis_base::decode(&commit.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB }).unwrap();
    let payload = osis_label::InboxPayload { commit: v, things, chain: Vec::new(), records: Vec::new(), dial: None };
    let now = e.now();
    osis_label::seal_inbox_blob(&a, &kem, &payload, now, &mut SeededRng::from_u64(11)).unwrap()
}

// spec/sync-inbox.md §2 Taking (connected: the commit's signature verifies under the author's
// key): a sync grant whose header names a connected author it was not signed by is not taken
// (a sync-alone blob is never ingested, so nothing else checks its signature).
#[test]
fn a_forged_author_is_not_connected_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, _) = granted(Role::Sync);
    let mut forged = commit_of(&mut lp, 0, &g);
    // peer 1's own account: connected (a role on its D), but it never signed this
    forged.header.author = pb;
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap();
    let blob = inbox_by_hand(&mut lp, 1, &forged, vec![osis_label::InboxThing { tid: t, sync_id: s, delete_keys: None }]);
    let e = &mut lp.peers[1].engine;
    let o = e.take_inbox_blob(&blob, false).unwrap().expect("opens");
    assert_eq!(o.taken, Taken::Waiting, "the author's signature does not verify: an invite request");
    assert!(e.sync_record(&t).unwrap().is_none(), "no sync record from an untaken blob");
}

// spec/sync-inbox.md §2 (sync ID hints: the sender's word until a held `sync.0` records
// them), spec/sync-set.md §2: a sync grant naming a sync ID that a held `sync.0` gives
// another thing keeps nothing unread under it; that sync ID stays its owner's.
#[test]
fn a_payload_sync_id_of_another_thing_is_not_kept_unread_spec_sync_inbox_2() {
    let (mut lp, t, _, g, _) = granted(Role::Sync);
    let (_, d1) = lp.peers[1].engine.account().unwrap().unwrap();
    let home1 = lp.peers[1].engine.home_sync_id(&d1).unwrap().unwrap();
    let commit = commit_of(&mut lp, 0, &g);
    let blob = inbox_by_hand(&mut lp, 1, &commit, vec![osis_label::InboxThing { tid: t, sync_id: Some(home1), delete_keys: None }]);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    assert_eq!(lp.peers[1].engine.sync_record(&t).unwrap().expect("a sync record").sync_ids, vec![home1], "recorded as the payload named it");
    add_item(&mut lp, 1, d1, t);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Unread(Vec::new()), "home1 is D's");
    assert_eq!(e.sync_set().unwrap().ids.get(&home1), Some(&(d1, Holding::Read)));
}

// spec/sync-inbox.md §2 Re-send (until the sender has seen the recipient take it, an open by
// the recipient among the signs: sync's to see): `delivered` ends a delivery, durably; a sync
// holder writes nothing, so the engine alone never sees it taken.
#[test]
fn delivered_ends_a_delivery_spec_sync_inbox_2() {
    let (mut lp, _, pb, g, _) = granted(Role::Sync);
    let e = &mut lp.peers[0].engine;
    assert!(e.deliveries().unwrap().contains(&(g, pb)));
    e.delivered(&g, &pb).unwrap();
    assert!(!e.deliveries().unwrap().contains(&(g, pb)));
    lp.peers[0].restart(7).unwrap();
    assert!(!lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)), "gone for good");
}

// spec/crypto.md §5 (passing on: needs the epoch each section was written under, so what was
// opened or sealed is kept): what this node keeps of a blob it sealed or opened
// lasts across a restart and goes with its commit when that is forgotten.
#[test]
fn blob_rows_go_with_their_commit() {
    let (mut lp, _) = people(1);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let t = thing_of(&mut lp, 0, d);
    add_item(&mut lp, 0, d, t);
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let (sealed, _) = lp.peers[0].engine.seal_body(&home, &c, &mut SeededRng::from_u64(3)).unwrap().unwrap();
    lp.peers[0].restart(8).unwrap();
    assert!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().is_some(), "durable");
    lp.peers[0].engine.forget_commits(&[c]).unwrap();
    assert!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().is_none());
    lp.peers[0].restart(9).unwrap();
    assert!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().is_none(), "its row gone too");
}


/// Whether `wrap` of blob `b` opens under peer `i`'s secret of read epoch `e` of `t`.
fn wrap_opens_under(lp: &LocalPeer, i: usize, t: &Tid, e: &osis_crypto::Epoch, b: &osis_base::BlobId, wrap: &[u8]) -> bool {
    let ep = lp.peers[i].engine.epochs(t).unwrap();
    ep.read.secret(e).is_some_and(|x| osis_crypto::unwrap(x, b, wrap).is_ok())
}

// spec/crypto.md §5 (who wraps under what: a fresh encryption of a body wraps under the epoch
// the commit was written under at S's thing, never the node's newest), spec/sync-judgement.md
// §1: a reader that is no writer of S re-seals a shared blob and a per-sync-ID copy after a
// rotation it holds, and rewraps the held shared blob; each wrap opens under the epoch it opened
// with, not the newer one. A copy's wrap is its only key, so a newest-epoch wrap would hand it
// to whoever holds only that epoch.
#[test]
fn a_fresh_encryption_wraps_under_its_written_epoch_spec_crypto_5() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    for p in [ps[1], ps[2]] {
        let done = lp.peers[0].engine.grant(&t, &p, &edge_of(Role::Read)).unwrap();
        for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
            if let Some(i) = ps.iter().position(|x| *x == h) {
                lp.peers[i].engine.take_inbox_blob(&b, true).unwrap();
            }
        }
    }
    // u: a thing t administers, with secrets of its own; a grant on it travels under t's sync ID
    // as a copy (a role commit on another thing)
    let u = thing_of(&mut lp, 0, t);
    lp.peers[0].engine.give_own_secrets(&u).unwrap();
    add_item(&mut lp, 0, t, u);
    for i in 0..2 {
        let (_, d) = lp.peers[i].engine.account().unwrap().unwrap();
        add_item(&mut lp, i, d, t);
    }
    spread(&mut lp);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let done = lp.peers[0].engine.grant(&u, &ps[1], &edge_of(Role::Read)).unwrap();
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(7)).unwrap();
    let plain = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let copy = *done.commits.iter().find(|c| lp.peers[0].engine.sync_bodies(c).unwrap().get(&s).is_some_and(|b| b.copy)).expect("the grant on u is a copy under t's sync ID");
    let e1 = crate::flows::newest_read(&lp, 0, t).unwrap();
    // peer 1 opens both from the blobs peer 0 logged under S
    let mut rng = SeededRng::from_u64(5);
    let mut held = Vec::new();
    for c in [plain, copy] {
        let (sealed, wrap) = lp.peers[0].engine.seal_body(&s, &c, &mut rng).unwrap().expect("peer 0 seals its own");
        assert!(matches!(lp.peers[1].engine.open_entry(&s, &sealed.id, &wrap, &sealed.blob).unwrap(), osis_engine::sync::Opened::Commit(x, _) if x == c));
        held.push((sealed.id, wrap));
    }
    // removing peer 2 rotates read: peer 1 holds a newer epoch
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap();
    spread(&mut lp);
    let e2 = crate::flows::newest_read(&lp, 1, t).unwrap();
    assert_ne!(e1, e2, "peer 1 holds the rotation's epoch");
    for (name, c) in [("shared blob", plain), ("copy", copy)] {
        let (again, wrap) = lp.peers[1].engine.seal_body(&s, &c, &mut rng).unwrap().unwrap_or_else(|| panic!("{name}: sealed under its written epoch"));
        assert!(wrap_opens_under(&lp, 1, &t, &e1, &again.id, &wrap), "{name}: wrapped under the epoch it was written under");
        assert!(!wrap_opens_under(&lp, 1, &t, &e2, &again.id, &wrap), "{name}: not under the newest");
    }
    // the held shared blob logged verbatim again (`rewrap`): its wrap by the same rule
    let (b, w) = &held[0];
    let again = lp.peers[1].engine.rewrap(&plain, b, &s, w, &s).unwrap().expect("its written epoch is held");
    assert!(wrap_opens_under(&lp, 1, &t, &e1, b, &again) && !wrap_opens_under(&lp, 1, &t, &e2, b, &again), "rewrapped under the epoch it was written under");
}

// spec/sync-inbox.md §2 (logging: a sender that does not write the inbox deposits under the
// recipient's deposit key; Re-send: the sync IDs the blob names, whose open by the recipient
// shows it took the delivery).
#[test]
fn a_delivery_names_and_signs_for_the_recipients_inbox_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, _) = granted(Role::Sync);
    let e = &mut lp.peers[0].engine;
    let home = e.home_sync_id(&t).unwrap().unwrap();
    assert_eq!(*e.delivery_names(&g, &pb).unwrap(), vec![home]);
    let inbox = e.inbox_of(&pb).expect("the recipient's inbox");
    let sg = e.signers(&inbox, Some(&pb)).unwrap();
    assert!(sg.stamp.is_none() && sg.delete.is_none(), "no head of another's inbox recorded here");
    let seed = e.deposit_seed(&pb).unwrap().expect("the recipient's deposit seed");
    assert_eq!(sg.deposit.map(|k| k.verifying_key()), Some(osis_crypto::deposit_key(&seed, &inbox).verifying_key()));
    // its own thing: the head's keys
    let own = e.signers(&home, None).unwrap();
    assert!(own.stamp.is_some() && own.delete.is_some() && own.deposit.is_some());
}

// spec/sync-ids.md §6 (steps: registered only once the source holds the role commits its epochs
// depend on): the genesis step's needs are the rotations of its epochs, held here.
#[test]
fn a_step_needs_its_epochs_rotations_spec_sync_ids_6() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let ids = e.sync_ids(&d).unwrap();
    let step = ids[0].path.steps[0].0.id();
    let needs = e.step_needs(&ids[0].id, &step).unwrap();
    assert!(!needs.is_empty());
    assert!(needs.iter().all(|c| e.core.ix.commits.contains_key(c)));
}

// spec/sync-judgement.md §2, §3 (own store; role entries first), §4 (falls of held parts: the
// mark a stand compares), §1 (per-sync-ID copies: known as one).
#[test]
fn read_facts_of_own_and_role_commits_spec_sync_judgement_3() {
    let (mut lp, t, _, g, _) = granted(Role::Write);
    let e = &mut lp.peers[0].engine;
    let s = e.home_sync_id(&t).unwrap().unwrap();
    let (_, d) = e.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let f = e.read_facts(&s, &c).unwrap();
    assert!(f.own && !f.role && f.must_not.is_none() && !f.missing);
    let r = e.read_facts(&s, &g).unwrap();
    assert!(r.own && r.role, "the grant is an own role commit");
    assert_eq!(e.body_fall_mark(&c).unwrap(), 0, "nothing fell yet");
    let (sealed, wrap) = e.seal_body(&s, &c, &mut SeededRng::from_u64(4)).unwrap().unwrap();
    assert_eq!(e.blob_copy(&sealed.id).unwrap(), Some(false));
    // the held blob logged verbatim under the same sync ID: a wrap of the same key
    let again = e.rewrap(&c, &sealed.id, &s, &wrap, &s).unwrap().expect("its epoch is held");
    let rc = e.read_credentials(&s).unwrap().unwrap();
    let key = |w: &[u8]| osis_label::unwrap_any(rc.read_secrets.iter().map(|x| &x.1), &sealed.id, w).map(|x| *x.1.expose());
    assert_eq!(key(&again), key(&wrap));
}

// spec/sync-judgement.md §6 (Read and unread move: a node lowered to sync keeps the sync secrets
// it held as its sync record and drops its engine state of S, which becomes kept unread).
#[test]
fn a_lowering_to_sync_writes_a_sync_record_spec_sync_judgement_6() {
    let (mut lp, t, pb, _, blob) = granted(Role::Read);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    assert!(lp.peers[1].engine.sync_record(&t).unwrap().is_none(), "a reader keeps no record");
    let held: Vec<_> = lp.peers[1].engine.epochs(&t).unwrap().sync.held().map(|(e, _)| e).collect();
    assert!(!held.is_empty());
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: Some(edge_of(Role::Sync)), retain: None }).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == pb {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    e.forget_lost(osis_engine::rotation::LostScope::All).unwrap();
    assert!(e.epochs(&t).is_none_or(|x| !x.read.holds_any()), "read secrets gone");
    let r = e.sync_record(&t).unwrap().expect("lowered: a sync record");
    assert!(held.iter().all(|x| r.secrets.contains_key(x)), "the sync secrets it held");
    assert_eq!(r.sync_ids, vec![lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap()]);
}

// spec/sync-judgement.md §1 Per-sync-ID copies (never shared with another sync ID; only a copy
// holds a copy's body): a held blob is logged verbatim under another sync ID only as a shared
// blob for a shared body. A grant on u travels under t's sync ID as a copy and under u's own as
// the shared blob; neither is rewrapped for the other.
#[test]
fn a_copy_is_never_logged_verbatim_elsewhere_spec_sync_judgement_1() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let u = thing_of(&mut lp, 0, t);
    lp.peers[0].engine.give_own_secrets(&u).unwrap();
    add_item(&mut lp, 0, t, u);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let e = &mut lp.peers[0].engine;
    let (s, su) = (e.home_sync_id(&t).unwrap().unwrap(), e.home_sync_id(&u).unwrap().unwrap());
    let done = e.grant(&u, &ps[1], &edge_of(Role::Read)).unwrap();
    let c = *done.commits.iter().find(|c| e.sync_bodies(c).unwrap().get(&s).is_some_and(|b| b.copy)).expect("a copy under t's sync ID");
    assert!(e.sync_bodies(&c).unwrap().get(&su).is_some_and(|b| !b.copy), "the shared blob under u's");
    let mut rng = SeededRng::from_u64(9);
    let (copy, copy_wrap) = e.seal_body(&s, &c, &mut rng).unwrap().expect("the copy seals");
    let (shared, shared_wrap) = e.seal_body(&su, &c, &mut rng).unwrap().expect("the shared blob seals");
    assert_eq!((e.blob_copy(&copy.id).unwrap(), e.blob_copy(&shared.id).unwrap()), (Some(true), Some(false)));
    assert!(e.rewrap(&c, &copy.id, &s, &copy_wrap, &su).unwrap().is_none(), "a copy goes under no other sync ID");
    assert!(e.rewrap(&c, &shared.id, &su, &shared_wrap, &s).unwrap().is_none(), "a copy body is held only by a copy");
    assert!(e.rewrap(&c, &shared.id, &su, &shared_wrap, &su).unwrap().is_some(), "a shared blob for a shared body");
}

// spec/sync-inbox.md §2 (following a payload sync ID: one no applied `sync.0` records, only while
// the blob is unexpired): a read grant whose payload names the recipient's own home sync ID
// gives the granted thing no hint, so home stays D's in the sync set; an honest payload's hint
// lasts across a restart until the blob's expiry.
#[test]
fn a_hint_is_no_recorded_sync_id_and_ends_with_its_blob_spec_sync_inbox_2() {
    let (mut lp, t, _, g, blob) = granted(Role::Read);
    let (_, d1) = lp.peers[1].engine.account().unwrap().unwrap();
    let home1 = lp.peers[1].engine.home_sync_id(&d1).unwrap().unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let commit = commit_of(&mut lp, 0, &g);
    let forged = inbox_by_hand(&mut lp, 1, &commit, vec![osis_label::InboxThing { tid: t, sync_id: Some(home1), delete_keys: None }]);
    let o = lp.peers[1].engine.take_inbox_blob(&forged, true).unwrap().expect("opens");
    assert_eq!(o.taken, Taken::Applied);
    assert!(o.hints.is_empty(), "home1 is recorded by D's sync.0: no hint");
    add_item(&mut lp, 1, d1, t);
    let e = &mut lp.peers[1].engine;
    assert!(e.sync_ids(&t).unwrap().iter().all(|o| o.id != home1));
    assert_eq!(e.sync_set().unwrap().ids.get(&home1), Some(&(d1, Holding::Read)));
    // the honest blob names t's own sync ID: followed as a hint
    let o = e.take_inbox_blob(&blob, true).unwrap().expect("opens");
    assert_eq!(o.hints, vec![(t, s)]);
    lp.peers[1].restart(5).unwrap();
    let hinted = |lp: &mut LocalPeer| lp.peers[1].engine.sync_ids(&t).unwrap().iter().any(|o| o.id == s && o.hint);
    assert!(hinted(&mut lp), "durable");
    lp.advance(osis_base::format::INBOX_LIFETIME_MS + 1);
    lp.peers[1].tick().unwrap();
    assert!(!hinted(&mut lp), "the blob expired: no longer followed");
}

/// Peer `i`'s node writes its own `reach.0` a second later; the commit (a card commit, spec/
/// permissions.md §4).
fn reach(lp: &mut LocalPeer, i: usize, k: u8) -> osis_base::CommitId {
    lp.advance(1000);
    let n = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    m.set(n, &ct::REACH, &ct::Reach { dialable: [k; 32], items: Vec::new(), account: None }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit once a later valid card
// commit of that node writing the same aspect is under the sync ID, an entry of it this node
// opened). Hostile: a later card held as a commit with no entry of it opened here (a forged
// supersession) supersedes nothing, and this node's own card never goes by this rule. The rule
// firing: core/engine/src/sync/tests_facts.rs.
#[test]
fn a_card_known_only_as_a_commit_supersedes_nothing_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let old = reach(&mut lp, 1, 1);
    reach(&mut lp, 1, 2);
    let (o1, _) = (reach(&mut lp, 0, 3), reach(&mut lp, 0, 4));
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&home, &old).unwrap().must_not, None, "a later card held but never opened here: kept");
    assert_eq!(e.read_facts(&home, &o1).unwrap().must_not, None, "its own card: never by this rule");
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit, for `node.0` and `reach.0`,
// once that node is a node of the account no more after an applied edge write on D ended its
// grant). Hostile: a removed node paired again is a node again, its card kept; its `keys.0` card
// never goes by this rule.
#[test]
fn a_card_goes_with_its_nodes_grant_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let n1 = lp.peers[1].engine.tid();
    let r = reach(&mut lp, 1, 1);
    spread(&mut lp);
    let keys = *lp.peers[0].engine.core.ix.by_aspect.get(&(n1, Ak::new("keys.0").unwrap())).unwrap().iter().next().unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&home, &r).unwrap().must_not, None, "a node of the account: kept");
    e.demote(&d, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    assert_eq!(e.read_facts(&home, &r).unwrap().must_not, Some(osis_engine::sync::MustNot::CardEnded));
    assert_eq!(e.read_facts(&home, &keys.1).unwrap().must_not, None, "its keys.0 card stays");
    e.pair(&n1).unwrap();
    assert_eq!(e.read_facts(&home, &r).unwrap().must_not, None, "paired again: kept");
}

// spec/sync-judgement.md §2 required set (the certificate blobs of spec/permissions.md §4): the
// other node's `reach.0` card is in D's home sync ID's required set, so read never judges it
// outside it (must-not-hold, deleted at a node keeping the sync ID unread by a delete-key
// holder); sealed as a copy, it opens at the card's own node.
#[test]
fn another_nodes_card_is_in_the_required_set_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let r = reach(&mut lp, 1, 1);
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let b = e.sync_bodies(&r).unwrap();
    assert!(b.get(&home).is_some_and(|m| m.certificate && m.copy && !m.parts.is_empty()), "the card's certificate body under D's home: {b:?}");
    let f = e.body_facts(&home, &r).unwrap();
    assert!(f.required && !f.closure, "{f:?}");
    let (sealed, wrap) = e.seal_body(&home, &r, &mut SeededRng::from_u64(1)).unwrap().expect("sealed as a certificate copy");
    assert_eq!(e.blob_copy(&sealed.id).unwrap(), Some(true));
    match lp.peers[1].engine.open_entry(&home, &sealed.id, &wrap, &sealed.blob).unwrap() {
        osis_engine::sync::Opened::Commit(c, _) => assert_eq!(c, r),
        o => panic!("{o:?}"),
    }
}

/// Peer 1 takes a write grant on peer 0's thing `t` and syncs it (in its synced group).
fn grantee() -> (LocalPeer, Tid) {
    let (mut lp, t, _, _, blob) = granted(Role::Write);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    let (_, d1) = lp.peers[1].engine.account().unwrap().unwrap();
    add_item(&mut lp, 1, d1, t);
    (lp, t)
}

// spec/permissions.md §3 Complete pass (a Pull sent before a role commit of the actor applied
// ends no pass after it): the grant applied at peer 1 from elsewhere wants a pass of the thing's
// sync ID from its arrival, on the engine's clock; a pass begun before it does not count, one
// begun at it does, and the re-seal trigger waits for it.
#[test]
fn a_pass_begun_before_a_role_commit_does_not_count_spec_perm_3() {
    let (mut lp, t) = grantee();
    let e = &mut lp.peers[1].engine;
    let s = e.home_sync_id(&t).unwrap().unwrap();
    let since = *e.passes_wanted().unwrap().get(&s).expect("a pass of the thing's sync ID wanted");
    assert!(since.0 > 0 && since <= e.pass_clock(), "from the grant's arrival, on the engine's clock");
    e.note_complete_pass(&s, osis_base::WallMs(since.0 - 1)).unwrap();
    assert_eq!(e.passes_wanted().unwrap().get(&s), Some(&since), "begun before it: still wanted");
    assert!(e.reseal_due(&t).unwrap().commits.is_empty());
    e.note_complete_pass(&s, since).unwrap();
    assert!(!e.passes_wanted().unwrap().contains_key(&s));
}

// spec/permissions.md §3 Complete pass, spec/sync-status.md §1: the want is derived from the role
// commits held and the passes noted, so a crash right after a role commit still wants the pass,
// and a pass noted is kept across a restart.
#[test]
fn a_restart_still_wants_the_pass_spec_perm_3() {
    let (mut lp, t) = grantee();
    let s = lp.peers[1].engine.home_sync_id(&t).unwrap().unwrap();
    let since = *lp.peers[1].engine.passes_wanted().unwrap().get(&s).unwrap();
    lp.peers[1].restart(7).unwrap();
    assert_eq!(lp.peers[1].engine.passes_wanted().unwrap().get(&s), Some(&since), "wanted after the crash");
    lp.peers[1].engine.note_complete_pass(&s, since).unwrap();
    lp.peers[1].restart(8).unwrap();
    assert!(!lp.peers[1].engine.passes_wanted().unwrap().contains_key(&s), "the pass noted survives");
}

// spec/sync-status.md §3 History complete (a complete pass of every sync ID carrying the thing):
// a fresh node wants one pass of its home, whenever begun; history is complete once it is noted.
#[test]
fn history_completes_with_a_pass_spec_sync_status_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let home = e.home_sync_id(&d).unwrap().unwrap();
    assert_eq!(e.passes_wanted().unwrap().get(&home), Some(&osis_base::WallMs(0)), "one pass, whenever");
    assert!(!e.history_complete(&d).unwrap());
    let now = e.pass_clock();
    e.note_complete_pass(&home, now).unwrap();
    assert!(e.history_complete(&d).unwrap() && e.passes_wanted().unwrap().is_empty());
}

// spec/sync-status.md §3 History complete: a pass belongs to a sync ID read here, so a sync ID
// left and read again wants a pass of its own (what it missed while away is not here): one that
// leaves loses its noted pass (sync's follow calls `forget_read`; an open drops it too, for one
// left while down), and a pass of a sync ID not read is not kept.
#[test]
fn a_pass_goes_with_its_sync_id_spec_sync_status_3() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let now = lp.peers[0].engine.pass_clock();
    lp.peers[0].engine.note_complete_pass(&home, now).unwrap();
    lp.peers[0].engine.note_complete_pass(&s, now).unwrap();
    add_item(&mut lp, 0, d, t);
    assert!(!lp.peers[0].engine.history_complete(&t).unwrap(), "noted while not read here: not kept");
    lp.peers[0].engine.note_complete_pass(&s, now).unwrap();
    assert!(lp.peers[0].engine.history_complete(&t).unwrap());
    let mut m = Mutation::new();
    m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Remove(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    lp.peers[0].restart(9).unwrap();
    add_item(&mut lp, 0, d, t);
    assert!(!lp.peers[0].engine.history_complete(&t).unwrap(), "left while down: read again, history not complete");
    assert_eq!(lp.peers[0].engine.passes_wanted().unwrap().get(&s), Some(&osis_base::WallMs(0)));
    let now = lp.peers[0].engine.pass_clock();
    lp.peers[0].engine.note_complete_pass(&s, now).unwrap();
    lp.peers[0].engine.forget_read(&s).unwrap();
    assert!(!lp.peers[0].engine.history_complete(&t).unwrap(), "forgotten: wanted again");
}

// spec/permissions.md §3 Complete pass: `passes_wanted` is a memo value over the engine's stamps,
// so an `Effects` key over it is due when a role commit arrives from elsewhere, with no polling
// and no hook, and its new value wants the pass from that arrival.
#[test]
fn passes_wanted_moves_with_a_role_commit_spec_perm_3() {
    let (mut lp, t) = grantee();
    let e = &mut lp.peers[1].engine;
    let s = e.home_sync_id(&t).unwrap().unwrap();
    let now = e.pass_clock();
    for x in e.passes_wanted().unwrap().keys().copied().collect::<Vec<_>>() {
        e.note_complete_pass(&x, now).unwrap();
    }
    let mut fx: osis_base::memo::Effects<(), std::sync::Arc<std::collections::BTreeMap<osis_base::SyncId, osis_base::WallMs>>> = osis_base::memo::Effects::new("test passes");
    fx.want(());
    let (_, first) = fx.settle(&(), || lp.peers[1].engine.passes_wanted().unwrap()).unwrap();
    assert!(first.is_empty() && fx.due().is_empty(), "nothing wanted, nothing due");
    lp.advance(1000);
    let pb = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    assert_eq!(fx.due(), vec![()], "the role commit's arrival moves the wants");
    let (_, now) = fx.settle(&(), || lp.peers[1].engine.passes_wanted().unwrap()).unwrap();
    assert!(now.get(&s).is_some_and(|x| x.0 > 0));
}

// spec/permissions.md §2 Tied grants (an explicit demotion of a tied grant held dead waits for a
// complete pass of every sync ID whose bodies carry a thing of the demotion's pre-sync scope,
// ended after the last role commit of G or T applied from elsewhere): a role commit on G from
// another node wants a pass of T's sync ID, which no other rule wants once passed.
#[test]
fn a_dead_tie_wants_a_pass_of_its_scope_spec_perm_2() {
    let (mut lp, ps) = people(3);
    let g = thing_of(&mut lp, 0, ps[0]);
    let t = thing_of(&mut lp, 0, ps[0]);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    for x in [g, t] {
        lp.peers[0].engine.give_own_secrets(&x).unwrap();
        add_item(&mut lp, 0, d, x);
    }
    add_item(&mut lp, 0, g, t);
    let e = &mut lp.peers[0].engine;
    let tie = e.placement(&t, &g, false).unwrap().unwrap();
    e.grant(&t, &g, &ct::Edge { role: Role::Write, until: None, invite: None, tied: Some(osis_engine::flows::tied::tie_ct(tie)) }).unwrap();
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Remove(osis_base::Value::Tid(t)) }).unwrap();
    e.commit(m).unwrap().unwrap();
    assert!(e.tied_unplaced(&Default::default(), &Default::default(), true).unwrap().contains(&(t, g)), "the tie is dead");
    let st = e.home_sync_id(&t).unwrap().unwrap();
    let now = e.pass_clock();
    for x in e.passes_wanted().unwrap().keys().copied().collect::<Vec<_>>() {
        e.note_complete_pass(&x, now).unwrap();
    }
    assert!(e.passes_wanted().unwrap().is_empty());
    let done = e.grant(&g, &ps[1], &edge_of(Role::Admin)).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == ps[1] {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    spread(&mut lp);
    lp.advance(1000);
    lp.peers[1].engine.grant(&g, &ps[2], &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let w = lp.peers[0].engine.passes_wanted().unwrap();
    assert!(w.get(&st).is_some_and(|x| x.0 > now.0), "T's sync ID, from the role commit on G: {w:?}");
}

// spec/crypto.md §4 (names): a rotation names the edge writes its rotator held that pin a holder
// below a role, and what it names travels with it: a removal's rotation logs with it the earlier
// removal it names.
#[test]
fn a_rotation_logs_with_it_the_commits_it_names_spec_crypto_4() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    let e = &mut lp.peers[0].engine;
    e.give_own_secrets(&t).unwrap();
    e.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    e.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    let first = *e.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits.last().unwrap();
    let second = *e.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap().commits.last().unwrap();
    let with = e.logged_with(&second).unwrap();
    assert!(with.contains(&first), "the earlier removal it names: {with:?}");
}

/// A record blob of `records` under `t`'s current read epoch at peer `i` (spec/wire.md §3), as
/// any reader of the sync ID could frame one: its ID, bytes and wrap.
fn record_blob_by_hand(lp: &mut LocalPeer, i: usize, t: &Tid, records: &[osis_base::CreationRecord]) -> (osis_base::BlobId, Vec<u8>, osis_engine::sync::Wrap) {
    let mut rng = SeededRng::from_u64(17);
    let plain = osis_commit::record_blob::encode_record_blob(records);
    let prefix = osis_label::Prefix::for_groups(osis_label::Prefix::random_salt(&mut rng), &[7; 16], None, &[]).unwrap().with_class(osis_label::Class::Durable);
    let (key, blob) = osis_label::frame(&prefix, &plain, &mut rng).unwrap();
    let id = osis_label::blob_id(&blob);
    let w = lp.peers[i].engine.wrap_secret(t, None).unwrap().expect("a read epoch");
    let wrap = osis_crypto::wrap(&w, &id, &key, 0).unwrap();
    (id, blob, wrap)
}

// spec/wire.md §3 (creation record; Record blob), spec/permissions.md §4 (Chain certificates),
// spec/commits.md §4 (Pending storage): a record's tid is the hash of its encoding, records go raw
// in a record blob. A reader of S framing a record blob cannot plant a false record for a thing it
// names: a record altered to name another first admin is a record of another tid, and the
// receiver learns nothing of the thing; the genuine record, sealed by its holder, is kept loose
// until a commit here awaits it, then learned as it is.
#[test]
fn a_forged_record_in_a_record_blob_names_no_other_thing_spec_wire_3() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let a = lp.peers[0].engine.account().unwrap().unwrap().0;
    let u = thing_of(&mut lp, 0, a);
    let real = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    assert!(lp.peers[1].engine.core.created(&u).is_none(), "u not spread");
    let osis_base::CreationRecord::Thing { nonce, .. } = real.clone() else { panic!() };
    let forged = osis_base::CreationRecord::Thing { admin: lp.peers[1].engine.tid(), nonce, link: None };
    assert_ne!(forged.tid(), u);
    let (id, blob, wrap) = record_blob_by_hand(&mut lp, 0, &d, std::slice::from_ref(&forged));
    match lp.peers[1].engine.open_entry(&home, &id, &wrap, &blob).unwrap() {
        osis_engine::sync::Opened::Records(tids) => assert_eq!(tids, [forged.tid()].into()),
        o => panic!("{o:?}"),
    }
    assert!(lp.peers[1].engine.core.created(&u).is_none(), "nothing learned of u");
    let (id, bytes, wrap) = lp.peers[0].engine.seal_records(&home, &[u].into(), &mut SeededRng::from_u64(3)).unwrap().expect("sealed");
    assert!(matches!(lp.peers[1].engine.open_entry(&home, &id, &wrap, &bytes).unwrap(), osis_engine::sync::Opened::Records(_)));
    assert!(lp.peers[1].engine.core.created(&u).is_none() && lp.peers[1].engine.carries_loose(&id), "nothing awaits u yet: loose");
    later_write_on(&mut lp, u);
    assert_eq!(lp.peers[1].engine.core.created(&u), Some(&real));
    assert!(!lp.peers[1].engine.carries_loose(&id), "its carrier gives something held");
}

/// Peer 0 writes on `u` and peer 1 ingests that commit alone (`u`'s record not with it): it
/// awaits `u`'s record there.
fn later_write_on(lp: &mut LocalPeer, u: Tid) {
    let mut m = Mutation::new();
    m.set(u, &REG, &s("later")).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let bytes = lp.peers[0].engine.commit_bytes(&c).unwrap().unwrap();
    lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap();
}

/// `n` junk records (things no commit names) and one genuine one in record blobs a reader of
/// S frames, opened at peer 1, then the junk blob's entry gone: (loose records while carried,
/// records learned, loose left, whether the genuine one was learned once awaited).
fn junk_records(n: usize) -> (usize, usize, usize, bool) {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let a = lp.peers[0].engine.account().unwrap().unwrap().0;
    let u = thing_of(&mut lp, 0, a);
    let real = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    let junk: Vec<osis_base::CreationRecord> = (0..n).map(|i| osis_base::CreationRecord::Thing { admin: a, nonce: { let mut x = [9u8; 32]; x[..8].copy_from_slice(&(i as u64).to_be_bytes()); x }, link: None }).collect();
    let known = |lp: &LocalPeer| junk.iter().filter(|r| lp.peers[1].engine.core.created(&r.tid()).is_some()).count();
    let (jb, jbytes, jwrap) = record_blob_by_hand(&mut lp, 0, &d, &junk);
    let (gb, gbytes, gwrap) = record_blob_by_hand(&mut lp, 0, &d, std::slice::from_ref(&real));
    assert_ne!(jb, gb);
    for (b, bytes, wrap) in [(&jb, &jbytes, &jwrap), (&gb, &gbytes, &gwrap)] {
        assert!(matches!(lp.peers[1].engine.open_entry(&home, b, wrap, bytes).unwrap(), osis_engine::sync::Opened::Records(_)));
    }
    let carried = lp.peers[1].engine.loose_records();
    let learned = known(&lp);
    lp.peers[1].engine.forget_carrier(&jb);
    let left = lp.peers[1].engine.loose_records();
    later_write_on(&mut lp, u);
    (carried, learned + known(&lp), left, lp.peers[1].engine.core.created(&u) == Some(&real))
}

// spec/commits.md §4 (Pending storage), spec/requirements.md (malicious readers only waste
// storage; peer input never causes unbounded storage): records nothing here awaits are kept only
// while their carrier is (its entry charged to the peer that brought it): n and 10n junk records
// are never learned and go with their blob's entry, and they evict nothing another blob carries.
#[test]
fn junk_records_go_with_their_carrier_spec_commits_4() {
    for n in [20, 200] {
        let (carried, learned, left, genuine) = junk_records(n);
        assert_eq!(carried, n + 1, "kept loose while carried");
        assert_eq!(learned, 0, "never learned: nothing names them");
        assert_eq!(left, 1, "gone with their carrier; the other blob's stays");
        assert!(genuine, "the other blob's record, learned once awaited");
    }
}

// spec/permissions.md §4 (Logging certificates: the records missing go as one record blob of the
// logging node's, while held in its own store): what the engine keeps of a record blob it sealed under S lasts across a
// restart, goes when its own entry does (`forget_record_blob`), and goes with S when S is read here
// no more (`forget_read`; an open drops those of every sync ID not read).
#[test]
fn record_blob_rows_go_with_their_sync_id_spec_perm_4() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let mut rng = SeededRng::from_u64(4);
    let (b, _, _) = lp.peers[0].engine.seal_records(&s, &[ps[0]].into(), &mut rng).unwrap().expect("sealed");
    let (b2, _, _) = lp.peers[0].engine.seal_records(&s, &[ps[0]].into(), &mut rng).unwrap().expect("sealed");
    lp.peers[0].restart(8).unwrap();
    assert_eq!(lp.peers[0].engine.record_blobs(&s).unwrap().keys().copied().collect::<Vec<_>>().len(), 2, "durable");
    lp.peers[0].engine.forget_record_blob(&s, &b2).unwrap();
    assert_eq!(lp.peers[0].engine.record_blobs(&s).unwrap().keys().copied().collect::<Vec<_>>(), vec![b]);
    lp.peers[0].engine.forget_read(&s).unwrap();
    assert!(lp.peers[0].engine.record_blobs(&s).unwrap().is_empty());
    lp.peers[0].restart(9).unwrap();
    assert!(lp.peers[0].engine.record_blobs(&s).unwrap().is_empty(), "its rows gone too");
    // left while down: an open drops them
    lp.peers[0].engine.seal_records(&s, &[ps[0]].into(), &mut rng).unwrap().expect("sealed");
    let mut m = Mutation::new();
    m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Remove(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    lp.peers[0].restart(10).unwrap();
    assert!(lp.peers[0].engine.record_blobs(&s).unwrap().is_empty(), "S not read at the open");
}

// spec/permissions.md §4 (Logging certificates: each node logs its account's chain certificates
// for the sync ID's group and for each actor it acted for, and a commit's author's chain goes
// with it), spec/sync-judgement.md §2 (required set: those certificates, nothing more): x is
// an item of t's closure that t reads; a private group h holds write on x, peer 1's account is in
// h. h's roster is no chain into t, and nobody wrote on x through h: its edge write on h is not
// under t's sync ID. Once peer 1 writes on x through h, its author's chain goes there.
#[test]
fn a_chain_goes_under_a_sync_id_only_for_its_group_or_a_write_there_spec_perm_4() {
    let (mut lp, ps) = people(2);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    add_item(&mut lp, 0, d, t);
    let x = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&x).unwrap();
    add_item(&mut lp, 0, t, x);
    let h = thing_of(&mut lp, 0, ps[0]);
    let e = &mut lp.peers[0].engine;
    e.give_own_secrets(&h).unwrap();
    e.grant(&x, &t, &edge_of(Role::Read)).unwrap();
    e.grant(&x, &h, &edge_of(Role::Write)).unwrap();
    let member = *e.grant(&h, &ps[1], &edge_of(Role::Write)).unwrap().commits.iter().find(|c| e.header(c).is_some_and(|hd| hd.aspects.iter().any(|a| a.tid == h && a.ak.as_str() == "roles.0"))).expect("the edge write on h");
    let s = e.home_sync_id(&t).unwrap().unwrap();
    assert_eq!(e.sync_holding(&s).unwrap(), Some((t, Holding::Read)));
    // (its `keys.0` part, the record of h's box to peer 1's account, goes as h's current `keys.0`)
    let roles = e.header(&member).unwrap().aspect_index(&h, "roles.0").unwrap();
    assert!(e.sync_bodies(&member).unwrap().get(&s).is_none_or(|b| !b.parts.contains(&roles)), "h's roster is nobody's chain into t: {:?}", e.sync_bodies(&member).unwrap());
    spread(&mut lp);
    let mut m = Mutation::new();
    m.set(x, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
    lp.peers[1].engine.commit(m).unwrap().unwrap();
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    assert!(e.sync_bodies(&member).unwrap().get(&s).is_some_and(|b| b.certificate && b.copy && b.parts.contains(&roles)), "the writer's chain to x: {:?}", e.sync_bodies(&member).unwrap());
}

// spec/sync-judgement.md §1 Certificate blobs (a node logging the same parts of a commit under
// several sync IDs logs one blob, wrapped under each): the account's `keys.0` part of its creating
// commit is a certificate under the sync IDs of t and u alike; the copy sealed under one is
// wrapped for the other, under its own thing's epoch. Under D's home the commit is a closure body,
// a per-sync-ID copy of other parts, never shared as either.
#[test]
fn a_certificate_copy_is_one_blob_under_every_sync_id_spec_sync_judgement_1() {
    let (mut lp, ps) = people(1);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let t = thing_of(&mut lp, 0, ps[0]);
    let u = thing_of(&mut lp, 0, ps[0]);
    for x in [t, u] {
        lp.peers[0].engine.give_own_secrets(&x).unwrap();
        add_item(&mut lp, 0, d, x);
    }
    let e = &mut lp.peers[0].engine;
    let ids = [d, t, u].map(|x| e.home_sync_id(&x).unwrap().unwrap());
    let [home, s, su] = ids;
    let keys = e.current_keys(&ps[0]);
    let c = *keys.iter().find(|c| {
        let b = e.sync_bodies(c).unwrap();
        matches!((b.get(&s), b.get(&su)), (Some(x), Some(y)) if x.certificate && y.certificate && x.parts == y.parts)
    }).expect("one certificate body under both");
    let mut rng = SeededRng::from_u64(5);
    let (sealed, wrap) = e.seal_body(&s, &c, &mut rng).unwrap().expect("sealed");
    let to = e.rewrap(&c, &sealed.id, &s, &wrap, &su).unwrap().expect("the same blob under u's sync ID");
    if e.sync_bodies(&c).unwrap().get(&home).is_some_and(|m| !m.certificate) {
        let (copy, copy_wrap) = e.seal_body(&home, &c, &mut rng).unwrap().expect("the closure copy");
        assert!(e.rewrap(&c, &copy.id, &home, &copy_wrap, &s).unwrap().is_none(), "a per-sync-ID copy is no certificate elsewhere");
        assert!(e.rewrap(&c, &sealed.id, &s, &wrap, &home).unwrap().is_none(), "a certificate is no closure body");
    }
    assert!(lp.peers[0].engine.epochs(&u).is_some_and(|ep| ep.read.held().any(|(x, _)| wrap_opens_under(&lp, 0, &u, &x, &sealed.id, &to))), "wrapped under u's epoch");
}

// spec/commits.md §4 (Records: learned once something awaits it): a loose record is learned when
// a commit by its actor arrives, the author's record being what that commit awaits.
#[test]
fn a_loose_author_record_is_learned_when_its_commit_comes_spec_commits_4() {
    let mut lp = crate::common::net_bare(2, 5);
    let a = lp.peers[0].engine.create_account().unwrap().0.account;
    let b = lp.peers[1].engine.create_account().unwrap().0.account;
    let t = thing_of(&mut lp, 0, a);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let s0 = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let rec = lp.peers[1].engine.core.created(&b).cloned().unwrap();
    let (id, bytes, wrap) = record_blob_by_hand(&mut lp, 0, &t, std::slice::from_ref(&rec));
    assert!(matches!(lp.peers[0].engine.open_entry(&s0, &id, &wrap, &bytes).unwrap(), osis_engine::sync::Opened::Records(_)));
    assert!(lp.peers[0].engine.core.created(&b).is_none() && lp.peers[0].engine.carries_loose(&id));
    let u = thing_of(&mut lp, 1, b);
    let mut m = Mutation::new();
    m.set(u, &REG, &s("later")).unwrap();
    let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
    let cb = lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap();
    lp.peers[0].engine.ingest(&cb, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.core.created(&b), Some(&rec), "the author's record, awaited");
}
