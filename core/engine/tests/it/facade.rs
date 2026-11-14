#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The engine's facade for sync (`osis_engine::sync`, notes/sync-boundary.md): each call against
//! the spec rule it serves, over `LocalPeer` (commits and inbox blobs carried by hand).

use crate::flows::{edge_of, people, spread, thing_of};
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
// §4 (owner, path), spec/sync-opens.md §4 (current read secrets; a roster digest J moves with).
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

// spec/data-model.md §9 (`caps^.0` on the node thing), spec/sync-ids.md §5 Caps.
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
    e.drop_sync_record(&t).unwrap();
    assert!(e.sync_record(&t).unwrap().is_none());
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Plain, "no secret held of it");
}

// spec/sync-inbox.md §2 (an untaken blob is an invite request: not applied, nothing followed),
// spec/sync-set.md §4 (invitations list it untaken; accepting takes it).
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

// spec/wire.md §9 position 5, spec/sync-judgement.md §6 Stops: a removal below sync carries a
// removal signature per sync ID, by the delete key of the newest step the sender records, at the
// sync epoch it boxed the recipient at; the recipient keeps it whatever it takes, its recipient
// the one the blob's AD names. A forged signature, or one for another recipient, verifies nowhere.
#[test]
fn a_removal_notice_reaches_a_sync_holder_spec_wire_9() {
    let (mut lp, t, pb, _, blob) = granted(Role::Sync);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    let s = lp.peers[1].engine.sync_record(&t).unwrap().unwrap().sync_ids[0];
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let rm = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == pb).expect("the removal's inbox blob").1;
    let e1 = &mut lp.peers[1].engine;
    let o = e1.take_inbox_blob(&rm, false).unwrap().unwrap();
    assert_eq!(o.commit, done.commits.first().copied());
    let ns = e1.removal_notices(&s).unwrap();
    assert_eq!(ns.len(), 1, "kept whether or not taken");
    let n = &ns[0];
    assert_eq!((n.recipient, n.commit), (pb, done.commits[0]));
    // verified under the delete key of a step on the path (here the head the sender recorded)
    let path = lp.peers[0].engine.sync_ids(&t).unwrap()[0].path.clone();
    let head = path.steps.last().unwrap().0.clone();
    assert!(osis_label::verify_removal(&head.keys.delete, &n.sync_id, &n.recipient, &n.commit, n.epoch, &n.sig).is_ok());
    // forged: another recipient, or another epoch, or a key off the path
    assert!(osis_label::verify_removal(&head.keys.delete, &n.sync_id, &Tid::from_bytes([1; 15]), &n.commit, n.epoch, &n.sig).is_err());
    assert!(osis_label::verify_removal(&head.keys.delete, &n.sync_id, &n.recipient, &n.commit, n.epoch + 1, &n.sig).is_err());
    assert!(osis_label::verify_removal(&head.keys.sync, &n.sync_id, &n.recipient, &n.commit, n.epoch, &n.sig).is_err());
    assert_eq!(lp.peers[1].engine.all_removal_notices().unwrap().len(), 1);
}

// spec/sync-judgement.md §6 Stops ("a Register may move its head past the step the removal was
// signed at"): a notice signed at a step that is no longer the head still verifies under that
// step's delete key, which stays on the path.
#[test]
fn a_notice_signed_at_an_older_step_verifies_on_the_path_spec_sync_judgement_6() {
    let (mut lp, t, pb, _, blob) = granted(Role::Sync);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let rm = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == pb).unwrap().1;
    // the admin steps again after signing (a fresh step, no rotation)
    let (s, head) = {
        let ids = lp.peers[0].engine.sync_ids(&t).unwrap();
        (ids[0].id, ids[0].path.steps.last().unwrap().0.clone())
    };
    let (step, _) = lp.peers[0].engine.issue_step(&t, &s, &head.id(), true).unwrap();
    let step = step.expect("a child step").0;
    assert_eq!(step.prev, Some(head.id()));
    let e1 = &mut lp.peers[1].engine;
    e1.take_inbox_blob(&rm, false).unwrap();
    let n = e1.removal_notices(&s).unwrap()[0].clone();
    let path = lp.peers[0].engine.sync_ids(&t).unwrap()[0].path.clone();
    assert_eq!(path.steps.last().unwrap().0.id(), step.id(), "the head moved");
    let on_path: Vec<_> = path.steps.iter().filter(|(x, _)| osis_label::verify_removal(&x.keys.delete, &n.sync_id, &n.recipient, &n.commit, n.epoch, &n.sig).is_ok()).map(|(x, _)| x.id()).collect();
    assert!(on_path.contains(&head.id()), "verifies under the older step on the path");
}

// spec/sync-judgement.md §6 Keeps / Stranded: a box arriving after a new step (the rotation that
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

// spec/sync-inbox.md §2 (Re-send until the sender has seen the recipient take it: a commit by
// the recipient writing a thing the blob names).
#[test]
fn a_delivery_is_owed_until_taken_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, blob) = granted(Role::Write);
    assert!(lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)));
    assert!(!lp.peers[0].engine.delivery_taken(&g, &pb).unwrap());
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
    lp.peers[1].engine.commit(m).unwrap().unwrap();
    spread(&mut lp);
    assert!(lp.peers[0].engine.delivery_taken(&g, &pb).unwrap());
    assert!(!lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)));
}

// spec/permissions.md §3 (a self-remover keeps its secrets until its self-removal is held
// elsewhere), spec/sync-status.md §2.
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

// spec/sync-judgement.md §1 (a fresh encryption; the section-epoch rule, Fathom's finding
// issues/reseal-under-own-epoch-leaks.md): a held commit this node neither wrote nor opened from a blob is never sealed (its
// written epoch unknown); an own commit is sealed under the epoch it is written under, and the
// blob opens with its wrap under home's read secret.
#[test]
fn seal_body_never_guesses_a_section_epoch_spec_sync_judgement_1() {
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
