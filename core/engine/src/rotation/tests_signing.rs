#![allow(clippy::unwrap_used)]
//! An account's signing chain as its nodes write it (spec/permissions.md §3, §5.5,
//! spec/crypto.md §9): a removal from D rotates the account with thing lists; listings, a
//! witness's addenda and merges name what the rotation's list could not.

use crate::flows::{CreatedAccount, Demotion, Done};
use crate::local_peer::LocalPeer;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_schema::core_types as ct;

fn edge(r: Role) -> ct::Edge {
    ct::Edge { role: r, until: None, invite: None, tied: None, floor: None }
}

/// Delivers `ids` a millisecond on: what a node received earlier it received in an earlier
/// millisecond (the signing chain places rotations by receipt, one millisecond's by ID).
fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
    lp.advance(1);
    for id in ids {
        if let Some(pk) = lp.peers[from].engine.package(id).unwrap() {
            lp.deliver(to, &pk).unwrap();
        }
    }
}

/// Peers `0..nodes` are nodes of account P (created on 0, the others paired); the rest each
/// create an account of their own. Peer 0 makes thing `t` (`x:a.0` = "p") and grants the first
/// outsider's account write there. All synced. Returns (lp, P, t).
fn world(n: usize, nodes: usize) -> (LocalPeer, CreatedAccount, Tid) {
    let (lp, (a, t)) = LocalPeer::cached(&format!("rotation::tests_signing::world/{n}/{nodes}"), || {
        let mut lp = LocalPeer::new_bare(n, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[0].engine.create_account().unwrap();
        for i in 1..nodes {
            let node = lp.peers[i].engine.tid();
            let ids = lp.peers[i].engine.commit_ids();
            send(&mut lp, i, 0, &ids);
            let (_, all) = lp.peers[0].engine.pair(&node).unwrap();
            send(&mut lp, 0, i, &all);
            lp.peers[i].engine.paired(&a.account).unwrap();
        }
        for i in nodes..n {
            lp.peers[i].engine.create_account().unwrap();
        }
        lp.sync_all().unwrap();
        let mut m = crate::Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a.account);
        m.set(t, &x(), &Value::Str("p".into())).unwrap();
        lp.peers[0].commit(m).unwrap();
        if nodes < n {
            let o = lp.peers[nodes].engine.me();
            lp.peers[0].engine.grant(&t, &o, &edge(Role::Write)).unwrap();
        }
        lp.sync_all().unwrap();
        lp.advance(1000);
        (lp, (a, t))
    });
    (lp, a, t)
}

fn x() -> Ak {
    Ak::new("x:a.0").unwrap()
}

fn write(lp: &mut LocalPeer, peer: usize, t: Tid, v: &str) -> CommitId {
    let mut m = crate::Mutation::new();
    m.set(t, &x(), &Value::Str(v.into())).unwrap();
    lp.peers[peer].commit(m).unwrap().unwrap()
}

fn read(lp: &mut LocalPeer, peer: usize, t: Tid) -> Option<Value> {
    lp.peers[peer].engine.get(&t, &x()).unwrap()
}

fn remove(lp: &mut LocalPeer, by: usize, d: Tid, node: usize) -> Done {
    let n = lp.peers[node].engine.tid();
    lp.peers[by].engine.demote(&d, &Demotion { holder: n, new: None, retain: None }).unwrap()
}

// spec/permissions.md §3, §5.5: removing a node from D is the removal and then a rotation of the
// account naming in its thing lists what the rotator held at the epoch it closes; at an outsider
// holding both, the account's earlier writes and grants still count, the removed node's later
// write at the closed epoch does not, and the removed node holds no seed of the new epoch
#[test]
fn removal_rotates_the_account_and_its_lists_keep_its_writes_spec_permissions_5_5() {
    let (mut lp, a, t) = world(3, 2);
    write(&mut lp, 1, t, "sibling");
    lp.sync_all().unwrap();
    let o = lp.peers[2].engine.me();
    let deposit = lp.peers[0].engine.deposit_seed(&a.devices).unwrap().unwrap();
    let done = remove(&mut lp, 0, a.devices, 1);
    assert_eq!(done.commits.len(), 2, "the removal, then the rotation");
    // D's labels derive deposit keys from the account's seed, fresh with the rotation, so the
    // removed node deposits under them no more (spec/crypto.md §3)
    assert_ne!(lp.peers[0].engine.deposit_seed(&a.devices).unwrap().unwrap().expose(), deposit.expose(), "a fresh deposit seed");
    let rot = lp.peers[0].engine.header(&done.commits[1]).unwrap();
    assert!(rot.rotation.is_some() && rot.author == a.account);
    // the outsider gets the rotation (with its lists), not the removal
    send(&mut lp, 0, 2, &done.commits[1..]);
    assert_eq!(read(&mut lp, 2, t), Some(Value::Str("sibling".into())), "the sibling's write was listed");
    assert_eq!(lp.peers[2].engine.core.role_now(&o, &t), Some(Role::Write), "the account's grant was listed");
    // the removed node, unaware, writes on at the closed epoch
    let late = write(&mut lp, 1, t, "removed");
    send(&mut lp, 1, 2, &[late]);
    assert_eq!(read(&mut lp, 2, t), Some(Value::Str("sibling".into())), "a write at the closed epoch no word names counts for nothing");
    send(&mut lp, 0, 1, &done.commits);
    assert!(!lp.peers[1].engine.core.accounts.contains_key(&a.account), "the removed node drops the account");
    assert!(seeds(&lp, 0, a.account) == 2 && seeds(&lp, 1, a.account) == 0, "the rotator holds both epochs' seeds, the removed node none");
    // restart and rebuild read the same
    let d0 = lp.peers[2].engine.index_digest();
    lp.peers[2].engine.reload().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[2].engine.index_digest()), None, "reopened");
    lp.peers[2].engine.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[2].engine.index_digest()), None, "rebuilt");
    assert_eq!(read(&mut lp, 2, t), Some(Value::Str("sibling".into())));
}

// spec/sync-judgement.md §1 (List blobs: a node holds a list blob's thing lists once it holds
// its rotation), spec/commits.md §4 (Pending storage): a list blob opened before its rotation is
// kept loose, carried by its blob, and held as the rotation arrives without it, so the sibling's
// write the list names counts; the carrier then carries nothing loose, and a reopen and a
// rebuild read the lists alike. A forged list of the same rotation, kept loose first, does not
// keep the genuine one out (each is verified against the list root as the rotation arrives).
// The same where the rotation comes on the path taken only for what it proves (`ingest_valid`, a
// stranded report's holder keys).
#[test]
fn a_list_blob_before_its_rotation_is_held_as_it_arrives_spec_sync_judgement_1() {
    for valid_only in [false, true] {
        list_before_rotation(valid_only);
    }
}

fn list_before_rotation(valid_only: bool) {
    let (mut lp, a, t) = world(3, 2);
    write(&mut lp, 1, t, "sibling");
    lp.sync_all().unwrap();
    let done = remove(&mut lp, 0, a.devices, 1);
    let pk = lp.peers[0].engine.package(&done.commits[1]).unwrap().unwrap();
    assert!(!pk.lists.is_empty());
    let forged: Vec<_> = osis_commit::thing_list::decode_list_blob(&pk.lists[0]).unwrap().into_iter().map(|mut c| {
        c.list.ids = osis_commit::thing_list::ListIds::Inline(Vec::new());
        c
    }).collect();
    let junk = osis_base::BlobId([6; 32]);
    assert_eq!(lp.peers[2].engine.take_list_blob(&junk, &osis_commit::thing_list::encode_list_blob(&forged)).unwrap(), Some(done.commits[1]));
    let carrier = osis_base::BlobId([7; 32]);
    for l in &pk.lists {
        assert_eq!(lp.peers[2].engine.take_list_blob(&carrier, l).unwrap(), Some(done.commits[1]));
    }
    assert!(lp.peers[2].engine.carries_loose(&carrier), "kept loose until its rotation");
    match valid_only {
        false => drop(lp.peers[2].receive(&pk.bytes, pk.blobs.clone()).unwrap()),
        true => assert!(matches!(lp.peers[2].engine.ingest_valid(&pk.bytes).unwrap(), Some(crate::Ingested::Applied(_))), "taken"),
    }
    assert!(!lp.peers[2].engine.carries_loose(&carrier), "held with its rotation");
    assert!(!lp.peers[2].engine.carries_loose(&junk), "the forged list goes as its rotation arrives");
    assert_eq!(read(&mut lp, 2, t), Some(Value::Str("sibling".into())), "the sibling's write was listed");
    let d0 = lp.peers[2].engine.index_digest();
    lp.peers[2].engine.reload().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[2].engine.index_digest()), None, "reopened");
    lp.peers[2].engine.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[2].engine.index_digest()), None, "rebuilt");
}

// spec/crypto.md §5 Who wraps under what (a rotation's thing lists wrap as it does: under the
// newest read epoch of the thing current when it was made): an outsider removed from t, t
// rotated, then the account rotated by a node removal; r's list of t wraps under t's epoch
// after the outsider's removal, which it never held, while it held t's earlier epoch
#[test]
fn a_party_removed_before_the_rotation_cannot_open_its_list_spec_crypto_5() {
    let (mut lp, a, t) = world(3, 2);
    let o = lp.peers[2].engine.me();
    let held = |lp: &LocalPeer, p: usize| -> Vec<[u8; 32]> {
        let ta = lp.peers[p].engine.core.secret_actor(&t).unwrap();
        lp.peers[p].engine.epochs(&ta).map(|e| e.read.held().map(|(_, s)| *s.expose()).collect()).unwrap_or_default()
    };
    assert!(!held(&lp, 2).is_empty(), "the outsider read t");
    let before = held(&lp, 0).len();
    lp.peers[0].engine.demote(&t, &Demotion { holder: o, new: None, retain: None }).unwrap();
    lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert!(held(&lp, 0).len() > before, "the outsider's removal rotates t");
    lp.advance(10);
    let done = remove(&mut lp, 0, a.devices, 1);
    let r = done.commits[1];
    let w = lp.peers[0].engine.list_wrap_secret(&t, &r).unwrap().expect("a wrap for r's list of t");
    assert!(!held(&lp, 2).contains(w.expose()), "the removed outsider holds the list's epoch");
}

// spec/permissions.md §5.5: a rotation's list names ephemeral commits as durable ones: a
// sibling's ephemeral write the rotator held still counts at an outsider once the rotation
// closes its epoch; one the removed node writes after it does not
#[test]
fn rotation_lists_name_ephemeral_writes_spec_permissions_5_5() {
    let (mut lp, a, t) = world(3, 2);
    let k = Ak::new("x:e+.0").unwrap();
    let eph = |lp: &mut LocalPeer, v: &str| {
        let mut m = crate::Mutation::new();
        m.set(t, &k, &Value::Str(v.into())).unwrap();
        let id = lp.peers[1].engine.commit_in_memory(m).unwrap().unwrap();
        lp.peers[1].engine.package(&id).unwrap().unwrap()
    };
    let pk = eph(&mut lp, "sibling");
    for to in [0, 2] {
        lp.peers[to].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap();
    }
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::Str("sibling".into())));
    let done = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &done.commits[1..]);
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::Str("sibling".into())), "listed by the rotation");
    let late = eph(&mut lp, "removed");
    lp.peers[2].engine.ingest_memory(&late.bytes, u64::MAX).unwrap();
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::Str("sibling".into())), "a later write at the closed epoch counts for nothing");
}

fn seeds(lp: &LocalPeer, peer: usize, p: Tid) -> usize {
    lp.peers[peer].engine.core.accounts.get(&p).map_or(0, |a| a.keys.len())
}

// spec/permissions.md §5.5 (Listings): a node of the account whose write the rotator had not
// received names it in its listing once it holds the rotation, so the write counts again
#[test]
fn an_offline_siblings_write_counts_by_its_listing_spec_permissions_5_5() {
    let (mut lp, a, t) = world(4, 3);
    let w = write(&mut lp, 2, t, "offline");
    let done = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 3, &done.commits[1..]);
    send(&mut lp, 2, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("p".into())), "unnamed at the closed epoch");
    // the sibling gets the removal and rotation, and lists its own write
    send(&mut lp, 0, 2, &done.commits);
    assert!(lp.peers[2].engine.signing_due().unwrap().commits.is_empty(), "the removal's rotation is held: none due");
    let listing = *lp.peers[2].engine.commit_ids().last().unwrap();
    let h = lp.peers[2].engine.header(&listing).unwrap();
    assert!(h.aspects.iter().any(|x| x.ak.as_str() == "listing.0" && x.tid == t), "{h:?}");
    // named, the write's body dropped with its fall is fetched again
    send(&mut lp, 2, 3, &[listing, w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("offline".into())), "named by its author's listing");
}

// spec/permissions.md §5.5 (Listings), spec/crypto.md §7: a node of the account whose listing goes
// on a thing whose delete keys are not here yet takes the rotation in (its own answer never fails
// the receive) and writes the listing once the keys come
#[test]
fn a_listing_waits_for_its_things_delete_keys_spec_permissions_5_5() {
    let (mut lp, a, _) = world(4, 3);
    // the outsider's thing `u`: the account writes there by a raw edge write, then a grant by the
    // flow gives `u` secrets of its own, its `keys.0` in that commit
    let q = lp.peers[3].engine.me();
    let mut m = crate::Mutation::new();
    let u = lp.peers[3].engine.new_thing(&mut m, q);
    m.op(u, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(a.account))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge(Role::Write))) }).unwrap();
    lp.peers[3].commit(m).unwrap();
    lp.peers[3].engine.grant(&u, &a.account, &edge(Role::Write)).unwrap();
    let pks = lp.packages(3).unwrap();
    let carries = |id: &CommitId| lp.peers[3].engine.writes_keyset(&u, id);
    let (key_pks, rest): (Vec<_>, Vec<_>) = pks.into_iter().partition(|pk| carries(&pk.id));
    for pk in rest.iter().chain(&key_pks) {
        lp.deliver(1, pk).unwrap();
    }
    for pk in &rest {
        lp.deliver(2, pk).unwrap();
    }
    assert!(!lp.peers[2].engine.holds_delete_keys(&u).unwrap(), "u's delete keys are not at node 2");
    let w = write(&mut lp, 1, u, "sibling");
    send(&mut lp, 1, 2, &[w]);
    lp.advance(10);
    // received before the rotation (the cutoff), and the rotator never received it: node 2 owes a
    // listing on `u`
    let done = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &done.commits);
    let listing_on = |lp: &LocalPeer| {
        let e = &lp.peers[2].engine;
        e.commit_ids().into_iter().find(|c| e.header(c).is_some_and(|h| h.author == a.account && h.aspects.iter().any(|x| x.ak.as_str() == "listing.0" && x.tid == u)))
    };
    assert_eq!(listing_on(&lp), None, "the listing waits for u's delete keys");
    for pk in &key_pks {
        lp.deliver(2, pk).unwrap();
    }
    assert!(listing_on(&lp).is_some(), "written once the keys came");
    let named = lp.peers[2].engine.get(&u, &Ak::new("listing.0").unwrap()).unwrap();
    let Some(Value::Map(entries)) = named else { panic!("{named:?}") };
    assert!(entries.values().any(|s| matches!(s, Value::Set(ids) if ids.contains(&Value::bytes(&w.0)))), "it names the sibling's write: {entries:?}");
}

// spec/permissions.md §5.5 (Addenda against a rotation): a writer of the thing that received the
// account's write before the rotation vouches for it, for the readers that hold no word of the
// account naming it
#[test]
fn a_writers_addendum_keeps_what_it_received_spec_permissions_5_5() {
    let (mut lp, a, t) = world(4, 2);
    let o = lp.peers[3].engine.me();
    lp.peers[0].engine.grant(&t, &o, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    // the soon removed node's write reaches the outside writer (peer 2), not the rotator
    let w = write(&mut lp, 1, t, "seen outside");
    send(&mut lp, 1, 2, &[w]);
    lp.advance(10);
    let done = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &done.commits[1..]);
    let ad = *lp.peers[2].engine.commit_ids().last().unwrap();
    assert!(lp.peers[2].engine.header(&ad).unwrap().aspects.iter().any(|x| x.ak.as_str() == "addenda.0"), "the writer answers the rotation");
    assert_eq!(read(&mut lp, 2, t), Some(Value::Str("seen outside".into())));
    send(&mut lp, 0, 3, &done.commits[1..]);
    send(&mut lp, 1, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("p".into())));
    // valid again, the write's body dropped with its fall is fetched again
    send(&mut lp, 2, 3, &[ad]);
    send(&mut lp, 1, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("seen outside".into())), "vouched for by the writer");
}

// spec/crypto.md §9, spec/permissions.md §5.4: two nodes removing a third at once fork the
// chain; an outsider follows the rotation it held first and is told of nothing. Each head's line
// lacks the other's removal (blocked), so each node holding both owes a rotation, none
// designated: both rotate at once, superseding both heads and naming them (signed at each), and
// their two rotations fork again. Outside the account only one of them is followed, so that fork
// is owed a merge too: the first node asked makes it, the other then owes nothing, and every
// write of the account counts at the outsider
#[test]
fn concurrent_rotations_fork_and_every_node_supersedes_them_spec_crypto_9() {
    let (mut lp, a, t) = world(4, 3);
    let d0 = remove(&mut lp, 0, a.devices, 2);
    let d1 = remove(&mut lp, 1, a.devices, 2);
    let (r0, r1) = (d0.commits[1], d1.commits[1]);
    send(&mut lp, 1, 0, &d1.commits);
    send(&mut lp, 0, 1, &d0.commits);
    // each holds both forks' seeds (each removal boxed it the epoch its rotation's seed sits under)
    let (m0, m1) = (lp.peers[0].engine.signing_due().unwrap(), lp.peers[1].engine.signing_due().unwrap());
    assert_eq!((m0.commits.len(), m1.commits.len()), (1, 1), "each node rotates");
    let (m0, m1) = (m0.commits[0], m1.commits[0]);
    for (k, m) in [(0, m0), (1, m1)] {
        let rh = lp.peers[k].engine.header(&m).unwrap().rotation.clone().unwrap();
        assert_eq!(rh.supersedes.iter().copied().collect::<std::collections::BTreeSet<_>>(), [r0, r1].into());
        assert_eq!(rh.names.len(), 1);
    }
    send(&mut lp, 0, 3, &[r0]);
    send(&mut lp, 1, 3, &[r1]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("p".into())), "the account's earlier write counts through the fork");
    let v = lp.peers[3].engine.core.account_view(&a.account).unwrap();
    assert_eq!(v.heads(), vec![r0], "the outsider follows the rotation it held first");
    assert!(lp.peers[3].engine.account_disputes().is_empty(), "honest concurrent rotations warn of nothing");
    send(&mut lp, 0, 1, &[m0]);
    send(&mut lp, 1, 0, &[m1]);
    let w0 = write(&mut lp, 0, t, "after");
    send(&mut lp, 1, 3, &[m1]);
    send(&mut lp, 0, 3, &[m0, w0]);
    // node 0 writes at its own rotation, which the outsider holds beside the one it follows
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("p".into())), "not yet: m1 is followed");
    let m2 = lp.peers[0].engine.signing_due().unwrap().commits;
    assert_eq!(m2.len(), 1, "the fork is owed a merge");
    send(&mut lp, 0, 1, &m2);
    assert!(lp.peers[1].engine.signing_due().unwrap().commits.is_empty(), "merged once");
    // the merge's list names node 0's listing, which names its write
    let ids = lp.peers[0].engine.commit_ids();
    send(&mut lp, 0, 3, &ids);
    // its body, dropped while it did not count, is offered again
    send(&mut lp, 0, 3, &[w0]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())), "node 0's write counts by its word");
    assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads(), m2);
    assert!(lp.peers[3].engine.account_disputes().is_empty());
}

// spec/requirements.md Cost, notes/coordination.md (Check scaling): a removal lists the commits
// of the epoch it closes, never the account's earlier history: the second rotation's lists are
// as long after n writes at the first epoch as after 10n
#[test]
fn a_rotation_lists_its_epoch_only() {
    let count = |n: usize| {
        let (mut lp, a, t) = world(3, 3);
        for i in 0..n {
            write(&mut lp, 0, t, &format!("e0 {i}"));
        }
        lp.sync_all().unwrap();
        let d = remove(&mut lp, 0, a.devices, 2);
        lp.sync_all().unwrap();
        for i in 0..5 {
            write(&mut lp, 0, t, &format!("e1 {i}"));
        }
        let second = remove(&mut lp, 0, a.devices, 1);
        let ids = |r: &CommitId, lp: &mut LocalPeer| lp.peers[0].engine.list_blob(r, None).unwrap().map(|b| osis_commit::thing_list::decode_list_blob(&b).unwrap().iter().map(|c| match &c.list.ids { osis_commit::thing_list::ListIds::Inline(v) => v.len(), _ => 0 }).sum::<usize>()).unwrap_or(0);
        (ids(&d.commits[1], &mut lp), ids(&second.commits[1], &mut lp))
    };
    let (small, large) = (count(5), count(50));
    assert!(large.0 >= small.0 + 45, "the first rotation lists its epoch: {small:?} {large:?}");
    assert_eq!(small.1, large.1, "the second lists only its own epoch");
}

// spec/permissions.md §5.4, §5.5: a removed node that forks the chain from its closed epoch, its
// rotation's list naming its own later write, wins nothing once a node of the account rotates:
// each node of the account holding the fork owes the rotation (none is designated), which
// supersedes the fork unnamed (D's roster does not authorize it), so the fork is rejected with
// its list, and the removed node's write counts for nothing at a sibling or an outsider holding
// either rotation; the two rotations fork, and the first node asked merges them
#[test]
fn a_removed_nodes_fork_is_rejected_by_every_node_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 3, &done.commits[1..]);
    // the removed node, unaware, writes and rotates: its rotation lists the write
    let late = write(&mut lp, 2, t, "removed");
    let fork = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    for to in [0, 1, 3] {
        send(&mut lp, 2, to, &[late, fork]);
    }
    let mut merges = Vec::new();
    for k in [0, 1] {
        merges.extend(lp.peers[k].engine.signing_due().unwrap().commits);
    }
    assert_eq!(merges.len(), 2, "each node of the account rotates");
    for (k, m) in [0, 1].into_iter().zip(&merges) {
        let h = lp.peers[k].engine.header(m).unwrap();
        let rh = h.rotation.as_ref().unwrap();
        assert!(rh.supersedes.contains(&fork) && rh.names.is_empty(), "the fork superseded unnamed: {rh:?}");
    }
    for (k, m) in [0, 1].into_iter().zip(merges.clone()) {
        for to in [0, 1, 3] {
            if to != k {
                send(&mut lp, k, to, &[m]);
            }
        }
    }
    // the two rotations made at once fork: the first node asked merges them, the other then
    // owes nothing
    let m = lp.peers[0].engine.signing_due().unwrap().commits;
    assert_eq!(m.len(), 1, "the fork is owed a merge");
    for to in [1, 3] {
        send(&mut lp, 0, to, &m);
    }
    assert!(lp.peers[1].engine.signing_due().unwrap().commits.is_empty(), "merged once");
    for k in [0, 1] {
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().heads(), m.clone());
    }
    // the write's body dropped with its fall is offered again
    send(&mut lp, 2, 3, &[late]);
    for k in [0, 1, 3] {
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("removed".into())), "peer {k}: the removed node's write counts after the merge");
    }
    let w = write(&mut lp, 1, t, "after");
    send(&mut lp, 1, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())), "the merge's epoch is open");
    // told: the account's line rejects a fork
    assert_eq!(lp.peers[3].engine.account_disputes().len(), 1);
}

// spec/permissions.md §5.5 (Listings): a listing names what it names only while it counts. A
// sibling's write counts at an outsider by the sibling's listing; once a later rotation closes
// the listing's epoch without naming the listing (its rotator never received it, and removes the
// sibling), the write counts for nothing, as a rebuild of the index reads it
#[test]
fn a_listing_names_nothing_once_its_epoch_closes_unnamed_spec_permissions_5_5() {
    let (mut lp, a, t) = world(4, 3);
    let c = write(&mut lp, 1, t, "sibling");
    let r1 = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &r1.commits);
    send(&mut lp, 0, 3, &r1.commits[1..]);
    let listing = *lp.peers[1].engine.commit_ids().last().unwrap();
    assert!(lp.peers[1].engine.header(&listing).unwrap().aspects.iter().any(|x| x.ak.as_str() == "listing.0"));
    send(&mut lp, 1, 3, &[listing, c]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("sibling".into())), "named by the listing");
    lp.advance(10);
    let r2 = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 3, &r2.commits[1..]);
    let incremental = read(&mut lp, 3, t);
    lp.peers[3].engine.rebuild_index().unwrap();
    assert_eq!(incremental, read(&mut lp, 3, t), "incremental and rebuilt agree");
    assert_eq!(incremental, Some(Value::Str("p".into())), "the listing's epoch closed unnamed: the write counts for nothing");
}

// spec/permissions.md §5.5 (listings; nothing waits for a thing list): a listing at an epoch a
// later rotation closes counts once that rotation's thing list naming it arrives, and then names
// what it names: the sibling's write it lists counts again, as a rebuild of the index reads it
#[test]
fn a_listing_named_late_names_again_spec_permissions_5_5() {
    let (mut lp, a, t) = world(5, 4);
    let c = write(&mut lp, 1, t, "sibling");
    let r1 = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &r1.commits);
    send(&mut lp, 0, 4, &r1.commits[1..]);
    let listing = *lp.peers[1].engine.commit_ids().last().unwrap();
    assert!(lp.peers[1].engine.header(&listing).unwrap().aspects.iter().any(|x| x.ak.as_str() == "listing.0"));
    send(&mut lp, 1, 0, &[listing]);
    send(&mut lp, 1, 4, &[listing, c]);
    assert_eq!(read(&mut lp, 4, t), Some(Value::Str("sibling".into())), "named by the listing");
    lp.advance(10);
    let r2 = remove(&mut lp, 0, a.devices, 3);
    let rot = r2.commits[1];
    assert!(lp.peers[0].engine.rotation_lists(&rot).unwrap().iter().any(|(_, ids)| ids.contains(&listing)), "the rotation lists the listing");
    // the rotation first, its lists after
    let pk = lp.peers[0].engine.package(&rot).unwrap().unwrap();
    lp.peers[4].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    assert_eq!(read(&mut lp, 4, t), Some(Value::Str("p".into())), "the listing unnamed at its closed epoch names nothing");
    for l in &pk.lists {
        lp.peers[4].engine.hold_lists(l).unwrap();
    }
    send(&mut lp, 1, 4, &[listing, c]);
    let incremental = read(&mut lp, 4, t);
    lp.peers[4].engine.rebuild_index().unwrap();
    send(&mut lp, 1, 4, &[listing, c]);
    assert_eq!(incremental, read(&mut lp, 4, t), "incremental and rebuilt agree");
    assert_eq!(incremental, Some(Value::Str("sibling".into())), "the listing, named, names the write again");
}

/// The keyset of `m` the box of `a`'s newest read epoch to `m` names, at peer `i`.
fn read_box_at(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid) -> Option<osis_crypto::Epoch> {
    let e = super::tests::newest_read(lp, i, a)?;
    let s = lp.peers[i].engine.get_typed(&a, &ct::SECRETS).unwrap()?;
    s.boxes.iter().find(|(k, _)| k.holder == m && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).and_then(|(_, b)| osis_keys::box_keysets(b).into_iter().next())
}

// spec/crypto.md §4 (Encrypting under: an account's epochs minted before a node's removal from
// its devices actor do not cover it): Carol (peer 0) removes her lost node L (peer 1) from her
// account P, which rotates P. T, a team of peer 2 she only reads, still boxes P at P's first
// epoch, whose seed L holds. Her X boxes T at that epoch of T, so she rotates X leaving T out and
// L opens nothing of it; once T's admin moves T onto P's new epoch, she seals T again.
#[test]
fn lost_node_opens_nothing_through_a_team_its_account_reads_spec_crypto_4() {
    use super::tests::{all_boxed, group, held_by, leaked, newest_read, openable, settle};
    let (mut lp, a, _) = world(3, 2);
    let p = a.account;
    let t = group(&mut lp, 2);
    lp.peers[2].engine.grant(&t, &p, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let x = group(&mut lp, 0);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let l = lp.peers[1].engine.tid();
    let p1 = read_box_at(&mut lp, 0, t, p).unwrap();
    let mut start = held_by(&lp, 1, &[t, x]);
    start.extend(osis_keys::ROLES.map(|r| (p, r, p1)));
    remove(&mut lp, 0, a.devices, 1);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
    assert!(!done.commits.is_empty() && still.is_empty(), "Carol rotates X (its box to P names P's closed epoch)");
    assert_eq!(read_box_at(&mut lp, 0, x, t), None, "leaving T out");
    let w = newest_read(&lp, 0, x).unwrap();
    assert!(!openable(&mut lp, 0, &[t, x], l, start.clone()).contains(&(x, Role::Read, w)), "L opens nothing Carol writes under X");
    lp.sync_all().unwrap();
    settle(&mut lp, &[2, 0], &[t, x]);
    assert!(all_boxed(&mut lp, 0, &[t, x]), "T boxed at X again");
    assert_ne!(read_box_at(&mut lp, 2, t, p), Some(p1), "T moved onto P's new epoch");
    assert_eq!(leaked(&mut lp, 0, &[t, x], l, start), Vec::<Tid>::new());
}

// spec/crypto.md §4 (Encrypting under; Account keysets; Seal): a node of P holding a removal
// from D but not yet P's rotation for it seals P at no epoch the removed node holds: it leaves P
// out of X until that rotation arrives.
#[test]
fn node_knowing_a_removal_seals_its_account_at_no_epoch_before_its_rotation_spec_crypto_4() {
    use super::tests::{group, newest_read, openable};
    let (mut lp, a, _) = world(3, 3);
    let p = a.account;
    let x = group(&mut lp, 2);
    lp.sync_all().unwrap();
    let l = lp.peers[1].engine.tid();
    let p1 = read_box_at(&mut lp, 2, x, p).unwrap();
    let mut start = super::tests::held_by(&lp, 1, &[x]);
    start.extend(osis_keys::ROLES.map(|r| (p, r, p1)));
    let done = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &done.commits[..1]);
    let _ = lp.peers[2].engine.ensure_rotated(&x).unwrap();
    let w = newest_read(&lp, 2, x).unwrap();
    assert_ne!(read_box_at(&mut lp, 2, x, p), Some(p1), "P not sealed at the epoch L holds");
    assert!(!openable(&mut lp, 2, &[x], l, start).contains(&(x, Role::Read, w)), "L opens nothing of X's new epoch");
}

// spec/crypto.md §4 (Encrypting under; Account keysets): order is not knowledge. N1 (peer 0)
// removes lost node L (peer 1) from D, rotating P (r1). N2 (peer 3), not holding that, later
// removes Y (peer 4): its rotation r2 of P, ordered after L's removal, seals r2's seed under D's
// epoch boxing L. T's admin (peer 5) moves T onto r2; N3 (peer 2) holds X boxing T and receives
// r2 first, so follows it (r2 is open there: T's box to P at r2 is not stale). N3, then holding
// everything, judges r2 by descent: no rotation naming L's removal is on r2's line, so N3
// rotates X leaving T out, and L opens nothing N3 writes under X.
#[test]
fn an_ignorant_fork_ordered_after_a_removal_covers_nothing_spec_crypto_4() {
    use super::tests::{group, held_by, newest_read, openable};
    let (mut lp, a, _) = world(6, 5);
    let p = a.account;
    let t = group(&mut lp, 5);
    lp.peers[5].engine.grant(&t, &p, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let x = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let l = lp.peers[1].engine.tid();
    let p0 = read_box_at(&mut lp, 5, t, p).unwrap();
    let mut known = held_by(&lp, 1, &[t, x]);
    let r1 = remove(&mut lp, 0, a.devices, 1);
    lp.advance(1000);
    remove(&mut lp, 3, a.devices, 4);
    let n2 = lp.peers[3].engine.commit_ids();
    send(&mut lp, 3, 5, &n2);
    let (rt, _) = lp.peers[5].engine.ensure_rotated(&t).unwrap();
    let p2 = read_box_at(&mut lp, 5, t, p).unwrap();
    assert_ne!(p2, p0, "T's admin moves T onto r2");
    // L holds r2's seed: D's epoch it sits under boxes L
    known.extend(osis_keys::ROLES.into_iter().flat_map(|r| [(p, r, p0), (p, r, p2)]));
    send(&mut lp, 3, 2, &n2);
    send(&mut lp, 5, 2, &rt.commits);
    lp.advance(1000);
    send(&mut lp, 0, 2, &r1.commits);
    assert_eq!(read_box_at(&mut lp, 2, t, p), Some(p2), "N3 holds T boxing P at r2");
    let _ = lp.peers[2].engine.ensure_rotated(&x).unwrap();
    let w = newest_read(&lp, 2, x).unwrap();
    assert!(!openable(&mut lp, 2, &[t, x], l, known).contains(&(x, Role::Read, w)), "L opens nothing N3 writes under X");
}

// spec/crypto.md §4 (Encrypting under; Account keysets): as the ignorant fork above, but N3
// never receives N2's commits: it holds L's removal, r1 and T's keyset boxing P at r2, which it
// cannot open (only r2's seed does). Sealing T there is judged by T's box to N3's own account at
// an epoch whose rotation it does not hold, so it shows no cover of L's removal: N3 rotates X
// leaving T out, and L opens nothing N3 writes under X.
#[test]
fn a_keyset_boxing_the_account_at_an_epoch_not_held_is_not_sealed_to_spec_crypto_4() {
    use super::tests::{group, held_by, newest_read, openable};
    let (mut lp, a, _) = world(6, 5);
    let p = a.account;
    let t = group(&mut lp, 5);
    lp.peers[5].engine.grant(&t, &p, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let x = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&x, &t, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let l = lp.peers[1].engine.tid();
    let p0 = read_box_at(&mut lp, 5, t, p).unwrap();
    let mut known = held_by(&lp, 1, &[t, x]);
    let r1 = remove(&mut lp, 0, a.devices, 1);
    lp.advance(1000);
    remove(&mut lp, 3, a.devices, 4);
    let n2 = lp.peers[3].engine.commit_ids();
    send(&mut lp, 3, 5, &n2);
    let (rt, _) = lp.peers[5].engine.ensure_rotated(&t).unwrap();
    let p2 = read_box_at(&mut lp, 5, t, p).unwrap();
    assert_ne!(p2, p0, "T's admin moves T onto r2");
    known.extend(osis_keys::ROLES.into_iter().flat_map(|r| [(p, r, p0), (p, r, p2)]));
    send(&mut lp, 5, 2, &rt.commits);
    lp.advance(1000);
    send(&mut lp, 0, 2, &r1.commits);
    let _ = lp.peers[2].engine.ensure_rotated(&x).unwrap();
    let w = newest_read(&lp, 2, x).unwrap();
    assert!(!openable(&mut lp, 2, &[t, x], l, known).contains(&(x, Role::Read, w)), "L opens nothing N3 writes under X");
}

// spec/crypto.md §9 (Seeds): a node takes a seed up only under an established epoch of D: N1 (peer 0)
// removes Y (peer 4, rotation r0), then L (peer 1, r1; the D epoch it mints, which r1's seed sits
// under, names both removals). N2 (peer 2) holds L's removal and r1 but not Y's removal: that D
// epoch opens for it but is not established, so it takes up no seed of r1 and signs nothing at
// r1, its removal of Z (peer 5) and the rotation from r1 among them; that rotation would seal the
// new seed under N2's own D epoch, boxing Y, on a line naming Y's removal, so a node knowing it
// would write under it. Once N2 holds Y's removal it takes the seed up, and its rotation for Z's
// removal goes under a D epoch boxing neither.
#[test]
fn a_seed_under_a_devices_epoch_not_established_is_not_taken_up_spec_crypto_9() {
    let (mut lp, a, _) = world(6, 6);
    let p = a.account;
    let ry = remove(&mut lp, 0, a.devices, 4);
    lp.advance(1000);
    let rl = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &ry.commits[1..]);
    send(&mut lp, 0, 2, &rl.commits);
    assert_eq!(seeds(&lp, 2, p), 1, "N2 takes up no seed under a D epoch whose names it has not met");
    lp.advance(1000);
    let z = lp.peers[5].engine.tid();
    assert!(lp.peers[2].engine.demote(&a.devices, &Demotion { holder: z, new: None, retain: None }).is_err(), "N2 signs nothing at r1 without its seed");
    send(&mut lp, 0, 2, &ry.commits[..1]);
    lp.peers[2].engine.signing_due().unwrap();
    assert_eq!(seeds(&lp, 2, p), 3, "Y's removal held: r0's and r1's seeds taken up");
    let rz = remove(&mut lp, 2, a.devices, 5);
    assert_eq!(rz.commits.len(), 2, "the removal, then the rotation");
    let rot = rz.commits[1];
    // the new seed goes under a D epoch boxing neither Y nor Z
    let key = lp.peers[2].engine.header(&rot).unwrap().rotation.as_ref().unwrap().signing_key;
    let acct = lp.peers[2].engine.get_typed(&a.devices, &ct::ACCOUNT).unwrap().unwrap();
    let under = acct.seeds.get(key.to_bytes().as_slice()).unwrap().under.clone();
    let boxes = lp.peers[2].engine.get_typed(&a.devices, &ct::SECRETS).unwrap().unwrap().boxes;
    let gone = [lp.peers[4].engine.tid(), z];
    assert!(boxes.keys().any(|k| k.role == Role::Read && k.epoch == under), "D's epoch boxes the nodes left");
    assert!(!boxes.keys().any(|k| k.role == Role::Read && k.epoch == under && gone.contains(&k.holder)), "Y and Z open no new seed");
}

// spec/permissions.md §3 (a node's removal from d), spec/crypto.md §4 (an account's epoch e is blocked): a removal
// is covered only by a rotation D's roster authorizes. N1 (peer 0) removes L (peer 1); N2 (peer
// 2) then removes N1, so N1's rotation no longer covers L's removal and N2's next rotation names
// it again: the epoch it mints covers both removals, so N2 seals P at it.
#[test]
fn a_removal_named_by_a_removed_node_is_named_again_spec_permissions_3() {
    use super::tests::group;
    let (mut lp, a, _) = world(3, 3);
    let p = a.account;
    let r1 = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &r1.commits);
    lp.advance(1000);
    remove(&mut lp, 2, a.devices, 0);
    let again = lp.peers[2].engine.signing_due().unwrap();
    assert_eq!(again.commits.len(), 1, "L's removal named again");
    let lists = lp.peers[2].engine.rotation_lists(&again.commits[0]).unwrap();
    assert!(lists.iter().any(|(_, ids)| ids.contains(&r1.commits[0])), "the new rotation names L's removal");
    assert!(lp.peers[2].engine.signing_due().unwrap().commits.is_empty(), "nothing more is due");
    let x = group(&mut lp, 2);
    let _ = lp.peers[2].engine.ensure_rotated(&x).unwrap();
    assert!(read_box_at(&mut lp, 2, x, p).is_some(), "N2 seals P into its own group");
}

// spec/permissions.md §5.4 (Following, at a node of P: the removals each rotation carries, those
// its header names by its minter signed at the epoch it rotates), §5.5 (a counting removal from D no rotation D's roster
// authorizes names, and no held rotation it does not count carries: named again). As above, but before N2 asks what is due, removed N1, holding r1's keys, forks at
// r1 sealed as a key actor it makes up (or as itself), its header naming L's removal: that fork
// carries nothing (its minter or its epoch is not the removal's), so N2's rotation answering it still names
// L's removal
#[test]
fn a_header_naming_anothers_removal_carries_none_spec_permissions_5_4() {
    header_naming_anothers_removal(false);
    header_naming_anothers_removal(true);
}

fn header_naming_anothers_removal(sealed_as_n1: bool) {
    use osis_crypto::{AccountEpochKeys, Secret32};
    let (mut lp, a, _) = world(3, 3);
    let r1 = remove(&mut lp, 0, a.devices, 1);
    send(&mut lp, 0, 2, &r1.commits);
    lp.advance(1000);
    remove(&mut lp, 2, a.devices, 0);
    let (rem, at) = (r1.commits[0], r1.commits[1]);
    let fb = {
        let e = &lp.peers[0].engine;
        let rec = e.core.created(&a.account).unwrap().clone();
        let vk = e.header(&at).unwrap().rotation.clone().unwrap().signing_key;
        let at_keys = AccountEpochKeys::from_seed(e.core.accounts.get(&a.account).unwrap().keys.get(&vk).unwrap().seed());
        let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([71; 32]));
        let header = osis_commit::RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: vec![at], names: Vec::new(), takes: Vec::new(), removals: vec![rem], list_root: [0; 32] };
        let made_up = super::tests_account::rotation_at(rec, (at, &at_keys), &[], &next, header, osis_base::Ts::make(e.now(), 0).unwrap());
        // and the same header sealed as N1 itself: its minter is the removal's, its epoch is not
        let mut b = osis_commit::CommitBlob::decode(&made_up).unwrap();
        let id = b.header.id();
        let inner = osis_crypto::seal_inner(&at_keys.inner, &id.0, &e.core.id.tid(), &e.core.id.keys().signing);
        b.sigs = osis_commit::Sigs::signed(&id, &at_keys.signing, Some(inner), Vec::new());
        if sealed_as_n1 { b.encode() } else { made_up }
    };
    let f = give(&mut lp, &fb, &[2]);
    let again = lp.peers[2].engine.signing_due().unwrap();
    assert_eq!(again.commits.len(), 1, "one rotation");
    let h = lp.peers[2].engine.header(&again.commits[0]).unwrap().rotation.clone().unwrap();
    assert!(h.supersedes.contains(&f), "the fork answered");
    let lists = lp.peers[2].engine.rotation_lists(&again.commits[0]).unwrap();
    assert!(lists.iter().any(|(_, ids)| ids.contains(&rem)), "L's removal named again");
    assert!(lp.peers[2].engine.signing_due().unwrap().commits.is_empty(), "nothing more is due");
}

/// A plain fork of `a`'s chain from its first epoch to a fresh epoch from `seed`, as removed
/// node `by` (which still holds the first epoch's seed) can sign after every merge.
fn refork(lp: &mut LocalPeer, by: usize, a: &CreatedAccount, seed: u8) -> Vec<u8> {
    let e = &lp.peers[by].engine;
    let rec = e.core.created(&a.account).unwrap().clone();
    let osis_base::CreationRecord::KeyActor { public_key, .. } = &rec else { panic!("an account") };
    let first = e.core.accounts.get(&a.account).unwrap().keys.get(&osis_crypto::VerifyingKey::from_slice(public_key).unwrap()).unwrap().seed().clone();
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    super::tests_account::rotation(rec, &osis_crypto::AccountEpochKeys::from_seed(&first), &osis_crypto::AccountEpochKeys::from_seed(&osis_crypto::Secret32::from_bytes([seed; 32])), ts)
}

/// Ingests `bytes` at each of `to`, a millisecond apart; its commit ID.
fn give(lp: &mut LocalPeer, bytes: &[u8], to: &[usize]) -> CommitId {
    for &k in to {
        lp.advance(1);
        lp.peers[k].engine.ingest(bytes, Vec::new()).unwrap();
    }
    osis_commit::CommitBlob::decode(bytes).unwrap().id()
}

/// The rotation `nodes` owe, each asked in turn once the rotations made before reach it (any
/// node of the account makes it: the first asked that holds what it answers), sent to every
/// peer in `to`.
fn merge(lp: &mut LocalPeer, nodes: &[usize], to: &[usize]) -> CommitId {
    let mut made = Vec::new();
    for &k in nodes {
        for &(by, m) in &made {
            if by != k {
                lp.advance(1);
                send(lp, by, k, &[m]);
            }
        }
        let d = lp.peers[k].engine.signing_due().unwrap();
        made.extend(d.commits.iter().map(|c| (k, *c)));
    }
    assert_eq!(made.len(), 1, "one rotation, by the first node asked that owes it: {made:?}");
    let (by, m) = made[0];
    for &k in to {
        if k != by {
            lp.advance(1);
            send(lp, by, k, &[m]);
        }
    }
    m
}

// spec/permissions.md §5.4 (Placing): a removed node keeps its old epoch's key and forks the chain
// plainly from it after every rotation. A reader that held the removal first disregards every
// such fork (it is beside the line it follows): the account's writes keep counting, none of the
// fork's does, and once a node of the account rejects a fork the reader is told
#[test]
fn a_removed_nodes_reforks_never_count_after_the_removal_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 3, &done.commits[1..]);
    let one = write(&mut lp, 1, t, "one");
    send(&mut lp, 1, 3, &[one]);
    let says = |lp: &mut LocalPeer, v: &str| assert_eq!(read(lp, 3, t), Some(Value::Str(v.into())));
    says(&mut lp, "one");
    let mut later = "one".to_string();
    for (round, seed) in [90u8, 91, 92].into_iter().enumerate() {
        let f = refork(&mut lp, 2, &a, seed);
        let f = give(&mut lp, &f, &[0, 1, 3]);
        let v = lp.peers[3].engine.core.account_view(&a.account).unwrap();
        assert!(v.heads().len() == 1 && !v.rotation_counts(&f), "round {round}: the fork is disregarded");
        says(&mut lp, &later);
        merge(&mut lp, &[0, 1], &[0, 1, 3]);
        later = format!("after rotation {round}");
        let w = write(&mut lp, 1, t, &later);
        send(&mut lp, 1, 3, &[w]);
        says(&mut lp, &later);
        assert_eq!(lp.peers[3].engine.account_disputes().len(), 1, "round {round}: told once a fork is rejected");
    }
}

// spec/permissions.md §5.4 (Placing; Warning): a reader the removed node's fork reached before the
// removal follows the fork; it is told once the account's line rejects it, and stays. Its user's
// switch to the account's line holds (through a rebuild and later forks), and every write of the
// account then counts there
#[test]
fn a_reader_the_fork_reached_first_stays_until_its_user_switches_spec_permissions_5_4() {
    let (mut lp, a, t) = world(6, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 3, &done.commits[1..]);
    let f1 = refork(&mut lp, 2, &a, 80);
    let f1 = give(&mut lp, &f1, &[0, 1, 3]);
    let m1 = merge(&mut lp, &[0, 1], &[0, 1, 3]);
    let w = write(&mut lp, 1, t, "merged");
    send(&mut lp, 1, 3, &[w]);
    // the removed node forks again; peers 4 and 5 get that fork before anything else
    let f2b = refork(&mut lp, 2, &a, 81);
    let f2 = give(&mut lp, &f2b, &[4, 5, 3]);
    let told = |lp: &mut LocalPeer, k: usize| lp.peers[k].drain_events().into_iter().filter(|e| matches!(e, crate::events::Event::AccountDisputed { .. })).count();
    for k in [4, 5] {
        send(&mut lp, 0, k, &done.commits[1..]);
        send(&mut lp, 3, k, &[f1, m1, w]);
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().heads(), vec![f2], "peer {k} follows the fork it held first");
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("merged".into())), "peer {k}: the account's line is beside it");
        assert_eq!(told(&mut lp, k), 0, "peer {k}: nothing rejects its fork yet");
    }
    // the next rotation of the account rejects the fork: told, and staying
    for k in [0, 1] {
        lp.advance(1);
        lp.peers[k].engine.ingest(&f2b, Vec::new()).unwrap();
    }
    let m2 = merge(&mut lp, &[0, 1], &[0, 1]);
    let w2 = write(&mut lp, 1, t, "after");
    for k in [3, 4, 5] {
        send(&mut lp, 0, k, &[m2]);
        send(&mut lp, 1, k, &[w2]);
    }
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())));
    assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads(), vec![m2]);
    for k in [4, 5] {
        assert_eq!(told(&mut lp, k), 1, "peer {k} is told");
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().heads(), vec![f2], "peer {k} stays");
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("after".into())));
        let ds = lp.peers[k].engine.account_disputes();
        assert!(ds.len() == 1 && ds[0].side == f2 && ds[0].lines.contains(&m2) && !ds[0].chosen);
    }
    // peer 5's user switches; a rebuild and a later fork change nothing
    lp.peers[5].engine.choose_line(a.account, m2).unwrap();
    // the write's body, dropped while it did not count, is offered again
    send(&mut lp, 1, 5, &[w2]);
    assert_eq!(read(&mut lp, 5, t), Some(Value::Str("after".into())), "switched");
    lp.peers[5].engine.rebuild_index().unwrap();
    let f3 = refork(&mut lp, 2, &a, 82);
    give(&mut lp, &f3, &[5]);
    assert_eq!(read(&mut lp, 5, t), Some(Value::Str("after".into())), "the switch holds");
    let ds = lp.peers[5].engine.account_disputes();
    assert!(ds.len() == 1 && ds[0].side == m2 && ds[0].chosen);
    assert_ne!(read(&mut lp, 4, t), Some(Value::Str("after".into())), "peer 4 stays with the fork");
}

// spec/permissions.md §5.4 (Following, at a node of P): a removed node's plain rotation never
// outweighs its removal at the account's nodes. Node 2 rotates while node 0 removes it; node 1
// gets node 2's rotation first and holds its seed, then the removal: it disregards node 2's
// rotation. The rotation of the account owed rejects it (unnamed): node 1 follows that, so its
// next write counts at an outsider
#[test]
fn a_node_follows_the_merge_over_a_removed_nodes_earlier_rotation_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let x0 = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    send(&mut lp, 2, 1, &[x0]);
    lp.advance(5);
    let done = remove(&mut lp, 0, a.devices, 2);
    lp.advance(5);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 2, 0, &[x0]);
    send(&mut lp, 0, 3, &done.commits[1..]);
    send(&mut lp, 2, 3, &[x0]);
    let m = merge(&mut lp, &[0, 1], &[0, 1, 3]);
    for k in [0, 1, 3] {
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().preferred(), m, "peer {k} prefers the rotation");
    }
    let w = write(&mut lp, 1, t, "after");
    send(&mut lp, 1, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())), "node 1's write counts");
    lp.peers[1].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[1].engine.core.account_view(&a.account).unwrap().preferred(), m, "node 1 after a rebuild");
}

// spec/permissions.md §5.5 (epoch rule; listings): an honest node's writes at a removed node's
// rotation outlive it. Laptop (node 2) rotates offline while phone (node 0) removes it; tablet
// (node 1) got the laptop's rotation first and wrote at its epoch. The phone's merge rejects the
// laptop's rotation, so its epoch is void; the tablet's listing names its own write there, and
// the write counts at every node and at an outsider, as a rebuilt index reads it
#[test]
fn an_honest_write_at_a_removed_nodes_rotation_counts_spec_permissions_5_5() {
    let (mut lp, a, t) = world(4, 3);
    let x0 = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    send(&mut lp, 2, 1, &[x0]);
    lp.advance(5);
    let w = write(&mut lp, 1, t, "tablet");
    assert_eq!(lp.peers[1].engine.header(&w).unwrap().epoch, Some(x0), "the tablet writes at the laptop's epoch");
    lp.advance(5);
    let done = remove(&mut lp, 0, a.devices, 2);
    lp.advance(5);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 2, 0, &[x0]);
    send(&mut lp, 0, 3, &done.commits[1..]);
    send(&mut lp, 2, 3, &[x0]);
    let m = merge(&mut lp, &[0, 1], &[0, 1, 3]);
    assert!(!lp.peers[0].engine.header(&m).unwrap().rotation.as_ref().unwrap().names.contains(&x0), "the merge leaves the laptop's rotation unnamed");
    let ids = lp.peers[1].engine.commit_ids();
    for k in [0, 3] {
        send(&mut lp, 1, k, &ids);
        // the write's body dropped while nothing named it is offered again
        send(&mut lp, 1, k, &[w]);
    }
    for k in [0, 1, 3] {
        assert!(!lp.peers[k].engine.core.account_view(&a.account).unwrap().rotation_counts(&x0), "peer {k}: the laptop's rotation is void");
        assert_eq!(read(&mut lp, k, t), Some(Value::Str("tablet".into())), "peer {k}: the tablet's write counts");
        lp.peers[k].engine.rebuild_index().unwrap();
        assert_eq!(read(&mut lp, k, t), Some(Value::Str("tablet".into())), "peer {k} after a rebuild");
    }
}

// spec/permissions.md §5.4 (Authorizes): a removed node's rotation beside its removal stands
// for D's roster nowhere, nor does a line built on it. The tablet (node 1) rotates on the
// laptop's (node 2) rotation before the phone's (node 0) removal of the laptop reaches it: the
// phone's merge names neither, the tablet follows the merge, and the tablet's write at its own
// rotation's epoch counts by its listing
#[test]
fn a_line_on_a_removed_nodes_rotation_is_merged_out_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let x0 = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    send(&mut lp, 2, 1, &[x0]);
    lp.advance(5);
    let s1 = lp.peers[1].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    let w = write(&mut lp, 1, t, "tablet");
    assert_eq!(lp.peers[1].engine.header(&w).unwrap().epoch, Some(s1));
    lp.advance(5);
    let done = remove(&mut lp, 0, a.devices, 2);
    lp.advance(5);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 2, 0, &[x0]);
    send(&mut lp, 1, 0, &[s1]);
    send(&mut lp, 0, 3, &done.commits[1..]);
    send(&mut lp, 2, 3, &[x0]);
    send(&mut lp, 1, 3, &[s1]);
    let m = merge(&mut lp, &[0, 1], &[0, 1, 3]);
    assert!(lp.peers[0].engine.header(&m).unwrap().rotation.as_ref().unwrap().names.is_empty(), "the merge names no line through the laptop's rotation");
    let ids = lp.peers[1].engine.commit_ids();
    for k in [0, 3] {
        send(&mut lp, 1, k, &ids);
        send(&mut lp, 1, k, &[w]);
    }
    for k in [0, 1, 3] {
        let v = lp.peers[k].engine.core.account_view(&a.account).unwrap();
        assert!(v.preferred() == m && !v.rotation_counts(&s1), "peer {k} prefers the rotation");
        assert_eq!(read(&mut lp, k, t), Some(Value::Str("tablet".into())), "peer {k}: the tablet's write counts");
    }
}

// spec/permissions.md §5.4 (Authorizes): a re-added node's rotations made after its re-add
// stand for D's roster. Node 0 removes node 2 and pairs it again; node 2 then removes node 1:
// node 0 follows node 2's rotation, minted by a current node descending from the re-grant
#[test]
fn a_re_added_nodes_later_rotation_is_authorized_spec_permissions_5_4() {
    let (mut lp, a, _) = world(3, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 2, &done.commits);
    lp.advance(5);
    let node = lp.peers[2].engine.tid();
    let (done, all) = lp.peers[0].engine.pair(&node).unwrap();
    send(&mut lp, 0, 2, &all);
    send(&mut lp, 0, 1, &done.commits);
    lp.peers[2].engine.paired(&a.account).unwrap();
    lp.sync_all().unwrap();
    lp.advance(5);
    let r = remove(&mut lp, 2, a.devices, 1);
    let rot = *r.commits.last().unwrap();
    assert!(lp.peers[2].engine.header(&rot).unwrap().rotation.is_some(), "the removal's rotation");
    send(&mut lp, 2, 0, &r.commits);
    let v = lp.peers[0].engine.core.account_view(&a.account).unwrap();
    assert_eq!(v.authorized_by(&rot), Some(node), "minted by the re-added node after its re-add");
    assert_eq!(v.preferred(), rot, "node 0 follows it");
}

// spec/permissions.md §5.4 (Authorizes): only a removal that counts puts its node beside it.
// The laptop (node 2), not yet holding its own removal, removes the tablet (node 1); the phone
// (node 0) has removed the laptop and gets that removal alone, after its rotation closed the
// epoch it is signed at, so it counts for nothing (as one a removed node forges there would),
// and the tablet's later rotation stands for D's roster at the phone
#[test]
fn a_removal_that_does_not_count_puts_nothing_beside_it_spec_permissions_5_4() {
    let (mut lp, a, _) = world(3, 3);
    let tablet = lp.peers[1].engine.tid();
    let bad = remove(&mut lp, 2, a.devices, 1);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    lp.advance(5);
    send(&mut lp, 2, 0, &bad.commits[..1]);
    assert!(lp.peers[0].engine.core.key_holders(&a.devices).iter().any(|(m, _)| *m == tablet), "the tablet's removal does not count");
    lp.advance(5);
    let r = lp.peers[1].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    send(&mut lp, 1, 0, &[r]);
    let v = lp.peers[0].engine.core.account_view(&a.account).unwrap();
    assert_eq!(v.authorized_by(&r), Some(tablet), "the tablet's rotation stands");
    assert_eq!(v.preferred(), r);
}

// spec/permissions.md §5.4, §5.5 (Honest nodes of P): no node is designated to act on a fork.
// Nodes 0 and 1 remove node 3 at once; each head's line lacks the other's removal, so each is
// owed a rotation. The node whose rotation is the lower head (the one a designated merger would
// have been) writes once, then is gone for good: the other nodes still rotate, list and settle,
// and the gone node's write, received before that rotation, counts at an outsider by their word
#[test]
fn the_lowest_heads_node_gone_for_good_leaves_nothing_waiting_spec_permissions_5_4() {
    let (mut lp, a, t) = world(5, 4);
    let d0 = remove(&mut lp, 0, a.devices, 3);
    let d1 = remove(&mut lp, 1, a.devices, 3);
    let (gone, other) = if d0.commits[1] < d1.commits[1] { (0, 1) } else { (1, 0) };
    let dg = if gone == 0 { &d0 } else { &d1 };
    let dother = if gone == 0 { &d1 } else { &d0 };
    lp.advance(1);
    let g = write(&mut lp, gone, t, "gone");
    for to in [other, 2] {
        send(&mut lp, gone, to, &dg.commits);
        send(&mut lp, gone, to, &[g]);
    }
    send(&mut lp, gone, 4, &[dg.commits[1], g]);
    send(&mut lp, other, 2, &dother.commits);
    send(&mut lp, other, 4, &dother.commits[1..]);
    // the gone node acts no more: the others owe and make the rotation
    let m = merge(&mut lp, &[other, 2], &[other, 2, 4]);
    let rh = lp.peers[4].engine.header(&m).unwrap().rotation.clone().unwrap();
    assert_eq!(rh.supersedes.len(), 2, "it supersedes both heads");
    for k in [other, 2] {
        lp.advance(1);
        let ids = lp.peers[k].engine.commit_ids();
        send(&mut lp, k, 4, &ids);
        assert!(lp.peers[k].engine.signing_due().unwrap().commits.is_empty(), "peer {k}: settled");
    }
    send(&mut lp, gone, 4, &[g]);
    assert_eq!(read(&mut lp, 4, t), Some(Value::Str("gone".into())), "the gone node's write counts by the others' word");
    let w = write(&mut lp, 2, t, "after");
    send(&mut lp, 2, 4, &[w]);
    assert_eq!(read(&mut lp, 4, t), Some(Value::Str("after".into())), "the account writes on");
    lp.peers[4].engine.rebuild_index().unwrap();
    assert_eq!(read(&mut lp, 4, t), Some(Value::Str("after".into())), "after a rebuild");
}

// spec/permissions.md §5.5 (cutoff; honest nodes of p): a removed node removes no one for good.
// The laptop (node 2) removes the tablet (node 1) with its rotation x0; the phone (node 0) has
// removed the laptop (R) and gets the laptop's removal and x0 after R. The phone's rotation
// rejects x0 unnamed and does not name the tablet's removal again (it received it after R
// closed its epoch): the tablet stays on D's roster at the phone, as a rebuild reads it
#[test]
fn a_removed_nodes_removal_named_only_by_its_fork_is_not_named_again_spec_permissions_5_5() {
    let (mut lp, a, _) = world(3, 3);
    let tablet = lp.peers[1].engine.tid();
    let bad = remove(&mut lp, 2, a.devices, 1);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    lp.advance(5);
    send(&mut lp, 2, 0, &bad.commits);
    let made = lp.peers[0].engine.signing_due().unwrap();
    let rot = *made.commits.iter().find(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.rotation.is_some())).expect("the phone rejects the laptop's fork");
    let rh = lp.peers[0].engine.header(&rot).unwrap().rotation.clone().unwrap();
    assert!(rh.supersedes.contains(&bad.commits[1]) && rh.names.is_empty(), "x0 superseded unnamed: {rh:?}");
    assert!(!lp.peers[0].engine.rotation_lists(&rot).unwrap().iter().any(|(_, ids)| ids.contains(&bad.commits[0])), "the tablet's removal is not named again");
    let on = |lp: &LocalPeer| lp.peers[0].engine.core.key_holders(&a.devices).iter().any(|(m, _)| *m == tablet);
    assert!(on(&lp), "the tablet stays on D's roster");
    lp.peers[0].engine.rebuild_index().unwrap();
    assert!(on(&lp), "after a rebuild");
    assert!(lp.peers[0].engine.signing_due().unwrap().commits.is_empty(), "nothing more is due");
}

// spec/permissions.md §5.5 (Thing lists): a rotation's lists name nothing until it is held. Nodes
// 0 and 1 rotate at once; node 0 writes at its own epoch, then rotates over both heads, its list
// naming that write. A reader holding node 0's line but not node 1's rotation gets the new
// rotation first (it waits for its other parent, across a restart): what its list names stands as
// before. Once node 1's rotation comes, the write counts by the list, as a rebuilt index reads it
#[test]
fn a_rotation_waiting_for_a_head_names_nothing_until_held_spec_permissions_5_5() {
    let (mut lp, a, t) = world(4, 3);
    let rot = |lp: &mut LocalPeer, k: usize| lp.peers[k].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    let ra = rot(&mut lp, 0);
    let w = write(&mut lp, 0, t, "at ra");
    send(&mut lp, 0, 3, &[ra, w]);
    let rb = rot(&mut lp, 1);
    send(&mut lp, 1, 0, &[rb]);
    let m = rot(&mut lp, 0);
    assert!(lp.peers[0].engine.rotation_lists(&m).unwrap().iter().any(|(_, ids)| ids.contains(&w)), "the rotation names the write");
    send(&mut lp, 0, 3, &[m]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("at ra".into())), "at an open epoch");
    // the kept lists wait across a restart
    lp.peers[3].restart(0).unwrap();
    send(&mut lp, 1, 3, &[rb]);
    assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads(), vec![m]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("at ra".into())), "named by the rotation's list");
    let d0 = lp.peers[3].engine.index_digest();
    lp.peers[3].engine.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[3].engine.index_digest()), None, "rebuilt");
}

// spec/permissions.md §5.5 (Listings): a node of the account that wrote on two things, u and t,
// before the rotator held either, takes the rotation in and lists both writes, one commit per
// thing, so neither listing goes under the other thing's sync IDs. Fails with one listing over
// every thing.
#[test]
fn a_listing_is_one_commit_per_thing_spec_permissions_5_5() {
    let (mut lp, a, t) = world(4, 3);
    let mut m = crate::Mutation::new();
    let u = lp.peers[2].engine.new_thing(&mut m, a.account);
    m.set(u, &x(), &Value::Str("mine".into())).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    write(&mut lp, 2, t, "offline");
    let done = remove(&mut lp, 0, a.devices, 1);
    for id in &done.commits {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        lp.deliver(2, &pk).expect("the rotation is taken in");
    }
    let e = &lp.peers[2].engine;
    let listings: Vec<std::sync::Arc<osis_commit::Header>> = e.commit_ids().into_iter().filter_map(|c| e.header(&c)).filter(|h| h.aspects.iter().any(|x| x.ak.as_str() == "listing.0")).collect();
    let on = |x: Tid| listings.iter().filter(|h| h.aspects.iter().any(|y| y.tid == x)).collect::<Vec<_>>();
    assert!(!on(u).is_empty() && !on(t).is_empty(), "both writes listed: {listings:?}");
    assert!(listings.iter().all(|h| h.aspects.iter().all(|y| y.tid == h.aspects[0].tid)), "one thing per listing");
}

// spec/permissions.md §5.5 (Nothing waits for a thing list), spec/requirements.md (outsiders
// never learn the account's devices): an outsider that holds the account's rotation before its
// thing list reads the account's earlier grant and write as unlisted; once the list arrives, without
// the removal, the grant counts again and the write's body,
// dropped while it did not count, counts missing again (`commit_parts_missing`) and reads once offered
#[test]
fn a_rotations_late_list_restores_the_accounts_earlier_word_at_an_outsider_spec_permissions_5_5() {
    let (mut lp, a, t) = world(3, 2);
    let sib = write(&mut lp, 1, t, "sibling");
    lp.sync_all().unwrap();
    let o = lp.peers[2].engine.me();
    let done = remove(&mut lp, 0, a.devices, 1);
    let pk = lp.peers[0].engine.package(&done.commits[1]).unwrap().unwrap();
    lp.advance(1);
    lp.peers[2].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    assert_eq!(lp.peers[2].engine.core.role_now(&o, &t), None, "the grant at the closed epoch is unlisted");
    assert_eq!(lp.peers[2].engine.hold_lists(&pk.lists[0]).unwrap(), crate::flows::ListsHeld::Held);
    assert!(lp.peers[2].engine.commit_parts_missing().contains_key(&sib), "the write is asked for again");
    lp.peers[2].reexamine().unwrap();
    assert_eq!(lp.peers[2].engine.core.role_now(&o, &t), Some(Role::Write), "the grant counts by the list");
    send(&mut lp, 1, 2, &[sib]);
    assert_eq!(read(&mut lp, 2, t), Some(Value::Str("sibling".into())));
    assert!(lp.peers[2].engine.header(&done.commits[0]).is_none(), "the outsider never holds the removal");
}

/// Commit `id` of peer `from` as a holder of its epoch's keys `k` re-signs it: its inner signature
/// sealed as key actor `z` (whose identity `zid` signs), the account's signature over it again.
fn inner_as(lp: &mut LocalPeer, from: usize, id: &CommitId, k: &osis_crypto::AccountEpochKeys, zid: &crate::identity::Identity) -> crate::local_peer::Package {
    let mut pk = lp.peers[from].engine.package(id).unwrap().unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let inner = osis_crypto::seal_inner(&k.inner, &id.0, &zid.tid(), &zid.keys().signing);
    b.sigs = osis_commit::Sigs::signed(id, &k.signing, Some(inner), b.sigs.merge.clone());
    pk.bytes = b.encode();
    pk
}

// spec/permissions.md §5.4 (Following, at a node of P): a removed node holds its old epochs'
// inner key, so it can seal a rotation's inner signature as any key actor it makes (here an
// outsider's node, standing in for a fresh one). A plain fork it so signs after its removal is
// no head at a node of the account holding the removal, and its write at the fork counts at none
// of them nor at an outsider holding the removal's rotation
#[test]
fn a_removed_nodes_fork_signed_as_another_key_actor_counts_nowhere_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 3, &done.commits[1..]);
    let z = lp.peers[3].engine.core.id.clone();
    let (_, k0) = lp.peers[2].engine.core.account_signing(&a.account).unwrap().unwrap();
    let fork = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    let (_, k1) = lp.peers[2].engine.core.account_signing(&a.account).unwrap().unwrap();
    let late = write(&mut lp, 2, t, "removed at its fork");
    let forged = [inner_as(&mut lp, 2, &fork, &k0, &z), inner_as(&mut lp, 2, &late, &k1, &z)];
    for to in [0, 1, 3] {
        lp.advance(1);
        for pk in &forged {
            lp.deliver(to, pk).unwrap();
        }
    }
    for k in [0, 1] {
        let v = lp.peers[k].engine.core.account_view(&a.account).unwrap();
        assert!(!v.heads().contains(&fork), "peer {k}: the forged fork is a head");
    }
    for k in [0, 1, 3] {
        let _ = lp.peers[k].engine.signing_due();
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("removed at its fork".into())), "peer {k}: the removed node's write counts");
    }
}

/// Merge rounds after `nodes` of the account rotate at once (spec/permissions.md §5.5, Limit:
/// merges made at once fork again). `lockstep`: every node runs its signing pass before any
/// rotation travels, `rounds` times. Else a random interleaving (seed `seed`) of single
/// deliveries and single nodes' signing passes, until nothing is owed. Returns the merges made
/// and whether the account's nodes end on one head.
fn merge_rounds(nodes: usize, seed: u64, lockstep: Option<usize>) -> (usize, bool) {
    let (mut lp, a, _) = world(nodes + 1, nodes);
    let mut q: Vec<(usize, usize, CommitId)> = Vec::new();
    for k in 0..nodes {
        let r = lp.peers[k].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
        q.extend((0..=nodes).filter(|to| *to != k).map(|to| (k, to, r)));
    }
    let mut made = 0;
    let mut s = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let mut next = |n: usize| {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((s >> 33) as usize) % n
    };
    if let Some(rounds) = lockstep {
        for _ in 0..rounds {
            for (from, to, r) in std::mem::take(&mut q) {
                send(&mut lp, from, to, &[r]);
            }
            for k in 0..nodes {
                let c = lp.peers[k].engine.signing_due().unwrap().commits;
                made += c.len();
                q.extend(c.iter().flat_map(|r| (0..=nodes).filter(|to| *to != k).map(move |to| (k, to, *r))));
            }
        }
    } else {
        let mut quiet = 0;
        while quiet < 4 * nodes {
            if !q.is_empty() && next(2) == 0 {
                let (from, to, r) = q.swap_remove(next(q.len()));
                send(&mut lp, from, to, &[r]);
                quiet = 0;
                continue;
            }
            let k = next(nodes);
            let c = lp.peers[k].engine.signing_due().unwrap().commits;
            made += c.len();
            if c.is_empty() && q.is_empty() {
                quiet += 1;
            }
            q.extend(c.iter().flat_map(|r| (0..=nodes).filter(|to| *to != k).map(move |to| (k, to, *r))));
        }
    }
    let heads: std::collections::BTreeSet<Vec<CommitId>> = (0..nodes).map(|k| lp.peers[k].engine.core.account_view(&a.account).unwrap().heads()).collect();
    (made, heads.len() == 1 && heads.iter().all(|h| h.len() == 1))
}

// By hand (a measurement, not a property): merge rounds after two or three of the account's
// nodes rotate at once
#[test]
#[ignore = "by hand: prints merge counts"]
fn merge_rounds_after_concurrent_rotations() {
    for nodes in [2, 3] {
        let (made, one) = merge_rounds(nodes, 0, Some(5));
        eprintln!("{nodes} nodes, lockstep 5 rounds: {made} merges, one head: {one}");
        let mut counts = Vec::new();
        for seed in 0..40 {
            let (made, one) = merge_rounds(nodes, seed, None);
            assert!(one, "{nodes} nodes seed {seed}: not one head");
            counts.push(made);
        }
        counts.sort();
        eprintln!("{nodes} nodes, random: merges {counts:?}");
    }
}

// spec/permissions.md §5.4 (Following, at a node of P: a re-add is a grant by a node other than
// the one removed): a removed node granting itself D again is not put back. Here at the epoch of
// a sibling's rotation made unaware of the removal and boxed to it, which descends from the
// removal's epoch, as a re-add's must: the removed node's fork from there is no head at the
// account's nodes, and its write there counts nowhere the removal is held
#[test]
fn a_removed_node_readding_itself_is_not_put_back_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 3, &done.commits[1..]);
    // the sibling, unaware, rotates; its epoch's seed is boxed to the removed node
    let rb = lp.peers[1].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    send(&mut lp, 1, 2, &[rb]);
    let xn = lp.peers[2].engine.tid();
    let mut sent = vec![rb];
    sent.extend(lp.peers[2].engine.grant(&a.devices, &xn, &edge(Role::Admin)).unwrap().commits);
    let fork = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    assert_eq!(lp.peers[2].engine.header(&fork).unwrap().epoch, Some(rb), "the removed node forks from the sibling's epoch");
    sent.push(fork);
    sent.push(write(&mut lp, 2, t, "removed"));
    send(&mut lp, 0, 1, &done.commits);
    for to in [0, 1, 3] {
        send(&mut lp, 2, to, &sent);
    }
    for k in [0, 1] {
        let _ = lp.peers[k].engine.signing_due();
        let v = lp.peers[k].engine.core.account_view(&a.account).unwrap();
        assert!(!lp.peers[k].engine.roster(&a.devices).contains_key(&xn), "peer {k}: the removed node is back on D");
        assert!(!v.heads().contains(&fork), "peer {k}: the removed node's fork is a head");
    }
    for k in [0, 1, 3] {
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("removed".into())), "peer {k}: the removed node's write counts");
    }
}

/// Pairs peer `new` from node `by` of account `a`; returns the grant.
fn pair_from(lp: &mut LocalPeer, a: &CreatedAccount, by: usize, new: usize) -> CommitId {
    let node = lp.peers[new].engine.tid();
    let ids = lp.peers[new].engine.commit_ids();
    send(lp, new, by, &ids);
    let (done, all) = lp.peers[by].engine.pair(&node).unwrap();
    send(lp, by, new, &all);
    lp.peers[new].engine.paired(&a.account).unwrap();
    done.commits[0]
}

// spec/permissions.md §5.1 (Frontier: a node's removal from D lists its word on D) and §5.4
// (Following, at a node of P: a removal hits its node's commits on D its frontier does not
// list). The laptop (node 2) pairs the tablet (peer 3); the phone (node 0) removes the laptop.
// Holding that grant before, the phone lists it: the tablet stays on D at the phone and at node
// 1. Holding it only after, the grant counts nowhere the removal is held: the tablet is no node
#[test]
fn a_device_a_removed_node_paired_stays_as_its_remover_held_it_spec_permissions_5_4() {
    for held in [true, false] {
        let mut lp = LocalPeer::new_bare(4, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[0].engine.create_account().unwrap();
        pair_from(&mut lp, &a, 0, 1);
        pair_from(&mut lp, &a, 0, 2);
        lp.sync_all().unwrap();
        lp.advance(1000);
        let tablet = lp.peers[3].engine.tid();
        let card = lp.peers[3].engine.commit_ids();
        let g = pair_from(&mut lp, &a, 2, 3);
        for k in [0, 1] {
            send(&mut lp, 3, k, &card);
        }
        if held {
            send(&mut lp, 2, 0, &[g]);
        }
        let done = remove(&mut lp, 0, a.devices, 2);
        send(&mut lp, 0, 1, &done.commits);
        for k in [0, 1] {
            send(&mut lp, 2, k, &[g]);
            let _ = lp.peers[k].engine.signing_due();
            assert_eq!(lp.peers[k].engine.roster(&a.devices).contains_key(&tablet), held, "peer {k}, held before the removal: {held}");
        }
    }
}

// spec/permissions.md §5.4 (Following, at a node of P): a device that took the other side's
// revocation is that side, whoever signs. R (peer 1) removes X (peer 2); X, unaware, revokes R.
// S (peer 3) rotated unaware (s1), then holds X's removal of R and its rotation as a header only
// (no seed): it takes the revocation, and its next rotation (s2) is signed at its own s1,
// supersedes nothing of R's and takes X's revocation. R and T (peer 0) never follow s2 (its seed
// X holds); R's merge takes s1 in and rejects s2; S answers once, and neither answers the
// other's answer again
#[test]
fn a_rotation_taking_the_thiefs_revocation_is_that_side_spec_permissions_5_4() {
    let (mut lp, a, _) = world(4, 4);
    let p = a.account;
    let (r, x, s, t) = (1, 2, 3, 0);
    let ra = remove(&mut lp, r, a.devices, x);
    send(&mut lp, r, t, &ra.commits);
    lp.advance(1000);
    let rx = remove(&mut lp, x, a.devices, r);
    let xr = rx.commits[1];
    let s1 = lp.peers[s].engine.run(|tx| crate::flows::signing::rotate_in(tx, p, &[], &mut Done::default())).unwrap().unwrap();
    lp.advance(1000);
    send(&mut lp, x, s, &rx.commits[..1]);
    let pk = lp.peers[x].engine.package(&xr).unwrap().unwrap();
    let mut header = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    header.parts.clear();
    lp.advance(1);
    lp.peers[s].receive_with(&header.encode(), Vec::new(), &pk.lists).unwrap();
    let v = lp.peers[s].engine.core.account_view(&p).unwrap();
    assert!(v.rotation_counts(&xr) && v.taken() == [xr], "S takes X's revocation of R: heads {:?}", v.heads());
    let s2 = lp.peers[s].engine.signing_due().unwrap().commits;
    assert_eq!(s2.len(), 1, "S's line lacks the removal of R");
    let s2 = s2[0];
    let h = lp.peers[s].engine.header(&s2).unwrap();
    let rh = h.rotation.clone().unwrap();
    assert!(h.epoch == Some(s1) && rh.supersedes == vec![s1] && rh.takes == vec![xr], "{rh:?}");
    for k in [r, t] {
        for c in ra.commits.iter().chain(&rx.commits).chain([&s1, &s2]) {
            let from = if ra.commits.contains(c) { r } else if *c == s1 || *c == s2 { s } else { x };
            if from != k {
                send(&mut lp, from, k, &[*c]);
            }
        }
        let v = lp.peers[k].engine.core.account_view(&p).unwrap();
        assert!(v.rotation_counts(&ra.commits[1]) && v.rotation_counts(&s1) && !v.rotation_counts(&s2), "peer {k}: heads {:?}", v.heads());
    }
    let m = lp.peers[r].engine.signing_due().unwrap().commits;
    assert_eq!(m.len(), 1);
    let rh = lp.peers[r].engine.header(&m[0]).unwrap().rotation.clone().unwrap();
    assert!(rh.names.contains(&s1) && rh.supersedes.contains(&s2) && !rh.names.contains(&s2) && rh.takes.is_empty(), "{rh:?}");
    send(&mut lp, r, t, &m);
    assert_eq!(lp.peers[t].engine.core.account_view(&p).unwrap().heads(), vec![m[0]]);
    send(&mut lp, r, s, &ra.commits);
    send(&mut lp, r, s, &m);
    let s3 = lp.peers[s].engine.signing_due().unwrap().commits;
    assert_eq!(s3.len(), 1, "S answers R's line once");
    let rh = lp.peers[s].engine.header(&s3[0]).unwrap().rotation.clone().unwrap();
    assert!(rh.supersedes.contains(&m[0]) && rh.takes == vec![xr], "{rh:?}");
    send(&mut lp, s, r, &s3);
    assert!(lp.peers[r].engine.signing_due().unwrap().commits.is_empty(), "R answers no answer");
    assert!(lp.peers[s].engine.signing_due().unwrap().commits.is_empty(), "nor S");
    assert_eq!(lp.peers[r].engine.core.account_view(&p).unwrap().heads(), vec![m[0]]);
}

/// Removed node `by`'s rotation of `a`'s chain to a fresh epoch from `seed`, signed at epoch `at`
/// and at each of `forks` (named, each with its seed), taking `takes`: what it can sign with the
/// keys it still holds, sealed as a key actor it makes up.
fn forge(lp: &mut LocalPeer, by: usize, a: &CreatedAccount, at: CommitId, forks: &[(CommitId, u8)], takes: &[CommitId], seed: u8) -> Vec<u8> {
    use osis_crypto::{AccountEpochKeys, Secret32};
    let e = &lp.peers[by].engine;
    let rec = e.core.created(&a.account).unwrap().clone();
    let held = e.core.accounts.get(&a.account).unwrap();
    let vk = match e.header(&at) {
        Some(h) => h.rotation.clone().unwrap().signing_key,
        None => {
            let osis_base::CreationRecord::KeyActor { public_key, .. } = &rec else { panic!("an account") };
            osis_crypto::VerifyingKey::from_slice(public_key).unwrap()
        }
    };
    let at_keys = AccountEpochKeys::from_seed(held.keys.get(&vk).unwrap().seed());
    let fork_keys: Vec<AccountEpochKeys> = forks.iter().map(|(_, s)| AccountEpochKeys::from_seed(&Secret32::from_bytes([*s; 32]))).collect();
    let next = AccountEpochKeys::from_seed(&Secret32::from_bytes([seed; 32]));
    let mut supersedes: Vec<CommitId> = std::iter::once(at).chain(forks.iter().map(|f| f.0)).collect();
    supersedes.sort();
    let mut names: Vec<CommitId> = forks.iter().map(|f| f.0).collect();
    names.sort();
    let fork_keys: Vec<&AccountEpochKeys> = names.iter().map(|n| &fork_keys[forks.iter().position(|f| f.0 == *n).unwrap()]).collect();
    let header = osis_commit::RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes, names, takes: takes.to_vec(), removals: Vec::new(), list_root: [0; 32] };
    let ts = osis_base::Ts::make(e.now(), 0).unwrap();
    super::tests_account::rotation_at(rec, (at, &at_keys), &fork_keys, &next, header, ts)
}

// spec/permissions.md §5.4: a rotation is held only once every rotation it takes is, at every
// node. The removed node forks taking a rotation no one holds; a reader it reached before the
// removal never follows it (the account's nodes hold it pending, so none would answer it)
#[test]
fn a_rotation_taking_what_no_one_holds_is_held_nowhere_spec_permissions_5_4() {
    let (mut lp, a, _) = world(4, 3);
    let f = forge(&mut lp, 2, &a, osis_commit::FIRST_EPOCH, &[], &[CommitId([0xee; 32])], 70);
    let fb = f;
    let f = give(&mut lp, &fb, &[3]);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 3, &done.commits[1..]);
    give(&mut lp, &fb, &[0, 1]);
    for k in [0, 1, 3] {
        let v = lp.peers[k].engine.core.account_view(&a.account).unwrap();
        assert!(!v.rotation_counts(&f) && v.heads() == vec![done.commits[1]], "peer {k}: heads {:?}", v.heads());
    }
}

// spec/permissions.md §5.5 (Honest nodes of P: one answer per line, as long as that line holds
// the rejection). B rotated unaware (rb, boxed to X); A removes X; X forks (f), reaching an
// outsider first. B's merge is signed at rb and rejects f: the outsider is told. X, holding rb's
// key, signs a rotation at rb accepting f (f2): f is now on a line through rb, so nothing rejects
// it and the warning goes. f2 is answered, and the outsider is told again
#[test]
fn a_rotation_undoing_an_answer_is_answered_spec_permissions_5_5() {
    let (mut lp, a, _) = world(4, 3);
    let p = a.account;
    let rb = lp.peers[1].engine.run(|tx| crate::flows::signing::rotate_in(tx, p, &[], &mut Done::default())).unwrap().unwrap();
    send(&mut lp, 1, 2, &[rb]);
    let done = remove(&mut lp, 0, a.devices, 2);
    let ra = done.commits[1];
    send(&mut lp, 0, 1, &done.commits);
    let fb = forge(&mut lp, 2, &a, osis_commit::FIRST_EPOCH, &[], &[], 80);
    let f = give(&mut lp, &fb, &[3, 1]);
    let h1 = lp.peers[1].engine.signing_due().unwrap().commits;
    assert_eq!(h1.len(), 1);
    let h = lp.peers[1].engine.header(&h1[0]).unwrap();
    let rh = h.rotation.clone().unwrap();
    assert!(h.epoch == Some(rb) && rh.names == vec![ra] && rh.supersedes.contains(&f), "{h:?}");
    send(&mut lp, 0, 3, &done.commits[1..]);
    send(&mut lp, 1, 3, &[rb, h1[0]]);
    assert_eq!(lp.peers[3].engine.account_disputes().len(), 1, "the outsider is told");
    let f2 = forge(&mut lp, 2, &a, rb, &[(f, 80)], &[], 81);
    let f2 = give(&mut lp, &f2, &[3, 1]);
    let v = lp.peers[3].engine.core.account_view(&p).unwrap();
    assert!(v.heads() == vec![f2] && lp.peers[3].engine.account_disputes().is_empty(), "nothing rejects f now: heads {:?}", v.heads());
    let h2 = lp.peers[1].engine.signing_due().unwrap().commits;
    assert_eq!(h2.len(), 1, "B answers f2");
    assert!(lp.peers[1].engine.header(&h2[0]).unwrap().rotation.clone().unwrap().supersedes.contains(&f2));
    send(&mut lp, 1, 3, &h2);
    assert_eq!(lp.peers[3].engine.account_disputes().len(), 1, "the outsider is told again");
}

// spec/permissions.md §5.4 (Following, at a node of P: the removals a rotation carries are those
// its header names). X rotates (x0) before A removes it. X, keeping the first epoch's keys, writes
// a removal of B on D signed at the first epoch, where x0 was signed: x0 names no removal, so it
// carries none, and T takes A's removal whether it holds x0, then the removal, then A's removal,
// or X's removal first (were x0 to carry it, x0 would be a revocation held before A's, and T would
// side with X)
#[test]
fn a_removal_written_later_turns_no_earlier_rotation_into_a_revocation_spec_permissions_5_4() {
    removal_written_later(false);
    removal_written_later(true);
}

fn removal_written_later(removal_first: bool) {
    let (mut lp, a, _) = world(5, 4);
    let (r, b, x, t) = (0, 1, 2, 3);
    let x0 = lp.peers[x].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap();
    // X's removal of B, signed at the first epoch with that epoch's keys
    let first = {
        let h = lp.peers[x].engine.core.accounts.get(&a.account).unwrap();
        h.keys.get(&h.first).unwrap().clone()
    };
    let holder = lp.peers[b].engine.tid();
    lp.peers[x].engine.demote(&a.devices, &Demotion { holder, new: None, retain: None }).unwrap();
    let c = lp.peers[x].engine.commit_ids().into_iter().find(|c| lp.peers[x].engine.header(c).is_some_and(|h| h.rotation.is_none() && h.aspects.iter().any(|s| s.tid == a.devices && s.ak.as_str() == "roles.0") && h.epoch != Some(osis_commit::FIRST_EPOCH))).unwrap();
    let mut pk = lp.peers[x].engine.package(&c).unwrap().unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    blob.header.epoch = Some(osis_commit::FIRST_EPOCH);
    let id = blob.header.id();
    let me = &lp.peers[x].engine.core.id;
    let inner = osis_crypto::seal_inner(&first.inner, &id.0, &me.tid(), &me.keys().signing);
    blob.sigs = osis_commit::Sigs::signed(&id, &first.signing, Some(inner), Vec::new());
    pk.id = id;
    pk.bytes = blob.encode();
    if removal_first {
        lp.advance(5);
        lp.deliver(t, &pk).unwrap();
    }
    send(&mut lp, x, t, &[x0]);
    lp.advance(5);
    let done = remove(&mut lp, r, a.devices, x);
    send(&mut lp, r, t, &done.commits);
    let ra = done.commits[1];
    let v = lp.peers[t].engine.core.account_view(&a.account).unwrap();
    assert!(v.rotation_counts(&ra) && !v.rotation_counts(&x0) && v.taken() == [ra], "removal first {removal_first}: heads {:?} taken {:?}", v.heads(), v.taken());
    if !removal_first {
        lp.advance(5);
        lp.deliver(t, &pk).unwrap();
        let v = lp.peers[t].engine.core.account_view(&a.account).unwrap();
        assert!(v.rotation_counts(&ra) && !v.rotation_counts(&x0) && v.taken() == [ra], "T keeps A's removal: heads {:?} taken {:?}", v.heads(), v.taken());
    }
}

// spec/permissions.md §5.4 (Placing: no earlier than the removals a rotation carries came to be
// held). X, not yet told of its removal, revokes A (its removal R on D and rotation q naming R).
// T gets q alone, then A's removal of X, then R: q is placed when R arrives, after A's removal,
// so T keeps A's removal (placed at q's own receipt, X's revocation would be held first and T
// would switch)
#[test]
fn a_revocation_is_placed_when_its_removal_arrives_spec_permissions_5_4() {
    let (mut lp, a, _) = world(5, 4);
    let (r, x, t) = (0, 2, 3);
    let rx = remove(&mut lp, x, a.devices, r);
    let (rem, q) = (rx.commits[0], rx.commits[1]);
    assert!(lp.peers[x].engine.header(&q).unwrap().rotation.clone().unwrap().removals == vec![rem], "q names its removal");
    send(&mut lp, x, t, &[q]);
    lp.advance(5);
    let done = remove(&mut lp, r, a.devices, x);
    send(&mut lp, r, t, &done.commits);
    send(&mut lp, x, t, &[rem]);
    let v = lp.peers[t].engine.core.account_view(&a.account).unwrap();
    assert!(v.rotation_counts(&done.commits[1]) && !v.rotation_counts(&q) && v.taken() == [done.commits[1]], "T keeps A's removal: heads {:?} taken {:?}", v.heads(), v.taken());
}

// spec/permissions.md §5.5 (Honest nodes of P: a disregarded rotation no counting rotation's
// rejection reaches is answered by each node once). X forks at the first epoch sealed as a key
// actor it made up (f), reaching B and reader R before A's removal of X does. B, unaware, answers
// f at the first epoch: f is signed there too, so B's rotation rejects nothing of it (contested
// from below) and R, following f, is not told. A holds B's answer and still answers f from its
// removal's epoch, which rejects it: R is told
#[test]
fn a_rotation_superseded_without_a_rejection_is_answered_spec_permissions_5_5() {
    let (mut lp, a, _) = world(5, 4);
    let (r0, b, x, rd) = (0, 1, 2, 4);
    let done = remove(&mut lp, r0, a.devices, x);
    let fb = forge(&mut lp, x, &a, osis_commit::FIRST_EPOCH, &[], &[], 90);
    let f = give(&mut lp, &fb, &[b, rd]);
    let hb = lp.peers[b].engine.signing_due().unwrap().commits;
    assert_eq!(hb.len(), 1, "B answers f");
    let h = lp.peers[b].engine.header(&hb[0]).unwrap();
    assert!(h.epoch == Some(osis_commit::FIRST_EPOCH) && h.rotation.clone().unwrap().supersedes.contains(&f));
    send(&mut lp, r0, rd, &done.commits[1..]);
    send(&mut lp, b, rd, &hb);
    assert!(lp.peers[rd].engine.account_disputes().is_empty(), "B's answer rejects nothing of f");
    give(&mut lp, &fb, &[r0]);
    send(&mut lp, b, r0, &hb);
    let ha = lp.peers[r0].engine.signing_due().unwrap().commits;
    assert!(ha.iter().any(|c| lp.peers[r0].engine.header(c).unwrap().rotation.clone().is_some_and(|rh| rh.supersedes.contains(&f))), "A answers f");
    send(&mut lp, r0, rd, &ha);
    assert_eq!(lp.peers[rd].engine.account_disputes().len(), 1, "R is told");
}

/// A plain rotation of `a` by node `k` at its preferred head; its commit ID.
fn rotate(lp: &mut LocalPeer, k: usize, a: &CreatedAccount) -> CommitId {
    lp.peers[k].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[], &mut Done::default())).unwrap().unwrap()
}

// spec/permissions.md §5.4 (Following, at a node of P; Following, outside P): the epoch rule reads D
// only at a node holding the account, so a node's judgment of its account moves when it leaves
// it, as a rebuild judges it. Nodes 0 and 2 rotate at once; node 1 holds both (node 0's first),
// which count there as its devices' rotations made at once. Node 0, not holding node 2's
// rotation, removes node 1: node 1 leaves and reads the chain as an outsider, where node 2's
// rotation is beside the line it follows
#[test]
fn a_node_leaving_its_account_judges_its_chain_as_an_outsider_spec_permissions_5_4() {
    let (mut lp, a, _) = world(3, 3);
    let r0 = rotate(&mut lp, 0, &a);
    let r2 = rotate(&mut lp, 2, &a);
    send(&mut lp, 0, 1, &[r0]);
    send(&mut lp, 2, 1, &[r2]);
    assert!(lp.peers[1].engine.core.account_view(&a.account).unwrap().rotation_counts(&r2), "inside, node 2's rotation counts");
    let done = remove(&mut lp, 0, a.devices, 1);
    // the rotation first: the removal's arrival is the last change
    send(&mut lp, 0, 1, &[done.commits[1]]);
    send(&mut lp, 0, 1, &[done.commits[0]]);
    assert!(!lp.peers[1].engine.core.accounts.contains_key(&a.account), "node 1 left");
    assert!(!lp.peers[1].engine.core.account_view(&a.account).unwrap().rotation_counts(&r2), "outside, it does not");
    lp.peers[1].engine.check_index();
}

// spec/permissions.md §5.4 (Following, at a node of P; Following, outside P): a reader paired into the
// account reads the chain as a node of it from then on, as a rebuild judges it. Nodes 0 and 1
// rotate at once; reader 2 holds both (node 0's first), node 1's beside the line it follows.
// Paired, it holds both as its devices' rotations made at once
#[test]
fn a_reader_paired_into_the_account_judges_its_chain_as_a_node_spec_permissions_5_4() {
    let (lp, a) = LocalPeer::cached("rotation::tests_signing::paired_reader", || {
        let mut lp = LocalPeer::new_bare(3, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[0].engine.create_account().unwrap();
        pair(&mut lp, &a, 1);
        lp.sync_all().unwrap();
        lp.advance(1000);
        (lp, a)
    });
    let mut lp = lp;
    let r0 = rotate(&mut lp, 0, &a);
    let r1 = rotate(&mut lp, 1, &a);
    send(&mut lp, 0, 2, &[r0]);
    send(&mut lp, 1, 2, &[r1]);
    assert!(!lp.peers[2].engine.core.account_view(&a.account).unwrap().rotation_counts(&r1), "outside, node 1's rotation is beside the line followed");
    lp.advance(1);
    pair(&mut lp, &a, 2);
    assert!(lp.peers[2].engine.core.accounts.contains_key(&a.account), "reader 2 holds the account");
    assert!(lp.peers[2].engine.core.account_view(&a.account).unwrap().rotation_counts(&r1), "inside, it counts");
    lp.peers[2].engine.check_index();
}

/// Node 0 pairs peer `i` into account `a`.
fn pair(lp: &mut LocalPeer, a: &CreatedAccount, i: usize) {
    let node = lp.peers[i].engine.tid();
    let ids = lp.peers[i].engine.commit_ids();
    send(lp, i, 0, &ids);
    let (_, all) = lp.peers[0].engine.pair(&node).unwrap();
    send(lp, 0, i, &all);
    lp.peers[i].engine.paired(&a.account).unwrap();
}

/// Carries what `from` holds that `to` does not hold whole as labels do: sealed (`LocalPeer::
/// sealed`, after the rotations due before it encrypts), each opened at `to` with the read secrets
/// it holds and ingested as far as it opens (its header and the sections it opens), with its
/// thing lists; again while anything new opens. The commits none of whose wraps opened at `to`.
fn carry_sealed(lp: &mut LocalPeer, from: usize, to: usize) -> Vec<CommitId> {
    loop {
        let ids: Vec<CommitId> = lp.peers[from].engine.commit_ids().into_iter().filter(|id| !lp.peers[to].engine.holds_whole(id)).collect();
        let mut opened = false;
        let mut shut = Vec::new();
        for sp in lp.sealed(from, &ids).unwrap() {
            let id = sp.id;
            if lp.peers[to].engine.holds_whole(&id) {
                continue;
            }
            let lists = lp.peers[from].engine.package(&id).unwrap().unwrap().lists;
            lp.advance(1);
            let e = &sp.entries[0];
            let eng = &mut lp.peers[to].engine;
            let Some(key) = e.wraps.iter().find_map(|(a, w)| osis_label::unwrap_any(eng.read_secrets(a).iter(), &e.id, w).map(|x| x.1)) else {
                shut.push(id);
                continue;
            };
            let o = eng.open_commit(&e.blob, &key).unwrap();
            let before = eng.core.ix.commits.get(&id).map(|m| m.missing_parts().count());
            if lp.peers[to].receive_with(&o.plaintext, sp.blobs.clone(), &lists).is_ok() {
                opened |= lp.peers[to].engine.core.ix.commits.get(&id).map(|m| m.missing_parts().count()) != before;
            }
        }
        if !opened {
            return shut;
        }
    }
}

/// What node `k` makes at the end of a complete pass of every actor it holds secrets of: the
/// re-seals and rotations due there (`reseal_after_pass`), then its account's signing chain
/// (`signing_due`).
fn pass_end(lp: &mut LocalPeer, k: usize) -> Vec<CommitId> {
    let mut made = Vec::new();
    let actors: Vec<Tid> = lp.peers[k].engine.core.ix.secrets.keys().copied().collect();
    for a in actors {
        made.extend(lp.peers[k].engine.reseal_after_pass(&a).unwrap().commits);
    }
    made.extend(lp.peers[k].engine.signing_due().unwrap().commits);
    made
}

// spec/permissions.md §3 (Required rotation), §5.5, spec/crypto.md §5 (Exception: an account's
// rotation is wrapped under the D epoch its seed's `under` supersedes): nodes 0 and 1 of four remove nodes 2 and 3 while
// apart, each writing after, and heal as labels carry commits, in either order, with or without
// each having been handed the other's removal and rotation first; then the two act in turn, each
// at the end of a pass. A sibling's removal R counts at the other only once its rotation Q (whose
// thing list for D names R) is held, so Q opens without R's new D epoch. Both removals hold at
// both, they end on one head after one merge, and the writes made apart count at both (the merge
// comes to count at the non-merger only once its seed is taken up, and is answered then)
#[test]
fn sibling_removals_apart_both_hold_spec_permissions_3() {
    for (first, handed) in [(0, false), (1, false), (0, true), (1, true)] {
        let (mut lp, a, t) = world(4, 4);
        let p = a.account;
        let d0 = remove(&mut lp, 0, a.devices, 2);
        let d1 = remove(&mut lp, 1, a.devices, 3);
        let w0 = write(&mut lp, 0, t, "zero");
        let w1 = write(&mut lp, 1, t, "one");
        if handed {
            send(&mut lp, 1, 0, &d1.commits);
            send(&mut lp, 0, 1, &d0.commits);
        }
        let other = 1 - first;
        let mut quiet = false;
        for _ in 0..6 {
            let before = lp.peers[0].engine.commit_ids().len() + lp.peers[1].engine.commit_ids().len();
            let shut = [carry_sealed(&mut lp, other, first), pass_end(&mut lp, first), carry_sealed(&mut lp, first, other), pass_end(&mut lp, other)];
            if shut.iter().all(Vec::is_empty) && lp.peers[0].engine.commit_ids().len() + lp.peers[1].engine.commit_ids().len() == before {
                quiet = true;
                break;
            }
        }
        let case = format!("first {first}, handed {handed}");
        assert!(quiet, "{case}: still carrying or acting after 6 rounds");
        let gone = [lp.peers[2].engine.tid(), lp.peers[3].engine.tid()];
        let heads: Vec<Vec<CommitId>> = [0, 1].iter().map(|k| lp.peers[*k].engine.core.account_view(&p).unwrap().heads()).collect();
        assert!(heads[0].len() == 1 && heads[0] == heads[1], "{case}: one head at both: {heads:?}");
        for k in [0, 1] {
            let roster = lp.peers[k].engine.roster(&a.devices);
            assert!(gone.iter().all(|n| !roster.contains_key(n)), "{case}: node {k} keeps a removed node on D");
            let v = lp.peers[k].engine.core.account_view(&p).unwrap();
            assert_eq!(v.rotation_ids().len(), 3, "{case}: node {k}: the two removals' rotations and one merge");
            for w in [w0, w1] {
                let m = lp.peers[k].engine.core.ix.commits.get(&w).cloned();
                assert!(m.is_some_and(|m| lp.peers[k].engine.core.standing(&w, &m.view) == osis_perm::EpochStanding::Counts), "{case}: node {k}: a write made apart does not count");
            }
        }
    }
}

// spec/permissions.md §5.5 (Honest nodes of P: a head it cannot merge is left to a node that can).
// B, unaware of A's removal of X, removes T; X forks plainly from the first epoch, signed as X (a
// node to B), with a seed only X holds. B's two heads: its own, naming T's removal, and X's fork,
// which lacks it and which B cannot merge. B owes nothing: rotating at its own head would leave
// X's fork as it is, pass after pass
#[test]
fn a_head_it_cannot_merge_owes_no_rotation_spec_permissions_5_5() {
    let (mut lp, a, _) = world(5, 4);
    let (b, x, t) = (1, 2, 3);
    let k0 = {
        let h = lp.peers[x].engine.core.accounts.get(&a.account).unwrap();
        h.keys.get(&h.first).unwrap().clone()
    };
    let q = remove(&mut lp, b, a.devices, t);
    assert_eq!(q.commits.len(), 2);
    let fb = forge(&mut lp, x, &a, osis_commit::FIRST_EPOCH, &[], &[], 91);
    let f = give(&mut lp, &fb, &[x]);
    let me = lp.peers[x].engine.core.id.clone();
    let pk = inner_as(&mut lp, x, &f, &k0, &me);
    lp.advance(1);
    lp.deliver(b, &pk).unwrap();
    let v = lp.peers[b].engine.core.account_view(&a.account).unwrap();
    assert!(v.heads().len() == 2 && v.rotation_counts(&f), "X's fork is a head at B: {:?}", v.heads());
    for pass in 0..2 {
        assert!(lp.peers[b].engine.signing_due().unwrap().commits.is_empty(), "pass {pass}: B rotates");
    }
}

// spec/crypto.md §5 (Section; Who wraps under what), §3 (MUST write a fresh one in each
// rotation): a node removed from D opens nothing of the account rotation that removes
// it but what readers outside the account hold: never the account's `keys.0` part, which
// carries D's fresh deposit seed
#[test]
fn a_removed_node_opens_no_keys_of_its_removal_rotation_spec_crypto_5() {
    let (mut lp, a, _) = world(2, 2);
    let done = remove(&mut lp, 0, a.devices, 1);
    let r = done.commits[1];
    let ai = lp.peers[0].engine.header(&r).unwrap().aspect_index(&a.account, "keys.0").expect("the rotation writes keys.0");
    let pks = lp.sealed(0, &[r]).unwrap();
    assert!(!pks.is_empty());
    let e = &mut lp.peers[1].engine;
    let mut opened = Vec::new();
    for pk in &pks {
        for en in &pk.entries {
            let Some(key) = en.wraps.iter().find_map(|(g, w)| osis_label::unwrap_any(e.read_secrets(g).iter(), &en.id, w).map(|x| x.1)) else { continue };
            opened.extend(e.open_commit(&en.blob, &key).unwrap().commit.parts.iter().map(|p| p.ai));
        }
    }
    assert!(!opened.contains(&ai), "the removed node read the account's new keys.0 (D's fresh deposit seed)");
}

// spec/permissions.md §5.4 (Following, at a node of P: who signed each role commit of P on D):
// a role commit's signatures are kept as facts of the commit (`note_role_sigs`): a node paired
// after node 0 removed node 1, given D's commits with those marking D (`account.0`) last, reads
// node 0 as the removal's maker, and every node's index rebuilt from the records matches. (By
// arrival order alone nothing on D applies before D's creating commit, which marks D: the order
// dependence the facts rule out is checked by the index check, `order::held_set_decides`.)
#[test]
fn a_node_paired_after_a_removal_reads_its_maker_spec_permissions_5_4() {
    let mut lp = LocalPeer::new_bare(3, 0, WallMs(1_700_000_000_000)).unwrap();
    let (a, _) = lp.peers[0].engine.create_account().unwrap();
    let pair = |lp: &mut LocalPeer, i: usize, marked_last: bool| {
        let node = lp.peers[i].engine.tid();
        let ids = lp.peers[i].engine.commit_ids();
        send(lp, i, 0, &ids);
        let (_, all) = lp.peers[0].engine.pair(&node).unwrap();
        let ids: Vec<CommitId> = lp.peers[0].engine.commit_ids();
        let all: Vec<CommitId> = if marked_last { ids } else { all };
        let marks = |lp: &LocalPeer, c: &CommitId| lp.peers[0].engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == a.devices && x.ak.as_str() == "account.0"));
        let (late, early): (Vec<CommitId>, Vec<CommitId>) = all.iter().partition(|c| marked_last && marks(lp, c));
        send(lp, 0, i, &early);
        send(lp, 0, i, &late);
        lp.peers[i].engine.paired(&a.account).unwrap();
    };
    pair(&mut lp, 1, false);
    let r = remove(&mut lp, 0, a.devices, 1).commits[0];
    pair(&mut lp, 2, true);
    let maker = lp.peers[0].engine.tid();
    let v = lp.peers[2].engine.core.account_view(&a.account).unwrap();
    let signed = v.devices.as_ref().and_then(|d| d.commits.get(&r)).and_then(|x| x.0);
    assert_eq!(signed, Some(maker), "node 2 reads node 0 as the removal's maker");
    // the signatures kept are facts of the commits held: read back from the commit records at an
    // open, and rebuilt from them, alike
    for k in 0..3 {
        let d = lp.peers[k].engine.index_digest();
        lp.peers[k].engine.reload().unwrap();
        assert_eq!(d.first_diff(&lp.peers[k].engine.index_digest()), None, "node {k}: reopened");
        lp.peers[k].engine.rebuild_index().unwrap();
        assert_eq!(d.first_diff(&lp.peers[k].engine.index_digest()), None, "node {k}: rebuilt");
    }
}

// spec/permissions.md §5.5 (Waiting), §5.4 (no removal of the set hits: a removal hits its node's commits on D its frontier
// does not list): nodes 0, 1, 2; node 0 rotates (r1, unseen by node 1), then removes node 1
// (r2). Node 1, removed, grants its tablet (peer 3) D, signed at the epoch r1 closes. Node 2 holds
// r1 without its D list and the grant (which counts while node 2 waits for the list: node 1 is a
// node there, unaware), acts on what it owes, then gets the list and r2 whole; or gets the grant
// only after. The grant counts nowhere once the list is held, and nothing anyone writes after
// (rotations, re-seals, merges) lets the tablet or node 1 open a secret of D sealed after the
// removal: a commit counting only while a node waits takes no lasting act.
#[test]
fn a_removed_nodes_grant_counted_while_waiting_reaches_no_one_spec_permissions_5_5() {
    for early in [true, false] {
        let (mut lp, a, _) = world(4, 3);
        let (p, d) = (a.account, a.devices);
        let tablet = lp.peers[3].engine.tid();
        let card = lp.peers[3].engine.commit_ids();
        for k in [1, 2] {
            send(&mut lp, 3, k, &card);
        }
        let r1 = lp.peers[0].engine.rotate_account(&p).unwrap().unwrap();
        let r1_pk = lp.peers[0].engine.package(&r1).unwrap().unwrap();
        let g = *lp.peers[1].engine.grant(&d, &tablet, &edge(Role::Admin)).unwrap().commits.last().unwrap();
        let ge = lp.peers[1].engine.header(&g).unwrap().epoch;
        assert!(ge.is_some() && ge != Some(r1), "signed at the epoch r1 closes");
        let before: std::collections::BTreeSet<_> = super::tests::held_secrets(&lp.peers[1], &[d]).into_keys().collect();
        let done = remove(&mut lp, 0, d, 1);
        lp.advance(1);
        assert!(matches!(lp.peers[2].receive_with(&r1_pk.bytes, Vec::new(), &[]).unwrap(), crate::Ingested::Applied(_)), "r1 held without its lists");
        let counts = |lp: &LocalPeer, k: usize| lp.peers[k].engine.core.counts_at_epoch(&g, &p, ge);
        if early {
            send(&mut lp, 1, 2, &[g]);
            assert!(lp.peers[2].engine.header(&g).is_some(), "the grant held");
            let _ = lp.peers[2].engine.signing_due();
            let _ = lp.peers[2].engine.reseal_after_pass(&d);
        }
        assert_eq!(lp.peers[2].engine.hold_lists(&r1_pk.lists[0]).unwrap(), crate::flows::lists::ListsHeld::Held);
        send(&mut lp, 0, 2, &done.commits);
        send(&mut lp, 1, 2, &[g]);
        assert!(lp.peers[2].engine.core.account_view(&p).unwrap().rotation_counts(&done.commits[1]), "r2 counts at node 2");
        assert!(!counts(&lp, 2), "early {early}: the removed node's grant counts at node 2");
        assert!(!lp.peers[2].engine.roster(&d).contains_key(&tablet), "early {early}: the tablet is on D at node 2");
        for _ in 0..3 {
            for k in [0, 2] {
                let _ = lp.peers[k].engine.signing_due();
                let _ = lp.peers[k].engine.reseal_after_pass(&d);
            }
            lp.peers[2].engine.rotate_account(&p).unwrap();
            lp.sync_all().unwrap();
        }
        for k in [0, 2] {
            assert!(!counts(&lp, k), "early {early}: peer {k} counts the grant");
            assert!(!lp.peers[k].engine.roster(&d).contains_key(&tablet), "early {early}: peer {k} keeps the tablet on D");
        }
        for party in [lp.peers[1].engine.tid(), tablet] {
            for k in [0, 2] {
                let new: Vec<_> = super::tests::openable(&mut lp, k, &[d], party, Default::default()).difference(&before).map(|x| (x.1, x.2.n())).collect();
                assert!(new.is_empty(), "early {early}: {party:?} opens D's secrets {new:?} sealed after the removal from what peer {k} holds");
            }
        }
    }
}

// spec/sync-opens.md §2 (its account, with the signed rotations the verifier lacks): a node's
// Prove carries what holding the epoch it proves at needs, each after what it needs, never a
// removed node's forks it holds (they would crowd the message's room: each a header with a KEM
// key); a verifier holding only the account's record takes them and the node's key is open there
#[test]
fn a_prove_carries_no_removed_nodes_fork_spec_sync_opens_2() {
    let (mut lp, a, _) = world(4, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    let r = done.commits[1];
    let forks: Vec<CommitId> = [80u8, 81, 82].into_iter().map(|s| {
        let f = refork(&mut lp, 2, &a, s);
        give(&mut lp, &f, &[0])
    }).collect();
    let v = lp.peers[0].engine.core.account_view(&a.account).unwrap();
    assert!(forks.iter().all(|f| v.holds(f) && !v.rotation_counts(f)), "held, disregarded");
    let given = lp.peers[0].engine.prove_rotations().unwrap();
    let ids: Vec<CommitId> = given.iter().map(|x| osis_commit::CommitBlob::decode(&osis_base::cbor::encode(x)).unwrap().id()).collect();
    assert!(ids.contains(&r), "the removal's rotation");
    assert!(!ids.iter().any(|i| forks.contains(i)), "no fork: {ids:?}");
    let record = lp.peers[0].engine.core.created(&a.account).cloned().unwrap();
    let key = lp.peers[0].engine.account_open_key().unwrap();
    let mut fresh = LocalPeer::new_bare(1, 7, WallMs(1_700_000_000_000)).unwrap();
    let e = &mut fresh.peers[0].engine;
    e.learn_records(vec![record.clone()]).unwrap();
    e.take_rotations(given).unwrap();
    assert!(e.key_open(&record, &key), "the node's key open at the verifier");
}
