#![allow(clippy::unwrap_used)]
//! An account's signing chain as its nodes write it (spec/permissions.md §3, §5.5,
//! spec/crypto.md §9): a removal from D rotates the account with thing lists; listings, a
//! witness's addenda and merges name what the rotation's list could not.

use crate::flows::{CreatedAccount, Delivery, Demotion, Done};
use crate::local_peer::LocalPeer;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_schema::core_types as ct;

fn edge(r: Role) -> ct::Edge {
    ct::Edge { role: r, until: None, invite: None, tied: None }
}

fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
    for id in ids {
        if let Some(pk) = lp.peers[from].engine.package(id).unwrap() {
            lp.deliver(to, &pk).unwrap();
        }
    }
}

fn carry(lp: &mut LocalPeer, from: usize, done: &Done) {
    for d in &done.deliveries {
        if let Delivery::Direct { to, commits } = d
            && let Some(i) = lp.peers.iter().position(|p| p.engine.tid() == *to)
        {
            send(lp, from, i, commits);
        }
    }
}

/// Peers `0..nodes` are nodes of account P (created on 0, the others paired); the rest each
/// create an account of their own. Peer 0 makes thing `t` (`x:a.0` = "p") and grants the first
/// outsider's account write there. All synced. Returns (lp, P, t).
fn world(n: usize, nodes: usize) -> (LocalPeer, CreatedAccount, Tid) {
    let (lp, (a, t)) = LocalPeer::cached(&format!("rotation::tests_signing::world/{n}/{nodes}"), || {
        let mut lp = LocalPeer::new_bare(n, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[0].engine.create_account(&[]).unwrap();
        for i in 1..nodes {
            let node = lp.peers[i].engine.tid();
            let ids = lp.peers[i].engine.commit_ids();
            send(&mut lp, i, 0, &ids);
            let done = lp.peers[0].engine.pair(&node).unwrap();
            carry(&mut lp, 0, &done);
            lp.peers[i].engine.paired(&a.account, &done.commits[0]).unwrap();
        }
        for i in nodes..n {
            lp.peers[i].engine.create_account(&[]).unwrap();
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
    let keys = Ak::new("keys.0").unwrap();
    // the outsider's thing `u`: the account writes there by a raw edge write, then a grant by the
    // flow gives `u` secrets of its own, its `keys.0` in that commit
    let q = lp.peers[3].engine.me();
    let mut m = crate::Mutation::new();
    let u = lp.peers[3].engine.new_thing(&mut m, q);
    m.op(u, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(a.account))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge(Role::Write))) }).unwrap();
    lp.peers[3].commit(m).unwrap();
    lp.peers[3].engine.grant(&u, &a.account, &edge(Role::Write)).unwrap();
    let pks = lp.packages(3).unwrap();
    let carries = |id: &CommitId| lp.peers[3].engine.header(id).unwrap().aspects.iter().any(|h| h.tid == u && h.ak == keys);
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
// chain; an outsider holding both reads both heads open and is told of nothing. Each head's line
// lacks the other's removal (blocked: either may be boxed to the removed node), so each node
// holding both owes a rotation, none designated: both rotate at once, superseding both heads and
// naming them (signed at each), and their two rotations fork and stand, owing nothing more; the
// account's next write at either counts at the outsider
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
    send(&mut lp, 0, 1, &[m0]);
    send(&mut lp, 1, 0, &[m1]);
    send(&mut lp, 0, 3, &[r0, r1]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("p".into())), "the account's earlier write counts through the fork");
    assert!(lp.peers[3].engine.account_disputes().is_empty(), "honest concurrent rotations warn of nothing");
    let w0 = write(&mut lp, 0, t, "after");
    send(&mut lp, 0, 3, &[m0, m1, w0]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())), "the rotations' epochs are open");
    assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads().len(), 2, "their fork stands");
    assert!(lp.peers[3].engine.account_disputes().is_empty());
    for k in [0, 1] {
        assert!(lp.peers[k].engine.signing_due().unwrap().commits.is_empty(), "peer {k}: a fork alone owes nothing");
    }
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
// either rotation; the two rotations fork and stand, owing nothing more
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
    for k in [0, 1] {
        assert!(lp.peers[k].engine.signing_due().unwrap().commits.is_empty(), "peer {k}: the two rotations' fork stands");
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().heads().len(), 2);
    }
    // the write's body dropped with its fall is offered again
    send(&mut lp, 2, 3, &[late]);
    for k in [0, 1, 3] {
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("removed".into())), "peer {k}: the removed node's write counts after the merge");
    }
    let w = write(&mut lp, 1, t, "after");
    send(&mut lp, 1, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())), "the merge's epoch is open");
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

// spec/permissions.md §5.5 (Listings, Nothing waits for a thing list): a listing at an epoch a
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

// spec/crypto.md §4 (Encrypting under, an account's epochs; Seal): a node of P holding a removal
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

// spec/crypto.md §4 (Encrypting under, an account's epochs): order is not knowledge. N1 (peer 0)
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

// spec/crypto.md §4 (Encrypting under, an account's epochs): as the ignorant fork above, but N3
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

// spec/crypto.md §9 (a node takes a seed up only under an established epoch of D): N1 (peer 0)
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

// spec/permissions.md §3 (a removal's rotation), spec/crypto.md §4 (an account's epochs): a removal
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

// spec/permissions.md §5.4 (Open): a removed node keeps its old epoch's key and forks the chain
// plainly from it after every rotation, a head nothing rejects until a node of the account
// rotates. Every head is open, so the account's earlier and later writes keep counting through
// every fork at a reader, it is told of nothing, and each rotation rejecting a fork ends it
#[test]
fn a_removed_nodes_reforks_hide_nothing_spec_permissions_5_4() {
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
        give(&mut lp, &f, &[0, 1, 3]);
        let v = lp.peers[3].engine.core.account_view(&a.account).unwrap();
        assert_eq!(v.heads().len(), 2, "round {round}: the fork stands until rejected");
        says(&mut lp, &later);
        assert!(lp.peers[3].engine.account_disputes().is_empty(), "round {round}: a lone fork is told of nowhere");
        merge(&mut lp, &[0, 1], &[0, 1, 3]);
        later = format!("after rotation {round}");
        let w = write(&mut lp, 1, t, &later);
        send(&mut lp, 1, 3, &[w]);
        says(&mut lp, &later);
        assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads().len(), 1, "round {round}: the rotation ends the fork");
    }
}

// spec/permissions.md §5.4 (Open, Doubt): every head is open, so a reader the removed node's
// fork reached before the removal and the rotation rejecting the earlier fork loses nothing: the
// account's write on that rotation's line counts there as anywhere, and nothing is told (no
// dispute, only a fork until a node of the account rejects it). The next rotation rejects the
// fork at every reader, whatever the order it received things in
#[test]
fn a_reader_the_fork_reached_first_loses_nothing_spec_permissions_5_4() {
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
        lp.advance(1);
        send(&mut lp, 0, k, &done.commits[1..]);
        lp.advance(1);
        send(&mut lp, 3, k, &[f1, m1, w]);
        assert_eq!(told(&mut lp, k), 0, "peer {k}: a fork is no dispute");
        assert_eq!(read(&mut lp, k, t), Some(Value::Str("merged".into())), "peer {k} reads every head");
        assert!(lp.peers[k].engine.account_disputes().is_empty());
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().heads(), { let mut h = vec![m1, f2]; h.sort(); h });
    }
    lp.peers[5].engine.rebuild_index().unwrap();
    assert_eq!(read(&mut lp, 5, t), Some(Value::Str("merged".into())), "peer 5 after a rebuild");
    // the next rotation rejects the fork at every reader
    for k in [0, 1] {
        lp.advance(1);
        lp.peers[k].engine.ingest(&f2b, Vec::new()).unwrap();
    }
    let m2 = merge(&mut lp, &[0, 1], &[0, 1]);
    let w2 = write(&mut lp, 1, t, "after");
    for k in [3, 4, 5] {
        lp.advance(1);
        send(&mut lp, 0, k, &[m2]);
        send(&mut lp, 1, k, &[w2]);
        assert_eq!(read(&mut lp, k, t), Some(Value::Str("after".into())), "peer {k}");
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().heads(), vec![m2], "peer {k}");
    }
}

// spec/permissions.md §5.4 (Nodes of P): a node of the account signs on the line D's roster
// authorizes. Node 2 rotates while node 0 removes it; node 1 gets node 2's rotation first and
// holds its seed. The rotation of the account owed then rejects node 2's fork (a removed
// node's, unnamed): node 1 prefers it, so its next write counts at an outsider
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

// spec/permissions.md §5.5 (Epoch rule, Listings): an honest node's writes at a removed node's
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

// spec/permissions.md §5.4 (Nodes of P): a removed node's rotation beside its removal stands
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

// spec/permissions.md §5.4 (Nodes of P): a re-added node's rotations made after its re-add
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
    let done = lp.peers[0].engine.pair(&node).unwrap();
    carry(&mut lp, 0, &done);
    send(&mut lp, 0, 1, &done.commits);
    lp.peers[2].engine.paired(&a.account, &done.commits[0]).unwrap();
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

// spec/permissions.md §5.4 (Nodes of P): only a removal that counts puts its node beside it.
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

// spec/permissions.md §5.5 (Cutoff, Honest nodes of P): a removed node removes no one for good.
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
// rotation first (it waits for its other parent): what its list names stands as before. Once
// node 1's rotation comes, the write counts by the list, as a rebuilt index reads it
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
    send(&mut lp, 1, 3, &[rb]);
    assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads(), vec![m]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("at ra".into())), "named by the rotation's list");
    let d0 = lp.peers[3].engine.index_digest();
    lp.peers[3].engine.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[3].engine.index_digest()), None, "rebuilt");
}
