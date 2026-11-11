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

fn seeds(lp: &LocalPeer, peer: usize, p: Tid) -> usize {
    lp.peers[peer].engine.core.accounts.get(&p).map_or(0, |a| a.seeds.len())
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
// chain; an outsider holding both follows one and is told of nothing; a node holding both
// merges them, signed at each fork, and the outsider holding the merge reads the merge's epoch,
// where the account's next write counts
#[test]
fn concurrent_rotations_fork_and_a_node_merges_them_spec_crypto_9() {
    let (mut lp, a, t) = world(4, 3);
    let d0 = remove(&mut lp, 0, a.devices, 2);
    let d1 = remove(&mut lp, 1, a.devices, 2);
    let (r0, r1) = (d0.commits[1], d1.commits[1]);
    send(&mut lp, 1, 0, &d1.commits);
    send(&mut lp, 0, 1, &d0.commits);
    // each holds both forks' seeds (each removal boxed it the epoch its rotation's seed sits
    // under); one of them merges, the node whose fork is the lower
    let (m0, m1) = (lp.peers[0].engine.signing_due().unwrap(), lp.peers[1].engine.signing_due().unwrap());
    assert_eq!(m0.commits.len() + m1.commits.len(), 1, "one merger");
    let i = if m0.commits.is_empty() { 1 } else { 0 };
    send(&mut lp, i, 1 - i, &[m0.commits.clone(), m1.commits.clone()].concat());
    let merge = *lp.peers[i].engine.commit_ids().iter().find(|c| lp.peers[i].engine.header(c).is_some_and(|h| h.rotation.as_ref().is_some_and(|r| !r.names.is_empty()))).unwrap();
    let h = lp.peers[i].engine.header(&merge).unwrap();
    let rh = h.rotation.as_ref().unwrap();
    assert_eq!(rh.supersedes.iter().copied().collect::<std::collections::BTreeSet<_>>(), [r0, r1].into());
    assert_eq!(rh.names.len(), 1);
    send(&mut lp, 0, 3, &[r0, r1]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("p".into())), "the account's earlier write counts through the fork");
    assert!(lp.peers[3].engine.account_disputes().is_empty(), "honest concurrent rotations warn of nothing");
    let w0 = write(&mut lp, 1 - i, t, "after the merge");
    send(&mut lp, 1 - i, 3, &[merge, w0]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after the merge".into())), "the merge's epoch is open");
    assert!(lp.peers[3].engine.account_disputes().is_empty());
    // nothing more is due
    for k in [0, 1] {
        assert!(lp.peers[k].engine.signing_due().unwrap().commits.is_empty(), "peer {k}");
    }
    let rotations = lp.peers[0].engine.commit_ids().iter().filter(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.rotation.is_some())).count();
    assert_eq!(rotations, 3, "two forks and one merge");
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
// rotation's list naming its own later write, wins nothing once a node of the account merges:
// the merge supersedes the fork unnamed (D's roster does not authorize it), so the fork is
// rejected with its list, and the removed node's write counts for nothing at a sibling or an
// outsider holding the merge
#[test]
fn a_removed_nodes_fork_is_merged_out_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let done = remove(&mut lp, 0, a.devices, 2);
    send(&mut lp, 0, 1, &done.commits);
    send(&mut lp, 0, 3, &done.commits[1..]);
    // the removed node, unaware, writes and rotates: its rotation lists the write
    let late = write(&mut lp, 2, t, "removed");
    let fork = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[])).unwrap().unwrap();
    for to in [0, 1, 3] {
        send(&mut lp, 2, to, &[late, fork]);
    }
    let mut merges = Vec::new();
    for k in [0, 1] {
        merges.extend(lp.peers[k].engine.signing_due().unwrap().commits);
    }
    assert_eq!(merges.len(), 1, "one node of the account merges");
    let h = lp.peers[0].engine.header(&merges[0]).or_else(|| lp.peers[1].engine.header(&merges[0])).unwrap();
    let rh = h.rotation.as_ref().unwrap();
    assert!(rh.supersedes.contains(&fork) && rh.names.is_empty(), "the fork superseded unnamed: {rh:?}");
    for k in [0, 1] {
        for to in [0, 1, 3] {
            if to != k {
                send(&mut lp, k, to, &merges);
            }
        }
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
    s.boxes.iter().find(|(k, _)| k.holder == m && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)).and_then(|(_, b)| osis_keys::box_epoch(b))
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
fn node_knowing_a_removal_seals_its_account_at_no_epoch_minted_before_spec_crypto_4() {
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

/// A plain fork of `a`'s chain from its first epoch to a fresh epoch from `seed`, as removed
/// node `by` (which still holds the first epoch's seed) can sign after every merge.
fn refork(lp: &mut LocalPeer, by: usize, a: &CreatedAccount, seed: u8) -> Vec<u8> {
    let e = &lp.peers[by].engine;
    let rec = e.core.created(&a.account).unwrap().clone();
    let osis_base::CreationRecord::KeyActor { public_key, .. } = &rec else { panic!("an account") };
    let first = e.core.accounts.get(&a.account).unwrap().seeds.get(public_key.as_slice()).unwrap().clone();
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

/// The merge one of `nodes` owes, sent to every peer in `to`.
fn merge(lp: &mut LocalPeer, nodes: &[usize], to: &[usize]) -> CommitId {
    let mut made = Vec::new();
    for &k in nodes {
        let d = lp.peers[k].engine.signing_due().unwrap();
        made.extend(d.commits.iter().map(|c| (k, *c)));
    }
    assert_eq!(made.len(), 1, "one merger: {made:?}");
    let (by, m) = made[0];
    for &k in to {
        if k != by {
            lp.advance(1);
            send(lp, by, k, &[m]);
        }
    }
    m
}

// spec/permissions.md §5.4 (Following): a removed node keeps its old epoch's key and forks the
// chain plainly from it after every merge, a rotation nothing rejects until the next merge. A
// reader holding the removal follows the line it already read: the account's earlier and later
// writes keep counting through every fork, it is told of nothing, and every merge ends the fork
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
        assert_eq!(v.heads().len(), 2, "round {round}: the fork stands until the merge");
        says(&mut lp, &later);
        assert!(lp.peers[3].engine.account_disputes().is_empty(), "round {round}: a lone fork is told of nowhere");
        merge(&mut lp, &[0, 1], &[0, 1, 3]);
        later = format!("after merge {round}");
        let w = write(&mut lp, 1, t, &later);
        send(&mut lp, 1, 3, &[w]);
        says(&mut lp, &later);
        assert_eq!(lp.peers[3].engine.core.account_view(&a.account).unwrap().heads().len(), 1, "round {round}: the merge ends the fork");
    }
}

// spec/permissions.md §5.4 (Following, Doubt): a reader that the removed node's fork reached
// before the removal and the merge follows that fork; the other line carries a merge, so it is
// told and lists the dispute, and switching to the merged line shows the account's writes there.
// Another reader in the same place is set right by the next merge alone, and every reader
// ends on the same reading whatever the order it received things in
#[test]
fn a_reader_the_fork_reached_first_is_told_and_switches_spec_permissions_5_4() {
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
        assert_eq!(told(&mut lp, k), 0, "peer {k}: the fork alone is no doubt");
        lp.advance(1);
        send(&mut lp, 0, k, &done.commits[1..]);
        lp.advance(1);
        send(&mut lp, 3, k, &[f1, m1, w]);
        assert_eq!(told(&mut lp, k), 1, "peer {k} is told once");
    }
    for k in [4, 5] {
        assert_ne!(read(&mut lp, k, t), Some(Value::Str("merged".into())), "peer {k} follows the fork it got first");
        let ds = lp.peers[k].engine.account_disputes();
        assert_eq!(ds.len(), 1, "peer {k}: in doubt, the other line carries a merge");
        assert_eq!((ds[0].account, ds[0].side, ds[0].chosen), (a.account, f2, false));
        assert!(ds[0].lines.contains(&m1));
    }
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("merged".into())), "peer 3 had the merged line first");
    assert!(lp.peers[3].engine.account_disputes().is_empty());
    // the line received first is read from what is held: a rebuilt index reads it alike
    lp.peers[5].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[5].engine.core.account_view(&a.account).unwrap().open(), f2, "peer 5 after a rebuild");
    lp.peers[4].engine.choose_line(a.account, m1).unwrap();
    // the write's body, dropped while it counted for nothing, is offered again
    send(&mut lp, 3, 4, &[w]);
    assert_eq!(read(&mut lp, 4, t), Some(Value::Str("merged".into())), "switched");
    let ds = lp.peers[4].engine.account_disputes();
    assert_eq!((ds.len(), ds[0].side, ds[0].chosen), (1, m1, true));
    // the next merge rejects the fork: peer 5 is set right without a choice
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
    assert!(lp.peers[5].engine.account_disputes().is_empty(), "the merge ended it");
}

// spec/permissions.md §5.4 (Nodes of P): a node of the account follows the line D's roster
// authorizes, as the merge reads it. Node 2 rotates while node 0 removes it; node 1 gets node
// 2's rotation first and holds its seed. Node 0's merge rejects node 2's fork (a removed node's,
// unnamed): node 1 follows the merge, so its next write counts at an outsider
#[test]
fn a_node_follows_the_merge_over_a_removed_nodes_earlier_rotation_spec_permissions_5_4() {
    let (mut lp, a, t) = world(4, 3);
    let x0 = lp.peers[2].engine.run(|tx| crate::flows::signing::rotate_in(tx, a.account, &[])).unwrap().unwrap();
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
        assert_eq!(lp.peers[k].engine.core.account_view(&a.account).unwrap().open(), m, "peer {k} follows the merge");
    }
    let w = write(&mut lp, 1, t, "after");
    send(&mut lp, 1, 3, &[w]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after".into())), "node 1's write counts");
    lp.peers[1].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[1].engine.core.account_view(&a.account).unwrap().open(), m, "node 1 after a rebuild");
}
