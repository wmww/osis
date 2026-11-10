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
    let mut lp = LocalPeer::new_bare(n, 1603, WallMs(1_700_000_000_000)).unwrap();
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
    let done = remove(&mut lp, 0, a.devices, 1);
    assert_eq!(done.commits.len(), 2, "the removal, then the rotation");
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
// chain, leaving no epoch open where both rotations are held; a node holding both merges them,
// signed at each fork, and an outsider holding the merge has an open epoch again, where the
// account's next write counts
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
    let w0 = write(&mut lp, 1 - i, t, "after the merge");
    send(&mut lp, 1 - i, 3, &[merge, w0]);
    assert_eq!(read(&mut lp, 3, t), Some(Value::Str("after the merge".into())), "the merge's epoch is open");
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
