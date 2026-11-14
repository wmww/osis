//! Stranded reports at the receiver (spec/permissions.md §4 Stranded, §3 Re-seal): the holder
//! keys a report brings are taken along the holder's authority chain alone, and the re-seal it
//! asks for writes only what differs.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, granted, group, synced};
use super::Reseal;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid};
use std::collections::BTreeSet;

/// Peer 2's team T holds read on peer 0's group G; everyone synced. (lp, G, T)
fn team_on_g() -> (LocalPeer, Tid, Tid) {
    let (lp, (g, t)) = LocalPeer::cached("rotation::tests_stranded::team_on_g", || {
        let mut lp = synced(3);
        let t = group(&mut lp, 2);
        lp.sync_all().unwrap();
        let g = group(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &t, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        (lp, (g, t))
    });
    (lp, g, t)
}

fn held(lp: &LocalPeer, i: usize, ids: &[CommitId]) -> usize {
    ids.iter().filter(|c| lp.peers[i].engine.header(c).is_some()).count()
}

fn ids_of(keys: &osis_label::HolderKeys) -> Vec<CommitId> {
    keys.commits.iter().map(|v| osis_commit::CommitBlob::decode(&osis_base::encode(v)).unwrap().id()).collect()
}

// spec/permissions.md §4 (stranded), spec/crypto.md §4 (Reported): the receiver takes the holder
// keys as chain certificates; a node gone from the holder learns its keyset only so. T rotates
// unseen by peer 0; the holder keys of T from peer 2 bring T's new keyset to peer 0.
#[test]
fn holder_keys_bring_the_holders_new_keyset_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let k = lp.peers[2].engine.rotate_leaving_out(&t, &[Role::Read], &[]).unwrap().unwrap();
    assert!(lp.peers[0].engine.header(&k).is_none(), "peer 0 lacks T's new keyset");
    let keys = lp.peers[2].engine.holder_keys(&t).unwrap();
    assert!(ids_of(&keys).contains(&k));
    assert!(lp.peers[0].engine.take_holder_keys(&t, &keys).unwrap() > 0);
    assert!(lp.peers[0].engine.current_keys(&t).contains(&k), "T's new keyset taken");
}

// spec/permissions.md §4 (stranded): nothing off the holder's authority chain is taken (peer
// input never causes unbounded storage, spec/requirements.md). A report naming T that
// carries the role commits and record of X, a group of peer 2's peer 0 never saw, leaves peer 0
// none of them; X's keys named under X itself are taken only as a holder's (X holds nothing).
#[test]
fn holder_keys_take_nothing_off_the_chain_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let x = group(&mut lp, 2);
    let keys = lp.peers[2].engine.holder_keys(&x).unwrap();
    let mut ids = ids_of(&keys);
    ids.retain(|c| lp.peers[0].engine.header(c).is_none());
    assert!(!ids.is_empty() && !lp.peers[0].engine.knows(&x));
    assert_eq!(lp.peers[0].engine.take_holder_keys(&t, &keys).unwrap(), 0);
    assert_eq!(held(&lp, 0, &ids), 0, "X's commits not kept");
    assert!(!lp.peers[0].engine.knows(&x), "X's record not kept");
}

// spec/permissions.md §3 (Re-seal), §4 (stranded): a re-seal a stranded notice asks for writes
// the holder's boxes at every current epoch held, unless each is as Seal gives it: the asked re-seal writes only where a box is missing or
// differs from the one Seal gives now, so asking again changes nothing once met.
#[test]
fn an_asked_reseal_writes_only_what_differs_spec_permissions_3() {
    let (mut lp, g, tids) = granted(2, &[(1, Role::Read)]);
    let m = tids[1];
    let ask = |lp: &mut LocalPeer| lp.peers[0].engine.run(|tx| super::reseal_one(tx, g, m, &BTreeSet::from([Role::Read]), Reseal::Asked)).unwrap().commits.len();
    assert_eq!(ask(&mut lp), 0, "boxed as Seal gives: nothing");
    lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Read], &[m]).unwrap().unwrap();
    assert_eq!(ask(&mut lp), 1, "left out: re-sealed");
    assert_eq!(ask(&mut lp), 0, "met: nothing more");
}

// spec/permissions.md §4 (stranded): no edge write of anything off the chain. Peer 0 knows X, a
// group of peer 2's on no path to T; a report naming T that carries a later grant on X leaves
// peer 0 without it.
#[test]
fn holder_keys_take_no_edge_write_off_the_chain_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let x = group(&mut lp, 2);
    lp.sync_all().unwrap();
    let p1 = lp.peers[1].engine.me();
    let c = lp.peers[2].engine.grant(&x, &p1, &edge(Role::Read)).unwrap().commits[0];
    let limits = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB };
    let v = osis_base::decode(&lp.peers[2].engine.run(|tx| tx.get_commit(&c)).unwrap().unwrap().encode(), &limits).unwrap();
    let keys = osis_label::HolderKeys { commits: vec![v], records: Vec::new() };
    assert_eq!(lp.peers[0].engine.take_holder_keys(&t, &keys).unwrap(), 0);
    assert!(lp.peers[0].engine.header(&c).is_none(), "the grant on X not kept");
}
