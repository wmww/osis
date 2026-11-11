#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Promotion of readers' deposits (spec/sync.md §5 Promotion, Clearing deposits): a writer
//! stamps a deposited commit only where the label must hold it and holds no stamped copy of it.

use crate::net::hosted_nodes;
use crate::net;
use net::*;
use osis_base::{BlobId, CommitId, LabelId, Role, Tid};
use osis_node::sync::{Action, EntryKind};
use osis_proto::{LabelStore, Message, encode_frame};
use std::collections::{BTreeMap, BTreeSet};

/// The durable commit entries node `n` holds under `l`: commit and parts.
fn commits_under(net: &mut Net, n: usize, l: &LabelId) -> BTreeMap<CommitId, Vec<usize>> {
    let mut out = BTreeMap::new();
    for (_, k) in net.sync(n).entries(l) {
        if let EntryKind::Commit { commit, parts, .. } = k
            && net.engine(n).header(&commit).is_some_and(|h| h.ephemeral.is_none())
        {
            out.insert(commit, parts);
        }
    }
    out
}

/// Whether the host holds `id` under `l` stamped.
fn stamped(net: &Net, host: usize, l: &LabelId, id: &BlobId) -> bool {
    net.hosts[host].hub.store().entry(l, id).unwrap().is_some_and(|m| m.stamp.is_some())
}

/// Reader `r` deposits at `host` under `g`'s label `l` `n` fresh encryptions of each of
/// `commits` (its parts there), all in one go: the IDs per commit.
fn flood(net: &mut Net, r: usize, (host, g, l): (usize, Tid, LabelId), commits: &BTreeMap<CommitId, Vec<usize>>, n: usize) -> BTreeMap<CommitId, Vec<BlobId>> {
    let (_, gl) = net.group_labels(r).into_iter().find(|(_, x)| x.id == l).unwrap();
    let head = net.host_path(host, &l).last().unwrap().clone();
    let keys = net.engine(r).head_keys(&g, gl.index, &head).unwrap();
    let deposit = keys.deposit.unwrap();
    let secret = net.engine(r).wrap_secret(&g, None).unwrap().unwrap();
    let mut rng = osis_crypto::SeededRng::from_u64(7);
    let (mut out, mut sends) = (BTreeMap::new(), Vec::new());
    let conn = net.conn_to(r, host).unwrap();
    for (c, parts) in commits {
        let Some(body) = net.engine(r).part_body(c, &parts.iter().copied().collect()).unwrap() else { continue };
        for _ in 0..n {
            let s = net.engine(r).seal_to(&body, osis_label::Class::Durable, &secret, &mut rng).unwrap().unwrap();
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key, body.order).unwrap();
            let sig = osis_label::sign_deposit(&deposit, &l, &s.id, &wrap);
            out.entry(*c).or_insert_with(Vec::new).push(s.id);
            sends.push(Action::Send { conn, bytes: encode_frame(&Message::Deposit { id: 0x4000_0001, label: l, blob: s.blob, wrap, sig }.encode()) });
        }
    }
    net.actions(r, sends);
    net.run();
    out
}

// spec/sync.md §5 (Promotion: a deposited commit the label must hold, one stamped copy; Clearing
// deposits: what no writer would promote counts toward the cap): reader `r` of groups `g` and `h`
// deposits under `g`'s label fresh encryptions of every commit it holds under either label, ten
// each, as many as the host takes while `a` is away. Writer `a` stamps none of a commit the label held stamped
// already, at most one of any other, none of `h`'s own role commits (no authority path into `g`),
// and its clearing leaves at most `DEPOSITS_WAITING` of the rest.
#[test]
fn a_readers_copies_are_promoted_once_spec_sync_5() {
    let (mut net, host, [a, r]) = hosted_nodes::<2>();
    let g = net.group(a, &[(r, Role::Read)], &[host]);
    let addr = net.hosts[host].address.clone();
    let h = net.group_seeded(a, &[(r, Role::Read)], vec![addr], 2);
    net.run();
    net.advance(60_000);
    let label = |net: &mut Net, x: Tid| net.group_labels(a).into_iter().find(|(y, _)| *y == x).unwrap().1.id;
    let (l, lh) = (label(&mut net, g), label(&mut net, h));
    let mut commits = commits_under(&mut net, r, &l);
    let under_g: BTreeSet<CommitId> = commits.keys().copied().collect();
    for (c, p) in commits_under(&mut net, r, &lh) {
        commits.entry(c).or_insert(p);
    }
    // h's own: every aspect on h
    let h_only: BTreeSet<CommitId> = commits.keys().filter(|c| !under_g.contains(c) && net.engine(r).header(c).is_some_and(|x| x.aspects.iter().all(|a| a.tid == h))).copied().collect();
    assert!(!h_only.is_empty(), "h's own role commits");
    // what the label holds stamped already, by commit
    let mut held: BTreeSet<CommitId> = BTreeSet::new();
    for (id, k) in net.sync(a).entries(&l) {
        if let EntryKind::Commit { commit, .. } = k
            && stamped(&net, host, &l, &id)
        {
            held.insert(commit);
        }
    }
    net.set_online(a, false);
    let ids = flood(&mut net, r, (host, g, l), &commits, 10);
    let taken = ids.values().flatten().filter(|id| net.host_ids(host, &l).contains(id)).count();
    assert!(taken > osis_base::format::DEPOSITS_WAITING, "the host took {taken}: past the clearing cap");
    net.set_online(a, true);
    for _ in 0..5 {
        net.advance(60_000);
    }
    for (c, mine) in &ids {
        let n = mine.iter().filter(|id| stamped(&net, host, &l, id)).count();
        if held.contains(c) || h_only.contains(c) {
            assert_eq!(n, 0, "{c:?}: held already or not the label's, none stamped");
        } else {
            assert!(n <= 1, "{c:?}: {n} stamped copies");
        }
    }
    let live = net.host_ids(host, &l);
    let waiting = ids.values().flatten().filter(|id| live.contains(id) && !stamped(&net, host, &l, id)).count();
    assert!(waiting <= osis_base::format::DEPOSITS_WAITING, "{waiting} unpromoted copies stay");
}
