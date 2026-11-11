#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Accounts on connections (spec/sync.md §10, Connection proofs, Pair key; issues/net-shared-set.md
//! step 10): an account proved at an epoch open here counts like any actor; a node key proves no
//! account and goes only to the nodes of its own account; a node removed from its account, once
//! the removal's rotation is held, proves the account nowhere.

use crate::net::local_nodes;
use crate::connection_proofs::{LISTENER, account_node, dial_with, paired_node, prove, proved_by};
use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{Role, Tid};
use osis_crypto::kdf::resume_tag;
use osis_engine::flows::Demotion;
use osis_node::labeling::Judgment;
use osis_proto::{ClientEvent, ClientInput, Command, Request};
use std::collections::BTreeSet;

fn records(net: &mut Net, n: usize, actor: Tid) -> Vec<osis_store::Record> {
    net.engine(n).run(|tx| Ok(tx.txn.records_of_actors(&[actor])?)).unwrap()
}

/// Every node tid of `nodes` that a connection at node `n` proved, per connection.
fn node_keys_proved(net: &mut Net, n: usize, nodes: &BTreeSet<Tid>) -> Vec<BTreeSet<Tid>> {
    net.sync(n).proven_connections().into_iter().map(|(_, p)| p.intersection(nodes).copied().collect()).collect()
}

// spec/sync.md §10 (Connection proofs, Pair key, Shared set): two nodes of different accounts that
// know each other's accounts, not each other's nodes, find their shared group and resume by
// record with no node identity exchanged: each side proved the other's account alone, and the
// record names the account
#[test]
fn accounts_find_their_groups_and_resume_with_no_node_identity_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, b);
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let (pa, pb) = (net.tid(a), net.tid(b));
    let nodes: BTreeSet<Tid> = [net.node_tid(a), net.node_tid(b)].into();
    let l = net.label(a);
    for (n, peer) in [(a, pb), (b, pa)] {
        let conns = net.sync(n).proven_connections();
        assert_eq!(conns.len(), 1, "{n}: one connection");
        assert_eq!(conns[0].1, BTreeSet::from([peer]), "{n}: the peer's account alone");
        assert!(net.sync(n).shared_members(conns[0].0).contains(&l), "{n}: g is shared");
        assert_eq!(net.sync(n).connection_record(conns[0].0).map(|id| records(&mut net, n, peer).iter().any(|r| r.id == id)), Some(true), "{n}: bound to a record naming the account");
    }
    let r = records(&mut net, a, pb)[0].r;
    assert_eq!(records(&mut net, b, pa)[0].r, r, "one r at both ends");
    assert!(nodes.iter().all(|t| records(&mut net, a, *t).is_empty() && records(&mut net, b, *t).is_empty()), "no record names a node");
    net.restart(a, 11);
    net.run();
    assert_eq!(records(&mut net, a, pb).len(), 1, "resumed, not a second record");
    assert_eq!(records(&mut net, a, pb)[0].r, r, "the same pair key");
    net.write(a, g, "after a restart");
    net.run();
    assert_eq!(net.read(b, g), Some(s("after a restart")), "the group syncs over the resumed record");
    for n in [a, b] {
        assert!(node_keys_proved(&mut net, n, &nodes).iter().all(BTreeSet::is_empty), "{n}: no node key crossed accounts");
    }
}

// spec/sync.md §10, issues/net-shared-set.md step 3: a node key proves no account. A node of P
// proving only its node key, at a node of another account that holds P's devices roster and
// shares a group with P, is neither known nor a holder: no proofs back, J unknown, and neither
// a record nor a shared set
#[test]
fn a_node_key_alone_reaches_nothing_at_another_account_spec_sync_10() {
    let (mut net, [a, x]) = local_nodes::<2>();
    let g = net.group_at(a, &[(x, Role::Write)], vec![]);
    net.run();
    let tx = net.node_tid(x);
    let (_, d) = net.engine(x).core.account_devices().unwrap();
    assert!(net.engine(a).core.timelines.get(&tx).is_some_and(|tl| tl.role(&tx, &d, osis_perm::At::KEYS).is_some()), "a holds x's devices roster: the chain from x to its account");
    let provers: Vec<_> = net.sync(x).provers(true).unwrap().into_iter().filter(|p| p.record.tid() == tx).collect();
    let mut p = dial_with(&mut net, a, [4; 32]);
    let evs = prove(&mut net, a, &mut p, provers);
    assert_eq!(proved_by(&evs), Vec::new(), "not known: no identity back");
    assert_eq!(net.sync(a).proven(p.conn).unwrap(), BTreeSet::from([tx]));
    let label = net.label(a);
    assert_eq!(net.sync(a).judgments(p.conn, &[label]).unwrap()[&label], Judgment::Unknown, "J reads no account from a node key");
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Resume { nonce: [5; 32], tags: vec![] }));
    let evs = crate::connection_proofs::pump(&mut net, a, &mut p, Vec::new(), outs);
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { kind: Request::Resume, .. })), "{evs:?}");
    assert_eq!(net.sync(a).connection_record(p.conn), None);
    assert!(net.sync(a).shared_members(p.conn).is_empty());
    let _ = g;
}

// spec/sync.md §10, spec/permissions.md §3: a node removed from its account, once the removal's
// rotation of P is held, proves P nowhere: its proofs as made before the removal (the closed
// epoch's key) find no record that names P, get no proof back and open nothing
#[test]
fn a_removed_node_after_the_rotation_matches_no_record_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (x1, account) = account_node(&mut net, 1, host);
    let x2 = paired_node(&mut net, 2, host, x1, account);
    let b = net.node(3, &[host]);
    reach_ed(&mut net, b);
    let g = net.group_at(b, &[(x1, Role::Write)], vec![]);
    assert_eq!(net.tid(x1), account);
    net.run();
    net.advance(70_000);
    net.run();
    let rec = records(&mut net, b, account);
    assert_eq!(rec.len(), 1, "b keeps one record of P");
    let r = rec[0].r;
    let old = net.sync(x2).provers(false).unwrap();
    // the removal from D, and P's rotation in the same transaction
    let (_, d) = net.engine(x1).core.account_devices().unwrap();
    let tx2 = net.node_tid(x2);
    let done = net.engine(x1).demote(&d, &Demotion { holder: tx2, new: None, retain: None }).unwrap();
    let acts = net.sync(x1).carry_out(done).unwrap();
    net.actions(x1, acts);
    net.set_online(x2, false);
    net.run();
    net.advance(70_000);
    net.run();
    assert!(old.iter().any(|p| p.record.tid() == account), "x2's proof of P as made before");
    let ch = [6; 32];
    let mut p = dial_with(&mut net, b, ch);
    let evs = prove(&mut net, b, &mut p, old.clone());
    assert_eq!(proved_by(&evs), Vec::new(), "nothing known proved: no identity back");
    assert!(!net.sync(b).proven(p.conn).unwrap().contains(&account), "P not proved by a closed epoch");
    let tag = resume_tag(&r, &LISTENER, &ch, &p.hello);
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Resume { nonce: [5; 32], tags: vec![tag] }));
    let evs = crate::connection_proofs::pump(&mut net, b, &mut p, Vec::new(), outs);
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { kind: Request::Resume, .. })), "no record found: {evs:?}");
    assert_eq!(net.sync(b).connection_record(p.conn), None);
    assert!(net.sync(b).shared_members(p.conn).is_empty(), "opens nothing");
    let record = net.engine(b).core.created(&account).unwrap().clone();
    let key = old.iter().find(|p| p.record.tid() == account).unwrap().key.verifying_key().to_bytes();
    assert!(!net.engine(b).account_key_open(&record, &key), "why: b holds the rotation, the epoch is closed");
    let _ = g;
}

// spec/sync.md §10 (Connection proofs): a node proves its node key to the nodes of its own account
// only, whichever side dialed: counted over every real connection of two nodes of P and a node
// of Q sharing a group
#[test]
fn a_node_key_goes_only_to_its_own_accounts_nodes_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (x1, account) = account_node(&mut net, 1, host);
    let x2 = paired_node(&mut net, 2, host, x1, account);
    let b = net.node(3, &[host]);
    for n in [x1, x2, b] {
        reach_ed(&mut net, n);
    }
    net.group_at(b, &[(x1, Role::Write)], vec![]);
    net.run();
    net.advance(70_000);
    net.run();
    let (t1, t2, tb) = (net.node_tid(x1), net.node_tid(x2), net.node_tid(b));
    let all: BTreeSet<Tid> = [t1, t2, tb].into();
    let (mut own, mut crossed) = (0, 0);
    for (n, mine) in [(x1, [t1, t2]), (x2, [t1, t2]), (b, [tb, tb])] {
        for keys in node_keys_proved(&mut net, n, &all) {
            own += keys.iter().filter(|k| mine.contains(k)).count();
            crossed += keys.iter().filter(|k| !mine.contains(k)).count();
        }
    }
    assert_eq!(crossed, 0, "a node key proved to another account's node");
    assert!(own >= 2, "x1 and x2 proved their node keys to each other: {own}");
    let conns_b = net.sync(b).proven_connections();
    assert!(conns_b.iter().any(|(_, p)| p.contains(&account)), "b sees P: {conns_b:?}");
}
