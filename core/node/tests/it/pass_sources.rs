#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Complete-pass sources (spec/permissions.md §3): a pass waits for every source a label was
//! received from that still reads it, keyed by what the connection's proofs identify (an own
//! node, else another account), connected or not, up to `peer_pass_wait_ms`.

use crate::connection_proofs::{account_node, paired_node};
use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{Role, Tid};

/// Node `a` (`a_seed`) gets an entry of group g from `src` by their direct connection alone (src
/// cut from the host); src goes offline; then a remote role commit on g (admin `d`'s grant)
/// reaches a by the host, and the host passes after it. `make` builds a and src.
fn gone_source(make: fn(&mut Net, usize) -> (usize, usize)) -> (Net, usize, usize, Tid) {
    // `make` is a function of this file: its address names it in this process
    let (net, (a, src, g)) = Net::cached(&format!("pass_sources::gone_source/{:p}", make as *const ()), || {
        let (net, a, src, g) = gone_source_built(make);
        (net, (a, src, g))
    });
    (net, a, src, g)
}

fn gone_source_built(make: fn(&mut Net, usize) -> (usize, usize)) -> (Net, usize, usize, Tid) {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, src) = make(&mut net, host);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, src);
    // a node of a's account reads g by the account
    let mut holders = vec![(c, Role::Read), (d, Role::Admin)];
    if net.tid(src) != net.tid(a) {
        holders.push((src, Role::Write));
    }
    let g = net.group(a, &holders, &[host]);
    net.run();
    net.advance(70_000);
    net.run();
    net.blocked.insert((src, host));
    net.drop_link(src, host);
    let t = net.item(src, g, g, "from src only");
    net.run();
    assert_eq!(net.read(a, t), Some(s("from src only")), "by the direct connection");
    // an own node is its own source, another account's node its account
    let ts = if net.tid(src) == net.tid(a) { net.node_tid(src) } else { net.tid(src) };
    assert!(net.sync(a).pass_source_held(ts) > 0, "src is a source of g at a");
    net.set_online(src, false);
    net.run();
    let tc = net.tid(c);
    net.grant(d, g, tc, Role::Write);
    net.run();
    net.advance(60_000);
    net.run();
    (net, a, src, g)
}

fn other_account(net: &mut Net, host: usize) -> (usize, usize) {
    (net.node(1, &[host]), net.node(2, &[host]))
}

fn own_node(net: &mut Net, host: usize) -> (usize, usize) {
    let (a, account) = account_node(net, 1, host);
    (a, paired_node(net, 2, host, a, account))
}

/// The pass at the host alone does not complete g while `src` is away; it does once src
/// reconnects and passes, or once the peer wait is over.
fn waits_for_gone_source(make: fn(&mut Net, usize) -> (usize, usize)) {
    let (mut net, a, src, g) = gone_source(make);
    assert!(!net.sync(a).complete_pass(&g), "src is not heard out: the host's pass alone is not complete");
    net.set_online(src, true);
    net.run();
    net.advance(60_000);
    net.run();
    assert!(net.sync(a).complete_pass(&g), "src reconnected and passed");

    let (mut net, a, _, g) = gone_source(make);
    assert!(!net.sync(a).complete_pass(&g));
    let wait = net.sync(a).config().peer_pass_wait_ms;
    net.advance(wait);
    net.run();
    assert!(net.sync(a).complete_pass(&g), "src never back: passed once the peer wait is over");
}

// spec/permissions.md §3: a node of another account the label was received from holds the pass
// while disconnected, until it reconnects or the peer wait ends.
#[test]
fn a_disconnected_account_holds_the_pass_spec_permissions_3() {
    waits_for_gone_source(other_account);
}

// spec/permissions.md §3: so does a node of this node's own account.
#[test]
fn a_disconnected_own_node_holds_the_pass_spec_permissions_3() {
    waits_for_gone_source(own_node);
}

/// `src` offline drops its records of the pair, then comes back: `a` keeps its old record of src
/// (orphaned) and makes another for the new connection.
fn lose_records(net: &mut Net, a: usize, src: usize) {
    net.set_online(src, false);
    net.run();
    net.engine(src).run(|tx| Ok(tx.txn.records_evict(0, &Default::default())?)).unwrap();
    net.set_online(src, true);
    net.run();
    net.advance(60_000);
    net.run();
    let ts = net.tid(src);
    assert!(net.engine(a).run(|tx| Ok(tx.txn.records_of_actors(&[ts])?)).unwrap().len() >= 2, "two records of one pair at a");
}

// spec/permissions.md §3, notes/peers.md Complete passes: what a node remembers of its sources
// is per source and label, not per record or connection: new records for one pair add nothing.
// A source is what the proofs identify, not a record: with several records for one pair (src lost
// its record), the orphan records hold no pass; src's passes over its new record complete g with
// no peer wait.
#[test]
fn pass_sources_do_not_grow_per_record_spec_permissions_3() {
    let (mut net, a, src, g) = gone_source(other_account);
    let ts = net.tid(src);
    net.set_online(src, true);
    net.run();
    let held = net.sync(a).pass_source_held(ts);
    for _ in 0..5 {
        lose_records(&mut net, a, src);
        let t = net.item(src, g, g, "again");
        net.run();
        assert_eq!(net.read(a, t), Some(s("again")), "src is heard on its new record");
    }
    let held_after = net.sync(a).pass_source_held(ts);
    assert_eq!(held_after, held, "5 more records, the same sources");
    net.advance(60_000);
    net.run();
    assert!(net.sync(a).complete_pass(&g), "src's passes on the new record count");
}

// spec/permissions.md §3, notes/peers.md Complete passes: a source is remembered only while it is
// known here: an account removed from the one group it shared with this node leaves nothing.
#[test]
fn an_unknown_source_is_forgotten_spec_permissions_3() {
    let (mut net, a, src, g) = gone_source(other_account);
    let ts = net.tid(src);
    assert!(net.sync(a).pass_source_held(ts) > 0);
    // gone_source made c and d after a and src
    let (ta, tc, td) = (net.tid(a), net.tid(2), net.tid(3));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin), (tc, Role::Write), (td, Role::Admin)]);
    remove_holder(e, g, ts, &rec, 91);
    net.run();
    assert_eq!(net.sync(a).pass_source_held(ts), 0, "src known no longer: nothing of it is left");
}
