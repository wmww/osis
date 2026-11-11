//! World copies (notes/testing.md, Copied worlds): a copied `Net` goes on exactly as the
//! original, and the two share nothing.

use crate::net::{Net, hosted};
use osis_base::{Role, Tid};

/// Further steps: writes and an item, a skewed node, a new node granted in, a restart, time.
fn further(net: &mut Net, g: Tid, t: Tid) {
    net.write(1, t, "b1");
    net.item(2, g, g, "c1");
    net.set_skew(2, 1_500);
    net.run();
    let d = net.node(9, &[0]);
    net.pair(d, 0);
    let dt = net.tid(d);
    net.grant(0, g, dt, Role::Read);
    net.run();
    net.restart(1, 77);
    net.advance(61_000);
    net.write(0, t, "a2");
    net.tick(5_000);
    net.round();
}

/// What a test could compare: each node's reads, indexes, timelines, stored bytes and
/// diagnostics; each host's labels and entries and stored bytes; the net's counters.
fn observe(net: &mut Net, t: Tid) -> Vec<String> {
    let mut out = vec![format!("{:?} {:?} {:?} {} {:?} {} {}", net.sent_kinds, net.uploaded, net.peer_kinds, net.sent_bytes, net.dialed, net.steps, net.queue_len())];
    for n in 0..net.nodes.len() {
        out.push(format!("{:?} {:?}", net.read(n, t), net.diagnostics(n)));
        let sync = net.sync(n);
        out.push(format!("{:?} {:?}", sync.label_status(), sync.pass_stats()));
        let e = net.engine(n);
        out.push(format!("{:?} {} {:?}", e.index_digest(), e.perm_digest(false), e.store_dump().unwrap()));
        out.push(format!("{:?} {:?}", net.nodes[n].backend.dump(), net.nodes[n].backend.io()));
    }
    for s in 0..net.hosts.len() {
        let labels = net.labels_at(s);
        out.push(format!("{labels:?} {:?} {:?}", labels.iter().map(|l| net.host_ids(s, l)).collect::<Vec<_>>(), net.hosts[s].backend.dump()));
    }
    out
}

fn runs() -> Vec<(&'static str, u64)> {
    osis_node::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect()
}

// spec: none (internal: notes/testing.md, Copied worlds). A copied net goes on exactly as the
// original: the same further steps leave the same reads, indexes, stores, host entries,
// counters and memo runs, and steps on either leave the other as it was.
#[test]
fn a_copied_net_goes_on_as_the_original() {
    let (mut net, _host, [_a, _b, _c], g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Admin)], ["x"], true);
    net.write(0, t, "unsettled");
    let mut copy = net.copy();
    let mut untouched = net.copy();
    assert_eq!(observe(&mut net, t), observe(&mut copy, t), "as copied");
    observe(&mut untouched, t);
    runs();
    further(&mut net, g, t);
    let ran = runs();
    further(&mut copy, g, t);
    assert_eq!(ran, runs(), "memo and phase runs");
    let after = observe(&mut copy, t);
    assert_eq!(observe(&mut net, t), after, "after the same steps");
    // steps on the original and on a copy left this one as it was
    further(&mut untouched, g, t);
    assert_eq!(observe(&mut untouched, t), after, "the others' steps stay in them");
}
