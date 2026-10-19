#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Node sync engines through blind nodes, in process (spec/sync.md §2-§9, §11).

mod net;
use net::*;
use osis_core::{Ak, Role, Value};
use osis_schema::AspectKey;
use osis_node::sync::Event;

pub fn trace(net: &mut Net, nodes: &[usize]) {
    for n in nodes {
        let d = net.sync(*n).take_diagnostics();
        if !d.is_empty() {
            eprintln!("node {n}: {d:?}");
        }
    }
}

// spec/sync.md §3, §5, §6: two nodes of one group converge through one blind server: closure
// bodies uploaded stamped, downloaded, unwrapped and applied, both ways.
#[test]
fn two_nodes_converge_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "hello");
    net.run();
    trace(&mut net, &[a, b]);
    assert_eq!(net.read(b, t), Some(s("hello")));
    net.write(b, t, "back");
    net.run();
    assert_eq!(net.read(a, t), Some(s("back")));
    assert!(net.sync(a).is_idle() && net.sync(b).is_idle());
    // nothing left to do: another round sends little
    let before = net.steps;
    net.run();
    assert!(net.steps - before < 8, "a quiet round exchanged {} messages", net.steps - before);
}

// spec/sync.md §5, §6: a reader relays the stamped must-hold entries it holds to a server
// lacking them; it originates nothing it may not (no stamp of its own).
#[test]
fn reader_relays_spec_sync_6() {
    let mut net = Net::new();
    let s1 = net.add_server();
    let s2 = net.add_server();
    let a = net.node(1, &[s1]);
    let r = net.node(2, &[s1, s2]);
    let c = net.node(3, &[s2]);
    net.blocked.insert((a, s2));
    net.blocked.insert((c, s1));
    let g = net.group(a, &[(r, Role::Read), (c, Role::Read)], &[s1, s2]);
    let t = net.item(a, g, g, "relayed");
    net.run();
    net.run();
    trace(&mut net, &[a, r, c]);
    assert_eq!(net.read(r, t), Some(s("relayed")));
    assert_eq!(net.read(c, t), Some(s("relayed")), "the reader carried the writer's entries to the second server");
}

// spec/sync.md §8: a subscribed node gets new log events pushed without asking.
#[test]
fn subscription_push_spec_sync_8() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "one");
    net.run();
    assert_eq!(net.read(b, t), Some(s("one")));
    net.write(a, t, "two");
    // only the writer acts; the other node hears by push
    net.feed(a, Event::Local);
    net.settle(100_000);
    assert_eq!(net.read(b, t), Some(s("two")));
}

// spec/sync.md §9: a signal reaches the label's other subscribers verified, fires the sender's
// own listeners, is stored nowhere; a targeted signal is dropped by other nodes.
#[test]
fn signals_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    net.run();
    let kind = Ak::new("/t/typing").unwrap();
    let acts = net.sync(a).signal(&t, kind.clone(), Value::Bool(true), None).unwrap();
    net.actions(a, acts);
    net.settle(10_000);
    assert_eq!(net.sync(a).take_signals().len(), 1, "own listeners fire");
    for n in [b, c] {
        let got = net.sync(n).take_signals();
        assert_eq!(got.len(), 1, "node {n}");
        assert_eq!((got[0].kind.clone(), got[0].value.clone()), (kind.clone(), Value::Bool(true)));
    }
    let ct = net.tid(c);
    let acts = net.sync(b).signal(&t, kind.clone(), Value::Int(2), Some(ct)).unwrap();
    net.actions(b, acts);
    net.settle(10_000);
    assert!(net.sync(a).take_signals().is_empty(), "targeted elsewhere: dropped");
    assert_eq!(net.sync(c).take_signals().len(), 1);
}

// spec/sync.md §11: a bundle replays a label as a peer with no cursor; a member that never
// reached a server ends up with the content.
#[test]
fn bundle_round_trip_spec_sync_11() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[]);
    net.blocked.insert((b, sv));
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "bundled");
    net.run();
    let (_, l) = net.sync(a).labels().into_iter().next().unwrap();
    let bytes = net.sync(a).export_bundle(&[l.id]).unwrap();
    assert_eq!(net.read(b, t), None);
    let acts = net.sync(b).import_bundle(&bytes).unwrap();
    assert!(acts.is_empty());
    trace(&mut net, &[b]);
    assert_eq!(net.read(b, t), Some(s("bundled")));
}

// spec/sync.md §6: the cursor, entries and heads survive a restart: the node resumes where it
// was and re-uploads nothing it placed before.
#[test]
fn restart_resumes_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "one");
    net.run();
    let l = net.label(a);
    let n = net.server_ids(sv, &l).len();
    net.restart(b, 22);
    net.run();
    assert_eq!(net.server_ids(sv, &l).len(), n, "nothing placed twice");
    net.write(a, t, "two");
    net.run();
    assert_eq!(net.read(b, t), Some(s("two")));
}

// spec/sync.md §5-§7 (headline): two devices that are never online together converge through
// one blind server, across a rotation, a compaction and an expiring write.
#[test]
fn briefly_online_devices_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    net.set_online(b, false);
    let t = net.item(a, g, g, "a1");
    let mut m = osis_node::Mutation::new();
    m.set(t, &BRIEF, &s("soon gone")).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    net.set_online(a, false);

    net.set_online(b, true);
    net.advance(10_000);
    trace(&mut net, &[b]);
    assert_eq!(net.read(b, t), Some(s("a1")));
    net.write(b, t, "b1");
    net.write(b, t, "b2");
    net.run();
    net.set_online(b, false);

    // A: a rotation (its own, no departure) and a compaction while B is away
    net.set_online(a, true);
    net.advance(10_000);
    assert_eq!(net.read(a, t), Some(s("b2")));
    let (at, bt) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    rotation(e, g, &rs, 61, false);
    let acts = net.sync(a).compact(&t, &Ak::new(REG.ak()).unwrap()).unwrap();
    net.actions(a, acts);
    net.run();
    net.write(a, t, "a2");
    net.run();
    trace(&mut net, &[a]);
    net.set_online(a, false);

    // an hour later the expiring write is gone everywhere; B catches up alone
    net.clock.advance(3_600_000);
    net.set_online(b, true);
    net.advance(10_000);
    trace(&mut net, &[b]);
    assert_eq!(net.read(b, t), Some(s("a2")));
    let brief = Ak::new(BRIEF.ak()).unwrap();
    assert_eq!(net.engine(b).get(&t, &brief).unwrap(), None);
    net.write(b, t, "b3");
    net.run();
    net.set_online(b, false);
    net.set_online(a, true);
    net.advance(10_000);
    assert_eq!(net.read(a, t), Some(s("b3")));
}
