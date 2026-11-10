#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The node log stream between readers (spec/sync.md §10, Stream; issues/net-reconnect.md, One
//! node log, one cursor): counted costs, and the invariant `osis_node::sync` stream.rs states.

use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{Role, Tid};
use osis_schema::RawKey;

const PULL: u64 = 41;
const SYNC: u64 = 15;
const SUBSCRIBE: u64 = 21;

/// Nodes `a` and `b` holding `n` groups together, `b` dialable: `a` dials `b` and pulls it.
fn pair(net: &mut Net, n: usize) -> (usize, usize, Vec<Tid>) {
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(net, b);
    let gs = (0..n).map(|i| net.group_seeded(b, &[(a, Role::Write)], vec![], 10 + i as u64)).collect();
    net.run();
    (a, b, gs)
}

// spec/sync.md §10 (Stream): a co-reader's entries come by one Pull stream, never a per-label Sync
#[test]
fn a_dialer_pulls_its_peer_stream_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    let t = net.item(b, gs[0], gs[0], "x");
    net.run();
    assert_eq!(net.read(a, t), Some(s("x")), "b's write reached a");
    assert!(net.peer_sent(a, PULL) > 0, "a pulls b");
    assert_eq!(net.peer_sent(a, SYNC) + net.peer_sent(a, SUBSCRIBE), 0, "no per-label Sync or Subscribe between readers");
}

/// What the stream replies and pushes carried, as a tamper hook sees them on peer links: per
/// message, whether it was a stream from the start, its events, and the blobs whose bytes it
/// carried.
#[derive(Default)]
struct Seen {
    replies: Vec<(bool, usize)>,
    pushed: usize,
    bodies: Vec<osis_base::BlobId>,
}

fn watch(net: &mut Net) -> std::rc::Rc<std::cell::RefCell<Seen>> {
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Seen::default()));
    let s = seen.clone();
    net.tamper = Some(Box::new(move |m| {
        let mut s = s.borrow_mut();
        let events = match m {
            osis_proto::Message::PullReply(r) => {
                s.replies.push((r.whole, r.events.len()));
                &r.events
            }
            osis_proto::Message::Stream(x) => {
                s.pushed += x.events.len();
                &x.events
            }
            osis_proto::Message::FetchReply { items, .. } => {
                s.bodies.extend(items.iter().filter(|f| f.entry.is_some()).map(|f| f.blob_id));
                return None;
            }
            _ => return None,
        };
        let carried: Vec<osis_base::BlobId> = events.iter().filter_map(|(_, e)| if let osis_proto::Event::Added { blob_id, blob: Some(_), .. } = e { Some(*blob_id) } else { None }).collect();
        s.bodies.extend(carried);
        None
    }));
    seen
}

/// Pulls and pages of a first contact sharing `n` sync IDs.
fn first_contact(n: usize) -> (usize, usize, usize) {
    let mut net = Net::new();
    let seen = watch(&mut net);
    let (a, _, gs) = pair(&mut net, n);
    assert_eq!(net.sync(a).labels().len(), n + 1, "every group's label and a's home");
    let _ = gs;
    let pages = seen.borrow().replies.len();
    (net.peer_sent(a, PULL), pages, net.peer_sent(a, SYNC) + net.peer_sent(a, SUBSCRIBE))
}

// spec/sync.md §10 (Stream): a first contact sharing n sync IDs joins them in O(1) Pulls: the joins
// of one batch of opens go in one Pull, its reply pages by size, not per sync ID
#[test]
fn first_contact_joins_in_constant_pulls_spec_sync_10() {
    let (p1, r1, s1) = first_contact(3);
    let (p10, r10, s10) = first_contact(30);
    assert_eq!((s1, s10), (0, 0), "no per-label Sync between readers");
    assert!(p10 <= p1 + 1 && r10 <= r1 + 1, "Pulls {p1} at n, {p10} at 10n; replies {r1}, {r10}");
}

// spec/sync.md §10 (Stream): the stream's position is the record's, so a restarted node goes on
// from it: nothing it already applied comes again
#[test]
fn a_restarted_node_resumes_its_stream_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 2);
    for (i, g) in gs.iter().enumerate() {
        net.item(b, *g, *g, &format!("x{i}"));
    }
    net.run();
    let seen = watch(&mut net);
    net.restart(a, 21);
    net.run();
    net.advance(60_000);
    let t = net.item(b, gs[0], gs[0], "after");
    net.run();
    assert_eq!(net.read(a, t), Some(s("after")), "the stream goes on after the restart");
    let seen = seen.borrow();
    assert!(!seen.replies.is_empty(), "a pulled again");
    assert!(seen.replies.iter().all(|(whole, _)| !whole), "the record's cursor holds: no stream from the start");
    let listed: usize = seen.replies.iter().map(|(_, n)| n).sum();
    assert!(listed <= 4, "only what changed since the cursor comes again: {listed} events");
}

// spec/sync.md §10 (Stream): a lost record is a first contact, a stream from the start, and what
// was written while apart arrives
#[test]
fn a_lost_record_is_a_first_contact_and_converges_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    net.set_online(a, false);
    net.run();
    let t = net.item(b, gs[0], gs[0], "apart");
    net.run();
    let in_use = std::collections::BTreeSet::new();
    net.engine(a).run(|tx| Ok(tx.txn.records_evict(0, &in_use)?)).unwrap();
    let seen = watch(&mut net);
    net.set_online(a, true);
    net.advance(120_000);
    assert_eq!(net.read(a, t), Some(s("apart")), "what was written apart arrives");
    assert!(seen.borrow().replies.first().is_some_and(|(whole, _)| *whole), "a stream from the start: {:?}", seen.borrow().replies);
}

// spec/sync.md §10 (Stream; spec/requirements.md, Nothing a node already holds is sent again): in a
// mesh a body crosses once to each node; a requester with more than one source of a sync ID is
// sent announcements and fetches the body from one source
#[test]
fn a_mesh_body_crosses_once_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach_ed(&mut net, b);
    reach_ed(&mut net, c);
    let g = net.group_seeded(b, &[(a, Role::Write), (c, Role::Write)], vec![], 10);
    net.pair(c, a);
    net.pair(b, c);
    net.run();
    net.advance(120_000);
    let seen = watch(&mut net);
    let t = net.item(b, g, g, "body");
    net.run();
    net.advance(60_000);
    assert_eq!((net.read(a, t), net.read(c, t)), (Some(s("body")), Some(s("body"))));
    let l = net.label(b);
    let entries = net.sync(b).entries(&l);
    let blob = entries.into_iter().find_map(|(id, k)| match k {
        osis_node::sync::EntryKind::Commit { commit, .. } if net.engine(b).header(&commit).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t)) => Some(id),
        _ => None,
    });
    let blob = blob.expect("the item's entry");
    let crossings = seen.borrow().bodies.iter().filter(|x| **x == blob).count();
    assert_eq!(crossings, 2, "once to a, once to c");
}

/// Pulls node `a` sends once back after `b`'s log aged out the deletions of what `a` held, at
/// `n` sync IDs, and whether `a` then holds what `b` holds.
fn back_after_aging(n: usize) -> (usize, bool, bool) {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, n);
    let day = 86_400_000;
    for (i, g) in gs.iter().enumerate() {
        let t = net.item(b, *g, *g, &format!("keep{i}"));
        let gone = net.item(b, *g, *g, "gone");
        let mut m = osis_node::Mutation::new();
        m.set(gone, &REG, &s("short")).unwrap();
        m.expires(gone, &osis_base::Ak::new(REG.ak()).unwrap(), osis_base::WallMs(net.now() + day)).unwrap();
        net.engine(b).commit(m).unwrap();
        let _ = t;
    }
    net.run();
    net.set_online(a, false);
    net.run();
    // the entries expire at b, and b's log drops their deletions with its tombstone life
    for _ in 0..4 {
        net.advance(8 * day);
    }
    let before = net.peer_sent(a, PULL);
    let seen = watch(&mut net);
    net.set_online(a, true);
    net.advance(120_000);
    let pulls = net.peer_sent(a, PULL) - before;
    let mut same = true;
    for l in net.group_labels(b).into_iter().map(|(_, l)| l.id).collect::<Vec<_>>() {
        let at = |net: &mut Net, x: usize| net.sync(x).entries(&l).into_iter().map(|(id, _)| id).collect::<std::collections::BTreeSet<_>>();
        same &= at(&mut net, a) == at(&mut net, b);
    }
    let whole = seen.borrow().replies.iter().any(|(w, _)| *w);
    (pulls, same, whole)
}

// issues/net-reconnect.md (Back after a long absence; Deletions): a node back after the peer's
// log dropped deletions past its cursor converges by one stream, whatever the number of sync IDs
// (counted at n and 10n); a deletion older than the log reaches it by its own judgment (expiry)
#[test]
fn back_after_aged_deletions_converges_in_one_stream_spec_sync_10() {
    let (p1, same1, whole1) = back_after_aging(1);
    let (p10, same10, whole10) = back_after_aging(10);
    assert!(same1 && same10, "a holds what b holds");
    assert!(!whole1 && !whole10, "the old cursor is honoured: no stream from the start");
    assert!(p10 <= p1 + 1, "Pulls back: {p1} at n, {p10} at 10n");
}

/// One differential run: `b` writes, opens new groups with `a`, restarts; `a` goes off and on,
/// restarts, loses its records. Once settled, `a`'s stream from `b` is caught up and `a` holds
/// every entry `b` serves under a label they share.
fn stream_run(seed: u64) {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let mut net = Net::new();
    let (a, b, mut gs) = pair(&mut net, 2);
    let mut life = 100;
    for step in 0..24 {
        match rnd(10) {
            0..=3 => {
                let g = gs[rnd(gs.len() as u64) as usize];
                net.item(b, g, g, &format!("v{step}"));
            }
            4 => {
                // a group opened after the stream started: it joins from the start
                let g = net.group_seeded(b, &[(a, Role::Write)], vec![], 50 + step);
                net.item(b, g, g, &format!("early{step}"));
                // a write the stream carries past the new group's first events
                net.item(b, gs[0], gs[0], &format!("past{step}"));
                gs.push(g);
            }
            5 => {
                let on = !net.nodes[a].online;
                net.set_online(a, on);
            }
            6 => {
                life += 1;
                net.restart(a, life);
            }
            7 => {
                life += 1;
                net.restart(b, life);
            }
            8 => {
                let in_use = std::collections::BTreeSet::new();
                net.engine(a).run(|tx| Ok(tx.txn.records_evict(0, &in_use)?)).unwrap();
            }
            _ => {}
        }
        net.advance(1_000 + rnd(90_000));
    }
    net.set_online(a, true);
    net.advance(120_000);
    net.advance(120_000);
    let conns = net.peer_conns(a);
    assert!(conns.iter().any(|(c, m, _)| *m == b && net.sync(a).stream_caught_up(*c)), "seed {seed}: a caught up with b");
    for (_, gl) in net.group_labels(b) {
        let l = gl.id;
        if !net.sync(a).labels().iter().any(|(_, x)| x.id == l) {
            continue;
        }
        let at_a: std::collections::BTreeSet<_> = net.sync(a).entries(&l).into_iter().map(|(id, _)| id).collect();
        let at_b: Vec<_> = net.sync(b).entries(&l).into_iter().map(|(id, _)| id).collect();
        let lacking: Vec<_> = at_b.iter().filter(|id| !at_a.contains(id) && net.engine(b).has_blob(id)).collect();
        assert!(lacking.is_empty(), "seed {seed}: a lacks {} of b's entries under {l:?}", lacking.len());
    }
}

// The stream's invariant (core/node/src/sync/stream.rs): no write is dropped, and a source a node
// judges caught up holds nothing it lacks, across restarts, record loss, outages and joins
#[test]
fn stream_differential_no_write_dropped_spec_sync_10() {
    for seed in 1..=6 {
        stream_run(seed);
    }
}

