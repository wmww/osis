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
const FETCH: u64 = 19;

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

// spec/sync.md §10 (Stream: both sides pull): a reader's own write reaches a co-reader by the
// co-reader pulling it, whoever dialed, with no Upload, Deposit or Open between them
#[test]
fn a_readers_write_reaches_a_co_reader_with_no_upload_spec_sync_10() {
    const OPEN: u64 = 4;
    const UPLOAD: u64 = 10;
    const DEPOSIT: u64 = 12;
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    let t = net.item(b, gs[0], gs[0], "x");
    net.run();
    net.write(a, t, "from the dialer");
    net.run();
    assert_eq!(net.read(b, t), Some(s("from the dialer")), "the listener pulled the dialer's write");
    assert!(net.peer_sent(b, PULL) > 0, "b pulls a");
    for n in [a, b] {
        assert_eq!(net.peer_sent(n, UPLOAD) + net.peer_sent(n, DEPOSIT) + net.peer_sent(n, OPEN), 0, "node {n}: no upload, deposit or open between readers");
    }
}

// spec/sync.md §10 (Stream, Applying), §7: a deletion in a reader's stream says only that the
// source no longer holds the entry: a co-reader with no other source keeps it
#[test]
fn a_readers_deletion_leaves_the_entry_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    let t = net.item(b, gs[0], gs[0], "kept");
    net.run();
    let l = label_of(&mut net, b, gs[0]);
    let held = |net: &mut Net| net.sync(a).entries(&l).into_iter().find_map(|(id, k)| match k {
        osis_node::sync::EntryKind::Commit { commit, .. } if net.engine(a).header(&commit).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t)) => Some(id),
        _ => None,
    });
    let entry = held(&mut net).expect("a holds the item's entry");
    let sent = std::rc::Rc::new(std::cell::Cell::new(false));
    let carried = sent.clone();
    net.tamper = Some(Box::new(move |m| match m {
        // b's push of its next write under l (a writes nothing there)
        osis_proto::Message::Stream(x) if !carried.get() && x.events.iter().any(|(y, e)| *y == l && matches!(e, osis_proto::Event::Added { .. })) => {
            carried.set(true);
            let mut x = (**x).clone();
            x.events.push((l, osis_proto::Event::Deleted(entry)));
            Some(osis_proto::Message::Stream(Box::new(x)))
        }
        _ => None,
    }));
    net.item(b, gs[0], gs[0], "a push to carry the deletion");
    net.run();
    assert!(sent.get(), "a push carried the deletion");
    assert_eq!(held(&mut net), Some(entry), "the entry stays");
    assert_eq!(net.read(a, t), Some(s("kept")));
}

// spec/sync.md §10 (Stream): a Pull answered Error is answered: the stream asks again after
// `resync_ms` instead of waiting for a reply that never comes. Both sides pull, one Pull in flight
// each, so the first two replies refused are one per side.
#[test]
fn a_refused_pull_is_asked_again_spec_sync_10() {
    let mut net = Net::new();
    let refused = std::rc::Rc::new(std::cell::Cell::new(0));
    let r = refused.clone();
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::PullReply(p) if r.get() < 2 => {
            r.set(r.get() + 1);
            Some(osis_proto::Message::Error { id: p.id, code: osis_proto::Code::RATE_LIMITED })
        }
        _ => None,
    }));
    let (a, b, gs) = pair(&mut net, 1);
    let t = net.item(b, gs[0], gs[0], "x");
    net.run();
    assert_eq!(refused.get(), 2, "a reply to each side was refused");
    let pulls = (net.peer_sent(a, PULL), net.peer_sent(b, PULL));
    let resync = net.sync(a).config().resync_ms;
    net.advance(resync + 1);
    net.run();
    assert!(net.peer_sent(a, PULL) > pulls.0 && net.peer_sent(b, PULL) > pulls.1, "each asked again");
    assert_eq!(net.read(a, t), Some(s("x")), "b's write reached a");
}

// spec/sync.md §10 (Shared set): a filter generation answered Error goes again, whole, after
// `resync_ms`, as a refused Pull does: with both sides' first filters refused nothing is shared
// until then
#[test]
fn a_refused_filter_goes_again_spec_sync_10() {
    let mut net = Net::new();
    let refused = std::rc::Rc::new(std::cell::Cell::new(0));
    let r = refused.clone();
    let ids = std::rc::Rc::new(std::cell::RefCell::new(std::collections::BTreeSet::new()));
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::Beacons { id, more: false, .. } => {
            ids.borrow_mut().insert(*id);
            None
        }
        osis_proto::Message::Shared { id, .. } if r.get() < 2 && ids.borrow().contains(id) => {
            r.set(r.get() + 1);
            Some(osis_proto::Message::Error { id: *id, code: osis_proto::Code::RATE_LIMITED })
        }
        _ => None,
    }));
    let (a, b, gs) = pair(&mut net, 1);
    let t = net.item(b, gs[0], gs[0], "x");
    net.run();
    assert_eq!(refused.get(), 2, "each side's filter was refused");
    let filters = (net.sync(a).pass_stats().filters_sent, net.sync(b).pass_stats().filters_sent);
    let resync = net.sync(a).config().resync_ms;
    net.advance(resync + 1);
    net.run();
    assert!(net.sync(a).pass_stats().filters_sent > filters.0 && net.sync(b).pass_stats().filters_sent > filters.1, "each sent its filter again");
    assert_eq!(net.read(a, t), Some(s("x")), "b's write reached a");
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

/// One differential run: `a` and `b` write, `b` opens new groups with `a`, restarts; `a` goes off
/// and on, restarts (also mid-stream, a fetch in flight), loses its records. Once settled, each side's stream from the other is
/// caught up and holds every entry the other serves under a label they share (both pull).
/// `paged`: every Pull asks the smallest reply with announcements only, so replies page.
fn stream_run(seed: u64, paged: bool) {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut rnd = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let mut net = Net::new();
    let bulk = if paged {
        net.tamper = Some(Box::new(smallest_pulls));
        90
    } else {
        0
    };
    let (a, b, mut gs) = pair(&mut net, 2);
    let mut life = 100;
    for step in 0..24 {
        match rnd(10) {
            0..=3 => {
                let g = gs[rnd(gs.len() as u64) as usize];
                // either side writes: each pulls the other
                let by = if rnd(2) == 0 { a } else { b };
                net.item(by, g, g, &format!("v{step}"));
            }
            4 => {
                // a group shared with `a` once its entries are written and the stream has moved
                // past them: it joins from the start, behind the stream's position
                let g = net.group_seeded(b, &[], vec![], 50 + step);
                let t = net.item(b, g, g, &format!("early{step}"));
                // more events than one page holds before the join
                for i in 0..bulk {
                    net.write(b, t, &format!("early{step}.{i}"));
                }
                net.run();
                net.item(b, gs[0], gs[0], &format!("past{step}"));
                net.run();
                let (tb, ta) = (net.tid(b), net.tid(a));
                let e = net.engine(b);
                set_edge(e, g, ta, Role::Write);
                let rec = recipients_of(e, &[(tb, Role::Admin), (ta, Role::Write)]);
                rotation(e, g, &rec, 500 + step, true);
                net.pair(b, a);
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
            _ => {
                // `a` crashes mid-stream: once it asked `b` for a body (bodies announced without
                // bytes), else once what `b`'s write caused is delivered
                let g = gs[rnd(gs.len() as u64) as usize];
                net.item(b, g, g, &format!("w{step}"));
                net.feed(b, osis_node::sync::Event::Local);
                let fetches = net.peer_sent(a, FETCH);
                while net.peer_sent(a, FETCH) == fetches && net.step() {}
                life += 1;
                net.restart(a, life);
            }
        }
        net.advance(1_000 + rnd(90_000));
    }
    net.set_online(a, true);
    net.advance(120_000);
    net.advance(120_000);
    for (x, y) in [(a, b), (b, a)] {
        let conns = net.peer_conns(x);
        assert!(conns.iter().any(|(c, m, _)| *m == y && net.sync(x).stream_caught_up(*c)), "seed {seed}: {x} caught up with {y}");
        for (_, gl) in net.group_labels(y) {
            let l = gl.id;
            if !net.sync(x).labels().iter().any(|(_, z)| z.id == l) {
                continue;
            }
            // a write is what must arrive: an entry of a commit `x` holds in another encryption
            // (one `y` kept after `x` dropped it: a reader's Deleted is not acted on) is no gap
            let at_x: std::collections::BTreeSet<_> = net.sync(x).entries(&l).into_iter().map(|(id, _)| id).collect();
            let at_y = net.sync(y).entries(&l);
            let lacking: Vec<_> = at_y
                .iter()
                .filter(|(id, k)| match k {
                    osis_node::sync::EntryKind::Commit { commit, .. } => net.engine(x).header(commit).is_none(),
                    _ => !at_x.contains(id) && net.engine(y).has_blob(id),
                })
                .collect();
            assert!(lacking.is_empty(), "seed {seed}: {x} lacks {} of {y}'s writes under {l:?}", lacking.len());
        }
    }
}

// The stream's invariant (core/node/src/sync/stream.rs): no write is dropped, and a source a node
// judges caught up holds nothing it lacks, across restarts, record loss, outages and joins
#[test]
fn stream_differential_no_write_dropped_spec_sync_10() {
    for seed in 1..=6 {
        stream_run(seed, false);
    }
}

// The same invariant with every reply paged (the smallest `max_reply`, announcements only)
#[test]
fn stream_differential_paged_spec_sync_10() {
    for seed in 1..=3 {
        stream_run(seed, true);
    }
}

/// A tamper making every Pull ask announcements only: bodies come by fetches.
fn announcements_only(m: &osis_proto::Message) -> Option<osis_proto::Message> {
    let osis_proto::Message::Pull(p) = m else { return None };
    let mut p = (**p).clone();
    p.inline_limit = 0;
    Some(osis_proto::Message::Pull(Box::new(p)))
}

/// Nodes `a` and `b` (`pair`, bodies by fetches); `b` writes an item and the messages go one at
/// a time until `a` asks `b` for a body, its answer not delivered yet.
fn fetch_in_flight(net: &mut Net) -> (usize, usize, Tid, Tid) {
    net.tamper = Some(Box::new(announcements_only));
    let (a, b, gs) = pair(net, 1);
    let t = net.item(b, gs[0], gs[0], "x");
    let fetches = net.peer_sent(a, FETCH);
    net.feed(b, osis_node::sync::Event::Local);
    while net.peer_sent(a, FETCH) == fetches {
        assert!(net.step(), "a asks for the body");
    }
    (a, b, gs[0], t)
}

// The stream's settling rule (core/node/src/sync/stream.rs): a body is owed until held or its
// source answered for it. A co-reader announcing an entry without bytes and serving bytes this
// node does not keep (a relay-only blob outside its window) holds nothing more of it: the
// stream settles and stops asking, rather than fetching it again every step
#[test]
fn a_body_served_and_not_kept_is_owed_no_more_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    let l = label_of(&mut net, b, gs[0]);
    let mut salt = [0u8; 16];
    salt[0] = 0x5a;
    let mut junk = osis_label::Prefix::new(salt, Some(osis_base::WallMs(1)), vec![]).unwrap().with_class(osis_label::Class::Relay).to_bytes();
    junk.extend_from_slice(&[7; 40]);
    let id = osis_label::blob_id(&junk);
    let announced = std::rc::Rc::new(std::cell::Cell::new(false));
    let an = announced.clone();
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::Stream(x) if !an.get() && x.events.iter().any(|(y, _)| *y == l) => {
            an.set(true);
            let mut x = (**x).clone();
            x.events.push((l, osis_proto::Event::Added { blob_id: id, blob: None, wrap: [0; osis_crypto::WRAP_LEN], stamp: None }));
            Some(osis_proto::Message::Stream(Box::new(x)))
        }
        osis_proto::Message::FetchReply { id: fid, items } if items.iter().any(|f| f.blob_id == id) => {
            let items = items.iter().map(|f| if f.blob_id == id { osis_proto::msg::Fetched { blob_id: id, entry: Some((junk.clone(), [0; osis_crypto::WRAP_LEN], None)) } } else { f.clone() }).collect();
            Some(osis_proto::Message::FetchReply { id: *fid, items })
        }
        _ => None,
    }));
    net.item(b, gs[0], gs[0], "a push to carry the announcement");
    net.run();
    assert!(announced.get(), "a push carried the announcement");
    let fetches = net.peer_sent(a, FETCH);
    for _ in 0..3 {
        net.advance(1_000);
        net.run();
    }
    assert_eq!(net.peer_sent(a, FETCH), fetches, "not fetched again");
    let conns = net.peer_conns(a);
    assert!(conns.iter().any(|(c, m, _)| *m == b && net.sync(a).stream_caught_up(*c)), "a's stream of b settled");
}

// The stream's invariant (core/node/src/sync/stream.rs): a position covers a body announced
// without bytes only once it is held. A node that crashes while fetching it comes back to a
// stream that announces it again, so the write arrives
#[test]
fn a_body_whose_fetch_was_lost_comes_again_spec_sync_10() {
    let mut net = Net::new();
    let (a, _, _, t) = fetch_in_flight(&mut net);
    net.restart(a, 21);
    net.run();
    net.advance(120_000);
    assert_eq!(net.read(a, t), Some(s("x")), "the write reached a after its fetch was lost");
}

// spec/sync.md §10 (Stream, reports): a reader reports applying a body only once it holds it, so
// the writer never reads `Synced` while the reader lacks its write
#[test]
fn a_body_is_reported_only_once_held_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, g, t) = fetch_in_flight(&mut net);
    let l = label_of(&mut net, b, g);
    let synced = |net: &mut Net| net.sync(b).label_status().into_iter().any(|x| x.label == l && x.sources > 0 && x.idle == x.sources);
    loop {
        if synced(&mut net) {
            assert_eq!(net.read(a, t), Some(s("x")), "b reads Synced only once a holds its write");
        }
        if !net.step() {
            break;
        }
    }
    net.run();
    assert!(synced(&mut net), "b reads Synced once a holds the write");
}

// spec/wire.md §11.2 (Beacons; Error answers a request): an Error answering a filter ends that
// generation as a refusal does, so the connection settles what it shares: no label of either side
// reads opening for good (one the peer does not share would never read `Synced`)
#[test]
fn a_filter_answered_error_settles_spec_wire_11_2() {
    let mut net = Net::new();
    let beacons = std::rc::Rc::new(std::cell::RefCell::new(std::collections::BTreeSet::new()));
    let refused = std::rc::Rc::new(std::cell::Cell::new(false));
    let (seen, r) = (beacons.clone(), refused.clone());
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::Beacons { id, .. } => {
            seen.borrow_mut().insert(*id);
            None
        }
        osis_proto::Message::Shared { id, .. } if !r.get() && seen.borrow().contains(id) => {
            r.set(true);
            Some(osis_proto::Message::Error { id: *id, code: osis_proto::Code::RATE_LIMITED })
        }
        _ => None,
    }));
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, b);
    let g = net.group_seeded(b, &[(a, Role::Write)], vec![], 10);
    // a group each holds alone
    net.group_seeded(a, &[], vec![], 11);
    net.group_seeded(b, &[], vec![], 12);
    net.run();
    net.item(b, g, g, "x");
    net.run();
    assert!(refused.get(), "a filter was answered Error");
    let l = label_of(&mut net, b, g);
    for n in [a, b] {
        for st in net.sync(n).label_status() {
            assert_eq!(st.opening, 0, "node {n}: {st:?}");
            if st.label == l {
                assert!(st.sources > 0 && st.idle == st.sources, "node {n} synced: {st:?}");
            }
        }
    }
}

/// A tamper making every Pull ask the smallest reply, announcements only.
fn smallest_pulls(m: &osis_proto::Message) -> Option<osis_proto::Message> {
    let osis_proto::Message::Pull(p) = m else { return None };
    let mut p = (**p).clone();
    p.max_reply = osis_proto::client::SMALL_REPLY as u64;
    p.inline_limit = 0;
    Some(osis_proto::Message::Pull(Box::new(p)))
}

// spec/sync.md §10 (Stream; spec/wire.md §11.2 PullReply): a join from the start with more events
// than a reply holds pages at its own position behind the stream's and merges into it, nothing
// dropped
#[test]
fn a_join_pages_behind_the_stream_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    let paged = std::rc::Rc::new(std::cell::Cell::new(0));
    let p = paged.clone();
    net.tamper = Some(Box::new(move |m| {
        if let osis_proto::Message::PullReply(r) = m {
            p.set(p.get() + r.joins.iter().filter(|(_, c)| c.is_some()).count());
        }
        smallest_pulls(m)
    }));
    // a group shared with `a` once its entries are written and the stream moved past them
    let g = net.group_seeded(b, &[], vec![], 50);
    let t = net.item(b, g, g, "early");
    for i in 0..300 {
        net.write(b, t, &format!("early{i}"));
    }
    net.run();
    let past = net.item(b, gs[0], gs[0], "past");
    net.run();
    assert_eq!(net.read(a, past), Some(s("past")), "the stream moved past the group's entries");
    let (tb, ta) = (net.tid(b), net.tid(a));
    let e = net.engine(b);
    set_edge(e, g, ta, Role::Write);
    let rec = recipients_of(e, &[(tb, Role::Admin), (ta, Role::Write)]);
    rotation(e, g, &rec, 500, true);
    net.pair(b, a);
    net.run();
    assert!(paged.get() > 0, "the join paged at its own position");
    let l = label_of(&mut net, b, g);
    let at_a: std::collections::BTreeSet<_> = net.sync(a).entries(&l).into_iter().map(|(id, _)| id).collect();
    let lacking = net.sync(b).entries(&l).into_iter().filter(|(id, _)| !at_a.contains(id)).count();
    assert_eq!(lacking, 0, "a holds every entry b serves under the joined group");
}


/// The label of group `g` at node `n`.
fn label_of(net: &mut Net, n: usize, g: Tid) -> osis_base::LabelId {
    net.group_labels(n).into_iter().find(|(x, _)| *x == g).unwrap().1.id
}

/// Makes `b`'s next stream push carrying an add under `l` also carry a head of another sync ID
/// for `l` (`step`): `a` holds no step it descends from, so `l` opens again there.
fn reopen_on_next_push(net: &mut Net, l: osis_base::LabelId, step: osis_label::Step) {
    let mut step = Some(step);
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::Stream(x) if x.events.iter().any(|(y, e)| *y == l && matches!(e, osis_proto::Event::Added { .. })) => {
            let mut x = (**x).clone();
            x.events.push((l, osis_proto::Event::Head(step.take()?)));
            Some(osis_proto::Message::Stream(Box::new(x)))
        }
        _ => None,
    }));
}

/// A step of group `g`'s label at node `n`.
fn a_step(net: &mut Net, n: usize, g: Tid) -> osis_label::Step {
    net.group_labels(n).into_iter().find(|(x, _)| *x == g).unwrap().1.steps.values().next().unwrap().0.clone()
}

// The stream's invariant (core/node/src/sync/stream.rs): a member's position moves only over what
// was applied. One that opens again on the connection (a head it cannot follow) misses nothing
// that arrives while it is not open: it leaves the stream and rejoins from where it stopped
#[test]
fn a_member_opening_again_misses_nothing_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 2);
    let l = label_of(&mut net, b, gs[0]);
    let step = a_step(&mut net, b, gs[1]);
    reopen_on_next_push(&mut net, l, step);
    net.item(b, gs[0], gs[0], "one");
    net.feed(b, osis_node::sync::Event::Local);
    let two = net.item(b, gs[0], gs[0], "two");
    net.feed(b, osis_node::sync::Event::Local);
    net.run();
    net.advance(120_000);
    assert_eq!(net.read(a, two), Some(s("two")), "what came while it opened again arrives");
}

// spec/sync.md §10 (Stream; spec/sync.md §9): the stream's memory part has no position a cursor
// names, so a member entering the stream on a connection, from a position or the start, gets its
// live memory entries listed
#[test]
fn a_member_rejoining_gets_its_live_memory_entries_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 2);
    let t = net.item(b, gs[0], gs[0], "v");
    net.run();
    let l = label_of(&mut net, b, gs[0]);
    let step = a_step(&mut net, b, gs[1]);
    reopen_on_next_push(&mut net, l, step);
    net.item(b, gs[0], gs[0], "one");
    net.feed(b, osis_node::sync::Event::Local);
    net.eph_write(b, t, &crate::common::ak("t:typing+.0"), s("typing"));
    net.run();
    net.advance(60_000);
    assert_eq!(net.eph_read(a, t, "t:typing+.0"), Some(s("typing")), "the live memory entry is listed at the rejoin");
}

// spec/sync.md §10 (Stream: filtered by the connection's shared set): a follow push goes out only
// after the step's re-judging, so a peer whose right a step ends is pushed nothing of that step
#[test]
fn nothing_is_pushed_past_a_lost_right_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    net.item(b, gs[0], gs[0], "before");
    net.run();
    let l = label_of(&mut net, b, gs[0]);
    let seen = std::rc::Rc::new(std::cell::RefCell::new((0usize, 0usize)));
    let s2 = seen.clone();
    net.tamper = Some(Box::new(move |m| {
        let mut s = s2.borrow_mut();
        match m {
            osis_proto::Message::Stream(x) => s.0 += x.events.iter().filter(|(y, _)| *y == l).count(),
            osis_proto::Message::Lost { items, .. } => s.1 += items.iter().filter(|(y, _)| *y == l).count(),
            _ => {}
        }
        None
    }));
    let (ta, tb) = (net.tid(a), net.tid(b));
    let rec = recipients_of(net.engine(b), &[(tb, Role::Admin)]);
    remove_holder(net.engine(b), gs[0], ta, &rec, 77);
    net.feed(b, osis_node::sync::Event::Local);
    net.run();
    let (pushed, lost) = *seen.borrow();
    assert!(lost > 0, "a's member closed");
    assert_eq!(pushed, 0, "nothing of the removing step was pushed to a");
}

// spec/wire.md §11.2 (Pull): a join whose cursor names no position of the server's log makes the
// reply a stream from the start, so the requester knows the join was read as a listing
#[test]
fn a_join_cursor_naming_no_position_is_a_stream_from_the_start_spec_sync_10() {
    let mut net = Net::new();
    let (a, _, gs) = pair(&mut net, 2);
    for g in &gs {
        net.item(a, *g, *g, "x");
    }
    net.run();
    let seen = std::rc::Rc::new(std::cell::RefCell::new((false, Vec::new())));
    let s2 = seen.clone();
    net.tamper = Some(Box::new(move |m| {
        let mut s = s2.borrow_mut();
        match m {
            osis_proto::Message::Pull(p) if !s.0 && p.joins.iter().any(|(_, c)| c.is_some()) => {
                s.0 = true;
                let mut p = (**p).clone();
                if let Some(c) = p.joins.iter_mut().find_map(|(_, c)| c.as_mut()) {
                    c[0] ^= 1;
                }
                Some(osis_proto::Message::Pull(Box::new(p)))
            }
            osis_proto::Message::PullReply(r) if s.0 => {
                s.1.push(r.whole);
                None
            }
            _ => None,
        }
    }));
    net.restart(a, 21);
    net.run();
    let s = seen.borrow();
    assert!(s.0, "a joined from a lag");
    assert_eq!(s.1.first(), Some(&true), "{:?}", s.1);
}

// spec/wire.md §11.2 (Pull: `max_reply` as for a Sync): the memory part pages within the reply's
// budget as the durable part does, so a listing of many memory entries never passes `max_reply`
// and each arrives
#[test]
fn memory_entries_page_within_max_reply_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    let ts: Vec<Tid> = (0..120).map(|i| net.item(b, gs[0], gs[0], &format!("t{i}"))).collect();
    net.run();
    net.set_online(a, false);
    net.run();
    for t in &ts {
        net.eph_write(b, *t, &crate::common::ak("t:typing+.0"), s("typing"));
    }
    let largest = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let l2 = largest.clone();
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::Pull(p) => {
            let mut p = (**p).clone();
            p.max_reply = osis_proto::client::SMALL_REPLY as u64;
            Some(osis_proto::Message::Pull(Box::new(p)))
        }
        osis_proto::Message::PullReply(_) | osis_proto::Message::Stream(_) => {
            l2.set(l2.get().max(m.encode().len()));
            None
        }
        _ => None,
    }));
    net.set_online(a, true);
    net.advance(60_000);
    let got = ts.iter().filter(|t| net.eph_read(a, **t, "t:typing+.0") == Some(s("typing"))).count();
    assert_eq!(got, ts.len(), "every memory entry arrived");
    assert!(largest.get() <= osis_proto::client::SMALL_REPLY, "a reply of {} bytes", largest.get());
}
