#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A hostile writer against other writers' wraps (spec/sync.md §5). Invariant: nothing a writer
//! uploads keeps a body from a reader for good. A stamped entry's wrap never changes at a host;
//! a useless first wrap (a race for a host the author has not reached yet, a hostile promotion)
//! loses to another host's wrap at a reader and to a fresh encryption from a node knowing the key.

use crate::net;
use net::*;
use osis_base::{BlobId, LabelId, Role, Tid};
use osis_crypto::{Secret32, WRAP_LEN};
use osis_node::sync::{Action, EntryKind};
use osis_proto::{Entry, LabelStore, Message, encode_frame};

const WRITER: u8 = 0;
const READER: u8 = 1;

fn send(net: &mut Net, h: usize, host: usize, m: Message) {
    let conn = net.conn_to(h, host).unwrap();
    net.actions(h, vec![Action::Send { conn, bytes: encode_frame(&m.encode()) }]);
    net.settle(10_000);
}

/// `h` uploads `id` through the real host engine with `wrap` and a valid stamp, or deposits it.
fn hostile_put(net: &mut Net, h: usize, host: usize, (g, l): (Tid, &LabelId), id: BlobId, wrap: [u8; WRAP_LEN], as_who: u8) {
    let (_, gl) = net.sync(h).labels().into_iter().find(|(_, x)| x.id == *l).unwrap();
    let head = net.host_path(host, l).last().unwrap().clone();
    let keys = net.engine(h).head_keys(&g, gl.index, &head).unwrap();
    let blob = net.engine(h).blob(&id).unwrap().unwrap();
    let m = if as_who == WRITER {
        let stamp = osis_label::sign_stamp(keys.write.as_ref().unwrap(), l, &id, &wrap);
        Message::Upload { id: 0x4000_0000, label: *l, entries: vec![Entry { blob, wrap, stamp, replaces: Vec::new() }] }
    } else {
        let sig = osis_label::sign_deposit(keys.deposit.as_ref().unwrap(), l, &id, &wrap);
        Message::Deposit { id: 0x4000_0001, label: *l, blob, wrap, sig }
    };
    send(net, h, host, m);
}

/// The entries under `l` carrying `t`, at node `n`.
fn entries_of(net: &mut Net, n: usize, l: &LabelId, t: Tid) -> Vec<BlobId> {
    let v: Vec<_> = net.sync(n).entries(l);
    v.into_iter()
        .filter_map(|(id, k)| match k {
            EntryKind::Commit { commit, .. } => net.engine(n).header(&commit).filter(|h| h.aspects.iter().any(|a| a.tid == t)).map(|_| id),
            _ => None,
        })
        .collect()
}

/// `wrong`: a wrap that opens, to another key; else garbage.
fn bad_wrap(net: &mut Net, h: usize, g: Tid, id: &BlobId, wrong: bool) -> [u8; WRAP_LEN] {
    if wrong {
        let read = net.engine(h).wrap_secret(&g, None).unwrap().unwrap();
        osis_crypto::wrap(&read, id, &Secret32::from_bytes([0x42; 32])).unwrap()
    } else {
        [0x13; WRAP_LEN]
    }
}

fn stored_wrap(net: &Net, host: usize, l: &LabelId, id: &BlobId) -> Option<[u8; WRAP_LEN]> {
    net.hosts[host].hub.store().entry(l, id).unwrap().map(|m| m.wrap)
}

struct Fx {
    net: Net,
    hosts: Vec<usize>,
    a: usize,
    h: usize,
    f: usize,
    g: Tid,
    l: LabelId,
}

/// Author `a` and hostile writer `h` syncing the label at `n` hosts; reader `f` not connected.
fn fixture(n: usize, seed: u64) -> Fx {
    let mut net = Net::new();
    let hosts: Vec<usize> = (0..n).map(|_| net.add_host()).collect();
    let a = net.node(seed * 10 + 1, &hosts);
    let h = net.node(seed * 10 + 2, &hosts);
    let f = net.node(seed * 10 + 3, &hosts);
    for s in &hosts {
        net.blocked.insert((f, *s));
    }
    let g = net.group(a, &[(h, Role::Write), (f, Role::Read)], &hosts);
    net.run();
    let l = net.label(a);
    Fx { net, hosts, a, h, f, g, l }
}

/// Reader `f` connects to `hosts`.
fn connect(fx: &mut Fx, hosts: &[usize], seed: u64) {
    for s in hosts {
        fx.net.blocked.remove(&(fx.f, *s));
    }
    fx.net.restart(fx.f, seed);
    fx.net.run();
}

// spec/sync.md §5: a writer re-uploading a held stamped entry under a garbage wrap, or one opening
// to another key, changes nothing at the host and logs nothing; a fresh reader reads it.
#[test]
fn stamped_wrap_never_replaced_spec_sync_5() {
    for wrong in [false, true] {
        let mut fx = fixture(1, 1);
        let (host, g, l, h, a) = (fx.hosts[0], fx.g, fx.l, fx.h, fx.a);
        let t = fx.net.item(a, g, g, "message");
        fx.net.run();
        assert_eq!(fx.net.read(h, t), Some(s("message")));
        for id in entries_of(&mut fx.net, h, &l, t) {
            let before = stored_wrap(&fx.net, host, &l, &id);
            let head = fx.net.hosts[host].hub.store().log_head(&l).unwrap();
            let w = bad_wrap(&mut fx.net, h, g, &id, wrong);
            hostile_put(&mut fx.net, h, host, (g, &l), id, w, WRITER);
            assert_eq!(stored_wrap(&fx.net, host, &l, &id), before);
            assert_eq!(fx.net.hosts[host].hub.store().log_head(&l).unwrap(), head, "nothing logged");
        }
        fx.net.run();
        connect(&mut fx, &[host], 33);
        assert_eq!(fx.net.read(fx.f, t), Some(s("message")));
    }
}

/// `a` writes with host `race` out of its reach; `h` learns the blob from the other host and
/// gets to `race` first (stamped, or deposited when `who` is `READER`), then leaves. `a` is left
/// cut off from `race`. The thing and its entries.
fn race(fx: &mut Fx, race: usize, wrong: bool, who: u8) -> (Tid, Vec<BlobId>) {
    let (g, l, a, h) = (fx.g, fx.l, fx.a, fx.h);
    fx.net.blocked.insert((a, race));
    fx.net.drop_link(a, race);
    let t = fx.net.item(a, g, g, "message");
    fx.net.run();
    assert_eq!(fx.net.read(h, t), Some(s("message")));
    let ids = entries_of(&mut fx.net, h, &l, t);
    assert!(!ids.is_empty());
    for id in &ids {
        let w = bad_wrap(&mut fx.net, h, g, id, wrong);
        hostile_put(&mut fx.net, h, race, (g, &l), *id, w, who);
        assert_eq!(stored_wrap(&fx.net, race, &l, id), Some(w), "first at that host");
    }
    fx.net.set_online(h, false);
    (t, ids)
}

fn reconnect(fx: &mut Fx, n: usize, host: usize, seed: u64) {
    fx.net.blocked.remove(&(n, host));
    fx.net.restart(n, seed);
    fx.net.run();
}

// spec/sync.md §5: a reader's deposit under a blob ID it saw elsewhere keeps no writer's wrap
// out: the writer's stamped upload takes the entry, and no second encryption is needed.
#[test]
fn stamped_upload_replaces_hostile_deposit_spec_sync_5() {
    let mut fx = fixture(2, 1);
    let r = fx.hosts[1];
    let (t, ids) = race(&mut fx, r, false, READER);
    let good: Vec<_> = ids.iter().map(|id| stored_wrap(&fx.net, fx.hosts[0], &fx.l, id).unwrap()).collect();
    let a = fx.a;
    reconnect(&mut fx, a, r, 41);
    fx.net.advance(600_000);
    for (id, good) in ids.iter().zip(&good) {
        assert_eq!(stored_wrap(&fx.net, r, &fx.l, id).as_ref(), Some(good), "promoted under the good wrap");
        assert!(fx.net.hosts[r].hub.store().entry(&fx.l, id).unwrap().unwrap().stamp.is_some());
    }
    connect(&mut fx, &[r], 33);
    assert_eq!(fx.net.read(fx.f, t), Some(s("message")));
    let (a, l) = (fx.a, fx.l);
    assert_eq!(entries_of(&mut fx.net, a, &l, t), ids, "no other encryption");
}

// spec/sync.md §5, §7: a writer that got first to a host with a useless wrap (a race the author
// cannot lose at the host it reached first): the author, knowing the key, places a fresh
// encryption there, and the useless entry goes whatever the order of their IDs; a reader of that
// host alone reads the body, and nothing more happens after that.
#[test]
fn raced_wrap_repaired_by_fresh_encryption_spec_sync_5() {
    for seed in 1..9u64 {
        let wrong = seed % 2 == 0;
        let mut fx = fixture(2, seed);
        let r = fx.hosts[1];
        let (t, ids) = race(&mut fx, r, wrong, WRITER);
        let a = fx.a;
    reconnect(&mut fx, a, r, 41);
        connect(&mut fx, &[r], 33);
        fx.net.advance(600_000);
        assert_eq!(fx.net.read(fx.f, t), Some(s("message")), "seed {seed} wrong {wrong}");
        let at = fx.net.host_ids(r, &fx.l);
        assert!(ids.iter().all(|id| !at.contains(id)), "seed {seed}: the useless entries went");
        let (a, l) = (fx.a, fx.l);
        let mine = entries_of(&mut fx.net, a, &l, t);
        let fresh = mine.iter().filter(|b| at.contains(b)).count();
        assert_eq!(fresh, ids.len(), "seed {seed}: one copy each there: {mine:?}");
        let deleted = fx.net.hosts[r].hub.store().log_after(&l, 0, usize::MAX).unwrap().unwrap().iter().filter(|(_, x)| matches!(x, osis_proto::LogRecord::Deleted(_))).count();
        assert_eq!(deleted, ids.len(), "seed {seed}: no copy deleted in between");
        let n = fx.net.host_ids(r, &fx.l).len();
        fx.net.advance(600_000);
        fx.net.advance(600_000);
        assert_eq!(fx.net.host_ids(r, &fx.l).len(), n, "seed {seed}: settled");
    }
}

// spec/sync.md §5: with the author and the hostile writer gone, a reader of both hosts takes the
// wrap that opens the blob, whichever host it hears first: it needs no repair.
#[test]
fn reader_takes_the_wrap_that_opens_spec_sync_5() {
    for (i, wrong) in [(0, false), (1, false), (0, true), (1, true)] {
        let mut fx = fixture(2, 7);
        let r = fx.hosts[1];
        let (t, _) = race(&mut fx, r, wrong, WRITER);
        fx.net.set_online(fx.a, false);
        let order = if i == 0 { [fx.hosts[0], r] } else { [r, fx.hosts[0]] };
        connect(&mut fx, &order[..1], 33);
        connect(&mut fx, &order[1..], 34);
        assert_eq!(fx.net.read(fx.f, t), Some(s("message")), "first {i} wrong {wrong}");
    }
}

// spec/sync.md §5, §7: the repairing author gone before its deletes leaves the useless entry beside
// the copy. An admin that heard the useless wrap first and took the good one from the other host
// deletes the useless entry, never the copy, whichever ID is higher.
#[test]
fn useless_entry_found_late_still_goes_spec_sync_7() {
    for seed in 1..9u64 {
        let mut net = Net::new();
        let hosts = vec![net.add_host(), net.add_host()];
        let (h1, h2) = (hosts[0], hosts[1]);
        let d = net.node(seed * 10 + 1, &hosts);
        let a = net.node(seed * 10 + 2, &hosts);
        let h = net.node(seed * 10 + 3, &hosts);
        let f = net.node(seed * 10 + 4, &hosts);
        let g = net.group(d, &[(a, Role::Write), (h, Role::Write), (f, Role::Read)], &hosts);
        net.run();
        net.set_online(d, false);
        let l = net.label(a);
        let mut fx = Fx { net, hosts, a, h, f, g, l };
        let (_, ids) = race(&mut fx, h2, false, WRITER);
        let mut net = fx.net;
        let before = net.host_ids(h2, &l);
        net.blocked.remove(&(a, h2));
        net.restart(a, 41);
        // the author goes as soon as the copies reach the host, before it can delete anything
        let mut fresh = Vec::new();
        for _ in 0..1000 {
            net.feed(a, osis_node::sync::Event::Local);
            net.round();
            fresh = net.host_ids(h2, &l).into_iter().filter(|b| !before.contains(b)).collect();
            if fresh.len() >= ids.len() {
                break;
            }
        }
        assert!(fresh.len() >= ids.len(), "seed {seed}: {fresh:?}");
        net.set_online(a, false);
        let at = net.host_ids(h2, &l);
        assert!(ids.iter().all(|id| at.contains(id)), "seed {seed}");
        // the admin hears the host with the useless wrap first
        net.blocked.insert((d, h1));
        net.set_online(d, true);
        net.restart(d, 51);
        net.run();
        net.blocked.remove(&(d, h1));
        net.restart(d, 52);
        net.run();
        net.advance(600_000);
        let at = net.host_ids(h2, &l);
        assert!(ids.iter().all(|id| !at.contains(id)), "seed {seed}: the useless entries went");
        assert!(fresh.iter().all(|id| at.contains(id)), "seed {seed}: the copies stay");
    }
}

// spec/sync.md §5: a node holding no key keeps a wrap that opens over a stamped one that does not
// (the first host's reply lost, the second host's wrap garbage: it must fetch again), and takes a
// stamped wrap over a deposited one when neither opens.
#[test]
fn keyless_node_keeps_the_wrap_that_opens_spec_sync_5() {
    let mut fx = fixture(1, 3);
    let (host, g, l, a, h, f) = (fx.hosts[0], fx.g, fx.l, fx.a, fx.h, fx.f);
    let t = fx.net.item(a, g, g, "message");
    fx.net.run();
    let ids = entries_of(&mut fx.net, h, &l, t);
    fx.net.hide_blobs.insert(f, ids.iter().copied().collect());
    connect(&mut fx, &[host], 33);
    let conn = fx.net.conn_to(f, host).unwrap();
    let (_, gl) = fx.net.sync(h).labels().into_iter().find(|(_, x)| x.id == l).unwrap();
    let head = fx.net.host_path(host, &l).last().unwrap().clone();
    let write = fx.net.engine(h).head_keys(&g, gl.index, &head).unwrap().write.unwrap();
    let push = |net: &mut Net, id: BlobId, wrap: [u8; WRAP_LEN], stamped: bool| {
        let stamp = stamped.then(|| osis_label::sign_stamp(&write, &l, &id, &wrap));
        let m = Message::Push { label: l, events: vec![osis_proto::Event::Added { blob_id: id, blob: None, wrap, stamp }], cursor: osis_proto::Cursor { log_id: [0; 16], seq: 0 } };
        net.feed(f, osis_node::sync::Event::Bytes { conn, bytes: encode_frame(&m.encode()) });
        net.settle(10_000);
        net.sync(f).entry_meta(&l, &id).unwrap().0
    };
    for id in &ids {
        let good = stored_wrap(&fx.net, host, &l, id).unwrap();
        assert_eq!(push(&mut fx.net, *id, good, true), good);
        assert_eq!(push(&mut fx.net, *id, [0x13; WRAP_LEN], true), good, "a garbage wrap replaces no wrap that opens");
    }
    // an entry nothing opens: a stamp wins, then the first stamped one stays
    let other = BlobId([0x77; 32]);
    assert_eq!(push(&mut fx.net, other, [1; WRAP_LEN], false), [1; WRAP_LEN]);
    assert_eq!(push(&mut fx.net, other, [2; WRAP_LEN], true), [2; WRAP_LEN]);
    assert_eq!(push(&mut fx.net, other, [3; WRAP_LEN], true), [2; WRAP_LEN]);
    fx.net.hide_blobs.remove(&f);
    fx.net.advance(600_000);
    assert_eq!(fx.net.read(f, t), Some(s("message")));
}

// spec/sync.md §5, randomized: writers, hosts, attacks and reading orders picked per seed; every
// reader ends up reading every message, at every host set it can reach, whatever a hostile writer
// uploaded and whichever order it heard things in, once one honest holder has been back.
#[test]
fn hostile_wraps_hide_nothing_randomized_spec_sync_5() {
    let mut failed = Vec::new();
    for seed in 0..24u64 {
        let mut d = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5bd1_e995;
        let mut pick = |n: u64| {
            d ^= d << 13;
            d ^= d >> 7;
            d ^= d << 17;
            d % n
        };
        let (n_hosts, msgs, attack) = (1 + pick(2) as usize, 1 + pick(3), pick(3));
        let reads = pick(4);
        let mut fx = fixture(n_hosts, seed + 1);
        let (g, l, a, h) = (fx.g, fx.l, fx.a, fx.h);
        let target = fx.hosts[n_hosts - 1];
        let raced = n_hosts == 2 && attack > 0;
        if raced {
            fx.net.blocked.insert((a, target));
            fx.net.drop_link(a, target);
        }
        let mut items = Vec::new();
        for m in 0..msgs {
            let v = format!("m{m}");
            let t = fx.net.item(a, g, g, &v);
            items.push((t, v));
        }
        fx.net.run();
        for (t, _) in items.clone() {
            for id in entries_of(&mut fx.net, h, &l, t) {
                let w = bad_wrap(&mut fx.net, h, g, &id, pick(2) == 0);
                if attack == 2 {
                    // a deposit first, then a hostile promotion
                    hostile_put(&mut fx.net, h, target, (g, &l), id, w, READER);
                }
                hostile_put(&mut fx.net, h, target, (g, &l), id, w, WRITER);
            }
        }
        fx.net.set_online(h, false);
        // the reader's hosts, in order
        let hosts: Vec<usize> = match (n_hosts, reads) {
            (1, _) => vec![fx.hosts[0]],
            (_, 0) => vec![fx.hosts[0], fx.hosts[1]],
            (_, 1) => vec![fx.hosts[1], fx.hosts[0]],
            (_, 2) => vec![fx.hosts[0]],
            _ => vec![fx.hosts[1]],
        };
        connect(&mut fx, &hosts[..1], 100);
        connect(&mut fx, &hosts[1..], 101);
        if raced {
            reconnect(&mut fx, a, target, 102);
        }
        fx.net.advance(600_000);
        fx.net.advance(600_000);
        for (t, v) in items {
            if fx.net.read(fx.f, t) != Some(s(&v)) {
                failed.push((seed, n_hosts, attack, reads, v));
            }
        }
    }
    assert!(failed.is_empty(), "{failed:?}");
}
