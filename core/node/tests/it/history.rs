//! An aspect's history (notes/api.md History) and purge by author (spec/wire.md §4,
//! spec/commits.md §5, spec/permissions.md §8), at the engine: what an entry reads, which change
//! each commit makes known, and order independence.

use crate::common::*;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_node::engine::history::{HistoryFrom, HistoryPos, HistoryRow, RowBody};
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_node::{ChangeId, Event, Mutation};
use osis_schema::core_types::{self as ct, Required};
use osis_schema::{Codec, Retention};
use std::collections::BTreeSet;

const MAX: usize = usize::MAX;

fn reg() -> Ak {
    ak("t:reg.0")
}

/// Alice (0) owns D, Bob (1) and Dan (3) write, Carol (2) is an admin.
fn setup(seed: u64) -> (LocalPeer, Tid, [Tid; 4]) {
    let mut lp = net(4, seed);
    let ids = [0, 1, 2, 3].map(|i| lp.peers[i].engine.tid());
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[3], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, d, ids)
}

fn write(lp: &mut LocalPeer, i: usize, d: Tid, r: Retention, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.retention(d, &reg(), r).unwrap();
    m.set(d, &reg(), &s(v)).unwrap();
    let c = lp.peers[i].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    c
}

fn purge(lp: &mut LocalPeer, i: usize, item: PurgeItem) -> CommitId {
    let mut m = Mutation::new();
    let now = lp.peers[i].engine.now();
    m.set(*item.tid(), &ct::PURGE, &now).unwrap();
    m.purge(item);
    let c = lp.peers[i].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    c
}

fn pack(lp: &mut LocalPeer, i: usize, c: &CommitId) -> Package {
    lp.peers[i].engine.package(c).unwrap().unwrap()
}

fn all(lp: &mut LocalPeer, i: usize) -> Vec<Package> {
    let ids: Vec<CommitId> = lp.peers[i].engine.commit_ids().into_iter().collect();
    let mut x: Vec<(osis_base::Ts, Package)> = ids.iter().map(|c| (lp.peers[i].engine.header(c).unwrap().ts, pack(lp, i, c))).collect();
    x.sort_by_key(|x| x.0);
    x.into_iter().map(|x| x.1).collect()
}

fn fresh(lp: &mut LocalPeer, base: &[Package], seed: u64) -> Peer {
    let now = lp.peers[0].engine.now();
    let mut p = Peer::new(seed, now).unwrap();
    for x in base {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    p
}

fn page(p: &mut Peer, d: Tid, from: HistoryFrom, n: usize) -> (Vec<HistoryRow>, bool) {
    p.engine.history(&d, &reg(), from, n, MAX).unwrap()
}

fn entry(p: &mut Peer, d: Tid, c: &CommitId) -> HistoryRow {
    p.engine.history_entry(&d, &reg(), &ChangeId::Commit(*c), MAX).unwrap().unwrap()
}

fn texts(rows: &[HistoryRow]) -> Vec<String> {
    rows.iter()
        .map(|r| match &r.body {
            RowBody::Held(Some(Value::Str(x))) => x.clone(),
            b => format!("{b:?}"),
        })
        .collect()
}

fn pos(r: &HistoryRow) -> HistoryPos {
    HistoryPos { ts: r.ts, id: r.id }
}

// notes/api.md History: pages by time from either end, neither bound counting itself, with their
// author, and a superseded body reads as written (the register reads only the last).
#[test]
fn pages_by_time_both_ways_superseded_reads() {
    let (mut lp, d, ids) = setup(401);
    let r = Retention::default();
    for (i, v) in [(1, "a"), (3, "b"), (1, "c"), (3, "d"), (1, "e")] {
        write(&mut lp, i, d, r, v);
        lp.sync_all().unwrap();
    }
    let p = &mut lp.peers[1];
    assert_eq!(p.engine.get(&d, &reg()).unwrap(), Some(s("e")), "only the last in the state");
    let (new, more) = page(p, d, HistoryFrom::Newest, 2);
    assert_eq!((texts(&new), more), (vec!["e".to_string(), "d".to_string()], true));
    assert_eq!(new[0].actor, ids[1]);
    assert_eq!(new[1].actor, ids[3]);
    assert!(new.iter().all(|r| r.valid && r.kind == Some(osis_commit::Kind::Content)));
    let (older, more) = page(p, d, HistoryFrom::Before(pos(&new[1])), 2);
    assert_eq!((texts(&older), more), (vec!["c".to_string(), "b".to_string()], true));
    let (last, more) = page(p, d, HistoryFrom::Before(pos(&older[1])), 2);
    assert_eq!((texts(&last), more), (vec!["a".to_string()], false));
    let (old, more) = page(p, d, HistoryFrom::Oldest, 2);
    assert_eq!((texts(&old), more), (vec!["a".to_string(), "b".to_string()], true));
    let (newer, more) = page(p, d, HistoryFrom::After(pos(&old[1])), 9);
    assert_eq!((texts(&newer), more), (vec!["c".to_string(), "d".to_string(), "e".to_string()], false));
    // a time: from there on, and up to it
    let (at, _) = page(p, d, HistoryFrom::After(HistoryPos::time(older[0].ts)), 1);
    assert_eq!(texts(&at), vec!["c".to_string()], "the entry stamped there counts");
    let (at, _) = page(p, d, HistoryFrom::Before(HistoryPos::time(older[0].ts)), 1);
    assert_eq!(texts(&at), vec!["b".to_string()]);
    // none: an empty page, not an error
    assert_eq!(page(p, Tid::from_bytes([9; 15]), HistoryFrom::Newest, 5), (Vec::new(), false));
    assert_eq!(page(p, d, HistoryFrom::Newest, 0).0, Vec::new());
    assert!(page(p, d, HistoryFrom::Newest, 0).1, "limit 0: more lies that way");
}

// notes/api.md History: a page stops past its byte bound, with at least one entry, and says more;
// one body past it alone reads as too large where the bound is smaller than it.
#[test]
fn page_stops_at_its_byte_bound() {
    let (mut lp, d, _) = setup(402);
    for v in ["0123456789", "abcdefghij", "klmnopqrst"] {
        write(&mut lp, 1, d, Retention::default(), v);
    }
    let e = &mut lp.peers[1].engine;
    let (rows, more) = e.history(&d, &reg(), HistoryFrom::Newest, 9, 5).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(more);
    assert_eq!(rows[0].body, RowBody::TooLarge, "the bound counts the body in memory");
    let (rows, more) = e.history(&d, &reg(), HistoryFrom::Newest, 9, 20).unwrap();
    assert!(rows.len() < 3 && more, "{rows:?}");
    let (rows, more) = e.history(&d, &reg(), HistoryFrom::Newest, 9, 100_000).unwrap();
    assert_eq!((rows.len(), more), (3, false));
}

// notes/api.md History, spec/permissions.md §5.2: an invalid body still reads, marked invalid, and
// reads valid again if it comes back: an app decides what to show.
#[test]
fn invalid_body_reads_marked() {
    let (mut lp, d, ids) = setup(403);
    let c = write(&mut lp, 1, d, Retention::default(), "v");
    assert!(entry(&mut lp.peers[1], d, &c).valid);
    lp.sync_all().unwrap();
    let f = ct::Frontier { commits: BTreeSet::new() };
    set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(f.to_value()));
    let r = entry(&mut lp.peers[0], d, &c);
    assert!(!r.valid);
    assert_eq!(r.body, RowBody::Held(Some(s("v"))));
    assert_eq!(r.actor, ids[1]);
}

// notes/api.md History, spec/commits.md §5: what is gone reads as what happened to it: purged by
// the earliest request, or dropped at its expiry (at once past it, before any tick); its entry
// stays where it was, with its author and time.
#[test]
fn purged_and_dropped_entries_read_as_such_spec_commits_5() {
    let (mut lp, d, ids) = setup(404);
    let r = Retention::default();
    let a = write(&mut lp, 1, d, r, "a");
    let b = write(&mut lp, 3, d, r, "b");
    lp.sync_all().unwrap();
    let first = purge(&mut lp, 0, PurgeItem::Commit { commit: b, tid: d, ak: reg() });
    let second = purge(&mut lp, 2, PurgeItem::Commit { commit: b, tid: d, ak: reg() });
    let expiring = {
        let mut m = Mutation::new();
        m.set(d, &reg(), &s("gone soon")).unwrap();
        m.expires(d, &reg(), osis_base::WallMs(lp.peers[0].engine.now().0 + 10)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    lp.sync_all().unwrap();
    let p = &mut lp.peers[1];
    assert_eq!(entry(p, d, &expiring).body, RowBody::Held(Some(s("gone soon"))));
    lp.advance(20);
    let p = &mut lp.peers[1];
    assert_eq!(entry(p, d, &expiring).body, RowBody::Dropped, "past its expiry, the tick or not");
    p.engine.tick().unwrap();
    assert_eq!(entry(p, d, &expiring).body, RowBody::Dropped);
    let e = entry(p, d, &b);
    assert_eq!((e.actor, e.body.clone()), (ids[3], RowBody::Purged(first)));
    assert!(e.valid);
    assert_eq!(entry(p, d, &a).body, RowBody::Held(Some(s("a"))));
    let _ = second;
    let (rows, _) = page(p, d, HistoryFrom::Oldest, 9);
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![ChangeId::Commit(a), ChangeId::Commit(b), ChangeId::Commit(expiring)], "gone bodies keep their place");
}

// spec/commits.md §5, notes/api.md History: a dropped body that a request then names reads purged.
#[test]
fn expired_then_purged_tells_the_watch_spec_commits_5() {
    let (mut lp, d, _) = setup(407);
    let mut m = Mutation::new();
    m.set(d, &reg(), &s("gone soon")).unwrap();
    m.expires(d, &reg(), osis_base::WallMs(lp.peers[0].engine.now().0 + 10)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(20);
    lp.peers[1].engine.tick().unwrap();
    lp.peers[1].engine.watch_history();
    lp.peers[1].drain_events();
    let rq = purge(&mut lp, 0, PurgeItem::Commit { commit: c, tid: d, ak: reg() });
    lp.sync_all().unwrap();
    assert_eq!(entry(&mut lp.peers[1], d, &c).body, RowBody::Purged(rq));
    assert!(history_of(&mut lp.peers[1], d).contains(&c), "its meta did not change, its entry did");
}

/// The commits on `(d, reg)` named by history events since the last drain.
fn history_of(p: &mut Peer, d: Tid) -> Vec<CommitId> {
    let mut out = Vec::new();
    for e in p.drain_events() {
        if let Event::History(ch) = e {
            out.extend(ch.iter().filter(|(t, a, _)| *t == d && *a == reg()).filter_map(|x| x.2.commit()));
        }
    }
    out
}

// notes/api.md History (the seam for issues/partial-history-fetch.md): a commit whose header is here
// and whose part is not reads as not fetched, not absent, in its place; its body's arrival tells the
// watch, in one event per commit.
#[test]
fn not_fetched_part_reads_so_and_late_body_tells_the_watch() {
    let (mut lp, d, ids) = setup(408);
    let mut m = Mutation::new();
    let e = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    lp.sync_all().unwrap();
    let base = all(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(d, &reg(), &s("here")).unwrap();
    m.set(e, &reg(), &s("away")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = pack(&mut lp, 0, &c);
    let mut p = fresh(&mut lp, &base, 409);
    let mut only = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let keep = only.header.aspects.iter().position(|a| a.tid == d).unwrap();
    only.parts.retain(|x| x.ai == keep);
    p.engine.watch_history();
    p.drain_events();
    p.engine.ingest(&only.encode(), pk.blobs.clone()).unwrap();
    assert!(history_of(&mut p, d).contains(&c), "new");
    assert_eq!(entry(&mut p, d, &c).body, RowBody::Held(Some(s("here"))));
    let (rows, _) = p.engine.history(&e, &reg(), HistoryFrom::Newest, 9, MAX).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].body, RowBody::NotFetched);
    p.drain_events();
    p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    let mut told = Vec::new();
    for ev in p.drain_events() {
        if let Event::History(ch) = ev {
            told.extend(ch.iter().cloned());
        }
    }
    assert_eq!(told, vec![(e, reg(), ChangeId::Commit(c))], "the late part's entry alone");
    assert_eq!(p.engine.history_entry(&e, &reg(), &ChangeId::Commit(c), MAX).unwrap().unwrap().body, RowBody::Held(Some(s("away"))));
}

// notes/api.md History: the watch names exactly the commits whose entries read otherwise, per
// commit: a new one, a late older one, one turning invalid, one purged; nothing for what did not
// change; and nothing at all until someone listens (a fall lists every commit it touches).
#[test]
fn events_per_commit_exact() {
    let (mut lp, d, ids) = setup(411);
    let r = Retention::default();
    lp.peers[1].drain_events();
    let c = write(&mut lp, 1, d, r, "one");
    assert!(history_of(&mut lp.peers[1], d).is_empty(), "off until asked for");
    lp.peers[1].engine.watch_history();
    let c2 = write(&mut lp, 1, d, r, "two");
    assert_eq!(history_of(&mut lp.peers[1], d), vec![c2], "a new one, and its earlier one's entry reads as it did");
    // a late older one: written before, arriving after
    let older = write(&mut lp, 3, d, r, "older");
    let pk = pack(&mut lp, 3, &older);
    let c3 = write(&mut lp, 1, d, r, "three");
    assert_eq!(history_of(&mut lp.peers[1], d), vec![c3]);
    lp.peers[1].engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    assert_eq!(history_of(&mut lp.peers[1], d), vec![older], "the arrival alone");
    // purged: that one
    let pc = purge(&mut lp, 0, PurgeItem::Commit { commit: c, tid: d, ak: reg() });
    let pp = pack(&mut lp, 0, &pc);
    lp.peers[1].drain_events();
    let pk = pack(&mut lp, 1, &c);
    let _ = pk;
    lp.peers[1].engine.ingest(&pp.bytes, pp.blobs.clone()).unwrap();
    assert_eq!(history_of(&mut lp.peers[1], d), vec![c], "the purged one only");
    // Bob's writes turn invalid at a demotion listing none of them: each of them, and no other
    let f = ct::Frontier { commits: BTreeSet::new() };
    lp.sync_all().unwrap();
    lp.peers[1].drain_events();
    let dm = set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(f.to_value()));
    let pd = pack(&mut lp, 0, &dm);
    lp.peers[3].engine.watch_history();
    lp.peers[3].drain_events();
    lp.peers[3].engine.ingest(&pd.bytes, pd.blobs.clone()).unwrap();
    let mut got = history_of(&mut lp.peers[3], d);
    got.sort();
    let mut want = vec![c, c2, c3];
    want.sort();
    assert_eq!(got, want, "Bob's, the purged one's too: it turned invalid; not Dan's");
}

// spec/commits.md §5 (fixed retention): `purge.0` keeps its retention through a compaction; the
// requests stand, and a receiver takes the snapshot.
#[test]
fn purge_aspect_compacts_spec_commits_5() {
    let (mut lp, d, ids) = setup(32);
    let a = write(&mut lp, 1, d, Retention::default(), "one");
    lp.sync_all().unwrap();
    let k = ak("purge.0");
    let rq = purge(&mut lp, 0, PurgeItem::Commit { commit: a, tid: d, ak: reg() });
    purge(&mut lp, 0, PurgeItem::Author { tid: d, ak: reg(), actor: ids[3] });
    let snap = lp.peers[0].engine.snapshot(&d, &k).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&snap).unwrap();
    assert_eq!(Some(h.aspects[0].retention), osis_commit::retention::fixed_retention("purge.0"));
    assert_eq!(lp.peers[0].engine.history(&d, &reg(), HistoryFrom::Oldest, 5, MAX).unwrap().0[0].body, RowBody::Purged(rq));
    lp.sync_all().unwrap();
    let got = lp.peers[3].engine.get(&d, &k).unwrap();
    assert_eq!(got, lp.peers[0].engine.get(&d, &k).unwrap());
    assert!(got.is_some());
}

// spec/wire.md §2, §4 (`MAX_AUTHOR_ITEMS`): one commit names so many authors at most, its author's
// node stopping it and a receiver refusing it: each walks the aspect.
#[test]
fn author_items_are_bounded_spec_wire_4() {
    let (mut lp, d, _) = setup(31);
    let items = |n: usize, m: &mut Mutation| {
        for i in 0..n {
            m.purge(PurgeItem::Author { tid: d, ak: reg(), actor: Tid::from_bytes([i as u8 + 1; 15]) });
        }
    };
    let max = osis_base::format::MAX_AUTHOR_ITEMS;
    for (n, ok) in [(max, true), (max + 1, false)] {
        let mut m = Mutation::new();
        let now = lp.peers[0].engine.now();
        m.set(d, &ct::PURGE, &now).unwrap();
        items(n, &mut m);
        assert_eq!(lp.peers[0].commit(m).is_ok(), ok, "{n} items");
        lp.advance(1_000);
    }
}


// spec/wire.md §4: the wire form is told apart by its place, and round-trips.
#[test]
fn author_item_round_trips_spec_wire_4() {
    let (mut lp, d, ids) = setup(405);
    let c = purge(&mut lp, 0, PurgeItem::Author { tid: d, ak: reg(), actor: ids[1] });
    let pk = pack(&mut lp, 0, &c);
    let mut p = fresh(&mut lp, &[], 406);
    let base = all(&mut lp, 0);
    for x in base.iter().chain([&pk]) {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    assert_eq!(p.engine.header(&c).unwrap().purge, vec![PurgeItem::Author { tid: d, ak: reg(), actor: ids[1] }]);
}

/// Every order of `n` items.
fn perms(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for p in perms(n - 1) {
        for i in 0..n {
            let mut q = p.clone();
            q.insert(i, n - 1);
            out.push(q);
        }
    }
    out
}

// spec/permissions.md §8, spec/commits.md §5: a purge by author drops exactly the author's deltas
// stamped before it, each only if the request holds the right over that delta at its own key: no
// override under `author` or `nobody`. The same in every arrival order of the delta, the setting
// requiring its retention, the author's demotion and the request, a delta arriving after the
// request falling under it; what another wrote and what the author writes later stay.
#[test]
fn purge_by_author_any_order_spec_perm_8() {
    for by in PurgeBy::ALL {
        // requester: 0 the owner, 2 an admin, 1 the author itself, 3 another writer
        for who in [0, 1, 3] {
            let want = match who {
                0 => by.admin(),
                1 => by.author(),
                _ => by.writer(),
            };
            let (mut lp, d, ids) = setup(410 + by as u64);
            let r = Retention { by, ..Retention::default() };
            let base = all(&mut lp, 0);
            let mut m = Mutation::new();
            m.set(d, &ct::REQUIRED, &[("t:".to_string(), Required::new(r, None))].into_iter().collect::<ct::RequiredRules>()).unwrap();
            let setting = lp.peers[0].commit(m).unwrap().unwrap();
            let setting = pack(&mut lp, 0, &setting);
            lp.sync_all().unwrap();
            lp.advance(1_000);
            let c = write(&mut lp, 1, d, r, "bob's");
            let other = write(&mut lp, 3, d, r, "dan's");
            let pc = pack(&mut lp, 1, &c);
            let po = pack(&mut lp, 3, &other);
            lp.sync_all().unwrap();
            let rq = purge(&mut lp, who, PurgeItem::Author { tid: d, ak: reg(), actor: ids[1] });
            let prq = pack(&mut lp, who, &rq);
            // an honest demotion: it lists the delta and the request (spec/permissions.md §5.1)
            let f = ct::Frontier { commits: [c, rq].into_iter().collect() };
            let dm = set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Read)), Some(f.to_value()));
            let pd = pack(&mut lp, 0, &dm);
            let items = [&pc, &setting, &pd, &prq];
            for (k, order) in perms(4).iter().enumerate() {
                // only the author's own request by the first class: the orders are the same work
                if k > 0 && by != PurgeBy::AuthorOrAdmin && order[0] != 0 {
                    continue;
                }
                let mut p = fresh(&mut lp, &base, 500 + k as u64);
                // another's on the first order, held before the request; after it on the rest
                if k == 0 {
                    p.engine.ingest(&po.bytes, po.blobs.clone()).unwrap();
                }
                for i in order {
                    p.engine.ingest(&items[*i].bytes, items[*i].blobs.clone()).unwrap();
                }
                if k != 0 {
                    p.engine.ingest(&po.bytes, po.blobs.clone()).unwrap();
                }
                let why = format!("{by:?} by peer {who}, order {order:?}");
                assert_eq!(p.engine.body_not_dropped(&c, &d, &reg()), !want, "{why}");
                assert!(p.engine.body_not_dropped(&other, &d, &reg()), "another's stays: {why}");
                let e = entry(&mut p, d, &c);
                assert_eq!(e.actor, ids[1], "{why}");
                if want {
                    assert_eq!(e.body, RowBody::Purged(rq), "{why}");
                } else {
                    assert_eq!(e.body, RowBody::Held(Some(s("bob's"))), "{why}");
                }
            }
        }
    }
}

// spec/permissions.md §8: a request by author reaches the deltas stamped before it only: what the
// author writes later stays, whichever arrives first.
#[test]
fn purge_by_author_spares_later_writes_spec_perm_8() {
    let (mut lp, d, ids) = setup(420);
    let r = Retention::default();
    let before = write(&mut lp, 1, d, r, "before");
    lp.sync_all().unwrap();
    let rq = purge(&mut lp, 0, PurgeItem::Author { tid: d, ak: reg(), actor: ids[1] });
    lp.sync_all().unwrap();
    let after = write(&mut lp, 1, d, r, "after");
    lp.sync_all().unwrap();
    for i in 0..4 {
        assert_eq!(entry(&mut lp.peers[i], d, &before).body, RowBody::Purged(rq), "peer {i}");
        assert_eq!(entry(&mut lp.peers[i], d, &after).body, RowBody::Held(Some(s("after"))), "peer {i}");
        assert_eq!(lp.peers[i].engine.get(&d, &reg()).unwrap(), Some(s("after")));
    }
}

// spec/commits.md §5: a purge by author names the author's snapshot too (as a whole-aspect purge
// does): that body goes, and another's value it carried stays in every node's read.
#[test]
fn purge_by_author_of_a_snapshot_keeps_anothers_value_spec_commits_5() {
    let (mut lp, d, ids) = setup(421);
    let r = Retention::default();
    let dan = write(&mut lp, 3, d, r, "dan's");
    lp.sync_all().unwrap();
    let snap = lp.peers[1].engine.snapshot(&d, &reg()).unwrap().unwrap();
    lp.advance(1_000);
    lp.sync_all().unwrap();
    let rq = purge(&mut lp, 0, PurgeItem::Author { tid: d, ak: reg(), actor: ids[1] });
    lp.sync_all().unwrap();
    for i in 0..4 {
        assert_eq!(entry(&mut lp.peers[i], d, &snap).body, RowBody::Purged(rq), "peer {i}");
        assert_eq!(entry(&mut lp.peers[i], d, &dan).body, RowBody::Held(Some(s("dan's"))), "peer {i}");
        assert_eq!(lp.peers[i].engine.get(&d, &reg()).unwrap(), Some(s("dan's")), "peer {i}");
    }
}

// spec/permissions.md §8, §7: an import counts as its origin's author: a purge by author reaches
// what a moved thing brought of theirs.
#[test]
fn purge_by_author_reaches_an_import_spec_perm_8() {
    let (mut lp, d, ids) = setup(422);
    write(&mut lp, 1, d, Retention::default(), "bob's");
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    let owner = ids[0];
    let _ = (&mut m, owner);
    let (copy, _) = lp.peers[0].engine.move_thing(&d, owner).unwrap();
    lp.advance(1_000);
    let (rows, _) = lp.peers[0].engine.history(&copy, &reg(), HistoryFrom::Newest, 9, MAX).unwrap();
    let import = rows.iter().find(|r| r.kind == Some(osis_commit::Kind::Import)).expect("an import").id.commit().unwrap();
    assert_eq!(rows.iter().find(|r| r.id == ChangeId::Commit(import)).unwrap().actor, ids[0], "by the mover");
    let rq = purge(&mut lp, 0, PurgeItem::Author { tid: copy, ak: reg(), actor: ids[1] });
    let e = lp.peers[0].engine.history_entry(&copy, &reg(), &ChangeId::Commit(import), MAX).unwrap().unwrap();
    assert_eq!(e.body, RowBody::Purged(rq));
}

/// Bob's write on D (retention `writer`), Alice's move: the copy and the import of that write.
fn moved(lp: &mut LocalPeer, d: Tid, owner: Tid) -> (Tid, CommitId, CommitId) {
    let c = write(lp, 1, d, Retention { by: PurgeBy::Writer, ..Default::default() }, "bob's");
    lp.sync_all().unwrap();
    let (copy, imports) = lp.peers[0].engine.move_thing(&d, owner).unwrap();
    let e = &lp.peers[0].engine;
    let i = *imports.iter().find(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == c))).unwrap();
    lp.advance(1_000);
    (copy, c, i)
}

// spec/commits.md §5, spec/requirements.md Purge: naming an import takes its values, as naming a
// delta does: no reset, a snapshot carrying them, a stale copy; the origin thing keeps its own.
#[test]
fn purge_import_takes_its_values_spec_commits_5() {
    let (mut lp, d, ids) = setup(431);
    let (copy, _, i) = moved(&mut lp, d, ids[0]);
    let snap = lp.peers[0].engine.snapshot(&copy, &reg()).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&copy, &reg()).unwrap(), Some(s("bob's")));
    let stale = pack(&mut lp, 0, &i);
    lp.advance(1_000);
    purge(&mut lp, 0, PurgeItem::Commit { commit: i, tid: copy, ak: reg() });
    lp.sync_all().unwrap();
    for p in 0..4 {
        lp.peers[p].engine.ingest(&stale.bytes, stale.blobs.clone()).unwrap();
        let e = &mut lp.peers[p].engine;
        assert_eq!(e.get(&copy, &reg()).unwrap(), None, "peer {p}");
        assert!(!e.body_not_dropped(&i, &copy, &reg()) && !e.body_not_dropped(&snap, &copy, &reg()), "peer {p}");
        assert_eq!(e.get(&d, &reg()).unwrap(), Some(s("bob's")), "peer {p}: a move is a copy");
    }
}

// spec/commits.md §5, spec/permissions.md §7, spec/requirements.md Purge: a copy moved on
// before any snapshot of it hands its import's writes on under that import. Naming the next
// copy's import takes them there, in any order and from a stale copy, and a third move brings
// nothing back; naming the first import before the move keeps them out of the next copy.
#[test]
fn purge_reaches_writes_moved_on_through_an_import_spec_commits_5() {
    let (mut lp, d, ids) = setup(434);
    let (copy, _, i1) = moved(&mut lp, d, ids[0]);
    let (copy2, imports) = lp.peers[0].engine.move_thing(&copy, ids[0]).unwrap();
    let i2 = *imports.iter().find(|i| lp.peers[0].engine.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == i1))).expect("an import of the import");
    set_edge(&mut lp.peers[0].engine, copy2, ids[1], Some(edge(Role::Read)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    for p in [0, 1] {
        assert_eq!(lp.peers[p].engine.get(&copy2, &reg()).unwrap(), Some(s("bob's")), "peer {p}");
    }
    let stale = pack(&mut lp, 0, &i2);
    let base: Vec<Package> = all(&mut lp, 0).into_iter().filter(|x| x.id != i2).collect();
    let rq = purge(&mut lp, 0, PurgeItem::Commit { commit: i2, tid: copy2, ak: reg() });
    lp.sync_all().unwrap();
    for p in [0, 1] {
        lp.peers[p].engine.ingest(&stale.bytes, stale.blobs.clone()).unwrap();
        let e = &mut lp.peers[p].engine;
        assert_eq!(e.get(&copy2, &reg()).unwrap(), None, "peer {p}");
        assert!(!e.body_not_dropped(&i2, &copy2, &reg()), "peer {p}");
    }
    // the request before the import
    let req = pack(&mut lp, 0, &rq);
    let mut f = fresh(&mut lp, &base, 4341);
    f.engine.ingest(&req.bytes, req.blobs.clone()).unwrap();
    f.engine.ingest(&stale.bytes, stale.blobs.clone()).unwrap();
    assert_eq!(f.engine.get(&copy2, &reg()).unwrap(), None, "request first");
    let (copy3, _) = lp.peers[0].engine.move_thing(&copy2, ids[0]).unwrap();
    assert_eq!(lp.peers[0].engine.get(&copy3, &reg()).unwrap(), None, "a third move");
    assert_eq!(lp.peers[0].engine.get(&copy, &reg()).unwrap(), Some(s("bob's")), "a move is a copy");

    let (mut lp, d, ids) = setup(435);
    let (copy, _, i1) = moved(&mut lp, d, ids[0]);
    purge(&mut lp, 0, PurgeItem::Commit { commit: i1, tid: copy, ak: reg() });
    let (copy2, imports) = lp.peers[0].engine.move_thing(&copy, ids[0]).unwrap();
    let e = &lp.peers[0].engine;
    assert!(!imports.iter().any(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == i1))), "nothing of a purged import");
    assert_eq!(lp.peers[0].engine.get(&copy2, &reg()).unwrap(), None);
}

// spec/permissions.md §7, spec/commits.md §5: another import listing the origin holds the same
// writes: it goes with the one named, whether it is held already, comes later, or is written later.
#[test]
fn purge_import_takes_others_of_the_origin_spec_commits_5() {
    let (mut lp, d, ids) = setup(432);
    let (copy, c, first) = moved(&mut lp, d, ids[0]);
    let of_c = |lp: &LocalPeer, v: Vec<CommitId>| *v.iter().find(|i| lp.peers[0].engine.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == c))).unwrap();
    let again = lp.peers[0].engine.reimport(&d, &copy).unwrap();
    let held = of_c(&lp, again);
    lp.advance(1_000);
    let base: Vec<Package> = all(&mut lp, 0);
    let rq = purge(&mut lp, 0, PurgeItem::Commit { commit: first, tid: copy, ak: reg() });
    let e = &mut lp.peers[0].engine;
    assert!(!e.body_not_dropped(&held, &copy, &reg()), "held already");
    assert_eq!(e.get(&copy, &reg()).unwrap(), None);
    lp.advance(1_000);
    let again = lp.peers[0].engine.reimport(&d, &copy).unwrap();
    let later = of_c(&lp, again);
    let e = &mut lp.peers[0].engine;
    assert!(!e.body_not_dropped(&later, &copy, &reg()), "written later");
    assert_eq!(e.get(&copy, &reg()).unwrap(), None);
    // a device coming later: the import held by others arrives after the request, whole or as
    // the bare header holders now give
    let (req, gone) = (pack(&mut lp, 0, &rq), pack(&mut lp, 0, &later));
    let whole = base.iter().find(|x| x.id == held).unwrap().clone();
    let rest: Vec<Package> = base.iter().filter(|x| x.id != held).cloned().collect();
    let mut p = fresh(&mut lp, &rest, 4321);
    p.engine.ingest(&req.bytes, req.blobs.clone()).unwrap();
    p.engine.ingest(&whole.bytes, whole.blobs.clone()).unwrap();
    assert!(!p.engine.body_not_dropped(&held, &copy, &reg()), "arrives after the request");
    assert_eq!(p.engine.get(&copy, &reg()).unwrap(), None);
    p.engine.ingest(&gone.bytes, gone.blobs.clone()).unwrap();
    assert!(p.engine.commit_ids().contains(&later) && !p.engine.pending().iter().any(|x| x.0 == later), "a missing delta holding purged writes counts as held");
}

/// Two imports `(i1, i2)` of Bob's write on a copy of D Alice owns, and Carol's (2) and Dan's (3)
/// requests naming one each, by admins on the copy; Bob (1) is a third admin, who demotes them, and
/// Alice demotes Bob leaving that out. `base` is what comes first, `pk` what each test orders.
struct TwoImports {
    lp: LocalPeer,
    copy: Tid,
    i: [CommitId; 2],
    pk: Vec<Package>,
    base: Vec<Package>,
}

/// Packages of `TwoImports`, by index.
const I1: usize = 0;
const I2: usize = 1;
const P1: usize = 2;
const P2: usize = 3;
const D_CAROL: usize = 4;
const D_DAN: usize = 5;
const D_BOB: usize = 6;
const I1_BARE: usize = 7;

fn two_imports(seed: u64) -> TwoImports {
    let (mut lp, d, ids) = setup(seed);
    let (copy, c, i1) = moved(&mut lp, d, ids[0]);
    let again = lp.peers[0].engine.reimport(&d, &copy).unwrap();
    let e = &lp.peers[0].engine;
    let i2 = *again.iter().find(|i| e.header(i).is_some_and(|h| h.origins.iter().any(|o| o.commit == c))).unwrap();
    lp.advance(1_000);
    for x in &ids[1..] {
        set_edge(&mut lp.peers[0].engine, copy, *x, Some(edge(Role::Admin)), None);
    }
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let base = all(&mut lp, 0);
    let imports = [pack(&mut lp, 0, &i1), pack(&mut lp, 0, &i2)];
    let p1 = purge(&mut lp, 2, PurgeItem::Commit { commit: i1, tid: copy, ak: reg() });
    let p2 = purge(&mut lp, 3, PurgeItem::Commit { commit: i2, tid: copy, ak: reg() });
    let (p1, p2) = (pack(&mut lp, 2, &p1), pack(&mut lp, 3, &p2));
    let dc = set_edge(&mut lp.peers[1].engine, copy, ids[2], None, None);
    lp.advance(1_000);
    let dd = set_edge(&mut lp.peers[1].engine, copy, ids[3], None, None);
    lp.advance(1_000);
    let db = set_edge(&mut lp.peers[0].engine, copy, ids[1], None, None);
    let (dc, dd, db) = (pack(&mut lp, 1, &dc), pack(&mut lp, 1, &dd), pack(&mut lp, 0, &db));
    let bare = pack(&mut lp, 2, &i1);
    let [a, b] = imports;
    let base = base.into_iter().filter(|x| x.id != i1 && x.id != i2).collect();
    TwoImports { lp, copy, i: [i1, i2], pk: vec![a, b, p1, p2, dc, dd, db, bare], base }
}

impl TwoImports {
    /// A fresh device holding the base, then the packages at `order`.
    fn given(&mut self, seed: u64, order: &[usize]) -> Peer {
        let base = self.base.clone();
        let mut p = fresh(&mut self.lp, &base, seed);
        for n in order {
            let x = &self.pk[*n];
            p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
        }
        p
    }

    /// What it reads, whether each import's body is gone, and the value-less list.
    fn seen(&self, p: &mut Peer) -> (Option<Value>, [bool; 2], usize) {
        let k = (self.copy, reg());
        let list = p.engine.core.ix.valueless.get(&k).map_or(0, |v| v.len());
        let gone = self.i.map(|i| !p.engine.body_not_dropped(&i, &self.copy, &reg()));
        (p.engine.get(&self.copy, &reg()).unwrap(), gone, list)
    }
}

// spec/permissions.md §8, spec/commits.md §5: one origin's writes held by two imports, a request on
// each. One falling leaves both gone: the other still takes the origin's writes.
#[test]
fn purge_import_one_request_of_two_falls_stays_gone_spec_perm_8() {
    let mut t = two_imports(433);
    let mut p = t.given(1, &[I1, I2, P1, P2]);
    assert_eq!(t.seen(&mut p), (None, [true, true], 1));
    let dc = t.pk[D_CAROL].clone();
    p.engine.ingest(&dc.bytes, dc.blobs).unwrap();
    assert_eq!(t.seen(&mut p), (None, [true, true], 1), "Dan's request stands");
    let e = &p.engine;
    assert!(!e.purge_stands(&t.pk[P1].id, &t.i[0], &t.copy, &reg()) && e.purge_stands(&t.pk[P2].id, &t.i[1], &t.copy, &reg()));
    // a copy of either import is taken again and goes: no value
    for n in [I1, I2] {
        let x = t.pk[n].clone();
        p.engine.ingest(&x.bytes, x.blobs).unwrap();
        assert_eq!(t.seen(&mut p), (None, [true, true], 1), "copy {n}");
    }
}

// spec/permissions.md §8: both requests fallen, both imports count as never received and the value
// is back with a copy of either; the demotions falling, the requests rise and take it again.
#[test]
fn purge_import_both_fall_then_rise_spec_perm_8() {
    let mut t = two_imports(434);
    let mut p = t.given(2, &[I1, I2, P1, P2, D_CAROL, D_DAN]);
    assert_eq!(t.seen(&mut p), (None, [false, false], 0), "missing until a copy comes");
    assert_eq!(p.engine.core.ix.commits.get(&t.i[0]).unwrap().missing.len(), 1);
    let x = t.pk[I1].clone();
    p.engine.ingest(&x.bytes, x.blobs).unwrap();
    assert_eq!(t.seen(&mut p), (Some(s("bob's")), [false, false], 0), "one copy gives it");
    let db = t.pk[D_BOB].clone();
    p.engine.ingest(&db.bytes, db.blobs).unwrap();
    assert_eq!(t.seen(&mut p), (None, [true, true], 1), "taken again");
    // and it survives an index rebuild
    p.engine.rebuild_index().unwrap();
    assert_eq!(t.seen(&mut p), (None, [true, true], 1));
}

// spec/permissions.md §8: a fall and rise with no copy between: the import's residue counts again,
// as at a node that never saw the fall, the other import's too.
#[test]
fn purge_import_rise_without_a_copy_reads_as_no_fall_spec_perm_8() {
    let mut t = two_imports(435);
    let mut a = t.given(3, &[I1, I2, P1, P2, D_CAROL, D_DAN, D_BOB]);
    let mut b = t.given(4, &[I1, I2, D_BOB, D_CAROL, D_DAN, P1, P2]);
    assert_eq!(t.seen(&mut a), (None, [true, true], 1));
    assert_eq!(t.seen(&mut a), t.seen(&mut b));
    assert_eq!(a.engine.state(&t.copy, &reg()).unwrap(), b.engine.state(&t.copy, &reg()).unwrap());
}

// spec/permissions.md §8: the import a rise names never had a body here, the other import did: the
// other's residue counts again though it was not the one to put the origin back on the list.
#[test]
fn purge_import_rise_rejoins_the_other_imports_residue_spec_perm_8() {
    let mut t = two_imports(437);
    let mut a = t.given(5, &[I2, P1, I1_BARE, D_CAROL, D_BOB]);
    let mut b = t.given(6, &[I2, D_BOB, D_CAROL, P1, I1_BARE]);
    assert_eq!(t.seen(&mut a), (None, [true, true], 1));
    assert_eq!(a.engine.state(&t.copy, &reg()).unwrap(), b.engine.state(&t.copy, &reg()).unwrap());
    assert!(a.engine.state(&t.copy, &reg()).unwrap().is_some(), "its value-less write");
}

// spec/commits.md §5: a snapshot arriving after a request on the whole aspect, stamped after it,
// drops for carrying an import's values, as for a request by name.
#[test]
fn purge_of_whole_aspect_drops_later_snapshot_of_an_import_spec_commits_5() {
    let (mut lp, d, ids) = setup(438);
    let (copy, _, _) = moved(&mut lp, d, ids[0]);
    set_edge(&mut lp.peers[0].engine, copy, ids[3], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let base = all(&mut lp, 0);
    let rq = purge(&mut lp, 0, PurgeItem::Aspect { tid: copy, ak: reg() });
    let rq = pack(&mut lp, 0, &rq);
    let snap = lp.peers[3].engine.snapshot(&copy, &reg()).unwrap().unwrap();
    let snap = pack(&mut lp, 3, &snap);
    let mut p = fresh(&mut lp, &base, 4380);
    p.engine.ingest(&rq.bytes, rq.blobs.clone()).unwrap();
    p.engine.ingest(&snap.bytes, snap.blobs.clone()).unwrap();
    assert!(!p.engine.body_not_dropped(&snap.id, &copy, &reg()));
    assert_eq!(p.engine.get(&copy, &reg()).unwrap(), None);
}

// spec/commits.md §5, §6: an import dropped as covered, its cover gone: never received, as a delta,
// its writes out of the state until a copy comes.
#[test]
fn import_uncovered_counts_as_never_received_spec_commits_5() {
    let (mut lp, d, ids) = setup(439);
    let (copy, _, i) = moved(&mut lp, d, ids[0]);
    set_edge(&mut lp.peers[0].engine, copy, ids[3], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let snap = lp.peers[3].engine.snapshot(&copy, &reg()).unwrap().unwrap();
    let base = all(&mut lp, 0);
    let (si, ss) = (pack(&mut lp, 0, &i), pack(&mut lp, 3, &snap));
    lp.advance(1_000);
    let dd = set_edge(&mut lp.peers[0].engine, copy, ids[3], None, None);
    let dd = pack(&mut lp, 0, &dd);
    let rest: Vec<Package> = base.into_iter().filter(|x| x.id != i).collect();
    let mut p = fresh(&mut lp, &rest, 4390);
    for x in [&si, &ss] {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    p.engine.drop_body(&i, &copy, &reg()).unwrap();
    assert_eq!(p.engine.get(&copy, &reg()).unwrap(), Some(s("bob's")));
    p.engine.ingest(&dd.bytes, dd.blobs.clone()).unwrap();
    assert!(p.engine.body_not_dropped(&i, &copy, &reg()), "missing");
    assert_eq!(p.engine.get(&copy, &reg()).unwrap(), None, "its cover gave it, and fell");
    p.engine.ingest(&si.bytes, si.blobs.clone()).unwrap();
    assert_eq!(p.engine.get(&copy, &reg()).unwrap(), Some(s("bob's")));
}

// spec/permissions.md §8: what the requests and demotions do to two imports is a function of what
// is held, its bodies given again, not of the order it came in.
#[test]
fn purge_import_fall_any_order_spec_perm_8() {
    let mut t = two_imports(436);
    for held in [vec![I1, I2, P1, P2, D_CAROL], vec![I1, I2, P1, D_CAROL], vec![I1, I2, P1, P2, D_CAROL, D_DAN], vec![I2, P1, P2, D_CAROL]] {
        let mut want = None;
        for (n, order) in perms(held.len()).into_iter().enumerate() {
            if n % 7 != 0 && n != 0 {
                continue;
            }
            let order: Vec<usize> = order.iter().map(|x| held[*x]).collect();
            let mut p = t.given(100 + n as u64, &order);
            // copies again: a part dropped before the fall comes back with one
            for x in held.iter().filter(|x| **x <= I2) {
                let x = t.pk[*x].clone();
                p.engine.ingest(&x.bytes, x.blobs).unwrap();
            }
            let got = (p.engine.get(&t.copy, &reg()).unwrap(), p.engine.state(&t.copy, &reg()).unwrap(), t.seen(&mut p).2);
            match &want {
                None => want = Some(got),
                Some(w) => assert_eq!(*w, got, "{order:?}"),
            }
        }
    }
}

// spec/commits.md §4, §5: an import's part waiting beside a missing one, the request held: held
// value-less, as a named delta's, not kept whole.
#[test]
fn purge_import_waiting_held_valueless_spec_commits_5() {
    let (mut lp, d, ids) = setup(433);
    let mut m = Mutation::new();
    let w = Retention { by: PurgeBy::Writer, ..Default::default() };
    m.retention(d, &reg(), w).unwrap();
    m.set(d, &reg(), &s("bob's")).unwrap();
    m.retention(d, &ak("t:kept.0"), w).unwrap();
    m.set(d, &KEPT, &s("beside")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let (copy, imports) = lp.peers[0].engine.move_thing(&d, ids[0]).unwrap();
    let i = *imports.iter().find(|i| lp.peers[0].engine.header(i).unwrap().aspects.len() == 2).unwrap();
    lp.advance(1_000);
    let whole = pack(&mut lp, 0, &i);
    let rest: Vec<Package> = all(&mut lp, 0).into_iter().filter(|x| x.id != i).collect();
    purge(&mut lp, 0, PurgeItem::Commit { commit: i, tid: copy, ak: reg() });
    let rq = all(&mut lp, 0).into_iter().last().unwrap();
    let mut p = fresh(&mut lp, &rest, 4331);
    p.engine.ingest(&rq.bytes, rq.blobs.clone()).unwrap();
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let h = part.header.clone();
    part.parts.retain(|x| h.aspects[x.ai].ak == reg());
    p.engine.ingest(&part.encode(), whole.blobs.clone()).unwrap();
    assert!(p.engine.stripped_count(&i).unwrap() > 0, "held value-less while it waits");
    p.engine.ingest(&whole.bytes, whole.blobs.clone()).unwrap();
    assert_eq!(p.engine.get(&copy, &reg()).unwrap(), None);
    assert_eq!(p.engine.get(&copy, &ak("t:kept.0")).unwrap(), Some(s("beside")), "only the aspect named");
}

// spec/permissions.md §7, §8: a void import (its origin has a delta on the thing, owning its dots
// there) owns no write of that origin: a purge naming it takes none, whichever came first; a
// request reaches them only by naming the origin.
#[test]
fn purge_of_void_import_spares_its_origin_spec_perm_7() {
    let (mut lp, d, ids) = setup(434);
    let (copy, _, _) = moved(&mut lp, d, ids[0]);
    set_edge(&mut lp.peers[0].engine, copy, ids[1], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.commit_form();
    m.retention(copy, &reg(), Retention { by: PurgeBy::Writer, ..Default::default() }).unwrap();
    m.set(copy, &reg(), &s("native")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync(1, 0).unwrap();
    lp.advance(1_000);
    let imports = lp.peers[0].engine.reimport(&copy, &copy).unwrap();
    let void = *imports.iter().find(|i| lp.peers[0].engine.header(i).unwrap().origins.iter().any(|o| o.commit == c)).unwrap();
    lp.advance(1_000);
    let rq = purge(&mut lp, 0, PurgeItem::Commit { commit: void, tid: copy, ak: reg() });
    let want = lp.peers[0].engine.state(&copy, &reg()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&copy, &reg()).unwrap(), Some(s("native")), "origin first");
    let all = all(&mut lp, 0);
    let last: Vec<CommitId> = vec![c, void, rq];
    let base: Vec<Package> = all.iter().filter(|x| !last.contains(&x.id)).cloned().collect();
    let by = |id: &CommitId| all.iter().find(|x| x.id == *id).unwrap().clone();
    for (n, order) in [[c, void, rq], [void, rq, c], [void, c, rq], [rq, void, c], [rq, c, void]].iter().enumerate() {
        let mut p = fresh(&mut lp, &base, 4340 + n as u64);
        for id in order {
            let x = by(id);
            p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
        }
        assert_eq!(p.engine.get(&copy, &reg()).unwrap(), Some(s("native")), "order {n}");
        assert_eq!(p.engine.state(&copy, &reg()).unwrap(), want, "order {n}");
        assert!(p.engine.body_not_dropped(&c, &copy, &reg()), "order {n}");
    }
}

// spec/commits.md §5: a purge request's blob is kept until its floor whatever its deltas' keep
// bounds: under at most 0 its write dying does not drop it early; past the floor it goes.
#[test]
fn purge_request_floor_holds_at_most_zero_spec_commits_5() {
    let (mut lp, d, _) = setup(435);
    let w = write(&mut lp, 0, d, Retention { by: PurgeBy::Writer, ..Default::default() }, "v");
    let mut m = Mutation::new();
    m.retention(d, &reg(), Retention { by: PurgeBy::Writer, at_most: osis_schema::Bound { abs: None, rel: Some(0) }, ..Default::default() }).unwrap();
    m.purge(PurgeItem::Commit { commit: w, tid: d, ak: reg() });
    m.set(d, &reg(), &s("p")).unwrap();
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    write(&mut lp, 0, d, Retention::default(), "later");
    assert_eq!(lp.peers[0].engine.get(&d, &reg()).unwrap(), Some(s("later")));
    assert!(lp.peers[0].engine.body_not_dropped(&p, &d, &reg()), "killed, before its floor");
    lp.advance(osis_base::format::ROLE_KEEP_MS + 1_000);
    lp.peers[0].engine.tick().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&p, &d, &reg()), "past its floor");
}
