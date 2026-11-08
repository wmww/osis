//! An aspect's history (notes/api.md History) and purge by author (spec/wire.md §4,
//! spec/commits.md §5, spec/permissions.md §6), at the engine: what an entry reads, which change
//! each commit makes known, and order independence.

use crate::common::*;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_node::engine::history::{HistoryFrom, HistoryPos, HistoryRow, RowBody};
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_node::{BatchId, Event, Mutation};
use osis_schema::core_types::{self as ct, Required};
use osis_schema::{Codec, Retention};
use std::collections::BTreeSet;

const MAX: usize = usize::MAX;

fn reg() -> Ak {
    ak("t:reg.0")
}

/// Alice (0) is first admin of D, Bob (1) and Dan (3) write, Carol (2) is an admin.
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
    p.engine.history_entry(&d, &reg(), &BatchId::Commit(*c), MAX).unwrap().unwrap()
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

// notes/api.md History, spec/crdt.md §5.6 Live: an edit of a held key reads as written, though
// alone it holds no creation and a read of the same bytes as a state shows nothing.
#[test]
fn edit_of_held_key_reads_as_written_spec_crdt_5_6() {
    let mut lp = net(1, 404);
    let t = new_thing(&mut lp, 0);
    let k = ak("t:big.0");
    let put = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &BIGMAP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k"))], op: osis_crdt::Op::Set(s(v)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    put(&mut lp, "a");
    lp.advance(10);
    let c = put(&mut lp, "b");
    let r = lp.peers[0].engine.history_entry(&t, &k, &BatchId::Commit(c), MAX).unwrap().unwrap();
    assert_eq!(r.body, RowBody::Held(Some(Value::Map([(s("k"), s("b"))].into()))));
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
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![BatchId::Commit(a), BatchId::Commit(b), BatchId::Commit(expiring)], "gone bodies keep their place");
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
    assert_eq!(told, vec![(e, reg(), BatchId::Commit(c))], "the late part's entry alone");
    assert_eq!(p.engine.history_entry(&e, &reg(), &BatchId::Commit(c), MAX).unwrap().unwrap().body, RowBody::Held(Some(s("away"))));
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
    // Dan received Bob's writes: he would vouch for them (spec/permissions.md §5.2); this counts
    // what turns invalid under a removal listing none
    lp.peers[3].engine.write_addenda(false);
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

// spec/permissions.md §6, spec/commits.md §5: a purge by author drops exactly the author's deltas
// stamped before it, each only if the request holds the right over that delta at its own key: no
// override under `author` or `nobody`. The same in every arrival order of the delta, the setting
// requiring its retention, the author's demotion and the request, a delta arriving after the
// request falling under it; what another wrote and what the author writes later stay.
#[test]
fn purge_by_author_any_order_spec_perm_6() {
    for by in PurgeBy::ALL {
        // requester: 0 the first admin, 2 an admin, 1 the author itself, 3 another writer
        for who in [0, 1, 3] {
            let want = match who {
                0 => by.admin(),
                1 => by.author(),
                _ => by.writer(),
            };
            let (mut lp, d, ids) = setup(410 + by as u64);
            let r = crate::common::purgeable_by(by);
            let base = all(&mut lp, 0);
            let mut m = Mutation::new();
            m.set(d, &ct::REQUIRED, &ct::RequiredRules { default: Some(Required::new(r, None)), ..ct::RequiredRules::default() }).unwrap();
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

// spec/permissions.md §6: a request by author reaches the deltas stamped before it only: what the
// author writes later stays, whichever arrives first.
#[test]
fn purge_by_author_spares_later_writes_spec_perm_6() {
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

// spec/commits.md §5: a purge request's blob is kept until its floor whatever its deltas'
// retention: under purge on replace the writer's cover does not drop it early; past the floor it
// goes (`T_FLOOR`).
#[test]
fn purge_request_floor_holds_purge_on_replace_spec_commits_5() {
    let (mut lp, d, _) = setup(435);
    let w = write(&mut lp, 0, d, Retention { by: PurgeBy::Writer, ..Default::default() }, "v");
    let mut m = Mutation::new();
    m.retention(d, &reg(), Retention { by: PurgeBy::Writer, history: Some(osis_schema::History::PurgeOnReplace) }).unwrap();
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
