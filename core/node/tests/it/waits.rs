#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Re-examination of pending commits (`apply/waits.rs`): what `reexamine` leaves out must wait
//! for the same reason as a full examination would say (spec/commits.md §4).

use crate::common;
use common::*;
use osis_commit::CommitBlob;
use osis_base::{Tid, Value, WallMs};
use osis_node::local_peer::LocalPeer;
use osis_node::{Ingested, Mutation, Reason};
use osis_schema::{PurgeBy, Retention};

fn only(bytes: &[u8], h: &osis_commit::Header, keep: impl Fn(Tid, &str) -> bool) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].tid, h.aspects[p.ai].ak.as_str()));
    b.encode()
}

/// A thing of peer 0 known to peer 1, which syncs it; the commits `writes` makes on it, one per
/// entry, the wall clock moving 10 ms between them, with peer 1 given none of them.
fn carrierless(seed: u64, writes: Vec<Mutate>) -> (LocalPeer, Tid, Vec<osis_node::local_peer::Package>) {
    let mut lp = net(2, seed);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut out = Vec::new();
    for w in writes {
        lp.advance(10);
        let mut m = Mutation::new();
        w(&mut m, t);
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        out.push(packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap());
    }
    (lp, t, out)
}

type Mutate = Box<dyn Fn(&mut Mutation, Tid)>;

/// A commit writing `GONE` (under retention `r`, when given) and, when `reg`, `REG`.
fn mixed(gone: &'static str, reg: Option<&'static str>, r: Option<Retention>) -> Mutate {
    Box::new(move |m, t| {
        if let Some(r) = r {
            m.retention(t, &GONE, r).unwrap();
        }
        m.set(t, &GONE, &s(gone)).unwrap();
        if let Some(v) = reg {
            m.set(t, &REG, &s(v)).unwrap();
        }
    })
}

/// Purgeable by any writer (`GONE` is purged on replace by `test_setting`).
fn by_writer() -> Option<Retention> {
    Some(Retention { by: PurgeBy::Writer })
}

fn reg_only(p: &osis_node::local_peer::Package) -> Vec<u8> {
    let b = CommitBlob::decode(&p.bytes).unwrap();
    let h = b.header.clone();
    only(&p.bytes, &h, |_, a| a == "t:reg.0")
}

// spec/commits.md §4, §5: a commit whose author may not write, one part withheld under purge on replace,
// gains nothing by it: the part held applies invalid, as does a later write. No setting governs
// fixed retention: a role-class part is never under purge on replace.
#[test]
fn forged_purge_on_replace_class_gives_no_rights_spec_commits_4() {
    let mut lp = net(3, 0x7c05);
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[2].engine.me();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    sync(&mut lp, 2, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    // peer 1 knows of peer 2's removal, peer 2 does not: it writes a part it withholds under at
    // most 0 with a part on `REG`, then a later write on `GONE`, both invalid at peer 1
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, w, None, None);
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut m = Mutation::new();
    mixed("forged", Some("forged"), by_writer())(&mut m, t);
    let forged = lp.peers[2].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 2).into_iter().find(|p| p.id == forged).unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    mixed("later", None, None)(&mut m, t);
    let later = lp.peers[2].commit(m).unwrap().unwrap();
    let pl = packages(&mut lp, 2).into_iter().find(|p| p.id == later).unwrap();
    lp.peers[1].receive(&reg_only(&pk), Vec::new()).unwrap();
    lp.deliver(1, &pl).unwrap();
    lp.peers[1].reexamine().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")), "the part stays invalid");
    assert_eq!(e.get(&t, &ak("t:gone.0")).unwrap(), None, "so does the later write");
    assert!(osis_commit::retention::fixed_retention("roles.0").is_some());
}

/// As node-sync's `drop_covered` for a right holder past keep at least (the bodies here are
/// `by: writer` with no keep at least): every body of `(t, a)` snapshot `s` covers. How many.
fn drop_covered_by(e: &mut osis_node::Engine, s: &osis_base::CommitId, t: &Tid, a: &osis_base::Ak) -> usize {
    let held: Vec<osis_base::CommitId> = e.core.ix.by_aspect.get(&(*t, a.clone())).into_iter().flatten().map(|x| x.1).collect();
    let mut n = 0;
    for c in held {
        if c != *s && e.body_not_dropped(&c, t, a) && e.covered(s, &c, t, a).unwrap() == Some(true) {
            e.drop_body(&c, t, a).unwrap();
            n += 1;
        }
    }
    n
}

/// Gives peer `to` of `lp` write on `t` and every commit of peer 0.
fn writer(lp: &mut LocalPeer, t: Tid, to: usize) {
    let w = lp.peers[to].engine.me();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
    sync(lp, 0, to);
}

// spec/commits.md §5, spec/crdt.md §8 (a delta with an expiry is never covered): a snapshot lists
// a live expiring part this node never received, carrying none of its value, as a holder's does:
// the part stays to join when it comes, before its T.
#[test]
fn expiring_part_stays_to_join_past_snapshot_spec_commits_5() {
    let far = T0.0 + 3_600_000;
    let put = move |k: &'static str, reg: bool, exp: bool| -> Mutate {
        Box::new(move |m, t| {
            let map = ak("t:gonemap.0");
            m.retention(t, &map, by_writer().unwrap()).unwrap();
            if exp {
                m.expires(t, &map, WallMs(far)).unwrap();
            }
            m.op(t, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(s("v")) }).unwrap();
            if reg {
                m.set(t, &REG, &s("1")).unwrap();
                // one expiry per commit (spec/commits.md §6)
                if exp {
                    m.expires(t, &REG, WallMs(far)).unwrap();
                }
            }
        })
    };
    for holders in [true, false] {
        let map = ak("t:gonemap.0");
        let (mut lp, t, c) = carrierless(0x7e01, vec![put("a", true, true), put("b", false, false)]);
        let w = lp.peers[1].engine.me();
        let grant = set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
        let pg = packages(&mut lp, 0).into_iter().find(|p| p.id == grant).unwrap();
        lp.deliver(1, &pg).unwrap();
        let held = holders.then(|| {
            let id = lp.peers[0].engine.snapshot(&t, &map).unwrap().unwrap();
            packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap()
        });
        lp.peers[1].receive(&reg_only(&c[0]), Vec::new()).unwrap();
        lp.deliver(1, &c[1]).unwrap();
        if let Some(p) = &held {
            lp.deliver(1, p).unwrap();
        }
        lp.peers[1].reexamine().unwrap();
        assert!(lp.peers[1].engine.pending().is_empty());
        let e = &mut lp.peers[1].engine;
        let snap = match &held {
            Some(p) => p.id,
            None => e.snapshot(&t, &map).unwrap().unwrap(),
        };
        assert_eq!(e.covered(&snap, &c[0].id, &t, &map).unwrap(), Some(false), "holder's: {holders}");
        drop_covered_by(e, &snap, &t, &map);
        lp.deliver(1, &c[0]).unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &map).unwrap(), lp.peers[0].engine.get(&t, &map).unwrap(), "holder's: {holders}");
    }
}

// spec/crdt.md §4.7, §5.6 Live: a map entry an expiring delta created stays past T with another
// writer's later lasting write inside it, under that write's own key, whatever the arrival order,
// under purge on replace.
#[test]
fn expired_entry_keeps_nested_write_alike_spec_crdt_4_7() {
    let map = ak("t:gonemap.0");
    let r = by_writer().unwrap();
    let mut lp = net(4, 0x7e09);
    let t = new_thing(&mut lp, 0);
    for i in 1..4 {
        writer(&mut lp, t, i);
    }
    for (a, b) in [(0, 1), (1, 0), (0, 2), (0, 3), (1, 2), (1, 3)] {
        sync(&mut lp, a, b);
    }
    let put = |v: &str| osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k"))], op: osis_crdt::Op::Set(s(v)) };
    let mut m = Mutation::new();
    m.retention(t, &map, r).unwrap();
    m.expires(t, &map, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &map, put("a")).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    let p1 = packages(&mut lp, 0).into_iter().find(|p| p.id == c1).unwrap();
    lp.deliver(1, &p1).unwrap();
    let mut m = Mutation::new();
    m.retention(t, &map, r).unwrap();
    m.op(t, &map, put("b")).unwrap();
    let c2 = lp.peers[1].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[1].engine.header(&c2).unwrap().expires, None, "the put's own expiry");
    let p2 = packages(&mut lp, 1).into_iter().find(|p| p.id == c2).unwrap();
    lp.deliver(2, &p1).unwrap();
    lp.deliver(2, &p2).unwrap();
    lp.deliver(3, &p2).unwrap();
    lp.deliver(3, &p1).unwrap();
    for p in [2, 3] {
        lp.peers[p].clock.advance(2 * 3_600_000);
        lp.peers[p].tick().unwrap();
    }
    assert_eq!(lp.peers[2].engine.get(&t, &map).unwrap(), lp.peers[3].engine.get(&t, &map).unwrap());
    assert_eq!(lp.peers[2].engine.get(&t, &map).unwrap(), Some(osis_base::Value::Map([(s("k"), s("b"))].into_iter().collect())), "the put keeps the entry");
}

// spec/commits.md §4: a creation record applies alone, synced or not: whichever the node learned
// first, the thing's next commit shows, and the part away holds only its own commit.
#[test]
fn creation_record_applies_alone_spec_commits_4() {
    for (seed, sync_first) in [(89, true), (90, false)] {
        let mut lp = net(2, seed);
        let mut m = Mutation::new();
        let me = lp.peers[0].engine.me();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &REG, &s("first")).unwrap();
        let c1 = lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].clock.advance(10);
        let mut m = Mutation::new();
        m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
        let c2 = lp.peers[0].commit(m).unwrap().unwrap();
        let pks = packages(&mut lp, 0);
        for pk in pks.iter().filter(|p| p.id != c1 && p.id != c2) {
            lp.deliver(1, pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        if sync_first {
            e.set_syncing(t, true).unwrap();
        }
        let h = lp.peers[0].engine.header(&c1).unwrap();
        let pk1 = pks.iter().find(|p| p.id == c1).unwrap();
        let record = only(&pk1.bytes, &h, |_, a| a == "created.0");
        let e = &mut lp.peers[1].engine;
        assert!(matches!(e.ingest(&record, Vec::new()).unwrap(), Ingested::Applied(_)), "sync_first {sync_first}");
        e.set_syncing(t, true).unwrap();
        e.ingest(&pks.iter().find(|p| p.id == c2).unwrap().bytes, Vec::new()).unwrap();
        assert!(e.get(&t, &ak("t:tags.0")).unwrap().is_some(), "sync_first {sync_first}: the next commit shows");
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), None);
        // the rest of it joins when it comes
        e.ingest(&pk1.bytes, Vec::new()).unwrap();
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("first")));
        assert!(e.pending().is_empty(), "{:?}", e.pending());
    }
}

// spec/commits.md §4: a creation record applied alone, then the thing's other part, then the rest
// of the commit: each joins as it comes, the commit's other thing synced or not.
#[test]
fn creation_record_then_the_rest_join_spec_commits_4() {
    let mut lp = net(2, 91);
    let u = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.me();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("t")).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pks = packages(&mut lp, 0);
    for pk in pks.iter().filter(|p| p.id != c) {
        lp.deliver(1, pk).unwrap();
    }
    let h = lp.peers[0].engine.header(&c).unwrap();
    let pk = pks.iter().find(|p| p.id == c).unwrap();
    let e = &mut lp.peers[1].engine;
    e.set_syncing(u, true).unwrap();
    assert!(matches!(e.ingest(&only(&pk.bytes, &h, |x, a| x == t && a == "created.0"), Vec::new()).unwrap(), Ingested::Applied(_)));
    let r = e.ingest(&only(&pk.bytes, &h, |x, a| x == t && a != "created.0"), Vec::new()).unwrap();
    assert_eq!(r, Ingested::Applied(c));
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")));
    assert_eq!(e.get(&u, &ak("t:reg.0")).unwrap(), Some(s("new")), "the synced thing's part is away");
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")));
    assert_eq!(e.get(&u, &ak("t:reg.0")).unwrap(), Some(s("u")));
    assert!(e.pending().is_empty(), "{:?}", e.pending());
}

// spec/commits.md §4 (a part waits alone): a page away holds back only its part, not the thing's
// other part, synced or not. spec/crdt.md §8, spec/commits.md §1: a delta above PAGE_TARGET pages;
// its pages travel as blobs listed in the chunk list and the receiver applies it identically.
#[test]
fn pages_away_hold_back_only_their_part_spec_commits_4() {
    let map: osis_base::ValueMap = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    for (seed, synced) in [(92, false), (93, true)] {
        let mut lp = net(2, seed);
        let t = new_thing(&mut lp, 0);
        sync(&mut lp, 0, 1);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("r")).unwrap();
        m.set(t, &BIG, &Value::Map(map.clone())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        assert!(!lp.peers[0].engine.header(&id).unwrap().chunks.is_empty(), "paged delta lists its pages");
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
        assert!(!pk.blobs.is_empty(), "paged");
        let e = &mut lp.peers[1].engine;
        if synced {
            e.set_syncing(t, true).unwrap();
        }
        let r = e.ingest(&pk.bytes, Vec::new()).unwrap();
        assert_eq!(r, Ingested::Applied(id), "synced {synced}");
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")), "synced {synced}");
        assert_eq!(e.pending(), vec![(id, Reason::WaitBlobs)]);
        assert_eq!(e.get_typed(&t, &BIG).unwrap(), None);
        e.put_blobs(pk.blobs.clone()).unwrap();
        e.reexamine().unwrap();
        assert_eq!(e.get_typed(&t, &BIG).unwrap(), Some(Value::Map(map.clone())));
        assert!(e.pending().is_empty(), "{:?}", e.pending());
        let big = ak("t:big.0");
        assert_eq!(lp.peers[0].engine.state(&t, &big).unwrap(), lp.peers[1].engine.state(&t, &big).unwrap(), "applied identically");
    }
}

// spec/commits.md §4 (what a node syncs decides nothing): a commit across things, one thing's part
// away. A node syncing that thing first and one learning it after the other part applied both show
// that part; the part away joins when it comes.
#[test]
fn cross_thing_part_shows_whatever_is_synced_spec_commits_4() {
    let read = |sync_first: bool| {
        let mut lp = net(2, 94);
        let (t, u) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
        sync(&mut lp, 0, 1);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("t")).unwrap();
        m.set(u, &REG, &s("u")).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
        let e = &mut lp.peers[1].engine;
        if sync_first {
            e.set_syncing(u, true).unwrap();
        }
        e.ingest(&only(&pk.bytes, &h, |x, _| x == t), Vec::new()).unwrap();
        e.set_syncing(u, true).unwrap();
        let away = e.get(&t, &ak("t:reg.0")).unwrap();
        e.ingest(&pk.bytes, Vec::new()).unwrap();
        (away, e.get(&t, &ak("t:reg.0")).unwrap(), e.get(&u, &ak("t:reg.0")).unwrap())
    };
    assert_eq!(read(true), (Some(s("t")), Some(s("t")), Some(s("u"))));
    assert_eq!(read(false), read(true));
}

// spec/commits.md §4 (a node never waits for a part): a writer of a synced group lists a thing the
// node never reads. A commit across it and a held thing shows the held thing's part at once.
#[test]
fn listed_thing_never_read_holds_nothing_back_spec_commits_4() {
    let mut lp = net(2, 97);
    let (g, t) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(g, true).unwrap();
    // created now: its record never reaches peer 1
    let v = new_thing(&mut lp, 0);
    let write_group = |lp: &mut LocalPeer, items: &[Tid]| {
        lp.peers[0].clock.advance(10);
        let mut m = Mutation::new();
        m.set(g, &osis_schema::core_types::GROUP, &osis_schema::core_types::Group { items: items.iter().copied().collect(), subgroups: Default::default() }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let listed = write_group(&mut lp, &[t, v]);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("t")).unwrap();
    m.set(v, &REG, &s("v")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pks = packages(&mut lp, 0);
    let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap();
    let e = &mut lp.peers[1].engine;
    e.ingest(&pk(&listed).bytes, Vec::new()).unwrap();
    assert!(e.core.syncs(&v));
    assert_eq!(e.ingest(&only(&pk(&id).bytes, &h, |x, _| x == t), Vec::new()).unwrap(), Ingested::Applied(id));
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")));
    assert!(e.pending().is_empty(), "{:?}", e.pending());
}

// spec/commits.md §4: what a node syncs is a function of the `group.0` it holds, so with a thing
// out of the synced group in the end, a commit across it reads alike in every order of the
// group's writes, of which one had the thing in.
#[test]
fn sync_set_of_final_group_reads_alike_in_any_order_spec_commits_4() {
    let mut lp = net(2, 100);
    let (root, sub, t, u) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    sync(&mut lp, 0, 1);
    let def = |items: &[Tid], subs: &[Tid]| osis_schema::core_types::Group { items: items.iter().copied().collect(), subgroups: subs.iter().copied().collect() };
    let write = |lp: &mut LocalPeer, g: Tid, d: &osis_schema::core_types::Group| {
        lp.peers[0].clock.advance(10);
        let mut m = Mutation::new();
        m.set(g, &osis_schema::core_types::GROUP, d).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let cs = [
        write(&mut lp, sub, &def(&[u], &[])),
        write(&mut lp, root, &def(&[t], &[sub])),
        write(&mut lp, root, &def(&[t], &[])),
    ];
    let mut m = Mutation::new();
    m.set(t, &REG, &s("t")).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    let pks = packages(&mut lp, 0);
    let pk = |id: &osis_base::CommitId| pks.iter().find(|p| p.id == *id).unwrap();
    let held = only(&pk(&c).bytes, &h, |x, _| x == t);
    let base: Vec<_> = pks.iter().filter(|p| p.id != c && !cs.contains(&p.id)).collect();
    let mut seqs: Vec<Vec<usize>> = vec![vec![]];
    for i in 0..4 {
        seqs = seqs.into_iter().flat_map(|v| (0..=v.len()).map(move |k| { let mut w = v.clone(); w.insert(k, i); w })).collect();
    }
    assert_eq!(seqs.len(), 24);
    for seq in seqs {
        let mut p = osis_node::local_peer::Peer::new(0x1000, lp.peers[0].engine.now()).unwrap();
        p.engine.set_syncing(root, true).unwrap();
        for b in &base {
            p.engine.ingest(&b.bytes, b.blobs.clone()).unwrap();
        }
        for &i in &seq {
            match cs.get(i) {
                Some(g) => p.engine.ingest(&pk(g).bytes, pk(g).blobs.clone()).unwrap(),
                None => p.engine.ingest(&held, Vec::new()).unwrap(),
            };
        }
        p.reexamine().unwrap();
        assert!(!p.engine.core.syncs(&u), "{seq:?}");
        assert!(p.engine.core.syncs(&t), "{seq:?}");
        assert_eq!(p.engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")), "{seq:?}");
        assert!(p.engine.pending().is_empty(), "{seq:?}: {:?}", p.engine.pending());
    }
}

// spec/crdt.md §5.7 Live: an expiring list element whose content another lasting write replaced
// whole stays past T with that value, rebuilt and at a late node holding a snapshot alike.
#[test]
fn list_element_overwritten_stays_past_expiry_spec_crdt_5_7() {
    let k = ak("t:list.0");
    let mut lp = net(2, 0x7a05);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    for (a, b) in [(0, 1), (1, 0)] {
        sync(&mut lp, a, b);
    }
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("hello")] } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Index(0)], op: osis_crdt::Op::Set(s("edited")) }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(2 * 3_600_000);
    lp.peers[1].tick().unwrap();
    let edited = Some(Value::List(vec![s("edited")]));
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), edited);
    lp.peers[1].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), edited, "rebuilt");
    // past T, a snapshot carries the value-less creation to a node without the expired commit
    lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks = packages(&mut lp, 1);
    let mut late = osis_node::local_peer::Peer::new(0x7a06, lp.peers[1].engine.now()).unwrap();
    late.engine.set_syncing(t, true).unwrap();
    for pk in &pks {
        let _ = late.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert_eq!(late.engine.get(&t, &k).unwrap(), edited, "a late node");
}

// spec/crdt.md §4.7: a snapshot written before T carries the element's creation value-less: a holder
// of the body reads it until T, whichever came first, and past T the list goes.
#[test]
fn list_element_stays_beside_snapshot_before_expiry_spec_crdt_4_7() {
    let k = ak("t:list.0");
    let mut lp = net(3, 0x7a19);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("hello")] } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(10);
    lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.sync_all().unwrap();
    let shown = Some(Value::List(vec![s("hello")]));
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), shown, "peer {i}");
    }
    lp.advance(2 * 3_600_000);
    for i in 0..3 {
        lp.peers[i].tick().unwrap();
        assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), None, "peer {i} past T");
    }
}

// spec/crdt.md §4.7, §5.7 Live: a purge of a list element's creation takes only its value: the
// element shows another writer's edit in it whichever of the request, the creation and the edit
// arrives first.
#[test]
fn purged_list_element_keeps_edit_in_any_order_spec_crdt_4_7() {
    let k = ak("t:list.0");
    let mut lp = net(3, 0x7a1b);
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("hello")] } }).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(5);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Index(0)], op: osis_crdt::Op::Set(s("edited")) }).unwrap();
    let e = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
    m.set(t, &REG, &s("beside")).unwrap();
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let body = lp.peers[1].engine.package(&c).unwrap().unwrap();
    let edit = lp.peers[0].engine.package(&e).unwrap().unwrap();
    let request = lp.peers[0].engine.package(&p).unwrap().unwrap();
    let rest: Vec<_> = packages(&mut lp, 0).into_iter().filter(|q| ![c, e, p].contains(&q.id)).collect();
    let mut digests = Vec::new();
    for order in [[&body, &edit, &request], [&request, &edit, &body], [&request, &body, &edit], [&edit, &request, &body]] {
        let mut q = osis_node::local_peer::Peer::new(0x7a1c, lp.peers[0].engine.now()).unwrap();
        q.engine.set_syncing(t, true).unwrap();
        for x in &rest {
            let _ = q.engine.ingest(&x.bytes, x.blobs.clone());
        }
        for x in order {
            let _ = q.engine.ingest(&x.bytes, x.blobs.clone());
        }
        assert_eq!(q.engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("edited")])));
        digests.push(q.engine.state_digest(&t, &k).unwrap());
    }
    assert!(digests.iter().all(|d| *d == digests[0]), "{digests:?}");
}

// spec/crdt.md §4.6, §5.7 Live: an un-merge past T rebuilds the state from the leftover: the expired
// element still shows another writer's edit in it, the one holding only its own value stays gone.
#[test]
fn expired_list_element_survives_unmerge_spec_crdt_4_6() {
    let k = ak("t:list.0");
    let mut lp = net(3, 0x7a1a);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    writer(&mut lp, t, 2);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("hello"), s("kept")] } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Index(0)], op: osis_crdt::Op::Set(s("edited")) }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(10);
    // a writer about to go, not told it has: its write is un-merged past T
    let x = lp.peers[2].engine.me();
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("late")] } }).unwrap();
    let bad = lp.peers[2].commit(m).unwrap().unwrap();
    let pk = lp.peers[2].engine.package(&bad).unwrap().unwrap();
    let _ = lp.deliver(1, &pk);
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("late"), s("edited"), s("kept")])));
    lp.advance(2 * 3_600_000);
    lp.peers[1].tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("late"), s("edited")])));
    let pk = lp.peers[0].engine.package(&d).unwrap().unwrap();
    let _ = lp.deliver(1, &pk);
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("edited")])), "un-merged");
}

// spec/crdt.md §4.7 (a snapshot carries the delta's list creations value-less, before and after T),
// spec/permissions.md §5.2: a snapshot from past T joins at a node before T still holding the body,
// whose valued copy wins: the element reads there until its own T.
#[test]
fn snapshot_past_expiry_beside_body_spec_crdt_4_7() {
    let k = ak("t:list.0");
    let mut lp = net(3, 0x7a16);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("hello")] } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.peers[1].clock.advance(3_600_000 + 1_000);
    lp.peers[2].clock.advance(3_600_000 - 1_000);
    lp.peers[1].tick().unwrap();
    let c = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    lp.peers[2].drain_events();
    let _ = lp.deliver(2, &pk);
    lp.peers[2].reexamine().unwrap();
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("hello")])));
    lp.peers[2].clock.advance(2_000);
    lp.peers[2].tick().unwrap();
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), None, "past its own T");
}

// spec/crdt.md §5.7 Live, §4.7: an expiring list element is a function of the commits held: another
// writer's edit in it arriving first or last, before or after T, reads and holds alike, and keeps it.
#[test]
fn list_element_expiry_in_any_order_spec_crdt_5_7() {
    let k = ak("t:list.0");
    let mut lp = net(2, 0x7a07);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("hello")] } }).unwrap();
    let put = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Index(0)], op: osis_crdt::Op::Set(s("edited")) }).unwrap();
    let edit = lp.peers[1].commit(m).unwrap().unwrap();
    let pks = packages(&mut lp, 1);
    let (a, b) = (pks.iter().find(|p| p.id == put).unwrap(), pks.iter().find(|p| p.id == edit).unwrap());
    let rest: Vec<_> = pks.iter().filter(|p| p.id != put && p.id != edit).collect();
    let mut digests = Vec::new();
    for (first, second, past) in [(a, b, false), (b, a, false), (a, b, true), (b, a, true)] {
        let mut p = osis_node::local_peer::Peer::new(0x7a08, lp.peers[1].engine.now()).unwrap();
        p.engine.set_syncing(t, true).unwrap();
        for x in &rest {
            let _ = p.engine.ingest(&x.bytes, x.blobs.clone());
        }
        let _ = p.engine.ingest(&first.bytes, first.blobs.clone());
        if past {
            p.clock.advance(2 * 3_600_000);
            p.tick().unwrap();
        }
        let _ = p.engine.ingest(&second.bytes, second.blobs.clone());
        if !past {
            assert_eq!(p.engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("edited")])));
            p.clock.advance(2 * 3_600_000);
            p.tick().unwrap();
        }
        assert_eq!(p.engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("edited")])), "past {past}");
        digests.push(p.engine.state_digest(&t, &k).unwrap());
    }
    assert!(digests.iter().all(|d| *d == digests[0]), "{digests:?}");
}

// spec/sync.md §7, spec/crdt.md §4.8: an edit into a removed entry is hidden, not dead, until a
// compacting writer's sweep: then its body goes under purge on replace and a snapshot carries
// neither its value nor the removed key.
#[test]
#[ignore = "issues/swept-hidden-write-uncoverable.md"]
fn repro_hidden_write_goes_at_compaction_spec_sync_7() {
    let k = ak("t:gonemap.0");
    let mut lp = net(2, 0x7a02);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let op = |lp: &mut LocalPeer, i: usize, path: Vec<osis_crdt::PathSeg>, op: osis_crdt::Op| {
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, osis_crdt::PathOp { path, op }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let key = || vec![osis_crdt::PathSeg::Key(s("SECRETKEY"))];
    op(&mut lp, 0, key(), osis_crdt::Op::Set(s("first")));
    lp.sync_all().unwrap();
    lp.advance(10);
    op(&mut lp, 0, vec![], osis_crdt::Op::Remove(s("SECRETKEY")));
    lp.advance(10);
    let edit = op(&mut lp, 1, key(), osis_crdt::Op::Set(s("HIDDENVAL")));
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &k).unwrap(), Some(Value::Map(Default::default())));
    let carries = |lp: &mut LocalPeer, what: &[u8]| {
        let c = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)).any(|b| b.windows(what.len()).any(|x| x == what))
    };
    assert!(!carries(&mut lp, b"HIDDENVAL"), "the value in a snapshot");
    assert!(!carries(&mut lp, b"SECRETKEY"), "the removed key in a snapshot");
    assert!(!lp.peers[0].engine.body_not_dropped(&edit, &t, &k), "the body covered");
    assert_eq!(lp.peers[0].engine.get(&t, &k).unwrap(), Some(Value::Map(Default::default())));
    // the sweep is an ordinary commit: another holder reads and drops alike
    lp.sync_all().unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&edit, &t, &k), "the body at another holder");
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::Map(Default::default())));
}

// spec/sync.md §7, spec/crdt.md §4.7: a purge of an edit hidden in a removed entry leaves no key.
#[test]
fn purged_hidden_edit_leaves_no_key_spec_sync_7() {
    let mut lp = net(2, 0x7a03);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let carries = |lp: &mut LocalPeer, k: &osis_base::Ak, what: &[u8]| {
        let c = lp.peers[0].engine.snapshot(&t, k).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)).any(|b| b.windows(what.len()).any(|x| x == what))
    };
    let gk = ak("t:gonemap.0");
    let op = |lp: &mut LocalPeer, i: usize, path: Vec<osis_crdt::PathSeg>, op: osis_crdt::Op| {
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, osis_crdt::PathOp { path, op }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let key = || vec![osis_crdt::PathSeg::Key(s("KEYTWO"))];
    op(&mut lp, 0, key(), osis_crdt::Op::Set(s("first")));
    lp.sync_all().unwrap();
    lp.advance(10);
    op(&mut lp, 0, vec![], osis_crdt::Op::Remove(s("KEYTWO")));
    lp.advance(10);
    let edit = op(&mut lp, 1, key(), osis_crdt::Op::Set(s("second")));
    lp.sync_all().unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Commit { commit: edit, tid: t, ak: gk.clone() });
    m.set(t, &REG, &s("beside")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert!(!carries(&mut lp, &gk, b"KEYTWO"), "the key after a purge of the edit");
}

// spec/sync.md §7: a sweep comes once for an edit hidden in a removed entry of text and not at all
// for the removal alone: a compaction does not write forever.
#[test]
fn sweep_of_removed_text_entry_ends_spec_sync_7() {
    let k = ak("t:docs.0");
    let mut lp = net(2, 0x7a17);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let key = || vec![osis_crdt::PathSeg::Key(s("k"))];
    let op = |lp: &mut LocalPeer, i: usize, path: Vec<osis_crdt::PathSeg>, op: osis_crdt::Op| {
        let mut m = Mutation::new();
        m.op(t, &DOCS, osis_crdt::PathOp { path, op }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap();
    };
    op(&mut lp, 0, key(), osis_crdt::Op::Set(s("hello")));
    lp.sync_all().unwrap();
    lp.advance(10);
    let grew = |lp: &mut LocalPeer, i: usize| {
        let n = lp.peers[i].engine.commit_ids().len();
        lp.peers[i].engine.snapshot(&t, &k).unwrap().unwrap();
        lp.peers[i].engine.commit_ids().len() - n
    };
    op(&mut lp, 0, vec![], osis_crdt::Op::Remove(s("k")));
    assert_eq!(grew(&mut lp, 0), 1, "the removal alone: the snapshot, no sweep");
    lp.advance(10);
    op(&mut lp, 1, key(), osis_crdt::Op::Set(s("hello there")));
    lp.sync_all().unwrap();
    lp.advance(10);
    assert_eq!(grew(&mut lp, 0), 2, "a sweep and the snapshot");
    lp.sync_all().unwrap();
    for i in [0, 1, 0] {
        lp.advance(10);
        assert_eq!(grew(&mut lp, i), 1, "swept: the snapshot alone");
    }
}

// spec/sync.md §7: a record merely lacking its creation is no hidden one: a snapshot before the
// creation arrives leaves it, and the entry reads with the edit in it once it does.
#[test]
fn partial_receipt_survives_compaction_spec_sync_7() {
    let k = ak("t:big.0");
    let mut lp = net(3, 0x7a04);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    writer(&mut lp, t, 2);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k"))], op: osis_crdt::Op::Set(s("first")) }).unwrap();
    let put = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k"))], op: osis_crdt::Op::Set(s("edited")) }).unwrap();
    let edit = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&edit).unwrap().unwrap();
    let _ = lp.deliver(2, &pk);
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::Map(Default::default())));
    let before = lp.peers[2].engine.commit_ids().len();
    lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    assert_eq!(lp.peers[2].engine.commit_ids().len(), before + 1, "the snapshot alone, no sweep");
    let pk = lp.peers[0].engine.package(&put).unwrap().unwrap();
    let _ = lp.deliver(2, &pk);
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::Map([(s("k"), s("edited"))].into_iter().collect())));
}


// spec/crdt.md §4.2, §5.6: a removed or reset text entry's records go with their writes, so a
// snapshot never carries the removed key (a removal, a map `replace`, `remove_aspect`).
#[test]
fn removed_text_entry_key_goes_spec_crdt_5_6() {
    for reset in [None, Some(osis_crdt::Op::Replace(Value::Map(Default::default()))), Some(osis_crdt::Op::RemoveAspect)] {
        let k = ak("t:docs.0");
        let mut lp = net(1, 0x7a18);
        let t = new_thing(&mut lp, 0);
        let mut m = Mutation::new();
        m.op(t, &DOCS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("SECRETKEY"))], op: osis_crdt::Op::Set(s("hello")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        let op = reset.clone().unwrap_or_else(|| osis_crdt::Op::Remove(s("SECRETKEY")));
        m.op(t, &DOCS, osis_crdt::PathOp { path: vec![], op }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let c = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(!std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)).any(|b| b.windows(9).any(|x| x == b"SECRETKEY")), "{reset:?}");
    }
}

// spec/crdt.md §4.7, §5.7 Live: a snapshot written before T carries the element's creation value-less,
// so a node holding only it, past T and with no way to get the expired commit, reads as a node that
// held the commit: others' writes in the element show at both.
#[test]
fn list_element_in_snapshot_before_expiry_reads_alike_spec_crdt_5_7() {
    let k = ak("t:listtext.0");
    let mut lp = net(3, 0x7a15);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &LISTTEXT, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("abc")] } }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &LISTTEXT, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Index(0)], op: osis_crdt::Op::Set(s("abcX")) }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(10);
    let snap = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks = packages(&mut lp, 1);
    let held: Vec<_> = pks.iter().filter(|p| p.id != c && (p.id == snap || lp.peers[1].engine.header(&p.id).is_some_and(|h| !h.aspects.iter().any(|a| a.ak == k)))).collect();
    for pk in held {
        let _ = lp.deliver(2, pk);
    }
    lp.advance(2 * 3_600_000);
    for i in [1, 2] {
        lp.peers[i].tick().unwrap();
    }
    let held = lp.peers[1].engine.get(&t, &k).unwrap();
    assert_eq!(held, Some(Value::List(vec![s("X")])), "the other writer's char shows");
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), held);
}

