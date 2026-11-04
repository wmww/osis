#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Re-examination of pending commits (`apply/waits.rs`): what `reexamine` leaves out must wait
//! for the same reason as a full examination would say (spec/commits.md §4).

use crate::common;
use common::*;
use osis_commit::CommitBlob;
use osis_base::{Tid, Value, WallMs};
use osis_node::local_peer::LocalPeer;
use osis_node::{Ingested, Mutation, Reason};
use osis_schema::{Bound, PurgeBy, Retention};

fn only(bytes: &[u8], h: &osis_commit::Header, keep: impl Fn(Tid, &str) -> bool) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].tid, h.aspects[p.ai].ak.as_str()));
    b.encode()
}

// spec/commits.md §4: a commit waiting for deltas, then a thing of it whose `created.0` is
// unknown starts syncing: it waits for that record now (examined in full, not only its
// missing deltas).
#[test]
fn syncing_on_reexamines_in_full_spec_commits_4() {
    let mut lp = net(2, 26);
    let t = new_thing(&mut lp, 0);
    let u = new_thing(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    for p in &pks[..3] {
        lp.deliver(1, p).unwrap();
    }
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    let partial = only(&pk.bytes, &h, |x, a| x == t && a == "t:reg.0");
    let r = lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.peers[1].engine.set_syncing(u, true).unwrap();
    // another reexamine: the debug check examines the skipped commit
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(id, Reason::UnknownCreated(u))]);
}

// spec/commits.md §4; spec/crdt.md §2.2: a delta wait examined at a later clock than
// `reexamine` last looked; the clock goes back: the commit is more than MAX_DRIFT ahead again.
#[test]
fn clock_back_after_ingest_reexamines_spec_commits_4() {
    let mut lp = net(2, 27);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let t0 = lp.peers[1].engine.now().0;
    lp.peers[0].clock.advance(2 * 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    let partial = only(&pk.bytes, &h, |_, a| a == "t:reg.0");
    lp.peers[1].clock.advance(2 * 3_600_000);
    let r = lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.peers[1].clock.set(WallMs(t0 + 1_800_000));
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(id, Reason::Drift)]);
}

// spec/commits.md §4; spec/requirements.md, Scale (peer input never causes unbounded
// allocation): 1000 unsigned junk commits naming unknown authors pend, and what re-examination
// keeps of them stays small and bounded.
#[test]
fn junk_pending_waits_bounded_spec_commits_4() {
    let mut lp = net(2, 29);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("x")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    for i in 0..1000u32 {
        let mut b = CommitBlob::decode(&pk.bytes).unwrap();
        let mut a = [0u8; 15];
        a[..4].copy_from_slice(&i.to_be_bytes());
        a[4] = 0xee;
        b.header.author = Tid::from_bytes(a);
        let r = lp.peers[1].engine.ingest(&b.encode(), Vec::new()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(_))), "{r:?}");
    }
    assert_eq!(lp.peers[1].engine.pending().len(), 1000);
    let bytes = lp.peers[1].engine.waits_bytes();
    assert!(bytes <= 1000 * 512, "{bytes} B kept for 1000 junk commits");
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

fn at_most(rel: Option<u64>, abs: Option<u64>) -> Option<Retention> {
    Some(Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs, rel } })
}

fn reg_only(p: &osis_node::local_peer::Package) -> Vec<u8> {
    let b = CommitBlob::decode(&p.bytes).unwrap();
    let h = b.header.clone();
    only(&p.bytes, &h, |_, a| a == "t:reg.0")
}

// spec/commits.md §4 (a delta past its keep-at-most bound counts as held): c1's
// `k` projection and c2 at a node syncing t, c1's at-most-0 body deleted at hosts with no
// carrier: c1 applies; the body, should a copy still come, joins as a late part and drops on
// arrival, ending as a node that got c1 whole.
#[test]
fn part_past_at_most_counts_as_held_spec_commits_4() {
    let (mut lp, t, c) = carrierless(0x7c01, vec![mixed("x", Some("1"), None), mixed("y", None, None)]);
    let gone = ak("t:gone.0");
    let e = |lp: &mut LocalPeer| lp.peers[1].engine.pending();
    let r = lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.deliver(1, &c[1]).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert!(e(&mut lp).is_empty(), "{:?}", e(&mut lp));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("1")));
    assert_eq!(lp.peers[1].engine.get(&t, &gone).unwrap(), Some(s("y")));
    // the late copy: as at the writer
    lp.deliver(1, &c[0]).unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&c[0].id, &t, &gone), "dropped on arrival");
    assert_eq!(lp.peers[1].engine.state(&t, &gone).unwrap(), lp.peers[0].engine.state(&t, &gone).unwrap());
    assert_eq!(lp.peers[1].engine.state(&t, &ak("t:reg.0")).unwrap(), lp.peers[0].engine.state(&t, &ak("t:reg.0")).unwrap());
}

// spec/commits.md §4: with no later commit on the aspect nothing shows the delta could have left
// (its write is live, or dead by a commit not here yet): it waits at any clock, also under at
// most 0. So a keep at most alone never releases a live part still on its way.
#[test]
fn live_part_keeps_waiting_spec_commits_4() {
    let (mut lp, t, c) = carrierless(0x7c02, vec![mixed("x", Some("1"), at_most(Some(0), None))]);
    lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
    lp.peers[1].clock.advance(30 * 24 * 3_600_000);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)]);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")));
    // the part arrives: applied whole
    lp.deliver(1, &c[0]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:gone.0")).unwrap(), Some(s("x")));
}

// spec/commits.md §4, §5 (D after replaced): the bound counts from the earliest later commit
// held, on this node's clock: before it the part waits, past it the commit applies (a tick is
// enough: the wait wakes at the bound). A clock behind the writer's only waits longer.
#[test]
fn part_waits_for_relative_bound_spec_commits_4() {
    const D: u64 = 600_000;
    let (mut lp, t, c) = carrierless(0x7c03, vec![mixed("x", Some("1"), at_most(Some(D), None)), mixed("y", None, at_most(Some(D), None))]);
    lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
    lp.deliver(1, &c[1]).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)], "before the bound");
    let bound = lp.peers[1].engine.header(&c[1].id).unwrap().ts.wall_ms().0 + D;
    lp.peers[1].clock.set(WallMs(bound - 1));
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)], "just before the bound");
    lp.peers[1].clock.set(WallMs(bound));
    lp.peers[1].engine.tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "at the bound");
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("1")));
    // a clock going back unapplies nothing
    lp.peers[1].clock.set(WallMs(bound - 1));
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("1")));
}

// spec/commits.md §4, §5 (an absolute keep at most): T passing alone shows nothing, the part is
// live or its killer is yet to come, and a live body leaves only with a carrier. With a later commit
// on the aspect it counts from T on this node's clock. A copy arriving later joins, as at the writer.
#[test]
fn part_past_absolute_bound_spec_commits_4() {
    let t_abs = T0.0 + 3_600_000;
    let (mut lp, t, c) = carrierless(0x7c04, vec![mixed("x", Some("1"), at_most(None, Some(t_abs))), mixed("y", None, None)]);
    let gone = ak("t:gone.0");
    lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
    lp.peers[1].clock.set(WallMs(t_abs + 1));
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)], "past T, nothing later here");
    lp.peers[1].clock.set(WallMs(T0.0 + 1_000));
    lp.deliver(1, &c[1]).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)], "a later commit, its clock before T");
    lp.peers[1].clock.set(WallMs(t_abs));
    lp.peers[1].engine.tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("1")));
    lp.deliver(1, &c[0]).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &gone).unwrap(), Some(s("y")));
    assert_eq!(lp.peers[1].engine.state(&t, &gone).unwrap(), lp.peers[0].engine.state(&t, &gone).unwrap());
    assert_eq!(lp.peers[1].engine.state(&t, &ak("t:reg.0")).unwrap(), lp.peers[0].engine.state(&t, &ak("t:reg.0")).unwrap());
}

// spec/commits.md §4, §5: the rule loosens atomic wait for a commit's own author only as far as
// writing the parts apart would: a commit whose author may not write gains nothing (its part stays
// invalid), and a later commit of any validity counts (validity may differ between nodes; a drop
// is final). Fixed retention has no keep at most, on the wire or off: a role-class part cannot use it.
#[test]
fn forged_at_most_class_gives_no_rights_spec_commits_4() {
    let mut lp = net(3, 0x7c05);
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[2].engine.tid();
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
    mixed("forged", Some("forged"), at_most(Some(0), None))(&mut m, t);
    let forged = lp.peers[2].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 2).into_iter().find(|p| p.id == forged).unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    mixed("later", None, None)(&mut m, t);
    let later = lp.peers[2].commit(m).unwrap().unwrap();
    let pl = packages(&mut lp, 2).into_iter().find(|p| p.id == later).unwrap();
    lp.peers[1].engine.ingest(&reg_only(&pk), Vec::new()).unwrap();
    lp.deliver(1, &pl).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")), "the part stays invalid");
    assert_eq!(e.get(&t, &ak("t:gone.0")).unwrap(), None, "so does the later write");
    assert!(osis_commit::retention::fixed_retention("roles.0").is_some_and(|r| r.at_most.abs.is_none() && r.at_most.rel.is_none()));
}

// spec/commits.md §4; `apply/waits.rs`: a later commit whose part on the aspect is not held (its
// own part counts as held, expired) writes no receipt there, and still wakes the wait (the debug
// check would panic on the stale answer).
#[test]
fn later_commit_without_part_wakes_wait_spec_commits_4() {
    let t_exp = T0.0 + 60_000;
    let expiring: Mutate = Box::new(move |m, t| {
        m.set(t, &GONE, &s("y")).unwrap();
        m.expires(t, &GONE, WallMs(t_exp)).unwrap();
        m.set(t, &REG, &s("2")).unwrap();
    });
    let (mut lp, t, c) = carrierless(0x7c07, vec![mixed("x", Some("1"), at_most(Some(0), None)), expiring]);
    lp.peers[1].clock.set(WallMs(t_exp + 1));
    lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)]);
    lp.peers[1].engine.ingest(&reg_only(&c[1]), Vec::new()).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("2")));
}

// spec/crdt.md §8 (a frontier reaches only writes the fragment reflects), spec/commits.md §4: a
// node that applied a commit without a live part and then snapshots the aspect claims nothing
// of that part, so its snapshot does not cover the body and the body still joins when it comes.
#[test]
fn snapshot_after_release_leaves_part_to_join_spec_crdt_8() {
    let map = ak("t:gonemap.0");
    let put = |k: &'static str, reg: Option<&'static str>| -> Mutate {
        Box::new(move |m, t| {
            let map = ak("t:gonemap.0");
            m.retention(t, &map, at_most(Some(0), None).unwrap()).unwrap();
            m.op(t, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(s("v")) }).unwrap();
            if let Some(v) = reg {
                m.set(t, &REG, &s(v)).unwrap();
            }
        })
    };
    let (mut lp, t, c) = carrierless(0x7c08, vec![put("a", Some("1")), put("b", None)]);
    let w = lp.peers[1].engine.tid();
    let grant = set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
    let pg = packages(&mut lp, 0).into_iter().find(|p| p.id == grant).unwrap();
    lp.deliver(1, &pg).unwrap();
    let b = CommitBlob::decode(&c[0].bytes).unwrap();
    let h = b.header.clone();
    lp.peers[1].engine.ingest(&only(&c[0].bytes, &h, |_, a| a == "t:reg.0"), Vec::new()).unwrap();
    lp.deliver(1, &c[1]).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.pending().is_empty(), "released by c2: {:?}", e.pending());
    let snap = e.snapshot(&t, &map).unwrap().unwrap();
    assert_eq!(e.covered(&snap, &c[0].id, &t, &map).unwrap(), Some(false), "the snapshot lacks the part's write");
    assert_eq!(e.covered(&snap, &c[1].id, &t, &map).unwrap(), Some(true), "c2 is in the snapshot, though the frontier stops at the gap");
    lp.deliver(1, &c[0]).unwrap();
    let want = lp.peers[0].engine.get(&t, &map).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &map).unwrap(), want, "the part joined");
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
    let w = lp.peers[to].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
    sync(lp, 0, to);
}

/// Two writers' history under keep at most and expiry on `t` (each commit also writing `t:reg.0`
/// sometimes, so it is two bodies), then two more writers: `w` given all of it, `g` given it in
/// another order with some of those bodies held back, both snapshotting and dropping what their
/// snapshots cover on the way, then each given the other's snapshots and `g` the bodies held back.
/// Whatever the frontiers stopped at, `g` ends as `w` reads and states, nothing pending.
fn gap_snapshot_check(seed: u64, len: u64, expiring: bool) -> Result<(), String> {
    let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let mut lp = net(4, seed);
    let t = new_thing(&mut lp, 0);
    for (from, to) in [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3), (3, 2), (2, 1), (3, 1)] {
        sync(&mut lp, from, to);
    }
    for i in 1..4 {
        writer(&mut lp, t, i);
    }
    for (from, to) in [(1, 0), (2, 0), (3, 0), (1, 2), (1, 3), (2, 3), (3, 2), (2, 1), (3, 1)] {
        sync(&mut lp, from, to);
    }
    let (g, w) = (2, 3);
    lp.peers[g].engine.set_syncing(t, true).unwrap();
    lp.peers[w].engine.set_syncing(t, true).unwrap();
    let aspects = [ak("t:gone.0"), ak("t:gonemap.0"), ak("t:shortmap.0")];
    let mut packs = Vec::new();
    for _ in 0..len {
        let by = below(2) as usize;
        lp.peers[by].clock.advance(1 + below(50));
        let (a, key, val) = (below(3) as usize, format!("k{}", below(3)), format!("v{}", below(1 << 20)));
        // an expiring put shares keys with the others: a write under its entry goes with it at T
        // (spec/crdt.md §5.6 Live)
        let expires = expiring && a > 0 && below(3) == 0;
        let mut m = Mutation::new();
        let op = if a == 0 || expires || below(4) > 0 { osis_crdt::PathOp { path: if a == 0 { vec![] } else { vec![osis_crdt::PathSeg::Key(s(&key))] }, op: osis_crdt::Op::Set(s(&val)) } } else { osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(s(&key)) } };
        m.retention(t, &aspects[a], at_most(Some(if a == 2 { 600_000 } else { 0 }), None).unwrap()).unwrap();
        m.op(t, &aspects[a], op).unwrap();
        if expires {
            let now = lp.peers[by].engine.now().0;
            m.expires(t, &aspects[a], WallMs(now + 3_600_000)).unwrap();
        }
        if below(2) == 0 {
            m.set(t, &REG, &s(&val)).unwrap();
        }
        if let Ok(Some(id)) = lp.peers[by].commit(m) {
            packs.push(packages(&mut lp, by).into_iter().find(|p| p.id == id).unwrap());
        }
        if below(4) == 0 {
            sync(&mut lp, by, 1 - by);
        }
    }
    let mut order: Vec<usize> = (0..packs.len()).collect();
    let shuffle = |o: &mut Vec<usize>, below: &mut dyn FnMut(u64) -> u64| {
        for x in (1..o.len()).rev() {
            o.swap(x, below(x as u64 + 1) as usize);
        }
    };
    let mut sent = [Vec::new(), Vec::new()];
    // half the runs without `w`'s snapshots, which would give `g` what it lost
    let w_snapshots = below(2) == 0;
    // past every write of the history: a bound counted from a later commit has passed (under D
    // of 10 min not yet)
    for p in [g, w] {
        lp.peers[p].clock.advance(len * 60);
    }
    // half the runs in the order written: a frontier reaches a part only past all before it
    let written = below(2) == 0;
    for (who, peer) in [g, w].into_iter().enumerate() {
        if !written {
            shuffle(&mut order, &mut below);
        }
        for &i in &order {
            let pk = &packs[i];
            let b = CommitBlob::decode(&pk.bytes).unwrap();
            let bytes = if who == 0 && b.parts.len() > 1 && below(2) == 0 { only(&pk.bytes, &b.header, |_, a| a == "t:reg.0") } else { pk.bytes.clone() };
            let _ = lp.peers[peer].engine.ingest(&bytes, pk.blobs.clone());
            let _ = lp.peers[peer].engine.reexamine();
            if (who == 0 || w_snapshots) && below(4) == 0 {
                let a = &aspects[1 + below(2) as usize];
                if let Ok(Some(id)) = lp.peers[peer].engine.snapshot(&t, a) {
                    sent[who].push((a.clone(), id, packages(&mut lp, peer).into_iter().find(|p| p.id == id).unwrap()));
                    drop_covered_by(&mut lp.peers[peer].engine, &id, &t, a);
                }
            }
        }
    }
    for (who, peer) in [g, w].into_iter().enumerate() {
        for (a, id, pk) in &sent[1 - who] {
            let _ = lp.peers[peer].engine.ingest(&pk.bytes, pk.blobs.clone());
            if below(2) == 0 {
                drop_covered_by(&mut lp.peers[peer].engine, id, &t, a);
            }
        }
    }
    shuffle(&mut order, &mut below);
    for &i in &order {
        let _ = lp.peers[g].engine.ingest(&packs[i].bytes, packs[i].blobs.clone());
    }
    let _ = lp.peers[g].engine.reexamine();
    for at in [0, 2 * 3_600_000] {
        for p in [g, w] {
            if at > 0 {
                lp.peers[p].clock.advance(at);
            }
            lp.peers[p].engine.tick().unwrap();
            let pending = lp.peers[p].engine.pending();
            if !pending.is_empty() {
                return Err(format!("peer {p} pends {pending:?}"));
            }
        }
        for a in aspects.iter().chain([&ak("t:reg.0")]) {
            let (x, y) = (lp.peers[g].engine.get(&t, a).unwrap(), lp.peers[w].engine.get(&t, a).unwrap());
            if x != y {
                return Err(format!("{a:?} reads differ, {at} ms on: {x:?} vs {y:?}"));
            }
            let (x, y) = (lp.peers[g].engine.state(&t, a).unwrap(), lp.peers[w].engine.state(&t, a).unwrap());
            if x != y {
                return Err(format!("{a:?} states differ, {at} ms on: {x:?}\nvs {y:?}"));
            }
        }
    }
    Ok(())
}

fn gap_snapshot_run(name: &str, seeds: std::ops::Range<u64>, len: u64) {
    let seeds: Vec<u64> = seeds.collect();
    let run = |seed: u64| osis_base::testenv::caught(|| [false, true].into_iter().try_for_each(|x| gap_snapshot_check(seed, len, x))).map_err(|e| format!("seed {seed} ({name}): {e}"));
    let fails: Vec<String> = osis_base::testenv::par_map(&seeds, osis_base::testenv::threads("OSIS_ORDER_THREADS").min(seeds.len()).max(1), run).into_iter().filter_map(Result::err).collect();
    assert!(fails.is_empty(), "{} failing:\n{}", fails.len(), fails.join("\n\n"));
}

// spec/crdt.md §8 (a frontier reaches only writes the fragment reflects), spec/commits.md §4 (a
// part counted as held joins on arrival, or never): `gap_snapshot_check`.
#[test]
fn gap_snapshots_converge_spec_crdt_8() {
    gap_snapshot_run("gap_snapshots_converge_spec_crdt_8", 0..4, 14);
}

// The same over more histories, longer.
#[test]
#[ignore = "tier 2"]
fn gap_snapshots_converge_large_spec_crdt_8() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", 1000..1300);
    gap_snapshot_run("gap_snapshots_converge_large_spec_crdt_8", seeds.range, 30);
}

// spec/commits.md §4: a commit whose part under a keep at most a node never gets waits with nothing
// on the aspect as late, an earlier-stamped commit there not counting, and goes at the aspect's
// next write.
#[test]
fn missing_part_waits_for_a_later_commit_spec_commits_4() {
    let map = ak("t:map.0");
    let r = at_most(Some(0), None).unwrap();
    let mut lp = net(3, 0x7e06);
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
    let mut m = Mutation::new();
    m.retention(t, &map, r).unwrap();
    m.op(t, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k"))], op: osis_crdt::Op::Set(item("x", 1)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    for (from, to) in [(0, 1), (0, 2), (1, 2)] {
        sync(&mut lp, from, to);
    }
    lp.peers[2].engine.set_syncing(t, true).unwrap();
    lp.peers[1].clock.advance(60_000);
    let mut m = Mutation::new();
    m.retention(t, &map, r).unwrap();
    m.op(t, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k")), osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Set(Value::Int(9)) }).unwrap();
    m.set(t, &REG, &s("b")).unwrap();
    let c1 = lp.peers[1].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.retention(t, &map, r).unwrap();
    m.op(t, &map, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(s("k")) }).unwrap();
    let c2 = lp.peers[0].commit(m).unwrap().unwrap();
    let p1 = packages(&mut lp, 1).into_iter().find(|p| p.id == c1).unwrap();
    let p2 = packages(&mut lp, 0).into_iter().find(|p| p.id == c2).unwrap();
    assert!(lp.peers[0].engine.header(&c2).unwrap().ts < lp.peers[1].engine.header(&c1).unwrap().ts);
    lp.peers[2].engine.ingest(&reg_only(&p1), Vec::new()).unwrap();
    lp.peers[2].engine.ingest(&p2.bytes, p2.blobs.clone()).unwrap();
    lp.peers[2].clock.advance(30 * 24 * 3_600_000);
    lp.peers[2].engine.tick().unwrap();
    assert_eq!(lp.peers[2].engine.pending(), vec![(c1, Reason::WaitDeltas)]);
    lp.peers[0].clock.advance(120_000);
    let mut m = Mutation::new();
    m.retention(t, &map, r).unwrap();
    m.op(t, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("j"))], op: osis_crdt::Op::Set(item("y", 2)) }).unwrap();
    let c3 = lp.peers[0].commit(m).unwrap().unwrap();
    let p3 = packages(&mut lp, 0).into_iter().find(|p| p.id == c3).unwrap();
    lp.peers[2].engine.ingest(&p3.bytes, p3.blobs.clone()).unwrap();
    lp.peers[2].engine.reexamine().unwrap();
    assert!(lp.peers[2].engine.pending().is_empty(), "{:?}", lp.peers[2].engine.pending());
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
            m.retention(t, &map, at_most(Some(0), None).unwrap()).unwrap();
            if exp {
                m.expires(t, &map, WallMs(far)).unwrap();
            }
            m.op(t, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(s("v")) }).unwrap();
            if reg {
                m.set(t, &REG, &s("1")).unwrap();
            }
        })
    };
    for holders in [true, false] {
        let map = ak("t:gonemap.0");
        let (mut lp, t, c) = carrierless(0x7e01, vec![put("a", true, true), put("b", false, false)]);
        let w = lp.peers[1].engine.tid();
        let grant = set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
        let pg = packages(&mut lp, 0).into_iter().find(|p| p.id == grant).unwrap();
        lp.deliver(1, &pg).unwrap();
        let held = holders.then(|| {
            let id = lp.peers[0].engine.snapshot(&t, &map).unwrap().unwrap();
            packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap()
        });
        lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
        lp.deliver(1, &c[1]).unwrap();
        if let Some(p) = &held {
            lp.deliver(1, p).unwrap();
        }
        lp.peers[1].engine.reexamine().unwrap();
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

// spec/crdt.md §4.7, §5.6 Live (was issues/expired-entry-key-kept.md): a map entry an expiring
// delta created goes at T with another writer's later write of the same key inside it, whatever
// the arrival order and under keep at most 0 (the expiry and the bound fall due at one instant:
// two timers, `records::timer_key`).
#[test]
fn expired_entry_goes_with_nested_write_alike_spec_crdt_4_7() {
    let map = ak("t:gonemap.0");
    let r = at_most(Some(0), None).unwrap();
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
    let p2 = packages(&mut lp, 1).into_iter().find(|p| p.id == c2).unwrap();
    lp.deliver(2, &p1).unwrap();
    lp.deliver(2, &p2).unwrap();
    lp.deliver(3, &p2).unwrap();
    lp.deliver(3, &p1).unwrap();
    for p in [2, 3] {
        lp.peers[p].clock.advance(2 * 3_600_000);
        lp.peers[p].engine.tick().unwrap();
    }
    assert_eq!(lp.peers[2].engine.get(&t, &map).unwrap(), lp.peers[3].engine.get(&t, &map).unwrap());
    assert_eq!(lp.peers[2].engine.get(&t, &map).unwrap(), Some(osis_base::Value::Map(Default::default())), "the key went with its entry");
}

// spec/commits.md §4: a commit's parts on two things, both records away: kept (a first sync of
// such commits costs no examination per applied commit), and either record's arrival wakes it.
#[test]
fn parts_waiting_on_two_records_are_kept_spec_commits_4() {
    for first in [0, 1] {
        let mut lp = net(2, 28);
        let k = new_thing(&mut lp, 0);
        sync(&mut lp, 0, 1);
        let known: std::collections::BTreeSet<_> = packages(&mut lp, 0).iter().map(|p| p.id).collect();
        let things = [new_thing(&mut lp, 0), new_thing(&mut lp, 0)];
        let records: Vec<Vec<_>> = {
            let made: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !known.contains(&p.id)).collect();
            things.iter().map(|t| made.iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.aspects.iter().any(|a| a.tid == *t))).cloned().collect()).collect()
        };
        let mut m = Mutation::new();
        m.set(things[0], &REG, &s("a")).unwrap();
        m.set(things[1], &REG, &s("b")).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
        let e = &mut lp.peers[1].engine;
        let before = e.waits_bytes();
        assert!(matches!(e.ingest(&pk.bytes, pk.blobs.clone()).unwrap(), Ingested::Pending(..)));
        assert!(e.waits_bytes() > before, "kept");
        for r in &records[first] {
            e.ingest(&r.bytes, r.blobs.clone()).unwrap();
        }
        // the debug check examines what is left out, and the arrived record's part applies
        e.tick().unwrap();
        assert_eq!(e.get(&things[first], &ak("t:reg.0")).unwrap(), Some(s(["a", "b"][first])));
        assert_eq!(e.get(&things[1 - first], &ak("t:reg.0")).unwrap(), None);
        assert!(e.pending().iter().any(|x| x.0 == id));
        for r in &records[1 - first] {
            e.ingest(&r.bytes, r.blobs.clone()).unwrap();
        }
        e.tick().unwrap();
        assert_eq!(e.get(&things[1 - first], &ak("t:reg.0")).unwrap(), Some(s(["a", "b"][1 - first])));
        assert!(e.pending().is_empty(), "{:?} {k:?}", e.pending());
    }
}

// spec/commits.md §4: what a node syncs follows the `group.0` it holds at once, with no pass in
// between: a wait for a thing leaving the synced group ends, one for a thing entering it starts.
#[test]
fn sync_set_follows_held_group_spec_commits_4() {
    let mut lp = net(2, 88);
    let (g, t, u) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let group = |items: &[Tid]| osis_schema::core_types::Group { items: items.iter().copied().collect(), subgroups: Default::default() };
    let mut m = Mutation::new();
    m.set(g, &osis_schema::core_types::GROUP, &group(&[t, u])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(g, true).unwrap();
    assert!(lp.peers[1].engine.core.syncs(&u));
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    let partial = only(&pk.bytes, &h, |x, _| x == t);
    let r = lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    // the group lets `u` go: nothing here syncs it now, so its part is no longer waited for
    lp.peers[0].clock.advance(10);
    let mut m = Mutation::new();
    m.set(g, &osis_schema::core_types::GROUP, &group(&[t])).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk2 = packages(&mut lp, 0).into_iter().find(|p| p.id == c).unwrap();
    lp.deliver(1, &pk2).unwrap();
    assert!(!lp.peers[1].engine.core.syncs(&u));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
}

// spec/commits.md §4: a creation record applies alone, synced or not: whichever the node learned
// first, the thing's next commit shows, and the part away holds only its own commit.
#[test]
fn creation_record_applies_alone_spec_commits_4() {
    for (seed, sync_first) in [(89, true), (90, false)] {
        let mut lp = net(2, seed);
        let mut m = Mutation::new();
        let me = lp.peers[0].engine.tid();
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

// spec/commits.md §4: a creation record applied alone holds nothing back for the commit's other
// things: the commit still waits whole for a synced thing's part.
#[test]
fn creation_record_alone_keeps_the_wait_spec_commits_4() {
    let mut lp = net(2, 91);
    let u = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.tid();
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
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), None, "the synced thing's part is away");
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")));
    assert_eq!(e.get(&u, &ak("t:reg.0")).unwrap(), Some(s("u")));
    assert!(e.pending().is_empty(), "{:?}", e.pending());
}

// spec/commits.md §4 (a part's wait is its thing's): a page away holds the thing's other part,
// synced or not.
#[test]
fn pages_away_hold_the_things_other_part_spec_commits_4() {
    let map: std::collections::BTreeMap<Value, Value> = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
    for (seed, synced) in [(92, false), (93, true)] {
        let mut lp = net(2, seed);
        let t = new_thing(&mut lp, 0);
        sync(&mut lp, 0, 1);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("r")).unwrap();
        m.set(t, &BIG, &Value::Map(map.clone())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
        assert!(!pk.blobs.is_empty(), "paged");
        let e = &mut lp.peers[1].engine;
        if synced {
            e.set_syncing(t, true).unwrap();
        }
        let r = e.ingest(&pk.bytes, Vec::new()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::WaitBlobs)), "synced {synced}: {r:?}");
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")), "synced {synced}");
        e.put_blobs(pk.blobs.clone()).unwrap();
        e.reexamine().unwrap();
        assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
        assert!(e.pending().is_empty(), "{:?}", e.pending());
    }
}

// spec/commits.md §4 (the exception, issues/sync-learned-after-apply.md): a commit across things,
// one thing's part away. A node syncing that thing first holds the commit; one learning it after
// the other part applied shows that part. They agree once the part comes.
#[test]
fn cross_thing_learned_late_stays_until_the_part_comes_spec_commits_4() {
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
    assert_eq!(read(true), (Some(s("new")), Some(s("t")), Some(s("u"))));
    assert_eq!(read(false), (Some(s("t")), Some(s("t")), Some(s("u"))));
}

// spec/commits.md §4 (the stated limit): a writer of a synced group lists a thing the node never
// reads. A commit across it and a held thing waits whole for its part, until the listing goes.
#[test]
fn listed_thing_never_read_holds_a_commit_across_it_spec_commits_4() {
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
    let unlisted = write_group(&mut lp, &[t]);
    let pks = packages(&mut lp, 0);
    let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap();
    let e = &mut lp.peers[1].engine;
    e.ingest(&pk(&listed).bytes, Vec::new()).unwrap();
    e.ingest(&only(&pk(&id).bytes, &h, |x, _| x == t), Vec::new()).unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")), "waits whole");
    assert!(e.pending().iter().any(|(c, _)| *c == id));
    e.ingest(&pk(&unlisted).bytes, Vec::new()).unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")), "the listing gone");
    assert!(e.pending().is_empty(), "{:?}", e.pending());
}

// spec/commits.md §4: a commit no part of which is held (a pending part went at its expiry) waits
// for its other deltas synced or not: whether it is recorded applied reads no sync set.
#[test]
fn partless_commit_waits_for_its_deltas_unsynced_spec_commits_4() {
    for (seed, synced) in [(95, true), (96, false)] {
        let mut lp = net(2, seed);
        let t = new_thing(&mut lp, 0);
        sync(&mut lp, 0, 1);
        let now = lp.peers[0].engine.now().0;
        let mut m = Mutation::new();
        m.set(t, &REG, &s("r")).unwrap();
        m.expires(t, &REG, WallMs(now + 1_000)).unwrap();
        m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
        let e = &mut lp.peers[1].engine;
        if synced {
            e.set_syncing(t, true).unwrap();
        }
        let r = e.ingest(&only(&pk.bytes, &h, |_, a| a == "t:reg.0"), Vec::new()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
        lp.peers[1].clock.advance(2_000);
        let e = &mut lp.peers[1].engine;
        e.tick().unwrap();
        assert_eq!(e.pending(), vec![(id, Reason::WaitDeltas)], "synced {synced}");
        assert!(!e.commit_ids().contains(&id), "synced {synced}");
    }
}

// spec/commits.md §4: two things of a commit, each with a part held and a part away: one thing's
// part coming to count as held frees that thing's content though the other's still waits.
#[test]
fn one_things_wait_ending_frees_it_alone_spec_commits_4() {
    let mut lp = net(2, 97);
    let (t, u) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    sync(&mut lp, 0, 1);
    let now = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.set(t, &REG, &s("t")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    m.expires(t, &TAGS, WallMs(now + 1_000)).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    m.set(u, &TAGS, &Value::Set([s("b")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    let e = &mut lp.peers[1].engine;
    let r = e.ingest(&only(&pk.bytes, &h, |_, a| a == "t:reg.0"), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.peers[1].clock.advance(2_000);
    let e = &mut lp.peers[1].engine;
    e.tick().unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")));
    assert_ne!(e.get(&u, &ak("t:reg.0")).unwrap(), Some(s("u")));
    assert_eq!(e.pending(), vec![(id, Reason::WaitDeltas)]);
    e.ingest(&pk.bytes, Vec::new()).unwrap();
    assert_eq!(e.get(&u, &ak("t:reg.0")).unwrap(), Some(s("u")));
    assert!(e.pending().is_empty(), "{:?}", e.pending());
}

// spec/commits.md §4, apply/waits.rs: a part of an applied commit waiting for a delta is left out of
// `reexamine` as a whole commit's wait is: its wait ends with the delta's expiry, not by being
// examined each time anything applies.
#[test]
fn applied_commits_delta_wait_is_kept_spec_commits_4() {
    let mut lp = net(2, 98);
    let now = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.tid();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    m.expires(t, &TAGS, WallMs(now + 1_000)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pks = packages(&mut lp, 0);
    for pk in pks.iter().filter(|p| p.id != c) {
        lp.deliver(1, pk).unwrap();
    }
    let h = lp.peers[0].engine.header(&c).unwrap();
    let pk = pks.iter().find(|p| p.id == c).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&only(&pk.bytes, &h, |_, a| a != "t:tags.0"), Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), None, "its thing's other part is away");
    assert_eq!(e.pending(), vec![(c, Reason::WaitDeltas)]);
    assert!(e.waits_bytes() > 0, "the wait is kept");
    lp.peers[1].clock.advance(2_000);
    let e = &mut lp.peers[1].engine;
    e.tick().unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")), "the delta counts as held");
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
        p.engine.reexamine().unwrap();
        assert!(!p.engine.core.syncs(&u), "{seq:?}");
        assert!(p.engine.core.syncs(&t), "{seq:?}");
        assert_eq!(p.engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("t")), "{seq:?}");
        assert!(p.engine.pending().is_empty(), "{seq:?}: {:?}", p.engine.pending());
    }
}
