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
        // one expiry per commit (spec/commits.md §6)
        m.expires(t, &REG, WallMs(t_exp)).unwrap();
    });
    let (mut lp, t, c) = carrierless(0x7c07, vec![mixed("x", Some("1"), at_most(Some(0), None)), expiring]);
    lp.peers[1].clock.set(WallMs(t_exp + 1));
    lp.peers[1].engine.ingest(&reg_only(&c[0]), Vec::new()).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(c[0].id, Reason::WaitDeltas)]);
    lp.peers[1].engine.ingest(&reg_only(&c[1]), Vec::new()).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty(), "{:?}", lp.peers[1].engine.pending());
    // the later write expired with its commit, value-less, the winner (spec/crdt.md §4.7)
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), None);
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
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_ORDER_START", "OSIS_ORDER_SEEDS", osis_base::testenv::large(1000..1300));
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
// the expiry's timer alone is set, `judge_at_most`).
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
    let map: osis_base::ValueMap = (0..2000).map(|i| (Value::Str(format!("key {i:05}")), Value::Str("v".repeat(60)))).collect();
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

// spec/commits.md §4 (the limit in notes/whole-commits.md, Moved from the spec): a writer of a synced group lists a thing the node never
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

// spec/commits.md §4, apply/waits.rs: a part of an applied commit waiting for a delta is left out of
// `reexamine` as a whole commit's wait is: its wait ends with the delta's expiry, not by being
// examined each time anything applies.
#[test]
fn applied_commits_delta_wait_is_kept_spec_commits_4() {
    let mut lp = net(2, 98);
    let now = lp.peers[0].engine.now().0;
    // the records first: an expiring commit carries none (spec/commits.md §6); `u`'s part
    // applies the commit while `t`'s content waits
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.tid();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    let u = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    for (x, k) in [(t, &REG), (t, &TAGS), (u, &REG)] {
        m.expires(x, k, WallMs(now + 1_000)).unwrap();
    }
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
    // its wait ended at the delta's expiry, the commit's: its own part went value-less with it
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), None);
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

// spec/crdt.md §5.7 Live: an expiring list element whose content another write replaced whole goes at T.
#[test]
fn list_element_overwritten_goes_at_expiry_spec_crdt_5_7() {
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
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![])));
    lp.peers[1].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![])), "rebuilt");
    // past T, a snapshot carries the end of the element to a node without the expired commit
    lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks = packages(&mut lp, 1);
    let mut late = osis_node::local_peer::Peer::new(0x7a06, lp.peers[1].engine.now()).unwrap();
    late.engine.set_syncing(t, true).unwrap();
    for pk in &pks {
        let _ = late.engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert_eq!(late.engine.get(&t, &k).unwrap(), Some(Value::List(vec![])), "a late node");
}

// spec/crdt.md §4.7: a snapshot written before T carries no end of the element: a holder of the body
// reads it until T, whichever came first.
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
        lp.peers[i].engine.tick().unwrap();
        assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), Some(Value::List(vec![])), "peer {i} past T");
    }
}

// spec/crdt.md §4.7, §5.7 Live: a purge of a list element's creation ends the element whichever of
// the request, the creation and another writer's edit in it arrives first.
#[test]
fn purged_list_element_ends_in_any_order_spec_crdt_4_7() {
    let k = ak("t:list.0");
    let mut lp = net(3, 0x7a1b);
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
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
        assert_eq!(q.engine.get(&t, &k).unwrap(), Some(Value::List(vec![])));
        digests.push(q.engine.state_digest(&t, &k).unwrap());
    }
    assert!(digests.iter().all(|d| *d == digests[0]), "{digests:?}");
}

// spec/crdt.md §4.6, §5.7 Live: an un-merge past T rebuilds the state from the residue: the element
// stays ended, a third writer's edit in it hidden.
#[test]
fn list_element_end_survives_unmerge_spec_crdt_4_6() {
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
    let x = lp.peers[2].engine.tid();
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("late")] } }).unwrap();
    let bad = lp.peers[2].commit(m).unwrap().unwrap();
    let pk = lp.peers[2].engine.package(&bad).unwrap().unwrap();
    let _ = lp.deliver(1, &pk);
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("late"), s("edited"), s("kept")])));
    lp.advance(2 * 3_600_000);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("late")])));
    let pk = lp.peers[0].engine.package(&d).unwrap().unwrap();
    let _ = lp.deliver(1, &pk);
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::List(vec![])), "un-merged");
}

// spec/permissions.md §5.2, spec/crdt.md §4.7: the element's end a snapshot from past T carries is a
// value-less copy of an expiring creation, no misstatement at a node still holding the body.
#[test]
fn list_element_end_is_no_misstatement_spec_perm_5_2() {
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
    lp.peers[1].engine.tick().unwrap();
    let c = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    lp.peers[2].drain_events();
    let _ = lp.deliver(2, &pk);
    lp.peers[2].engine.reexamine().unwrap();
    let evs = lp.peers[2].drain_events();
    assert!(!evs.iter().any(|e| matches!(e, osis_node::Event::Diagnostic(x) if x.kind == osis_node::DiagnosticKind::Misstated)), "{evs:?}");
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::List(vec![])));
}

// spec/crdt.md §5.7 Live, §4.7: the end of an expiring list element is a function of the commits held:
// its edit arriving first or last, before or after T, reads and holds alike.
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
            p.engine.tick().unwrap();
        }
        let _ = p.engine.ingest(&second.bytes, second.blobs.clone());
        if !past {
            assert_eq!(p.engine.get(&t, &k).unwrap(), Some(Value::List(vec![s("edited")])));
            p.clock.advance(2 * 3_600_000);
            p.engine.tick().unwrap();
        }
        assert_eq!(p.engine.get(&t, &k).unwrap(), Some(Value::List(vec![])), "past {past}");
        digests.push(p.engine.state_digest(&t, &k).unwrap());
    }
    assert!(digests.iter().all(|d| *d == digests[0]), "{digests:?}");
}

// spec/sync.md §7, spec/crdt.md §4.8: an edit into a removed entry is hidden, not dead, until a
// compacting writer's sweep: then its body goes under keep at most 0 and a snapshot carries neither
// its value nor the removed key.
#[test]
fn hidden_write_goes_at_compaction_spec_sync_7() {
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
    assert!(!lp.peers[0].engine.body_not_dropped(&edit, &t, &k), "the body past its bound");
    assert_eq!(lp.peers[0].engine.get(&t, &k).unwrap(), Some(Value::Map(Default::default())));
    // the sweep is an ordinary commit: another holder reads and drops alike
    lp.sync_all().unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&edit, &t, &k), "the body at another holder");
    assert_eq!(lp.peers[1].engine.get(&t, &k).unwrap(), Some(Value::Map(Default::default())));
}

// spec/sync.md §7: an edit into an entry or element that expired is hidden the same way and goes the
// same way; a purge of a hidden edit leaves no key.
#[test]
fn hidden_write_in_expired_or_purged_goes_at_compaction_spec_sync_7() {
    let mut lp = net(2, 0x7a03);
    let t = new_thing(&mut lp, 0);
    writer(&mut lp, t, 1);
    lp.sync_all().unwrap();
    let carries = |lp: &mut LocalPeer, k: &osis_base::Ak, what: &[u8]| {
        let c = lp.peers[0].engine.snapshot(&t, k).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)).any(|b| b.windows(what.len()).any(|x| x == what))
    };
    // expired: a map entry and a list element, each edited by the other writer
    let (mk, lk) = (ak("t:big.0"), ak("t:list.0"));
    let mut m = Mutation::new();
    m.expires(t, &mk, WallMs(T0.0 + 3_600_000)).unwrap();
    m.expires(t, &lk, WallMs(T0.0 + 3_600_000)).unwrap();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("KEYONE"))], op: osis_crdt::Op::Set(s("x")) }).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("y")] } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &BIG, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("KEYONE"))], op: osis_crdt::Op::Set(s("MAPEDIT")) }).unwrap();
    m.op(t, &LIST, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Index(0)], op: osis_crdt::Op::Set(s("LISTEDIT")) }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(2 * 3_600_000);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &lk).unwrap(), Some(Value::List(vec![])));
    assert!(!carries(&mut lp, &mk, b"MAPEDIT"), "an edit of an expired entry");
    assert!(!carries(&mut lp, &mk, b"KEYONE"), "its key");
    assert!(!carries(&mut lp, &lk, b"LISTEDIT"), "an edit of an expired element");
    // purged: the key its record repeats goes
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

// spec/sync.md §7: a removed entry of text keeps bare anchors no reset takes, so a sweep comes once
// for an edit hidden in it and not at all for the removal alone: a compaction does not write forever.
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


// issues/removed-text-entry-keeps-key.md, spec/crdt.md §5.6: a removal leaves a text's bare anchors
// in the record that repeats the key, so a snapshot carries the removed key.
#[test]
#[ignore = "issues/removed-text-entry-keeps-key.md"]
fn removed_text_entry_key_goes_repro_spec_crdt_5_6() {
    let k = ak("t:docs.0");
    let mut lp = net(1, 0x7a18);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.op(t, &DOCS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("SECRETKEY"))], op: osis_crdt::Op::Set(s("hello")) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &DOCS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(s("SECRETKEY")) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let c = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(!std::iter::once(&pk.bytes).chain(pk.blobs.iter().map(|(_, b)| b)).any(|b| b.windows(9).any(|x| x == b"SECRETKEY")));
}

// issues/list-element-snapshot-before-expiry.md, spec/crdt.md §5.7 Live: a snapshot written before T
// cannot carry the element's end (a valued copy must beat it), so a node holding only it, past T and
// with no way to get the expired commit, shows others' writes in the element until a later snapshot.
#[test]
#[ignore = "issues/list-element-snapshot-before-expiry.md"]
fn list_element_in_snapshot_before_expiry_goes_repro_spec_crdt_5_7() {
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
    lp.peers[2].engine.tick().unwrap();
    assert_eq!(lp.peers[2].engine.get(&t, &k).unwrap(), Some(Value::List(vec![])));
}
