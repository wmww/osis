//! Signals without `+` (spec/data-model.md §2, spec/commits.md §5 Signals), at the engine: each
//! write is history from the moment it is written, never joined into a state, kept at least until
//! its keep bound, expiry or purge; a validity change rebuilds nothing.

use crate::common::*;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid};
use osis_commit::PurgeItem;
use osis_node::engine::listing::{CommitFrom, PartBody};
use osis_node::local_peer::LocalPeer;
use osis_node::{Event, Mutation};
use osis_schema::core_types::{self as ct};
use osis_schema::{Codec, History, Retention};
use std::collections::{BTreeMap, BTreeSet};

const HOUR: u64 = 3_600_000;

fn log() -> Ak {
    ak("t:log~0")
}

fn keep(until: Option<u64>, after: Option<u64>) -> Retention {
    Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::Keep { until, after }) }
}

/// Alice (0) is first admin of D; Bob (1) writes.
fn setup(seed: u64) -> (LocalPeer, Tid, [Tid; 2]) {
    let mut lp = net(2, seed);
    let ids = [0, 1].map(|i| lp.peers[i].engine.me());
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, d, ids)
}

fn send(lp: &mut LocalPeer, i: usize, d: Tid, r: Retention, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

fn body(lp: &mut LocalPeer, i: usize, d: Tid, c: &CommitId) -> PartBody {
    body_at(&mut lp.peers[i], d, c)
}

fn body_at(p: &mut osis_node::local_peer::Peer, d: Tid, c: &CommitId) -> PartBody {
    p.engine.held_part(&d, &log(), c, usize::MAX).unwrap().unwrap().body
}

// spec/data-model.md §2, spec/commits.md §5 Signals: never in state and never merged: concurrent
// writes each stay their own commit, the aspect reads absent, each is told as its commit
#[test]
fn signal_never_in_state_never_merged_spec_commits_5() {
    let (mut lp, d, _) = setup(1);
    let rx = listen(&mut lp.peers[0]);
    let r = keep(Some(osis_commit::FOREVER), None);
    let a = send(&mut lp, 0, d, r, "hi");
    let b = send(&mut lp, 1, d, r, "yo");
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.get(&d, &log()).unwrap(), None);
        assert!(!lp.peers[i].engine.aspects(&d).unwrap().contains(&log()));
        assert_eq!(body(&mut lp, i, d, &a), PartBody::Held(Some(s("hi"))));
        assert_eq!(body(&mut lp, i, d, &b), PartBody::Held(Some(s("yo"))));
        let (rows, _) = lp.peers[i].engine.held_parts(&d, &log(), CommitFrom::Oldest, 10, usize::MAX).unwrap();
        assert_eq!(rows.len(), 2);
    }
    let evs: Vec<Event> = rx.try_iter().collect();
    for e in &evs {
        if let Event::Applied { changed, .. } = e {
            assert!(!changed.iter().any(|(_, k)| *k == log()), "a signal changes no read");
        }
    }
    assert_eq!(told_in(&mut lp.peers[0], d, evs), held(&[(a, "hi"), (b, "yo")]));
    assert_eq!(lp.peers[0].engine.snapshot(&d, &log()).unwrap(), None, "nothing to compact");
}

// spec/commits.md §5 Signals: kept at least until its keep bound (D after written, or T); past it
// this engine drops it (a node may), also on receiving it past the bound, so nothing nobody
// promised to keep is kept for good; kept for good under forever
#[test]
fn signal_kept_until_its_bound_spec_commits_5() {
    let (mut lp, d, _) = setup(2);
    let t0 = lp.peers[0].engine.now().0;
    let d_after = send(&mut lp, 0, d, keep(None, Some(HOUR)), "d");
    let until = send(&mut lp, 0, d, keep(Some(t0 + 2 * HOUR), None), "t");
    let ever = send(&mut lp, 0, d, keep(Some(osis_commit::FOREVER), None), "f");
    lp.advance(HOUR - 10_000);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(body(&mut lp, 0, d, &d_after), PartBody::Held(Some(s("d"))));
    lp.advance(20_000);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(body(&mut lp, 0, d, &d_after), PartBody::Dropped);
    assert!(!lp.peers[0].engine.body_not_dropped(&d_after, &d, &log()));
    assert_eq!(body(&mut lp, 0, d, &until), PartBody::Held(Some(s("t"))));
    lp.advance(HOUR);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(body(&mut lp, 0, d, &until), PartBody::Dropped);
    // a node receiving them past the bound drops them on arrival
    sync(&mut lp, 0, 1);
    assert_eq!(body(&mut lp, 1, d, &until), PartBody::Dropped);
    assert_eq!(body(&mut lp, 1, d, &ever), PartBody::Held(Some(s("f"))));
    lp.advance(1000 * 24 * HOUR);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(body(&mut lp, 0, d, &ever), PartBody::Held(Some(s("f"))));
}

// spec/commits.md §5 Signals: a node that dropped a signal body past its keep bound does not take
// a copy offered again by a peer that still holds it (a node may keep it past the bound): the
// offer is a duplicate, changes nothing and tells no listener, so syncing settles; both nodes list
// the write alike, as dropped
#[test]
fn signal_dropped_past_its_bound_not_taken_again_spec_commits_5() {
    let (mut lp, d, _) = setup(8);
    let c = send(&mut lp, 0, d, keep(None, Some(HOUR)), "brief");
    lp.sync_all().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.advance(HOUR - 10_000);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(body(&mut lp, 1, d, &c), PartBody::Held(Some(s("brief"))), "kept at least to its bound");
    lp.advance(20_000);
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(body(&mut lp, 1, d, &c), PartBody::Dropped);
    // peer 0 has run no timer: it still holds the body past the bound, and lists it as dropped
    assert!(lp.peers[0].engine.body_not_dropped(&c, &d, &log()));
    let rows = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.held_parts(&d, &log(), CommitFrom::Oldest, 10, usize::MAX).unwrap().0;
    assert_eq!(rows(&mut lp, 0), rows(&mut lp, 1));
    assert_eq!(body(&mut lp, 0, d, &c), PartBody::Dropped);
    let rx = listen(&mut lp.peers[1]);
    for _ in 0..3 {
        let at = lp.peers[1].engine.point();
        let r = lp.deliver(1, &pk).unwrap();
        assert!(matches!(r, osis_node::Ingested::Duplicate(_)), "not taken: {r:?}");
        assert_eq!(lp.peers[1].engine.point(), at, "the offer changes nothing");
        assert!(!lp.peers[1].engine.body_not_dropped(&c, &d, &log()));
    }
    lp.sync_all().unwrap();
    assert!(!lp.peers[1].engine.body_not_dropped(&c, &d, &log()));
    assert!(told(&mut lp.peers[1], d, &rx).is_empty(), "no listener told again");
    assert_eq!(rows(&mut lp, 0), rows(&mut lp, 1));
}

// spec/commits.md §5 Signals, §6: expiry and purge act per write, before the keep bound
#[test]
fn signal_purge_and_expiry_per_write_spec_commits_5() {
    let (mut lp, d, ids) = setup(3);
    let r = keep(Some(osis_commit::FOREVER), None);
    let gone = send(&mut lp, 1, d, r, "oops");
    let kept = send(&mut lp, 1, d, r, "ok");
    let now = lp.peers[1].engine.now().0;
    let mut m = Mutation::new();
    m.retention(d, &log(), keep(None, Some(24 * HOUR))).unwrap();
    m.set(d, &log(), &s("brief")).unwrap();
    m.expires_all(osis_base::WallMs(now + HOUR));
    let brief = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
    m.purge(PurgeItem::Commit { commit: gone, tid: d, ak: log() });
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(2 * HOUR);
    lp.sync_all().unwrap();
    for i in 0..2 {
        lp.peers[i].engine.tick().unwrap();
        assert_eq!(body(&mut lp, i, d, &gone), PartBody::Purged(p));
        assert_eq!(body(&mut lp, i, d, &kept), PartBody::Held(Some(s("ok"))));
        assert_eq!(body(&mut lp, i, d, &brief), PartBody::Dropped);
    }
    let _ = ids;
}

// spec/commits.md §5 (signal keeps history), spec/crdt.md §4.6: a writer gives a signal keep
// history and one root set; a receiver drops a part on one keeping no history, or in a snapshot,
// alone. An undo writes nothing back for a signal (it reads absent before and after)
#[test]
fn signal_without_keep_history_refused_spec_commits_5() {
    let (mut lp, d, _) = setup(4);
    let mut m = Mutation::new();
    m.set(d, &log(), &s("x")).unwrap();
    assert!(matches!(lp.peers[0].commit(m), Err(osis_node::Error::Misuse(e)) if e.contains("keeps history")));
    let mut m = Mutation::new();
    m.retention(d, &log(), Retention { by: PurgeBy::Writer, history: Some(History::PurgeOnReplace) }).unwrap();
    m.set(d, &log(), &s("x")).unwrap();
    assert!(lp.peers[0].commit(m).is_err());
    let mut m = Mutation::new();
    m.retention(d, &log(), keep(Some(osis_commit::FOREVER), None)).unwrap();
    m.op(d, &log(), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("k"))], op: osis_crdt::Op::Set(s("x")) }).unwrap();
    assert!(matches!(lp.peers[0].commit(m), Err(osis_node::Error::Misuse(e)) if e.contains("one set at the root")));
    // a forged one: Bob's copy holds it, Alice drops the part on arrival, the commit stands
    let mut m = Mutation::new();
    m.set(d, &log(), &s("forged")).unwrap();
    m.set(d, &REG, &s("beside")).unwrap();
    m.retention(d, &REG, crate::common::kept_day()).unwrap();
    let f = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    assert!(!matches!(body(&mut lp, 0, d, &f), PartBody::Held(_)));
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("beside")));
    let c = send(&mut lp, 0, d, keep(Some(osis_commit::FOREVER), None), "sent");
    assert_eq!(lp.peers[0].engine.revert(&c).unwrap(), None, "nothing to undo");
    let mut m = Mutation::new();
    m.retention(d, &log(), keep(Some(osis_commit::FOREVER), None)).unwrap();
    m.set(d, &log(), &s("both")).unwrap();
    m.set(d, &REG, &s("undone")).unwrap();
    m.retention(d, &REG, crate::common::kept_day()).unwrap();
    let both = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].engine.revert(&both).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("beside")));
    assert_eq!(body(&mut lp, 0, d, &both), PartBody::Held(Some(s("both"))), "the signal stays in history");
}

/// Rebuilds a demotion of Bob runs at Alice once Bob wrote `n` signals and a value (`value`).
fn kick_rebuilds(seed: u64, n: usize, value: bool) -> (u64, LocalPeer, Tid, Vec<CommitId>) {
    let (mut lp, d, ids) = setup(seed);
    let r = keep(Some(osis_commit::FOREVER), None);
    let sent: Vec<CommitId> = (0..n).map(|k| send(&mut lp, 1, d, r, &format!("m{k}"))).collect();
    if value {
        let mut m = Mutation::new();
        m.set(d, &ak("t:val.0"), &s("v")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
    }
    lp.sync_all().unwrap();
    let before = lp.peers[0].engine.rebuilds();
    set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(ct::Frontier::default().to_value()));
    (lp.peers[0].engine.rebuilds() - before, lp, d, sent)
}

// spec/commits.md §5 Signals, spec/permissions.md §5.2: a kick re-judges which signal writes
// count without a rebuild, at any count of them; the same kick on a value rebuilds it
#[test]
fn signal_kick_rejudges_without_a_rebuild_spec_perm_5_2() {
    for n in [2, 20] {
        let (rebuilds, mut lp, d, sent) = kick_rebuilds(5, n, false);
        assert_eq!(rebuilds, 0, "{n} signals");
        for c in &sent {
            let e = lp.peers[0].engine.held_part(&d, &log(), c, usize::MAX).unwrap().unwrap();
            assert!(!e.valid);
            assert_eq!(e.body, PartBody::Dropped);
        }
        assert_eq!(lp.peers[0].engine.get(&d, &log()).unwrap(), None);
    }
    assert!(kick_rebuilds(6, 2, true).0 > 0);
}

/// A commit listener on `p` (`Engine::watch_commits`).
fn listen(p: &mut osis_node::local_peer::Peer) -> std::sync::mpsc::Receiver<Event> {
    p.engine.watch_commits();
    p.engine.subscribe()
}

/// The commits on `d`'s signal `evs` told of (`Event::Commits`, what `on_fire` delivers), each
/// as it reads now.
fn told_in(p: &mut osis_node::local_peer::Peer, d: Tid, evs: impl IntoIterator<Item = Event>) -> BTreeMap<CommitId, PartBody> {
    let ids: BTreeSet<CommitId> = evs
        .into_iter()
        .flat_map(|e| match e {
            Event::Commits(ch) => ch.iter().filter(|x| x.tid == d && x.ak == log()).map(|x| x.id).collect(),
            _ => Vec::new(),
        })
        .collect();
    ids.into_iter().map(|c| (c, body_at(p, d, &c))).collect()
}

fn told(p: &mut osis_node::local_peer::Peer, d: Tid, rx: &std::sync::mpsc::Receiver<Event>) -> BTreeMap<CommitId, PartBody> {
    let evs: Vec<Event> = rx.try_iter().collect();
    told_in(p, d, evs)
}

/// Entries held with these values.
fn held(xs: &[(CommitId, &str)]) -> BTreeMap<CommitId, PartBody> {
    xs.iter().map(|(c, v)| (*c, PartBody::Held(Some(s(v))))).collect()
}

// spec/commits.md §5 Signals: a write is told as its commit wherever that commit reads otherwise: a
// late part when it joins; one arriving past its expiry or its keep bound as dropped
#[test]
fn signal_told_where_it_is_history_spec_commits_5() {
    let (mut lp, d, _) = setup(7);
    let base: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().collect::<Vec<_>>();
    let mut base: Vec<_> = base.iter().map(|c| (lp.peers[0].engine.header(c).unwrap().ts, lp.peers[0].engine.package(c).unwrap().unwrap())).collect();
    base.sort_by_key(|x| x.0);
    let now = lp.peers[0].engine.now();
    let mut m = Mutation::new();
    m.retention(d, &log(), keep(Some(osis_commit::FOREVER), None)).unwrap();
    m.set(d, &log(), &s("late")).unwrap();
    m.set(d, &REG, &s("first")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let mut p = osis_node::local_peer::Peer::new(70, now).unwrap();
    for (_, x) in &base {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    let rx = listen(&mut p);
    let mut only = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let keep_reg = only.header.aspects.iter().position(|a| a.ak.as_str() == "t:reg.0").unwrap();
    only.parts.retain(|x| x.ai == keep_reg);
    p.engine.ingest(&only.encode(), pk.blobs.clone()).unwrap();
    assert_eq!(told(&mut p, d, &rx), BTreeMap::from([(c, PartBody::NotFetched)]), "its header came");
    p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    assert_eq!(told(&mut p, d, &rx), held(&[(c, "late")]), "the late part joined");
    // past its expiry or keep bound on arrival: told as dropped
    let rx = listen(&mut lp.peers[1]);
    let t = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.retention(d, &log(), keep(Some(osis_commit::FOREVER), None)).unwrap();
    m.set(d, &log(), &s("expired")).unwrap();
    m.expires_all(osis_base::WallMs(t + HOUR));
    let e = lp.peers[0].commit(m).unwrap().unwrap();
    let b = send(&mut lp, 0, d, keep(None, Some(HOUR)), "past bound");
    let kept = send(&mut lp, 0, d, keep(Some(osis_commit::FOREVER), None), "kept");
    lp.advance(2 * HOUR);
    sync(&mut lp, 0, 1);
    let mut want = held(&[(c, "late"), (kept, "kept")]);
    want.extend([(e, PartBody::Dropped), (b, PartBody::Dropped)]);
    assert_eq!(told(&mut lp.peers[1], d, &rx), want);
}

// spec/commits.md §5 Signals: a write that leaves the listing and shows again is told again: Bob's
// write is told at Alice, a kick drops it as invalid, a re-grant (spec/permissions.md §5.2) makes
// it valid, and the refetched part is told once more
#[test]
fn signal_told_again_when_shown_again_spec_commits_5() {
    let (mut lp, d, ids) = setup(9);
    let rx = listen(&mut lp.peers[0]);
    let c = send(&mut lp, 1, d, keep(Some(osis_commit::FOREVER), None), "hi");
    lp.sync_all().unwrap();
    assert_eq!(told(&mut lp.peers[0], d, &rx), held(&[(c, "hi")]));
    set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(ct::Frontier::default().to_value()));
    assert_eq!(told(&mut lp.peers[0], d, &rx), BTreeMap::from([(c, PartBody::Dropped)]));
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(told(&mut lp.peers[0], d, &rx), held(&[(c, "hi")]));
}

// spec/commits.md §5 Signals: a body kept while invalid (Bob's own write, made after a kick he
// holds) is told when it turns valid, with no part joining: a re-grant covers writes in the gap
// (spec/permissions.md §5.2)
#[test]
fn signal_kept_invalid_told_when_valid_spec_commits_5() {
    let (mut lp, d, ids) = setup(10);
    set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(ct::Frontier::default().to_value()));
    lp.sync_all().unwrap();
    let rx = listen(&mut lp.peers[1]);
    let mut m = Mutation::new();
    m.retention(d, &log(), keep(Some(osis_commit::FOREVER), None)).unwrap();
    m.set(d, &log(), &s("gap")).unwrap();
    let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    let valid = |lp: &mut LocalPeer| lp.peers[1].engine.held_part(&d, &log(), &c, usize::MAX).unwrap().unwrap().valid;
    assert!(!valid(&mut lp));
    assert_eq!(told(&mut lp.peers[1], d, &rx), held(&[(c, "gap")]), "own body kept while invalid");
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    assert!(valid(&mut lp));
    assert_eq!(told(&mut lp.peers[1], d, &rx), held(&[(c, "gap")]), "told again: now valid");
}


// spec/commits.md §5 Signals: past its keep bound a signal part is past every bound, so nothing
// makes it missing again: a write dropped as invalid that turns valid past it, or a purge of it
// that falls past it, is not fetched again, flags no suspect and reads dropped, as at a node
// where it stayed valid or unpurged
#[test]
fn signal_past_its_bound_never_missing_again_spec_commits_5() {
    let suspects = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.suspects().unwrap();
    // valid again: Alice kicks Bob, re-grants past the bound
    let (mut lp, d, ids) = setup(41);
    let c = send(&mut lp, 1, d, keep(None, Some(HOUR)), "hi");
    lp.sync_all().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(ct::Frontier::default().to_value()));
    assert_eq!(body(&mut lp, 0, d, &c), PartBody::Dropped);
    lp.advance(2 * HOUR);
    lp.peers[1].engine.tick().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert!(lp.peers[i].engine.held_part(&d, &log(), &c, usize::MAX).unwrap().unwrap().valid);
        assert_eq!(body(&mut lp, i, d, &c), PartBody::Dropped);
        assert!(suspects(&mut lp, i).is_empty(), "nothing to fetch back");
    }
    // a purge falling: Carol (admin) purges Bob's write, Alice kicks her past the bound
    let mut lp = net(3, 42);
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let c = send(&mut lp, 1, d, keep(None, Some(HOUR)), "oops");
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.set(d, &ct::PURGE, &lp.peers[2].engine.now()).unwrap();
    m.purge(PurgeItem::Commit { commit: c, tid: d, ak: log() });
    let p = lp.peers[2].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(body(&mut lp, 0, d, &c), PartBody::Purged(p));
    lp.advance(2 * HOUR);
    for i in 0..3 {
        lp.peers[i].engine.tick().unwrap();
    }
    set_edge(&mut lp.peers[0].engine, d, ids[2], None, Some(ct::Frontier::default().to_value()));
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(body(&mut lp, i, d, &c), PartBody::Dropped, "peer {i}");
        assert!(suspects(&mut lp, i).is_empty(), "peer {i}: nothing to fetch back");
    }
}

// spec/sync.md §6, spec/commits.md §5 Signals: a signal part is must-hold only while kept: past
// its bound a node still holding it (its timer not yet run) holds it as may-hold, so no pass
// places it again. This engine runs due timers before every step, so a pass meets it only when
// the clock crosses the bound during one; the judgment is checked directly
#[test]
fn signal_past_its_bound_not_must_hold_spec_sync_6() {
    use crate::net::Net;
    let mut net = Net::new();
    let h = net.add_host();
    let a = net.node(1, &[h]);
    let g = net.group(a, &[], &[h]);
    let t = net.item(a, g, g, "x");
    net.run();
    let mut m = Mutation::new();
    m.retention(t, &log(), keep(None, Some(HOUR))).unwrap();
    m.set(t, &log(), &s("brief")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let (key, l) = (net.address(h).key, net.label(a));
    let must = |net: &mut Net| net.sync(a).verdicts(&key, &l).unwrap().unwrap().must_hold.iter().any(|(x, _)| *x == c);
    assert!(must(&mut net), "kept: must-hold");
    net.clock.advance(HOUR + 1);
    assert!(net.engine(a).body_not_dropped(&c, &t, &log()), "its timer not run: held");
    assert!(!must(&mut net), "past its bound: not must-hold");
}
