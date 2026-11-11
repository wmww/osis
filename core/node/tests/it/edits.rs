//! Signal edits (spec/commits.md §5 Signals), at the engine and between nodes: a fire naming the
//! fire it replaces reads in that fire's place, for the same verified actor, in every arrival order.

use crate::common::*;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, WallMs};
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

/// Purgeable by its author or admins (what history keeps is the thing's setting).
fn purgeable() -> Retention {
    Retention { by: PurgeBy::AuthorOrAdmin }
}

/// `n` peers, a thing `d` of peer 0's every other peer writes: built once per `n`
/// (`LocalPeer::cached`).
fn net_with(n: usize) -> (LocalPeer, Tid, Vec<Tid>) {
    let (lp, (d, ids)) = LocalPeer::cached(&format!("edits::net_with/{n}"), || {
        let (lp, d, ids) = net_with_built(n);
        (lp, (d, ids))
    });
    (lp, d, ids)
}

fn net_with_built(n: usize) -> (LocalPeer, Tid, Vec<Tid>) {
    let mut lp = net(n, 0);
    let ids: Vec<Tid> = (0..n).map(|i| lp.peers[i].engine.me()).collect();
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    // the thing keeps its signal's fires for good
    m.set(d, &ct::RETENTION, &setting(&[(log().as_str(), History::FOREVER)])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    for x in &ids[1..] {
        set_edge(&mut lp.peers[0].engine, d, *x, Some(edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, d, ids)
}

fn setup() -> (LocalPeer, Tid, Vec<Tid>) {
    net_with(2)
}

fn fire(lp: &mut LocalPeer, i: usize, d: Tid, r: Retention, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

fn edit(lp: &mut LocalPeer, i: usize, d: Tid, r: Retention, v: &str, of: CommitId) -> CommitId {
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s(v)).unwrap();
    m.replaces(d, &log(), of).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// What a listing of `d`'s signal reads, oldest first: (place, version the body comes from, body).
fn list(lp: &mut LocalPeer, i: usize, d: Tid) -> Vec<(CommitId, Option<CommitId>, PartBody)> {
    let aks = [(d, log())];
    let e = &mut lp.peers[i].engine;
    let mut out = Vec::new();
    let mut from = CommitFrom::Oldest;
    loop {
        let places = e.places(&aks, from, 10);
        let Some(last) = places.last() else { break };
        from = CommitFrom::After(*last);
        for p in places {
            if !e.listed_at(&p.id, &aks).unwrap() {
                continue;
            }
            let row = e.commit_row(&p.id, &|_, _| true, usize::MAX).unwrap().unwrap();
            let part = &row.parts[0];
            out.push((p.id, part.version.map(|v| v.id), part.body.clone()));
        }
    }
    out
}

fn body(v: &str) -> PartBody {
    PartBody::Held(Some(s(v)))
}

// spec/commits.md §5 Signals: reads as its newest version, in the original's place and order; the
// versions are not listed of their own; another's fire keeps its place
#[test]
fn an_edit_reads_in_the_originals_place_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    // stamped after it (the same `ts` would order them by commit ID)
    lp.advance(10);
    let bob = fire(&mut lp, 1, d, r, "bob");
    let v1 = edit(&mut lp, 0, d, r, "two", o);
    let v2 = edit(&mut lp, 0, d, r, "three", o);
    lp.sync_all().unwrap();
    for i in 0..2 {
        let got = list(&mut lp, i, d);
        assert_eq!(got, vec![(o, Some(v2), body("three")), (bob, None, body("bob"))]);
        assert!(!lp.peers[i].engine.listed_at(&v1, &[(d, log())]).unwrap());
        assert_eq!(lp.peers[i].engine.held_parts(&d, &log(), CommitFrom::Oldest, 10, usize::MAX).unwrap().0.len(), 4, "the versions are still held");
    }
}

// spec/commits.md §5 Signals: a function of the held commits: every order of arrival reads alike,
// a version waiting for its original standing alone until it comes
#[test]
fn every_arrival_order_reads_alike_spec_commits_5() {
    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let (mut lp, d, _) = net_with(3);
        let r = purgeable();
        let o = fire(&mut lp, 0, d, r, "one");
        let v1 = edit(&mut lp, 0, d, r, "two", o);
        let v2 = edit(&mut lp, 0, d, r, "three", o);
        let want = list(&mut lp, 0, d);
        assert_eq!(want, vec![(o, Some(v2), body("three"))]);
        let bytes: Vec<Vec<u8>> = [o, v1, v2].iter().map(|c| lp.peers[0].engine.commit_bytes(c).unwrap().unwrap()).collect();
        for &i in &order {
            lp.peers[2].receive(&bytes[i], Vec::new()).unwrap();
        }
        assert_eq!(list(&mut lp, 2, d), want, "order {order:?}");
    }
}

// spec/commits.md §5 Signals: a claim on another actor's fire, on a version (no chains), or on
// nothing is a fire of its own at its own place
#[test]
fn forged_claims_stand_alone_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let forged = edit(&mut lp, 1, d, r, "bobs", o);
    let v = edit(&mut lp, 0, d, r, "two", o);
    let chain = edit(&mut lp, 0, d, r, "three", v);
    let dangling = edit(&mut lp, 0, d, r, "four", CommitId([7; 32]));
    lp.sync_all().unwrap();
    let want = vec![(o, Some(v), body("two")), (forged, None, body("bobs")), (chain, None, body("three")), (dangling, None, body("four"))];
    let mut sorted = want;
    sorted.sort_by_key(|x| (lp.peers[0].engine.header(&x.0).unwrap().ts, x.0));
    assert_eq!(list(&mut lp, 0, d), sorted);
    assert_eq!(list(&mut lp, 1, d), sorted);
}

// spec/commits.md §5 Signals: an edit turned invalid is not honored, the previous version shows;
// removal rebuilds nothing else
#[test]
fn an_edit_after_a_kick_is_not_honored_spec_commits_5() {
    let (mut lp, d, ids) = setup();
    let r = purgeable();
    let bob = 1;
    let o = fire(&mut lp, bob, d, r, "mine");
    lp.sync_all().unwrap();
    let v = edit(&mut lp, bob, d, r, "edited", o);
    // kick bob, keeping only the original (its frontier names it, not the edit)
    let f = ct::Frontier { commits: BTreeSet::from([o]) };
    set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(f.to_value()));
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 0, d), vec![(o, None, body("mine"))], "the edit fell");
    // at its writer, its own invalid part is marked and reads as itself, at its own place
    assert_eq!(list(&mut lp, 1, d), vec![(o, None, body("mine")), (v, None, body("edited"))]);
    assert!(!lp.peers[1].engine.commit_row(&v, &|_, _| true, usize::MAX).unwrap().unwrap().parts[0].valid);
}

// spec/commits.md §5 Signals: a valid edit of an invalid original stands alone at its own place
#[test]
fn a_valid_edit_of_an_invalid_original_stands_alone_spec_commits_5() {
    let mut lp = net(2, 0);
    let ids = [0, 1].map(|i| lp.peers[i].engine.me());
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    keep_in(&mut m, d, &setting(&[(log().as_str(), History::FOREVER)]));
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Read)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let r = purgeable();
    // bob, a reader, writes before he may, then is granted and edits it
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("one")).unwrap();
    let o = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let v = edit(&mut lp, 1, d, r, "two", o);
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 0, d), vec![(v, None, body("two"))], "the edit alone at its own place");
}

// spec/commits.md §5 Signals: versions fall with their original and fold under it again when both
// return (the kicker's kick falls)
#[test]
fn versions_return_folded_with_their_original_spec_commits_5() {
    let (mut lp, d, ids) = net_with(3);
    let r = purgeable();
    let (bob, carol) = (1, 2);
    set_edge(&mut lp.peers[0].engine, d, ids[carol], Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    let o = fire(&mut lp, bob, d, r, "one");
    let v = edit(&mut lp, bob, d, r, "two", o);
    // carol kicks bob before receiving them, and alice removes carol before receiving her kick
    set_edge(&mut lp.peers[carol].engine, d, ids[bob], None, Some(ct::Frontier::default().to_value()));
    set_edge(&mut lp.peers[0].engine, d, ids[carol], None, Some(ct::Frontier::default().to_value()));
    for c in [o, v] {
        let b = lp.peers[bob].engine.commit_bytes(&c).unwrap().unwrap();
        lp.peers[carol].receive(&b, Vec::new()).unwrap();
    }
    assert_eq!(list(&mut lp, carol, d), vec![], "both fell at carol");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(list(&mut lp, i, d), vec![(o, Some(v), body("two"))], "folded again at {i}");
    }
}

fn purge_commit(lp: &mut LocalPeer, i: usize, d: Tid, items: Vec<PurgeItem>) -> CommitId {
    let mut m = Mutation::new();
    m.set(d, &ct::PURGE, &lp.peers[i].engine.now()).unwrap();
    for p in items {
        m.purge(p);
    }
    lp.peers[i].commit(m).unwrap().unwrap()
}

fn named(d: Tid, c: CommitId) -> PurgeItem {
    PurgeItem::Commit { commit: c, tid: d, ak: log() }
}

// spec/commits.md §5 Signals, Purge: a purge takes only what it names; a purged newest version
// keeps older ones from showing, an edit purging its predecessors in its own commit stays honored
#[test]
fn a_purge_takes_only_what_it_names_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let v = edit(&mut lp, 0, d, r, "two", o);
    lp.sync_all().unwrap();
    // purging the newest version: older text does not come back
    let rq = purge_commit(&mut lp, 0, d, vec![named(d, v)]);
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(o, Some(v), PartBody::Purged(rq))]);
    // an edit's own purge of the original leaves the edit honored
    let (mut lp, d, _) = setup();
    let o = fire(&mut lp, 0, d, r, "one");
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("two")).unwrap();
    m.replaces(d, &log(), o).unwrap();
    m.purge(named(d, o));
    let v = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(list(&mut lp, i, d), vec![(o, Some(v), body("two"))], "node {i}");
    }
    // a purge of the original alone leaves a version written after it
    let (mut lp, d, _) = setup();
    let o = fire(&mut lp, 0, d, r, "one");
    let rq = purge_commit(&mut lp, 0, d, vec![named(d, o)]);
    let v = edit(&mut lp, 0, d, r, "two", o);
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(o, Some(v), body("two"))]);
    let _ = rq;
}

// spec/commits.md §5 Signals: an edit expired shows the previous; an over-long one stands alone
// once its original is gone
#[test]
fn expiry_shows_the_previous_or_stands_alone_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let t = lp.peers[0].engine.now().0;
    let timed = |lp: &mut LocalPeer, v: &str, at: u64, of: Option<CommitId>| {
        let mut m = Mutation::new();
        m.retention(d, &log(), r).unwrap();
        m.set(d, &log(), &s(v)).unwrap();
        if let Some(o) = of {
            m.replaces(d, &log(), o).unwrap();
        }
        m.expires_all(WallMs(t + at));
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let o = timed(&mut lp, "one", 6 * HOUR, None);
    let short = timed(&mut lp, "short", 2 * HOUR, Some(o));
    let long = timed(&mut lp, "long", 9 * HOUR, Some(o));
    let _ = short;
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(o, Some(long), body("long"))]);
    lp.advance(7 * HOUR);
    lp.peers[1].tick().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(long, None, body("long"))], "the original gone, the over-long edit alone");
}

// spec/commits.md §5 Signals: a writer gives an edit its original's expiry; it ends with it
#[test]
fn an_edit_takes_its_originals_expiry_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let t = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("one")).unwrap();
    m.expires_all(WallMs(t + HOUR));
    let o = lp.peers[0].commit(m).unwrap().unwrap();
    let v = edit(&mut lp, 0, d, r, "two", o);
    assert_eq!(lp.peers[0].engine.header(&v).unwrap().expires, lp.peers[0].engine.header(&o).unwrap().expires);
    lp.advance(HOUR + 1);
    lp.peers[0].tick().unwrap();
    assert_eq!(list(&mut lp, 0, d), vec![], "both end together");
}

// spec/commits.md §5 Signals: an original past its window leaves the listing, its versions (each
// in the same window from its own `ts`) then stand alone at their own places
#[test]
fn an_original_past_its_keep_frees_its_versions_spec_commits_5() {
    let (mut lp, d, _) = setup();
    set_setting(&mut lp, 0, d, &setting(&[(log().as_str(), History::Keep { until: None, after: Some(2 * HOUR) })]));
    lp.advance(1_000);
    let o = fire(&mut lp, 0, d, purgeable(), "one");
    lp.advance(HOUR);
    let v = edit(&mut lp, 0, d, purgeable(), "two", o);
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(o, Some(v), body("two"))]);
    lp.advance(HOUR + HOUR / 2);
    lp.peers[1].tick().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(v, None, body("two"))]);
}

// spec/commits.md §5 Signals: `final` on the setting's entry is a writer default: the writer
// refuses an edit, and one written anyway is honored (no validity rule)
#[test]
fn final_is_a_writer_default_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let rules: ct::RetentionSetting = BTreeMap::from([(log(), ct::RetentionEntry { history: Some(History::FOREVER), r#final: true, ..Default::default() })]).into();
    let mut m = Mutation::new();
    m.set(d, &ct::RETENTION, &rules).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("two")).unwrap();
    m.replaces(d, &log(), o).unwrap();
    assert!(lp.peers[0].commit(m).is_err(), "the writer refuses");
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("two")).unwrap();
    m.replaces(d, &log(), o).unwrap();
    let v = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(list(&mut lp, 1, d), vec![(o, Some(v), body("two"))], "honored");
}

// spec/commits.md §5 Purge: a request that expires reaches only deltas expiring no later
#[test]
fn an_expiring_request_reaches_only_earlier_expiries_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let t = lp.peers[0].engine.now().0;
    let write = |lp: &mut LocalPeer, v: &str, at: Option<u64>| {
        let mut m = Mutation::new();
        m.retention(d, &log(), r).unwrap();
        m.set(d, &log(), &s(v)).unwrap();
        if let Some(x) = at {
            m.expires_all(WallMs(x));
        }
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let permanent = write(&mut lp, "kept", None);
    let brief = write(&mut lp, "brief", Some(t + HOUR));
    let later = write(&mut lp, "later", Some(t + 3 * HOUR));
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("edit")).unwrap();
    for c in [permanent, brief, later] {
        m.purge(named(d, c));
    }
    m.expires_all(WallMs(t + 2 * HOUR));
    // a writer refuses a request naming what it would not reach: this one is written anyway
    lp.peers[0].engine.core.skip_writer_rules = true;
    let rq = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    let got: BTreeMap<_, _> = list(&mut lp, 1, d).into_iter().map(|x| (x.0, x.2)).collect();
    assert_eq!(got[&permanent], body("kept"), "no expiry: out of reach");
    assert_eq!(got[&brief], PartBody::Purged(rq));
    assert_eq!(got[&later], body("later"), "expires later than the request");
}

// spec/commits.md §5 Signals: listeners hear an edit under the original's place; a version waiting
// for its original under its own, then gone when it comes
#[test]
fn listeners_hear_the_original_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let v = edit(&mut lp, 0, d, r, "two", o);
    let bytes = lp.peers[0].engine.commit_bytes(&o).unwrap().unwrap();
    let vb = lp.peers[0].engine.commit_bytes(&v).unwrap().unwrap();
    let rx = lp.peers[1].engine.subscribe();
    lp.peers[1].engine.watch_commits();
    lp.peers[1].receive(&vb, Vec::new()).unwrap();
    let told = |rx: &std::sync::mpsc::Receiver<Event>| -> BTreeSet<CommitId> { rx.try_iter().filter_map(|e| if let Event::Commits(ch) = e { Some(ch.iter().filter(|x| x.tid == d && x.ak == log()).map(|x| x.id).collect::<Vec<_>>()) } else { None }).flatten().collect() };
    assert_eq!(told(&rx), BTreeSet::from([v]));
    assert_eq!(list(&mut lp, 1, d), vec![(v, None, body("two"))]);
    lp.peers[1].receive(&bytes, Vec::new()).unwrap();
    let t = told(&rx);
    assert!(t.contains(&o) && t.contains(&v), "the original reads otherwise, the version leaves its place: {t:?}");
    assert_eq!(list(&mut lp, 1, d), vec![(o, Some(v), body("two"))]);
}

// spec/commits.md §5 Signals (listeners): a version is told only when it is listed of its own
// before or after; a purge of the fire with its versions, and an expiry ending the fire with them, are
// each one change of the fire
#[test]
fn a_folded_version_ending_with_its_fire_is_not_told_spec_commits_5() {
    let told = |rx: &std::sync::mpsc::Receiver<Event>, d: Tid| -> Vec<CommitId> { rx.try_iter().filter_map(|e| if let Event::Commits(ch) = e { Some(ch.iter().filter(|x| x.tid == d && x.ak == log()).map(|x| x.id).collect::<Vec<_>>()) } else { None }).flatten().collect() };
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let v = edit(&mut lp, 0, d, r, "two", o);
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.watch_commits();
    purge_commit(&mut lp, 0, d, vec![named(d, v), named(d, o)]);
    assert_eq!(told(&rx, d), vec![o], "a delete: one change of the fire");
    let (mut lp, d, _) = setup();
    let t = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("one")).unwrap();
    m.expires_all(WallMs(t + HOUR));
    let o = lp.peers[0].commit(m).unwrap().unwrap();
    edit(&mut lp, 0, d, r, "two", o);
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.watch_commits();
    lp.advance(HOUR + 1);
    lp.peers[0].tick().unwrap();
    assert_eq!(list(&mut lp, 0, d), vec![]);
    assert_eq!(told(&rx, d), vec![o], "an expiry: one change of the fire");
    // the newest version ending first: the fire reads the previous, told as its change
    let (mut lp, d, _) = setup();
    let o = fire(&mut lp, 0, d, r, "one");
    let t = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.retention(d, &log(), r).unwrap();
    m.set(d, &log(), &s("two")).unwrap();
    m.replaces(d, &log(), o).unwrap();
    m.expires_all(WallMs(t + HOUR));
    lp.peers[0].commit(m).unwrap().unwrap();
    let rx = lp.peers[0].engine.subscribe();
    lp.peers[0].engine.watch_commits();
    lp.advance(HOUR + 1);
    lp.peers[0].tick().unwrap();
    assert_eq!(list(&mut lp, 0, d), vec![(o, None, body("one"))]);
    assert_eq!(told(&rx, d), vec![o], "a version's expiry: one change of the fire");
}

// spec/commits.md §5 Signals: the fold survives a restart
#[test]
fn the_fold_survives_a_restart_spec_commits_5() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let v = edit(&mut lp, 0, d, r, "two", o);
    let want = list(&mut lp, 0, d);
    assert_eq!(want, vec![(o, Some(v), body("two"))]);
    lp.peers[0].restart(0).unwrap();
    assert_eq!(list(&mut lp, 0, d), want);
}

// spec/commits.md §5 Signals: a page and a quote read one body per entry, whatever the size of the
// signal and the number of versions of a message
#[test]
fn bodies_read_are_flat_in_n_spec_commits_5() {
    fn count(n: usize) -> (u64, u64, u64) {
        let (mut lp, d, _) = setup();
        let r = purgeable();
        // the quote is of the oldest message: a walk from the newest pays the whole signal
        let mut first = None;
        for i in 0..n {
            let o = fire(&mut lp, 0, d, r, &format!("m{i}"));
            for j in 0..3 {
                edit(&mut lp, 0, d, r, &format!("m{i}e{j}"), o);
            }
            first.get_or_insert(o);
        }
        osis_node::costs::take();
        let aks = [(d, log())];
        let places = lp.peers[0].engine.places(&aks, CommitFrom::Newest, 20);
        for p in &places {
            assert!(lp.peers[0].engine.listed_at(&p.id, &aks).unwrap());
            let row = lp.peers[0].engine.commit_row(&p.id, &|_, _| true, usize::MAX).unwrap().unwrap();
            assert!(matches!(row.parts[0].body, PartBody::Held(_)));
        }
        let bodies = |c: &[(&str, std::time::Duration, u64)], k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
        let c = osis_node::costs::take();
        let (page, judged) = (bodies(&c, "listing: body read"), bodies(&c, "listing: version judged"));
        let row = lp.peers[0].engine.commit_row(&first.unwrap(), &|_, _| true, usize::MAX).unwrap().unwrap();
        assert_eq!(row.parts[0].body, body("m0e2"));
        let c = osis_node::costs::take();
        (page, judged, bodies(&c, "listing: body read") + bodies(&c, "listing: version judged"))
    }
    assert_eq!(count(25), count(250));
}

// spec/commits.md §2: `replaces` off a durable signal is a bad part, never applied; a writer
// refuses it
#[test]
fn replaces_off_a_durable_signal_is_a_bad_part_spec_commits_2() {
    let (mut lp, d, _) = setup();
    let o = fire(&mut lp, 0, d, purgeable(), "one");
    let claim = || {
        let mut m = Mutation::new();
        m.set(d, &REG, &s("x")).unwrap();
        m.replaces(d, &REG, o).unwrap();
        m
    };
    assert!(lp.peers[0].commit(claim()).is_err());
    lp.peers[0].engine.commit_hostile(claim()).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.get(&d, &ak("t:reg.0")).unwrap(), None);
}

/// A small splitmix stream (the scripted runs below).
struct Mix(u64);
impl Mix {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((z ^ (z >> 31)) % n as u64) as usize
    }
}

// spec/commits.md §5 Signals; spec: none (rebuildable indexes): over scripted runs of fires, honored,
// forged and chained edits, purges (edits purging their predecessors too), a writer removed (its
// writes falling, his writes while out invalid everywhere) and back, expiry and keep bounds passing:
// after every step the incremental indexes equal a reopen and a rebuild from the commit records
// (`Engine::check_index`), and at the end a node fed every commit in a shuffled order, some header
// first and body later, reads the same listing, its listener told of each change of what it lists
#[test]
fn incremental_equals_rebuilt_and_every_order_reads_alike_spec_commits_5() {
    let (mut folded, mut out_writes) = (0, 0);
    for seed in 0..10u64 {
        let mut g = Mix(seed);
        let (mut lp, d, ids) = net_with(3);
        let (alice, bob, obs) = (0, 1, 2);
        let mut fires: Vec<CommitId> = Vec::new();
        let mut bob_in = true;
        for step in 0..14 {
            let now = lp.peers[alice].engine.now().0;
            let who = if g.below(2) == 1 { bob } else { alice };
            // now and then alice moves the window: kept for good, or two hours from each fire
            let h = [History::FOREVER, History::Keep { until: None, after: Some(2 * HOUR) }][g.below(2)];
            let r = purgeable();
            if step % 4 == 3 {
                set_setting(&mut lp, alice, d, &setting(&[(log().as_str(), h)]));
            }
            let mut m = Mutation::new();
            m.retention(d, &log(), r).unwrap();
            match g.below(6) {
                0 | 1 => {
                    m.set(d, &log(), &s(&format!("f{step}"))).unwrap();
                    if g.below(3) == 0 {
                        m.expires_all(WallMs(now + (1 + g.below(4) as u64) * HOUR));
                    }
                }
                2 | 3 if !fires.is_empty() => {
                    let of = fires[g.below(fires.len())];
                    m.set(d, &log(), &s(&format!("e{step}"))).unwrap();
                    m.replaces(d, &log(), of).unwrap();
                    if g.below(3) == 0 {
                        m.purge(named(d, fires[g.below(fires.len())]));
                    }
                }
                4 if !fires.is_empty() => {
                    m = Mutation::new();
                    m.set(d, &ct::PURGE, &lp.peers[who].engine.now()).unwrap();
                    m.purge(named(d, fires[g.below(fires.len())]));
                }
                5 => {
                    if bob_in {
                        // a hand-built frontier keeps some of his writes: the rest fall
                        let keep: BTreeSet<CommitId> = fires.iter().filter(|_| g.below(2) == 0).copied().collect();
                        set_edge(&mut lp.peers[alice].engine, d, ids[bob], None, Some(ct::Frontier { commits: keep }.to_value()));
                    } else {
                        set_edge(&mut lp.peers[alice].engine, d, ids[bob], Some(edge(Role::Write)), None);
                    }
                    bob_in = !bob_in;
                    m = Mutation::new();
                }
                _ => {
                    lp.advance(g.below(3) as u64 * HOUR + 1);
                    m = Mutation::new();
                }
            }
            // bob out writes anyway: invalid at every node
            let out = who == bob && !bob_in;
            let wrote = if m.is_empty() { None } else if out { lp.peers[bob].engine.commit_hostile(m).ok().flatten() } else { lp.peers[who].commit(m).ok().flatten() };
            out_writes += usize::from(out && wrote.is_some());
            fires.extend(wrote);
            sync(&mut lp, alice, bob);
            sync(&mut lp, bob, alice);
            for i in [alice, bob] {
                lp.peers[i].tick().unwrap();
            }
            for i in [alice, bob] {
                lp.peers[i].engine.check_index();
            }
        }
        let want = list(&mut lp, alice, d);
        // every commit alice holds, shuffled, a third of them header first
        let mut all: Vec<CommitId> = lp.peers[alice].engine.commit_ids();
        for i in (1..all.len()).rev() {
            all.swap(i, g.below(i + 1));
        }
        // it holds exactly alice's commits: no addenda of its own
        lp.peers[obs].engine.write_addenda(false);
        // listeners: every arrival tells each commit whose listed form changed, and never a claim
        // folded under its original (an edit is heard as its original's change)
        let claims: BTreeSet<CommitId> = all.iter().filter(|c| lp.peers[alice].engine.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.replaces.is_some()))).copied().collect();
        let rx = lp.peers[obs].engine.subscribe();
        lp.peers[obs].engine.watch_commits();
        let feed = |lp: &mut LocalPeer, bytes: &[u8]| {
            let shown = |lp: &mut LocalPeer| list(lp, obs, d).into_iter().map(|(c, v, b)| (c, (v, b))).collect::<BTreeMap<_, _>>();
            let alone = |lp: &mut LocalPeer| lp.peers[obs].engine.places(&[(d, log())], CommitFrom::Oldest, usize::MAX).iter().map(|p| p.id).collect::<BTreeSet<CommitId>>();
            let (before, was_alone) = (shown(lp), alone(lp));
            let _ = lp.peers[obs].receive(bytes, Vec::new());
            let (after, is_alone) = (shown(lp), alone(lp));
            let told: BTreeSet<CommitId> = rx.try_iter().filter_map(|e| if let Event::Commits(ch) = e { Some(ch.iter().filter(|x| x.tid == d && x.ak == log()).map(|x| x.id).collect::<Vec<_>>()) } else { None }).flatten().collect();
            let changed: BTreeSet<CommitId> = before.keys().chain(after.keys()).filter(|c| before.get(c) != after.get(c)).copied().collect();
            assert!(changed.is_subset(&told), "seed {seed}: a listed change untold: {changed:?} told {told:?}");
            // a claim standing alone is any fire (told when its state moves, listed or not)
            let stray: Vec<&CommitId> = told.difference(&changed).filter(|c| claims.contains(c) && !was_alone.contains(c) && !is_alone.contains(c)).collect();
            assert!(stray.is_empty(), "seed {seed}: a folded claim told of its own: {stray:?}");
        };
        let mut late = Vec::new();
        for c in &all {
            let Some(bytes) = lp.peers[alice].engine.commit_bytes(c).unwrap() else { continue };
            if g.below(3) == 0 {
                let mut bare = osis_commit::CommitBlob::decode(&bytes).unwrap();
                bare.parts.clear();
                feed(&mut lp, &bare.encode());
                late.push(bytes);
            } else {
                feed(&mut lp, &bytes);
            }
        }
        for b in late {
            feed(&mut lp, &b);
        }
        // a body dropped as invalid in passing is fetched again once valid (node-sync's part)
        for c in &all {
            if let Some(bytes) = lp.peers[alice].engine.commit_bytes(c).unwrap() {
                feed(&mut lp, &bytes);
            }
        }
        lp.peers[obs].reexamine().unwrap();
        lp.peers[obs].tick().unwrap();
        assert_eq!(list(&mut lp, obs, d), want, "seed {seed}: shuffled");
        lp.peers[obs].engine.check_index();
        folded += want.iter().filter(|x| x.1.is_some()).count();
    }
    assert!(folded > 0 && out_writes > 0, "reach: {folded} folded, {out_writes} writes while out");
}

// spec/commits.md §7: an undo of a signal's part writes nothing back, so undoing an edit leaves
// the original reading as the edit; to restore text, replace again
#[test]
fn an_undo_of_an_edit_changes_no_reading_spec_commits_7() {
    let (mut lp, d, _) = setup();
    let r = purgeable();
    let o = fire(&mut lp, 0, d, r, "one");
    let v = edit(&mut lp, 0, d, r, "two", o);
    let mut m = Mutation::new();
    m.undo(v);
    let _ = lp.peers[0].engine.write(m);
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(list(&mut lp, i, d), vec![(o, Some(v), body("two"))], "node {i}");
    }
}
