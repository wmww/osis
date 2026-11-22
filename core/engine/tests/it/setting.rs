#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A thing's history setting (spec/commits.md §5 The setting, History, Purge on replace): what
//! is listed follows the held valid settings in any arrival order; a setting acts from its own
//! stamp; the setting itself has fixed retention and binds nothing for a writer that is no admin.

use crate::common::*;
use osis_base::{CommitId, PurgeBy, Role, Tid, Value, WallMs};
use osis_commit::retention::fixed_purge_by;
use osis_engine::local_peer::{LocalPeer, Package, Peer};
use osis_engine::Mutation;
use osis_schema::core_types as ct;
use osis_schema::{Codec, History};

const HOUR: u64 = 3_600_000;
const A: &str = "t:reg.0";

fn keep(after: u64) -> History {
    History::Keep { until: None, after: Some(after) }
}

/// Alice (0) is mint admin of D, Bob (1) writes, Carol (2) is an admin: built once
/// (`LocalPeer::cached`).
fn setup() -> (LocalPeer, Tid) {
    LocalPeer::cached("setting::setup", || setup_seeded(0))
}

/// `setup` over `net(3, seed)`.
fn setup_seeded(seed: u64) -> (LocalPeer, Tid) {
    let mut lp = net(3, seed);
    let mut m = Mutation::new();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.hold(d);
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
    // the fresh node's account, granted read on D: what it is handed of D applies (content of a
    // thing outside its node closure waits, spec/commits.md §4 Outside the node closure)
    let mut f = fresh_account();
    lp.peers[0].know(&[f.engine.me()]).unwrap();
    for id in f.engine.commit_ids() {
        let pk = f.engine.package(&id).unwrap().unwrap();
        lp.deliver(0, &pk).unwrap();
    }
    set_edge(&mut lp.peers[0].engine, d, f.engine.me(), Some(edge(Role::Read)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, d)
}

/// The fresh node's account as `setup_seeded` grants it (seed `FRESH` at `T0`).
fn fresh_account() -> Peer {
    Peer::new(FRESH, crate::common::T0).unwrap()
}

/// Peer `i` writes `v` on `A` of `d`.
fn put(lp: &mut LocalPeer, i: usize, d: Tid, v: &str) -> CommitId {
    let mut m = Mutation::new();
    m.set(d, &ak(A), &s(v)).unwrap();
    let c = lp.peers[i].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    c
}

/// Peer `i`, an admin, writes `x` on `d`.
fn set(lp: &mut LocalPeer, i: usize, d: Tid, x: &ct::RetentionSetting) -> CommitId {
    let c = set_setting(lp, i, d, x);
    lp.advance(1_000);
    c
}

fn listed(p: &mut Peer, c: &CommitId, d: Tid) -> bool {
    p.engine.listed_at(c, &[(d, ak(A))]).unwrap()
}

fn pack(lp: &mut LocalPeer, i: usize, c: &CommitId) -> Package {
    lp.peers[i].engine.package(c).unwrap().unwrap()
}

/// What every node holds before the writes under test (the thing, its roles).
fn base(lp: &mut LocalPeer) -> Vec<Package> {
    let ids = lp.peers[0].engine.commit_ids();
    let mut x: Vec<(osis_base::Ts, Package)> = ids.iter().map(|c| (lp.peers[0].engine.header(c).unwrap().ts, pack(lp, 0, c))).collect();
    x.sort_by_key(|x| x.0);
    x.into_iter().map(|x| x.1).collect()
}

/// A node apart from `setup`'s (seeds 0 to 2).
const FRESH: u64 = 3;

/// A node of the account `setup` grants read on `d` (`fresh_account`), holding `d`, at wall
/// time `at`, holding `base` then `order`.
fn fresh(d: Tid, base: &[Package], order: &[&Package], at: WallMs) -> Peer {
    let mut p = fresh_account();
    p.engine.hold(osis_base::Strong(d)).unwrap();
    p.clock.set(at);
    for x in base.iter().chain(order.iter().copied()) {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    p
}

// spec/commits.md §5 The setting: `retention^.0` has ordinary retention (`admin` by default),
// is snapshotted like any aspect, is written whole and never undone
#[test]
fn setting_itself_ordinary_spec_commits_5() {
    assert_eq!(fixed_purge_by("retention^.0"), None);
    let (mut lp, d) = setup();
    let c = set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    let h = lp.peers[0].engine.header(&c).unwrap();
    assert_eq!(h.aspects.iter().find(|a| a.ak.as_str() == "retention^.0").unwrap().purge_by, PurgeBy::Admin);
    assert!(lp.peers[0].engine.snapshot(&d, &ak("retention^.0")).unwrap().is_some(), "compacted as any aspect");
    // a partial write would say something else alone
    let mut m = Mutation::new();
    m.op(d, &ct::RETENTION, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("t:x"))], op: osis_crdt::Op::Set(ct::RetentionEntry::default().to_value()) }).unwrap();
    assert!(lp.peers[0].commit(m).is_err(), "a partial write refused");
    // an undo of it writes nothing on it
    let mut m = Mutation::new();
    m.undo(c);
    if let Ok(Some(u)) = lp.peers[0].commit(m) {
        assert!(lp.peers[0].engine.header(&u).unwrap().aspects.iter().all(|a| a.ak.as_str() != "retention^.0"));
    }
}

// spec/permissions.md §5.2, §6: a writer's setting is invalid: it goes at every node but its
// author's and keeps nothing in history; no other delta's validity depends on a setting
#[test]
fn writers_setting_keeps_nothing_spec_perm_6() {
    let (mut lp, d) = setup();
    let x = setting(&[(A, History::FOREVER)]);
    let mut m = Mutation::new();
    m.set(d, &ct::RETENTION, &x).unwrap();
    assert!(matches!(lp.peers[1].commit(m), Err(osis_engine::Error::Permission { .. })));
    let mut m = Mutation::new();
    m.set(d, &ct::RETENTION, &x).unwrap();
    let junk = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let v1 = put(&mut lp, 1, d, "one");
    let v2 = put(&mut lp, 1, d, "two");
    lp.sync_all().unwrap();
    for i in [0, 2] {
        let e = &lp.peers[i].engine;
        assert_eq!(e.body_valid(&junk, &d, &ak("retention^.0")), Some(false), "peer {i}");
        assert!(!e.body_not_dropped(&junk, &d, &ak("retention^.0")), "peer {i}: gone");
        assert!(e.body_valid(&v1, &d, &ak(A)).unwrap() && e.body_valid(&v2, &d, &ak(A)).unwrap());
        assert!(!listed(&mut lp.peers[i], &v1, d), "peer {i}: no history promised");
    }
}

// spec/commits.md §5 The setting: past `MAX_RETENTION_ENTRIES` or with a key that is no AK a
// delta is no setting, and a writer refuses it
#[test]
fn setting_over_its_bounds_is_none_spec_commits_5() {
    let n = osis_base::format::MAX_RETENTION_ENTRIES;
    let entry = ct::RetentionEntry { history: Some(History::FOREVER), ..Default::default() };
    let many: ct::RetentionSetting = (0..=n).map(|i| (ak(&format!("t:n{i}.0")), entry)).collect();
    let fits: ct::RetentionSetting = (0..n).map(|i| (ak(&format!("t:n{i}.0")), entry)).collect();
    assert!(ct::setting_fits(&fits) && !ct::setting_fits(&many));
    let Value::Map(mut no_ak) = setting(&[(A, History::FOREVER)]).to_value() else { panic!() };
    no_ak.insert(Value::Int(0), Value::Map([(s("t:reg"), entry.to_value())].into_iter().collect()));
    let raw = osis_schema::Aspect::<Value>::new("retention^.0", &osis_schema::CORE);
    for over in [many.to_value(), Value::Map(no_ak)] {
        assert!(ct::retention_setting(&over).is_none());
        let (mut lp, d) = setup();
        let mut m = Mutation::new();
        m.set(d, &raw, &over).unwrap();
        assert!(lp.peers[0].commit(m).is_err(), "refused");
        let mut m = Mutation::new();
        m.set(d, &raw, &over).unwrap();
        lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
        lp.advance(1_000);
        let v1 = put(&mut lp, 1, d, "one");
        put(&mut lp, 1, d, "two");
        lp.sync_all().unwrap();
        assert!(!listed(&mut lp.peers[2], &v1, d), "no setting keeps it");
    }
}

// spec/commits.md §5 In force: the timeline (`ix.retention`) survives an open and a rebuild
#[test]
fn setting_after_reopen_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    put(&mut lp, 1, d, "two");
    lp.sync_all().unwrap();
    let want = format!("{:?}", lp.peers[2].engine.core.ix.retention.get(&d));
    assert!(listed(&mut lp.peers[2], &v1, d));
    lp.peers[2].restart(321).unwrap();
    assert_eq!(format!("{:?}", lp.peers[2].engine.core.ix.retention.get(&d)), want);
    assert!(listed(&mut lp.peers[2], &v1, d));
    lp.peers[2].engine.rebuild_index().unwrap();
    assert_eq!(format!("{:?}", lp.peers[2].engine.core.ix.retention.get(&d)), want);
    assert!(listed(&mut lp.peers[2], &v1, d));
}

// spec/commits.md §5 The setting, Dropped stays dropped: a shortening hides what it ends at once,
// and a later extension reaches what each node still holds, never what it dropped
#[test]
fn shortening_hides_and_extension_reaches_only_what_is_held_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    put(&mut lp, 1, d, "two");
    lp.sync_all().unwrap();
    assert!(listed(&mut lp.peers[2], &v1, d));
    set(&mut lp, 0, d, &setting(&[]));
    lp.sync_all().unwrap();
    assert!(!listed(&mut lp.peers[2], &v1, d), "shortened: out");
    // Alice covers and drops it (out of history); the others hold it
    lp.peers[0].engine.snapshot(&d, &ak(A)).unwrap().unwrap();
    lp.peers[0].engine.drop_body(&v1, &d, &ak(A)).unwrap();
    assert!(lp.peers[2].engine.body_not_dropped(&v1, &d, &ak(A)));
    set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    lp.sync_all().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&v1, &d, &ak(A)), "dropped stays dropped");
    for i in 0..3 {
        let held = lp.peers[i].engine.body_not_dropped(&v1, &d, &ak(A));
        assert_eq!(listed(&mut lp.peers[i], &v1, d), held, "peer {i}: an extension reaches what is held");
    }
    assert!(listed(&mut lp.peers[2], &v1, d), "a reader holding it shows it again");
    // what is replaced under the extension is kept
    let v3 = put(&mut lp, 1, d, "three");
    put(&mut lp, 1, d, "four");
    lp.sync_all().unwrap();
    assert!(listed(&mut lp.peers[2], &v3, d));
}

// spec/commits.md §5 Dropped stays dropped: a node that rightly dropped a body out of history
// does not fetch it again when a late setting (stamped earlier) puts it in history, nor take a
// copy a node still holding it (and listing it) offers
#[test]
fn dropped_before_a_late_extension_is_not_fetched_spec_commits_5() {
    let (mut lp, d) = setup();
    // Carol's setting, stamped before the writes, reaches the others late
    let x = set(&mut lp, 2, d, &setting(&[(A, History::FOREVER)]));
    let px = pack(&mut lp, 2, &x);
    let v1 = put(&mut lp, 1, d, "one");
    put(&mut lp, 1, d, "two");
    let snap = lp.peers[1].engine.snapshot(&d, &ak(A)).unwrap().unwrap();
    for i in [0, 1] {
        for c in [v1, snap] {
            let pk = pack(&mut lp, 1, &c);
            lp.deliver(i, &pk).unwrap();
        }
    }
    // Alice drops v1 as covered: out of history, nothing keeps it
    lp.peers[0].engine.drop_body(&v1, &d, &ak(A)).unwrap();
    for i in [0, 1] {
        lp.deliver(i, &px).unwrap();
    }
    let ai = lp.peers[0].engine.header(&v1).unwrap().aspects.iter().position(|a| a.ak == ak(A)).unwrap();
    let m = lp.peers[0].engine.core.ix.commits.get(&v1).unwrap();
    assert!(m.is_dropped(ai) && !m.missing(ai), "dropped, not missing: not fetched");
    assert!(!listed(&mut lp.peers[0], &v1, d), "not held: not listed");
    assert!(listed(&mut lp.peers[1], &v1, d), "held: in history");
    // Bob, holding it, offers everything: Alice takes no copy
    lp.sync(1, 0).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&v1, &d, &ak(A)), "a copy offered is not taken");
    assert!(!listed(&mut lp.peers[0], &v1, d));
}

// spec/commits.md §5 (purge on replace cover), §5 (purge on replace drop): a setting arriving late at a
// writer holding a body it puts under purge on replace makes the writer cover it (one snapshot),
// and the body goes
#[test]
fn late_purge_on_replace_setting_makes_holders_cover_spec_commits_5() {
    let (mut lp, d) = setup();
    let x = set(&mut lp, 2, d, &setting(&[(A, History::PurgeOnReplace)]));
    let px = pack(&mut lp, 2, &x);
    let v1 = put(&mut lp, 1, d, "one");
    put(&mut lp, 1, d, "two");
    let snaps = |p: &mut Peer| p.engine.commit_ids().iter().filter(|c| p.engine.header(c).unwrap().kind == osis_commit::Kind::ContentSnapshot).count();
    assert_eq!(snaps(&mut lp.peers[1]), 0);
    assert!(lp.peers[1].engine.body_not_dropped(&v1, &d, &ak(A)), "no setting held: kept");
    lp.deliver(1, &px).unwrap();
    assert_eq!(snaps(&mut lp.peers[1]), 1, "the writer covers it");
    assert!(!lp.peers[1].engine.body_not_dropped(&v1, &d, &ak(A)), "and it goes");
    assert!(!listed(&mut lp.peers[1], &v1, d));
}

// spec/commits.md §5 One way: a keep after purge on replace carries a floor at its own stamp, so
// what was written before it is under purge on replace when replaced, at every node; what is
// written after it is kept
#[test]
fn purge_then_keep_keeps_what_is_written_after_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, History::PurgeOnReplace)]));
    let v0 = put(&mut lp, 0, d, "zero");
    lp.advance(1_000);
    let k = set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    let e = lp.peers[0].engine.get(&d, &ak("retention^.0")).unwrap().and_then(|v| ct::retention_setting(&v)).unwrap();
    assert_eq!(e.rules[&ak(A)].purge_before, Some(lp.peers[0].engine.header(&k).unwrap().ts), "the floor at its own stamp");
    lp.advance(1_000);
    let v1 = put(&mut lp, 0, d, "one");
    put(&mut lp, 0, d, "two");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(!listed(&mut lp.peers[i], &v0, d), "peer {i}: written before the floor");
        assert!(listed(&mut lp.peers[i], &v1, d), "peer {i}: written after it");
    }
    assert!(!lp.peers[0].engine.body_not_dropped(&v0, &d, &ak(A)), "the writer covered it");
}

// spec/commits.md §5 One way: the floor is the keep's whole `ts`, so content written in the
// same ms as the keep, before it, is under the floor too, at every node
#[test]
fn written_in_the_keeps_own_ms_before_it_is_floored_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, History::PurgeOnReplace)]));
    let mut m = Mutation::new();
    m.set(d, &ak(A), &s("zero")).unwrap();
    let v0 = lp.peers[0].commit(m).unwrap().unwrap();
    let k = set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    let (h0, hk) = (lp.peers[0].engine.header(&v0).unwrap().ts, lp.peers[0].engine.header(&k).unwrap().ts);
    assert!(h0.wall_ms() == hk.wall_ms() && h0 < hk, "one ms, the write first");
    put(&mut lp, 0, d, "one");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(!listed(&mut lp.peers[i], &v0, d), "peer {i}: written before the floor");
    }
}

// spec/commits.md §5 One way: concurrent admins. Alice turns purge on replace on; Carol, not
// holding it, writes a keep, which carries no floor. A node holding both joins the floor at the
// keep's stamp, in either order, so content replaced under Alice's setting is not listed (by the
// keep alone it would be); what is written after the keep is. Carol, once she holds Alice's,
// writes the join into her next setting.
#[test]
fn concurrent_admins_lose_no_purge_floor_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    let p = set(&mut lp, 0, d, &setting(&[(A, History::PurgeOnReplace)]));
    let v0 = put(&mut lp, 1, d, "zero");
    let v1 = put(&mut lp, 1, d, "one");
    let k = set(&mut lp, 2, d, &setting(&[(A, History::FOREVER)]));
    let v2 = put(&mut lp, 1, d, "two");
    let v3 = put(&mut lp, 1, d, "three");
    let kept = ct::retention_setting(&lp.peers[2].engine.get(&d, &ak("retention^.0")).unwrap().unwrap()).unwrap();
    assert_eq!(kept.rules[&ak(A)].purge_before, None, "written without Alice's setting");
    let pk: Vec<Package> = [(0, &p), (1, &v0), (1, &v1), (2, &k), (1, &v2), (1, &v3)].into_iter().map(|(i, c)| pack(&mut lp, i, c)).collect();
    let rest = [&pk[1], &pk[2], &pk[4], &pk[5]];
    let now = lp.peers[0].engine.now();
    let mut alone = fresh(d, &base, &[&pk[3], rest[0], rest[1], rest[2], rest[3]], now);
    assert!(listed(&mut alone, &v0, d), "the keep alone lists it: that node never heard of the purge");
    for order in [[&pk[0], &pk[3]], [&pk[3], &pk[0]]] {
        let mut n = fresh(d, &base, &[order[0], order[1], rest[0], rest[1], rest[2], rest[3]], now);
        assert!(!listed(&mut n, &v0, d), "replaced under purge on replace");
        assert!(listed(&mut n, &v2, d), "written after the keep");
    }
    lp.deliver(2, &pk[0]).unwrap();
    let k2 = set(&mut lp, 2, d, &setting(&[(A, History::FOREVER)]));
    let joined = ct::retention_setting(&lp.peers[2].engine.get(&d, &ak("retention^.0")).unwrap().unwrap()).unwrap();
    assert_eq!(joined.rules[&ak(A)].purge_before, Some(lp.peers[2].engine.header(&k).unwrap().ts), "the join, at the keep's stamp");
    let pk2 = pack(&mut lp, 2, &k2);
    let mut later = fresh(d, &base, &[&pk2, rest[0], rest[1], rest[2], rest[3]], now);
    assert!(!listed(&mut later, &v0, d) && listed(&mut later, &v2, d), "the carried join, alone");
}

// spec/commits.md §5 Purge on replace: content replaced under purge on replace is never listed,
// even when its replacing write is stamped ahead of the node's clock (within drift)
#[test]
fn purge_on_replace_never_listed_ahead_of_the_clock_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    // a keep before it: the timeline dates its bodies
    let k = set(&mut lp, 0, d, &setting(&[(A, keep(10 * HOUR))]));
    let x = set(&mut lp, 0, d, &setting(&[(A, History::PurgeOnReplace)]));
    let v1 = put(&mut lp, 1, d, "one");
    let v2 = put(&mut lp, 1, d, "two");
    let pks = [pack(&mut lp, 0, &k), pack(&mut lp, 0, &x), pack(&mut lp, 1, &v1), pack(&mut lp, 1, &v2)];
    // half an hour behind the writer
    let at = WallMs(lp.peers[0].engine.now().0 - HOUR / 2);
    let mut p = fresh(d, &base, &[&pks[0], &pks[1], &pks[2], &pks[3]], at);
    assert!(p.engine.body_not_dropped(&v1, &d, &ak(A)), "a reader holds it until a writer covers it");
    assert!(!listed(&mut p, &v1, d), "never history");
}

// spec/commits.md §5 Keep bounds (a body leaves history no earlier than replaced): a part replaced ahead of a reader's clock is bounded by its
// replacement until the clock reaches it; a value reading the bound is due again then, by time
// alone.
#[test]
fn a_replacement_ahead_of_the_clock_bounds_until_reached_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    // v1 written under purge on replace, replaced after the keep: under its floor, out at its
    // replacement, but dated (the current setting keeps history)
    let x = set(&mut lp, 0, d, &setting(&[(A, History::PurgeOnReplace)]));
    let v1 = put(&mut lp, 1, d, "one");
    lp.advance(1_000);
    let k = set(&mut lp, 0, d, &setting(&[(A, keep(10 * HOUR))]));
    lp.advance(1_000);
    let v2 = put(&mut lp, 1, d, "two");
    let pks = [pack(&mut lp, 0, &x), pack(&mut lp, 1, &v1), pack(&mut lp, 0, &k), pack(&mut lp, 1, &v2)];
    let at = WallMs(lp.peers[0].engine.now().0 - HOUR / 2);
    let mut p = fresh(d, &base, &[&pks[0], &pks[1], &pks[2], &pks[3]], at);
    let r = p.engine.header(&v2).unwrap().ts.wall_ms().0;
    let mut fx: osis_base::memo::Effects<(), Vec<u64>> = osis_base::memo::Effects::new("test keeps");
    fx.want(());
    let (_, first) = fx.settle(&(), || p.engine.part_keeps(&v1).unwrap()).unwrap();
    assert_eq!(first, vec![r], "bounded by its replacement ahead of the clock");
    p.clock.advance(HOUR);
    let now = p.engine.now();
    p.engine.set_now(now);
    assert_eq!(fx.due(), vec![()], "the clock passing the replacement moves it");
    let (_, after) = fx.settle(&(), || p.engine.part_keeps(&v1).unwrap()).unwrap();
    assert!(after.iter().all(|b| *b < r), "{after:?}");
}

// spec/commits.md §5 Dated only where history is kept: each part of a body is dated by its own
// writes and kept by its own aspect's setting alone. One commit writes the register (kept an
// hour) and another aspect (no history). Replacing only the other aspect dates nothing: the kept
// part is current, kept while live, and the unkept part has no bound; spec/commits.md §7 Listed
// parts: the unkept part is not listed (current by its own writes only). Replacing the kept part
// then keeps that part an hour from its own replacement, and the other part none.
#[test]
fn a_part_keeps_by_its_own_aspect_spec_commits_5() {
    for (kept, other) in [("t:b.0", "t:a.0"), ("t:a.0", "t:b.0")] {
        let (mut lp, d) = setup();
        set(&mut lp, 0, d, &setting(&[(kept, keep(HOUR))]));
        lp.sync_all().unwrap();
        let mut m = Mutation::new();
        m.set(d, &ak(kept), &s("k")).unwrap();
        m.set(d, &ak(other), &s("x")).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        let live = |e: &mut osis_engine::Engine| e.header(&c).unwrap().aspects.iter().map(|a| if a.ak == ak(kept) { u64::MAX } else { 0 }).collect::<Vec<_>>();
        let want = live(&mut lp.peers[1].engine);
        assert_eq!(lp.peers[1].engine.part_keeps(&c).unwrap(), want, "{kept}: the kept part kept while live, the other none");
        let mut m = Mutation::new();
        m.set(d, &ak(other), &s("y")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.part_keeps(&c).unwrap(), want, "{kept}: the other aspect's death dates no kept part");
        assert_eq!(e.replaced_at(&c, &d, &ak(other)).unwrap(), None, "{kept}: no history on the other aspect");
        assert!(e.delta_live(&c, &d, &ak(kept)).unwrap(), "{kept}: the kept part is current");
        // listing is per part: the kept part's live write keeps no other part listed
        assert!(e.listed_at(&c, &[(d, ak(kept))]).unwrap(), "{kept}: the current part listed");
        assert!(!e.listed_at(&c, &[(d, ak(other))]).unwrap(), "{kept}: the replaced unkept part not listed");
        let mut m = Mutation::new();
        m.set(d, &ak(kept), &s("l")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        let r = lp.peers[1].engine.now().0;
        lp.advance(1_000);
        let e = &mut lp.peers[1].engine;
        assert_eq!((part_keep(e, &c, &d, &ak(kept)), part_keep(e, &c, &d, &ak(other))), (r + HOUR, 0), "{kept}: kept by its own replacement alone");
    }
}

// spec/requirements.md Purge on replace, spec/commits.md §5 (purge on replace drop): every node
// holding it drops the body once it holds the cover; §5 Keep bounds (each delta kept by its
// own aspect's setting alone): one commit writes a kept aspect and a purge-on-replace one in one
// body; replacing both, the writer covers the purge-on-replace part and it goes at once at every
// node holding it, while the kept part stays an hour from its own replacement.
#[test]
fn purge_on_replace_part_goes_whatever_its_commit_keeps_spec_commits_5() {
    let (kept, gone) = ("t:a.0", "t:b.0");
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(kept, keep(HOUR)), (gone, History::PurgeOnReplace)]));
    lp.sync_all().unwrap();
    let both = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.set(d, &ak(kept), &s(v)).unwrap();
        m.set(d, &ak(gone), &s(v)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        c
    };
    let c = both(&mut lp, "one");
    lp.sync_all().unwrap();
    both(&mut lp, "two");
    let r = lp.peers[1].engine.now().0 - 1_000;
    lp.sync_all().unwrap();
    // at the writer, and at the admins that held the whole body before the replacement came
    for (i, p) in lp.peers.iter_mut().enumerate() {
        let e = &mut p.engine;
        assert!(e.body_not_dropped(&c, &d, &ak(kept)), "node {i}: the kept part stays");
        assert_eq!(part_keep(e, &c, &d, &ak(kept)), r + HOUR, "node {i}: kept by its own replacement");
        assert!(!e.body_not_dropped(&c, &d, &ak(gone)), "node {i}: the purge-on-replace part is gone");
    }
}

// spec/commits.md §5 In force: two admins' settings at one wall ms are ordered by key, whatever
// order they arrive in: the later by key is in force, the other for no time at all
#[test]
fn two_admins_at_one_stamp_ordered_by_key_spec_commits_5() {
    let mut seen = Vec::new();
    for keeper in [0, 2] {
        let (mut lp, d) = setup();
        let base = base(&mut lp);
        let other = 2 - keeper;
        let k = set_setting(&mut lp, keeper, d, &setting(&[(A, keep(HOUR))]));
        let n = set_setting(&mut lp, other, d, &setting(&[]));
        lp.advance(1_000);
        let (hk, hn) = (lp.peers[keeper].engine.header(&k).unwrap(), lp.peers[other].engine.header(&n).unwrap());
        assert_eq!(hk.ts.wall_ms(), hn.ts.wall_ms(), "one wall ms");
        let keeps = (hk.ts, hk.signer, k) > (hn.ts, hn.signer, n);
        seen.push(keeps);
        let v1 = put(&mut lp, 1, d, "one");
        let v2 = put(&mut lp, 1, d, "two");
        let pks = [pack(&mut lp, keeper, &k), pack(&mut lp, other, &n), pack(&mut lp, 1, &v1), pack(&mut lp, 1, &v2)];
        let now = lp.peers[1].engine.now();
        for order in [[0, 1, 2, 3], [1, 0, 2, 3], [2, 3, 1, 0], [3, 0, 2, 1]] {
            let mut p = fresh(d, &base, &order.map(|i| &pks[i]), now);
            assert_eq!(listed(&mut p, &v1, d), keeps, "keeper {keeper}, {order:?}: the later by key is in force");
        }
    }
    assert!(seen.contains(&true) && seen.contains(&false), "{seen:?}");
}

// notes/engine-retention-dating.md When, spec/crdt.md §4.8 When: a write dies at its superseder's own
// stamp, read from any held body holding it. x1 is replaced by x2, kept 10 minutes; a snapshot
// taken later carries x2, and x2's body drops under it: x1 still dies at x2's stamp, so its
// listing and keep stay (dated at the snapshot, x1 was listed again)
#[test]
fn a_covered_drop_redates_nothing_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let x1 = put(&mut lp, 0, d, "one");
    let x2 = put(&mut lp, 0, d, "two");
    lp.advance(5 * 60_000);
    lp.peers[0].engine.snapshot(&d, &ak(A)).unwrap().unwrap();
    lp.advance(7 * 60_000);
    lp.peers[0].tick().unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.body_not_dropped(&x1, &d, &ak(A)) && e.body_not_dropped(&x2, &d, &ak(A)));
    let keep = e.part_keeps(&x1).unwrap();
    assert!(!listed(&mut lp.peers[0], &x1, d), "out of history 10 minutes after x2");
    let e = &mut lp.peers[0].engine;
    e.drop_body(&x2, &d, &ak(A)).unwrap();
    assert!(!e.body_not_dropped(&x2, &d, &ak(A)), "x2 is live and covered: in no history, it drops");
    assert_eq!(e.part_keeps(&x1).unwrap(), keep, "x1's keep stays");
    assert!(!listed(&mut lp.peers[0], &x1, d), "x1 is not listed again");
}

// spec/commits.md §5 (when a body was replaced): a date is a function of the held bodies, so a
// body leaving before its bound (`Engine::drop_body` skips it) takes its superseding writes with
// it: what it replaced dies at the next held superseder (`bounds::moved_by_changes` following a
// leaving body; a row left at the dropped one is early).
#[test]
fn a_body_leaving_redates_what_it_replaced_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let x1 = put(&mut lp, 0, d, "one");
    lp.advance(1_000);
    let x2 = put(&mut lp, 0, d, "two");
    lp.advance(1_000);
    let x3 = put(&mut lp, 0, d, "three");
    lp.advance(1_000);
    let e = &mut lp.peers[0].engine;
    let s = e.snapshot(&d, &ak(A)).unwrap().unwrap();
    assert_eq!(e.replaced_at(&x1, &d, &ak(A)).unwrap(), Some(e.header(&x2).unwrap().ts));
    assert_eq!(e.covered(&s, &x2, &d, &ak(A)).unwrap(), Some(true));
    e.drop_body(&x2, &d, &ak(A)).unwrap();
    assert_eq!(e.replaced_at(&x1, &d, &ak(A)).unwrap(), Some(e.header(&x3).unwrap().ts), "x1 dies at x3 once x2 is gone");
}

/// Drops, in `order`, each held body of `(d, a)` that `s` covers once its keep-at-least bound
/// allows (`Engine::drop_from` on the node's clock, as node-sync does), and checks after each
/// drop that every commit in `watch` still held is listed and kept (in history: its keep bound
/// ahead of the clock) as before (notes/engine-retention-dating.md Invariant). Returns the
/// bodies dropped.
fn drop_allowed(p: &mut Peer, d: Tid, a: &str, s: CommitId, order: &[CommitId], watch: &[CommitId]) -> Vec<CommitId> {
    let k = ak(a);
    let listed = |p: &mut Peer| -> Vec<Option<(bool, bool)>> {
        let now = p.engine.now().0;
        watch.iter().map(|c| p.engine.body_not_dropped(c, &d, &k).then(|| (p.engine.listed_at(c, &[(d, k.clone())]).unwrap(), p.engine.part_keeps(c).unwrap().iter().any(|x| *x > now)))).collect()
    };
    let before = listed(p);
    let mut dropped = Vec::new();
    for c in order {
        let now = p.engine.now().0;
        if !p.engine.body_not_dropped(c, &d, &k) || p.engine.drop_from(c, &d, &k).unwrap() > now || p.engine.covered(&s, c, &d, &k).unwrap() != Some(true) {
            continue;
        }
        p.engine.drop_body(c, &d, &k).unwrap();
        dropped.push(*c);
        let after = listed(p);
        assert!(after.iter().zip(&before).all(|(a, b)| a.is_none() || a == b), "{order:?}: dropping {c:?} moved a listing or keep: {before:?} to {after:?}");
    }
    dropped
}

// notes/engine-retention-dating.md When, spec/commits.md §5 Bodies and deaths: a body is replaced at
// the latest death among its writes. W sets field 1; B sets fields 0 and 1; C replaces B's field
// 0 at once, X its field 1 twelve minutes later (kept 10 minutes). B stays in history from X's
// stamp, so it drops only after every dead write it alone holds has left; W, which only B's
// field 1 dated, never shows again whatever drops first (B dated at its first death dropped
// early, and W redated to X)
#[test]
fn a_body_dies_at_its_latest_death_spec_commits_5() {
    const REC: &str = "t:rec.0";
    for first in [true, false] {
        let (mut lp, d) = setup();
        let field = |lp: &mut LocalPeer, fs: &[(u64, Value)]| {
            let mut m = Mutation::new();
            for (f, v) in fs {
                m.op(d, &ak(REC), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(*f)], op: osis_crdt::Op::Set(v.clone()) }).unwrap();
            }
            let c = lp.peers[0].commit(m).unwrap().unwrap();
            lp.advance(1_000);
            c
        };
        set(&mut lp, 0, d, &setting(&[(REC, keep(10 * 60_000))]));
        let w = field(&mut lp, &[(1, Value::Int(1))]);
        let b = field(&mut lp, &[(0, s("b")), (1, Value::Int(2))]);
        let c = field(&mut lp, &[(0, s("c"))]);
        lp.advance(12 * 60_000);
        let x = field(&mut lp, &[(1, Value::Int(3))]);
        let snap = lp.peers[0].engine.snapshot(&d, &ak(REC)).unwrap().unwrap();
        let rb = lp.peers[0].engine.replaced_at(&b, &d, &ak(REC)).unwrap();
        assert_eq!(rb, Some(lp.peers[0].engine.header(&x).unwrap().ts), "B at its latest death");
        let order = if first { [b, w, c] } else { [w, c, b] };
        let dropped = drop_allowed(&mut lp.peers[0], d, REC, snap, &order, &[w, b, c]);
        assert!(dropped.contains(&w) && !dropped.contains(&b), "{dropped:?}: W out of history, B in it");
    }
}

// notes/engine-retention-dating.md When, spec/crdt.md §4.8 When: a text element's creation dies at
// the earliest held delete stamped after its latest held undelete. Inserted, deleted, undeleted
// (an undo of the delete) and deleted again twelve minutes later (kept 10 minutes): the
// creation dies at the second delete, so dropping the first delete's body (out of history,
// covered) puts nothing back in history (dated at the first delete, the insert came back into
// history once that body went)
#[test]
fn text_creation_dies_at_delete_after_undelete_spec_crdt_4_8() {
    const TX: &str = "t:text.0";
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(TX, keep(10 * 60_000))]));
    let op = |lp: &mut LocalPeer, op: osis_crdt::Op| {
        let mut m = Mutation::new();
        m.op(d, &TEXT, osis_crdt::PathOp { path: vec![], op }).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        c
    };
    let ins = op(&mut lp, osis_crdt::Op::Insert { at: 0, items: vec![s("x")] });
    let del = op(&mut lp, osis_crdt::Op::Delete { at: 0, len: 1 });
    let mut m = Mutation::new();
    m.undo(del);
    let und = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(12 * 60_000);
    let redel = op(&mut lp, osis_crdt::Op::Delete { at: 0, len: 1 });
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.replaced_at(&ins, &d, &ak(TX)).unwrap(), Some(e.header(&redel).unwrap().ts), "at the delete after the undelete");
    let snap = e.snapshot(&d, &ak(TX)).unwrap().unwrap();
    let dropped = drop_allowed(&mut lp.peers[0], d, TX, snap, &[del, und, ins], &[ins, del, und]);
    assert!(dropped.contains(&del), "{dropped:?}: the first delete is out of history");
}

// spec/crdt.md §4.8 When, notes/engine-retention-dating.md Invariant: a
// valid snapshot's copy of an invalid delta's write counts as the write itself. W is replaced by
// Bob's X; snapshot B carries X; Bob is removed (X invalid, vouched by B), and W still dies at X's
// own stamp. Ten minutes on W is out of history; snapshot S covers B (no dead write: it drops at
// once) and carries X again, so with B dropped W still dies at X: no covered drop moves a listing.
#[test]
fn vouched_copy_dates_at_its_write_spec_crdt_4_8() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let w = put(&mut lp, 0, d, "one");
    let x = put(&mut lp, 1, d, "two");
    lp.sync_all().unwrap();
    let b = lp.peers[0].engine.snapshot(&d, &ak(A)).unwrap().unwrap();
    lp.advance(1_000);
    let bob = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, d, bob, None, Some(ct::Frontier::default()));
    lp.advance(1_000);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&d, &ak(A)).unwrap(), Some(s("two")), "X vouched by B");
    assert_eq!(e.replaced_at(&w, &d, &ak(A)).unwrap(), Some(e.header(&x).unwrap().ts), "W dies at X, not at B");
    lp.advance(11 * 60_000);
    lp.peers[0].tick().unwrap();
    assert!(lp.peers[0].engine.body_not_dropped(&w, &d, &ak(A)) && !listed(&mut lp.peers[0], &w, d), "W held, out of history");
    let e = &mut lp.peers[0].engine;
    let s2 = e.snapshot(&d, &ak(A)).unwrap().unwrap();
    assert!(e.covered(&s2, &b, &d, &ak(A)).unwrap() == Some(true) && e.drop_from(&b, &d, &ak(A)).unwrap() <= e.now().0);
    e.drop_body(&b, &d, &ak(A)).unwrap();
    assert_eq!(e.replaced_at(&w, &d, &ak(A)).unwrap(), Some(e.header(&x).unwrap().ts), "W still dies at X");
    assert!(!listed(&mut lp.peers[0], &w, d), "a covered drop moved W back into history");
}

/// The aspect no setting keeps in `covered_drops_move_nothing_*`, beside `A` (kept ten minutes).
const B: &str = "t:other.0";

/// What a covered drop must leave alone of held part `c` on `a` (`covered_drops_move_nothing_*`):
/// whether it is listed and its body in history, and for a body in history its keep bounds and
/// the part's replaced-at.
type Standing = (bool, bool, Option<(Vec<u64>, Option<osis_base::Ts>)>);

/// `Standing` of `c` on `a` (`None`: dropped).
fn standing(p: &mut Peer, c: &CommitId, d: Tid, a: &str) -> Option<Standing> {
    let now = p.engine.now().0;
    if !p.engine.body_not_dropped(c, &d, &ak(a)) {
        return None;
    }
    let keeps = p.engine.part_keeps(c).unwrap();
    let kept = keeps.iter().any(|x| *x > now);
    let bound = kept.then(|| (keeps, p.engine.replaced_at(c, &d, &ak(a)).unwrap()));
    Some((p.engine.listed_at(c, &[(d, ak(a))]).unwrap(), kept, bound))
}

/// One history of `covered_drops_move_nothing_*`: writes by Alice, Bob and Carol on a register
/// `A` kept ten minutes, on `B` no setting keeps, or on both in one commit,
/// syncs, Alice's snapshots of either, and maybe Bob removed with none of his writes counting
/// (so snapshots vouch for them), at random gaps; then at a node holding all of it every part
/// some held snapshot covers and whose keep bound passed is dropped, in random order.
/// The covered drops `seed`'s history made, each checked.
fn covered_drops_history(seed: u64) -> usize {
    let mut r = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = |n: u64| {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r % n
    };
    let (mut lp, d) = setup_seeded(9000 + seed);
    lp.peers[0].engine.keep_bodies(true);
    // no writer answers the removal: what Bob's writes count for is what snapshots vouch for
    for i in 0..3 {
        lp.peers[i].engine.write_addenda(false);
    }
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let bob = lp.peers[1].engine.me();
    let mut removed = false;
    for i in 0..16 {
        match below(10) {
            0..=3 => {
                let by = [0, 1, 2][below(3) as usize];
                let on: &[&str] = [&[A][..], &[B][..], &[A, B][..]][below(3) as usize];
                if !(removed && by == 1) {
                    let mut m = Mutation::new();
                    for a in on {
                        m.set(d, &ak(a), &s(&format!("v{i}"))).unwrap();
                    }
                    lp.peers[by].commit(m).unwrap().unwrap();
                }
            }
            4 => lp.sync_all().unwrap(),
            5..=7 => {
                lp.sync_all().unwrap();
                lp.peers[0].engine.snapshot(&d, &ak([A, B][below(2) as usize])).unwrap();
            }
            8 | 9 if !removed && i >= 6 => {
                set_edge(&mut lp.peers[0].engine, d, bob, None, Some(ct::Frontier::default()));
                removed = true;
            }
            _ => {}
        }
        lp.advance(below(5 * 60_000));
    }
    lp.sync_all().unwrap();
    lp.advance(below(10 * 60_000));
    for a in [A, B] {
        lp.peers[0].engine.snapshot(&d, &ak(a)).unwrap();
    }
    // a node holding every body Alice wrote or received, dropping nothing on its own
    let mut ids: Vec<(osis_base::Ts, CommitId)> = lp.peers[0].engine.commit_ids().into_iter().map(|c| (lp.peers[0].engine.header(&c).unwrap().ts, c)).collect();
    ids.sort();
    let packs: Vec<Package> = ids.iter().filter_map(|(_, c)| lp.peers[0].engine.package(c).unwrap()).collect();
    let mut p = fresh(d, &packs, &[], lp.peers[0].engine.now());
    let p = &mut p;
    let on: Vec<(CommitId, &str)> =
        p.engine.commit_ids().into_iter().flat_map(|c| [A, B].map(|a| (c, a))).filter(|(c, a)| p.engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.ak == ak(a)))).collect();
    let snaps: Vec<(CommitId, &str)> = on.iter().copied().filter(|(c, _)| p.engine.header(c).unwrap().kind.is_compaction()).collect();
    let before: Vec<_> = on.iter().map(|(c, a)| standing(p, c, d, a)).collect();
    let mut order = on.clone();
    for i in (1..order.len()).rev() {
        order.swap(i, below(i as u64 + 1) as usize);
    }
    let mut dropped = 0;
    for (c, a) in &order {
        let k = ak(a);
        let now = p.engine.now().0;
        if !p.engine.body_not_dropped(c, &d, &k) || p.engine.drop_from(c, &d, &k).unwrap() > now {
            continue;
        }
        let covering = snaps.iter().any(|(s, sa)| sa == a && s != c && p.engine.body_not_dropped(s, &d, &k) && p.engine.covered(s, c, &d, &k).unwrap() == Some(true));
        if !covering || p.engine.drop_body(c, &d, &k).is_err() {
            continue;
        }
        dropped += 1;
        for ((x, xa), b) in on.iter().zip(&before) {
            let now = standing(p, x, d, xa);
            assert!(now.is_none() || now == *b, "seed {seed}: dropping {c:?} on {a} moved {x:?} on {xa}: {b:?} to {now:?}");
        }
    }
    dropped
}

// notes/engine-retention-dating.md Invariant, spec/crdt.md §4.8 When,
// spec/commits.md §5 Dated only where history is kept: random small histories on a kept and an
// unkept aspect, some commits writing both, every covered part past its
// keep bound dropped in random order; no drop moves the listing, in-history status, keep bounds
// or replaced-at of a held body in history.
#[test]
#[ignore = "property"]
fn covered_drops_move_nothing_plain_spec_commits_5() {
    let seeds: Vec<u64> = (0..10).collect();
    let dropped = osis_base::testenv::run_seeds("setting::covered_drops_move_nothing_plain_spec_commits_5", &seeds, false, covered_drops_replay, covered_drops_history);
    osis_base::testenv::reach_floor("seeds dropping a covered body", dropped.into_iter().map(|n| usize::from(n > 0)), 1, 2);
}

/// Seeds: OSIS_COVERED_START, OSIS_COVERED_SEEDS (default 0..1000, a tenth at small size).
#[test]
#[ignore = "property"]
fn covered_drops_move_nothing_large_spec_commits_5() {
    let range = osis_base::testenv::Seeds::from_env("OSIS_COVERED_START", "OSIS_COVERED_SEEDS", osis_base::testenv::large(0..1000));
    let dropped = range.run("setting::covered_drops_move_nothing_large_spec_commits_5", covered_drops_replay, covered_drops_history);
    osis_base::testenv::reach_floor("seeds dropping a covered body", dropped.into_iter().map(|n| usize::from(n > 0)), 1, 2);
}

fn covered_drops_replay(s: u64) -> String {
    format!("OSIS_COVERED_START={s} OSIS_COVERED_SEEDS=1 cargo test -p osis-engine --test it -- --ignored --exact setting::covered_drops_move_nothing_large_spec_commits_5")
}

// spec/commits.md §5 Dated only where history is kept (notes/engine-retention-dating.md
// Invariant): W writes a kept aspect (10 minutes) and an unkept one in one
// commit; B replaces the unkept write, E replaces B fifteen minutes later. W's unkept part is
// dated by nothing (no history on its aspect), so B, also undated, drops at once under a
// snapshot and moves none of W's bounds. Dated across the commit, W was out by B's date and came
// back into history at E's.
#[test]
fn an_unkept_part_dates_no_other_part_spec_commits_5() {
    let (kept, other) = ("t:b.0", "t:a.0");
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(kept, keep(10 * 60_000))]));
    let write = |lp: &mut LocalPeer, fs: &[(&str, &str)]| {
        let mut m = Mutation::new();
        for (a, v) in fs {
            m.set(d, &ak(a), &s(v)).unwrap();
        }
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let w = write(&mut lp, &[(kept, "k"), (other, "x")]);
    lp.advance(1_000);
    let b = write(&mut lp, &[(other, "y")]);
    lp.advance(15 * 60_000);
    write(&mut lp, &[(other, "z")]);
    lp.advance(1_000);
    let e = &mut lp.peers[0].engine;
    e.keep_bodies(true);
    let snap = e.snapshot(&d, &ak(other)).unwrap().unwrap();
    assert!(e.covered(&snap, &b, &d, &ak(other)).unwrap() == Some(true) && e.drop_from(&b, &d, &ak(other)).unwrap() <= e.now().0);
    let before = (e.part_keeps(&w).unwrap(), e.replaced_at(&w, &d, &ak(kept)).unwrap(), e.replaced_at(&w, &d, &ak(other)).unwrap());
    let live: Vec<u64> = e.header(&w).unwrap().aspects.iter().map(|a| if a.ak == ak(kept) { u64::MAX } else { 0 }).collect();
    assert_eq!(before, (live, None, None), "W's kept part current (kept while live), its other part undated");
    e.drop_body(&b, &d, &ak(other)).unwrap();
    assert_eq!((e.part_keeps(&w).unwrap(), e.replaced_at(&w, &d, &ak(kept)).unwrap(), e.replaced_at(&w, &d, &ak(other)).unwrap()), before, "a covered drop moved W");
}

/// Peer `p` listens for commit events on every thing.
fn watch(p: &mut Peer) {
    p.engine.listen_commits(std::sync::Arc::new(|_| true));
    p.drain_events();
}

/// The commits on `(d, A)` commit events named since the last drain.
fn told(p: &mut Peer, d: Tid) -> Vec<CommitId> {
    let mut out = Vec::new();
    for e in p.drain_events() {
        if let osis_engine::Event::Commits(ch) = e {
            out.extend(ch.iter().filter(|x| x.tid == d && x.ak == ak(A)).map(|x| x.id));
        }
    }
    out
}

// spec/commits.md §5 The setting, notes/api.md Commits: what is listed follows the setting,
// whatever order the setting and the bodies arrive in, and across a restart: kept an hour after
// replaced, then not; the body leaving history as its window passes is told to a commit
// listener, and nothing that stays is told
#[test]
fn history_follows_the_setting_and_leaving_is_told_in_any_order_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    let x = set(&mut lp, 0, d, &setting(&[(A, keep(HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    let v2 = put(&mut lp, 1, d, "two");
    let pks = [pack(&mut lp, 0, &x), pack(&mut lp, 1, &v1), pack(&mut lp, 1, &v2)];
    let now = lp.peers[0].engine.now();
    let orders = [[0, 1, 2], [1, 0, 2], [1, 2, 0], [2, 1, 0], [0, 2, 1], [2, 0, 1]].map(|o| (o, false));
    for (order, restart) in orders.into_iter().chain([([1, 2, 0], true)]) {
        let mut p = fresh(d, &base, &order.map(|i| &pks[i]), now);
        if restart {
            p.restart(355).unwrap();
        }
        assert!(listed(&mut p, &v1, d), "{order:?}: in history");
        assert!(listed(&mut p, &v2, d), "{order:?}: live");
        watch(&mut p);
        p.clock.advance(HOUR - 5_000);
        p.tick().unwrap();
        assert!(told(&mut p, d).is_empty(), "{order:?}: nothing leaves before its window passes");
        p.clock.advance(7_000);
        p.tick().unwrap();
        assert_eq!(told(&mut p, d), vec![v1], "{order:?}: told as it leaves");
        assert!(!listed(&mut p, &v1, d) && listed(&mut p, &v2, d), "{order:?}: out an hour after replaced");
        p.clock.advance(10 * HOUR);
        p.tick().unwrap();
        assert!(told(&mut p, d).is_empty(), "{order:?}: the live one stays");
    }
}

// spec/commits.md §5 The setting (notes/engine-retention-history.md Tess's decisions, 1): a setting arriving late, stamped while a body was
// still in history, brings back a body that left meanwhile where it is still held: listed and told
// again; a later shortening by its stamp takes it out again, told
#[test]
fn late_setting_brings_back_and_is_told_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    put(&mut lp, 1, d, "two");
    lp.sync_all().unwrap();
    // Carol extends while v1 is in history; Alice receives it two hours later
    let late = set(&mut lp, 2, d, &setting(&[(A, keep(10 * HOUR))]));
    let pk = pack(&mut lp, 2, &late);
    watch(&mut lp.peers[0]);
    lp.advance(2 * HOUR);
    lp.peers[0].tick().unwrap();
    assert_eq!(told(&mut lp.peers[0], d), vec![v1], "left");
    assert!(!listed(&mut lp.peers[0], &v1, d));
    lp.deliver(0, &pk).unwrap();
    assert!(listed(&mut lp.peers[0], &v1, d), "back where held");
    assert!(told(&mut lp.peers[0], d).contains(&v1), "told as it comes back");
    let short = set(&mut lp, 0, d, &setting(&[(A, keep(HOUR))]));
    assert!(lp.peers[0].engine.header(&short).is_some());
    assert!(!listed(&mut lp.peers[0], &v1, d), "out from the shortening's stamp");
    assert!(told(&mut lp.peers[0], d).contains(&v1), "told as it leaves");
}

// spec/commits.md §5 The setting: the first setting keeping an aspect, arriving after bodies
// replaced since its stamp, shows the held ones and tells them
#[test]
fn first_keeping_setting_arriving_late_shows_and_tells_spec_commits_5() {
    let (mut lp, d) = setup();
    let late = set(&mut lp, 2, d, &setting(&[(A, keep(10 * HOUR))]));
    let pk = pack(&mut lp, 2, &late);
    let v1 = put(&mut lp, 1, d, "one");
    let v2 = put(&mut lp, 1, d, "two");
    for c in [v1, v2] {
        let p = pack(&mut lp, 1, &c);
        lp.deliver(0, &p).unwrap();
    }
    assert!(!listed(&mut lp.peers[0], &v1, d), "no history promised yet");
    watch(&mut lp.peers[0]);
    lp.deliver(0, &pk).unwrap();
    assert!(listed(&mut lp.peers[0], &v1, d), "in history from the setting's stamp");
    assert!(told(&mut lp.peers[0], d).contains(&v1), "told as it shows");
    lp.advance(11 * HOUR);
    lp.peers[0].tick().unwrap();
    assert!(!listed(&mut lp.peers[0], &v1, d) && told(&mut lp.peers[0], d).contains(&v1), "and as it leaves");
}

// notes/engine-retention-history.md Leaving history, notes/api.md Commits (listeners): a snapshot whose
// carried write a later write kills leaves the listing at its keep bound, and is told then.
#[test]
fn a_snapshot_is_told_leaving_history_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let x1 = put(&mut lp, 0, d, "one");
    let s = lp.peers[0].engine.snapshot(&d, &ak(A)).unwrap().unwrap();
    lp.advance(1_000);
    lp.peers[0].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
    put(&mut lp, 0, d, "two");
    assert!(listed(&mut lp.peers[0], &x1, d) && listed(&mut lp.peers[0], &s, d), "in history");
    lp.peers[0].drain_events();
    lp.advance(11 * 60_000);
    lp.peers[0].tick().unwrap();
    let mut told = Vec::new();
    for e in lp.peers[0].drain_events() {
        if let osis_engine::Event::Commits(ch) = e {
            told.extend(ch.iter().filter(|x| x.tid == d).map(|x| x.id));
        }
    }
    for c in [x1, s] {
        assert!(!listed(&mut lp.peers[0], &c, d) && told.contains(&c), "{c:?} left history, told");
    }
}

// spec/commits.md §5 The setting: a body leaves history when the current setting stops keeping
// it, never before it was replaced. Alice keeps the register 10 min after replaced and writes it;
// Bob replaces it; Carol replaces it again. A node whose clock is behind all of it gets Carol's
// write before Bob's: Alice's write is dated at Bob's stamp whatever the order (its row is its
// replaced-at), in history until the clock passes 10 min after it, and told once out.
#[test]
fn a_late_row_leaves_no_earlier_than_replaced_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    let early = lp.peers[0].engine.now();
    let keep = set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let v = put(&mut lp, 0, d, "alice");
    lp.sync_all().unwrap();
    let b = put(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let c = put(&mut lp, 2, d, "carol");
    let packs: Vec<Package> = [(0, keep), (0, v), (2, c), (1, b)].iter().map(|(i, x)| pack(&mut lp, *i, x)).collect();
    let mut p = fresh(d, &base, &packs.iter().collect::<Vec<_>>(), early);
    p.engine.listen_commits(std::sync::Arc::new(|_: &Tid| true));
    p.drain_events();
    let told = |p: &mut Peer| -> Vec<CommitId> { p.drain_events().into_iter().filter_map(|e| if let osis_engine::Event::Commits(ch) = e { Some(ch.iter().filter(|x| x.tid == d).map(|x| x.id).collect::<Vec<_>>()) } else { None }).flatten().collect() };
    let now = lp.peers[0].engine.now();
    p.clock.set(now);
    p.tick().unwrap();
    assert!(listed(&mut p, &v, d) && !told(&mut p).contains(&v), "in history, not told");
    p.clock.set(WallMs(now.0 + 10 * 60_000 + 1_000));
    p.tick().unwrap();
    assert!(!listed(&mut p, &v, d));
    assert!(told(&mut p).contains(&v), "told once out");
}
