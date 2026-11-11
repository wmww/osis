#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A thing's history setting (spec/commits.md §5 The setting, History, Purge on replace): what
//! is listed follows the held valid settings in any arrival order; a setting acts from its own
//! stamp; the setting itself has fixed retention and binds nothing for a writer that is no admin.

use crate::common::*;
use osis_base::{CommitId, Role, Tid, Value, WallMs};
use osis_commit::retention::fixed_retention;
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_node::Mutation;
use osis_schema::core_types as ct;
use osis_schema::{Codec, History};

const HOUR: u64 = 3_600_000;
const A: &str = "t:reg.0";

fn keep(after: u64) -> History {
    History::Keep { until: None, after: Some(after) }
}

/// Alice (0) is first admin of D, Bob (1) writes, Carol (2) is an admin: built once
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
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, d)
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

/// A node at wall time `at` holding `base` then `order`.
fn fresh(base: &[Package], order: &[&Package], seed: u64, at: WallMs) -> Peer {
    let mut p = Peer::new(seed, at).unwrap();
    for x in base.iter().chain(order.iter().copied()) {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    p
}

// spec/commits.md §5 Fixed retention, The setting: `retention^.0` is `nobody`, kept forever,
// never snapshotted or undone, and written whole
#[test]
fn setting_itself_fixed_spec_commits_5() {
    assert_eq!(fixed_retention("retention^.0"), Some(osis_commit::retention::KEPT_RETENTION));
    let (mut lp, d) = setup();
    let c = set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    let h = lp.peers[0].engine.header(&c).unwrap();
    assert_eq!(h.aspects.iter().find(|a| a.ak.as_str() == "retention^.0").unwrap().retention, osis_commit::retention::KEPT_RETENTION);
    assert!(lp.peers[0].engine.snapshot(&d, &ak("retention^.0")).is_err(), "never compacted");
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
    assert!(matches!(lp.peers[1].commit(m), Err(osis_node::Error::Permission { .. })));
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

// spec/commits.md §5 The setting: what is listed follows the setting, whatever order the setting
// and the bodies arrive in: kept an hour after replaced, then not
#[test]
fn history_follows_the_setting_in_any_order_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    let x = set(&mut lp, 0, d, &setting(&[(A, keep(HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    let v2 = put(&mut lp, 1, d, "two");
    let pks = [pack(&mut lp, 0, &x), pack(&mut lp, 1, &v1), pack(&mut lp, 1, &v2)];
    let now = lp.peers[0].engine.now();
    for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0], [2, 1, 0], [0, 2, 1], [2, 0, 1]] {
        let mut p = fresh(&base, &order.map(|i| &pks[i]), FRESH, now);
        assert!(listed(&mut p, &v1, d), "{order:?}: in history");
        assert!(listed(&mut p, &v2, d), "{order:?}: live");
        p.clock.advance(HOUR + 2_000);
        p.tick().unwrap();
        assert!(!listed(&mut p, &v1, d), "{order:?}: out an hour after replaced");
    }
}

// spec/commits.md §5 History: a shortening hides what it ends, and a later extension does not
// bring it back (a setting acts from its own stamp)
#[test]
fn shortening_hides_and_extension_does_not_bring_back_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    put(&mut lp, 1, d, "two");
    lp.sync_all().unwrap();
    assert!(listed(&mut lp.peers[2], &v1, d));
    set(&mut lp, 0, d, &setting(&[]));
    lp.sync_all().unwrap();
    assert!(!listed(&mut lp.peers[2], &v1, d), "shortened: out");
    set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(!listed(&mut lp.peers[i], &v1, d), "peer {i}: an extension reaches nothing that left");
    }
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
    assert!(m.dropped.contains_key(&ai) && !m.missing.contains(&ai), "dropped, not missing: not fetched");
    assert!(!listed(&mut lp.peers[0], &v1, d), "not held: not listed");
    assert!(listed(&mut lp.peers[1], &v1, d), "held: in history");
    // Bob, holding it, offers everything: Alice takes no copy
    lp.sync(1, 0).unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&v1, &d, &ak(A)), "a copy offered is not taken");
    assert!(!listed(&mut lp.peers[0], &v1, d));
}

// spec/commits.md §5 Purge on replace: a setting arriving late at a writer holding a body it
// puts under purge on replace makes the writer cover it (one snapshot), and the body goes
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

// spec/commits.md §5 One way: once purge on replace is set for an aspect, a later keep keeps
// nothing there
#[test]
fn purge_then_keep_shows_nothing_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, History::PurgeOnReplace)]));
    set(&mut lp, 0, d, &setting(&[(A, History::FOREVER)]));
    let v1 = put(&mut lp, 0, d, "one");
    put(&mut lp, 0, d, "two");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(!listed(&mut lp.peers[i], &v1, d), "peer {i}");
    }
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
    let mut p = fresh(&base, &[&pks[0], &pks[1], &pks[2], &pks[3]], FRESH, at);
    assert!(p.engine.body_not_dropped(&v1, &d, &ak(A)), "a reader holds it until a writer covers it");
    assert!(!listed(&mut p, &v1, d), "never history");
}

// spec/commits.md §5 Dated only where history is kept: each part of a body class is dated by its
// own writes and kept by its own aspect's setting, and the body stays until the latest of them.
// One commit writes the register (kept an hour) and another aspect (no history) in one class.
// Replacing only the other aspect dates nothing: the kept part is current (so the body stays for
// that), and the unkept part adds no bound; spec/commits.md §7 Listed parts: the unkept part is
// not listed (current by its own writes only). Replacing the kept part then keeps the body an
// hour from that part's own replacement.
#[test]
fn a_body_class_keeps_by_its_kept_aspect_spec_commits_5() {
    for (kept, other) in [("t:b.0", "t:a.0"), ("t:a.0", "t:b.0")] {
        let (mut lp, d) = setup();
        set(&mut lp, 0, d, &setting(&[(kept, keep(HOUR))]));
        lp.sync_all().unwrap();
        let mut m = Mutation::new();
        m.set(d, &ak(kept), &s("k")).unwrap();
        m.set(d, &ak(other), &s("x")).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        assert_eq!(lp.peers[1].engine.body_keeps(&c).unwrap(), vec![0, 0], "{kept}: not replaced");
        let mut m = Mutation::new();
        m.set(d, &ak(other), &s("y")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.body_keeps(&c).unwrap(), vec![0, 0], "{kept}: the other aspect's death dates no kept part");
        assert_eq!(e.replaced_at(&c, &d, &ak(other)).unwrap(), None, "{kept}: no history on the other aspect");
        assert!(e.body_live(&c, &d, &ak(kept)).unwrap(), "{kept}: the kept part is current");
        // listing is per part: the kept part's live write keeps the bytes, not the other part's listing
        assert!(e.listed_at(&c, &[(d, ak(kept))]).unwrap(), "{kept}: the current part listed");
        assert!(!e.listed_at(&c, &[(d, ak(other))]).unwrap(), "{kept}: the replaced unkept part not listed");
        let mut m = Mutation::new();
        m.set(d, &ak(kept), &s("l")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        let r = lp.peers[1].engine.now().0;
        lp.advance(1_000);
        assert_eq!(lp.peers[1].engine.body_keeps(&c).unwrap(), vec![r + HOUR, r + HOUR], "{kept}: kept by its kept part's own replacement");
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
        let keeps = (hk.ts, hk.author, k) > (hn.ts, hn.author, n);
        seen.push(keeps);
        let v1 = put(&mut lp, 1, d, "one");
        let v2 = put(&mut lp, 1, d, "two");
        let pks = [pack(&mut lp, keeper, &k), pack(&mut lp, other, &n), pack(&mut lp, 1, &v1), pack(&mut lp, 1, &v2)];
        let now = lp.peers[1].engine.now();
        for order in [[0, 1, 2, 3], [1, 0, 2, 3], [2, 3, 1, 0], [3, 0, 2, 1]] {
            let mut p = fresh(&base, &order.map(|i| &pks[i]), FRESH, now);
            assert_eq!(listed(&mut p, &v1, d), keeps, "keeper {keeper}, {order:?}: the later by key is in force");
        }
    }
    assert!(seen.contains(&true) && seen.contains(&false), "{seen:?}");
}

// notes/engine-retention.md Replaced (When), spec/crdt.md §4.8 When: a write dies at its superseder's own
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
    let keep = e.body_keeps(&x1).unwrap();
    assert!(!listed(&mut lp.peers[0], &x1, d), "out of history 10 minutes after x2");
    let e = &mut lp.peers[0].engine;
    e.drop_body(&x2, &d, &ak(A)).unwrap();
    assert!(!e.body_not_dropped(&x2, &d, &ak(A)), "x2 is live and covered: in no history, it drops");
    assert_eq!(e.body_keeps(&x1).unwrap(), keep, "x1's keep stays");
    assert!(!listed(&mut lp.peers[0], &x1, d), "x1 is not listed again");
}

/// Drops, in `order`, each held body of `(d, a)` that `s` covers once its keep-at-least bound
/// allows (`Engine::drop_from` on the node's clock, as node-sync does), and checks after each
/// drop that every commit in `watch` still held is listed and kept (in history: its keep bound
/// ahead of the clock) as before (notes/engine-retention.md Replaced, Invariant). Returns the
/// bodies dropped.
fn drop_allowed(p: &mut Peer, d: Tid, a: &str, s: CommitId, order: &[CommitId], watch: &[CommitId]) -> Vec<CommitId> {
    let k = ak(a);
    let listed = |p: &mut Peer| -> Vec<Option<(bool, bool)>> {
        let now = p.engine.now().0;
        watch.iter().map(|c| p.engine.body_not_dropped(c, &d, &k).then(|| (p.engine.listed_at(c, &[(d, k.clone())]).unwrap(), p.engine.body_keeps(c).unwrap().iter().any(|x| *x > now)))).collect()
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

// notes/engine-retention.md Replaced (When), spec/commits.md §5 Bodies and deaths: a body is replaced at
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

// notes/engine-retention.md Replaced (When, text), spec/crdt.md §4.8 When: a text element's creation dies at
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

// spec/crdt.md §4.8 When, notes/engine-retention.md Replaced (the covered-drop invariant): a
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
    set_edge(&mut lp.peers[0].engine, d, bob, None, Some(ct::Frontier::default().to_value()));
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
    let keeps = p.engine.body_keeps(c).unwrap();
    let kept = keeps.iter().any(|x| *x > now);
    let bound = kept.then(|| (keeps, p.engine.replaced_at(c, &d, &ak(a)).unwrap()));
    Some((p.engine.listed_at(c, &[(d, ak(a))]).unwrap(), kept, bound))
}

/// One history of `covered_drops_move_nothing_*`: writes by Alice, Bob and Carol on a register
/// `A` kept ten minutes, on `B` no setting keeps, or on both in one commit (one body class),
/// syncs, Alice's snapshots of either, and maybe Bob removed with none of his writes counting
/// (so snapshots vouch for them), at random gaps; then at a node holding all of it every part
/// some held snapshot covers and whose body's keep bound passed is dropped, in random order.
fn covered_drops_history(seed: u64) {
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
                set_edge(&mut lp.peers[0].engine, d, bob, None, Some(ct::Frontier::default().to_value()));
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
    let mut p = fresh(&packs, &[], 9100 + seed, lp.peers[0].engine.now());
    let p = &mut p;
    let on: Vec<(CommitId, &str)> =
        p.engine.commit_ids().into_iter().flat_map(|c| [A, B].map(|a| (c, a))).filter(|(c, a)| p.engine.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.ak == ak(a)))).collect();
    let snaps: Vec<(CommitId, &str)> = on.iter().copied().filter(|(c, _)| p.engine.header(c).unwrap().kind.is_compaction()).collect();
    let before: Vec<_> = on.iter().map(|(c, a)| standing(p, c, d, a)).collect();
    let mut order = on.clone();
    for i in (1..order.len()).rev() {
        order.swap(i, below(i as u64 + 1) as usize);
    }
    for (c, a) in &order {
        let k = ak(a);
        let now = p.engine.now().0;
        if !p.engine.body_not_dropped(c, &d, &k) || p.engine.drop_from(c, &d, &k).unwrap() > now || p.engine.read_alone(c, &d, &k).unwrap() {
            continue;
        }
        let covering = snaps.iter().any(|(s, sa)| sa == a && s != c && p.engine.body_not_dropped(s, &d, &k) && p.engine.covered(s, c, &d, &k).unwrap() == Some(true));
        if !covering || p.engine.drop_body(c, &d, &k).is_err() {
            continue;
        }
        for ((x, xa), b) in on.iter().zip(&before) {
            let now = standing(p, x, d, xa);
            assert!(now.is_none() || now == *b, "seed {seed}: dropping {c:?} on {a} moved {x:?} on {xa}: {b:?} to {now:?}");
        }
    }
}

// notes/engine-retention.md Replaced (the covered-drop invariant), spec/crdt.md §4.8 When,
// spec/commits.md §5 Dated only where history is kept: random small histories on a kept and an
// unkept aspect, some commits writing both in one body class, every covered part past its body's
// keep bound dropped in random order; no drop moves the listing, in-history status, keep bounds
// or replaced-at of a held body in history.
#[test]
fn covered_drops_move_nothing_spec_commits_5() {
    let seeds: Vec<u64> = (0..100).collect();
    osis_base::testenv::run_seeds("setting::covered_drops_move_nothing_spec_commits_5", &seeds, false, |s| format!("seed {s}"), covered_drops_history);
}

// spec/commits.md §5 Dated only where history is kept, notes/engine-retention.md Replaced (the
// covered-drop invariant): W writes a kept aspect (10 minutes) and an unkept one in one body
// class; B replaces the unkept write, E replaces B fifteen minutes later. W's unkept part is
// dated by nothing (no history on its aspect), so B, also undated, drops at once under a
// snapshot and moves none of W's bounds. Dated across the class, W was out by B's date and came
// back into history at E's.
#[test]
fn an_unkept_part_dates_no_class_spec_commits_5() {
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
    let before = (e.body_keeps(&w).unwrap(), e.replaced_at(&w, &d, &ak(kept)).unwrap(), e.replaced_at(&w, &d, &ak(other)).unwrap());
    assert_eq!(before, (vec![0, 0], None, None), "W's kept part current, its other part undated");
    e.drop_body(&b, &d, &ak(other)).unwrap();
    assert_eq!((e.body_keeps(&w).unwrap(), e.replaced_at(&w, &d, &ak(kept)).unwrap(), e.replaced_at(&w, &d, &ak(other)).unwrap()), before, "a covered drop moved W");
}

/// Peer `p` listens for commit events on every thing.
fn watch(p: &mut Peer) {
    p.engine.listen_commits(std::sync::Arc::new(|_| true), &[]).unwrap();
    p.drain_events();
}

/// The commits on `(d, A)` commit events named since the last drain.
fn told(p: &mut Peer, d: Tid) -> Vec<CommitId> {
    let mut out = Vec::new();
    for e in p.drain_events() {
        if let osis_node::Event::Commits(ch) = e {
            out.extend(ch.iter().filter(|x| x.tid == d && x.ak == ak(A)).map(|x| x.id));
        }
    }
    out
}

// notes/api.md Commits, spec/commits.md §5 History: a body leaving history as its window passes
// is told to a commit listener, whatever order the setting and the bodies arrived in and across
// a restart, and nothing that stays is told
#[test]
fn leaving_history_is_told_in_any_order_spec_commits_5() {
    let (mut lp, d) = setup();
    let base = base(&mut lp);
    let x = set(&mut lp, 0, d, &setting(&[(A, keep(HOUR))]));
    let v1 = put(&mut lp, 1, d, "one");
    let v2 = put(&mut lp, 1, d, "two");
    let pks = [pack(&mut lp, 0, &x), pack(&mut lp, 1, &v1), pack(&mut lp, 1, &v2)];
    let now = lp.peers[0].engine.now();
    for (n, order) in [[0, 1, 2], [1, 2, 0], [2, 1, 0]].into_iter().enumerate() {
        let mut p = fresh(&base, &order.map(|i| &pks[i]), FRESH, now);
        if n == 1 {
            p.restart(355).unwrap();
        }
        watch(&mut p);
        p.clock.advance(HOUR - 5_000);
        p.tick().unwrap();
        assert!(told(&mut p, d).is_empty(), "{order:?}: nothing leaves before its window passes");
        p.clock.advance(10_000);
        p.tick().unwrap();
        assert_eq!(told(&mut p, d), vec![v1], "{order:?}: told as it leaves");
        assert!(!listed(&mut p, &v1, d) && listed(&mut p, &v2, d), "{order:?}");
        p.clock.advance(10 * HOUR);
        p.tick().unwrap();
        assert!(told(&mut p, d).is_empty(), "{order:?}: the live one stays");
    }
}

// spec/commits.md §5 The setting (notes/engine-retention.md History, Tess's decision 1): a setting arriving late, stamped while a body was
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

// notes/engine-retention.md Leaving history, notes/api.md Commits (listeners): a snapshot whose
// carried write a later write kills leaves the listing at its keep bound, and is told then.
#[test]
fn a_snapshot_is_told_leaving_history_spec_commits_5() {
    let (mut lp, d) = setup();
    set(&mut lp, 0, d, &setting(&[(A, keep(10 * 60_000))]));
    let x1 = put(&mut lp, 0, d, "one");
    let s = lp.peers[0].engine.snapshot(&d, &ak(A)).unwrap().unwrap();
    lp.advance(1_000);
    lp.peers[0].engine.listen_commits(std::sync::Arc::new(|_: &Tid| true), &[d]).unwrap();
    put(&mut lp, 0, d, "two");
    assert!(listed(&mut lp.peers[0], &x1, d) && listed(&mut lp.peers[0], &s, d), "in history");
    lp.peers[0].drain_events();
    lp.advance(11 * 60_000);
    lp.peers[0].tick().unwrap();
    let mut told = Vec::new();
    for e in lp.peers[0].drain_events() {
        if let osis_node::Event::Commits(ch) = e {
            told.extend(ch.iter().filter(|x| x.tid == d).map(|x| x.id));
        }
    }
    for c in [x1, s] {
        assert!(!listed(&mut lp.peers[0], &c, d) && told.contains(&c), "{c:?} left history, told");
    }
}
