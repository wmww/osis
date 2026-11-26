#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Validity through perm at the engine level, with hand-fed role commits: the Bob
//! revocation scenario and the Carol variant (notes/revocation.md), re-grant,
//! overlapping counters.

use crate::common;
use common::*;
use osis_base::Classified;
use osis_base::{Role, Tid, Value, WallMs};
use osis_engine::local_peer::LocalPeer;
use osis_engine::{Event, Ingested, Mutation};
use osis_engine::DemotionScope;
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};

const DAY: u64 = 86_400_000;



fn revoke(lp: &mut LocalPeer, admin: usize, t: Tid, holder: Tid) {
    let scope = of(holder, t);
    let f = frontier_now(lp, admin, &scope);
    set_edge(&mut lp.peers[admin].engine, t, holder, None, Some(f.clone()));
}

/// Alice (0) is mint admin of D and grants Bob (1) and Carol (2) write: built once
/// (`LocalPeer::cached`).
fn setup() -> (LocalPeer, Tid, Tid, Tid) {
    let (lp, (d, b, c)) = LocalPeer::cached("validity::setup", || {
        let (lp, d, b, c) = setup_built();
        (lp, (d, b, c))
    });
    (lp, d, b, c)
}

fn setup_built() -> (LocalPeer, Tid, Tid, Tid) {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    (lp, d, b, c)
}

// notes/revocation.md; spec/permissions.md §5.2: Bob's edit X made offline before
// the revoke and Y after it are both invalid wherever the revoke is held; his edit Alice had
// received stays (the frontier covers it); Bob's own node un-merges both.
#[test]
fn bob_revocation_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup();
    add_tag(&mut lp, 1, d, "mon");
    sync(&mut lp, 1, 0);
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "x"); // Wed, offline
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b); // Thu, without having seen X
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "y"); // Fri
    assert!(tags(&mut lp, 1, d).contains("y"));
    lp.advance(DAY);
    sync(&mut lp, 1, 0); // Sun
    sync(&mut lp, 0, 1);
    for i in [0, 1] {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["mon".to_string()]), "node {i}");
    }
    assert_eq!(lp.peers[0].engine.state(&d, &ak("t:tags.0")).unwrap(), lp.peers[1].engine.state(&d, &ak("t:tags.0")).unwrap());
    // Bob's node saw its own edits go
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: osis_engine::Cause::Validity, .. })));
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    // re-grant makes every write of Bob valid again, the gap included: Alice dropped them while
    // invalid (spec/permissions.md §6) and fetches them again from Bob, who kept his own
    lp.advance(DAY);
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    sync(&mut lp, 1, 0);
    for i in [0, 1] {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["mon".into(), "x".into(), "y".into()]), "node {i}");
    }
}

// notes/revocation.md, The reference scenario (Carol variant): Carol, a writer offline with Bob, applied X
// before the revoke; once she holds the revoke she vouches for X (spec/permissions.md §5.2,
// Addenda), so X stays everywhere, her own edit too.
#[test]
#[ignore = "stub rewrite: entry by references and chain-holder stubs (R2)"]
fn carol_variant_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup();
    let obs = reader(&mut lp, 0, d, 0x5e2);
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "x");
    add_tag(&mut lp, 2, d, "carol");
    sync(&mut lp, 1, 2);
    assert!(tags(&mut lp, 2, d).contains("x"));
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 2);
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["carol".to_string(), "x".to_string()]));
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["carol".to_string(), "x".to_string()]), "node {i}");
    }
    // the result is a function of the held set, not of arrival order
    let mut lp2 = LocalPeer::of(vec![obs], 1).unwrap();
    lp2.advance(2 * DAY);
    // what the sync IDs the observer syncs carry
    let synced = lp2.synced(0).unwrap();
    let mut pks: Vec<_> = [0, 1, 2].iter().flat_map(|i| lp.packages_under(*i, &synced).unwrap()).collect();
    pks.reverse();
    for _ in 0..2 {
        for p in &pks {
            unless_refused(lp2.deliver(0, p));
        }
    }
    assert!(lp2.peers[0].engine.pending().is_empty(), "{:?}", lp2.peers[0].engine.pending());
    assert_eq!(tags(&mut lp2, 0, d), BTreeSet::from(["carol".to_string(), "x".to_string()]));
}

// spec/permissions.md §5.1: a register value a revoked writer overwrote comes back on
// un-merge (re-join of the held bodies, spec/crdt.md §4.6).
#[test]
fn unmerge_restores_register_spec_crdt_4_6() {
    let (mut lp, d, b, _) = setup();
    // an un-merge study: nobody vouches (Carol would, spec/permissions.md §5.2)
    for p in &mut lp.peers {
        p.engine.write_addenda(false);
    }
    put(&mut lp, 0, d, &REG, &s("alice"));
    lp.sync_all().unwrap();
    lp.advance(1000);
    put(&mut lp, 1, d, &REG, &s("bob"));
    sync(&mut lp, 1, 2);
    assert_eq!(lp.peers[2].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob")));
    lp.advance(1000);
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 2);
    assert_eq!(lp.peers[2].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("alice")));
}

// spec/commits.md §4: two commits of one session with overlapping ranges on one aspect
// are both invalid.
// spec/permissions.md §5.2 (dot reuse)
#[test]
fn overlapping_counters_spec_commits_4() {
    let (mut lp, d, _, _) = setup();
    let other = ak("x:other.0");
    let first = put(&mut lp, 1, d, &other, &s("first"));
    let h = lp.peers[1].engine.header(&first).unwrap();
    // Bob's key signs a second commit of the same session reusing those counters
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let second = forge_reg(&mut lp, d, &other, h.aspects[0].lo, ts, "second");
    sync(&mut lp, 1, 0);
    assert_eq!(lp.peers[0].engine.get(&d, &other).unwrap(), Some(s("first")));
    lp.peers[0].receive(&second, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &other).unwrap(), None);
}

// spec/commits.md §4 (overlapping counters void both commits but for their `created.0`: a
// record needs no authority, spec/permissions.md §1): Alice's minting of T is void by a second
// commit of her session reusing its counters on T's register; Bob drops the register's value,
// and the minting still counts as T's creation.
#[test]
fn a_void_minting_still_creates_spec_commits_4() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let t = new_shared(&mut lp, 0);
    lp.sync_all().unwrap();
    let minting = lp.peers[1].engine.creation(&t).expect("Bob holds T's minting").commit;
    let h = lp.peers[0].engine.header(&minting).unwrap();
    assert!(h.form == session_of(&lp, 0), "the minting is of Alice's session");
    let lo = h.aspects.iter().find(|x| x.tid == t && x.ak.as_str() == "t:reg.0").unwrap().lo;
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let second = forge_reg_keyed(&mut lp, 0, t, &ak("t:reg.0"), lo, ts, "second", true);
    assert_eq!(lp.peers[1].engine.get_typed(&t, &REG).unwrap(), Some(s("new")));
    lp.peers[1].receive(&second, Vec::new()).unwrap();
    assert_eq!(lp.peers[1].engine.get_typed(&t, &REG).unwrap(), None, "both commits are void");
    assert_eq!(lp.peers[1].engine.creation(&t).map(|c| c.commit), Some(minting), "the void minting's record counts");
}

/// Bob's key signs a commit of his engine's session on `d`'s `ak` with counters from `lo`
/// (any he used before included), setting the register to `v` at `ts`.
fn forge_reg(lp: &mut LocalPeer, d: Tid, ak: &osis_base::Ak, lo: u64, ts: osis_base::Ts, v: &str) -> Vec<u8> {
    forge_reg_keyed(lp, 1, d, ak, lo, ts, v, true)
}

/// `forge_reg` by peer `by`, listing the keys `d`'s maker lists (`listed`) or made-up ones.
#[allow(clippy::too_many_arguments)]
fn forge_reg_keyed(lp: &mut LocalPeer, by: usize, d: Tid, ak: &osis_base::Ak, lo: u64, ts: osis_base::Ts, v: &str, listed: bool) -> Vec<u8> {
    use crate::common::{forged_write, held_secrets, seal_with};
    let b = lp.peers[by].engine.tid();
    let mut cb = osis_commit::CommitBuilder::new(osis_commit::Kind::Content, ts, b, osis_commit::Path::default(), crate::common::session_of(lp, by));
    let mut aw = forged_write(&cb, d, ak, lo, &s(v));
    aw.purge_by = osis_base::PurgeBy::Writer;
    cb.aspects.push(aw);
    let secrets = held_secrets(lp, &[d]);
    let secrets = if listed { secrets } else { secrets.all_made_up() };
    seal_with(lp.peers[by].engine.identity().signing(), cb, &secrets).unwrap().encode()
}

// spec/crypto.md §7 (Checked keys: a delta on T of a commit listing for T a key that is not right
// applies nowhere), spec/commits.md §4 (Unjudgeable): a delta listing, at level 1 or 3, a key no
// step up its thing's record chain bears applies at no reader, and the same write listing the
// step's keys does. Bob, a writer of `d`, signs a write listing made-up keys (keys he could
// hold, to delete the blob at a store whatever its purge-by).
#[test]
fn a_delta_listing_a_key_no_step_bears_applies_nowhere_spec_crypto_7() {
    let (mut lp, d, _, _) = setup();
    let x = ak("x:other.0");
    let first = put(&mut lp, 1, d, &x, &s("first"));
    sync(&mut lp, 1, 0);
    let h = lp.peers[1].engine.header(&first).unwrap();
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let forged = forge_reg_keyed(&mut lp, 1, d, &x, h.aspects[0].hi, ts, "forged", false);
    lp.peers[0].receive(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &x).unwrap(), Some(s("first")), "its key is on no step");
    // at another reader as well
    sync(&mut lp, 1, 2);
    lp.peers[2].receive(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[2].engine.get(&d, &x).unwrap(), Some(s("first")));
    // the same write listing the step's keys applies: the keys alone kept the other out
    let listed = forge_reg(&mut lp, d, &x, h.aspects[0].hi + 1, ts, "listed");
    for i in [0, 2] {
        lp.peers[i].receive(&listed, Vec::new()).unwrap();
        assert_eq!(lp.peers[i].engine.get(&d, &x).unwrap(), Some(s("listed")), "peer {i}");
    }
    lp.advance(1000);
    put(&mut lp, 2, d, &x, &s("third"));
    sync(&mut lp, 2, 0);
    for i in [0, 2] {
        assert_eq!(lp.peers[i].engine.get(&d, &x).unwrap(), Some(s("third")), "peer {i}");
    }
}

// spec/commits.md §4 (Unjudgeable: a commit judged on missing evidence is never judged invalid
// for it), spec/sync-judgement.md §2 (Judged invalid): a delta listing a key no held step
// places waits for the step (the reader cannot tell a wrong key from a `sync.0` write it lacks),
// so its body under the thing's sync ID is not judged invalid: judged so, the reader would unlog
// it, perhaps its last carrier, while the step that places it is on its way.
#[test]
fn a_body_listing_an_unplaced_key_is_not_judged_invalid_spec_commits_4() {
    let (mut lp, d, _, _) = setup();
    let x = ak("x:other.0");
    let first = put(&mut lp, 1, d, &x, &s("first"));
    sync(&mut lp, 1, 0);
    let h = lp.peers[1].engine.header(&first).unwrap();
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let forged = forge_reg_keyed(&mut lp, 1, d, &x, h.aspects[0].hi, ts, "forged", false);
    let id = osis_commit::CommitBlob::decode(&forged).unwrap().id();
    lp.peers[0].receive(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &x).unwrap(), Some(s("first")), "the delta waits");
    let e = &mut lp.peers[0].engine;
    let sd = e.sync_id_of(&d).unwrap().unwrap();
    assert!(!e.body_facts(&sd, &osis_engine::sync::BodyId::unit(id)).unwrap().invalid, "unjudgeable, not invalid");
}

/// Peer 0 of `setup` given `k` of Bob's writes listing made-up keys, each by an entry let go
/// after: the commits peer 0 holds or keeps pending, more than before.
fn kept_after_miskeyed(k: u64) -> usize {
    let (mut lp, d, _, _) = setup();
    let x = ak("x:other.0");
    let first = put(&mut lp, 1, d, &x, &s("first"));
    sync(&mut lp, 1, 0);
    let h = lp.peers[1].engine.header(&first).unwrap();
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let kept = |e: &mut osis_engine::Engine| e.commit_ids().len() + e.pending().len();
    let before = kept(&mut lp.peers[0].engine);
    for i in 0..k {
        let forged = forge_reg_keyed(&mut lp, 1, d, &x, h.aspects[0].hi + 2 * i, ts, "forged", false);
        let id = osis_commit::CommitBlob::decode(&forged).unwrap().id();
        assert_eq!(lp.peers[0].receive(&forged, Vec::new()).unwrap(), Ingested::Pending(id, osis_engine::Reason::Miskeyed(d)), "it pends");
        lp.peers[0].engine.release_entry(&id).unwrap();
    }
    assert_eq!(lp.peers[0].engine.get(&d, &x).unwrap(), Some(s("first")));
    kept(&mut lp.peers[0].engine) - before
}

// spec/commits.md §4 (Unjudgeable; Pending storage), spec/crypto.md §7 (Checked keys): a commit
// whose every part lists a key no held step places pends, kept only while an entry carries it
// (so within the bounds on unvouched input), never held as a body: a reader pushing n or 10n
// such writes leaves nothing once their entries go.
#[test]
fn miskeyed_writes_pend_and_go_with_their_entries_spec_commits_4() {
    for k in [3, 30] {
        assert_eq!(kept_after_miskeyed(k), 0, "at {k}");
    }
}

/// The ID of an applied ingest.
fn applied(r: Ingested) -> osis_base::CommitId {
    match r {
        Ingested::Applied(id) => id,
        other => panic!("{other:?}"),
    }
}

/// Peer `i`'s frontier over `scope` as of now.
fn frontier_now(lp: &mut LocalPeer, i: usize, scope: &DemotionScope) -> osis_schema::core_types::Frontier {
    let now = lp.peers[i].engine.now();
    lp.peers[i].engine.frontier(scope, now).unwrap()
}

/// A fresh reader of `d` granted by Alice (`LocalPeer::fresh_reader`), pushed: its index.
fn push_reader(lp: &mut LocalPeer, d: Tid, seed: u64) -> usize {
    let r = lp.fresh_reader(0, d, seed);
    lp.peers.push(r);
    lp.peers.len() - 1
}

/// Bob's demotion scope on `d`.
fn of(b: Tid, d: Tid) -> DemotionScope {
    DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) }
}

// spec/permissions.md §5.1 (frontier; as commit ids, never counters), §5.2, Tess's decision
// (a): Bob writes, Alice overwrites it, compacts (Bob's write is dead, so the snapshot carries
// nothing of his) and removes him, her frontier listing nothing (the snapshot covers his commit).
// Bob then signs a newer commit on the counters his first one used. A fresh node holding the
// removal and the snapshot but not the first commit judges the forgery invalid (with counter
// frontiers it counted, and nothing it held carried that dot); Alice, holding both, voids both
// (one dot, one write).
// spec/permissions.md §5.2 (dot reuse)
#[test]
fn revoked_writer_forging_into_covered_counters_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    let obs = reader(&mut lp, 0, d, 0x5e1);
    let reg = ak("t:reg.0");
    let first = put(&mut lp, 1, d, &REG, &s("bob"));
    let lo = lp.peers[1].engine.header(&first).unwrap().aspects.iter().find(|a| a.ak == reg).unwrap().lo;
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    put(&mut lp, 0, d, &REG, &s("alice"));
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &reg).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.covered(&snap, &first, &d, &reg).unwrap(), Some(true));
    lp.advance(DAY);
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(f.commits.contains(&first), "listed, compacted or not");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.clone()));
    lp.advance(1_000);
    let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_reg(&mut lp, d, &reg, lo, ts, "forged");
    let mut fresh = LocalPeer::of(vec![obs], 1).unwrap();
    fresh.advance(3 * DAY);
    give_carried(&mut lp, 0, &mut fresh, 0, |p| p.id == first);
    fresh.peers[0].reexamine().unwrap();
    fresh.peers[0].receive(&forged, Vec::new()).unwrap();
    assert_eq!(fresh.peers[0].engine.get(&d, &reg).unwrap(), Some(s("alice")), "a fresh node");
    lp.peers[0].receive(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &reg).unwrap(), Some(s("alice")), "Alice");
}

// spec/permissions.md §5.2 (dot reuse), spec/crdt.md §4.6: Bob writes "bob", Alice compacts
// (her snapshot carries his write under his dot), then Bob signs a newer commit on the same
// counters. Both of Bob's commits are void; the snapshot's copy alone counts: Alice reads "bob",
// with and without a removal of Bob (frontier not listing his first commit) before the forgery.
// Was issue equivocation-after-snapshot (closed): the forgery's write stayed because a valid snapshot
// held a write under its dot, and the in-place un-merge differed from a rebuild.
#[test]
fn equivocation_under_snapshot_dot_reads_snapshot_copy_spec_perm_5_2() {
    for remove in [false, true] {
        let (mut lp, d, b, _) = setup();
        let reg = ak("t:reg.0");
        let first = put(&mut lp, 1, d, &REG, &s("bob"));
        let lo = lp.peers[1].engine.header(&first).unwrap().aspects.iter().find(|a| a.ak == reg).unwrap().lo;
        sync(&mut lp, 1, 0);
        lp.advance(1_000);
        lp.peers[0].engine.snapshot(&d, &reg).unwrap().unwrap();
        lp.advance(DAY);
        if remove {
            let now = lp.peers[0].engine.now();
            let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
            assert!(f.commits.contains(&first), "listed, compacted or not");
            set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.clone()));
            lp.advance(1_000);
        }
        let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
        let forged = forge_reg(&mut lp, d, &reg, lo, ts, "forged");
        lp.peers[0].receive(&forged, Vec::new()).unwrap();
        assert_eq!(lp.peers[0].engine.get(&d, &reg).unwrap(), Some(s("bob")), "remove {remove}");
        assert!(!lp.peers[0].engine.body_valid(&first, &d, &reg).unwrap(), "remove {remove}: the first commit is void");
    }
}

// spec/permissions.md §5.1, §5.2: Alice removes Bob holding his compacted tag and his
// uncompacted register write: her frontier lists both, compacted or not; both stay, at Alice
// and at a fresh node that never gets the compacted commit (the snapshot vouches for it).
#[test]
fn frontier_lists_compacted_too_snapshot_vouches_at_fresh_node_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    let tags_ak = ak("t:tags.0");
    let tag = put_op(&mut lp, 1, d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("mon")) });
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    let reg = put(&mut lp, 1, d, &REG, &s("b"));
    sync(&mut lp, 1, 0);
    lp.advance(DAY);
    let f = frontier_now(&mut lp, 0, &of(b, d));
    assert!(f.commits.contains(&reg) && f.commits.contains(&tag), "{f:?}");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.clone()));
    let mut fresh = fresh_net(&mut lp, 0, d, 1000); // a reader apart from lp's (its own seeds)
    fresh.advance(3 * DAY);
    give_carried(&mut lp, 0, &mut fresh, 0, |p| p.id == tag);
    fresh.peers[0].reexamine().unwrap();
    for (i, l) in [(0, &mut lp), (0, &mut fresh)] {
        assert_eq!(tags(l, i, d), BTreeSet::from(["mon".to_string()]));
        assert_eq!(l.peers[i].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("b")));
    }
}

// spec/permissions.md §5.1 (frontier; had received as of; a commit is listed whether a still holds
// its body, dropped it or compacted it): a backdated frontier lists Bob's commits Alice received by
// its cutoff, not those received after. Bob writes "1" before the cut and "2" after, then
// snapshots both; Alice receives the snapshot after the cut too. Only "1" is listed (a frontier
// now lists both writes), so after the backdated revoke the snapshot and "2" are invalid and
// "1", covered by the snapshot, stays.
#[test]
fn backdated_frontier_lists_by_cutoff_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    let reg = ak("t:reg.0");
    let one = put(&mut lp, 1, d, &REG, &s("1"));
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    let cut = lp.peers[0].engine.now();
    lp.advance(1_000);
    let two = put(&mut lp, 1, d, &REG, &s("2"));
    let snap = lp.peers[1].engine.snapshot(&d, &reg).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    assert_eq!(lp.peers[0].engine.covered(&snap, &one, &d, &reg).unwrap(), Some(true));
    lp.advance(1_000);
    let now = frontier_now(&mut lp, 0, &of(b, d));
    assert!(now.commits.contains(&one) && now.commits.contains(&two), "{now:?}");
    let f = lp.peers[0].engine.frontier(&of(b, d), cut).unwrap();
    assert!(f.commits.contains(&one) && !f.commits.contains(&two) && !f.commits.contains(&snap), "{f:?}");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.clone()));
    assert_eq!(lp.peers[0].engine.get(&d, &reg).unwrap(), Some(s("1")), "received by the cut, should stay");
}

// spec/commits.md §3, §4 (counter ranges on one aspect overlap are both invalid): role commits use commit form and a session-form one
// is bad input, so a node cannot void its own grant by later reusing its counters (overlapping
// session ranges void both commits): Bob keeps the edge Alice gave him.
#[test]
fn reused_counters_never_void_a_grant_spec_commits_4() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, writer_ctx};
    use osis_crdt::{AnyView, DeltaBuilder, Delta, Op, PathOp, PathSeg, Writer, encode_delta};
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (a, b, c) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
    let h = lp.peers[0].engine.header(&g).unwrap();
    assert_eq!(h.form, Form::Commit, "role commits use commit form");
    let holders = h.aspects.iter().find(|x| x.tid == d && x.ak.as_str() == "roles.0").unwrap();
    // Alice's key signs a session-form commit on d's roles.0 with the grant's range
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let empty = osis_crdt::Fragment::default();
    let form = crate::common::session_of(&lp, 0);
    let mut builder = DeltaBuilder::new(&empty, Writer::new(ts, form.own_source(a, osis_base::CommitId([0; 32])), holders.lo));
    builder.apply(&PathOp { path: vec![PathSeg::Key(Value::Weak(c))], op: Op::Set(edge(Role::Read).to_value()) }, &AnyView).unwrap();
    let (f, range) = builder.finish().unwrap();
    assert!(range.lo < holders.hi && holders.lo < range.hi, "the ranges overlap");
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Role, ts, a, range.lo, range.hi), None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, a, osis_commit::Path::default(), form);
    let mut aw = AspectWrite::new(d, holders.ak.clone(), range.lo, range.hi, bytes);
    aw.purge_by = osis_commit::retention::ROLE_PURGE_BY;
    cb.aspects.push(aw);
    // a session-form role commit is refused when built and when received (spec/commits.md §4)
    let secrets = crate::common::held_secrets(&mut lp, &[d]);
    let e = crate::common::seal_with(lp.peers[0].engine.identity().signing(), cb, &secrets).unwrap_err();
    assert!(e.to_string().contains("session form outside a content commit"), "{e}");
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
}

// spec/commits.md §2: a role commit changes at most
// one edge; a frontier needs a demotion. A writer refuses such a commit before it leaves.
#[test]
fn role_content_rules_spec_commits_2() {
    let (mut lp, d, b, c) = setup();
    let put = |x: Tid, r: Role| osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Weak(x))], op: osis_crdt::Op::Set(edge(r).to_value()) };
    let mut m = Mutation::new();
    for x in [b, c] {
        m.op(d, &osis_schema::core_types::ROLES, put(x, Role::Admin)).unwrap();
    }
    assert_eq!(lp.peers[0].commit(m).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    let mut m = Mutation::new();
    m.op(d, &osis_schema::core_types::ROLES, put(b, Role::Admin)).unwrap();
    m.frontier(osis_perm::Frontier::default());
    assert_eq!(lp.peers[0].commit(m).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    // validity survives a restart (perm inputs reload from the store)
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    lp.peers[1].restart(470).unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    assert_eq!(lp.peers[1].engine.roster(&d).len(), 2, "the record edge and the one grant left");
}

// spec/crdt.md §3.3 rule 2: a commit-form delta's own dots sort above node dots (and below
// every other commit), so a commit-form removal of entries another node wrote encodes
// canonically whichever node tid sorts first (the remover and the writer swapped).
#[test]
fn commit_form_order_spec_crdt_3_3() {
    for [a, w] in [[0, 1], [1, 0]] {
        let mut lp = net(2, 0);
        let d = new_thing(&mut lp, a);
        let b = lp.peers[w].engine.tid();
        set_edge(&mut lp.peers[a].engine, d, b, Some(edge(Role::Write)), None);
        sync(&mut lp, a, w);
        let map = ak("t:map.0");
        let mut m = Mutation::new();
        for k in ["a", "b", "c"] {
            m.op(d, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(Value::Int(1)) }).unwrap();
        }
        lp.peers[w].commit(m).unwrap().unwrap();
        sync(&mut lp, w, a);
        let mut m = Mutation::new();
        m.commit_form();
        for k in ["a", "b", "c"] {
            m.op(d, &map, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s(k)) }).unwrap();
            m.op(d, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(Value::Int(2)) }).unwrap();
        }
        lp.peers[a].commit(m).unwrap_or_else(|e| panic!("remover {a}: {e}")).unwrap();
    }
}

// spec/wire.md §4: spec/requirements.md, Permissions: every write is attributable and verifiable. A node cannot
// sign a write claiming an actor whose write secret it does not hold.
#[test]
fn foreign_actor_claim_refused_spec_wire_4() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("forged")).unwrap();
    m.act_as(c);
    assert!(lp.peers[1].engine.commit(m).is_err(), "a write claiming an actor the node does not act for was signed");
}

/// Bob's (peer 1) key signs a commit-form commit setting `d`'s register to `v`, naming `actor`
/// as the actor it acts for, past the writer's rules.
fn forge_acting(lp: &mut LocalPeer, d: Tid, actor: Tid, v: &str) -> Vec<u8> {
    let path = if actor == lp.peers[1].engine.tid() { osis_commit::Path::default() } else { osis_commit::Path::through(actor) };
    forge_by(lp, 1, d, &ak("t:reg.0"), &s(v), 1, osis_commit::Kind::Content, path)
}

// spec/permissions.md §1 Path, spec/commits.md §4 Unjudgeable: Bob, a writer of D, signs a write
// stated through Carol though nothing was ever granted him on her: no write is held on that edge
// of its path, so receivers cannot judge it; it pends and never reads as Carol's. The same write
// stated as Bob himself is valid.
#[test]
fn a_write_stated_through_an_ungranted_actor_pends_spec_commits_4() {
    let (mut lp, d, b, c) = setup();
    lp.advance(1_000);
    let forged = forge_acting(&mut lp, d, c, "as carol");
    let r = lp.peers[0].receive(&forged, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, osis_engine::Reason::MissingChain(x)) if x == b), "{r:?}");
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("new")), "a write acting for an actor its author cannot act for applied");
    lp.advance(1_000);
    let own = forge_acting(&mut lp, d, b, "as bob");
    lp.peers[0].receive(&own, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("as bob")));
}

// spec/commits.md §4 (Unjudgeable): an edge write that is itself unjudgeable is no evidence, and
// hides none that is. 0 makes x (shared with 1), o, o2 and q, all its own. Stating its path
// through o, which holds nothing on x, it writes one `roles.0` part on x giving o read (its path
// ends at o: judgeable, so the part is held) and q admin (on o's edge on x, which no write set
// before it: unjudgeable). A write acting as q on x after it waits at 1: q's grant is no write it
// could rely on. Once 0 grants q write on x, the same forgery through o2 and a write as q after
// both apply, the write valid: the forgery after the grant stalls nothing.
#[test]
fn an_unjudgeable_edge_write_is_no_evidence_spec_commits_4() {
    let mut lp = net(2, 0);
    let x = new_shared(&mut lp, 0);
    let (o, o2, q) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    sync(&mut lp, 0, 1);
    let forge = |lp: &mut LocalPeer, o: Tid, lo: u64| {
        lp.advance(1_000);
        let v = Value::Map(osis_base::ValueMap::from([(Value::Weak(o), edge(Role::Read).to_value()), (Value::Weak(q), edge(Role::Admin).to_value())]));
        let f = forge_by(lp, 0, x, &ak("roles.0"), &v, lo, osis_commit::Kind::Role, osis_commit::Path { purge: 0, things: vec![o], direct: 0 });
        assert!(matches!(lp.peers[1].receive(&f, Vec::new()).unwrap(), Ingested::Applied(_)), "its write on o's edge is judgeable");
    };
    let as_q = |lp: &mut LocalPeer, v: &str| {
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.set(x, &REG, &s(v)).unwrap();
        m.act_as(q);
        let id = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
        sync(lp, 0, 1);
        id
    };
    forge(&mut lp, o, 1 << 40);
    let w = as_q(&mut lp, "as q");
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.pending().iter().any(|(id, r)| *id == w && matches!(r, osis_engine::Reason::MissingChain(_))), "only an unjudgeable write on q's edge on x: {:?}", e1.pending());
    assert_eq!(e1.get(&x, &ak("t:reg.0")).unwrap(), Some(s("new")));
    lp.advance(1_000);
    set_edge(&mut lp.peers[0].engine, x, q, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    forge(&mut lp, o2, 1 << 41);
    let w2 = as_q(&mut lp, "as q again");
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pending().iter().any(|(id, _)| *id == w2), "{:?}", e1.pending());
    assert!(e1.pending().iter().any(|(id, _)| *id == w), "a grant ordered after the first write is none of its evidence");
    assert_eq!(e1.get(&x, &ak("t:reg.0")).unwrap(), Some(s("as q again")));
}

/// A role commit signed by peer `by`'s key writing `v` to `ak` on `t`, built by hand past
/// the writer-side rules; its counters start at `lo`.
pub(crate) fn forge_role_commit(lp: &mut LocalPeer, by: usize, t: Tid, ak: &osis_base::Ak, v: &Value, lo: u64) -> Vec<u8> {
    forge_commit(lp, by, t, ak, v, lo, osis_commit::Kind::Role)
}

/// `forge_role_commit` of any kind; an AK the core schema does not declare is written untyped.
fn forge_commit(lp: &mut LocalPeer, by: usize, t: Tid, ak: &osis_base::Ak, v: &Value, lo: u64, kind: osis_commit::Kind) -> Vec<u8> {
    forge_by(lp, by, t, ak, v, lo, kind, osis_commit::Path::default())
}

/// A commit by peer `by` writing `v` to `ak` on thing `t` from counter `lo`, stating `path`,
/// whatever its rights there.
#[allow(clippy::too_many_arguments)]
pub(crate) fn forge_by(lp: &mut LocalPeer, by: usize, t: Tid, ak: &osis_base::Ak, v: &Value, lo: u64, kind: osis_commit::Kind, path: osis_commit::Path) -> Vec<u8> {
    let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
    // commit form (spec/commits.md §3): own dots name the commit, a placeholder until built
    let mut cb = osis_commit::CommitBuilder::new(kind, ts, lp.peers[by].engine.tid(), path, osis_commit::Form::Commit);
    let mut aw = crate::common::forged_write(&cb, t, ak, lo, v);
    aw.purge_by = osis_commit::retention::write_purge_by(ak.as_str(), None, None).unwrap();
    cb.aspects.push(aw);
    crate::common::seal(lp, by, cb, &[t]).encode()
}

// spec/permissions.md §3 (lost access): only an unfinalized single-use link race defers a
// loss. Bob, who held read with the may-grant flag on D, left on his own; his later grant of Carol (forged past his
// writer rules) is void because he left, yet it is no redemption: once Alice removes Carol,
// Carol drops D's secrets.
#[test]
fn void_grant_by_leaver_keeps_no_secrets_spec_perm_3() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    // minted with the account as admin: independent from its creation
    let d = {
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let d = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(d, &REG, &s("new")).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(d);
        d
    };
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let flagged = osis_schema::core_types::Edge { may_grant: true, ..edge(Role::Read) };
    lp.peers[0].engine.grant(&d, &b, &flagged).unwrap();
    lp.peers[0].engine.grant(&d, &c, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    lp.peers[1].engine.demote(&d, &osis_engine::flows::Demotion { holder: b, new: None, retain: None }).unwrap();
    lp.advance(1_000);
    let grant = Value::Map(osis_base::ValueMap::from([(Value::Weak(c), edge(Role::Read).to_value())]));
    let forged = forge_role_commit(&mut lp, 1, d, &ak("roles.0"), &grant, 1 << 40);
    lp.sync_all().unwrap();
    lp.peers[2].receive(&forged, Vec::new()).unwrap();
    assert!(!lp.peers[2].engine.roster(&d).contains_key(&b), "Bob left");
    lp.advance(1_000);
    lp.peers[0].engine.demote(&d, &osis_engine::flows::Demotion { holder: c, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[2].engine.role_on(&d), None);
    lp.peers[2].engine.drop_lost_secrets().unwrap();
    // the epochs of D's mint admin Carol observed (its keysets, as evidence) derive no secret
    assert!(!lp.peers[2].engine.epochs(&d).is_some_and(|e| e.holds_any()), "Carol kept D's secrets");
}

// spec/permissions.md §1 (role-class by admins): a writer's `sync.0` write, forged past its own node's writer-side refusal, is invalid where it is received (the
// same write by its author once an admin applies).
#[test]
fn forged_role_class_unmerged_spec_perm_1() {
    use osis_schema::{RawKey, core_types as ct};
    let (mut lp, d, _, _) = setup();
    let sync_id = ct::SyncEntry { steps: BTreeMap::new() };
    let sync_ids: ct::SyncIds = BTreeMap::from([(osis_base::SyncId([5; 16]), sync_id)]);
    let a = ak(ct::SYNC.ak());
    let before = lp.peers[0].engine.get(&d, &a).unwrap();
    let forged = forge_role_commit(&mut lp, 1, d, &a, &sync_ids.to_value(), 1);
    lp.peers[0].receive(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &a).unwrap(), before, "a writer's role-class write applied");
    // control: the same write by the same key applies once its author is an admin
    let b = lp.peers[1].engine.tid();
    edge_write(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    let honest = forge_role_commit(&mut lp, 1, d, &a, &sync_ids.to_value(), 100);
    lp.peers[0].receive(&honest, Vec::new()).unwrap();
    let Some(Value::Map(now)) = lp.peers[0].engine.get(&d, &a).unwrap() else { panic!("no sync IDs") };
    let Value::Map(forged) = sync_ids.to_value() else { unreachable!() };
    assert!(forged.iter().all(|(k, v)| now.get(k) == Some(v)), "the admin's write applied");
}

// spec/permissions.md §5.2 (admin-only): a writer's node refuses its write of a `^` aspect,
// durable or ephemeral; one forged past that is invalid at every node, its author's included;
// the same write once its author holds admin applies everywhere
#[test]
fn admin_only_aspect_needs_admin_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup();
    let key = ak("t:settings^.0");
    let write = |v: &str| {
        let mut m = Mutation::new();
        m.set(d, &key, &s(v)).unwrap();
        m
    };
    assert!(matches!(lp.peers[1].commit(write("bob")), Err(osis_engine::Error::Permission { .. })));
    let mut m = Mutation::new();
    m.set(d, &ak("t:settings+^.0"), &s("bob")).unwrap();
    assert!(matches!(lp.peers[1].engine.write(m), Err(osis_engine::Error::Permission { .. })), "an ephemeral `^` write refused too");
    lp.advance(1_000);
    let forged = forge_commit(&mut lp, 1, d, &key, &s("bob"), 1, osis_commit::Kind::Content);
    // control: the same forged write on an unmarked key applies
    let plain = ak("t:settings.0");
    let control = forge_commit(&mut lp, 1, d, &plain, &s("bob"), 1, osis_commit::Kind::Content);
    for i in 0..3 {
        lp.peers[i].receive(&forged, Vec::new()).unwrap();
        lp.peers[i].receive(&control, Vec::new()).unwrap();
        assert_eq!(lp.peers[i].engine.get(&d, &key).unwrap(), None, "{i}: a writer's `^` write applied");
        assert_eq!(lp.peers[i].engine.get(&d, &plain).unwrap(), Some(s("bob")), "{i}");
    }
    lp.sync_all().unwrap();
    assert!((0..3).all(|i| lp.peers[i].engine.get(&d, &key).unwrap().is_none()));
    // the same write once its author is an admin applies
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    lp.peers[1].commit(write("bob, admin")).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.get(&d, &key).unwrap(), Some(s("bob, admin")), "{i}");
    }
}

// spec/permissions.md §5.1 (frontier: an admin-only write rests on the lowered hop): an
// admin's `^` write the demoter had received stays valid when it demotes that admin to write;
// one it had not received goes
#[test]
fn admin_only_write_covered_by_demotion_frontier_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    let (seen, unseen) = (ak("t:seen^.0"), ak("t:unseen^.0"));
    put(&mut lp, 1, d, &seen, &s("received"));
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    put(&mut lp, 1, d, &unseen, &s("offline"));
    lp.advance(1_000);
    lp.peers[0].engine.demote(&d, &osis_engine::flows::Demotion { holder: b, new: Some(edge(Role::Write)), retain: None }).unwrap();
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.get(&d, &seen).unwrap(), Some(s("received")), "{i}: a covered `^` write lost");
        assert_eq!(lp.peers[i].engine.get(&d, &unseen).unwrap(), None, "{i}");
    }
}

// spec/permissions.md §5.2 (admin-only): a writer's compaction snapshot of a `^` aspect is
// invalid, so it vouches for nothing it carries; the same snapshot of an unmarked aspect is valid
#[test]
fn admin_only_snapshot_by_writer_invalid_spec_perm_5_2() {
    let (mut lp, d, _, _) = setup();
    for (k, valid) in [("t:conf^.0", false), ("t:conf.0", true)] {
        let key = ak(k);
        // Alice's write reaches Carol only
        put(&mut lp, 0, d, &key, &s("alice"));
        sync(&mut lp, 0, 2);
        lp.advance(1_000);
        if !valid {
            assert!(matches!(lp.peers[2].engine.snapshot(&d, &key), Err(osis_engine::Error::Permission { .. })), "the writer's node refuses it");
        }
        let st = lp.peers[2].engine.state(&d, &key).unwrap().unwrap();
        let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
        let snap = forge_snapshot(&mut lp, 2, d, &key, now, st);
        lp.peers[1].receive(&snap, Vec::new()).unwrap();
        assert_eq!(lp.peers[1].engine.get(&d, &key).unwrap(), valid.then(|| s("alice")), "{k}");
        lp.advance(1_000);
    }
}

// spec/permissions.md §5.2 (compaction snapshot; vouches for every write it carries):
// Alice compacts Bob's edits, then revokes him with a frontier that covers "mon", not "x". The
// snapshot vouches for "x": Alice (holding Bob's commit, invalid now) and Dave (holding only
// the snapshot) keep both, whether the revoke arrives after the snapshot or before it, across a
// restart and a re-grant.
#[test]
fn snapshot_vouches_for_its_writes_spec_perm_5_2() {
    for revoke_first in [false, true] {
        let (mut lp, d, b, _) = setup();
        push_reader(&mut lp, d, 4700);
        lp.sync_all().unwrap();
        add_tag(&mut lp, 1, d, "mon");
        sync(&mut lp, 1, 0);
        let mon = lp.peers[1].engine.commit_ids().into_iter().filter(|c| lp.peers[1].engine.header(c).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).max_by_key(|c| lp.peers[1].engine.header(c).unwrap().ts).unwrap();
        lp.advance(DAY);
        add_tag(&mut lp, 1, d, "x");
        sync(&mut lp, 1, 0);
        let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        lp.advance(DAY);
        // a frontier holding "mon" only
        let f = osis_schema::core_types::Frontier { commits: BTreeSet::from([mon]) };
        let rv = set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.clone()));
        let both = BTreeSet::from(["mon".to_string(), "x".to_string()]);
        assert_eq!(tags(&mut lp, 0, d), both, "Alice: the snapshot vouches for x");
        // Dave: everything of Alice's but Bob's own commits
        let pks: Vec<_> = packages_for(&mut lp, 0, 3).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.signer != b)).collect();
        let (late, early): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| if revoke_first { p.id == snap } else { p.id == rv });
        for pk in early.iter().chain(&late) {
            lp.deliver(3, pk).unwrap();
        }
        lp.peers[3].reexamine().unwrap();
        assert!(lp.peers[3].engine.header(&snap).is_some(), "the snapshot applied");
        assert!(lp.peers[3].engine.header(&mon).is_none(), "Bob's own commit is not held");
        assert_eq!(tags(&mut lp, 3, d), both, "revoke first: {revoke_first}");
        lp.peers[3].restart(5).unwrap();
        assert_eq!(tags(&mut lp, 3, d), both, "after a restart");
        lp.advance(DAY);
        let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
        let pk = package_for(&mut lp, 0, 3, g);
        lp.deliver(3, &pk).unwrap();
        assert_eq!(tags(&mut lp, 3, d), both, "re-granted");
        assert_eq!(tags(&mut lp, 0, d), both, "Alice, re-granted");
    }
}

/// One map entry `k: v` written under `src` at `ts` with counters from `lo`.
fn entry_by(src: osis_crdt::Source, ts: osis_base::Ts, lo: u64, k: &str, v: &str) -> osis_crdt::Fragment {
    let mut w = osis_crdt::Writer::new(ts, src, lo);
    osis_crdt::create(&mut w, &osis_crdt::AnyView, &Value::Map(osis_base::ValueMap::from([(s(k), s(v))]))).unwrap()
}

/// The own source of held commit `c` at peer `i` (a session-form commit's session).
fn source_of(lp: &LocalPeer, i: usize, c: &osis_base::CommitId) -> osis_crdt::Source {
    let h = lp.peers[i].engine.header(c).unwrap();
    h.form.own_source(h.signer, *c)
}

/// Frontiers of one session source.
fn frontier_of(src: &osis_crdt::Source, ctr: u64) -> osis_crdt::Frontiers {
    let mut fr = osis_crdt::Frontiers::default();
    assert!(fr.insert(src, ctr));
    fr
}

// spec/permissions.md §5.2 (a valid s vouches for every write it carries; its writes join like any write), spec/crdt.md §5.6 (the records of a dot are one entry; creation by stamp): a writer's snapshot carrying two entries under Bob's dots dated before his
// grant shows them (nothing judges them as Bob's), with the mint admin's write it carries; one
// copying a dot of Bob's held commit under another key and an older `ts` loses its creation to
// Bob's, so only Bob's entry shows.
#[test]
fn writer_snapshot_vouches_spec_perm_5_2() {
    let (mut lp, d, _, _) = setup();
    let m_ak = ak("x:m.0");
    let real = put(&mut lp, 1, d, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("bob"))])));
    sync(&mut lp, 1, 0);
    let lo = lp.peers[1].engine.header(&real).unwrap().aspects[0].lo;
    let bs = source_of(&lp, 1, &real);
    assert!(lo >= 1, "room for a forged counter below Bob's");
    let entries = |lp: &mut LocalPeer| keys_of(lp, 0, d);
    assert_eq!(entries(&mut lp), BTreeSet::from([s("k")]));
    lp.advance(1_000);
    let old = osis_base::Ts::make(WallMs(T0.0 - DAY), 0).unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    // a carried ts for a dot of a held commit other than its own, under another key: its own
    // record, its older creation beaten by the held delta's
    let clash = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(bs.clone(), old, lo, "f0", "x"));
    lp.peers[0].receive(&clash, Vec::new()).unwrap();
    assert_eq!(entries(&mut lp), BTreeSet::from([s("k")]), "a copy of a held write at an older ts and another key");
    let mut f = entry_by(bs.clone(), old, 1 << 39, "f1", "x");
    f.join(entry_by(bs.clone(), old, 1 << 40, "f2", "y"));
    // and a valid write of Alice's (the snapshot applies)
    let a = lp.peers[0].engine.tid();
    f.join(entry_by(crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32])), now, 1 << 42, "c", "alice"));
    let snap = forge_snapshot(&mut lp, 2, d, &m_ak, now, f);
    lp.peers[0].receive(&snap, Vec::new()).unwrap();
    let want = BTreeSet::from([s("k"), s("c"), s("f1"), s("f2")]);
    assert_eq!(entries(&mut lp), want, "the writer's carried writes count");
    lp.peers[0].restart(53).unwrap();
    assert_eq!(entries(&mut lp), want, "after a restart");
}

// spec/crdt.md §8, §2.2: a snapshot carrying a write stamped after the snapshot's own `ts` is bad
// input (so a node's next stamp exceeds every stamp it holds); one stamped at it applies.
#[test]
fn snapshot_future_stamp_refused_spec_crdt_8() {
    let (mut lp, d, _, _) = setup();
    let m_ak = ak("x:m.0");
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let later = osis_base::Ts::make(WallMs(lp.peers[2].engine.now().0 + 1_000), 0).unwrap();
    let a = lp.peers[0].engine.tid();
    let asrc = crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32]));
    let bad = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(asrc.clone(), later, 1 << 42, "c", "x"));
    assert_eq!(lp.peers[0].receive(&bad, Vec::new()).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    let ok = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(asrc, now, 1 << 42, "c", "x"));
    lp.peers[0].receive(&ok, Vec::new()).unwrap();
}

// spec/permissions.md §5.2 (a valid s vouches for every write it carries): Dave holds
// Bob's tag only inside Alice's compaction snapshot, which arrives before Bob's grant: the
// write shows at once, its index persisted equals a rebuild from the commit records, and it
// stays once the grant arrives, across a restart.
#[test]
fn snapshot_before_grant_counts_spec_perm_5_2() {
    let mut lp = net(2, 0);
    lp.peers.push(osis_engine::local_peer::Peer::new(5700, T0).unwrap());
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    // Dave reads d, so he keeps what he is given of it
    let dave = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, dave, Some(edge(Role::Read)), None);
    let b = lp.peers[1].engine.tid();
    let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    add_tag(&mut lp, 1, d, "x");
    sync(&mut lp, 1, 0);
    lp.advance(DAY);
    let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    // Dave: Alice's commits but the grant, then the grant
    let pks: Vec<_> = packages_reading(&mut lp, 0, 2, d).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.signer != b)).collect();
    let (holders, content): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| p.id == g);
    for pk in &content {
        lp.deliver(2, pk).unwrap();
    }
    lp.peers[2].reexamine().unwrap();
    assert!(lp.peers[2].engine.header(&snap).is_some(), "the snapshot applied");
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["x".to_string()]), "vouched for by Alice's snapshot");
    let e = &mut lp.peers[2].engine;
    let before = e.index_digest();
    e.reload().unwrap();
    assert_eq!(e.index_digest(), before, "loaded from the persisted index");
    e.rebuild_index().unwrap();
    assert_eq!(e.index_digest(), before, "rebuilt from the commit records");
    for pk in &holders {
        lp.deliver(2, pk).unwrap();
    }
    lp.peers[2].reexamine().unwrap();
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["x".to_string()]), "valid once the grant is held");
    lp.peers[2].restart(58).unwrap();
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["x".to_string()]), "after a restart");
}

// spec/permissions.md §5.2: Carol compacts the tags (her snapshot carries Bob's and Alice's
// writes, none of hers); Alice then removes Carol with a frontier that lacks the snapshot. A
// fresh node receiving everything reads what Alice reads (Carol's snapshot gives nothing; the
// writes come from their own commits).
#[test]
fn demoted_compactor_fresh_node_spec_perm_5_2() {
    let (mut lp, d, _, c) = setup();
    let fresh = reader(&mut lp, 0, d, 5900);
    lp.peers.push(fresh);
    add_tag(&mut lp, 0, d, "alice");
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    lp.advance(DAY);
    let st = lp.peers[0].engine.state(&d, &ak("t:tags.0")).unwrap().unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let snap = forge_snapshot(&mut lp, 2, d, &ak("t:tags.0"), now, st);
    lp.peers[2].receive(&snap, Vec::new()).unwrap();
    lp.sync_all().unwrap();
    lp.advance(DAY);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(osis_schema::core_types::Frontier::default()));
    lp.sync_all().unwrap();
    let want = BTreeSet::from(["alice".to_string(), "bob".to_string()]);
    assert_eq!(tags(&mut lp, 0, d), want);
    assert_eq!(tags(&mut lp, 3, d), want, "a fresh node reads the same");
    assert_eq!(lp.peers[3].engine.state(&d, &ak("t:tags.0")).unwrap(), lp.peers[0].engine.state(&d, &ak("t:tags.0")).unwrap());
}

/// The keys of `x:m.0` on `d` at peer `i`.
fn keys_of(lp: &mut LocalPeer, i: usize, d: Tid) -> BTreeSet<Value> {
    match lp.peers[i].engine.get(&d, &ak("x:m.0")).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect(),
        _ => BTreeSet::new(),
    }
}

/// The map `{"a": "1"}`.
fn a1() -> Value {
    Value::Map(osis_base::ValueMap::from([(s("a"), s("1"))]))
}

/// Bob (`b`, peer 1) puts entry "k" in `d`'s `x:m.0`; once everyone holds it, a day later Alice
/// revokes him, and a day passes.
fn bob_writes_k_then_revoked(lp: &mut LocalPeer, d: Tid, b: Tid) {
    put_at(lp, 1, d, &["k"], a1());
    lp.sync_all().unwrap();
    lp.advance(DAY);
    revoke(lp, 0, d, b);
    lp.advance(DAY);
}

fn put_at(lp: &mut LocalPeer, i: usize, t: Tid, path: &[&str], v: Value) {
    let mut m = Mutation::new();
    let path = path.iter().map(|k| osis_crdt::PathSeg::Key(s(k))).collect();
    m.op(t, &ak("x:m.0"), osis_crdt::PathOp { path, op: osis_crdt::Op::Set(v) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap();
}

// spec/permissions.md §5.2 (a valid s vouches for every write it carries), Tess's decision, notes/revocation.md, Snapshots vouch: Bob, removed, creates entries
// "early" and "late" offline; Carol, not yet aware, writes inside "late" and compacts. Her
// snapshot vouches for Bob's entries: Dave, holding only Alice's and Carol's commits, and Alice,
// who also holds Bob's commit (invalid), both keep them with Carol's write. spec/crdt.md §4.6
// (function of the held set), spec/permissions.md §5.1: alike with Dave receiving Carol's write
// inside "late" before her snapshot (dated after it, as spec/crdt.md §8 requires).
#[test]
fn entry_created_after_demotion_spec_perm_5_2() {
    for snapshot_first in [true, false] {
        entry_created_after_demotion(snapshot_first);
    }
}

fn entry_created_after_demotion(snapshot_first: bool) {
    let (mut lp, d, b, _) = setup();
    // Dave reads d
    push_reader(&mut lp, d, 6100);
    lp.sync_all().unwrap();
    bob_writes_k_then_revoked(&mut lp, d, b);
    // one commit, two entries: "late" is its second creation (its dot is no stamp of the commit)
    let mut m = Mutation::new();
    for k in ["early", "late"] {
        m.op(d, &ak("x:m.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(a1()) }).unwrap();
    }
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 2);
    put_at(&mut lp, 2, d, &["late", "b"], s("2"));
    let st = lp.peers[2].engine.state(&d, &ak("x:m.0")).unwrap().unwrap();
    // after every stamp it carries (spec/crdt.md §8)
    lp.advance(1);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    assert!(st.max_ts().unwrap() < now);
    let snap = forge_snapshot(&mut lp, 2, d, &ak("x:m.0"), now, st);
    let snap_id = applied(lp.peers[2].receive(&snap, Vec::new()).unwrap());
    // Dave: Alice's and Carol's commits (the snapshot among them), none of Bob's
    for from in [0, 2] {
        let mut pks: Vec<_> = packages_for(&mut lp, from, 3).into_iter().filter(|p| lp.peers[from].engine.header(&p.id).is_some_and(|h| h.signer != b)).collect();
        if snapshot_first {
            pks.sort_by_key(|p| p.id != snap_id);
        }
        for pk in &pks {
            lp.deliver(3, pk).unwrap();
        }
    }
    lp.peers[3].reexamine().unwrap();
    sync(&mut lp, 1, 0);
    sync(&mut lp, 2, 0);
    let keys = |lp: &mut LocalPeer, i: usize| keys_of(lp, i, d);
    let want = BTreeSet::from([s("early"), s("k"), s("late")]);
    assert_eq!(keys(&mut lp, 0), want, "Alice");
    assert_eq!(keys(&mut lp, 3), want, "Dave");
    let read = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get(&d, &ak("x:m.0")).unwrap();
    assert_eq!(read(&mut lp, 0), read(&mut lp, 3), "Carol's write inside late too");
    lp.peers[3].engine.rebuild_state(&d, &ak("x:m.0")).unwrap();
    assert_eq!(read(&mut lp, 0), read(&mut lp, 3), "Dave, rebuilt");
}

// spec/crdt.md §4.6 (a valid snapshot's copies): a record a valid snapshot holds, by its dot, stays with the valid writes
// nested in it, §5.6 (a keyed record whose dot's creation is held): Bob, removed,
// creates entry "late" offline; Carol writes inside it, then sends a snapshot carrying Bob's
// creation under another key ("evil"). The snapshot holds Bob's dot, so "late" keeps Carol's
// write, but no creation under "late" is left: only the snapshot's key shows, in every order.
#[test]
fn differing_key_copy_shows_only_its_key_spec_crdt_4_6() {
    let (mut lp, d, b, _) = setup();
    let fresh = reader(&mut lp, 0, d, 6500);
    lp.peers.push(fresh);
    lp.sync_all().unwrap();
    bob_writes_k_then_revoked(&mut lp, d, b);
    put_at(&mut lp, 1, d, &["late"], a1());
    let late = *lp.peers[1].engine.commit_ids().iter().max_by_key(|id| lp.peers[1].engine.header(id).unwrap().ts).unwrap();
    let h = lp.peers[1].engine.header(&late).unwrap();
    let lo = h.aspects.iter().find(|x| x.ak.as_str() == "x:m.0").unwrap().lo;
    sync(&mut lp, 1, 2);
    put_at(&mut lp, 2, d, &["late", "b"], s("2"));
    lp.advance(1);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let snap = forge_snapshot(&mut lp, 2, d, &ak("x:m.0"), now, entry_by(h.form.own_source(b, osis_base::CommitId([0; 32])), h.ts, lo, "evil", "x"));
    lp.peers[2].receive(&snap, Vec::new()).unwrap();
    let keys = |lp: &mut LocalPeer, i: usize| keys_of(lp, i, d);
    let want = BTreeSet::from([s("evil"), s("k")]);
    // Dave: everything, the snapshot first or last
    for (i, snap_first) in [(3, true), (0, false)] {
        let mut pks: Vec<_> = [0, 1, 2].into_iter().flat_map(|from| packages_for(&mut lp, from, i)).collect();
        pks.sort_by_key(|p| (p.bytes != snap) == snap_first);
        for pk in &pks {
            lp.deliver(i, pk).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        assert_eq!(keys(&mut lp, i), want, "peer {i}");
        lp.peers[i].engine.rebuild_state(&d, &ak("x:m.0")).unwrap();
        assert_eq!(keys(&mut lp, i), want, "peer {i}, rebuilt");
    }
}

// spec/permissions.md §5.2: commit-form writes a valid snapshot carries count: nothing judges
// them per author.
#[test]
fn commit_form_carried_writes_vouched_spec_perm_5_2() {
    let (mut lp, d, _, _) = setup();
    let m_ak = ak("x:m.0");
    lp.advance(1_000);
    let old = osis_base::Ts::make(WallMs(T0.0 - DAY), 0).unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let (x, y) = (osis_base::CommitId([0xA1; 32]), osis_base::CommitId([0xB2; 32]));
    let by = |c: osis_base::CommitId, ts, k: &str| {
        let mut w = osis_crdt::Writer::new(ts, osis_crdt::Source::commit(c), 1);
        osis_crdt::create(&mut w, &osis_crdt::AnyView, &Value::Map(osis_base::ValueMap::from([(s(k), s(k))]))).unwrap()
    };
    let mut f = by(x, old, "bob");
    f.join(by(y, now, "alice"));
    let keys = |lp: &mut LocalPeer, i: usize| keys_of(lp, i, d);
    let missing = forge_snapshot(&mut lp, 2, d, &m_ak, now, f);
    lp.peers[0].receive(&missing, Vec::new()).unwrap();
    assert_eq!(keys(&mut lp, 0), BTreeSet::from([s("alice"), s("bob")]));
}

fn write_reg(lp: &mut LocalPeer, i: usize, t: Tid, v: &str) -> osis_engine::Result<Option<osis_base::CommitId>> {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    lp.peers[i].commit(m)
}

// spec/permissions.md §1 (a path climbs role grants, record edges included), §4: n0 is mint
// admin of A, A writes B, B admin of C (n1 mint admin of B and C). n0's write on C applies at n0 and a receiver; a
// node with no path may not write C. A fresh reader of C given n0's certificates for C but A's
// raw record (the record-link step) holds nothing of the write until that record arrives.
#[test]
#[ignore = "issues/writes-on-unheld-things-tests.md"]
fn record_then_edge_chain_applies_spec_perm_1() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let a = new_thing(&mut lp, 0);
    let b = new_thing(&mut lp, 1);
    let c = new_thing(&mut lp, 1);
    // a reader of C holding neither A nor what A writes
    let obs = reader(&mut lp, 1, c, 0x5e3);
    lp.sync_all().unwrap();
    let ab = edge_write(&mut lp.peers[1].engine, b, a, Some(edge(Role::Write)), None);
    let bc = edge_write(&mut lp.peers[1].engine, c, b, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    assert!(write_reg(&mut lp, 2, c, "n2").is_err(), "no path: no write");
    let w = write_reg(&mut lp, 0, c, "n0").unwrap().unwrap();
    sync(&mut lp, 0, 2);
    for i in [0, 2] {
        assert_eq!(lp.peers[i].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")), "peer {i}");
    }
    // the certificates carry the edges and the records, A's among them, raw
    let certs = lp.peers[0].engine.certificates(&c).unwrap();
    assert!(certs.records.contains(&a));
    assert!(certs.commits.contains_key(&ab) && certs.commits.contains_key(&bc));
    let mut fresh = LocalPeer::of(vec![obs], 1).unwrap();
    for id in certs.commits.keys() {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        fresh.deliver(0, &pk).unwrap();
    }
    let rec = |lp: &LocalPeer, t: &Tid| lp.peers[0].engine.core.created(t).cloned().unwrap();
    let pk = lp.peers[0].engine.package(&w).unwrap().unwrap();
    let r = fresh.deliver(0, &pk).unwrap();
    assert!(matches!(r, Ingested::Pending(_, osis_engine::Reason::MissingChain(_) | osis_engine::Reason::UnknownCreated(_))), "{r:?}");
    // the records it awaits, with their chains (a record nothing awaits is not kept)
    let all = certs.records.iter().map(|t| rec(&lp, t)).collect();
    fresh.peers[0].engine.learn_records(all).unwrap();
    // what was thrown out is fetched again once its record came
    for id in certs.commits.keys() {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        fresh.deliver(0, &pk).unwrap();
    }
    fresh.deliver(0, &pk).unwrap();
    assert!(fresh.peers[0].engine.pending().is_empty(), "{:?}", fresh.peers[0].engine.pending());
    assert_eq!(fresh.peers[0].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")));
}

// spec/permissions.md §1 (`MAX_CHAIN_DEPTH`): n0 is mint admin of a chain of things down to one
// link past the cap. A descent runs within the cap (spec/permissions.md §1 Record chain): an edge
// on C to the thing at the cap lets n0 write C, the write applying at n0 and a receiver; through
// the thing one link past it no path gives the role, and the write is refused.
#[test]
fn record_chain_depth_edge_chain_spec_perm_1() {
    use osis_base::format::MAX_CHAIN_DEPTH;
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let mut up = lp.peers[0].engine.tid();
    let root = lp.peers[0].engine.node_root().unwrap();
    let mut chain = Vec::new();
    for i in 0..=MAX_CHAIN_DEPTH {
        let mut m = Mutation::new();
        up = lp.peers[0].engine.new_thing(&mut m, up);
        m.op(root, &osis_schema::core_types::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(up)) }).unwrap();
        // the thing past the cap opens nothing here, so nothing holds it: made past the writer's rules
        if i == MAX_CHAIN_DEPTH {
            lp.peers[0].engine.commit_hostile(m).unwrap();
        } else {
            lp.peers[0].commit(m).unwrap();
        }
        chain.push(up);
    }
    let (at_cap, past) = (chain[MAX_CHAIN_DEPTH - 1], chain[MAX_CHAIN_DEPTH]);
    for (k, holder) in [at_cap, past].into_iter().enumerate() {
        let c = new_thing(&mut lp, 1);
        share(&mut lp, 1, c);
        lp.sync_all().unwrap();
        edge_write(&mut lp.peers[1].engine, c, holder, Some(edge(Role::Admin)), None);
        let p0 = lp.peers[0].engine.tid();
        set_edge(&mut lp.peers[1].engine, c, p0, Some(edge(Role::Read)), None);
        lp.sync_all().unwrap();
        let r = write_reg(&mut lp, 0, c, "n0");
        if k == 1 {
            // a descent runs within `MAX_CHAIN_DEPTH` record edges: past it the path gives nothing
            assert!(matches!(r, Err(osis_engine::Error::Permission { .. })), "past the cap: {r:?}");
            continue;
        }
        r.unwrap().unwrap();
        sync(&mut lp, 0, 2);
        for i in [0, 2] {
            assert_eq!(lp.peers[i].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")), "case {k} peer {i}");
        }
    }
}

// spec/permissions.md §1, §4: n0 reaches C only through edges n0 -> G1 -> G2 -> C while it is
// mint admin of thousands of things that are mint admins of more (more than any walk-size cap): its write on C
// applies (the chain search goes backward from C, never through the things below n0).
#[test]
#[ignore = "by hand"]
fn chain_found_past_owned_flood_spec_perm_4() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let n0 = lp.peers[0].engine.tid();
    let g1 = new_thing(&mut lp, 1);
    let g2 = new_thing(&mut lp, 1);
    let c = new_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    set_edge(&mut lp.peers[1].engine, g1, n0, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[1].engine, g2, g1, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[1].engine, c, g2, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    for _ in 0..21 {
        let mut m = Mutation::new();
        for _ in 0..200 {
            let a = lp.peers[0].engine.new_thing(&mut m, n0);
            lp.peers[0].engine.new_thing(&mut m, a);
        }
        lp.peers[0].commit(m).unwrap();
    }
    write_reg(&mut lp, 0, c, "n0").unwrap().unwrap();
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")));
}

/// The index digest without the held set.
fn index_of(e: &osis_engine::Engine) -> osis_engine::engine::IndexDigest {
    e.index_digest().without_held()
}

// spec/permissions.md §2 (writing inside an entry it does not create is bad input; a new entry holding the whole grant): a write inside a holder's entry
// is refused, so field changes cannot compose (was: a change adding `until`, then one raising
// the role, left an admin edge with no `until`); written as remove + put, each change is the
// whole edge.
#[test]
fn edge_change_is_remove_and_put_spec_perm_2() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let c = lp.peers[1].engine.tid();
    let until = Some(WallMs(T0.0 + 30 * DAY));
    set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Write)), None);
    lp.advance(1_000);
    set_edge(&mut lp.peers[0].engine, d, c, Some(osis_schema::core_types::Edge { until, ..edge(Role::Write) }), None);
    lp.advance(1_000);
    // the role field alone, into the entry the last change created
    let mut m = Mutation::new();
    let path = vec![osis_crdt::PathSeg::Key(Value::Weak(c))];
    m.op(d, &osis_schema::core_types::ROLES, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(edge(Role::Admin).to_value()) }).unwrap();
    assert_eq!(lp.peers[0].engine.commit(m).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    set_edge(&mut lp.peers[0].engine, d, c, Some(osis_schema::core_types::Edge { until, ..edge(Role::Admin) }), None);
    let e = lp.peers[0].engine.roster(&d).get(&c).cloned().unwrap();
    assert_eq!((e.role, e.until), (Role::Admin, until));
}

/// Account actors for `lp`'s peers, known to all.
fn accounts(lp: &mut LocalPeer) -> Vec<Tid> {
    let ps = (0..lp.peers.len()).map(|i| lp.peers[i].engine.tid()).collect();
    lp.sync_all().unwrap();
    ps
}

/// The entry resets in the `roles.0` deltas on `d` of `done`'s commits at peer 0.
fn roles_resets(lp: &mut LocalPeer, d: Tid, done: &osis_engine::flows::Done) -> usize {
    let mut n = 0;
    for c in &done.commits {
        let Some(f) = lp.peers[0].engine.body_fragment(c, &d, &ak("roles.0")).unwrap() else { continue };
        if let Some(osis_crdt::SlotRef::Frag(osis_crdt::Fragment::Map(m))) = f.slot(osis_crdt::Encoding::Map) {
            n += m.entries().filter(|(_, r, _, _)| r.is_some()).count();
        }
    }
    n
}

/// A grants B write and removes it `k` times on one thing: the entry resets of the last grant
/// and the last removal.
fn churn_resets(k: usize) -> (usize, usize) {
    use osis_engine::flows::Demotion;
    let mut lp = net(2, 0);
    let ps = accounts(&mut lp);
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ps[0]);
    m.set(d, &REG, &s("x")).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.hold(d);
    let mut last = (0, 0);
    for _ in 0..k {
        lp.advance(10);
        let g = lp.peers[0].engine.grant(&d, &ps[1], &edge(Role::Write)).unwrap();
        lp.advance(10);
        let r = lp.peers[0].engine.demote(&d, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
        last = (roles_resets(&mut lp, d, &g), roles_resets(&mut lp, d, &r));
    }
    last
}

// spec/permissions.md §2: an edge write resets the holder's current entry alone, so a holder's
// k-th grant and removal carry as many resets at 2 and at 20 rounds of churn.
#[test]
fn holder_churn_resets_are_flat_spec_perm_2() {
    let (small, big) = (churn_resets(2), churn_resets(20));
    assert_eq!(small, (0, 1), "a grant after a removal resets nothing; a removal its grant's entry");
    assert_eq!(small, big);
}

// spec/crdt.md §4.6, spec/permissions.md §5.2, spec/requirements.md Decentralization: paged
// states (a map, a set, a map in a struct field, a text, a list) where B's writes land on random
// pages, some overwriting and deleting A's, and A writes under B's creations (a value in B's
// entry, chars after B's); C, who never saw B's writes, revokes B. A's un-merge (a rebuild per
// flipped aspect) equals a fresh node given everything with B's writes last, before and after
// a restart, reads by
// range included; nothing B wrote reads. A property, not a default test (about 7 s: a paged text's join per
// element under the rebuild check); the engine's `tests_paged` un-merge paged collections in the default tests.
#[test]
#[ignore = "property"]
fn unmerge_paged_matches_fresh_large_spec_crdt_4_6() {
    use osis_crdt::{Op, PathOp, PathSeg};
    {
        // each aspect's state far above a page, so it pages
        const N: usize = 140;
        const CHARS: usize = 17_000;
        let (mut lp, d, b, _) = setup();
        let c = lp.peers[2].engine.tid();
        set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Admin)), None);
        let pad = "x".repeat(500);
        let key = |i: usize, sfx: &str| s(&format!("key-{i:05}{sfx}"));
        let big: osis_base::ValueMap = (0..N).map(|i| (key(i, ""), s(&pad))).collect();
        let tagset: osis_base::ValueSet = (0..N).map(|i| key(i, &pad)).collect();
        let text: String = (0..CHARS as u32).map(|i| char::from_u32(0x1F600 + i % 64).unwrap()).collect();
        let mut m = Mutation::new();
        m.set(d, &BIG, &Value::Map(big.clone())).unwrap();
        m.set(d, &TAGS, &Value::Set(tagset)).unwrap();
        m.set(d, &BOOK, &Value::Map([(Value::Int(0), Value::Map(big)), (Value::Int(1), s("n"))].into_iter().collect())).unwrap();
        m.set(d, &TEXT, &Value::Str(text)).unwrap();
        m.set(d, &LIST, &Value::List((0..N).map(|i| key(i, &pad)).collect())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        let mut r = osis_base::testenv::picker(0);
        let op = |lp: &mut LocalPeer, i: usize, a: &osis_schema::Aspect<Value>, path: Vec<PathSeg>, op: Op| {
            let mut m = Mutation::new();
            m.op(d, a, PathOp { path, op }).unwrap();
            lp.peers[i].commit(m).unwrap().unwrap();
        };
        let ins = |at: usize, v: &str| Op::Insert { at, items: vec![s(v)] };
        // B's writes, each on a random page; A's under some of them
        let mut b_keys = Vec::new();
        let mut text_at = Vec::new();
        for j in 0..2 {
            let k = key(r(N), "b");
            b_keys.push(k.clone());
            op(&mut lp, 1, &BIG, vec![PathSeg::Key(k.clone())], Op::Set(s(&format!("B{j}"))));
            op(&mut lp, 1, &TAGS, vec![], Op::Add(k.clone()));
            op(&mut lp, 1, &BOOK, vec![PathSeg::Field(0), PathSeg::Key(k)], Op::Set(s("B")));
            let at = r(CHARS);
            text_at.push(at);
            op(&mut lp, 1, &TEXT, vec![], ins(at, "BB"));
            op(&mut lp, 1, &LIST, vec![], ins(r(N), "B"));
        }
        // overwrites and deletes of A's: un-merging needs A's bodies again
        op(&mut lp, 1, &BIG, vec![PathSeg::Key(key(r(N), ""))], Op::Set(s("B")));
        op(&mut lp, 1, &TEXT, vec![], Op::Delete { at: r(CHARS), len: 3 });
        op(&mut lp, 1, &TAGS, vec![], Op::Remove(key(r(N), &pad)));
        sync(&mut lp, 1, 0);
        for (k, at) in b_keys.iter().zip(&text_at).take(1) {
            op(&mut lp, 0, &BIG, vec![PathSeg::Key(k.clone())], Op::Set(s("A-under-B")));
            op(&mut lp, 0, &BOOK, vec![PathSeg::Field(0), PathSeg::Key(k.clone())], Op::Set(s("A-under-B")));
            // somewhere in or right after B's chars (indexes shift a little; any spot will do)
            op(&mut lp, 0, &TEXT, vec![], ins(at + 1, "a"));
        }
        op(&mut lp, 0, &BIG, vec![PathSeg::Key(key(r(N), "a"))], Op::Set(s("A")));
        // C revokes B unseen
        let scope = of(b, d);
        let f = frontier_now(&mut lp, 2, &scope);
        let rv = set_edge(&mut lp.peers[2].engine, d, b, None, Some(f.clone()));
        let pk = package_for(&mut lp, 2, 0, rv);
        osis_base::costs::take();
        lp.deliver(0, &pk).unwrap();
        let costs = osis_base::costs::take();
        let n = |k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
        // the five aspects B wrote; A writes no addendum (spec/permissions.md §5.2 Addenda): it
        // received B's writes in the millisecond it received the revocation, outside its window
        assert_eq!(n("rejudge: rebuild"), 5, "one rebuild per flipped aspect");        // the fresh node, a reader holding d (a node not holding it keeps none of its content):
        // B's writes last
        let mut fresh = lp.fresh_reader(0, d, 8001);
        let pks = lp.packages_to_peer(0, &mut fresh).unwrap();
        let is_b = |lp: &LocalPeer, id: &osis_base::CommitId| lp.peers[0].engine.header(id).is_some_and(|h| h.signer == b && !is_role(&lp.peers[0].engine, id));
        for p in pks.iter().filter(|p| !is_b(&lp, &p.id)).chain(pks.iter().filter(|p| is_b(&lp, &p.id))) {
            fresh.engine.ingest(&p.bytes, p.blobs.clone()).unwrap();
        }
        let aks = ["t:big.0", "t:tags.0", "t:book.0", "t:text.0", "t:list.0"].map(ak);
        for round in 0..2 {
            if round == 1 {
                lp.peers[0].restart(901).unwrap();
            }
            for a in &aks {
                let e = &mut lp.peers[0].engine;
                let got = (e.get(&d, a).unwrap(), e.state(&d, a).unwrap());
                assert_eq!(got, (fresh.engine.get(&d, a).unwrap(), fresh.engine.state(&d, a).unwrap()), "round {round} {a:?}");
                let v = format!("{:?}", got.0);
                assert!(!v.contains("\"B") && !v.contains("b\"") && !v.contains("A-under-B") && !v.contains('B'), "{a:?}: B's writes read");
            }
            for (a, len) in [(&aks[3], CHARS), (&aks[4], N)] {
                let lo = r(len - 60);
                let whole = lp.peers[0].engine.get(&d, a).unwrap();
                let want = match whole {
                    Some(Value::Str(t)) => Some(Value::Str(t.chars().skip(lo).take(50).collect())),
                    Some(Value::List(l)) => Some(Value::List(l[lo..lo + 50].to_vec())),
                    v => panic!("{v:?}"),
                };
                assert_eq!(lp.peers[0].engine.get_range(&d, a, &[], lo..lo + 50).unwrap(), want, "round {round} {a:?} range");
            }
        }
    }
}

// spec/crdt.md §4.6 (function of the held set), spec/commits.md §4 (is joined on arrival): Bob, removed, puts entry "late", text "BB" and a register in one
// commit; Carol writes inside "late" and between Bob's chars. Dave gets Bob's commit with only
// its register part, the rest later, Carol's commit anywhere among them: Bob's creation and chars
// go, Carol's map write stays in a record with no creation (read hidden), as at Eve, who held
// Bob's commit whole before Carol's; a node never getting the rest agrees with itself in either
// order.
#[test]
fn late_invalid_part_unmerges_alike_spec_crdt_4_6() {
    let (mut lp, d, b, _) = setup();
    // Bob's independent thing (its own secrets: he grants read on it)
    let bob = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let u = lp.peers[1].engine.new_thing(&mut m, bob);
    lp.peers[1].commit(m).unwrap();
    lp.hold(u);
    // Dave and Eve, and the fresh nodes below: readers of d (granted by Alice) and u (by Bob)
    let reader = |lp: &mut LocalPeer, seed: u64| {
        push_reader(lp, d, seed);
        let i = lp.peers.len() - 1;
        lp.hold_at(i, u);
        let who = lp.peers[i].engine.tid();
        // Bob takes its account's commits, as Alice did, so he can grant it
        for id in lp.peers[i].engine.commit_ids() {
            if let Some(pk) = lp.peers[i].engine.package(&id).unwrap() {
                lp.deliver(1, &pk).unwrap();
            }
        }
        lp.peers[1].know(&[who]).unwrap();
        lp.peers[1].engine.grant(&u, &who, &edge(Role::Read)).unwrap();
        i
    };
    reader(&mut lp, 9100);
    reader(&mut lp, 9101);
    lp.sync_all().unwrap();
    bob_writes_k_then_revoked(&mut lp, d, b);
    let mut m = Mutation::new();
    m.op(d, &ak("x:m.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("late"))], op: osis_crdt::Op::Set(a1()) }).unwrap();
    m.op(d, &TEXT, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 0, items: vec![s("B"), s("B")] } }).unwrap();
    m.set(d, &REG, &s("bob")).unwrap();
    m.set(u, &REG, &s("bob")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 2);
    let mut m = Mutation::new();
    m.op(d, &ak("x:m.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("late")), osis_crdt::PathSeg::Key(s("b"))], op: osis_crdt::Op::Set(s("2")) }).unwrap();
    m.op(d, &TEXT, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Insert { at: 1, items: vec![s("c")] } }).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    let n = *lp.peers[2].engine.commit_ids().iter().max_by_key(|id| lp.peers[2].engine.header(id).unwrap().ts).unwrap();
    let ck = lp.peers[1].engine.package(&c).unwrap().unwrap();
    let nk = lp.peers[2].engine.package(&n).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&c).unwrap();
    let mut partial = osis_commit::CommitBlob::decode(&ck.bytes).unwrap();
    let mut elsewhere = partial.clone();
    partial.parts.retain(|p| h.aspects[p.ai].ak.as_str() == "t:reg.0" && h.aspects[p.ai].tid == d);
    elsewhere.parts.retain(|p| h.aspects[p.ai].tid == u);
    let (partial, elsewhere) = (partial.encode(), elsewhere.encode());
    // what d's and u's sync IDs carry but Bob's commit, then `seq`
    let feed = |lp: &mut LocalPeer, i: usize, seq: &[&[u8]]| {
        let base: Vec<_> = lp.packages_of(0, &d).unwrap().into_iter().chain(lp.packages_of(1, &u).unwrap()).filter(|p| p.id != c).collect();
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        for bytes in seq {
            lp.peers[i].receive(bytes, Vec::new()).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
    };
    feed(&mut lp, 4, &[&ck.bytes, &nk.bytes]);
    let look = |lp: &mut LocalPeer, i: usize| {
        let e = &mut lp.peers[i].engine;
        let mut out = Vec::new();
        for a in [ak("x:m.0"), ak("t:reg.0"), ak("t:text.0")] {
            out.push(format!("{:?}\n{:?}", e.get(&d, &a).unwrap(), e.state(&d, &a).unwrap()));
        }
        // the invalid index on D and U (another's root is judged by whoever holds it) and Bob's
        // and Carol's commits (each node has its own identity)
        let invalid: Vec<_> = e.core.ix.invalid.iter().filter(|((t, _), _)| [d, u].contains(t)).collect();
        let ix = index_of(e);
        out.push(format!("{invalid:?}\n{:?}\n{:?}", ix.commits.get(&c), ix.commits.get(&n)));
        out
    };
    let want = look(&mut lp, 4);
    assert!(!want[3].starts_with("[]"), "Bob's parts on D invalid at Eve");
    // the read, not the state: Carol's write stays under "late"
    let shown = |x: &str| x.lines().next().unwrap().contains("late");
    assert!(!shown(&want[0]), "Eve: {}", want[0]);
    let orders: [&[&[u8]]; 3] = [&[&nk.bytes, &partial, &ck.bytes], &[&partial, &nk.bytes, &ck.bytes], &[&partial, &ck.bytes, &nk.bytes]];
    for (k, seq) in orders.iter().enumerate() {
        let i = reader(&mut lp, 9200 + k as u64);
        // it keeps the accounts Eve keeps (`LocalPeer::sync_all` introduced her)
        let all: Vec<Tid> = (0..4).map(|j| lp.peers[j].engine.tid()).collect();
        lp.peers[i].know(&all).unwrap();
        feed(&mut lp, i, seq);
        assert_eq!(look(&mut lp, i), want, "order {k}");
    }
    // the map and text parts never come: alike either way too: the removal leaves them invalid, so
    // nothing waits for them (spec/commits.md §4) and Carol's map write stays hidden
    let mut seen = Vec::new();
    for (k, seq) in [[&nk.bytes, &partial], [&partial, &nk.bytes]].iter().enumerate() {
        let i = reader(&mut lp, 9300 + k as u64);
        feed(&mut lp, i, &seq.map(|x| x.as_slice()));
        seen.push(look(&mut lp, i));
    }
    assert_eq!(seen[0], seen[1], "partial");
    assert!(!shown(&seen[0][0]), "partial: {}", seen[0][0]);
    // none of its parts on the thing comes, the one on another thing does: the commit is applied
    // from its header's word on the thing, alike either way, Carol's map write hidden
    let mut seen = Vec::new();
    for (k, seq) in [[&nk.bytes, &elsewhere], [&elsewhere, &nk.bytes]].iter().enumerate() {
        let i = reader(&mut lp, 9400 + k as u64);
        feed(&mut lp, i, &seq.map(|x| x.as_slice()));
        seen.push(look(&mut lp, i));
    }
    assert_eq!(seen[0], seen[1], "elsewhere");
    assert!(!shown(&seen[0][0]), "elsewhere: {}", seen[0][0]);
}

// spec/permissions.md §5.2 (copies; a valid snapshot speaks for current state alone; never compared with it; a node attributes a write's signer and time only to a commit it holds), spec/crdt.md §4.1 (copy order): Bob writes "real" (commit C); Carol, a
// writer, sends a snapshot carrying C's dot and `ts` with another value. Nodes holding C (after
// or before the snapshot) read the greater copy by the copy order; a node holding only the
// snapshot reads its copy, and once it holds C reads as the others. Only the holders of C
// attribute a change to Bob, and a change the snapshot makes at C's holder is the snapshot's
// (its author, its ID). Carol's removal with a frontier not listing the snapshot restores
// "real" where C is held and the earlier value where it is not.
#[test]
fn differing_copies_join_by_copy_order_alike_spec_perm_5_2() {
    use osis_crdt::{Writer, create};
    let (mut lp, d, b, c) = setup();
    let mut obs = reader(&mut lp, 0, d, 0x5fc1);
    let base = packages_for_peer(&mut lp, 0, &mut obs);
    lp.advance(1_000);
    let real = put(&mut lp, 1, d, &REG, &s("real"));
    sync(&mut lp, 1, 0);
    sync(&mut lp, 1, 2);
    let h = lp.peers[1].engine.header(&real).unwrap();
    let reg = ak("t:reg.0");
    let lo = h.aspects.iter().find(|x| x.tid == d && x.ak == reg).unwrap().lo;
    let rpk = package_for_peer(&mut lp, 1, &mut obs, real);
    // a copy greater than "real" by the copy order, and one lesser
    for (forged_value, wins) in [("zzz forged", true), ("aaa", false)] {
        let mut w = Writer::new(h.ts, h.form.own_source(b, osis_base::CommitId([0; 32])), lo);
        let f = create(&mut w, &osis_crdt::AnyView, &s(forged_value)).unwrap();
        lp.advance(1_000);
        let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
        let forged = forge_snapshot(&mut lp, 2, d, &reg, now, f);
        let with_c = if wins { s(forged_value) } else { s("real") };
        // C then the snapshot, the other way round, the snapshot alone
        let mut fid = None;
        let first = lp.peers.len();
        let peers: Vec<(usize, Option<bool>)> = [Some(true), Some(false), None].into_iter().enumerate().map(|(k, x)| (first + k, x)).collect();
        for &(i, real_first) in &peers {
            let at = lp.peers[0].engine.now();
            lp.peers.push(fresh_copy(&mut obs, at));
            for p in &base {
                lp.deliver(i, p).unwrap();
            }
            if real_first == Some(true) {
                lp.deliver(i, &rpk).unwrap();
            }
            lp.peers[i].drain_events();
            match lp.peers[i].receive(&forged, Vec::new()).unwrap() {
                Ingested::Applied(id) => fid = Some(id),
                other => panic!("{other:?}"),
            }
            let evs = lp.peers[i].drain_events();
            if real_first == Some(true) {
                let changed = evs.iter().any(|e| matches!(e, Event::Applied { id, signer, changed, .. } if Some(*id) == fid && *signer == c && changed.contains(&(d, reg.clone()))));
                assert_eq!(changed, wins, "peer {i}: the change is the snapshot's: {evs:?}");
            }
            if real_first == Some(false) {
                lp.deliver(i, &rpk).unwrap();
            }
            lp.peers[i].reexamine().unwrap();
            let want = if real_first.is_some() { with_c.clone() } else { s(forged_value) };
            assert_eq!(lp.peers[i].engine.get(&d, &reg).unwrap(), Some(want), "peer {i}");
            // history: from verified commits only
            let e = &lp.peers[i].engine;
            let by_bob = e.held_commits(&[(d, reg.clone())]).iter().any(|x| x.header.signer == b);
            assert_eq!(by_bob, real_first.is_some(), "peer {i}: Bob's commit listed only where held");
            let ch = e.changed(&d).unwrap();
            assert_eq!(ch.commit == real, real_first.is_some(), "peer {i}: last change");
            assert!(ch.node != c, "peer {i}: a snapshot is no change");
        }
        let (p0, p1, p2) = (peers[0].0, peers[1].0, peers[2].0);
        assert_eq!(lp.peers[p0].engine.state(&d, &reg).unwrap(), lp.peers[p1].engine.state(&d, &reg).unwrap(), "states alike");
        // the snapshot-only node given C reads as the others
        lp.deliver(p2, &rpk).unwrap();
        lp.peers[p2].reexamine().unwrap();
        assert_eq!(lp.peers[p2].engine.get(&d, &reg).unwrap(), Some(with_c.clone()), "peer {p2}, C late");
        assert_eq!(lp.peers[p2].engine.state(&d, &reg).unwrap(), lp.peers[p0].engine.state(&d, &reg).unwrap(), "states alike, C late");
        lp.peers[p0].restart(0x5fd0 + p0 as u64).unwrap();
        assert_eq!(lp.peers[p0].engine.get(&d, &reg).unwrap(), Some(with_c.clone()), "after a restart");
        // Carol removed, the snapshot not in the frontier: it gives nothing
        let scope = of(c, d);
        let at = lp.peers[0].engine.now();
        let mut fr = lp.peers[0].engine.frontier(&scope, at).unwrap();
        fr.commits.remove(&fid.unwrap());
        let rv = set_edge(&mut lp.peers[0].engine, d, c, None, Some(fr.clone()));
        let rv = package_for(&mut lp, 0, p0, rv);
        for i in [p0, p1, p2] {
            lp.deliver(i, &rv).unwrap();
            lp.peers[i].reexamine().unwrap();
            assert_eq!(lp.peers[i].engine.get(&d, &reg).unwrap(), Some(s("real")), "peer {i}, Carol removed");
        }
        // Carol granted again for the next round
        set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        lp.advance(1_000);
    }
}

// spec/permissions.md §5.2, spec/commits.md §5 (compaction): Alice's commit C writes `x:m.0` and
// `t:reg.0` (another purge-by class, another blob). A node that gets Alice's snapshot of `x:m.0`
// and the blob of C without its `x:m.0` delta (dropped at the peer after compaction) holds C
// without that delta and takes C's write from the snapshot, in either order; the delta coming
// late changes nothing. A reader's snapshot copying C's `x:m.0` write with another value counts
// for nothing where C's delta is held, the delta arriving after the snapshot included.
#[test]
fn snapshot_copy_of_a_delta_never_held_counts_spec_perm_5_2() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let mut obs = reader(&mut lp, 0, t, 0x5f40);
    let base = packages_for_peer(&mut lp, 0, &mut obs);
    let m_ak = ak("x:m.0");
    let mut m = Mutation::new();
    m.set(t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))]))).unwrap();
    m.set(t, &REG, &s("reg")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&t, &m_ak).unwrap().unwrap();
    let want = states(&mut lp.peers[0].engine, &[t]);
    let pks = packages_for_peer(&mut lp, 0, &mut obs);
    let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
    let h = lp.peers[0].engine.header(&c).unwrap();
    let (ck, sk) = (pk(c), pk(snap));
    let mut partial = osis_commit::CommitBlob::decode(&ck.bytes).unwrap();
    partial.parts.retain(|p| h.aspects[p.ai].ak != m_ak);
    let partial = partial.encode();
    let lo = h.aspects.iter().find(|x| x.tid == t && x.ak == m_ak).unwrap().lo;
    let hi = h.aspects.iter().find(|x| x.tid == t && x.ak == m_ak).unwrap().hi;
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let asrc = h.form.own_source(a, osis_base::CommitId([0; 32]));
    let forged = forge_snapshot_with(&mut lp, 1, t, &m_ak, now, entry_by(asrc.clone(), h.ts, lo, "k", "zzz forged"), frontier_of(&asrc, hi - 1));
    let mut feed = |lp: &mut LocalPeer, seq: &[&[u8]]| {
        let now = lp.peers[0].engine.now();
        { let at = now; lp.peers.push(fresh_copy(&mut obs, at)); }
        let i = lp.peers.len() - 1;
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        for bytes in seq {
            unless_refused(lp.peers[i].receive(bytes, Vec::new()));
            lp.peers[i].reexamine().unwrap();
        }
        i
    };
    // honest: C's `x:m.0` delta never held, or late
    for (k, seq) in [vec![&sk.bytes[..], &partial[..]], vec![&partial[..], &sk.bytes[..]], vec![&partial[..], &sk.bytes[..], &ck.bytes[..]]].iter().enumerate() {
        let i = feed(&mut lp, seq);
        assert!(lp.peers[i].engine.header(&c).is_some(), "order {k}: C applied");
        assert_eq!(states(&mut lp.peers[i].engine, &[t]), want, "order {k}");
        if k < 2 {
            // C's `x:m.0` body holds no delta here: covered (spec/commits.md §5)
            assert_eq!(lp.peers[i].engine.covered(&snap, &c, &t, &m_ak).unwrap(), Some(true), "order {k}");
        }
    }
    // forged: where C's delta is held, whichever came first
    for (k, seq) in [vec![&ck.bytes[..], &forged[..]], vec![&forged[..], &ck.bytes[..]], vec![&forged[..], &partial[..], &ck.bytes[..]], vec![&partial[..], &forged[..], &ck.bytes[..]]].iter().enumerate() {
        let i = feed(&mut lp, seq);
        assert!(lp.peers[i].engine.header(&c).is_some(), "forged order {k}: C applied");
        assert_eq!(states(&mut lp.peers[i].engine, &[t]), want, "forged order {k}");
        lp.peers[i].restart(0x5f60 + k as u64).unwrap();
        assert_eq!(states(&mut lp.peers[i].engine, &[t]), want, "forged order {k}, after a restart");
    }
}


// spec/commits.md §5 (the snapshot holds each live write of the body with the body's payload), spec/crdt.md §4.1 (copy order): a writer's snapshot copying a held write with
// another value covers neither that write's body nor the honest snapshot carrying it, whichever
// copy wins; the honest snapshot, stamped earlier, never covers it.
#[test]
fn snapshot_differing_copy_never_covers_body_spec_commits_5() {
    for (forged_value, wins) in [("zzz forged", true), ("aaa", false)] {
        let mut lp = net(2, 0);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let (a, w) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
        let m_ak = ak("x:m.0");
        let c = put(&mut lp, 0, t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))])));
        lp.advance(1_000);
        let honest = lp.peers[0].engine.snapshot(&t, &m_ak).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&c).unwrap();
        let x = h.aspects.iter().find(|x| x.tid == t && x.ak == m_ak).unwrap();
        lp.advance(1_000);
        let now = osis_base::Ts::make(lp.peers[0].engine.now(), 0).unwrap();
        sync(&mut lp, 0, 1);
        let asrc = h.form.own_source(a, osis_base::CommitId([0; 32]));
        let forged = forge_snapshot_with(&mut lp, 1, t, &m_ak, now, entry_by(asrc.clone(), h.ts, x.lo, "k", forged_value), frontier_of(&asrc, x.hi - 1));
        let f = applied(lp.peers[0].receive(&forged, Vec::new()).unwrap());
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.covered(&honest, &c, &t, &m_ak).unwrap(), Some(true), "{forged_value}: the honest snapshot covers C");
        assert_eq!(e.get(&t, &m_ak).unwrap(), Some(Value::Map(osis_base::ValueMap::from([(s("k"), s(if wins { forged_value } else { "real" }))]))), "{forged_value}: the copy order decides");
        assert_eq!(e.covered(&f, &c, &t, &m_ak).unwrap(), Some(false), "{forged_value}: the other never covers C");
        assert_eq!(e.covered(&honest, &f, &t, &m_ak).unwrap(), Some(false), "{forged_value}: the earlier snapshot never covers the later");
        assert_eq!(e.covered(&f, &honest, &t, &m_ak).unwrap(), Some(false), "{forged_value}: the other never covers the honest snapshot");
    }
}

// spec/commits.md §5 (covering copies), spec/permissions.md §5.2: writer W's snapshot
// carries co-writer X's write to a kept register (relative keep-at-least, X's write live, past
// MAX_DRIFT) with a greater value. It wins the copy order, but X's body is not covered by it,
// and is kept; once W is removed with a frontier not listing the snapshot, X's write reads again.
#[test]
fn greater_forged_copy_keeps_original_body_spec_commits_5() {
    let (mut lp, d, x, w) = setup();
    let kept = ak("t:kept.0");
    let c = put(&mut lp, 1, d, &KEPT, &s("real"));
    sync(&mut lp, 1, 0);
    sync(&mut lp, 1, 2);
    lp.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
    let h = lp.peers[1].engine.header(&c).unwrap();
    let a = h.aspects.iter().find(|a| a.tid == d && a.ak == kept).unwrap();
    let xsrc = h.form.own_source(x, c);
    let mut wr = osis_crdt::Writer::new(h.ts, xsrc.clone(), a.lo);
    let copy = osis_crdt::create(&mut wr, &osis_crdt::AnyView, &s("zzz forged")).unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let forged = forge_snapshot_with(&mut lp, 2, d, &kept, now, copy, frontier_of(&xsrc, a.hi - 1));
    let f = applied(lp.peers[0].receive(&forged, Vec::new()).unwrap());
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&d, &kept).unwrap(), Some(s("zzz forged")), "the greater copy wins");
    // the greater copy covers nothing (judged by the join with the copies under X's dots
    // stripped); X's live write is kept history anyway (spec/commits.md §5 Kept while live)
    assert_eq!(e.covered(&f, &c, &d, &kept).unwrap(), Some(false), "the forged copy does not cover X's body");
    assert!(e.drop_from(&c, &d, &kept).unwrap() > e.now().0, "kept while live");
    assert!(e.body_not_dropped(&c, &d, &kept), "X's body kept");
    let fr = osis_schema::core_types::Frontier { commits: BTreeSet::new() };
    set_edge(&mut lp.peers[0].engine, d, w, None, Some(fr.clone()));
    assert_eq!(lp.peers[0].engine.get(&d, &kept).unwrap(), Some(s("real")), "X's write reads again");
}

/// Peer 1's snapshot of its state of `t`'s tags plus an element under a `Commit(c)` dot `c`
/// (Alice's commit-form commit) did not use, stamped a second later.
fn extra_dot_snapshot(lp: &mut LocalPeer, t: Tid, c: osis_base::CommitId) -> Vec<u8> {
    use osis_crdt::{DeltaBuilder, Op, PathOp, Source, Writer};
    let tags = ak("t:tags.0");
    let ch = lp.peers[0].engine.header(&c).unwrap();
    let hi = ch.aspects.iter().find(|x| x.tid == t && x.ak == tags).unwrap().hi;
    let mut f = lp.peers[1].engine.state(&t, &tags).unwrap().unwrap().clone();
    let mut builder = DeltaBuilder::new(&f, Writer::new(ch.ts, Source::commit(c), hi + 10));
    builder.apply(&PathOp { path: Vec::new(), op: Op::Add(s("evil")) }, &osis_crdt::AnyView).unwrap();
    f.join(builder.finish().unwrap().0);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    forge_snapshot_with(lp, 1, t, &tags, now, f, osis_crdt::Frontiers::default())
}

/// Alice's commit-form tag C on `t`, compacted into her snapshot: (C, the snapshot).
fn commit_form_tag_compacted(lp: &mut LocalPeer, t: Tid) -> (osis_base::CommitId, osis_base::CommitId) {
    let mut m = Mutation::new();
    m.commit_form();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    (c, lp.peers[0].engine.snapshot(&t, &ak("t:tags.0")).unwrap().unwrap())
}

// spec/permissions.md §5.2 (an invalid s gives nothing), §5.1, spec/commits.md §5: a commit-form
// commit C's body dropped (covered by the mint admin's snapshot), a snapshot then carrying an
// extra element under `Commit(C)` never shows: a reader's (its author could not write the
// aspect), and a writer's made after its author's demotion and backdated before it, whether the
// demotion (frontier not listing it) or the snapshot arrived first (was issue
// snapshot-copy-residue (closed): one held set, two states).
#[test]
fn dropped_commit_dot_copy_by_reader_or_demoted_writer_changes_nothing_spec_perm_5_2() {
    for role in [Role::Read, Role::Write] {
        let mut lp = net(4, 0);
        lp.sync_all().unwrap();
        let w = lp.peers[1].engine.tid();
        let t = new_thing(&mut lp, 0);
        share(&mut lp, 0, t);
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(role)), None);
        let (c, honest) = commit_form_tag_compacted(&mut lp, t);
        let tags = ak("t:tags.0");
        for i in 1..4 {
            sync(&mut lp, 0, i);
        }
        for i in 2..4 {
            assert_eq!(lp.peers[i].engine.covered(&honest, &c, &t, &tags).unwrap(), Some(true), "{role:?}");
            lp.peers[i].engine.drop_body(&c, &t, &tags).unwrap();
        }
        let before = lp.peers[2].engine.get(&t, &tags).unwrap();
        let forged = extra_dot_snapshot(&mut lp, t, c);
        if role == Role::Read {
            let got = lp.peers[2].receive(&forged, Vec::new());
            assert_eq!(lp.peers[2].engine.get(&t, &tags).unwrap(), before, "a reader's: {got:?}");
            continue;
        }
        lp.advance(1_000);
        let rv = set_edge(&mut lp.peers[0].engine, t, w, None, Some(osis_schema::core_types::Frontier::default()));
        let rv_pk = package_for(&mut lp, 0, 2, rv);
        // peer 2: the snapshot first (valid then), then the demotion; peer 3: the other way round
        lp.peers[2].receive(&forged, Vec::new()).unwrap();
        lp.deliver(2, &rv_pk).unwrap();
        lp.deliver(3, &rv_pk).unwrap();
        lp.peers[3].receive(&forged, Vec::new()).unwrap();
        for i in 2..4 {
            lp.peers[i].reexamine().unwrap();
        }
        assert_eq!(lp.peers[3].engine.get(&t, &tags).unwrap(), before, "demotion first");
        assert_eq!(lp.peers[2].engine.get(&t, &tags).unwrap(), before, "snapshot first");
    }
}

// spec/commits.md §5 (Covered): an honest snapshot covers a commit writing inside an entry an
// earlier commit created (the body repeats the entry's record without its creation, which the
// snapshot holds: that record is no write of the body's), and a body this node holds no delta of.
#[test]
fn snapshot_covers_write_inside_earlier_entry_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
    let map = ak("t:map.0");
    put(&mut lp, 0, t, &MAP, &Value::Map(osis_base::ValueMap::from([(s("k"), item("x", 1))])));
    let c = put_op(&mut lp, 0, t, &MAP, PathOp { path: vec![PathSeg::Key(s("k")), PathSeg::Field(1)], op: Op::Set(Value::Int(2)) });
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&t, &map).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.covered(&snap, &c, &t, &map).unwrap(), Some(true));
}

// spec/requirements.md, Threat model ("malicious readers can only waste storage"), Decentralization;
// spec/permissions.md §5.2 (compaction snapshot; judged as a delta of that aspect): a
// reader's snapshot gives nothing and covers nothing, whether it arrives after the mint admin's
// commit C (a copy of peer 2) or before it (a copy of peer 3), across a restart. Forged: another
// value under the dot and `ts` of C's session-form register write; a map entry under the dot and
// `ts` of C's entry creation, another key; a register write under a counter the mint admin never
// used; the reader's state plus an entry at such a counter, stamped now.
#[test]
fn a_readers_snapshot_changes_nothing_spec_perm_5_2() {
    use osis_crdt::{Writer, create};
    let mut lp = net(4, 0);
    let t = new_thing(&mut lp, 0);
    let a = lp.peers[0].engine.tid();
    // the reader 1 and observers 2 and 3 read t
    for i in 1..4 {
        let o = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, o, Some(edge(Role::Read)), None);
    }
    sync(&mut lp, 0, 3);
    let (reg, m_ak) = (ak("t:reg.0"), ak("x:m.0"));
    let mut m = Mutation::new();
    m.set(t, &REG, &s("real")).unwrap();
    m.set(t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))]))).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let h = lp.peers[0].engine.header(&c).unwrap();
    let lo = |x: &osis_base::Ak| h.aspects.iter().find(|w| w.tid == t && w.ak == *x).unwrap().lo;
    let asrc = h.form.own_source(a, osis_base::CommitId([0; 32]));
    let unused = crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32]));
    let before = states(&mut lp.peers[2].engine, &[t]);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let mut with_entry = lp.peers[1].engine.state(&t, &m_ak).unwrap().unwrap().clone();
    with_entry.join(entry_by(unused.clone(), now, 1 << 40, "evil", "x"));
    let reg_at = |ts, src, lo| create(&mut Writer::new(ts, src, lo), &osis_crdt::AnyView, &s("zzz forged")).unwrap();
    let cases = [
        ("held dot", &reg, reg_at(h.ts, asrc.clone(), lo(&reg))),
        ("entry key", &m_ak, entry_by(asrc.clone(), h.ts, lo(&m_ak), "evil", "x")),
        ("unused dot", &reg, reg_at(now, unused.clone(), 1 << 40)),
        ("reader state", &m_ak, with_entry),
    ];
    for (k, (case, x, f)) in cases.into_iter().enumerate() {
        let forged = forge_snapshot(&mut lp, 1, t, x, now, f);
        let (after, first) = (lp.peers.len(), lp.peers.len() + 1);
        let (p2, p3) = (lp.peers[2].copy().unwrap(), lp.peers[3].copy().unwrap());
        lp.peers.extend([p2, p3]);
        let got = lp.peers[after].receive(&forged, Vec::new());
        assert_eq!(states(&mut lp.peers[after].engine, &[t]), before, "{case}: after C: {got:?}");
        let Ok(Ingested::Applied(fid)) = got else { panic!("{case}: {got:?}") };
        assert_eq!(lp.peers[after].engine.covered(&fid, &c, &t, x).unwrap(), Some(false), "{case}: an invalid snapshot covers nothing");
        let pre = lp.peers[first].engine.get(&t, x).unwrap();
        let got = lp.peers[first].receive(&forged, Vec::new());
        assert_eq!(lp.peers[first].engine.get(&t, x).unwrap(), pre, "{case}: before C: {got:?}");
        sync(&mut lp, 0, first);
        assert_eq!(states(&mut lp.peers[first].engine, &[t]), before, "{case}: then C");
        assert_eq!(lp.peers[after].engine.state(&t, x).unwrap(), lp.peers[first].engine.state(&t, x).unwrap(), "{case}: states alike");
        lp.peers[first].restart(0x5f01 + k as u64).unwrap();
        assert_eq!(states(&mut lp.peers[first].engine, &[t]), before, "{case}: after a restart");
    }
}

// spec/permissions.md §5.1 (frontier), §5.2 (compaction snapshot): Carol, a writer, compacts the
// tags; Dave holds Bob's tag only inside her snapshot. Alice then demotes Carol: with a frontier
// listing the snapshot (Alice had received it) Dave keeps Bob's tag; with one that does not, the
// snapshot is stripped like Carol's other writes and Bob's tag goes at Dave (Alice, holding Bob's
// commit, keeps it), whichever of the snapshot and the demotion Dave gets first, across a restart.
#[test]
fn demoted_compactor_snapshot_by_frontier_spec_perm_5_2() {
    for (covered, demote_first) in [(true, false), (true, true), (false, false), (false, true)] {
        let (mut lp, d, b, c) = setup();
        add_tag(&mut lp, 0, d, "alice");
        add_tag(&mut lp, 1, d, "bob");
        lp.sync_all().unwrap();
        // Dave gets only what is delivered below
        push_reader(&mut lp, d, 6100);
        let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
        lp.advance(DAY);
        let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        sync(&mut lp, 2, 0);
        lp.advance(DAY);
        let rv = if covered {
            let scope = of(c, d);
            let f = frontier_now(&mut lp, 0, &scope);
            assert!(f.commits.contains(&snap), "the frontier lists the snapshot");
            set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.clone()))
        } else {
            set_edge(&mut lp.peers[0].engine, d, c, None, Some(osis_schema::core_types::Frontier::default()))
        };
        let all = BTreeSet::from(["alice".to_string(), "bob".to_string()]);
        assert_eq!(tags(&mut lp, 0, d), all, "Alice holds Bob's commit");
        let pks: Vec<_> = packages_reading(&mut lp, 0, 3, d).into_iter().filter(|p| !bob.contains(&p.id)).collect();
        let (late, early): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| if demote_first { p.id == snap } else { p.id == rv });
        for pk in early.iter().chain(&late) {
            lp.deliver(3, pk).unwrap();
        }
        lp.peers[3].reexamine().unwrap();
        assert!(lp.peers[3].engine.header(&snap).is_some() && lp.peers[3].engine.header(&rv).is_some());
        assert!(bob.iter().all(|x| lp.peers[3].engine.header(x).is_none()), "Bob's commit is not held");
        let want = if covered { all.clone() } else { BTreeSet::from(["alice".to_string()]) };
        let case = format!("covered {covered}, demotion first {demote_first}");
        assert_eq!(tags(&mut lp, 3, d), want, "{case}");
        lp.peers[3].restart(6101).unwrap();
        assert_eq!(tags(&mut lp, 3, d), want, "{case}, after a restart");
    }
}

// spec/permissions.md §5.2: a write a valid snapshot gives stays although a reader's snapshot
// copying it (invalid, so giving none of its writes) is held too, in either order: one carrier's
// copy never voids another's.
#[test]
fn reader_copy_voids_no_valid_carrier_spec_perm_5_2() {
    for forged_first in [false, true] {
        let mut lp = net(3, 0);
        lp.sync_all().unwrap();
        let d = new_thing(&mut lp, 0);
        let (b, r) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, d, r, Some(edge(Role::Read)), None);
        let mut obs = reader(&mut lp, 0, d, 0x5f84);
        lp.sync_all().unwrap();
        add_tag(&mut lp, 1, d, "bob");
        lp.sync_all().unwrap();
        let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
        lp.advance(1_000);
        let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
        let f = lp.peers[2].engine.state(&d, &ak("t:tags.0")).unwrap().unwrap().clone();
        let forged = forge_snapshot(&mut lp, 2, d, &ak("t:tags.0"), now, f);
        { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
        if forged_first {
            unless_refused(lp.peers[3].receive(&forged, Vec::new()));
        }
        for pk in packages_for(&mut lp, 0, 3).into_iter().filter(|p| !bob.contains(&p.id)) {
            lp.deliver(3, &pk).unwrap();
        }
        lp.peers[3].receive(&forged, Vec::new()).unwrap();
        lp.peers[3].reexamine().unwrap();
        assert!(lp.peers[3].engine.header(&snap).is_some() && bob.iter().all(|x| lp.peers[3].engine.header(x).is_none()));
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["bob".to_string()]), "forged first: {forged_first}");
        lp.peers[3].restart(0x5f85).unwrap();
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["bob".to_string()]), "forged first: {forged_first}, after a restart");
    }
}


// spec/crdt.md §4.6, spec/permissions.md §5.2: Bob's write is carried, without its commit, by
// Alice's valid snapshots S and S2 (later, covering S) and a reader's invalid one R. Dropping S's
// body as covered leaves S2's copy and R's invalid one, which voids nothing: the write stays
// whether R arrived before or after the drop.
#[test]
fn valid_carrier_dropped_alike_either_order_spec_perm_5_2() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, r) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, r, Some(edge(Role::Read)), None);
    let mut obs = reader(&mut lp, 0, d, 0x5f89);
    lp.sync_all().unwrap();
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    lp.advance(1_000);
    lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let f = lp.peers[2].engine.state(&d, &ak("t:tags.0")).unwrap().unwrap().clone();
    let forged = forge_snapshot(&mut lp, 2, d, &ak("t:tags.0"), now, f);
    let pks: Vec<_> = packages_for_peer(&mut lp, 0, &mut obs).into_iter().filter(|p| !bob.contains(&p.id)).collect();
    let mut got = Vec::new();
    for (i, forged_first) in [(3, true), (4, false)] {
        { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
        for pk in &pks {
            lp.deliver(i, pk).unwrap();
        }
        if forged_first {
            lp.peers[i].receive(&forged, Vec::new()).unwrap();
        }
        lp.peers[i].engine.drop_body(&snap, &d, &ak("t:tags.0")).unwrap();
        if !forged_first {
            lp.peers[i].receive(&forged, Vec::new()).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        got.push(tags(&mut lp, i, d));
    }
    assert_eq!(got[0], got[1], "invalid copy before the drop, after it");
    assert_eq!(got[0], BTreeSet::from(["bob".to_string()]));
}

// spec/permissions.md §5.2 (copies; its writes join like any write; wherever held): a valid writer's snapshot copying a
// dropped commit-form commit C's writes plus an element under a `Commit(C)` dot C did not use.
// The extra element shows, whether the snapshot arrived before the drop or after, also after a
// rebuild of the aspect, an honest snapshot without it and a restart, as at a node that never
// held C.
#[test]
fn snapshot_extra_dot_of_dropped_delta_joins_alike_spec_perm_5_2() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let w = lp.peers[1].engine.tid();
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    let o = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, o, Some(edge(Role::Read)), None);
    let obs = reader(&mut lp, 0, t, 0x5f8b);
    let (c, honest) = commit_form_tag_compacted(&mut lp, t);
    let tags = ak("t:tags.0");
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let before = lp.peers[2].engine.get(&t, &tags).unwrap();
    assert!(before.is_some());
    let forged = extra_dot_snapshot(&mut lp, t, c);
    let mut setup = (lp, obs);
    for forged_first in [false, true] {
        let (mut lp, mut obs) = (setup.0.copy().unwrap(), setup.1.copy().unwrap());
        let with = match &before {
            Some(Value::Set(v)) => Some(Value::Set(v.iter().cloned().chain([s("evil")]).collect())),
            other => panic!("{other:?}"),
        };
        let before = with;
        let e = &mut lp.peers[2].engine;
        if forged_first {
            e.ingest(&forged, Vec::new()).unwrap();
            assert_eq!(e.get(&t, &tags).unwrap(), before, "forged first, delta held");
        }
        assert_eq!(e.covered(&honest, &c, &t, &tags).unwrap(), Some(true));
        e.drop_body(&c, &t, &tags).unwrap();
        if !forged_first {
            e.ingest(&forged, Vec::new()).unwrap();
        }
        e.reexamine().unwrap();
        assert_eq!(e.get(&t, &tags).unwrap(), before, "forged first: {forged_first}");
        e.rebuild_state(&t, &tags).unwrap();
        assert_eq!(e.get(&t, &tags).unwrap(), before, "forged first: {forged_first}, rebuilt");
        // an honest snapshot after the drop: both count
        lp.advance(1_000);
        lp.peers[0].engine.snapshot(&t, &tags).unwrap().unwrap();
        sync(&mut lp, 0, 2);
        let e = &mut lp.peers[2].engine;
        e.rebuild_state(&t, &tags).unwrap();
        assert_eq!(e.get(&t, &tags).unwrap(), before, "forged first: {forged_first}, honest after the drop");
        lp.peers[2].restart(0x5f89).unwrap();
        assert_eq!(lp.peers[2].engine.get(&t, &tags).unwrap(), before, "forged first: {forged_first}, restarted");
        // a node that never held C, only the snapshots
        let pks: Vec<_> = packages_for(&mut lp, 0, 3).into_iter().filter(|p| p.id != c).collect();
        { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
        for p in &pks {
            unless_refused(lp.deliver(3, p));
        }
        lp.peers[3].receive(&forged, Vec::new()).unwrap();
        lp.peers[3].reexamine().unwrap();
        assert_eq!(lp.peers[3].engine.get(&t, &tags).unwrap(), before, "forged first: {forged_first}, C never held");
    }
}

// spec/permissions.md §5.2 (a valid s vouches for every write it carries): revocation is exact where no valid snapshot carries the write; Tess's decision "Snapshots vouch", notes/revocation.md, spec/requirements.md Permissions: Bob's "mon" reaches Alice;
// his "x" reaches only Carol, who compacts the tags before she learns of his removal; his "y"
// reaches only Carol after her compaction. Alice removes Bob with what she received. "x" stays,
// "y" goes, alike at Alice, at Carol, at a new node holding everything but Bob's own commits,
// and at nodes holding Bob's commits too, in every order of the snapshot, the revoke and "x"
// and "y" themselves, and after a rebuild of the state and a restart.
#[test]
fn removed_holder_write_compacted_earlier_stays_alike_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup();
    let id_of = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.commit_ids().into_iter().filter(|c| lp.peers[i].engine.header(c).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).max_by_key(|c| lp.peers[i].engine.header(c).unwrap().ts).unwrap();
    add_tag(&mut lp, 1, d, "mon");
    lp.sync_all().unwrap();
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "x");
    let x = id_of(&mut lp, 1);
    sync(&mut lp, 1, 2);
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    lp.advance(1_000);
    add_tag(&mut lp, 1, d, "y");
    let y = id_of(&mut lp, 1);
    sync(&mut lp, 1, 2);
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    let rv = *lp.peers[0].engine.commit_ids().iter().max_by_key(|c| lp.peers[0].engine.header(c).unwrap().ts).unwrap();
    // Carol received "y" before the revoke and vouches for it (spec/permissions.md §5.2, Addenda)
    let want = BTreeSet::from(["mon".to_string(), "x".to_string(), "y".to_string()]);
    // Alice and Carol exchange everything; "y", come to Alice before Carol's addendum, went while
    // invalid (spec/permissions.md §6) and is fetched again once vouched for
    lp.sync(0, 2).unwrap();
    lp.sync(2, 0).unwrap();
    lp.sync(2, 0).unwrap();
    for i in [0, 2] {
        assert_eq!(tags(&mut lp, i, d), want, "peer {i}");
    }
    let late = [x, y, snap, rv];
    let mut all: Vec<osis_engine::local_peer::Package> = Vec::new();
    let orders: Vec<Vec<osis_base::CommitId>> = vec![vec![snap, rv], vec![rv, snap], vec![x, y, snap, rv], vec![rv, x, y, snap], vec![snap, rv, y, x], vec![y, rv, snap, x]];
    let mut states = Vec::new();
    for (n, order) in orders.iter().enumerate() {
        let i = push_reader(&mut lp, d, 0x5f8b + n as u64);
        // what Carol sends a reader of d (alike for each)
        if all.is_empty() {
            all = packages_reading(&mut lp, 2, i, d);
        }
        let base: Vec<_> = all.iter().filter(|p| !late.contains(&p.id)).cloned().collect();
        let pk = |id| all.iter().find(|p| p.id == id).unwrap().clone();
        for p in base.iter().cloned().chain(order.iter().map(|id| pk(*id))) {
            lp.deliver(i, &p).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        // "y" reads only where its body came (Carol's addendum vouches for it)
        let want: BTreeSet<String> = want.iter().filter(|t| t.as_str() != "y" || order.contains(&y)).cloned().collect();
        assert_eq!(tags(&mut lp, i, d), want, "order {order:?}");
        lp.peers[i].engine.rebuild_state(&d, &ak("t:tags.0")).unwrap();
        assert_eq!(tags(&mut lp, i, d), want, "order {order:?}, rebuilt");
        lp.peers[i].restart(0x5f9b + n as u64).unwrap();
        assert_eq!(tags(&mut lp, i, d), want, "order {order:?}, restarted");
        states.push((order.contains(&y), lp.peers[i].engine.get(&d, &ak("t:tags.0")).unwrap()));
    }
    // one state per held set: with "y" and without
    for with_y in [false, true] {
        let same: Vec<_> = states.iter().filter(|(w, _)| *w == with_y).map(|(_, s)| s).collect();
        assert!(same.windows(2).all(|w| w[0] == w[1]), "with y {with_y}");
    }
}

// spec/permissions.md §5.2, spec/crdt.md §4.6 (a function of the held set): Bob's tag reaches a
// fresh node inside Alice's snapshot S1 and Carol's later S2, which covers S1 (also with Bob's
// own commit held and made invalid by his removal with an empty frontier: vouched for). Alice
// removes Carol before receiving S2 (her frontier does not list it). A node holding S2 as valid
// drops S1 (covered), then gets the removals: S1 is missing again (S2 carries it no more) and
// gives nothing until it arrives again; another gets the removals first (S2 invalid, S1 kept).
// Once the first has S1 again, both read Bob's tag, also after a rebuild and a restart.
#[test]
fn coverer_demoted_after_cover_drop_alike_spec_perm_5_2() {
    for bob_held in [false, true] {
        let (mut lp, d, b, c) = setup();
        let mut obs = reader(&mut lp, 0, d, 0x5fa1);
        add_tag(&mut lp, 1, d, "bob");
        lp.sync_all().unwrap();
        let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
        lp.advance(1_000);
        let s1 = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        sync(&mut lp, 0, 2);
        lp.advance(1_000);
        let s2 = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        lp.advance(DAY);
        let latest = |lp: &mut LocalPeer| *lp.peers[0].engine.commit_ids().iter().max_by_key(|x| lp.peers[0].engine.header(x).unwrap().ts).unwrap();
        revoke(&mut lp, 0, d, c);
        let mut late = vec![latest(&mut lp)];
        if bob_held {
            lp.advance(1_000);
            set_edge(&mut lp.peers[0].engine, d, b, None, Some(osis_schema::core_types::Frontier::default()));
            late.push(latest(&mut lp));
        }
        sync(&mut lp, 0, 2);
        let pks: Vec<_> = packages_for_peer(&mut lp, 2, &mut obs).into_iter().filter(|p| bob_held || !bob.contains(&p.id)).collect();
        let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
        let base: Vec<_> = pks.iter().filter(|p| p.id != s2 && !late.contains(&p.id)).cloned().collect();
        let mut got = Vec::new();
        for (n, demote_first) in [false, true].into_iter().enumerate() {
            let i = lp.peers.len();
            { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
            for p in &base {
                lp.deliver(i, p).unwrap();
            }
            if !demote_first {
                lp.deliver(i, &pk(s2)).unwrap();
                let e = &mut lp.peers[i].engine;
                assert_eq!(e.covered(&s2, &s1, &d, &ak("t:tags.0")).unwrap(), Some(true), "S2 covers S1");
                e.drop_body(&s1, &d, &ak("t:tags.0")).unwrap();
            }
            for id in &late {
                lp.deliver(i, &pk(*id)).unwrap();
            }
            if demote_first {
                lp.deliver(i, &pk(s2)).unwrap();
            } else {
                // S1 gives nothing until fetched again
                lp.peers[i].reexamine().unwrap();
                assert!(tags(&mut lp, i, d).is_empty(), "Bob's commit held: {bob_held}; S1 missing");
                lp.deliver(i, &pk(s1)).unwrap();
            }
            lp.peers[i].reexamine().unwrap();
            let t = tags(&mut lp, i, d);
            lp.peers[i].engine.rebuild_state(&d, &ak("t:tags.0")).unwrap();
            assert_eq!(tags(&mut lp, i, d), t, "Bob's commit held: {bob_held}; demote first: {demote_first}, rebuilt");
            lp.peers[i].restart(0x5fa3 + n as u64).unwrap();
            assert_eq!(tags(&mut lp, i, d), t, "Bob's commit held: {bob_held}; demote first: {demote_first}, restarted");
            got.push(t);
        }
        assert_eq!(got[1], BTreeSet::from(["bob".to_string()]), "Bob's commit held: {bob_held}; removal first");
        assert_eq!(got[0], got[1], "Bob's commit held: {bob_held}; cover drop then removal, S1 fetched again");
    }
}

// spec/permissions.md §5.2 (a snapshot that turns invalid; gives nothing), spec/crdt.md §4.6: Bob's tag
// reaches fresh nodes only through snapshots: Alice's honest one and Carol's carrying another
// value under Bob's dot and `ts`. Alice then removes Carol with a frontier not listing Carol's.
// Whether Carol's copy came first (valid) or after the removal, the state ends alike: Alice's copy
// (turned invalid it gives nothing, its copies of shared dots included).
#[test]
fn invalidated_copy_of_shared_dot_goes_alike_spec_perm_5_2() {
    use osis_crdt::{DeltaBuilder, Op, PathOp, Writer};
    let (mut lp, d, b, c) = setup();
    let mut obs = reader(&mut lp, 0, d, 0x5fb1);
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let tags_ak = ak("t:tags.0");
    let bob = lp.peers[1].engine.commit_ids().into_iter().find(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak == tags_ak))).unwrap();
    let bh = lp.peers[1].engine.header(&bob).unwrap();
    let lo = bh.aspects.iter().find(|a| a.ak == tags_ak).unwrap().lo;
    let empty = osis_crdt::Fragment::default();
    let mut builder = DeltaBuilder::new(&empty, Writer::new(bh.ts, bh.form.own_source(b, osis_base::CommitId([0; 32])), lo));
    builder.apply(&PathOp { path: Vec::new(), op: Op::Add(s("evil")) }, &osis_crdt::AnyView).unwrap();
    let (evil, _) = builder.finish().unwrap();
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let forged = forge_snapshot(&mut lp, 2, d, &tags_ak, now, evil);
    lp.advance(1_000);
    let honest = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, c);
    let rv = *lp.peers[0].engine.commit_ids().iter().max_by_key(|x| lp.peers[0].engine.header(x).unwrap().ts).unwrap();
    let pks: Vec<_> = packages_for_peer(&mut lp, 0, &mut obs).into_iter().filter(|p| p.id != bob).collect();
    let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
    let base: Vec<_> = pks.iter().filter(|p| p.id != honest && p.id != rv).cloned().collect();
    let mut got = Vec::new();
    for (n, removal_first) in [false, true].into_iter().enumerate() {
        let i = lp.peers.len();
        { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        if removal_first {
            lp.deliver(i, &pk(rv)).unwrap();
        }
        lp.peers[i].receive(&forged, Vec::new()).unwrap();
        lp.deliver(i, &pk(honest)).unwrap();
        if !removal_first {
            lp.deliver(i, &pk(rv)).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        got.push(tags(&mut lp, i, d));
        lp.peers[i].engine.rebuild_state(&d, &tags_ak).unwrap();
        assert_eq!(tags(&mut lp, i, d), got[n], "removal first: {removal_first}, rebuilt");
        lp.peers[i].restart(0x5fb3 + n as u64).unwrap();
        assert_eq!(tags(&mut lp, i, d), got[n], "removal first: {removal_first}, restarted");
    }
    assert_eq!(got[1], BTreeSet::from(["bob".to_string()]), "removal first");
    assert_eq!(got[0], got[1], "Carol's copy first, then the removal");
}

/// The tag writes (`t:tags.0`) on D Alice (0) holds.
fn tag_writes(lp: &mut LocalPeer, d: Tid) -> BTreeSet<osis_base::CommitId> {
    let tags_ak = ak("t:tags.0");
    let e = &mut lp.peers[0].engine;
    e.commit_ids().into_iter().filter(|x| e.header(x).is_some_and(|h| h.kind == osis_commit::Kind::Content && h.aspects.iter().any(|a| a.tid == d && a.ak == tags_ak))).collect()
}

/// Bob's (1) removal of "ash" from D's tags, then Alice's (0) revoke of each of `revoked` (not
/// having seen it): the removal's package for `obs`, and what else `obs` is sent past `known`.
fn removal_then_revokes(lp: &mut LocalPeer, obs: &mut osis_engine::local_peer::Peer, d: Tid, revoked: &[Tid], known: &BTreeSet<osis_base::CommitId>) -> (osis_engine::local_peer::Package, Vec<osis_engine::local_peer::Package>) {
    lp.advance(1_000);
    let rm = put_op(lp, 1, d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("ash")) });
    let rm_pk = package_for_peer(lp, 1, obs, rm);
    lp.advance(1_000);
    for h in revoked {
        revoke(lp, 0, d, *h);
    }
    let rv = packages_for_peer(lp, 0, obs).into_iter().filter(|p| !known.contains(&p.id)).collect();
    (rm_pk, rv)
}

/// A fresh copy of `obs` pushed, holding `before`: its index.
fn push_holding(lp: &mut LocalPeer, obs: &mut osis_engine::local_peer::Peer, before: &[osis_engine::local_peer::Package]) -> usize {
    let at = lp.peers[0].engine.now();
    lp.peers.push(fresh_copy(obs, at));
    let i = lp.peers.len() - 1;
    for pk in before {
        lp.deliver(i, pk).unwrap();
    }
    i
}

/// Peer `i` drops the body of each of `xs` on D's tags as covered by `snap`.
fn drop_covered(lp: &mut LocalPeer, i: usize, snap: &osis_base::CommitId, xs: &BTreeSet<osis_base::CommitId>, d: Tid) {
    let (e, tags_ak) = (&mut lp.peers[i].engine, ak("t:tags.0"));
    for x in xs {
        assert_eq!(e.covered(snap, x, &d, &tags_ak).unwrap(), Some(true));
        e.drop_body(x, &d, &tags_ak).unwrap();
    }
}

/// Peer `i` takes Bob's removal `rm` and the revokes `rv`: the removal first (applied while
/// valid, D's tags then `left`) or after `rv` and `between`; then reexamines.
fn take_removal_and_revokes(lp: &mut LocalPeer, i: usize, d: Tid, removal_first: bool, (rm, rv): &(osis_engine::local_peer::Package, Vec<osis_engine::local_peer::Package>), left: &[&str], between: impl FnOnce(&mut LocalPeer)) {
    if removal_first {
        lp.deliver(i, rm).unwrap();
        assert_eq!(tags(lp, i, d), left.iter().map(|x| x.to_string()).collect(), "the removal applied while valid");
    }
    for pk in rv {
        lp.deliver(i, pk).unwrap();
    }
    between(lp);
    if !removal_first {
        lp.deliver(i, rm).unwrap();
    }
    lp.peers[i].reexamine().unwrap();
}

// spec/permissions.md §5.2, spec/crdt.md §4.6: Alice's element, its delta dropped as covered by
// her snapshot S, is removed by Bob, whose revoke then voids the removal. A node that applied
// the removal while valid and one that got the revoke first both read the element: the rebuild
// takes it again from S's copy, the dropped delta giving nothing (sim work_sets).
#[test]
fn covered_drop_restored_after_remover_revoked_alike_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup();
    let mut obs = reader(&mut lp, 0, d, 0x5f8b);
    add_tag(&mut lp, 0, d, "ash");
    let tags_ak = ak("t:tags.0");
    let added = tag_writes(&mut lp, d);
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    let before = packages_for_peer(&mut lp, 0, &mut obs);
    let late = removal_then_revokes(&mut lp, &mut obs, d, &[b], &before.iter().map(|p| p.id).collect());
    let mut got = Vec::new();
    for removal_first in [true, false] {
        let i = push_holding(&mut lp, &mut obs, &before);
        drop_covered(&mut lp, i, &snap, &added, d);
        take_removal_and_revokes(&mut lp, i, d, removal_first, &late, &[], |_| {});
        got.push((tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap()));
    }
    assert_eq!(got[0].0, BTreeSet::from(["ash".to_string()]), "removal applied, then voided");
    assert_eq!(got[1].0, got[0].0, "removal arrived voided");
    assert_eq!(got[1].1, got[0].1, "one state");
}

// spec/permissions.md §5.2, spec/crdt.md §4.6: as above, but the snapshot covering Alice's
// dropped delta is Carol's, and Alice revokes Carol (frontier not listing it) and Bob together.
// A node that dropped the delta under Carol's cover has it missing again once the revokes
// arrive: without it, the element is gone whether Bob's removal applied valid before or arrived
// voided; with the delta fetched again, it reads what a node that got the revokes first (and
// held the delta throughout) reads.
#[test]
fn covered_drop_coverer_and_remover_revoked_alike_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup();
    let mut obs = reader(&mut lp, 0, d, 0x5fc1);
    add_tag(&mut lp, 0, d, "ash");
    lp.sync_all().unwrap();
    let tags_ak = ak("t:tags.0");
    let added = tag_writes(&mut lp, d);
    let before = packages_for_peer(&mut lp, 0, &mut obs);
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    let snap_pk = package_for_peer(&mut lp, 2, &mut obs, snap);
    // without having seen the removal or Carol's snapshot
    let late = removal_then_revokes(&mut lp, &mut obs, d, &[c, b], &before.iter().map(|p| p.id).collect());
    let mut got = Vec::new();
    // dropped under Carol's cover: the removal applied valid, or arrived voided; held throughout
    for (drop, removal_first) in [(true, true), (true, false), (false, false)] {
        let i = push_holding(&mut lp, &mut obs, &before);
        if drop {
            lp.deliver(i, &snap_pk).unwrap();
            drop_covered(&mut lp, i, &snap, &added, d);
        }
        take_removal_and_revokes(&mut lp, i, d, removal_first, &late, &[], |lp| {
            if !drop {
                lp.deliver(i, &snap_pk).unwrap();
            }
        });
        if drop {
            assert!(tags(&mut lp, i, d).is_empty(), "removal first: {removal_first}; the dropped delta missing");
            lp.peers[i].engine.rebuild_state(&d, &tags_ak).unwrap();
            assert!(tags(&mut lp, i, d).is_empty(), "removal first: {removal_first}; missing, rebuilt");
            for pk in before.iter().filter(|p| added.contains(&p.id)) {
                lp.deliver(i, pk).unwrap();
            }
            lp.peers[i].reexamine().unwrap();
        }
        let t = tags(&mut lp, i, d);
        lp.peers[i].engine.rebuild_state(&d, &tags_ak).unwrap();
        assert_eq!(tags(&mut lp, i, d), t, "drop: {drop}, removal first: {removal_first}; rebuilt");
        lp.peers[i].restart(0x5fd1 + i as u64).unwrap();
        assert_eq!(tags(&mut lp, i, d), t, "drop: {drop}, removal first: {removal_first}; restarted");
        got.push((t, lp.peers[i].engine.state(&d, &tags_ak).unwrap()));
    }
    assert_eq!(got[2].0, BTreeSet::from(["ash".to_string()]), "revokes first");
    assert_eq!(got[0], got[2], "cover drop and removal, then the revokes, the delta fetched again");
    assert_eq!(got[1], got[2], "cover drop, the revokes, then the removal, the delta fetched again");
}

// spec/permissions.md §5.2, spec/commits.md §5: as `covered_drop_restored_after_remover_revoked`,
// with the cover chained: Alice's delta dropped under her snapshot S1, S1 dropped under her S2.
// S2's copy is the delta's write in the rebuild after Bob's removal turns invalid.
#[test]
fn chained_cover_drop_restored_after_remover_revoked_alike_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup();
    // a covering study, not a witness one: nobody vouches
    for p in &mut lp.peers {
        p.engine.write_addenda(false);
    }
    add_tag(&mut lp, 0, d, "ash");
    let mut obs = reader(&mut lp, 0, d, 0x5fd1);
    let tags_ak = ak("t:tags.0");
    let added = tag_writes(&mut lp, d);
    lp.advance(1_000);
    let s1 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    add_tag(&mut lp, 0, d, "elm");
    lp.advance(1_000);
    let s2 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    let all = packages_for_peer(&mut lp, 0, &mut obs);
    let s2_pk = all.iter().find(|p| p.id == s2).unwrap().clone();
    let before: Vec<_> = all.into_iter().filter(|p| p.id != s2).collect();
    let late = removal_then_revokes(&mut lp, &mut obs, d, &[b], &before.iter().map(|p| p.id).chain([s2]).collect());
    let mut got = Vec::new();
    for removal_first in [true, false] {
        let i = push_holding(&mut lp, &mut obs, &before);
        drop_covered(&mut lp, i, &s1, &added, d);
        lp.deliver(i, &s2_pk).unwrap();
        drop_covered(&mut lp, i, &s2, &BTreeSet::from([s1]), d);
        take_removal_and_revokes(&mut lp, i, d, removal_first, &late, &["elm"], |_| {});
        got.push((tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap()));
    }
    assert_eq!(got[0].0, BTreeSet::from(["ash".to_string(), "elm".to_string()]), "removal applied, then voided");
    assert_eq!(got[1], got[0], "removal arrived voided");
}

fn latest_of(lp: &mut LocalPeer, i: usize) -> osis_base::CommitId {
    *lp.peers[i].engine.commit_ids().iter().max_by_key(|x| lp.peers[i].engine.header(x).unwrap().ts).unwrap()
}

/// Delivers commits `ids` held by peer `from` to peer `i` without their parts on aspect `a`: `i` holds their headers, their writes there only through snapshots (spec/crdt.md §8:
/// a snapshot's frontier counts only on held headers).
fn deliver_stripped(lp: &mut LocalPeer, from: usize, i: usize, ids: &BTreeSet<osis_base::CommitId>, a: &osis_base::Ak) -> Vec<Ingested> {
    let pks: Vec<_> = packages_for(lp, from, i).into_iter().filter(|p| ids.contains(&p.id)).collect();
    pks.iter()
        .map(|p| {
            let h = lp.peers[from].engine.header(&p.id).unwrap();
            let mut blob = osis_commit::CommitBlob::decode(&p.bytes).unwrap();
            blob.parts.retain(|x| h.aspects[x.ai].ak != *a);
            lp.peers[i].receive(&blob.encode(), Vec::new()).unwrap()
        })
        .collect()
}

// spec/permissions.md §5.2: the cover's validity flips back. Bob (admin) removes Carol before
// seeing her S2, which covers Alice's S1; Alice removes Bob before seeing that removal, so it is
// void and S2 valid again. A node that dropped S1 under S2 and got Bob's removal first has S1
// missing, and drops S2 and Carol's tag while invalid; once Alice's removal arrives (S2 valid
// again) and what went missing is fetched, it reads what nodes that never dropped S1 read,
// whichever removal they got first.
#[test]
fn cover_drop_coverer_flips_back_alike_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup();
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    let mut obs = reader(&mut lp, 0, d, 0x5fe1);
    lp.sync_all().unwrap();
    let tags_ak = ak("t:tags.0");
    add_tag(&mut lp, 0, d, "ash");
    let ash = latest_of(&mut lp, 0);
    lp.advance(1_000);
    let s1 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    sync(&mut lp, 0, 2);
    add_tag(&mut lp, 2, d, "cy");
    lp.advance(1_000);
    let s2 = lp.peers[2].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    revoke(&mut lp, 1, d, c);
    let by_bob = latest_of(&mut lp, 1);
    lp.advance(1_000);
    revoke(&mut lp, 0, d, b);
    let by_alice = latest_of(&mut lp, 0);
    let mut all: BTreeMap<osis_base::CommitId, _> = BTreeMap::new();
    let mut order = Vec::new();
    for i in 0..3 {
        for p in packages_for_peer(&mut lp, i, &mut obs) {
            all.entry(p.id).or_insert_with(|| {
                order.push(p.id);
                p
            });
        }
    }
    // Alice's tag reaches the fresh nodes only inside S1 and S2
    let base: Vec<_> = order.iter().filter(|x| ![by_bob, by_alice, ash].contains(x)).copied().collect();
    let mut got = Vec::new();
    // (drop S1, Bob's removal first)
    for (n, (drop, bob_first)) in [(true, true), (false, true), (false, false), (true, false)].into_iter().enumerate() {
        let i = lp.peers.len();
        { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
        for x in &base {
            lp.deliver(i, &all[x]).unwrap();
        }
        if drop {
            let e = &mut lp.peers[i].engine;
            assert_eq!(e.covered(&s2, &s1, &d, &tags_ak).unwrap(), Some(true), "S2 covers S1");
            e.drop_body(&s1, &d, &tags_ak).unwrap();
        }
        let (first, second) = if bob_first { (by_bob, by_alice) } else { (by_alice, by_bob) };
        lp.deliver(i, &all[&first]).unwrap();
        lp.peers[i].reexamine().unwrap();
        if bob_first {
            let want: BTreeSet<String> = if drop { BTreeSet::new() } else { BTreeSet::from(["ash".to_string()]) };
            assert_eq!(tags(&mut lp, i, d), want, "drop {drop}: S2 invalid");
        }
        lp.deliver(i, &all[&second]).unwrap();
        lp.peers[i].reexamine().unwrap();
        let mid = (tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap());
        // what went missing is fetched again (S1 uncovered; with Bob's removal first, Carol's
        // tag and S2, dropped while invalid, spec/permissions.md §6); node-sync would drop S1
        // again under S2
        for x in base.iter().chain([&s1]) {
            lp.deliver(i, &all[x]).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        let t = (tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap());
        if !bob_first {
            assert_eq!(mid, t, "drop {drop}: nothing went missing");
        }
        lp.peers[i].engine.rebuild_state(&d, &tags_ak).unwrap();
        assert_eq!((tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap()), t, "drop {drop}, Bob first {bob_first}: rebuilt");
        lp.peers[i].restart(0x5ff1 + n as u64).unwrap();
        assert_eq!((tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap()), t, "drop {drop}, Bob first {bob_first}: restarted");
        got.push(t);
    }
    assert_eq!(got[1].0, BTreeSet::from(["ash".to_string(), "cy".to_string()]), "S1 held throughout");
    for (n, g) in got.iter().enumerate() {
        assert_eq!(g, &got[1], "case {n}");
    }
}

// spec/permissions.md §5.2, spec/sync-compaction.md §1: as `coverer_demoted_after_cover_drop_alike_*`, with
// an older valid snapshot S0 of Alice's that lacks Bob's tag. S1 missing again (S2 invalid) is no
// body S0 covers: a compactor judging it against S0 keeps it, so once fetched again it gives
// Bob's tag as at a node that never dropped it.
#[test]
fn missing_snapshot_not_covered_by_older_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup();
    let mut obs = reader(&mut lp, 0, d, 0x6001);
    let tags_ak = ak("t:tags.0");
    add_tag(&mut lp, 0, d, "ash");
    let s0 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.ak == tags_ak))).collect();
    lp.advance(1_000);
    let s1 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    sync(&mut lp, 0, 2);
    lp.advance(1_000);
    add_tag(&mut lp, 2, d, "cy");
    let s2 = lp.peers[2].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, c);
    let rv = latest_of(&mut lp, 0);
    sync(&mut lp, 0, 2);
    let pks: Vec<_> = packages_for_peer(&mut lp, 2, &mut obs).into_iter().filter(|p| !bob.contains(&p.id)).collect();
    let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
    let i = lp.peers.len();
    { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
    for p in pks.iter().filter(|p| p.id != rv) {
        lp.deliver(i, p).unwrap();
    }
    let e = &mut lp.peers[i].engine;
    assert_eq!(e.covered(&s0, &s1, &d, &tags_ak).unwrap(), Some(false), "S0 lacks Bob's tag");
    assert_eq!(e.covered(&s2, &s1, &d, &tags_ak).unwrap(), Some(true), "S2 covers S1");
    e.drop_body(&s1, &d, &tags_ak).unwrap();
    lp.deliver(i, &pk(rv)).unwrap();
    lp.peers[i].reexamine().unwrap();
    assert!(!tags(&mut lp, i, d).contains("bob"), "S1 missing");
    let e = &mut lp.peers[i].engine;
    assert_ne!(e.covered(&s0, &s1, &d, &tags_ak).unwrap(), Some(true), "S0 does not cover missing S1");
    lp.deliver(i, &pk(s1)).unwrap();
    lp.peers[i].reexamine().unwrap();
    assert!(tags(&mut lp, i, d).contains("bob"), "S1 back");
}

// spec/permissions.md §5.1 (frontier: received headers, never a snapshot's claims), §5.2: Bob's
// tag reaches a fresh node only through Carol's snapshot S; Alice removes Carol with a frontier
// not listing S; the fresh node holds Bob's headers without his parts. Whether S came first
// (valid, then invalid) or after the removal, the fresh node's frontier for Bob lists exactly
// his received commits, also after a restart.
#[test]
fn flipped_snapshot_leaves_frontier_alike_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup();
    add_tag(&mut lp, 1, d, "bob");
    sync(&mut lp, 1, 2);
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b)).collect();
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    lp.advance(DAY);
    // Alice removes Carol without listing S
    let scope = of(c, d);
    let mut f = frontier_now(&mut lp, 0, &scope);
    f.commits.remove(&snap);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.clone()));
    let rv = *lp.peers[0].engine.commit_ids().iter().max_by_key(|x| lp.peers[0].engine.header(x).unwrap().ts).unwrap();
    let held = lp.commit_ids(0);
    let of_bob = of(b, d);
    let mut got = Vec::new();
    let mut pks = Vec::new();
    for (n, order) in [[snap, rv], [rv, snap]].into_iter().enumerate() {
        // a reader of d: a node holding d with no role keeps none of its content
        let i = push_reader(&mut lp, d, 0x5fc1 + n as u64);
        // what Alice sends a reader of d (alike for each)
        if pks.is_empty() {
            pks = packages_reading(&mut lp, 0, i, d).into_iter().filter(|p| held.contains(&p.id) && !bob.contains(&p.id)).collect();
        }
        let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
        let base: Vec<_> = pks.iter().filter(|p| p.id != snap && p.id != rv).cloned().collect();
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        for id in order {
            lp.deliver(i, &pk(id)).unwrap();
            if id == snap {
                // Bob's headers: S's frontier counts on them while S is valid
                deliver_stripped(&mut lp, 1, i, &bob, &ak("t:tags.0"));
            }
        }
        lp.peers[i].reexamine().unwrap();
        assert!(tags(&mut lp, i, d).is_empty(), "order {order:?}");
        let now = lp.peers[i].engine.now();
        let f = lp.peers[i].engine.frontier(&of_bob, now).unwrap();
        lp.peers[i].restart(0x5fc3 + n as u64).unwrap();
        assert_eq!(lp.peers[i].engine.frontier(&of_bob, now).unwrap(), f, "order {order:?}, restarted");
        got.push(f);
    }
    let on_d: BTreeSet<_> = bob.iter().copied().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.aspects.iter().any(|a| a.tid == d))).collect();
    assert_eq!(got[1].commits, on_d, "removal first");
    assert_eq!(got[0], got[1], "snapshot first, then the removal");
}

/// Bob's commit X (a tag and the register; commit form if `commit_form`), Carol's snapshot S of
/// the tags listing X (frontier or `Absorbed`), Alice's removal R of Carol not listing S. Gives
/// the commits Alice holds, X, S and R.
fn listed_part_setup(commit_form: bool) -> (LocalPeer, Tid, BTreeSet<osis_base::CommitId>, [osis_base::CommitId; 3]) {
    let (mut lp, d, _, c) = setup();
    let mut m = Mutation::new();
    if commit_form {
        m.commit_form();
    }
    m.op(d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("bob")) }).unwrap();
    m.set(d, &REG, &s("bob")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    let x = latest_of(&mut lp, 1);
    sync(&mut lp, 1, 2);
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    lp.advance(DAY);
    let scope = of(c, d);
    let mut f = frontier_now(&mut lp, 0, &scope);
    f.commits.remove(&snap);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.clone()));
    let rv = latest_of(&mut lp, 0);
    let held = lp.commit_ids(0);
    (lp, d, held, [x, snap, rv])
}

/// A fresh peer holding `d`, granted read on it by Alice (`LocalPeer::fresh_reader`), given what
/// the sync IDs it syncs once a sync from Alice ends carry of `held` (R moves `d`'s:
/// spec/sync-ids.md), with S, R and X (without its tags part) in `order`; with those packages.
fn listed_part_peer(lp: &mut LocalPeer, d: Tid, held: &BTreeSet<osis_base::CommitId>, ids: [osis_base::CommitId; 3], order: &[osis_base::CommitId], seed: u64) -> (usize, Vec<osis_engine::local_peer::Package>) {
    let [x, ..] = ids;
    let i = push_reader(lp, d, seed);
    let pks: Vec<_> = packages_reading(lp, 0, i, d).into_iter().filter(|p| held.contains(&p.id)).collect();
    for p in pks.iter().filter(|p| !ids.contains(&p.id)) {
        lp.deliver(i, p).unwrap();
    }
    for id in order {
        let p = pks.iter().find(|p| p.id == *id).unwrap();
        if *id == x {
            let h = lp.peers[0].engine.header(&x).unwrap();
            let mut blob = osis_commit::CommitBlob::decode(&p.bytes).unwrap();
            blob.parts.retain(|q| h.aspects[q.ai].ak != ak("t:tags.0"));
            lp.peers[i].receive(&blob.encode(), Vec::new()).unwrap();
        } else {
            lp.deliver(i, p).unwrap();
        }
    }
    lp.peers[i].reexamine().unwrap();
    (i, pks)
}

// spec/commits.md §4, spec/permissions.md §5.2: Carol's S lists Bob's X (its frontier, or its
// `Absorbed` for a commit-form X). Whether X (without its tags part) arrives before S, while S is
// valid, or after Carol's removal made it invalid, it applies alike: the register shows, the tag
// does not, also after a restart; at a node that got the removal first, the part joins once it
// arrives.
#[test]
fn part_listed_by_invalid_snapshot_applies_alike_in_any_order_spec_commits_4() {
    for commit_form in [false, true] {
        let (mut lp, d, held, ids) = listed_part_setup(commit_form);
        let [x, snap, rv] = ids;
        let every = [[snap, x, rv], [x, snap, rv], [snap, rv, x], [rv, snap, x], [x, rv, snap], [rv, x, snap]];
        let orders = if commit_form { &[][..] } else { &every[..] };
        // (order, seed, the part arriving late in place of a restart)
        let cases = orders.iter().enumerate().map(|(n, o)| (*o, 0x5fdb + n as u64, false)).chain([([rv, snap, x], 0x5fd9, true)]);
        for (n, (order, seed, late)) in cases.enumerate() {
            let (i, pks) = listed_part_peer(&mut lp, d, &held, ids, &order, seed);
            for restarted in [false, true].into_iter().filter(|r| !(*r && late)) {
                if restarted {
                    lp.peers[i].restart(0x5fe9 + n as u64).unwrap();
                }
                let at = format!("commit form {commit_form}, order {n}, restarted {restarted}");
                let e = &mut lp.peers[i].engine;
                assert!(e.pending().is_empty(), "{at}: {:?}", e.pending());
                assert_eq!(e.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob")), "{at}");
                assert!(!tags(&mut lp, i, d).contains("bob"), "{at}");
            }
            if late {
                lp.deliver(i, pks.iter().find(|p| p.id == x).unwrap()).unwrap();
                assert!(tags(&mut lp, i, d).contains("bob"), "commit form {commit_form}: the part joined late");
            }
        }
    }
}

// spec/permissions.md §5.1 (frontier; as of t), §5.2: a snapshot's frontiers count as received
// from when its part arrived, not its header: a late part of Carol's snapshot S (Bob's tag
// reaching the node only through it, his header held) is not in a frontier backdated to before
// it came.
#[test]
fn late_snapshot_part_received_when_it_came_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    add_tag(&mut lp, 1, d, "bob");
    sync(&mut lp, 1, 2);
    // Bob's commits on d
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.signer == b && h.aspects.iter().any(|a| a.tid == d))).collect();
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    let held = lp.commit_ids(0);
    let i = push_reader(&mut lp, d, 0x5fd1);
    let pks: Vec<_> = packages_reading(&mut lp, 0, i, d).into_iter().filter(|p| held.contains(&p.id) && !bob.contains(&p.id)).collect();
    lp.hold_at(i, d);
    // it keeps the writers' accounts, Carol's chain among them, as it arrives
    let writers: Vec<Tid> = (0..3).map(|j| lp.peers[j].engine.tid()).collect();
    lp.peers[i].know(&writers).unwrap();
    for p in pks.iter().filter(|p| p.id != snap) {
        lp.deliver(i, p).unwrap();
    }
    let pk = pks.iter().find(|p| p.id == snap).unwrap();
    let h = lp.peers[i].engine.header(&snap).or_else(|| lp.peers[0].engine.header(&snap)).unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    blob.parts.retain(|p| h.aspects[p.ai].ak.as_str() != "t:tags.0");
    // the commit applies without its part (spec/commits.md §4)
    assert_eq!(lp.peers[i].receive(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(snap));
    lp.advance(1_000);
    assert!(!tags(&mut lp, i, d).contains("bob"));
    lp.advance(DAY);
    let before = lp.peers[i].engine.now();
    lp.advance(DAY);
    lp.deliver(i, pk).unwrap();
    assert!(tags(&mut lp, i, d).contains("bob"));
    // Bob's headers (not his parts): S's frontier counts on them
    let got = deliver_stripped(&mut lp, 1, i, &bob, &ak("t:tags.0"));
    assert!(got.iter().all(|g| matches!(g, Ingested::Applied(_))), "{got:?}");
    let of_bob = of(b, d);
    assert_eq!(lp.peers[i].engine.frontier(&of_bob, before).unwrap(), osis_schema::core_types::Frontier::default(), "backdated before the part");
    let now = lp.peers[i].engine.now();
    assert_ne!(lp.peers[i].engine.frontier(&of_bob, now).unwrap(), osis_schema::core_types::Frontier::default(), "now");
}

// spec/crdt.md §8 (frontiers and `Absorbed` are no receipts), spec/permissions.md §5.1, §5.2,
// spec/commits.md §4: Bob's own snapshot S claims `Frontiers {Bob: 2^40}` and `Absorbed` of a
// commit nobody holds. Alice, holding S and Bob's one tag (S before or after it), removes Bob:
// her frontier lists S (it covers the tag, so the tag is left out), never the ghost. Bob's later
// tag, at a counter S
// claims, is invalid at Alice and at fresh nodes getting it before or after the removal, and its
// header alone shows nothing of it.
#[test]
fn inflated_snapshot_claims_count_nothing_spec_crdt_8() {
    let tags_ak = ak("t:tags.0");
    for (n, snap_first) in [true, false].into_iter().enumerate() {
        let (mut lp, d, b, _) = setup();
        add_tag(&mut lp, 1, d, "mon");
        lp.advance(1_000);
        let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
        let f = lp.peers[1].engine.state(&d, &tags_ak).unwrap().unwrap();
        let ghost = osis_base::CommitId([9; 32]);
        let bs = crate::common::session_of(&lp, 1).own_source(b, osis_base::CommitId([0; 32]));
        let forged = forge_snapshot_absorbing(&mut lp, 1, d, &tags_ak, ts, f, frontier_of(&bs, 1 << 40), BTreeMap::from([(ghost, b)]));
        if snap_first {
            assert!(matches!(lp.peers[0].receive(&forged, Vec::new()).unwrap(), Ingested::Applied(_)));
            sync(&mut lp, 1, 0);
        } else {
            sync(&mut lp, 1, 0);
            assert!(matches!(lp.peers[0].receive(&forged, Vec::new()).unwrap(), Ingested::Applied(_)));
        }
        lp.advance(DAY);
        let of_bob = of(b, d);
        let f = frontier_now(&mut lp, 0, &of_bob);
        let sid = osis_commit::CommitBlob::decode(&forged).unwrap().id();
        assert!(f.commits.contains(&sid), "snap first {snap_first}");
        assert!(!f.commits.contains(&ghost), "snap first {snap_first}: a claim is no receipt");
        revoke(&mut lp, 0, d, b);
        let rv = latest_of(&mut lp, 0);
        lp.advance(DAY);
        let before: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().collect();
        add_tag(&mut lp, 1, d, "late");
        let late: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
        // S claims the late tag's counter, but was stamped before it: the header alone shows nothing
        let i = push_reader(&mut lp, d, 0x6110 + n as u64);
        for p in packages_reading(&mut lp, 0, i, d).into_iter().filter(|p| p.id != rv) {
            lp.deliver(i, &p).unwrap();
        }
        let got = deliver_stripped(&mut lp, 1, i, &late, &tags_ak);
        assert!(got.iter().all(|g| matches!(g, Ingested::Applied(..))), "snap first {snap_first}: {got:?}");
        assert!(!tags(&mut lp, i, d).contains("late"), "snap first {snap_first}");
        sync(&mut lp, 1, 0);
        assert_eq!(tags(&mut lp, 0, d), BTreeSet::from(["mon".to_string()]), "snap first {snap_first}: Alice");
        // what Alice sends a reader of d: what reader i, which took it all, syncs
        let synced = lp.synced(i).unwrap();
        let all: Vec<_> = lp.packages_under(0, &synced).unwrap();
        for (k, removal_first) in [true, false].into_iter().enumerate() {
            let j = push_reader(&mut lp, d, 0x6120 + 2 * n as u64 + k as u64);
            let (first, second): (Vec<_>, Vec<_>) = all.iter().cloned().partition(|p| (p.id == rv) == removal_first || (!late.contains(&p.id) && p.id != rv));
            for p in first.iter().chain(&second) {
                lp.deliver(j, p).unwrap();
            }
            lp.peers[j].reexamine().unwrap();
            assert_eq!(tags(&mut lp, j, d), BTreeSet::from(["mon".to_string()]), "snap first {snap_first}, removal first {removal_first}");
        }
    }
}

/// A content commit signed by peer `by`'s key carrying only `created.0` of `rec`'s thing at `ts`,
/// its delta `ops` run from counter `lo` (the record's view, else untyped), purgeable by `admin`.
fn forge_created(lp: &mut LocalPeer, by: usize, rec: &osis_base::CreationRecord, ts: osis_base::Ts, lo: u64, ops: &[osis_crdt::PathOp], typed: bool) -> Result<Vec<u8>, String> {
    forge_minting(lp, by, rec, ts, lo, ops, typed, osis_schema::PurgeBy::default(), rec.expires(), true)
}

/// `forge_created` with purge-by `purge_by`, in a commit expiring at `expires`, listing the
/// delete keys the record's maker lists (`listed`) or made-up ones.
#[allow(clippy::too_many_arguments)]
fn forge_minting(lp: &mut LocalPeer, by: usize, rec: &osis_base::CreationRecord, ts: osis_base::Ts, lo: u64, ops: &[osis_crdt::PathOp], typed: bool, purge_by: osis_schema::PurgeBy, expires: Option<u64>, listed: bool) -> Result<Vec<u8>, String> {
    use osis_commit::{AspectWrite, CommitBuilder, Kind, writer_ctx};
    use osis_crdt::{DeltaBuilder, Delta, Writer, encode_delta};
    let view = osis_schema::core_schema().view("created.0").unwrap();
    let author = lp.peers[by].engine.tid();
    let empty = osis_crdt::Fragment::default();
    let form = crate::common::forged_session(author);
    let mut b = DeltaBuilder::new(&empty, Writer::new(ts, form.own_source(author, osis_base::CommitId([0; 32])), lo));
    for op in ops {
        if typed { b.apply(op, &view) } else { b.apply(op, &osis_crdt::AnyView) }.map_err(|e| format!("{e:?}"))?;
    }
    let (f, r) = b.finish().ok_or("empty")?;
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Content, ts, author, r.lo, r.hi), None).map_err(|e| format!("{e:?}"))?;
    let mut aw = AspectWrite::new(rec.tid(), ak("created.0"), r.lo, r.hi, bytes);
    aw.purge_by = purge_by;
    // stated along its mint admin, as a writer of it mints (spec/permissions.md §1 Path)
    let path = match rec.mint_admin() {
        Some(up) if up != author => osis_commit::Path { purge: 0, things: vec![up], direct: 0 },
        _ => osis_commit::Path::default(),
    };
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, path, form);
    cb.aspects.push(aw);
    cb.expires = expires;
    let secrets = lp.peers[0].engine.hand_secrets(std::slice::from_ref(rec));
    let secrets = if listed { secrets } else { secrets.all_made_up() };
    Ok(crate::common::seal_with(lp.peers[by].engine.identity().signing(), cb, &secrets).map_err(|e| format!("{e:?}"))?.encode())
}

/// Bob's minting of `rec` at peer 1, stamped `k` ms from now: one write setting the record,
/// purgeable by `by`, in a commit expiring at `expires`.
fn reminting(lp: &mut LocalPeer, rec: &osis_base::CreationRecord, k: u64, lo: u64, by: osis_base::PurgeBy, expires: Option<u64>) -> Vec<u8> {
    use osis_crdt::{Op, PathOp};
    let ts = osis_base::Ts::make(WallMs(lp.peers[1].engine.now().0 + k), 0).unwrap();
    forge_minting(lp, 1, rec, ts, lo, &[PathOp { path: Vec::new(), op: Op::Set(rec.to_value()) }], true, by, expires, true).unwrap()
}

/// Peer 0's purge of `x`'s creation.
fn destroy(lp: &mut LocalPeer, x: Tid) -> osis_base::CommitId {
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let now = e.now();
    m.set(x, &osis_schema::core_types::PURGE, &now).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: x, ak: osis_schema::core_types::CREATED.name() });
    e.commit(m).unwrap().unwrap()
}

// spec/commits.md §5 (Destruction: a commit carrying a minting expires exactly at its record's
// `expires`; a minting never restores a thing), spec/requirements.md (data may carry an expiry at
// which every node drops it): Alice makes x expiring at T, so its record carries T. Bob, a
// writer holding the record, mints x again in a commit that does not expire or expires later,
// before T and after it: each is refused, and x is gone at T and stays gone. A minting expiring
// at T applies and changes nothing.
#[test]
fn a_minting_never_extends_an_expiring_thing_spec_commits_5() {
    use osis_base::PurgeBy::Admin;
    let (mut lp, d, _, _) = setup();
    let t = lp.peers[0].engine.now().0 + 10_000;
    let mut m = Mutation::new();
    let x = m.create(lp.peers[0].engine.thing_record(d, Some(WallMs(t))));
    lp.peers[0].engine.hold_where_it_lives(&mut m, x, d);
    m.set(x, &REG, &s("x")).unwrap();
    m.expires_all(WallMs(t));
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let rec = lp.peers[1].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap().unwrap();
    assert_eq!(rec.expires(), Some(t), "the record carries the expiry");
    let applied = |lp: &mut LocalPeer, b: &[u8]| matches!(lp.peers[0].receive(b, Vec::new()), Ok(Ingested::Applied(_)));
    for (lo, expires) in [(9000, None), (9100, Some(t + 1_000_000))] {
        let b = reminting(&mut lp, &rec, 1, lo, Admin, expires);
        assert!(!applied(&mut lp, &b), "expires {expires:?}: refused before T");
    }
    let same = reminting(&mut lp, &rec, 2, 9200, Admin, Some(t));
    assert!(applied(&mut lp, &same), "a minting expiring with its record applies");
    lp.advance(10_001);
    lp.peers[0].tick().unwrap();
    assert!(!lp.peers[0].engine.knows(&x), "x gone at T");
    let b = reminting(&mut lp, &rec, 1, 9300, Admin, None);
    assert!(!applied(&mut lp, &b), "refused after T");
    lp.peers[0].tick().unwrap();
    assert!(!lp.peers[0].engine.knows(&x), "x stays gone");
}

// spec/commits.md §5 (Destruction: a minting never restores a thing: while it is destroyed a
// minting of it is a part on an unknown thing), spec/requirements.md (purging a thing's creation
// destroys it): Bob, a writer holding x's record, mints x again, stamped before or after Alice
// destroys x, arriving at Carol before or after Alice's request.
// x is destroyed at every node in both orders, and a minting arriving while it is destroyed waits
// as a part on an unknown thing, never applied.
#[test]
fn a_minting_never_restores_a_destroyed_thing_spec_commits_5() {
    use osis_base::PurgeBy;
    for first in [false, true] {
        let (mut lp, d, _, _) = setup();
        let mut m = Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, d);
        m.set(x, &REG, &s("x")).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        let rec = lp.peers[1].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap().unwrap();
        let before = reminting(&mut lp, &rec, 1, 9000, PurgeBy::Admin, None);
        lp.advance(1_000);
        let q = destroy(&mut lp, x);
        let after = reminting(&mut lp, &rec, 1, 9100, PurgeBy::Admin, None);
        if first {
            assert!(matches!(lp.peers[2].receive(&before, Vec::new()), Ok(Ingested::Applied(_))), "live: a minting applies");
            crate::flows::send_carried(&mut lp, 0, 2, &[q]);
        } else {
            crate::flows::send_carried(&mut lp, 0, 2, &[q]);
            assert!(matches!(lp.peers[2].receive(&before, Vec::new()), Ok(Ingested::Pending(_, osis_engine::Reason::UnknownCreated(_)))), "destroyed: a minting stamped before waits");
        }
        assert!(matches!(lp.peers[2].receive(&after, Vec::new()), Ok(Ingested::Pending(_, osis_engine::Reason::UnknownCreated(_)))), "first {first}: destroyed, a minting stamped after waits");
        for b in [&before, &after] {
            unless_refused(lp.peers[0].receive(b, Vec::new()));
        }
        lp.sync_all().unwrap();
        for i in 0..3 {
            assert!(!lp.peers[i].engine.knows(&x), "first {first}: x destroyed at peer {i}");
        }
    }
}

// spec/permissions.md §6 (Destruction: judged as any request), spec/requirements.md Deletion (a
// purge counts only if its author had the right, judged as an edit's validity is): Alice grants
// Bob admin on d by a direct edge; Bob destroys d; Alice, not holding it, removes Bob from d
// later, listing nothing (as she would a thief's destruction backdated before her removal: one
// held set). Carol, given both in either order, reads d live, and with its value once synced, as
// Alice does: the removal is read for the destruction's right whatever its stamp.
#[test]
fn a_destruction_falls_with_a_later_removal_on_its_thing_in_either_order_spec_permissions_6() {
    for first in [false, true] {
        let (mut lp, d, b, _) = setup();
        set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
        lp.sync_all().unwrap();
        lp.advance(1_000);
        let q = {
            let e = &mut lp.peers[1].engine;
            let mut m = Mutation::new();
            let now = e.now();
            m.set(d, &osis_schema::core_types::PURGE, &now).unwrap();
            m.purge(osis_commit::PurgeItem::Aspect { tid: d, ak: osis_schema::core_types::CREATED.name() });
            e.commit(m).unwrap().unwrap()
        };
        lp.advance(1_000);
        let r = edge_write(&mut lp.peers[0].engine, d, b, None, Some(osis_schema::core_types::Frontier::default()));
        if first {
            crate::flows::send_carried(&mut lp, 1, 2, &[q]);
            assert!(!lp.peers[2].engine.knows(&d), "destroyed while the removal is not held");
            crate::flows::send_carried(&mut lp, 0, 2, &[r]);
        } else {
            crate::flows::send_carried(&mut lp, 0, 2, &[r]);
            crate::flows::send_carried(&mut lp, 1, 2, &[q]);
        }
        // what Carol dropped comes back from Alice, who kept it
        lp.sync_all().unwrap();
        for i in [0, 2] {
            assert!(lp.peers[i].engine.knows(&d), "first {first}: d live at peer {i}");
            assert_eq!(lp.peers[i].engine.get_typed(&d, &REG).unwrap(), Some(s("new")), "first {first}: peer {i}");
        }
    }
}

// spec/commits.md §2 (created one minting): Bob's
// commits whose `created.0` reads the record but is no minting of it (padded with a reset, or
// written untyped) are refused whole; his commit carrying one minting applies, and the honest
// creating commit (another minting of the same record, as two nodes persisting one ephemeral
// thing carry) joins it; no snapshot of `created.0` is written.
#[test]
fn padded_durable_created_refused_spec_commits_2() {
    use osis_crdt::{Op, PathOp};
    let (mut lp, d, b, _) = setup();
    // Bob makes things in d: granted by the flow (its keys), his node holds it
    lp.peers[0].engine.grant(&d, &b, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[1].engine.hold(osis_base::Strong(d)).unwrap();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, d);
    m.set(x, &REG, &s("x")).unwrap();
    let honest = lp.peers[1].commit(m).unwrap().unwrap();
    lp.hold(x);
    let rec = lp.peers[1].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let r = rec.to_value();
    let created = |lp: &mut LocalPeer| lp.peers[0].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap();
    let ts = |lp: &mut LocalPeer, k: u64| osis_base::Ts::make(WallMs(lp.peers[1].engine.now().0 + k), 0).unwrap();
    let padded = [(vec![PathOp { path: Vec::new(), op: Op::Replace(r.clone()) }], true), (vec![PathOp { path: Vec::new(), op: Op::Set(r.clone()) }], false)];
    for (k, (ops, typed)) in padded.into_iter().enumerate() {
        let t = ts(&mut lp, k as u64 + 1);
        let b = forge_created(&mut lp, 1, &rec, t, 1000 * (k as u64 + 1), &ops, typed).unwrap();
        // no record comes of it: until a record tells its hash the part cannot be judged
        assert!(matches!(lp.peers[0].receive(&b, Vec::new()), Ok(Ingested::Pending(_, osis_engine::Reason::MissingChain(_) | osis_engine::Reason::UnknownCreated(_)))), "typed {typed}");
        assert!(created(&mut lp).is_none());
    }
    let t = ts(&mut lp, 10);
    let one = forge_created(&mut lp, 1, &rec, t, 5000, &[PathOp { path: Vec::new(), op: Op::Set(r) }], true).unwrap();
    assert!(matches!(lp.peers[0].receive(&one, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(created(&mut lp), Some(rec.clone()));
    assert!(lp.peers[0].engine.pending().is_empty(), "with the record the padded ones are bad, and go: {:?}", lp.peers[0].engine.pending());
    crate::flows::send_carried(&mut lp, 1, 0, &[honest]);
    assert_eq!(lp.peers[0].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("x")));
    assert_eq!(created(&mut lp), Some(rec));
    assert!(matches!(lp.peers[0].engine.snapshot(&x, &ak("created.0")), Err(osis_engine::Error::Misuse(_))));
}

// spec/crypto.md §7 (Checked keys: `created.0` excepted), spec/permissions.md §1 (a record needs
// no authority): Bob's minting of x listing made-up delete keys leaves every other delta of it
// unjudgeable, but its `created.0` hashes to x's tid and applies: x exists at Alice's node.
#[test]
fn a_minting_listing_unplaced_keys_still_creates_spec_crypto_7() {
    use osis_crdt::{Op, PathOp};
    let (mut lp, d, b, _) = setup();
    lp.peers[0].engine.grant(&d, &b, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[1].engine.hold(osis_base::Strong(d)).unwrap();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, d);
    m.set(x, &REG, &s("x")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.hold(x);
    let rec = lp.peers[1].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let ts = osis_base::Ts::make(WallMs(lp.peers[1].engine.now().0 + 1), 0).unwrap();
    let forged = forge_minting(&mut lp, 1, &rec, ts, 5000, &[PathOp { path: Vec::new(), op: Op::Set(rec.to_value()) }], true, osis_schema::PurgeBy::default(), rec.expires(), false).unwrap();
    let id = osis_commit::CommitBlob::decode(&forged).unwrap().id();
    lp.peers[0].receive(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap(), Some(rec));
    assert_eq!(lp.peers[0].engine.creation(&x).map(|c| c.commit), Some(id), "the minting creates x");
}

// spec/crdt.md §8 (frontiers and absorbed are no receipts), spec/permissions.md §5.2 (a valid s vouches for every write it carries): Bob's tags are compacted into Carol's snapshot S
// and their blobs gone, so late admin Dan holds only S and his removal of Bob does not cover
// them; Alice and Carol, still holding Bob's commits, judge them invalid, but S keeps the tags at
// every node, fresh ones in either order included.
#[test]
fn late_joiner_after_compaction_keeps_writes_spec_crdt_8() {
    let mut lp = net(4, 0);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, c, j) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Write)), None);
    let mut obs = reader(&mut lp, 0, d, 0x6210);
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    let before: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().collect();
    add_tag(&mut lp, 1, d, "mon");
    add_tag(&mut lp, 1, d, "tue");
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| !before.contains(x)).collect();
    sync(&mut lp, 1, 0);
    sync(&mut lp, 1, 2);
    lp.advance(1000);
    lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    set_edge(&mut lp.peers[0].engine, d, j, Some(edge(Role::Admin)), None);
    lp.advance(1000);
    for p in packages_reading(&mut lp, 0, 3, d).into_iter().filter(|p| !bob.contains(&p.id)) {
        lp.deliver(3, &p).unwrap();
    }
    lp.peers[3].reexamine().unwrap();
    let want = BTreeSet::from(["mon".to_string(), "tue".to_string()]);
    assert_eq!(tags(&mut lp, 3, d), want);
    lp.advance(DAY);
    let scope = of(b, d);
    let now = lp.peers[3].engine.now();
    assert!(lp.peers[3].engine.frontier(&scope, now).unwrap().commits.is_disjoint(&bob), "no held header of Bob's");
    revoke(&mut lp, 3, d, b);
    lp.advance(1000);
    sync(&mut lp, 3, 0);
    sync(&mut lp, 3, 2);
    let all = packages_for_peer(&mut lp, 0, &mut obs);
    for reversed in [false, true] {
        let i = lp.peers.len();
        { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
        let mut v = all.clone();
        if reversed {
            v.reverse();
        }
        for p in &v {
            lp.deliver(i, p).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        for k in [0, 2, 3, i] {
            assert_eq!(tags(&mut lp, k, d), want, "peer {k}, reversed {reversed}");
        }
    }
    assert!(!lp.peers[0].engine.roster(&d).contains_key(&b));
}



// spec/permissions.md §5.1 (frontier; a commit is listed whether a still holds its body, dropped it or compacted it),
// notes/revocation.md, Frontier encoding: Bob writes a kept register twice and Carol, any writer, snapshots it
// just before Alice removes Bob. The snapshot keeps only "two"; Alice lists both, so Bob's
// superseded "one" stays valid where held; a new node never given it reads alike. Past the
// keep-at-least window both are still listed.
#[test]
fn frontier_lists_kept_writes_compacted_or_not_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    let kept = ak("t:kept.0");
    let write = |lp: &mut LocalPeer, v: &str| {
        let c = put(lp, 1, d, &KEPT, &s(v));
        lp.advance(1_000);
        c
    };
    let one = write(&mut lp, "one");
    let two = write(&mut lp, "two");
    sync(&mut lp, 1, 2);
    let snap = lp.peers[2].engine.snapshot(&d, &kept).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.covered(&snap, &one, &d, &kept).unwrap(), Some(true));
    assert_eq!(lp.peers[0].engine.covered(&snap, &two, &d, &kept).unwrap(), Some(true));
    lp.advance(1_000);
    let f = frontier_now(&mut lp, 0, &of(b, d));
    assert!(f.commits.contains(&one), "a superseded write inside its keep-at-least window is listed");
    assert!(f.commits.contains(&two), "a covered live write is listed too");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.clone()));
    assert_eq!(lp.peers[0].engine.body_valid(&one, &d, &kept), Some(true), "kept history stays valid at the holder");
    let mut fresh = fresh_net(&mut lp, 0, d, 1000); // a reader apart from lp's (its own seeds)
    fresh.advance(DAY);
    give_carried(&mut lp, 0, &mut fresh, 0, |p| p.id == one);
    fresh.peers[0].reexamine().unwrap();
    assert!(fresh.peers[0].engine.header(&one).is_none());
    for l in [&mut lp, &mut fresh] {
        assert_eq!(l.peers[0].engine.get(&d, &kept).unwrap(), Some(s("two")));
        assert!(!l.peers[0].engine.roster(&d).contains_key(&b));
    }
    // past the window (and MAX_DRIFT), Alice's compaction could drop it: listed all the same
    lp.advance(2 * DAY);
    let f = frontier_now(&mut lp, 0, &of(b, d));
    assert!(f.commits.contains(&one) && f.commits.contains(&two), "{f:?}");
}

// spec/permissions.md §5.1: a commit with a delta on a thing the demoter does not hold is listed,
// even when its part in question is droppable there (the demoter cannot judge the other delta).
// Bob's one commit writes D and his own thing E; Alice gets only its D part, which Carol's
// snapshot covers.
#[test]
fn frontier_lists_commit_with_unheld_part_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup();
    let reg = ak("t:reg.0");
    let e = new_thing(&mut lp, 1);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("both")).unwrap();
    m.set(e, &REG, &s("both")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let h = lp.peers[1].engine.header(&c).unwrap();
    blob.parts.retain(|p| h.aspects[p.ai].tid == d);
    lp.peers[0].receive(&blob.encode(), pk.blobs.clone()).unwrap();
    lp.peers[2].receive(&blob.encode(), pk.blobs.clone()).unwrap();
    assert!(lp.peers[0].engine.header(&c).is_some());
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &reg).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    assert_eq!(lp.peers[0].engine.covered(&snap, &c, &d, &reg).unwrap(), Some(true));
    lp.advance(1_000);
    let f = frontier_now(&mut lp, 0, &of(b, d));
    assert!(f.commits.contains(&c), "{f:?}");
}

/// Peer 1's key signs a commit (of `a`'s class) writing aspect `a` of `k` (a thing it has no
/// role on), under a session of its own.
fn forge_on(lp: &mut LocalPeer, k: Tid, a: &str) -> osis_commit::CommitBlob {
    use osis_commit::Kind;
    let b = lp.peers[1].engine.tid();
    // peer 0 learns peer 1's record again: nothing there needs it, so it went at the last pass end
    let own = lp.peers[1].engine.get_typed(&b, &osis_schema::core_types::CREATED).unwrap().unwrap();
    lp.peers[0].engine.learn_records(vec![own]).unwrap();
    let kind = if osis_schema::core_types::is_role_class(a) { Kind::Role } else { Kind::Content };
    // a role commit is its own source (its body goes in the probe below: header only)
    let form = if kind == Kind::Role { osis_commit::Form::Commit } else { forged_session(b) };
    let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let mut cb = osis_commit::CommitBuilder::new(kind, ts, b, osis_commit::Path::default(), form);
    let mut w = crate::common::forged_write(&cb, k, &ak(a), 1, &Value::Map(Default::default()));
    if let Some(r) = osis_commit::retention::fixed_purge_by(a) {
        w.purge_by = r;
    }
    cb.aspects.push(w);
    crate::common::seal(lp, 1, cb, &[k])
}

// spec/sync-ids.md §4 (owner): a thing's sync IDs are its `sync.0` state: a stranger's header-only commit
// listing `sync.0` on a thing (it applies, its part invalid) gives the thing no sync ID here.
#[test]
fn stranger_sync_id_listing_sync_ids_nothing_spec_sync_2() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    lp.hold(t);
    let mut blob = forge_on(&mut lp, t, "sync.0");
    blob.parts.clear();
    let id = blob.id();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.ingest(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(id));
    assert!(!e.things_with_sync_ids().contains(&t), "a listing sync IDs nothing");
    // nor after a reopen
    e.reload().unwrap();
    assert!(!e.things_with_sync_ids().contains(&t));
}

/// What a forged commit writes on one aspect: the value, or `None` for a part sent header only.
type ForgedPart<'a> = (Tid, &'a str, Option<Value>);

/// Peer `by`'s key signs a content commit (memory class with `memory`) setting each of
/// `parts`, with `undoes` and `expires`, no rights checked; parts given no value are sent
/// header only. Dedups from peer `holder`'s records.
fn forge_parts(lp: &mut LocalPeer, by: usize, holder: usize, parts: &[ForgedPart<'_>], undoes: Option<osis_base::CommitId>, expires: Option<u64>, memory: bool) -> osis_commit::CommitBlob {
    let b = lp.peers[by].engine.tid();
    let form = forged_session(b);
    let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
    let mut cb = osis_commit::CommitBuilder::new(osis_commit::Kind::Content, ts, b, osis_commit::Path::default(), form);
    cb.undoes = undoes;
    cb.expires = expires;
    if memory {
        cb.ephemeral = Some(osis_commit::EphClass::Plain);
    }
    let mut recs = Vec::new();
    for (t, a, v) in parts {
        let mut w = crate::common::forged_write(&cb, *t, &ak(a), 1, v.as_ref().unwrap_or(&s("header only")));
        if memory {
            w.purge_by = osis_commit::retention::EPHEMERAL_PURGE_BY;
        }
        cb.aspects.push(w);
        if let Some(r) = lp.peers[holder].engine.core.created(t) {
            recs.push(r.clone());
        }
    }
    // a thing given no record (its part sent header only) gets a made-up dedup secret
    let mut secrets = lp.peers[holder].engine.hand_secrets(&recs);
    secrets.unknown = Some(osis_crypto::Secret32::from_bytes([0; 32]));
    let mut blob = crate::common::seal_with(lp.peers[by].engine.identity().signing(), cb, &secrets).unwrap();
    let bare: BTreeSet<usize> = parts.iter().enumerate().filter(|(_, p)| p.2.is_none()).map(|(i, _)| i).collect();
    blob.parts.retain(|p| !bare.contains(&p.ai));
    blob
}

// spec/crdt.md §4.6 (read as it did just before that commit): undo steps back through an earlier undo (z, a, b;
// b undone to a; undoing a writes z). A stranger's commit naming that undo or listing the aspect
// later changes nothing: an undo of it sent header only, a later change sent header only, an undo
// of it validly writing only the stranger's own thing.
#[test]
fn stranger_undo_listing_moves_no_step_back_spec_crdt_4_6() {
    for variant in ["none", "undo header only", "change header only", "undo valid elsewhere"] {
        let mut lp = net(2, 0);
        lp.sync_all().unwrap();
        let t = new_thing_keeping(&mut lp, 0, &[("t:reg.0", crate::common::DAY)]);
        let set = |lp: &mut LocalPeer, v: &str| {
            lp.advance(1_000);
            put(lp, 0, t, &REG, &s(v))
        };
        set(&mut lp, "z");
        let c1 = set(&mut lp, "a");
        let c2 = set(&mut lp, "b");
        lp.advance(1_000);
        let u2 = lp.peers[0].engine.revert(&c2).unwrap().unwrap();
        assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("a")));
        lp.advance(1_000);
        let me = lp.peers[1].engine.tid();
        let forged = match variant {
            "undo header only" => Some(forge_parts(&mut lp, 1, 0, &[(t, "t:reg.0", None)], Some(u2), None, false)),
            "change header only" => Some(forge_parts(&mut lp, 1, 0, &[(t, "t:reg.0", None)], None, None, false)),
            "undo valid elsewhere" => Some(forge_parts(&mut lp, 1, 0, &[(me, "t:reg.0", Some(s("mine")))], Some(u2), None, false)),
            _ => None,
        };
        if let Some(blob) = forged {
            let id = blob.id();
            let got = lp.peers[0].receive(&blob.encode(), Vec::new()).unwrap();
            // its own node thing is no thing the receiver holds: its part waits there
            let applied = got == Ingested::Applied(id) || variant == "undo valid elsewhere" && got == Ingested::Pending(id, osis_engine::Reason::Outside(me));
            assert!(applied, "{variant}: {got:?}");
        }
        lp.advance(1_000);
        assert!(lp.peers[0].engine.revert(&c1).unwrap().is_some(), "{variant}: the undo writes");
        assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("z")), "{variant}");
    }
}

// spec/crdt.md §4.6 (undo rights): peer 1 writes a
// register while it holds write, then is lowered to read with a frontier keeping that write
// valid. Its undo of the write is `Permission`, nothing applied; peer 0, an admin, may undo it
// (restoring the read before it, from the kept history it holds: not its own commit).
#[test]
fn undo_needs_write_spec_crdt_4_6() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let t = new_thing_keeping(&mut lp, 0, &[("t:reg.0", crate::common::DAY)]);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    put(&mut lp, 0, t, &REG, &s("prior"));
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let c = put(&mut lp, 1, t, &REG, &s("b's"));
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let f = osis_schema::core_types::Frontier { commits: [c].into_iter().collect() };
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Read)), Some(f.clone()));
    lp.sync_all().unwrap();
    lp.advance(1_000);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("b's")), "the write stays valid");
    let held = lp.peers[1].engine.commit_ids().len();
    let r = lp.peers[1].engine.revert(&c);
    assert!(matches!(r, Err(osis_engine::Error::Permission { .. })), "{r:?}");
    assert_eq!(lp.peers[1].engine.commit_ids().len(), held);
    assert!(lp.peers[0].engine.revert(&c).unwrap().is_some());
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("prior")));
}

// spec/sync-ids.md §1 (repair): a reused chunk a peer deleted is written again with the reusing delta's purge-by and expiry: an invalid commit linking the value (a reader's, expiring soon) lends
// the rewrite nothing.
#[test]
fn invalid_reuse_lends_relink_no_expiry_spec_sync_1() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let r = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let mut big = vec![0u8; 1 << 20];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(0), &mut big);
    put(&mut lp, 0, t, &BLOB, &Value::Bytes(big));
    lp.sync_all().unwrap();
    let blob_ak = ak("t:blob.0");
    let link = lp.peers[0].engine.state(&t, &blob_ak).unwrap().unwrap().read().unwrap();
    assert!(matches!(link, Value::Link(_)));
    lp.advance(1_000);
    let soon = lp.peers[1].engine.now().0 + DAY;
    let blob = forge_parts(&mut lp, 1, 0, &[(t, "t:blob.0", Some(link))], None, Some(soon), false);
    let id = blob.id();
    assert_eq!(lp.peers[0].receive(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(id));
    let e = &mut lp.peers[0].engine;
    let lost = e.live_trees(&t).unwrap().blobs;
    let c = e.relink(&lost, &[t].into(), &mut |_, _| true).unwrap().expect("a rewrite");
    assert_eq!(e.header(&c).unwrap().expires, None, "the own commit's expiry, not the reader's");
}

// spec/sync-ids.md §1 (repair: judged holding no commit pending, not parked, on the aspect):
// a write of a co-writer pending here for drift on the aspect holds back the rewrite.
#[test]
fn relink_waits_for_a_commit_pending_on_the_aspect_spec_sync_1() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    let mut big = vec![0u8; 1 << 20];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(1), &mut big);
    put(&mut lp, 0, t, &BLOB, &Value::Bytes(big.clone()));
    lp.sync_all().unwrap();
    lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
    big[0] ^= 1;
    let c = put(&mut lp, 1, t, &BLOB, &Value::Bytes(big));
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    assert!(matches!(lp.deliver(0, &pk).unwrap(), Ingested::Pending(_, osis_engine::Reason::Drift)));
    let e = &mut lp.peers[0].engine;
    let lost = e.live_trees(&t).unwrap().blobs;
    assert_eq!(e.relink(&lost, &[t].into(), &mut |_, _| true).unwrap(), None, "a commit pends on the aspect");
}

// spec/wire.md §4 position 12, spec/permissions.md §5.1 step 4 (writer rule): an explicit edge
// write carries a frontier iff it audits. A lower role with none is refused (it would drop
// every write of the holder's), as is a frontier on a write whose `until` is alive (it audits
// nothing); `Engine::needs_frontier` says which.
#[test]
fn frontier_iff_the_write_audits_spec_wire_4() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;
    let (mut lp, d, b, _) = setup();
    let write = |e: &mut osis_engine::Engine, x: ct::Edge, frontier: bool| {
        let mut m = Mutation::new();
        m.op(d, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(b)) }).unwrap();
        m.op(d, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(b))], op: Op::Set(x.to_value()) }).unwrap();
        if frontier {
            m.frontier(osis_perm::Frontier::default());
        }
        e.commit(m)
    };
    let e = &mut lp.peers[0].engine;
    let read = edge(Role::Read);
    assert!(e.needs_frontier(&d, &b, Some(&read)));
    let r = write(e, read.clone(), false);
    assert!(matches!(&r, Err(osis_engine::Error::BadInput(m)) if m.contains("audits with no frontier")), "{r:?}");
    write(e, read.clone(), true).unwrap().unwrap();
    let timed = ct::Edge { until: Some(WallMs(e.now().0 + DAY)), ..read };
    assert!(!e.needs_frontier(&d, &b, Some(&timed)));
    let r = write(e, timed.clone(), true);
    assert!(matches!(&r, Err(osis_engine::Error::BadInput(m)) if m.contains("audits nothing")), "{r:?}");
    write(e, timed, false).unwrap().unwrap();
}

static KICK: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "kick.osis",
    "revision 1;\n\
     purge_by(author, admin) aspect k:s.0: string;\n\
     purge_by(author, admin) aspect k:m.0: struct { text 0: string, name 1: option<string>, tags 2: set<int> };\n",
);
static KICK_SEQ: osis_schema::StaticSchema = osis_schema::StaticSchema::new("kick-seq.osis", "revision 1; purge_by(author, admin) aspect k:m.0: struct { text 0: string, marks 3: list<int> };\n");

// spec: none (costs, spec/requirements.md Scale; notes/chat.md): a kick that drops a kept aspect's
// newest writes reads its bodies only down to the newest valid one, a whole value of any
// encoding as a scalar (`Fragment::settled_above`: nothing below it can change the state, a
// sequence's records included), so the bodies a kick reads do not grow with the aspect's length;
// nor does the state (counted as the stamps and dots it holds).
#[test]
fn kick_reads_bodies_down_to_its_winner() {
    let whole = |v: &Value| Value::Map([(Value::Int(0), v.clone()), (Value::Int(1), Value::Enum(1, Some(Box::new(s("nm"))))), (Value::Int(2), Value::Set([Value::Int(1), Value::Int(2)].into_iter().collect()))].into_iter().collect());
    let marked = Value::Map([(Value::Int(0), s("old")), (Value::Int(3), Value::List(vec![Value::Int(1)]))].into_iter().collect());
    // (aspect, the value of message `v`, an early write holding a sequence)
    type Case = (&'static str, fn(&Value) -> Value, Option<(&'static osis_schema::StaticSchema, Value)>);
    let cases: [Case; 3] = [("k:s.0", |v| v.clone(), None), ("k:m.0", whole, None), ("k:m.0", whole, Some((&KICK_SEQ, marked)))];
    for (name, val, seq) in cases {
        let k = ak(name);
        let bodies_read = |n: usize| -> (u64, usize) {
            let mut lp = net(2, 0);
            let (alice, bob) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
            let mut m = Mutation::new();
            let d = lp.peers[0].engine.new_thing(&mut m, alice);
            lp.peers[0].commit(m).unwrap().unwrap();
            lp.hold(d);
            set_edge(&mut lp.peers[0].engine, d, bob, Some(edge(Role::Write)), None);
            lp.sync_all().unwrap();
            let write = |lp: &mut LocalPeer, i: usize, schema: &'static osis_schema::StaticSchema, v: Value| {
                let mut m = Mutation::new();
                m.replace(d, &osis_schema::Aspect::<Value>::new(name, schema), &v).unwrap();
                lp.peers[i].commit(m).unwrap().unwrap();
            };
            if let Some((schema, v)) = &seq {
                write(&mut lp, 0, schema, v.clone());
            }
            for j in 0..n {
                write(&mut lp, 0, &KICK, val(&s(&format!("a{j}"))));
            }
            lp.sync_all().unwrap();
            for j in 0..5 {
                write(&mut lp, 1, &KICK, val(&s(&format!("b{j}"))));
            }
            lp.sync_all().unwrap();
            assert_eq!(lp.peers[0].engine.get(&d, &k).unwrap(), Some(val(&s("b4"))));
            let size = format!("{:?}", lp.peers[0].engine.state(&d, &k).unwrap()).matches("STid(").count();
            // a kick with nothing of Bob's listed: his writes fall, Alice's newest wins again
            osis_base::costs::take();
            set_edge(&mut lp.peers[0].engine, d, bob, None, Some(osis_schema::core_types::Frontier::default()));
            let costs = osis_base::costs::take();
            assert_eq!(lp.peers[0].engine.get(&d, &k).unwrap(), Some(val(&s(&format!("a{}", n - 1)))));
            (costs.iter().find(|c| c.0 == "rebuild: body").map_or(0, |c| c.2), size)
        };
        let ((few, small), (many, big)) = (bodies_read(10), bodies_read(100));
        // flat in n: Bob's, Alice's newest, and the re-reads of dropping Bob's invalid bodies
        assert!(few == many && few < 20, "{name}: bodies read at 10 and 100 kept writes: {few}, {many}");
        assert_eq!(small, big, "{name}: state at 10 and 100 kept writes");
    }
}

// spec/permissions.md §5.2, spec/crdt.md §4.6, §6.1: every read is a function of the valid
// writes held. Bob, revoked unseen, inserts "X" into Alice's text "ab", into the text inside her
// list<text>, and as the only element of a list nobody else writes. Carol gets his commit after
// the revoke's `ts`, before she holds the revoke, and inserts "y" after each X, "z" after the
// first y. A node holding Bob's commit reads as a node that never got it (y and z at X's place,
// at the end; the list absent), whether it arrived invalid or flipped (Carol's node).
#[test]
fn invalid_insert_leaves_no_trace_in_order_spec_crdt_6_1() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let (mut lp, d, b, _) = setup();
    let op = |lp: &mut LocalPeer, i: usize, a: &osis_schema::Aspect<Value>, path: Vec<PathSeg>, at: usize, v: &str| {
        let mut m = Mutation::new();
        m.op(d, a, PathOp { path, op: Op::Insert { at, items: vec![s(v)] } }).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let mut m = Mutation::new();
    m.set(d, &TEXT, &s("ab")).unwrap();
    m.set(d, &LISTTEXT, &Value::List(vec![s("ab")])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(DAY);
    let mut m = Mutation::new();
    m.op(d, &TEXT, PathOp { path: vec![], op: Op::Insert { at: 1, items: vec![s("X")] } }).unwrap();
    m.op(d, &LISTTEXT, PathOp { path: vec![PathSeg::Index(0)], op: Op::Insert { at: 1, items: vec![s("X")] } }).unwrap();
    m.op(d, &LIST, PathOp { path: vec![], op: Op::Insert { at: 0, items: vec![s("X")] } }).unwrap();
    let bob = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    lp.advance(DAY);
    // received after the revoke's `ts`: no addendum of Carol's vouches for it (spec/permissions.md §5.2)
    sync(&mut lp, 1, 2);
    op(&mut lp, 2, &TEXT, vec![], 2, "y");
    op(&mut lp, 2, &TEXT, vec![], 3, "z");
    op(&mut lp, 2, &LISTTEXT, vec![PathSeg::Index(0)], 2, "y");
    let read = |lp: &mut LocalPeer, i: usize| ["t:text.0", "t:listtext.0", "t:list.0"].map(|a| lp.peers[i].engine.get(&d, &ak(a)).unwrap());
    assert_eq!(read(&mut lp, 2), [Some(s("aXyzb")), Some(Value::List(vec![s("aXyb")])), Some(Value::List(vec![s("X")]))], "before the revoke");
    sync(&mut lp, 2, 0);
    sync(&mut lp, 1, 0);
    sync(&mut lp, 0, 2);
    // the list held only Bob's element: absent, as where his commit never came
    let want = [Some(s("abyz")), Some(Value::List(vec![s("aby")])), None];
    assert_eq!(read(&mut lp, 0), want, "Alice: Bob's commit arrived invalid");
    assert_eq!(read(&mut lp, 2), want, "Carol: Bob's commit flipped invalid");
    // fresh nodes: without Bob's commit, with it first, with it last
    let held = lp.commit_ids(0);
    let mut pks = Vec::new();
    for k in 0..3 {
        let i = push_reader(&mut lp, d, 9500 + k as u64);
        // what Alice sends a reader of d (alike for each)
        if pks.is_empty() {
            pks = packages_reading(&mut lp, 0, i, d).into_iter().filter(|p| held.contains(&p.id)).collect();
        }
        let (without, with_bob): (Vec<_>, Vec<_>) = pks.iter().partition(|p| p.id != bob);
        let orders = [without.clone(), with_bob.iter().chain(&without).copied().collect(), without.iter().chain(&with_bob).copied().collect::<Vec<_>>()];
        let order = &orders[k];
        for p in order {
            lp.deliver(i, p).unwrap();
        }
        lp.peers[i].reexamine().unwrap();
        assert_eq!(read(&mut lp, i), want, "fresh node {k}");
    }
}

static ANCHOR_TEXT: osis_schema::StaticSchema = osis_schema::StaticSchema::new("anchor-text.osis", "revision 1; purge_by(author, admin) aspect k:t.0: text;\n");
static ANCHOR_STR: osis_schema::StaticSchema = osis_schema::StaticSchema::new("anchor-str.osis", "revision 1; purge_by(author, admin) aspect k:t.0: string;\n");

// spec/crdt.md §4.2, §4.6, §6.1, §7: a rebuild is the join of every held body. A register write
// resets older text, whose records go; a later insert anchored at an old char sits at its virtual
// anchor, so a rebuild settled at the register reads no older body and Carol's insert shows after
// a kick rebuilt the aspect as before it.
#[test]
fn rebuild_past_a_register_places_older_anchors_spec_crdt_4_2() {
    let (mut lp, d, b, _) = setup();
    let text = osis_schema::Aspect::<Value>::new("k:t.0", &ANCHOR_TEXT);
    let reg = osis_schema::Aspect::<Value>::new("k:t.0", &ANCHOR_STR);
    let k = ak("k:t.0");
    put_op(&mut lp, 0, d, &text, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Insert { at: 0, items: vec![s("abc")] } });
    lp.sync_all().unwrap();
    // Alice's old app saves a string over it; Bob writes one after
    for (i, v) in [(0, "Q"), (1, "B")] {
        let mut m = Mutation::new();
        m.replace(d, &reg, &s(v)).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap();
        sync(&mut lp, i, 1 - i);
    }
    // a kick with nothing of Bob's listed: the rebuild settles at Alice's register write
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(osis_schema::core_types::Frontier::default()));
    // Carol, who saw only the text, inserts after its `b`, later
    lp.advance(DAY);
    put_op(&mut lp, 2, d, &text, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Insert { at: 2, items: vec![s("Z")] } });
    sync(&mut lp, 2, 0);
    // the text slot is chosen (Carol's stamp is the greatest): the register's chars, then Z at
    // its virtual anchor
    assert_eq!(lp.peers[0].engine.get(&d, &k).unwrap(), Some(s("QZ")));
}

// spec/crdt.md §5.7: a reopen forgets a deleted text element's char; the delete falling (its
// author demoted with nothing listed) brings it back from its creation's body
#[test]
fn delete_falls_after_reopen_reads_text_spec_crdt_5_7() {
    for reopen in [false, true] {
        let mut lp = net(3, 0);
        let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
        let mut m = Mutation::new();
        let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.hold(d);
        set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
        lp.sync_all().unwrap();
        lp.advance(1_000);
        put(&mut lp, 1, d, &TEXT, &s("abc"));
        lp.sync_all().unwrap();
        lp.advance(1_000);
        put_op(&mut lp, 2, d, &TEXT, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Delete { at: 1, len: 1 } });
        lp.sync_all().unwrap();
        lp.advance(1_000);
        let read = |lp: &mut LocalPeer| lp.peers[0].engine.get(&d, &ak("t:text.0")).unwrap();
        assert_eq!(read(&mut lp), Some(s("ac")));
        if reopen {
            lp.peers[0].engine.reload().unwrap();
            assert_eq!(read(&mut lp), Some(s("ac")));
        }
        set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Read)), Some(osis_schema::core_types::Frontier::default()));
        assert_eq!(read(&mut lp), Some(s("abc")), "reopen {reopen}");
    }
}

// spec/requirements.md Convergence (holders of the same commits read alike), spec/permissions.md
// §5.2 (Position; Addenda): Alice grants Bob and Carol write; in one fresh millisecond Bob writes v5
// and Alice, not having seen it, removes Bob, so both carry the same `ts`. The HLC makes that tie
// proof they were concurrent, so layer 2 orders v5 before the removal whatever the tids: Carol
// received v5 before the removal (`carol_first`, a millisecond earlier) and her addendum keeps it, else it is lost. Then
// everyone exchanges everything, and a fresh node is handed every commit: all read alike, for
// either order of Alice's and Bob's tids (the tied pair; the addenda property draws every
// assignment). Ordering v5 after the removal by tid made the outcome depend on whose tid was lower.
#[test]
#[ignore = "stub rewrite: entry by references and chain-holder stubs (R2)"]
fn a_removed_writers_write_at_the_removals_ts_reads_alike_whatever_the_tids_spec_perm_5_2() {
    for [a, b, c] in [[0, 1, 2], [1, 0, 2]] {
        for carol_first in [true, false] {
            let mut lp = net(3, 0);
            lp.sync_all().unwrap();
            let t = new_thing(&mut lp, a);
            let mut obs = reader(&mut lp, a, t, 0x7e5);
            let (bob, carol) = (lp.peers[b].engine.tid(), lp.peers[c].engine.tid());
            let write = |lp: &mut LocalPeer, i: usize, v: &str| {
                put(lp, i, t, &REG, &s(v))
            };
            write(&mut lp, a, "v3");
            lp.peers[a].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
            write(&mut lp, a, "v4");
            lp.peers[a].engine.grant(&t, &carol, &edge(Role::Write)).unwrap();
            lp.sync_all().unwrap();
            lp.advance(DAY);
            let v5 = write(&mut lp, b, "v5");
            let rm = lp.peers[a].engine.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None }).unwrap().commits;
            let ts = |lp: &LocalPeer, i: usize, id| lp.peers[i].engine.header(id).unwrap().ts;
            assert!(rm.iter().all(|r| ts(&lp, a, r) == ts(&lp, b, &v5)), "v5 and the removal share a ts");
            if carol_first {
                sync(&mut lp, b, c);
                // before the removal reaches her (spec/permissions.md §5.2 Addenda, Writing: R's
                // window ends at R's arrival, at an earlier millisecond)
                lp.advance(1);
            }
            sync(&mut lp, a, c);
            for _ in 0..3 {
                lp.sync_all().unwrap();
            }
            let mut pks: Vec<_> = (0..3).flat_map(|i| packages_for_peer(&mut lp, i, &mut obs)).collect();
            pks.sort_by_key(|p| p.id);
            pks.dedup_by_key(|p| p.id);
            { let at = lp.peers[0].engine.now(); lp.peers.push(fresh_copy(&mut obs, at)); }
            for _ in 0..2 {
                for p in &pks {
                    unless_refused(lp.deliver(3, p));
                }
            }
            lp.peers[3].reexamine().unwrap();
            // each keeps its own roots' commits and the chains it needs: compared on t
            let on_t = |e: &osis_engine::Engine, c: &osis_base::CommitId| e.header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t));
            let held: Vec<BTreeSet<_>> = (0..3).map(|i| lp.peers[i].engine.commit_ids().into_iter().filter(|c| on_t(&lp.peers[i].engine, c)).collect()).collect();
            let reads: Vec<_> = (0..4).map(|i| lp.peers[i].engine.get_typed(&t, &REG).unwrap()).collect();
            let at = format!("Alice {a}, Bob {b}, Carol {c}, Carol first {carol_first}");
            assert!(held.iter().all(|h| *h == held[0]), "{at}: every node holds the same commits on t");
            let want = s(if carol_first { "v5" } else { "v4" });
            assert!(reads.iter().all(|r| *r == Some(want.clone())), "{at}: every node and the fresh one read {want:?}; reads {reads:?}");
        }
    }
}

// spec/permissions.md §5.2 (Position; Addenda: security): Bob, removed, makes a write stamped at
// exactly his removal's `ts` (from a copy of his node from before he learned of it: byte for byte
// what a backdating forger makes) and sends it only after the removal reached every writer. The
// tie orders it before the removal, so it needs an addendum, and no writer received it by the
// removal's `ts`: it is lost everywhere, whatever the tids (both orders of the tied pair's).
#[test]
fn a_removed_writers_write_forged_at_the_removals_ts_is_lost_everywhere_spec_perm_5_2() {
    for [a, b, c] in [[0, 1, 2], [1, 0, 2]] {
        let mut lp = net(3, 0);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, a);
        let (bob, carol) = (lp.peers[b].engine.tid(), lp.peers[c].engine.tid());
        put(&mut lp, a, t, &REG, &s("v4"));
        lp.peers[a].engine.grant(&t, &bob, &edge(Role::Write)).unwrap();
        lp.peers[a].engine.grant(&t, &carol, &edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(DAY);
        let mut unaware = lp.peers[b].copy().unwrap();
        let rm = lp.peers[a].engine.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None }).unwrap().commits;
        for _ in 0..3 {
            lp.sync_all().unwrap();
        }
        let mut m = Mutation::new();
        m.set(t, &REG, &s("forged")).unwrap();
        let f = unaware.commit(m).unwrap().unwrap();
        let ts = unaware.engine.header(&f).unwrap().ts;
        assert!(rm.iter().all(|r| lp.peers[a].engine.header(r).unwrap().ts == ts), "stamped at the removal's ts");
        let pk = unaware.engine.package(&f).unwrap().unwrap();
        for i in 0..3 {
            unless_refused(lp.deliver(i, &pk));
        }
        for _ in 0..3 {
            lp.sync_all().unwrap();
        }
        for i in 0..3 {
            assert!(lp.peers[i].engine.commit_ids().contains(&f), "peer {i} holds the forged write");
            assert_eq!(lp.peers[i].engine.get_typed(&t, &REG).unwrap(), Some(s("v4")), "Alice {a}, Bob {b}, Carol {c}: peer {i}");
        }
    }
}

// spec/permissions.md §5.1 (drops: falls, security), §5.2 Position: Bob, an admin, is removed; a copy
// of his node from before he learned of it grants Carol admin stamped at exactly the removal's
// `ts`, sent only after the removal reached every node. Ordered before the removal or after it by
// the tids, the grant is no part of the removal's frontier: Carol's role is what Alice gave her at
// every node, whatever the tids (both orders of the tied pair's).
#[test]
fn a_removed_admins_grant_forged_at_the_removals_ts_counts_nowhere_spec_perm_5_1() {
    for [a, b, c] in [[0, 1, 2], [1, 0, 2]] {
        let mut lp = net(3, 0);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, a);
        let (bob, carol) = (lp.peers[b].engine.tid(), lp.peers[c].engine.tid());
        lp.peers[a].engine.grant(&t, &bob, &edge(Role::Admin)).unwrap();
        lp.peers[a].engine.grant(&t, &carol, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(DAY);
        let mut unaware = lp.peers[b].copy().unwrap();
        let rm = lp.peers[a].engine.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None }).unwrap().commits;
        for _ in 0..3 {
            lp.sync_all().unwrap();
        }
        let fs = unaware.engine.grant(&t, &carol, &edge(Role::Admin)).unwrap().commits;
        let f = *fs.last().unwrap();
        let ts = unaware.engine.header(&f).unwrap().ts;
        let at = format!("Alice {a}, Bob {b}, Carol {c}");
        assert!(rm.iter().all(|r| lp.peers[a].engine.header(r).unwrap().ts == ts), "{at}: stamped at the removal's ts");
        for f in &fs {
            let pk = unaware.engine.package(f).unwrap().unwrap();
            for i in 0..3 {
                unless_refused(lp.deliver(i, &pk));
            }
        }
        for _ in 0..3 {
            lp.sync_all().unwrap();
        }
        for i in 0..3 {
            assert!(lp.peers[i].engine.commit_ids().contains(&f), "{at}: peer {i} holds the forged grant");
            assert_eq!(lp.peers[i].engine.roster(&t).get(&carol).map(|e| e.role), Some(Role::Read), "{at}: peer {i}: Carol's role");
            assert_eq!(lp.peers[i].engine.roster(&t).get(&bob), None, "{at}: peer {i}: Bob removed");
        }
    }
}

/// Bob (1), a writer of D and E (minted by Alice, 0), writes both acting as D: the result. D holds
/// no role on E, so no path to E goes through D.
fn acting_on_two() -> osis_engine::Result<Option<osis_base::CommitId>> {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let (d, e) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, e, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("on d")).unwrap();
    m.set(e, &REG, &s("on e")).unwrap();
    m.act_as(d);
    lp.peers[1].commit(m)
}

/// Alice (0) mints D, P and the holder H; Bob (1) holds write on H, H on D, Bob on P directly;
/// Carol (2) reads P alone. Bob's write on D goes through H, on P along the empty path: one
/// write of both states the split form.
/// Built once (`LocalPeer::cached`).
fn two_paths_world() -> (LocalPeer, Tid, Tid, Tid) {
    let (lp, (h, d, p)) = LocalPeer::cached("validity::two_paths_world", || {
        let mut lp = net(3, 0);
        lp.sync_all().unwrap();
        let (h, d, p) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, h, b, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, d, h, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, p, b, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, p, c, Some(edge(Role::Read)), None);
        lp.sync_all().unwrap();
        lp.advance(1_000);
        (lp, (h, d, p))
    });
    (lp, h, d, p)
}

/// Bob's (1) one write of D and P in `two_paths_world`: its ID and opened form.
fn bob_writes_both(lp: &mut LocalPeer, d: Tid, p: Tid) -> (osis_base::CommitId, osis_commit::CommitBlob) {
    let mut m = Mutation::new();
    m.set(d, &REG, &s("on d")).unwrap();
    m.set(p, &REG, &s("on p")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    (id, held(lp, 1, &id))
}

/// `two_paths_world` with Bob's write of both made (`bob_writes_both`): D, P, its ID and opened
/// form. Built once (`LocalPeer::cached`).
fn split_world() -> (LocalPeer, (Tid, Tid, osis_base::CommitId, osis_commit::CommitBlob)) {
    LocalPeer::cached("validity::split_world", || {
        let (mut lp, _, d, p) = two_paths_world();
        let (id, c) = bob_writes_both(&mut lp, d, p);
        (lp, (d, p, id, c))
    })
}

/// Commit `id` as peer `i` holds it, opened.
fn held(lp: &mut LocalPeer, i: usize, id: &osis_base::CommitId) -> osis_commit::CommitBlob {
    osis_commit::CommitBlob::decode(&lp.peers[i].engine.package(id).unwrap().unwrap().bytes).unwrap()
}

/// Where thing `t` is among commit `c`'s things.
fn place(c: &osis_commit::CommitBlob, t: Tid) -> usize {
    c.header.things().iter().position(|x| *x == t).unwrap()
}

/// Split commit `c`'s entries.
fn entries(c: &osis_commit::CommitBlob) -> Vec<Vec<u8>> {
    let osis_commit::Paths::Split(sp) = &c.header.path else { panic!("split") };
    sp.entries.clone()
}

/// The path keys each section of `c` carries as its writer seals it: its own thing's.
fn own(c: &osis_commit::CommitBlob) -> impl Fn(usize) -> BTreeMap<usize, [u8; 32]> + Copy + '_ {
    |i| BTreeMap::from([(i, c.keys[&i])])
}

/// An entry of `n` bytes that opens under no key.
fn junk(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 37 % 251) as u8).collect()
}

/// Each thing's path as commit `c` states it: read off its one path, or its entry opened.
fn paths_stated(c: &osis_commit::CommitBlob) -> Vec<(Tid, Vec<Tid>)> {
    c.header.things().into_iter().map(|t| match c.path(&t) {
        Some(osis_commit::ThingPath::Known(p)) => (t, p.to(&t).to_vec()),
        x => panic!("{t:?}: {x:?}"),
    }).collect()
}

// A write is never refused or split for its paths (notes/path-form.md; a1-spec Open 17), spec/wire.md §4 `Split`: a write of things
// its signer reaches through different actors is one commit, never refused or split: Bob writes D
// through H and P directly, and the commit states each thing's own path, sealed. Alice reads both;
// Carol, who opens P's section alone, reads P as Alice does; every node's index is its store's.
#[test]
fn a_write_through_different_actors_is_one_split_commit_spec_wire_4() {
    let (mut lp, h, d, p) = two_paths_world();
    let (id, c) = bob_writes_both(&mut lp, d, p);
    assert!(c.header.is_split(), "{:?}", c.header.path);
    assert_eq!(c.header.purge_author(), lp.peers[1].engine.tid());
    let mut want = vec![(d, vec![h]), (p, vec![])];
    want.sort();
    let mut got = paths_stated(&c);
    got.sort();
    assert_eq!(got, want, "each thing's own path");
    lp.sync_all().unwrap();
    for i in 0..3 {
        let e = &mut lp.peers[i].engine;
        assert!(e.commit_ids().contains(&id), "peer {i} holds it");
        assert_eq!(e.get(&p, &ak("t:reg.0")).unwrap(), Some(s("on p")), "peer {i} reads P");
        e.check_index();
    }
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("on d")), "Alice reads D");
}

// spec/wire.md §4 `Split`, `PathKey`; notes/path-form.md Per consumer: a node judges a split
// commit's thing by the path key an encryption of its parts carried or by the roles secret it
// holds, so it ends where the whole commit takes it however the parts come (whole, header first,
// one thing's copy before the other's), its live index what its store loads.
#[test]
fn split_paths_judge_alike_however_parts_come_spec_wire_4() {
    let (_, (d, p, id, c)) = split_world();
    assert!(c.header.is_split());
    let only = |keep: Option<Tid>| osis_commit::rewrite(&c, |ai| Some(c.header.aspects[ai].tid) != keep).encode();
    for (name, order) in [("whole", vec![c.encode()]), ("header, p, d", vec![only(None), only(Some(p)), only(Some(d))]), ("header, d, p", vec![only(None), only(Some(d)), only(Some(p))]), ("p, d", vec![only(Some(p)), only(Some(d))])] {
        let (mut lp, _) = split_world();
        let a = &mut lp.peers[0];
        for b in &order {
            unless_refused(a.engine.ingest(b, Vec::new()));
            a.reexamine().unwrap();
            a.engine.check_index();
        }
        assert!(a.engine.commit_ids().contains(&id), "{name}");
        assert_eq!(a.engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("on d")), "{name}");
        assert_eq!(a.engine.get(&p, &ak("t:reg.0")).unwrap(), Some(s("on p")), "{name}");
    }
}

// spec/wire.md §4 `PathKey` (an encryption carries the path keys of its parts' things and no other),
// spec/sync-judgement.md §1: Bob's split commit sealed as sync IDs carry it (`Engine::seal_package`,
// a section per thing under its read secret), not handed over opened. Carol, reading P alone and
// holding no secret of D, opens P's section: she holds P's path key alone and judges P from it,
// while D's path opens nowhere at her and waits; Alice opens both sections and decides both.
#[test]
fn a_sealed_split_commit_gives_each_reader_its_own_things_keys_spec_wire_4() {
    let (mut lp, (d, p, id, _)) = split_world();
    let pks = lp.sealed(1, &[id]).unwrap();
    assert_eq!(pks.len(), 1);
    for i in [2, 0] {
        assert!(lp.deliver_sealed(i, &pks).unwrap().is_empty(), "peer {i} opened a section");
    }
    let stated = |lp: &mut LocalPeer, i: usize| {
        let c = held(lp, i, &id);
        let e = &mut lp.peers[i].engine;
        let things = c.header.things();
        let keys: Vec<Tid> = c.keys.keys().map(|i| things[*i]).collect();
        let paths = e.core.ix.commits.get(&id).unwrap().view.paths.clone().unwrap();
        (keys, paths.get(&d).map(Option::is_some), paths.get(&p).map(Option::is_some), e.core.ix.paths_unknown.contains(&id))
    };
    assert_eq!(stated(&mut lp, 2), (vec![p], None, Some(true), true), "Carol: P's key alone, D waits");
    assert_eq!(lp.peers[2].engine.get(&p, &ak("t:reg.0")).unwrap(), Some(s("on p")));
    let alice = stated(&mut lp, 0);
    assert_eq!((alice.1, alice.2, alice.3), (Some(true), Some(true), false), "Alice decides both");
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("on d")));
    for i in [0, 2] {
        lp.peers[i].engine.check_index();
    }
}

/// Bob's (1) split commit `c` with `entries` and purge author `author`, signed again: its header
/// and signatures (no part).
fn resigned(lp: &mut LocalPeer, c: &osis_commit::CommitBlob, entries: Vec<Vec<u8>>, author: Option<Tid>) -> osis_commit::CommitBlob {
    resigned_with(lp, c, osis_commit::Paths::Split(osis_commit::Split { author, entries }))
}

/// Bob's (1) commit `c` stating `path`, signed again: its header and signatures (no part).
fn resigned_with(lp: &mut LocalPeer, c: &osis_commit::CommitBlob, path: osis_commit::Paths) -> osis_commit::CommitBlob {
    let mut h = c.header.clone();
    h.path = path;
    let key = lp.peers[1].engine.identity().signing().clone();
    let id = h.id();
    let sigs = osis_commit::Sigs::signed(&id, &key);
    osis_commit::CommitBlob { header: h, sigs, parts: Vec::new(), keys: BTreeMap::new() }
}

/// What a reader opening the sections of `f` (signed header) that hold `c`'s parts on the things
/// at `places` gets (`Envelope::open`, the commit crate's opening): each such section carrying
/// the path keys `keys(place)` names.
fn opened_sections(f: &osis_commit::CommitBlob, c: &osis_commit::CommitBlob, places: &[usize], keys: &dyn Fn(usize) -> BTreeMap<usize, [u8; 32]>) -> Vec<u8> {
    let things = c.header.things();
    let secret = osis_crypto::Secret32::from_bytes([9; 32]);
    let id = f.header.id();
    let mut rng = osis_crypto::SeededRng::from_u64(0);
    let mut sections: Vec<osis_commit::Section> = places
        .iter()
        .map(|i| {
            let ps: Vec<&osis_commit::Part> = c.parts.iter().filter(|p| c.header.aspects[p.ai].tid == things[*i]).collect();
            osis_commit::Section::seal(&id, &ps, Some(&keys(*i)), Vec::new(), &secret, &mut rng).unwrap()
        })
        .collect();
    sections.sort_by_key(|s| s.ais.first().copied());
    let env = osis_commit::Envelope { header: f.header.clone(), sigs: f.sigs.clone(), sections };
    env.open(|_| vec![secret.clone()]).unwrap().commit.encode()
}

// spec/wire.md §4 `Split` (an entry that is no padded list, breaks `Path`'s rules or leaves out the
// purge author leaves its thing's parts holding nothing at every reader of it; a section carrying a
// key its entry does not commit to, or a key beyond its parts' things, holds nothing), spec/commits.md
// §4 Hostile input: Bob's split commit writing D (through H) and P, forged and signed again. Each
// forgery harms only the things it forges, alike at every reader of them whatever sections each
// opened and in whatever order: Alice (reads D and P) takes both sections at once, P's then D's, or
// D's then P's; Carol (reads P) takes P's. An entry under a key of the writer's own, carried by
// the thing's section, opens for every reader of that section (what a writer holding no roles
// secret seals, `engine::write::path_secret`).
#[test]
fn hostile_split_commits_harm_only_their_forged_things_alike_everywhere_spec_wire_4() {
    let (mut lp, (d, p, _, c)) = split_world();
    let h = *paths_stated(&c).iter().find(|(t, _)| *t == d).unwrap().1.first().unwrap();
    let bob = lp.peers[1].engine.tid();
    let (id_, ip, es) = (place(&c, d), place(&c, p), entries(&c));
    let own = own(&c);
    let mine = [7u8; 32];
    let with = |i: usize, e: Vec<u8>| {
        let mut es = es.clone();
        es[i] = e;
        es
    };
    let mut swapped = es.clone();
    swapped.swap(0, 1);
    type Keys<'a> = Box<dyn Fn(usize) -> BTreeMap<usize, [u8; 32]> + 'a>;
    // (name, entries, author, the keys each section carries, D applies, P applies)
    type Case<'a> = (&'a str, Vec<Vec<u8>>, Option<Tid>, Keys<'a>, bool, bool);
    let cases: Vec<Case<'_>> = vec![
        ("honest", es.clone(), None, Box::new(own), true, true),
        ("a forged entry", with(id_, junk(es[id_].len())), None, Box::new(own), false, true),
        ("an entry under another key", with(id_, osis_commit::Split::seal(&mine, &[h], 0).unwrap()), None, Box::new(own), false, true),
        ("an entry under the writer's own key, carried", with(id_, osis_commit::Split::seal(&mine, &[h], 0).unwrap()), None, Box::new(|i| if i == id_ { BTreeMap::from([(i, mine)]) } else { own(i) }), true, true),
        ("entries swapped", swapped, None, Box::new(own), false, false),
        ("a list naming the signer", with(id_, osis_commit::Split::seal(&c.keys[&id_], &[bob], 0).unwrap()), None, Box::new(own), false, true),
        ("a purge author off P's path", es.clone(), Some(h), Box::new(own), true, false),
        ("a key beyond P's section's things", es.clone(), None, Box::new(|i| if i == ip { c.keys.clone() } else { own(i) }), true, false),
    ];
    let reg = |lp: &mut LocalPeer, i: usize, t: Tid| lp.peers[i].engine.get(&t, &ak("t:reg.0")).unwrap();
    for (name, entries, author, keys, d_ok, p_ok) in cases {
        let f = resigned(&mut lp, &c, entries, author);
        for (order, deliveries) in [("both", vec![vec![id_, ip]]), ("p, d", vec![vec![ip], vec![id_]]), ("d, p", vec![vec![id_], vec![ip]])] {
            let (mut w, _) = split_world();
            let before = (reg(&mut w, 0, d), reg(&mut w, 0, p));
            for places in &deliveries {
                unless_refused(w.peers[0].engine.ingest(&opened_sections(&f, &c, places, &*keys), Vec::new()));
                w.peers[0].reexamine().unwrap();
            }
            unless_refused(w.peers[2].engine.ingest(&opened_sections(&f, &c, &[ip], &*keys), Vec::new()));
            w.peers[2].reexamine().unwrap();
            let at = format!("{name}, {order}");
            assert_eq!(reg(&mut w, 0, d), if d_ok { Some(s("on d")) } else { before.0.clone() }, "{at}: Alice's D");
            assert_eq!(reg(&mut w, 0, p), if p_ok { Some(s("on p")) } else { before.1.clone() }, "{at}: Alice's P");
            assert_eq!(reg(&mut w, 2, p), reg(&mut w, 0, p), "{at}: Carol's P is Alice's");
            for i in [0, 2] {
                w.peers[i].engine.check_index();
            }
        }
    }
}

/// Arithmetic modulo 2^130 − 5, Poly1305's field: little-endian 64-bit limbs.
mod p1305 {
    pub type N = [u64; 3];
    pub const P: N = [0xffff_ffff_ffff_fffb, u64::MAX, 3];

    fn ge(a: &N, b: &N) -> bool {
        (0..3).rev().find(|i| a[*i] != b[*i]).is_none_or(|i| a[i] > b[i])
    }

    fn sub_raw(a: &N, b: &N) -> N {
        let mut out = [0u64; 3];
        let mut borrow = false;
        for i in 0..3 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            out[i] = d2;
            borrow = b1 || b2;
        }
        out
    }

    fn reduce(mut x: [u64; 6]) -> N {
        loop {
            let h = [(x[2] >> 2) | (x[3] << 62), (x[3] >> 2) | (x[4] << 62), (x[4] >> 2) | (x[5] << 62), x[5] >> 2];
            if h == [0; 4] {
                break;
            }
            let l = [x[0], x[1], x[2] & 3];
            let mut carry = 0u128;
            for (i, xi) in x.iter_mut().enumerate() {
                let v = u128::from(l.get(i).copied().unwrap_or(0)) + 5 * u128::from(h.get(i).copied().unwrap_or(0)) + carry;
                *xi = v as u64;
                carry = v >> 64;
            }
        }
        let mut r = [x[0], x[1], x[2]];
        while ge(&r, &P) {
            r = sub_raw(&r, &P);
        }
        r
    }

    pub fn add(a: &N, b: &N) -> N {
        let mut out = [0u64; 6];
        let mut carry = 0u128;
        for i in 0..3 {
            let v = u128::from(a[i]) + u128::from(b[i]) + carry;
            out[i] = v as u64;
            carry = v >> 64;
        }
        out[3] = carry as u64;
        reduce(out)
    }

    pub fn sub(a: &N, b: &N) -> N {
        add(a, &sub_raw(&P, &reduce([b[0], b[1], b[2], 0, 0, 0])))
    }

    pub fn mul(a: &N, b: &N) -> N {
        let mut o = [0u64; 6];
        for i in 0..3 {
            let mut carry = 0u128;
            for j in 0..3 {
                let v = u128::from(o[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
                o[i + j] = v as u64;
                carry = v >> 64;
            }
            o[i + 3] = carry as u64;
        }
        reduce(o)
    }

    pub fn pow(a: &N, e: &N) -> N {
        let mut out: N = [1, 0, 0];
        for bit in (0..192).rev() {
            out = mul(&out, &out);
            if e[bit / 64] >> (bit % 64) & 1 == 1 {
                out = mul(&out, a);
            }
        }
        out
    }

    pub fn inv(a: &N) -> N {
        pow(a, &sub_raw(&P, &[2, 0, 0]))
    }

    /// A 16-byte little-endian block, with `top` the bit above it (Poly1305's 2^128).
    pub fn block(b: &[u8], top: u64) -> N {
        let w = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        [w(0), w(8), top]
    }
}

/// Poly1305's `r` (clamped) and `s` from keystream `ks`'s one-time key.
fn r_s(ks: &osis_crypto::aead::Keystream) -> (p1305::N, u128) {
    let pk = ks.poly_key();
    let mut r = pk;
    for i in [3, 7, 11, 15] {
        r[i] &= 15;
    }
    for i in [4, 8, 12] {
        r[i] &= 252;
    }
    (p1305::block(&r[..16], 0), u128::from_le_bytes(pk[16..].try_into().unwrap()))
}

/// A split entry of class 4 committing to `k1` whose ciphertext opens under both `k1` and `k2`:
/// XChaCha20-Poly1305 commits to no key, so whoever picks both keys solves one linear equation
/// over Poly1305's field for one ciphertext block. Under `k1` it opens to a canonical list of four
/// tids (a path of well-formed shape, purge author the signer); under `k2` to bytes that are no
/// list. Its commitment (spec/crypto.md §5 Path entry) names `k1` alone.
fn entry_under_two_keys(k1: &[u8; 32], k2: &[u8; 32]) -> Vec<u8> {
    use osis_crypto::aead::{Keystream, ZERO_NONCE, open};
    use p1305::*;
    let (ks1, ks2) = (Keystream::new(k1, &ZERO_NONCE), Keystream::new(k2, &ZERO_NONCE));
    let ((r1, s1), (r2, s2)) = (r_s(&ks1), r_s(&ks2));
    // the MAC's blocks: the class's 67-byte ciphertext (four tids and two zero bytes of padding)
    // padded to five, then the lengths (no AD)
    const LEN: usize = 67;
    let mut lens = [0u8; 16];
    lens[8..].copy_from_slice(&(LEN as u64).to_le_bytes());
    let coef = |r: &N, i: usize| pow(r, &[6 - i as u64, 0, 0]);
    let mac = |r: &N, s: u128, ct: &[u8; 80]| {
        let acc = (0..5).map(|i| block(&ct[16 * i..16 * i + 16], 1)).chain([block(&lens, 1)]).enumerate().fold([0, 0, 0], |acc, (i, m)| add(&acc, &mul(&m, &coef(r, i))));
        (u128::from(acc[0]) | (u128::from(acc[1]) << 64)).wrapping_add(s)
    };
    // block 2 (bytes 32..47) solved for; its byte 1 is a tid's head (0x4f) under `k1`
    let c_inv = inv(&sub(&coef(&r1, 2), &coef(&r2, 2)));
    for n in 0u64..1_000_000 {
        let mut pt = vec![0x84u8];
        for j in 0..4u64 {
            pt.push(0x4f);
            pt.extend_from_slice(&osis_base::hash::hash(&(4 * n + j).to_le_bytes())[..15]);
        }
        pt.resize(LEN, 0);
        let mut ct = [0u8; 80];
        for i in 0..LEN {
            ct[i] = pt[i] ^ ks1.byte(i);
        }
        let rest = |r: &N| (0..6).filter(|i| *i != 2).map(|i| if i < 5 { (i, block(&ct[16 * i..16 * i + 16], 1)) } else { (i, block(&lens, 1)) }).fold([0, 0, 0], |acc, (i, m)| add(&acc, &mul(&m, &coef(r, i))));
        let base = sub(&rest(&r1), &rest(&r2));
        let ds = s2.wrapping_sub(s1);
        for k in 0..4u64 {
            let want = [ds as u64, (ds >> 64) as u64, k];
            let m = mul(&sub(&want, &base), &c_inv);
            if m[2] != 1 || (m[0] >> 8) as u8 != 0x4f ^ ks1.byte(33) {
                continue;
            }
            ct[32..40].copy_from_slice(&m[0].to_le_bytes());
            ct[40..48].copy_from_slice(&m[1].to_le_bytes());
            let tag = mac(&r1, s1, &ct);
            if tag != mac(&r2, s2, &ct) {
                continue;
            }
            let mut entry = ct[..LEN].to_vec();
            entry.extend_from_slice(&tag.to_le_bytes());
            assert!(open(k1, &ZERO_NONCE, &[], &entry).is_ok() && open(k2, &ZERO_NONCE, &[], &entry).is_ok());
            return [osis_commit::key_commitment(k1).to_vec(), entry].concat();
        }
    }
    panic!("no entry opening under both keys");
}

// spec/wire.md §4 `Split` (a reader opens a thing's entry with the path key an encryption of its
// parts carries; an encryption carrying a key its entry does not commit to holds nothing),
// spec/crypto.md §5 Path entry, spec/commits.md §4: a thing's path is one fact of the commit, read
// alike by every reader in any order. XChaCha20-Poly1305 commits to no key, so Bob seals D's entry
// to open under two keys of his choosing (a path under `k1`, no list under `k2`; the entry commits
// to `k1`), and seals D's parts twice: `one` holds D's parts carrying `k1`; `other` D's parts
// carrying `k2` and P's. Alice takes both in either order, or one alone. `k2` is no key of the
// entry, so `other`'s D section holds nothing, wherever it comes: P's write applies wherever
// `other` is held, and `k2` never stands for D's key. Wherever `one` is held its part on D waits
// with `k1` (D's write, stated along the made-up path `k1` opens, cannot be judged and applies
// nowhere; with `one` alone the commit pends whole), and the applied commit keeps no key for D and
// leaves D's path unopened, in either order, before and after a reopen. Without the commitment,
// `other` after `one` would replace D's key (one key per (commit, thing)).
#[test]
fn an_entry_opening_under_two_keys_judges_alike_in_any_order_spec_wire_4() {
    let (mut lp, (d, p, _, c)) = split_world();
    let (id_, ip, mut es) = (place(&c, d), place(&c, p), entries(&c));
    let (k1, k2) = ([11u8; 32], [22u8; 32]);
    es[id_] = entry_under_two_keys(&k1, &k2);
    let f = resigned(&mut lp, &c, es, None);
    assert!(matches!(f.header.open_path(id_, &k1), Some(osis_commit::ThingPath::Known(_))), "a path under one key");
    assert_eq!(f.header.open_path(id_, &k2), None, "the other is no key of the entry");
    assert!(osis_crypto::aead::open(&k2, &osis_crypto::aead::ZERO_NONCE, &[], &entries(&f)[id_][osis_commit::COMMITMENT_LEN..]).is_ok(), "though the ciphertext opens under it");
    let under = |k: [u8; 32], places: &[usize]| opened_sections(&f, &c, places, &|i| BTreeMap::from([(i, if i == id_ { k } else { c.keys[&i] })]));
    let (one, other) = (under(k1, &[id_]), under(k2, &[id_, ip]));
    let reg = |w: &mut LocalPeer, t: Tid| w.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap();
    let id = f.header.id();
    for order in [vec![&one, &other], vec![&other, &one], vec![&one], vec![&other]] {
        let (mut w, _) = split_world();
        let before = (reg(&mut w, d), reg(&mut w, p));
        for b in &order {
            unless_refused(w.peers[0].engine.ingest(b, Vec::new()));
            w.peers[0].reexamine().unwrap();
            w.peers[0].engine.check_index();
        }
        let at = format!("Alice holding {} encryption(s), the first {}", order.len(), if order[0] == &one { "one" } else { "the other" });
        for reopened in [false, true] {
            if reopened {
                crate::flows::reopen(&mut w, 0).unwrap();
            }
            // `k1` is kept with D's waiting part alone, whichever came first; `k2` opens nothing
            let e = &mut w.peers[0].engine;
            let opened = e.core.ix.commits.get(&id).and_then(|m| m.view.paths.clone()).and_then(|p| p.get(&d).cloned());
            let on_d = f.header.aspects.iter().position(|a| a.tid == d).unwrap();
            let waits = e.pending_parts(&id).unwrap().is_some_and(|p| p.contains(&on_d));
            assert_eq!(opened, None, "{at}: D's path ({reopened})");
            assert_eq!(waits, order.contains(&&one), "{at}: D's part waits ({reopened})");
            if order.contains(&&other) {
                assert_eq!(held(&mut w, 0, &id).keys.get(&id_), None, "{at}: D's key in the applied commit ({reopened})");
            }
            // spec/permissions.md §1 Path, spec/commits.md §4 Unjudgeable: under `k1` the entry
            // states a path of four made-up things, no edge of which a held write set, so D's
            // write cannot be judged and applies in no order; which key opens the entry is what
            // the orders must agree on
            assert_eq!(reg(&mut w, d), before.0.clone(), "{at}: D ({reopened})");
            assert_eq!(reg(&mut w, p), if order.contains(&&other) { Some(s("on p")) } else { before.1.clone() }, "{at}: P ({reopened})");
        }
    }
}

// spec/wire.md §4 `Split` (a reader opens a thing's entry with the path key an encryption of its
// parts carries, else with the read roles secrets it holds; a thing whose entry opens nowhere at a
// node is judged there only once it opens), spec/crypto.md §5 Path entry (a reader accepts only
// the key the entry commits to): the roles-secret route. Bob's entry for D commits to a key of his
// own, `mine`, its ciphertext also opening (to no list) under the key Alice derives from D's roles
// secret. Holding P's section alone, Alice tries her roles secret: it is no key of D's entry, so
// D's path waits (undecided, the commit in `paths_unknown`), as it does where D's section carries
// a key the entry does not commit to; once D's section carrying `mine` comes, D's part is held,
// its path opened (made-up things, so it waits unjudged). Every durable step checks that no waiting entry opens to a fresh attempt
// (debug builds, `apply::paths::missed`).
#[test]
fn a_roles_secret_opens_an_entry_only_as_its_committed_key_spec_wire_4() {
    let (mut lp, (d, p, _, c)) = split_world();
    let (id_, ip, mut es) = (place(&c, d), place(&c, p), entries(&c));
    let (mine, roles) = ([33u8; 32], c.keys[&id_]);
    es[id_] = entry_under_two_keys(&mine, &roles);
    let f = resigned(&mut lp, &c, es, None);
    assert_eq!(f.header.open_path(id_, &roles), None, "the roles secret's key is no key of D's entry");
    let id = f.header.id();
    let ck = &c.keys;
    let keyed = |k: [u8; 32]| move |i: usize| BTreeMap::from([(i, if i == id_ { k } else { ck[&i] })]);
    let on_d = f.header.aspects.iter().position(|a| a.tid == d).unwrap();
    // whether D's part is held (waiting), and D's register
    let state = |w: &mut LocalPeer| {
        let e = &mut w.peers[0].engine;
        (e.pending_parts(&id).unwrap().is_some_and(|p| p.contains(&on_d)), e.get(&d, &ak("t:reg.0")).unwrap())
    };
    for (name, first) in [("P's section alone", opened_sections(&f, &c, &[ip], &keyed(mine))), ("D's section carrying the roles key", opened_sections(&f, &c, &[id_, ip], &keyed(roles)))] {
        let (mut w, _) = split_world();
        let before = w.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap();
        unless_refused(w.peers[0].engine.ingest(&first, Vec::new()));
        w.peers[0].reexamine().unwrap();
        w.peers[0].engine.check_index();
        assert_eq!(state(&mut w), (false, before.clone()), "{name}: nothing of D is held");
        assert!(w.peers[0].engine.core.ix.paths_unknown.contains(&id), "{name}: D's entry opens nowhere");
        assert_eq!(w.peers[0].engine.get(&p, &ak("t:reg.0")).unwrap(), Some(s("on p")), "{name}: P applies");
        unless_refused(w.peers[0].engine.ingest(&opened_sections(&f, &c, &[id_], &keyed(mine)), Vec::new()));
        w.peers[0].reexamine().unwrap();
        w.peers[0].engine.check_index();
        // spec/permissions.md §1 Path, spec/commits.md §4 Unjudgeable: the committed key opens
        // the entry to a path of four made-up things, no edge of which a held write set: D's
        // part is held, waiting unjudged, and its write stays out
        assert_eq!(state(&mut w), (true, before), "{name}, then D's section carrying the committed key");
    }
}

/// A section wrap (spec/wire.md §4: nonce, then the section key sealed under `kdf("section", read
/// secret)`, AD the commit ID) that opens under both `e1` and `e2`: under `e1` to the returned
/// section key, under `e2` to another. XChaCha20-Poly1305 commits to no key, and the section key
/// is the writer's free choice, so one Poly1305 equation solved for its second block does it.
fn section_wrap_under_two_secrets(e1: &osis_crypto::Secret32, e2: &osis_crypto::Secret32, id: &osis_base::CommitId) -> (Vec<u8>, [u8; 32]) {
    use osis_crypto::aead::{Keystream, open};
    use p1305::*;
    let wk = |e: &osis_crypto::Secret32| *osis_crypto::kdf::kdf(osis_crypto::kdf::SECTION, e.expose(), b"").expose();
    let (w1, w2) = (wk(e1), wk(e2));
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&32u64.to_le_bytes());
    lens[8..].copy_from_slice(&32u64.to_le_bytes());
    for n in 0u64..1_000 {
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&osis_base::hash::hash(&n.to_le_bytes())[..24]);
        let (ks1, ks2) = (Keystream::new(&w1, &nonce), Keystream::new(&w2, &nonce));
        let ((r1, s1), (r2, s2)) = (r_s(&ks1), r_s(&ks2));
        // the MAC's blocks: AD (two), ciphertext (two), lengths; ciphertext block 1 solved for
        let coef = |r: &N, i: usize| pow(r, &[5 - i as u64, 0, 0]);
        let ct0: [u8; 16] = osis_base::hash::hash(&(n + 1_000_000).to_le_bytes())[..16].try_into().unwrap();
        let fixed = [(0, block(&id.0[..16], 1)), (1, block(&id.0[16..], 1)), (2, block(&ct0, 1)), (4, block(&lens, 1))];
        let rest = |r: &N| fixed.iter().fold([0, 0, 0], |acc, (i, m)| add(&acc, &mul(m, &coef(r, *i))));
        let base = sub(&rest(&r1), &rest(&r2));
        let c_inv = inv(&sub(&coef(&r1, 3), &coef(&r2, 3)));
        let ds = s2.wrapping_sub(s1);
        for k in 0..4u64 {
            let m = mul(&sub(&[ds as u64, (ds >> 64) as u64, k], &base), &c_inv);
            if m[2] != 1 {
                continue;
            }
            let mut sealed = ct0.to_vec();
            sealed.extend_from_slice(&m[0].to_le_bytes());
            sealed.extend_from_slice(&m[1].to_le_bytes());
            let tag = |r: &N, s: u128| {
                let mut ms = fixed.to_vec();
                ms.push((3, block(&sealed[16..32], 1)));
                let acc = ms.iter().fold([0, 0, 0], |acc, (i, b)| add(&acc, &mul(b, &coef(r, *i))));
                (u128::from(acc[0]) | (u128::from(acc[1]) << 64)).wrapping_add(s)
            };
            if tag(&r1, s1) != tag(&r2, s2) {
                continue;
            }
            sealed.extend_from_slice(&tag(&r1, s1).to_le_bytes());
            let (Ok(k1), Ok(k2)) = (open(&w1, &nonce, &id.0, &sealed), open(&w2, &nonce, &id.0, &sealed)) else { continue };
            assert_ne!(k1, k2);
            return ([nonce.to_vec(), sealed].concat(), k1.try_into().unwrap());
        }
    }
    panic!("no section wrap opening under both secrets");
}

// spec/wire.md §4 (taking the first whose wrap gives a key that opens the ciphertext),
// spec/crypto.md §5 Section, spec/commits.md §4 (No local error from peer bytes: judged a
// function of the held set, never of the order secrets are tried in): a section wrap commits to
// no key, so Bob seals D's section under a wrap that opens to its key under D's
// epoch e1 and to another key under e2. A reader holding e1 alone, e2 and e1 (tried newest first),
// or e1 and e2, reads D's parts alike; one holding e2 alone, whose key opens nothing, reads the
// encryption as bad input, as any section a held secret unwraps to a key opening nothing.
#[test]
fn a_section_wrap_opening_under_two_epochs_reads_alike_spec_wire_4() {
    let (_, (d, _, _, c)) = split_world();
    let id = c.id();
    let i = place(&c, d);
    let (e1, e2) = (osis_crypto::Secret32::from_bytes([0xe1; 32]), osis_crypto::Secret32::from_bytes([0xe2; 32]));
    // D's section as the writer seals it, its contents taken and sealed again under the solved key
    let ps: Vec<&osis_commit::Part> = c.parts.iter().filter(|p| c.header.aspects[p.ai].tid == d).collect();
    let honest = osis_commit::Section::seal(&id, &ps, Some(&own(&c)(i)), Vec::new(), &e1, &mut osis_crypto::SeededRng::from_u64(0)).unwrap();
    let sk = osis_crypto::unwrap_section(&e1, &id, &honest.wrap).unwrap();
    let contents = osis_crypto::open_section(&id, &sk, &honest.ciphertext).unwrap();
    let (wrap, k1) = section_wrap_under_two_secrets(&e1, &e2, &id);
    let ciphertext = osis_crypto::aead::seal(&k1, &osis_crypto::aead::ZERO_NONCE, &id.0, &contents).unwrap();
    let k2 = osis_crypto::unwrap_section(&e2, &id, &wrap).unwrap();
    assert!(osis_crypto::open_section(&id, &k2, &ciphertext).is_err(), "e2's key opens nothing");
    let env = osis_commit::Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections: vec![osis_commit::Section { ciphertext, wrap, ..honest }] };
    let theirs = |o: &osis_commit::CommitBlob| o.parts.iter().filter(|p| c.header.aspects[p.ai].tid == d).count();
    for (held, name) in [(vec![e1.clone()], "e1"), (vec![e2.clone(), e1.clone()], "e2 then e1"), (vec![e1.clone(), e2.clone()], "e1 then e2")] {
        let o = env.open(|_| held.clone()).unwrap_or_else(|e| panic!("{name}: {e:?}")).commit;
        assert_eq!((theirs(&o), o.keys.get(&i)), (ps.len(), Some(&c.keys[&i])), "{name}: D's parts and path key");
        assert!(matches!(o.path(&d), Some(osis_commit::ThingPath::Known(_))), "{name}");
    }
    assert!(env.open(|_| vec![e2.clone()]).is_err(), "e2 alone: bad input");
}

// notes/path-form.md, Whom a write is by (a commit's one purge author is a member of each thing's stated path), spec/wire.md §4:
// a hand-built purge author acts no wider than the stated paths allow, in either path form. Bob (writer of H, H of D, Bob
// of P) restates his writes: clear, naming H (accepted), a thing Q he holds nothing on (invalid),
// an index past its things (refused), a made-up thing (waits for its record, never applies), H then
// Q naming Q; split, naming H (D's entry lists H: D applies; P's members leave H out: P holds
// nothing), Q listed on D's entry (invalid), a made-up author (never applies). Each reader ends as
// its stated paths give.
#[test]
fn a_stated_purge_author_acts_no_wider_than_its_stated_paths_spec_permissions_5_2() {
    use osis_commit::{Path, Paths, Split};
    let (mut lp, h, d, p) = two_paths_world();
    let q = new_thing(&mut lp, 0);
    let made_up = Tid::from_bytes([77; 15]);
    lp.sync_all().unwrap();
    // Bob's write of D alone (one path, `[H]`) and of D and P (split)
    let one_id = put(&mut lp, 1, d, &REG, &s("forged d"));
    let one = held(&mut lp, 1, &one_id);
    let (_, both) = bob_writes_both(&mut lp, d, p);
    let (id_, es) = (place(&both, d), entries(&both));
    let with_d = |listed: &[Tid]| {
        let mut es = es.clone();
        es[id_] = Split::seal(&both.keys[&id_], listed, 0).unwrap();
        es
    };
    let clear = |purge: usize, things: Vec<Tid>| Paths::One(Path { purge, things, direct: 0 });
    // (name, base commit, path, D applies, P applies)
    let cases: Vec<(&str, &osis_commit::CommitBlob, Paths, bool, bool)> = vec![
        ("clear, naming H", &one, clear(1, vec![h]), true, false),
        ("clear, naming Q", &one, clear(1, vec![q]), false, false),
        ("clear, an index past its things", &one, clear(2, vec![h]), false, false),
        ("clear, naming a made-up thing", &one, clear(1, vec![made_up]), false, false),
        ("clear, H then Q, naming Q", &one, clear(2, vec![h, q]), false, false),
        ("split, naming H", &both, Paths::Split(Split { author: Some(h), entries: es.clone() }), true, false),
        ("split, naming Q listed on D's entry", &both, Paths::Split(Split { author: Some(q), entries: with_d(&[q]) }), false, false),
        ("split, naming a made-up thing listed on D's entry", &both, Paths::Split(Split { author: Some(made_up), entries: with_d(&[made_up]) }), false, false),
    ];
    for (name, base, path, d_ok, p_ok) in cases {
        let mut w = lp.copy().unwrap();
        let before = (w.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), w.peers[0].engine.get(&p, &ak("t:reg.0")).unwrap());
        let f = resigned_with(&mut w, base, path);
        let all: Vec<usize> = (0..base.header.things().len()).collect();
        let bytes = if base.header.is_split() { opened_sections(&f, base, &all, &|i| BTreeMap::from([(i, base.keys[&i])])) } else { osis_commit::CommitBlob { parts: base.parts.clone(), ..f }.encode() };
        for i in [0, 2] {
            unless_refused(w.peers[i].engine.ingest(&bytes, Vec::new()));
            w.peers[i].reexamine().unwrap();
        }
        let want_d = if d_ok { Some(s(if base.header.is_split() { "on d" } else { "forged d" })) } else { before.0.clone() };
        assert_eq!(w.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), want_d, "{name}: D");
        assert_eq!(w.peers[0].engine.get(&p, &ak("t:reg.0")).unwrap(), if p_ok { Some(s("on p")) } else { before.1.clone() }, "{name}: P");
        assert_eq!(w.peers[2].engine.get(&p, &ak("t:reg.0")).unwrap(), w.peers[0].engine.get(&p, &ak("t:reg.0")).unwrap(), "{name}: Carol's P");
        for i in [0, 2] {
            w.peers[i].engine.check_index();
        }
    }
}

// spec/wire.md §4 `Split` (an entry that opens nowhere leaves its thing's parts holding nothing),
// spec/commits.md §5 (a thing is known by its creation record): Bob makes X with admin D beside a write of P,
// X's entry forged. Alice, holding every section, holds no minting of X (X's section, its key
// opening nothing, holds nothing): X is unknown there, nothing on it applies; D's strong to X and
// P's write stand, as any write naming a thing never made.
#[test]
fn a_creation_under_a_forged_entry_makes_nothing_spec_wire_4() {
    let (mut lp, _, d, p) = two_paths_world();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, d);
    m.set(x, &REG, &s("made")).unwrap();
    m.set(p, &REG, &s("beside")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let c = held(&mut lp, 1, &id);
    let (ix, mut es) = (place(&c, x), entries(&c));
    es[ix] = junk(es[ix].len());
    let f = resigned(&mut lp, &c, es, None);
    let all: Vec<usize> = (0..c.header.things().len()).collect();
    unless_refused(lp.peers[0].engine.ingest(&opened_sections(&f, &c, &all, &own(&c)), Vec::new()));
    lp.peers[0].reexamine().unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(!e.knows(&x), "no minting of X");
    assert_eq!(e.get(&x, &ak("t:reg.0")).unwrap(), None);
    assert_eq!(e.get(&p, &ak("t:reg.0")).unwrap(), Some(s("beside")), "P's write stands");
    let held = e.get(&d, &ak("holds.0")).unwrap();
    assert!(matches!(&held, Some(Value::Set(h)) if h.contains(&Value::Strong(x))), "D's strong to X stands: {held:?}");
    e.check_index();
}

// spec/wire.md §4 `Split` (a path is header data), spec/commits.md §5 Purge: what a node decided of
// a split commit's paths outlives the parts that brought the keys. Alice holds Bob's split commit
// whole and purges his part on P; P's path stays known, live and after a reopen, and D's write
// stands.
#[test]
fn a_split_commits_path_outlives_its_parts_spec_wire_4() {
    let (mut lp, _, d, p) = two_paths_world();
    let (id, _) = bob_writes_both(&mut lp, d, p);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    let now = lp.peers[0].engine.now();
    m.set(p, &osis_schema::core_types::PURGE, &now).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: p, ak: ak("t:reg.0") });
    lp.peers[0].commit(m).unwrap().unwrap();
    for reopened in [false, true] {
        if reopened {
            crate::flows::reopen(&mut lp, 0).unwrap();
        }
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&p, &ak("t:reg.0")).unwrap(), None, "purged ({reopened})");
        assert_eq!(e.get(&d, &ak("t:reg.0")).unwrap(), Some(s("on d")), "D stands ({reopened})");
        let paths = e.core.ix.commits.get(&id).unwrap().view.paths.clone().unwrap();
        assert_eq!((paths.get(&p).map(Option::is_some), paths.get(&d).map(Option::is_some)), (Some(true), Some(true)), "kept ({reopened})");
        assert!(!e.core.ix.paths_unknown.contains(&id));
        e.check_index();
    }
}

// spec/commits.md §4 (while its header lists are not resolved): a split
// commit whose aspect list goes by link judges nothing before the list comes: Bob writes P's
// aspects past a list's threshold and one of D; Alice, given the commit without its list blobs, holds nothing of it
// and P stays as it was; given the blobs, both apply.
#[test]
fn a_split_commit_with_its_aspect_list_by_link_waits_for_it_spec_commits_4() {
    let (mut lp, _, d, p) = two_paths_world();
    let mut m = Mutation::new();
    let first = link_aspects(&mut m, p);
    m.set(d, &REG, &s("on d")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&id).unwrap();
    assert!(h.is_split() && h.links != osis_commit::Links::default(), "split, its aspect list by link: {} aspects, split {}", h.aspects.len(), h.is_split());
    assert!(!pk.blobs.is_empty());
    unless_refused(lp.peers[0].engine.ingest(&pk.bytes, Vec::new()));
    lp.peers[0].reexamine().unwrap();
    assert!(!lp.peers[0].engine.commit_ids().contains(&id), "nothing judged before the list");
    assert_eq!(lp.peers[0].engine.get(&p, &first).unwrap(), None);
    unless_refused(lp.peers[0].engine.ingest(&pk.bytes, pk.blobs.clone()));
    lp.peers[0].reexamine().unwrap();
    assert!(lp.peers[0].engine.commit_ids().contains(&id));
    assert_eq!(lp.peers[0].engine.get(&p, &first).unwrap(), Some(s("v")));
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("on d")));
    lp.peers[0].engine.check_index();
}

// spec/permissions.md §6 (The right); notes/path-form.md, Whom a write is by (the one purge author, in the clear),
// notes/path-form.md Per consumer: a purge request is judged alike in both path forms: Bob purges
// his own write on D (through H, purgeable by its author) alone (one path, `[H]`) and beside a write
// of P (split). At every node the outcome is the same in either form: his write goes; Alice's
// write on P, which he has no right to purge, he cannot request gone in either form.
#[test]
fn a_purge_request_is_judged_alike_in_both_path_forms_spec_permissions_6() {
    let mut outcomes = Vec::new();
    for beside in [false, true] {
        let (mut lp, _, d, p) = two_paths_world();
        let by = osis_base::PurgeBy::AuthorOrAdmin;
        let before = lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap();
        let mut m = Mutation::new();
        m.set(d, &REG, &s("his")).unwrap();
        m.purge_by(d, &REG, by).unwrap();
        let his = lp.peers[1].commit(m).unwrap().unwrap();
        let hers = put(&mut lp, 0, p, &REG, &s("hers"));
        lp.sync_all().unwrap();
        let mut m = Mutation::new();
        let now = lp.peers[1].engine.now();
        m.set(d, &osis_schema::core_types::PURGE, &now).unwrap();
        m.purge_commit(his, d, ak("t:reg.0"));
        if beside {
            m.set(p, &osis_base::Ak::new("t:other.0").unwrap(), &s("beside")).unwrap();
        }
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        assert_eq!(lp.peers[1].engine.header(&id).unwrap().is_split(), beside);
        // a request on Alice's write, which he has no right to purge: refused at his node
        let mut m = Mutation::new();
        m.set(p, &osis_schema::core_types::PURGE, &now).unwrap();
        m.purge_commit(hers, p, ak("t:reg.0"));
        m.set(d, &osis_base::Ak::new("t:other.0").unwrap(), &s("beside")).unwrap();
        assert!(lp.peers[1].commit(m).is_err(), "no right on hers");
        lp.sync_all().unwrap();
        let reads = (0..3).map(|i| (lp.peers[i].engine.get(&d, &ak("t:reg.0")).unwrap(), lp.peers[i].engine.get(&p, &ak("t:reg.0")).unwrap())).collect::<Vec<_>>();
        assert_eq!(reads[0].0, before, "his write purged: what it replaced reads ({beside})");
        assert_eq!(reads[0].1, Some(s("hers")), "hers stays ({beside})");
        outcomes.push(reads);
    }
    assert_eq!(outcomes[0], outcomes[1]);
}

// spec/commits.md §4 Unjudgeable (a split commit's thing whose entry opens nowhere here is
// examined again when the held role inputs move), notes/sync-facade.md Pending: Carol, a reader
// of P, holds Bob's split commit without D's part: D's path opens nowhere at her. Granted D (the
// grant alone delivered, no part of the commit), she opens D's entry from D's roles secret at once,
// with no restart; so too after a transaction of hers that changed something rolled back between.
#[test]
fn a_path_waiting_opens_when_its_roles_secret_comes_spec_commits_4() {
    for rolled_back in [false, true] {
        let (mut lp, _, d, p) = two_paths_world();
        let (id, c) = bob_writes_both(&mut lp, d, p);
        let ip = place(&c, p);
        let only_p = osis_commit::CommitBlob { keys: BTreeMap::from([(ip, c.keys[&ip])]), ..osis_commit::rewrite(&c, |ai| c.header.aspects[ai].tid != p) };
        unless_refused(lp.peers[2].engine.ingest(&only_p.encode(), Vec::new()));
        lp.peers[2].reexamine().unwrap();
        assert_eq!(lp.peers[2].engine.get(&p, &ak("t:reg.0")).unwrap(), Some(s("on p")));
        assert!(lp.peers[2].engine.core.ix.paths_unknown.contains(&id), "D's path opens nowhere at Carol");
        if rolled_back {
            let r: osis_engine::Result<()> = lp.peers[2].engine.run(|tx| {
                tx.core.touch();
                Err(osis_engine::Error::BadInput("rolled back"))
            });
            assert!(r.is_err());
        }
        let carol = lp.peers[2].engine.tid();
        let grant = lp.peers[0].engine.grant(&d, &carol, &edge(Role::Read)).unwrap().commits;
        for g in grant {
            let pk = lp.peers[0].engine.package(&g).unwrap().unwrap();
            unless_refused(lp.peers[2].engine.ingest(&pk.bytes, pk.blobs.clone()));
        }
        // the grant's fire takes it: its box opens then, no part of Bob's commit delivered
        lp.pass_fires(2).unwrap();
        lp.peers[2].reexamine().unwrap();
        assert!(lp.peers[2].engine.epochs(&d).is_some_and(|e| !e.read.held_roles().is_empty()), "Carol holds D's roles secret");
        assert!(!lp.peers[2].engine.core.ix.paths_unknown.contains(&id), "D's path opened (rolled back: {rolled_back})");
        assert_eq!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().view.paths.as_ref().unwrap().get(&d).map(Option::is_some), Some(true));
        lp.peers[2].engine.check_index();
    }
}

// spec/commits.md §4 Unjudgeable, notes/sync-facade.md Pending: a roles secret that opens a
// waiting path opens it in the transaction that brought it, however it came. Carol holds Bob's
// split commit without D's part; Alice's grant of D comes from her clock far ahead, so it pends
// for drift, yet its box gives Carol D's roles secret (reading): D's entry opens at once.
#[test]
fn a_path_waiting_opens_when_a_pending_commit_gives_its_roles_secret_spec_commits_4() {
    let (mut lp, _, d, p) = two_paths_world();
    let (id, c) = bob_writes_both(&mut lp, d, p);
    let ip = place(&c, p);
    let only_p = osis_commit::CommitBlob { keys: BTreeMap::from([(ip, c.keys[&ip])]), ..osis_commit::rewrite(&c, |ai| c.header.aspects[ai].tid != p) };
    unless_refused(lp.peers[2].engine.ingest(&only_p.encode(), Vec::new()));
    lp.peers[2].reexamine().unwrap();
    assert!(lp.peers[2].engine.core.ix.paths_unknown.contains(&id), "D's path opens nowhere at Carol");
    let carol = lp.peers[2].engine.tid();
    lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
    let grant = lp.peers[0].engine.grant(&d, &carol, &edge(Role::Read)).unwrap().commits;
    for g in grant {
        let pk = lp.peers[0].engine.package(&g).unwrap().unwrap();
        assert!(matches!(lp.peers[2].engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)));
    }
    assert!(lp.peers[2].engine.epochs(&d).is_some_and(|e| e.read.epochs().any(|(ep, _)| e.read.roles_secret(ep).is_some())), "Carol reads D's roles secret");
    assert!(!lp.peers[2].engine.core.ix.paths_unknown.contains(&id), "D's path opened");
    assert_eq!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().view.paths.as_ref().unwrap().get(&d).map(Option::is_some), Some(true));
    lp.peers[2].engine.check_index();
}

// spec/commits.md §4 Unjudgeable; notes/principles.md Fast by construction, notes/sync-facade.md Pending: a split commit whose
// path opens nowhere waits on what may open it, never on everything: k commits forged by Bob
// with D's entry opening nowhere, held at Alice, cost an unrelated write of hers nothing, at k = 1
// and k = 10.
#[test]
fn split_commits_waiting_on_a_path_cost_an_unrelated_write_nothing_spec_commits_4() {
    let work = |k: usize| {
        let (mut lp, _, d, p) = two_paths_world();
        let mine = new_thing(&mut lp, 0);
        for n in 0..k {
            let mut m = Mutation::new();
            m.set(d, &REG, &s(&format!("on d {n}"))).unwrap();
            m.set(p, &REG, &s(&format!("on p {n}"))).unwrap();
            let id = lp.peers[1].commit(m).unwrap().unwrap();
            let c = held(&mut lp, 1, &id);
            let (id_, ip, mut es) = (place(&c, d), place(&c, p), entries(&c));
            es[id_] = junk(es[id_].len());
            let f = resigned(&mut lp, &c, es, None);
            unless_refused(lp.peers[0].engine.ingest(&opened_sections(&f, &c, &[ip], &own(&c)), Vec::new()));
            lp.peers[0].reexamine().unwrap();
        }
        assert_eq!(lp.peers[0].engine.core.ix.paths_unknown.len(), k);
        osis_base::costs::take();
        put(&mut lp, 0, mine, &REG, &s("unrelated"));
        let costs = osis_base::costs::take();
        ["paths: waits settled", "paths: commits opened again", "timeline: commits given"].map(|n| costs.iter().find(|x| x.0 == n).map_or(0, |x| x.2))
    };
    // the write is given to the walk once: its later touches (`put_meta`) move nothing the walk
    // reads (`Paths::reads`)
    assert_eq!(work(1), [0, 0, 1]);
    assert_eq!(work(10), [0, 0, 1]);
}

// A write is never refused or split for its paths (notes/path-form.md), spec/wire.md §4 `Split`: a write making things beside
// writes reached another way is one commit, never refused: Bob makes X with admin D (through H), Y
// with his own root and Z with P, each beside a write reached another way. Alice (D's and P's
// admin) reads each new thing from that commit; Carol, a reader of P, reads Z from it; granted D
// after, she reads X from what she then syncs.
#[test]
fn a_write_making_things_beside_writes_reached_another_way_is_one_commit_spec_wire_4() {
    let (mut lp, _, d, p) = two_paths_world();
    let root = lp.peers[1].engine.tid();
    let mut made = Vec::new();
    for (n, (admin, beside)) in [(d, p), (root, d), (p, d)].into_iter().enumerate() {
        let mut m = Mutation::new();
        let x = lp.peers[1].engine.new_thing(&mut m, admin);
        m.set(x, &REG, &s("made")).unwrap();
        m.set(beside, &REG, &s(&format!("beside {n}"))).unwrap();
        let before = lp.peers[1].engine.commit_ids().len();
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        assert_eq!(lp.peers[1].engine.commit_ids().len(), before + 1, "one commit");
        assert!(lp.peers[1].engine.header(&id).unwrap().is_split(), "{admin:?}: split");
        made.push(x);
    }
    lp.sync_all().unwrap();
    let reg = |lp: &mut LocalPeer, i: usize, t: Tid| lp.peers[i].engine.get(&t, &ak("t:reg.0")).unwrap();
    for x in [made[0], made[2]] {
        assert_eq!(reg(&mut lp, 0, x), Some(s("made")), "Alice reads {x:?}");
    }
    assert_eq!(reg(&mut lp, 2, made[2]), Some(s("made")), "Carol reads Z, minted with admin P");
    assert_eq!(reg(&mut lp, 1, made[1]), Some(s("made")), "Bob reads Y");
    let c = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Read)), None);
    lp.hold(made[0]);
    for _ in 0..2 {
        lp.sync_all().unwrap();
    }
    assert_eq!(reg(&mut lp, 2, made[0]), Some(s("made")), "Carol, granted D later, reads X");
    assert_eq!(reg(&mut lp, 2, d), Some(s("beside 2")), "and D");
    for i in 0..3 {
        lp.peers[i].engine.check_index();
    }
}

// spec/crypto.md §5 Path entry, spec/wire.md §4 `PathKey`: every encryption of a thing's parts
// carries its path key, so a reader holding none of the roles secrets the entry is under opens it
// from the encryption it reads: Bob makes X with admin D beside a write of P (X's entry under D's roles
// secret); X is then granted to Carol, which makes X independent: she holds X's own epochs and its
// derived ones by history, never D's, and reads X from the sections sync seals.
#[test]
fn a_reader_holding_only_later_epochs_opens_the_path_from_its_section_spec_crypto_5() {
    let (mut lp, _, d, p) = two_paths_world();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, d);
    m.set(x, &REG, &s("made")).unwrap();
    m.set(p, &REG, &s("beside")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    assert!(lp.peers[1].engine.header(&id).unwrap().is_split());
    lp.hold(x);
    lp.sync_all().unwrap();
    let c = lp.peers[2].engine.tid();
    lp.peers[0].engine.grant(&x, &c, &edge(Role::Read)).unwrap();
    for _ in 0..2 {
        lp.sync_all().unwrap();
    }
    assert!(lp.peers[2].engine.epochs(&d).is_none_or(|e| e.read.held_roles().is_empty()), "Carol holds no roles secret of D");
    assert_eq!(lp.peers[2].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("made")), "Carol reads X");
    lp.peers[2].engine.check_index();
}

// spec/wire.md §4 `PathKey` (a header-only copy of a split commit destroying things carries their
// path keys), spec/commits.md §5 Destruction: Bob destroys his thing O in the commit that writes D
// through H. Carol holds Q, minted with admin O and granted to her (independent, so she holds no roles
// secret of O): she needs O's destruction and takes it as the header-only copy carries it (no
// part, O's path key alone), judging O destroyed.
#[test]
fn a_destruction_beside_a_write_through_another_actor_reaches_a_dependents_holder_spec_wire_4() {
    let (mut lp, _, d, _) = two_paths_world();
    let me = lp.peers[1].engine.tid();
    let o = crate::flows::thing_of(&mut lp, 1, me);
    let q = crate::flows::thing_of(&mut lp, 1, o);
    let c = lp.peers[2].engine.tid();
    lp.peers[1].engine.grant(&q, &c, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[2].engine.get(&q, &ak("t:reg.0")).unwrap(), Some(s("new")), "Carol reads Q");
    assert!(lp.peers[2].engine.epochs(&o).is_none_or(|e| e.read.held_roles().is_empty()), "Carol holds no roles secret of O");
    let mut m = Mutation::new();
    let now = lp.peers[1].engine.now();
    m.set(o, &osis_schema::core_types::PURGE, &now).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: o, ak: osis_schema::core_types::CREATED.name() });
    m.set(d, &REG, &s("beside")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
    let whole = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    assert!(whole.header.is_split());
    assert!(lp.peers[1].engine.destroyed(&o));
    // what opening the header-only copy gives: the header and O's path key
    let at = whole.header.things().iter().position(|t| *t == o).unwrap();
    let keys = whole.keys.iter().filter(|(i, _)| **i == at).map(|(i, k)| (*i, *k)).collect();
    let header_only = osis_commit::CommitBlob { header: whole.header.clone(), sigs: whole.sigs.clone(), parts: Vec::new(), keys };
    unless_refused(lp.peers[2].engine.ingest(&header_only.encode(), pk.blobs.clone()));
    lp.peers[2].reexamine().unwrap();
    assert!(lp.peers[2].engine.destroyed(&o), "Carol holds O destroyed");
    lp.peers[2].engine.check_index();
}

// spec/wire.md §4 field 2; notes/path-form.md The engine's choice: no honest commit states a wrong path. Over a world of
// grants, holders and creations, every part's path read off what each commit Alice holds states is
// a real chain: each hop an edge or a record descent held, from the signer to the thing.
#[test]
fn every_stated_path_is_a_chain_of_held_edges_spec_wire_4() {
    let (mut lp, _, d, p) = two_paths_world();
    bob_writes_both(&mut lp, d, p);
    put(&mut lp, 1, d, &REG, &s("d alone"));
    lp.sync_all().unwrap();
    let e = &mut lp.peers[0].engine;
    let ids = e.commit_ids();
    let mut checked = 0;
    for id in ids {
        let Some(h) = e.header(&id) else { continue };
        if h.kind.is_role() || h.purge_author() != h.signer {
            continue;
        }
        let pk = e.package(&id).unwrap().unwrap();
        let c = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        // the record chain of `x`, `x` first
        let chain = |e: &osis_engine::Engine, x: Tid| std::iter::successors(Some(x), |y| e.core.created(y).and_then(|r| r.mint_admin())).take(70).collect::<Vec<_>>();
        let hop = |e: &osis_engine::Engine, from: Tid, to: Tid| from == to || e.key_role(&to, &from).is_some() || chain(e, to).contains(&from);
        for (t, listed) in paths_stated(&c) {
            let mut at = h.signer;
            for x in listed.iter().copied().chain([t]) {
                assert!(hop(e, at, x), "{id:?}: {at:?} holds nothing on {x:?} (path to {t:?}: {listed:?})");
                at = x;
            }
            checked += 1;
        }
    }
    assert!(checked >= 4, "{checked} paths checked");
}

/// Bob (1) writes `m`: the header's path.
fn bobs_path(lp: &mut LocalPeer, m: Mutation) -> osis_commit::Paths {
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    lp.peers[1].engine.header(&id).unwrap().path.clone()
}

/// Bob (1) holds write on `chain[0]`, each thing of `chain` on the next, the last on `t`, and
/// write on `d` directly; Alice (0) mints them all.
fn holders_world(n: usize) -> (LocalPeer, Vec<Tid>, Tid, Tid) {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let chain: Vec<Tid> = (0..n).map(|_| new_thing(&mut lp, 0)).collect();
    let (t, d) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let b = lp.peers[1].engine.tid();
    let mut holder = b;
    for x in chain.iter().copied().chain([t]) {
        set_edge(&mut lp.peers[0].engine, x, holder, Some(edge(Role::Write)), None);
        holder = x;
    }
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, chain, t, d)
}

// spec/permissions.md §1 Path, spec/wire.md §4 field 2: a write states the chain of
// holders by which its signer reaches what it writes, naming the signer as purge author (the
// thing it acts for, listed, where it acts for one): none for what it holds directly, three for a
// thing reached through three; every node applies it as before (Interim, spec/permissions.md
// §5.2). Where the things' paths differ the commit states the split form (notes/path-form.md).
#[test]
fn a_write_states_the_holders_it_goes_through_spec_wire_4() {
    let (mut lp, chain, t, d) = holders_world(3);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("on t")).unwrap();
    assert_eq!(bobs_path(&mut lp, m), osis_commit::Paths::One(osis_commit::Path { purge: 0, things: chain.clone(), direct: 0 }));
    let mut m = Mutation::new();
    m.set(d, &REG, &s("on d")).unwrap();
    assert_eq!(bobs_path(&mut lp, m), osis_commit::Paths::One(osis_commit::Path::default()));
    let mut m = Mutation::new();
    m.set(chain[2], &REG, &s("on c2")).unwrap();
    assert_eq!(bobs_path(&mut lp, m), osis_commit::Paths::One(osis_commit::Path { purge: 0, things: chain[..2].to_vec(), direct: 0 }));
    // acting for a holder: the path goes through it, naming it
    let mut m = Mutation::new();
    m.set(t, &REG, &s("as c0")).unwrap();
    m.act_as(chain[0]);
    assert_eq!(bobs_path(&mut lp, m), osis_commit::Paths::One(osis_commit::Path { purge: 1, things: chain.clone(), direct: 0 }));
    let mut m = Mutation::new();
    m.set(t, &REG, &s("on t again")).unwrap();
    m.set(d, &REG, &s("on d again")).unwrap();
    assert!(matches!(bobs_path(&mut lp, m), osis_commit::Paths::Split(sp) if sp.author.is_none() && sp.entries.len() == 2), "paths differ");
    lp.sync_all().unwrap();
    for i in 0..2 {
        let e = &mut lp.peers[i].engine;
        assert_eq!((e.get(&t, &ak("t:reg.0")).unwrap(), e.get(&d, &ak("t:reg.0")).unwrap()), (Some(s("on t again")), Some(s("on d again"))), "peer {i}");
        e.check_index();
    }
}

// spec/wire.md §2 MAX_PATH_THINGS: a write through 64 holders states them all; one through 65 is
// refused, naming the limit.
#[test]
#[ignore = "by hand: 66 role commits, about 10 s"]
fn a_path_holds_at_most_max_path_things_spec_wire_2() {
    let (mut lp, chain, t, _) = holders_world(osis_base::format::MAX_PATH_THINGS + 1);
    let last = *chain.last().unwrap();
    let mut m = Mutation::new();
    m.set(last, &REG, &s("64 through")).unwrap();
    let osis_commit::Paths::One(p) = bobs_path(&mut lp, m) else { panic!("one path") };
    assert_eq!(p.things.len(), osis_base::format::MAX_PATH_THINGS);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("65 through")).unwrap();
    let err = lp.peers[1].commit(m).unwrap_err().to_string();
    assert!(err.contains("MAX_PATH_THINGS"), "{err}");
}

// spec/wire.md §4 field 2, notes/principles.md Check scaling: finding a write's path walks the things reaching what it
// writes, once per role change: as many at 10n role commits held elsewhere as at n, and none for
// a second write while the roles stand; a content write steps the role walk through no part.
#[test]
fn finding_a_path_does_not_grow_with_history_spec_wire_4() {
    let walked = |n: usize| {
        let (mut lp, _, t, _) = holders_world(1);
        let b = lp.peers[1].engine.tid();
        for _ in 0..n {
            let x = new_thing(&mut lp, 0);
            set_edge(&mut lp.peers[0].engine, x, b, Some(edge(Role::Read)), None);
        }
        lp.sync_all().unwrap();
        let count = |lp: &mut LocalPeer, v: &str| {
            osis_base::costs::take();
            let parts = osis_perm::commits_walked();
            put(lp, 1, t, &REG, &s(v));
            assert_eq!(osis_perm::commits_walked(), parts, "{v}: a content write walks no role part");
            osis_base::costs::take().iter().find(|x| x.0 == "perm: ways walked").map_or(0, |x| x.2)
        };
        (count(&mut lp, "first"), count(&mut lp, "second"))
    };
    let (small, large) = (walked(2), walked(20));
    assert_eq!(small, large, "at n and 10n role commits held elsewhere");
    assert!(small.0 > 0 && small.1 == 0, "walked once while the roles stand: {small:?}");
}

// spec/permissions.md §1 Path; spec/wire.md §4 field 2: the path a write states is the
// shortest on the edges alive at its `ts`: a direct grant ending with no edge write since, the
// path goes through the holder; a shorter one granted, it is taken; removed, the holder again.
#[test]
fn a_writes_path_follows_its_edges_and_their_ends_spec_wire_4() {
    let (mut lp, chain, t, _) = holders_world(1);
    let b = lp.peers[1].engine.tid();
    let until = WallMs(lp.peers[0].engine.now().0 + 5_000);
    set_edge(&mut lp.peers[0].engine, t, b, Some(osis_schema::core_types::Edge { until: Some(until), ..edge(Role::Write) }), None);
    lp.sync_all().unwrap();
    let write = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        let osis_commit::Paths::One(p) = bobs_path(lp, m) else { panic!("one path") };
        p.things
    };
    assert_eq!(write(&mut lp, "direct"), Vec::<Tid>::new(), "direct while it lasts");
    lp.advance(10_000);
    assert_eq!(write(&mut lp, "ended"), chain, "through the holder once it ends");
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    assert_eq!(write(&mut lp, "granted"), Vec::<Tid>::new(), "a shorter path granted");
    lp.peers[0].engine.demote(&t, &osis_engine::flows::Demotion { holder: b, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(write(&mut lp, "removed"), chain, "the used path removed");
}

// spec/permissions.md §1 Path: among paths as short, the writer's choice is a function
// of the edges it holds, not of the order they came in: Bob reaches T through H1 or H2.
#[test]
fn a_writes_path_is_a_function_of_the_held_edges_spec_wire_4() {
    let chosen = |first: usize| {
        let mut lp = net(2, 0);
        lp.sync_all().unwrap();
        let hs = [new_thing(&mut lp, 0), new_thing(&mut lp, 0)];
        let t = new_thing(&mut lp, 0);
        let b = lp.peers[1].engine.tid();
        for i in [first, 1 - first] {
            set_edge(&mut lp.peers[0].engine, hs[i], b, Some(edge(Role::Write)), None);
            lp.sync_all().unwrap();
            set_edge(&mut lp.peers[0].engine, t, hs[i], Some(edge(Role::Write)), None);
            lp.sync_all().unwrap();
        }
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("x")).unwrap();
        let osis_commit::Paths::One(p) = bobs_path(&mut lp, m) else { panic!("one path") };
        assert_eq!(p.things.len(), 1);
        hs.iter().position(|h| *h == p.things[0]).unwrap()
    };
    assert_eq!(chosen(0), chosen(1));
}

// spec/wire.md §4 (one path), spec/requirements.md Confidentiality between readers: one path in
// the clear unless it would tell a reader of one thing written a fact of another's roster. Bob writes through his
// holder H. Two things H holds by grant, D and P, written together, are one hop past `[H]` alike,
// but `[H]` would show D's readers that H holds P (and P's that H holds D): split. D and X, made
// under D through H, state `[H, D]` in the clear: X derives from D, so D's readers read X whole.
#[test]
fn one_path_in_the_clear_only_where_it_shows_no_reader_another_roster_spec_wire_4() {
    let mut lp = net(3, 0);
    lp.sync_all().unwrap();
    let (h, d, p) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, h, b, Some(edge(Role::Write)), None);
    for t in [d, p] {
        set_edge(&mut lp.peers[0].engine, t, h, Some(edge(Role::Admin)), None);
    }
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.set(d, &REG, &s("on d")).unwrap();
    m.set(p, &REG, &s("on p")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let c = held(&mut lp, 1, &id);
    assert!(c.header.is_split(), "two grants past one holder: {:?}", c.header.path);
    let mut got = paths_stated(&c);
    got.sort();
    let mut want = vec![(d, vec![h]), (p, vec![h])];
    want.sort();
    assert_eq!(got, want);
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, d);
    m.set(x, &REG, &s("under d")).unwrap();
    m.set(d, &REG, &s("beside x")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let hd = lp.peers[1].engine.header(&id).unwrap();
    assert_eq!(hd.path, osis_commit::Paths::One(osis_commit::Path { purge: 0, things: vec![h, d], direct: 0 }), "a dependent beside its parent");
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("under d")));
}

// spec/wire.md §4 field 2; notes/path-form.md One path: a creation states one path in the
// clear: minted with the node thing along the empty path (18 B on `signer` and `path`); under a
// parent the signer holds by a grant along `[D]` (34 B), the new thing one record edge past it.
// spec/permissions.md §1 Path (nothing but the stated path judges a part): a write acting as D on
// E, which D holds no role on, is refused: no path through D gives the role.
#[test]
fn the_engine_states_one_path_for_a_creation_spec_wire_4() {
    let path_bytes = |h: &osis_commit::Header| {
        let all = h.encode();
        let l = osis_base::cbor::Item::parse(&all, &osis_base::Limits::new(512, 1 << 24)).unwrap().as_list().unwrap();
        [1, 2].iter().map(|i| l.get(*i).unwrap().bytes().len()).sum::<usize>()
    };
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let made = |lp: &LocalPeer, i: usize, t: Tid| lp.peers[i].engine.commit_ids().into_iter().find(|c| lp.peers[i].engine.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak.as_str() == "created.0"))).unwrap();
    let h = lp.peers[0].engine.header(&made(&lp, 0, t)).unwrap();
    assert!(h.things().len() > 1, "a creation writes the thing and its holder");
    assert_eq!(h.path, osis_commit::Paths::One(osis_commit::Path::default()));
    assert_eq!(path_bytes(&h), 18);
    // with a mint admin Bob holds by a grant
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, t);
    m.set(x, &REG, &s("under t")).unwrap();
    lp.peers[1].commit(m).unwrap();
    let h = lp.peers[1].engine.header(&made(&lp, 1, x)).unwrap();
    assert_eq!(h.path, osis_commit::Paths::One(osis_commit::Path { purge: 0, things: vec![t], direct: 0 }));
    assert_eq!(path_bytes(&h), 34);
    assert!(matches!(acting_on_two(), Err(osis_engine::Error::Permission { .. })), "acting as D on E, which D holds nothing on");
}

// spec/wire.md §4 `Split` (a reader opens an entry with a key a part carries, else with the read
// roles secrets up the thing's record chain), spec/permissions.md §3 (Lost access: the read
// secrets go): Carol reads P, and D through `reader` (D itself, or the mint admin D derives its
// secrets from); given Bob's split commit with P's parts alone, she opens D's entry by those
// secrets. Removed from `reader`, she drops them: D's entry opens nowhere at her then, so it
// waits, live as after a reopen.
fn lost_secrets_paths(lp: &mut LocalPeer, d: Tid, p: Tid, reader: Tid) {
    let c = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, reader, c, Some(edge(Role::Read)), None);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.set(d, &REG, &s("on d")).unwrap();
    m.set(p, &REG, &s("on p")).unwrap();
    let id = lp.peers[1].engine.commit(m).unwrap().unwrap();
    let full = held(lp, 1, &id);
    assert!(full.header.is_split());
    let pi = place(&full, p);
    let mut only_p = osis_commit::rewrite(&full, |ai| full.header.aspects[ai].tid != p);
    only_p.keys.retain(|i, _| *i == pi);
    unless_refused(lp.peers[2].engine.ingest(&only_p.encode(), Vec::new()));
    lp.peers[2].reexamine().unwrap();
    let state = |lp: &LocalPeer| {
        let e = &lp.peers[2].engine;
        let paths = e.core.ix.commits.get(&id).unwrap().view.paths.clone().unwrap();
        (paths.get(&d).map(Option::is_some), paths.get(&p).map(Option::is_some), e.core.ix.paths_unknown.contains(&id))
    };
    assert_eq!(state(lp), (Some(true), Some(true), false), "D's entry opened by her secrets");
    lp.peers[2].engine.check_index();
    let removal = set_edge(&mut lp.peers[0].engine, reader, c, None, None);
    let pk = lp.peers[0].engine.package(&removal).unwrap().unwrap();
    unless_refused(lp.peers[2].engine.ingest(&pk.bytes, pk.blobs));
    lp.peers[2].reexamine().unwrap();
    let lost = lp.peers[2].engine.role_duties().unwrap();
    assert!(lost.contains(&reader), "{lost:?}");
    assert_eq!(state(lp), (None, Some(true), true), "D's entry waits");
    lp.peers[2].engine.check_index();
    crate::flows::reopen(lp, 2).unwrap();
    assert_eq!(state(lp), (None, Some(true), true), "D's entry waits after a reopen");
}

// spec/wire.md §4 `Split`, spec/permissions.md §3: `lost_secrets_paths`, Carol reading D itself.
#[test]
fn a_path_opened_by_read_secrets_waits_once_they_are_lost_spec_wire_4() {
    let (mut lp, _, d, p) = two_paths_world();
    lost_secrets_paths(&mut lp, d, p, d);
}

// spec/wire.md §4 `Split`, spec/permissions.md §3: `lost_secrets_paths`, Carol reading D's mint
// admin A, whose secrets D's derive from.
#[test]
fn a_path_opened_by_a_mint_admins_read_secrets_waits_once_they_are_lost_spec_wire_4() {
    let (mut lp, _, _, p) = two_paths_world();
    let a = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, a, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, a);
    m.set(d, &REG, &s("new")).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    lost_secrets_paths(&mut lp, d, p, a);
}
