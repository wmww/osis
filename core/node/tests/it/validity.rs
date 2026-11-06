#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Validity through perm at the engine level, with hand-fed role commits: the Bob
//! revocation scenario and the Carol variant (notes/permissions.md, Revocation), re-grant,
//! overlapping counters.

use crate::common;
use common::*;
use osis_base::Classified;
use osis_base::{Role, Tid, Value, WallMs};
use osis_node::local_peer::LocalPeer;
use osis_node::{Event, Ingested, Mutation, Reason};
use osis_perm::DemotionScope;
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};

const DAY: u64 = 86_400_000;

fn tags(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<String> {
    match lp.peers[i].engine.get(&t, &ak("t:tags.0")).unwrap() {
        Some(Value::Set(s)) => s.into_iter().map(|v| if let Value::Str(x) = v { x } else { String::new() }).collect(),
        _ => BTreeSet::new(),
    }
}

fn add_tag(lp: &mut LocalPeer, i: usize, t: Tid, tag: &str) {
    let mut m = Mutation::new();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s(tag)) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap();
}

fn revoke(lp: &mut LocalPeer, admin: usize, t: Tid, holder: Tid) {
    let scope = DemotionScope { roles: BTreeMap::from([(holder, BTreeSet::from([t]))]), content: BTreeMap::from([(holder, BTreeSet::from([t]))]) };
    let now = lp.peers[admin].engine.now();
    let f = lp.peers[admin].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[admin].engine, t, holder, None, Some(f.to_value()));
}

/// Alice (0) owns D and grants Bob (1) and Carol (2) write.
fn setup(seed: u64) -> (LocalPeer, Tid, Tid, Tid) {
    let mut lp = net(3, seed);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    (lp, d, b, c)
}

// notes/permissions.md Revocation; spec/permissions.md §5.2: Bob's edit X made offline before
// the revoke and Y after it are both invalid wherever the revoke is held; his edit Alice had
// received stays (the frontier covers it); Bob's own node un-merges both.
#[test]
fn bob_revocation_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(41);
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
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: osis_node::Cause::Validity, .. })));
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    // re-grant makes every write of Bob valid again, the gap included
    lp.advance(DAY);
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    for i in [0, 1] {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["mon".into(), "x".into(), "y".into()]), "node {i}");
    }
}

// notes/permissions.md Revocation, Carol variant: Carol, offline with Bob, applied X; once
// she holds the revoke X is un-merged at her node too, while her own edit stays.
// spec/permissions.md §5.2
#[test]
fn carol_variant_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(42);
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "x");
    add_tag(&mut lp, 2, d, "carol");
    sync(&mut lp, 1, 2);
    assert!(tags(&mut lp, 2, d).contains("x"));
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 2);
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["carol".to_string()]));
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["carol".to_string()]), "node {i}");
    }
    // the result is a function of the held set, not of arrival order
    let mut lp2 = net(1, 43);
    lp2.advance(2 * DAY);
    let mut pks: Vec<_> = [0, 1, 2].iter().flat_map(|i| lp.packages(*i).unwrap()).collect();
    pks.reverse();
    for _ in 0..2 {
        for p in &pks {
            let _ = lp2.deliver(0, p);
        }
    }
    assert!(lp2.peers[0].engine.pending().is_empty(), "{:?}", lp2.peers[0].engine.pending());
    assert_eq!(tags(&mut lp2, 0, d), BTreeSet::from(["carol".to_string()]));
}

// spec/permissions.md §5.1: a register value a revoked writer overwrote comes back on
// un-merge (re-join of the held bodies, spec/crdt.md §4.6).
#[test]
fn unmerge_restores_register_spec_crdt_4_6() {
    let (mut lp, d, b, _) = setup(44);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("alice")).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("bob")).unwrap();
    lp.peers[1].commit(m).unwrap();
    sync(&mut lp, 1, 2);
    assert_eq!(lp.peers[2].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob")));
    lp.advance(1000);
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 2);
    assert_eq!(lp.peers[2].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("alice")));
}

/// Secrets for hand-built commits: dedup, and made-up delete keys (hosts' business).
struct Dedup(osis_base::CreationRecord);
impl osis_commit::Secrets for Dedup {
    fn dedup(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([3; 32])).verifying_key())
    }
    fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([1; 32])).verifying_key())
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([2; 32])).verifying_key())
    }
}

// spec/commits.md §4: two commits of one session with overlapping ranges on one aspect
// are both invalid.
// spec/permissions.md §5.2 (dot reuse)
#[test]
fn overlapping_counters_spec_commits_4() {
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Delta, Writer, create, encode_delta};
    let (mut lp, d, b, _) = setup(45);
    let other = ak("x:other.0");
    let mut m = Mutation::new();
    m.set(d, &other, &s("first")).unwrap();
    let first = lp.peers[1].commit(m).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&first).unwrap();
    let (lo, hi) = (h.aspects[0].lo, h.aspects[0].hi);
    // Bob's key signs a second commit of the same session reusing those counters
    let ts = osis_base::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let mut w = Writer::new(ts, h.form.own_source(b, osis_base::CommitId([0; 32])), lo);
    let f = create(&mut w, &AnyView, &s("second")).unwrap();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(h.form, Kind::Content, ts, b, lo, hi), None).unwrap();
    let mut aw = AspectWrite::new(d, other.clone(), lo, hi, bytes);
    aw.retention = osis_schema::Retention { by: osis_schema::PurgeBy::Nobody, ..Default::default() };
    let mut cb = CommitBuilder::new(Kind::Content, ts, b, b, h.form);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let built = cb.build(&lp.peers[1].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap();
    sync(&mut lp, 1, 0);
    assert_eq!(lp.peers[0].engine.get(&d, &other).unwrap(), Some(s("first")));
    lp.peers[0].engine.ingest(&built.commit.encode(), Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &other).unwrap(), None);
}

/// Bob's key signs a commit of his engine's session on `d`'s `ak` with counters from `lo`
/// (any he used before included), setting the register to `v` at `ts`.
fn forge_reg(lp: &mut LocalPeer, d: Tid, ak: &osis_base::Ak, lo: u64, ts: osis_base::Ts, v: &str) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Delta, Writer, create, encode_delta};
    let b = lp.peers[1].engine.tid();
    let form = crate::common::session_of(lp, 1);
    let mut w = Writer::new(ts, form.own_source(b, osis_base::CommitId([0; 32])), lo);
    let f = create(&mut w, &AnyView, &s(v)).unwrap();
    let hi = lo + 1;
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Content, ts, b, lo, hi), None).unwrap();
    let mut aw = AspectWrite::new(d, ak.clone(), lo, hi, bytes);
    aw.retention = osis_schema::Retention { by: osis_schema::PurgeBy::Nobody, ..Default::default() };
    let mut cb = CommitBuilder::new(Kind::Content, ts, b, b, form);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[1].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

/// Bob's demotion scope on `d`.
fn of(b: Tid, d: Tid) -> DemotionScope {
    DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) }
}

// spec/permissions.md §5.1 (a frontier lists commit IDs, never counters), §5.2, Tess's decision
// (a): Bob writes, Alice overwrites it, compacts (Bob's write is dead, so the snapshot carries
// nothing of his) and removes him, her frontier listing nothing (the snapshot covers his commit).
// Bob then signs a newer commit on the counters his first one used. A fresh node holding the
// removal and the snapshot but not the first commit judges the forgery invalid (with counter
// frontiers it counted, and nothing it held carried that dot); Alice, holding both, voids both
// (one dot, one write).
// spec/permissions.md §5.2 (dot reuse)
#[test]
fn revoked_writer_forging_into_covered_counters_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x7101);
    let reg = ak("t:reg.0");
    let mut m = Mutation::new();
    m.set(d, &REG, &s("bob")).unwrap();
    let first = lp.peers[1].commit(m).unwrap().unwrap();
    let lo = lp.peers[1].engine.header(&first).unwrap().aspects.iter().find(|a| a.ak == reg).unwrap().lo;
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("alice")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &reg).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.covered(&snap, &first, &d, &reg).unwrap(), Some(true));
    lp.advance(DAY);
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(!f.commits.contains(&first), "covered: not listed");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
    lp.advance(1_000);
    let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_reg(&mut lp, d, &reg, lo, ts, "forged");
    let mut fresh = net(1, 0x7102);
    fresh.advance(3 * DAY);
    for p in packages(&mut lp, 0).into_iter().filter(|p| p.id != first) {
        fresh.deliver(0, &p).unwrap();
    }
    fresh.peers[0].engine.reexamine().unwrap();
    fresh.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
    assert_eq!(fresh.peers[0].engine.get(&d, &reg).unwrap(), Some(s("alice")), "a fresh node");
    lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
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
    for (seed, remove) in [(0x7111, false), (0x7112, true)] {
        let (mut lp, d, b, _) = setup(seed);
        let reg = ak("t:reg.0");
        let mut m = Mutation::new();
        m.set(d, &REG, &s("bob")).unwrap();
        let first = lp.peers[1].commit(m).unwrap().unwrap();
        let lo = lp.peers[1].engine.header(&first).unwrap().aspects.iter().find(|a| a.ak == reg).unwrap().lo;
        sync(&mut lp, 1, 0);
        lp.advance(1_000);
        lp.peers[0].engine.snapshot(&d, &reg).unwrap().unwrap();
        lp.advance(DAY);
        if remove {
            let now = lp.peers[0].engine.now();
            let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
            assert!(!f.commits.contains(&first), "covered: not listed");
            set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
            lp.advance(1_000);
        }
        let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
        let forged = forge_reg(&mut lp, d, &reg, lo, ts, "forged");
        lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
        assert_eq!(lp.peers[0].engine.get(&d, &reg).unwrap(), Some(s("bob")), "remove {remove}");
        assert!(!lp.peers[0].engine.body_valid(&first, &d, &reg).unwrap(), "remove {remove}: the first commit is void");
    }
}

// spec/permissions.md §5.1, §5.2: Alice removes Bob holding his compacted tag and his
// uncompacted register write: her frontier lists the register write only; both stay, at Alice
// and at a fresh node that never gets the compacted commit (the snapshot vouches for it).
#[test]
fn frontier_lists_uncovered_snapshot_vouches_covered_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x7103);
    let tags_ak = ak("t:tags.0");
    let mut m = Mutation::new();
    m.op(d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s("mon")) }).unwrap();
    let tag = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("b")).unwrap();
    let reg = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(DAY);
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(f.commits.contains(&reg) && !f.commits.contains(&tag), "{f:?}");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
    let mut fresh = net(1, 0x7104);
    fresh.advance(3 * DAY);
    for p in packages(&mut lp, 0).into_iter().filter(|p| p.id != tag) {
        fresh.deliver(0, &p).unwrap();
    }
    fresh.peers[0].engine.reexamine().unwrap();
    for (i, l) in [(0, &mut lp), (0, &mut fresh)] {
        assert_eq!(tags(l, i, d), BTreeSet::from(["mon".to_string()]));
        assert_eq!(l.peers[i].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("b")));
    }
}

// spec/permissions.md §5.1 (what A had received as of T): a backdated frontier lists Bob's
// commits Alice received by its cutoff, not those received after.
// spec/permissions.md §5.1 (frontier received)
#[test]
fn backdated_frontier_lists_by_cutoff_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x7105);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("1")).unwrap();
    let one = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    let cut = lp.peers[0].engine.now();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("2")).unwrap();
    let two = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let f = lp.peers[0].engine.frontier(&of(b, d), cut).unwrap();
    assert!(f.commits.contains(&one) && !f.commits.contains(&two), "{f:?}");
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(f.commits.contains(&one) && f.commits.contains(&two), "{f:?}");
}

// spec/commits.md §3, §4 (counter reuse): role commits use commit form and a session-form one
// is bad input, so a node cannot void its own grant by later reusing its counters (overlapping
// session ranges void both commits): Bob keeps the edge Alice gave him.
#[test]
fn reused_counters_never_void_a_grant_spec_commits_4() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Batch, Delta, Op, PathOp, PathSeg, Writer, encode_delta};
    let mut lp = net(3, 46);
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
    let mut batch = Batch::new(&empty, Writer::new(ts, form.own_source(a, osis_base::CommitId([0; 32])), holders.lo));
    batch.apply(&PathOp { path: vec![PathSeg::Key(Value::Tid(c))], op: Op::Set(edge(Role::Read).to_value()) }, &AnyView).unwrap();
    let (f, range) = batch.finish().unwrap();
    assert!(range.lo < holders.hi && holders.lo < range.hi, "the ranges overlap");
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Role, ts, a, range.lo, range.hi), None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, a, a, form);
    let mut aw = AspectWrite::new(d, holders.ak.clone(), range.lo, range.hi, bytes);
    aw.retention = osis_commit::retention::ROLE_RETENTION;
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    // a session-form role commit is refused when built and when received (spec/commits.md §4)
    let e = cb.build(&lp.peers[0].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap_err();
    assert!(e.to_string().contains("session form outside a content commit"), "{e}");
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
}

// spec/wire.md §4 field 12: a role commit whose frontier does not decode as a frontier is bad
// input, never a demotion without a frontier (which would drop every audited write).
#[test]
fn malformed_frontier_is_bad_input_spec_wire_4() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Batch, Delta, Op, PathOp, Writer, encode_delta};
    let (mut lp, d, b, _) = setup(48);
    let a = lp.peers[0].engine.tid();
    let ts = osis_base::Ts::make(WallMs(lp.peers[0].engine.now().0 + 5), 0).unwrap();
    let empty = osis_crdt::Fragment::default();
    let mut batch = Batch::new(&empty, Writer::new(ts, Form::Commit.own_source(a, osis_base::CommitId([0; 32])), 1).keyed_removals(true));
    let view = osis_schema::core_schema().view("roles.0").unwrap();
    batch.apply(&PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(b))], op: Op::Set(edge(Role::Read).to_value()) }, &view).unwrap();
    let (f, range) = batch.finish().unwrap();
    let cx = writer_ctx(Form::Commit, Kind::Role, ts, a, range.lo, range.hi);
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, a, a, Form::Commit);
    let mut aw = AspectWrite::new(d, ak("roles.0"), range.lo, range.hi, bytes);
    aw.retention = osis_commit::retention::ROLE_RETENTION;
    cb.aspects.push(aw);
    cb.frontier = Some(Value::Int(5));
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let built = cb.build(&lp.peers[0].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap();
    let e = lp.peers[1].engine.ingest(&built.commit.encode(), Vec::new()).unwrap_err();
    assert_eq!(e.class(), osis_base::ErrorClass::BadInput, "{e}");
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
}

// spec/commits.md §2: a role commit changes at most
// one edge; a frontier needs a demotion. A writer refuses such a commit before it leaves.
#[test]
fn role_content_rules_spec_commits_2() {
    let (mut lp, d, b, c) = setup(47);
    let put = |x: Tid, r: Role| osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(x))], op: osis_crdt::Op::Set(edge(r).to_value()) };
    let mut m = Mutation::new();
    for x in [b, c] {
        m.op(d, &osis_schema::core_types::ROLES, put(x, Role::Admin)).unwrap();
    }
    assert_eq!(lp.peers[0].commit(m).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    let mut m = Mutation::new();
    m.op(d, &osis_schema::core_types::ROLES, put(b, Role::Admin)).unwrap();
    m.frontier(osis_schema::core_types::Frontier::default().to_value());
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
// canonically whichever node tid sorts first.
#[test]
fn commit_form_order_spec_crdt_3_3() {
    for seed in 0..8 {
        let mut lp = net(2, seed);
        lp.sync_all().unwrap();
        let d = new_thing(&mut lp, 0);
        let b = lp.peers[1].engine.tid();
        set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
        sync(&mut lp, 0, 1);
        let map = ak("t:map.0");
        let mut m = Mutation::new();
        for k in ["a", "b", "c"] {
            m.op(d, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(Value::Int(1)) }).unwrap();
        }
        lp.peers[1].commit(m).unwrap().unwrap();
        sync(&mut lp, 1, 0);
        let mut m = Mutation::new();
        m.commit_form();
        for k in ["a", "b", "c"] {
            m.op(d, &map, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s(k)) }).unwrap();
            m.op(d, &map, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(Value::Int(2)) }).unwrap();
        }
        lp.peers[0].commit(m).unwrap_or_else(|e| panic!("seed {seed}: {e}")).unwrap();
    }
}

// spec/wire.md §4: spec/requirements.md, Authorship: every write is attributable and verifiable. A node cannot
// sign a write claiming an actor whose write secret it does not hold (the author chain).
#[test]
fn foreign_actor_claim_refused_spec_wire_4() {
    let mut lp = net(3, 77);
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
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Delta, Source, Writer, create, encode_delta};
    let b = lp.peers[1].engine.tid();
    let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let mut w = Writer::new(ts, Source::commit(osis_base::CommitId([0; 32])), 1);
    let f = create(&mut w, &AnyView, &s(v)).unwrap();
    let r = w.range();
    let cx = writer_ctx(Form::Commit, Kind::Content, ts, b, r.lo, r.hi);
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let mut aw = AspectWrite::new(d, ak("t:reg.0"), r.lo, r.hi, bytes);
    aw.retention = osis_schema::Retention { by: osis_schema::PurgeBy::Nobody, ..Default::default() };
    let mut cb = CommitBuilder::new(Kind::Content, ts, b, actor, Form::Commit);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[1].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

// spec/permissions.md §5.2 (acting for an actor): Bob, a writer of D, signs a write naming
// Carol as its actor though he holds no write on her. Receivers judge it invalid, so it can
// never read as Carol's; the same write naming Bob himself is valid.
#[test]
fn forged_actor_invalid_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup(46);
    lp.advance(1_000);
    let forged = forge_acting(&mut lp, d, c, "as carol");
    lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
    assert!(lp.peers[0].engine.pending().is_empty());
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("new")), "a write acting for an actor its author cannot act for applied");
    lp.advance(1_000);
    let own = forge_acting(&mut lp, d, b, "as bob");
    lp.peers[0].engine.ingest(&own, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("as bob")));
}

// spec/permissions.md §5.2 (acting for an actor), spec/commits.md §4 (order independence):
// Dave (3), with no right on D, grants Bob write on himself; Bob writes D acting for Dave.
// Alice gets the write before the grant (invalid: Bob cannot act for Dave as far as she knows)
// and judges it valid once the grant arrives, though nothing about D changed.
#[test]
fn acting_valid_once_grant_arrives_spec_perm_5_2() {
    let mut lp = net(4, 47);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, dave) = (lp.peers[1].engine.tid(), lp.peers[3].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    set_edge(&mut lp.peers[3].engine, dave, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 3, 1);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("for dave")).unwrap();
    // Dave's node has no write secret to derive an author-class delete key from
    m.retention(d, &REG, osis_schema::Retention { by: osis_schema::PurgeBy::Nobody, ..Default::default() }).unwrap();
    m.act_as(dave);
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
    lp.deliver(0, &pk).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("new")));
    sync(&mut lp, 3, 0);
    assert_eq!(lp.peers[0].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("for dave")));
}

/// A role commit signed by peer `by`'s key writing `v` to `ak` on `t`, built by hand past
/// the writer-side rules; its counters start at `lo`.
pub(crate) fn forge_role_commit(lp: &mut LocalPeer, by: usize, t: Tid, ak: &osis_base::Ak, v: &Value, lo: u64) -> Vec<u8> {
    forge_commit(lp, by, t, ak, v, lo, osis_commit::Kind::Role)
}

/// `forge_role_commit` of any kind; an AK the core schema does not declare is written untyped.
fn forge_commit(lp: &mut LocalPeer, by: usize, t: Tid, ak: &osis_base::Ak, v: &Value, lo: u64, kind: osis_commit::Kind) -> Vec<u8> {
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    forge_by(&lp.peers[by].engine, rec, t, ak, v, lo, kind)
}

/// A commit by `by` on thing `t`, whose creation record is `rec`, whatever its rights there.
pub(crate) fn forge_by(by: &osis_node::Engine, rec: osis_base::CreationRecord, t: Tid, ak: &osis_base::Ak, v: &Value, lo: u64, kind: osis_commit::Kind) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    let author = by.tid();
    let ts = osis_base::Ts::make(by.now(), 0).unwrap();
    // commit form (spec/commits.md §3): own dots name the commit, a placeholder until built
    let mut w = Writer::new(ts, Source::commit(osis_base::CommitId([0; 32])), lo);
    let f = match osis_schema::core_schema().view(ak.as_str()) {
        Some(view) => create(&mut w, &view, v).unwrap(),
        None => create(&mut w, &osis_crdt::AnyView, v).unwrap(),
    };
    let r = w.range();
    let cx = writer_ctx(Form::Commit, kind, ts, author, r.lo, r.hi);
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let mut aw = AspectWrite::new(t, ak.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
    let mut cb = CommitBuilder::new(kind, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    cb.build(&by.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

// spec/permissions.md §3 (lost access): only an unfinalized single-use link race defers a
// loss. Bob, who held invite on D, left on his own; his later grant of Carol (forged past his
// writer rules) is void because he left, yet it is no redemption: once Alice removes Carol,
// Carol drops D's secrets.
#[test]
fn void_grant_by_leaver_keeps_no_secrets_spec_perm_3() {
    let mut lp = net(3, 523);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let inv = osis_schema::core_types::Edge { invite: Some(Role::Read), ..edge(Role::Read) };
    lp.peers[0].engine.grant(&d, &b, &inv).unwrap();
    lp.peers[0].engine.grant(&d, &c, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    lp.peers[1].engine.demote(&d, &osis_node::flows::Demotion { holder: b, new: None, presync: osis_node::flows::PreSync::Synced, retain: None }).unwrap();
    lp.advance(1_000);
    let grant = Value::Map(osis_base::ValueMap::from([(Value::Tid(c), edge(Role::Read).to_value())]));
    let forged = forge_role_commit(&mut lp, 1, d, &ak("roles.0"), &grant, 1 << 40);
    lp.sync_all().unwrap();
    lp.peers[2].engine.ingest(&forged, Vec::new()).unwrap();
    assert!(!lp.peers[2].engine.roster(&d).contains_key(&b), "Bob left");
    lp.advance(1_000);
    lp.peers[0].engine.demote(&d, &osis_node::flows::Demotion { holder: c, new: None, presync: osis_node::flows::PreSync::Synced, retain: None }).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[2].engine.role_on(&d), None);
    lp.peers[2].engine.drop_lost_secrets().unwrap();
    assert!(lp.peers[2].engine.epochs(&d).is_none(), "Carol kept D's secrets");
}

// spec/permissions.md §1 (role-class by admins): a writer's `label.0` write, forged past its own node's writer-side refusal, is invalid where it is received (the
// same write by its author once an admin applies).
#[test]
fn forged_role_class_unmerged_spec_perm_1() {
    use osis_schema::{RawKey, core_types as ct};
    let (mut lp, d, _, _) = setup(49);
    let label = ct::Label { index: 0, steps: BTreeMap::new(), hosts: Vec::new(), replaced: false };
    let labels: ct::Labels = BTreeMap::from([(osis_base::LabelId([5; 16]), label)]);
    let a = ak(ct::LABEL.ak());
    let before = lp.peers[0].engine.get(&d, &a).unwrap();
    let forged = forge_role_commit(&mut lp, 1, d, &a, &labels.to_value(), 1);
    lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &a).unwrap(), before, "a writer's role-class write applied");
    // control: the same write by the same key applies once its author is an admin
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    let honest = forge_role_commit(&mut lp, 1, d, &a, &labels.to_value(), 100);
    lp.peers[0].engine.ingest(&honest, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &a).unwrap(), Some(labels.to_value()));
}

// spec/permissions.md §5.2 (admin-only): a writer's node refuses its write of a `^` aspect,
// durable or ephemeral; one forged past that is invalid at every node, its author's included;
// the same write once its author holds admin applies everywhere
#[test]
fn admin_only_aspect_needs_admin_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(53);
    let key = ak("t:settings.0^");
    let write = |v: &str| {
        let mut m = Mutation::new();
        m.set(d, &key, &s(v)).unwrap();
        m
    };
    assert!(matches!(lp.peers[1].commit(write("bob")), Err(osis_node::Error::Permission { .. })));
    let mut m = Mutation::new();
    m.set(d, &ak("t:settings.0^~"), &s("bob")).unwrap();
    assert!(matches!(lp.peers[1].engine.write(m), Err(osis_node::Error::Permission { .. })), "an ephemeral `^` write refused too");
    lp.advance(1_000);
    let forged = forge_commit(&mut lp, 1, d, &key, &s("bob"), 1, osis_commit::Kind::Content);
    // control: the same forged write on an unmarked key applies
    let plain = ak("t:settings.0");
    let control = forge_commit(&mut lp, 1, d, &plain, &s("bob"), 1, osis_commit::Kind::Content);
    for i in 0..3 {
        lp.peers[i].engine.ingest(&forged, Vec::new()).unwrap();
        lp.peers[i].engine.ingest(&control, Vec::new()).unwrap();
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

// spec/permissions.md §5.1 (a demotion's frontier covers the aspects it puts in question): an
// admin's `^` write the demoter had received stays valid when it demotes that admin to write;
// one it had not received goes
#[test]
fn admin_only_write_covered_by_demotion_frontier_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(57);
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    let (seen, unseen) = (ak("t:seen.0^"), ak("t:unseen.0^"));
    let mut m = Mutation::new();
    m.set(d, &seen, &s("received")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &unseen, &s("offline")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    lp.peers[0].engine.demote(&d, &osis_node::flows::Demotion { holder: b, new: Some(edge(Role::Write)), presync: osis_node::flows::PreSync::Synced, retain: None }).unwrap();
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
    let (mut lp, d, _, _) = setup(58);
    for (k, valid) in [("t:conf.0^", false), ("t:conf.0", true)] {
        let key = ak(k);
        // Alice's write reaches Carol only
        let mut m = Mutation::new();
        m.set(d, &key, &s("alice")).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        sync(&mut lp, 0, 2);
        lp.advance(1_000);
        if !valid {
            assert!(matches!(lp.peers[2].engine.compaction_snapshot(&d, &key), Err(osis_node::Error::Permission { .. })), "the writer's node refuses it");
        }
        let st = lp.peers[2].engine.state(&d, &key).unwrap().unwrap();
        let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
        let snap = forge_snapshot(&mut lp, 2, d, &key, now, st);
        lp.peers[1].engine.ingest(&snap, Vec::new()).unwrap();
        assert_eq!(lp.peers[1].engine.get(&d, &key).unwrap(), valid.then(|| s("alice")), "{k}");
        lp.advance(1_000);
    }
}

// spec/permissions.md §5.2 (a valid compaction snapshot vouches for the writes it carries):
// Alice compacts Bob's edits, then revokes him with a frontier that covers "mon", not "x". The
// snapshot vouches for "x": Alice (holding Bob's commit, invalid now) and Dave (holding only
// the snapshot) keep both, whether the revoke arrives after the snapshot or before it, across a
// restart and a re-grant.
#[test]
fn snapshot_vouches_for_its_writes_spec_perm_5_2() {
    for revoke_first in [false, true] {
        let (mut lp, d, b, _) = setup(47);
        lp.peers.push(osis_node::local_peer::Peer::new(4700, T0).unwrap());
        lp.sync_all().unwrap();
        add_tag(&mut lp, 1, d, "mon");
        sync(&mut lp, 1, 0);
        let mon = lp.peers[1].engine.commit_ids().into_iter().filter(|c| lp.peers[1].engine.header(c).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).max_by_key(|c| lp.peers[1].engine.header(c).unwrap().ts).unwrap();
        lp.advance(DAY);
        add_tag(&mut lp, 1, d, "x");
        sync(&mut lp, 1, 0);
        let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        lp.advance(DAY);
        // a frontier holding "mon" only
        let f = osis_schema::core_types::Frontier { commits: BTreeSet::from([mon]) };
        let rv = set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
        let both = BTreeSet::from(["mon".to_string(), "x".to_string()]);
        assert_eq!(tags(&mut lp, 0, d), both, "Alice: the snapshot vouches for x");
        // Dave: everything of Alice's but Bob's own commits
        let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
        let (late, early): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| if revoke_first { p.id == snap } else { p.id == rv });
        for pk in early.iter().chain(&late) {
            lp.deliver(3, pk).unwrap();
        }
        lp.peers[3].engine.reexamine().unwrap();
        assert!(lp.peers[3].engine.header(&snap).is_some(), "the snapshot applied");
        assert!(lp.peers[3].engine.header(&mon).is_none(), "Bob's own commit is not held");
        assert_eq!(tags(&mut lp, 3, d), both, "revoke first: {revoke_first}");
        lp.peers[3].restart(5).unwrap();
        assert_eq!(tags(&mut lp, 3, d), both, "after a restart");
        lp.advance(DAY);
        let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == g).unwrap();
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
    h.form.own_source(h.author, *c)
}

/// Frontiers of one session source.
fn frontier_of(src: &osis_crdt::Source, ctr: u64) -> osis_crdt::Frontiers {
    let mut fr = osis_crdt::Frontiers::default();
    assert!(fr.insert(src, ctr));
    fr
}

// spec/permissions.md §5.2 (a valid snapshot vouches for the writes it carries, and its copy
// governs a held delta's write): a writer's snapshot carrying two entries under Bob's dots dated
// before his grant shows them (nothing judges them as Bob's), with the owner's write it
// carries; one copying a dot of Bob's held commit otherwise replaces Bob's entry.
#[test]
fn writer_snapshot_vouches_spec_perm_5_2() {
    let (mut lp, d, _, _) = setup(53);
    let m_ak = ak("x:m.0");
    let mut m = Mutation::new();
    m.set(d, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("bob"))]))).unwrap();
    let real = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let lo = lp.peers[1].engine.header(&real).unwrap().aspects[0].lo;
    let bs = source_of(&lp, 1, &real);
    assert!(lo >= 1, "room for a forged counter below Bob's");
    let entries = |lp: &mut LocalPeer| match lp.peers[0].engine.get(&d, &m_ak).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    assert_eq!(entries(&mut lp), BTreeSet::from([s("k")]));
    lp.advance(1_000);
    let old = osis_base::Ts::make(WallMs(T0.0 - DAY), 0).unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    // a carried ts for a dot of a held commit other than its own: the held delta gives that dot
    let clash = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(bs.clone(), old, lo, "f0", "x"));
    lp.peers[0].engine.ingest(&clash, Vec::new()).unwrap();
    assert_eq!(entries(&mut lp), BTreeSet::from([s("f0")]), "a copy of a held write at another ts");
    let mut f = entry_by(bs.clone(), old, 1 << 39, "f1", "x");
    f.join(entry_by(bs.clone(), old, 1 << 40, "f2", "y"));
    // and a valid write of Alice's (the snapshot applies)
    let a = lp.peers[0].engine.tid();
    f.join(entry_by(crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32])), now, 1 << 42, "c", "alice"));
    let snap = forge_snapshot(&mut lp, 2, d, &m_ak, now, f);
    lp.peers[0].engine.ingest(&snap, Vec::new()).unwrap();
    let want = BTreeSet::from([s("f0"), s("c"), s("f1"), s("f2")]);
    assert_eq!(entries(&mut lp), want, "the writer's carried writes count");
    lp.peers[0].restart(53).unwrap();
    assert_eq!(entries(&mut lp), want, "after a restart");
}

// spec/crdt.md §8, §2.2: a snapshot carrying a write stamped after the snapshot's own `ts` is bad
// input (so a node's next stamp exceeds every stamp it holds); one stamped at it applies.
#[test]
fn snapshot_future_stamp_refused_spec_crdt_8() {
    let (mut lp, d, _, _) = setup(57);
    let m_ak = ak("x:m.0");
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let later = osis_base::Ts::make(WallMs(lp.peers[2].engine.now().0 + 1_000), 0).unwrap();
    let a = lp.peers[0].engine.tid();
    let asrc = crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32]));
    let bad = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(asrc.clone(), later, 1 << 42, "c", "x"));
    assert_eq!(lp.peers[0].engine.ingest(&bad, Vec::new()).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    let ok = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(asrc, now, 1 << 42, "c", "x"));
    lp.peers[0].engine.ingest(&ok, Vec::new()).unwrap();
}

// spec/permissions.md §5.2 (a valid snapshot vouches for the writes it carries): Dave holds
// Bob's tag only inside Alice's compaction snapshot, which arrives before Bob's grant: the
// write shows at once, its index persisted equals a rebuild from the commit records, and it
// stays once the grant arrives, across a restart.
#[test]
fn snapshot_before_grant_counts_spec_perm_5_2() {
    let mut lp = net(2, 57);
    lp.peers.push(osis_node::local_peer::Peer::new(5700, T0).unwrap());
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    add_tag(&mut lp, 1, d, "x");
    sync(&mut lp, 1, 0);
    lp.advance(DAY);
    let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    // Dave: Alice's commits but the grant, then the grant
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
    let (holders, content): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| p.id == g);
    for pk in &content {
        lp.deliver(2, pk).unwrap();
    }
    lp.peers[2].engine.reexamine().unwrap();
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
    lp.peers[2].engine.reexamine().unwrap();
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
    let (mut lp, d, _, c) = setup(59);
    lp.peers.push(osis_node::local_peer::Peer::new(5900, T0).unwrap());
    add_tag(&mut lp, 0, d, "alice");
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    lp.advance(DAY);
    let st = lp.peers[0].engine.state(&d, &ak("t:tags.0")).unwrap().unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let snap = forge_snapshot(&mut lp, 2, d, &ak("t:tags.0"), now, st);
    lp.peers[2].engine.ingest(&snap, Vec::new()).unwrap();
    lp.sync_all().unwrap();
    lp.advance(DAY);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    lp.sync_all().unwrap();
    let want = BTreeSet::from(["alice".to_string(), "bob".to_string()]);
    assert_eq!(tags(&mut lp, 0, d), want);
    assert_eq!(tags(&mut lp, 3, d), want, "a fresh node reads the same");
    assert_eq!(lp.peers[3].engine.state(&d, &ak("t:tags.0")).unwrap(), lp.peers[0].engine.state(&d, &ak("t:tags.0")).unwrap());
}

fn put_at(lp: &mut LocalPeer, i: usize, t: Tid, path: &[&str], v: Value) {
    let mut m = Mutation::new();
    let path = path.iter().map(|k| osis_crdt::PathSeg::Key(s(k))).collect();
    m.op(t, &ak("x:m.0"), osis_crdt::PathOp { path, op: osis_crdt::Op::Set(v) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap();
}

// spec/permissions.md §5.2 (a valid snapshot vouches for the writes it carries; owner
// decision, notes/mvp-progress.md round 13 "Snapshots vouch"): Bob, removed, creates entries
// "early" and "late" offline; Carol, not yet aware, writes inside "late" and compacts. Her
// snapshot vouches for Bob's entries: Dave, holding only Alice's and Carol's commits, and Alice,
// who also holds Bob's commit (invalid), both keep them with Carol's write.
#[test]
fn entry_created_after_demotion_spec_perm_5_2() {
    entry_created_after_demotion(true);
}

// spec/crdt.md §4.6 (un-merge is a function of the held set), spec/permissions.md §5.2: as
// `entry_created_after_demotion_spec_perm_5_2`, with Dave receiving Carol's write inside "late"
// before her snapshot (dated after it, as spec/crdt.md §8 requires): alike.
#[test]
fn entry_created_after_demotion_write_first_spec_perm_5_1() {
    entry_created_after_demotion(false);
}

fn entry_created_after_demotion(snapshot_first: bool) {
    let (mut lp, d, b, _) = setup(61);
    lp.peers.push(osis_node::local_peer::Peer::new(6100, T0).unwrap());
    lp.sync_all().unwrap();
    let one = |k: &str, v: &str| Value::Map(osis_base::ValueMap::from([(s(k), s(v))]));
    put_at(&mut lp, 1, d, &["k"], one("a", "1"));
    lp.sync_all().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    lp.advance(DAY);
    // one commit, two entries: "late" is its second creation (its dot is no stamp of the commit)
    let mut m = Mutation::new();
    for k in ["early", "late"] {
        m.op(d, &ak("x:m.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(one("a", "1")) }).unwrap();
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
    let snap_id = match lp.peers[2].engine.ingest(&snap, Vec::new()).unwrap() { osis_node::Ingested::Applied(id) => id, x => panic!("{x:?}") };
    // Dave: Alice's and Carol's commits (the snapshot among them), none of Bob's
    for from in [0, 2] {
        let mut pks: Vec<_> = packages(&mut lp, from).into_iter().filter(|p| lp.peers[from].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
        if snapshot_first {
            pks.sort_by_key(|p| p.id != snap_id);
        }
        for pk in &pks {
            lp.deliver(3, pk).unwrap();
        }
    }
    lp.peers[3].engine.reexamine().unwrap();
    sync(&mut lp, 1, 0);
    sync(&mut lp, 2, 0);
    let keys = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&d, &ak("x:m.0")).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    let want = BTreeSet::from([s("early"), s("k"), s("late")]);
    assert_eq!(keys(&mut lp, 0), want, "Alice");
    assert_eq!(keys(&mut lp, 3), want, "Dave");
    let read = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get(&d, &ak("x:m.0")).unwrap();
    assert_eq!(read(&mut lp, 0), read(&mut lp, 3), "Carol's write inside late too");
    lp.peers[3].engine.rebuild_state(&d, &ak("x:m.0")).unwrap();
    assert_eq!(read(&mut lp, 0), read(&mut lp, 3), "Dave, rebuilt");
}

// spec/crdt.md §4.6 (a record whose creation a valid snapshot's copy keeps stays with the
// valid writes nested in it), spec/permissions.md §5.2 (misstated copies): Bob, removed, creates
// entry "late" offline; Carol writes inside it, then sends a snapshot carrying Bob's creation
// under another key ("evil"). Bob's record ("late") has no creation left anywhere, so Carol's
// write nested in it goes with his un-merged writes; the snapshot's own record stays.
#[test]
fn misstated_copy_keeps_no_other_record_spec_crdt_4_6() {
    let (mut lp, d, b, _) = setup(65);
    lp.peers.push(osis_node::local_peer::Peer::new(6500, T0).unwrap());
    lp.sync_all().unwrap();
    let one = |k: &str, v: &str| Value::Map(osis_base::ValueMap::from([(s(k), s(v))]));
    put_at(&mut lp, 1, d, &["k"], one("a", "1"));
    lp.sync_all().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    lp.advance(DAY);
    put_at(&mut lp, 1, d, &["late"], one("a", "1"));
    let late = *lp.peers[1].engine.commit_ids().iter().max_by_key(|id| lp.peers[1].engine.header(id).unwrap().ts).unwrap();
    let h = lp.peers[1].engine.header(&late).unwrap();
    let lo = h.aspects.iter().find(|x| x.ak.as_str() == "x:m.0").unwrap().lo;
    sync(&mut lp, 1, 2);
    put_at(&mut lp, 2, d, &["late", "b"], s("2"));
    lp.advance(1);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let snap = forge_snapshot(&mut lp, 2, d, &ak("x:m.0"), now, entry_by(h.form.own_source(b, osis_base::CommitId([0; 32])), h.ts, lo, "evil", "x"));
    lp.peers[2].engine.ingest(&snap, Vec::new()).unwrap();
    let keys = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&d, &ak("x:m.0")).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    let want = BTreeSet::from([s("evil"), s("k")]);
    // Dave: everything, the snapshot first or last
    for (i, snap_first) in [(3, true), (0, false)] {
        let mut pks: Vec<_> = [0, 1, 2].into_iter().flat_map(|from| packages(&mut lp, from)).collect();
        pks.sort_by_key(|p| (p.bytes != snap) == snap_first);
        for pk in &pks {
            lp.deliver(i, pk).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        assert_eq!(keys(&mut lp, i), want, "peer {i}");
        lp.peers[i].engine.rebuild_state(&d, &ak("x:m.0")).unwrap();
        assert_eq!(keys(&mut lp, i), want, "peer {i}, rebuilt");
    }
}

// spec/permissions.md §5.2: commit-form writes a valid snapshot carries count: nothing judges
// them per author.
#[test]
fn commit_form_carried_writes_vouched_spec_perm_5_2() {
    let (mut lp, d, _, _) = setup(63);
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
    let keys = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&d, &m_ak).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    let missing = forge_snapshot(&mut lp, 2, d, &m_ak, now, f);
    lp.peers[0].engine.ingest(&missing, Vec::new()).unwrap();
    assert_eq!(keys(&mut lp, 0), BTreeSet::from([s("alice"), s("bob")]));
}

/// Delivers commits `ids` of peer `from` to peer `to`.
fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[osis_base::CommitId]) {
    for id in ids {
        let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
        lp.deliver(to, &pk).unwrap();
    }
}

// spec/permissions.md §5.1 step 4 (D only grows): osis-perm joint neutrality seed 6's shape
// (notes/permissions.md, sticky residue). n0 removes A2 from A0 (W, unseen by n1) and grants n1
// write on A2 (G, unseen too); n1 lowers A1 to write on A0 (R). The full walk drops W (R is a
// fall on A0 while W stands) and keeps it dropped after R stops being one; G stands, n0 keeping
// admin on A2 through A1 (one class: a path lost while another keeps it is no fall).
#[test]
fn sticky_residue_spec_perm_5_1() {
    let mut lp = net(3, 61);
    lp.sync_all().unwrap();
    let (n0, n1) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    // A0 owned by n1, A1 by n0, A2 by A0; A1 admin on A0, A2 write on A1
    let a0 = new_thing(&mut lp, 1);
    let a1 = new_thing(&mut lp, 0);
    let a2 = {
        let mut m = Mutation::new();
        let t = lp.peers[1].engine.new_thing(&mut m, a0);
        m.set(t, &REG, &s("a2")).unwrap();
        lp.peers[1].commit(m).unwrap();
        t
    };
    set_edge(&mut lp.peers[1].engine, a0, a1, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    set_edge(&mut lp.peers[0].engine, a1, a2, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    // n0 through A1: A2 admin on A0, then removed (W); n1 write on A2 (G); A1 admin on A2
    let step = |lp: &mut LocalPeer| lp.advance(1000);
    step(&mut lp);
    let c1 = set_edge(&mut lp.peers[0].engine, a0, a2, Some(edge(Role::Admin)), None);
    step(&mut lp);
    set_edge(&mut lp.peers[0].engine, a0, a2, None, None);
    step(&mut lp);
    set_edge(&mut lp.peers[0].engine, a2, n1, Some(edge(Role::Write)), None);
    step(&mut lp);
    let c6 = set_edge(&mut lp.peers[0].engine, a2, a1, Some(edge(Role::Admin)), None);
    // n1 has c1 and c6, not W or G, when it lowers A1 to write on A0 (R)
    send(&mut lp, 0, 1, &[c1, c6]);
    step(&mut lp);
    let scope = DemotionScope { roles: BTreeMap::from([(n0, BTreeSet::from([a0, a2]))]), content: BTreeMap::new() };
    let now = lp.peers[1].engine.now();
    let f = lp.peers[1].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[1].engine, a0, a1, Some(edge(Role::Write)), Some(f.to_value()));
    // nodes A (2) and B (1) hold the full history
    for i in [1, 2] {
        sync(&mut lp, 0, i);
        sync(&mut lp, 1, i);
    }
    let has_g = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&a2).contains_key(&n1);
    assert!(lp.peers[2].engine.roster(&a0).contains_key(&a2), "W dropped: A2 stays admin on A0");
    assert!(has_g(&lp, 2) && has_g(&lp, 1), "G stands: no fall on A2");
}

fn write_reg(lp: &mut LocalPeer, i: usize, t: Tid, v: &str) -> osis_node::Result<Option<osis_base::CommitId>> {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    lp.peers[i].commit(m)
}

// spec/permissions.md §1 (paths climb owner links and edges), §4 (chain certificates): n0 owns
// A, A writes B, B admin of C (n1 owns B and C). n0's write on C applies at n0 and a receiver; a
// node with no path may not write C. A fresh receiver given n0's certificates for C but A's
// `created.0` (the owner-link step) keeps the write pending on n0's chain until it arrives.
#[test]
fn owner_then_edge_chain_applies_spec_perm_1() {
    let mut lp = net(3, 62);
    lp.sync_all().unwrap();
    let n0 = lp.peers[0].engine.tid();
    let a = new_thing(&mut lp, 0);
    let b = new_thing(&mut lp, 1);
    let c = new_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    let ab = set_edge(&mut lp.peers[1].engine, b, a, Some(edge(Role::Write)), None);
    let bc = set_edge(&mut lp.peers[1].engine, c, b, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    assert!(write_reg(&mut lp, 2, c, "n2").is_err(), "no path: no write");
    let w = write_reg(&mut lp, 0, c, "n0").unwrap().unwrap();
    sync(&mut lp, 0, 2);
    for i in [0, 2] {
        assert_eq!(lp.peers[i].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")), "peer {i}");
    }
    // the certificates carry the edges and A's `created.0`
    let certs = lp.peers[0].engine.certificates(&c);
    let created = |e: &osis_node::Engine, id: &osis_base::CommitId, t: Tid| e.header(id).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "created.0"));
    let a_rec = *certs.keys().find(|id| created(&lp.peers[0].engine, id, a)).expect("A's created.0 certified");
    assert!(certs.contains_key(&ab) && certs.contains_key(&bc));
    let mut fresh = net(1, 63);
    for id in certs.keys().filter(|id| **id != a_rec) {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        fresh.deliver(0, &pk).unwrap();
    }
    let pk = lp.peers[0].engine.package(&w).unwrap().unwrap();
    let r = fresh.deliver(0, &pk).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(x)) if x == n0), "{r:?}");
    let pk = lp.peers[0].engine.package(&a_rec).unwrap().unwrap();
    fresh.deliver(0, &pk).unwrap();
    assert!(fresh.peers[0].engine.pending().is_empty());
    assert_eq!(fresh.peers[0].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")));
}

// spec/permissions.md §1 (`MAX_OWNER_DEPTH`): n0 owns a chain of things down to one link past
// the cap. Owner links count on a path as perm's effective role counts them: an edge on C to
// the thing at the cap or past it lets n0 write C, and the write applies at n0 and a receiver.
#[test]
fn owner_chain_depth_edge_chain_spec_perm_1() {
    use osis_base::format::MAX_OWNER_DEPTH;
    let mut lp = net(3, 64);
    lp.sync_all().unwrap();
    let mut owner = lp.peers[0].engine.tid();
    let mut chain = Vec::new();
    for _ in 0..=MAX_OWNER_DEPTH {
        let mut m = Mutation::new();
        owner = lp.peers[0].engine.new_thing(&mut m, owner);
        lp.peers[0].commit(m).unwrap();
        chain.push(owner);
    }
    let (at_cap, past) = (chain[MAX_OWNER_DEPTH - 1], chain[MAX_OWNER_DEPTH]);
    for (k, holder) in [at_cap, past].into_iter().enumerate() {
        let c = new_thing(&mut lp, 1);
        lp.sync_all().unwrap();
        set_edge(&mut lp.peers[1].engine, c, holder, Some(edge(Role::Admin)), None);
        lp.sync_all().unwrap();
        write_reg(&mut lp, 0, c, "n0").unwrap().unwrap();
        sync(&mut lp, 0, 2);
        for i in [0, 2] {
            assert_eq!(lp.peers[i].engine.get(&c, &ak("t:reg.0")).unwrap(), Some(s("n0")), "case {k} peer {i}");
        }
    }
}

// spec/permissions.md §1, §4: n0 reaches C only through edges n0 -> G1 -> G2 -> C while it
// owns thousands of things that own more (more than any walk-size cap): its write on C
// applies (the chain search goes backward from C, never through n0's owned things).
#[test]
#[ignore = "tier 2"]
fn chain_found_past_owned_flood_spec_perm_4() {
    let mut lp = net(2, 77);
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
fn index_of(e: &osis_node::Engine) -> osis_node::engine::IndexDigest {
    e.index_digest().without_held()
}

// spec/permissions.md §2 (an edge change is remove + put): a write inside a holder's entry
// is refused, so field changes cannot compose (was: a change adding `until`, then one raising
// the role, left an admin edge with no `until`); written as remove + put, each change is the
// whole edge.
#[test]
fn edge_change_is_remove_and_put_spec_perm_2() {
    let mut lp = net(2, 67);
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
    let path = vec![osis_crdt::PathSeg::Key(Value::Tid(c))];
    m.op(d, &osis_schema::core_types::ROLES, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(edge(Role::Admin).to_value()) }).unwrap();
    assert_eq!(lp.peers[0].engine.commit(m).unwrap_err().class(), osis_base::ErrorClass::BadInput);
    set_edge(&mut lp.peers[0].engine, d, c, Some(osis_schema::core_types::Edge { until, ..edge(Role::Admin) }), None);
    let e = lp.peers[0].engine.roster(&d).get(&c).cloned().unwrap();
    assert_eq!((e.role, e.until), (Role::Admin, until));
}

/// Account actors for `lp`'s peers, known to all.
fn persons(lp: &mut LocalPeer) -> Vec<Tid> {
    let hosts = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
    let ps = (0..lp.peers.len()).map(|i| lp.peers[i].engine.create_person(&hosts).unwrap().0.person).collect();
    lp.sync_all().unwrap();
    ps
}

/// Hands `done`'s inbox blobs to every other peer.
fn carry(lp: &mut LocalPeer, from: usize, done: &osis_node::flows::Done) {
    for d in &done.deliveries {
        if let osis_node::flows::Delivery::Inbox { blob, .. } = d {
            for i in (0..lp.peers.len()).filter(|i| *i != from) {
                let _ = lp.peers[i].engine.accept_inbox(blob);
            }
        }
    }
}

// spec/permissions.md §2, §5.1: C grants B write; A removes C with a frontier that misses the
// grant, so the walk drops it, but its entry stays live in the `roles.0` state. A grants B
// again (same role or another): the grant resets that entry and puts a new one, and B reads its
// edge (was: the grant flow diffed into the dropped entry: nothing, or a field write B never
// resolved).
#[test]
fn regrant_over_dropped_entry_spec_perm_2() {
    for again in [Role::Write, Role::Admin] {
        use osis_node::flows::{Demotion, PreSync};
        let mut lp = net(3, 71);
        let ps = persons(&mut lp);
        let (pb, pc) = (ps[1], ps[2]);
        let mut m = Mutation::new();
        let d = lp.peers[0].engine.new_thing(&mut m, ps[0]);
        m.set(d, &REG, &s("x")).unwrap();
        lp.peers[0].commit(m).unwrap();
        let done = lp.peers[0].engine.grant(&d, &pc, &edge(Role::Admin)).unwrap();
        carry(&mut lp, 0, &done);
        lp.sync_all().unwrap();
        lp.advance(10);
        let g = lp.peers[2].engine.grant(&d, &pb, &edge(Role::Write)).unwrap().commits;
        lp.advance(10);
        let done = lp.peers[0].engine.demote(&d, &Demotion { holder: pc, new: None, presync: PreSync::Synced, retain: None }).unwrap();
        carry(&mut lp, 0, &done);
        lp.advance(10);
        // A holds the dropped grant; B never does
        send(&mut lp, 2, 0, &g);
        assert_eq!(lp.peers[0].engine.roster(&d).get(&pb), None, "the grant is dropped");
        lp.advance(10);
        let done = lp.peers[0].engine.grant(&d, &pb, &edge(again)).unwrap();
        carry(&mut lp, 0, &done);
        let ids: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !g.contains(c)).collect();
        send(&mut lp, 0, 1, &ids);
        assert_eq!(lp.peers[0].engine.roster(&d).get(&pb).map(|e| e.role), Some(again), "at A");
        assert_eq!(lp.peers[1].engine.roster(&d).get(&pb).map(|e| e.role), Some(again), "at B");
    }
}

// spec/permissions.md §5 (a function of the commits held), §5.2: two snapshots carrying Bob's
// writes without his commit, held in either order, are recorded alike (was: the carried groups
// were listed in arrival order, so the persisted index differed).
#[test]
fn carried_writes_recorded_alike_in_any_order_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(69);
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let tags = ak("t:tags.0");
    let x = lp.peers[0].engine.snapshot(&d, &tags).unwrap().unwrap();
    let y = lp.peers[2].engine.snapshot(&d, &tags).unwrap().unwrap();
    lp.sync_all().unwrap();
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
    let mut seen = Vec::new();
    for flip in [false, true] {
        let mut p = osis_node::local_peer::Peer::new(6900, lp.peers[0].engine.now()).unwrap();
        let mut order: Vec<_> = pks.iter().filter(|p| p.id != x && p.id != y).collect();
        let (s1, s2) = if flip { (y, x) } else { (x, y) };
        order.extend(pks.iter().filter(|p| p.id == s1).chain(pks.iter().filter(|p| p.id == s2)));
        for pk in order {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        assert!(!p.engine.index_digest().carried.is_empty(), "the writes are carried");
        seen.push(index_of(&p.engine));
    }
    assert_eq!(seen[0], seen[1]);
}

// spec/crdt.md §4.6, spec/permissions.md §5.2, spec/requirements.md Decentralization: paged
// states (a map, a set, a map in a struct field, a text, a list) where B's writes land on random
// pages, some overwriting and deleting A's, and A writes under B's creations (a value in B's
// entry, chars after B's); C, who never saw B's writes, revokes B. A's un-merge (a rebuild per
// flipped aspect) equals a fresh node given everything with B's writes last (B's text records
// arriving invalid kept as hidden anchors there too), before and after a restart, reads by
// range included; nothing B wrote reads. Tier 2 (about 7 s: a paged text's join per element under
// the rebuild check); the engine's `tests_paged` un-merge paged collections in tier 1.
#[test]
#[ignore = "tier 2"]
fn unmerge_paged_matches_fresh_spec_crdt_4_6() {
    use osis_crdt::{Op, PathOp, PathSeg};
    {
        // each aspect's state past `PAGE_TARGET`, so it pages
        const N: usize = 140;
        const CHARS: usize = 17_000;
        let (mut lp, d, b, _) = setup(81);
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
        let mut x = 0x9e37_79b9_7f4a_7c14u64;
        let mut r = |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n.max(1) as u64) as usize
        };
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
        let scope = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
        let now = lp.peers[2].engine.now();
        let f = lp.peers[2].engine.frontier(&scope, now).unwrap();
        let rv = set_edge(&mut lp.peers[2].engine, d, b, None, Some(f.to_value()));
        let pk = packages(&mut lp, 2).into_iter().find(|p| p.id == rv).unwrap();
        osis_node::costs::take();
        lp.deliver(0, &pk).unwrap();
        let costs = osis_node::costs::take();
        let n = |k: &str| costs.iter().find(|c| c.0 == k).map_or(0, |c| c.2);
        assert_eq!(n("rejudge: rebuild"), 5, "one rebuild per flipped aspect");
        // the fresh node: B's writes last
        let pks = packages(&mut lp, 0);
        let is_b = |lp: &LocalPeer, id: &osis_base::CommitId| lp.peers[0].engine.header(id).is_some_and(|h| h.author == b && !is_role(&lp.peers[0].engine, id));
        let mut fresh = osis_node::local_peer::Peer::new(8001, lp.peers[0].engine.now()).unwrap();
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

// spec/crdt.md §4.6 (un-merge is a function of the held set), spec/commits.md §4 (a late
// delta joins on arrival): Bob, removed, puts entry "late", text "BB" and a register in one
// commit; Carol writes inside "late" and between Bob's chars. Dave gets Bob's commit with only
// its register part, the rest later, Carol's commit anywhere among them: Carol's map write goes
// with Bob's creation and Bob's chars stay hidden anchors, as at Eve, who held Bob's commit
// whole before Carol's; a node never getting the rest agrees with itself in either order.
#[test]
fn late_invalid_part_unmerges_alike_spec_crdt_4_6() {
    let (mut lp, d, b, _) = setup(91);
    lp.peers.push(osis_node::local_peer::Peer::new(9100, T0).unwrap());
    lp.peers.push(osis_node::local_peer::Peer::new(9101, T0).unwrap());
    let u = new_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    let one = |k: &str, v: &str| Value::Map(osis_base::ValueMap::from([(s(k), s(v))]));
    put_at(&mut lp, 1, d, &["k"], one("a", "1"));
    lp.sync_all().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    lp.advance(DAY);
    let mut m = Mutation::new();
    m.op(d, &ak("x:m.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("late"))], op: osis_crdt::Op::Set(one("a", "1")) }).unwrap();
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
    let base: Vec<_> = packages(&mut lp, 0);
    let ck = lp.peers[1].engine.package(&c).unwrap().unwrap();
    let nk = lp.peers[2].engine.package(&n).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&c).unwrap();
    let mut partial = osis_commit::CommitBlob::decode(&ck.bytes).unwrap();
    let mut elsewhere = partial.clone();
    partial.parts.retain(|p| h.aspects[p.ai].ak.as_str() == "t:reg.0" && h.aspects[p.ai].tid == d);
    elsewhere.parts.retain(|p| h.aspects[p.ai].tid == u);
    let (partial, elsewhere) = (partial.encode(), elsewhere.encode());
    let feed = |lp: &mut LocalPeer, i: usize, seq: &[&[u8]]| {
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        for bytes in seq {
            lp.peers[i].engine.ingest(bytes, Vec::new()).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
    };
    feed(&mut lp, 4, &[&ck.bytes, &nk.bytes]);
    let look = |lp: &mut LocalPeer, i: usize| {
        let e = &mut lp.peers[i].engine;
        let mut out = Vec::new();
        for a in [ak("x:m.0"), ak("t:reg.0"), ak("t:text.0")] {
            out.push(format!("{:?}\n{:?}", e.get(&d, &a).unwrap(), e.state(&d, &a).unwrap()));
        }
        // the invalid index and Bob's and Carol's commits (each node has its own identity)
        let ix = index_of(e);
        out.push(format!("{}\n{:?}\n{:?}", ix.tables["invalid"], ix.commits.get(&c), ix.commits.get(&n)));
        out
    };
    let want = look(&mut lp, 4);
    assert!(!want[0].contains("late"), "Eve: {}", want[0]);
    let orders: [&[&[u8]]; 3] = [&[&nk.bytes, &partial, &ck.bytes], &[&partial, &nk.bytes, &ck.bytes], &[&partial, &ck.bytes, &nk.bytes]];
    for (k, seq) in orders.iter().enumerate() {
        let i = lp.peers.len();
        let now = lp.peers[0].engine.now();
        lp.peers.push(osis_node::local_peer::Peer::new(9200 + k as u64, now).unwrap());
        feed(&mut lp, i, seq);
        assert_eq!(look(&mut lp, i), want, "order {k}");
    }
    // the map and text parts never come: alike either way too: the removal leaves them invalid, so
    // nothing waits for them (spec/commits.md §4) and Carol's map write goes with the commit
    let mut seen = Vec::new();
    for (k, seq) in [[&nk.bytes, &partial], [&partial, &nk.bytes]].iter().enumerate() {
        let i = lp.peers.len();
        let now = lp.peers[0].engine.now();
        lp.peers.push(osis_node::local_peer::Peer::new(9300 + k as u64, now).unwrap());
        feed(&mut lp, i, &seq.map(|x| x.as_slice()));
        seen.push(look(&mut lp, i));
    }
    assert_eq!(seen[0], seen[1], "partial");
    assert!(!seen[0][0].contains("late"), "partial: {}", seen[0][0]);
    // none of its parts on the thing comes, the one on another thing does: the commit is applied
    // from its header's word on the thing, alike either way, Carol's map write going with it
    let mut seen = Vec::new();
    for (k, seq) in [[&nk.bytes, &elsewhere], [&elsewhere, &nk.bytes]].iter().enumerate() {
        let i = lp.peers.len();
        let now = lp.peers[0].engine.now();
        lp.peers.push(osis_node::local_peer::Peer::new(9400 + k as u64, now).unwrap());
        feed(&mut lp, i, &seq.map(|x| x.as_slice()));
        seen.push(look(&mut lp, i));
    }
    assert_eq!(seen[0], seen[1], "elsewhere");
    assert!(!seen[0][0].contains("late"), "elsewhere: {}", seen[0][0]);
}

// spec/permissions.md §5.2 (a snapshot is trusted for what the content is now, never for who
// wrote it or when; Tess's decision, notes/permissions.md Snapshots and history): Bob writes "real" (commit C); Carol,
// a writer, sends a snapshot carrying C's dot and `ts` with "zzz forged". A node holding C (after
// or before the snapshot) and one holding only the snapshot read the same: the snapshot's copy.
// Only the holders of C attribute a change to Bob, and the change the snapshot made at C's
// holder is the snapshot's (its author, its ID); C's holder reports the misstatement. Carol's
// removal with a frontier not listing the snapshot restores "real" where C is held and the
// earlier value where it is not.
#[test]
fn forged_copy_governs_held_original_alike_spec_perm_5_2() {
    use osis_crdt::{Writer, create};
    let (mut lp, d, b, c) = setup(0x5fc0);
    let base = packages(&mut lp, 0);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("real")).unwrap();
    let real = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    sync(&mut lp, 1, 2);
    let h = lp.peers[1].engine.header(&real).unwrap();
    let reg = ak("t:reg.0");
    let lo = h.aspects.iter().find(|x| x.tid == d && x.ak == reg).unwrap().lo;
    let mut w = Writer::new(h.ts, h.form.own_source(b, osis_base::CommitId([0; 32])), lo);
    let f = create(&mut w, &osis_crdt::AnyView, &s("zzz forged")).unwrap();
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let forged = forge_snapshot(&mut lp, 2, d, &reg, now, f);
    let rpk = packages(&mut lp, 1).into_iter().find(|p| p.id == real).unwrap();
    // peers 3, 4: C then the snapshot, the other way round; peer 5: the snapshot alone
    let mut fid = None;
    for (i, real_first) in [(3, Some(true)), (4, Some(false)), (5, None)] {
        lp.peers.push(osis_node::local_peer::Peer::new(0x5fc1 + i as u64, lp.peers[0].engine.now()).unwrap());
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        if real_first == Some(true) {
            lp.deliver(i, &rpk).unwrap();
        }
        lp.peers[i].drain_events();
        match lp.peers[i].engine.ingest(&forged, Vec::new()).unwrap() {
            Ingested::Applied(id) => fid = Some(id),
            other => panic!("{other:?}"),
        }
        let evs = lp.peers[i].drain_events();
        if real_first == Some(true) {
            assert!(evs.iter().any(|e| matches!(e, Event::Applied { id, author, changed, .. } if Some(*id) == fid && *author == c && changed.contains(&(d, reg.clone())))), "peer {i}: the change is the snapshot's: {evs:?}");
            assert!(evs.iter().any(|e| matches!(e, Event::Diagnostic(x) if x.kind == osis_node::DiagnosticKind::Misstated && x.commit == fid && x.peer == Some(c))), "peer {i}: reported: {evs:?}");
        }
        if real_first == Some(false) {
            lp.deliver(i, &rpk).unwrap();
            assert!(lp.peers[i].drain_events().iter().any(|e| matches!(e, Event::Diagnostic(x) if x.kind == osis_node::DiagnosticKind::Misstated && x.commit == fid)), "peer {i}: reported");
        }
        lp.peers[i].engine.reexamine().unwrap();
        assert_eq!(lp.peers[i].engine.get(&d, &reg).unwrap(), Some(s("zzz forged")), "peer {i}");
        // history: from verified commits only
        let e = &lp.peers[i].engine;
        let by_bob = e.held_commits(Some(&[(d, reg.clone())])).iter().any(|x| x.header.author == b);
        assert_eq!(by_bob, real_first.is_some(), "peer {i}: Bob's commit listed only where held");
        let ch = e.changed(&d).unwrap();
        assert_eq!(ch.commit == Some(real), real_first.is_some(), "peer {i}: last change");
        assert!(ch.node != c, "peer {i}: a snapshot is no change");
    }
    assert_eq!(lp.peers[3].engine.state(&d, &reg).unwrap(), lp.peers[5].engine.state(&d, &reg).unwrap(), "states alike");
    lp.peers[3].restart(0x5fd0).unwrap();
    assert_eq!(lp.peers[3].engine.get(&d, &reg).unwrap(), Some(s("zzz forged")), "after a restart");
    // Carol removed, the snapshot not in the frontier: it gives nothing
    let scope = DemotionScope { roles: BTreeMap::from([(c, BTreeSet::from([d]))]), content: BTreeMap::from([(c, BTreeSet::from([d]))]) };
    let at = lp.peers[0].engine.now();
    let mut fr = lp.peers[0].engine.frontier(&scope, at).unwrap();
    fr.commits.remove(&fid.unwrap());
    let rv = set_edge(&mut lp.peers[0].engine, d, c, None, Some(fr.to_value()));
    let rv = packages(&mut lp, 0).into_iter().find(|p| p.id == rv).unwrap();
    for (i, want) in [(3, Some(s("real"))), (4, Some(s("real"))), (5, Some(s("new")))] {
        lp.deliver(i, &rv).unwrap();
        lp.peers[i].engine.reexamine().unwrap();
        assert_eq!(lp.peers[i].engine.get(&d, &reg).unwrap(), want, "peer {i}, Carol removed");
    }
}

// spec/permissions.md §5.2 (a value-less copy of a held delta's write without expiry misstates
// it; reported only otherwise): Carol's snapshot carries Bob's held write value-less, as an
// honest one taken after a purge not yet seen here would. Its copy governs (the value goes at
// the holder, as where Bob's commit is not held) and no misstatement is reported.
#[test]
fn valueless_copy_governs_unreported_spec_perm_5_2() {
    use osis_crdt::{Writer, create};
    let (mut lp, d, b, _) = setup(0x5fe0);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &REG, &s("real")).unwrap();
    let real = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let h = lp.peers[1].engine.header(&real).unwrap();
    let reg = ak("t:reg.0");
    let lo = h.aspects.iter().find(|x| x.tid == d && x.ak == reg).unwrap().lo;
    let mut w = Writer::new(h.ts, h.form.own_source(b, osis_base::CommitId([0; 32])), lo);
    let mut f = create(&mut w, &osis_crdt::AnyView, &s("real")).unwrap();
    f.strip(&|_| true);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let forged = forge_snapshot(&mut lp, 2, d, &reg, now, f);
    lp.peers[0].drain_events();
    lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
    lp.peers[0].engine.reexamine().unwrap();
    let evs = lp.peers[0].drain_events();
    assert_eq!(lp.peers[0].engine.get(&d, &reg).unwrap(), None, "the snapshot's copy governs");
    assert!(!evs.iter().any(|e| matches!(e, Event::Diagnostic(x) if x.kind == osis_node::DiagnosticKind::Misstated)), "not reported: {evs:?}");
}

// spec/requirements.md, Threat model ("malicious readers can only waste storage"), Decentralization;
// spec/permissions.md §5.2: a reader's snapshot gives nothing. A reader's snapshot carrying another
// value under the dot and `ts` of a writer's session-form write changes nothing, whether it arrives
// after that write's commit (peer 2) or before it (peer 3); a restart keeps it so.
#[test]
fn snapshot_forging_held_node_dot_changes_nothing_spec_perm_5_2() {
    use osis_crdt::{Writer, create};
    let mut lp = net(4, 0x5f01);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    sync(&mut lp, 0, 3);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("real")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let h = lp.peers[0].engine.header(&c).unwrap();
    let lo = h.aspects.iter().find(|x| x.tid == t && x.ak.as_str() == "t:reg.0").unwrap().lo;
    let reg = ak("t:reg.0");
    let before = states(&mut lp.peers[2].engine, &[t]);
    // the reader re-uses (a's session, lo) and its ts
    let mut w = Writer::new(h.ts, h.form.own_source(a, osis_base::CommitId([0; 32])), lo);
    let f = create(&mut w, &osis_crdt::AnyView, &s("zzz forged")).unwrap();
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_snapshot(&mut lp, 1, t, &reg, now, f);
    let got = lp.peers[2].engine.ingest(&forged, Vec::new());
    assert_eq!(states(&mut lp.peers[2].engine, &[t]), before, "after c: {got:?}");
    let got = lp.peers[3].engine.ingest(&forged, Vec::new());
    sync(&mut lp, 0, 3);
    assert_eq!(states(&mut lp.peers[3].engine, &[t]), before, "before c: {got:?}");
    assert_eq!(lp.peers[2].engine.state(&t, &reg).unwrap(), lp.peers[3].engine.state(&t, &reg).unwrap(), "states alike");
    lp.peers[3].restart(0x5f01).unwrap();
    assert_eq!(states(&mut lp.peers[3].engine, &[t]), before, "after a restart");
}

// spec/permissions.md §5.2: as above, a reader's copy of a writer's map entry creation (its dot
// and `ts`) under another key and value changes nothing in either order.
#[test]
fn snapshot_forging_entry_key_changes_nothing_spec_perm_5_2() {
    let mut lp = net(4, 0x5f03);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    sync(&mut lp, 0, 3);
    let m_ak = ak("x:m.0");
    let mut m = Mutation::new();
    m.set(t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))]))).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let h = lp.peers[0].engine.header(&c).unwrap();
    let lo = h.aspects.iter().find(|x| x.tid == t && x.ak == m_ak).unwrap().lo;
    let before = states(&mut lp.peers[2].engine, &[t]);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_snapshot(&mut lp, 1, t, &m_ak, now, entry_by(h.form.own_source(a, osis_base::CommitId([0; 32])), h.ts, lo, "evil", "x"));
    let got = lp.peers[2].engine.ingest(&forged, Vec::new());
    assert_eq!(states(&mut lp.peers[2].engine, &[t]), before, "after c: {got:?}");
    let got = lp.peers[3].engine.ingest(&forged, Vec::new());
    sync(&mut lp, 0, 3);
    assert_eq!(states(&mut lp.peers[3].engine, &[t]), before, "before c: {got:?}");
    assert_eq!(lp.peers[2].engine.state(&t, &m_ak).unwrap(), lp.peers[3].engine.state(&t, &m_ak).unwrap(), "states alike");
}

// spec/permissions.md §5.2, spec/commits.md §5 (compaction): Alice's commit C writes `x:m.0` and
// `t:reg.0` (another retention class, another blob). A node that gets Alice's snapshot of `x:m.0`
// and the blob of C without its `x:m.0` delta (dropped at the host after compaction) holds C
// without that delta and takes C's write from the snapshot, in either order; the delta coming
// late changes nothing. A reader's snapshot copying C's `x:m.0` write with another value counts
// for nothing where C's delta is held, the delta arriving after the snapshot included.
#[test]
fn snapshot_copy_of_a_delta_never_held_counts_spec_perm_5_2() {
    let mut lp = net(3, 0x5f04);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let base = packages(&mut lp, 0);
    let m_ak = ak("x:m.0");
    let mut m = Mutation::new();
    m.set(t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))]))).unwrap();
    m.set(t, &REG, &s("reg")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&t, &m_ak).unwrap().unwrap();
    let want = states(&mut lp.peers[0].engine, &[t]);
    let pks = packages(&mut lp, 0);
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
    let feed = |lp: &mut LocalPeer, seed: u64, seq: &[&[u8]]| {
        let now = lp.peers[0].engine.now();
        lp.peers.push(osis_node::local_peer::Peer::new(seed, now).unwrap());
        let i = lp.peers.len() - 1;
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        for bytes in seq {
            let _ = lp.peers[i].engine.ingest(bytes, Vec::new());
            lp.peers[i].engine.reexamine().unwrap();
        }
        i
    };
    // honest: C's `x:m.0` delta never held, or late
    for (k, seq) in [vec![&sk.bytes[..], &partial[..]], vec![&partial[..], &sk.bytes[..]], vec![&partial[..], &sk.bytes[..], &ck.bytes[..]]].iter().enumerate() {
        let i = feed(&mut lp, 0x5f40 + k as u64, seq);
        assert!(lp.peers[i].engine.header(&c).is_some(), "order {k}: C applied");
        assert_eq!(states(&mut lp.peers[i].engine, &[t]), want, "order {k}");
        if k < 2 {
            // C's `x:m.0` body holds no delta here: covered (spec/commits.md §5)
            assert_eq!(lp.peers[i].engine.covered(&snap, &c, &t, &m_ak).unwrap(), Some(true), "order {k}");
        }
    }
    // forged: where C's delta is held, whichever came first
    for (k, seq) in [vec![&ck.bytes[..], &forged[..]], vec![&forged[..], &ck.bytes[..]], vec![&forged[..], &partial[..], &ck.bytes[..]], vec![&partial[..], &forged[..], &ck.bytes[..]]].iter().enumerate() {
        let i = feed(&mut lp, 0x5f50 + k as u64, seq);
        assert!(lp.peers[i].engine.header(&c).is_some(), "forged order {k}: C applied");
        assert_eq!(states(&mut lp.peers[i].engine, &[t]), want, "forged order {k}");
        lp.peers[i].restart(0x5f60 + k as u64).unwrap();
        assert_eq!(states(&mut lp.peers[i].engine, &[t]), want, "forged order {k}, after a restart");
    }
}


// spec/commits.md §5 (covering copies), spec/permissions.md §5.2: a snapshot copying a held write with
// another value does not cover that write's body (joining it into the snapshot changes no bytes:
// the copies of one dot tie), so the body is not dropped for it; the honest snapshot covers both
// the body and the forged snapshot, whose copy C's held delta gives.
#[test]
fn forged_snapshot_covers_nothing_spec_commits_5() {
    let mut lp = net(2, 0x5f05);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let m_ak = ak("x:m.0");
    let mut m = Mutation::new();
    m.set(t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))]))).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let honest = lp.peers[0].engine.snapshot(&t, &m_ak).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    let x = h.aspects.iter().find(|x| x.tid == t && x.ak == m_ak).unwrap();
    let now = osis_base::Ts::make(lp.peers[0].engine.now(), 0).unwrap();
    sync(&mut lp, 0, 1);
    let asrc = h.form.own_source(a, osis_base::CommitId([0; 32]));
    let forged = forge_snapshot_with(&mut lp, 1, t, &m_ak, now, entry_by(asrc.clone(), h.ts, x.lo, "k", "zzz forged"), frontier_of(&asrc, x.hi - 1));
    let f = match lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap() {
        Ingested::Applied(id) => id,
        other => panic!("{other:?}"),
    };
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.covered(&honest, &c, &t, &m_ak).unwrap(), Some(true), "the honest snapshot covers C");
    assert_eq!(e.covered(&f, &c, &t, &m_ak).unwrap(), Some(false), "the forged one does not");
    assert_eq!(e.covered(&honest, &f, &t, &m_ak).unwrap(), Some(true), "the honest snapshot covers the forged one");
}

// spec/requirements.md, Threat model ("malicious readers can only waste storage"); spec/permissions.md
// §5.2: a reader's snapshot carrying the owner's register write under a counter the owner never
// used, stamped now, changes nothing: its author could not write the aspect.
#[test]
fn snapshot_forging_unused_dot_changes_nothing_spec_perm_5_2() {
    use osis_crdt::{Writer, create};
    let mut lp = net(3, 0x5f71);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("real")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let reg = ak("t:reg.0");
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let mut w = Writer::new(now, crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32])), 1 << 40);
    let f = create(&mut w, &osis_crdt::AnyView, &s("zzz forged")).unwrap();
    let forged = forge_snapshot(&mut lp, 1, t, &reg, now, f);
    let got = lp.peers[2].engine.ingest(&forged, Vec::new());
    assert_eq!(lp.peers[2].engine.get(&t, &reg).unwrap(), Some(s("real")), "{got:?}");
}

// spec/permissions.md §5.2, spec/commits.md §5: a commit-form commit C's body dropped (covered by
// the owner's snapshot), a reader's snapshot then carrying an extra element under `Commit(C)`
// changes nothing: its author could not write the aspect.
#[test]
fn snapshot_forging_dropped_commit_dot_changes_nothing_spec_perm_5_2() {
    use osis_crdt::{Batch, Op, PathOp, Source, Writer};
    let mut lp = net(3, 0x5f72);
    lp.sync_all().unwrap();
    let r = lp.peers[1].engine.tid();
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let mut m = Mutation::new();
    m.commit_form();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let tags = ak("t:tags.0");
    lp.advance(1_000);
    let honest = lp.peers[0].engine.snapshot(&t, &tags).unwrap().unwrap();
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    assert_eq!(lp.peers[2].engine.covered(&honest, &c, &t, &tags).unwrap(), Some(true));
    lp.peers[2].engine.drop_body(&c, &t, &tags).unwrap();
    let before = lp.peers[2].engine.get(&t, &tags).unwrap();
    let ch = lp.peers[0].engine.header(&c).unwrap();
    let hi = ch.aspects.iter().find(|x| x.tid == t && x.ak == tags).unwrap().hi;
    let cur = lp.peers[1].engine.state(&t, &tags).unwrap().unwrap().clone();
    let mut batch = Batch::new(&cur, Writer::new(ch.ts, Source::commit(c), hi + 10));
    batch.apply(&PathOp { path: Vec::new(), op: Op::Add(s("evil")) }, &osis_crdt::AnyView).unwrap();
    let (extra, _) = batch.finish().unwrap();
    let mut f = cur;
    f.join(extra);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_snapshot_with(&mut lp, 1, t, &tags, now, f, osis_crdt::Frontiers::default());
    let got = lp.peers[2].engine.ingest(&forged, Vec::new());
    assert_eq!(lp.peers[2].engine.get(&t, &tags).unwrap(), before, "{got:?}");
}

// spec/commits.md §5 (covering copies): an honest snapshot covers a commit writing inside an entry an
// earlier commit created (the body repeats the entry's record without its creation, which the
// snapshot holds: that record is no write of the body's), and a body this node holds no delta of.
#[test]
fn snapshot_covers_write_inside_earlier_entry_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(1, 0x5f73);
    let t = new_thing(&mut lp, 0);
    let map = ak("t:map.0");
    let mut m = Mutation::new();
    m.set(t, &MAP, &Value::Map(osis_base::ValueMap::from([(s("k"), item("x", 1))]))).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("k")), PathSeg::Field(1)], op: Op::Set(Value::Int(2)) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&t, &map).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.covered(&snap, &c, &t, &map).unwrap(), Some(true));
}

// spec/requirements.md, Threat model; spec/permissions.md §5.2 (a snapshot is valid only if its
// author could write the aspect at it): a reader's snapshot of the owner's state plus an entry
// at a counter the owner never used gives nothing, before or after the owner's commit, across a
// restart, and covers nothing although it copies the commit exactly.
#[test]
fn reader_snapshot_gives_nothing_either_order_spec_perm_5_2() {
    let mut lp = net(4, 0x5f81);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (a, r) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    sync(&mut lp, 0, 3);
    let m_ak = ak("x:m.0");
    let mut m = Mutation::new();
    m.set(t, &m_ak, &Value::Map(osis_base::ValueMap::from([(s("k"), s("real"))]))).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let want = lp.peers[0].engine.get(&t, &m_ak).unwrap();
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let mut f = lp.peers[1].engine.state(&t, &m_ak).unwrap().unwrap().clone();
    f.join(entry_by(crate::common::session_of(&lp, 0).own_source(a, osis_base::CommitId([0; 32])), now, 1 << 40, "evil", "x"));
    let forged = forge_snapshot(&mut lp, 1, t, &m_ak, now, f);
    let fid = match lp.peers[2].engine.ingest(&forged, Vec::new()).unwrap() {
        Ingested::Applied(id) => id,
        other => panic!("{other:?}"),
    };
    assert_eq!(lp.peers[2].engine.get(&t, &m_ak).unwrap(), want, "after the commit");
    assert_eq!(lp.peers[2].engine.covered(&fid, &c, &t, &m_ak).unwrap(), Some(false), "an invalid snapshot covers nothing");
    lp.peers[3].engine.ingest(&forged, Vec::new()).unwrap();
    assert_eq!(lp.peers[3].engine.get(&t, &m_ak).unwrap(), None, "before the commit");
    sync(&mut lp, 0, 3);
    assert_eq!(lp.peers[3].engine.get(&t, &m_ak).unwrap(), want, "then the commit");
    assert_eq!(lp.peers[2].engine.state(&t, &m_ak).unwrap(), lp.peers[3].engine.state(&t, &m_ak).unwrap(), "states alike");
    lp.peers[3].restart(0x5f82).unwrap();
    assert_eq!(lp.peers[3].engine.get(&t, &m_ak).unwrap(), want, "after a restart");
}

// spec/permissions.md §5.1 (frontier), §5.2 (snapshot authority): Carol, a writer, compacts the
// tags; Dave holds Bob's tag only inside her snapshot. Alice then demotes Carol: with a frontier
// listing the snapshot (Alice had received it) Dave keeps Bob's tag; with one that does not, the
// snapshot is stripped like Carol's other writes and Bob's tag goes at Dave (Alice, holding Bob's
// commit, keeps it), whichever of the snapshot and the demotion Dave gets first, across a restart.
#[test]
fn demoted_compactor_snapshot_by_frontier_spec_perm_5_2() {
    for (covered, demote_first) in [(true, false), (true, true), (false, false), (false, true)] {
        let (mut lp, d, b, c) = setup(61);
        add_tag(&mut lp, 0, d, "alice");
        add_tag(&mut lp, 1, d, "bob");
        lp.sync_all().unwrap();
        // Dave gets only what is delivered below
        lp.peers.push(osis_node::local_peer::Peer::new(6100, lp.peers[0].engine.now()).unwrap());
        let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
        lp.advance(DAY);
        let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        sync(&mut lp, 2, 0);
        lp.advance(DAY);
        let rv = if covered {
            let scope = DemotionScope { roles: BTreeMap::from([(c, BTreeSet::from([d]))]), content: BTreeMap::from([(c, BTreeSet::from([d]))]) };
            let now = lp.peers[0].engine.now();
            let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
            assert!(f.commits.contains(&snap), "the frontier lists the snapshot");
            set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.to_value()))
        } else {
            set_edge(&mut lp.peers[0].engine, d, c, None, Some(osis_schema::core_types::Frontier::default().to_value()))
        };
        let all = BTreeSet::from(["alice".to_string(), "bob".to_string()]);
        assert_eq!(tags(&mut lp, 0, d), all, "Alice holds Bob's commit");
        let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)).collect();
        let (late, early): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| if demote_first { p.id == snap } else { p.id == rv });
        for pk in early.iter().chain(&late) {
            lp.deliver(3, pk).unwrap();
        }
        lp.peers[3].engine.reexamine().unwrap();
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
        let mut lp = net(3, 0x5f83);
        lp.sync_all().unwrap();
        let d = new_thing(&mut lp, 0);
        let (b, r) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, d, r, Some(edge(Role::Read)), None);
        lp.sync_all().unwrap();
        add_tag(&mut lp, 1, d, "bob");
        lp.sync_all().unwrap();
        let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
        lp.advance(1_000);
        let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
        let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
        let f = lp.peers[2].engine.state(&d, &ak("t:tags.0")).unwrap().unwrap().clone();
        let forged = forge_snapshot(&mut lp, 2, d, &ak("t:tags.0"), now, f);
        lp.peers.push(osis_node::local_peer::Peer::new(0x5f84, lp.peers[0].engine.now()).unwrap());
        if forged_first {
            let _ = lp.peers[3].engine.ingest(&forged, Vec::new());
        }
        for pk in packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)) {
            lp.deliver(3, &pk).unwrap();
        }
        lp.peers[3].engine.ingest(&forged, Vec::new()).unwrap();
        lp.peers[3].engine.reexamine().unwrap();
        assert!(lp.peers[3].engine.header(&snap).is_some() && bob.iter().all(|x| lp.peers[3].engine.header(x).is_none()));
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["bob".to_string()]), "forged first: {forged_first}");
        lp.peers[3].restart(0x5f85).unwrap();
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["bob".to_string()]), "forged first: {forged_first}, after a restart");
    }
}

// spec/permissions.md §5.2 (an invalid snapshot gives nothing; a received delta's dots take no
// copies), §5.1: a writer's snapshot, made after its author's demotion and backdated before it,
// carries an extra element under a dropped commit-form commit's `Commit(C)`. It never shows,
// whether the demotion (frontier not listing it) or the snapshot arrived first (was
// issue snapshot-copy-residue (closed): one held set, two states).
#[test]
fn demoted_writer_dropped_dot_copy_alike_spec_perm_5_2() {
    use osis_crdt::{Batch, Op, PathOp, Source, Writer};
    let mut lp = net(4, 0x5f87);
    lp.sync_all().unwrap();
    let w = lp.peers[1].engine.tid();
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.commit_form();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("a")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let tags = ak("t:tags.0");
    lp.advance(1_000);
    let honest = lp.peers[0].engine.snapshot(&t, &tags).unwrap().unwrap();
    for i in 1..4 {
        sync(&mut lp, 0, i);
    }
    for i in 2..4 {
        assert_eq!(lp.peers[i].engine.covered(&honest, &c, &t, &tags).unwrap(), Some(true));
        lp.peers[i].engine.drop_body(&c, &t, &tags).unwrap();
    }
    let before = lp.peers[2].engine.get(&t, &tags).unwrap();
    let ch = lp.peers[0].engine.header(&c).unwrap();
    let hi = ch.aspects.iter().find(|x| x.tid == t && x.ak == tags).unwrap().hi;
    let cur = lp.peers[1].engine.state(&t, &tags).unwrap().unwrap().clone();
    let mut batch = Batch::new(&cur, Writer::new(ch.ts, Source::commit(c), hi + 10));
    batch.apply(&PathOp { path: Vec::new(), op: Op::Add(s("evil")) }, &osis_crdt::AnyView).unwrap();
    let (extra, _) = batch.finish().unwrap();
    let mut f = cur;
    f.join(extra);
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_snapshot_with(&mut lp, 1, t, &tags, now, f, osis_crdt::Frontiers::default());
    lp.advance(1_000);
    let rv = set_edge(&mut lp.peers[0].engine, t, w, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    let rv_pk = packages(&mut lp, 0).into_iter().find(|p| p.id == rv).unwrap();
    // peer 2: the snapshot first (valid then), then the demotion; peer 3: the other way round
    lp.peers[2].engine.ingest(&forged, Vec::new()).unwrap();
    lp.deliver(2, &rv_pk).unwrap();
    lp.deliver(3, &rv_pk).unwrap();
    lp.peers[3].engine.ingest(&forged, Vec::new()).unwrap();
    for i in 2..4 {
        lp.peers[i].engine.reexamine().unwrap();
    }
    assert_eq!(lp.peers[3].engine.get(&t, &tags).unwrap(), before, "demotion first");
    assert_eq!(lp.peers[2].engine.get(&t, &tags).unwrap(), before, "snapshot first");
}

// spec/crdt.md §4.6, spec/permissions.md §5.2: Bob's write is carried, without its commit, by
// Alice's valid snapshot S and a reader's invalid one R. Dropping S's body leaves only R's
// invalid copy, which voids nothing: the write stays whether R arrived before or after the drop
// (was issue dropped-carrier-voids-write).
#[test]
fn valid_carrier_dropped_alike_either_order_spec_perm_5_2() {
    let mut lp = net(3, 0x5f88);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, r) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, r, Some(edge(Role::Read)), None);
    lp.sync_all().unwrap();
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let f = lp.peers[2].engine.state(&d, &ak("t:tags.0")).unwrap().unwrap().clone();
    let forged = forge_snapshot(&mut lp, 2, d, &ak("t:tags.0"), now, f);
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)).collect();
    let mut got = Vec::new();
    for (i, forged_first) in [(3, true), (4, false)] {
        lp.peers.push(osis_node::local_peer::Peer::new(0x5f89 + i as u64, lp.peers[0].engine.now()).unwrap());
        for pk in &pks {
            lp.deliver(i, pk).unwrap();
        }
        if forged_first {
            lp.peers[i].engine.ingest(&forged, Vec::new()).unwrap();
        }
        lp.peers[i].engine.drop_body(&snap, &d, &ak("t:tags.0")).unwrap();
        if !forged_first {
            lp.peers[i].engine.ingest(&forged, Vec::new()).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        got.push(tags(&mut lp, i, d));
    }
    assert_eq!(got[0], got[1], "invalid copy before the drop, after it");
    assert_eq!(got[0], BTreeSet::from(["bob".to_string()]));
}

// spec/permissions.md §5.2 (a valid snapshot's copies count whether or not the delta owning
// their dots was received, held or dropped): a valid writer's snapshot copying a dropped
// commit-form commit C's writes plus an element under a `Commit(C)` dot C did not use. The extra
// element shows, whether the snapshot arrived before the drop or after, also after a rebuild of
// the aspect, an honest snapshot without it and a restart, as at a node that never held C.
#[test]
fn forged_copy_under_dropped_delta_alike_spec_perm_5_2() {
    use osis_crdt::{Batch, Op, PathOp, Source, Writer};
    for forged_first in [false, true] {
        let mut lp = net(3, 0x5f88);
        lp.sync_all().unwrap();
        let w = lp.peers[1].engine.tid();
        let t = new_thing(&mut lp, 0);
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
        let mut m = Mutation::new();
        m.commit_form();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("a")) }).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let tags = ak("t:tags.0");
        lp.advance(1_000);
        let honest = lp.peers[0].engine.snapshot(&t, &tags).unwrap().unwrap();
        for i in 1..3 {
            sync(&mut lp, 0, i);
        }
        let before = lp.peers[2].engine.get(&t, &tags).unwrap();
        assert!(before.is_some());
        let ch = lp.peers[0].engine.header(&c).unwrap();
        let hi = ch.aspects.iter().find(|x| x.tid == t && x.ak == tags).unwrap().hi;
        let cur = lp.peers[1].engine.state(&t, &tags).unwrap().unwrap().clone();
        let mut batch = Batch::new(&cur, Writer::new(ch.ts, Source::commit(c), hi + 10));
        batch.apply(&PathOp { path: Vec::new(), op: Op::Add(s("evil")) }, &osis_crdt::AnyView).unwrap();
        let (extra, _) = batch.finish().unwrap();
        let mut f = cur;
        f.join(extra);
        lp.advance(1_000);
        let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
        let forged = forge_snapshot_with(&mut lp, 1, t, &tags, now, f, osis_crdt::Frontiers::default());
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
        let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| p.id != c).collect();
        lp.peers.push(osis_node::local_peer::Peer::new(0x5f8b, lp.peers[0].engine.now()).unwrap());
        for p in &pks {
            let _ = lp.deliver(3, p);
        }
        lp.peers[3].engine.ingest(&forged, Vec::new()).unwrap();
        lp.peers[3].engine.reexamine().unwrap();
        assert_eq!(lp.peers[3].engine.get(&t, &tags).unwrap(), before, "forged first: {forged_first}, C never held");
    }
}

// spec/permissions.md §5.2 (a valid snapshot vouches for the writes it carries; revocation is
// exact where no valid snapshot carries the write; Tess's decision "Snapshots vouch",
// notes/mvp-progress.md round 13), spec/requirements.md Permissions: Bob's "mon" reaches Alice;
// his "x" reaches only Carol, who compacts the tags before she learns of his removal; his "y"
// reaches only Carol after her compaction. Alice removes Bob with what she received. "x" stays,
// "y" goes, alike at Alice, at Carol, at a new node holding everything but Bob's own commits,
// and at nodes holding Bob's commits too, in every order of the snapshot, the revoke and "x"
// and "y" themselves, and after a rebuild of the state and a restart.
#[test]
fn removed_holder_write_compacted_earlier_stays_alike_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(0x5f8a);
    let id_of = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.commit_ids().into_iter().filter(|c| lp.peers[i].engine.header(c).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).max_by_key(|c| lp.peers[i].engine.header(c).unwrap().ts).unwrap();
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
    let want = BTreeSet::from(["mon".to_string(), "x".to_string()]);
    // Alice and Carol exchange everything
    lp.sync(0, 2).unwrap();
    lp.sync(2, 0).unwrap();
    for i in [0, 2] {
        assert_eq!(tags(&mut lp, i, d), want, "peer {i}");
    }
    let all: Vec<_> = packages(&mut lp, 2);
    let late = [x, y, snap, rv];
    let base: Vec<_> = all.iter().filter(|p| !late.contains(&p.id)).cloned().collect();
    let pk = |id| all.iter().find(|p| p.id == id).unwrap().clone();
    let orders: Vec<Vec<osis_base::CommitId>> = vec![vec![snap, rv], vec![rv, snap], vec![x, y, snap, rv], vec![rv, x, y, snap], vec![snap, rv, y, x], vec![y, rv, snap, x]];
    let mut states = Vec::new();
    for (n, order) in orders.iter().enumerate() {
        let i = lp.peers.len();
        lp.peers.push(osis_node::local_peer::Peer::new(0x5f8b + n as u64, lp.peers[0].engine.now()).unwrap());
        for p in base.iter().cloned().chain(order.iter().map(|id| pk(*id))) {
            lp.deliver(i, &p).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        assert_eq!(tags(&mut lp, i, d), want, "order {order:?}");
        lp.peers[i].engine.rebuild_state(&d, &ak("t:tags.0")).unwrap();
        assert_eq!(tags(&mut lp, i, d), want, "order {order:?}, rebuilt");
        lp.peers[i].restart(0x5f9b + n as u64).unwrap();
        assert_eq!(tags(&mut lp, i, d), want, "order {order:?}, restarted");
        states.push(lp.peers[i].engine.get(&d, &ak("t:tags.0")).unwrap());
    }
    assert!(states.windows(2).all(|w| w[0] == w[1]));
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
        let (mut lp, d, b, c) = setup(0x5fa0);
        add_tag(&mut lp, 1, d, "bob");
        lp.sync_all().unwrap();
        let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).collect();
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
            set_edge(&mut lp.peers[0].engine, d, b, None, Some(osis_schema::core_types::Frontier::default().to_value()));
            late.push(latest(&mut lp));
        }
        sync(&mut lp, 0, 2);
        let pks: Vec<_> = packages(&mut lp, 2).into_iter().filter(|p| bob_held || !bob.contains(&p.id)).collect();
        let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
        let base: Vec<_> = pks.iter().filter(|p| p.id != s2 && !late.contains(&p.id)).cloned().collect();
        let mut got = Vec::new();
        for (n, demote_first) in [false, true].into_iter().enumerate() {
            let i = lp.peers.len();
            lp.peers.push(osis_node::local_peer::Peer::new(0x5fa1 + n as u64, lp.peers[0].engine.now()).unwrap());
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
                lp.peers[i].engine.reexamine().unwrap();
                assert!(tags(&mut lp, i, d).is_empty(), "Bob's commit held: {bob_held}; S1 missing");
                lp.deliver(i, &pk(s1)).unwrap();
            }
            lp.peers[i].engine.reexamine().unwrap();
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

// spec/permissions.md §5.2 (a snapshot turned invalid gives nothing), spec/crdt.md §4.6: Bob's tag
// reaches fresh nodes only through snapshots: Alice's honest one and Carol's carrying another
// value under Bob's dot and `ts`. Alice then removes Carol with a frontier not listing Carol's.
// Whether Carol's copy came first (valid) or after the removal, the state ends alike: Alice's copy
// (its turning invalid strips its copies of shared dots too, `copies::given_by`).
#[test]
fn invalidated_copy_of_shared_dot_goes_alike_spec_perm_5_2() {
    use osis_crdt::{Batch, Op, PathOp, Writer};
    let (mut lp, d, b, c) = setup(0x5fb0);
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let tags_ak = ak("t:tags.0");
    let bob = lp.peers[1].engine.commit_ids().into_iter().find(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak == tags_ak))).unwrap();
    let bh = lp.peers[1].engine.header(&bob).unwrap();
    let lo = bh.aspects.iter().find(|a| a.ak == tags_ak).unwrap().lo;
    let empty = osis_crdt::Fragment::default();
    let mut batch = Batch::new(&empty, Writer::new(bh.ts, bh.form.own_source(b, osis_base::CommitId([0; 32])), lo));
    batch.apply(&PathOp { path: Vec::new(), op: Op::Add(s("evil")) }, &osis_crdt::AnyView).unwrap();
    let (evil, _) = batch.finish().unwrap();
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let forged = forge_snapshot(&mut lp, 2, d, &tags_ak, now, evil);
    lp.advance(1_000);
    let honest = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, c);
    let rv = *lp.peers[0].engine.commit_ids().iter().max_by_key(|x| lp.peers[0].engine.header(x).unwrap().ts).unwrap();
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| p.id != bob).collect();
    let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
    let base: Vec<_> = pks.iter().filter(|p| p.id != honest && p.id != rv).cloned().collect();
    let mut got = Vec::new();
    for (n, removal_first) in [false, true].into_iter().enumerate() {
        let i = lp.peers.len();
        lp.peers.push(osis_node::local_peer::Peer::new(0x5fb1 + n as u64, lp.peers[0].engine.now()).unwrap());
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        if removal_first {
            lp.deliver(i, &pk(rv)).unwrap();
        }
        lp.peers[i].engine.ingest(&forged, Vec::new()).unwrap();
        lp.deliver(i, &pk(honest)).unwrap();
        if !removal_first {
            lp.deliver(i, &pk(rv)).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        got.push(tags(&mut lp, i, d));
        lp.peers[i].engine.rebuild_state(&d, &tags_ak).unwrap();
        assert_eq!(tags(&mut lp, i, d), got[n], "removal first: {removal_first}, rebuilt");
        lp.peers[i].restart(0x5fb3 + n as u64).unwrap();
        assert_eq!(tags(&mut lp, i, d), got[n], "removal first: {removal_first}, restarted");
    }
    assert_eq!(got[1], BTreeSet::from(["bob".to_string()]), "removal first");
    assert_eq!(got[0], got[1], "Carol's copy first, then the removal");
}

// spec/permissions.md §5.2, spec/crdt.md §4.6: Alice's element, its delta dropped as covered by
// her snapshot S, is removed by Bob, whose revoke then voids the removal. A node that applied
// the removal while valid and one that got the revoke first both read the element: the rebuild
// takes it again from S's copy, the dropped delta giving nothing (was
// issue sim-work-sets-tag-lost (closed), sim work_sets seeds 15061, 15110).
#[test]
fn covered_drop_restored_after_remover_revoked_alike_spec_perm_5_2() {
    let mut lp = net(2, 0x5f8a);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    add_tag(&mut lp, 0, d, "ash");
    let tags_ak = ak("t:tags.0");
    let added: BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|x| lp.peers[0].engine.header(x).is_some_and(|h| h.kind == osis_commit::Kind::Content && h.aspects.iter().any(|a| a.ak == tags_ak))).collect();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    let before = packages(&mut lp, 0);
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("ash")) }).unwrap();
    let rm = lp.peers[1].commit(m).unwrap().unwrap();
    let rm_pk = packages(&mut lp, 1).into_iter().find(|p| p.id == rm).unwrap();
    lp.advance(1_000);
    revoke(&mut lp, 0, d, b); // without having seen the removal
    let known: BTreeSet<_> = before.iter().map(|p| p.id).collect();
    let rv: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !known.contains(&p.id)).collect();
    let mut got = Vec::new();
    for (i, removal_first) in [(2, true), (3, false)] {
        lp.peers.push(osis_node::local_peer::Peer::new(0x5f8b + i as u64, lp.peers[0].engine.now()).unwrap());
        for pk in &before {
            lp.deliver(i, pk).unwrap();
        }
        for c in &added {
            assert_eq!(lp.peers[i].engine.covered(&snap, c, &d, &tags_ak).unwrap(), Some(true));
            lp.peers[i].engine.drop_body(c, &d, &tags_ak).unwrap();
        }
        if removal_first {
            lp.deliver(i, &rm_pk).unwrap();
            assert!(tags(&mut lp, i, d).is_empty(), "the removal applied while valid");
        }
        for pk in &rv {
            lp.deliver(i, pk).unwrap();
        }
        if !removal_first {
            lp.deliver(i, &rm_pk).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
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
    let (mut lp, d, b, c) = setup(0x5fc0);
    add_tag(&mut lp, 0, d, "ash");
    lp.sync_all().unwrap();
    let tags_ak = ak("t:tags.0");
    let added: BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|x| lp.peers[0].engine.header(x).is_some_and(|h| h.kind == osis_commit::Kind::Content && h.aspects.iter().any(|a| a.ak == tags_ak))).collect();
    let before = packages(&mut lp, 0);
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    let snap_pk = packages(&mut lp, 2).into_iter().find(|p| p.id == snap).unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("ash")) }).unwrap();
    let rm = lp.peers[1].commit(m).unwrap().unwrap();
    let rm_pk = packages(&mut lp, 1).into_iter().find(|p| p.id == rm).unwrap();
    lp.advance(1_000);
    revoke(&mut lp, 0, d, c); // without having seen the removal or Carol's snapshot
    revoke(&mut lp, 0, d, b);
    let known: BTreeSet<_> = before.iter().map(|p| p.id).collect();
    let rv: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !known.contains(&p.id)).collect();
    let mut got = Vec::new();
    // dropped under Carol's cover: the removal applied valid, or arrived voided; held throughout
    for (i, drop, removal_first) in [(3, true, true), (4, true, false), (5, false, false)] {
        lp.peers.push(osis_node::local_peer::Peer::new(0x5fc1 + i as u64, lp.peers[0].engine.now()).unwrap());
        for pk in &before {
            lp.deliver(i, pk).unwrap();
        }
        if drop {
            lp.deliver(i, &snap_pk).unwrap();
            for x in &added {
                assert_eq!(lp.peers[i].engine.covered(&snap, x, &d, &tags_ak).unwrap(), Some(true));
                lp.peers[i].engine.drop_body(x, &d, &tags_ak).unwrap();
            }
        }
        if removal_first {
            lp.deliver(i, &rm_pk).unwrap();
            assert!(tags(&mut lp, i, d).is_empty(), "the removal applied while valid");
        }
        for pk in &rv {
            lp.deliver(i, pk).unwrap();
        }
        if !drop {
            lp.deliver(i, &snap_pk).unwrap();
        }
        if !removal_first {
            lp.deliver(i, &rm_pk).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        if drop {
            assert!(tags(&mut lp, i, d).is_empty(), "removal first: {removal_first}; the dropped delta missing");
            lp.peers[i].engine.rebuild_state(&d, &tags_ak).unwrap();
            assert!(tags(&mut lp, i, d).is_empty(), "removal first: {removal_first}; missing, rebuilt");
            for pk in before.iter().filter(|p| added.contains(&p.id)) {
                lp.deliver(i, pk).unwrap();
            }
            lp.peers[i].engine.reexamine().unwrap();
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
    let (mut lp, d, b, _) = setup(0x5fd0);
    add_tag(&mut lp, 0, d, "ash");
    let tags_ak = ak("t:tags.0");
    let added: BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|x| lp.peers[0].engine.header(x).is_some_and(|h| h.kind == osis_commit::Kind::Content && h.aspects.iter().any(|a| a.ak == tags_ak))).collect();
    lp.advance(1_000);
    let s1 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    add_tag(&mut lp, 0, d, "elm");
    lp.advance(1_000);
    let s2 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    let all = packages(&mut lp, 0);
    let s2_pk = all.iter().find(|p| p.id == s2).unwrap().clone();
    let before: Vec<_> = all.into_iter().filter(|p| p.id != s2).collect();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.op(d, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(s("ash")) }).unwrap();
    let rm = lp.peers[1].commit(m).unwrap().unwrap();
    let rm_pk = packages(&mut lp, 1).into_iter().find(|p| p.id == rm).unwrap();
    lp.advance(1_000);
    revoke(&mut lp, 0, d, b);
    let known: BTreeSet<_> = before.iter().map(|p| p.id).chain([s2]).collect();
    let rv: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !known.contains(&p.id)).collect();
    let mut got = Vec::new();
    for (i, removal_first) in [(3, true), (4, false)] {
        lp.peers.push(osis_node::local_peer::Peer::new(0x5fd1 + i as u64, lp.peers[0].engine.now()).unwrap());
        for pk in &before {
            lp.deliver(i, pk).unwrap();
        }
        let e = &mut lp.peers[i].engine;
        for x in &added {
            assert_eq!(e.covered(&s1, x, &d, &tags_ak).unwrap(), Some(true));
            e.drop_body(x, &d, &tags_ak).unwrap();
        }
        lp.deliver(i, &s2_pk).unwrap();
        let e = &mut lp.peers[i].engine;
        assert_eq!(e.covered(&s2, &s1, &d, &tags_ak).unwrap(), Some(true));
        e.drop_body(&s1, &d, &tags_ak).unwrap();
        if removal_first {
            lp.deliver(i, &rm_pk).unwrap();
            assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["elm".to_string()]), "the removal applied while valid");
        }
        for pk in &rv {
            lp.deliver(i, pk).unwrap();
        }
        if !removal_first {
            lp.deliver(i, &rm_pk).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        got.push((tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap()));
    }
    assert_eq!(got[0].0, BTreeSet::from(["ash".to_string(), "elm".to_string()]), "removal applied, then voided");
    assert_eq!(got[1], got[0], "removal arrived voided");
}

fn latest_of(lp: &mut LocalPeer, i: usize) -> osis_base::CommitId {
    *lp.peers[i].engine.commit_ids().iter().max_by_key(|x| lp.peers[i].engine.header(x).unwrap().ts).unwrap()
}

/// Delivers commits `ids` held by peer `from` to peer `i`, syncing `t`, without their parts on
/// `(t, a)`: `i` holds their headers, their writes there only through snapshots (spec/crdt.md §8:
/// a snapshot's frontier counts only on held headers).
fn deliver_stripped(lp: &mut LocalPeer, from: usize, i: usize, ids: &BTreeSet<osis_base::CommitId>, t: Tid, a: &osis_base::Ak) -> Vec<Ingested> {
    lp.peers[i].engine.set_syncing(t, true).unwrap();
    let pks: Vec<_> = packages(lp, from).into_iter().filter(|p| ids.contains(&p.id)).collect();
    pks.iter()
        .map(|p| {
            let h = lp.peers[from].engine.header(&p.id).unwrap();
            let mut blob = osis_commit::CommitBlob::decode(&p.bytes).unwrap();
            blob.parts.retain(|x| h.aspects[x.ai].ak != *a);
            lp.peers[i].engine.ingest(&blob.encode(), Vec::new()).unwrap()
        })
        .collect()
}

// spec/permissions.md §5.2: the cover's validity flips back. Bob (admin) removes Carol before
// seeing her S2, which covers Alice's S1; Alice removes Bob before seeing that removal, so it is
// void and S2 valid again. A node that dropped S1 under S2 and got Bob's removal first has S1
// missing; once Alice's removal arrives (S2 valid again), and again once S1 is fetched, it reads
// what nodes that never dropped S1 read, whichever removal they got first.
#[test]
fn cover_drop_coverer_flips_back_alike_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup(0x5fe0);
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
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
        for p in packages(&mut lp, i) {
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
        lp.peers.push(osis_node::local_peer::Peer::new(0x5fe1 + n as u64, lp.peers[0].engine.now()).unwrap());
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
        lp.peers[i].engine.reexamine().unwrap();
        if bob_first {
            let want: BTreeSet<String> = if drop { BTreeSet::new() } else { BTreeSet::from(["ash".to_string()]) };
            assert_eq!(tags(&mut lp, i, d), want, "drop {drop}: S2 invalid");
        }
        lp.deliver(i, &all[&second]).unwrap();
        lp.peers[i].engine.reexamine().unwrap();
        let mid = (tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap());
        if drop && bob_first {
            // S1 back (a late part); node-sync would drop it again under S2
            lp.deliver(i, &all[&s1]).unwrap();
            lp.peers[i].engine.reexamine().unwrap();
        }
        let t = (tags(&mut lp, i, d), lp.peers[i].engine.state(&d, &tags_ak).unwrap());
        assert_eq!(mid, t, "drop {drop}, Bob first {bob_first}: S1 fetched again");
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

// spec/permissions.md §5.2, spec/sync.md §7: as `coverer_demoted_after_cover_drop_alike_*`, with
// an older valid snapshot S0 of Alice's that lacks Bob's tag. S1 missing again (S2 invalid) is no
// body S0 covers: a compactor judging it against S0 keeps it, so once fetched again it gives
// Bob's tag as at a node that never dropped it.
#[test]
fn missing_snapshot_not_covered_by_older_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup(0x6000);
    let tags_ak = ak("t:tags.0");
    add_tag(&mut lp, 0, d, "ash");
    let s0 = lp.peers[0].engine.snapshot(&d, &tags_ak).unwrap().unwrap();
    lp.advance(1_000);
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak == tags_ak))).collect();
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
    let pks: Vec<_> = packages(&mut lp, 2).into_iter().filter(|p| !bob.contains(&p.id)).collect();
    let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
    let i = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x6001, lp.peers[0].engine.now()).unwrap());
    for p in pks.iter().filter(|p| p.id != rv) {
        lp.deliver(i, p).unwrap();
    }
    let e = &mut lp.peers[i].engine;
    assert_eq!(e.covered(&s0, &s1, &d, &tags_ak).unwrap(), Some(false), "S0 lacks Bob's tag");
    assert_eq!(e.covered(&s2, &s1, &d, &tags_ak).unwrap(), Some(true), "S2 covers S1");
    e.drop_body(&s1, &d, &tags_ak).unwrap();
    lp.deliver(i, &pk(rv)).unwrap();
    lp.peers[i].engine.reexamine().unwrap();
    assert!(!tags(&mut lp, i, d).contains("bob"), "S1 missing");
    let e = &mut lp.peers[i].engine;
    assert_ne!(e.covered(&s0, &s1, &d, &tags_ak).unwrap(), Some(true), "S0 does not cover missing S1");
    lp.deliver(i, &pk(s1)).unwrap();
    lp.peers[i].engine.reexamine().unwrap();
    assert!(tags(&mut lp, i, d).contains("bob"), "S1 back");
}

// spec/permissions.md §5.1 (frontier: received headers, never a snapshot's claims), §5.2: Bob's
// tag reaches a fresh node only through Carol's snapshot S; Alice removes Carol with a frontier
// not listing S; the fresh node holds Bob's headers without his parts. Whether S came first
// (valid, then invalid) or after the removal, the fresh node's frontier for Bob lists exactly
// his received commits, also after a restart.
#[test]
fn flipped_snapshot_leaves_frontier_alike_spec_perm_5_2() {
    let (mut lp, d, b, c) = setup(0x5fc0);
    add_tag(&mut lp, 1, d, "bob");
    sync(&mut lp, 1, 2);
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b)).collect();
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    lp.advance(DAY);
    // Alice removes Carol without listing S
    let scope = DemotionScope { roles: BTreeMap::from([(c, BTreeSet::from([d]))]), content: BTreeMap::from([(c, BTreeSet::from([d]))]) };
    let now = lp.peers[0].engine.now();
    let mut f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    f.commits.remove(&snap);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.to_value()));
    let rv = *lp.peers[0].engine.commit_ids().iter().max_by_key(|x| lp.peers[0].engine.header(x).unwrap().ts).unwrap();
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)).collect();
    let pk = |id| pks.iter().find(|p| p.id == id).unwrap().clone();
    let base: Vec<_> = pks.iter().filter(|p| p.id != snap && p.id != rv).cloned().collect();
    let of_bob = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
    let mut got = Vec::new();
    for (n, order) in [[snap, rv], [rv, snap]].into_iter().enumerate() {
        let i = lp.peers.len();
        lp.peers.push(osis_node::local_peer::Peer::new(0x5fc1 + n as u64, lp.peers[0].engine.now()).unwrap());
        for p in &base {
            lp.deliver(i, p).unwrap();
        }
        for id in order {
            lp.deliver(i, &pk(id)).unwrap();
            if id == snap {
                // Bob's headers: S's frontier counts on them while S is valid
                deliver_stripped(&mut lp, 1, i, &bob, d, &ak("t:tags.0"));
            }
        }
        lp.peers[i].engine.reexamine().unwrap();
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
/// the packages Alice holds, X, S and R.
fn listed_part_setup(seed: u64, commit_form: bool) -> (LocalPeer, Tid, Vec<osis_node::local_peer::Package>, [osis_base::CommitId; 3]) {
    let (mut lp, d, _, c) = setup(seed);
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
    let scope = DemotionScope { roles: BTreeMap::from([(c, BTreeSet::from([d]))]), content: BTreeMap::from([(c, BTreeSet::from([d]))]) };
    let now = lp.peers[0].engine.now();
    let mut f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    f.commits.remove(&snap);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.to_value()));
    let rv = latest_of(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    (lp, d, pks, [x, snap, rv])
}

/// A fresh peer given Alice's packages, with S, R and X (without its tags part) in `order`.
fn listed_part_peer(lp: &mut LocalPeer, d: Tid, pks: &[osis_node::local_peer::Package], ids: [osis_base::CommitId; 3], order: &[osis_base::CommitId], seed: u64) -> usize {
    let [x, ..] = ids;
    let i = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(seed, lp.peers[0].engine.now()).unwrap());
    for p in pks.iter().filter(|p| !ids.contains(&p.id)) {
        lp.deliver(i, p).unwrap();
    }
    lp.peers[i].engine.set_syncing(d, true).unwrap();
    for id in order {
        let p = pks.iter().find(|p| p.id == *id).unwrap();
        if *id == x {
            let h = lp.peers[0].engine.header(&x).unwrap();
            let mut blob = osis_commit::CommitBlob::decode(&p.bytes).unwrap();
            blob.parts.retain(|q| h.aspects[q.ai].ak != ak("t:tags.0"));
            lp.peers[i].engine.ingest(&blob.encode(), Vec::new()).unwrap();
        } else {
            lp.deliver(i, p).unwrap();
        }
    }
    lp.peers[i].engine.reexamine().unwrap();
    i
}

// spec/commits.md §4, spec/permissions.md §5.2: Carol's S lists Bob's X (its frontier, or its
// `Absorbed` for a commit-form X); a node that got Carol's removal first (S invalid) and X without
// its tags part applies the rest of X; the part joins once it arrives.
#[test]
fn part_listed_by_invalid_snapshot_applies_spec_commits_4() {
    for commit_form in [false, true] {
        let (mut lp, d, pks, ids) = listed_part_setup(0x5fd8, commit_form);
        let [x, snap, rv] = ids;
        let i = listed_part_peer(&mut lp, d, &pks, ids, &[rv, snap, x], 0x5fd9);
        assert!(lp.peers[i].engine.pending().is_empty(), "commit form {commit_form}: {:?}", lp.peers[i].engine.pending());
        assert_eq!(lp.peers[i].engine.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob")), "commit form {commit_form}");
        assert!(!tags(&mut lp, i, d).contains("bob"), "commit form {commit_form}");
        lp.deliver(i, pks.iter().find(|p| p.id == x).unwrap()).unwrap();
        assert!(tags(&mut lp, i, d).contains("bob"), "commit form {commit_form}: the part joined late");
    }
}

// spec/commits.md §4: whether X (without its tags part) arrives before S, while
// S is valid, or after Carol's removal made it invalid, it applies alike: the register shows,
// the tag does not, also after a restart.
#[test]
fn listed_part_alike_in_any_order_spec_commits_4() {
    let (mut lp, d, pks, ids) = listed_part_setup(0x5fda, false);
    let [x, snap, rv] = ids;
    let orders = [[snap, x, rv], [x, snap, rv], [snap, rv, x], [rv, snap, x], [x, rv, snap], [rv, x, snap]];
    for (n, order) in orders.iter().enumerate() {
        let i = listed_part_peer(&mut lp, d, &pks, ids, order, 0x5fdb + n as u64);
        for restarted in [false, true] {
            if restarted {
                lp.peers[i].restart(0x5fe9 + n as u64).unwrap();
            }
            let e = &mut lp.peers[i].engine;
            assert!(e.pending().is_empty(), "order {n} restarted {restarted}: {:?}", e.pending());
            assert_eq!(e.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob")), "order {n} restarted {restarted}");
            assert!(!tags(&mut lp, i, d).contains("bob"), "order {n} restarted {restarted}");
        }
    }
}

// spec/permissions.md §5.1 (frontier as of T), §5.2: a snapshot's frontiers count as received
// from when its part arrived, not its header: a late part of Carol's snapshot S (Bob's tag
// reaching the node only through it, his header held) is not in a frontier backdated to before
// it came.
#[test]
fn late_snapshot_part_received_when_it_came_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x5fd0);
    add_tag(&mut lp, 1, d, "bob");
    sync(&mut lp, 1, 2);
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b)).collect();
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &ak("t:tags.0")).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)).collect();
    let i = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5fd1, lp.peers[0].engine.now()).unwrap());
    for p in pks.iter().filter(|p| p.id != snap) {
        lp.deliver(i, p).unwrap();
    }
    let pk = pks.iter().find(|p| p.id == snap).unwrap();
    let h = lp.peers[i].engine.header(&snap).or_else(|| lp.peers[0].engine.header(&snap)).unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    blob.parts.retain(|p| h.aspects[p.ai].ak.as_str() != "t:tags.0");
    // the commit applies without its part (spec/commits.md §4)
    assert_eq!(lp.peers[i].engine.ingest(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(snap));
    lp.advance(1_000);
    assert!(!tags(&mut lp, i, d).contains("bob"));
    lp.advance(DAY);
    let before = lp.peers[i].engine.now();
    lp.advance(DAY);
    lp.deliver(i, pk).unwrap();
    assert!(tags(&mut lp, i, d).contains("bob"));
    // Bob's headers (not his parts): S's frontier counts on them
    let got = deliver_stripped(&mut lp, 1, i, &bob, d, &ak("t:tags.0"));
    assert!(got.iter().all(|g| matches!(g, Ingested::Applied(_))), "{got:?}");
    let of_bob = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
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
        let (mut lp, d, b, _) = setup(0x6100 + n as u64);
        add_tag(&mut lp, 1, d, "mon");
        lp.advance(1_000);
        let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
        let f = lp.peers[1].engine.state(&d, &tags_ak).unwrap().unwrap();
        let ghost = osis_base::CommitId([9; 32]);
        let bs = crate::common::session_of(&lp, 1).own_source(b, osis_base::CommitId([0; 32]));
        let forged = forge_snapshot_absorbing(&mut lp, 1, d, &tags_ak, ts, f, frontier_of(&bs, 1 << 40), BTreeMap::from([(ghost, b)]));
        if snap_first {
            assert!(matches!(lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap(), Ingested::Applied(_)));
            sync(&mut lp, 1, 0);
        } else {
            sync(&mut lp, 1, 0);
            assert!(matches!(lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap(), Ingested::Applied(_)));
        }
        lp.advance(DAY);
        let of_bob = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
        let now = lp.peers[0].engine.now();
        let f = lp.peers[0].engine.frontier(&of_bob, now).unwrap();
        let sid = osis_commit::CommitBlob::decode(&forged).unwrap().id();
        assert_eq!(f.commits, BTreeSet::from([sid]), "snap first {snap_first}");
        assert!(!f.commits.contains(&ghost), "snap first {snap_first}");
        revoke(&mut lp, 0, d, b);
        let rv = latest_of(&mut lp, 0);
        lp.advance(DAY);
        let before: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().collect();
        add_tag(&mut lp, 1, d, "late");
        let late: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
        // S claims the late tag's counter, but was stamped before it: the header alone shows nothing
        let i = lp.peers.len();
        lp.peers.push(osis_node::local_peer::Peer::new(0x6110 + n as u64, lp.peers[0].engine.now()).unwrap());
        for p in packages(&mut lp, 0).into_iter().filter(|p| p.id != rv) {
            lp.deliver(i, &p).unwrap();
        }
        let got = deliver_stripped(&mut lp, 1, i, &late, d, &tags_ak);
        assert!(got.iter().all(|g| matches!(g, Ingested::Applied(..))), "snap first {snap_first}: {got:?}");
        assert!(!tags(&mut lp, i, d).contains("late"), "snap first {snap_first}");
        sync(&mut lp, 1, 0);
        assert_eq!(tags(&mut lp, 0, d), BTreeSet::from(["mon".to_string()]), "snap first {snap_first}: Alice");
        let all = packages(&mut lp, 0);
        for (k, removal_first) in [true, false].into_iter().enumerate() {
            let j = lp.peers.len();
            lp.peers.push(osis_node::local_peer::Peer::new(0x6120 + 2 * n as u64 + k as u64, lp.peers[0].engine.now()).unwrap());
            let (first, second): (Vec<_>, Vec<_>) = all.iter().cloned().partition(|p| (p.id == rv) == removal_first || (!late.contains(&p.id) && p.id != rv));
            for p in first.iter().chain(&second) {
                lp.deliver(j, p).unwrap();
            }
            lp.peers[j].engine.reexamine().unwrap();
            assert_eq!(tags(&mut lp, j, d), BTreeSet::from(["mon".to_string()]), "snap first {snap_first}, removal first {removal_first}");
        }
    }
}

// spec/commits.md §5 (a dropped snapshot stands in from its header), spec/crdt.md §8
// (frontiers are no receipts), spec/permissions.md §5.1, §5.2: Bob's map entries reach a fresh node
// only through Carol's snapshot S (it holds his header, not his part); Alice's overwrite of one
// entry kills it in S, which drops at its keep-at-most bound with the other entry still live.
// The node's frontier for Bob lists his received commit, the same before and after the drop
// (also restarted and rebuilt), at a node getting S past its bound, and once S turns invalid.
#[test]
fn dropped_snapshot_leaves_frontier_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let (mut lp, d, b, c) = setup(0x5fe0);
    let sm = ak("t:gonemap.0");
    let entry = |k: &str, v: &str| {
        let mut m = Mutation::new();
        m.op(d, &GONEMAP, PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(v)) }).unwrap();
        m
    };
    let mut m = entry("k1", "b");
    m.op(d, &GONEMAP, PathOp { path: vec![PathSeg::Key(s("k2"))], op: Op::Set(s("b")) }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 2);
    let bob: BTreeSet<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b)).collect();
    lp.advance(1_000);
    // Carol's own entry (her node learns the aspect's schema bounds from it)
    lp.peers[2].commit(entry("k3", "c")).unwrap().unwrap();
    let snap = lp.peers[2].engine.snapshot(&d, &sm).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    lp.advance(1_000);
    lp.peers[0].commit(entry("k1", "a")).unwrap().unwrap();
    let i = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5fe1, lp.peers[0].engine.now()).unwrap());
    for p in packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)) {
        lp.deliver(i, &p).unwrap();
    }
    lp.peers[i].engine.reexamine().unwrap();
    let got = deliver_stripped(&mut lp, 1, i, &bob, d, &sm);
    assert!(got.iter().all(|g| matches!(g, Ingested::Applied(_))), "{got:?}");
    let e = &mut lp.peers[i].engine;
    assert!(e.body_not_dropped(&snap, &d, &sm), "S held");
    let of_bob = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
    let now = e.now();
    let held = e.frontier(&of_bob, now).unwrap();
    let on_d: BTreeSet<_> = bob.iter().copied().filter(|x| e.header(x).is_some_and(|h| h.aspects.iter().any(|a| a.tid == d))).collect();
    assert!(!on_d.is_empty() && held.commits == on_d, "Bob's header received");
    lp.advance(DAY);
    let e = &mut lp.peers[i].engine;
    e.tick().unwrap();
    assert!(!e.body_not_dropped(&snap, &d, &sm), "S dropped at its bound");
    assert!(matches!(e.get(&d, &sm).unwrap(), Some(Value::Map(m)) if m.contains_key(&s("k2"))), "k2 still live");
    assert_eq!(e.frontier(&of_bob, now).unwrap(), held, "dropped");
    lp.peers[i].restart(0x5fe2).unwrap();
    assert_eq!(lp.peers[i].engine.frontier(&of_bob, now).unwrap(), held, "dropped, restarted");
    lp.peers[i].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[i].engine.frontier(&of_bob, now).unwrap(), held, "dropped, rebuilt");
    // a node getting S past its bound drops it on arrival, with the same frontier
    let j = lp.peers.len();
    lp.peers.push(osis_node::local_peer::Peer::new(0x5fe4, lp.peers[0].engine.now()).unwrap());
    for p in packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)) {
        lp.deliver(j, &p).unwrap();
    }
    lp.peers[j].engine.reexamine().unwrap();
    let got = deliver_stripped(&mut lp, 1, j, &bob, d, &sm);
    assert!(got.iter().all(|g| matches!(g, Ingested::Applied(_))), "{got:?}");
    let e = &mut lp.peers[j].engine;
    assert!(e.due_live_drops().unwrap().iter().any(|x| x.0 == snap), "S due on arrival, its carrier first");
    e.tick().unwrap();
    assert!(!e.body_not_dropped(&snap, &d, &sm), "S dropped on arrival");
    let late = e.frontier(&of_bob, e.now()).unwrap();
    assert_eq!(late, held, "dropped on arrival");
    // Alice removes Carol without listing S: S gives nothing, dropped or not
    let scope = DemotionScope { roles: BTreeMap::from([(c, BTreeSet::from([d]))]), content: BTreeMap::from([(c, BTreeSet::from([d]))]) };
    let at = lp.peers[0].engine.now();
    let mut f = lp.peers[0].engine.frontier(&scope, at).unwrap();
    f.commits.remove(&snap);
    let rv = set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.to_value()));
    let rvp = lp.peers[0].engine.package(&rv).unwrap().unwrap();
    lp.deliver(i, &rvp).unwrap();
    lp.peers[i].engine.reexamine().unwrap();
    let now = lp.peers[i].engine.now();
    assert_eq!(lp.peers[i].engine.frontier(&of_bob, now).unwrap(), held, "S invalid");
    lp.peers[i].restart(0x5fe3).unwrap();
    assert_eq!(lp.peers[i].engine.frontier(&of_bob, now).unwrap(), held, "S invalid, restarted");
}

// spec/commits.md §5, spec/permissions.md §5.2 (a part dropped as covered is missing again only
// once no coverer carries it): Bob's entry k1 is dropped at Alice's node as covered by her
// snapshot S, which later drops at its keep-at-most bound (its entry k2 overwritten) with k1
// still live: S's writes stay in the state, so it still carries k1. Carol's unrelated snapshot
// then turns invalid: k1 stays, Bob's commit stays dropped, as at Bob's node holding it.
#[test]
fn bound_dropped_coverer_still_carries_spec_commits_5() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let (mut lp, d, b, c) = setup(0x5ff0);
    let sm = ak("t:gonemap.0");
    let entry = |k: &str, v: &str| {
        let mut m = Mutation::new();
        m.op(d, &GONEMAP, PathOp { path: vec![PathSeg::Key(s(k))], op: Op::Set(s(v)) }).unwrap();
        m
    };
    lp.peers[1].commit(entry("k1", "b")).unwrap().unwrap();
    lp.peers[0].commit(entry("k2", "a")).unwrap().unwrap();
    lp.sync_all().unwrap();
    let bob = lp.peers[1].engine.commit_ids().into_iter().find(|x| lp.peers[1].engine.header(x).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak == sm))).unwrap();
    lp.advance(1_000);
    let snap = lp.peers[0].engine.snapshot(&d, &sm).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.covered(&snap, &bob, &d, &sm).unwrap(), Some(true), "S covers Bob's");
    e.drop_body(&bob, &d, &sm).unwrap();
    lp.advance(1_000);
    lp.peers[0].commit(entry("k2", "a2")).unwrap().unwrap();
    lp.advance(DAY);
    lp.peers[0].engine.tick().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&snap, &d, &sm), "S dropped at its bound");
    let k1 = |lp: &mut LocalPeer, i: usize| matches!(lp.peers[i].engine.get(&d, &sm).unwrap(), Some(Value::Map(m)) if m.get(&s("k1")) == Some(&s("b")));
    assert!(k1(&mut lp, 0), "k1 live");
    // Carol's snapshot, then her removal by Alice with a frontier not listing it
    lp.sync_all().unwrap();
    lp.peers[2].commit(entry("k3", "c")).unwrap().unwrap();
    let s2 = lp.peers[2].engine.snapshot(&d, &sm).unwrap().unwrap();
    let new: Vec<_> = packages(&mut lp, 2).into_iter().filter(|p| p.id == s2 || lp.peers[0].engine.header(&p.id).is_none()).collect();
    for p in new {
        lp.deliver(0, &p).unwrap();
    }
    let scope = DemotionScope { roles: BTreeMap::from([(c, BTreeSet::from([d]))]), content: BTreeMap::from([(c, BTreeSet::from([d]))]) };
    let at = lp.peers[0].engine.now();
    let mut f = lp.peers[0].engine.frontier(&scope, at).unwrap();
    f.commits.remove(&s2);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(f.to_value()));
    lp.peers[0].engine.reexamine().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&bob, &d, &sm), "Bob's commit still dropped");
    assert!(k1(&mut lp, 0), "k1 still live");
    sync(&mut lp, 0, 1);
    assert!(k1(&mut lp, 1), "k1 live at Bob's");
    lp.peers[0].restart(0x5ff1).unwrap();
    assert!(k1(&mut lp, 0), "k1 still live, restarted");
}

/// A content commit signed by peer `by`'s key carrying only `created.0` of `rec`'s thing at `ts`,
/// its delta `ops` run from counter `lo` (the record's view, else untyped).
fn forge_created(lp: &mut LocalPeer, by: usize, rec: &osis_base::CreationRecord, ts: osis_base::Ts, lo: u64, ops: &[osis_crdt::PathOp], typed: bool) -> Result<Vec<u8>, String> {
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Batch, Delta, Writer, encode_delta};
    let view = osis_schema::core_schema().view("created.0").unwrap();
    let author = lp.peers[by].engine.tid();
    let empty = osis_crdt::Fragment::default();
    let form = crate::common::forged_session(author);
    let mut b = Batch::new(&empty, Writer::new(ts, form.own_source(author, osis_base::CommitId([0; 32])), lo));
    for op in ops {
        if typed { b.apply(op, &view) } else { b.apply(op, &osis_crdt::AnyView) }.map_err(|e| format!("{e:?}"))?;
    }
    let (f, r) = b.finish().ok_or("empty")?;
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Content, ts, author, r.lo, r.hi), None).map_err(|e| format!("{e:?}"))?;
    let mut aw = AspectWrite::new(rec.tid(), ak("created.0"), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::fixed_retention("created.0").unwrap();
    let mut cb = CommitBuilder::new(Kind::Content, ts, author, author, form);
    cb.aspects.push(aw);
    Ok(cb.build(&lp.peers[by].engine.identity().keys().signing, &Dedup(rec.clone()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode())
}

// spec/commits.md §2 (created one minting): Bob's
// commits whose `created.0` reads the record but is no minting of it (padded with a reset, or
// written untyped) are refused whole; his commit carrying one minting applies, and the honest
// creating commit (another minting of the same record, as two nodes persisting one ephemeral
// thing carry) joins it; no snapshot of `created.0` is written.
#[test]
fn padded_durable_created_refused_spec_commits_2() {
    use osis_crdt::{Op, PathOp};
    let (mut lp, d, _, _) = setup(53);
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, d);
    m.set(x, &REG, &s("x")).unwrap();
    let honest = lp.peers[1].commit(m).unwrap().unwrap();
    let rec = lp.peers[1].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let r = rec.to_value();
    let created = |lp: &mut LocalPeer| lp.peers[0].engine.get_typed(&x, &osis_schema::core_types::CREATED).unwrap();
    let ts = |lp: &mut LocalPeer, k: u64| osis_base::Ts::make(WallMs(lp.peers[1].engine.now().0 + k), 0).unwrap();
    let padded = [(vec![PathOp { path: Vec::new(), op: Op::Replace(r.clone()) }], true), (vec![PathOp { path: Vec::new(), op: Op::Set(r.clone()) }], false)];
    for (k, (ops, typed)) in padded.into_iter().enumerate() {
        let t = ts(&mut lp, k as u64 + 1);
        let b = forge_created(&mut lp, 1, &rec, t, 1000 * (k as u64 + 1), &ops, typed).unwrap();
        // no record comes of it; until a record tells its hash the part cannot be judged, so it waits
        assert!(matches!(lp.peers[0].engine.ingest(&b, Vec::new()), Ok(Ingested::Pending(..))), "typed {typed}");
        assert!(created(&mut lp).is_none());
    }
    let t = ts(&mut lp, 10);
    let one = forge_created(&mut lp, 1, &rec, t, 5000, &[PathOp { path: Vec::new(), op: Op::Set(r) }], true).unwrap();
    assert!(matches!(lp.peers[0].engine.ingest(&one, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(created(&mut lp), Some(rec.clone()));
    assert!(lp.peers[0].engine.pending().is_empty(), "with the record the padded ones are bad, and go");
    send(&mut lp, 1, 0, &[honest]);
    assert_eq!(lp.peers[0].engine.get(&x, &ak("t:reg.0")).unwrap(), Some(s("x")));
    assert_eq!(created(&mut lp), Some(rec));
    assert!(matches!(lp.peers[0].engine.snapshot(&x, &ak("created.0")), Err(osis_node::Error::Misuse(_))));
}

// spec/crdt.md §8 (a snapshot's frontier is no receipt), spec/permissions.md §5.2
// (a valid snapshot vouches for what it carries): Bob's tags are compacted into Carol's snapshot S
// and their blobs gone, so late admin Dan holds only S and his removal of Bob does not cover
// them; Alice and Carol, still holding Bob's commits, judge them invalid, but S keeps the tags at
// every node, fresh ones in either order included.
#[test]
fn late_joiner_after_compaction_keeps_writes_spec_crdt_8() {
    let mut lp = net(4, 0x6200);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (b, c, j) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, c, Some(edge(Role::Write)), None);
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
    for p in packages(&mut lp, 0).into_iter().filter(|p| !bob.contains(&p.id)) {
        lp.deliver(3, &p).unwrap();
    }
    lp.peers[3].engine.reexamine().unwrap();
    let want = BTreeSet::from(["mon".to_string(), "tue".to_string()]);
    assert_eq!(tags(&mut lp, 3, d), want);
    lp.advance(DAY);
    let scope = DemotionScope { roles: BTreeMap::from([(b, BTreeSet::from([d]))]), content: BTreeMap::from([(b, BTreeSet::from([d]))]) };
    let now = lp.peers[3].engine.now();
    assert!(lp.peers[3].engine.frontier(&scope, now).unwrap().commits.is_disjoint(&bob), "no held header of Bob's");
    revoke(&mut lp, 3, d, b);
    lp.advance(1000);
    sync(&mut lp, 3, 0);
    sync(&mut lp, 3, 2);
    let all = packages(&mut lp, 0);
    for (n, reversed) in [false, true].into_iter().enumerate() {
        let i = lp.peers.len();
        lp.peers.push(osis_node::local_peer::Peer::new(0x6210 + n as u64, lp.peers[0].engine.now()).unwrap());
        let mut v = all.clone();
        if reversed {
            v.reverse();
        }
        for p in &v {
            lp.deliver(i, p).unwrap();
        }
        lp.peers[i].engine.reexamine().unwrap();
        for k in [0, 2, 3, i] {
            assert_eq!(tags(&mut lp, k, d), want, "peer {k}, reversed {reversed}");
        }
    }
    assert!(!lp.peers[0].engine.roster(&d).contains_key(&b));
}



// spec/permissions.md §5.1 (what A had received as of T; covered commits left out only under a
// snapshot that vouches after the demotion): Alice receives Bob's write before a backdated
// revoke's cut and Bob's own snapshot covering it after. The snapshot is not listed (received
// late), so it is invalid after the removal; the write must be listed and stay.
#[test]
fn backdated_frontier_lists_write_covered_after_cut_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x7171);
    let reg = ak("t:reg.0");
    let mut m = Mutation::new();
    m.set(d, &REG, &s("bob")).unwrap();
    let first = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    let cut = lp.peers[0].engine.now();
    lp.advance(1_000);
    let snap = lp.peers[1].engine.snapshot(&d, &reg).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    assert_eq!(lp.peers[0].engine.covered(&snap, &first, &d, &reg).unwrap(), Some(true));
    lp.advance(1_000);
    let f = lp.peers[0].engine.frontier(&of(b, d), cut).unwrap();
    assert!(f.commits.contains(&first) && !f.commits.contains(&snap), "{f:?}");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
    assert_eq!(lp.peers[0].engine.get(&d, &reg).unwrap(), Some(s("bob")), "received by the cut, should stay");
}

// spec/permissions.md §5.1 (a frontier leaves out only what the demoter's compaction could drop
// now), notes/frontier-study.md: Bob writes a kept register twice and Carol, any
// writer, snapshots it just before Alice removes Bob. The snapshot keeps only "two"; Bob's
// superseded "one" is inside its keep-at-least window, so Alice lists it and it stays valid where
// held; a new node never given it reads alike. The live "two", covered, is left out (the
// snapshot vouches for it), and once the window is past "one" is left out too.
#[test]
fn frontier_keeps_superseded_kept_write_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x7181);
    let kept = ak("t:kept.0");
    let write = |lp: &mut LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.set(d, &KEPT, &s(v)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
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
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(f.commits.contains(&one), "a superseded write inside its keep-at-least window is listed");
    assert!(!f.commits.contains(&two), "a covered live write past its bound is left out");
    set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
    assert_eq!(lp.peers[0].engine.body_valid(&one, &d, &kept), Some(true), "kept history stays valid at the holder");
    let mut fresh = net(1, 0x7183);
    fresh.advance(DAY);
    for p in packages(&mut lp, 0).into_iter().filter(|p| p.id != one) {
        fresh.deliver(0, &p).unwrap();
    }
    fresh.peers[0].engine.reexamine().unwrap();
    assert!(fresh.peers[0].engine.header(&one).is_none());
    for l in [&mut lp, &mut fresh] {
        assert_eq!(l.peers[0].engine.get(&d, &kept).unwrap(), Some(s("two")));
        assert!(!l.peers[0].engine.roster(&d).contains_key(&b));
    }
    // past the window (and MAX_DRIFT), Alice's compaction could drop it: left out
    lp.advance(2 * DAY);
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(!f.commits.contains(&one) && !f.commits.contains(&two), "{f:?}");
}

// spec/permissions.md §5.1: a commit with a delta on a thing the demoter does not hold is listed,
// even when its part in question is droppable there (the demoter cannot judge the other delta).
// Bob's one commit writes D and his own thing E; Alice gets only its D part, which Carol's
// snapshot covers.
#[test]
fn frontier_lists_commit_with_unheld_part_spec_perm_5_1() {
    let (mut lp, d, b, _) = setup(0x7185);
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
    lp.peers[0].engine.ingest(&blob.encode(), pk.blobs.clone()).unwrap();
    lp.peers[2].engine.ingest(&blob.encode(), pk.blobs.clone()).unwrap();
    assert!(lp.peers[0].engine.header(&c).is_some());
    lp.advance(1_000);
    let snap = lp.peers[2].engine.snapshot(&d, &reg).unwrap().unwrap();
    sync(&mut lp, 2, 0);
    assert_eq!(lp.peers[0].engine.covered(&snap, &c, &d, &reg).unwrap(), Some(true));
    lp.advance(1_000);
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&of(b, d), now).unwrap();
    assert!(f.commits.contains(&c), "{f:?}");
}

/// Peer 1's key signs a content commit writing `node.0` on `k` (a card on a thing it has no
/// role on), under a session of its own.
fn forge_card(lp: &mut LocalPeer, k: Tid) -> osis_commit::CommitBlob {
    forge_on(lp, k, "node.0")
}

/// Peer 1's key signs a commit (of `a`'s class) writing aspect `a` of `k` (a thing it has no
/// role on), under a session of its own.
fn forge_on(lp: &mut LocalPeer, k: Tid, a: &str) -> osis_commit::CommitBlob {
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Delta, Writer, create, encode_delta};
    let b = lp.peers[1].engine.tid();
    let kind = if osis_schema::core_types::is_role_class(a) { Kind::Role } else { Kind::Content };
    // a role commit is its own source (its body goes in the probe below: header only)
    let form = if kind == Kind::Role { osis_commit::Form::Commit } else { forged_session(b) };
    let ts = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let mut w = Writer::new(ts, form.own_source(b, osis_base::CommitId([0; 32])), 1);
    let v = osis_schema::RawKey::encode(&osis_schema::core_types::NODE, &osis_schema::core_types::NodeInfo { software: "forged".into() });
    let f = create(&mut w, &AnyView, &v).unwrap();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, kind, ts, b, 1, 2), None).unwrap();
    let mut cb = CommitBuilder::new(kind, ts, b, b, form);
    let mut w = AspectWrite::new(k, ak(a), 1, 2, bytes);
    if let Some(r) = osis_commit::retention::fixed_retention(a) {
        w.retention = r;
    }
    cb.aspects.push(w);
    let rec = lp.peers[0].engine.get_typed(&k, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[1].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit
}

// spec/permissions.md §4 (a node card), §5.2: whether a key
// actor is a node reads its valid state, never a header's aspect list. A stranger's commit
// writing `node.0` on a recovery key or a link key, header only (it applies, its part invalid)
// or whole (its part waits), leaves the key a key actor: its boxes keep the static form, it gets no
// direct deliveries.
#[test]
fn stranger_card_makes_no_node_spec_perm_4() {
    for header_only in [true, false] {
        let mut lp = net(2, 951);
        lp.sync_all().unwrap();
        let hosts = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
        let (p, _) = lp.peers[0].engine.create_person(&hosts).unwrap();
        let recovery = osis_node::identity::Identity::from_seed(p.card.seed.clone()).tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, p.person);
        lp.peers[0].commit(m).unwrap();
        let spec = osis_node::flows::LinkSpec { target: t, role: Role::Read, until: None, hosts, peers: Vec::new(), single_use: false };
        let (link, _, _) = lp.peers[0].engine.create_link(&p.person, &spec).unwrap();
        let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
        for k in [recovery, l] {
            assert!(!lp.peers[0].engine.is_node(&k).unwrap(), "a key actor");
            let mut blob = forge_card(&mut lp, k);
            if header_only {
                blob.parts.clear();
            }
            let id = blob.id();
            // whole, its part waits on the author's reach (pending); header only, it applies
            let got = lp.peers[0].engine.ingest(&blob.encode(), Vec::new()).unwrap();
            assert!(got == Ingested::Applied(id) || (!header_only && matches!(got, Ingested::Pending(..))), "header only {header_only}: {got:?}");
            assert!(!lp.peers[0].engine.is_node(&k).unwrap(), "header only {header_only}: a stranger's card makes no node");
        }
    }
}

// spec/sync.md §2 (a group's labels are its `label.0` state): a stranger's header-only commit
// listing `label.0` on a thing (it applies, its part invalid) gives the thing no label here:
// it is not a labeled group, nor published under its owner's home label.
#[test]
fn stranger_label_listing_labels_nothing_spec_sync_2() {
    let mut lp = net(2, 952);
    lp.sync_all().unwrap();
    let hosts = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
    let (p, _) = lp.peers[0].engine.create_person(&hosts).unwrap();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, p.person);
    lp.peers[0].commit(m).unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.labeled_groups().contains(&p.person), "the account's home label");
    let before = e.published_under(&p.person);
    let mut blob = forge_on(&mut lp, t, "label.0");
    blob.parts.clear();
    let id = blob.id();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.ingest(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(id));
    assert!(!e.labeled_groups().contains(&t), "a listing labels nothing");
    assert!(!e.published_under(&p.person).contains(&t));
    assert_eq!(e.published_under(&p.person), before);
    // nor after a reopen
    e.reload().unwrap();
    assert!(!e.labeled_groups().contains(&t));
}

/// Secrets for hand-built commits on several things: each thing's dedup from its record, a
/// made-up one for a thing given none (its part sent header only).
struct Dedups(BTreeMap<Tid, osis_base::CreationRecord>);
impl osis_commit::Secrets for Dedups {
    fn dedup(&self, t: &Tid) -> Option<osis_crypto::Secret32> {
        Some(self.0.get(t).map_or(osis_crypto::Secret32::from_bytes([0; 32]), |r| osis_crypto::dedup_secret(r.nonce())))
    }
    fn admin_key(&self, t: &Tid) -> Option<osis_crypto::VerifyingKey> {
        let _ = t;
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([3; 32])).verifying_key())
    }
    fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([1; 32])).verifying_key())
    }
    fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
        Some(osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([2; 32])).verifying_key())
    }
}

/// What a forged commit writes on one aspect: the value, or `None` for a part sent header only.
type ForgedPart<'a> = (Tid, &'a str, Option<Value>);

/// Peer `by`'s key signs a content commit (memory class with `memory`) setting each of
/// `parts`, with `undoes` and `expires`, no rights checked; parts given no value are sent
/// header only. Dedups from peer `holder`'s records.
fn forge_parts(lp: &mut LocalPeer, by: usize, holder: usize, parts: &[ForgedPart<'_>], undoes: Option<osis_base::CommitId>, expires: Option<u64>, memory: bool) -> osis_commit::CommitBlob {
    use osis_commit::{AspectWrite, CommitBuilder, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Delta, Writer, create, encode_delta};
    let b = lp.peers[by].engine.tid();
    let form = forged_session(b);
    let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
    let mut cb = CommitBuilder::new(Kind::Content, ts, b, b, form);
    cb.undoes = undoes;
    cb.expires = expires;
    if memory {
        cb.ephemeral = Some(osis_commit::EphClass::Plain);
    }
    let mut recs = BTreeMap::new();
    for (t, a, v) in parts {
        let mut w = Writer::new(ts, form.own_source(b, osis_base::CommitId([0; 32])), 1);
        let f = create(&mut w, &AnyView, v.as_ref().unwrap_or(&s("header only"))).unwrap();
        let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(form, Kind::Content, ts, b, 1, 2), None).unwrap();
        let mut w = AspectWrite::new(*t, ak(a), 1, 2, bytes);
        if memory {
            w.retention = osis_commit::retention::EPHEMERAL_RETENTION;
        }
        cb.aspects.push(w);
        if let Some(r) = lp.peers[holder].engine.core.created(t) {
            recs.insert(*t, r.clone());
        }
    }
    let mut blob = cb.build(&lp.peers[by].engine.identity().keys().signing, &Dedups(recs), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit;
    let bare: BTreeSet<usize> = parts.iter().enumerate().filter(|(_, p)| p.2.is_none()).map(|(i, _)| i).collect();
    blob.parts.retain(|p| !bare.contains(&p.ai));
    blob
}

// spec/crdt.md §4.6 (restores the prior read): undo steps back through an earlier undo (z, a, b;
// b undone to a; undoing a writes z). A stranger's commit naming that undo or listing the aspect
// later changes nothing: an undo of it sent header only, a later change sent header only, an undo
// of it validly writing only the stranger's own thing.
#[test]
fn stranger_undo_listing_moves_no_step_back_spec_crdt_4_6() {
    for variant in ["none", "undo header only", "change header only", "undo valid elsewhere"] {
        let mut lp = net(2, 0x5f21);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let set = |lp: &mut LocalPeer, v: &str| {
            lp.advance(1_000);
            let mut m = Mutation::new();
            m.set(t, &REG, &s(v)).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap()
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
            assert_eq!(lp.peers[0].engine.ingest(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(id), "{variant}");
        }
        lp.advance(1_000);
        assert!(lp.peers[0].engine.revert(&c1).unwrap().is_some(), "{variant}: the undo writes");
        assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("z")), "{variant}");
    }
}

// spec/crdt.md §4.6 (undo rights): peer 1 writes a
// register while it holds write, then is lowered to read with a frontier keeping that write
// valid. Its undo of the write is `Permission`, nothing applied; peer 0, an admin, may undo it
// (restoring the read before it, from the bodies it holds: not its own commit).
#[test]
fn undo_needs_write_spec_crdt_4_6() {
    let mut lp = net(2, 0x5f22);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let prior = lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("b's")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let f = osis_schema::core_types::Frontier { commits: [c].into_iter().collect() };
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Read)), Some(f.to_value()));
    lp.sync_all().unwrap();
    lp.advance(1_000);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("b's")), "the write stays valid");
    let held = lp.peers[1].engine.commit_ids().len();
    let r = lp.peers[1].engine.revert(&c);
    assert!(matches!(r, Err(osis_node::Error::Permission { .. })), "{r:?}");
    assert_eq!(lp.peers[1].engine.commit_ids().len(), held);
    assert!(lp.peers[0].engine.revert(&c).unwrap().is_some());
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), prior);
}

// spec/sync.md §9 (a received memory thing goes once no commit here needs it): a stranger's
// commit naming a memory thing, durable or memory class, sent header only (it applies, its part
// invalid), does not keep the thing once its writer's memory commit expired.
#[test]
fn stranger_listing_keeps_no_memory_thing_spec_sync_9() {
    for durable in [true, false] {
        let mut lp = net(3, 0x5f23);
        lp.sync_all().unwrap();
        let d = new_thing(&mut lp, 0);
        lp.sync_all().unwrap();
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let w = e.new_thing(&mut m, d);
        let a = ak("t:tags.0~");
        m.set(w, &a, &s("x")).unwrap();
        m.expires(w, &a, WallMs(e.now().0 + 60_000)).unwrap();
        let id = e.commit_in_memory(m).unwrap().unwrap();
        let pk = e.package(&id).unwrap().unwrap();
        assert!(matches!(lp.peers[1].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap(), Ingested::Applied(_)));
        assert!(lp.peers[1].engine.core.created(&w).is_some());
        let blob = forge_parts(&mut lp, 2, 1, &[(w, if durable { "t:reg.0" } else { "t:tags.0~" }, None)], None, None, !durable);
        let fid = blob.id();
        let got = if durable { lp.peers[1].engine.ingest(&blob.encode(), Vec::new()) } else { lp.peers[1].engine.ingest_memory(&blob.encode(), u64::MAX) };
        assert_eq!(got.unwrap(), Ingested::Applied(fid), "durable {durable}");
        lp.advance(61_000);
        let e = &mut lp.peers[1].engine;
        e.tick().unwrap();
        e.take_memory_drops();
        assert!(e.core.created(&w).is_none(), "durable {durable}: freed");
    }
}

// spec/sync.md §1 (a reused chunk a host deleted is written again with the reusing delta's
// retention and expiry): an invalid commit linking the value (a reader's, expiring soon) lends
// the rewrite nothing.
#[test]
fn invalid_reuse_lends_relink_no_expiry_spec_sync_1() {
    let mut lp = net(2, 0x5f25);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let r = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let mut big = vec![0u8; 1 << 20];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(5), &mut big);
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(big)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let blob_ak = ak("t:blob.0");
    let link = lp.peers[0].engine.state(&t, &blob_ak).unwrap().unwrap().read().unwrap();
    assert!(matches!(link, Value::Link(_)));
    lp.advance(1_000);
    let soon = lp.peers[1].engine.now().0 + DAY;
    let blob = forge_parts(&mut lp, 1, 0, &[(t, "t:blob.0", Some(link))], None, Some(soon), false);
    let id = blob.id();
    assert_eq!(lp.peers[0].engine.ingest(&blob.encode(), Vec::new()).unwrap(), Ingested::Applied(id));
    let e = &mut lp.peers[0].engine;
    let lost = e.live_trees(&t).unwrap().blobs;
    let c = e.relink(&lost, &mut |_, _| true).unwrap().expect("a rewrite");
    assert_eq!(e.header(&c).unwrap().expires, None, "the own commit's expiry, not the reader's");
}
