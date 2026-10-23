#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Validity through perm at the engine level, with hand-fed membership commits: the Bob
//! revocation scenario and the Carol variant (notes/permissions.md, Revocation), re-grant,
//! overlapping counters.

use crate::common;
use common::*;
use osis_core::Classified;
use osis_core::{Role, Tid, Value, WallMs};
use osis_node::local_peer::LocalPeer;
use osis_node::{Event, Mutation};
use osis_perm::DemotionScope;
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};

const DAY: u64 = 86_400_000;

fn tags(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<String> {
    match lp.peers[i].engine.get(&t, &ak("/t/tags")).unwrap() {
        Some(Value::Set(s)) => s.into_iter().map(|v| if let Value::Str(x) = v { x } else { String::new() }).collect(),
        _ => BTreeSet::new(),
    }
}

fn add_tag(lp: &mut LocalPeer, i: usize, t: Tid, tag: &str) {
    let mut m = Mutation::new();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s(tag)) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap();
}

fn revoke(lp: &mut LocalPeer, admin: usize, t: Tid, member: Tid) {
    let scope = DemotionScope { membership: BTreeMap::from([(member, BTreeSet::from([t]))]), content: BTreeMap::from([(member, BTreeSet::from([t]))]) };
    let now = lp.peers[admin].engine.now();
    let f = lp.peers[admin].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[admin].engine, t, member, None, Some(f.to_value()));
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
    assert_eq!(lp.peers[0].engine.state(&d, &ak("/t/tags")).unwrap(), lp.peers[1].engine.state(&d, &ak("/t/tags")).unwrap());
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
    assert_eq!(lp.peers[2].engine.get(&d, &ak("/t/reg")).unwrap(), Some(s("bob")));
    lp.advance(1000);
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 2);
    assert_eq!(lp.peers[2].engine.get(&d, &ak("/t/reg")).unwrap(), Some(s("alice")));
}

/// Secrets for hand-built commits: dedup, and made-up delete keys (servers' business).
struct Dedup(osis_core::CreationRecord);
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

// spec/commits.md §4: two commits by one node with overlapping node-form ranges on one aspect
// are both invalid.
// spec/permissions.md §5.2 (dot reuse)
#[test]
fn overlapping_counters_spec_commits_4() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Delta, Source, Writer, create, encode_delta};
    let (mut lp, d, b, _) = setup(45);
    let other = ak("/x/other");
    let mut m = Mutation::new();
    m.set(d, &other, &s("first")).unwrap();
    let first = lp.peers[1].commit(m).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&first).unwrap();
    let (lo, hi) = (h.aspects[0].lo, h.aspects[0].hi);
    // Bob's key signs a second commit reusing those counters
    let ts = osis_core::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let mut w = Writer::new(ts, Source::node(b), lo);
    let f = create(&mut w, &AnyView, &s("second")).unwrap();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Kind::Content, ts, b, lo, hi), None).unwrap();
    let mut aw = AspectWrite::new(d, other.clone(), lo, hi, bytes);
    aw.retention = osis_schema::Retention { by: osis_schema::PurgeBy::Nobody, ..Default::default() };
    let mut cb = CommitBuilder::new(Kind::Content, ts, b, b, Form::Node);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let built = cb.build(&lp.peers[1].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap();
    sync(&mut lp, 1, 0);
    assert_eq!(lp.peers[0].engine.get(&d, &other).unwrap(), Some(s("first")));
    lp.peers[0].engine.ingest(&built.commit.encode(), Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &other).unwrap(), None);
}

// spec/commits.md §3, §4 (counter reuse): membership commits use commit form and a node-form one
// is bad input, so a node cannot void its own grant by later reusing its counters (overlapping
// node-form ranges void both commits): Bob keeps the edge Alice gave him.
#[test]
fn reused_counters_never_void_a_grant_spec_commits_4() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{AnyView, Batch, Delta, Op, PathOp, PathSeg, Source, Writer, encode_delta};
    let mut lp = net(3, 46);
    lp.sync_all().unwrap();
    let d = new_thing(&mut lp, 0);
    let (a, b, c) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
    let h = lp.peers[0].engine.header(&g).unwrap();
    assert_eq!(h.form, Form::Commit, "membership commits use commit form");
    let members = h.aspects.iter().find(|x| x.tid == d && x.ak.as_str() == "/members").unwrap();
    // Alice's key signs a node-form commit on d's /members with the grant's range
    let ts = osis_core::Ts::make(WallMs(h.ts.wall_ms().0 + 5), 0).unwrap();
    let empty = osis_crdt::Fragment::default();
    let mut batch = Batch::new(&empty, Writer::new(ts, Source::node(a), members.lo));
    batch.apply(&PathOp { path: vec![PathSeg::Key(Value::Tid(c))], op: Op::Set(edge(Role::Read).to_value()) }, &AnyView).unwrap();
    let (f, range) = batch.finish().unwrap();
    assert!(range.lo < members.hi && members.lo < range.hi, "the ranges overlap");
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Kind::Membership, ts, a, range.lo, range.hi), None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Membership, ts, a, a, Form::Node);
    let mut aw = AspectWrite::new(d, members.ak.clone(), range.lo, range.hi, bytes);
    aw.retention = osis_commit::retention::MEMBERSHIP_RETENTION;
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    // a node-form membership commit is refused when built and when received (spec/commits.md §4)
    let e = cb.build(&lp.peers[0].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap_err();
    assert!(e.to_string().contains("node-form membership"), "{e}");
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
}

// spec/commits.md §2: a membership commit changes at most
// one edge; a frontier needs a demotion. A writer refuses such a commit before it leaves.
#[test]
fn membership_content_rules_spec_commits_2() {
    let (mut lp, d, b, c) = setup(47);
    let put = |x: Tid, r: Role| osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(x))], op: osis_crdt::Op::Set(edge(r).to_value()) };
    let mut m = Mutation::new();
    for x in [b, c] {
        m.op(d, &osis_schema::core_types::MEMBERS, put(x, Role::Admin)).unwrap();
    }
    assert_eq!(lp.peers[0].commit(m).unwrap_err().class(), osis_core::ErrorClass::BadInput);
    let mut m = Mutation::new();
    m.op(d, &osis_schema::core_types::MEMBERS, put(b, Role::Admin)).unwrap();
    m.frontier(osis_schema::core_types::Frontier::default().to_value());
    assert_eq!(lp.peers[0].commit(m).unwrap_err().class(), osis_core::ErrorClass::BadInput);
    // validity survives a restart (perm inputs reload from the store)
    revoke(&mut lp, 0, d, b);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    lp.peers[1].restart(470).unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    assert_eq!(lp.peers[1].engine.roster(&d).len(), 1);
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
        let map = ak("/t/map");
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

/// A membership commit signed by peer `by`'s key writing `v` to `ak` on `t`, built by hand past
/// the writer-side rules; its counters start at `lo`.
fn forge_membership(lp: &mut LocalPeer, by: usize, t: Tid, ak: &osis_core::Ak, v: &Value, lo: u64) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    let author = lp.peers[by].engine.tid();
    let ts = osis_core::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
    let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
    // commit form (spec/commits.md §3): own dots name the commit, a placeholder until built
    let own = Source::commit(osis_core::CommitId([0; 32]));
    let mut w = Writer::new(ts, own.clone(), lo);
    let f = create(&mut w, &view, v).unwrap();
    let r = w.range();
    let mut cx = writer_ctx(Kind::Membership, ts, author, r.lo, r.hi);
    cx.own = own;
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
    let mut aw = AspectWrite::new(t, ak.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Membership, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[by].engine.identity().keys().signing, &Dedup(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

// spec/permissions.md §1 (membership-class by admins): a writer's `/moved`, `/was` or `/label`
// write, forged past its own node's writer-side refusal, is invalid where it is received (the
// same write by its author once an admin applies).
#[test]
fn forged_membership_class_unmerged_spec_perm_1() {
    use osis_schema::{AspectKey, core_types as ct};
    let (mut lp, d, _, _) = setup(49);
    let other = new_thing(&mut lp, 0);
    let label = ct::Label { index: 0, steps: BTreeMap::new(), servers: Vec::new(), replaced: false };
    let labels: ct::Labels = BTreeMap::from([(osis_core::LabelId([5; 16]), label)]);
    let writes = [(ct::MOVED.ak(), Value::Tid(other)), (ct::WAS.ak(), Value::Tid(other)), (ct::LABEL.ak(), labels.to_value())];
    for (a, v) in &writes {
        let a = ak(a);
        let before = lp.peers[0].engine.get(&d, &a).unwrap();
        let forged = forge_membership(&mut lp, 1, d, &a, v, 1);
        lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
        assert_eq!(lp.peers[0].engine.get(&d, &a).unwrap(), before, "{a}: a writer's membership-class write applied");
    }
    // control: the same write by the same key applies once its author is an admin
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    let a = ak(ct::MOVED.ak());
    let honest = forge_membership(&mut lp, 1, d, &a, &Value::Tid(other), 100);
    lp.peers[0].engine.ingest(&honest, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.get(&d, &a).unwrap(), Some(Value::Tid(other)));
}

// spec/permissions.md §5.2 (a compaction snapshot vouches for nothing): Dave holds Bob's edits
// only inside Alice's compaction snapshot; Alice's revoke of Bob covers "mon", not "x" (its
// frontier stops below it): Dave un-merges "x" from the snapshot body as Bob's write and keeps
// "mon", whether the revoke arrives after the snapshot or before it, across a restart; a re-grant
// brings "x" back.
#[test]
fn snapshot_vouches_for_nothing_spec_perm_5_2() {
    for revoke_first in [false, true] {
        let (mut lp, d, b, _) = setup(47);
        lp.peers.push(osis_node::local_peer::Peer::new(4700, T0).unwrap());
        lp.sync_all().unwrap();
        add_tag(&mut lp, 1, d, "mon");
        sync(&mut lp, 1, 0);
        let mon = lp.peers[1].engine.commit_ids().into_iter().filter(|c| lp.peers[1].engine.header(c).is_some_and(|h| h.author == b && h.aspects.iter().any(|a| a.ak.as_str() == "/t/tags"))).max_by_key(|c| lp.peers[1].engine.header(c).unwrap().ts).unwrap();
        let mon_hi = lp.peers[1].engine.header(&mon).unwrap().aspects.iter().find(|a| a.ak.as_str() == "/t/tags").unwrap().hi;
        lp.advance(DAY);
        add_tag(&mut lp, 1, d, "x");
        sync(&mut lp, 1, 0);
        let snap = lp.peers[0].engine.snapshot(&d, &ak("/t/tags")).unwrap().unwrap();
        lp.advance(DAY);
        // a frontier holding "mon" only
        let f = osis_schema::core_types::Frontier { writes: BTreeMap::from([(d, BTreeMap::from([("/t/tags".to_string(), BTreeMap::from([(b, mon_hi - 1)]))]))]), commits: BTreeSet::new() };
        let rv = set_edge(&mut lp.peers[0].engine, d, b, None, Some(f.to_value()));
        assert_eq!(tags(&mut lp, 0, d), BTreeSet::from(["mon".to_string()]), "Alice un-merges x");
        // Dave: everything of Alice's but Bob's own commits
        let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
        let (late, early): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| if revoke_first { p.id == snap } else { p.id == rv });
        for pk in early.iter().chain(&late) {
            lp.deliver(3, pk).unwrap();
        }
        lp.peers[3].engine.reexamine().unwrap();
        assert!(lp.peers[3].engine.header(&snap).is_some(), "the snapshot applied");
        assert!(lp.peers[3].engine.header(&mon).is_none(), "Bob's own commit is not held");
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["mon".to_string()]), "revoke first: {revoke_first}");
        lp.peers[3].restart(5).unwrap();
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["mon".to_string()]), "after a restart");
        // a re-grant makes Bob's writes valid again, those carried by the snapshot too
        lp.advance(DAY);
        let g = set_edge(&mut lp.peers[0].engine, d, b, Some(edge(Role::Write)), None);
        let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == g).unwrap();
        lp.deliver(3, &pk).unwrap();
        assert_eq!(tags(&mut lp, 3, d), BTreeSet::from(["mon".to_string(), "x".to_string()]), "re-granted");
    }
}

/// A content snapshot of `(t, a)` by peer `by` at `ts` carrying `f` (hand-built, unchecked).
fn forge_snapshot(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_core::Ak, ts: osis_core::Ts, f: osis_crdt::Fragment) -> Vec<u8> {
    forge_snapshot_with(lp, by, t, a, ts, f, Default::default())
}

fn forge_snapshot_with(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_core::Ak, ts: osis_core::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers) -> Vec<u8> {
    forge_snapshot_full(lp, by, t, a, ts, f, frontiers, BTreeMap::new())
}

#[allow(clippy::too_many_arguments)]
fn forge_snapshot_full(lp: &mut LocalPeer, by: usize, t: Tid, a: &osis_core::Ak, ts: osis_core::Ts, f: osis_crdt::Fragment, frontiers: osis_crdt::Frontiers, authors: BTreeMap<osis_core::CommitId, (Tid, osis_core::Ts)>) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    let author = lp.peers[by].engine.tid();
    let snap = osis_crdt::Snapshot { absorbed: Default::default(), nonce: [7; 16], fragment: f, frontiers, authors };
    let bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Kind::ContentSnapshot, ts, author, 0, 0), None).unwrap();
    let mut aw = AspectWrite::new(t, a.clone(), 0, 0, bytes);
    aw.retention = osis_commit::retention::snapshot_retention(a.as_str(), None);
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, author, Form::Node);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[by].engine.identity().keys().signing, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

/// Secrets for hand-built commits with `writer` retention: dedup, and made-up delete keys
/// (servers' business).
struct Keys(osis_core::CreationRecord);
impl osis_commit::Secrets for Keys {
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

/// One map entry `k: v` written by `node` at `ts` with counters from `lo`.
fn entry_by(node: Tid, ts: osis_core::Ts, lo: u64, k: &str, v: &str) -> osis_crdt::Fragment {
    let mut w = osis_crdt::Writer::new(ts, osis_crdt::Source::node(node), lo);
    osis_crdt::create(&mut w, &osis_crdt::AnyView, &Value::Map(BTreeMap::from([(s(k), s(v))]))).unwrap()
}

// spec/permissions.md §5.2 (a compaction snapshot vouches for nothing), spec/crdt.md §8: a
// writer's hostile snapshot carrying two entries of Bob dated before his grant (creation and
// value at that ts) un-merges exactly those, not Bob's held write, and keeps the owner's write it
// carries; one dating a dot of Bob's held commit otherwise is bad input.
#[test]
fn hostile_snapshot_strips_only_its_dots_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(53);
    let m_ak = ak("/x/m");
    let mut m = Mutation::new();
    m.set(d, &m_ak, &Value::Map(BTreeMap::from([(s("k"), s("bob"))]))).unwrap();
    let real = lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let lo = lp.peers[1].engine.header(&real).unwrap().aspects[0].lo;
    assert!(lo >= 1, "room for a forged counter below Bob's");
    let entries = |lp: &mut LocalPeer| match lp.peers[0].engine.get(&d, &m_ak).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    assert_eq!(entries(&mut lp), BTreeSet::from([s("k")]));
    lp.advance(1_000);
    let old = osis_core::Ts::make(WallMs(T0.0 - DAY), 0).unwrap();
    let now = osis_core::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    // a carried ts for a dot of a held commit other than its own is bad input
    let clash = forge_snapshot(&mut lp, 2, d, &m_ak, now, entry_by(b, old, lo, "f0", "x"));
    assert_eq!(lp.peers[0].engine.ingest(&clash, Vec::new()).unwrap_err().class(), osis_core::ErrorClass::BadInput);
    let mut f = entry_by(b, old, 1 << 39, "f1", "x");
    f.join(entry_by(b, old, 1 << 40, "f2", "y"));
    // and a valid write of Alice's (the snapshot applies)
    let a = lp.peers[0].engine.tid();
    f.join(entry_by(a, now, 1 << 42, "c", "alice"));
    let snap = forge_snapshot(&mut lp, 2, d, &m_ak, now, f);
    lp.peers[0].engine.ingest(&snap, Vec::new()).unwrap();
    let want = BTreeSet::from([s("k"), s("c")]);
    assert_eq!(entries(&mut lp), want, "Bob's held write stays; the forged ones go");
    lp.peers[0].restart(53).unwrap();
    assert_eq!(entries(&mut lp), want, "after a restart");
}

// spec/permissions.md §7 (a write is imported from a snapshot covering it, else its own commit):
// a writer's snapshot whose frontier claims Bob's write without carrying it does not make a move
// lose it: the copy imports it from Bob's commit (the current state holds it), and the
// snapshot's own carried write too.
#[test]
fn inflated_frontier_keeps_write_in_move_spec_perm_7() {
    let (mut lp, d, b, _) = setup(55);
    let m_ak = ak("/x/m");
    let mut m = Mutation::new();
    m.set(d, &m_ak, &Value::Map(BTreeMap::from([(s("k"), s("bob"))]))).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    let now = osis_core::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let a = lp.peers[0].engine.tid();
    let fr = osis_crdt::Frontiers(BTreeMap::from([(b, 1 << 40)]));
    let snap = forge_snapshot_with(&mut lp, 2, d, &m_ak, now, entry_by(a, now, 1 << 42, "c", "alice"), fr);
    lp.peers[0].engine.ingest(&snap, Vec::new()).unwrap();
    let want = Some(Value::Map(BTreeMap::from([(s("c"), s("alice")), (s("k"), s("bob"))])));
    assert_eq!(lp.peers[0].engine.get(&d, &m_ak).unwrap(), want);
    lp.advance(1_000);
    let (copy, _) = lp.peers[0].engine.move_thing(&d, a).unwrap();
    assert_eq!(lp.peers[0].engine.get(&copy, &m_ak).unwrap(), want, "the copy holds both");
}

// spec/permissions.md §5.2 (a snapshot vouches for nothing): Dave holds Bob's tag only inside
// Alice's compaction snapshot, which arrives before Bob's grant: Bob's carried write is invalid
// there (stripped), its index persisted equals a rebuild from the commit records, and the
// grant arriving makes it valid and merged, across a restart.
#[test]
fn snapshot_before_grant_then_valid_spec_perm_5_2() {
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
    let snap = lp.peers[0].engine.snapshot(&d, &ak("/t/tags")).unwrap().unwrap();
    // Dave: Alice's commits but the grant, then the grant
    let pks: Vec<_> = packages(&mut lp, 0).into_iter().filter(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
    let (members, content): (Vec<_>, Vec<_>) = pks.into_iter().partition(|p| p.id == g);
    for pk in &content {
        lp.deliver(2, pk).unwrap();
    }
    lp.peers[2].engine.reexamine().unwrap();
    assert!(lp.peers[2].engine.header(&snap).is_some(), "the snapshot applied");
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::new(), "Bob's carried write is invalid without his grant");
    let e = &mut lp.peers[2].engine;
    let before = e.index_digest();
    e.reload_index().unwrap();
    assert_eq!(e.index_digest(), before, "loaded from the persisted index");
    e.rebuild_index().unwrap();
    assert_eq!(e.index_digest(), before, "rebuilt from the commit records");
    for pk in &members {
        lp.deliver(2, pk).unwrap();
    }
    lp.peers[2].engine.reexamine().unwrap();
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["x".to_string()]), "valid once the grant is held");
    lp.peers[2].restart(58).unwrap();
    assert_eq!(tags(&mut lp, 2, d), BTreeSet::from(["x".to_string()]), "after a restart");
}

// spec/permissions.md §5.2: Carol compacts the tags (her snapshot carries Bob's and Alice's
// writes, none of hers); Alice then removes Carol with a frontier that lacks the snapshot. A
// fresh node receiving everything reads what Alice reads (the snapshot's writes are judged as
// their authors', not Carol's).
#[test]
fn demoted_compactor_fresh_node_spec_perm_5_2() {
    let (mut lp, d, _, c) = setup(59);
    lp.peers.push(osis_node::local_peer::Peer::new(5900, T0).unwrap());
    add_tag(&mut lp, 0, d, "alice");
    add_tag(&mut lp, 1, d, "bob");
    lp.sync_all().unwrap();
    lp.advance(DAY);
    let st = lp.peers[0].engine.state(&d, &ak("/t/tags")).unwrap().unwrap();
    let now = osis_core::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let snap = forge_snapshot(&mut lp, 2, d, &ak("/t/tags"), now, st);
    lp.peers[2].engine.ingest(&snap, Vec::new()).unwrap();
    lp.sync_all().unwrap();
    lp.advance(DAY);
    set_edge(&mut lp.peers[0].engine, d, c, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    lp.sync_all().unwrap();
    let want = BTreeSet::from(["alice".to_string(), "bob".to_string()]);
    assert_eq!(tags(&mut lp, 0, d), want);
    assert_eq!(tags(&mut lp, 3, d), want, "a fresh node reads the same");
    assert_eq!(lp.peers[3].engine.state(&d, &ak("/t/tags")).unwrap(), lp.peers[0].engine.state(&d, &ak("/t/tags")).unwrap());
}

fn put_at(lp: &mut LocalPeer, i: usize, t: Tid, path: &[&str], v: Value) {
    let mut m = Mutation::new();
    let path = path.iter().map(|k| osis_crdt::PathSeg::Key(s(k))).collect();
    m.op(t, &ak("/x/m"), osis_crdt::PathOp { path, op: osis_crdt::Op::Set(v) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap();
}

// spec/permissions.md §5.2, spec/crdt.md §5.6 and §8 (a snapshot carries each entry's creation
// `ts`): Bob, removed, creates entry "late" offline; Carol, not yet aware, writes inside it and
// compacts. Dave holds only Alice's and Carol's commits and Carol's snapshot: "late" is created
// by Bob after his removal, so it goes with Carol's write under it, as at Alice, who holds
// Bob's commit.
#[test]
fn entry_created_after_demotion_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(61);
    lp.peers.push(osis_node::local_peer::Peer::new(6100, T0).unwrap());
    lp.sync_all().unwrap();
    let one = |k: &str, v: &str| Value::Map(BTreeMap::from([(s(k), s(v))]));
    put_at(&mut lp, 1, d, &["k"], one("a", "1"));
    lp.sync_all().unwrap();
    lp.advance(DAY);
    revoke(&mut lp, 0, d, b);
    lp.advance(DAY);
    // one commit, two entries: "late" is its second creation (its dot is no stamp of the commit)
    let mut m = Mutation::new();
    for k in ["early", "late"] {
        m.op(d, &ak("/x/m"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: osis_crdt::Op::Set(one("a", "1")) }).unwrap();
    }
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 2);
    put_at(&mut lp, 2, d, &["late", "b"], s("2"));
    let st = lp.peers[2].engine.state(&d, &ak("/x/m")).unwrap().unwrap();
    let now = osis_core::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let snap = forge_snapshot(&mut lp, 2, d, &ak("/x/m"), now, st);
    lp.peers[2].engine.ingest(&snap, Vec::new()).unwrap();
    // Dave: Alice's and Carol's commits (the snapshot among them), none of Bob's
    for from in [0, 2] {
        let pks: Vec<_> = packages(&mut lp, from).into_iter().filter(|p| lp.peers[from].engine.header(&p.id).is_some_and(|h| h.author != b)).collect();
        for pk in &pks {
            lp.deliver(3, pk).unwrap();
        }
    }
    lp.peers[3].engine.reexamine().unwrap();
    sync(&mut lp, 1, 0);
    sync(&mut lp, 2, 0);
    let keys = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&d, &ak("/x/m")).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    assert_eq!(keys(&mut lp, 0), BTreeSet::from([s("k")]), "Alice");
    assert_eq!(keys(&mut lp, 3), BTreeSet::from([s("k")]), "Dave");
}

// spec/crdt.md §8 (`Authors`), spec/permissions.md §5.2: commit-form writes a snapshot carries
// are judged as their commit's author at its `ts`: one named for Bob before his grant goes, one
// named for Alice stays; a snapshot without the author of a commit-form write is bad input.
#[test]
fn commit_form_carried_writes_judged_spec_perm_5_2() {
    let (mut lp, d, b, _) = setup(63);
    let m_ak = ak("/x/m");
    lp.advance(1_000);
    let a = lp.peers[0].engine.tid();
    let old = osis_core::Ts::make(WallMs(T0.0 - DAY), 0).unwrap();
    let now = osis_core::Ts::make(lp.peers[2].engine.now(), 0).unwrap();
    let (x, y) = (osis_core::CommitId([0xA1; 32]), osis_core::CommitId([0xB2; 32]));
    let by = |c: osis_core::CommitId, ts, k: &str| {
        let mut w = osis_crdt::Writer::new(ts, osis_crdt::Source::commit(c), 1);
        osis_crdt::create(&mut w, &osis_crdt::AnyView, &Value::Map(BTreeMap::from([(s(k), s(k))]))).unwrap()
    };
    let mut f = by(x, old, "bob");
    f.join(by(y, now, "alice"));
    let missing = forge_snapshot(&mut lp, 2, d, &m_ak, now, f.clone());
    assert_eq!(lp.peers[0].engine.ingest(&missing, Vec::new()).unwrap_err().class(), osis_core::ErrorClass::BadInput);
    let authors = BTreeMap::from([(x, (b, old)), (y, (a, now))]);
    let snap = forge_snapshot_full(&mut lp, 2, d, &m_ak, now, f, Default::default(), authors);
    lp.peers[0].engine.ingest(&snap, Vec::new()).unwrap();
    let keys = match lp.peers[0].engine.get(&d, &m_ak).unwrap() {
        Some(Value::Map(m)) => m.into_keys().collect::<BTreeSet<_>>(),
        _ => BTreeSet::new(),
    };
    assert_eq!(keys, BTreeSet::from([s("alice")]));
}

/// Delivers commits `ids` of peer `from` to peer `to`.
fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[osis_core::CommitId]) {
    for id in ids {
        let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
        lp.deliver(to, &pk).unwrap();
    }
}

// spec/permissions.md §5.1 step 4 (D only grows), §6 (epoch starts; a re-snapshot's roster):
// issues/perm-resnapshot-self-undermining-drop.md, seed 6's shape. n0 removes A2 from A0 (W,
// unseen by n1) and grants n1 write on A2 (G, unseen too); n1 lowers A1 to write on A0 (R). The
// full walk drops W and G (R is a fall while W stands) and keeps them dropped after R stops being
// one; n1's roster snapshot of A0 has A2 admin, so replayed R is no fall and G stands. Device A
// (full history) and device B (n1, the compactor) disagree until B's snapshot reaches A; then A,
// B and late joiners (with or without W) agree on the snapshot's answer.
#[test]
fn resnapshot_residue_heals_on_sync_spec_perm_6() {
    let mut lp = net(5, 61);
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
    // n0 also holds an admin edge on A1 (issues/node-chain-check-skips-owner-links.md)
    set_edge(&mut lp.peers[0].engine, a1, n0, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    set_edge(&mut lp.peers[1].engine, a0, a1, Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    set_edge(&mut lp.peers[0].engine, a1, a2, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    // n0 through A1: A2 admin on A0, then removed (W); n1 write on A2 (G); A1 admin on A2
    let step = |lp: &mut LocalPeer| lp.advance(1000);
    step(&mut lp);
    let c1 = set_edge(&mut lp.peers[0].engine, a0, a2, Some(edge(Role::Admin)), None);
    step(&mut lp);
    let w = set_edge(&mut lp.peers[0].engine, a0, a2, None, None);
    step(&mut lp);
    set_edge(&mut lp.peers[0].engine, a2, n1, Some(edge(Role::Write)), None);
    step(&mut lp);
    let c6 = set_edge(&mut lp.peers[0].engine, a2, a1, Some(edge(Role::Admin)), None);
    // n1 has c1 and c6, not W or G, when it lowers A1 to write on A0 (R)
    send(&mut lp, 0, 1, &[c1, c6]);
    step(&mut lp);
    let scope = DemotionScope { membership: BTreeMap::from([(n0, BTreeSet::from([a0, a2]))]), content: BTreeMap::new() };
    let now = lp.peers[1].engine.now();
    let f = lp.peers[1].engine.frontier(&scope, now).unwrap();
    set_edge(&mut lp.peers[1].engine, a0, a1, Some(edge(Role::Write)), Some(f.to_value()));
    // devices A (2) and B (1) hold the full history
    for i in [1, 2] {
        sync(&mut lp, 0, i);
        sync(&mut lp, 1, i);
    }
    let has_g = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&a2).contains_key(&n1);
    assert!(lp.peers[2].engine.roster(&a0).contains_key(&a2), "W dropped: A2 stays admin on A0");
    assert!(!has_g(&lp, 2) && !has_g(&lp, 1), "the full walk keeps G dropped (sticky)");
    // B compacts A0: it judges from its own snapshot and G stands; A has not got it yet
    let snap = *lp.peers[1].engine.roster_snapshot(&a0, None).unwrap().commits.last().unwrap();
    assert!(has_g(&lp, 1), "B: G stands under its snapshot");
    assert!(!has_g(&lp, 2), "A: G dropped until the snapshot arrives");
    send(&mut lp, 1, 2, &[snap]);
    assert!(has_g(&lp, 2), "A adopts the snapshot as A0's epoch start: G stands");
    assert_eq!(lp.peers[2].engine.roster(&a0), lp.peers[1].engine.roster(&a0));
    assert_eq!(lp.peers[2].engine.roster(&a2), lp.peers[1].engine.roster(&a2));
    // late joiners: one gets everything, one everything but W (as a compacted relay serves it)
    sync(&mut lp, 1, 3);
    let all_but_w: Vec<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|c| *c != w).collect();
    send(&mut lp, 1, 4, &all_but_w);
    for i in [0, 3, 4] {
        if i == 0 {
            sync(&mut lp, 1, 0);
        }
        assert!(has_g(&lp, i), "device {i}: G stands");
        assert_eq!(lp.peers[i].engine.roster(&a0), lp.peers[1].engine.roster(&a0), "device {i}");
        assert_eq!(lp.peers[i].engine.roster(&a2), lp.peers[1].engine.roster(&a2), "device {i}");
    }
}
