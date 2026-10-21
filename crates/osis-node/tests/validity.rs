#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Validity through perm at the engine level, with hand-fed membership commits: the Bob
//! revocation scenario and the Carol variant (notes/permissions.md, Revocation), re-grant,
//! overlapping counters.

mod common;
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

/// Secrets for hand-built commits with `nobody` retention: dedup only.
struct Dedup(osis_core::CreationRecord);
impl osis_commit::Secrets for Dedup {
    fn dedup(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        None
    }
    fn chain_write(&self) -> Option<osis_crypto::Secret32> {
        None
    }
    fn write(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        None
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
    let mut w = Writer::new(ts, Source::node(author), lo);
    let f = create(&mut w, &view, v).unwrap();
    let r = w.range();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Kind::Membership, ts, author, r.lo, r.hi), None).unwrap();
    let mut aw = AspectWrite::new(t, ak.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Membership, ts, author, author, Form::Node);
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
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    let author = lp.peers[by].engine.tid();
    let snap = osis_crdt::Snapshot { nonce: [7; 16], fragment: f, frontiers };
    let bytes = osis_crdt::encode_snapshot(&snap, &writer_ctx(Kind::ContentSnapshot, ts, author, 0, 0), None).unwrap();
    let mut aw = AspectWrite::new(t, a.clone(), 0, 0, bytes);
    aw.retention = osis_commit::retention::snapshot_retention(a.as_str(), None);
    let mut cb = CommitBuilder::new(Kind::ContentSnapshot, ts, author, author, Form::Node);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    cb.build(&lp.peers[by].engine.identity().keys().signing, &Tokens(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

/// Secrets for hand-built commits with `writer` retention: dedup, and made-up write secrets
/// (delete tokens are servers' business).
struct Tokens(osis_core::CreationRecord);
impl osis_commit::Secrets for Tokens {
    fn dedup(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::dedup_secret(self.0.nonce()))
    }
    fn admin(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        None
    }
    fn chain_write(&self) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::Secret32::from_bytes([1; 32]))
    }
    fn write(&self, _: &Tid) -> Option<osis_crypto::Secret32> {
        Some(osis_crypto::Secret32::from_bytes([2; 32]))
    }
}

/// One map entry `k: v` written by `node` at `ts` with counters from `lo`.
fn entry_by(node: Tid, ts: osis_core::Ts, lo: u64, k: &str, v: &str) -> osis_crdt::Fragment {
    let mut w = osis_crdt::Writer::new(ts, osis_crdt::Source::node(node), lo);
    osis_crdt::create(&mut w, &osis_crdt::AnyView, &Value::Map(BTreeMap::from([(s(k), s(v))]))).unwrap()
}

// spec/permissions.md §5.2 (a compaction snapshot vouches for nothing), spec/commits.md §2
// (written by a node that may write the aspect): a writer's hostile snapshot carrying two stamps
// of Bob from before his grant, at counters below and far above his real ones, un-merges exactly
// those dots, not Bob's held write between them, and keeps the owner's write it carries.
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
    let mut f = entry_by(b, old, lo - 1, "f1", "x");
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
