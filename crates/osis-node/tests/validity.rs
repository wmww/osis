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

// issues/commit-delta-content-rules.md; spec/commits.md §2: a membership commit changes at most
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
