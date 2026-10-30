//! Roster snapshot inputs (spec/permissions.md §6, spec/commits.md §4): linked tenure frontiers
//! recorded once read, never audited as empty, bounded, bad input when unlisted or not a
//! frontier; members named twice; certificate projections failing closed.

use crate::local_peer::LocalPeer;
use crate::{Ingested, Mutation};
use osis_base::{CommitId, Role, Tid, Ts, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::core_types as ct;
use osis_schema::Codec;
use std::collections::{BTreeMap, BTreeSet};

const T0: WallMs = WallMs(1_700_000_000_000);

fn tags(lp: &mut LocalPeer, i: usize, t: Tid) -> Option<Value> {
    lp.peers[i].engine.get(&t, &osis_base::Ak::new("/t/tags").unwrap()).unwrap()
}

/// A frontier covering `x`'s first write on `t`'s `/t/tags`, padded past `CHUNK_THRESHOLD`
/// with `pad` (distinct pads give distinct frontiers).
fn big_frontier(t: Tid, x: Tid, pad: u8) -> ct::Frontier {
    let tags = |n: u64| BTreeMap::from([("/t/tags".to_string(), BTreeMap::from([(x, n)]))]);
    let mut writes = BTreeMap::from([(t, tags(1))]);
    for i in 0..4000u32 {
        let b = i.to_be_bytes();
        writes.insert(Tid::from_bytes([b[0], b[1], b[2], b[3], pad, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]), tags(5));
    }
    ct::Frontier { writes, commits: BTreeSet::new() }
}

/// Peer 0 owns `t`; peer 1's node wrote a tag as a writer and was demoted with a linked
/// frontier covering it; peer 0 wrote a roster snapshot of `t` (the ledger links it).
fn demoted_writer() -> (LocalPeer, Tid, Tid, CommitId) {
    demoted_writer_of(2)
}

fn demoted_writer_of(n: usize) -> (LocalPeer, Tid, Tid, CommitId) {
    let mut lp = LocalPeer::new(n, 940, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let x = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &osis_base::Ak::new("/t/reg").unwrap(), &Value::Int(1)).unwrap();
    lp.peers[0].commit(m).unwrap();
    edge(&mut lp, t, x, Some(Role::Write), None);
    lp.sync(0, 1).unwrap();
    let mut m = Mutation::new();
    m.op(t, &osis_base::Ak::new("/t/tags").unwrap(), PathOp { path: Vec::new(), op: Op::Add(Value::Str("by x".into())) }).unwrap();
    lp.peers[1].commit(m).unwrap();
    lp.sync(1, 0).unwrap();
    edge(&mut lp, t, x, None, Some(big_frontier(t, x, 1).to_value()));
    let s = *lp.peers[0].engine.roster_snapshot(&t, None).unwrap().commits.last().unwrap();
    (lp, t, x, s)
}

fn edge(lp: &mut LocalPeer, t: Tid, m: Tid, role: Option<Role>, frontier: Option<Value>) {
    let mut mu = Mutation::new();
    let op = match role {
        Some(role) => PathOp { path: vec![PathSeg::Key(Value::Tid(m))], op: Op::Set(ct::Edge { role, until: None, invite: None, since: None }.to_value()) },
        None => PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(m)) },
    };
    mu.op(t, &ct::MEMBERS, op).unwrap();
    if let Some(f) = frontier {
        mu.frontier(f);
    }
    lp.peers[0].commit(mu).unwrap().unwrap();
}

/// The linked frontiers' tree blobs of commit `c` (its chunk list).
fn chunk_blobs(lp: &mut LocalPeer, c: &CommitId) -> Vec<osis_base::BlobId> {
    lp.peers[0].engine.header(c).unwrap().chunks.iter().map(|x| x.blob).collect()
}

// spec/permissions.md §6: a linked frontier read once is recorded, so a restart with its tree
// gone still judges by it; with neither the record nor the tree, the snapshot stays out of the
// timeline (never an empty frontier) and no roster snapshot of the thing is written.
#[test]
fn load_with_missing_frontier_blob_spec_perm_6() {
    let (mut lp, t, _, s) = demoted_writer();
    let roster = lp.peers[0].engine.roster(&t);
    let blobs = chunk_blobs(&mut lp, &s);
    assert!(!blobs.is_empty());
    lp.peers[0].engine.run(|tx| {
        for b in &blobs {
            tx.txn.delete_blob(b);
        }
        Ok(())
    }).unwrap();
    lp.peers[0].restart(941).unwrap();
    assert_eq!(lp.peers[0].engine.roster(&t), roster);
    assert_eq!(tags(&mut lp, 0, t), Some(Value::Set([Value::Str("by x".into())].into())), "judged by the recorded frontier");
    // the record gone too: kept out of the timeline, refused as a snapshot source
    lp.peers[0].engine.run(|tx| {
        let mut keys = Vec::new();
        tx.scan(b"n/", |k, _| {
            keys.push(k.to_vec());
            Ok(())
        })?;
        for k in keys {
            tx.txn.remove_local(&[b"n/".as_slice(), &k].concat(), osis_store::Shred::No)?;
        }
        Ok(())
    }).unwrap();
    lp.peers[0].restart(942).unwrap();
    assert!(lp.peers[0].engine.core.ix.frontier_unknown.contains(&t));
    assert!(lp.peers[0].engine.roster_snapshot(&t, None).is_err(), "no snapshot from an unknown ledger");
    assert_eq!(tags(&mut lp, 0, t), Some(Value::Set([Value::Str("by x".into())].into())), "the full history still judges it");
}

/// Peer 0 writes, breaking the writer rules, a roster snapshot of `t` whose ledger is
/// `tenures` (values as written); returns the commit.
fn raw_snapshot(lp: &mut LocalPeer, t: Tid, tenures: Vec<Value>) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Replace(Value::Map(BTreeMap::new())) }).unwrap();
    m.op(t, &ct::TENURES, PathOp { path: Vec::new(), op: Op::Replace(Value::Set(tenures.into_iter().collect())) }).unwrap();
    m.roster = true;
    lp.peers[0].engine.core.skip_writer_rules = true;
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].engine.core.skip_writer_rules = false;
    c
}

fn tenure(member: Tid, frontier: Option<Value>) -> Value {
    let mut v = ct::Tenure { member, role: Role::Write, since: None, until: ct::EdgeKey { ts: Ts::make(T0, 0).unwrap(), node: member, commit: osis_base::CommitId([0; 32]) }, frontier: None }.to_value();
    if let (Value::Map(m), Some(f)) = (&mut v, frontier) {
        m.insert(Value::Int(4), Value::Enum(1, Some(Box::new(f))));
    }
    v
}

fn deliver_all(lp: &mut LocalPeer, last: &CommitId) -> crate::Result<Ingested> {
    for p in lp.packages(0).unwrap() {
        if p.id != *last {
            lp.deliver(1, &p).unwrap();
        }
    }
    let pk = lp.peers[0].engine.package(last).unwrap().unwrap();
    lp.deliver(1, &pk)
}

// spec/permissions.md §5, §6, spec/commits.md §4: a snapshot whose linked frontier's blobs are
// not held waits for them, also when a later epoch start of its thing is applied, so the held
// snapshots do not depend on arrival order (issues/roster-superseded-order.md).
#[test]
fn linked_frontier_wait_order_independent_spec_perm_6() {
    use osis_perm::HeldSet;
    let (mut lp, t, _, s1) = demoted_writer_of(3);
    lp.advance(10);
    let s2 = raw_snapshot(&mut lp, t, Vec::new());
    let missing = chunk_blobs(&mut lp, &s1);
    assert!(!missing.is_empty());
    let pk1 = lp.peers[0].engine.package(&s1).unwrap().unwrap();
    let pk2 = lp.peers[0].engine.package(&s2).unwrap().unwrap();
    let bare = crate::local_peer::Package { id: s1, bytes: pk1.bytes.clone(), blobs: pk1.blobs.iter().filter(|(b, _)| !missing.contains(b)).cloned().collect() };
    for p in lp.packages(0).unwrap() {
        if p.id != s1 && p.id != s2 {
            lp.deliver(1, &p).unwrap();
            lp.deliver(2, &p).unwrap();
        }
    }
    // peer 1: S2 first, then S1 without its frontier's blobs
    assert!(matches!(lp.deliver(1, &pk2).unwrap(), Ingested::Applied(_)));
    assert!(matches!(lp.deliver(1, &bare).unwrap(), Ingested::Pending(..)), "waits despite the later start");
    // peer 2: S1 without blobs, then S2
    assert!(matches!(lp.deliver(2, &bare).unwrap(), Ingested::Pending(..)));
    assert!(matches!(lp.deliver(2, &pk2).unwrap(), Ingested::Applied(_)));
    for i in [1, 2] {
        assert!(matches!(lp.deliver(i, &pk1).unwrap(), Ingested::Applied(_)));
    }
    let held = |lp: &LocalPeer, i: usize| -> BTreeSet<CommitId> { lp.peers[i].engine.core.ix.held.roster_snapshots(&t).iter().map(|s| s.id).collect() };
    assert_eq!(held(&lp, 1), BTreeSet::from([s1, s2]));
    assert_eq!(held(&lp, 1), held(&lp, 2));
    assert_eq!(lp.peers[1].engine.roster(&t), lp.peers[2].engine.roster(&t));
}

// spec/permissions.md §6 (linked frontier bounds): a linked frontier whose value is not a frontier
// is bad input.
#[test]
fn malformed_linked_frontier_spec_perm_6() {
    let mut lp = LocalPeer::new(2, 943, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    let junk = Value::Bytes(vec![9; osis_base::format::CHUNK_THRESHOLD + 10]);
    let c = raw_snapshot(&mut lp, t, vec![tenure(me, Some(junk))]);
    assert!(matches!(deliver_all(&mut lp, &c), Err(crate::Error::BadInput(_))));
}

// spec/permissions.md §6, spec/commits.md §4: a link outside the commit's chunk list is bad
// input, never waited for.
#[test]
fn unresolvable_linked_frontier_spec_perm_6() {
    let mut lp = LocalPeer::new(2, 944, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    let fake = osis_base::Link { hash: [3; 32], blob: osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] };
    let c = raw_snapshot(&mut lp, t, vec![tenure(me, Some(Value::Link(fake)))]);
    assert!(matches!(deliver_all(&mut lp, &c), Err(crate::Error::BadInput(_))));
}

// spec/permissions.md §6 (linked frontier bounds): many tenures linking one frontier read it
// once; distinct linked frontiers above the bound are bad input.
#[test]
fn linked_frontier_amplification_bound_spec_perm_6() {
    let mut lp = LocalPeer::new(1, 945, T0).unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    let f1 = big_frontier(t, me, 1).to_value();
    let size = osis_base::encode(&f1).len();
    let same: Vec<Value> = (0..40u8).map(|i| tenure(Tid::from_bytes([i; 15]), Some(f1.clone()))).collect();
    let c = raw_snapshot(&mut lp, t, same);
    let check = |lp: &mut LocalPeer, c: CommitId, cap: usize| {
        lp.peers[0].engine.core.frontiers.clear();
        lp.peers[0].engine.run(|tx| {
            let h = (*tx.core.ix.commits.get(&c).unwrap().header).clone();
            let parts = super::edge_parts(tx, &c)?;
            super::validity::linked_frontiers_capped(tx, &h, &parts, cap).map(|l| l.frontiers.len())
        })
    };
    assert_eq!(check(&mut lp, c, size + 64).unwrap(), 1, "forty tenures, one frontier read");
    let two = vec![tenure(Tid::from_bytes([1; 15]), Some(f1)), tenure(Tid::from_bytes([2; 15]), Some(big_frontier(t, me, 2).to_value()))];
    let c2 = raw_snapshot(&mut lp, t, two);
    assert!(matches!(check(&mut lp, c2, size + 64), Err(crate::Error::BadInput(_))));
    assert_eq!(check(&mut lp, c2, 3 * size).unwrap(), 2);
}

// spec/permissions.md §6: a roster snapshot naming one member in two `/members` deltas is bad
// input (which one counts would depend on the deltas a node holds).
#[test]
fn member_named_twice_spec_perm_6() {
    let mut lp = LocalPeer::new(2, 946, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let x = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    edge(&mut lp, t, x, Some(Role::Read), None);
    let c = *lp.peers[0].engine.roster_snapshot(&t, None).unwrap().commits.last().unwrap();
    let r = lp.peers[0].engine.run(|tx| {
        let h = (*tx.core.ix.commits.get(&c).unwrap().header).clone();
        let mut parts = super::held_parts_at(tx, &c, &|_| true)?;
        super::validity::check_roster_parts(&h, &parts)?;
        let named = parts.iter().find(|(ai, _, d)| h.aspects[*ai].ak.as_str() == "/members" && matches!(d, osis_commit::Decoded::Delta(d) if super::validity::named_members("/members", &d.fragment) == vec![x])).cloned().unwrap();
        parts.push(named);
        super::validity::check_roster_parts(&h, &parts)
    });
    assert!(matches!(r, Err(crate::Error::BadInput(_))));
}

// spec/permissions.md §4, §6: a roster snapshot certificate that cannot be read here is not
// placed at all, never whole.
#[test]
fn unreadable_snapshot_certificate_fails_closed_spec_perm_6() {
    let mut lp = LocalPeer::new(1, 947, T0).unwrap();
    let rx = lp.peers[0].engine.subscribe();
    let e = &mut lp.peers[0].engine;
    let t = e.tid();
    let parts = e.snapshot_parts(&CommitId([7; 32]), &BTreeSet::from([t]), &BTreeSet::from([t]));
    assert!(parts.is_empty());
    let mut diag = false;
    while let Ok(ev) = rx.try_recv() {
        diag |= matches!(ev, crate::Event::Diagnostic(_));
    }
    assert!(diag, "a diagnostic says why");
}

// spec/data-model.md §6, spec/permissions.md §6: a `/tenures` element is never chunked whole,
// its frontier is: a frontier just under `CHUNK_THRESHOLD` stays inline (no link) while
// its tenure element is above it, and the snapshot applies elsewhere, judging by that frontier.
#[test]
fn tenure_with_frontier_under_threshold_spec_perm_6() {
    use osis_base::format::CHUNK_THRESHOLD;
    let mut lp = LocalPeer::new(2, 948, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let x = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &osis_base::Ak::new("/t/reg").unwrap(), &Value::Int(1)).unwrap();
    lp.peers[0].commit(m).unwrap();
    edge(&mut lp, t, x, Some(Role::Write), None);
    lp.sync(0, 1).unwrap();
    let mut m = Mutation::new();
    m.op(t, &osis_base::Ak::new("/t/tags").unwrap(), PathOp { path: Vec::new(), op: Op::Add(Value::Str("by x".into())) }).unwrap();
    lp.peers[1].commit(m).unwrap();
    lp.sync(1, 0).unwrap();
    // the largest frontier of this shape at or under the threshold
    let tw = |n: u64| BTreeMap::from([("/t/tags".to_string(), BTreeMap::from([(x, n)]))]);
    let frontier = |n: u32| {
        let mut f = ct::Frontier { writes: BTreeMap::from([(t, tw(1))]), commits: BTreeSet::new() };
        for i in 0..n {
            let b = i.to_be_bytes();
            f.writes.insert(Tid::from_bytes([b[0], b[1], b[2], b[3], 9, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]), tw(5));
        }
        f
    };
    let size = |f: &ct::Frontier| osis_base::encode(&f.to_value()).len();
    // binary search for the most extra entries that fit
    let (mut lo, mut hi) = (0u32, 1u32);
    while size(&frontier(hi)) <= CHUNK_THRESHOLD {
        (lo, hi) = (hi, hi * 2);
    }
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if size(&frontier(mid)) <= CHUNK_THRESHOLD { lo = mid } else { hi = mid }
    }
    let f = frontier(lo);
    assert!(size(&f) <= CHUNK_THRESHOLD && size(&f) + 64 > CHUNK_THRESHOLD);
    edge(&mut lp, t, x, None, Some(f.to_value()));
    let s = *lp.peers[0].engine.roster_snapshot(&t, None).unwrap().commits.last().unwrap();
    let ledger = lp.peers[0].engine.get(&t, &osis_base::Ak::new("/tenures").unwrap()).unwrap();
    let Some(Value::Set(ledger)) = ledger else { panic!("no ledger") };
    let mut links = Vec::new();
    ledger.iter().for_each(|e| crate::engine::large::links_in(e, &mut links));
    assert!(links.is_empty() && ledger.iter().any(|e| osis_base::encode(e).len() > CHUNK_THRESHOLD), "the tenure element is above the threshold, inline");
    deliver_all(&mut lp, &s).unwrap();
    assert_eq!(tags(&mut lp, 1, t), Some(Value::Set([Value::Str("by x".into())].into())), "judged by the inline frontier");
}

// spec/commits.md §2, spec/permissions.md §9: a redemption's grant and self-removal are both on
// K; the writer refuses a self-removal on one thing plus a grant on another (two edges).
#[test]
fn redemption_on_two_targets_refused_spec_commits_2() {
    let mut lp = LocalPeer::new(2, 950, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let a = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let n = lp.peers[0].engine.new_thing(&mut m, me);
    let k = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    edge(&mut lp, n, a, Some(Role::Admin), None);
    edge(&mut lp, k, a, Some(Role::Admin), None);
    lp.sync_all().unwrap();
    let x = Tid::from_bytes([9; 15]);
    let mut mu = Mutation::new();
    mu.op(n, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(a)) }).unwrap();
    mu.op(k, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(x))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, since: None }.to_value()) }).unwrap();
    let r = lp.peers[1].commit(mu);
    assert!(matches!(r, Err(crate::Error::BadInput(m)) if m.contains("more than one edge")), "{r:?}");
}
