#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The receiving path: verification, dedup, pending reasons, parking, atomic apply, late
//! deltas, events, and convergence under random delivery.

mod common;
use common::*;
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, Form, Kind, MemoryBlobs};
use osis_core::Classified;
use osis_core::{Role, Tid, Ts, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_crypto::{RngCore, Secret32, SeededRng};
use osis_node::{Event, Ingested, Mutation, Origin, Reason};
use osis_schema::{Bound, PurgeBy, Retention};

// spec/commits.md §4: a commit whose signature does not verify is bad input: a diagnostic,
// nothing stored.
#[test]
fn bad_signature_rejected_spec_commits_4() {
    let mut lp = net(2, 21);
    new_thing(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    let mut blob = CommitBlob::decode(&pks[2].bytes).unwrap();
    let Value::Enum(c, Some(p)) = blob.signature.to_value() else { panic!() };
    let Value::Bytes(mut sig) = *p else { panic!() };
    sig[0] ^= 1;
    blob.signature = osis_crypto::Signature::from_value(&Value::Enum(c, Some(Box::new(Value::Bytes(sig))))).unwrap();
    for p in &pks[..2] {
        lp.deliver(1, p).unwrap();
    }
    lp.peers[1].drain_events();
    let r = lp.peers[1].engine.ingest(&blob.encode(), Vec::new());
    assert_eq!(r.unwrap_err().class(), osis_core::ErrorClass::BadInput);
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Diagnostic(d) if d.kind == osis_node::DiagnosticKind::BadInput)));
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.commit_ids().len(), 4);
}

// spec/commits.md §4: receivers dedup by commit ID; remote applies fire events with origin.
#[test]
fn dedup_and_events_spec_commits_4() {
    let mut lp = net(2, 22);
    let t = new_thing(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    for p in &pks {
        assert!(matches!(lp.deliver(1, p).unwrap(), Ingested::Applied(_)));
    }
    for p in &pks {
        assert!(matches!(lp.deliver(1, p).unwrap(), Ingested::Duplicate(_)));
    }
    let ev = lp.peers[1].drain_events();
    let last = ev.iter().rev().find_map(|e| match e {
        Event::Applied { origin, changed, author, .. } => Some((*origin, changed.clone(), *author)),
        _ => None,
    });
    let (origin, changed, author) = last.unwrap();
    assert_eq!(origin, Origin::Remote);
    assert_eq!(author, lp.peers[0].engine.tid());
    assert!(changed.contains(&(t, ak("/t/reg"))));
}

// spec/commits.md §4: unknown `/created` of the author or a touched thing keeps a commit
// pending, counted as not received; it applies once the record arrives.
#[test]
fn pending_until_created_spec_commits_4() {
    let mut lp = net(2, 23);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("second")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pks = packages(&mut lp, 0);
    // the last commit first: its author's /created is unknown
    let r = lp.deliver(1, pks.last().unwrap()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(_))), "{r:?}");
    assert!(lp.peers[1].engine.receipt(&t, &ak("/t/reg")).unwrap().nodes.is_empty());
    // node commits, then the thing's creation
    for p in &pks[..2] {
        lp.deliver(1, p).unwrap();
    }
    let r = lp.peers[1].engine.ingest(&pks.last().unwrap().bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
    lp.deliver(1, &pks[2]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("second")));
    // pending survives a restart too (checked through a fresh pending commit)
    let mut m = Mutation::new();
    m.set(t, &REG, &s("third")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let mut lp2 = net(1, 24);
    assert!(matches!(lp2.deliver(0, &pk).unwrap(), Ingested::Pending(..)));
    lp2.peers[0].restart(99).unwrap();
    assert_eq!(lp2.peers[0].engine.pending().len(), 1);
}

// spec/crdt.md §2.2: a commit more than MAX_DRIFT ahead is parked until local time catches
// up; then it applies and advances the clock.
#[test]
fn drift_parks_spec_crdt_2_2() {
    let mut lp = net(2, 25);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[0].clock.advance(2 * 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("future")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Pending(_, Reason::Drift)));
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending().len(), 1);
    lp.peers[1].clock.advance(3_600_000 + 1);
    lp.peers[1].engine.tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("future")));
    // the HLC moved past the received ts
    let me = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t2 = lp.peers[1].engine.new_thing(&mut m, me);
    m.set(t2, &REG, &s("x")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    let theirs = lp.peers[0].engine.header(&pk.id).unwrap().ts;
    assert!(lp.peers[1].engine.header(&id).unwrap().ts > theirs);
}

fn without_parts(bytes: &[u8], keep: impl Fn(&str) -> bool, h: &osis_commit::Header) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].ak.as_str()));
    b.encode()
}

// spec/commits.md §4: atomic apply waits for every delta under a synced thing; a delta of an
// applied commit arriving later is joined on arrival.
#[test]
fn atomic_wait_and_late_delta_spec_commits_4() {
    let mut lp = net(2, 26);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let partial = without_parts(&pk.bytes, |a| a == "/t/reg", &h);
    // not synced: applies with what arrived
    assert!(matches!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/tags")).unwrap(), None);
    lp.peers[1].drain_events();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(_)));
    assert!(lp.peers[1].engine.get(&t, &ak("/t/tags")).unwrap().is_some());
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: osis_node::Cause::LateDelta, .. })));
    // synced: waits
    let mut lp = net(2, 27);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let partial = without_parts(&pk.bytes, |a| a == "/t/reg", &h);
    assert!(matches!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Pending(_, Reason::WaitDeltas)));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("new")));
    // stopping to sync the thing re-examines it
    lp.peers[1].engine.set_syncing(t, false).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("r")));
}

/// Secrets for hand-built commits with `nobody` retention: dedup only.
struct Dedup(Vec<osis_core::CreationRecord>);
impl osis_commit::Secrets for Dedup {
    fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.0.iter().find(|r| r.tid() == *tid).map(|r| osis_crypto::dedup_secret(r.nonce()))
    }
    fn admin(&self, _: &Tid) -> Option<Secret32> {
        None
    }
    fn chain_write(&self) -> Option<Secret32> {
        None
    }
    fn write(&self, _: &Tid) -> Option<Secret32> {
        None
    }
}

// spec/versioning.md §2: an unknown encoding or format version parks the commit as bytes; it
// is relayed and re-examined (after an upgrade), never rejected; others still apply.
#[test]
fn parked_spec_versioning_2() {
    let mut lp = net(2, 28);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[0].engine;
    let rec = e.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let ts = Ts::make(WallMs(T0.0 + 10), 0).unwrap();
    let delta = osis_core::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])]));
    let mut w = AspectWrite::new(t, ak("/t/future"), 100, 101, delta);
    w.retention = Retention { by: PurgeBy::Nobody, at_least: Bound::default(), at_most: Bound::default() };
    let mut b = CommitBuilder::new(Kind::Content, ts, e.tid(), e.tid(), Form::Node);
    b.aspects.push(w);
    let built = b.build(&e.identity().keys().signing, &Dedup(vec![rec]), &mut MemoryBlobs::default(), &mut SeededRng::from_u64(1)).unwrap();
    let bytes = built.commit.encode();
    let r = lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Parked(_)), "{r:?}");
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending().len(), 1);
    assert_eq!(lp.peers[1].engine.commit_bytes(&built.commit.id()).unwrap(), Some(bytes));
    // an unknown format version: the header does not even decode
    let mut v = osis_core::decode(&built.commit.encode(), &osis_core::Limits::DEFAULT).unwrap();
    if let Value::List(items) = &mut v
        && let Some(Value::List(h)) = items.first_mut()
    {
        h[0] = Value::Int(2);
    }
    let r = lp.peers[1].engine.ingest(&osis_core::encode(&v), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Parked(_)), "{r:?}");
    // other commits still apply
    let mut m = Mutation::new();
    m.set(t, &REG, &s("on")).unwrap();
    lp.peers[0].commit(m).unwrap();
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("on")));
    assert_eq!(lp.peers[1].engine.pending().len(), 2);
}

// spec/commits.md §2, §4: membership before content: a grantee's write arriving before its
// grant waits for the chain and applies after.
#[test]
fn grantee_waits_for_grant_spec_commits_4() {
    let mut lp = net(3, 29);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("from b")).unwrap();
    lp.peers[1].commit(m).unwrap();
    // peer 2 gets b's own commits first, then a's
    for pk in packages(&mut lp, 1) {
        if lp.peers[1].engine.header(&pk.id).unwrap().author == b {
            lp.deliver(2, &pk).unwrap();
        }
    }
    assert!(!lp.peers[2].engine.pending().is_empty());
    sync(&mut lp, 0, 2);
    assert!(lp.peers[2].engine.pending().is_empty(), "{:?}", lp.peers[2].engine.pending());
    assert_eq!(lp.peers[2].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s("from b")));
}

// spec/crdt.md §4.1 at the node level: three writers, random ops, random delivery order with
// duplicates converge to equal states.
#[test]
fn random_delivery_converges_spec_crdt_4_1() {
    for seed in 0..4u64 {
        let mut rng = SeededRng::from_u64(seed);
        let mut lp = net(3, 100 + seed);
        // node identities everywhere; the thing, grants and later a revoke travel out of order
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        for i in 1..3 {
            let m = lp.peers[i].engine.tid();
            set_edge(&mut lp.peers[0].engine, t, m, Some(edge(Role::Write)), None);
        }
        let mut sent: Vec<osis_node::local_peer::Package> = lp.packages(0).unwrap();
        for i in 1..3 {
            for p in sent.clone() {
                lp.deliver(i, &p).unwrap();
            }
        }
        let victim = lp.peers[2].engine.tid();
        for step in 0..30 {
            if step == 15 {
                // revoke node 2 mid-run (spec/permissions.md §5.2), frontier from node 0's receipts
                let scope = osis_perm::DemotionScope { membership: [(victim, [t].into())].into(), content: [(victim, [t].into())].into() };
                let now = lp.peers[0].engine.now();
                let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
                let id = set_edge(&mut lp.peers[0].engine, t, victim, None, Some(osis_schema::Codec::to_value(&f)));
                sent.push(lp.peers[0].engine.package(&id).unwrap().unwrap());
            }
            let i = (rng.next_u32() % 3) as usize;
            let mut m = Mutation::new();
            let x = rng.next_u32() as i64 % 5;
            match rng.next_u32() % 5 {
                0 => m.set(t, &REG, &s(&format!("v{step}"))).unwrap(),
                1 => m.op(t, &COUNT, PathOp { path: Vec::new(), op: Op::Inc(Value::Int(x)) }).unwrap(),
                2 => m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(&format!("t{x}"))) }).unwrap(),
                3 => m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Remove(s(&format!("t{x}"))) }).unwrap(),
                _ => m.op(t, &MAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s(&format!("k{x}")))], op: Op::Set(item("m", step)) }).unwrap(),
            };
            lp.peers[i].clock.advance(rng.next_u32() as u64 % 50);
            if let Ok(Some(id)) = lp.peers[i].commit(m) {
                sent.push(lp.peers[i].engine.package(&id).unwrap().unwrap());
            }
            // deliver a random earlier package to a random peer
            if !sent.is_empty() {
                let k = (rng.next_u32() as usize) % sent.len();
                let to = (rng.next_u32() % 3) as usize;
                let pk = sent[k].clone();
                let _ = lp.deliver(to, &pk);
            }
        }
        // deliver everything in a shuffled order, twice
        for _ in 0..2 {
            let mut order: Vec<usize> = (0..sent.len()).collect();
            for i in (1..order.len()).rev() {
                order.swap(i, (rng.next_u32() as usize) % (i + 1));
            }
            for k in order {
                for to in 0..3 {
                    let pk = sent[k].clone();
                    lp.deliver(to, &pk).unwrap();
                }
            }
        }
        let a = states(&mut lp.peers[0].engine, &[t]);
        for i in 0..3 {
            assert!(lp.peers[i].engine.pending().is_empty(), "{i} {:?}", lp.peers[i].engine.pending());
        }
        for i in 1..3 {
            assert_eq!(a, states(&mut lp.peers[i].engine, &[t]), "seed {seed}");
            for (tid, ak, _) in &a {
                assert_eq!(lp.peers[0].engine.state(tid, ak).unwrap(), lp.peers[i].engine.state(tid, ak).unwrap());
            }
        }
    }
}

