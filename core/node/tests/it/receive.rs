#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The receiving path: verification, dedup, pending reasons, parking, apply, late
//! deltas and events.

use crate::common;
use common::*;
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, Kind, MemoryBlobs};
use osis_base::Classified;
use osis_base::{Role, Tid, Ts, Value, WallMs};
use osis_crypto::{Secret32, SeededRng};
use osis_node::{Event, Ingested, Mutation, Origin, Reason};

// spec/commits.md §4: a commit whose signature does not verify is bad input: a diagnostic,
// nothing stored.
// spec/commits.md §4 (signature)
#[test]
fn bad_signature_rejected_spec_commits_4() {
    let mut lp = net(2, 21);
    new_thing(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    let mut blob = CommitBlob::decode(&pks[2].bytes).unwrap();
    let Value::Enum(c, Some(p)) = blob.sigs.signature.to_value() else { panic!() };
    let Value::Bytes(mut sig) = *p else { panic!() };
    sig[0] ^= 1;
    blob.sigs.signature = osis_crypto::Signature::from_value(&Value::Enum(c, Some(Box::new(Value::Bytes(sig))))).unwrap();
    for p in &pks[..2] {
        lp.deliver(1, p).unwrap();
    }
    lp.peers[1].drain_events();
    let r = lp.peers[1].engine.ingest(&blob.encode(), Vec::new());
    assert_eq!(r.unwrap_err().class(), osis_base::ErrorClass::BadInput);
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
    assert!(changed.contains(&(t, ak("t:reg.0"))));
}

// spec/commits.md §4: unknown `created.0` of the author or a touched thing keeps a commit
// pending, counted as not received; it applies once the record arrives.
#[test]
fn pending_until_created_spec_commits_4() {
    let mut lp = net(2, 23);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("second")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pks = packages(&mut lp, 0);
    // the last commit first: its author's created.0 is unknown
    let r = lp.deliver(1, pks.last().unwrap()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(_))), "{r:?}");
    let me = lp.peers[0].engine.tid();
    let scope = osis_perm::DemotionScope { roles: Default::default(), content: [(me, [t].into())].into() };
    let now = lp.peers[1].engine.now();
    assert!(!lp.peers[1].engine.frontier(&scope, now).unwrap().commits.contains(&pks.last().unwrap().id), "pending: not received");
    // node commits, then the thing's creation
    for p in &pks[..2] {
        lp.deliver(1, p).unwrap();
    }
    let r = lp.peers[1].engine.ingest(&pks.last().unwrap().bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
    lp.deliver(1, &pks[2]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("second")));
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

// spec/commits.md §4: commits waiting for a thing's `created.0` apply once it arrives; while
// they wait, commits applied in between re-examine none of them (spec/requirements.md, Scale:
// a first sync is O(commits), not O(commits × pending)).
#[test]
fn pending_not_reexamined_while_unchanged_spec_commits_4() {
    let mut lp = net(2, 28);
    let u = new_thing(&mut lp, 0);
    let t = new_thing(&mut lp, 0);
    for i in 0..40 {
        for x in [t, u] {
            let mut m = Mutation::new();
            m.set(x, &REG, &s(&format!("v{i}"))).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
    }
    let pks = packages(&mut lp, 0);
    // node commits and u's creation; t's creation (pks[3]) last
    for p in &pks[..3] {
        lp.deliver(1, p).unwrap();
    }
    osis_node::costs::take();
    for (i, p) in pks[4..].iter().enumerate() {
        let r = lp.deliver(1, p).unwrap();
        if i % 2 == 0 {
            assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
        } else {
            assert!(matches!(r, Ingested::Applied(_)), "{r:?}");
        }
    }
    let examined = |c: &[(&str, std::time::Duration, u64)]| c.iter().find(|x| x.0 == "examine").map_or(0, |x| x.2);
    assert_eq!(examined(&osis_node::costs::take()), 80, "each commit examined once");
    lp.deliver(1, &pks[3]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("v39")));
    assert_eq!(examined(&osis_node::costs::take()), 41);
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
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("future")));
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

// spec/commits.md §4: a node applies the parts it holds and never waits for one, synced or not, on
// one thing or across things; a delta of an applied commit arriving later is joined on arrival.
#[test]
fn applies_what_is_held_and_late_delta_spec_commits_4() {
    let mut lp = net(2, 26);
    let t = new_thing(&mut lp, 0);
    let u = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(u, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let partial = without_parts(&pk.bytes, |a| a == "t:reg.0", &h);
    // another thing, not synced: applies with what arrived
    assert!(matches!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
    assert_eq!(lp.peers[1].engine.get(&u, &ak("t:tags.0")).unwrap(), None);
    lp.peers[1].drain_events();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(_)));
    assert!(lp.peers[1].engine.get(&u, &ak("t:tags.0")).unwrap().is_some());
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: osis_node::Cause::LateDelta, .. })));
    // the same thing, synced: applies what is held too
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
    let partial = without_parts(&pk.bytes, |a| a == "t:reg.0", &h);
    assert_eq!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:tags.0")).unwrap(), None);
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(_)));
    assert!(lp.peers[1].engine.get(&t, &ak("t:tags.0")).unwrap().is_some());
    // across things, the other one synced: applies what is held
    let mut lp = net(2, 28);
    let (t, u) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(u, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(u, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let partial = without_parts(&pk.bytes, |a| a == "t:reg.0", &h);
    assert_eq!(lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
    assert!(lp.peers[1].engine.pending().is_empty());
}

/// Secrets for hand-built commits: dedup, and made-up delete keys (hosts' business).
pub(crate) struct Dedup(pub(crate) Vec<osis_base::CreationRecord>);
impl osis_commit::Secrets for Dedup {
    fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.0.iter().find(|r| r.tid() == *tid).map(|r| osis_crypto::dedup_secret(r.nonce()))
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

// spec/versioning.md §2: an unknown encoding or format version parks the commit as bytes; it
// is relayed and re-examined (after an upgrade), never rejected; others still apply.
// spec/versioning.md §2 (park unknown)
#[test]
fn parked_spec_versioning_2() {
    let mut lp = net(2, 28);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[0].engine;
    let rec = e.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let ts = Ts::make(WallMs(T0.0 + 10), 0).unwrap();
    let delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])]));
    let mut w = AspectWrite::new(t, ak("t:future.0"), 100, 101, delta);
    w.retention = crate::common::purgeable_by(osis_base::PurgeBy::Nobody);
    let mut b = CommitBuilder::new(Kind::Content, ts, e.tid(), e.tid(), crate::common::forged_session(e.tid()));
    b.aspects.push(w);
    let built = b.build(&e.identity().keys().signing, &Dedup(vec![rec]), &mut MemoryBlobs::default(), &mut SeededRng::from_u64(1)).unwrap();
    let bytes = built.commit.encode();
    let r = lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Parked(_)), "{r:?}");
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending().len(), 1);
    assert_eq!(lp.peers[1].engine.commit_bytes(&built.commit.id()).unwrap(), Some(bytes));
    // an unknown format version: the header does not even decode
    let mut v = osis_base::decode(&built.commit.encode(), &osis_base::Limits::DEFAULT).unwrap();
    if let Value::List(items) = &mut v
        && let Some(Value::List(h)) = items.first_mut()
    {
        h[0] = Value::Int(2);
    }
    let r = lp.peers[1].engine.ingest(&osis_base::encode(&v), Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Parked(_)), "{r:?}");
    // other commits still apply
    let mut m = Mutation::new();
    m.set(t, &REG, &s("on")).unwrap();
    lp.peers[0].commit(m).unwrap();
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("on")));
    assert_eq!(lp.peers[1].engine.pending().len(), 2);
}

// spec/commits.md §2, §4: role before content: a grantee's write arriving before its
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
    assert_eq!(lp.peers[2].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("from b")));
}
