#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The receiving path: verification, dedup, pending reasons, parking, apply, late
//! deltas and events.

use crate::common;
use common::*;
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, Kind, MemoryBlobs};
use osis_base::Classified;
use osis_base::{Role, Tid, Ts, Value, WallMs};
use osis_crypto::{Secret32, SeededRng};
use osis_engine::{Event, Ingested, Mutation, Origin, Reason};

/// The index among `pks` of the commit creating `t`.
fn creation_of(lp: &mut osis_engine::local_peer::LocalPeer, pks: &[osis_engine::local_peer::Package], t: Tid) -> usize {
    pks.iter().position(|p| lp.peers[0].engine.header(&p.id).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak.as_str() == "created.0"))).unwrap()
}

// spec/commits.md §4: a commit whose signature does not verify is bad input: a diagnostic,
// nothing stored.
// spec/commits.md §4 (signature)
#[test]
fn bad_signature_rejected_spec_commits_4() {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    let at = creation_of(&mut lp, &pks, t);
    let mut blob = CommitBlob::decode(&pks[at].bytes).unwrap();
    let Value::Enum(c, Some(p)) = blob.sigs.signature.to_value() else { panic!() };
    let Value::Bytes(mut sig) = *p else { panic!() };
    sig[0] ^= 1;
    blob.sigs.signature = osis_crypto::Signature::from_value(&Value::Enum(c, Some(Box::new(Value::Bytes(sig))))).unwrap();
    for p in &pks[..at] {
        lp.deliver(1, p).unwrap();
    }
    let held = lp.peers[1].engine.commit_ids().len();
    lp.peers[1].drain_events();
    let r = lp.peers[1].receive(&blob.encode(), Vec::new());
    assert_eq!(r.unwrap_err().class(), osis_base::ErrorClass::BadInput);
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Diagnostic(d) if d.kind == osis_engine::DiagnosticKind::BadInput)));
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.commit_ids().len(), held);
}

// spec/commits.md §4: receivers dedup by commit ID; remote applies fire events with origin.
#[test]
fn dedup_and_events_spec_commits_4() {
    let mut lp = net(2, 0);
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
    assert_eq!(author, lp.peers[0].engine.me());
    assert!(changed.contains(&(t, ak("t:reg.0"))));
}

// spec/commits.md §4 (Unjudgeable, Pending storage): unknown `created.0` of the author or a
// touched thing: the commit pends, kept across a restart, and applies once the record comes.
#[test]
fn pending_until_created_spec_commits_4() {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("second")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pks = packages(&mut lp, 0);
    // the last commit first: its author's created.0 is unknown
    let r = lp.deliver(1, pks.last().unwrap()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(_))), "{r:?}");
    let me = lp.peers[0].engine.me();
    let scope = osis_perm::DemotionScope { roles: Default::default(), content: [(me, [t].into())].into() };
    let now = lp.peers[1].engine.now();
    assert!(!lp.peers[1].engine.frontier(&scope, now).unwrap().commits.contains(&pks.last().unwrap().id), "not judged: not received");
    // the author's commits, then the thing's creation
    let c = creation_of(&mut lp, &pks, t);
    for p in &pks[..c] {
        lp.deliver(1, p).unwrap();
    }
    let r = lp.peers[1].receive(&pks.last().unwrap().bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
    lp.deliver(1, &pks[c]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("second")));
    // kept pending across a restart
    let mut m = Mutation::new();
    m.set(t, &REG, &s("third")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let mut lp2 = net(1, 1); // a node apart from lp's (its own seeds)
    assert!(matches!(lp2.deliver(0, &pk).unwrap(), Ingested::Pending(_, osis_engine::Reason::MissingChain(_) | osis_engine::Reason::UnknownCreated(_))));
    assert!(lp2.peers[0].engine.pending().iter().any(|(c, _)| *c == pk.id));
    lp2.peers[0].restart(99).unwrap();
    assert!(lp2.peers[0].engine.pending().iter().any(|(c, _)| *c == pk.id));
}

// spec/commits.md §4 (Unjudgeable): only a grant leads from its holder to a thing (a path climbs
// grants, spec/permissions.md §1); a removal names its holder and leads nowhere. 1 makes t and u,
// u's first admin t, removes from t the grant 0 never had, then grants 0 read; 0 forges one commit
// granting itself admin on both. A node holding all but the grant: nothing leads from 0 to t or u
// (the removal names 0), so it keeps nothing of the forgery; with the grant it does, and holds it
// invalid: both rosters stay as 1 wrote them.
#[test]
fn a_removal_leads_no_author_to_a_thing_spec_commits_4() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::Codec;
    use osis_schema::core_types::{Edge, ROLES};
    let mut lp = net(3, 0);
    let a = lp.peers[0].engine.me();
    sync(&mut lp, 0, 1);
    let t = new_thing(&mut lp, 1);
    let mut m = Mutation::new();
    let u = lp.peers[1].engine.new_thing(&mut m, t);
    m.set(u, &REG, &s("u")).unwrap();
    lp.peers[1].commit(m).unwrap();
    lp.peers[1].engine.demote(&t, &osis_engine::flows::Demotion { holder: a, new: None, retain: None }).unwrap();
    // the grant that makes 0 able to sign, held back from 2 till the end
    lp.peers[1].engine.grant(&t, &a, &Edge { role: Role::Read, until: None, invite: None, tied: None }).unwrap();
    let grant = packages(&mut lp, 1).pop().unwrap();
    for p in packages(&mut lp, 1) {
        lp.deliver(0, &p).unwrap();
    }
    let mut m = Mutation::new();
    for x in [t, u] {
        m.op(x, &ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(a)) }).unwrap();
        m.op(x, &ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(a))], op: Op::Set(Edge { role: Role::Admin, until: None, invite: None, tied: None }.to_value()) }).unwrap();
    }
    let forged = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    let forged = packages(&mut lp, 0).into_iter().find(|p| p.id == forged).unwrap();
    let rosters = |lp: &mut osis_engine::local_peer::LocalPeer| [t, u].map(|x| lp.peers[2].engine.roster(&x));
    for p in packages(&mut lp, 1).iter().chain(&packages(&mut lp, 0)).filter(|p| p.id != forged.id && p.id != grant.id) {
        lp.deliver(2, p).unwrap();
    }
    let before = rosters(&mut lp);
    let r = lp.deliver(2, &forged).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(x)) if x == a), "{r:?}");
    assert!(!lp.peers[2].engine.commit_ids().contains(&forged.id));
    assert_eq!(rosters(&mut lp), before);
    // a grant leads from g's first admin to t, and through t's record to u
    lp.deliver(2, &grant).unwrap();
    let before = rosters(&mut lp);
    assert_eq!(before[0].get(&a).map(|e| e.role), Some(Role::Read));
    lp.deliver(2, &forged).unwrap();
    assert!(lp.peers[2].engine.commit_ids().contains(&forged.id));
    assert_eq!(rosters(&mut lp), before);
    assert!(!before[1].contains_key(&a));
}

// spec/commits.md §4 (Unjudgeable): commits awaiting a thing's `created.0` pend and apply once
// it comes; meanwhile commits applied in between judge none of them again
// (spec/requirements.md, Scale: a first sync is O(commits), not O(commits × awaiting)).
#[test]
fn pending_not_reexamined_while_unchanged_spec_commits_4() {
    let mut lp = net(2, 0);
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
    // the author's commits and u's creation; t's creation last
    let c = creation_of(&mut lp, &pks, t);
    for p in &pks[..c] {
        lp.deliver(1, p).unwrap();
    }
    osis_base::costs::take();
    for (i, p) in pks[c + 1..].iter().enumerate() {
        let r = lp.deliver(1, p).unwrap();
        if i % 2 == 0 {
            assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
        } else {
            assert!(matches!(r, Ingested::Applied(_)), "{r:?}");
        }
    }
    let examined = |c: &[(&str, std::time::Duration, u64)]| c.iter().find(|x| x.0 == "examine").map_or(0, |x| x.2);
    assert_eq!(examined(&osis_base::costs::take()), 80, "each commit examined once");
    lp.deliver(1, &pks[c]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("v39")));
    assert_eq!(examined(&osis_base::costs::take()), 41);
}

// spec/crdt.md §2.2: a commit more than MAX_DRIFT ahead is parked until local time catches
// up; then it applies and advances the clock.
#[test]
fn drift_parks_spec_crdt_2_2() {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[0].clock.advance(2 * 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("future")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Pending(_, Reason::Drift)));
    lp.peers[1].tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending().len(), 1);
    lp.peers[1].clock.advance(3_600_000 + 1);
    lp.peers[1].tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("future")));
    // the HLC moved past the received ts
    let me = lp.peers[1].engine.me();
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
    let mut lp = net(2, 0);
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
    assert!(matches!(lp.peers[1].receive(&partial, Vec::new()).unwrap(), Ingested::Applied(_)));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
    assert_eq!(lp.peers[1].engine.get(&u, &ak("t:tags.0")).unwrap(), None);
    lp.peers[1].drain_events();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(_)));
    assert!(lp.peers[1].engine.get(&u, &ak("t:tags.0")).unwrap().is_some());
    assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: osis_engine::Cause::LateDelta, .. })));
    // the same thing, synced: applies what is held too
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let partial = without_parts(&pk.bytes, |a| a == "t:reg.0", &h);
    assert_eq!(lp.peers[1].receive(&partial, Vec::new()).unwrap(), Ingested::Applied(id));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:tags.0")).unwrap(), None);
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(_)));
    assert!(lp.peers[1].engine.get(&t, &ak("t:tags.0")).unwrap().is_some());
    // across things, the other one synced: applies what is held
    let mut lp = net(2, 0);
    let (t, u) = (new_thing(&mut lp, 0), new_thing(&mut lp, 0));
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(u, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).pop().unwrap();
    let partial = without_parts(&pk.bytes, |a| a == "t:reg.0", &h);
    assert_eq!(lp.peers[1].receive(&partial, Vec::new()).unwrap(), Ingested::Applied(id));
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
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let e = &mut lp.peers[0].engine;
    let rec = e.get_typed(&t, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let ts = Ts::make(WallMs(T0.0 + 10), 0).unwrap();
    let delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])]));
    let mut w = AspectWrite::new(t, ak("t:future.0"), 100, 101, delta);
    w.retention = crate::common::purgeable_by(osis_base::PurgeBy::Writer);
    let mut b = CommitBuilder::new(Kind::Content, ts, e.me(), e.me(), crate::common::forged_session(e.me()));
    b.aspects.push(w);
    let forge_key = e.sign_forged(&mut b);
    let built = b.build(&forge_key, &Dedup(vec![rec]), &mut MemoryBlobs::default(), &mut SeededRng::from_u64(0)).unwrap();
    let bytes = built.commit.encode();
    let r = lp.peers[1].receive(&bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Applied(_)), "its header waits for no part: {r:?}");
    lp.peers[1].reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(built.commit.id(), osis_engine::Reason::Parked)], "the part kept as bytes");
    // an unknown format version: the header does not even decode
    let mut v = osis_base::decode(&built.commit.encode(), &osis_base::Limits::DEFAULT).unwrap();
    if let Value::List(items) = &mut v
        && let Some(Value::List(h)) = items.first_mut()
    {
        h[0] = Value::Int(2);
    }
    let r = lp.peers[1].receive(&osis_base::encode(&v), Vec::new()).unwrap();
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
    let mut lp = net(3, 0);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.me();
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
    assert_eq!(lp.peers[2].engine.get(&t, &ak("t:reg.0")).unwrap(), None, "before the grant nothing is judged");
    sync(&mut lp, 0, 2);
    assert_eq!(lp.peers[2].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("from b")));
}

// spec/commits.md §4 (Unjudgeable, Pending storage): role commits on a thing that come before its
// creation pend, kept with their bytes; the creation coming last applies them all in one
// re-examination, and nothing fetches them again.
#[test]
fn role_commits_before_their_creation_pend_then_apply_spec_commits_4() {
    let (mut lp, ps) = crate::flows::people(3);
    let t = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    lp.peers[0].engine.grant(&t, &ps[1], &crate::flows::edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&t, &ps[1], &crate::flows::edge_of(Role::Write)).unwrap();
    let pks = packages(&mut lp, 0);
    let c = creation_of(&mut lp, &pks, t);
    let roles: Vec<_> = pks[c + 1..].iter().filter(|p| is_role(&lp.peers[0].engine, &p.id)).cloned().collect();
    assert!(roles.len() >= 3, "the rotation and the grants");
    for p in &roles {
        let r = lp.peers[2].receive(&p.bytes, p.blobs.clone()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
    }
    assert_eq!(lp.peers[2].engine.pending().len(), roles.len(), "each kept pending");
    lp.peers[2].receive(&pks[c].bytes, pks[c].blobs.clone()).unwrap();
    let e = &mut lp.peers[2].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.roster(&t).get(&ps[1]).map(|x| x.role), Some(Role::Write));
    assert!(e.roster(&t).get(&ps[2]).is_none());
    assert_eq!(lp.peers[2].redelivered, 0, "nothing fetched again");
}
