#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The receiving path: verification, dedup, pending reasons, parking, apply, late
//! deltas and events.

use crate::common;
use common::*;
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, Kind};
use osis_base::Classified;
use osis_base::{Role, Tid, Ts, Value, Time};
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
    let pks = packages_to(&mut lp, 0, 1);
    let at = creation_of(&mut lp, &pks, t);
    let mut blob = CommitBlob::decode(&pks[at].bytes).unwrap();
    blob.sigs.signature.0[0] ^= 1;
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
    // peer 1 reads t, then is sent a commit on it it lacks
    let t = new_shared(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("second")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pks: Vec<_> = packages_to(&mut lp, 0, 1).into_iter().filter(|p| !lp.peers[1].engine.commit_ids().contains(&p.id) && lp.peers[0].engine.header(&p.id).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t))).collect();
    assert!(!pks.is_empty());
    lp.peers[1].drain_events();
    for p in &pks {
        assert!(matches!(lp.deliver(1, p).unwrap(), Ingested::Applied(_)));
    }
    for p in &pks {
        assert!(matches!(lp.deliver(1, p).unwrap(), Ingested::Duplicate(_)));
    }
    let ev = lp.peers[1].drain_events();
    let last = ev.iter().rev().find_map(|e| match e {
        Event::Applied { origin, changed, signer, .. } => Some((*origin, changed.clone(), *signer)),
        _ => None,
    });
    let (origin, changed, author) = last.unwrap();
    assert_eq!(origin, Origin::Remote);
    assert_eq!(author, lp.peers[0].engine.tid());
    assert!(changed.contains(&(t, ak("t:reg.0"))));
}

// spec/commits.md §4 (Unjudgeable; Pending storage): unknown `created.0` of the author or a
// touched thing: the commit pends, kept across a restart, and applies once the record comes.
#[test]
fn pending_until_created_spec_commits_4() {
    let mut lp = net_apart(2, 0);
    let r = lp.peers[1].engine.tid();
    // 1 reads t; it holds nothing of 0's; 0 keeps 1, its inbox among it, to signal its grant
    for _ in 0..2 {
        lp.peers[0].know(&[r]).unwrap();
        sync(&mut lp, 1, 0);
    }
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("second")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pks = packages_to(&mut lp, 0, 1);
    // the last commit first, before the grant's fire: its author's created.0 is unknown
    lp.hold_fires(true);
    let r = lp.deliver(1, pks.last().unwrap()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(_))), "{r:?}");
    let me = lp.peers[0].engine.tid();
    let scope = osis_engine::DemotionScope { roles: Default::default(), content: [(me, [t].into())].into() };
    let now = lp.peers[1].engine.now();
    assert!(!lp.peers[1].engine.frontier(&scope, now).unwrap().commits.contains(&pks.last().unwrap().id), "not judged: not received");
    // the author's commits, then the thing's creation
    let c = creation_of(&mut lp, &pks, t);
    for p in &pks[..c] {
        lp.deliver(1, p).unwrap();
    }
    let r = lp.peers[1].receive(&pks.last().unwrap().bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
    // 1's grant waits for the creation too
    for p in &pks[c + 1..pks.len() - 1] {
        lp.deliver(1, p).unwrap();
    }
    // the grant's signal, then the creation
    lp.hold_fires(false);
    lp.deliver(1, &pks[c]).unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("second")));
    // kept pending across a restart
    let mut m = Mutation::new();
    m.set(t, &REG, &s("third")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let pk = packages_to(&mut lp, 0, 1).pop().unwrap();
    let mut lp2 = net(1, 1); // a node apart from lp's (its own seeds)
    assert!(matches!(lp2.deliver(0, &pk).unwrap(), Ingested::Pending(_, osis_engine::Reason::MissingChain(_) | osis_engine::Reason::UnknownCreated(_))));
    assert!(lp2.peers[0].engine.pending().iter().any(|(c, _)| *c == pk.id));
    lp2.peers[0].restart(99).unwrap();
    assert!(lp2.peers[0].engine.pending().iter().any(|(c, _)| *c == pk.id));
}

// spec/commits.md §4 (Unjudgeable): a held edge write ordered before a part, a removal as a grant,
// makes that edge of its stated path arrived. 1 makes t and u, u's mint admin t, removes from t
// the grant 0 never had, then grants 0 read; 0 forges one commit granting 2 admin on both, each
// along its own edge on the thing. At a node holding all but the grant, the removal is the held
// write on 0's edge on t: the forgery's part on t is held, invalid; its part on u waits (the path
// it states to u is 0's own edge on u, which no write set: the record edge from t to u is no edge
// of it, §1 Path), the grant changing neither. Both rosters stay as 1 wrote them.
#[test]
fn a_removal_ordered_before_a_part_is_evidence_spec_commits_4() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::Codec;
    use osis_schema::core_types::{Grant, ROLES};
    let mut lp = net_apart(3, 0);
    let a = lp.peers[0].engine.tid();
    sync(&mut lp, 0, 1);
    sync(&mut lp, 2, 1);
    let t = new_thing(&mut lp, 1);
    // 2 reads t
    let r = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[1].engine, t, r, Some(edge(Role::Read)), None);
    let mut m = Mutation::new();
    let u = lp.peers[1].engine.new_thing(&mut m, t);
    m.set(u, &REG, &s("u")).unwrap();
    lp.peers[1].commit(m).unwrap();
    lp.hold(u);
    lp.peers[1].engine.demote(&t, &osis_engine::flows::Demotion { holder: a, new: None, retain: None }).unwrap();
    // the grant that makes 0 able to sign, held back from 2 till the end
    let grant = *lp.peers[1].engine.grant(&t, &a, &Grant { role: Role::Read, until: None, may_grant: false, retain: false, floor: None }).unwrap().commits.last().unwrap();
    let grant = package_for(&mut lp, 1, 2, grant);
    for p in packages_to(&mut lp, 1, 0) {
        lp.deliver(0, &p).unwrap();
    }
    let mut m = Mutation::new();
    for x in [t, u] {
        m.op(x, &ROLES, PathOp { path: vec![], op: Op::Remove(Value::Weak(r)) }).unwrap();
        m.op(x, &ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(r))], op: Op::Set(Grant { role: Role::Admin, until: None, may_grant: false, retain: false, floor: None }.to_value()) }).unwrap();
    }
    let forged = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    let forged = package_for(&mut lp, 0, 2, forged);
    let rosters = |lp: &mut osis_engine::local_peer::LocalPeer| [t, u].map(|x| lp.peers[2].engine.roster(&x));
    for p in packages_for(&mut lp, 1, 2).iter().chain(&packages_for(&mut lp, 0, 2)).filter(|p| p.id != forged.id && p.id != grant.id) {
        lp.deliver(2, p).unwrap();
    }
    let before = rosters(&mut lp);
    lp.deliver(2, &forged).unwrap();
    assert!(lp.peers[2].engine.commit_ids().contains(&forged.id), "the removal is the held write on 0's edge on t");
    let on_u = lp.peers[2].engine.header(&forged.id).unwrap().aspects.iter().position(|x| x.tid == u).unwrap();
    let waits = Some(std::collections::BTreeSet::from([on_u]));
    assert_eq!(lp.peers[2].engine.pending_parts(&forged.id).unwrap(), waits, "its part on u waits");
    assert_eq!(rosters(&mut lp), before);
    lp.deliver(2, &grant).unwrap();
    assert_eq!(lp.peers[2].engine.pending_parts(&forged.id).unwrap(), waits);
    let after = rosters(&mut lp);
    assert_eq!(after[0].get(&a).map(|e| e.role), Some(Role::Read));
    assert_eq!(after[0].get(&r).map(|e| e.role), Some(Role::Read));
    assert!(!after[1].contains_key(&a) && !after[1].contains_key(&r));
}

// spec/commits.md §4 (Unjudgeable), spec/permissions.md §1 Path (nothing but the stated path
// judges a part: another path that would also give the role does not): 0 makes x and o, both its
// own, so its record chain leads to each; it shares x with 1 and writes x stating its path through
// o, which holds nothing on x. No write is held on o's edge on x, so 1 cannot judge the write: it
// pends, whatever else leads from 0 to x. 0's grant of write on x to o, stamped after the write,
// is no write ordered before it: it still pends.
#[test]
fn a_part_waits_for_the_edges_of_its_stated_path_spec_commits_4() {
    let mut lp = net(2, 0);
    let x = new_shared(&mut lp, 0);
    let o = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(x, &REG, &s("before")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let mut m = Mutation::new();
    m.set(x, &REG, &s("through o")).unwrap();
    m.act_as(o);
    let c = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.pending().iter().any(|(id, r)| *id == c && matches!(r, Reason::MissingChain(_))), "no write held on o's edge on x: {:?}", e1.pending());
    assert_eq!(e1.get(&x, &REG.name()).unwrap(), Some(s("before")));
    edge_write(&mut lp.peers[0].engine, x, o, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.pending().iter().any(|(id, r)| *id == c && matches!(r, Reason::MissingChain(_))), "a grant ordered after it: {:?}", e1.pending());
    assert_eq!(e1.get(&x, &REG.name()).unwrap(), Some(s("before")));
}

// spec/commits.md §4 (Unjudgeable): commits awaiting a thing's `created.0` pend and apply once
// it comes; meanwhile commits applied in between judge none of them again
// (spec/requirements.md, Scale: a first sync is O(commits), not O(commits × awaiting)).
#[test]
fn pending_not_reexamined_while_unchanged_spec_commits_4() {
    // 1 a node of 0's account
    let mut lp = net_one(2);
    let u = new_thing(&mut lp, 0);
    let t = new_thing(&mut lp, 0);
    for i in 0..40 {
        for x in [t, u] {
            let mut m = Mutation::new();
            m.set(x, &REG, &s(&format!("v{i}"))).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
    }
    let pks = packages_to(&mut lp, 0, 1);
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
    // the 40 that waited and the creation, whose content part on t is examined again as t
    // enters the node closure (spec/commits.md §4 Outside the node closure: what enters wakes
    // its waiting parts, examined again in that transaction)
    assert_eq!(examined(&osis_base::costs::take()), 42);
}

// spec/crdt.md §2.2: a commit more than MAX_DRIFT ahead is parked until local time catches
// up; then it applies and advances the clock.
#[test]
fn drift_parks_spec_crdt_2_2() {
    let mut lp = net(2, 0);
    let t = new_shared(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[0].clock.advance(2 * 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("future")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = package_for(&mut lp, 0, 1, id);
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Pending(_, Reason::Drift)));
    lp.peers[1].tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending().len(), 1);
    lp.peers[1].clock.advance(3_600_000 + 1);
    lp.peers[1].tick().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("future")));
    // the HLC moved past the received ts
    let me = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    let t2 = lp.peers[1].engine.new_thing(&mut m, me);
    m.set(t2, &REG, &s("x")).unwrap();
    let id = lp.peers[1].commit(m).unwrap().unwrap();
    lp.hold(t2);
    let theirs = lp.peers[0].engine.header(&pk.id).unwrap().ts;
    assert!(lp.peers[1].engine.header(&id).unwrap().ts > theirs);
}

fn without_parts(bytes: &[u8], keep: impl Fn(&str) -> bool, h: &osis_commit::Header) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].ak.as_str()));
    b.encode()
}

// spec/commits.md §4: a node applies the parts it holds and never waits for one, on one thing or
// across things; a delta of an applied commit arriving later is joined on arrival.
#[test]
fn applies_what_is_held_and_late_delta_spec_commits_4() {
    // the parts on two things, then both on one
    for same in [false, true] {
        let mut lp = net(2, 0);
        let t = new_shared(&mut lp, 0);
        let u = if same { t } else { new_shared(&mut lp, 0) };
        sync(&mut lp, 0, 1);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("r")).unwrap();
        m.set(u, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let pk = package_for(&mut lp, 0, 1, id);
        let partial = without_parts(&pk.bytes, |a| a == "t:reg.0", &h);
        assert_eq!(lp.peers[1].receive(&partial, Vec::new()).unwrap(), Ingested::Applied(id), "{same}");
        assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("r")));
        assert_eq!(lp.peers[1].engine.get(&u, &ak("t:tags.0")).unwrap(), None);
        assert!(lp.peers[1].engine.pending().is_empty());
        lp.peers[1].drain_events();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Applied(_)));
        assert!(lp.peers[1].engine.get(&u, &ak("t:tags.0")).unwrap().is_some());
        assert!(lp.peers[1].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: osis_engine::Cause::LateDelta, .. })), "{same}");
    }
}

// spec/versioning.md §2: an unknown encoding or format version parks the commit as bytes; it
// is relayed and re-examined (after an upgrade), never rejected; others still apply.
// spec/versioning.md §2 (park unknown)
#[test]
fn parked_spec_versioning_2() {
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    share(&mut lp, 0, t);
    sync(&mut lp, 0, 1);
    let ts = Ts::make(Time(T0.0 + 10), 0).unwrap();
    let delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![0; 16]), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Int(99)])]));
    let mut w = AspectWrite::new(t, ak("t:future.0"), 100, 101, delta);
    w.purge_by = osis_base::PurgeBy::Writer;
    let me = lp.peers[0].engine.tid();
    let mut b = CommitBuilder::new(Kind::Content, ts, me, osis_commit::Path::default(), crate::common::forged_session(me));
    b.aspects.push(w);
    let commit = crate::common::seal(&mut lp, 0, b, &[t]);
    let bytes = commit.encode();
    let r = lp.peers[1].receive(&bytes, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Applied(_)), "its header waits for no part: {r:?}");
    lp.peers[1].reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(commit.id(), osis_engine::Reason::Parked)], "the part kept as bytes");
    // an unknown format version: the header does not even decode
    let mut v = osis_base::decode(&commit.encode(), &osis_base::Limits::DEFAULT).unwrap();
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

// spec/commits.md §5 What a held thing needs, §4 Pending storage: a pending commit needs its
// evidence as a held one does. b's two writes on t reach reader 2 before b's grant; one of them
// goes (its carrier left), so the evidence of b's path is judged: the other, still pending on t,
// keeps it, and applies once the grant comes, b's evidence not sent again.
#[test]
fn a_pending_commit_keeps_its_evidence_spec_commits_5() {
    let mut lp = net(3, 0);
    let t = new_thing(&mut lp, 0);
    let r = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    for pk in packages_to(&mut lp, 0, 2) {
        lp.deliver(2, &pk).unwrap();
    }
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let w = ["one", "two"].map(|v| {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(1);
        c
    });
    let own: Vec<_> = packages_to(&mut lp, 1, 2).into_iter().filter(|pk| lp.peers[1].engine.header(&pk.id).unwrap().signer == b).collect();
    for pk in &own {
        lp.deliver(2, pk).unwrap();
    }
    let e = &mut lp.peers[2].engine;
    assert!(w.iter().all(|c| e.pending().iter().any(|(x, _)| x == c)), "{:?}", e.pending());
    assert!(e.release_entry(&w[0]).unwrap());
    // the grant, and nothing more of b's
    let bs = [b, lp.peers[1].engine.tid()];
    let rest: Vec<_> = packages_to(&mut lp, 0, 2).into_iter().filter(|pk| !bs.contains(&lp.peers[0].engine.header(&pk.id).unwrap().signer)).collect();
    for pk in &rest {
        lp.deliver(2, pk).unwrap();
    }
    let e = &mut lp.peers[2].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("two")));
}

// spec/commits.md §2, §4: role before content: a grantee's write arriving before its
// grant waits for the chain and applies after.
#[test]
fn grantee_waits_for_grant_spec_commits_4() {
    let mut lp = net(3, 0);
    let t = new_thing(&mut lp, 0);
    // peer 2 reads t first
    let r = lp.peers[2].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, r, Some(edge(Role::Read)), None);
    for pk in packages_to(&mut lp, 0, 2) {
        lp.deliver(2, &pk).unwrap();
    }
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("from b")).unwrap();
    lp.peers[1].commit(m).unwrap();
    // then b's own commits, then a's
    for pk in packages_for(&mut lp, 1, 2) {
        if lp.peers[1].engine.header(&pk.id).unwrap().signer == b {
            lp.deliver(2, &pk).unwrap();
        }
    }
    assert_eq!(lp.peers[2].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("new")), "before the grant nothing is judged");
    sync(&mut lp, 0, 2);
    assert_eq!(lp.peers[2].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("from b")));
}

// spec/commits.md §4 (Unjudgeable; Pending storage): role commits on a thing that come before its
// creation pend, kept with their bytes; the creation coming last applies them all in one
// re-examination, and nothing fetches them again.
#[test]
fn role_commits_before_their_creation_pend_then_apply_spec_commits_4() {
    let (mut lp, ps) = crate::flows::people(3);
    let t = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.make_independent(&t).unwrap();
    lp.peers[0].engine.grant(&t, &ps[1], &crate::flows::edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&t, &ps[1], &crate::flows::edge_of(Role::Write)).unwrap();
    // 2 reads t
    lp.hold_at(2, t);
    lp.peers[0].engine.grant(&t, &ps[2], &crate::flows::edge_of(Role::Read)).unwrap();
    let pks = packages_to(&mut lp, 0, 2);
    let c = creation_of(&mut lp, &pks, t);
    let roles: Vec<_> = pks[c + 1..].iter().filter(|p| is_role(&lp.peers[0].engine, &p.id)).cloned().collect();
    assert!(roles.len() >= 3, "the rotation and the grants");
    for p in &roles {
        let r = lp.peers[2].receive(&p.bytes, p.blobs.clone()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t), "{r:?}");
    }
    assert_eq!(lp.peers[2].engine.pending().len(), roles.len(), "each kept pending");
    lp.peers[2].receive(&pks[c].bytes, pks[c].blobs.clone()).unwrap();
    // the grant's signal: 2 follows t
    lp.pass_fires(2).unwrap();
    let e = &mut lp.peers[2].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert_eq!(e.roster(&t).get(&ps[1]).map(|x| x.role), Some(Role::Write));
    assert_eq!(e.roster(&t).get(&ps[2]).map(|x| x.role), Some(Role::Read));
    assert_eq!(lp.peers[2].redelivered, 0, "nothing fetched again");
}

// spec/commits.md §4 (Unjudgeable: a pending commit keeps its unjudgeable parts; Copies: it keeps
// the first copy of each delta it could not check, a copy that proves not to match goes and the
// node judges again the copies it holds as blobs): a write awaiting its thing's record arrives
// first as a junk copy (its delta's bytes replaced), then true; neither can be checked, so the
// junk one is kept. Once the record comes the junk goes and the commit is named for its carriers
// to bring again (sync opens every entry naming it again, `store::follow`); the true copy then
// gives the write.
#[test]
fn junk_first_while_a_record_is_away_goes_once_it_comes_spec_commits_4() {
    // 1 a node of 0's account
    let mut lp = net_one(2);
    let t = new_thing(&mut lp, 0);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("true")).unwrap();
    let w = lp.peers[0].commit(m).unwrap().unwrap();
    let pks = packages_to(&mut lp, 0, 1);
    let c = creation_of(&mut lp, &pks, t);
    for p in &pks[..c] {
        lp.deliver(1, p).unwrap();
    }
    let true_copy = pks.iter().find(|p| p.id == w).unwrap().bytes.clone();
    let mut junk = CommitBlob::decode(&true_copy).unwrap();
    let ai = junk.header.aspects.iter().position(|a| a.tid == t && a.ak.as_str() == "t:reg.0").unwrap();
    let p = junk.parts.iter_mut().find(|p| p.ai == ai).unwrap();
    p.delta = osis_base::encode(&Value::List(vec![Value::Int(2)]));
    let e = &mut lp.peers[1].engine;
    assert!(matches!(e.ingest(&junk.encode(), Vec::new()).unwrap(), Ingested::Pending(_, Reason::UnknownCreated(x)) if x == t));
    assert!(matches!(e.ingest(&true_copy, Vec::new()).unwrap(), Ingested::Pending(..)));
    e.take_redeliver();
    e.ingest(&pks[c].bytes, pks[c].blobs.clone()).unwrap();
    e.reexamine().unwrap();
    assert!(e.take_redeliver().contains(&w), "named for its carriers");
    assert_ne!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("true")), "the junk copy gave nothing");
    e.ingest(&true_copy, Vec::new()).unwrap();
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("true")));
}
