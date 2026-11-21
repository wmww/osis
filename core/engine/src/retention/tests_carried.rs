//! A purge of a commit this node holds no header of (spec/commits.md §5 Purge, Without the
//! header): judged by the facts the snapshots carrying its writes state (spec/crdt.md §8), so it
//! takes every copy at a node that holds only a snapshot and the request.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn reg() -> Ak {
    Ak::new("x:a.0").unwrap()
}

/// Admin 0, writer 1 and reader 2 on a thing of 0.
fn world() -> (LocalPeer, Tid) {
    LocalPeer::cached("retention::tests_carried::world", || {
        let mut lp = LocalPeer::fresh(3, T0);
        lp.sync_all().unwrap();
        let (a, w, x) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(60_000);
        (lp, t)
    })
}

/// Writer 1 writes `v1` then `SECRET` purgeable by `by` and compacts the register; admin 0
/// gets them all, reader 2 nothing. The commit of `SECRET` and the snapshot.
fn written(lp: &mut LocalPeer, t: Tid, by: PurgeBy) -> (CommitId, CommitId) {
    let mut c = None;
    for v in ["v1", "SECRET"] {
        let mut m = Mutation::new();
        m.purge_by(t, &reg(), by).unwrap();
        m.set(t, &reg(), &Value::Str(v.into())).unwrap();
        c = lp.peers[1].commit(m).unwrap();
        lp.advance(1_000);
    }
    let s = lp.peers[1].engine.snapshot(&t, &reg()).unwrap().unwrap();
    lp.advance(1_000);
    lp.sync(1, 0).unwrap();
    (c.unwrap(), s)
}

/// Peer `by`'s request carrying `item` (past its own refusal: receivers judge it).
fn request(lp: &mut LocalPeer, by: usize, t: Tid, item: PurgeItem) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &lp.peers[by].engine.now()).unwrap();
    m.purge(item);
    let p = lp.peers[by].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    p
}

// spec/commits.md §5 Purge (Without the header), spec/crdt.md §4.7 Copies, §8 Facts: a node that
// never received the purged commit, holding only a snapshot carrying it and the request, in
// either order, holds its copy value-less: by stamp or by author, an admin's request or its
// author's under `author_or_admin`. Its author's under `admin` takes nothing, there as where the
// header is held: the snapshot states the class.
#[test]
fn snapshot_and_request_alone_take_the_copy_spec_commits_5() {
    let cases = [(0, PurgeBy::Admin, true), (1, PurgeBy::AuthorOrAdmin, true), (1, PurgeBy::Admin, false)];
    for (by, class, takes) in cases {
        for author in [false, true] {
            for request_first in [false, true] {
                let what = format!("purger {by}, {class:?}, by author {author}, request first {request_first}");
                let (mut lp, t) = world();
                let (c, s) = written(&mut lp, t, class);
                let item = match author {
                    false => lp.peers[0].engine.purge_item(&c, t, reg()).unwrap(),
                    true => PurgeItem::Author { tid: t, ak: reg(), author: lp.peers[1].engine.me() },
                };
                let p = request(&mut lp, by, t, item);
                let (sp, pp) = (lp.peers[1].engine.package(&s).unwrap().unwrap(), lp.peers[by].engine.package(&p).unwrap().unwrap());
                let order = if request_first { [&pp, &sp] } else { [&sp, &pp] };
                for pk in order {
                    lp.deliver(2, pk).unwrap();
                }
                let e = &mut lp.peers[2].engine;
                assert!(!e.commit_ids().contains(&c), "{what}: the commit never reached the reader");
                let read = e.get(&t, &reg()).unwrap();
                assert_eq!(read == Some(Value::Str("SECRET".into())), !takes, "{what}: reads {read:?}");
                // where the header is held the request judges alike
                lp.deliver(0, &pp).unwrap();
                let e = &mut lp.peers[0].engine;
                assert_eq!(e.get(&t, &reg()).unwrap() == Some(Value::Str("SECRET".into())), !takes, "{what}: at the admin");
            }
        }
    }
}

// spec/commits.md §5 Covered, spec/crdt.md §8 Facts: a snapshot stating wider facts for a carried
// commit than an earlier snapshot does never covers it, so a writer's lie cannot drop the honest
// statement and widen a purge where the header is not held. Writer 3 states `writer` for
// writer 1's `admin` write and purges it by stamp: the reader, holding both snapshots and the
// request but never the commit, still reads it.
#[test]
fn a_wider_fact_never_covers_spec_commits_5() {
    let (mut lp, t) = LocalPeer::cached("retention::tests_carried::four", || {
        let mut lp = LocalPeer::fresh(4, T0);
        lp.sync_all().unwrap();
        let me = |lp: &LocalPeer, i: usize| lp.peers[i].engine.me();
        let mut m = Mutation::new();
        let a = me(&lp, 0);
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
        for (i, role) in [(1, Role::Write), (2, Role::Read), (3, Role::Write)] {
            let who = me(&lp, i);
            lp.peers[0].engine.grant(&t, &who, &edge(role)).unwrap();
        }
        lp.sync_all().unwrap();
        lp.advance(60_000);
        (lp, t)
    });
    let (c, s1) = written(&mut lp, t, PurgeBy::Admin);
    lp.sync(1, 3).unwrap();
    let item = lp.peers[1].engine.purge_item(&c, t, reg()).unwrap();
    let PurgeItem::Commit { ts, src, .. } = item.clone() else { unreachable!() };
    lp.peers[3].engine.core.lie_facts = Some([((ts, src), osis_crdt::Fact { by: PurgeBy::Writer, purge_author: None })].into());
    let s2 = lp.peers[3].engine.snapshot(&t, &reg()).unwrap().unwrap();
    lp.advance(1_000);
    let p = request(&mut lp, 3, t, item);
    for (from, id) in [(1, s1), (3, s2), (3, p)] {
        let pk = lp.peers[from].engine.package(&id).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
    }
    let e = &mut lp.peers[2].engine;
    assert!(!e.commit_ids().contains(&c));
    assert_eq!(e.run(|tx| super::snapshot::covered_join(tx, &s2, &s1, &t, &reg())).unwrap(), Some(false), "the wider statement covers the honest one");
    assert_eq!(e.get(&t, &reg()).unwrap(), Some(Value::Str("SECRET".into())), "the liar's purge took another's admin-class write");
}

/// At peer `i`: every body a held valid snapshot of `ak` covers is dropped, then every
/// forgettable commit forgotten (what node-sync's compaction does).
fn compact_forget(lp: &mut LocalPeer, i: usize, t: Tid, ak: &Ak) {
    let e = &mut lp.peers[i].engine;
    for c in e.commit_ids() {
        // refused (nothing changes) unless a held valid snapshot covers it
        if e.header(&c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == *ak)) {
            let _ = e.drop_body(&c, &t, ak);
        }
    }
    let due: Vec<_> = e.commit_ids().into_iter().filter(|c| e.forgettable(c).unwrap()).collect();
    e.forget_commits(&due).unwrap();
}

/// Admin `by`'s request purging commit `c` on `(t, ak)` by ID, through the writer's own check.
fn purge_by_id(lp: &mut LocalPeer, by: usize, t: Tid, ak: &Ak, c: CommitId) -> crate::error::Result<Option<CommitId>> {
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &lp.peers[by].engine.now()).unwrap();
    m.purge_commit(c, t, ak.clone());
    let r = lp.peers[by].commit(m);
    lp.advance(1_000);
    r
}

fn names_on(lp: &LocalPeer, i: usize, t: Tid, ak: &Ak) -> usize {
    lp.peers[i].engine.core.ix.forgotten_names.get(&(t, ak.clone())).map_or(0, |m| m.len())
}

// spec/commits.md §5 Forgetting, Purge: a purge by ID of a write its node forgot under a cover
// (header and ID gone) still reaches its value at every node: the purger (after a restart too),
// the writer, and a late joiner holding only the snapshot and the request. Only that write: the
// other aspect, written and forgotten alike, reads on.
#[test]
fn purge_by_id_reaches_a_forgotten_write_spec_commits_5() {
    let other = Ak::new("x:b.0").unwrap();
    for restart in [false, true] {
        let (mut lp, t) = world();
        let (c, s) = written(&mut lp, t, PurgeBy::Admin);
        let mut m = Mutation::new();
        m.set(t, &other, &Value::Str("KEEP".into())).unwrap();
        lp.peers[1].commit(m).unwrap();
        lp.advance(1_000);
        let so = lp.peers[1].engine.snapshot(&t, &other).unwrap().unwrap();
        lp.advance(1_000);
        lp.sync(1, 0).unwrap();
        // forgotten at the writer, then received again from the admin: its header decides again
        compact_forget(&mut lp, 1, t, &reg());
        assert_eq!(names_on(&lp, 1, t, &reg()), 1, "named at the writer");
        lp.sync(0, 1).unwrap();
        assert!(lp.peers[1].engine.commit_ids().contains(&c), "received again");
        assert_eq!(names_on(&lp, 1, t, &reg()), 0, "held again: no name");
        for i in [0, 1] {
            compact_forget(&mut lp, i, t, &reg());
            compact_forget(&mut lp, i, t, &other);
            assert!(!lp.peers[i].engine.commit_ids().contains(&c), "forgotten at {i}");
            assert_eq!(names_on(&lp, i, t, &reg()), 1, "named at {i}");
        }
        if restart {
            lp.peers[0].restart(7).unwrap();
        }
        // the writer holds no right over an admin-class write: refused by its name, as by its header
        assert!(matches!(purge_by_id(&mut lp, 1, t, &reg(), c), Err(crate::Error::Permission { .. })), "restart {restart}: the writer's purge");
        let p = purge_by_id(&mut lp, 0, t, &reg(), c).unwrap().unwrap();
        // the late joiner: the snapshots and the request, never the commit
        for (from, id) in [(1, s), (1, so), (0, p)] {
            let pk = lp.peers[from].engine.package(&id).unwrap().unwrap();
            lp.deliver(2, &pk).unwrap();
        }
        lp.sync(0, 1).unwrap();
        for i in 0..3 {
            let e = &mut lp.peers[i].engine;
            assert_ne!(e.get(&t, &reg()).unwrap(), Some(Value::Str("SECRET".into())), "restart {restart}: read at {i}");
            assert_eq!(e.get(&t, &other).unwrap(), Some(Value::Str("KEEP".into())), "restart {restart}: the other write at {i}");
        }
        assert!(lp.peers[2].engine.purge_item(&c, t, reg()).is_none(), "the late joiner never held the header: no name");
    }
}

// spec/commits.md §5 Forgetting, spec/crdt.md §5.5: a removal from a set leaves a tombstone, a
// reset carrying no value, so no purge can act on it and its commit keeps no name; the adding
// commit keeps one while its other element lives, and none once that is removed too.
#[test]
fn a_set_removal_keeps_no_name_spec_commits_5() {
    let (mut lp, t) = world();
    let set = Ak::new("x:s.0").unwrap();
    let op = |m: &mut Mutation, v: i64, add: bool| {
        let v = Value::Int(v);
        let op = if add { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
        m.op(t, &set, osis_crdt::PathOp { path: vec![], op }).unwrap();
    };
    let mut m = Mutation::new();
    op(&mut m, 1, true);
    op(&mut m, 2, true);
    lp.peers[1].commit(m).unwrap();
    lp.advance(1_000);
    for (v, left) in [(1, 1), (2, 0)] {
        let mut m = Mutation::new();
        op(&mut m, v, false);
        lp.peers[1].commit(m).unwrap();
        lp.advance(1_000);
        lp.peers[1].engine.snapshot(&t, &set).unwrap().unwrap();
        lp.advance(1_000);
        compact_forget(&mut lp, 1, t, &set);
        assert_eq!(names_on(&lp, 1, t, &set), left, "{v} removed");
        let rows = lp.peers[1].engine.local_census().unwrap().get("fn/").map_or(0, |x| x.0);
        assert_eq!(rows, left, "{v} removed: rows");
    }
}

// spec/commits.md §5 Forgetting, notes/growth.md: a name lives while a held snapshot carries a
// write of it: overwritten and compacted again it goes, so a register overwritten n times holds
// at most one name, in the index and in the store, the same after a restart.
#[test]
fn a_dead_write_keeps_no_name_spec_commits_5() {
    let (mut lp, t) = world();
    for n in 0..12 {
        let mut m = Mutation::new();
        m.set(t, &reg(), &Value::Int(n)).unwrap();
        lp.peers[1].commit(m).unwrap();
        lp.advance(1_000);
        lp.peers[1].engine.snapshot(&t, &reg()).unwrap().unwrap();
        lp.advance(1_000);
        compact_forget(&mut lp, 1, t, &reg());
        assert!(names_on(&lp, 1, t, &reg()) <= 1, "write {n}: {} names", names_on(&lp, 1, t, &reg()));
        let rows = lp.peers[1].engine.local_census().unwrap().get("fn/").map_or(0, |x| x.0);
        assert!(rows <= 1, "write {n}: {rows} rows");
    }
    assert_eq!(names_on(&lp, 1, t, &reg()), 1, "the live write's");
    lp.peers[1].restart(3).unwrap();
    assert_eq!(names_on(&lp, 1, t, &reg()), 1, "after a restart");
    // overwritten again: the old snapshot leaving alone (nothing forgotten in its transaction)
    // takes the name with it, before the new write is forgotten
    let old = lp.peers[1].engine.core.ix.snapshots.get(&(t, reg())).unwrap()[0].1;
    let mut m = Mutation::new();
    m.set(t, &reg(), &Value::Int(99)).unwrap();
    let last = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    lp.peers[1].engine.snapshot(&t, &reg()).unwrap().unwrap();
    lp.advance(1_000);
    lp.peers[1].engine.drop_body(&old, &t, &reg()).unwrap();
    assert_eq!(names_on(&lp, 1, t, &reg()), 0, "the dead write's name");
    compact_forget(&mut lp, 1, t, &reg());
    assert!(!lp.peers[1].engine.commit_ids().contains(&last));
    assert_eq!(names_on(&lp, 1, t, &reg()), 1, "only the live write's");
}

// Security invariant (spec/requirements.md Deletion, spec/commits.md §5 Purge): a purge naming a
// write by ID reaches its value wherever held, and only that write's, whether or not its node
// forgot the commit. Differential: two runs of the same random writes, compactions and purges by
// ID, one forgetting every covered commit at once and one forgetting nothing, read alike at every
// node, and no node reads a purged value.
#[test]
#[ignore = "property"]
fn purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5() {
    let aks: Vec<Ak> = ["x:a.0", "x:b.0", "x:c.0"].into_iter().map(|a| Ak::new(a).unwrap()).collect();
    let name = "retention::tests_carried::purge_by_id_reads_alike_forgotten_or_not_plain_spec_commits_5";
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_PURGE_BY_ID_START", "OSIS_PURGE_BY_ID_SEEDS", 0..8);
    let replay = |s: u64| format!("OSIS_PURGE_BY_ID_START={s} OSIS_PURGE_BY_ID_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact {name}");
    // per seed: its purges by ID of a commit the purger forgot
    let by_name = seeds.run(name, replay, |seed| {
        let mut by_name = 0usize;
        let (mut runs, t) = {
            let (lp, t) = world();
            let mut b = lp;
            let a = b.copy().unwrap();
            (vec![a, b], t)
        };
        let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = |n: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % n
        };
        // per write: its commit in each run (IDs differ: each run draws its own blinds)
        let mut written: Vec<([CommitId; 2], usize, i64)> = Vec::new();
        let mut purged: Vec<i64> = Vec::new();
        for step in 0..14i64 {
            let (op, who, a) = (next(4), next(2) as usize, next(aks.len() as u64) as usize);
            let pick = (!written.is_empty()).then(|| written[next(written.len() as u64) as usize]);
            let mut ids = [CommitId([0; 32]); 2];
            for (r, lp) in runs.iter_mut().enumerate() {
                match op {
                    0 | 1 => {
                        let mut m = Mutation::new();
                        m.set(t, &aks[a], &Value::Int(step)).unwrap();
                        ids[r] = lp.peers[who].commit(m).unwrap().unwrap();
                    }
                    2 => {
                        lp.peers[who].engine.snapshot(&t, &aks[a]).unwrap();
                    }
                    _ => {
                        let Some((cs, a, v)) = pick else { continue };
                        let c = cs[r];
                        // the admin's request; in the forgetting run its header may be gone,
                        // and with no held snapshot carrying the write (dead) its name too:
                        // nothing of it is left to purge, so the reads below still agree
                        let forgot = lp.peers[0].engine.header(&c).is_none();
                        let r2 = purge_by_id(lp, 0, t, &aks[a], c);
                        if r == 0 && forgot && r2.is_ok() {
                            by_name += 1;
                        }
                        assert!(r2.is_ok() || (r == 0 && matches!(r2, Err(crate::Error::UnknownCommit(_)))), "seed {seed} step {step} run {r}: {r2:?}");
                        if r == 0 {
                            purged.push(v);
                        }
                    }
                }
                lp.advance(1_000);
                lp.sync_all().unwrap();
                lp.peers[0].engine.purge_resnapshots().unwrap();
                lp.peers[1].engine.purge_resnapshots().unwrap();
                lp.sync_all().unwrap();
                if r == 0 {
                    for i in 0..3 {
                        for ak in &aks {
                            compact_forget(lp, i, t, ak);
                        }
                    }
                }
            }
            if op < 2 {
                written.push((ids, a, step));
            }
            for i in 0..3 {
                for ak in &aks {
                    let got: Vec<Option<Value>> = runs.iter_mut().map(|lp| lp.peers[i].engine.get(&t, ak).unwrap()).collect();
                    assert_eq!(got[0], got[1], "seed {seed} step {step}: node {i} {ak}, forgetting vs not");
                    assert!(!purged.iter().any(|v| got[0] == Some(Value::Int(*v))), "seed {seed} step {step}: node {i} reads a purged value {:?}", got[0]);
                }
            }
        }
        by_name
    });
    // a seed may purge nothing through a name (about 1 per seed on average)
    osis_base::testenv::reach_floor("purges through a name", by_name, 1, 4);
}

// spec/commits.md §5 Purge: a purge that expires reaches only deltas expiring no later, so one
// naming a write that never expires is refused, never written to drop less than it says: by its
// name as by its header.
#[test]
fn an_expiring_purge_of_a_forgotten_write_is_refused_spec_commits_5() {
    for forget in [false, true] {
        let (mut lp, t) = world();
        let (c, _) = written(&mut lp, t, PurgeBy::Admin);
        if forget {
            compact_forget(&mut lp, 0, t, &reg());
            assert!(!lp.peers[0].engine.commit_ids().contains(&c));
        }
        let mut m = Mutation::new();
        let other = Ak::new("x:b.0").unwrap();
        m.set(t, &other, &Value::Int(1)).unwrap();
        m.expires(t, &other, osis_base::WallMs(T0.0 + 3_600_000)).unwrap();
        m.purge_commit(c, t, reg());
        let r = lp.peers[0].commit(m);
        assert!(matches!(r, Err(crate::Error::Clash(_))), "forget {forget}: {r:?}");
    }
}

/// `world` with admin 0's thing X, which writer 1 writes and which holds write on the thing:
/// writer 1 writes `SECRET` acting as X, purgeable by its author or an admin (X its purge author,
/// writer 1 its signer); admin 0 gets it and writes a snapshot of the register. X, the commit and
/// admin 0's snapshot.
fn written_as_x(lp: &mut LocalPeer, t: Tid) -> (Tid, CommitId, CommitId) {
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.me();
    let x = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    lp.hold(x);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, retain: false, floor: None };
    let w = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&x, &w, &edge).unwrap();
    lp.peers[0].engine.grant(&t, &x, &edge).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.purge_by(t, &reg(), PurgeBy::AuthorOrAdmin).unwrap();
    m.set(t, &reg(), &Value::Str("SECRET".into())).unwrap();
    m.act_as(x);
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[1].engine.header(&c).unwrap().purge_author(), x, "X is the commit's purge author");
    lp.advance(1_000);
    lp.sync(1, 0).unwrap();
    let s = lp.peers[0].engine.snapshot(&t, &reg()).unwrap().unwrap();
    lp.advance(1_000);
    (x, c, s)
}

/// Whether reader 2, given packages `ids` (by peer) and admin 0's request by author `author`
/// and never the commit `c`, reads `SECRET`.
fn reads_after(lp: &mut LocalPeer, t: Tid, c: CommitId, ids: &[(usize, CommitId)], author: Tid) -> bool {
    let p = request(lp, 0, t, PurgeItem::Author { tid: t, ak: reg(), author });
    for (from, id) in ids.iter().chain([&(0, p)]) {
        let pk = lp.peers[*from].engine.package(id).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
    }
    let e = &mut lp.peers[2].engine;
    assert!(!e.commit_ids().contains(&c), "the commit never reached the reader");
    e.get(&t, &reg()).unwrap() == Some(Value::Str("SECRET".into()))
}

// spec/crdt.md §8 (Facts: its purge author where that is not its signer),
// spec/commits.md §5 (Without the header): admin 0's snapshot states, for writer 1's write made as X, the
// purge author its own commit named: X, neither writer 1 (its signer) nor admin 0 (the
// snapshot's). Reader 2, holding the snapshot and never the commit, has the copy taken by a
// request by author X and kept against one by author writer 1. Fails with a fact naming the
// snapshot's signer or the carried commit's.
#[test]
fn a_snapshot_states_each_carried_writes_own_purge_author_spec_crdt_8() {
    for (by_x, takes) in [(true, true), (false, false)] {
        let (mut lp, t) = world();
        let (x, c, s) = written_as_x(&mut lp, t);
        let author = if by_x { x } else { lp.peers[1].engine.me() };
        assert_eq!(!reads_after(&mut lp, t, c, &[(0, s)], author), takes, "by author X {by_x}");
    }
}

// spec/commits.md §5 (Without the header: dropped only if it stands by every held valid snapshot),
// issues/forged-copy-undetected.md (a snapshot's word for a carried write is never compared with
// the original): admin 0's snapshot
// misnames writer 1's write made as X, stating its signer, writer 1, as its purge author
// (a fact naming none). Reader 2 holding that
// snapshot alone has the copy taken by a request by author writer 1, as by any snapshot's word
// (today's behaviour, the owner's question); holding writer 1's honest snapshot too, the two
// disagree and the request takes nothing.
#[test]
fn a_misnamed_purge_author_misleads_only_a_node_holding_no_honest_snapshot_spec_commits_5() {
    for honest_too in [false, true] {
        let (mut lp, t) = world();
        let me = lp.peers[1].engine.me();
        let (_, c, _) = written_as_x(&mut lp, t);
        let honest = lp.peers[1].engine.snapshot(&t, &reg()).unwrap().unwrap();
        let item = lp.peers[0].engine.purge_item(&c, t, reg()).unwrap();
        let PurgeItem::Commit { ts, src, .. } = item else { unreachable!() };
        lp.peers[0].engine.core.lie_facts = Some([((ts, src), osis_crdt::Fact { by: PurgeBy::AuthorOrAdmin, purge_author: None })].into());
        lp.advance(1_000);
        let lie = lp.peers[0].engine.snapshot(&t, &reg()).unwrap().unwrap();
        lp.advance(1_000);
        let mut held = vec![(0, lie)];
        if honest_too {
            held.push((1, honest));
        }
        assert_eq!(reads_after(&mut lp, t, c, &held, me), honest_too, "honest snapshot held too {honest_too}");
    }
}

// spec/commits.md §5 (Without the header), spec/permissions.md §6 (author: the purge author with
// write on the thing), issues/forged-copy-undetected.md: a writer's snapshot misnaming the purge
// author of an ADMIN's write as the writer itself lets the writer's own request by author take
// that write at a node holding the snapshot and the request alone: a writer erases a write only
// admins may purge (`author_or_admin`, the admin its author), there. Admin 0, holding the header,
// still reads it; reader 2 reads it again once the commit reaches it (the header decides), so
// the loss lasts only while no honest carrying body reaches it: the lie never covers the
// original (its facts disagree with the header, spec/commits.md §5 Covered), so honest holders
// keep logging it. Today's behaviour, the owner's question (the issue).
#[test]
fn a_writers_misnamed_fact_lets_it_erase_an_admins_write_at_a_snapshot_only_node_spec_commits_5() {
    let (mut lp, t) = world();
    let mut m = Mutation::new();
    m.purge_by(t, &reg(), PurgeBy::AuthorOrAdmin).unwrap();
    m.set(t, &reg(), &Value::Str("SECRET".into())).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    lp.sync(0, 1).unwrap();
    let forger = lp.peers[1].engine.me();
    let item = lp.peers[1].engine.purge_item(&c, t, reg()).unwrap();
    let PurgeItem::Commit { ts, src, .. } = item else { unreachable!() };
    lp.peers[1].engine.core.lie_facts = Some([((ts, src), osis_crdt::Fact { by: PurgeBy::AuthorOrAdmin, purge_author: Some(forger) })].into());
    let lie = lp.peers[1].engine.snapshot(&t, &reg()).unwrap().unwrap();
    lp.advance(1_000);
    let p = request(&mut lp, 1, t, PurgeItem::Author { tid: t, ak: reg(), author: forger });
    let secret = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get(&t, &reg()).unwrap() == Some(Value::Str("SECRET".into()));
    for id in [lie, p] {
        let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
        lp.deliver(0, &pk).unwrap();
    }
    assert!(!lp.peers[2].engine.commit_ids().contains(&c), "the commit never reached the reader");
    assert!(!secret(&mut lp, 2), "the writer's request took the admin's write at the reader");
    assert!(secret(&mut lp, 0), "the admin, holding the header, still reads it");
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    assert!(secret(&mut lp, 2), "the header decides once it arrives");
}
