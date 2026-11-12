//! A purge of a commit this node holds no header of (spec/commits.md §5 Purge, Without the
//! header): judged by the facts the snapshots carrying its writes state (spec/crdt.md §8), so it
//! takes every copy at a node that holds only a snapshot and the request.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_schema::core_types as ct;
use osis_schema::Retention;

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
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
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
        m.retention(t, &reg(), Retention { by }).unwrap();
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
                    true => PurgeItem::Author { tid: t, ak: reg(), actor: lp.peers[1].engine.me() },
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
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
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
    lp.peers[3].engine.core.lie_facts = Some([((ts, src), osis_crdt::Fact { by: PurgeBy::Writer, actor: None })].into());
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
