//! A destroyed thing at one node (spec/commits.md §5 Destruction): what it keeps is held by the
//! ordinary rules, while it is in the node closure or a held thing needs it, and released whole as
//! any thing. Across nodes: osis-sync's `destruction::` tests; the reference reading: held-model.

use crate::common::{REG, s};
use crate::flows::{people, thing_of};
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{CommitId, Strong, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_schema::core_types as ct;

/// A purge of `t`'s creation by peer 0.
fn purge(lp: &mut LocalPeer, t: Tid) -> CommitId {
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let now = e.now();
    m.set(t, &ct::PURGE, &now).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: t, ak: ct::CREATED.name() });
    e.commit(m).unwrap().unwrap()
}

/// Adds (`on`) or removes a strong to `t` in a `holds.0`.
fn holds(t: Tid, on: bool) -> PathOp {
    let v = Value::Strong(t);
    PathOp { path: vec![], op: if on { Op::Add(v) } else { Op::Remove(v) } }
}

/// Past every request's purge floor (`ROLE_KEEP`).
fn past_floor(lp: &mut LocalPeer) {
    lp.advance(ROLE_KEEP_MS + 1_000);
    lp.peers[0].tick().unwrap();
}

/// Whether peer 0 holds destroyed `t`'s record.
fn keeps(lp: &mut LocalPeer, t: &Tid) -> bool {
    let e = &mut lp.peers[0].engine;
    assert!(!e.knows(t), "t reads as absent");
    e.core.created(t).is_some()
}

/// A plain thing under D with a value, held by a strong in D's `holds.0`.
fn under_d(lp: &mut LocalPeer) -> Tid {
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let mut m = Mutation::new();
    let t = m.create(e.thing_record(d, None));
    m.set(t, &REG, &s("new")).unwrap();
    m.op(d, &ct::HOLDS, holds(t, true)).unwrap();
    e.commit(m).unwrap();
    t
}

// spec/commits.md §5 (Destruction: what stays is held by the ordinary rules alone; a request
// destroying it is a commit carrying a purge request, kept and logged as any), spec/sync-set.md §3:
// t, held from D, destroyed, keeps its record and the request past the purge's floor while held;
// its strong removed and released beside a live thing x, it keeps what x keeps.
#[test]
fn a_destroyed_thing_is_held_and_released_as_any_thing_spec_commits_5() {
    let (mut lp, _) = people(1);
    let (t, x) = (under_d(&mut lp), under_d(&mut lp));
    let q = purge(&mut lp, t);
    past_floor(&mut lp);
    assert!(keeps(&mut lp, &t), "held: t keeps its record past the floor");
    assert!(lp.peers[0].engine.commit_ids().contains(&q), "held: the request stays");
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let mut m = Mutation::new();
    m.op(d, &ct::HOLDS, holds(t, false)).unwrap();
    m.op(d, &ct::HOLDS, holds(x, false)).unwrap();
    e.commit(m).unwrap();
    e.released(&[t, x].into()).unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.core.created(&t).is_some(), e.core.created(&x).is_some(), "released: its record as x's");
    assert_eq!(e.held_actors().contains(&t), e.held_actors().contains(&x), "released: its secrets as x's");
}

// spec/commits.md §5 (Destruction: a destroyed thing keeps its record while a held thing needs
// it: a dependent, by a held creation record naming it mint admin): t, under the account and
// held from D, is u's mint admin; u is held from the node root. t destroyed and released from
// the node closure keeps its record while u lives; u destroyed and released too, t keeps nothing
// once the pass ends (it lost its last need), its chain topping at this node's own account.
#[test]
fn a_dependent_keeps_a_destroyed_things_record_spec_commits_5() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    let u = thing_of(&mut lp, 0, t);
    lp.peers[0].engine.hold(Strong(u)).unwrap();
    purge(&mut lp, t);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let mut m = Mutation::new();
    m.op(d, &ct::HOLDS, holds(t, false)).unwrap();
    e.commit(m).unwrap();
    e.released(&[t].into()).unwrap();
    assert!(!e.closure_holds(&t), "t released");
    assert!(keeps(&mut lp, &t), "u names t mint admin: t keeps its record");
    assert_eq!(lp.peers[0].engine.get_typed(&u, &REG).unwrap(), Some(s("new")), "u reads on");
    purge(&mut lp, u);
    let e = &mut lp.peers[0].engine;
    e.unhold(Strong(u)).unwrap();
    e.released(&[u].into()).unwrap();
    e.settle_needs().unwrap();
    assert!(!keeps(&mut lp, &u), "nothing needs u");
    assert!(!keeps(&mut lp, &t), "u let go of t: t keeps nothing");
}
