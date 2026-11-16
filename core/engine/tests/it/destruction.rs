//! A destroyed thing's dependents and mintings at one node (spec/commits.md §5 Destruction, A
//! thing's mintings travel with its record): what a destroyed thing keeps while a held thing needs
//! it, and how its mintings go under a sync ID lacking it. Across nodes: osis-sync's
//! `destruction::` tests; the reference reading: held-model.

use crate::common::{REG, s};
use crate::flows::{people, thing_of};
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{CommitId, Tid};
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

/// Past every request's window (`ROLE_KEEP`): what keeps a destroyed thing then is what needs it.
fn past_window(lp: &mut LocalPeer) {
    lp.advance(ROLE_KEEP_MS + 1_000);
    lp.peers[0].tick().unwrap();
}

/// Whether peer 0 still keeps destroyed `t`'s record (it keeps nothing once nothing needs it).
fn keeps(lp: &mut LocalPeer, t: &Tid) -> bool {
    let e = &mut lp.peers[0].engine;
    assert!(e.destroyed(t) && !e.knows(t), "t destroyed");
    e.core.created(t).is_some()
}

// spec/commits.md §5 (Destruction: a destroyed thing keeps its record while a held thing needs
// it: a dependent, by a held creation record naming it first admin, whatever needed it letting go
// of it, however it goes, it keeps nothing then either): t, u's first admin, destroyed, keeps its
// record past the request's window while u lives; u destroyed too, past its window t keeps
// nothing.
#[test]
fn a_dependent_keeps_a_destroyed_things_record_spec_commits_5() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    let u = thing_of(&mut lp, 0, t);
    purge(&mut lp, t);
    past_window(&mut lp);
    assert!(keeps(&mut lp, &t), "u names t first admin: t keeps its record");
    assert_eq!(lp.peers[0].engine.get_typed(&u, &REG).unwrap(), Some(s("new")), "u reads on");
    purge(&mut lp, u);
    past_window(&mut lp);
    assert!(!keeps(&mut lp, &u), "nothing needs u");
    assert!(!keeps(&mut lp, &t), "u let go of t: t keeps nothing");
}
