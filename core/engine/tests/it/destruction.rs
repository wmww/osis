//! A destroyed thing's dependents and mintings at one node (spec/commits.md §5 Destruction, A
//! thing's mintings travel with its record): what a destroyed thing keeps while a held thing needs
//! it, and how its mintings go under a sync ID lacking it. Across nodes: osis-sync's
//! `destruction::` tests; the reference reading: held-model.

use crate::common::{REG, s};
use crate::flows::{people, thing_of};
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{CommitId, Tid, Value, WallMs};
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
// it: a dependent, by a held creation record naming it first admin; whatever needed it letting go
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

// spec/commits.md §5 (Destruction: a held thing needs a destroyed thing it references in a live
// durable value other than in `group.0`; whatever needed it letting go, it keeps nothing): r
// references t in a value and g lists it in `group.0`; t destroyed keeps its record past the
// window while r's value names it, and nothing once r's value no longer does (g's listing needs
// nothing).
#[test]
fn a_reference_keeps_a_destroyed_thing_but_a_group_does_not_spec_commits_5() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    let r = thing_of(&mut lp, 0, ps[0]);
    let g = thing_of(&mut lp, 0, ps[0]);
    let refs = osis_base::Ak::new("x:ref.0").unwrap();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(r, &refs, &Value::Tid(t)).unwrap();
    let mut gr = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    gr.items.insert(t);
    m.set(g, &ct::GROUP, &gr).unwrap();
    e.commit(m).unwrap().unwrap();
    purge(&mut lp, t);
    past_window(&mut lp);
    assert!(keeps(&mut lp, &t), "r's value references t: t keeps its record");
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(r, &refs, &Value::Int(0)).unwrap();
    e.commit(m).unwrap().unwrap();
    lp.peers[0].tick().unwrap();
    assert!(!keeps(&mut lp, &t), "only g's group.0 lists t: it keeps nothing");
}

// spec/commits.md §5 (A thing's mintings travel with its record: a minting's standing, valued
// ones after value-less ones, then by end (an expiry before none); the witness is the highest),
// spec/sync-judgement.md §2 (a header-only copy of a minting its witness supersedes): t, u's first
// admin and outside D's closure, minted expiring and then again durable: the durable one is the
// witness, and each minting has a header-only copy in D's required set as a minting of t, which
// sync ranks (`BodyMeta::mints`); a copy of the witness alone would leave the other outside it,
// so a node holding only it drops what another keeps.
#[test]
fn every_minting_of_a_thing_whose_record_goes_is_a_minting_copy_spec_commits_5() {
    let (mut lp, ps) = people(1);
    let e = &mut lp.peers[0].engine;
    let far = e.now().0 + 10 * ROLE_KEEP_MS;
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, ps[0]);
    m.set(t, &REG, &s("t")).unwrap();
    m.expires_all(WallMs(far));
    let first = e.commit(m).unwrap().unwrap();
    let (_, d) = e.account().unwrap().unwrap();
    let mut m = Mutation::new();
    let u = e.new_thing(&mut m, t);
    m.set(u, &REG, &s("u")).unwrap();
    let mut gr = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
    gr.items.insert(u);
    m.set(d, &ct::GROUP, &gr).unwrap();
    e.commit(m).unwrap().unwrap();
    let rec = e.core.created(&t).cloned().unwrap();
    let mut m = Mutation::new();
    m.create(rec);
    let again = e.commit_hostile(m).unwrap().unwrap();
    e.follow().unwrap();
    let w = e.witness(&t).unwrap();
    assert_eq!(w.commit, again, "the durable minting stands highest");
    let ms = e.mintings_of(&t);
    let low = ms.iter().find(|m| m.commit == first).unwrap();
    assert!(low.standing < w.standing && low.expires == Some(far));
    let s = e.home_sync_id(&d).unwrap().unwrap();
    for c in [first, again] {
        let b = e.sync_bodies(&c).unwrap();
        let meta = b.get(&s).unwrap_or_else(|| panic!("{c:?} has a body under D"));
        assert!(meta.header_only && meta.certificate && meta.mints.contains(&t), "{c:?}: {meta:?}");
    }
}
