//! Two people (commits delivered by hand, as in `sync`): who can see a thing, tagging (places or
//! nests only: sharing through a tag waits on issues/tag-sharing-op.md), undo across people.
use osis::internals::Internals as _;
use osis::core::NAME;
use osis::{Config, EdgeOpts, ManualClock, MemStore, Osis, Role, StoreAt, WallMs};
use osis_app::data::{Data, NewKind};
use std::sync::Arc;

fn cfg(seed: u64, clock: &Arc<ManualClock>) -> Config {
    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
    c.seed = Some(seed);
    c.clock = Some(clock.clone());
    c
}

/// Every commit `from` holds that `to` takes (another person's private commits it cannot use
/// are refused; that is fine here).
fn deliver(from: &Osis, to: &Osis) {
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        let _ = to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
    }
}

fn sync(a: &Data, b: &Data) {
    for _ in 0..2 {
        deliver(&a.db, &b.db);
        deliver(&b.db, &a.db);
    }
}

/// Alice and Bob, two people, each with an app group; each holds the other's commits.
fn two_people() -> (Data, Data) {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Data::new(Osis::create(cfg(1, &clock)).unwrap().0);
    let b = Data::new(Osis::create(cfg(2, &clock)).unwrap().0);
    a.main_group().unwrap();
    b.main_group().unwrap();
    sync(&a, &b);
    (a, b)
}

/// A tag Alice made in the app and shared with Bob (`role`).
fn shared_tag(a: &Data, b: &Data, role: Role) -> osis::Tid {
    let tag = a.create(NewKind::Tag).unwrap();
    a.db.grant(tag, b.db.me(), role, EdgeOpts::default()).unwrap();
    tag
}

/// Tagging places and shares nothing, even into a shared tag: the thing stays "Only you" and
/// Bob does not reach it (sharing through a tag waits on core, issues/tag-sharing-op.md).
#[test]
fn tagging_shares_nothing() {
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    assert_eq!(a.tags_of(n).unwrap(), vec![shared]);
    assert_eq!(a.reach(n).unwrap().who(), "Only you");
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), None);
    a.remove_tag(n, shared).unwrap();
    assert!(a.tags_of(n).unwrap().is_empty());
}

/// Who can see a thing reached through someone else's tag (here an edge given by hand): Bob's
/// note in Alice's tag names Alice (the tag's owner, on no roster); Alice's note shared with Bob
/// names her as owner.
#[test]
fn reach_through_someone_elses_tag() {
    let (a, b) = two_people();
    let tag = shared_tag(&a, &b, Role::Write);
    sync(&a, &b);
    let nb = b.create(NewKind::Note).unwrap();
    b.add_tag(nb, tag).unwrap();
    b.db.grant(nb, tag, Role::Write, EdgeOpts::default()).unwrap();
    let r = b.reach(nb).unwrap();
    assert_eq!((r.people.len(), r.via.clone()), (1, vec![tag]), "{r:?}");
    assert_ne!(r.who(), "Only you");
    let na = a.create(NewKind::Note).unwrap();
    a.db.grant(na, b.db.me(), Role::Read, EdgeOpts::default()).unwrap();
    sync(&a, &b);
    assert_eq!(b.reach(na).unwrap().people.len(), 1, "Alice owns it");
}

/// An edge that ends later still counts now: who can see it must not hide a current reader.
#[test]
fn reach_counts_an_edge_until_it_ends() {
    let (a, b) = two_people();
    let tag = a.create(NewKind::Tag).unwrap();
    let until = WallMs(a.db.now().0 + 86_400_000);
    a.db.grant(tag, b.db.me(), Role::Read, EdgeOpts { until: Some(until), invite: None }).unwrap();
    assert_eq!(a.reach(tag).unwrap().people.len(), 1);
}

/// Undo takes back only my own changes: not a thing's creation (that would leave it in no
/// group), and never Bob's edit of a thing we share.
#[test]
fn undo_is_mine_and_keeps_the_thing() {
    let (a, b) = two_people();
    let tag = shared_tag(&a, &b, Role::Write);
    let n = a.create(NewKind::Note).unwrap();
    assert!(!a.undo(n).unwrap(), "nothing to undo on a new thing");
    assert!(a.things().unwrap().contains(&n));
    a.add_tag(n, tag).unwrap();
    a.db.grant(n, tag, Role::Write, EdgeOpts::default()).unwrap();
    a.db.write_with(|w| w.at(n, NAME).set(&"mine".to_string())).unwrap();
    assert!(a.undo(n).unwrap());
    assert_eq!(a.name(n).unwrap(), "");
    assert!(!a.undo(n).unwrap(), "back at the creation");
    assert!(a.things().unwrap().contains(&n) && a.tags_of(n).unwrap() == vec![tag]);
    a.db.write_with(|w| w.at(n, NAME).set(&"alice".to_string())).unwrap();
    sync(&a, &b);
    b.db.write_with(|w| w.at(n, NAME).set(&"bob".to_string())).unwrap();
    sync(&a, &b);
    assert_eq!(a.name(n).unwrap(), "bob");
    let _ = a.undo(n);
    assert_eq!(a.name(n).unwrap(), "bob", "Bob's change stays");
    // a created tag keeps its place too
    let t = a.create(NewKind::Tag).unwrap();
    assert!(!a.undo(t).unwrap());
    assert_eq!(a.kind(t).unwrap(), osis_app::data::Kind::Tag);
    assert!(a.all_tags().unwrap().contains(&t));
}

/// "Edited" counts content changes, not sharing; a clock running ahead cannot date it ahead.
#[test]
fn edited_time() {
    let (a, b) = two_people();
    let n = a.create(NewKind::Note).unwrap();
    let made = a.changed(n).unwrap();
    let tag = shared_tag(&a, &b, Role::Read);
    a.add_tag(n, tag).unwrap();
    a.db.grant(n, tag, Role::Read, EdgeOpts::default()).unwrap();
    assert_eq!(a.changed(n), Some(made), "a placement or an edge is not an edit");
    assert!(a.changed(n).unwrap() <= a.db.now().0);
}

/// Tagging a tag nests it (a subgroup, not an item); removing un-nests.
#[test]
fn tagging_a_tag_nests_it() {
    let (a, _b) = two_people();
    let inner = a.create(NewKind::Tag).unwrap();
    let deeper = a.create(NewKind::Tag).unwrap();
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, inner).unwrap();
    a.add_tag(deeper, inner).unwrap();
    let g = a.get(inner, osis::core::GROUP).unwrap().unwrap();
    assert!(g.subgroups.contains(&deeper) && !g.items.contains(&deeper), "a tag nests as a subgroup");
    assert_eq!(a.tags_of(deeper).unwrap(), vec![inner]);
    assert_eq!(a.tag_contents(inner).unwrap(), (vec![deeper], vec![n]));
    a.remove_tag(deeper, inner).unwrap();
    assert!(a.tag_contents(inner).unwrap().0.is_empty(), "un-nested");
}
