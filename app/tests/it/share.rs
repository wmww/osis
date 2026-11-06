//! Two accounts (commits delivered by hand, as in `sync`): who can see a thing, tagging (adds or
//! nests only: sharing through a tag waits on issues/tag-sharing-op.md), undo across accounts.
use osis::internals::Internals as _;
use osis::core::NAME;
use osis::{GrantOpts, MemStore, Osis, Role, Store, Time};
use osis::internals::{ManualClock};
use osis_app::data::{Data, NewKind};
use std::sync::Arc;

fn cfg(seed: u64, clock: &Arc<ManualClock>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.app.internals.seed = Some(seed);
    c.app.internals.clock = Some(clock.clone());
    c
}

/// Every commit `from` holds that `to` takes (another account's private commits it cannot use
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

/// Alice and Bob, two accounts, each with an app group; each holds the other's commits.
fn two_people() -> (Data, Data) {
    let clock = Arc::new(ManualClock::new(Time(1_760_000_000_000)));
    let a = Data::new(osis::internals::create(cfg(1, &clock)).unwrap());
    let b = Data::new(osis::internals::create(cfg(2, &clock)).unwrap());
    a.main_group().unwrap();
    b.main_group().unwrap();
    sync(&a, &b);
    (a, b)
}

/// A tag Alice made in the app and shared with Bob (`role`).
fn shared_tag(a: &Data, b: &Data, role: Role) -> osis::Tid {
    let tag = a.create(NewKind::Tag).unwrap();
    a.db.grant(tag, b.db.me(), role, GrantOpts::default()).unwrap();
    tag
}

/// Tagging adds to a tag and shares nothing, even into a shared tag: the thing stays "Only you" and
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
    assert_eq!(b.db.role_on(n).unwrap(), None);
    a.remove_tag(n, shared).unwrap();
    assert!(a.tags_of(n).unwrap().is_empty());
}

/// Who can see a thing reached through someone else's tag (here a grant given by hand): Bob's
/// note in Alice's tag names Alice (the tag's first admin); Alice's note shared with Bob names her
/// (its first admin).
#[test]
fn reach_through_someone_elses_tag() {
    let (a, b) = two_people();
    let tag = shared_tag(&a, &b, Role::Write);
    sync(&a, &b);
    let nb = b.create(NewKind::Note).unwrap();
    b.add_tag(nb, tag).unwrap();
    b.db.grant(nb, tag, Role::Write, GrantOpts::default()).unwrap();
    let r = b.reach(nb).unwrap();
    assert_eq!((r.people.len(), r.via.clone()), (1, vec![tag]), "{r:?}");
    assert_ne!(r.who(), "Only you");
    let na = a.create(NewKind::Note).unwrap();
    a.db.grant(na, b.db.me(), Role::Read, GrantOpts::default()).unwrap();
    sync(&a, &b);
    assert_eq!(b.reach(na).unwrap().people.len(), 1, "Alice, its first admin");
}

/// A grant that ends later still counts now: who can see it must not hide a current reader.
#[test]
fn reach_counts_an_edge_until_it_ends() {
    let (a, b) = two_people();
    let tag = a.create(NewKind::Tag).unwrap();
    let until = Time(a.db.now().unwrap().0 + 86_400_000);
    a.db.grant(tag, b.db.me(), Role::Read, GrantOpts { until: Some(until), may_grant: None }).unwrap();
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
    a.db.grant(n, tag, Role::Write, GrantOpts::default()).unwrap();
    let mut w = a.db.write();
    w.at(n, NAME).set(&"mine".to_string()).unwrap();
    w.commit().unwrap();
    assert!(a.undo(n).unwrap());
    assert_eq!(a.name(n).unwrap(), "");
    assert!(!a.undo(n).unwrap(), "back at the creation");
    assert!(a.things().unwrap().contains(&n) && a.tags_of(n).unwrap() == vec![tag]);
    let mut w = a.db.write();
    w.at(n, NAME).set(&"alice".to_string()).unwrap();
    w.commit().unwrap();
    sync(&a, &b);
    let mut w = b.db.write();
    w.at(n, NAME).set(&"bob".to_string()).unwrap();
    w.commit().unwrap();
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
    let made = a.changed(n).unwrap().unwrap();
    let tag = shared_tag(&a, &b, Role::Read);
    a.add_tag(n, tag).unwrap();
    a.db.grant(n, tag, Role::Read, GrantOpts::default()).unwrap();
    assert_eq!(a.changed(n).unwrap(), Some(made), "a membership or a grant is not an edit");
    assert!(a.changed(n).unwrap().unwrap() <= a.db.now().unwrap().0);
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
    let g = a.db.at(inner, osis::internals::core_types::GROUP).get().unwrap().unwrap();
    assert!(g.subgroups.contains(&deeper) && !g.items.contains(&deeper), "a tag nests as a subgroup");
    assert_eq!(a.tags_of(deeper).unwrap(), vec![inner]);
    assert_eq!(a.tag_contents(inner).unwrap(), (vec![deeper], vec![n]));
    a.remove_tag(deeper, inner).unwrap();
    assert!(a.tag_contents(inner).unwrap().0.is_empty(), "un-nested");
}
