//! Two people (commits delivered by hand, as in `sync`): who can see a thing, the share
//! confirmation's reach, tagging into a shared tag, undo across people.
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

/// A shared tag confirms and a private one does not; confirming shares: the thing reaches Bob
/// (an edge for the tag, not only a placement) and he holds a role on it.
#[test]
fn tagging_into_a_shared_tag_shares() {
    let (a, b) = two_people();
    let private = a.create(NewKind::Tag).unwrap();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    assert_eq!(a.share_reach(n, private).unwrap(), None, "a private tag needs no confirmation");
    a.add_tag(n, private).unwrap();
    assert_eq!(a.reach(n).unwrap().who(), "Only you");
    let r = a.share_reach(n, shared).unwrap().expect("a shared tag confirms");
    assert_eq!(r.people.len(), 1);
    a.add_tag(n, shared).unwrap();
    let r = a.reach(n).unwrap();
    assert_eq!(r.people.len(), 1, "{r:?}");
    assert_eq!(r.via, vec![shared]);
    assert_eq!(a.share_reach(n, shared).unwrap(), None, "already shared there");
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read), "Bob reaches it, capped by his role on the tag");
}

/// Bob puts his own note into Alice's tag: his view of who sees it names Alice (the tag's owner,
/// who is on no roster), and so does the confirmation. A thing Bob cannot share (Alice's) is only
/// placed, without a confirmation that would promise sharing.
#[test]
fn reach_through_someone_elses_tag() {
    let (a, b) = two_people();
    let tag = shared_tag(&a, &b, Role::Write);
    sync(&a, &b);
    let nb = b.create(NewKind::Note).unwrap();
    let r = b.share_reach(nb, tag).unwrap().expect("Alice's tag reaches Alice");
    assert_eq!(r.people.len(), 1, "{r:?}");
    b.add_tag(nb, tag).unwrap();
    let r = b.reach(nb).unwrap();
    assert_eq!((r.people.len(), r.via.clone()), (1, vec![tag]), "{r:?}");
    assert_ne!(r.who(), "Only you");
    let na = a.create(NewKind::Note).unwrap();
    a.db.grant(na, b.db.me(), Role::Read, EdgeOpts::default()).unwrap();
    sync(&a, &b);
    assert_eq!(b.share_reach(na, tag).unwrap(), None, "not Bob's to share");
    assert_eq!(b.reach(na).unwrap().people.len(), 1, "Alice owns it");
}

/// An edge that ends later still counts now: who can see it must not hide a current reader.
#[test]
fn reach_counts_an_edge_until_it_ends() {
    let (a, b) = two_people();
    let tag = a.create(NewKind::Tag).unwrap();
    let until = WallMs(a.db.now().0 + 86_400_000);
    a.db.grant(tag, b.db.me(), Role::Read, EdgeOpts { until: Some(until), invite: None }).unwrap();
    assert_eq!(a.tag_reach(tag).unwrap().people.len(), 1);
    let n = a.create(NewKind::Note).unwrap();
    assert!(a.share_reach(n, tag).unwrap().is_some());
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
    assert_eq!(a.changed(n), Some(made), "the tag's edge is not an edit");
    assert!(a.changed(n).unwrap() <= a.db.now().0);
}
