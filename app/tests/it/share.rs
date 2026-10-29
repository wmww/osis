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

/// Tagging a tag nests it (a subgroup, not an item); nesting into a shared tag shares the
/// sub-tag and, recursively, what is tagged with it, so Bob reads a note two levels down.
#[test]
fn nesting_a_tag_shares_below() {
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let inner = a.create(NewKind::Tag).unwrap();
    let deeper = a.create(NewKind::Tag).unwrap();
    let n = a.create(NewKind::Note).unwrap();
    let m = a.create(NewKind::Note).unwrap();
    a.add_tag(n, inner).unwrap();
    a.add_tag(deeper, inner).unwrap();
    a.add_tag(m, deeper).unwrap();
    let g = a.get(inner, osis::core::GROUP).unwrap().unwrap();
    assert!(g.subgroups.contains(&deeper) && !g.items.contains(&deeper), "a tag nests as a subgroup");
    assert_eq!(a.tags_of(deeper).unwrap(), vec![inner]);
    assert_eq!(a.tag_contents(inner).unwrap(), (vec![deeper], vec![n]));
    assert!(a.share_reach(inner, shared).unwrap().is_some());
    a.add_tag(inner, shared).unwrap();
    assert_eq!(a.reach(m).unwrap().people.len(), 1, "two levels down: {:?}", a.reach(m).unwrap());
    sync(&a, &b);
    for t in [inner, deeper, n, m] {
        assert_eq!(b.db.role_on(t), Some(Role::Read), "Bob reaches {t} through the chain");
    }
    a.remove_tag(deeper, inner).unwrap();
    assert!(a.tag_contents(inner).unwrap().0.is_empty(), "un-nested");
}

/// Removing a tag takes back the access tagging gave, and only that: not while the thing is
/// still under the tag another way (here: in a sub-tag of it).
#[test]
fn removing_a_tag_revokes_only_its_own_access() {
    use osis::WaitForSync::Skip;
    use osis_kit::tasks::block_on;
    // no servers here: the pre-sync is skipped (the app uses core's default, Required)
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read));
    // still under the tag through a sub-tag: kept
    let sub = a.create(NewKind::Tag).unwrap();
    a.add_tag(sub, shared).unwrap();
    a.add_tag(n, sub).unwrap();
    a.remove_tag(n, shared).unwrap();
    assert!(!a.revoke_needed(n, shared).unwrap(), "still under the tag through the sub-tag");
    a.remove_tag(n, sub).unwrap();
    // as the UI does: removing it from the sub-tag takes back the sub-tag's access first
    assert!(a.revoke_needed(n, sub).unwrap());
    block_on(a.revoke(n, sub, Skip)).unwrap();
    assert!(a.revoke_needed(n, shared).unwrap());
    block_on(a.revoke(n, shared, Skip)).unwrap();
    assert!(a.db.roster(n).get(&shared).is_none_or(|e| e.until.is_some()), "the tag's edge on the note ended");
    assert!(!a.revoke_needed(n, shared).unwrap(), "nothing left to take back");
    assert_eq!(a.reach(n).unwrap().who(), "Only you");
    // a thing never shared through the tag: nothing to do
    let m = a.create(NewKind::Note).unwrap();
    assert!(!a.revoke_needed(m, shared).unwrap());
    // reached another way too (a sub-tag's edge left in place): it stays reachable
    let k = a.create(NewKind::Note).unwrap();
    a.add_tag(k, shared).unwrap();
    a.add_tag(k, sub).unwrap();
    a.db.write_with(|w| w.unplace(k, shared).and_then(|()| w.unplace(k, sub))).unwrap();
    assert!(a.revoke_needed(k, shared).unwrap());
    let r = block_on(a.revoke(k, shared, Skip));
    assert!(matches!(r, Err(osis_app::data::RevokeError::Kept(_))), "{r:?}");
    assert!(!a.db.member_path(k, shared).is_empty(), "the tag still reaches it through the sub-tag");
}

/// Waiting revocations: queued, still applying until done, dropped when the thing is re-tagged
/// or deleted, and visible on the person's other app group.
#[test]
fn waiting_revocations() {
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    assert!(a.revoke_needed(n, shared).unwrap());
    a.queue_revoke(n, shared).unwrap();
    a.queue_revoke(n, shared).unwrap();
    assert_eq!(a.pending_revokes().unwrap(), vec![(n, shared)], "once");
    assert!(a.revoke_applies(n, shared).unwrap());
    // re-tagged: no longer applies
    a.add_tag(n, shared).unwrap();
    assert!(!a.revoke_applies(n, shared).unwrap());
    a.remove_tag(n, shared).unwrap();
    assert!(a.revoke_applies(n, shared).unwrap());
    // deleted: no longer applies
    a.delete(n).unwrap();
    assert!(!a.revoke_applies(n, shared).unwrap());
    a.drop_revoke(n, shared).unwrap();
    assert!(a.pending_revokes().unwrap().is_empty());
}

/// Alice on two paired devices and Bob; every node holds the others' commits after `sync3`.
fn alice_twice_and_bob() -> (Data, Data, Data) {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Osis::create(cfg(1, &clock)).unwrap().0;
    let j = Osis::pair(cfg(3, &clock), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let a2 = Data::new(j.finish(&reply).unwrap());
    let a = Data::new(a);
    let b = Data::new(Osis::create(cfg(2, &clock)).unwrap().0);
    a.main_group().unwrap();
    b.main_group().unwrap();
    sync3(&a, &a2, &b);
    (a, a2, b)
}

fn sync3(a: &Data, a2: &Data, b: &Data) {
    for _ in 0..2 {
        sync(a, a2);
        sync(a, b);
        sync(a2, b);
    }
}

/// Removing a thing from the sub-tag after removing it from the tag: the tag's own edge is no
/// longer kept by anything and must be among what the removal takes back.
#[test]
fn removal_after_a_kept_one_takes_back_the_parents_edge() {
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let sub = a.create(NewKind::Tag).unwrap();
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.add_tag(sub, shared).unwrap();
    a.add_tag(n, sub).unwrap();
    a.remove_tag(n, shared).unwrap();
    assert!(a.revocations_after_removal(n).unwrap().is_empty(), "still under the tag through the sub-tag");
    a.remove_tag(n, sub).unwrap();
    assert_eq!(a.revocations_after_removal(n).unwrap(), std::collections::BTreeSet::from([(n, shared), (n, sub)]));
    // un-nesting the sub-tag also frees what only it kept under the tag
    let k = a.create(NewKind::Note).unwrap();
    a.add_tag(k, shared).unwrap();
    a.add_tag(k, sub).unwrap();
    a.remove_tag(k, shared).unwrap();
    a.remove_tag(sub, shared).unwrap();
    let r = a.revocations_after_removal(sub).unwrap();
    assert!(r.contains(&(sub, shared)) && r.contains(&(k, shared)), "{r:?}");
}

/// Nested several levels and in a cycle, a thing is still under the tag: nothing is taken back.
#[test]
fn deep_and_cyclic_nesting_keeps_access() {
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let (x, y, z) = (a.create(NewKind::Tag).unwrap(), a.create(NewKind::Tag).unwrap(), a.create(NewKind::Tag).unwrap());
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.add_tag(x, shared).unwrap();
    a.add_tag(y, x).unwrap();
    a.add_tag(z, y).unwrap();
    a.add_tag(x, z).unwrap(); // a cycle x -> y -> z -> x
    a.add_tag(n, z).unwrap();
    a.remove_tag(n, shared).unwrap();
    assert!(a.under(shared, n).unwrap());
    assert!(!a.revoke_needed(n, shared).unwrap());
    assert!(a.revocations_after_removal(n).unwrap().is_empty());
}

/// The tag's edge goes, never an edge Bob holds himself on the same thing.
#[test]
fn revoking_a_tag_keeps_a_direct_share() {
    use osis::WaitForSync::Skip;
    use osis_kit::tasks::block_on;
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.db.grant(n, b.db.me(), Role::Read, EdgeOpts::default()).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    assert!(a.revoke_needed(n, shared).unwrap());
    block_on(a.revoke(n, shared, Skip)).unwrap();
    assert!(a.db.roster(n).contains_key(&b.db.me()), "Bob's own edge stays");
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read));
}

/// Re-tagging while the revocation runs (the tag's edge still live, so the re-tag grants
/// nothing): once the revocation lands, the thing is placed in the tag and must still reach it.
#[test]
fn retag_during_a_revocation_keeps_access() {
    use osis::WaitForSync::Skip;
    use osis_kit::tasks::block_on;
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    assert!(a.revoke_applies(n, shared).unwrap());
    // the UI checked and started the task; the user puts it back before it ran
    a.add_tag(n, shared).unwrap();
    block_on(a.revoke(n, shared, Skip)).unwrap();
    assert_eq!(a.tags_of(n).unwrap(), vec![shared]);
    assert!(!a.db.member_path(n, shared).is_empty(), "placed in the shared tag but no longer shared");
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read));
}

/// Both of Alice's devices run the same waiting revocation before hearing of each other: the
/// result merges, Bob reaches the thing no more, and the entry is moot on both.
#[test]
fn two_devices_revoke_the_same_entry() {
    use osis::WaitForSync::Skip;
    use osis_kit::tasks::block_on;
    let (a, a2, b) = alice_twice_and_bob();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    sync3(&a, &a2, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read));
    a.remove_tag(n, shared).unwrap();
    a.queue_revoke(n, shared).unwrap();
    sync3(&a, &a2, &b);
    assert_eq!(a2.pending_revokes().unwrap(), vec![(n, shared)]);
    assert!(a2.revoke_applies(n, shared).unwrap());
    block_on(a.revoke(n, shared, Skip)).unwrap();
    block_on(a2.revoke(n, shared, Skip)).unwrap();
    sync3(&a, &a2, &b);
    for d in [&a, &a2] {
        assert!(d.db.member_path(n, shared).is_empty());
        assert!(!d.revoke_applies(n, shared).unwrap());
        assert_eq!(d.reach(n).unwrap().who(), "Only you");
    }
    assert_eq!(b.db.role_on(n), None, "Bob no longer reaches it");
    // the merged rotations leave the thing writable and synced between the devices (what Bob
    // can decrypt is not testable here: `deliver` hands over plaintext commits)
    a2.db.write_with(|w| w.at(n, NAME).set(&"after".to_string())).unwrap();
    sync3(&a, &a2, &b);
    assert_eq!(a.name(n).unwrap(), "after");
}

/// Re-tagged on Alice's other device while the first one revokes, before either hears of the
/// other: after the merge the thing is in the tag and the tag's members reach it.
#[test]
fn retag_on_another_device_during_a_revocation() {
    use osis::WaitForSync::Skip;
    use osis_kit::tasks::block_on;
    let (a, a2, b) = alice_twice_and_bob();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    a.queue_revoke(n, shared).unwrap();
    sync3(&a, &a2, &b);
    for first in [true, false] {
        if first {
            a2.add_tag(n, shared).unwrap();
        }
        block_on(a.revoke(n, shared, Skip)).unwrap();
        if !first {
            a2.add_tag(n, shared).unwrap();
        }
        sync3(&a, &a2, &b);
        assert_eq!(a.tags_of(n).unwrap(), vec![shared]);
        assert!(!a.db.member_path(n, shared).is_empty(), "placed in the shared tag but no longer shared");
        // again, the other way round
        a.remove_tag(n, shared).unwrap();
        a.queue_revoke(n, shared).unwrap();
        sync3(&a, &a2, &b);
    }
    a2.add_tag(n, shared).unwrap();
    sync3(&a, &a2, &b);
    assert_eq!(a.tags_of(n).unwrap(), vec![shared]);
    assert!(!a.db.member_path(n, shared).is_empty(), "placed in the shared tag but no longer shared");
}
