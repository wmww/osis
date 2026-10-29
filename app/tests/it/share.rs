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
    let (a, a2, b, _) = alice_twice_and_bob_clock();
    (a, a2, b)
}

fn alice_twice_and_bob_clock() -> (Data, Data, Data, Arc<ManualClock>) {
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
    (a, a2, b, clock)
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

/// Re-tagging before the revocation runs (the tag's edge still live, so there is nothing to
/// confirm): the re-tag grants again and drops the entry, the revocation finds nothing to do,
/// and the thing still reaches the tag.
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

/// The commits `from` holds now (to deliver only what comes after).
fn held(from: &Data) -> std::collections::BTreeSet<osis::CommitId> {
    from.db.engine(|e| e.commit_ids()).into_iter().collect()
}

/// Delivers only the commits `from` made since `before`, except those in `skip`.
fn deliver_since(from: &Data, to: &Data, before: &std::collections::BTreeSet<osis::CommitId>, skip: &std::collections::BTreeSet<osis::CommitId>) {
    let pks = from.db.engine(|e| e.commit_ids().into_iter().filter(|id| !before.contains(id) && !skip.contains(id)).filter_map(|id| e.package(&id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        let _ = to.db.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
    }
}

/// What the UI does with the waiting revocations (`retry_revokes` and `revoked`), run at once.
fn run_pending(d: &Data) {
    use osis_kit::tasks::block_on;
    for (t, g) in d.pending_revokes().unwrap() {
        if d.revoke_moot(t, g).unwrap() {
            d.drop_revoke(t, g).unwrap();
            continue;
        }
        if !d.revoke_applies(t, g).unwrap() {
            continue;
        }
        match block_on(d.revoke(t, g, osis::WaitForSync::Skip)) {
            Ok(()) | Err(osis_app::data::RevokeError::Kept(_)) => d.drop_revoke(t, g).unwrap(),
            Err(osis_app::data::RevokeError::Failed(_)) => {}
        }
    }
}

/// Alice's other device hears of the waiting revocation (her app group) before of the removal
/// itself (the tag's group, another label): the thing still looks tagged there, which must not
/// drop the entry, or the access is never taken back.
#[test]
fn entry_seen_before_the_removal_is_kept() {
    let (a, a2, b) = alice_twice_and_bob();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    sync3(&a, &a2, &b);
    let before = held(&a);
    a.remove_tag(n, shared).unwrap();
    let unplace: std::collections::BTreeSet<_> = held(&a).difference(&before).copied().collect();
    for (x, m) in a.revocations_after_removal(n).unwrap() {
        a.queue_revoke(x, m).unwrap();
    }
    deliver_since(&a, &a2, &before, &unplace);
    assert_eq!(a2.pending_revokes().unwrap(), vec![(n, shared)]);
    assert_eq!(a2.tags_of(n).unwrap(), vec![shared], "a2 has not seen the removal");
    run_pending(&a2);
    sync3(&a, &a2, &b);
    run_pending(&a);
    sync3(&a, &a2, &b);
    assert!(a.tags_of(n).unwrap().is_empty());
    assert!(a.db.member_path(n, shared).is_empty(), "removed from the tag but the tag still reaches it");
    assert_eq!(b.db.role_on(n), None);
}

/// A re-tag on Alice's other device re-grants (the entry was waiting there); her first device
/// sees the placement but not yet the grant (another thing's commit), and the user removes the
/// thing again there. The removal is later than the grant it has not seen, so core's removal
/// covers it: the tag keeps no access to a thing the user took out of it.
#[test]
fn removal_racing_an_unseen_regrant() {
    let (a, a2, b, clock) = alice_twice_and_bob_clock();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    a.queue_revoke(n, shared).unwrap();
    sync3(&a, &a2, &b);
    // a2's `add_tag`, step by step: the placement, the re-grant, the entry dropped
    let before = held(&a2);
    a2.db.write_with(|w| w.place(n, shared)).unwrap();
    let placed = held(&a2);
    clock.advance(1000);
    a2.db.grant(n, shared, Role::Write, EdgeOpts::default()).unwrap();
    let grant: std::collections::BTreeSet<_> = held(&a2).difference(&placed).copied().collect();
    a2.drop_revoke(n, shared).unwrap();
    deliver_since(&a2, &a, &before, &grant);
    assert_eq!(a.tags_of(n).unwrap(), vec![shared]);
    assert!(a.pending_revokes().unwrap().is_empty());
    clock.advance(1000);
    a.remove_tag(n, shared).unwrap();
    for (x, m) in a.revocations_after_removal(n).unwrap() {
        a.queue_revoke(x, m).unwrap();
    }
    run_pending(&a);
    sync3(&a, &a2, &b);
    run_pending(&a);
    run_pending(&a2);
    sync3(&a, &a2, &b);
    assert!(a.tags_of(n).unwrap().is_empty());
    assert!(a.pending_revokes().unwrap().is_empty());
    for d in [&a, &a2] {
        assert!(d.db.member_path(n, shared).is_empty(), "taken out of the tag, but the unseen re-grant kept it shared");
    }
    assert_eq!(b.db.role_on(n), None);
}

/// Delivers each commit `from` holds and `to` lacks with probability one half.
fn deliver_some(from: &Data, to: &Data, rng: &mut u64) {
    let have = held(to);
    let pks = from.db.engine(|e| e.commit_ids().into_iter().filter(|id| !have.contains(id)).filter_map(|id| e.package(&id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        if next(rng).is_multiple_of(2) {
            let _ = to.db.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
    }
}

fn next(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

/// Alice's two devices take a thing out of a shared tag and put it back in random order,
/// running their waiting revocations as the UI does and hearing of each other only in part.
/// Once both hold everything, the waiting revocations reach a fixed point (no device keeps
/// undoing the other: no grant/revoke ping-pong), and a thing out of the tag is not shared.
#[test]
fn retag_and_removal_races_settle() {
    let mut out_but_shared = Vec::new();
    for seed in 1..=8u64 {
        let (a, a2, b, clock) = alice_twice_and_bob_clock();
        let shared = shared_tag(&a, &b, Role::Read);
        let n = a.create(NewKind::Note).unwrap();
        a.add_tag(n, shared).unwrap();
        sync3(&a, &a2, &b);
        let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let devs = [&a, &a2];
        for _ in 0..10 {
            clock.advance(1000);
            let (d, o) = if next(&mut rng).is_multiple_of(2) { (devs[0], devs[1]) } else { (devs[1], devs[0]) };
            match next(&mut rng) % 4 {
                0 if d.tags_of(n).unwrap().contains(&shared) => {
                    d.remove_tag(n, shared).unwrap();
                    for (x, m) in d.revocations_after_removal(n).unwrap() {
                        d.queue_revoke(x, m).unwrap();
                    }
                }
                1 if !d.tags_of(n).unwrap().contains(&shared) => {
                    if let Err(e) = d.add_tag(n, shared) {
                        eprintln!("seed {seed}: add_tag: {e}");
                    }
                }
                2 => run_pending(d),
                _ => deliver_some(d, o, &mut rng),
            }
        }
        sync3(&a, &a2, &b);
        let mut quiet = false;
        for _ in 0..4 {
            let before = (held(&a).len(), held(&a2).len());
            clock.advance(1000);
            run_pending(&a);
            run_pending(&a2);
            sync3(&a, &a2, &b);
            if (held(&a).len(), held(&a2).len()) == before {
                quiet = true;
                break;
            }
        }
        assert!(quiet, "seed {seed}: the devices keep writing (ping-pong)");
        let tagged = a.tags_of(n).unwrap().contains(&shared);
        assert_eq!(tagged, a2.tags_of(n).unwrap().contains(&shared));
        let reached = !a.db.member_path(n, shared).is_empty();
        if !tagged && reached {
            out_but_shared.push(seed);
        }
        if tagged && !reached {
            eprintln!("seed {seed}: tagged but unshared (the documented re-tag gap)");
        }
    }
    assert!(out_but_shared.is_empty(), "out of the tag but still shared: seeds {out_but_shared:?}");
}

/// The wider check after a removal takes back only what left the tag: a thing under the tag by
/// two sub-tags (a diamond) loses one sub-tag's edge and Bob still reaches it through the
/// other; a thing placed in the tag directly and in an un-nested sub-tag keeps its edges; a tag
/// both nested and placed is taken out both ways; a cycle cut from the tag frees what only it
/// held there.
#[test]
fn wider_removal_check_takes_back_only_what_left() {
    use std::collections::BTreeSet;
    let (a, b) = two_people();
    let t = shared_tag(&a, &b, Role::Read);
    let (x, y) = (a.create(NewKind::Tag).unwrap(), a.create(NewKind::Tag).unwrap());
    a.add_tag(x, t).unwrap();
    a.add_tag(y, t).unwrap();
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, x).unwrap();
    a.add_tag(n, y).unwrap();
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read));
    // diamond
    a.remove_tag(n, x).unwrap();
    assert_eq!(a.revocations_after_removal(n).unwrap(), BTreeSet::from([(n, x)]));
    for (p, m) in a.revocations_after_removal(n).unwrap() {
        a.queue_revoke(p, m).unwrap();
    }
    run_pending(&a);
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read), "still under the tag through the other sub-tag");
    // directly in the tag and in a sub-tag that is un-nested
    let k = a.create(NewKind::Note).unwrap();
    a.add_tag(k, t).unwrap();
    a.add_tag(k, y).unwrap();
    a.remove_tag(y, t).unwrap();
    let r = a.revocations_after_removal(y).unwrap();
    assert_eq!(r, BTreeSet::from([(y, t)]), "only y's own edge: k is in the tag itself, n was in y only");
    for (p, m) in r {
        a.queue_revoke(p, m).unwrap();
    }
    run_pending(&a);
    sync(&a, &b);
    assert_eq!(b.db.role_on(k), Some(Role::Read), "placed in the tag itself");
    assert_eq!(b.db.role_on(n), None, "n was under the tag only through y");
    // a tag both nested and placed as an item: taken out both ways
    a.db.write_with(|w| w.place(x, t)).unwrap();
    a.remove_tag(x, t).unwrap();
    assert!(!a.under(t, x).unwrap());
    assert_eq!(a.revocations_after_removal(x).unwrap(), BTreeSet::from([(x, t)]));
    // a cycle x -> z -> x hung under the tag by x: cut, everything only it held goes
    let z = a.create(NewKind::Tag).unwrap();
    a.add_tag(x, t).unwrap();
    a.add_tag(z, x).unwrap();
    a.add_tag(x, z).unwrap();
    let c = a.create(NewKind::Note).unwrap();
    a.add_tag(c, z).unwrap();
    sync(&a, &b);
    assert_eq!(b.db.role_on(c), Some(Role::Read));
    a.remove_tag(x, t).unwrap();
    assert_eq!(a.revocations_after_removal(x).unwrap(), BTreeSet::from([(x, t)]), "inside the cycle every edge is still held");
    for (p, m) in a.revocations_after_removal(x).unwrap() {
        a.queue_revoke(p, m).unwrap();
    }
    run_pending(&a);
    sync(&a, &b);
    assert_eq!(b.db.role_on(c), None);
    assert_eq!(b.db.role_on(z), None);
}

/// Alice's first device has taken the tag's access back; her other device, not yet aware of
/// that, re-tags and re-grants (the entry waits there). The first device then hears of the
/// placement but not yet of the grant (another thing's commit), and the user takes the thing out
/// again there: the edge is not live there, so nothing is queued. When the grant arrives
/// (later than the demotion, so it stands), Bob reaches a thing the user took out of the tag.
/// Any grant the remover has not seen while it sees the placement does this (a confirmed share
/// too): issues/app-revoke-unseen-grant.md.
#[test]
#[ignore = "issues/app-revoke-unseen-grant.md"]
fn removal_missing_a_later_grant() {
    use osis_kit::tasks::block_on;
    let (a, a2, b, clock) = alice_twice_and_bob_clock();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    a.queue_revoke(n, shared).unwrap();
    sync3(&a, &a2, &b);
    clock.advance(1000);
    block_on(a.revoke(n, shared, osis::WaitForSync::Skip)).unwrap();
    // a2's `add_tag` before it hears of the demotion, step by step
    clock.advance(1000);
    let before = held(&a2);
    a2.db.write_with(|w| w.place(n, shared)).unwrap();
    let placed = held(&a2);
    a2.db.grant(n, shared, Role::Write, EdgeOpts::default()).unwrap();
    let grant: std::collections::BTreeSet<_> = held(&a2).difference(&placed).copied().collect();
    a2.drop_revoke(n, shared).unwrap();
    deliver_since(&a2, &a, &before, &grant);
    clock.advance(1000);
    assert_eq!(a.tags_of(n).unwrap(), vec![shared]);
    a.remove_tag(n, shared).unwrap();
    for (x, m) in a.revocations_after_removal(n).unwrap() {
        a.queue_revoke(x, m).unwrap();
    }
    run_pending(&a);
    sync3(&a, &a2, &b);
    run_pending(&a);
    run_pending(&a2);
    sync3(&a, &a2, &b);
    assert!(a.tags_of(n).unwrap().is_empty());
    assert_eq!(b.db.role_on(n), None, "out of the tag, but the unseen grant shares it");
}

/// Once the tag's access to a thing was taken back, granting it again fails ("another node
/// must rotate first": Alice's every node acts through her own tag, so no rotation of hers
/// covers the tag's departure): a re-tag leaves the thing tagged, unshared, with an error.
/// issues/tag-regrant-after-revoke.md.
#[test]
#[ignore = "issues/tag-regrant-after-revoke.md"]
fn retag_after_a_revocation_shares_again() {
    use osis_kit::tasks::block_on;
    let (a, b) = two_people();
    let shared = shared_tag(&a, &b, Role::Read);
    let n = a.create(NewKind::Note).unwrap();
    a.add_tag(n, shared).unwrap();
    a.remove_tag(n, shared).unwrap();
    block_on(a.revoke(n, shared, osis::WaitForSync::Skip)).unwrap();
    a.add_tag(n, shared).unwrap();
    sync(&a, &b);
    assert_eq!(b.db.role_on(n), Some(Role::Read));
}
