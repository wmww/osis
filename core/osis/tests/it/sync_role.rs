//! Role `sync` (spec/permissions.md §1-§3, spec/sync-ids.md §2): below read, it gives the sync secret
//! and with it the label sync key, and nothing to read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::CreateIn;
use crate::common::{self, *};
use osis::internals::Internals as _;
use osis::{GrantOpts, Osis, Role, SetRoleOpts, Tid, Value};
use osis_crypto::{LabelRole, Secret32, VerifyingKey, label_role_key};
use osis_sim::world::World;
use std::collections::BTreeSet;

fn item(db: &Osis, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str(v.into())).unwrap();
    w.commit().unwrap();
    t
}

fn group(db: &Osis) -> Tid {
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.home()]).unwrap();
    w.commit().unwrap();
    db.sync(g, &[]).unwrap();
    g
}

/// Alice and Bob on one peer, Bob granted `role` on Alice's synced group holding one item:
/// built once per role (`World::cached`).
fn shared(role: Role) -> (World, Osis, Osis, Tid, Tid) {
    let (w, [alice, bob], (g, t)) = World::cached(&format!("sync_role::shared/{role:?}"), || {
        let (mut w, alice, mut others, ids) = common::people(1);
        let bob = others.remove(0);
        let g = group(&alice);
        let t = item(&alice, g, "for readers");
        alice.grant(g, ids[0], role, GrantOpts::default()).unwrap();
        w.run();
        (w, [alice, bob], (g, t))
    });
    (w, alice, bob, g, t)
}

/// The held secrets of role `r` of `g` at `db`, newest first, reading-only ones included.
fn secrets(db: &Osis, g: Tid, r: Role) -> Vec<Secret32> {
    db.engine(|e| e.epochs(&g).map(|x| x.role(r).held_newest_first().into_iter().map(|(_, s)| s.clone()).collect()).unwrap_or_default())
}

/// The newest epoch of role `r` of `g` at `db`.
fn newest(db: &Osis, g: Tid, r: Role) -> osis_crypto::Epoch {
    db.engine(|e| e.epochs(&g).and_then(|x| x.role(r).newest())).unwrap()
}

/// The sync keys of every step of `g`'s labels at `db` (its `label.0`).
fn step_sync_keys(db: &Osis, g: Tid) -> Vec<VerifyingKey> {
    db.engine(|e| e.group_labels(&g).unwrap().into_iter().flat_map(|l| l.steps.into_values().map(|(s, _)| s.keys.sync)).collect())
}

/// The label sync keys `secrets` derive.
fn derived(secrets: &[Secret32]) -> BTreeSet<[u8; 32]> {
    secrets.iter().map(|s| label_role_key(LabelRole::Sync, s).verifying_key().to_bytes()).collect()
}

/// The sync keys of the steps Alice's newest sync epoch registers.
fn newest_step_keys(alice: &Osis, g: Tid) -> BTreeSet<[u8; 32]> {
    let s = secrets(alice, g, Role::Sync);
    let mine = derived(&s[..1]);
    step_sync_keys(alice, g).into_iter().map(|k| k.to_bytes()).filter(|k| mine.contains(k)).collect()
}

// spec/permissions.md §1, spec/sync-ids.md §2-§3: a sync grant reaches Bob by his inbox with his box of
// the sync secret; he derives the label's current sync key from it, and holds no read, write or
// admin secret: no section of the group opens, so he reads nothing of it.
#[test]
fn a_sync_only_holder_derives_the_sync_key_and_opens_no_section_spec_permissions_1() {
    let (_w, alice, bob, g, t) = shared(Role::Sync);
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Sync));
    let held = secrets(&bob, g, Role::Sync);
    assert!(!held.is_empty(), "Bob holds the sync secret");
    for r in [Role::Read, Role::Write, Role::Admin] {
        assert!(secrets(&bob, g, r).is_empty(), "Bob holds no {r:?} secret");
    }
    let keys = newest_step_keys(&alice, g);
    assert!(!keys.is_empty(), "a step registers Alice's newest sync epoch");
    assert!(keys.is_subset(&derived(&held)), "Bob derives the head's sync key");
    assert_eq!(bob.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), None, "no section opens");
}

// spec/permissions.md §3: removing a holder of sync rotates sync alone: the head's sync key moves
// (Bob's secrets derive none of the new step's), the read epoch stays.
#[test]
fn removing_a_sync_holder_moves_the_sync_key_and_not_the_read_epoch_spec_permissions_3() {
    let (mut w, alice, bob, g, _) = shared(Role::Sync);
    let (sync0, read0) = (newest(&alice, g, Role::Sync), newest(&alice, g, Role::Read));
    let held = secrets(&bob, g, Role::Sync);
    alice.set_role(g, bob.me(), None, SetRoleOpts::default()).unwrap();
    item(&alice, g, "after");
    w.run();
    assert_ne!(newest(&alice, g, Role::Sync), sync0, "sync rotated");
    assert_eq!(newest(&alice, g, Role::Read), read0, "read kept its epoch");
    let keys = newest_step_keys(&alice, g);
    assert!(!keys.is_empty(), "a step registers the new sync epoch");
    assert!(keys.is_disjoint(&derived(&held)), "Bob's secrets derive no new sync key");
}

// spec/permissions.md §3: a reader's removal leaves sync too, so both rotate.
#[test]
fn removing_a_reader_moves_the_sync_key_spec_permissions_3() {
    let (mut w, alice, bob, g, _) = shared(Role::Read);
    assert!(!secrets(&bob, g, Role::Sync).is_empty(), "a reader holds the sync secret");
    let (sync0, read0) = (newest(&alice, g, Role::Sync), newest(&alice, g, Role::Read));
    alice.set_role(g, bob.me(), None, SetRoleOpts::default()).unwrap();
    item(&alice, g, "after");
    w.run();
    assert_ne!(newest(&alice, g, Role::Sync), sync0, "sync rotated");
    assert_ne!(newest(&alice, g, Role::Read), read0, "read rotated");
}

// spec/permissions.md §2: an invite grant within the author's effective invite: a reader whose
// grant carries `invite: sync` grants sync and nothing above it.
#[test]
fn a_reader_with_invite_sync_grants_sync_and_nothing_more_spec_permissions_2() {
    let (mut w, alice, mut others, ids) = common::people(2);
    let (bob, carol) = (others.remove(0), others.remove(0));
    let g = group(&alice);
    alice.grant(g, ids[0], Role::Read, GrantOpts { may_grant: Some(Role::Sync), ..GrantOpts::default() }).unwrap();
    let card = carol.contact_card().unwrap();
    w.run();
    w.until(bob.import_contact(&card), 1000, 10).unwrap();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Read));
    assert!(bob.grant(g, carol.me(), Role::Read, GrantOpts::default()).is_err(), "read is above Bob's invite");
    bob.grant(g, carol.me(), Role::Sync, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(alice.grants(g).unwrap()[&carol.me()].role, Role::Sync);
    assert_eq!(carol.role_on(g).unwrap(), Some(Role::Sync));
    assert!(secrets(&carol, g, Role::Read).is_empty(), "Carol reads nothing");
}

// spec/permissions.md §1: a node of P holds read or above on P's devices actor D; a sync grant
// on D to another account makes none of its nodes one of P's.
#[test]
fn a_sync_grant_on_d_makes_no_node_spec_permissions_1() {
    let (mut w, alice, bob, _, _) = shared(Role::Sync);
    let before: Vec<Tid> = alice.nodes().unwrap().into_iter().map(|n| n.node).collect();
    alice.grant(alice.home(), bob.me(), Role::Sync, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(alice.grants(alice.home()).unwrap()[&bob.me()].role, Role::Sync);
    let after: Vec<Tid> = alice.nodes().unwrap().into_iter().map(|n| n.node).collect();
    assert_eq!(after, before, "Alice's nodes are unchanged");
    assert!(!after.contains(&bob.node()) && !after.contains(&bob.me()));
    assert!(!alice.engine(|e| e.core.own_node(&bob.node())), "Bob's node is no node of Alice");
    assert_eq!(bob.me(), bob.engine(|e| e.account_tid()).unwrap(), "Bob's node acts as Bob alone");
}

// spec/permissions.md §3 (lost access): a reader demoted to sync drops its read secrets and what
// only they read, and keeps the sync secret.
#[test]
fn a_reader_demoted_to_sync_keeps_the_sync_secret_alone_spec_permissions_3() {
    let (mut w, alice, bob, g, t) = shared(Role::Read);
    w.run();
    let x = |db: &Osis| db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap();
    assert_eq!(x(&bob), Some(Value::Str("for readers".into())), "a reader reads");
    alice.set_role(g, bob.me(), Some(Role::Sync), SetRoleOpts::default()).unwrap();
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Sync));
    assert!(!secrets(&bob, g, Role::Sync).is_empty(), "the sync secret stays");
    assert!(secrets(&bob, g, Role::Read).is_empty(), "the read secrets go");
    assert_eq!(bob.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), None, "what only they read goes");
}

// spec/sync-inbox.md §2, spec/permissions.md §3: a holder of sync alone reads no rotation under the
// label (its commits open under read secrets), so a rotation boxing it reaches it by its inbox:
// Bob derives the new sync key after Carol's removal.
#[test]
fn a_rotation_reaches_a_sync_only_holder_by_its_inbox_spec_sync_3() {
    let (mut w, alice, others, ids) = common::people(2);
    let (bob, carol) = (&others[0], &others[1]);
    let g = group(&alice);
    for id in &ids {
        alice.grant(g, *id, Role::Sync, GrantOpts::default()).unwrap();
    }
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Sync));
    let sync0 = newest(&alice, g, Role::Sync);
    alice.set_role(g, carol.me(), None, SetRoleOpts::default()).unwrap();
    item(&alice, g, "after");
    w.run();
    assert_ne!(newest(&alice, g, Role::Sync), sync0, "sync rotated");
    let keys = newest_step_keys(&alice, g);
    assert!(!keys.is_empty() && keys.is_subset(&derived(&secrets(bob, g, Role::Sync))), "Bob derives the new sync key");
    assert!(keys.is_disjoint(&derived(&secrets(carol, g, Role::Sync))), "Carol does not");
}

// spec/permissions.md §3, spec/sync-inbox.md §2, spec/wire.md §9: a removed holder learns its removal
// by the notice its inbox gets, judged by the author's chain. Bob, holding sync alone, read
// nothing under the group's label, so Carol's admin grant (after his) reaches him only as the
// chain the notice carries: he then holds no role on the group, drops its sync secret and syncs
// none of it, as a removed reader does. (Carol meets Bob's card under the label once Alice copies
// it, `SETTLE_MS` after receiving it; Bob, syncing no group of hers, admits the notice as an
// invite request, which the world accepts.)
#[test]
fn a_removed_sync_only_holder_learns_its_removal_spec_sync_3() {
    for role in [Role::Read, Role::Sync] {
        let (mut w, alice, others, ids) = common::people(2);
        let (bob, carol) = (&others[0], &others[1]);
        let g = group(&alice);
        alice.grant(g, ids[0], role, GrantOpts::default()).unwrap();
        w.run();
        alice.grant(g, ids[1], Role::Admin, GrantOpts::default()).unwrap();
        w.run();
        w.advance(60_000);
        w.run();
        assert_eq!(bob.role_on(g).unwrap(), Some(role));
        assert!(!secrets(bob, g, Role::Sync).is_empty(), "{role:?}: Bob holds the sync secret");
        carol.set_role(g, bob.me(), None, SetRoleOpts::default()).unwrap();
        w.run();
        assert_eq!(bob.role_on(g).unwrap(), None, "{role:?}: Bob holds no role");
        assert!(secrets(bob, g, Role::Sync).is_empty(), "{role:?}: Bob drops the sync secret");
        assert!(!bob.status().unwrap().groups.contains_key(&g), "{role:?}: Bob syncs none of it");
    }
}

// spec/permissions.md §7: a link's role is read or above (redeeming reads K's roster as L): one
// at sync is refused when made, writing nothing; a read link is made as before.
#[test]
fn a_link_at_sync_is_refused_spec_permissions_7() {
    let (_w, alice, _, _) = common::people(0);
    let g = group(&alice);
    let commits = alice.engine(|e| e.commit_ids().len());
    assert!(matches!(alice.make_link(g, Role::Sync, Default::default()), Err(osis::Error::Invalid(_))));
    assert_eq!(alice.engine(|e| e.commit_ids().len()), commits, "nothing written");
    assert!(alice.links().unwrap().is_empty());
    alice.make_link(g, Role::Read, Default::default()).unwrap();
}
