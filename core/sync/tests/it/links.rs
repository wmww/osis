//! A link's first contact over real connections (spec/sync-inbox.md §6, spec/permissions.md §7):
//! the redeemer dials the sharer node by the link's hints, opens K by the link key's static entry,
//! takes the head's entry box, pulls K and joins.

use crate::harness::{World, two_nodes};
use osis_base::Role;
use osis_label::ShareLink;
use osis_sync::types::Waiting;

/// Node 0 makes a read link to its profile; node 1 redeems it; run to quiet.
fn redeemed() -> (World, ShareLink) {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    assert_eq!(w.redeem(1, &link), Waiting::Pending);
    w.run();
    (w, link)
}

// spec/sync-inbox.md §6 (First contact), spec/sync-set.md §2 (Sync set: a link's sync ID while
// its redeemer redeems it), spec/sync-opens.md §5 (Opening: a static entry's answer carries the
// head's entry box and the path): K, listed in the sharer's D, opens at node 1 by L's static entry, and node 1
// takes K's read secret from the head's entry box.
#[test]
fn a_link_opens_k_by_its_static_entry_spec_sync_inbox_6() {
    let (mut w, link) = redeemed();
    let s = link.k_label;
    assert!(matches!(w.engine(0).sync_holding(&s).unwrap(), Some((_, osis_engine::sync::Holding::Read))), "the sharer syncs K");
    assert!(matches!(w.engine(1).sync_holding(&s).unwrap(), Some((t, osis_engine::sync::Holding::Read)) if t == link.k), "the redeemer follows K's sync ID");
    assert!(w.status(1).get(&s).is_some_and(|st| !st.sources.is_empty()), "K open at the sharer");
    assert!(!w.engine(1).read_credentials(&s).unwrap().unwrap().read_secrets.is_empty(), "K's read secret from the entry box");
}

// spec/permissions.md §7 (Redeem), §4 (Chain certificates; Logging certificates):
// node 1, holding nothing of node 0's account, joins K from the link alone: K's commits apply
// there by the certificates and records K's sync ID carries; the join is held at node 0, and node
// 1 reads K's roster and the content node 0 writes after.
#[test]
fn a_redeemer_joins_k_spec_permissions_7() {
    let (mut w, link) = redeemed();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    assert!(w.engine(1).roster(&link.k).contains_key(&a1), "node 1's account joined K here");
    assert!(w.engine(0).roster(&link.k).contains_key(&a1), "the join held at the sharer");
    assert_eq!(w.engine(1).roster(&link.k).get(&a0).map(|e| e.role), Some(Role::Admin), "K's roster as the sharer's");
    assert_eq!(w.redeem(1, &link), Waiting::Done);
    // node 1's user files the profile (spec/sync-set.md §4): it syncs K as any thing of its D
    let p0 = w.node(0).profile.unwrap();
    w.write(1, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let mut g = e.get_typed(&d, &osis_schema::core_types::GROUP).unwrap().unwrap_or_default();
        g.items.insert(p0);
        let mut m = osis_engine::Mutation::new();
        m.set(d, &osis_schema::core_types::GROUP, &g).unwrap();
        e.commit(m).unwrap().unwrap();
    });
    w.run();
    w.write(0, |e| {
        let mut m = osis_engine::Mutation::new();
        m.set(p0, &osis_base::Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(7)).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).get(&p0, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap(), Some(osis_base::Value::Int(7)), "K's content read");
}

/// Node 0's read link to its profile, followed at node 1 (not run): node 1 knows K only from the
/// link text.
fn followed() -> (World, ShareLink) {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    w.write(1, |e| e.follow_link(&link)).unwrap();
    (w, link)
}

fn learned_nothing(w: &mut World, s: &osis_base::SyncId) -> bool {
    w.engine(1).read_credentials(s).unwrap().unwrap().read_secrets.is_empty()
}

// spec/sync-opens.md §5 (Opening: for a static entry the tester takes the box's secrets only when
// the path verifies from its genesis step, the box's sync secret derives the head's sync key and
// `sig` verifies under it): a box sealed to L with secrets of the forger's choosing, on K's real
// path, opens nothing; nor does the real box on a path of another sync ID; the real one opens the
// head's sync key and learns nothing until `learn_grant`.
#[test]
fn a_static_grant_is_verified_before_it_is_learned_spec_sync_opens_5() {
    use osis_crypto::{BoxSlot, EntryItem, Epoch, KeyActorKeys, Secret32, SeededRng};
    let (mut w, link) = followed();
    let s = link.k_label;
    let path = w.engine(0).sync_ids(&link.k).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.clone();
    let steps: Vec<osis_label::Step> = path.iter().map(|(st, _)| st.clone()).collect();
    let head = steps.last().unwrap().clone();
    let lkeys = KeyActorKeys::from_seed(&link.seed);
    let entry = osis_crypto::static_entry(&s, &lkeys.signing.verifying_key());
    let real = path.last().unwrap().1.as_ref().unwrap().entries.get(&entry).unwrap().clone();
    let (x, y) = (Secret32::from_bytes([9; 32]), Secret32::from_bytes([8; 32]));
    let item = EntryItem { epoch: Epoch::derive(&link.k, Role::Read, 1, &x).unwrap(), secret: x, earlier: None, sync: (Epoch::derive(&link.k, Role::Sync, 1, &y).unwrap(), y) };
    let slot = BoxSlot::Entry { label: s, step_key: head.step_key, group: link.k };
    let sealed = osis_crypto::seal_entry(lkeys.kem.public(), &slot, &item, &mut SeededRng::from_u64(1)).unwrap();
    let osis_schema::core_types::SecretBox::Sealed(mut sb) = real.clone() else { panic!("a sealed entry box") };
    sb.sealed = osis_schema::core_types::Sealed::X25519MlKem768(sealed);
    let forged = osis_schema::core_types::SecretBox::Sealed(sb);
    assert!(w.engine(1).open_grant(&s, &entry, &steps, &forged).unwrap().is_none(), "a forged box opens nothing");
    let p0 = w.node(0).profile.unwrap();
    let other: Vec<osis_label::Step> = w.engine(0).sync_ids(&p0).unwrap()[0].path.steps.iter().map(|(st, _)| st.clone()).collect();
    assert!(w.engine(1).open_grant(&s, &entry, &other, &real).unwrap().is_none(), "a path of another sync ID opens nothing");
    assert!(learned_nothing(&mut w, &s));
    let g = w.engine(1).open_grant(&s, &entry, &steps, &real).unwrap().expect("the real grant opens");
    assert_eq!(g.key, head.keys.sync.to_bytes());
    assert!(learned_nothing(&mut w, &s), "opened, not learned before the signature verifies");
    w.write(1, |e| e.learn_grant(&g)).unwrap();
    assert!(!learned_nothing(&mut w, &s), "learned once the caller takes it");
}

// spec/sync-set.md §2 (Sync set: a link's sync ID while its redeemer redeems it): the link text is untrusted. A link
// naming a thing node 1 syncs as K, or naming that thing's sync ID as K's, changes nothing of how
// node 1 syncs it.
#[test]
fn a_link_text_never_moves_another_things_sync_id_spec_sync_set_2() {
    let mut w = two_nodes();
    let real = w.make_link(0, w.node(0).profile.unwrap(), Role::Read);
    let set = w.engine(1).sync_set().unwrap();
    let (&own, &(t, _)) = set.ids.iter().next().expect("node 1 syncs something");
    let thing_before = w.engine(1).thing_sync(&t).unwrap();
    // K = that thing, under the real link's sync ID
    let as_k = ShareLink { k: t, ..real.clone() };
    w.write(1, |e| e.follow_link(&as_k)).unwrap();
    assert_eq!(w.engine(1).thing_sync(&t).unwrap(), thing_before, "a held thing named as K syncs as before");
    assert_eq!(w.engine(1).sync_holding(&real.k_label).unwrap(), None, "the link's sync ID is nobody's here");
    w.write(1, |e| e.unfollow_link(&t));
    // K's sync ID = that thing's
    let stolen = ShareLink { k_label: own, ..real };
    w.write(1, |e| e.follow_link(&stolen)).unwrap();
    assert_eq!(*w.engine(1).sync_set().unwrap(), *set, "the sync set is as before");
    assert_eq!(w.engine(1).thing_sync(&stolen.k).unwrap(), osis_engine::sync::ThingSync::Plain, "K has no sync ID of its own here");
}

// spec/permissions.md §7 (Redeem: the link has ended, and the redeemer stops there, when a held
// role history shows L's grant removed): a link finalized before it is redeemed answers `Never`
// and keeps nothing.
#[test]
fn an_ended_link_is_not_redeemed_spec_permissions_7() {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    let l = osis_engine::identity::key_actor_tid(&link.seed);
    w.write(0, |e| e.finalize_link(&link.k, &l)).unwrap();
    assert!(w.engine(0).link_ended(&link));
    assert!(matches!(w.redeem(0, &link), Waiting::Never(_)));
    assert!(w.engine(0).read_credentials(&link.k_label).unwrap().is_none_or(|c| c.acting.is_empty()), "L not acted for");
}

