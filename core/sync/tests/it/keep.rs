//! Keeping S unread end to end, in a world of product nodes: a grant of sync on a group kept
//! unread, a write logged there, pulled and held, then the removal noticed and the store
//! shredded, through the engine facade and the modules wherever they are built; and the inbox
//! module's deliveries in a node (re-sent only at expiry, not at a restart).

use crate::harness::history::introduce;
use crate::harness::{World, two_nodes};
use osis_base::{Ak, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_engine::sync::Holding;
use osis_label::Class;
use osis_proto::Code;
use osis_schema::core_types as ct;
use osis_sync::types::Entry;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// Node `i` adds `t` to its account's group D (its synced group's closure).
fn add_to_d(w: &mut World, i: usize, t: Tid) {
    w.write(i, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.insert(t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap().unwrap();
    });
}

/// The deposited inbox blobs node 0 logged under `inbox` (its deliveries), carried by hand into
/// node 1's store as the Deposit items they are (offers over a connection are the wiring not yet
/// driven here); then node 1 settles.
fn carry_deposits(w: &mut World, inbox: &SyncId) -> usize {
    let mut n = 0;
    for e in w.store(0).entries(inbox).unwrap().into_iter().filter(|e| e.deposited && e.own) {
        if w.store(1).entry(inbox, &e.blob).unwrap().is_some() {
            continue;
        }
        let bytes = w.store(0).bytes(&e.blob).unwrap().expect("its bytes");
        let mut st = w.store(1).clone();
        assert_eq!(st.log(inbox, Entry { own: false, ..e }, Some(bytes), None).unwrap(), Code::OK);
        n += 1;
    }
    w.write(1, |_| ());
    w.run();
    n
}

// spec/sync-judgement.md §6 (keeps, stops), spec/sync-inbox.md §2 (logging, taking), spec/sync-ids.md
// §6 (Register, a store keeping S unread takes stamped entries): node 0 grants node 1's account
// sync on a thing of its synced group; its inbox module logs the inbox blob deposited under node
// 1's inbox; carried to node 1, node 1's inbox module takes it as an invitation, the user accepts
// (a sync record, the thing kept unread once node 1 lists it); a step registered and a write stamped there are held; node 0
// removes node 1: the removal's notice, carried the same way, stops node 1, which shreds S and
// drops its record. Carried by hand (not yet driven over a connection): the Deposit items, the
// Register and the pulled entry (opens' and streams' rows between the two nodes).
#[test]
fn grant_kept_unread_held_then_removed_and_shredded_spec_sync_judgement_6() {
    let mut w = two_nodes();
    introduce(&mut w);
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &Ak::new("t:reg.0").unwrap(), &Value::Int(1)).unwrap();
        e.commit(m).unwrap();
        e.give_own_secrets(&t).unwrap();
        t
    });
    add_to_d(&mut w, 0, t);
    let s: SyncId = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Sync))).unwrap();
    w.run();
    let inbox = w.engine(0).inbox_of(&a1).expect("node 1's inbox");
    let logged = w.store(0).entries(&inbox).unwrap();
    assert!(logged.len() == 1 && logged[0].deposited && logged[0].own, "the grant's inbox blob deposited under node 1's inbox");
    assert_eq!(carry_deposits(&mut w, &inbox), 1);
    // taken by node 1's inbox module: an invitation (the sender is not connected), which the
    // user accepts (spec/sync-set.md §4)
    assert!(w.engine(1).invitations().unwrap().iter().any(|i| i.thing == t && !i.taken), "an invitation");
    let b = logged[0].blob;
    let o = w.write(1, |e| e.take_inbox(&inbox, &b, true)).unwrap().expect("opens");
    assert_eq!(o.taken, osis_engine::sync::Taken::Applied);
    w.run();
    let record = w.engine(1).sync_record(&t).unwrap().expect("a sync record");
    assert_eq!(record.sync_ids, vec![s]);
    add_to_d(&mut w, 1, t);
    w.run();
    assert_eq!(w.engine(1).sync_holding(&s).unwrap(), Some((t, Holding::Unread)), "kept unread");
    // the path registered (a reader's Register), then a write stamped for its head
    let path = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    let mut st1 = w.store(1).clone();
    for (step, claims) in &path.steps {
        assert_eq!(st1.take_register(&s, step, claims.as_ref()).unwrap(), Code::OK);
    }
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("t:reg.0").unwrap(), &Value::Int(2)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    let (sealed, wrap) = w.engine(0).seal_body(&s, &c, &mut osis_crypto::SeededRng::from_u64(1)).unwrap().expect("an own write seals");
    let stamp = w.engine(0).signers(&s, None).unwrap().stamp.expect("node 0 writes S");
    let e = Entry { blob: sealed.id, wrap, stamp: Some(osis_label::sign_stamp(&stamp, &s, &sealed.id, &wrap, false)), deposited: false, own: false, role: false, class: Class::Durable, expires: None };
    assert_eq!(st1.take_stamped(&s, &e, sealed.blob.clone()).unwrap(), Code::OK);
    w.write(1, |_| ());
    w.run();
    assert!(w.store(1).entry(&s, &sealed.id).unwrap().is_some(), "held at the node keeping S unread");
    assert_eq!(w.engine(1).sync_holding(&s).unwrap(), Some((t, Holding::Unread)), "still kept: nothing opens there");
    // removed: the notice reaches node 1 and stops it
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(carry_deposits(&mut w, &inbox), 1, "the removal's inbox blob");
    assert_eq!(w.engine(1).removal_notices(&s).unwrap().len(), 1);
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "S shredded");
    assert!(w.store(1).path(&s).unwrap().is_none(), "its path too");
    assert!(w.engine(1).sync_record(&t).unwrap().is_none(), "the record dropped");
    assert_eq!(w.engine(1).sync_holding(&s).unwrap(), None);
}

/// The own entries node `i` logged under `inbox`.
fn own_logged(w: &World, i: usize, inbox: &SyncId) -> Vec<osis_base::BlobId> {
    w.store(i).entries(inbox).unwrap().into_iter().filter(|e| e.own).map(|e| e.blob).collect()
}

// spec/sync-inbox.md §2 Re-send (an inbox blob goes again at its prefix expiry until the sender
// sees it taken; nothing else seals it again): node 0's grant to node 1, never taken, is logged
// once; past the blob's expiry it is sealed again as a new blob; a restart seals nothing again
// (the blob sent is durable).
#[test]
fn a_delivery_goes_again_only_at_its_expiry_spec_sync_inbox_2() {
    let mut w = two_nodes();
    introduce(&mut w);
    let a1 = w.node(1).account.unwrap();
    let a0 = w.node(0).account.unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        e.commit(m).unwrap();
        e.give_own_secrets(&t).unwrap();
        t
    });
    add_to_d(&mut w, 0, t);
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Sync))).unwrap();
    w.run();
    let inbox = w.engine(0).inbox_of(&a1).expect("node 1's inbox");
    let first = own_logged(&w, 0, &inbox);
    assert_eq!(first.len(), 1, "logged once");
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 3 * osis_base::format::MAX_DRIFT_MS);
    w.run();
    let again = own_logged(&w, 0, &inbox);
    assert!(again.len() == 1 && again != first, "sealed again past its expiry: {again:?}");
    w.power_off(0);
    w.power_on(0);
    w.run();
    assert_eq!(own_logged(&w, 0, &inbox), again, "a restart seals nothing again");
}
