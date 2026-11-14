//! Keeping S unread end to end, in a world of product nodes: a grant of sync on a group kept
//! unread, a write logged there, pulled and held, then the removal's step registered and the copy
//! dropped, through the engine facade and the modules wherever they are built; and the inbox
//! module's deliveries in a node (re-sent only at expiry, not at a restart).

use crate::harness::history::hand_all;
use crate::harness::{World, contacts, two_nodes};
use osis_base::{Ak, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}

/// Node `i` adds `t` to its account's group D (its synced group's closure).
fn add_to_d(w: &mut World, i: usize, t: Tid) {
    w.write(i, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.insert(t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        // as the product writes (`Engine::write`): an accept keeps what it offers
        e.write(m).unwrap().unwrap();
    });
}

/// Node 0 grants its contact node 1's account sync on a thing of its synced group, which node
/// 1's user lists; a write is held there; node 0 removes node 1, logs the removal's rotation,
/// then issues its step (nothing by hand) and registers it at node 1. Each step through the product's dials and connections, checked on the way
/// (spec/sync-opens.md §1: node 0 dials node 1 by its dial list, node 1 dials node 0 by the
/// grant's hint).
fn kept_then_removed() -> (World, Tid, SyncId) {
    let (mut w, t, s) = kept();
    let a1 = w.node(1).account.unwrap();
    let before = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.len();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    w.run();
    let path = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    assert_eq!(path.steps.len(), before + 1, "the removal's step issued");
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), path.steps.last().map(|(st, _)| st.id()), "and registered at node 1");
    (w, t, s)
}

/// `kept_then_removed` up to the removal: a write held at node 1, which keeps S unread.
fn kept() -> (World, Tid, SyncId) {
    let mut w = contacts();
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
    // the grant's inbox blob reached node 1's inbox, held as an offer: an invitation, which node
    // 1's user accepts by listing the thing (spec/sync-set.md §4), keeping its sync ID
    let inv = w.engine(1).invitations().unwrap();
    assert!(inv.iter().any(|i| i.thing == t && !i.taken && i.role == Role::Sync), "an invitation: {inv:?}");
    assert!(w.engine(1).sync_record(&t).unwrap().is_none(), "nothing kept before the accept");
    add_to_d(&mut w, 1, t);
    assert_eq!(w.engine(1).sync_record(&t).unwrap().expect("kept").sync_ids, vec![s]);
    w.run();
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some((t, Holding::Unread)), "kept unread");
    // node 1's filter shows its grant's sync key once it accepts and its own test opens S: node 0
    // registers the genesis, then the rest of the recorded path (spec/sync-ids.md §6 Walk)
    let path = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), path.steps.last().map(|(st, _)| st.id()), "S's path registered at node 1");
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("t:reg.0").unwrap(), &Value::Int(2)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let blobs = w.engine(0).commit_blobs(&c).unwrap();
    assert!(blobs.iter().any(|b| w.store(1).entry(&s, b).ok().flatten().is_some()), "the write held at the node keeping S unread");
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some((t, Holding::Unread)), "still kept: nothing opens there");
    (w, t, s)
}

// spec/sync-judgement.md §3 (Own store; Deletes), §2 (required set: the certificate blobs are in
// it): the chain certificate a reader of S needs to judge node 0's writes there
// (its account's current `keys.0`, a part on a thing outside S's closure) is logged in node 0's
// own store, reaches node 1 keeping S unread, and node 0, which holds S's delete key, never
// deletes it there, an hour on.
#[test]
fn a_delete_key_holder_never_deletes_a_needed_certificate_at_an_unread_source_spec_sync_judgement_2() {
    let (mut w, _, s) = kept();
    let a0 = w.node(0).account.unwrap();
    let keys = w.engine(0).current_keys(&a0);
    assert!(!keys.is_empty());
    let held_at = |w: &mut World, i: usize| {
        let blobs: Vec<osis_base::BlobId> = keys.iter().flat_map(|c| w.engine(0).commit_blobs(c).unwrap().iter().copied().collect::<Vec<_>>()).collect();
        blobs.iter().any(|b| w.store(i).entry(&s, b).ok().flatten().is_some())
    };
    assert!(held_at(&mut w, 0), "logged in node 0's own store of S");
    assert!(held_at(&mut w, 1), "held at the node keeping S unread");
    w.advance(3_600_000);
    w.run();
    assert!(held_at(&mut w, 0) && held_at(&mut w, 1), "never deleted");
}

// spec/sync-judgement.md §6 (Keeps; Stops), spec/sync-inbox.md §2 (Logging), spec/sync-ids.md
// §6 (Steps: an admin issues the step due; Taking a stamped entry; Walk: moving it, genesis first), spec/sync-opens.md §1 (whom to
// dial), §4 (Admissible: with no head, its newest sync secret's key): `kept_then_removed`: the
// removal's step reaches node 1's head, whose sync key it holds no box for: its copy of S goes
// (its path and record stay), it shows nothing, and a write after the removal reaches it not.
#[test]
fn grant_kept_unread_held_then_removed_drops_its_copy_spec_sync_judgement_6() {
    let (mut w, t, s) = kept_then_removed();
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "its copy dropped");
    assert!(w.status(1)[&s].stranded, "at a head past its keys");
    assert!(w.store(1).head(&s).unwrap().is_some() && w.engine(1).sync_record(&t).unwrap().is_some(), "path and record stay");
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("t:reg.0").unwrap(), &Value::Int(3)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let blobs = w.engine(0).commit_blobs(&c).unwrap();
    assert!(!blobs.iter().any(|b| w.store(1).entry(&s, b).ok().flatten().is_some()), "nothing after the removal");
    assert!(w.store(1).entries(&s).unwrap().is_empty());
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
    hand_all(&mut w);
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

/// The work (`osis_base::costs`) and deliveries of one write by node 0 to a thing node 1's
/// account was granted read on and one by node 1 to its own account's group, each run to quiet,
/// after `n` writes by node 0.
fn one_write_after(n: usize) -> std::collections::BTreeMap<&'static str, u64> {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world};
    let mut w = world(0, 2);
    let mut steps = vec![New(0), Grant(0, 0, 1, Gives::Reads), Run];
    steps.extend((0..n).flat_map(|_| [Write(0, 0), Run]));
    for s in &steps {
        crate::harness::step(&mut w, s);
    }
    osis_base::costs::take();
    let d = w.deliveries;
    for s in [Write(0, 0), Run, New(1), Run] {
        crate::harness::step(&mut w, &s);
    }
    let mut c: std::collections::BTreeMap<_, _> = osis_base::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
    c.insert("deliveries", w.deliveries - d);
    c
}

// spec/sync-inbox.md §2 (Taking): an inbox blob is taken once: while its commit is held, a
// write moving what the take read (the reader's own account) takes nothing again, and an entry
// whose prefix no inbox blob has (the inbox's own commits) is tried with no key; so writes open
// nothing as an inbox blob, take only their own new entries, and cost the same after n and 10n
// writes.
#[test]
fn a_taken_inbox_blob_is_taken_once_spec_sync_inbox_2() {
    let (a, b) = (one_write_after(2), one_write_after(20));
    let n = |m: &std::collections::BTreeMap<&str, u64>, k: &str| m.get(k).copied().unwrap_or(0);
    assert_eq!((n(&a, "inbox: open tried"), n(&b, "inbox: open tried")), (0, 0), "{a:?}");
    assert!(n(&a, "inbox: take") <= n(&a, "inbox: entry fed"), "an entry taken again: {a:?}");
    for k in ["inbox: take", "inbox: held judged", "ingest", "tx", "deliveries"] {
        assert_eq!(n(&a, k), n(&b, k), "{k} per write grows with the writes before it");
    }
}

// spec/sync-inbox.md §2 (Taking): taking a taken inbox blob again writes nothing (its delete-key
// hints and sync ID hint kept as they are), so a judgement that takes it is at its fixpoint:
// nothing it read moved.
#[test]
fn taking_an_inbox_blob_again_moves_nothing_spec_sync_inbox_2() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world};
    use osis_engine::sync::Taken;
    let mut w = world(0, 2);
    for s in [New(0), Grant(0, 0, 1, Gives::Reads), Run] {
        crate::harness::step(&mut w, &s);
    }
    let account = w.node(1).account.expect("an account");
    let inbox = w.engine(1).inbox_of(&account).expect("its inbox");
    let blobs: Vec<_> = w.store(1).entries(&inbox).unwrap().into_iter().map(|e| e.blob).collect();
    let mut applied = 0;
    for b in blobs {
        let mut fx = osis_base::memo::Effects::new("test: take");
        fx.want(());
        let e = w.engine(1);
        let (_, now) = fx.settle(&(), || e.take_inbox(&inbox, &b, false).unwrap().map(|o| o.taken)).expect("wanted");
        applied += usize::from(now == Some(Taken::Applied));
        assert!(fx.due().is_empty(), "taking {b:?} again moved what it read");
    }
    assert!(applied > 0, "the grant's inbox blob was taken");
}

// spec/sync-ids.md §6 (Steps: an admin issues a step after logging the rotation commits it
// registers), spec/permissions.md §3: with node 1, the only node keeping S unread, powered off,
// node 0's removal of it records the step with no connection open; once node 1 is on, the step
// reaches its head.
#[test]
fn a_removal_issues_its_step_with_no_connection_spec_sync_ids_6() {
    let (mut w, t, s) = kept();
    let a1 = w.node(1).account.unwrap();
    let path = |w: &mut World| w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    let before = path(&mut w).steps.len();
    w.power_off(1);
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    w.run();
    let p = path(&mut w);
    assert_eq!(p.steps.len(), before + 1, "the removal's step, with node 1 off");
    w.power_on(1);
    w.run();
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), p.steps.last().map(|(st, _)| st.id()), "registered at node 1 once on");
}

// spec/sync-ids.md §6 (Steps; Walk: Test), spec/sync-judgement.md §6 (Keeps): after
// `kept_then_removed` node 0 grants node 1 sync again; node 1 holds only the new sync epoch's
// secret, which no recorded step bears. Node 0 tests the sync key of each sync secret it holds,
// so S opens at node 1, and registers the path to the removal's step (issued once its rotation
// was logged), so node 1 reaches the head under its new sync key.
#[test]
fn a_store_granted_again_after_its_removal_reaches_the_head_spec_sync_ids_6() {
    let (mut w, t, s) = kept_then_removed();
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Sync))).unwrap();
    w.run();
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some((t, Holding::Unread)), "kept unread again");
    let path = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), path.steps.last().map(|(st, _)| st.id()), "S's path registered at node 1");
    assert!(!w.status(1)[&s].stranded, "node 1 holds its head's sync secret");
}
