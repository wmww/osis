//! Holding across nodes (spec/sync-set.md §1-§4, notes/refgraph-tests.md R4, H3, L5, L9, T2,
//! T4, T6, T7): what a strong, a ticket and a role each do once sync carries them. Each on a
//! fixture copy; the closure's own rules are engine `closure::`, the whole by the differential.

use crate::harness::{World, contacts, siblings};
use osis_base::{Ak, Role, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

fn ak() -> Ak {
    Ak::new("x:v.0").unwrap()
}

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, floor: None }
}

/// A thing node `i` makes under `admin` (its account root when `None`), held there, value `v`.
fn make(w: &mut World, i: usize, admin: Option<Tid>, v: &str) -> Tid {
    let v = v.to_owned();
    w.write(i, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin.unwrap_or(d)));
        m.set(t, &ak(), &Value::Str(v)).unwrap();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

/// Node `i` adds (`on`) or removes a strong from `from` (its account root when `None`) to `t`;
/// the write's NotCarried strongs.
fn strong(w: &mut World, i: usize, from: Option<Tid>, t: Tid, on: bool) {
    w.write(i, |e| {
        let from = from.unwrap_or_else(|| e.account_root().unwrap());
        let mut m = Mutation::new();
        let v = Value::Strong(t);
        m.op(from, &ct::HOLDS, PathOp { path: vec![], op: if on { Op::Add(v) } else { Op::Remove(v) } }).unwrap();
        e.commit(m).unwrap();
    });
}

fn value(w: &mut World, i: usize, t: &Tid) -> Option<Value> {
    w.engine(i).get(t, &ak()).unwrap()
}

/// How node `i`'s sync set holds `t`, by any sync ID.
fn holding(w: &mut World, i: usize, t: &Tid) -> Option<Holding> {
    let set = w.engine(i).sync_set().unwrap();
    let h: Vec<Holding> = set.ids.values().filter(|(ts, _)| ts.contains(t)).map(|(_, h)| *h).collect();
    h.iter().copied().max_by_key(|h| matches!(h, Holding::Read))
}

/// D's tickets for `t` at node `i`.
fn d_tickets(w: &mut World, i: usize, t: &Tid) -> usize {
    let d = w.engine(i).account_root().unwrap();
    w.engine(i).get_typed(&d, &ct::TICKETS).unwrap().unwrap_or_default().iter().filter(|k| k.target == *t).count()
}

// spec/sync-set.md §2, spec/permissions.md §3: refgraph R4. A strong grants nothing; removing a
// reference revokes nothing. Bob writes a strong to Alice's T he has no role on: nothing of
// T reaches him, the strong is NotCarried. Alice grants Bob read, Bob accepts, then Alice drops
// her own strong: Bob's roster entry and his reads stay.
#[test]
fn a_strong_grants_nothing_and_its_removal_revokes_nothing_spec_sync_set_2() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let d1 = w.engine(1).account_root().unwrap();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), None, "a strong alone fetches nothing");
    assert_eq!(holding(&mut w, 1, &t), None);
    assert!(w.engine(1).not_carried().unwrap().contains(&(d1, t)), "the strong is NotCarried");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())), "granted, his strong reads");
    strong(&mut w, 0, None, t, false);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).roster(&t).get(&bob).map(|e| e.role), Some(Role::Read), "Bob's roster entry stays");
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("after".into())), "Bob still reads");
}

// spec/sync-set.md §3: refgraph H3. A strong to a thing no node holds reads as not held. A
// strong to a tid no node ever made, and one to a thing whose only holder released it, hold
// nothing and read absent, with no marker: the referrer's own sync set and store are as before.
#[test]
fn a_strong_to_a_thing_never_fetched_holds_nothing_spec_sync_set_3() {
    let mut w = contacts();
    let before = w.engine(1).sync_set().unwrap().ids.clone();
    let never = Tid::from_bytes([0x5a; 15]);
    let gone = make(&mut w, 0, None, "gone");
    strong(&mut w, 0, None, gone, false);
    w.run();
    for t in [never, gone] {
        strong(&mut w, 1, None, t, true);
    }
    w.run();
    for t in [never, gone] {
        assert_eq!(value(&mut w, 1, &t), None);
        assert!(!w.engine(1).closure_holds(&t) && !w.engine(1).in_sync_things(&t).unwrap());
    }
    assert!(!w.engine(0).closure_holds(&gone) && value(&mut w, 0, &gone).is_none(), "released at its maker");
    assert_eq!(w.engine(1).sync_set().unwrap().ids, before, "nothing synced for either");
}

// spec/sync-inbox.md §5 (Nothing before the strong), spec/sync-set.md §4 (Accepting) (refgraph
// T2): a grant's ticket reaches Bob; until he accepts, nothing of T is fetched or synced (his
// sync set and store hold nothing of it); declining is never accepting; accepting is the strong.
#[test]
fn nothing_is_fetched_before_the_strong_spec_sync_inbox_5() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    let k = w.engine(1).ticket_for(&t).unwrap().expect("the ticket reached Bob");
    w.advance(10 * osis_sync::types::RESYNC_MS);
    assert!(!w.engine(1).sync_set().unwrap().ids.contains_key(&k.sync_id), "not synced before the strong");
    assert!(w.store(1).entries(&k.sync_id).unwrap().is_empty(), "nothing stored");
    assert!(value(&mut w, 1, &t).is_none() && !w.engine(1).closure_holds(&t));
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())), "accepted: read");
}

// spec/sync-set.md §1 (The account's tickets) (refgraph T4): node 1 accepts a grant; D gets a
// ticket for it, so its sibling and a node paired later hold it without the inbox; node 1
// releasing it removes D's ticket, and every node of the account lets it go.
#[test]
fn the_accounts_tickets_follow_what_it_accepts_spec_sync_set_1() {
    let mut w = siblings();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(d_tickets(&mut w, 1, &t), 1, "D's ticket written");
    let n = w.pair(1);
    w.run();
    for i in [2, n] {
        assert_eq!(value(&mut w, i, &t), Some(Value::Str("hi".into())), "node {i} of the account holds it");
    }
    strong(&mut w, 1, None, t, false);
    w.run();
    for i in [1, 2, n] {
        assert_eq!(d_tickets(&mut w, i, &t), 0, "node {i}: D's ticket removed with the release");
        assert!(!w.engine(i).closure_holds(&t), "node {i} released it");
    }
}

/// Alice gives Bob read on T; before Bob accepts she lowers him to sync (`lowered`) or removes
/// him; Bob accepts; run.
fn accepted_after_a_change(lowered: bool) -> (World, Tid) {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    let new = lowered.then(|| edge(Role::Sync));
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new, retain: None })).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    (w, t)
}

// spec/sync-set.md §2: refgraph T7. A ticket enters at the lower of its own role and the
// holder's; a read ticket whose holder holds sync alone on T enters T kept unread, one whose
// holder holds no role enters nothing. Alice grants Bob read and, before he accepts, lowers him to sync
// or removes him. His accept syncs T read on the ticket's word for good, reading nothing
// (issues/reference-graph.md Status).
#[test]
#[ignore = "issues/reference-graph.md"]
fn repro_a_ticket_enters_at_the_lower_of_its_role_and_the_holders_spec_sync_set_2() {
    for lowered in [true, false] {
        let (mut w, t) = accepted_after_a_change(lowered);
        assert_eq!(value(&mut w, 1, &t), None, "lowered {lowered}");
        assert_eq!(holding(&mut w, 1, &t), lowered.then_some(Holding::Unread), "lowered {lowered}: kept unread, or nothing");
    }
}

// spec/sync-set.md §1, §2: refgraph T6, its rotation arm. A key change keeps sync-only holders.
// Bob keeps T unread by a sync ticket; Alice rotates T's keys
// and writes: Bob still keeps it unread and his store takes the write.
#[test]
fn a_key_change_keeps_a_sync_only_holder_spec_sync_set_2() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Sync))).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    let s = w.engine(1).ticket_for(&t).unwrap().expect("the ticket").sync_id;
    let before = w.store(1).entries(&s).unwrap().len();
    w.write(0, |e| e.give_own_secrets_again(&t)).unwrap();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "still kept unread");
    assert!(w.store(1).entries(&s).unwrap().len() > before, "the store takes what came after");
}

// spec/sync-set.md §3: refgraph L5. A thing goes when its last reference goes, waiting for no
// absent peer. Alice's T, read by Bob through his strong: Alice dropping hers leaves T held by
// Bob's; once Bob drops his too, T is gone at both.
#[test]
fn the_last_reference_gone_the_thing_is_gone_for_everyone_spec_sync_set_3() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())));
    strong(&mut w, 0, None, t, false);
    w.run();
    assert_eq!(value(&mut w, 0, &t), None, "Alice let it go");
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())), "Bob's strong still holds it");
    strong(&mut w, 1, None, t, false);
    w.run();
    for i in [0, 1] {
        assert!(!w.engine(i).closure_holds(&t) && value(&mut w, i, &t).is_none(), "node {i}: gone");
    }
}

// spec/permissions.md §3 (Left out: a node that may rotate, holding the epoch's secret and the
// grant, re-seals the holder), spec/sync-set.md §2: two nodes of Alice's account grant Bob read
// on T at once, each its first grant, so each gives T own keys of its own; Bob accepts. Once all
// is delivered he reads T. He reads nothing, his roster full (issues/reference-graph.md Status).
#[test]
#[ignore = "issues/reference-graph.md"]
fn repro_concurrent_first_grants_by_two_nodes_reach_the_grantee_spec_permissions_3() {
    let mut w = siblings();
    let t = make(&mut w, 1, None, "hi");
    w.run();
    let alice = w.node(0).account.unwrap();
    for i in [1, 2] {
        w.write(i, |e| e.grant(&t, &alice, &edge(Role::Read))).unwrap();
    }
    strong(&mut w, 0, None, t, true);
    w.run();
    assert_eq!(w.engine(0).roster(&t).get(&alice).map(|e| e.role), Some(Role::Read));
    assert_eq!(value(&mut w, 0, &t), Some(Value::Str("hi".into())), "Alice reads T");
}

// spec/sync-set.md §3 (lowering from read to sync is no release: S becomes kept unread with its
// store) (refgraph L9 across nodes): Bob reads T; Alice lowers him to sync: he reads nothing and
// keeps T unread.
#[test]
fn a_reader_lowered_to_sync_keeps_the_thing_unread_spec_sync_set_3() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())));
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t), None, "lowered: reads nothing");
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "kept unread");
}
