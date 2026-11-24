//! Holding across nodes (spec/sync-set.md §1-§4): what a strong and a role each do once sync carries them. Each on a
//! fixture copy; the closure's own rules are engine `closure::`, the whole by the differential.

use crate::harness::{World, contacts, edge, fixture_with, siblings};
use osis_base::{Ak, Role, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

fn ak() -> Ak {
    Ak::new("x:v.0").unwrap()
}

/// A thing node `i` mints with admin `admin` (its account root when `None`), held there, value `v`.
fn make(w: &mut World, i: usize, admin: Option<Tid>, v: &str) -> Tid {
    let v = v.to_owned();
    let d = w.node(i).account.unwrap();
    w.write(i, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin.unwrap_or(d), None));
        m.set(t, &ak(), &Value::Str(v)).unwrap();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

/// Node 0 makes T (`make`) and grants node 1's account (Bob) read on it; run. Built once per
/// process (`fixture_with`): the world, T and Bob.
fn granted() -> (World, (Tid, Tid)) {
    fixture_with("holding granted", || {
        let mut w = contacts();
        let t = make(&mut w, 0, None, "hi");
        let bob = w.node(1).account.unwrap();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
        w.run();
        (w, (t, bob))
    })
}

/// On `siblings`, Bob's node 1 makes T0 and grants Alice (node 0's account) read on it; Alice
/// holds T0; run. Built once per process (`fixture_with`): the world, Alice, Bob and T0.
fn alice_reads_t0() -> (World, (Tid, Tid, Tid)) {
    fixture_with("holding alice reads t0", || {
        let mut w = siblings();
        let (alice, bob) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
        let t0 = make(&mut w, 1, None, "t0");
        w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
        strong(&mut w, 0, None, t0, true);
        w.run();
        (w, (alice, bob, t0))
    })
}

/// On `contacts`, Bob (node 1) grants Alice read on T0, mints T1 with admin T0, grants T1 read on T0
/// (keyless: T1's key derives from T0's) and Alice read on T1; she holds both. Built once per
/// process (`fixture_with`): the world, Alice, T0 and T1.
fn keyless_way() -> (World, (Tid, Tid, Tid)) {
    fixture_with("holding keyless way", || {
        let mut w = contacts();
        let alice = w.node(0).account.unwrap();
        let t0 = make(&mut w, 1, None, "t0");
        w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
        let t1 = make_in(&mut w, 1, t0, "t1");
        w.write(1, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
        w.write(1, |e| e.grant(&t1, &alice, &edge(Role::Read))).unwrap();
        for t in [t0, t1] {
            strong(&mut w, 0, None, t, true);
        }
        w.run();
        (w, (alice, t0, t1))
    })
}

/// On `contacts`, Bob (node 1) makes T0 and T1, grants T1 read on T0 (with key access) and Alice read on
/// T1 only; she holds both. Built once per process (`fixture_with`): the world, Alice, T0 and T1.
fn keyed_way() -> (World, (Tid, Tid, Tid)) {
    fixture_with("holding keyed way", || {
        let mut w = contacts();
        let alice = w.node(0).account.unwrap();
        let t0 = make(&mut w, 1, None, "t0");
        let t1 = make(&mut w, 1, None, "t1");
        w.write(1, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
        w.write(1, |e| e.grant(&t1, &alice, &edge(Role::Read))).unwrap();
        for t in [t0, t1] {
            strong(&mut w, 0, None, t, true);
        }
        w.run();
        (w, (alice, t0, t1))
    })
}

/// Node `i` adds (`on`) or removes a strong from `from` (its account root when `None`) to `t`;
/// the write's NotCarried strongs.
fn strong(w: &mut World, i: usize, from: Option<Tid>, t: Tid, on: bool) {
    let from = from.unwrap_or_else(|| w.node(i).account.unwrap());
    w.write(i, |e| {
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

// spec/sync-set.md §2, spec/permissions.md §3: a strong grants nothing; removing a
// reference revokes nothing. Bob writes a strong to Alice's T he has no role on: nothing of
// T reaches him, the strong is NotCarried. Alice grants Bob read, Bob holds T, then Alice writes
// and drops her own strong: she lets T go, Bob's roster entry and his reads stay.
// spec/sync-set.md §3: a thing goes when its last reference goes, waiting for no absent peer:
// once Bob drops his strong too, T is gone at both.
#[test]
fn a_strong_grants_nothing_and_its_removal_revokes_nothing_spec_sync_set_2() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "hi");
    let d1 = w.node(1).account.unwrap();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), None, "a strong alone fetches nothing");
    assert_eq!(holding(&mut w, 1, &t), None);
    assert!(w.engine(1).not_carried().unwrap().contains(&(d1, t)), "the strong is NotCarried");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())), "granted, his strong reads");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    strong(&mut w, 0, None, t, false);
    w.run();
    assert_eq!(value(&mut w, 0, &t), None, "Alice let it go");
    assert_eq!(w.engine(1).roster(&t).get(&bob).map(|e| e.role), Some(Role::Read), "Bob's roster entry stays");
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("after".into())), "Bob still reads");
    strong(&mut w, 1, None, t, false);
    w.run();
    for i in [0, 1] {
        assert!(!w.engine(i).closure_holds(&t) && value(&mut w, i, &t).is_none(), "node {i}: gone");
    }
}

// spec/sync-set.md §3: a strong to a thing no node holds reads as not held. A
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

// spec/sync-set.md §4 (nothing else makes a node hold a thing it is granted a role on),
// spec/sync-inbox.md §5: a grant reaches Bob; until he holds T by a strong, nothing of T is fetched or synced
// (his sync set and store hold nothing of it).
#[test]
fn nothing_is_fetched_before_the_strong_spec_sync_inbox_5() {
    let (mut w, (t, _)) = granted();
    let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
    w.advance(10 * osis_sync::types::RESYNC_MS);
    assert!(!w.engine(1).sync_set().unwrap().ids.contains_key(&s), "not synced before the strong");
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "nothing stored");
    assert!(value(&mut w, 1, &t).is_none() && !w.engine(1).closure_holds(&t));
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())), "held: read");
}

// spec/sync-set.md §1: node 1 holds a granted thing by a strong in D, so its sibling and a node
// paired later hold it too; node 1 releasing it, every node of the account lets it go. Its
// sibling holds it again from the shared D: every node reads it again (release kept its edge piece while the grant's fire is held, forgetting the rest of
// it). spec/sync-inbox.md §4 (A sealed fire is promoted in place): Alice, who neither reads nor
// writes Bob's inbox, seals the grant fire; Bob's nodes, its writers, hold it stamped under the
// inbox's sync ID.
#[test]
#[ignore = "accounts: pairing"]
fn the_accounts_nodes_follow_what_it_holds_spec_sync_set_1() {
    let mut w = siblings();
    let t = make(&mut w, 0, None, "hi");
    let (alice, bob) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    let inbox = w.engine(1).inbox_thing(&bob).unwrap();
    let s = w.engine(1).sync_id_of(&inbox).unwrap().unwrap();
    for i in [1, 2] {
        let stamped = w.store(i).entries(&s).unwrap().into_iter().filter(|e| e.stamp.is_some() && !e.deposited);
        let fires: Vec<_> = stamped.filter(|e| w.engine(i).blob_commit(&e.blob).and_then(|c| w.engine(i).header(&c)).is_some_and(|h| h.signer == alice && h.aspects.iter().any(|a| a.tid == inbox && a.ak.as_str() == "grant@~0"))).collect();
        assert_eq!(fires.len(), 1, "node {i}: Alice's sealed fire stamped once");
        // in place: the sealed blob itself, its wrap filler no read secret of the inbox opens
        assert!(osis_blob::unwrap_any(w.engine(i).read_secrets(&inbox).iter(), &fires[0].blob, &fires[0].wrap).is_none(), "node {i}: promoted in place, not encrypted again");
    }
    strong(&mut w, 1, None, t, true);
    w.run();
    let n = w.pair(1);
    w.run();
    for i in [2, n] {
        assert_eq!(value(&mut w, i, &t), Some(Value::Str("hi".into())), "node {i} of the account holds it");
    }
    strong(&mut w, 1, None, t, false);
    w.run();
    for i in [1, 2, n] {
        assert!(!w.engine(i).closure_holds(&t), "node {i} released it");
    }
    strong(&mut w, 2, None, t, true);
    w.run();
    for i in [1, 2, n] {
        assert_eq!(value(&mut w, i, &t), Some(Value::Str("hi".into())), "node {i}: held again by its sibling, read");
    }
}

/// Alice gives Bob read on T; before Bob holds it she lowers him to sync (`lowered`) or removes
/// him; Bob holds it; run.
fn held_after_a_change(lowered: bool) -> (World, Tid) {
    let (mut w, (t, bob)) = granted();
    let new = lowered.then(|| edge(Role::Sync));
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new, retain: None })).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    (w, t)
}

// spec/sync-set.md §2: a strong enters a thing at the role the held role commits give. Alice
// grants Bob read and, before he holds it, lowers him to sync or removes him; his strong keeps T
// unread (lowered) or enters nothing (removed).
#[test]
fn a_strong_enters_at_the_role_the_role_commits_give_spec_sync_set_2() {
    for lowered in [true, false] {
        let (mut w, t) = held_after_a_change(lowered);
        assert_eq!(value(&mut w, 1, &t), None, "lowered {lowered}");
        assert_eq!(holding(&mut w, 1, &t), lowered.then_some(Holding::Unread), "lowered {lowered}: kept unread, or nothing");
    }
}

// spec/sync-set.md §1, §2: a key change keeps sync-only holders.
// Bob keeps T unread by a sync grant; Alice rotates T's keys
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
    let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
    let before = w.store(1).entries(&s).unwrap().len();
    w.write(0, |e| e.make_independent_again(&t)).unwrap();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "still kept unread");
    assert!(w.store(1).entries(&s).unwrap().len() > before, "the store takes what came after");
}

/// On `siblings`, Bob's node 1 makes T (`make`); run. Built once per process (`fixture_with`): the
/// world and T.
fn bobs_thing() -> (World, Tid) {
    fixture_with("holding bobs thing", || {
        let mut w = siblings();
        let t = make(&mut w, 1, None, "hi");
        w.run();
        (w, t)
    })
}

/// Two nodes of Bob's account (1 and 2, cut off from each other) key Bob's dependent T
/// (`bobs_thing`) at once: node `first` grants Alice read, the other grants her read too or, with
/// `rotate`, rotates T; each makes T independent with a sync ID of its own. Alice holds T with
/// only node `first` reachable, then all heal.
/// Whichever she took first, she ends on T's sync ID and reads T's newest value.
fn independent_at_once(first: usize, rotate: bool) {
    let (mut w, t) = bobs_thing();
    let alice = w.node(0).account.unwrap();
    w.partition(1, 2);
    w.partition(0, 3 - first);
    w.write(first, |e| e.grant(&t, &alice, &edge(Role::Read))).unwrap();
    match rotate {
        true => w.write(3 - first, |e| e.make_independent_again(&t)).unwrap(),
        false => w.write(3 - first, |e| e.grant(&t, &alice, &edge(Role::Read))).unwrap(),
    };
    w.flush();
    strong(&mut w, 0, None, t, true);
    w.flush();
    w.heal();
    w.run();
    w.write(3 - first, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    let s = w.engine(1).sync_id_of(&t).unwrap();
    assert_eq!(w.engine(1).sync_ids(&t).unwrap().len(), 2, "first {first}, rotate {rotate}: two sync IDs");
    for i in 0..3 {
        assert_eq!(w.engine(i).sync_id_of(&t).unwrap(), s, "first {first}, rotate {rotate}: node {i}'s sync ID of T");
    }
    assert_eq!(w.engine(0).roster(&t).get(&alice).map(|e| e.role), Some(Role::Read));
    assert_eq!(value(&mut w, 0, &t), Some(Value::Str("after".into())), "first {first}, rotate {rotate}: Alice reads T");
}

// spec/permissions.md §3, spec/sync-ids.md §2, spec/sync-inbox.md §5 (Grant from outside): two
// siblings make T's first grant to Alice at once, each giving T a sync ID of its own; she reads T
// whichever offer she took first.
#[test]
fn concurrent_first_grants_by_two_nodes_reach_the_grantee_spec_permissions_3() {
    for first in [1, 2] {
        independent_at_once(first, false);
    }
}

// spec/permissions.md §3, spec/sync-ids.md §2, spec/sync-inbox.md §5 (Grant from outside): one
// sibling grants Alice read on T while another makes T independent by a rotation; she reads T's
// newest value whichever sibling granted (so whether the sync ID her offer names is T's or not).
#[test]
fn a_grant_beside_a_siblings_rotation_reaches_the_grantee_spec_permissions_3() {
    for first in [1, 2] {
        independent_at_once(first, true);
    }
}


// spec/permissions.md §3 (Lost access: what was read goes), spec/crypto.md §4 (a reader tries each
// live entry of a history key): Bob reads T across Carol's removal from it (a rotation whose
// history box lists what the new epoch supersedes and who departed); Alice lowers him to sync.
// He keeps T's sync secrets, and what he holds of their history is what a fresh load of his
// store reads.
#[test]
fn a_reader_lowered_to_sync_keeps_its_sync_epochs_as_a_load_reads_them_spec_permissions_3() {
    let mut w = crate::harness::history::world_of(0, 3, 3);
    let t = make(&mut w, 0, None, "hi");
    let (bob, carol) = (w.node(1).account.unwrap(), w.node(2).account.unwrap());
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.write(0, |e| e.grant(&t, &carol, &edge(Role::Sync))).unwrap();
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: carol, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())));
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "kept unread");
    w.engine(1).check_index();
}

// spec/sync-set.md §1, §2 (local part): a node's local part. A node of an account makes a dependent
// thing minted with its node root as admin, held from there: the node writes it as itself, holds and reads it,
// and no sync ID carries it, so its sibling never holds it.
#[test]
fn a_thing_under_the_node_root_stays_on_its_node_spec_sync_set_2() {
    let mut w = siblings();
    let x = w.write(1, |e| {
        let root = e.node_root().unwrap();
        let mut m = Mutation::new();
        let x = m.create(e.thing_record(root, None));
        m.set(x, &ak(), &Value::Str("mine".into())).unwrap();
        m.op(root, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(x)) }).unwrap();
        e.commit(m).unwrap();
        x
    });
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(x, &ak(), &Value::Str("still mine".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(w.engine(1).closure_holds(&x), "held in the local part");
    assert_eq!(value(&mut w, 1, &x), Some(Value::Str("still mine".into())));
    assert!(w.engine(1).carrying(&x).unwrap().is_empty(), "under no sync ID");
    assert!(!w.engine(2).knows(&x), "the sibling never holds it");
}

/// Alice's dependent T0 and T1 (minted with admin T0 when `of_t0`, else with her account root), T0 -> T1; Bob
/// granted read on T1 and holding it; T1 granted read on T0, its first grant (T0 made independent).
fn shared_through_a_thing(of_t0: bool) -> (World, Tid, Tid) {
    let mut w = contacts();
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, of_t0.then_some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    w.write(0, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
    (w, t0, t1)
}

// spec/sync-set.md §2 (T's keys open), spec/sync-judgement.md §1 Per-sync-ID copies:
// T1 granted read on T0 (T0's first grant) and T1 -> T0: Bob, a reader of T1, reads T0 and what
// was written on it before it was independent. T0's role commits reach him under T1's sync ID as
// per-sync-ID copies, logged though a certificate copy of fewer parts was logged there first.
#[test]
fn a_reader_of_a_thing_reads_what_it_is_granted_spec_sync_set_2() {
    let (mut w, t0, t1) = shared_through_a_thing(false);
    strong(&mut w, 0, Some(t1), t0, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("v1".into())), "Bob reads T0");
    assert_eq!(holding(&mut w, 1, &t0), Some(Holding::Read));
}

// spec/crypto.md §4 Key access, spec/sync-set.md §2: T1 is minted with admin T0, so T1 granted read on
// T0 closes a cycle and is keyless: it reads nothing through it. Bob, a reader of T1, never reads
// T0, whether T1 references it or he holds it from his account root and is granted sync on it
// (then he keeps it unread by his sync grant).
#[test]
fn a_keyless_grant_reads_nothing_through_it_spec_crypto_4() {
    for direct in [false, true] {
        let (mut w, t0, t1) = shared_through_a_thing(true);
        match direct {
            false => strong(&mut w, 0, Some(t1), t0, true),
            true => {
                strong(&mut w, 1, None, t0, true);
                w.run();
                let bob = w.node(1).account.unwrap();
                w.write(0, |e| e.grant(&t0, &bob, &edge(Role::Sync))).unwrap();
            }
        }
        w.run();
        assert_eq!(value(&mut w, 1, &t0), None, "direct {direct}: Bob reads no T0");
        assert!(w.engine(1).read_secrets(&t0).is_empty(), "direct {direct}: nor holds its read secrets");
        assert_eq!(holding(&mut w, 1, &t0), direct.then_some(Holding::Unread), "direct {direct}");
    }
}

// spec/permissions.md §3 (Lost access), spec/sync-set.md §3 (Lowering from read to sync): Alice
// mints T1 with admin T0 and grants Bob write on T1 (T1 made independent); she then lowers T0's record edge
// on T1 to sync, her only path to a role on T1. She loses read access to T1: she reads none of
// it and keeps it unread by the sync secret T0's sync role gives; Bob still reads it.
#[test]
fn lowering_the_makers_only_path_to_sync_keeps_the_thing_unread_spec_permissions_3() {
    let mut w = contacts();
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, Some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Write))).unwrap();
    w.run();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("v2".into())));
    w.write(0, |e| e.leaving_adminless(|e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: Some(edge(Role::Sync)), retain: None }))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("v2".into())), "Bob still reads T1");
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost read on T1");
    assert_eq!(holding(&mut w, 0, &t1), Some(Holding::Unread), "she keeps it unread at sync");
}

// spec/sync-judgement.md §6 (Read and unread move), spec/sync.md §3 (Held sync secrets): Alice,
// T1's only reader, grants Bob read on it and lowers T0's record edge on T1 to sync. She keeps
// T1 unread by the sync secret held from her own reading, its store kept: Bob, holding it only
// then, reads T1 from it.
#[test]
fn the_last_reader_lowered_to_sync_keeps_the_store_for_a_later_reader_spec_sync_judgement_6() {
    let mut w = contacts();
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, Some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    w.run();
    w.write(0, |e| e.leaving_adminless(|e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: Some(edge(Role::Sync)), retain: None }))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None);
    assert_eq!(holding(&mut w, 0, &t1), Some(Holding::Unread));
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("v2".into())), "Bob holds it later and reads");
}

// spec/sync-inbox.md §5 (Grant from outside: a removal too goes as an offer): Alice grants Bob
// read on T0, so he reads T1, minted with admin T0. One of her nodes removes him from T0 while
// the other, not yet knowing it, grants him sync on T1, boxing him T1's read secret; Bob holds
// T1 alone and pairs a second node. Both of his nodes keep T1 unread.
#[test]
fn a_removal_beside_a_sync_grant_keeps_the_thing_unread_at_each_node_spec_sync_inbox_5() {
    // Alice: nodes 1 and 2; Bob: node 0, then node 3
    let mut w = siblings();
    let t0 = make(&mut w, 1, None, "v1");
    let t1 = make(&mut w, 1, Some(t0), "v2");
    let bob = w.node(0).account.unwrap();
    w.write(1, |e| e.grant(&t0, &bob, &edge(Role::Read))).unwrap();
    w.run();
    w.write(2, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None })).unwrap();
    w.write(1, |e| e.grant(&t1, &bob, &edge(Role::Sync))).unwrap();
    strong(&mut w, 0, None, t1, true);
    w.pair(0);
    w.run();
    for i in [0, 3] {
        assert_eq!(holding(&mut w, i, &t1), Some(Holding::Unread), "node {i} keeps T1 unread");
    }
}

// spec/commits.md §4 (Pending storage), spec/sync-judgement.md §3 (it opens again each entry of
// it its store still holds), notes/sync.md
// Arriving early: Bob holds T ahead and drops it again just as Alice grants him read, so his
// node receives her grant under his account root's sync ID after the release and it pends,
// needing T's record. Its pending copy then goes while the entry stays (in a history: the commit
// applies from a fire's copy and is forgotten between two follows of the store). Neither held
// nor pending, the entry waits for that sync ID again (store::Follow::lost_parks), as one whose
// held commit is forgotten does.
#[test]
#[ignore = "sync rewrite: copies per (commit, thing)"]
fn an_entry_whose_pending_commit_is_forgotten_is_parked_again_spec_sync_judgement_3() {
    let mut w = siblings();
    w.parks = true;
    let t = make(&mut w, 0, None, "v1");
    let bob = w.node(1).account.unwrap();
    strong(&mut w, 2, None, t, true);
    w.run();
    let g = w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t, false);
    w.run();
    let pending: Vec<_> = g.commits.iter().copied().filter(|c| w.engine(1).pends(c)).collect();
    assert!(!pending.is_empty(), "the grant pends at Bob's node, its thing released");
    for c in &pending {
        w.engine(1).release_entry(c).unwrap();
    }
    w.run();
    w.check_parks();
}

// spec/permissions.md §3 (Lost access): Alice mints T1 with admin T0, grants Bob sync on it, writes,
// then removes T0's record edge on T1, her only path to T1. The removal's own entries under T0's
// and D's sync IDs, read still, name a commit she forgets with T1: each is parked again
// (store::Follow::lost_parks), so the access returning opens it.
#[test]
fn removing_the_makers_only_path_parks_its_entries_spec_permissions_3() {
    let mut w = contacts();
    w.parks = true;
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, Some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Sync))).unwrap();
    w.run();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t1, &ak(), &Value::Str("v3".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.check_parks();
    w.write(0, |e| e.leaving_adminless(|e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None }))).unwrap();
    w.check_parks();
    w.run();
    w.check_parks();
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost T1");
}


// spec/permissions.md §3 (Lost access: a node that lost read through its own self-removal drops
// once the commit is held elsewhere): Alice mints T1 with admin T0 and grants Bob read; Bob holds it.
// She removes T0's record edge on T1, her only path to T1, a self-removal: she keeps T1's
// secrets and store until Bob holds the removal, so Bob's roster loses T0 as the reference's.
#[test]
fn a_self_removal_of_the_makers_only_path_reaches_the_reader_spec_permissions_3() {
    let mut w = contacts();
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, Some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert!(w.engine(1).roster(&t1).contains_key(&t0), "Bob reads T0's record edge");
    w.write(0, |e| e.leaving_adminless(|e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None }))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost T1");
    let roster: Vec<Tid> = w.engine(1).roster(&t1).into_keys().collect();
    assert_eq!(roster, vec![bob], "Bob holds the removal");
}

// spec/permissions.md §4 (Role changes travel): cut off from his sibling and from Alice, one of
// Bob's nodes removes Alice from T, never having seen the grant his other node gives her. Alice
// takes the grant by its fire and reads T; the removal, a body under T's sync ID that applies by
// its place on the timeline whatever its writer held, reaches her once its writer does, and she
// reads T no more.
#[test]
fn a_removal_its_writer_made_blind_reaches_the_removed_reader_spec_permissions_4() {
    let mut w = siblings();
    let t = make(&mut w, 1, None, "v1");
    let alice = w.node(0).account.unwrap();
    strong(&mut w, 0, None, t, true);
    w.run();
    w.partition(1, 2);
    w.partition(0, 2);
    w.write(1, |e| e.grant(&t, &alice, &edge(Role::Read))).unwrap();
    // the removal orders after the grant (spec/permissions.md §5.1 key order)
    w.advance(10);
    w.write(2, |e| e.demote(&t, &osis_engine::flows::Demotion { holder: alice, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t), Some(Value::Str("v1".into())), "Alice reads T by the grant");
    w.heal();
    w.run();
    assert_eq!(value(&mut w, 0, &t), None, "Alice reads T no more");
}

// spec/permissions.md §3 (Lost access; No secret taken back): Bob mints T1 with admin T0 and grants
// Alice read on T0, so she reads T1 through T0. Cut off from his sibling, one of Bob's nodes
// removes her from T0 while the other grants her sync on T1, still boxing her T1's read secret;
// Alice holds T1. Her role there shows sync alone, so she keeps T1 unread and reads none of it.
#[test]
fn a_read_secret_boxed_beside_a_removal_goes_once_the_role_shows_sync_spec_permissions_3() {
    let mut w = siblings();
    let t0 = make(&mut w, 1, None, "v1");
    let t1 = make(&mut w, 1, Some(t0), "v2");
    strong(&mut w, 1, Some(t0), t1, true);
    let alice = w.node(0).account.unwrap();
    w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
    w.run();
    w.partition(1, 2);
    w.write(2, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: alice, new: None, retain: None })).unwrap();
    w.write(1, |e| e.grant(&t1, &alice, &edge(Role::Sync))).unwrap();
    strong(&mut w, 0, None, t1, true);
    w.heal();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None, "Alice reads none of T1");
    assert_eq!(holding(&mut w, 0, &t1), Some(Holding::Unread), "she keeps T1 unread");
}

// spec/sync-inbox.md §5 (Grant from outside), spec/sync-set.md §2: Alice grants Bob read on T,
// lowers him to sync and grants read again, each an offer on his inbox; a node Bob pairs holds
// T. Both of Bob's nodes read T.
#[test]
fn a_grant_lowered_and_given_again_reads_at_each_of_the_grantees_nodes_spec_sync_inbox_5() {
    let mut w = contacts();
    let t = make(&mut w, 0, None, "v1");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.pair(1);
    w.run();
    w.write(0, |e| e.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 2, None, t, true);
    w.run();
    for i in [1, 2] {
        assert_eq!(value(&mut w, i, &t), Some(Value::Str("v1".into())), "node {i} reads T");
    }
}

// spec/sync-judgement.md §2 (the key part of S's actor: a grant's edge piece travels under its holder's sync
// ID), spec/sync-set.md §2: Alice grants H read on T; Bob reads H and holds T from his account root,
// not from H. His keys open T through H; the grant travels under H's sync ID with T's boxes to
// H and T's `sync.0`, so he learns T's sync ID and reads T, though no offer goes (Alice writes
// H) and he may not write H.
#[test]
fn a_reader_by_a_chain_through_a_holder_thing_reads_spec_sync_judgement_2() {
    let mut w = contacts();
    let h = make(&mut w, 0, None, "h");
    let t = make(&mut w, 0, None, "t");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&h, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, h, true);
    w.run();
    assert_eq!(value(&mut w, 1, &h), Some(Value::Str("h".into())), "Bob reads H");
    w.write(0, |e| e.grant(&t, &h, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("t".into())), "Bob reads T through H");
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Read));
}

// spec/sync-inbox.md §5 (Grant from outside), §1, spec/sync-judgement.md §2 (the key part of S's actor);
// Bob's T1 holds T0 by a strong; Alice, who knows T1's public key record but neither reads nor
// syncs T1 (she reads T4, holder on T3 minted with admin T1), grants T1 read on T0, an offer on
// T1's inbox. T1 takes no grants from outside, so Bob, T1's reader, does not read T0; once T1's
// admin enables its inbox signals (as chat and kit do at creation: spec/permissions.md §5.2
// External fires), the offer Alice sent is valid and Bob reads T0 through T1.
#[test]
#[ignore = "accounts: pairing"]
fn a_grant_to_a_holder_its_granter_does_not_sync_reaches_its_readers_spec_sync_inbox_5() {
    let mut w = contacts();
    let alice = w.node(0).account.unwrap();
    let t1 = make(&mut w, 1, None, "t1");
    let t3 = make(&mut w, 1, Some(t1), "t3");
    let t4 = make(&mut w, 1, None, "t4");
    w.write(1, |e| e.grant(&t4, &alice, &edge(Role::Read))).unwrap();
    w.write(1, |e| e.grant(&t3, &t4, &edge(Role::Read))).unwrap();
    strong(&mut w, 0, None, t4, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t4), Some(Value::Str("t4".into())), "Alice reads T4");
    let t0 = make(&mut w, 0, None, "t0");
    strong(&mut w, 1, Some(t1), t0, true);
    w.write(0, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t0), None, "T1 takes no offer from Alice: Bob does not read T0");
    w.write(1, |e| {
        let mut m = Mutation::new();
        let mut x = ct::RetentionSetting::default();
        x.take_inbox_signals();
        m.set(t1, &ct::RETENTION, &x).unwrap();
        e.commit(m)
    })
    .unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("t0".into())), "enabled: Bob reads T0 through T1");
    assert_eq!(holding(&mut w, 1, &t0), Some(Holding::Read));
    // T3's chain was needed by T4 alone (spec/commits.md §5 What a held thing needs): released
    // with it
    assert!(w.engine(0).mint_admin(&t3).is_some(), "Alice holds T3's record while T4 is held");
    strong(&mut w, 0, None, t4, false);
    w.run();
    assert_eq!(w.engine(0).mint_admin(&t3), None, "T3's record goes with T4");
}

// spec/permissions.md §4 (Role changes travel), spec/sync-judgement.md §2 (the key part of S's actor: a later
// edge write on the edge of a grant A takes, a removal among them, is in A's own sync ID's
// required set): Bob's node 2 mints T2 with admin
// his T0, grants Alice sync on it (T2 made independent) and removes T0's record edge there. That removal
// names T0 by an edge write, so it travels under T0's sync ID: Bob's node 1, reading T2 only
// through T0, takes it and reads T2 no more, as node 2.
#[test]
fn a_removed_record_edge_reaches_its_mint_admins_readers_spec_permissions_4() {
    let (mut w, t0) = bobs_thing();
    let alice = w.node(0).account.unwrap();
    let t2 = make_in(&mut w, 2, t0, "t2");
    w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Sync))).unwrap();
    w.write(2, |e| e.leaving_adminless(|e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None }))).unwrap();
    w.run();
    for i in [1, 2] {
        assert!(!w.engine(i).roster(&t2).contains_key(&t0), "node {i} sees T0's record edge removed");
        assert_eq!(value(&mut w, i, &t2), None, "node {i} reads T2 no more");
    }
}

// spec/permissions.md §3 (Lost access: a node drops every local unit it can no longer read),
// spec/sync.md §3: Bob's node 2 makes T0 and grants Alice read; his node 1 mints T1 with admin T0;
// Alice holds both. Node 1 removes Alice from T0 while node 2, not yet knowing, grants her sync
// on T1 (T1 made independent). Alice holds sync alone on T1 and nothing on T0: she reads neither.
#[test]
fn a_reader_removed_as_a_sibling_grants_on_a_dependent_reads_it_no_more_spec_permissions_3() {
    let mut w = siblings();
    let alice = w.node(0).account.unwrap();
    let t0 = make(&mut w, 2, None, "t0");
    w.write(2, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
    w.run();
    strong(&mut w, 0, None, t0, true);
    let t1 = make_in(&mut w, 1, t0, "t1");
    strong(&mut w, 0, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1 through T0");
    w.write(1, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: alice, new: None, retain: None })).unwrap();
    w.write(2, |e| e.grant(&t1, &alice, &edge(Role::Sync))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t0), None, "Alice reads T0 no more");
    assert_eq!(value(&mut w, 0, &t1), None, "Alice reads T1 no more: {}", w.why_role(0, &t1));
}

/// A thing node `i` mints with admin `admin`, held from `admin` alone, value `v`.
fn make_in(w: &mut World, i: usize, admin: Tid, v: &str) -> Tid {
    let v = v.to_owned();
    w.write(i, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin, None));
        m.set(t, &ak(), &Value::Str(v)).unwrap();
        m.op(admin, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

// spec/sync-judgement.md §3 (Dropped bodies: a pull anew opens again each entry its store still
// holds), notes/sync-store.md (Parked entries): Bob's T0 holds X and Y, minted with it; Alice reads
// T0. Her engine forgets X's minting whole while its entry stays in her store under T0's sync ID
// (in a history: a release forgets the commit making a holder independent that T0's readers
// keep must-hold).
// Its blob noted no more, the entry waits for T0's sync ID, so when Y -> X reaches her and T0's
// sync ID is pulled anew, it opens again.
#[test]
fn an_entry_of_a_commit_forgotten_whole_opens_again_at_a_pull_anew_spec_sync_judgement_3() {
    let mut w = siblings();
    let alice = w.node(0).account.unwrap();
    let t0 = make(&mut w, 1, None, "t0");
    let x = make_in(&mut w, 1, t0, "x");
    let y = make_in(&mut w, 1, t0, "y");
    w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
    strong(&mut w, 0, None, t0, true);
    w.run();
    let minting: Vec<_> = w.engine(0).commit_ids().into_iter().filter(|c| w.engine(0).header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == x))).collect();
    w.write(0, |e| e.forget_commits(&minting)).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &x), None, "X forgotten at Alice");
    strong(&mut w, 1, Some(y), x, true);
    w.run();
    assert_eq!(value(&mut w, 0, &x), Some(Value::Str("x".into())), "Alice reads X again");
}

// spec/sync-judgement.md §2 (the key part of S's actor: a grant's edge piece travels under its holder's sync
// ID), spec/permissions.md §3 (a commit of which it holds the header alone was read by no secret and
// stays): Alice's node 2 makes T0 and T1 and grants Bob read on T0 while her node 0 grants T0
// sync on T1. Bob, reading T0, takes T0's certificates of T1 (its minting as a header alone, its
// `sync.0`, its boxes to T0), so he holds T1's sync secrets and no read: he loses access to T1,
// which must not forget the minting's header, read by no secret of T1.
#[test]
fn a_reader_of_a_holder_holds_its_targets_boxes_to_it_spec_sync_judgement_2() {
    let mut w = contacts();
    w.pair(0);
    w.run();
    let bob = w.node(1).account.unwrap();
    let t0 = make(&mut w, 2, None, "t0");
    let t1 = make(&mut w, 2, None, "t1");
    w.run();
    w.write(2, |e| e.grant(&t0, &bob, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&t1, &t0, &edge(Role::Sync))).unwrap();
    w.run();
    strong(&mut w, 1, None, t0, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("t0".into())));
}


// spec/sync-set.md §2 (counts as independent; kept unread), spec/permissions.md §3 (Lost
// access), §4 (Key part): Bob reads T1, which Alice granted sync on
// T2 and then removed, so T1's certificates bring Bob T2's `sync.0` and the role commits
// naming T1 alone. Alice grants Bob sync on T2 directly, after the rotation that removed T1: the
// grant reaches him as an offer (its fire), and he holds its box and no copy of that rotation.
// The role commits naming T1 show no role of his on T2, so they neither keep the box out nor drop
// the sync secret it gives. He keeps T2 unread.
#[test]
fn a_sync_grant_beside_a_removed_holders_role_commits_keeps_the_thing_unread_spec_sync_set_2() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let t0 = make(&mut w, 0, None, "t0");
    let t1 = make(&mut w, 0, None, "t1");
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    let t2 = make_in(&mut w, 0, t0, "t2");
    w.write(0, |e| e.grant(&t2, &t1, &edge(Role::Sync))).unwrap();
    w.write(0, |e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t1, new: None, retain: None })).unwrap();
    w.write(0, |e| e.grant(&t2, &bob, &edge(Role::Sync))).unwrap();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("t1".into())), "Bob reads T1");
    strong(&mut w, 1, None, t2, true);
    w.run();
    assert_eq!(holding(&mut w, 1, &t2), Some(Holding::Unread), "Bob keeps T2 unread");
}

// spec/sync-set.md §2 (Held for keys; Sync set: its sync ID, for role entries alone),
// spec/sync-opens.md §4 (Source: a keys source), spec/sync-streams.md §4 (Toward a peer holding
// S's thing for keys), spec/sync-ids.md §6 (Role entries): Bob reads T1 and X, each granted to
// him and held; T1 holds read on H and H on X, so H is a holder X's grants name, on a path from
// Bob to X, that his node closure does not read. He holds H for keys: its sync ID is in his sync
// set so, he declares it opening it, and Alice, reading H, shows him its role entries alone:
// every entry he holds under it is one she stamped as a role entry, he holds no entry of H's
// content though she logs it there, and he reads no value of H. Fails with H synced as read, or
// with a server that sends a keys source every entry.
#[test]
fn a_holder_held_for_keys_is_shown_its_role_entries_alone_spec_sync_set_2() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let t1 = make(&mut w, 0, None, "t1");
    let h = make(&mut w, 0, None, "h");
    let x = make(&mut w, 0, None, "x");
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&x, &bob, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&h, &t1, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&x, &h, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    strong(&mut w, 1, None, x, true);
    w.run();
    assert_eq!(value(&mut w, 1, &x), Some(Value::Str("x".into())), "Bob reads X");
    assert!(w.engine(1).held_for_keys(&h), "H is on a path from Bob to X");
    assert_eq!(holding(&mut w, 1, &h), Some(Holding::Keys), "its sync ID is held for keys");
    assert_eq!(holding(&mut w, 1, &t1), Some(Holding::Read), "T1's is read");
    assert_eq!(value(&mut w, 1, &h), None, "Bob reads nothing of H");
    let sh = w.engine(0).sync_id_of(&h).unwrap().unwrap();
    let st = w.node(0).node.status_of(&sh).expect("Alice syncs H");
    assert!(st.sources.values().any(|x| x.src.class == osis_proto::SourceClass::Keys), "Bob declared himself a keys source of H: {:?}", st.sources);
    let hers = w.store(0).entries(&sh).unwrap();
    let role: std::collections::BTreeSet<_> = hers.iter().filter(|e| e.role).map(|e| e.blob).collect();
    assert!(!role.is_empty() && role.len() < hers.len(), "Alice logs H's role entries and its content under its sync ID");
    let his = w.store(1).entries(&sh).unwrap();
    assert!(!his.is_empty(), "Bob holds H's role entries");
    for e in &his {
        assert!(role.contains(&e.blob) || e.own, "Bob holds an entry of H that is no role entry: {:?}", e.blob);
    }
    assert!(his.iter().any(|e| role.contains(&e.blob)), "shown by Alice");
}

// spec/permissions.md §4 (Role changes travel: under the sync ID of each thing whose keys open
// the holder), spec/sync-judgement.md §2: Bob reads T1, granted read on H, granted read on X;
// T1 -> X, so Bob reads X through T1 and H, holding H for keys alone. Alice removes H from X: X leaves T1's
// sync unit with the removal, which reaches Bob under T1's sync ID (T1's keys open H), so his
// role commits show him no role on X. A, dependent on X (notes/closure-model.md Hole, its dependent
// form), held by T1 -> A, leaves T1's sync unit with X: Bob reads it no more, and no store keeps
// an entry under T1's sync ID of a commit on A alone (Alice, holding T1's delete key, deleted
// hers; Bob logs none again), spec/sync-set.md §3 (A thing leaving a sync unit).
#[test]
fn a_removal_reaches_a_reader_opening_the_holder_through_a_second_thing_spec_permissions_4() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let t1 = make(&mut w, 0, None, "t1");
    let h = make(&mut w, 0, None, "h");
    let x = make(&mut w, 0, None, "x");
    let a = make(&mut w, 0, Some(x), "a");
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&h, &t1, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&x, &h, &edge(Role::Read))).unwrap();
    strong(&mut w, 0, Some(t1), x, true);
    strong(&mut w, 0, Some(t1), a, true);
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 1, &x), Some(Value::Str("x".into())), "Bob reads X through T1 and H");
    assert_eq!(value(&mut w, 1, &a), Some(Value::Str("a".into())), "and A, dependent on X");
    assert_eq!(holding(&mut w, 1, &h), Some(Holding::Keys), "X's grants name H: Bob holds it for keys");
    let s1 = w.engine(0).sync_id_of(&t1).unwrap().unwrap();
    // entries under T1's sync ID of commits on A and things outside T1's sync unit
    let of_a = |w: &mut World, i: usize| {
        let es = w.store(i).entries(&s1).unwrap();
        es.iter().filter(|e| w.engine(i).blob_commit(&e.blob).and_then(|c| w.engine(i).header(&c)).is_some_and(|hd| hd.aspects.iter().any(|p| p.tid == a) && !hd.aspects.iter().any(|p| [t1, h, x].contains(&p.tid)))).count()
    };
    assert!(of_a(&mut w, 0) > 0 && of_a(&mut w, 1) > 0, "A's commits under T1's sync ID");
    w.write(0, |e| e.demote(&x, &osis_engine::flows::Demotion { holder: h, new: None, retain: None })).unwrap();
    w.run();
    assert!(!w.engine(1).roster(&x).contains_key(&h), "Bob holds H's removal");
    assert_eq!(w.engine(1).role_on(&x), None, "his role commits show him no role on X");
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    w.run();
    assert_eq!(value(&mut w, 1, &x), None, "Bob reads X no more");
    assert_eq!(value(&mut w, 1, &a), None, "nor A");
    assert_eq!((of_a(&mut w, 0), of_a(&mut w, 1)), (0, 0), "A's commits left T1's sync ID at both");
}

/// A thing node 1 mints with admin `admin`, held from its account root alone, value `v`, beside
/// `also` written on `x` in the same commit: the thing and the commit.
fn make_beside(w: &mut World, admin: Tid, v: &str, x: Tid, by: osis_base::PurgeBy) -> (Tid, osis_base::CommitId) {
    let v = v.to_owned();
    let d = w.node(1).account.unwrap();
    w.write(1, |e| {
        let mut m = Mutation::new();
        let y = m.create(e.thing_record(admin, None));
        m.set(y, &ak(), &Value::Str(v)).unwrap().purge_by(y, &ak(), by).unwrap();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(y)) }).unwrap();
        m.set(x, &ak(), &Value::Str("x2".into())).unwrap();
        (y, e.commit(m).unwrap().unwrap())
    })
}

// spec/sync-judgement.md §1 (Sealed sections), spec/commits.md §5 (Purge): Bob's commit mints Y
// with admin T0, held from his account root alone, with a value beside a write to X, which Alice
// holds through T0. She can derive Y's read secret but does not hold Y, so Y's purge request
// never reaches her: she takes Y's record alone, never its value, before the purge or after; she
// reads X. Fails if a node opens the sections of a thing it merely has the secret for. That no
// disk of hers holds the value: flows::a_section_of_a_thing_not_held_leaves_nothing_on_disk
// (osis-engine), the forensic attack on a node of a smaller history.
#[test]
fn a_section_of_a_thing_not_held_stays_sealed_spec_sync_judgement_1() {
    let mut w = contacts();
    let alice = w.node(0).account.unwrap();
    let t0 = make(&mut w, 1, None, "t0");
    let x = make_in(&mut w, 1, t0, "x");
    w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
    strong(&mut w, 0, None, t0, true);
    w.run();
    let (y, c) = make_beside(&mut w, t0, "y", x, osis_base::PurgeBy::Writer);
    w.run();
    let of_y = |w: &mut World| w.engine(0).all_aspects().unwrap().iter().filter(|(t, _)| *t == y).count();
    assert_eq!(value(&mut w, 0, &x), Some(Value::Str("x2".into())), "Alice reads X");
    assert!(!w.engine(0).closure_holds(&y), "Alice does not hold Y");
    assert_eq!(of_y(&mut w), 0, "Alice holds a state of Y");
    w.advance(10);
    w.write(1, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(y, &ct::PURGE, &now).unwrap();
        m.purge_commit(c, y, ak());
        e.commit(m).unwrap().unwrap();
    });
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    w.run();
    assert_eq!(of_y(&mut w), 0, "Alice holds a state of Y after its purge");
    assert_eq!(value(&mut w, 0, &x), Some(Value::Str("x2".into())), "Alice still reads X");
}

// spec/sync-judgement.md §1 (Sealed sections): a commit making a thing and the strong to it
// carries the thing's record in a section of a thing the receiver does not hold yet. Bob's
// commit mints Y with admin T0 with T0's strong to it, reaching Alice before or after she holds T0;
// and Bob's commit making Z, held from his account root, before he adds T0's strong to it,
// after which the minting reaches her under T0's sync ID. Each time she takes the record, the
// strong brings the thing in, and the section opens again: she reads both.
#[test]
fn a_thing_made_beside_its_strong_opens_once_held_spec_sync_judgement_1() {
    for held_first in [true, false] {
        let mut w = contacts();
        let alice = w.node(0).account.unwrap();
        let t0 = make(&mut w, 1, None, "t0");
        w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
        if held_first {
            strong(&mut w, 0, None, t0, true);
            w.run();
        }
        let y = make_in(&mut w, 1, t0, "y");
        let (z, _) = make_beside(&mut w, t0, "z", y, osis_base::PurgeBy::Admin);
        if !held_first {
            strong(&mut w, 0, None, t0, true);
        }
        w.run();
        assert_eq!(value(&mut w, 0, &y), Some(Value::Str("x2".into())), "held first {held_first}: Alice reads Y");
        assert_eq!(value(&mut w, 0, &z), None, "held first {held_first}: Z is not held");
        strong(&mut w, 1, Some(t0), z, true);
        w.run();
        assert_eq!(value(&mut w, 0, &z), Some(Value::Str("z".into())), "held first {held_first}: Alice reads Z");
    }
}

// spec/crypto.md §4 (Key access: a grant's holder boxed with the grant itself held; History box:
// a grant writes it again): Alice mints T with her root as admin and X with admin T, both dependent; she grants
// Bob's account sync on X and on T (making each independent), X sync on T (keyless: X is one of
// T's dependents), then Bob read on T, and Bob holds T. What was written before T was independent
// is sealed under T's derived epochs, and the commit making it independent wraps under them: the read grant boxes Bob at read with the
// history entry carrying them (not only at sync, his key access before the grant), so he reads
// T and X.
#[test]
fn a_grant_after_its_thing_became_independent_brings_the_history_its_boxes_open_spec_crypto_4() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let t = make(&mut w, 0, None, "t");
    let x = make_in(&mut w, 0, t, "x");
    w.write(0, |e| e.grant(&x, &bob, &edge(Role::Sync))).unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Sync))).unwrap();
    w.write(0, |e| e.grant(&t, &x, &edge(Role::Sync))).unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("t".into())), "Bob reads T");
    assert_eq!(value(&mut w, 1, &x), Some(Value::Str("x".into())), "Bob reads X");
}

// spec/sync-set.md §3 (A thing leaving a sync unit: delete-key holders delete by their own view; a
// node whose view still holds X there logs it again), spec/sync-judgement.md §3 (Dropped bodies:
// what is forgotten with a released thing is fetched again once a strong in the node closure
// reaches it again): on `three`, node 0 (admin) holds X and Y in thing 0's sync unit (T -> X,
// T -> Y), node 1 keeps it unread, node 2 writes it. Node 2, cut off, writes Y -> X and goes off
// while node 0 removes T -> X, releases X and deletes its value at node 1. Node 2 then meets node
// 1 alone: its view still holds X, so it logs X's value there again; node 0, meeting node 1
// alone, takes Y -> X and reads X again from the store.
#[test]
fn a_thing_left_by_one_view_is_logged_again_by_one_still_holding_it_spec_sync_set_3() {
    let (mut w, t, s) = crate::harness::history::three(crate::harness::history::Gives::Writes, 2);
    let x = make_in(&mut w, 0, t, "x");
    let y = make_in(&mut w, 0, t, "y");
    w.run();
    assert_eq!(value(&mut w, 2, &x), Some(Value::Str("x".into())), "node 2 reads X");
    let of_x = |w: &mut World| {
        let es = w.store(1).entries(&s).unwrap();
        es.iter().filter(|e| w.engine(2).blob_commit(&e.blob).and_then(|c| w.engine(2).header(&c)).is_some_and(|h| h.aspects.iter().any(|a| a.tid == x && a.ak == ak()))).count()
    };
    assert!(of_x(&mut w) > 0, "X's value under S at node 1");
    w.partition(0, 2);
    w.partition(1, 2);
    strong(&mut w, 2, Some(y), x, true);
    w.power_off(2);
    strong(&mut w, 0, Some(t), x, false);
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    assert_eq!(value(&mut w, 0, &x), None, "released at node 0");
    assert_eq!(of_x(&mut w), 0, "node 0 deleted X's value at node 1");
    w.partition(0, 1);
    w.rejoin(1, 2);
    w.power_on(2);
    w.advance(31_000);
    assert!(of_x(&mut w) > 0, "node 2 logged X's value at node 1 again");
    w.partition(1, 2);
    w.rejoin(0, 1);
    w.advance(31_000);
    assert_eq!(value(&mut w, 0, &x), Some(Value::Str("x".into())), "node 0 reads X again, from the store");
}

// spec/permissions.md §3 (Lost access: a node drops every local unit it can no longer read),
// spec/permissions.md §4 (Role changes travel): Bob's node 2 makes T0 and T2 with admin T0 and removes
// T0's record edge on T2 before his node 1 has synced either. Node 1, reading T2 only through T0,
// loses it, as node 2, and a pass on still reads it no more, though node 1 meets T2's minting
// under T0's sync ID after the loss (its blob seals T2's value under epochs node 1 holds, from
// before T2 was independent).
#[test]
fn a_removed_record_edge_reaches_a_reader_entering_with_it_spec_permissions_3() {
    let mut w = siblings();
    let alice = w.node(0).account.unwrap();
    let t0 = make(&mut w, 2, None, "t0");
    let t2 = make_in(&mut w, 2, t0, "t2");
    w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Sync))).unwrap();
    w.write(2, |e| e.leaving_adminless(|e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None }))).unwrap();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("t0".into())), "node 1 reads T0");
    for i in [1, 2] {
        assert!(!w.engine(i).roster(&t2).contains_key(&t0), "node {i} sees T0's record edge removed");
        assert_eq!(value(&mut w, i, &t2), None, "node {i} reads T2 no more");
    }
}

/// Whether node `i` holds a state of `t`'s value aspect (content, not certificates).
fn holds_value(w: &mut World, i: usize, t: &Tid) -> bool {
    w.engine(i).all_aspects().unwrap().iter().any(|(x, a)| x == t && *a == ak())
}

/// Every entry node `from`'s store holds under `s`, opened again by node `to`'s engine as a
/// writer of `s`'s thing filing it anew would have it arrive (spec/sync-ids.md §5), then run;
/// in the store's order of them, or (`back`) the reverse.
fn refile(w: &mut World, from: usize, to: usize, s: &osis_base::SyncId, back: bool) {
    let mut es = w.store(from).entries(s).unwrap();
    if back {
        es.reverse();
    }
    for e in es {
        let Some(bytes) = w.store(from).bytes(&e.blob).unwrap() else { continue };
        w.engine(to).open_entry(s, &e.blob, &e.wrap, &bytes, u64::MAX).unwrap();
    }
    w.run();
}

// spec/sync-set.md §2 (T's keys open), spec/commits.md §4 (Outside the node closure): Bob's node 1
// makes T0 and grants Alice read on it; his node 2 mints T2 with admin T0 (its value sealed under T0's
// epochs), grants Alice sync on T2 (T2 made independent) and removes T0's record edge. T0 holds no role on T2:
// no reader of T0 reads T2, its maker's nodes included, and every entry under T0's sync ID filed
// again after the loss by a writer of T0 (who holds them all) gives none of T2's content back.
#[test]
fn a_mint_admins_readers_read_a_thing_no_more_once_its_record_edge_goes_spec_sync_set_2() {
    // in either order the entries are filed again in
    for back in [false, true] {
        let (mut w, (alice, _, t0)) = alice_reads_t0();
        let t2 = make_in(&mut w, 2, t0, "t2");
        w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Sync))).unwrap();
        w.write(2, |e| e.leaving_adminless(|e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None }))).unwrap();
        w.run();
        w.advance(osis_proto::limits::PASS_WAIT_MS);
        w.run();
        let s0 = w.engine(1).sync_id_of(&t0).unwrap().unwrap();
        for refiled in [false, true] {
            for i in [0, 1, 2] {
                assert_eq!(value(&mut w, i, &t0), Some(Value::Str("t0".into())), "back {back}, refiled {refiled}: node {i} reads T0");
                assert_eq!(value(&mut w, i, &t2), None, "back {back}, refiled {refiled}: node {i} reads T2 no more");
                assert!(!holds_value(&mut w, i, &t2), "back {back}, refiled {refiled}: node {i} holds T2's value");
            }
            for to in [0, 1] {
                refile(&mut w, 2, to, &s0, back);
            }
            w.advance(osis_proto::limits::PASS_WAIT_MS);
            w.run();
        }
    }
}

// spec/permissions.md §3 (Lost access), spec/sync-set.md §2 (T's keys open): Bob makes T0 and grants Alice read on it; his node 2 mints T2 with admin T0, grants his account
// admin on T2 and removes T0's record edge. Alice, reading T2 only through T0, reads it no more,
// whatever T0's sync ID still carries (Bob's node 2 files its entries again). Bob grants T0 read on
// T2 again: she reads T2 again, and only then.
#[test]
#[ignore = "accounts: pairing"]
fn a_mint_admins_readers_read_a_thing_again_once_granted_again_spec_permissions_3() {
    let (mut w, (_, bob, t0)) = alice_reads_t0();
    let t2 = make_in(&mut w, 2, t0, "t2");
    w.write(2, |e| e.grant(&t2, &bob, &edge(Role::Admin))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())), "Alice reads T2 through T0");
    w.write(2, |e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None })).unwrap();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    let s0 = w.engine(1).sync_id_of(&t0).unwrap().unwrap();
    refile(&mut w, 2, 0, &s0, false);
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    assert_eq!(value(&mut w, 0, &t2), None, "Alice reads T2 no more");
    assert!(!holds_value(&mut w, 0, &t2), "Alice holds T2's value");
    w.write(2, |e| e.grant(&t2, &t0, &edge(Role::Read))).unwrap();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())), "Alice reads T2 again");
}

/// Bob's node 1 makes T0 and grants Alice read on it; Alice holds T0. Node 1 mints T1 with admin T0
/// (made independent by a grant of Bob's admin when `key1`), then T2 with admin T1, made independent so. Each record edge
/// stands: (world, T0, T1, T2). Built once per process per `key1` (`fixture_with`).
fn record_chain_of_three(key1: bool) -> (World, Tid, Tid, Tid) {
    let (w, (t0, t1, t2)) = fixture_with(&format!("holding record chain {key1}"), || record_chain_built(key1));
    (w, t0, t1, t2)
}

/// `record_chain_of_three`, built.
fn record_chain_built(key1: bool) -> (World, (Tid, Tid, Tid)) {
    let (mut w, (_, bob, t0)) = alice_reads_t0();
    let t1 = make_in(&mut w, 1, t0, "t1");
    if key1 {
        w.write(1, |e| e.grant(&t1, &bob, &edge(Role::Admin))).unwrap();
    }
    let t2 = make_in(&mut w, 1, t1, "t2");
    w.write(1, |e| e.grant(&t2, &bob, &edge(Role::Admin))).unwrap();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    (w, (t0, t1, t2))
}

// spec/sync-set.md §2 (T's keys open: read counts through chains of role grants, the lowest role
// along a chain), spec/permissions.md §1: T0 admin on T1 and T1
// admin on T2 by their record edges, each independent (or T1 left dependent): Alice, a reader of T0,
// reads T1 and T2, and what is written on T2 after it was made independent.
#[test]
fn a_reader_reads_down_a_chain_of_standing_record_edges_spec_sync_set_2() {
    for key1 in [false, true] {
        let (mut w, _t0, t1, t2) = record_chain_of_three(key1);
        w.write(1, |e| {
            let mut m = Mutation::new();
            m.set(t2, &ak(), &Value::Str("t2 later".into())).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "key1 {key1}: Alice reads T1");
        assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2 later".into())), "key1 {key1}: Alice reads T2");
        assert_eq!(holding(&mut w, 0, &t2), Some(Holding::Read), "key1 {key1}");
    }
}

// spec/sync-set.md §2 (T's keys open), spec/permissions.md §3 (Lost access): as above, T1 independent; Bob
// lowers T1's record edge on T2 to sync. T0 reads T2 by no chain: Alice reads T2 no more and holds
// none of its content, whatever T0's and T1's sync IDs carry (node 2 files them again), while
// she reads T1 still.
#[test]
fn a_reader_down_a_chain_lowered_to_sync_reads_the_thing_no_more_spec_permissions_3() {
    let (mut w, t0, t1, t2) = record_chain_of_three(true);
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())));
    w.write(1, |e| e.leaving_adminless(|e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t1, new: Some(edge(Role::Sync)), retain: None }))).unwrap();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    for t in [t0, t1] {
        let s = w.engine(1).sync_id_of(&t).unwrap().unwrap();
        refile(&mut w, 1, 0, &s, false);
    }
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1");
    assert_eq!(value(&mut w, 0, &t2), None, "Alice reads T2 no more");
    assert!(!holds_value(&mut w, 0, &t2), "Alice holds T2's value");
}

// spec/sync-set.md §3 (Lowering from read to sync is no release: S becomes kept unread with its
// store), spec/permissions.md §3 (Lost access): Bob reads T; lowered to sync he reads nothing and
// keeps T unread, holding none of its content, and so across a restart.
#[test]
fn a_reader_lowered_to_sync_holds_no_content_across_a_restart_spec_permissions_3() {
    let (mut w, (t, bob)) = granted();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("hi".into())));
    assert!(holds_value(&mut w, 1, &t));
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t), None, "lowered: reads nothing");
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "kept unread");
    assert!(!holds_value(&mut w, 1, &t), "lowered: holds T's value");
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    refile(&mut w, 0, 1, &s, false);
    w.power_off(1);
    w.power_on(1);
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread));
    assert!(!holds_value(&mut w, 1, &t), "restarted: holds T's value");
    assert_eq!(value(&mut w, 1, &t), None);
}

// spec/sync-set.md §2 (T's keys open), spec/permissions.md §3 (Lost access): Alice reads T0;
// Bob's T2, minted with admin T0, is independent and Alice granted sync on T2 directly, holding it from her root too.
// She reads T2 through T0. Bob removes T0's record edge: she keeps T2 unread by her own sync
// grant and holds none of its content.
#[test]
fn a_thing_read_through_one_unit_and_kept_unread_directly_spec_sync_set_2() {
    let (mut w, (alice, bob, t0)) = alice_reads_t0();
    let t2 = make_in(&mut w, 1, t0, "t2");
    w.write(1, |e| e.grant(&t2, &bob, &edge(Role::Admin))).unwrap();
    w.write(1, |e| e.grant(&t2, &alice, &edge(Role::Sync))).unwrap();
    w.run();
    strong(&mut w, 0, None, t2, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())), "Alice reads T2 through T0");
    w.write(1, |e| e.demote(&t2, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None })).unwrap();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    let s0 = w.engine(1).sync_id_of(&t0).unwrap().unwrap();
    refile(&mut w, 1, 0, &s0, false);
    w.advance(osis_proto::limits::PASS_WAIT_MS);
    w.run();
    assert_eq!(value(&mut w, 0, &t2), None, "Alice reads T2 no more");
    assert_eq!(holding(&mut w, 0, &t2), Some(Holding::Unread), "kept unread by her sync grant");
    assert!(!holds_value(&mut w, 0, &t2), "Alice holds T2's value");
}

// spec/sync-judgement.md §1 (Sealed sections), §2 (must-hold): Alice reads T0; Bob's node 2 mints
// T2 with admin T0 (its value sealed under T0's epochs), then grants Alice admin on T2 (T2 made
// independent) and she holds it: she reads T2's minting value, and holds every part her siblings
// judge must-hold.
#[test]
fn a_grantee_reads_the_minting_value_of_a_dependent_made_independent_spec_sync_judgement_1() {
    let (mut w, (alice, _, t0)) = alice_reads_t0();
    let t2 = make_in(&mut w, 2, t0, "t2");
    w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Admin))).unwrap();
    strong(&mut w, 0, None, t2, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())), "Alice reads T2's minting value");
}

// spec/sync-set.md §2 (Held for keys): Bob holds T2 kept unread by a chain through T1, which he
// reads (T1 holds sync on T2). He drops his strong to T1: his grant on T1 stands, T1's own data,
// so T2 stays kept unread, and T1, read by his closure no more and named holder on a thing he
// syncs, is held for keys: its content goes.
#[test]
#[ignore = "accounts: pairing"]
fn a_holder_dropped_on_a_chain_is_held_for_keys_and_its_target_stays_spec_sync_set_2() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let t1 = make(&mut w, 0, None, "t1");
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    let t2 = make(&mut w, 0, None, "t2");
    w.write(0, |e| e.grant(&t2, &t1, &edge(Role::Sync))).unwrap();
    w.run();
    strong(&mut w, 1, None, t2, true);
    w.run();
    assert_eq!(holding(&mut w, 1, &t2), Some(Holding::Unread), "T2 kept unread through T1");
    assert!(!w.engine(1).held_for_keys(&t1), "T1 is read, held by a strong");
    strong(&mut w, 1, None, t1, false);
    w.run();
    assert_eq!(holding(&mut w, 1, &t2), Some(Holding::Unread), "T2 stays: the grant on T1 stands");
    assert!(w.engine(1).held_for_keys(&t1), "T1 is held for keys");
    assert_eq!(value(&mut w, 1, &t1), None, "T1's content goes");
}

// spec/permissions.md §3 (Retain: a way alive is a grant with key access), spec/crypto.md §4 Key
// access: Bob grants Alice read on T0, mints T1 with admin T0, grants T1 read on T0 (keyless: T1's key
// derives from T0's) and Alice read on T1; she holds both. Bob removes her from T0: T1's keyless
// grant reads nothing of T0, so it keeps her no copy, and she reads T0 no more.
#[test]
fn a_keyless_grant_keeps_no_copy_spec_permissions_3() {
    let (mut w, (alice, t0, t1)) = keyless_way();
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "Alice reads T0");
    w.write(1, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: alice, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1");
    assert_eq!(value(&mut w, 0, &t0), None, "Alice reads T0 no more: {}", w.why_role(0, &t0));
    assert!(w.engine(0).read_secrets(&t0).is_empty(), "T0's secrets go");
}

// spec/permissions.md §3 (Retain: a way alive with key access keeps): Bob grants T1 read on T0 (both
// his own, the grant with key access) and Alice read on T1 only; she holds both. Bob removes her from T1
// saying retain: she keeps a copy of T1, and of T0 by T1's live grant.
#[test]
#[ignore = "accounts: making an account"]
fn a_keyed_live_grant_from_a_kept_holder_keeps_a_copy_spec_permissions_3() {
    let (mut w, (alice, t0, t1)) = keyed_way();
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "Alice reads T0 through T1");
    w.write(1, |e| e.demote(&t1, &osis_engine::flows::Demotion { holder: alice, new: None, retain: Some(true) })).unwrap();
    w.run();
    let mut kept = w.engine(0).kept_copies();
    kept.sort();
    let mut want = vec![t0, t1];
    want.sort();
    assert_eq!(kept, want, "copies of T1 and T0 kept: {}", w.why_role(0, &t0));
    // the debug dump names the retain decision (notes/test-harnesses.md, Why kept and row dumps)
    let why = w.why_role(0, &t0);
    assert!(why.contains("kept copy: yes, of ") && why.contains(&format!("kept marks: {t0} on ")), "{why}");
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "the copy of T0 reads");
    assert!(w.engine(0).read_secrets(&t0).is_empty(), "T0's secrets go");
}

// spec/permissions.md §3 (Retain: an ended way judged over the writes before its removal),
// spec/crypto.md §4 Key access: Bob grants Alice read on T1 only; his offline sibling grants T0 read
// on T1, then Bob T1 read on T0 (with key access at Bob). Bob removes T1's grant saying retain: Alice keeps a
// copy of T0. The sibling's grant arrives, ordered first: T1's grant was keyless before its removal,
// so the copy goes, as at a node that held every write together.
#[test]
fn an_ended_way_found_keyless_drops_its_copy_spec_permissions_3() {
    let mut w = siblings();
    let alice = w.node(0).account.unwrap();
    let t0 = make(&mut w, 1, None, "t0");
    let t1 = make(&mut w, 1, None, "t1");
    w.write(1, |e| e.grant(&t1, &alice, &edge(Role::Read))).unwrap();
    for t in [t0, t1] {
        strong(&mut w, 0, None, t, true);
    }
    w.run();
    w.partition(0, 2);
    w.partition(1, 2);
    w.write(2, |e| e.grant(&t1, &t0, &edge(Role::Read))).unwrap();
    w.advance(1000);
    w.write(1, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "Alice reads T0 through T1");
    w.write(1, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: t1, new: None, retain: Some(true) })).unwrap();
    w.run();
    assert_eq!(w.engine(0).kept_copies(), vec![t0], "a copy of T0 kept: {}", w.why_role(0, &t0));
    w.heal();
    w.run();
    assert!(w.engine(0).roster(&t1).contains_key(&t0), "Alice holds the sibling's grant");
    assert!(w.engine(0).kept_copies().is_empty(), "the copy of T0 goes: {}", w.why_role(0, &t0));
    assert_eq!(value(&mut w, 0, &t0), None, "Alice reads T0 no more");
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1");
}

// spec/sync-ids.md §2 (two admins making a thing independent at once: the greatest sync ID),
// spec/sync-inbox.md §5 (Grant from outside): Bob's offline sibling grants T0 read on T1, making
// T1 independent with a sync ID of its own; Bob, apart, grants Alice read on T1 (another sync ID,
// the one his offer to her names), which she holds. Once the sibling is back, every writer syncs
// T1 by the greater sync ID: Alice follows it and holds the sibling's grant as Bob does.
fn a_reader_follows_a_forked_sync_id(cycle: bool) {
    // up to Bob's grants, built once per process (`fixture_with`)
    let (mut w, (t0, t1)) = fixture_with("holding forked sync id", || {
        let mut w = siblings();
        let t0 = make(&mut w, 1, None, "t0");
        let t1 = make(&mut w, 1, None, "t1");
        w.run();
        w.partition(0, 2);
        w.partition(1, 2);
        w.write(2, |e| e.grant(&t1, &t0, &edge(Role::Read))).unwrap();
        w.advance(1000);
        (w, (t0, t1))
    });
    let alice = w.node(0).account.unwrap();
    if cycle {
        w.write(1, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
    }
    w.write(1, |e| e.grant(&t1, &alice, &edge(Role::Read))).unwrap();
    strong(&mut w, 0, None, t1, true);
    w.run();
    w.heal();
    w.run();
    assert!(w.engine(1).roster(&t1).contains_key(&t0), "Bob holds the sibling's grant");
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1");
    assert_eq!(w.engine(0).roster(&t1), w.engine(1).roster(&t1), "Alice's roster of T1 is Bob's: {}", w.why_role(0, &t1));
}

// The fork alone: a re-seal of the sibling's epoch boxes Alice.
#[test]
fn a_reader_follows_a_forked_sync_id_spec_sync_inbox_5() {
    a_reader_follows_a_forked_sync_id(false);
}

// Bob's grant of T1 on T0 closes a cycle with the sibling's (ordered first, it makes Bob's keyless):
// a rotation of T1, which boxes Alice at the epoch it is wrapped under, replaces the re-seal.
#[test]
fn a_reader_follows_a_forked_sync_id_through_a_rotation_spec_sync_inbox_5() {
    a_reader_follows_a_forked_sync_id(true);
}

// spec/permissions.md §3 (Retain: an ended way by a grant with key access just before its removal
// keeps): Bob grants T1 read on T0 (both his own, the grant with key access) and Alice read on T1 only; she
// holds both. Bob removes T1's grant saying retain: she keeps a copy of T0 and still reads T1.
#[test]
fn an_ended_keyed_grant_keeps_a_copy_spec_permissions_3() {
    let (mut w, (_, t0, t1)) = keyed_way();
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "Alice reads T0 through T1");
    w.write(1, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: t1, new: None, retain: Some(true) })).unwrap();
    w.run();
    assert_eq!(w.engine(0).kept_copies(), vec![t0], "a copy of T0 kept: {}", w.why_role(0, &t0));
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "the copy of T0 reads");
    assert!(w.engine(0).read_secrets(&t0).is_empty(), "T0's secrets go");
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1");
}

// spec/sync-set.md §3 (Release: the node's own writes are served in the pass in flight before
// it drops), spec/permissions.md §3 (Lost access: a node syncing a sync ID of the thing waits for
// a complete pass): Bob grants Alice write on T, which she holds; she writes and drops her
// strong before syncing. Her write reaches Bob before she lets T go.
#[test]
fn an_own_write_before_a_dropped_strong_reaches_its_peer_spec_sync_set_3() {
    let mut w = contacts();
    let alice = w.node(0).account.unwrap();
    let t = make(&mut w, 1, None, "bob");
    w.write(1, |e| e.grant(&t, &alice, &edge(Role::Write))).unwrap();
    strong(&mut w, 0, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t), Some(Value::Str("bob".into())), "Alice reads T");
    // both before the node sends anything
    let a0 = alice;
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("alice".into())).unwrap();
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        m.op(a0, &ct::HOLDS, PathOp { path: vec![], op: Op::Remove(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(value(&mut w, 0, &t), None, "Alice let T go");
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("alice".into())), "Bob holds Alice's write");
}

// spec/permissions.md §3 (Retain: a way by a grant with key access, an ended one's judged just before
// its removal), spec/crypto.md §4 Key access: Bob grants Alice read on T0, mints T1 with admin T0, grants
// T1 read on T0 (keyless) and Alice read on T1; she holds both. Bob removes T1's grant saying retain,
// then removes Alice from T0: the ended keyless grant read nothing of T0, so it keeps her no copy.
#[test]
fn an_ended_keyless_grant_keeps_no_copy_spec_permissions_3() {
    let (mut w, (alice, t0, t1)) = keyless_way();
    assert_eq!(value(&mut w, 0, &t0), Some(Value::Str("t0".into())), "Alice reads T0");
    w.write(1, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: t1, new: None, retain: Some(true) })).unwrap();
    w.run();
    w.write(1, |e| e.demote(&t0, &osis_engine::flows::Demotion { holder: alice, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("t1".into())), "Alice reads T1");
    assert!(w.engine(0).kept_copies().is_empty(), "no copy kept");
    assert_eq!(value(&mut w, 0, &t0), None, "Alice reads T0 no more: {}", w.why_role(0, &t0));
}

/// Node `i` writes its account's inbox setting with `grant@~0` enabled as at creation, or not.
fn inbox_grants(w: &mut World, i: usize, enabled: bool) {
    w.write(i, |e| {
        let me = e.me();
        let inbox = e.inbox_thing(&me).unwrap();
        let mut x = e.get_typed(&inbox, &ct::RETENTION).unwrap().unwrap();
        let keep = ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() };
        if enabled {
            x.rules.insert(Ak::new("grant@~0").unwrap(), keep);
        } else {
            x.rules.remove(&Ak::new("grant@~0").unwrap());
        }
        let mut m = Mutation::new();
        m.set(inbox, &ct::RETENTION, &x).unwrap();
        e.commit(m).unwrap();
    });
}

// spec/sync-inbox.md §4 (A sealed fire), notes/principles.md (work in proportion to change): Bob's
// inbox enables no grant fires; Alice grants Bob read on T, her grant fire deposited sealed at
// Bob's node, which refuses it. Writes of Bob's own elsewhere open the refused deposit no more
// often for being ten times as many; Bob enabling grant fires takes it: the grant is his.
#[test]
#[ignore = "accounts: making an account"]
fn a_refused_sealed_fire_is_opened_again_only_when_what_refused_it_moves_spec_sync_inbox_4() {
    let mut w = contacts();
    inbox_grants(&mut w, 1, false);
    w.run();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    let inbox = w.engine(1).inbox_thing(&bob).unwrap();
    let s = w.engine(1).sync_id_of(&inbox).unwrap().unwrap();
    assert!(w.store(1).entries(&s).unwrap().iter().any(|e| e.deposited && !e.own), "Alice's fire deposited at Bob's node");
    assert_eq!(w.engine(1).role_on(&t), None, "refused: no grant taken");
    let x = make(&mut w, 1, None, "x");
    w.run();
    let opens = |w: &mut World, n: usize| {
        osis_base::costs::take();
        for i in 0..n {
            w.write(1, |e| {
                let mut m = Mutation::new();
                m.set(x, &ak(), &Value::Int(i as i64)).unwrap();
                e.commit(m).unwrap();
            });
            w.run();
        }
        osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "inbox: deposit opened").map(|(.., c)| c).sum::<u64>()
    };
    let (few, many) = (opens(&mut w, 1), opens(&mut w, 10));
    assert!(many <= few, "opens of the refused deposit grow with unrelated writes: {few} at 1, {many} at 10");
    inbox_grants(&mut w, 1, true);
    w.run();
    assert_eq!(w.engine(1).role_on(&t), Some(Role::Read), "enabled: the fire is taken");
}

// spec/sync-inbox.md §3 (opens a deposit it takes): Bob's node 1 reads T, which
// keeps fires of `x:ping@~0`, and fires it, by deposit (it does not write T). Its sibling, node 2,
// also reads T and declares it keeps T unread, so node 1 offers it the Deposit item; Alice
// promotes the deposit in place. Node 2 holds the blob's bytes from the deposit, so the stamp
// fetches nothing: it reads the fire only because it opened the deposit it took.
#[test]
fn a_reader_opens_a_deposit_it_takes_spec_sync_inbox_3() {
    let mut w = siblings();
    w.lie(2, Some(crate::harness::lies::Lie::Declare(osis_proto::SourceClass::Store)));
    let ping = Ak::new("x:ping@~0").unwrap();
    let t = make(&mut w, 0, None, "hi");
    let x = ct::RetentionSetting::of(ping.clone(), osis_schema::History::FOREVER);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ct::RETENTION, &x).unwrap();
        e.commit(m).unwrap();
    });
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    strong(&mut w, 1, None, t, true);
    w.run();
    assert_eq!(value(&mut w, 2, &t), Some(Value::Str("hi".into())), "node 2 reads T");
    w.write(1, |e| e.fire_open(&t, ping.as_str(), Value::Str("ping".into()))).unwrap();
    w.run();
    for i in [0, 1, 2] {
        let fires: Vec<Option<Value>> = w.engine(i).body_page(&t, &ping, true, 0, 10).unwrap().into_iter().map(|b| b.value).collect();
        assert_eq!(fires, [Some(Value::Str("ping".into()))], "node {i} reads Bob's fire");
    }
}
