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

/// A thing node `i` mints with admin `admin` (its account when `None`), held there, value `v`.
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

/// Node `i` adds (`on`) or removes a strong from `from` (its account when `None`) to `t`;
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

/// Node `i` lowers `holder`'s record edge on `t` to `to` (removes it at `None`), leaving `t`
/// adminless if so.
fn lower_record_edge(w: &mut World, i: usize, t: Tid, holder: Tid, to: Option<Role>) {
    w.write(i, |e| e.leaving_adminless(|e| e.demote(&t, &osis_engine::flows::Demotion { holder, new: to.map(edge), retain: None }))).unwrap();
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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

// spec/sync-set.md §1, §2: a key change keeps sync-only holders.
// Bob keeps T unread by a sync grant; Alice rotates T's keys
// and writes: Bob still keeps it unread and his store takes the write.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
    w.write(0, |e| e.make_independent(&t)).unwrap();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "still kept unread");
    assert!(w.store(1).entries(&s).unwrap().len() > before, "the store takes what came after");
}


// spec/permissions.md §3 (Lost access: what was read goes), spec/crypto.md §4 (a reader tries each
// live entry of a history key): Bob reads T across Carol's removal from it (a rotation whose
// history box lists what the new epoch supersedes and who departed); Alice lowers him to sync.
// He keeps T's sync secrets, and what he holds of their history is what a fresh load of his
// store reads.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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

/// Alice (node 0) makes T0 and T1 (`make`: "v1" and "v2"; T1 minted with admin T0 when `of_t0`,
/// else with her account), T0 -> T1. T0, T1 and Bob (node 1's account).
fn t0_holding_t1(w: &mut World, of_t0: bool) -> (Tid, Tid, Tid) {
    let t0 = make(w, 0, None, "v1");
    let t1 = make(w, 0, of_t0.then_some(t0), "v2");
    strong(w, 0, Some(t0), t1, true);
    (t0, t1, w.node(1).account.unwrap())
}

/// Alice's dependent T0 and T1 (minted with admin T0 when `of_t0`, else with her account), T0 -> T1; Bob
/// granted read on T1 and holding it; T1 granted read on T0, its first grant (T0 made independent).
fn shared_through_a_thing(of_t0: bool) -> (World, Tid, Tid) {
    let mut w = contacts();
    let (t0, t1, bob) = t0_holding_t1(&mut w, of_t0);
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_of_a_thing_reads_what_it_is_granted_spec_sync_set_2() {
    let (mut w, t0, t1) = shared_through_a_thing(false);
    strong(&mut w, 0, Some(t1), t0, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("v1".into())), "Bob reads T0");
    assert_eq!(holding(&mut w, 1, &t0), Some(Holding::Read));
}

// spec/permissions.md §3 (Lost access), spec/sync-set.md §3 (Lowering from read to sync): Alice
// mints T1 with admin T0 and grants Bob write on T1 (T1 made independent); she then lowers T0's record edge
// on T1 to sync, her only path to a role on T1. She loses read access to T1: she reads none of
// it and keeps it unread by the sync secret T0's sync role gives; Bob still reads it.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn lowering_the_makers_only_path_to_sync_keeps_the_thing_unread_spec_permissions_3() {
    let mut w = contacts();
    let (t0, t1, bob) = t0_holding_t1(&mut w, true);
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Write))).unwrap();
    w.run();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t1), Some(Value::Str("v2".into())));
    lower_record_edge(&mut w, 0, t1, t0, Some(Role::Sync));
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn the_last_reader_lowered_to_sync_keeps_the_store_for_a_later_reader_spec_sync_judgement_6() {
    let mut w = contacts();
    let (t0, t1, bob) = t0_holding_t1(&mut w, true);
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    w.run();
    lower_record_edge(&mut w, 0, t1, t0, Some(Role::Sync));
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None);
    assert_eq!(holding(&mut w, 0, &t1), Some(Holding::Unread));
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("v2".into())), "Bob holds it later and reads");
}

// spec/commits.md §4 (Pending storage), spec/sync-judgement.md §3 (it opens again each entry of
// it its store still holds), notes/sync.md
// Arriving early: Bob holds T ahead and drops it again just as Alice grants him read, so his
// node receives her grant under his account's sync ID after the release and it pends,
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
    let (t0, t1, bob) = t0_holding_t1(&mut w, true);
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Sync))).unwrap();
    w.run();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t1, &ak(), &Value::Str("v3".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.check_parks();
    lower_record_edge(&mut w, 0, t1, t0, None);
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_self_removal_of_the_makers_only_path_reaches_the_reader_spec_permissions_3() {
    let mut w = contacts();
    let (t0, t1, bob) = t0_holding_t1(&mut w, true);
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert!(w.engine(1).roster(&t1).contains_key(&t0), "Bob reads T0's record edge");
    lower_record_edge(&mut w, 0, t1, t0, None);
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost T1");
    let roster: Vec<Tid> = w.engine(1).roster(&t1).into_keys().collect();
    assert_eq!(roster, vec![bob], "Bob holds the removal");
}

// spec/permissions.md §4 (Notices): cut off from his sibling and from Alice, one of Bob's nodes
// removes Alice from T, never having seen the grant his other node gives her: it sends her
// nothing (no fire, so no header of T's goes to her readers). Alice takes the grant by its fire
// and reads T; after the heal Bob's other node judges her departed and logs a notice of the
// removal under the epoch her grant boxed her, which it serves her alone: she applies the removal
// and reads T no more.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
    assert!(w.engine(2).fires_owed().is_empty(), "the blind remover sends Alice nothing");
    w.run();
    assert_eq!(value(&mut w, 0, &t), Some(Value::Str("v1".into())), "Alice reads T by the grant");
    w.heal();
    w.run();
    assert_eq!(value(&mut w, 0, &t), None, "Alice reads T no more");
}

// spec/permissions.md §4 (Notices), spec/sync-hostile.md (a removed reader learns at most one
// rotation past what it read): Alice grants Bob and Carol read on T, lowers Bob to sync (his node
// keeps T's sync ID as a store, every entry) and then removes Carol. Bob kept the read secrets he
// held, as a hostile node would: none opens a notice of Carol's removal in his store, by its wrap
// or its seal. Carol's node opens one by her account's key and reads T no more.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_lowered_to_sync_opens_no_later_removals_notice_spec_permissions_4() {
    let mut w = World::new(0);
    for _ in 0..3 {
        w.add_node();
    }
    crate::harness::history::introduce(&mut w);
    w.run();
    let t = make(&mut w, 0, None, "v1");
    let (bob, carol) = (w.node(1).account.unwrap(), w.node(2).account.unwrap());
    for (i, h) in [(1, bob), (2, carol)] {
        w.write(0, |e| e.grant(&t, &h, &edge(Role::Read))).unwrap();
        strong(&mut w, i, None, t, true);
    }
    w.run();
    assert_eq!(value(&mut w, 1, &t), Some(Value::Str("v1".into())), "Bob reads T");
    let kept: Vec<(osis_crypto::Epoch, osis_crypto::RoleSecret)> = w.engine(1).epochs(&t).map(|e| e.read.held().map(|(e, s)| (e, s.clone())).collect()).unwrap_or_default();
    w.write(0, |e| e.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(holding(&mut w, 1, &t), Some(Holding::Unread), "Bob keeps T unread");
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let bobs = w.engine(0).notice_rows(&s);
    w.write(0, |e| e.demote(&t, &osis_engine::flows::Demotion { holder: carol, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 2, &t), None, "Carol reads T no more");
    let carols: Vec<_> = w.engine(0).notice_rows(&s).into_keys().filter(|b| !bobs.contains_key(b)).collect();
    assert!(!carols.is_empty(), "Alice logs a notice of Carol's removal");
    for b in &carols {
        let e = w.store(1).entry(&s, b).unwrap().expect("Bob's store holds the notice");
        let bytes = w.bytes(1, b).unwrap();
        for (ep, sec) in &kept {
            assert!(osis_crypto::unwrap(sec.secret(), b, &e.wrap).is_err(), "a kept secret opens no notice's wrap");
            assert!(osis_blob::open_fire(&bytes, &t, ep, sec.kem()).is_err(), "nor its seal");
        }
    }
}

// spec/permissions.md §3 (Lost access; No secret taken back): Bob mints T1 with admin T0 and grants
// Alice read on T0, so she reads T1 through T0. Cut off from his sibling, one of Bob's nodes
// removes her from T0 while the other grants her sync on T1, still boxing her T1's read secret;
// Alice holds T1. Her role there shows only sync, so she keeps T1 unread and reads none of it.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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

/// Bob's node 2 mints T2 with admin T0 (`make_in`, "t2"), grants `alice` sync on it (T2 made
/// independent) and removes T0's record edge on it.
fn unlinked_t2(w: &mut World, t0: Tid, alice: Tid) -> Tid {
    let t2 = make_in(w, 2, t0, "t2");
    w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Sync))).unwrap();
    lower_record_edge(w, 2, t2, t0, None);
    t2
}

// spec/permissions.md §3 (Lost access: a node drops every local unit it can no longer read),
// spec/sync.md §3: Bob's node 2 makes T0 and grants Alice read; his node 1 mints T1 with admin T0;
// Alice holds both. Node 1 removes Alice from T0 while node 2, not yet knowing, grants her sync
// on T1 (T1 made independent). Alice holds only sync on T1 and nothing on T0: she reads neither.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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


/// A thing node 1 mints with admin `admin`, held from its account alone, value `v`, beside
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
// with admin T0, held from his account alone, with a value beside a write to X, which Alice
// holds through T0. She can derive Y's read secret but does not hold Y, so Y's purge request
// never reaches her: she takes Y's record alone, never its value, before the purge or after; she
// reads X. Fails if a node opens the sections of a thing it merely has the secret for. That no
// disk of hers holds the value: flows::a_section_of_a_thing_not_held_leaves_nothing_on_disk
// (osis-engine), the forensic attack on a node of a smaller history.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
// and Bob's commit making Z, held from his account, before he adds T0's strong to it,
// after which the minting reaches her under T0's sync ID. Each time she takes the record, the
// strong brings the thing in, and the section opens again: she reads both.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
        let Some(bytes) = w.bytes(from, &e.blob) else { continue };
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_mint_admins_readers_read_a_thing_no_more_once_its_record_edge_goes_spec_sync_set_2() {
    // in either order the entries are filed again in
    for back in [false, true] {
        let (mut w, (alice, _, t0)) = alice_reads_t0();
        let t2 = unlinked_t2(&mut w, t0, alice);
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
#[ignore = "issues/paired-node-grant-to-its-account.md"]
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

// spec/permissions.md §2 (Granting), §8 (Pairing: a paired node acts for the account at admin):
// Bob's node 1 mints T0 with admin his account and T with admin T0; his paired node 2 grants his
// account admin on T: the grant stands (T's roster lists it), as it does when node 1 writes it.
// Fails: node 2's grant is valid at both nodes but left out of T's roster.
#[test]
#[ignore = "issues/paired-node-grant-to-its-account.md"]
fn repro_a_paired_nodes_grant_to_its_account_stands() {
    let mut w = siblings();
    let bob = w.node(1).account.unwrap();
    let t0 = w.write(1, |e| e.create_with_admin(&bob).unwrap().0);
    let t = w.write(1, |e| e.create_with_admin(&t0).unwrap().0);
    w.run();
    w.write(2, |e| e.grant(&t, &bob, &edge(Role::Admin))).unwrap();
    w.run();
    for i in [1, 2] {
        assert!(w.engine(i).roster(&t).contains_key(&bob), "node {i}: Bob's grant on T stands");
    }
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_down_a_chain_lowered_to_sync_reads_the_thing_no_more_spec_permissions_3() {
    let (mut w, t0, t1, t2) = record_chain_of_three(true);
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())));
    lower_record_edge(&mut w, 1, t2, t1, Some(Role::Sync));
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_grantee_reads_the_minting_value_of_a_dependent_made_independent_spec_sync_judgement_1() {
    let (mut w, (alice, _, t0)) = alice_reads_t0();
    let t2 = make_in(&mut w, 2, t0, "t2");
    w.write(2, |e| e.grant(&t2, &alice, &edge(Role::Admin))).unwrap();
    strong(&mut w, 0, None, t2, true);
    w.run();
    assert_eq!(value(&mut w, 0, &t2), Some(Value::Str("t2".into())), "Alice reads T2's minting value");
}

// spec/permissions.md §3 (Retain: a way alive is a grant with key access), spec/crypto.md §4 Key
// access: Bob grants Alice read on T0, mints T1 with admin T0, grants T1 read on T0 (keyless: T1's key
// derives from T0's) and Alice read on T1; she holds both. Bob removes her from T0: T1's keyless
// grant reads nothing of T0, so it keeps her no copy, and she reads T0 no more.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "issues/kept-copy-through-a-holder.md"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
// Bob's offline sibling grants T0 read on T1, making T1 independent with a sync ID of its own;
// Bob, apart, grants Alice read on T1 (another sync ID), which she holds. Once the sibling is back, every writer syncs
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_follows_a_forked_sync_id_spec_sync_inbox_5() {
    a_reader_follows_a_forked_sync_id(false);
}

// Bob's grant of T1 on T0 closes a cycle with the sibling's (ordered first, it makes Bob's keyless):
// a rotation of T1, which boxes Alice at the epoch it is wrapped under, replaces the re-seal.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_follows_a_forked_sync_id_through_a_rotation_spec_sync_inbox_5() {
    a_reader_follows_a_forked_sync_id(true);
}

// spec/permissions.md §3 (Retain: an ended way by a grant with key access just before its removal
// keeps): Bob grants T1 read on T0 (both his own, the grant with key access) and Alice read on T1 only; she
// holds both. Bob removes T1's grant saying retain: she keeps a copy of T0 and still reads T1.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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
    let account = w.node(i).account.unwrap();
    w.write(i, |e| {
        let inbox = e.inbox_of(&account).unwrap().unwrap();
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_refused_sealed_fire_is_opened_again_only_when_what_refused_it_moves_spec_sync_inbox_4() {
    let mut w = contacts();
    inbox_grants(&mut w, 1, false);
    w.run();
    let t = make(&mut w, 0, None, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
    w.run();
    let inbox = w.engine(1).inbox_of(&bob).unwrap().unwrap();
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
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
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


// spec/sync-set.md §2 Carriers: Bob makes T0 and T1 (minted with admin T0, held from T0) and gives
// Alice's account write on T0, which it holds no strong to; Alice makes T2 and writes T2 -> T1.
// T1 is in her account's unit (its keys open T1 through T0), but no node reading the account holds
// T1 and none of Alice's syncs T0: nothing carries it, and Alice reads nothing of it.
#[test]
fn a_dependent_nobody_carries_into_a_unit_is_not_held_spec_sync_set_2() {
    use crate::harness::script::*;
    let mut w = contacts();
    let _ = crate::harness::play(&mut w, &[New(0), NewIn(0, 0), Give(0, 0, Holder::Node(1), Writes), New(1), Strong(1, Some(2), 1), Run], String::new());
    let t1 = w.history.things[1].0;
    assert!(crate::harness::history::reads(w.engine(0), &t1).value.is_some(), "Bob reads T1");
    assert!(crate::harness::history::reads(w.engine(1), &t1).value.is_none(), "nothing carries T1 to Alice");
}

// spec/sync-set.md §2 Carriers: as above with U, Alice's thing Bob reads and holds, granted write
// on T0 (U holding write on Alice's T3 first, so its keysets carry the KEM keys a granter seals to), and U -> T1 written by Alice before she holds anything of T1. Bob reads U and holds T1
// through T0: a bridge, logging T1 under U's sync ID, from which Alice reads it.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_bridge_carries_a_dependent_into_another_unit_spec_sync_set_2() {
    use crate::harness::script::*;
    let mut w = contacts();
    let steps = [New(0), NewIn(0, 0), New(1), Give(1, 2, Holder::Node(0), Reads), Strong(0, None, 2), New(1), Give(1, 3, Holder::Thing(2), Writes), Run, Give(0, 0, Holder::Thing(2), Writes), Strong(1, Some(2), 1), Run];
    let _ = crate::harness::play(&mut w, &steps, String::new());
    let t1 = w.history.things[1].0;
    assert!(crate::harness::history::reads(w.engine(1), &t1).value.is_some(), "Alice reads T1 through Bob's bridge");
}
