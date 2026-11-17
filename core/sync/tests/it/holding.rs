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
// T reaches him, the strong is NotCarried. Alice grants Bob read, Bob accepts, then Alice writes
// and drops her own strong: Bob's roster entry and his reads stay.
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
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    strong(&mut w, 0, None, t, false);
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

// spec/sync-set.md §2: refgraph T7. A ticket supplies up to the lower of its own role and the
// holder's; a read ticket whose holder holds sync alone on T keeps T unread, one whose holder
// holds no role enters nothing. Alice grants Bob read and, before he accepts, lowers him to sync
// or removes him; his accept takes the removal notice on his inbox with the ticket's fire, so T
// is kept unread (lowered) or not entered (removed).
#[test]
fn a_ticket_enters_at_the_lower_of_its_role_and_the_holders_spec_sync_set_2() {
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

/// Two nodes of Bob's account (1 and 2, cut off from each other) key Bob's plain T at once: node
/// `first` grants Alice read, the other grants her read too or, with `rotate`, rotates T; each
/// gives T own keys and a sync ID of its own. Alice holds T with only node `first` reachable,
/// then all heal.
/// Whichever she took first, she ends on T's home sync ID and reads T's newest value.
fn keyed_at_once(first: usize, rotate: bool) {
    let mut w = siblings();
    let t = make(&mut w, 1, None, "hi");
    w.run();
    let alice = w.node(0).account.unwrap();
    w.partition(1, 2);
    w.partition(0, 3 - first);
    w.write(first, |e| e.grant(&t, &alice, &edge(Role::Read))).unwrap();
    match rotate {
        true => w.write(3 - first, |e| e.give_own_secrets_again(&t)).unwrap(),
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
    let home = w.engine(1).home_sync_id(&t).unwrap();
    assert_eq!(w.engine(1).sync_ids(&t).unwrap().len(), 2, "first {first}, rotate {rotate}: two sync IDs");
    for i in 0..3 {
        assert_eq!(w.engine(i).home_sync_id(&t).unwrap(), home, "first {first}, rotate {rotate}: node {i}'s home");
    }
    assert_eq!(w.engine(0).roster(&t).get(&alice).map(|e| e.role), Some(Role::Read));
    assert_eq!(value(&mut w, 0, &t), Some(Value::Str("after".into())), "first {first}, rotate {rotate}: Alice reads T");
}

// spec/permissions.md §3, spec/sync-ids.md §2, spec/sync-inbox.md §5 (Ticket sync IDs): two
// siblings make T's first grant to Alice at once; she reads T whichever she took first.
#[test]
fn concurrent_first_grants_by_two_nodes_reach_the_grantee_spec_permissions_3() {
    for first in [1, 2] {
        keyed_at_once(first, false);
    }
}

// spec/permissions.md §3, spec/sync-ids.md §2, spec/sync-inbox.md §5 (Ticket sync IDs): one
// sibling grants Alice read on T while another gives T own keys by a rotation; she reads T's
// newest value whichever sibling granted (so whether hers is the home sync ID or not).
#[test]
fn a_grant_beside_a_siblings_keying_reaches_the_grantee_spec_permissions_3() {
    for first in [1, 2] {
        keyed_at_once(first, true);
    }
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


// spec/permissions.md §3 (Lost access: what was read goes), spec/crypto.md §4 (an epoch's history
// is what its live entries say): Bob reads T across Carol's removal from it (a rotation whose
// history box lists what the new epoch supersedes and who departed); Alice lowers him to sync.
// He keeps T's sync secrets, and what he holds of their history is what a fresh load of his
// store reads.
#[test]
fn a_reader_lowered_to_sync_keeps_its_sync_epochs_as_a_load_reads_them_spec_permissions_3() {
    let mut w = crate::harness::history::world(0, 3);
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

// spec/sync-set.md §1, §2 (refgraph U4): a node's local part. A node of an account makes a plain
// thing under its node root, held from there: the node writes it as itself, holds and reads it,
// and no sync ID carries it, so its sibling never holds it.
#[test]
fn a_thing_under_the_node_root_stays_on_its_node_spec_sync_set_2() {
    let mut w = siblings();
    let x = w.write(1, |e| {
        let root = e.node_root().unwrap();
        let mut m = Mutation::new();
        let x = m.create(e.thing_record(root));
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

/// Alice's plain T0 and T1 (under T0 when `under`, else under her account root), T0 -> T1; Bob
/// granted read on T1 and holding it; T1 granted read on T0, its first grant (T0's own keys).
fn shared_through_a_thing(under: bool) -> (World, Tid, Tid) {
    let mut w = contacts();
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, under.then_some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    w.write(0, |e| e.grant(&t0, &t1, &edge(Role::Read))).unwrap();
    (w, t0, t1)
}

// spec/sync-set.md §2 (refgraph U5 across nodes), spec/sync-judgement.md §1 Per-sync-ID copies:
// T1 granted read on T0 (T0's first grant) and T1 -> T0: Bob, a reader of T1, reads T0 and what
// was written on it before it had own keys. T0's role commits reach him under T1's sync ID as
// per-sync-ID copies, logged though a certificate copy of fewer parts was logged there first.
#[test]
fn a_reader_of_a_thing_reads_what_it_is_granted_spec_sync_set_2() {
    let (mut w, t0, t1) = shared_through_a_thing(false);
    strong(&mut w, 0, Some(t1), t0, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("v1".into())), "Bob reads T0");
    assert_eq!(holding(&mut w, 1, &t0), Some(Holding::Read));
}

// spec/crypto.md §4 Key access, spec/sync-set.md §2: T1 is made under T0, so T1 granted read on
// T0 closes a cycle and is keyless: it reads nothing through it. Bob, a reader of T1, never reads
// T0, whether T1 references it or he holds it from his account root and is granted sync on it
// (then he keeps it unread, his ticket a sync one).
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

// spec/sync-set.md §2 (What a held ticket does), §4 (Declining is doing nothing): Alice's T1 is
// made under T0 and held from it; Bob keeps T1 unread by a sync ticket, then is granted read on
// T0, T1's first admin, which gives him read on T1 by chain. A ticket's secret is taken only at a
// strong to its thing, so until he accepts T0 he holds no secret of T0, no role commit of T1 and
// no read secret of T1: T1 stays unread. Accepting T0, he reads T1.
#[test]
fn a_read_role_by_chain_through_an_unaccepted_thing_reads_nothing_spec_sync_set_4() {
    let mut w = contacts();
    let t0 = make(&mut w, 0, None, "v1");
    let t1 = make(&mut w, 0, Some(t0), "v2");
    strong(&mut w, 0, Some(t0), t1, true);
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Sync))).unwrap();
    w.run();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(holding(&mut w, 1, &t1), Some(Holding::Unread), "kept unread by the sync ticket");
    w.write(0, |e| e.grant(&t0, &bob, &edge(Role::Read))).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t1), None, "T0 not accepted: Bob reads no T1");
    assert_eq!(holding(&mut w, 1, &t1), Some(Holding::Unread));
    strong(&mut w, 1, None, t0, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("v2".into())), "T0 accepted: Bob reads T1");
    assert_eq!(holding(&mut w, 1, &t1), Some(Holding::Read));
}

// spec/permissions.md §3 (Lost access), spec/sync-set.md §3 (Lowering from read to sync): Alice
// makes T1 under T0 and grants Bob write on T1 (T1's own keys); she then lowers T0's record edge
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
    w.write(0, |e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("v2".into())), "Bob still reads T1");
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost read on T1");
    assert_eq!(holding(&mut w, 0, &t1), Some(Holding::Unread), "she keeps it unread at sync");
}

// spec/sync-judgement.md §6 (Read and unread move), spec/sync.md §3 (Held sync secrets): Alice,
// T1's only reader, grants Bob read on it and lowers T0's record edge on T1 to sync. She keeps
// T1 unread by the sync secret held from her own reading, its store kept: Bob, accepting only
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
    w.write(0, |e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: Some(edge(Role::Sync)), retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None);
    assert_eq!(holding(&mut w, 0, &t1), Some(Holding::Unread));
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(value(&mut w, 1, &t1), Some(Value::Str("v2".into())), "Bob accepts later and reads");
}

// spec/permissions.md §3 (Lost access): Alice makes T1 under T0, grants Bob sync on it, writes,
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
    w.write(0, |e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None })).unwrap();
    w.check_parks();
    w.run();
    w.check_parks();
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost T1");
}


// spec/permissions.md §3 (Lost access: a node that lost read through its own self-removal drops
// once the commit is held elsewhere): Alice makes T1 under T0 and grants Bob read; Bob accepts.
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
    w.write(0, |e| e.demote(&t1, &osis_engine::flows::Demotion { holder: t0, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(value(&mut w, 0, &t1), None, "Alice lost T1");
    let roster: Vec<Tid> = w.engine(1).roster(&t1).into_keys().collect();
    assert_eq!(roster, vec![bob], "Bob holds the removal");
}

// spec/sync-inbox.md §5 (Removal notice): cut off from his sibling, one of Bob's nodes removes
// Alice from T, never having seen the grant his other node gives her. The removal stands; its
// writer, holding no grant as it wrote it, fired no notice. Every node applying it with the
// grant held owes one (the sibling, and the writer once the grant reaches it), and Alice, who
// reads T by the grant, takes it and reads T no more.
#[test]
fn a_removal_its_writer_made_blind_reaches_the_removed_reader_spec_sync_inbox_5() {
    let mut w = siblings();
    let t = make(&mut w, 1, None, "v1");
    let alice = w.node(0).account.unwrap();
    strong(&mut w, 0, None, t, true);
    w.run();
    w.partition(1, 2);
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

// spec/permissions.md §3 (Lost access, No secret taken back): Bob makes T1 under T0 and grants
// Alice read on T0, so she reads T1 by the chain. Cut off from his sibling, one of Bob's nodes
// removes her from T0 while the other grants her sync on T1, still boxing her T1's read secret;
// Alice accepts T1. Her role there shows sync alone, so she keeps T1 unread and reads none of it.
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

// spec/sync-inbox.md §5 (Ticket sync IDs), spec/sync-set.md §2 (What a held ticket does): Alice
// grants Bob read on T, lowers him to sync and grants read again, each a ticket on his inbox;
// Bob's sibling accepts T. T, entered on the tickets' word, moves to read once its role commits
// make it keyed, while no `sync.0` of it is held: the tickets' sync ID stays synced through the
// move, the one way that `sync.0` arrives, and both of Bob's nodes read T.
#[test]
fn a_thing_entered_on_a_ticket_keeps_its_sync_id_as_it_gains_own_keys_spec_sync_inbox_5() {
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

// spec/sync-judgement.md §2 (A grant naming a holder travels under the holder's sync ID with the
// target's sync record), spec/sync-set.md §2: Alice grants H read on T; Bob reads H and holds T
// from his account root, not from H. His keys open T by the chain through H; the grant travels
// under H's sync ID with T's sync record, so he learns T's sync ID and reads T, though no one
// writes him a ticket and he may not write H.
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

// spec/sync-inbox.md §5 (Delivery of a grant), spec/sync-judgement.md §2 (A grant naming a
// holder): Bob's T1 holds T0 by a strong; Alice, who knows T1's public key record but neither
// reads nor syncs T1 (she reads T4, holder on T3 made under T1), grants T1 read on T0. Bob, T1's
// reader, then reads T0 through T1.
#[test]
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
    assert_eq!(value(&mut w, 1, &t0), Some(Value::Str("t0".into())), "Bob reads T0 through T1");
    assert_eq!(holding(&mut w, 1, &t0), Some(Holding::Read));
    // T3's chain was needed by T4 alone (spec/commits.md §5 What a held thing needs): released
    // with it
    assert!(w.engine(0).first_admin(&t3).is_some(), "Alice holds T3's record while T4 is held");
    strong(&mut w, 0, None, t4, false);
    w.run();
    assert_eq!(w.engine(0).first_admin(&t3), None, "T3's record goes with T4");
}

// spec/sync-inbox.md §5 (Nothing before the strong), spec/sync-set.md §2 (What a held ticket
// does): Bob held T1 by a read ticket, then lost his own grant; T1 is granted sync to T0 and Bob
// sync on T0, which he has not accepted. T0's grant to Bob is taken only at a strong to T0, so he
// holds no role on T0 and none on T1 through it: his strong to T1 holds nothing.
#[test]
fn a_role_by_chain_through_an_unaccepted_thing_counts_nothing_spec_sync_inbox_5() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let t0 = make(&mut w, 0, None, "t0");
    let t1 = make(&mut w, 0, None, "t1");
    w.write(0, |e| e.grant(&t1, &bob, &edge(Role::Read))).unwrap();
    strong(&mut w, 1, None, t1, true);
    w.run();
    assert_eq!(holding(&mut w, 1, &t1), Some(Holding::Read));
    w.write(0, |e| e.grant(&t1, &t0, &edge(Role::Sync))).unwrap();
    w.write(0, |e| e.demote(&t1, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None })).unwrap();
    w.write(0, |e| e.grant(&t0, &bob, &edge(Role::Sync))).unwrap();
    w.run();
    assert_eq!(holding(&mut w, 1, &t1), None, "T0 unaccepted: no role on T1 through it");
    assert_eq!(value(&mut w, 1, &t1), None);
}

/// A thing node `i` makes under `admin`, held from `admin` alone, value `v`.
fn make_in(w: &mut World, i: usize, admin: Tid, v: &str) -> Tid {
    let v = v.to_owned();
    w.write(i, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin));
        m.set(t, &ak(), &Value::Str(v)).unwrap();
        m.op(admin, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

// spec/sync-judgement.md §3 (Dropped bodies: what is forgotten with a released thing is fetched
// again once a strong in the node closure reaches it again), spec/sync-set.md §3: Bob's T0 holds
// X and Y, made under it; Alice reads T0. Bob's node 1 removes T0 -> X while his node 2, cut off,
// writes Y -> X: Alice and node 1 release X, then Y -> X reaches them and they read X again.
#[test]
fn a_released_thing_reached_again_is_fetched_again_spec_sync_judgement_3() {
    let mut w = siblings();
    let alice = w.node(0).account.unwrap();
    let t0 = make(&mut w, 1, None, "t0");
    let x = make_in(&mut w, 1, t0, "x");
    let y = make_in(&mut w, 1, t0, "y");
    w.write(1, |e| e.grant(&t0, &alice, &edge(Role::Read))).unwrap();
    strong(&mut w, 0, None, t0, true);
    w.run();
    assert_eq!(value(&mut w, 0, &x), Some(Value::Str("x".into())), "Alice reads X");
    w.partition(0, 2);
    w.partition(1, 2);
    strong(&mut w, 1, Some(t0), x, false);
    w.run();
    assert_eq!(value(&mut w, 0, &x), None, "released at Alice");
    assert_eq!(value(&mut w, 1, &x), None, "released at node 1");
    strong(&mut w, 2, Some(y), x, true);
    w.heal();
    w.run();
    for i in 0..3 {
        assert_eq!(value(&mut w, i, &x), Some(Value::Str("x".into())), "node {i} reads X again");
    }
}

// spec/sync-judgement.md §2 (A grant naming a holder travels under the holder's sync ID with the
// target's sync record), spec/permissions.md §3 (Lost access forgets what only the lost secrets
// read): Alice's node 2 makes T0 and T1 and grants Bob read on T0 while her node 0 grants T0 sync
// on T1. Bob, reading T0, takes T0's certificates of T1 (its minting as a header alone, its sync
// record, its boxes to T0), so he holds T1's sync secrets and no read: he loses access to T1,
// which must not forget the minting's header, read by no secret of T1.
#[test]
fn a_reader_of_a_holder_holds_its_targets_sync_record_spec_sync_judgement_2() {
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


// spec/sync-set.md §2 (What a held ticket does), spec/permissions.md §3 (Lost access): Bob reads
// T1, which Alice granted sync on T2 and then removed, so T1's certificates bring Bob T2's sync
// record and the role commits naming T1 alone. Alice grants Bob sync on T2 directly and he
// accepts it after T1: those role commits show no role of his on T2, so they neither keep his ticket out nor
// drop the sync secrets it gives. He keeps T2 unread.
#[test]
fn a_sync_ticket_beside_a_removed_holders_role_commits_keeps_the_thing_unread_spec_sync_set_2() {
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
