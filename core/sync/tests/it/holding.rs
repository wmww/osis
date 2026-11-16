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
