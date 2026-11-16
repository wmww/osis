//! Entering a thing by a ticket over real connections (spec/sync-inbox.md §5 Ticket sync IDs,
//! spec/sync-set.md §2, spec/sync-hostile.md): a grant's ticket reaches the grantee's inbox, the
//! grantee accepts, syncs the ticket's sync ID and reads the thing; a ticket's sync ID is its
//! issuer's word, so a forged one pulls in and cuts off nothing.

use crate::harness::{World, contacts};
use osis_base::{Ak, Role, SyncId, Tid, Ticket, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

fn ak() -> Ak {
    Ak::new("x:v.0").unwrap()
}

/// A thing node `i` makes under its account root, which holds it, with value `v`.
fn make(w: &mut World, i: usize, v: &str) -> Tid {
    let v = v.to_owned();
    w.write(i, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, d);
        m.set(t, &ak(), &Value::Str(v)).unwrap();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

/// Node 0 makes T and grants node 1's account read on it; run: the ticket reaches node 1.
fn granted() -> (World, Tid) {
    let mut w = contacts();
    let t = make(&mut w, 0, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &ct::Edge { role: Role::Read, until: None, invite: None, floor: None })).unwrap();
    w.run();
    (w, t)
}

/// Node 1 writes `tickets` into its account root and accepts `t` (a strong there); run.
fn accept(w: &mut World, t: Tid, tickets: &[Ticket]) {
    let tickets = tickets.to_vec();
    w.write(1, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        for k in tickets {
            m.op(d, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(k))) }).unwrap();
        }
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
}

/// Node 1's ticket for `t`, its sync ID replaced by `s`: what any holder of node 1's account's
/// public record could box (a ticket is unsigned).
fn forged(w: &mut World, t: &Tid, s: SyncId) -> Ticket {
    let k = w.engine(1).ticket_for(t).unwrap().expect("the grant's ticket");
    Ticket { sync_id: s, ..k }
}

// spec/sync-inbox.md §5 (Delivery of a grant, Ticket sync IDs), spec/sync-set.md §4 (Accepting):
// Alice grants Bob read on T; her ticket reaches Bob's inbox; Bob accepts by a strong in his
// account root, syncs the ticket's sync ID over real connections and reads T, then holds it by
// its own `sync.0`.
#[test]
fn an_accepted_ticket_syncs_its_thing_spec_sync_inbox_5() {
    let (mut w, t) = granted();
    let k = w.engine(1).ticket_for(&t).unwrap().expect("the ticket reached Bob's inbox");
    accept(&mut w, t, &[]);
    assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T");
    assert!(w.engine(1).closure_holds(&t));
    assert_eq!(w.engine(1).sync_holder(&k.sync_id).unwrap(), Some(([t].into(), Holding::Read)), "T's own sync ID");
}

// spec/sync-hostile.md (a ticket's sync ID is its issuer's word), spec/sync-inbox.md §5 Ticket
// sync IDs: beside the grant's ticket, Bob holds one for T naming the sync ID of Alice's profile,
// which Bob reads as her contact, and one naming the sync ID of a thing of Alice's he may not
// read. The first cuts nothing off (the profile keeps its sync ID); the second pulls nothing in
// (nothing of that thing reaches Bob); the genuine one is fetched and T read.
#[test]
fn a_forged_ticket_sync_id_pulls_in_and_cuts_off_nothing_spec_sync_hostile() {
    let (mut w, t) = granted();
    let p0 = w.node(0).profile.unwrap();
    let sp = w.engine(1).home_sync_id(&p0).unwrap().expect("Bob syncs Alice's profile");
    assert_eq!(w.engine(1).sync_holder(&sp).unwrap(), Some(([p0].into(), Holding::Read)));
    // Alice's inbox: own keys, read by her nodes alone
    let a0 = w.node(0).account.unwrap();
    let x = w.engine(0).inbox_thing(&a0).unwrap();
    let sx = w.engine(0).home_sync_id(&x).unwrap().expect("the inbox's sync ID");
    let ks = [forged(&mut w, &t, sp), forged(&mut w, &t, sx)];
    accept(&mut w, t, &ks);
    assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T by its genuine ticket");
    assert_eq!(w.engine(1).sync_holder(&sp).unwrap(), Some(([p0].into(), Holding::Read)), "the profile keeps its sync ID");
    // the profile still syncs: Alice's next write on it reaches Bob
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(p0, &ak(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).get(&p0, &ak()).unwrap(), Some(Value::Str("new".into())), "the profile syncs");
    assert!(w.store(1).entries(&sx).unwrap().is_empty(), "nothing of x under its sync ID at Bob");
    assert!(!w.engine(1).closure_holds(&x) && w.engine(1).get(&x, &ak()).unwrap().is_none(), "x is not pulled in");
    assert!(!w.engine(1).sync_set().unwrap().ids.contains_key(&sx), "T's own sync.0 held: the forged ID is no longer fetched");
}


// spec/sync-set.md §1 (The account's tickets), §2: a node paired to an account enters the
// account's profile by D's ticket for it, though the secrets its account's boxes give read the
// profile as derived from the account until the profile's keyset arrives: it holds the profile
// and syncs its sync ID, across a restart.
#[test]
fn a_paired_node_enters_the_profile_by_ds_ticket_spec_sync_set_1() {
    let mut w = crate::harness::siblings();
    let p = w.node(1).profile.unwrap();
    let s = w.engine(1).home_sync_id(&p).unwrap().expect("the profile's sync ID");
    for restart in [false, true] {
        if restart {
            w.power_off(2);
            w.power_on(2);
            w.run();
        }
        assert!(w.engine(2).closure_holds(&p), "the paired node holds the profile (restart {restart})");
        assert_eq!(w.engine(2).sync_holder(&s).unwrap(), Some(([p].into(), Holding::Read)), "and syncs its sync ID (restart {restart})");
    }
}

// spec/sync-inbox.md §5 Ticket sync IDs (refgraph T5), spec/sync-hostile.md: Alice grants Bob
// read on A and B; Bob accepts both at once, holding beside their tickets one for the lower tid
// naming the other's sync ID (a writer of something Bob holds can have him accept one). That sync
// ID is synced once for both, so each thing still fetches its own and Bob reads both. What
// arrives under it is judged for each: engine `tickets::a_sync_id_two_things_tickets_name_is_judged_for_each_spec_sync_inbox_5`.
#[test]
fn a_forged_ticket_naming_another_accepted_things_sync_id_blocks_no_fetch_spec_sync_inbox_5() {
    let mut w = contacts();
    let bob = w.node(1).account.unwrap();
    let mut ts = Vec::new();
    for v in ["a", "b"] {
        let t = make(&mut w, 0, v);
        w.write(0, |e| e.grant(&t, &bob, &ct::Edge { role: Role::Read, until: None, invite: None, floor: None })).unwrap();
        ts.push((t, v));
    }
    w.run();
    ts.sort();
    let ((lo, v_lo), (hi, v_hi)) = (ts[0], ts[1]);
    let s_hi = w.engine(1).ticket_for(&hi).unwrap().expect("hi's ticket").sync_id;
    let k = forged(&mut w, &lo, s_hi);
    w.write(1, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        m.op(d, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(k))) }).unwrap();
        for t in [lo, hi] {
            m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        }
        e.commit(m).unwrap();
    });
    // until the higher's own `sync.0` arrives, its sync ID is in the sync set for both (a sync.0
    // reaching Bob another way ends the claim sooner: what Bob reads then does not tell the rule)
    assert_eq!(w.engine(1).sync_held(&s_hi).unwrap(), Some(([lo, hi].into(), Holding::Read)), "synced once, for both");
    w.run();
    assert_eq!(w.engine(1).get(&lo, &ak()).unwrap(), Some(Value::Str(v_lo.into())), "Bob reads the lower");
    assert_eq!(w.engine(1).get(&hi, &ak()).unwrap(), Some(Value::Str(v_hi.into())), "Bob reads the higher");
    assert_eq!(w.engine(1).sync_holder(&s_hi).unwrap(), Some(([hi].into(), Holding::Read)), "its own sync.0 held: the higher's sync ID is its alone");
}

/// Deliveries to every node over a long quiet spell after `w` ran (a retry loop shows here).
fn quiet_deliveries(w: &mut World) -> u64 {
    let d = w.deliveries;
    w.advance(20 * osis_sync::types::RESYNC_MS);
    w.deliveries - d
}

// spec/sync-hostile.md, spec/sync-inbox.md §5 (refgraph T5's other forged cases): beside the
// grant's ticket for T, Bob accepts a ticket for T at an epoch not T's (stale), or one for a
// thing its issuer does not hold, naming T's sync ID. Each opens nothing (Bob reads T by the
// genuine one; the other thing is not held) and nothing is retried: the quiet spell after costs
// what it costs with no forged ticket.
#[test]
fn a_stale_or_unheld_targets_forged_ticket_opens_and_retries_nothing_spec_sync_hostile() {
    let base = {
        let (mut w, t) = granted();
        accept(&mut w, t, &[]);
        quiet_deliveries(&mut w)
    };
    for arm in ["stale epoch", "unheld target"] {
        let (mut w, t) = granted();
        let k = w.engine(1).ticket_for(&t).unwrap().expect("the grant's ticket");
        let x = osis_base::Tid::from_bytes([0x5a; 15]);
        let bad = match arm {
            "stale epoch" => {
                assert!(k.epoch.0 > 0, "T was keyed past its first epoch");
                Ticket { epoch: (k.epoch.0 - 1, k.epoch.1), ..k.clone() }
            }
            _ => Ticket { target: x, ..k.clone() },
        };
        accept(&mut w, t, &[bad]);
        if arm == "unheld target" {
            w.write(1, |e| {
                let d = e.account_root().unwrap();
                let mut m = Mutation::new();
                m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(x)) }).unwrap();
                e.commit(m).unwrap();
            });
            w.run();
            assert!(!w.engine(1).closure_holds(&x) && !w.engine(1).in_sync_things(&x).unwrap(), "{arm}: x is not entered");
        }
        assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "{arm}: Bob reads T by its genuine ticket");
        assert_eq!(w.engine(1).sync_holder(&k.sync_id).unwrap(), Some(([t].into(), Holding::Read)), "{arm}: T's sync ID is T's");
        assert_eq!(quiet_deliveries(&mut w), base, "{arm}: nothing retried");
    }
}
