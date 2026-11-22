//! Entering a thing by a ticket over real connections (spec/sync-inbox.md §5 Ticket sync IDs,
//! spec/sync-set.md §2, spec/sync-hostile.md): a grant's ticket reaches the grantee's inbox, the
//! grantee accepts, syncs the ticket's sync ID and reads the thing; a ticket's sync ID is its
//! issuer's word, so a forged one pulls in and cuts off nothing.

use crate::harness::{World, contacts, edge, fixture_with};
use osis_base::{Ak, Role, SyncId, Tid, Ticket, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

fn ak() -> Ak {
    Ak::new("x:v.0").unwrap()
}

/// A thing node `i` mints with its account root as admin, which holds it, with value `v`.
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

/// Node 0 makes T and grants node 1's account read on it; run: the ticket reaches node 1. Built
/// once per process (`fixture_with`).
fn granted() -> (World, Tid) {
    fixture_with("tickets granted", || {
        let mut w = contacts();
        let t = make(&mut w, 0, "hi");
        let bob = w.node(1).account.unwrap();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
        w.run();
        (w, t)
    })
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

// spec/sync-inbox.md §5 (Delivery of a grant; Ticket sync IDs), spec/sync-set.md §4 (Accepting):
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

// spec: none (debug dumps, notes/test-harnesses.md): after Bob accepts Alice's grant,
// `sync_ids_of` shows each node syncing T's sync ID and Bob holding its ticket; `describe_commit`
// names Alice's next write on T; the settle round counters count that write's steps.
#[test]
fn debug_dumps_name_sync_ids_commits_and_rounds() {
    let (mut w, t) = granted();
    let k = w.engine(1).ticket_for(&t).unwrap().expect("the ticket reached Bob's inbox");
    accept(&mut w, t, &[]);
    let s = crate::harness::trace::short(&k.sync_id);
    let d = w.sync_ids_of(&t);
    let lines: Vec<&str> = d.lines().collect();
    assert!(lines[0].starts_with(&format!("n0: syncs [{s} ")), "{d}");
    assert!(lines[1].starts_with(&format!("n1: syncs [{s} ")) && lines[1].contains(&format!("ticket {s} Read")), "{d}");
    osis_base::costs::take();
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("again".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let costs: std::collections::BTreeMap<&str, u64> = osis_base::costs::take().into_iter().map(|(n, _, k)| (n, k)).collect();
    let (steps, rounds, most) = (costs["settle steps"], costs["settle rounds"], costs["settle rounds most"]);
    assert!(steps > 0 && rounds >= steps && most <= crate::harness::ROUND_CAP && costs["settle follows moved"] <= rounds, "{costs:?}");
    #[cfg(debug_assertions)]
    {
        let d = w.describe_commit(&c);
        assert!(d.contains("Content by ") && d.contains("(n0 account)") && d.contains(&format!("{t} x:v.0")), "{d}");
    }
    let _ = c;
}

// spec/sync-hostile.md (a ticket's sync ID is its issuer's word), spec/sync-inbox.md §5 Ticket
// sync IDs: beside the grant's ticket, Bob holds one for T naming the sync ID of Alice's profile,
// which Bob reads as her contact, and one naming the sync ID of a thing of Alice's he may not
// read. The first cuts nothing off (the profile keeps its sync ID); the second pulls nothing in
// (that thing is neither held nor read at Bob; issues/forged-ticket-sync-id-entries.md for the
// entries he stores under its sync ID meanwhile); the genuine one is fetched and T read.
#[test]
fn a_forged_ticket_sync_id_pulls_in_and_cuts_off_nothing_spec_sync_hostile() {
    let (mut w, t) = granted();
    let p0 = w.node(0).profile.unwrap();
    let sp = w.engine(1).sync_id_of(&p0).unwrap().expect("Bob syncs Alice's profile");
    assert_eq!(w.engine(1).sync_holder(&sp).unwrap(), Some(([p0].into(), Holding::Read)));
    // Alice's inbox: independent, read by her nodes alone
    let a0 = w.node(0).account.unwrap();
    let x = w.engine(0).inbox_thing(&a0).unwrap();
    let sx = w.engine(0).sync_id_of(&x).unwrap().expect("the inbox's sync ID");
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
    assert!(!w.engine(1).closure_holds(&x) && w.engine(1).get(&x, &ak()).unwrap().is_none(), "x is not pulled in");
    // the forged ID, which T's held `sync.0` does not record, stays fetched while its ticket is
    // held (it could be another admin's keying, spec/sync-inbox.md §5), opening nothing
    assert_eq!(w.engine(1).sync_holder(&sx).unwrap().map(|(ts, _)| ts), Some([t].into()), "T's alone at Bob");
}


// spec/sync-set.md §1 (The account's tickets), §2: a node paired to an account enters the
// account's profile by D's ticket for it, though the secrets its account's boxes give read the
// profile as derived from the account until the profile's keyset arrives: it holds the profile
// and syncs its sync ID, across a restart.
#[test]
fn a_paired_node_enters_the_profile_by_ds_ticket_spec_sync_set_1() {
    let mut w = crate::harness::siblings();
    let p = w.node(1).profile.unwrap();
    let s = w.engine(1).sync_id_of(&p).unwrap().expect("the profile's sync ID");
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

// spec/sync-inbox.md §5 Ticket sync IDs, spec/sync-hostile.md: Alice grants Bob
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
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
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

// spec/sync-hostile.md, spec/sync-inbox.md §5 (S's things: a forged claim only adds a thing whose
// secrets open nothing there): beside the
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

// spec/sync-inbox.md §1, §5 (Delivery of a grant): an account that paired a second node before
// its contact card was made is reached all the same: its contact knows its inbox and a grant's
// ticket reaches it.
#[test]
fn a_card_made_after_pairing_carries_the_inbox_spec_sync_inbox_5() {
    let mut w = World::new(0);
    w.add_node();
    w.add_node();
    w.pair(0);
    crate::harness::history::introduce(&mut w);
    w.run();
    let a0 = w.node(0).account.unwrap();
    assert!(w.engine(1).inbox_thing(&a0).is_some(), "node 1 knows account 0's inbox");
    let t = make(&mut w, 1, "hi");
    w.write(1, |e| e.grant(&t, &a0, &edge(Role::Read))).unwrap();
    w.run();
    assert!(w.engine(0).ticket_for(&t).unwrap().is_some(), "the ticket reached account 0");
}

// spec/sync-set.md §2, spec/sync-ids.md §5: a ticket it can open enters the thing at a
// strong, and the store is the truth after a crash. Bob's node loses power at the second durable
// write of its accept of a granted thing (the write's outcome unknown) and restarts in place. Its
// strong and the ticket stand, so it enters the thing and reads it.
#[test]
fn a_crash_after_accepting_keeps_the_thing_entered_spec_sync_set_2() {
    let (mut w, t) = granted();
    w.disk_fault(1, 2, crate::harness::DiskFault::Crash);
    let r = w.write(1, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).map(|_| ())
    });
    assert!(r.is_err() && w.crashes == 1, "the accept's write crashed, its outcome unknown");
    w.run();
    let d = w.engine(1).account_root().unwrap();
    assert!(w.engine(1).get_typed(&d, &ct::HOLDS).unwrap().unwrap_or_default().contains(&osis_base::Ref::Strong(osis_base::Strong(t))), "the strong stands");
    assert!(w.engine(1).ticket_for(&t).unwrap().is_some(), "the ticket stands");
    assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T");
}

/// Node 0 makes T and gives node 1's account `role` on it; node 1 accepts; run.
fn accepted(role: Role) -> (World, Tid) {
    let mut w = contacts();
    let t = make(&mut w, 0, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &ct::Edge { role, until: None, invite: None, retain: false, floor: None })).unwrap();
    w.run();
    accept(&mut w, t, &[]);
    (w, t)
}

/// Node `i` adds (`on`) or removes its account root's strong to `t`; run.
fn root_strong(w: &mut World, i: usize, t: Tid, on: bool) {
    w.write(i, |e| {
        let d = e.account_root().unwrap();
        let mut m = Mutation::new();
        let v = Value::Strong(t);
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: if on { Op::Add(v) } else { Op::Remove(v) } }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
}

// spec/permissions.md §2, spec/sync-set.md §2: a re-granted reader reads again; the node enters
// at its role as the role commits it holds show. Alice removes Bob from T (or lowers
// him to sync), then grants him read again; Bob, his strong kept, reads her next write: the new
// ticket's fire carries the grant (wrapped under a secret Bob lacks), taken at his strong, so the
// role commits he holds give read again.
#[test]
fn a_reader_granted_again_reads_again_spec_sync_set_2() {
    for lowered in [false, true] {
        let (mut w, t) = accepted(Role::Read);
        let bob = w.node(1).account.unwrap();
        let new = lowered.then_some(edge(Role::Sync));
        w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new, retain: None })).unwrap();
        w.run();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read))).unwrap();
        w.run();
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(t, &ak(), &Value::Str("again".into())).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("again".into())), "lowered {lowered}: Bob reads again");
    }
}

// spec/sync-set.md §2: a ticket supplies up to the lower of its role and the holder's, judged
// again as either changes, and nothing it does undoes itself. Alice removes Bob from T; his strong and
// the stale ticket stay. He enters nothing, and nothing is fetched again over a quiet spell: the
// role commits that judged the ticket stay while the strong and the ticket do, so his release of
// T does not make the ticket's word count again (a stale ticket taken and dropped in turn).
#[test]
fn a_stale_ticket_enters_nothing_and_is_not_retaken_spec_sync_set_2() {
    let removed = |keep: bool| {
        let (mut w, t) = accepted(Role::Read);
        let bob = w.node(1).account.unwrap();
        w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new: None, retain: None })).unwrap();
        w.run();
        if !keep {
            root_strong(&mut w, 1, t, false);
        }
        (w, t)
    };
    let base = quiet_deliveries(&mut removed(false).0);
    let (mut w, t) = removed(true);
    assert!(w.engine(1).ticket_for(&t).unwrap().is_some(), "the stale ticket is still held");
    assert!(!w.engine(1).in_sync_things(&t).unwrap() && w.engine(1).get(&t, &ak()).unwrap().is_none(), "entered nothing");
    assert_eq!(quiet_deliveries(&mut w), base, "nothing fetched again");
    assert!(!w.engine(1).in_sync_things(&t).unwrap(), "still nothing entered");
}

/// D's tickets for `t` at node `i`, by (sync ID, epoch n).
fn d_tickets(w: &mut World, i: usize, t: &Tid) -> Vec<(SyncId, u64)> {
    let d = w.engine(i).account_root().unwrap();
    w.engine(i).get_typed(&d, &ct::TICKETS).unwrap().unwrap_or_default().iter().filter(|k| k.target == *t).map(|k| (k.sync_id, k.epoch.0)).collect()
}

/// Node 1 holds `k` in its profile, which any writer of a thing it holds could have it hold; run.
fn hold_in_profile(w: &mut World, k: Ticket) {
    let profile = w.node(1).profile.unwrap();
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.op(profile, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(k))) }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
}

// spec/sync-set.md §1 (The account's tickets), spec/sync.md §3 (Kept sync IDs), spec/crypto.md
// §4 Uses: Bob keeps T unread by Alice's sync grant. A ticket for T naming its sync ID at a
// higher epoch with a secret of its maker's choosing (what any holder of Bob's public record can
// box), held before Bob accepts T or after, is established by no step of T's path, so D's ticket
// boxes the grant's secret and never the forged one: a node of Bob's paired later enters T by
// D's tickets alone. A genuine rotation's secret, which the next step bears, replaces it in D.
#[test]
fn ds_ticket_for_a_thing_kept_unread_boxes_the_newest_established_secret_spec_sync_set_1() {
    for forged_first in [true, false] {
        let mut w = contacts();
        let t = make(&mut w, 0, "hi");
        let bob = w.node(1).account.unwrap();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Sync))).unwrap();
        w.run();
        let genuine = w.engine(1).ticket_for(&t).unwrap().expect("the grant's ticket");
        let s = genuine.sync_id;
        let k = w.engine(1).reboxed_ticket(&genuine, genuine.epoch.0 + 5, &osis_crypto::Secret32::from_bytes([9; 32])).unwrap();
        if forged_first {
            hold_in_profile(&mut w, k.clone());
        }
        accept(&mut w, t, &[]);
        assert_eq!(w.engine(1).sync_held(&s).unwrap().map(|x| x.1), Some(Holding::Unread), "T kept unread");
        if !forged_first {
            hold_in_profile(&mut w, k);
        }
        assert_eq!(d_tickets(&mut w, 1, &t), vec![(s, genuine.epoch.0)], "D boxes the grant's secret alone (forged first: {forged_first})");
        // Alice rotates sync: Bob's new secret's key is on the next step of his path
        w.write(0, |e| e.rotate_leaving_out(&t, &[Role::Sync], &[])).unwrap().expect("a rotation");
        w.run();
        assert_eq!(d_tickets(&mut w, 1, &t), vec![(s, genuine.epoch.0 + 1)], "the rotation's secret replaces the grant's in D (forged first: {forged_first})");
    }
}

// spec/sync-set.md §1 (The account's tickets; D's tickets follow what the node holds), spec/permissions.md
// §3 Lost access: Bob keeps T unread by a sync grant, is given read, then removed. His node,
// losing read and keeping T unread by the sync ticket's word, takes D's read ticket for T out
// with the read secrets, so a node of his paired after enters T by sync alone and reads nothing.
#[test]
fn a_lost_read_takes_ds_read_ticket_with_it_spec_sync_set_1() {
    let (mut w, t) = accepted(Role::Sync);
    let bob = w.node(1).account.unwrap();
    let d_roles = |w: &mut World, i: usize| -> Vec<Role> {
        let d = w.engine(i).account_root().unwrap();
        w.engine(i).get_typed(&d, &ct::TICKETS).unwrap().unwrap_or_default().iter().filter(|k| k.target == t).map(|k| k.role).collect()
    };
    w.write(0, |e| e.grant(&t, &bob, &ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None })).unwrap();
    w.run();
    assert!(d_roles(&mut w, 1).contains(&Role::Read), "Bob reads T: D holds his read ticket");
    w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new: None, retain: None })).unwrap();
    w.run();
    assert_eq!(d_roles(&mut w, 1), vec![Role::Sync], "D's read ticket went with the read");
    let n = w.pair(1);
    w.run();
    assert_eq!(w.engine(n).get(&t, &ak()).unwrap(), None, "a node paired after reads nothing of T");
}
