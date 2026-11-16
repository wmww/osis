//! Tickets and the account's tickets (spec/data-model.md §8 Tickets, spec/sync-set.md §1, §2,
//! spec/sync-inbox.md §5).

use crate::common::REG;
use crate::flows::{edge_of, people};
use std::collections::BTreeSet;
use osis_base::{Role, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

// spec/sync-set.md §1 The account's tickets: the account's creation leaves D holding a ticket
// for the profile and for the inbox, sealed to the account, which its node opens.
#[test]
fn creation_writes_the_account_tickets_spec_sync_set_1() {
    let (mut lp, ps) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let inbox = e.inbox_thing(&ps[0]).unwrap();
    let profile = e.profile_of(&ps[0]).unwrap();
    let held = e.get_typed(&d, &ct::TICKETS).unwrap().unwrap_or_default();
    for t in [profile, inbox] {
        let k = held.iter().find(|k| k.target == t).unwrap_or_else(|| panic!("no ticket for {t:?}: {held:?}"));
        assert_eq!((k.role, k.holder), (Role::Read, ps[0]));
        assert_eq!(e.ticket_for(&t).unwrap().as_ref(), Some(k), "its node opens it");
    }
}

// spec/sync-inbox.md §2, §5: a grant fires a ticket on the grantee's inbox as a sealed fire;
// the grantee's node opens it under its inbox's sync ID and holds the ticket, which grants
// nothing until it accepts (a strong in its node closure), after which it reads the thing and
// writes D's ticket for it.
#[test]
fn a_grant_reaches_its_grantee_as_a_ticket_spec_sync_inbox_5() {
    let (mut lp, ps) = people(2);
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.account_root().unwrap();
    let mut m = Mutation::new();
    let t = e0.new_thing(&mut m, d0);
    m.op(d0, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    m.set(t, &osis_base::Ak::new("x:v.0").unwrap(), &Value::Str("hi".into())).unwrap();
    e0.commit(m).unwrap();
    e0.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let fires = e0.fires_owed();
    assert_eq!(fires.len(), 1, "one ticket fired");
    let out = e0.sealed_fire(&fires[0]).unwrap().expect("sealed");
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(Some(out.thing), e1.inbox_thing(&ps[1]));
    let b = osis_blob::blob_id(&out.blob);
    let opened = e1.open_entry(&out.sync_id, &b, &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, osis_engine::sync::Opened::Commit(..)), "{opened:?}");
    let k = e1.ticket_for(&t).unwrap().expect("the ticket is held");
    assert_eq!((k.target, k.role, k.holder), (t, Role::Read, ps[1]));
    assert!(!e1.closure_holds(&t), "nothing before the strong");
    let d1 = e1.account_root().unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    e1.commit(m).unwrap();
    assert!(!e1.closure_holds(&t), "no own keys here yet: none of its data held for it");
    assert_eq!(e1.sync_set().unwrap().ids.get(&k.sync_id), Some(&([t].into(), osis_engine::sync::Holding::Read)), "accepted: the ticket's sync ID read");
    lp.sync_all().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.get(&t, &osis_base::Ak::new("x:v.0").unwrap()).unwrap(), Some(Value::Str("hi".into())));
    assert_eq!(e1.account_ticket_due(&t).unwrap(), Some(Role::Read), "established: D's ticket owed");
    e1.write_account_ticket(&t).unwrap();
    assert_eq!(e1.account_ticket_due(&t).unwrap(), None, "D's ticket written");
}

/// The ticket lookup work (`tickets: rows read`) of the last of `n` grants' tickets reaching an
/// account that accepted all `n` things first: the fires sit on one inbox signal.
fn last_arrival_work(n: usize) -> u64 {
    let (mut lp, ps) = people(2);
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.account_root().unwrap();
    let mut things = Vec::new();
    for _ in 0..n {
        let mut m = Mutation::new();
        let t = e0.new_thing(&mut m, d0);
        m.op(d0, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e0.commit(m).unwrap();
        e0.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
        things.push(t);
    }
    let fires: Vec<_> = e0.fires_owed().iter().map(|f| e0.sealed_fire(f).unwrap().expect("sealed")).collect();
    assert_eq!(fires.len(), n);
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.account_root().unwrap();
    let mut m = Mutation::new();
    for t in &things {
        m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(*t)) }).unwrap();
    }
    e1.commit(m).unwrap();
    let mut last = 0;
    for out in &fires {
        let b = osis_blob::blob_id(&out.blob);
        osis_base::costs::take();
        e1.open_entry(&out.sync_id, &b, &[0; 57], &out.blob, u64::MAX).unwrap();
        last = osis_base::costs::take().into_iter().filter(|(k, _, _)| *k == "tickets: rows read").map(|(_, _, c)| c).sum();
    }
    for t in &things {
        assert!(e1.ticket_for(t).unwrap().is_some(), "every ticket held");
    }
    last
}

// spec/sync-set.md §2 Cost: finding a target's tickets reads its ticket rows alone, never the
// inbox signal's other fires: the last of n tickets arriving for a held strong's target costs the
// same at n and 10n (so n tickets cost n, not n²).
#[test]
fn a_ticket_lookup_reads_the_targets_tickets_alone_at_n_and_10n() {
    let (small, large) = (last_arrival_work(4), last_arrival_work(40));
    assert!(small > 0, "the arrival looked its target's tickets up");
    assert_eq!(small, large, "the lookup reads the target's tickets alone");
}

// spec/data-model.md §8 Tickets, spec/sync-set.md §2 (refgraph T1): a ticket lets its holder sync
// the target from a strong on. Placed by hand in a thing account 1 holds (no inbox), before any
// of T's commits: a read ticket's sync ID is synced at once and, given T's commits sealed, T
// reads; a sync ticket's is synced and T stays unread; one sealed to account 2 syncs nothing.
#[test]
fn a_ticket_enters_its_target_at_a_strong_spec_sync_set_2() {
    for arm in ["read", "sync", "sealed to another"] {
        let (mut lp, ps) = people(3);
        let before: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
        let e0 = &mut lp.peers[0].engine;
        let (d0, p0) = (e0.account_root().unwrap(), e0.me());
        let mut m = Mutation::new();
        let t = e0.new_thing(&mut m, p0);
        m.set(t, &REG, &Value::Str("v".into())).unwrap();
        e0.commit(m).unwrap();
        let _ = d0;
        let role = if arm == "sync" { Role::Sync } else { Role::Read };
        let holder = if arm == "read" || arm == "sync" { ps[1] } else { ps[2] };
        e0.grant(&t, &holder, &edge_of(role)).unwrap();
        let k = e0.ticket_of(&t, role, &holder).unwrap().expect("a ticket");
        let e1 = &mut lp.peers[1].engine;
        let d1 = e1.account_root().unwrap();
        let mut m = Mutation::new();
        let h = e1.new_thing(&mut m, d1);
        m.set(h, &osis_base::Ak::new("x:k.0").unwrap(), &Value::Ticket(Box::new(k))).unwrap();
        m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e1.commit(m).unwrap();
        // on the ticket's word: its sync ID synced, none of T's data held for it yet
        assert_eq!(e1.in_sync_things(&t).unwrap(), arm != "sealed to another", "{arm}: entered at the strong");
        // sealed as sync IDs carry them: a reader opens what its secrets open
        let ids: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
        let pks = lp.sealed(0, &ids).unwrap();
        lp.deliver_sealed(1, &pks).unwrap();
        let e1 = &mut lp.peers[1].engine;
        e1.check_closure();
        let read = e1.get(&t, &osis_base::Ak::new("t:reg.0").unwrap()).unwrap();
        match arm {
            "read" => assert_eq!(read, Some(Value::Str("v".into())), "{arm}"),
            "sync" => assert!(read.is_none() && e1.in_sync_things(&t).unwrap(), "{arm}: kept unread"),
            _ => assert!(read.is_none() && !e1.closure_holds(&t) && !e1.in_sync_things(&t).unwrap(), "{arm}"),
        }
    }
}

// spec/sync-inbox.md §5 Ticket sync IDs (refgraph T5): a sync ID the tickets of several things
// name is synced once and what arrives under it is judged for each of them, whatever their tid
// order. Account 1 takes A's and B's grants' tickets from its inbox and holds one for A naming
// B's sync ID (what anyone holding its public record can box): that sync ID is A's and B's, and
// an entry of either arriving under it is judged as under its own thing's sync ID.
#[test]
fn a_sync_id_two_things_tickets_name_is_judged_for_each_spec_sync_inbox_5() {
    use osis_engine::sync::{Holding, Opened};
    let (mut lp, ps) = people(2);
    let before: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    let e0 = &mut lp.peers[0].engine;
    let p0 = e0.me();
    let mut ts = Vec::new();
    for v in ["x", "y"] {
        let mut m = Mutation::new();
        let t = e0.new_thing(&mut m, p0);
        m.set(t, &REG, &Value::Str(v.into())).unwrap();
        e0.commit(m).unwrap();
        e0.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
        ts.push(t);
    }
    ts.sort();
    let (a, b) = (ts[0], ts[1]);
    let fires: Vec<_> = e0.fires_owed().iter().map(|f| e0.sealed_fire(f).unwrap().expect("sealed")).collect();
    let e1 = &mut lp.peers[1].engine;
    for f in &fires {
        let id = osis_blob::blob_id(&f.blob);
        e1.open_entry(&f.sync_id, &id, &[0; 57], &f.blob, u64::MAX).unwrap();
    }
    let (ka, kb) = (e1.ticket_for(&a).unwrap().expect("A's ticket"), e1.ticket_for(&b).unwrap().expect("B's ticket"));
    let (sa, sb) = (ka.sync_id, kb.sync_id);
    let forged = osis_base::Ticket { sync_id: sb, ..ka };
    let d1 = e1.account_root().unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(forged))) }).unwrap();
    for t in [a, b] {
        m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    }
    e1.commit(m).unwrap();
    e1.take_ticket_fires().unwrap();
    assert_eq!(e1.sync_held(&sb).unwrap(), Some(([a, b].into(), Holding::Read)), "B's sync ID is both things'");
    assert_eq!(e1.sync_held(&sa).unwrap(), Some(([a].into(), Holding::Read)), "A's own is A's");
    // every new commit on A or B as node 0 logs it under its thing's sync ID, offered to node 1
    // under its own thing's sync ID and under B's
    let ids: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    let mut rng = osis_crypto::SeededRng::from_u64(1);
    let mut offered = Vec::new();
    for c in &ids {
        for s in [sa, sb] {
            if let Some((sealed, wrap)) = lp.peers[0].engine.seal_body(&s, c, &[], &mut rng).unwrap() {
                offered.push((s, sealed.id, wrap, sealed.blob));
            }
        }
    }
    let e1 = &mut lp.peers[1].engine;
    let opens = |e: &mut osis_engine::Engine, u: &osis_base::SyncId, x: &(osis_base::SyncId, osis_base::BlobId, osis_engine::sync::Wrap, Vec<u8>)| matches!(e.open_entry(u, &x.1, &x.2, &x.3, u64::MAX).unwrap(), Opened::Commit(..));
    // under B's sync ID alone first (an entry waiting on another opens once that one is held)
    let mut under_b = BTreeSet::new();
    for _ in 0..2 {
        for (i, x) in offered.iter().enumerate() {
            if opens(e1, &sb, x) {
                under_b.insert(i);
            }
        }
    }
    assert!(offered.iter().enumerate().any(|(i, x)| x.0 == sa && under_b.contains(&i)), "A's entries open under B's sync ID");
    assert!(offered.iter().enumerate().any(|(i, x)| x.0 == sb && under_b.contains(&i)), "B's entries open under it");
    // the rest under each one's own (A's `sync.0` taken, B's sync ID is no longer A's)
    for x in &offered {
        opens(e1, &x.0, x);
    }
    assert_eq!(e1.get(&a, &reg).unwrap(), Some(Value::Str("x".into())), "A read");
    assert_eq!(e1.get(&b, &reg).unwrap(), Some(Value::Str("y".into())), "B read");
}
