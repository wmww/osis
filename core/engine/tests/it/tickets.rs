//! Tickets and the account's tickets (spec/data-model.md §8 Tickets, spec/sync-set.md §1, §2,
//! spec/sync-inbox.md §5).

use crate::flows::{edge_of, people};
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
    assert_eq!(e1.sync_set().unwrap().ids.get(&k.sync_id), Some(&(t, osis_engine::sync::Holding::Read)), "accepted: the ticket's sync ID read");
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
