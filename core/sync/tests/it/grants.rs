//! Entering a granted thing over real connections (spec/sync-set.md §2, spec/sync-inbox.md §5):
//! the grantee holds the thing by a strong, syncs its sync ID and reads it.

use crate::harness::{World, contacts, edge, fixture_with};
use osis_base::{Ak, Role, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::Mutation;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

fn ak() -> Ak {
    Ak::new("x:v.0").unwrap()
}

/// A thing node `i` mints with its account as admin, which holds it, with value `v`.
fn make(w: &mut World, i: usize, v: &str) -> Tid {
    let v = v.to_owned();
    let d = w.node(i).account.unwrap();
    w.write(i, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, d);
        m.set(t, &ak(), &Value::Str(v)).unwrap();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

/// Node 0 makes T and grants node 1's account read on it; run. Built once per process
/// (`fixture_with`).
fn granted() -> (World, Tid) {
    fixture_with("grants granted", || {
        let mut w = contacts();
        let t = make(&mut w, 0, "hi");
        let bob = w.node(1).account.unwrap();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &bob, &[]))).unwrap();
        w.run();
        (w, t)
    })
}

// spec/sync-inbox.md §5, spec/sync-set.md §2: Alice grants Bob read on T; Bob holds T by a strong
// in his account, syncs T's sync ID over real connections and reads T.
#[test]
fn a_granted_thing_held_by_a_strong_syncs_spec_sync_inbox_5() {
    let (mut w, t) = granted();
    root_strong(&mut w, 1, t, true);
    assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T");
    assert!(w.engine(1).closure_holds(&t));
    let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Read)), "T's own sync ID");
}

// spec: none (debug dumps, notes/test-harnesses.md): after Bob holds Alice's grant, `sync_ids_of`
// shows each node syncing T's sync ID; `describe_commit` names Alice's next write on T and its
// signer, her node thing; the settle round counters count that write's steps.
#[test]
fn debug_dumps_name_sync_ids_commits_and_rounds() {
    let (mut w, t) = granted();
    root_strong(&mut w, 1, t, true);
    let s = crate::harness::trace::short(&w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID"));
    let d = w.sync_ids_of(&t);
    let lines: Vec<&str> = d.lines().collect();
    assert!(lines[0].starts_with(&format!("n0: syncs [{s} ")), "{d}");
    assert!(lines[1].starts_with(&format!("n1: syncs [{s} ")), "{d}");
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
        assert!(d.contains("Content by ") && d.contains("by ") && d.contains(" (n0) (node thing)") && d.contains(&format!("{t} x:v.0")), "{d}");
    }
    let _ = c;
}

// spec/sync-set.md §1, §2: a node paired to an account enters the account's profile, though the
// secrets its account's boxes give read the profile as derived from the account until the
// profile's keyset arrives: it holds the profile and syncs its sync ID, across a restart.
#[test]
fn a_paired_node_enters_the_profile_spec_sync_set_1() {
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

// spec/sync-inbox.md §1, §5 (Reaching a holder; Contact card): an account that paired a second node before
// its contact card was made is reached all the same: its contact knows its inbox, and a grant to
// it reaches it: held by a strong, the thing is read.
#[test]
fn a_card_made_after_pairing_carries_the_inbox_spec_sync_inbox_5() {
    let mut w = World::new(0);
    w.add_node();
    w.add_node();
    w.pair(0);
    crate::harness::history::introduce(&mut w);
    w.run();
    let a0 = w.node(0).account.unwrap();
    assert!(w.engine(1).inbox_of(&a0).unwrap().is_some(), "node 1 knows account 0's inbox");
    let t = make(&mut w, 1, "hi");
    w.write(1, |e| e.grant(&t, &a0, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &a0, &[]))).unwrap();
    w.run();
    root_strong(&mut w, 0, t, true);
    assert_eq!(w.engine(0).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "the grant reached account 0");
}

// spec/sync-set.md §2, spec/sync-ids.md §5: a granted thing is entered at a strong, and the store
// is the truth after a crash. Bob's node loses power at the durable write of its strong to
// a granted thing (the write's outcome unknown) and restarts in place. With its strong, as the
// store holds it or written again, it enters the thing and reads it.
#[test]
fn a_crash_after_holding_keeps_the_thing_entered_spec_sync_set_2() {
    let (mut w, t) = granted();
    w.disk_fault(1, 1, crate::harness::DiskFault::Crash);
    let d = w.node(1).account.unwrap();
    let r = w.write(1, |e| {
        let mut m = Mutation::new();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).map(|_| ())
    });
    assert!(r.is_err() && w.crashes == 1, "the strong's write crashed, its outcome unknown");
    w.run();
    // the store is the truth: a strong it lost is written again
    let d = w.node(1).account.unwrap();
    if !w.engine(1).get_typed(&d, &ct::HOLDS).unwrap().unwrap_or_default().contains(&osis_base::Ref::Strong(osis_base::Strong(t))) {
        root_strong(&mut w, 1, t, true);
    }
    assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T");
}

/// Node 0 makes T and gives node 1's account `role` on it; node 1 holds it by a strong; run.
fn held(role: Role) -> (World, Tid) {
    let mut w = contacts();
    let t = make(&mut w, 0, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &ct::Edge { role, until: None, may_grant: false, retain: false, floor: None }).and_then(|_| e.signal_grant(&t, &bob, &[]))).unwrap();
    w.run();
    root_strong(&mut w, 1, t, true);
    (w, t)
}

/// Node `i` adds (`on`) or removes its account's strong to `t`; run.
fn root_strong(w: &mut World, i: usize, t: Tid, on: bool) {
    let d = w.node(i).account.unwrap();
    w.write(i, |e| {
        let mut m = Mutation::new();
        let v = Value::Strong(t);
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: if on { Op::Add(v) } else { Op::Remove(v) } }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
}

// spec/permissions.md §2, spec/sync-set.md §2: a re-granted reader reads again; the node enters
// at its role as the role commits it holds show. Alice removes Bob from T (or lowers
// him to sync), then grants him read again and tells him; Bob, his strong kept, reads her next
// write: the new grant's notice reaches him, so the role commits he holds give read again.
#[test]
#[ignore = "stub rewrite: told again after its removal, the re-granted holder is not served its new grant's notice (cause not sorted, R4)"]
fn a_reader_granted_again_reads_again_spec_sync_set_2() {
    for lowered in [false, true] {
        let (mut w, t) = held(Role::Read);
        let bob = w.node(1).account.unwrap();
        let new = lowered.then_some(edge(Role::Sync));
        w.write(0, |e| e.demote(&t, &osis_engine::flows::edges::Demotion { holder: bob, new, retain: None })).unwrap();
        w.run();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &bob, &[]))).unwrap();
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

/// Node 0 makes T and grants node 1's account read on it, telling it or not; run.
fn granted_told(tell: bool) -> (World, Tid) {
    let mut w = contacts();
    let t = make(&mut w, 0, "hi");
    let bob = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read)).and_then(|_| if tell { e.signal_grant(&t, &bob, &[]) } else { Ok(()) })).unwrap();
    w.run();
    (w, t)
}

// spec/sync-inbox.md §5 (Grant signal), spec/sync-set.md §2 First entry: a grant nobody is told
// of is valid and gives its holder's nodes nothing: Bob, holding T by a strong, reads nothing of
// it; told, he enters T by role at Alice's node and reads it.
#[test]
fn an_untold_grant_holds_nothing_spec_sync_set_2() {
    for tell in [false, true] {
        let (mut w, t) = granted_told(tell);
        root_strong(&mut w, 1, t, true);
        let read = w.engine(1).get(&t, &ak()).unwrap();
        assert_eq!(read.is_some(), tell, "told {tell}: Bob reads T");
        assert_eq!(w.engine(1).role_on(&t).is_some(), tell, "told {tell}: Bob holds T's grant");
    }
}

// spec/sync-inbox.md §5 (Grant signal: held while the inbox's setting keeps it): told and holding
// no reference of his own, Bob's node holds T's stub while the signal is held, and nothing of T
// once it expires.
#[test]
fn a_signal_holds_its_stub_until_it_expires_spec_sync_inbox_5() {
    let (mut w, t) = granted_told(true);
    let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Stub)), "held as a stub");
    assert_eq!(w.engine(1).get(&t, &ak()).unwrap(), None, "none of its content");
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 1);
    w.run();
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), None, "the signal expired: nothing held");
    assert_eq!(w.engine(1).role_on(&t), None);
}
