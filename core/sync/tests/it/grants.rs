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
// signer, her node thing; `members_of` shows each node holding T's sync ID open to the other, and
// `view` Alice's roster, that write, her syncing and her open member of T; the settle round
// counters count that write's steps.
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
        let m = w.members_of(&t);
        for (i, j) in [(0, 1), (1, 0)] {
            assert!(m.lines().any(|l| l.starts_with(&format!("n{i} ")) && l.contains(&format!(" n{j} {s}: Member {{"))), "n{i} holds T's sync ID open to n{j}: {m}");
        }
        let v = w.view(0, &t);
        assert!(v.contains(&format!("    {d}")) && v.contains("  roster (") && v.contains(&format!(" n1 {s}: Member")) && v.contains(&format!("  n0: syncs [{s} ")), "{v}");
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
// write: the role commits he holds give read again.
#[test]
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
// it; told, he enters T at Alice's node and reads it.
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

// spec/sync-inbox.md §5 (Grant signal: its peers are dial hints once the app accepts it),
// spec/sync-hostile.md §1: Alice tells Bob of T naming her node; held alone the signal makes Bob's
// node dial nothing (its peers are the sender's word); once Bob holds T by a strong his node dials
// it as a hint (beside its other reasons) while the signal is held, and not once it expires.
#[test]
fn an_accepted_signals_peers_are_dial_hints_spec_sync_inbox_5() {
    use osis_sync::driver::dials::Why;
    let mut w = crate::harness::contacts();
    let t = make(&mut w, 0, "hi");
    let bob = w.node(1).account.unwrap();
    let peer = w.node(0).key.0;
    let hints = osis_blob::link_peers(peer, &w.net.reach.items(0), &w.node(0).node.config().dial);
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &bob, &hints))).unwrap();
    w.run();
    let hinted = |w: &World| w.dials(1).why(&peer).contains(&Why::Hint);
    assert!(!hinted(&w), "held, not accepted: no dial hint");
    root_strong(&mut w, 1, t, true);
    assert!(hinted(&w), "accepted: the signal's peer is a dial hint");
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 1);
    w.run();
    assert!(!hinted(&w), "gone with the signal");
}

// spec/sync-ids.md §3 (Claims; Taking a claim), §6 Head, spec/sync-opens.md §4 (One open rule):
// grant and claim are one write, and a claim key among the head claim keys opens S whole. Alice grants Bob read and
// tells him while Bob's node reaches only Carol's node, which keeps T unread; Alice's node goes
// off. Bob asks Carol's node Head, opens T's sync ID there by his claim key, finds his claim in the
// grant's blob and reads T: no reader of T online.
#[test]
fn a_grantee_gets_in_at_a_store_with_no_reader_online_spec_sync_ids_3() {
    let mut w = crate::harness::history::world_of(0, 3, 3);
    let t = make(&mut w, 0, "hi");
    let (carol, bob) = (w.node(1).account.unwrap(), w.node(2).account.unwrap());
    w.write(0, |e| e.grant(&t, &carol, &edge(Role::Sync)).and_then(|_| e.signal_grant(&t, &carol, &[]))).unwrap();
    w.run();
    root_strong(&mut w, 1, t, true);
    root_strong(&mut w, 2, t, true);
    let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
    assert_eq!(w.engine(1).sync_holder(&s).unwrap().map(|x| x.1), Some(Holding::Unread), "Carol's node keeps T unread");
    // the grant reaches Carol's store; Alice's node goes off as soon as Bob's holds the signal
    let claims = w.store(1).head_claim_keys(&s).unwrap().len();
    w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &bob, &[]))).unwrap();
    while w.engine(2).sync_holder(&s).unwrap().is_none() || w.store(1).head_claim_keys(&s).unwrap().len() == claims {
        assert!(w.step_or_wake(), "the signal reaches Bob");
    }
    w.power_off(0);
    assert_eq!(w.engine(2).get(&t, &ak()).unwrap(), None, "Bob reads nothing of T yet");
    w.run();
    assert_eq!(w.engine(2).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T, got in at Carol's store");
}

// spec/wire.md §5 (Claim pages), spec/sync-ids.md §3 (Claim block; Bound; Taking a claim),
// spec/sync-opens.md §4: a rotation boxing more holders than one claim page holds goes with its
// claims in pages, and the store holding them lets every holder in. Alice's node writes pages of
// 2 claims; T has Carol's node keeping it unread, and Bob and Dave granted read but not told, so
// each grant's claims go as 2 pages and the rotation's 8 as 4. Told after the rotation, with
// Alice's node off, Bob's and Dave's nodes, holding nothing of T, each get in at Carol's store by
// a claim only a page holds, take its entry from a page and read the write after the rotation.
// Carol's node takes the new sync secret by its sync claim in a page.
#[test]
fn a_rotation_boxing_more_holders_than_a_page_lets_each_in_at_a_store_spec_wire_5() {
    let mut w = crate::harness::history::world_of(0, 4, 4);
    let t = make(&mut w, 0, "before");
    let [carol, bob, dave] = [1, 2, 3].map(|i| w.node(i).account.unwrap());
    w.write(0, |e| e.grant(&t, &carol, &edge(Role::Sync)).and_then(|_| e.signal_grant(&t, &carol, &[]))).unwrap();
    w.run();
    for i in 1..4 {
        root_strong(&mut w, i, t, true);
    }
    let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
    assert_eq!(w.engine(1).sync_holder(&s).unwrap().map(|x| x.1), Some(Holding::Unread), "Carol's node keeps T unread");
    // from here every entry of Bob and Dave is in a page: a grant's 2 pad to 4
    w.write(0, |e| e.set_claim_page(2));
    for h in [bob, dave] {
        w.write(0, |e| e.grant(&t, &h, &edge(Role::Read))).unwrap();
    }
    w.write(0, |e| e.rotate_leaving_out(&t, &[Role::Sync, Role::Read, Role::Write, Role::Admin], &[])).unwrap().expect("a rotation");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    // the rotation's entries went in pages to Carol's store
    let paged = w.store(1).entries(&s).unwrap().into_iter().map(|e| w.store(1).pages_of(&s, &e.blob).unwrap().len()).max();
    assert_eq!(paged, Some(4), "8 entries in 4 pages of 2");
    assert!(w.store(1).head_claim_keys(&s).unwrap().len() >= 8, "the store shows the claims in the pages at the head");
    let head = w.store(1).path(&s).unwrap().expect("a path").steps.last().unwrap().keys.sync;
    assert!(w.engine(1).kept_sync_secrets(&s).iter().any(|(_, x)| osis_crypto::role_key(osis_crypto::RoleKey::Sync, x).verifying_key() == head), "Carol's node took the head's sync secret from a page");
    for (i, h) in [(2, bob), (3, dave)] {
        assert_eq!(w.engine(i).sync_holder(&s).unwrap(), None, "node {i} holds nothing of T yet");
        w.write(0, |e| e.signal_grant(&t, &h, &[])).unwrap();
    }
    while [2, 3].iter().any(|i| w.engine(*i).sync_holder(&s).unwrap().is_none()) {
        assert!(w.step_or_wake(), "the signals reach Bob and Dave");
    }
    w.power_off(0);
    w.run();
    for i in [2, 3] {
        assert_eq!(w.engine(i).get(&t, &ak()).unwrap(), Some(Value::Str("after".into())), "node {i} got in at Carol's store");
    }
}

// spec/sync-ids.md §3 (Claims), spec/sync-opens.md §4-§5 (shows:
// its head claim keys; tests: its claim keys at the source's step): one sync ID with n and 10n holders
// (each granted apart, then a rotation boxing them all), what a node keeping it unread shows for
// it (each head claim key is a filter entry) and what one new grantee getting in at that store costs
// (claim keys indexed, claim blocks verified, beacons, decapsulations), counted: each grows at most
// linearly with the holders, and the grantee's own work not at all.
#[test]
fn an_open_at_a_store_costs_at_most_linear_in_holders_spec_sync_ids_3() {
    let measure = |n: usize| {
        let mut w = crate::harness::history::world_of(0, 3, 3);
        let t = make(&mut w, 0, "hi");
        let (carol, bob) = (w.node(1).account.unwrap(), w.node(2).account.unwrap());
        w.write(0, |e| e.grant(&t, &carol, &edge(Role::Sync)).and_then(|_| e.signal_grant(&t, &carol, &[]))).unwrap();
        w.run();
        root_strong(&mut w, 1, t, true);
        root_strong(&mut w, 2, t, true);
        let s = w.engine(0).sync_id_of(&t).unwrap().expect("T's sync ID");
        for _ in 0..n {
            w.write(0, |e| {
                let mut m = Mutation::new();
                let me = e.tid();
                let x = e.new_thing(&mut m, me);
                e.commit(m).unwrap();
                e.grant(&t, &x, &edge(Role::Read)).unwrap();
            });
        }
        w.run();
        w.write(0, |e| e.rotate_leaving_out(&t, &[Role::Sync, Role::Read, Role::Write, Role::Admin], &[])).unwrap().expect("a rotation");
        w.run();
        let shown = w.store(1).head_claim_keys(&s).unwrap().len();
        // one new grantee, getting in at the store alone (as `a_grantee_gets_in_at_a_store_*`)
        let beacons = w.node(2).node.opens().work().beacons;
        osis_base::costs::take();
        let claims = w.store(1).head_claim_keys(&s).unwrap().len();
        w.write(0, |e| e.grant(&t, &bob, &edge(Role::Read)).and_then(|_| e.signal_grant(&t, &bob, &[]))).unwrap();
        while w.engine(2).sync_holder(&s).unwrap().is_none() || w.store(1).head_claim_keys(&s).unwrap().len() == claims {
            assert!(w.step_or_wake(), "the signal reaches Bob");
        }
        w.power_off(0);
        w.run();
        assert_eq!(w.engine(2).get(&t, &ak()).unwrap(), Some(Value::Str("hi".into())), "Bob reads T, got in at Carol's store");
        let costs: std::collections::BTreeMap<&str, u64> = osis_base::costs::take().into_iter().map(|(k, _, c)| (k, c)).collect();
        let at = |name: &str| costs.get(name).copied().unwrap_or(0);
        let open = [
            ("claims indexed at the store", (w.store(1).head_claim_keys(&s).unwrap().len() - claims) as u64),
            ("blocks verified at the store", at("store: claim blocks verified @node 1")),
            ("blocks verified at the grantee", at("store: claim blocks verified @node 2")),
            ("beacons at the grantee", w.node(2).node.opens().work().beacons - beacons),
            ("decapsulations at the grantee", at("kem: decapsulate @node 2")),
        ];
        (shown as u64, open)
    };
    let (small, large) = (measure(2), measure(20));
    eprintln!("holders 2 then 20: filter entries for S {} / {}", small.0, large.0);
    for ((name, a), (_, b)) in small.1.iter().zip(large.1.iter()) {
        eprintln!("  {name}: {a} / {b}");
    }
    assert!(large.0 <= 10 * small.0 + 8, "filter entries for S: {} at n, {} at 10n", small.0, large.0);
    for ((name, a), (_, b)) in small.1.iter().zip(large.1.iter()) {
        assert!(*b <= 10 * a + 8, "{name}: {a} at n, {b} at 10n");
    }
}
