//! Stubs in sync (spec/sync-set.md §2 Stubs, Holding a stub; spec/permissions.md §4 Stub): a
//! unit carries the stubs of what it references but does not carry whole and of the holders on its
//! chains, logged under its sync ID by a node holding their role entries; a node reading the unit
//! holds each stub and follows its role entries from the thing's own sync IDs. Node 0 makes every
//! thing here; node 1, of another account holding no grant of its own, reaches them only by
//! redeeming a public link to U, the referrer, so whatever it holds of the rest it found by U.

use crate::harness::history::value_ak;
use crate::harness::{World, edge};
use osis_base::{Ak, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_engine::sync::Holding;
use osis_schema::core_types as ct;

/// Node 0 makes a thing minted with its account, holding `v`, held by a strong from the account.
fn make(w: &mut World, v: &str) -> Tid {
    let a = w.node(0).account.expect("an account");
    w.write(0, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(a, None));
        m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
        m.op(a, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
        t
    })
}

fn set(w: &mut World, t: Tid, v: &str) {
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap();
    });
}

/// Node 0 sets `from`'s reference aspect to `r` (a strong or a weak).
fn refer(w: &mut World, from: Tid, r: Value) {
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(from, &Ak::new("x:ref.0").unwrap(), &r).unwrap();
        e.commit(m).unwrap();
    });
}

fn grant(w: &mut World, on: Tid, to: Tid, role: Option<Role>) {
    match role {
        Some(r) => drop(w.write(0, |e| e.grant(&on, &to, &edge(r))).unwrap()),
        None => drop(w.write(0, |e| e.demote(&on, &osis_engine::flows::Demotion { holder: to, new: None, retain: None })).unwrap()),
    }
}

fn reads(w: &mut World, i: usize, t: &Tid) -> Option<Value> {
    w.engine(i).get(t, &value_ak()).ok().flatten()
}

/// How node `i` holds `t`'s sync ID as node 0 knows it (`None`: not in its sync set).
fn holding(w: &mut World, i: usize, t: &Tid) -> Option<Holding> {
    let s: SyncId = w.engine(0).sync_ids(t).unwrap().first().expect("a sync ID").id;
    w.engine(i).sync_set().unwrap().ids.get(&s).map(|h| h.1)
}

/// U, made public, set up by `arrange`; node 1 redeems a public link to U and runs.
fn redeemed(arrange: impl FnOnce(&mut World, Tid)) -> (World, Tid) {
    let mut w = crate::harness::contacts();
    let u = make(&mut w, "u");
    grant(&mut w, u, Tid::PUBLIC, Some(Role::Read));
    arrange(&mut w, u);
    w.run();
    let link = w.public_link(0, u).expect("U is public");
    w.redeem_any(1, &link);
    w.run();
    assert!(reads(&mut w, 1, &u).is_some(), "node 1 reads U by the public link");
    (w, u)
}

// spec/sync-set.md §2 (T's keys open: the public's grant read from X's role entries, which U's
// sync ID carries): U strongs X, which node 0 made public: node 1, reading U, reads X.
#[test]
fn a_public_thing_referenced_is_read_by_the_referrers_reader_spec_sync_set_2() {
    let mut x = Tid::PUBLIC;
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        grant(w, x, Tid::PUBLIC, Some(Role::Read));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(reads(&mut w, 1, &x), Some(Value::Str("x".into())));
}

// spec/sync-set.md §2 (Stubs: the holders on a unit's chains; Holding a stub), spec/permissions.md
// §4 (A hop's removal): U strongs X; X grants R read, R grants U read. Node 1 reads X through the
// chain, judging it by R's stub in U (R's grant to U is R's role entry, U's sync ID carries it)
// and holds R as a stub, reading nothing of R's content. R then removes U, and node 0 writes X
// again: node 1 reads nothing written since. (How a departed stub holder is told its removal is
// notes/stub-rewrite.md R3, Q6.)
#[test]
fn a_two_hop_chain_is_read_by_its_holders_stub_and_ends_at_its_removal_spec_sync_set_2() {
    let (mut x, mut r) = (Tid::PUBLIC, Tid::PUBLIC);
    let (mut w, u) = redeemed(|w, u| {
        x = make(w, "x1");
        r = make(w, "r");
        grant(w, x, r, Some(Role::Read));
        grant(w, r, u, Some(Role::Read));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(reads(&mut w, 1, &x), Some(Value::Str("x1".into())), "node 1 reads X through R");
    assert_eq!(holding(&mut w, 1, &r), Some(Holding::Stub), "R held as a stub");
    assert!(!w.engine(1).left_closure().contains_key(&r), "R's stub stays, U's unit carrying it");
    assert_eq!(reads(&mut w, 1, &r), None, "none of R's content");
    grant(&mut w, r, u, None);
    set(&mut w, x, "x2");
    w.run();
    assert_ne!(reads(&mut w, 1, &x), Some(Value::Str("x2".into())), "nothing of X written since");
}

// spec/sync-set.md §2 (Stubs: a weak to a thing the unit's keys open brings its stub; Holding a
// stub: kept current): U weaks X, which grants U read and Z write. Node 1 holds X as a stub: X's
// sync ID in the stub class, X's role entries and none of its content. X then removes Z: node 1
// holds the removal, from X's own sync ID (U's sync ID carries what node 0 logs of X's stub).
#[test]
fn a_weak_brings_a_stub_kept_current_spec_sync_set_2() {
    let (mut x, mut z) = (Tid::PUBLIC, Tid::PUBLIC);
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        z = make(w, "z");
        grant(w, x, u, Some(Role::Read));
        grant(w, x, z, Some(Role::Write));
        refer(w, u, Value::Weak(x));
    });
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Stub), "X held as a stub");
    assert!(w.engine(1).roster(&x).contains_key(&z), "its role entries");
    assert_eq!(reads(&mut w, 1, &x), None, "none of its content");
    grant(&mut w, x, z, None);
    w.run();
    assert!(!w.engine(1).roster(&x).contains_key(&z), "X's removal of Z reached node 1");
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Stub), "still a stub");
}

// spec/sync-set.md §2 (Stubs: a reference to a thing the unit's keys do not open where the unit
// holds sync; Node closure: kept unread): U strongs X, which grants U sync. Node 1 keeps X unread
// (it stores X's sync ID) and reads none of it.
#[test]
fn a_reference_at_sync_keeps_the_thing_unread_spec_sync_set_2() {
    let mut x = Tid::PUBLIC;
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        grant(w, x, u, Some(Role::Sync));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Unread), "X kept unread");
    assert_eq!(reads(&mut w, 1, &x), None);
}

// spec/sync-set.md §2 (First entry; Not carried): node 0 grants node 1's account read on X and
// tells it nothing; node 1 strongs X from its node root. Nothing it syncs carries X and it holds
// no signal: it holds nothing of X, and X's sync ID is not in its sync set (control:
// `a_public_thing_referenced_is_read_by_the_referrers_reader_*`, the reference carried by U).
#[test]
fn an_unsignalled_grant_holds_nothing_spec_sync_set_2() {
    let mut x = Tid::PUBLIC;
    let (mut w, _) = redeemed(|w, _| x = make(w, "x"));
    let b = w.node(1).account.expect("an account");
    grant(&mut w, x, b, Some(Role::Read));
    w.write(1, |e| e.hold(osis_base::Strong(x))).unwrap();
    w.run();
    assert_eq!(reads(&mut w, 1, &x), None, "nothing of X");
    assert_eq!(holding(&mut w, 1, &x), None, "X's sync ID not synced");
}
