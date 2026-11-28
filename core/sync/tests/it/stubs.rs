//! Stubs in sync (spec/sync-set.md §2 Stubs, Holding a stub; spec/permissions.md §4 Stub): a
//! unit carries the stubs of what it references but does not carry whole and of the holders on its
//! chains, logged under its sync ID by a node holding their role entries; a node reading the unit
//! holds each stub and follows its role entries from the thing's own sync IDs. Node 0 makes every
//! thing here; node 1, of another account holding no grant of its own, reaches them only by
//! redeeming a locator of U, the referrer, so whatever it holds of the rest it found by U.

use crate::harness::history::value_ak;
use crate::harness::{World, grant};
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

fn set_role(w: &mut World, on: Tid, to: Tid, role: Option<Role>) {
    match role {
        Some(r) => drop(w.write(0, |e| e.grant(&on, &to, &grant(r))).unwrap()),
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

/// U, made public, set up by `arrange`; node 1 redeems a locator of U and runs.
fn redeemed(arrange: impl FnOnce(&mut World, Tid)) -> (World, Tid) {
    let mut w = crate::harness::contacts();
    let u = make(&mut w, "u");
    set_role(&mut w, u, Tid::PUBLIC, Some(Role::Read));
    arrange(&mut w, u);
    w.run();
    let link = w.locator(0, u).expect("U is public");
    w.redeem_any(1, &link);
    w.run();
    assert!(reads(&mut w, 1, &u).is_some(), "node 1 reads U by the locator");
    (w, u)
}

// spec/sync-set.md §2 (T's keys open: the public's grant read from X's role entries, which U's
// sync ID carries): U strongs X, which node 0 made public: node 1, reading U, reads X.
#[test]
fn a_public_thing_referenced_is_read_by_the_referrers_reader_spec_sync_set_2() {
    let mut x = Tid::PUBLIC;
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        set_role(w, x, Tid::PUBLIC, Some(Role::Read));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(reads(&mut w, 1, &x), Some(Value::Str("x".into())));
}

// spec/sync-set.md §2 (Stubs: the holders on a unit's chains; Holding a stub), spec/permissions.md
// §4 (A hop's removal): U strongs X; X grants R read, R grants U read. Node 1 reads X through the
// chain, judging it by R's stub in U (R's grant to U is R's role entry, U's sync ID carries it)
// and holds R as a stub, a chain holder's (X's roster naming R brings nothing: a role-class
// aspect's weaks bring no stub), reading nothing of R's content. R then removes U, and node 0 writes X
// again: node 1 reads nothing written since, and takes R's removal of U by its older step's proof
// (spec/sync-opens.md §4 One open rule: served up to that step's end, the rotation wrapped under
// the epoch it holds): R's roster there names U no more, so X is read no more and R is no chain
// holder.
#[test]
fn a_two_hop_chain_is_read_by_its_holders_stub_and_ends_at_its_removal_spec_sync_set_2() {
    let (mut x, mut r) = (Tid::PUBLIC, Tid::PUBLIC);
    let (mut w, u) = redeemed(|w, u| {
        x = make(w, "x1");
        r = make(w, "r");
        set_role(w, x, r, Some(Role::Read));
        set_role(w, r, u, Some(Role::Read));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(reads(&mut w, 1, &x), Some(Value::Str("x1".into())), "node 1 reads X through R");
    assert_eq!(holding(&mut w, 1, &r), Some(Holding::Stub), "R held as a stub");
    assert!(!w.engine(1).left_closure().contains_key(&r), "R's stub stays, U's unit carrying it");
    assert_eq!(reads(&mut w, 1, &r), None, "none of R's content");
    set_role(&mut w, r, u, None);
    set(&mut w, x, "x2");
    w.run();
    assert_ne!(reads(&mut w, 1, &x), Some(Value::Str("x2".into())), "nothing of X written since");
    assert!(!w.engine(1).roster(&r).contains_key(&u), "R's removal of U taken");
    assert_ne!(holding(&mut w, 1, &x), Some(Holding::Read), "X read no more");
    assert_eq!(holding(&mut w, 1, &r), None, "R no chain holder");
}

// spec/sync-set.md §2 (Stubs: the holders on a unit's chains): U strongs X; X grants R1 read, R1
// grants R2 read, R2 grants U read. Node 1 reads X by R1's and R2's stubs, chain holders', the
// rosters naming them bringing nothing (control: chain stubs given nowhere, node 1 reads nothing
// of X).
#[test]
fn a_three_hop_chain_is_read_by_its_far_holders_stub_spec_sync_set_2() {
    let (mut x, mut r2) = (Tid::PUBLIC, Tid::PUBLIC);
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        let r1 = make(w, "r1");
        r2 = make(w, "r2");
        set_role(w, x, r1, Some(Role::Read));
        set_role(w, r1, r2, Some(Role::Read));
        set_role(w, r2, u, Some(Role::Read));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(reads(&mut w, 1, &x), Some(Value::Str("x".into())), "node 1 reads X through R1 and R2");
    assert_eq!(holding(&mut w, 1, &r2), Some(Holding::Stub), "R2 held as a stub");
}

// spec/sync-set.md §2 (Stubs: a role-class aspect's weaks aside, a thing is in no unit for having
// been granted something): U strongs X, which grants U read and H sync; H grants U read.
// X's roster names H, which U's keys open, but H is on no chain by which U reads X: node 1, reading
// X, holds nothing of H (fails with a roster's holders counted as weaks: H held as a stub).
#[test]
fn a_holder_on_no_chain_is_no_stub_spec_sync_set_2() {
    let (mut x, mut h) = (Tid::PUBLIC, Tid::PUBLIC);
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        h = make(w, "h");
        set_role(w, x, u, Some(Role::Read));
        set_role(w, x, h, Some(Role::Sync));
        set_role(w, h, u, Some(Role::Read));
        refer(w, u, Value::Strong(x));
    });
    assert_eq!(reads(&mut w, 1, &x), Some(Value::Str("x".into())), "node 1 reads X");
    assert_eq!(holding(&mut w, 1, &h), None, "nothing of H");
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
        set_role(w, x, u, Some(Role::Read));
        set_role(w, x, z, Some(Role::Write));
        refer(w, u, Value::Weak(x));
    });
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Stub), "X held as a stub");
    assert!(w.engine(1).roster(&x).contains_key(&z), "its role entries");
    assert_eq!(reads(&mut w, 1, &x), None, "none of its content");
    set_role(&mut w, x, z, None);
    w.run();
    assert!(!w.engine(1).roster(&x).contains_key(&z), "X's removal of Z reached node 1");
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Stub), "still a stub");
}

// spec/data-model.md §8 (Held history: a weak in a held body brings its stub as one in a current
// value does): U, whose setting keeps its history and holds its targets, weaks X (which grants U
// read), then replaces the weak with text. Node 1 holds X as a stub by the replaced body alone,
// and holds nothing of X once U's setting no longer holds its targets (fails with history's weaks
// counted for nothing: X never held).
#[test]
fn a_weak_in_held_history_brings_a_stub_spec_data_model_8() {
    let keep = osis_schema::History::Keep { until: None, after: Some(10 * 60_000) };
    let setting = |holds| ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(keep), ..Default::default() }), history_holds_targets: holds, ..Default::default() };
    let put = |w: &mut World, u: Tid, s: ct::RetentionSetting| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(u, &ct::RETENTION, &s).unwrap();
            e.commit(m).unwrap();
        });
    };
    let mut x = Tid::PUBLIC;
    let (mut w, u) = redeemed(|w, u| {
        x = make(w, "x");
        set_role(w, x, u, Some(Role::Read));
        put(w, u, setting(true));
        refer(w, u, Value::Weak(x));
        refer(w, u, Value::Str("no reference".into()));
    });
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Stub), "X held as a stub by U's history");
    assert_eq!(reads(&mut w, 1, &x), None, "none of its content");
    put(&mut w, u, setting(false));
    w.run();
    assert_eq!(holding(&mut w, 1, &x), None, "nothing of X once U's history holds no targets");
}

// spec/sync-set.md §2 (Stubs: a reference to a thing the unit's keys do not open where the unit
// holds sync; Node closure: kept unread): U strongs X, which grants U sync. Node 1 keeps X unread
// (it stores X's sync ID) and reads none of it.
#[test]
fn a_reference_at_sync_keeps_the_thing_unread_spec_sync_set_2() {
    let mut x = Tid::PUBLIC;
    let (mut w, _) = redeemed(|w, u| {
        x = make(w, "x");
        set_role(w, x, u, Some(Role::Sync));
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
    set_role(&mut w, x, b, Some(Role::Read));
    w.write(1, |e| e.hold(osis_base::Strong(x))).unwrap();
    w.run();
    assert_eq!(reads(&mut w, 1, &x), None, "nothing of X");
    assert_eq!(holding(&mut w, 1, &x), None, "X's sync ID not synced");
}

// spec/sync-set.md §2 (Stubs: the holders on a unit's chains; Role entries a unit's chains read),
// spec/permissions.md §4 Stub (a sync-only cut names the holders on its unit's chains): node 0
// makes H0 (public, granting node 1's account A sync), H2 and X minted with H0, X granting A sync
// and H2 sync. A holds sync on X directly and through H0 and H2, the hop from H0 to H2 being H2's
// record grant; node 1, told of X and H0 by their signals, holds both as stubs but nothing of H2: it
// knows of that hop only from evidence (H2 named holder on X), which no logger of A's unit holds
// as H2's role entries (fails with a sync chain judged from every grant held: H2 a chain stub).
#[test]
fn a_chain_hop_only_evidence_shows_is_no_chain_spec_sync_set_2() {
    let mut w = crate::harness::contacts();
    let a = w.node(1).account.expect("an account");
    let h0 = make(&mut w, "h0");
    let tell = |w: &mut World, t: Tid, to: Tid, r: Role| w.write(0, |e| e.grant(&t, &to, &grant(r)).and_then(|_| e.signal_grant(&t, &to, &[]))).unwrap();
    tell(&mut w, h0, a, Role::Sync);
    set_role(&mut w, h0, Tid::PUBLIC, Some(Role::Read));
    let made_in = |w: &mut World, v: &str| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            let t = m.create(e.thing_record(h0, None));
            m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
            m.op(h0, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let (h2, x) = (made_in(&mut w, "h2"), made_in(&mut w, "x"));
    tell(&mut w, x, a, Role::Sync);
    set_role(&mut w, x, h2, Some(Role::Sync));
    w.run();
    assert_eq!(holding(&mut w, 1, &x), Some(Holding::Stub), "X a stub, by its signal");
    assert_eq!(holding(&mut w, 1, &h2), None, "nothing of H2");
}
