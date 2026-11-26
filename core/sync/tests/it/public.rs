//! The public in sync (spec/sync-set.md §2 T's keys open; spec/sync-ids.md §3 the
//! public entry; spec/sync-opens.md §4-§5; spec/wire.md §10 public links): what the public reads
//! is carried whole by every unit whose strongs reach it, entered by readers served only that
//! unit, and opened by anyone holding a public link.

use crate::harness::history::{self, Gives, value_ak};
use crate::harness::{World, edge, two_nodes};
use osis_base::{Role, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Node `i` makes a thing minted with `admin`, holding `v`, held by a strong from `admin`.
fn make(w: &mut World, i: usize, admin: Tid, v: &str) -> Tid {
    w.write(i, |e| {
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin, None));
        m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
        strong(&mut m, admin, t);
        e.commit(m).unwrap();
        t
    })
}

fn strong(m: &mut Mutation, from: Tid, to: Tid) {
    m.op(from, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(to)) }).unwrap();
}

fn set(w: &mut World, i: usize, t: Tid, v: &str) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap();
    });
}

fn reads(w: &mut World, i: usize, t: &Tid) -> Option<Value> {
    w.engine(i).get(t, &value_ak()).ok().flatten()
}

/// T (node 0's, kept unread by node 1, read by node 2) strongs P, a thing node 0 made public, and
/// D, a dependent of X, another public thing T reaches no other way. Node 2 reaches node 1 alone,
/// which keeps T unread: whatever node 2 reads of P and D it reads from T's sync ID.
fn reaching_public() -> (World, Tid, Tid, Tid) {
    let (mut w, t, _) = history::three(Gives::Reads, 1);
    let a = w.node(0).account.unwrap();
    let p = make(&mut w, 0, a, "p1");
    let x = make(&mut w, 0, a, "x1");
    let d = make(&mut w, 0, x, "d1");
    for g in [p, x] {
        w.write(0, |e| e.grant(&g, &Tid::PUBLIC, &edge(Role::Read))).unwrap();
    }
    w.write(0, |e| {
        let mut m = Mutation::new();
        strong(&mut m, t, p);
        strong(&mut m, t, d);
        e.commit(m).unwrap();
    });
    w.partition(0, 2);
    w.run();
    (w, t, p, d)
}

// spec/permissions.md §1 (The public): the public's removal is carried while a strong reaches the
// thing, and the public's departure rotates read as any. Node 0 removes the public from P and
// writes again. Node 2 learns the removal from what T carries of P (P leaves T's unit there as at
// node 0) and reads nothing written since (model control `WhileRead`: without the removal it
// would keep P in the unit).
#[test]
fn removing_the_public_ends_what_a_reader_of_the_referrer_reads_spec_sync_set_2() {
    let (mut w, t, p, _) = reaching_public();
    w.write(0, |e| e.demote(&p, &osis_engine::flows::Demotion { holder: Tid::PUBLIC, new: None, retain: None })).unwrap();
    set(&mut w, 0, p, "p2");
    w.run();
    assert!(!w.engine(0).sync_unit(&t).contains(&p), "P left T's unit at its logger");
    assert!(!w.engine(2).sync_unit(&t).contains(&p), "and at the reader");
    assert_ne!(reads(&mut w, 2, &p), Some(Value::Str("p2".into())), "nothing written since the removal");
}

// spec/sync-set.md §4 (Redeeming a public link), spec/sync-opens.md §4 (Departed), §5 (Opening),
// spec/permissions.md §3 (No secret taken back): node 1 grants node 0's account write on X (no
// strong to it), makes X public and removes that grant. Node 0, a departed peer of X at node 1,
// redeems a public link to X: node 1 shows it the public entry at X's newest read epoch, which
// covers its departure; node 0 takes the answer's box though it judges node 1 a holder, and the
// box's secret though its removal is held (the epoch covers it), and reads X. Each rule undone
// leaves it pending.
#[test]
fn a_removed_grantee_redeems_a_public_link_spec_sync_set_4() {
    use crate::harness::Step::*;
    use crate::harness::history::Holder;
    let mut w = crate::harness::contacts();
    let _ = crate::harness::play(&mut w, &[New(1), Give(1, 0, Holder::Node(0), Gives::Writes), Run, Give(1, 0, Holder::Public, Gives::Reads), Revoke(1, 0, Holder::Node(0)), Run], String::new());
    let t = w.history.things[0].0;
    let link = w.public_link(1, t).expect("X is public");
    assert_eq!(w.redeem_any(0, &link), osis_sync::types::Waiting::Pending);
    w.run();
    assert!(reads(&mut w, 0, &t).is_some(), "node 0 reads X by the public link");
    assert!(!w.node(0).node.redeeming(&t), "redeemed");
}

// spec/sync-inbox.md §6 (First contact): node 1
// redeems a public link to P while node 0 is unreachable and restarts: the redeem goes on from its
// kept row (as a share link's), and once node 0 is back node 1 reads P.
#[test]
fn a_public_redeem_goes_on_across_a_restart_spec_sync_inbox_6() {
    let mut w = two_nodes();
    let a = w.node(0).account.unwrap();
    let p = make(&mut w, 0, a, "p1");
    w.write(0, |e| e.grant(&p, &Tid::PUBLIC, &edge(Role::Read))).unwrap();
    w.run();
    let link = w.public_link(0, p).expect("P is public");
    w.partition(0, 1);
    assert_eq!(w.redeem_any(1, &link), osis_sync::types::Waiting::Pending);
    w.advance(1_000);
    w.power_off(1);
    w.power_on(1);
    w.advance(1);
    assert!(w.node(1).node.redeeming(&p), "kept across the restart");
    w.heal();
    w.run();
    assert_eq!(reads(&mut w, 1, &p), Some(Value::Str("p1".into())), "read by the public link");
    assert!(!w.node(1).node.redeeming(&p), "redeemed");
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(!w.node(1).node.redeeming(&p), "nothing kept once redeemed");
}

// spec/wire.md §10, spec/sync-set.md §4, spec/sync-opens.md §4-§5: redeeming a public link writes
// a strong to its target; the public entry is shown where the public reads S's thing and tested
// by its redeemer, its Hit carries no proof and its answer the head's open entry box. Node 1, holding no
// role of node 0's and nothing of P, redeems a public link to P and reads it.
#[test]
fn a_stranger_opens_a_public_thing_by_a_public_link_spec_wire_10() {
    let mut w = two_nodes();
    let a = w.node(0).account.unwrap();
    let p = make(&mut w, 0, a, "p1");
    w.write(0, |e| e.grant(&p, &Tid::PUBLIC, &edge(Role::Read))).unwrap();
    w.run();
    let link = w.public_link(0, p).expect("P is public");
    assert_eq!(reads(&mut w, 1, &p), None, "a stranger to P");
    assert_eq!(w.redeem_any(1, &link), osis_sync::types::Waiting::Pending);
    w.run();
    assert_eq!(reads(&mut w, 1, &p), Some(Value::Str("p1".into())), "read by the public link");
    assert!(!w.node(1).node.redeeming(&p), "redeemed: the strong holds it");
    assert_eq!(w.redeem_any(1, &link), osis_sync::types::Waiting::Done);
}


// spec/sync-set.md §2 (Dependent entry), §4 (Redeeming a public link), spec/wire.md §10:
// node 0 makes X public, X strongs D (X's dependent); node 1, a stranger, redeems a public link to
// D. Its account's strong to D enters X's unit, read by the public's grant, so node 1 reads D and
// keeps receiving D's writes under X's sync ID (no node reading its account holds D otherwise);
// once the public is removed it reads nothing written since.
#[test]
fn a_stranger_redeems_a_public_link_to_a_dependent_and_follows_it_spec_sync_set_2() {
    let mut w = two_nodes();
    let a = w.node(0).account.unwrap();
    let x = make(&mut w, 0, a, "x1");
    let d = make(&mut w, 0, x, "d1");
    w.write(0, |e| e.grant(&x, &Tid::PUBLIC, &edge(Role::Read))).unwrap();
    w.run();
    let link = w.public_link(0, d).expect("D is public");
    assert_eq!(w.redeem_any(1, &link), osis_sync::types::Waiting::Pending);
    w.run();
    assert_eq!(reads(&mut w, 1, &d), Some(Value::Str("d1".into())), "read by the public link");
    assert!(!w.node(1).node.redeeming(&d), "redeemed: the strong holds it");
    set(&mut w, 0, d, "d2");
    w.run();
    assert_eq!(reads(&mut w, 1, &d), Some(Value::Str("d2".into())), "D's later writes reach it");
    w.write(0, |e| e.demote(&x, &osis_engine::flows::Demotion { holder: Tid::PUBLIC, new: None, retain: None })).unwrap();
    set(&mut w, 0, d, "d3");
    w.run();
    assert_ne!(reads(&mut w, 1, &d), Some(Value::Str("d3".into())), "nothing written since the removal");
}

// spec/sync-opens.md §5 (Opening), spec/crypto.md §4 (Roles secrets): X rotates after the public's
// grant, so the grant's commit is wrapped under an epoch older than those the head's open entry box
// gives. A stranger redeeming a public link to X opens it by the roles secrets the history of the
// box's epoch carries, holding no role yet, and reads X.
#[test]
fn a_stranger_redeems_a_public_link_after_a_rotation_spec_crypto_4() {
    let mut w = two_nodes();
    let a = w.node(0).account.unwrap();
    let p = make(&mut w, 0, a, "p1");
    w.write(0, |e| e.grant(&p, &Tid::PUBLIC, &edge(Role::Read))).unwrap();
    let q = make(&mut w, 0, a, "q");
    w.write(0, |e| e.grant(&p, &q, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.demote(&p, &osis_engine::flows::Demotion { holder: q, new: None, retain: None })).unwrap();
    w.run();
    let link = w.public_link(0, p).expect("P is public");
    assert_eq!(w.redeem_any(1, &link), osis_sync::types::Waiting::Pending);
    w.run();
    assert_eq!(reads(&mut w, 1, &p), Some(Value::Str("p1".into())), "read by the public link");
}

// spec/wire.md §10, spec/sync-set.md §4: the link text is untrusted. A crafted public link to D,
// a dependent of X that the public does not read, names Y (another thing the public reads) as
// D's independent with Y's sync ID: node 1 follows Y and opens it, but D's record says its
// independent is X, whose public grant is never held, so it writes no strong to D and reads
// nothing of it.
#[test]
fn a_public_link_naming_another_independent_reads_nothing_of_its_target_spec_wire_10() {
    let mut w = two_nodes();
    let a = w.node(0).account.unwrap();
    let x = make(&mut w, 0, a, "x1");
    let d = make(&mut w, 0, x, "d1");
    let y = make(&mut w, 0, a, "y1");
    w.write(0, |e| e.grant(&y, &Tid::PUBLIC, &edge(Role::Read))).unwrap();
    w.run();
    let Some(osis_blob::Link::Public(ly)) = w.public_link(0, y) else { panic!("Y is public") };
    assert!(w.public_link(0, d).is_none(), "D is not public");
    let crafted = osis_blob::Link::Public(osis_blob::PublicLink { target: d, independent: Some(y), ..ly });
    assert_eq!(w.redeem_any(1, &crafted), osis_sync::types::Waiting::Pending);
    w.run();
    assert_eq!(reads(&mut w, 1, &d), None, "D read by a link naming another independent");
    assert_eq!(reads(&mut w, 1, &x), None);
}
