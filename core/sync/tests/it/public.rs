//! The public in sync (spec/sync-set.md §2 T's keys open, Public pieces; spec/sync-ids.md §3 the
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

// spec/sync-set.md §2 (T's keys open; Public pieces), spec/sync-judgement.md §2 (the stubs and
// public pieces S's sync unit carries): T's keys open what the public reads by its own grant on
// the thing's independent, and T's pieces show it. Node 2, served only by node 1 keeping T unread, reads P whole and D (whose independent X no
// strong reaches: its piece is X's), and computes T's unit as node 0 does. Without the clause
// neither is carried; without the pieces node 2 never enters them (held-model `closure::public`).
#[test]
fn a_reader_served_by_a_store_reads_what_the_public_reads_spec_sync_set_2() {
    let (mut w, t, p, d) = reaching_public();
    assert_eq!(reads(&mut w, 2, &p), Some(Value::Str("p1".into())), "P read through T alone");
    assert_eq!(reads(&mut w, 2, &d), Some(Value::Str("d1".into())), "a public thing's dependent read through T");
    let unit = w.engine(0).sync_unit(&t);
    assert!(unit.contains(&p) && unit.contains(&d), "T's unit carries both at its logger");
    assert_eq!(w.engine(2).sync_unit(&t), unit, "the reader computes the logger's unit");
}

// spec/sync-set.md §2 (Public pieces), spec/permissions.md §1 (The public): a removal's piece
// stays carried while a strong reaches the thing, and the public's departure rotates read as
// any. Node 0 removes the
// public from P and writes again. Node 2 learns the removal from T's pieces (P leaves T's unit
// there as at node 0) and reads nothing written since (model control `WhileRead`: without the
// removal's piece it would keep P in the unit).
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
