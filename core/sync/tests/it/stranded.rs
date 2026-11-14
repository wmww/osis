//! Stranded reports end to end (spec/permissions.md §4 Stranded, §3 Re-seal): a holder left out of
//! a rotation reports, an admin re-seals it, its members read again.

use crate::flows::edge;
use crate::harness::history::{file, world};
use crate::harness::{World, contacts};
use osis_base::{Ak, Role, Tid, Value};
use osis_engine::Mutation;

fn put(w: &mut World, i: usize, t: Tid, ak: &Ak, v: &str) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, ak, &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap();
    });
}

/// Node 1's team T (node 0's account reads it) holds read on node 0's thing G; node 1 reads G
/// through T alone; every other node's account reads G directly. (world, G, T, ak)
fn team_reads(mut w: World) -> (World, Tid, Tid, Ak) {
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let new = |w: &mut World, i: usize, a: Tid| {
        w.write(i, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            e.commit(m).unwrap();
            t
        })
    };
    let t = new(&mut w, 1, a1);
    file(&mut w, 1, vec![t], Vec::new());
    w.write(1, |e| e.grant(&t, &a0, &edge(Role::Read))).unwrap();
    w.run();
    file(&mut w, 0, Vec::new(), vec![t]);
    w.run();
    let g = new(&mut w, 0, a0);
    file(&mut w, 0, vec![g], Vec::new());
    put(&mut w, 0, g, &ak, "before");
    w.write(0, |e| e.grant(&g, &t, &edge(Role::Read))).unwrap();
    for i in 2..w.len() {
        let a = w.node(i).account.unwrap();
        w.write(0, |e| e.grant(&g, &a, &edge(Role::Read))).unwrap();
    }
    w.run();
    for i in 1..w.len() {
        file(&mut w, i, Vec::new(), vec![g]);
    }
    w.run();
    assert_eq!(w.engine(1).get(&g, &ak).unwrap(), Some(Value::Str("before".into())), "node 1 reads G through T");
    (w, g, t, ak)
}

// spec/permissions.md §4 (stranded), §3 (Re-seal): a Stranded message to a connected peer that
// proved an account holding write or above; the receiver re-seals the current holder it names at
// the end of a complete pass. Node 0 rotates G leaving team T out,
// so node 1 holds no current read secret of G. Heard out, node 1 reports itself stranded on G to
// node 0, which re-seals T at its next complete pass's end; node 1 reads what node 0 wrote
// meanwhile and after, and is stranded no more.
#[test]
fn a_holder_left_out_of_a_rotation_reads_again_by_its_report_spec_permissions_4() {
    let (mut w, g, t, ak) = team_reads(contacts());
    let a0 = w.node(0).account.unwrap();
    let inbox = w.engine(1).inbox_of(&a0).unwrap();
    let deposits = |w: &World| w.store(1).entries(&inbox).unwrap().into_iter().filter(|e| e.own && e.deposited).count();
    let before = deposits(&w);
    w.write(0, |e| e.rotate_leaving_out(&g, &[Role::Read], &[t])).unwrap();
    put(&mut w, 0, g, &ak, "left out");
    w.run();
    assert_eq!(w.engine(1).get(&g, &ak).unwrap(), Some(Value::Str("left out".into())), "node 1 reads G again");
    put(&mut w, 0, g, &ak, "after");
    w.run();
    assert_eq!(w.engine(1).get(&g, &ak).unwrap(), Some(Value::Str("after".into())));
    let s = w.engine(1).sync_ids(&g).unwrap()[0].id;
    assert!(!w.status(1)[&s].stranded, "stranded no more");
    assert_eq!(deposits(&w), before, "a writer connected: no notice");
}

// spec/permissions.md §4 (stranded), spec/wire.md §9 (Stranded notice): with no writer of the
// actor connected, a stranded notice under the inbox of each admin it holds. Node 1, cut off
// from node 0 (G's only writer), learns G's rotation leaving T out from node 2, a reader; it
// deposits a notice under node 0's inbox. Once node 0 is reachable again node 1 is re-sealed and
// reads.
#[test]
fn a_holder_with_no_writer_connected_leaves_a_notice_spec_permissions_4() {
    let (mut w, g, t, ak) = team_reads(world(0, 3));
    let a0 = w.node(0).account.unwrap();
    let inbox = w.engine(1).inbox_of(&a0).unwrap();
    let deposits = |w: &World| w.store(1).entries(&inbox).unwrap().into_iter().filter(|e| e.own && e.deposited).count();
    let before = deposits(&w);
    w.partition(0, 1);
    w.run();
    w.write(0, |e| e.rotate_leaving_out(&g, &[Role::Read], &[t])).unwrap();
    put(&mut w, 0, g, &ak, "left out");
    w.run();
    assert_eq!(w.engine(2).get(&g, &ak).unwrap(), Some(Value::Str("left out".into())), "node 2 reads it");
    let s = w.engine(1).sync_ids(&g).unwrap()[0].id;
    assert!(w.status(1)[&s].stranded, "node 1 is stranded on G");
    assert_eq!(deposits(&w), before + 1, "one notice deposited under node 0's inbox");
    // once per step's sync key (spec/permissions.md §4): neither node 2 reconnecting nor node 1
    // restarting sends it again
    w.cap = 2 * crate::harness::RULE_CAP;
    w.cut(1, 2);
    w.run();
    assert_eq!(deposits(&w), before + 1, "no notice again at a reconnect");
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(w.status(1)[&s].stranded, "still stranded on G");
    assert_eq!(deposits(&w), before + 1, "no notice again at a restart");
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&g, &ak).unwrap(), Some(Value::Str("left out".into())), "node 1 reads G again");
}

// spec/permissions.md §4 (stranded), §3 (Re-seal): a notice asks only for a re-seal the
// recipient judges itself. A stranded notice taken from the admin's inbox asks a complete
// pass of G's sync ID once; taking it again (or a repeat with the same keys) asks nothing more,
// and one naming a thing that is no holder of G asks nothing.
#[test]
fn a_stranded_notice_asks_one_pass_spec_permissions_4() {
    let (mut w, g, t, _) = team_reads(contacts());
    let a0 = w.node(0).account.unwrap();
    let s = w.engine(0).sync_ids(&g).unwrap()[0].id;
    let mut rng = osis_crypto::SeededRng::from_seed([7; 32]);
    let notice = w.engine(1).stranded_notice(&s, &t, &a0, &mut rng).unwrap().unwrap();
    let a1 = w.node(1).account.unwrap();
    let stranger = w.engine(1).stranded_notice(&s, &a1, &a0, &mut rng).unwrap().unwrap();
    let wanted = |w: &mut World| w.engine(0).passes_wanted().unwrap().contains_key(&s);
    assert!(!wanted(&mut w));
    w.write(0, |e| e.take_inbox_blob(&stranger, false)).unwrap();
    assert!(!wanted(&mut w), "a thing holding nothing on G asks nothing");
    w.write(0, |e| e.take_inbox_blob(&notice, false)).unwrap();
    assert!(wanted(&mut w), "a pass of G's sync ID is wanted");
    w.run();
    assert!(!wanted(&mut w), "met at the pass's end");
    w.write(0, |e| e.take_inbox_blob(&notice, false)).unwrap();
    assert!(!wanted(&mut w), "the same report again asks nothing");
}

// spec/permissions.md §4 (stranded): a receiver that may re-seal the actor takes the holder
// keys when they name a current holder of it. T rotates unseen by nodes 0 and 2; a report naming T
// brings T's new keyset to node 0 (G's admin), never to node 2 (a reader of G, who may re-seal
// nothing there).
#[test]
fn holder_keys_are_taken_only_where_a_reseal_may_follow_spec_permissions_4() {
    let (mut w, g, t, _) = team_reads(world(0, 3));
    w.partition(0, 1);
    w.partition(1, 2);
    w.run();
    let k = w.write(1, |e| e.rotate_leaving_out(&t, &[Role::Read], &[])).unwrap().unwrap();
    let keys = w.engine(1).holder_keys(&t).unwrap();
    let s = w.engine(0).sync_ids(&g).unwrap()[0].id;
    for i in [2, 0] {
        assert!(w.engine(i).header(&k).is_none(), "node {i} lacks T's new keyset");
        w.write(i, |e| e.take_stranded(&s, &t, &keys)).unwrap();
    }
    assert!(w.engine(2).header(&k).is_none(), "node 2 takes nothing");
    assert!(w.engine(0).current_keys(&t).contains(&k), "node 0 takes T's new keyset");
}

// spec/permissions.md §4 (stranded: every source refused every open it had to try, wherever its
// walk stopped), spec/sync-ids.md §6 (Walk: Stranded there): node 1 reads G, node 2 keeps it
// unread; cut off from node 0, node 1 reaches only node 2, whose head moves to the step of a
// rotation of G's sync and read roles leaving node 1's account out. Its walk at node 2 stops
// past its keys, so with no source it is stranded and deposits a notice under node 0's inbox;
// once node 0 is reachable it is re-sealed and reads. Neither a reconnect nor a restart sends
// it again.
#[test]
fn a_reader_reaching_only_a_store_past_its_keys_reports_spec_permissions_4() {
    let mut w = world(0, 3);
    let (a0, a1, a2) = (w.node(0).account.unwrap(), w.node(1).account.unwrap(), w.node(2).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let g = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, vec![g], Vec::new());
    put(&mut w, 0, g, &ak, "before");
    w.write(0, |e| e.grant(&g, &a1, &edge(Role::Read))).unwrap();
    w.write(0, |e| e.grant(&g, &a2, &edge(Role::Sync))).unwrap();
    w.run();
    for i in [1, 2] {
        file(&mut w, i, Vec::new(), vec![g]);
    }
    w.run();
    let s = w.engine(0).sync_ids(&g).unwrap()[0].id;
    assert_eq!(w.engine(1).get(&g, &ak).unwrap(), Some(Value::Str("before".into())), "node 1 reads G");
    assert_eq!(w.engine(2).sync_holder(&s).unwrap(), Some((g, osis_engine::sync::Holding::Unread)), "node 2 keeps G unread");
    let inbox = w.engine(1).inbox_of(&a0).unwrap();
    let deposits = |w: &World| w.store(1).entries(&inbox).unwrap().into_iter().filter(|e| e.own && e.deposited).count();
    let before = deposits(&w);
    w.partition(0, 1);
    w.run();
    w.write(0, |e| e.rotate_leaving_out(&g, &[Role::Sync, Role::Read], &[a1])).unwrap();
    put(&mut w, 0, g, &ak, "left out");
    w.run();
    let head = w.engine(0).sync_ids(&g).unwrap()[0].path.steps.last().map(|(st, _)| st.id());
    assert_eq!(w.store(2).head(&s).unwrap().map(|h| h.id()), head, "node 2 at the rotation's step");
    assert!(w.status(1)[&s].stranded, "node 1 is stranded on G");
    assert_eq!(deposits(&w), before + 1, "one notice deposited under node 0's inbox");
    // once per step's sync key (spec/permissions.md §4): neither node 2 reconnecting nor node 1
    // restarting sends it again
    w.cap = 2 * crate::harness::RULE_CAP;
    w.cut(1, 2);
    w.run();
    assert_eq!(deposits(&w), before + 1, "no notice again at a reconnect");
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert!(w.status(1)[&s].stranded, "still stranded on G");
    assert_eq!(deposits(&w), before + 1, "no notice again at a restart");
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&g, &ak).unwrap(), Some(Value::Str("left out".into())), "node 1 reads G again");
    assert!(!w.status(1)[&s].stranded, "stranded no more");
}
