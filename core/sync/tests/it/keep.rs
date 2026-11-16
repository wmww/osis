//! Keeping S unread end to end, in a world of product nodes: a grant of sync on a group kept
//! unread, a write logged there, pulled and held, then the removal's step registered and the copy
//! dropped, through the engine facade and the modules wherever they are built; and the inbox
//! module's deliveries in a node (re-sent only at expiry, not at a restart).

use crate::harness::World;
use osis_base::{Ak, Role, Value};
use osis_engine::Mutation;
use osis_engine::sync::Holding;

// spec/sync-judgement.md §3 (Own store: stamped when it writes S, a pulled entry stamped in place;
// Reader that is not a writer), spec/sync-ids.md §6 (Taking a stamped entry: a stamp under a
// superseded write key is refused; Steps: the registrar logs the rotation stamped under the
// source's head): node 0 (admin) writes t three times and a large value while node 1, keeping t's sync ID S unread,
// is off, then rotates t's write secret, issuing a step. Each own entry of node 0 stands stamped under
// the new head, the rotations the step registers under the step before it. With node 0 off,
// node 2 (a reader, no writer) registers the path at node 1, which takes the write node 0 logs as
// node 0 stamped it: node 2 deposits no write, at node 1's old head (it registers the step there
// first) or its new one, and registers the step only once node 1 holds the write rotation (holding
// no write secret to tell the step's write epoch, it reads the current one), so nothing is refused.
#[test]
fn a_head_move_restamps_own_entries_and_readers_deposit_nothing_spec_sync_judgement_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, value_ak, world};
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run, Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some((t, Holding::Unread)));
    assert_eq!(w.engine(2).sync_holder(&s).unwrap(), Some((t, Holding::Read)));
    w.power_off(1);
    let mut writes = Vec::new();
    for i in 0..3 {
        writes.push(w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Int(i)).unwrap();
            e.commit(m).unwrap().unwrap()
        }));
    }
    // a large value: its chunk and tree-node blobs go under S as own entries too
    let mut big = vec![0u8; osis_base::format::CHUNK_THRESHOLD + 1];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(1), &mut big);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("u:big.0").unwrap(), &Value::Bytes(big)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let pieces = w.store(0).entries(&s).unwrap().into_iter().filter(|e| e.own && w.engine(0).blob_commit(&e.blob).is_none()).count();
    assert!(pieces > 2, "pieces and record blobs logged: {pieces}");
    let path = |w: &mut World| w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    let before = path(&mut w).steps.len();
    let a0 = w.node(0).account.unwrap();
    w.write(0, |e| e.rotate_boxing_only(&[t], &[Role::Write], &[a0])).unwrap().expect("a rotation");
    w.run();
    let p = path(&mut w);
    assert_eq!(p.steps.len(), before + 1, "the rotation's step issued");
    let (parent, head) = (&p.steps[before - 1].0, &p.steps[before].0);
    let needs = w.engine(0).step_needs(&s, &head.id()).unwrap();
    assert!(!needs.is_empty());
    for e in w.store(0).entries(&s).unwrap().into_iter().filter(|e| e.own) {
        let c = w.engine(0).blob_commit(&e.blob);
        let key = if c.is_some_and(|c| needs.contains(&c)) { &parent.keys.write } else { &head.keys.write };
        let stamp = e.stamp.expect("stamped");
        assert!(osis_blob::verify_stamp(key, &s, &e.blob, &e.wrap, &stamp).is_ok(), "own entry {:?} of {c:?} stamped under its step", e.blob);
    }
    // a rotation the step registers held under no stamp that stands here (a stamp of no key
    // standing in) is stamped in place under the step's parent, not the new head, so a store
    // behind can still take it
    let (rb, rc) = w.store(0).entries(&s).unwrap().into_iter().find_map(|e| w.engine(0).blob_commit(&e.blob).filter(|c| needs.contains(c)).map(|c| (e, c))).expect("an entry of a rotation the step registers");
    w.store(0).clone().log(&s, osis_sync::types::Entry { stamp: Some(osis_crypto::Signature([7; 64])), ..rb }, None, None).unwrap();
    w.power_off(0);
    w.power_on(0);
    w.run();
    let e = w.store(0).entry(&s, &rb.blob).unwrap().expect("kept");
    assert!(e.own && e.stamp.is_some_and(|x| osis_blob::verify_stamp(&parent.keys.write, &s, &e.blob, &e.wrap, &x).is_ok()), "{rc:?} stamped under the parent: {e:?}");
    // node 0's own entries of the writes it still logs (the last; the others are replaced), and
    // node 2's deposits of the writes
    let logged: Vec<osis_base::BlobId> = w.store(0).entries(&s).unwrap().into_iter().filter(|e| e.own && w.engine(0).blob_commit(&e.blob).is_some_and(|c| writes.contains(&c))).map(|e| e.blob).collect();
    assert!(!logged.is_empty());
    let reader_deposits = |w: &mut World| {
        let es: Vec<osis_sync::types::Entry> = w.store(2).entries(&s).unwrap().into_iter().filter(|e| e.own && e.deposited).collect();
        es.iter().filter(|e| w.engine(2).blob_commit(&e.blob).is_some_and(|c| writes.contains(&c))).count()
    };
    assert_eq!(reader_deposits(&mut w), 0);
    w.power_off(0);
    w.power_on(1);
    w.run();
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), Some(head.id()), "node 2 registered the step at node 1");
    for b in &logged {
        assert!(w.store(1).entry(&s, b).unwrap().is_some_and(|e| e.stamp.is_some()), "{b:?} taken at node 1 as node 0 stamped it");
    }
    assert_eq!(reader_deposits(&mut w), 0, "node 2 deposits nothing");
    // node 2, holding no write secret, registered the step only once node 1 held the write
    // rotation, so node 1 took it as node 0 stamped it, never refused (code 9) nor deposited
    for c in needs.iter() {
        let blobs = w.engine(0).commit_blobs(c).unwrap();
        assert!(blobs.iter().any(|b| w.store(1).entry(&s, b).unwrap().is_some_and(|e| e.stamp.is_some() && !e.deposited)), "rotation {c:?} taken stamped at node 1");
        assert!(!blobs.iter().chain(w.engine(2).commit_blobs(c).unwrap().iter()).any(|b| w.store(2).entry(&s, b).unwrap().is_some_and(|e| e.own && e.deposited)), "node 2 deposits no rotation {c:?}");
    }
}
