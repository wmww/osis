//! Keeping S unread end to end, in a world of product nodes: a grant of sync on a thing with own
//! keys kept unread, a write logged there, pulled and held, then the removal's step registered and the copy
//! dropped, through the engine facade and the modules wherever they are built; the inbox
//! module's deliveries in a node (re-sent only at expiry, not at a restart); and the record blobs
//! readers keep in their own stores.

use crate::harness::World;
use osis_base::{Ak, Role, Value};
use osis_engine::Mutation;
use osis_engine::sync::Holding;

// spec/sync-judgement.md §3 (Own store: stamped when it writes S, a pulled entry stamped in place;
// Giving a body), spec/sync-ids.md §6 (Taking a stamped entry: a stamp under a
// superseded write key is refused; Steps: the registrar logs the rotation stamped under the
// source's head): node 0 (admin) writes t three times and a large value while node 1, keeping t's sync ID S unread,
// is off, then rotates t's write secret, issuing a step. Each own entry of node 0 stands stamped under
// the new head, the rotations the step registers under the step before it. With node 0 off,
// node 2 (a reader, no writer) registers the path at node 1, which takes the write node 0 logs as
// node 0 stamped it: node 2 deposits no write, at node 1's old head (it registers the step there
// first) or its new one, and registers the step only once node 1 holds the write rotation (holding
// no write secret to tell the step's write epoch, it reads the current one), so nothing is refused.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_head_move_restamps_own_entries_and_readers_deposit_nothing_spec_sync_judgement_3() {
    use crate::harness::history::{Gives, three, value_ak};
    let (mut w, t, s) = three(Gives::Reads, 2);
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Unread)));
    assert_eq!(w.engine(2).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Read)));
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
    // a rotation the step waits on held under no stamp that stands here (a stamp of no key
    // standing in, or one under the new head: logged as the head moved) is stamped in place
    // under the step's parent, not the new head, so a store behind can still take it
    let (rb, rc) = w.store(0).entries(&s).unwrap().into_iter().find_map(|e| w.engine(0).blob_commit(&e.blob).filter(|c| needs.contains(c)).map(|c| (e, c))).expect("an entry of a rotation the step registers");
    let at_head = w.engine(0).step_write_key(&s, &head.id()).unwrap().expect("node 0 writes the head");
    for stamp in [osis_crypto::Signature([7; 64]), osis_blob::sign_stamp(&at_head, &s, &rb.blob, &rb.wrap, rb.role)] {
        w.store(0).clone().log(&s, osis_sync::types::Entry { stamp: Some(stamp), ..rb.clone() }, None, None).unwrap();
        w.power_off(0);
        w.power_on(0);
        w.run();
        let e = w.store(0).entry(&s, &rb.blob).unwrap().expect("kept");
        assert!(e.own && e.stamp.is_some_and(|x| osis_blob::verify_stamp(&parent.keys.write, &s, &e.blob, &e.wrap, &x).is_ok()), "{rc:?} stamped under the parent: {e:?}");
    }
    // node 0's own entries of the writes it still logs (the last; the others are replaced)
    let logged: Vec<osis_base::BlobId> = w.store(0).entries(&s).unwrap().into_iter().filter(|e| e.own && w.engine(0).blob_commit(&e.blob).is_some_and(|c| writes.contains(&c))).map(|e| e.blob).collect();
    assert!(!logged.is_empty());
    w.power_off(0);
    w.power_on(1);
    w.run();
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), Some(head.id()), "node 2 registered the step at node 1");
    for b in &logged {
        assert!(w.store(1).entry(&s, b).unwrap().is_some_and(|e| e.stamp.is_some()), "{b:?} taken at node 1 as node 0 stamped it");
    }
    let deposited: Vec<osis_sync::types::Entry> = w.store(1).entries(&s).unwrap().into_iter().filter(|e| e.deposited).collect();
    assert!(!deposited.iter().any(|e| w.engine(2).blob_commit(&e.blob).is_some_and(|c| writes.contains(&c))), "node 2 deposits no write: {deposited:?}");
    // node 2, holding no write secret, registered the step only once node 1 held the write
    // rotation, so node 1 took it as node 0 stamped it, never refused (code 9). (Node 2 may log
    // an encryption of its own beside it: a rotation's parts are role parts, which any holder
    // encrypts, spec/crypto.md §4 Roles secrets, and it holds the rotation from its offer before
    // S's stream shows it, spec/permissions.md §4 Logging certificates.)
    for c in needs.iter() {
        let blobs = w.engine(0).commit_blobs(c).unwrap();
        assert!(blobs.iter().any(|b| w.store(1).entry(&s, b).unwrap().is_some_and(|e| e.stamp.is_some() && !e.deposited)), "rotation {c:?} taken stamped at node 1");
    }
}

// spec/sync-ids.md §6 (Steps: each role commit a recorded step depends on is waited on by one
// step, stamped under its parent; Taking a stamped entry: one under a superseded write key goes
// as a deposit), spec/sync-judgement.md §3 (Giving a body): node 0 rotates t's write secret twice
// while node 1, keeping t's sync ID S unread, is off, issuing two steps; the second's write epoch
// supersedes the first's. In every node's view the steps wait on disjoint commits, each stamped
// under the parent of the step waiting on it, and the second does not wait on the first's
// rotation. Node 1, moved one step at a time, holds every commit each step waits on: node 2 (no
// write secret) waits on the write rotations only at the step that brought the newest write key,
// so it may register the first step before node 1 took that step's rotation, stamped by node 0
// under genesis; node 0 then gives it as a deposit.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_store_moved_step_by_step_holds_what_each_step_waits_on_spec_sync_ids_6() {
    use crate::harness::history::{Gives, three};
    let (mut w, t, s) = three(Gives::Reads, 2);
    let path = |w: &mut World| w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.clone();
    let before = path(&mut w).steps.len();
    w.power_off(1);
    let a0 = w.node(0).account.unwrap();
    for _ in 0..2 {
        w.write(0, |e| e.rotate_boxing_only(&[t], &[Role::Write], &[a0])).unwrap().expect("a rotation");
        w.run();
    }
    let p = path(&mut w);
    assert_eq!(p.steps.len(), before + 2, "a step per rotation");
    w.power_on(1);
    w.run();
    assert_eq!(w.store(1).head(&s).unwrap().map(|h| h.id()), p.steps.last().map(|(st, _)| st.id()));
    for i in [0, 2] {
        let mut seen = std::collections::BTreeSet::new();
        for (k, (st, _)) in p.steps.iter().enumerate() {
            for c in w.engine(i).step_needs(&s, &st.id()).unwrap().iter() {
                assert!(seen.insert(*c), "node {i}: {c:?} waited on by two steps");
                let parent = w.engine(i).step_parent(&s, c).unwrap().map(|x| x.id());
                assert_eq!(parent, k.checked_sub(1).map(|j| p.steps[j].0.id()), "node {i}: {c:?} under step {k}'s parent");
            }
        }
    }
    let (first, second) = (p.steps[before].0.id(), p.steps[before + 1].0.id());
    let firsts = w.engine(0).step_needs(&s, &first).unwrap();
    assert!(!firsts.is_empty() && !w.engine(0).step_needs(&s, &second).unwrap().is_empty());
    for (k, (st, _)) in p.steps.iter().enumerate().skip(1) {
        for c in w.engine(0).step_needs(&s, &st.id()).unwrap().iter() {
            let blobs = w.engine(0).commit_blobs(c).unwrap();
            let held: Vec<_> = blobs.iter().map(|b| w.store(1).entry(&s, b).unwrap()).collect();
            let own: Vec<_> = blobs.iter().map(|b| w.store(0).entry(&s, b).unwrap()).collect();
            assert!(held.iter().any(|e| e.as_ref().is_some_and(|e| e.role)), "{c:?} of step {k} of {} held at node 1, a role entry: {held:?} node 0 {own:?}", p.steps.len());
        }
    }
}

// spec/sync-opens.md §6 (whose peer J judges departed is ended too; this side registers there
// the recorded steps after the source's step), spec/sync-judgement.md §6 (Stops): node 1 keeps t's sync ID S
// unread and node 2 reads it. Node 0 removes node 1's account while cut off from node 1, so only
// node 2, learning the removal from node 0, can tell node 1: it registers the removal's step
// there, and node 1 drops its copy.
//
// spec/sync-status.md §1 (the sources of S: peers with S open on a connection up now): node 2
// ends S toward node 1 and closes it once node 1 reports reaching its end (a close opens makes on
// a report, not on a message): at quiet neither node counts the other a source of S on a
// connection where S is no member (`World::run` checks every node).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_moves_a_removed_store_past_its_keys_spec_sync_opens_6() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, Holder, three};
    let (mut w, t, s) = three(Gives::Reads, 2);
    w.cap = crate::harness::WIDE_CAP;
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Unread)));
    assert!(!w.store(1).entries(&s).unwrap().is_empty(), "node 1 keeps S");
    w.partition(0, 1);
    let _ = crate::harness::play(&mut w, &[Revoke(0, 0, Holder::Node(1)), Run], String::new());
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "node 1 stopped: {} entries kept", w.store(1).entries(&s).unwrap().len());
    for i in 1..3 {
        let sources: Vec<_> = w.node(i).node.status_of(&s).map(|x| x.sources.into_keys().collect()).unwrap_or_default();
        assert!(sources.iter().all(|c| w.node(i).node.opens().members(*c).contains_key(&s)), "node {i}'s sources of S are members");
    }
}

// spec/sync-opens.md §4 (Admissible: toward a peer J judges departed, a reader shows the sync
// proofs of its recorded steps), §6 (A reader moves a removed store past its keys): node 1 keeps
// t's sync ID S unread, fetched from node 0 alone, and node 2 reads it. Node 0 removes node 1
// while cut off from it; node 2, learning the removal, has never shown node 1 its step (node 1
// was cut off from it while that step was the newest), so only a filter showing every recorded
// step lets node 1's Hit on its step open S there to be moved past its keys. Fails when a
// departed peer is shown nothing: node 1 keeps its copy.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_moves_a_removed_store_it_never_showed_its_step_spec_sync_opens_6() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, Holder, world_of};
    let mut w = world_of(0, 3, 3);
    w.cap = crate::harness::WIDE_CAP;
    w.partition(1, 2);
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Unread)));
    assert!(!w.store(1).entries(&s).unwrap().is_empty(), "node 1 keeps S");
    w.partition(0, 1);
    let _ = crate::harness::play(&mut w, &[Revoke(0, 0, Holder::Node(1)), Run], String::new());
    w.rejoin(1, 2);
    let _ = crate::harness::play(&mut w, &[Run], String::new());
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "node 1 stopped: {} entries kept", w.store(1).entries(&s).unwrap().len());
}

// spec/sync-opens.md §6 (A reader moves a removed store past its keys; whether or not S was open
// there at the removal): node 0 lowers node 1 from write to sync and removes it at once, so node
// 0 judges node 1 departed while still a reader source there and closes S at once; node 1 then
// keeps S unread at the lowering's step and cannot read the removal. Its Hit on that step's sync
// proof, which node 0's filter shows toward a departed peer, opens S ended at node 0, which
// registers past node 1's keys, and node 1 drops its copy.
#[test]
#[ignore = "stub rewrite: the differential's oracle on held-model's stub closure (R4)"]
fn a_reader_moves_a_store_departed_before_it_kept_s_unread_spec_sync_opens_6() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, Holder, world_of};
    let mut w = world_of(0, 2, 2);
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let _ = crate::harness::play(&mut w, &[Lower(0, 0, Holder::Node(1), Gives::Syncs), Revoke(0, 0, Holder::Node(1)), Run], String::new());
    assert!(w.store(1).entries(&s).unwrap().is_empty(), "node 1 stopped: {} entries kept", w.store(1).entries(&s).unwrap().len());
}

/// The record blobs node `i` holds in its own store for `s`.
fn record_blobs(w: &mut World, s: &osis_base::SyncId, i: usize) -> Vec<osis_base::BlobId> {
    let noted = w.engine(i).cert_blobs(s);
    w.store(i).entries(s).unwrap().into_iter().map(|e| e.blob).filter(|b| noted.contains_key(b)).collect()
}

/// Node `i` seals `records` with `rng` and logs the record blob in its own store.
fn log_own_records(w: &mut World, s: &osis_base::SyncId, i: usize, records: &std::collections::BTreeSet<osis_base::Tid>, rng: &mut osis_crypto::SeededRng) {
    let (blob, bytes, wrap) = w.engine(i).seal_records(s, records, rng).unwrap().expect("sealed");
    let e = osis_sync::types::Entry { blob, wrap, stamp: None, deposited: true, own: true, role: false, class: osis_blob::Class::Durable, expires: None };
    w.store(i).clone().log(s, e, Some(bytes), None).unwrap();
}

// spec/permissions.md §4 (Logging certificates: a record blob logged by any node counts once
// opened, while held in the own store): two readers of S each sealing a record blob of the same
// records at once (each before it saw the other's) settle, with the writer, on one record blob in
// every own store: one carrying all another carries, and more or under a lower ID, wins; none
// logs another of its own.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn readers_logging_the_same_records_settle_on_one_record_blob_spec_permissions_4() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world_of};
    let mut w = world_of(0, 3, 3);
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let records: std::collections::BTreeSet<osis_base::Tid> = w.engine(0).cert_blobs(&s).values().flat_map(|c| c.tids.iter()).copied().collect();
    assert!(!records.is_empty(), "S carries records");
    let held = |w: &mut World, i: usize| record_blobs(w, &s, i);
    for i in [1, 2] {
        log_own_records(&mut w, &s, i, &records, &mut osis_crypto::SeededRng::from_u64(i as u64));
    }
    // each reader comes back holding its own
    for i in [1, 2] {
        w.power_off(i);
        w.power_on(i);
    }
    w.run();
    let one = held(&mut w, 0);
    assert_eq!(one.len(), 1, "one record blob at the writer: {one:?}");
    for i in [1, 2] {
        assert_eq!(held(&mut w, i), one, "node {i} holds the same one record blob");
        let noted = w.engine(i).cert_blobs(&s);
        assert_eq!(noted.keys().copied().collect::<Vec<_>>(), one, "node {i} notes only it");
        assert!(noted.values().all(|x| x.tids.is_superset(&records)), "it carries every record");
    }
    // the winner then goes from every store (its losers counted only while a source showed them,
    // never fetched again): each node logs a record blob carrying the records anew, and they
    // settle on one again
    let won = one[0];
    for i in 0..3 {
        assert!(w.store(i).clone().drop_entry(&s, &won, Vec::new()).unwrap(), "node {i} held the winner");
    }
    for i in 0..3 {
        w.power_off(i);
        w.power_on(i);
    }
    w.run();
    let again = held(&mut w, 0);
    assert!(again.len() == 1 && again[0] != won, "one fresh record blob at the writer: {again:?}");
    for i in [1, 2] {
        assert_eq!(held(&mut w, i), again, "node {i} holds the fresh record blob");
        assert!(w.engine(i).cert_blobs(&s)[&again[0]].tids.is_superset(&records), "node {i}: it carries every record");
    }
}

/// Node 0 writes t and grants node 1 read; node 1 lets the one record blob of t's sync ID S go
/// and logs one of its own of the same records, a higher ID (a loser). (world, S, [the winner],
/// node 1's own)
fn reader_holding_a_loser() -> (World, osis_base::SyncId, Vec<osis_base::BlobId>, osis_base::BlobId) {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world_of};
    let mut w = world_of(0, 2, 2);
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let won = record_blobs(&mut w, &s, 0);
    assert_eq!(won.len(), 1, "one record blob at the writer: {won:?}");
    assert_eq!(record_blobs(&mut w, &s, 1), won, "the reader holds it");
    let records = w.engine(0).cert_blobs(&s)[&won[0]].tids.clone();
    assert!(w.store(1).clone().unlog_entry(&s, &won[0]).unwrap());
    let own = (0u64..)
        .find_map(|n| {
            let x = w.engine(1).seal_records(&s, &records, &mut osis_crypto::SeededRng::from_u64(n)).unwrap().expect("sealed");
            (x.0 > won[0]).then_some(x)
        })
        .unwrap();
    let e = osis_sync::types::Entry { blob: own.0, wrap: own.2, stamp: None, deposited: true, own: true, role: false, class: osis_blob::Class::Durable, expires: None };
    w.store(1).clone().log(&s, e, Some(own.1), None).unwrap();
    (w, s, won, own.0)
}

// spec/permissions.md §4 (Logging certificates: a record blob counts once opened, while held in the
// own store or shown at a source, and of two counted the loser leaves the own store): a reader that
// opened the winner and let it go (it judged it losing while its view of S's records was short)
// holds a loser of its own; the winner, shown at the writer, beats it there, and the reader
// fetches the winner and keeps it in place of its own.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_fetches_a_winning_record_blob_it_let_go_spec_permissions_4() {
    let (mut w, s, won, _) = reader_holding_a_loser();
    let noted = |w: &mut World, i: usize| record_blobs(w, &s, i);
    w.power_off(1);
    w.power_on(1);
    w.run();
    assert_eq!(noted(&mut w, 0), won, "the writer keeps the winner");
    assert_eq!(noted(&mut w, 1), won, "the reader fetched the winner and dropped its own");
}

// spec/permissions.md §4 (Logging certificates: a winner the own store lacks is fetched where
// shown, and a loser leaves once the winner is held): the reader holds a losing record blob of its own
// while the winner is shown only at the writer, which is unreachable. It keeps its own until it
// holds the winner: a source showing a blob it never serves leaves no reader without one.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_reader_keeps_a_losing_record_blob_until_it_holds_the_winner_spec_permissions_4() {
    let (mut w, s, won, own) = reader_holding_a_loser();
    let noted = |w: &mut World, i: usize| record_blobs(w, &s, i);
    w.power_off(0);
    w.power_off(1);
    w.power_on(1);
    w.flush();
    assert_eq!(noted(&mut w, 1), vec![own], "the reader keeps its own while the winner is out of reach");
    w.power_on(0);
    w.run();
    assert_eq!(noted(&mut w, 1), won, "the reader fetched the winner and dropped its own");
}

// spec/sync-ids.md §6 (Steps: a reader registers at each source keeping S unread the steps after
// the source's step), spec/sync-opens.md §6 (whether or not a connection holds its record):
// node 0 rotates t's write secret, issuing a step, while node 1 (keeping S
// unread) is apart from every reader, its record held by no connection; once they meet again the
// step is registered there, with nothing else moving.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_step_issued_while_a_store_is_away_is_registered_when_it_is_back_spec_sync_ids_6() {
    use crate::harness::history::{Gives, three};
    let (mut w, t, s) = three(Gives::Reads, 2);
    w.cap = crate::harness::WIDE_CAP;
    w.partition(0, 1);
    w.partition(1, 2);
    w.run();
    let a0 = w.node(0).account.unwrap();
    w.write(0, |e| e.rotate_boxing_only(&[t], &[Role::Write], &[a0])).unwrap().expect("a rotation");
    w.run();
    let head = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.last().unwrap().0.id();
    let at1 = |w: &World| w.store(1).path(&s).unwrap().and_then(|p| p.steps.last().map(|(st, _)| st.id()));
    assert_ne!(at1(&w), Some(head), "away: not registered");
    w.heal();
    w.run();
    assert_eq!(at1(&w), Some(head), "back: registered");
}

// spec/sync-ids.md §6 (Steps), spec/sync-opens.md §6 (whether or not a connection holds its
// record): node 0's Register of a new step at node 1 (keeping S unread) is lost with its
// connection; the plan, judged again while no connection holds the record, waits, and the step
// goes once they meet again.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_register_lost_with_its_connection_goes_again_at_the_reconnect_spec_sync_ids_6() {
    use crate::harness::history::{Gives, three};
    let (mut w, t, s) = three(Gives::Reads, 2);
    w.partition(1, 2);
    w.run();
    let a0 = w.node(0).account.unwrap();
    osis_base::costs::take();
    w.write(0, |e| e.rotate_boxing_only(&[t], &[Role::Write], &[a0])).unwrap().expect("a rotation");
    let registered = || osis_base::costs::take().into_iter().any(|(k, _, n)| k == "inbox: registered" && n > 0);
    let mut sent = false;
    while !sent && w.step_or_wake() {
        sent = registered();
    }
    assert!(sent, "node 0 sent a Register");
    w.cut(0, 1);
    let head = w.engine(0).sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.last().unwrap().0.id();
    let at1 = |w: &World| w.store(1).path(&s).unwrap().and_then(|p| p.steps.last().map(|(st, _)| st.id()));
    assert_ne!(at1(&w), Some(head), "the Register was lost");
    w.run();
    assert_eq!(at1(&w), Some(head), "registered once they met again");
}

// spec/sync-inbox.md §1 (Public key record), §3 (Who takes it: a Deposit item signed by S's
// head's deposit key), spec/crypto.md §7 (Checked keys: the steps placing a listed key ride as the commit's
// evidence): node 1 removes its sibling, node 2 (spec/permissions.md §8 Removing), which rotates
// the account's inbox; node 0, a contact, then grants the account read on a thing of its own and
// node 1 holds it: node 1 reads it, node 0 having taken the inbox's newer `keys.0` copies with
// the `sync.0` steps placing their keys (without them it judges them miskeyed and seals the
// grant fire with the old deposit seed, which node 1 refuses under its new head). They reach
// node 0 in the account's card on the public profile, which node 1 rewrites once its own
// rotations end with no pass in flight (spec/sync-inbox.md §1 Card; fails if cards are
// refreshed only at a pass's end).
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_grant_from_outside_reaches_an_account_that_removed_a_node() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, Holder, reads};
    let mut w = crate::harness::siblings();
    let _ = crate::harness::play(&mut w, &[Unpair(1, 2), Run, New(0), Give(0, 0, Holder::Node(1), Gives::Reads), Strong(1, None, 0), Run], String::new());
    let t = w.history.things[0].0;
    assert!(reads(w.engine(1), &t).value.is_some(), "node 1 reads the thing granted to its account");
}

// spec/sync-status.md §3, spec/sync-inbox.md §2 (delivery): a wait on all waits until each
// sealed fire this node sends is delivered. Node 1 grants node 0's account (a contact it
// cannot reach) read on a thing its sibling, node 2, syncs: the wait on all at node 1 stays pending
// while the grant's fire is owed, though the thing itself is synced; it ends once node 0 is back and
// takes the fire.
#[test]
#[ignore = "stub rewrite: entry by references and stubs, pairing by values (R2, R3)"]
fn a_wait_on_all_waits_for_a_sealed_fire_owed_spec_sync_status_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, Holder};
    use osis_sync::types::{Scope, Waiting};
    let mut w = crate::harness::siblings();
    w.partition(0, 1);
    w.partition(0, 2);
    let _ = crate::harness::play(&mut w, &[New(1), Run], String::new());
    let t = w.history.things[0].0;
    assert_eq!(w.wait(1, Scope::Thing(t)), Waiting::Done, "the thing is synced with node 2");
    assert_eq!(w.wait(1, Scope::All), Waiting::Done, "nothing owed yet");
    let _ = crate::harness::play(&mut w, &[Give(1, 0, Holder::Node(0), Gives::Reads), Run], String::new());
    assert!(!w.engine(1).fires_owed().is_empty(), "the grant's fire is owed");
    assert_eq!(w.wait(1, Scope::Thing(t)), Waiting::Done, "the thing is synced with node 2");
    assert_eq!(w.wait(1, Scope::All), Waiting::Pending, "the grant is held nowhere else");
    w.heal();
    w.advance(60_000);
    assert!(w.engine(1).fires_owed().is_empty(), "node 0 took the fire");
    assert_eq!(w.wait(1, Scope::All), Waiting::Done);
}
