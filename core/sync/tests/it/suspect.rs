//! Suspect lists and their repair end to end (spec/permissions.md §4 Suspect, Suspect list;
//! spec/sync-compaction.md §1 Repair). Node 0 writes thing 0, node 1's account reads it. Node 1
//! takes a paged commit of node 0's with a page away and then the request purging it: the part
//! goes at once and node 1 flags the aspect, holding less than node 0 with no body left to fetch
//! (notes/engine-suspects.md, What it backstops). Its list reaches node 0, which snapshots.

use crate::harness::Step::*;
use crate::harness::history::{Gives, world};
use crate::harness::lies::Lie;
use crate::harness::{World, play};
use osis_base::{Ak, CommitId, Tid, Value, ValueMap};
use osis_engine::retention::suspect::Why;
use osis_commit::Kind;
use osis_engine::Mutation;
use osis_schema::{Aspect, StaticSchema};

static SCHEMA: StaticSchema = StaticSchema::new("suspect.osis", "revision 1;\naspect t:big.0: map<string, string>;\n");
/// A map, so a large write pages (spec/crdt.md §8).
const BIG: Aspect<Value> = Aspect::new("t:big.0", &SCHEMA);

fn big() -> Ak {
    Ak::new("t:big.0").unwrap()
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

/// Node 0's content snapshots of `(t, big)`.
fn snapshots(w: &mut World, t: Tid) -> usize {
    let e = w.engine(0);
    e.commit_ids().iter().filter(|c| e.header(c).is_some_and(|h| h.kind == Kind::ContentSnapshot && h.aspect_index(&t, "t:big.0").is_some())).count()
}

/// The divergence: node 1 flags `(t, big)` and reads apart from node 0, nothing left to fetch.
fn diverged() -> (World, Tid) {
    let mut w = world(0, 2);
    w.cap = 4 * crate::harness::RULE_CAP;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &BIG, &Value::Map(ValueMap::from([(s("older"), s("kept"))]))).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    w.partition(0, 1);
    w.flush();
    let fill: ValueMap = (0..200).map(|i| (s(&format!("k{i:03}")), s(&format!("SUSPECT-{}", "f".repeat(1100))))).collect();
    let (whole, request) = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &BIG, &Value::Map(fill)).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        let whole = e.package(&c).unwrap().unwrap();
        let mut m = Mutation::new();
        m.set(t, &Ak::new("u:v.0").unwrap(), &s("public")).unwrap();
        m.purge_commit(c, t, big());
        let p = e.commit(m).unwrap().unwrap();
        (whole, e.package(&p).unwrap().unwrap())
    });
    assert!(whole.blobs.len() > 1, "paged: {} blobs, {} bytes", whole.blobs.len(), whole.bytes.len());
    let mut held = whole.blobs.clone();
    held.pop();
    w.write(1, |e| {
        e.ingest_with_lists(&whole.bytes, held, None, &whole.lists).unwrap();
        e.reexamine().unwrap();
        e.ingest_with_lists(&request.bytes, request.blobs.clone(), None, &request.lists).unwrap();
        e.reexamine().unwrap();
    });
    assert_eq!(w.engine(1).suspects().into_iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(), vec![(t, big())], "node 1 flags the aspect");
    (w, t)
}

fn digests(w: &mut World, t: Tid) -> (Option<[u8; 16]>, Option<[u8; 16]>) {
    (w.engine(0).state_digest(&t, &big()).unwrap(), w.engine(1).state_digest(&t, &big()).unwrap())
}

// spec/permissions.md §4 (Suspect list), spec/sync-compaction.md §1 (Repair): a divergence a
// retention drop left is repaired by a writer's snapshot, asked by the reader's list.
#[test]
fn a_reader_left_apart_by_a_drop_is_repaired_by_its_list_spec_sync_compaction_1() {
    let (mut w, t) = diverged();
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    assert!(w.store(0).first_synced(&s).unwrap() && w.store(1).first_synced(&s).unwrap(), "both past their first sync of S");
    let before = snapshots(&mut w, t);
    w.heal();
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 1, "node 0 re-snapshotted once");
    let (a, b) = digests(&mut w, t);
    assert_eq!(a, b, "the two read alike");
    assert!(w.engine(1).suspects().is_empty(), "the flag is settled by the snapshot");
    assert_eq!(w.engine(1).get(&t, &big()).unwrap(), w.engine(0).get(&t, &big()).unwrap());
    // a dormant flag lists nothing, and an empty list goes nowhere: no list at a reconnect
    let sent = || osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "inbox: suspect sent").map(|(.., n)| n).sum::<u64>();
    sent();
    w.cut(0, 1);
    w.run();
    assert_eq!(sent(), 0, "nothing listed");
    // a flag raised while connected goes at once; the same state is repaired by nobody
    w.write(1, |e| e.flag_suspect(&t, &big(), Why::PendingExpiry, &[(CommitId([5; 32]), 0)]).unwrap());
    w.run();
    assert!(sent() >= 1, "listed at once");
    w.write(1, |e| e.flag_suspect(&t, &Ak::new("u:v.0").unwrap(), Why::PendingExpiry, &[(CommitId([6; 32]), 0)]).unwrap());
    w.run();
    assert!(sent() >= 1, "a list moving goes again");
    assert_eq!(snapshots(&mut w, t), before + 1, "same state: no snapshot");
}

// spec/sync-compaction.md §1 (Repair: unless it already wrote one from that same state),
// spec/permissions.md §4 (Suspect list: sent to a peer until it answers it, again whenever the
// flags change): node 1 never gets node 0's snapshot (node 0 withholds every entry from it), so
// its flag and its different digest stay. Node 0 snapshots once per state of its own: not again
// at a reconnect (the list was taken: not sent again) nor after its restart, again once its
// state moved and node 1's flags change.
#[test]
fn a_repeated_report_repairs_once_per_state_across_restarts_spec_sync_compaction_1() {
    let (mut w, t) = diverged();
    let before = snapshots(&mut w, t);
    w.lie(0, Some(Lie::Withhold));
    w.heal();
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 1, "repaired once");
    let (a, b) = digests(&mut w, t);
    assert_ne!(a, b, "node 1 never got it");
    w.cut(0, 1);
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 1, "the same state: not again at a reconnect");
    w.power_off(0);
    w.power_on(0);
    w.lie(0, Some(Lie::Withhold));
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 1, "nor after a restart");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &BIG, &Value::Map(ValueMap::from([(s("newer"), s("v"))]))).unwrap();
        e.commit(m).unwrap();
    });
    w.cut(0, 1);
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 1, "the list was taken: not sent again at a reconnect");
    w.write(1, |e| e.flag_suspect(&t, &big(), Why::PendingExpiry, &[(CommitId([5; 32]), 0)]).unwrap());
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 2, "its state moved, the list sent again: once more");
}


/// Node `i`'s first sync of S not ended (staged: its row taken away) or ended (`set_first_synced`),
/// then node `i` stepped so it reads it again.
fn first_synced(w: &mut World, i: usize, s: osis_base::SyncId, ended: bool) {
    let mut store = w.node(i).store.clone();
    if ended {
        store.set_first_synced(&s).unwrap();
    } else {
        store.with_tx(|x| x.remove_local(&[b"F/".as_slice(), &s.0].concat(), osis_store::Shred::No)).unwrap();
    }
    w.write(i, |_| ());
}

fn sent() -> u64 {
    osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "inbox: suspect sent").map(|(.., n)| n).sum()
}

// spec/permissions.md §4 (Suspect list: a node past its first sync of L, and as its first sync
// of L ends): node 1 mid its first sync sends nothing (its digest is of a partial state), then
// sends as it ends, and node 0 repairs.
#[test]
fn a_sender_lists_only_past_its_first_sync_spec_permissions_4() {
    let (mut w, t) = diverged();
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let before = snapshots(&mut w, t);
    first_synced(&mut w, 1, s, false);
    sent();
    w.heal();
    w.run();
    assert_eq!(sent(), 0, "nothing sent mid first sync");
    assert_eq!(snapshots(&mut w, t), before);
    first_synced(&mut w, 1, s, true);
    w.run();
    assert!(sent() >= 1, "sent as it ends");
    assert_eq!(snapshots(&mut w, t), before + 1, "and repaired");
}

// spec/sync-compaction.md §1 (Repair): past its first sync there; the last list a peer sent
// before the node's first sync ended is judged as that sync ends): node 0 mid its first sync
// keeps node 1's list, writes nothing, and repairs as its first sync ends.
#[test]
fn a_list_received_mid_first_sync_is_judged_as_it_ends_spec_sync_compaction_1() {
    let (mut w, t) = diverged();
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let before = snapshots(&mut w, t);
    first_synced(&mut w, 0, s, false);
    sent();
    w.heal();
    w.run();
    assert!(sent() >= 1, "node 1 sent its list");
    assert_eq!(snapshots(&mut w, t), before, "node 0 waits");
    first_synced(&mut w, 0, s, true);
    w.run();
    assert_eq!(snapshots(&mut w, t), before + 1, "repaired as its first sync ends");
    assert_eq!(digests(&mut w, t).0, digests(&mut w, t).1);
}

// spec/permissions.md §4 (Suspect list: an aspect is left out while a source's stream shows a
// body its flag names present under L): node 1 flags `u:v.0` for node 0's write, which node 0's
// stream shows: nothing is listed and node 0 writes no snapshot, while a flag naming a body no
// stream shows goes at once. Fails if a node lists a state it is still fetching into (a writer
// would repair it for nothing).
#[test]
fn a_flag_naming_a_body_a_source_shows_waits_spec_permissions_4() {
    let mut w = world(0, 2);
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let v = Ak::new("u:v.0").unwrap();
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &v, &s("x")).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let count = |w: &mut World| {
        let e = w.engine(0);
        e.commit_ids().iter().filter(|x| e.header(x).is_some_and(|h| h.kind == Kind::ContentSnapshot)).count()
    };
    let before = count(&mut w);
    sent();
    w.write(1, |e| e.flag_suspect(&t, &v, Why::Uncovered, &[(c, 0)]).unwrap());
    w.run();
    assert_eq!(sent(), 0, "the body node 0 shows is fetched, not listed");
    assert_eq!(count(&mut w), before, "no repair");
    w.write(1, |e| e.flag_suspect(&t, &big(), Why::Uncovered, &[(CommitId([7; 32]), 0)]).unwrap());
    w.run();
    assert!(sent() >= 1, "a body no stream shows is listed at once");
}

// spec/permissions.md §4 (Suspect list: a peer keeping L unread is sent none), spec/sync-opens.md
// §4 (Source: what a node discloses to a source is bounded by what its peer proved, never by
// the class it declared): node 2 keeps S unread (its account syncs S, reads nothing) and declares
// it reads S. Node 1's lists reach node 0, whose account may read S, and never node 2: it learns
// no tid, AK or digest of S's closure.
#[test]
fn a_false_reader_declaration_gets_no_list_spec_permissions_4() {
    let mut w = world(0, 3);
    w.lie(2, Some(Lie::Declare { unread: false }));
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Grant(0, 0, 2, Gives::Syncs), Run, Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    first_synced(&mut w, 1, s, true);
    sent();
    w.write(1, |e| e.flag_suspect(&t, &big(), Why::Uncovered, &[(CommitId([7; 32]), 0)]).unwrap());
    w.run();
    assert!(sent() >= 1, "listed to node 0");
    let a = w.node(2).account;
    let declared: Vec<_> = w.status(1).get(&s).map(|st| st.sources.values().filter(|x| x.src.account == a).map(|x| x.src.class).collect()).unwrap_or_default();
    assert_eq!(declared, [osis_sync::types::SourceClass::Reader], "node 1 takes node 2's word for its class");
    let heard = |w: &World, i: usize| w.liar(i).and_then(|l| l.suspects.get(&s).copied()).unwrap_or(0);
    assert_eq!(heard(&w, 2), 0, "a node keeping S unread is not, whatever it declares");
}
