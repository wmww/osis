//! Suspect lists end to end (spec/permissions.md §4 Suspect, Suspect list): which flags a node
//! lists and to whom. No fixture here leaves two readers apart for a writer's snapshot to repair:
//! a dropped body is gone with no effect (expired, purged: spec/crdt.md §4.7), carried by a held
//! valid snapshot (covered), or counts as never received and is fetched again from any holder,
//! so co-readers holding the same commits read alike (notes/engine-suspects.md, What it
//! backstops).

use crate::harness::history::{Gives, world_of};
use crate::harness::lies::Lie;
use crate::harness::{World, play};
use crate::harness::Step::*;
use osis_base::{Ak, CommitId, Value};
use osis_engine::retention::suspect::Why;
use osis_commit::Kind;
use osis_engine::Mutation;

fn big() -> Ak {
    Ak::new("t:big.0").unwrap()
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
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

/// Node 0 writes thing 0, node 1's account reads it, both past their first sync of S; then node 1
/// flags `t:big.0` for a body no stream shows.
fn flagged() -> (World, osis_base::Tid, osis_base::SyncId) {
    let mut w = world_of(0, 2, 2);
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    assert!(w.store(0).first_synced(&s).unwrap() && w.store(1).first_synced(&s).unwrap(), "both past their first sync of S");
    (w, t, s)
}

// spec/permissions.md §4 (Suspect list: a node past its first sync of L, and as its first sync
// of L ends): node 1 mid its first sync sends nothing (its digest is of a partial state), then
// sends as it ends.
#[test]
fn a_sender_lists_only_past_its_first_sync_spec_permissions_4() {
    let (mut w, t, s) = flagged();
    first_synced(&mut w, 1, s, false);
    sent();
    w.write(1, |e| e.flag_suspect(&t, &big(), Why::Uncovered, &[(CommitId([7; 32]), 0)]).unwrap());
    w.run();
    assert_eq!(sent(), 0, "nothing sent mid first sync");
    first_synced(&mut w, 1, s, true);
    w.run();
    assert!(sent() >= 1, "sent as it ends");
}

// spec/permissions.md §4 (Suspect list: on each connection sharing L): a list goes again on every
// new connection while the flag stands, after the receiver restarted too. Fails if a list answered
// Ok is sent at no later connection.
#[test]
fn a_list_goes_again_on_each_connection_spec_permissions_4() {
    let (mut w, t, _) = flagged();
    sent();
    w.write(1, |e| e.flag_suspect(&t, &big(), Why::Uncovered, &[(CommitId([7; 32]), 0)]).unwrap());
    w.run();
    assert!(sent() >= 1, "listed at once");
    w.power_off(0);
    w.power_on(0);
    w.run();
    assert!(sent() >= 1, "sent again after the receiver's restart");
    w.cut(0, 1);
    w.run();
    assert!(sent() >= 1, "and at a reconnect");
}

// spec/permissions.md §4 (Suspect list: an aspect is left out while a source's stream shows a
// body its flag names present under L): node 1 flags `u:v.0` for node 0's write, which node 0's
// stream shows: nothing is listed and node 0 writes no snapshot, while a flag naming a body no
// stream shows goes at once. Fails if a node lists a state it is still fetching into (a writer
// would repair it for nothing).
#[test]
fn a_flag_naming_a_body_a_source_shows_waits_spec_permissions_4() {
    let mut w = world_of(0, 2, 2);
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
    let mut w = world_of(0, 3, 3);
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
