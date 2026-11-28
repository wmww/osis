//! Growth with the number of writes (spec/requirements.md Scale; notes/growth.md): what a
//! writer, a reader and a node keeping S unread store, counted at n and 10n writes, never timed. Node 0 makes thing 0; node 1's account syncs it (kept unread), node 2's
//! reads it (`writers`: writes it too).

use crate::harness::Step::*;
use crate::harness::history::{self, Gives, value_ak, world_of};
use crate::harness::{World, grant, fixture_with, play};
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use std::collections::BTreeMap;

const DAY_MS: u64 = 86_400_000;

fn setup(gives: Gives) -> (World, Tid) {
    let (w, t, _) = history::three(gives, 1);
    (w, t)
}

/// Rows by kind (a key up to its first `/`): count and key plus value bytes.
type Census = BTreeMap<String, (usize, usize)>;

fn census(rows: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Census {
    let mut out = Census::new();
    for (k, v) in rows {
        let end = k.iter().position(|b| *b == b'/').map_or(k.len().min(3), |p| p + 1);
        let e = out.entry(String::from_utf8_lossy(k.get(..end).unwrap_or(&k)).into_owned()).or_default();
        e.0 += 1;
        e.1 += k.len() + v.len();
    }
    out
}

/// What a node holds: its engine's and its sync store's rows by kind, and the blobs on its disks
/// (count, bytes). Pages are not counted: their layout follows the history of writes within a
/// bound, not the data.
type Held = (Census, Census, [(u64, u64); 2]);

/// What node `i` holds (`Held`).
fn held(w: &mut World, i: usize) -> Held {
    let engine = w.engine(i).local_census().expect("census");
    let store = census(w.store(i).with_read(|t| t.scan_local(b"", b"", usize::MAX)).expect("scan").into_iter().map(|kv| (kv.0, kv.1)));
    let d = w.disk_use(i);
    (engine, store, [(d[0].2, d[0].3), (d[1].2, d[1].3)])
}

/// Writes `from..to` by the nodes `by` in turn, each a whole replace of t's value, a second
/// apart, then a snapshot by the last writer (what the compaction trigger leaves held moves in a
/// cycle of writes; a snapshot ends it at the same place), a run and twice the tombstone lifetime
/// plus two days with no writes: what each node holds then. The first aging forgets the covered
/// writes and deletes entries at each store in that run; a node keeps each delete it saw at a
/// source a tombstone lifetime (`w/`), and how many it saw follows the run's order, not the
/// number of writes. The second aging ends on none.
fn at(w: &mut World, t: Tid, by: &[usize], from: usize, to: usize) -> Vec<Held> {
    for i in from..to {
        let n = by[i % by.len()];
        w.write(n, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(format!("v{i:08}"))).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        w.advance(1_000);
    }
    if to > from {
        w.write(by[(to - 1) % by.len()], |e| e.snapshot(&t, &value_ak())).unwrap();
        w.run();
    }
    for _ in 0..2 {
        w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
        w.run();
    }
    (0..3).map(|i| held(w, i)).collect()
}

/// A store's per-entry attribution rows: who brought an entry uncharged (`B/`), who it is charged
/// to (`W/`), whether it is unstamped (`D/`). One per entry at most, and which peer's copy came
/// first is the run's order, not the number of writes (an author whose own entry went and came
/// back holds a peer's copy, or logs its own, by which arrives first; a lowered writer's own copy
/// is unstamped): each is bounded by the entries (`E/`), not compared.
const ATTRIBUTION: [&str; 3] = ["B/", "W/", "D/"];

/// No more rows of any kind at 10n than at n, nor blobs (a few bytes for a counter that
/// widened); a store's attribution rows at most one per entry.
#[track_caller]
fn flat(a: &[Held], b: &[Held]) {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        for (d, p, q) in [("engine", &x.0, &y.0), ("store", &x.1, &y.1)] {
            let compared = |k: &String| d == "engine" || !ATTRIBUTION.contains(&k.as_str());
            let bytes = |c: &Census| c.iter().filter(|(k, _)| compared(k)).map(|(_, v)| v.1).sum::<usize>();
            let fewer = q.iter().filter(|(k, _)| compared(k)).all(|(k, v)| v.0 <= p.get(k).map_or(0, |x| x.0));
            let entries = q.get("E/").map_or(0, |e| e.0);
            let bounded = q.iter().filter(|(k, _)| !compared(k)).all(|(_, v)| v.0 <= entries);
            assert!(fewer && bounded && bytes(q) <= bytes(p) + 64, "node {i} {d}: rows by kind (count, bytes) {p:?} at n, {q:?} at 10n");
        }
        for (d, p, q) in [("engine", x.2[0], y.2[0]), ("store", x.2[1], y.2[1])] {
            assert!(q.0 <= p.0 && q.1 <= p.1 + 64, "node {i} {d} disk: blobs (count, bytes) {p:?} at n, {q:?} at 10n");
        }
    }
}

fn grows_nothing(gives: Gives, by: &[usize]) {
    let (mut w, t) = setup(gives);
    // a warm-up: each aspect's history cursor settles with time alone
    at(&mut w, t, by, 0, 0);
    at(&mut w, t, by, 0, 2);
    let n = at(&mut w, t, by, 2, 5);
    let n10 = at(&mut w, t, by, 5, 35);
    for i in [0, 2] {
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("v00000034".into())), "node {i} reads the newest");
    }
    flat(&n, &n10);
}

// spec/commits.md §5 Own replaces and Forgetting, spec/requirements.md Scale: one writer replacing
// one register 3 and 30 more times stores the same rows and blobs at the writer, a reader and a node
// keeping S unread once tombstones have aged out.
#[test]
fn single_writer_replace_grows_nothing_spec_commits_5() {
    grows_nothing(Gives::Reads, &[0]);
}

// spec/commits.md §5 Covered and Forgetting, spec/sync-compaction.md §1 (trigger): two writers
// replacing one register in turn store the same at 3 and 30 more writes (automatic compaction covers
// the other's writes).
#[test]
fn several_writers_grow_nothing_spec_commits_5() {
    grows_nothing(Gives::Writes, &[0, 2]);
}

/// `moves` inbox moves of node 0's account, back and forth between thing 0 and the inbox it was
/// made with, each a `keys.0` write on the account and a card rewrite on its profile
/// (spec/sync-inbox.md §1; a move to thing 0 writes its setting too), a second apart, then a
/// snapshot of the card and of the account's `keys.0` by node 0; then `ROLE_KEEP` passes (a replaced role-class body's keep
/// bound) and aged as `at` ages: per node, the card bodies on the profile and the account's
/// `keys.0` bodies it holds then.
fn moves_at(w: &mut World, moves: usize) -> Vec<(usize, usize)> {
    for i in 0..moves {
        let k = if i % 2 == 0 { Some(0) } else { None };
        let _ = play(w, &[Inbox(0, k), Run], String::new());
        w.advance(1_000);
    }
    let (a, profile) = (w.node(0).account.unwrap(), w.node(0).profile.unwrap());
    let t = w.history.things[0].0;
    let card = osis_schema::core_types::card_ak(&a);
    let keys = Ak::new("keys.0").unwrap();
    w.write(0, |e| e.snapshot(&profile, &card)).unwrap();
    w.write(0, |e| e.snapshot(&a, &keys)).unwrap();
    w.run();
    w.advance(osis_base::format::ROLE_KEEP_MS);
    w.run();
    at(w, t, &[0], 0, 0);
    (0..3).map(|i| (w.engine(i).held_bodies(&profile, &card), w.engine(i).held_bodies(&a, &keys))).collect()
}

// spec/commits.md §5 Covered and Fixed retention, spec/sync-compaction.md §1 (trigger),
// spec/data-model.md §9 (card aspect): node 0's account moving its inbox 1 and 10 more times
// writes the account's `keys.0` and rewrites its card on the profile each time; the replaced card
// writes are covered (the card aspect compacts as any aspect) and the replaced `keys.0` bodies go
// past `ROLE_KEEP`, so each node holds as many card and `keys.0` bodies at 10n as at n. (Each
// move is a role commit, whose header is kept as any role commit's.)
#[test]
fn card_rewrites_grow_nothing_spec_commits_5() {
    let (mut w, _) = setup(Gives::Reads);
    moves_at(&mut w, 2);
    let n = moves_at(&mut w, 1);
    let n10 = moves_at(&mut w, 10);
    assert_eq!(n, n10, "card and keys.0 bodies held per node at n and 10n moves");
}

/// `n` rotations of every role of thing 0 by node 0, its admin, a second apart, node 1 keeping
/// each sync secret as it comes; then `ROLE_KEEP`
/// passes (a replaced role-class body's keep bound): the `keys.0` bodies of thing 0 each node
/// holds then, and what reading S's path costs there (`path_reads`).
fn keysets_after_rotations(w: &mut World, n: usize) -> (Vec<usize>, Vec<u64>) {
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let kept = w.engine(1).kept_sync_secrets(&s).len();
    for i in 1..=n {
        w.write(0, |e| e.rotate_leaving_out(&t, &[Role::Sync, Role::Read, Role::Write, Role::Admin], &[])).unwrap().expect("a rotation");
        w.run();
        w.advance(1_000);
        assert_eq!(w.engine(1).kept_sync_secrets(&s).len(), kept + i, "node 1 keeps each new sync secret of thing 0");
    }
    w.advance(osis_base::format::ROLE_KEEP_MS);
    w.run();
    let keys = Ak::new("keys.0").unwrap();
    ((0..3).map(|i| w.engine(i).held_bodies(&t, &keys)).collect(), path_reads(w, &s))
}

/// Per node, the store rows and derivations that reading S's path a second time costs: its
/// path, head and head ID from the store, and every step's needs and the parent of the step
/// waiting on each held role commit from the engine (`Engine::step_parent`, asked per role entry
/// judged).
fn path_reads(w: &mut World, s: &osis_base::SyncId) -> Vec<u64> {
    let mut out = Vec::new();
    for i in 0..3 {
        let ask = |w: &mut World| {
            let path = w.store(i).path(s).unwrap();
            let _ = (w.store(i).head(s).unwrap(), w.store(i).head_id(s).unwrap());
            for st in path.iter().flat_map(|p| p.steps.iter()) {
                for c in w.engine(i).step_needs(s, &st.id()).unwrap().iter() {
                    w.engine(i).step_parent(s, c).unwrap();
                }
            }
        };
        ask(w);
        osis_base::costs::take();
        ask(w);
        let costs = osis_base::costs::take();
        out.push(costs.iter().filter(|(k, ..)| matches!(*k, "store rows read" | "sync: steps needs")).map(|(.., n)| n).sum());
    }
    out
}

// spec/commits.md §5 Fixed retention and Covered, spec/sync-compaction.md §1 (trigger): thing 0
// rotated 1 and 10 more times by its admin, synced by node 1 (kept unread) and read by node 2.
// Each rotation replaces the keysets before it; the admin's `keys.0` snapshots cover them, and
// past `ROLE_KEEP` every node drops them, so each holds as many `keys.0` bodies at 10n as at n.
// (Each rotation's boxes and step stay live in `secrets.0` and `sync.0`, kept for good.) A path
// read again costs as much at 10n as at n: the store keeps S's path parsed and the engine its
// steps' needs, each changed where what it reads moves (fails where a read parses every step).
#[test]
fn rotations_keep_keysets_flat_spec_commits_5() {
    let (mut w, _) = setup(Gives::Reads);
    keysets_after_rotations(&mut w, 1);
    let (n, reads) = keysets_after_rotations(&mut w, 1);
    let (n10, reads10) = keysets_after_rotations(&mut w, 10);
    assert_eq!(n, n10, "keys.0 bodies held per node at n and 10n rotations");
    assert_eq!(reads, reads10, "store rows and derivations of a path read again per node at n and 10n rotations");
}

// spec/sync-opens.md §1 (One connection per pair): the differential's nodes dial each other at
// once at first contact, yet each pair keeps one connection, so each write crosses each pair on one
// stream: deliveries per write are the same at n and 10n writes, all on one connection per pair.
#[test]
fn each_write_crosses_each_pair_on_one_connection_spec_sync_opens_1() {
    let (mut w, _) = setup(Gives::Writes);
    for i in 0..3 {
        let mut peers: Vec<usize> = w.links_of(i).into_iter().map(|(_, j)| j).collect();
        peers.sort();
        assert_eq!(peers, (0..3).filter(|j| *j != i).collect::<Vec<_>>(), "node {i}: one connection per peer");
    }
    let writes = |w: &mut World, n: usize| {
        let d = w.deliveries;
        for _ in 0..n {
            let _ = play(w, &[Write(0, 0), Run], String::new());
        }
        w.deliveries - d
    };
    // the first two writes after setup carry the grants' tail; after them deliveries repeat every
    // 3 writes (the writer node 2 deletes some replaced bodies at node 1 beside the admin)
    writes(&mut w, 2);
    w.trace = true;
    let (a, b) = (writes(&mut w, 3), writes(&mut w, 30));
    assert_eq!(b, 10 * a, "deliveries per write at n and 10n");
    let ends: std::collections::BTreeSet<_> = w.seen.iter().filter_map(|s| match s {
        crate::harness::Seen::Bytes { node, conn, .. } => Some((*node, *conn)),
        _ => None,
    }).collect();
    assert!(ends.len() <= 6, "bytes on one connection per pair: {ends:?}");
}

/// Node 0 makes thing 0 and grants node 1's account write and node 2's read (no node keeps it
/// unread: a store keeps what it holds of an invalid body until its expiry,
/// notes/engine-retention.md); node 1 writes `u:n.0`, purgeable by its writer. Cut off from
/// node 0, node 1 is lowered to read there. Built once per process (`fixture_with`): the world,
/// the thing and node 1's write.
fn lowered() -> (World, (Tid, CommitId)) {
    fixture_with("growth lowered", || {
        let mut w = world_of(0, 3, 3);
        w.cap = crate::harness::WIDE_CAP;
        let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 2, Gives::Reads), Run], String::new());
        let t = w.history.things[0].0;
        let note = Ak::new("u:n.0").unwrap();
        let mine = w.write(1, |e| {
            let mut m = Mutation::new();
            m.set(t, &note, &Value::Str("mine".into())).unwrap().purge_by(t, &note, osis_schema::PurgeBy::Writer).unwrap();
            e.commit(m).unwrap().unwrap()
        });
        w.run();
        w.partition(0, 1);
        w.partition(0, 2);
        let a1 = w.node(1).account.unwrap();
        w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: Some(grant(Role::Read)), retain: None })).unwrap();
        w.run();
        (w, (t, mine))
    })
}

/// On `lowered`, node 1 writes `n` values it still believes valid, the first purging its own
/// earlier write (`writer` purge-by, so it may as a writer); node 2, cut off from node 0 too,
/// takes them; then nodes 0 and 2 meet, then all: every node judges them invalid. Then a restart
/// of every node and the tombstone lifetime: the world, the thing, the invalid commits and what
/// each node holds (`Held`).
fn lowered_writes(n: usize) -> (World, Tid, Vec<CommitId>, Vec<Held>) {
    let (mut w, (t, mine)) = lowered();
    let note = Ak::new("u:n.0").unwrap();
    let mut bad = Vec::new();
    for i in 0..n {
        w.advance(1_000);
        bad.push(w.write(1, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(format!("w{i:04}"))).unwrap();
            if i == 0 {
                m.purge_commit(mine, t, note.clone());
            }
            e.commit(m).unwrap().unwrap()
        }));
    }
    // node 2 holds them (valid as it judges), then meets node 0 alone: each holds an invalid body
    // the other's stream shows
    w.run();
    let (first, last) = (bad[0], bad[n - 1]);
    assert!(w.engine(2).holds_commit(&first) && w.engine(2).holds_commit(&last), "node 2 took the writes");
    w.heal();
    w.partition(0, 1);
    w.partition(1, 2);
    w.run();
    // known while node 1's stream, as node 2 last heard it, shows them: valid again, they are
    // fetched there
    assert!(w.engine(2).kept_invalid(&first) && w.engine(2).kept_invalid(&last), "node 2 dropped them as invalid, their headers kept");
    w.heal();
    w.run();
    for i in 0..3 {
        w.power_off(i);
        w.power_on(i);
    }
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    let held = (0..3).map(|i| held(&mut w, i)).collect();
    (w, t, bad, held)
}

// spec/commits.md §5 (Forgetting: a commit judged invalid goes once no entry of it is known),
// spec/sync-judgement.md §3 (Own store: a body judged invalid leaves it with no tombstone),
// spec/permissions.md §6 (A purge request: an invalid one purges nothing): a lowered writer's invalid writes,
// one carrying a purge request, leave no header at the other nodes, nor a store entry anywhere,
// the author included (it keeps its own commits for its user): every node's store and the
// others' engines hold the same at 10 and 20 such writes (both past what arms a compaction of the value), the purge took nothing, and nothing of
// them is held at nodes 0 and 2. Then a re-grant makes them valid again: the author logs them
// again and every node reads its last write. Fails if a node keeps its entry of a body judged
// invalid, the author included, or the engine keeps a commit known only for invalid parts.
#[test]
fn a_lowered_writers_invalid_writes_leave_nothing_and_return_on_regrant_spec_commits_5() {
    let (_, _, _, few) = lowered_writes(10);
    let (mut w, t, bad, many) = lowered_writes(20);
    // the author keeps its own commits for its user: its engine is not compared
    let mut few = few;
    few[1].0 = many[1].0.clone();
    flat(&few, &many);
    let note = Ak::new("u:n.0").unwrap();
    for i in [0, 2] {
        assert!(bad.iter().all(|c| !w.engine(i).holds_commit(c)), "node {i} forgot every invalid write");
        assert_eq!(w.engine(i).get(&t, &note).unwrap(), Some(Value::Str("mine".into())), "node {i}: the invalid request purged nothing");
        assert_ne!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("w0019".into())));
    }
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &grant(Role::Write))).unwrap();
    w.run();
    for i in 0..3 {
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("w0019".into())), "node {i} reads the re-granted writer's last write");
    }
    for i in [0, 2] {
        // the author's own replaces cover the rest: never sent again
        assert!(w.engine(i).holds_commit(&bad[0]) && w.engine(i).holds_commit(&bad[19]), "node {i} holds the writes valid again");
        assert_eq!(w.engine(i).get(&t, &note).unwrap(), None, "node {i}: the request valid again purges");
    }
}

// spec/permissions.md §6 (Invalid deltas: valid again, fetched from any holder), spec/commits.md
// §5 (Forgetting: no entry of a blob of it is known): node 2 judges a lowered writer's write invalid, its
// author never having heard of the demotion, and the re-grant reaches node 2 while the author is
// away: node 2 reads the write from node 3, which keeps S unread and holds it. Fails if node 2
// forgets the write while node 3 shows it and nothing brings it back.
#[test]
fn a_write_valid_again_before_its_author_hears_comes_from_a_store_spec_permissions_6() {
    let mut w = world_of(0, 4, 4);
    w.cap = crate::harness::WIDE_CAP;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 2, Gives::Reads), Grant(0, 0, 3, Gives::Syncs), Run], String::new());
    let t = w.history.things[0].0;
    // two islands: {0, 2} hear the demotion, {1, 3} the write
    for (a, b) in [(0, 1), (0, 3), (1, 2), (2, 3)] {
        w.partition(a, b);
    }
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: Some(grant(Role::Read)), retain: None })).unwrap();
    w.run();
    let key = Ak::new("u:k.0").unwrap();
    let x = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &key, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let blobs = w.engine(1).commit_blobs(&x).unwrap();
    let at_store = |w: &mut World| w.store(3).entries(&s).unwrap().iter().any(|e| blobs.contains(&e.blob));
    assert!(at_store(&mut w), "node 3 holds the write");
    // the author goes away before hearing of the demotion; node 2 meets node 3
    w.heal();
    for b in [0, 2, 3] {
        w.partition(1, b);
    }
    w.run();
    assert_ne!(w.engine(2).get(&t, &key).unwrap(), Some(Value::Str("x".into())), "node 2 judges the write invalid");
    assert!(at_store(&mut w), "node 3 keeps its entry (none deleted for being invalid)");
    w.write(0, |e| e.grant(&t, &a1, &grant(Role::Write))).unwrap();
    w.run();
    assert_eq!(w.engine(2).get(&t, &key).unwrap(), Some(Value::Str("x".into())), "node 2 reads the write valid again, from node 3");
}

// spec/permissions.md §6 (Invalid deltas: valid again, received again from any holder),
// spec/commits.md §5 (Forgetting: an invalid commit carrying a request goes only where the
// request holds the right over nothing): node 1's account, lowered to read on things 0 and 1,
// writes on thing 0 and purges its own write on thing 1. Node 0 judges it invalid and its request
// void, and forgets it; a re-grant of write on thing 1 alone gives the request force while the
// commit's part on thing 0 stays invalid: every node reads the purge.
#[test]
fn a_request_given_force_again_reaches_a_node_that_forgot_it_spec_perm_6() {
    let mut w = world_of(0, 2, 2);
    let _ = play(&mut w, &[New(0), New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 1, 1, Gives::Writes), Run], String::new());
    let (t, u) = (w.history.things[0].0, w.history.things[1].0);
    let y = Ak::new("u:y.0").unwrap();
    let mine = Some(Value::Str("mine".into()));
    let own = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(u, &y, &Value::Str("mine".into())).unwrap().purge_by(u, &y, osis_schema::PurgeBy::Writer).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.partition(0, 1);
    let a1 = w.node(1).account.unwrap();
    let read = || Some(grant(Role::Read));
    for x in [t, u] {
        w.write(0, |e| e.demote(&x, &Demotion { holder: a1, new: read(), retain: None })).unwrap();
    }
    w.run();
    w.advance(1_000);
    let q = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("late".into())).unwrap();
        m.purge_commit(own, u, y.clone());
        e.commit(m).unwrap().unwrap()
    });
    w.heal();
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    assert!(!w.engine(0).holds_commit(&q), "node 0 forgot the invalid commit");
    assert_eq!(w.engine(0).get(&u, &y).unwrap(), mine, "its request void at node 0");
    w.write(0, |e| e.grant(&u, &a1, &grant(Role::Write))).unwrap();
    w.run();
    for i in 0..2 {
        assert_eq!(w.engine(i).get(&u, &y).unwrap(), None, "node {i} reads the purge given force");
    }
}

// spec/sync-opens.md §6 (Where it stopped; Lost: each Lost for a member open at its receiver is
// answered), spec/sync-streams.md §4 (Joining): a head move at a node keeping S unread ends the
// readers' opens by the old sync key, and each reader opens S again by the new one: both sides
// rejoin from where they stopped, so what a reader and the store send each other per head move
// does not grow with the n entries of S (no listing from the start either way), at n and 10n.
// Node 0 makes thing 0, node 1's account syncs it (kept unread), nodes 2 and 3 read it; two
// copies of that world get n and 10n entries, then node 3's account is removed (a rotation of
// read and sync: node 1's head moves); counted between node 1 and node 2 (a reader, no writer),
// each way.
#[test]
fn a_head_move_relists_nothing_between_a_reader_and_a_store_at_n_and_10n() {
    let mut w = world_of(0, 4, 4);
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Grant(0, 0, 3, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let head_move = |w: &mut World, n: usize| {
        for i in 0..n {
            w.write(0, |e| {
                let mut m = Mutation::new();
                m.set(t, &Ak::new(format!("u:e{i}.0")).unwrap(), &Value::Int(i as i64)).unwrap();
                e.commit(m).unwrap();
            });
        }
        w.run();
        assert!(w.store(1).entries(&s).unwrap().len() >= n, "the store holds every entry");
        let steps = |w: &World| w.store(1).path(&s).unwrap().map_or(0, |p| p.steps.len());
        let sent = |w: &World| (w.net.between.get(&(1, 2)).copied().unwrap_or(0), w.net.between.get(&(2, 1)).copied().unwrap_or(0));
        let (before, head) = (sent(w), steps(w));
        let _ = play(w, &[Remove(0, 0, 3), Run], String::new());
        assert_eq!(steps(w), head + 1, "the store's head moved");
        let after = sent(w);
        (after.0 - before.0, after.1 - before.1)
    };
    let mut large = w.copy();
    let (a, b) = (head_move(&mut w, 3), head_move(&mut large, 30));
    assert!(b.0 <= a.0 + 64 && b.1 <= a.1 + 64, "bytes (store to reader, reader to store) across a head move: {a:?} at n, {b:?} at 10n\n{}", large.net.census());
    // at quiet every byte sent is in a whole frame the census counts
    for (&(x, y), &bytes) in &large.net.between {
        let framed: u64 = large.net.frames.iter().filter(|((a, b, _), _)| (*a, *b) == (x, y)).map(|(_, t)| t.1).sum();
        assert_eq!(framed, bytes, "n{x} -> n{y}: the census against the bytes sent\n{}", large.net.census());
    }
}

/// `round` played for rounds 0..10 on `w`: a copy taken after the first is ended by `end`, then
/// the original after the tenth: what two worlds playing 1 and 10 rounds end with (a copy goes on
/// as its original would).
fn one_and_ten<T>(mut w: World, mut round: impl FnMut(&mut World, usize), end: impl Fn(&mut World) -> T) -> [(World, T); 2] {
    round(&mut w, 0);
    let mut one = w.copy();
    let at_one = end(&mut one);
    for k in 1..10 {
        round(&mut w, k);
    }
    let at_ten = end(&mut w);
    [(one, at_one), (w, at_ten)]
}

/// A round: node 0 mints a dependent thing with its account D as admin held from D, a dependent
/// thing minted with its node root as admin held from it, and one minted with its node thing
/// (held from the node root, `Engine::create_with_admin`), writes each, removes every strong to them and runs (a pass
/// releases them).
fn own_round(w: &mut World) {
    use osis_schema::core_types::HOLDS;
    let (root, d) = (w.engine(0).node_root().unwrap(), w.node(0).account.unwrap());
    let p = w.engine(0).tid();
    let strong = |m: &mut Mutation, from: Tid, to: Tid, on: bool| {
        let v = Value::Strong(to);
        let op = if on { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
        m.op(from, &HOLDS, osis_crdt::PathOp { path: vec![], op }).unwrap();
    };
    let ts = w.write(0, |e| {
        let mut ts = Vec::new();
        for from in [d, root] {
            let mut m = Mutation::new();
            let t = m.create(e.thing_record(from, None));
            strong(&mut m, from, t, true);
            e.commit(m).unwrap();
            ts.push((t, from));
        }
        ts.push((e.create_with_admin(&p).unwrap().0, root));
        for (t, _) in &ts {
            let mut m = Mutation::new();
            m.set(*t, &value_ak(), &Value::Str("new".into())).unwrap();
            e.commit(m).unwrap();
        }
        ts
    });
    w.run();
    w.write(0, |e| {
        for (t, from) in &ts {
            let mut m = Mutation::new();
            strong(&mut m, *from, *t, false);
            e.commit(m).unwrap();
        }
    });
    w.run();
    for (t, _) in &ts {
        if w.engine(0).core.created(t).is_some() {
            panic!("released: {t:?} keeps its record\n{}", why_kept(w, 0, t));
        }
    }
    w.advance(1_000);
}

/// Node 0 snapshots its roots' `holds.0` (what the trigger leaves held moves
/// in a cycle; a snapshot ends it at the same place), then the tombstone lifetime and two days
/// pass: what it holds then.
fn aged(w: &mut World) -> Held {
    snapshot_roots(w, 0);
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    held(w, 0)
}

/// Node `i` snapshots its node root's and account's `holds.0`.
fn snapshot_roots(w: &mut World, i: usize) {
    use osis_schema::core_types::HOLDS;
    let (root, d) = (w.engine(i).node_root().unwrap(), w.node(i).account.unwrap());
    w.write(i, |e| {
        for (t, ak) in [(d, HOLDS.name()), (root, HOLDS.name())] {
            e.snapshot(&t, &ak).unwrap();
        }
    });
}

/// What a set removal's tombstone may add to the roots' snapshots, in their records (`c/`) and
/// in their blobs: spec/requirements.md Scale, a few bytes per removal (issues/zero-growth.md,
/// Set removals: no cover can drop one).
const TOMBSTONE_BYTES: usize = 32;

/// `h` holds what a fresh node of the same account holds (`fresh`), after `removals` set
/// removals in the roots: every family's rows, but the schemas it learned (`d/`, the node's
/// own), `cv/` (`handed`) and the blob sequence row, the same count of blobs, and no more bytes than the removals'
/// tombstones add to the snapshot records (`c/`) and blobs. `cv/` holds at most one row per
/// held commit (one per held part dropped as covered whose coverer went: the trigger's
/// snapshots a fresh node never took); the caller checks it flat. On a mismatch the message
/// adds `explain` of the families that differ (`leaked`).
#[track_caller]
fn as_fresh(h: &Held, fresh: &Held, removals: usize, what: &str, explain: &mut dyn FnMut(&[String]) -> String) {
    let rest = |c: &Census| {
        let mut c = c.clone();
        c.remove("d/");
        c.remove("cv/");
        // one row per store, written at its first ciphertext-store release (`records::BLOB_SEQ`)
        c.remove("blo");
        if let Some(x) = c.get_mut("c/") {
            x.1 = 0;
        }
        c
    };
    let snap = |c: &Census| c.get("c/").copied().unwrap_or_default();
    let tombs = removals * TOMBSTONE_BYTES;
    let differ = |side: &str, a: &Census, b: &Census| -> Vec<String> { a.keys().chain(b.keys()).filter(|k| a.get(*k) != b.get(*k)).map(|k| format!("{side} {k}")).collect() };
    if (rest(&h.0), &h.1) != (rest(&fresh.0), &fresh.1) {
        let fams: Vec<String> = differ("engine", &rest(&h.0), &rest(&fresh.0)).into_iter().chain(differ("store", &h.1, &fresh.1)).collect();
        assert_eq!((rest(&h.0), &h.1), (rest(&fresh.0), &fresh.1), "{what}: rows by family{}", explain(&fams));
    }
    if !(snap(&h.0).0 == snap(&fresh.0).0 && snap(&h.0).1 <= snap(&fresh.0).1 + tombs) {
        panic!("{what}: c/ {:?}, a fresh node's {:?}, {removals} removals{}", snap(&h.0), snap(&fresh.0), explain(&["engine c/".into()]));
    }
    if h.0.get("cv/").map_or(0, |x| x.0) > snap(&fresh.0).0 {
        panic!("{what}: cv/ {:?}{}", h.0.get("cv/"), explain(&["engine cv/".into()]));
    }
    for (d, (a, b)) in ["engine", "store"].iter().zip(h.2.iter().zip(&fresh.2)) {
        if !(a.0 == b.0 && a.1 <= b.1 + tombs as u64) {
            panic!("{what}: {d} blobs (count, bytes) {a:?}, a fresh node's {b:?}{}", explain(&["engine c/".into(), "engine bp/".into()]));
        }
    }
}

/// Debug builds: the rows of `families` (`"engine c/"`, `"store E/"`) node `i` of `w` holds and
/// node `j` of `base` (a fresh world's, same seed: the same roots) does not, each with its
/// decoded key, then why node `i` keeps each thing those rows name that no row of `base` names
/// (`World::rows`, `World::why_kept`; notes/test-harnesses.md, Why kept and row dumps).
#[cfg(debug_assertions)]
fn leaked(w: &mut World, i: usize, base: &mut World, j: usize, families: &[String]) -> String {
    use std::fmt::Write;
    let base_rows = base.rows(j, "", None);
    let keys: std::collections::BTreeSet<(&str, &[u8])> = base_rows.iter().map(|(d, r)| (*d, r.raw.as_slice())).collect();
    let base_tids: std::collections::BTreeSet<Tid> = base_rows.iter().flat_map(|(_, r)| r.tids.iter().copied()).collect();
    // rows of the families that differ and no row of `base` has, those naming a thing `base`
    // has no row naming first (commit IDs differ between the worlds: a row of a root's commit
    // has its own key at each)
    let (mut fresh_named, mut other) = (Vec::new(), Vec::new());
    for (d, r) in w.rows(i, "", None) {
        if families.contains(&format!("{d} {}", r.family)) && !keys.contains(&(d, r.raw.as_slice())) {
            match r.tids.iter().any(|t| !base_tids.contains(t)) {
                true => fresh_named.push((d, r)),
                false => other.push((d, r)),
            }
        }
    }
    let shown = if fresh_named.is_empty() { &other } else { &fresh_named };
    let mut out = format!("\nrows a fresh node lacks ({} naming a thing it has no row of, {} others):", fresh_named.len(), other.len());
    for (d, r) in shown.iter().take(60) {
        let names: Vec<String> = r.tids.iter().map(|t| t.to_string()).collect();
        let _ = write!(out, "\n  {d} {}{} ({} bytes), names [{}]", r.family, r.key, r.bytes, names.join(" "));
    }
    if shown.len() > 60 {
        let _ = write!(out, "\n  ... {} more", shown.len() - 60);
    }
    let tids: std::collections::BTreeSet<Tid> = shown.iter().flat_map(|(_, r)| r.tids.iter()).filter(|t| !base_tids.contains(t)).copied().collect();
    let _ = write!(out, "\nwhy kept:");
    for t in tids.iter().take(20) {
        let _ = write!(out, "\n{}", why_kept(w, i, t));
    }
    out
}

/// Debug builds: why node `i` keeps `t` (`World::why_kept`).
fn why_kept(w: &mut World, i: usize, t: &Tid) -> String {
    #[cfg(debug_assertions)]
    {
        w.why_kept(i, t)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (w, i, t);
        String::new()
    }
}

#[cfg(not(debug_assertions))]
fn leaked(_: &mut World, _: usize, _: &mut World, _: usize, _: &[String]) -> String {
    String::new()
}

/// A fresh node of one account with its roots snapshotted, as the rounds' worlds end (`aged`) at 0
/// rounds: the world and what it holds. Built once per process.
fn fresh_node() -> (World, Held) {
    fixture_with("growth fresh node", || {
        let mut w = world_of(0, 1, 1);
        let h = aged(&mut w);
        (w, h)
    })
}

// Releasing everything, its own-things arm (issues/storage-owners.md), spec/sync-set.md §3 (Nothing of R stays): what a node mints with its account as admin, its account
// and its node root, written and then released, leaves its rows and blobs as a fresh node's of the
// same account once tombstones have aged out, at 1 and 10 rounds: but the roots' set tombstones,
// a few bytes per removal (the round's strongs), and `cv/` (flat).
// A mismatch prints the rows a fresh node lacks and why each thing they name is kept (`leaked`:
// notes/test-harnesses.md, Why kept and row dumps).
#[test]
fn releasing_own_things_returns_storage_to_a_fresh_nodes_spec_sync_set_3() {
    let (mut wf, fresh) = fresh_node();
    let [(mut wa, a), (mut wb, b)] = one_and_ten(world_of(0, 1, 1), |w, _| own_round(w), aged);
    as_fresh(&a, &fresh, 4, "1 round", &mut |f| leaked(&mut wa, 0, &mut wf, 0, f));
    as_fresh(&b, &fresh, 10 * 4, "10 rounds", &mut |f| leaked(&mut wb, 0, &mut wf, 0, f));
    assert_eq!(a.0.get("cv/"), b.0.get("cv/"), "cv/ flat");
}

/// A round: node 0 mints a thing with its account as admin expiring a second later, held
/// from D and written in the same commit (a disappearing message), and lets it expire.
fn expiry_round(w: &mut World) {
    use osis_schema::core_types::HOLDS;
    let d = w.node(0).account.unwrap();
    let t = w.write(0, |e| {
        let at = osis_base::Time(e.now().0 + 1_000);
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(d, Some(at)));
        m.op(d, &HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
        m.set(t, &value_ak(), &Value::Str("brief".into())).unwrap();
        m.expires_all(at);
        e.commit(m).unwrap();
        t
    });
    w.run();
    w.advance(2_000);
    w.run();
    assert!(!w.engine(0).knows(&t), "expired");
}

// S1, its expiry arm, spec/commits.md §5 (Destruction: a thing goes by ordinary expiry at its
// record's; Forgetting: a part not held on a thing whose record is not held, a forgotten name
// past its expiry), spec/requirements.md (data may carry an expiry at which every node drops it):
// a thing minted to expire with its holding strong, written and expired, leaves its rows and blobs
// as a fresh node's of the same account, at 1 and 10 rounds, the expired strongs in D's snapshot
// included (gone with their adds, spec/crdt.md §4.7).
#[test]
fn expired_things_return_storage_to_a_fresh_nodes_spec_commits_5() {
    let (mut wf, fresh) = fresh_node();
    let [(mut wa, a), (mut wb, b)] = one_and_ten(world_of(0, 1, 1), |w, _| expiry_round(w), aged);
    as_fresh(&a, &fresh, 0, "1 round", &mut |f| leaked(&mut wa, 0, &mut wf, 0, f));
    as_fresh(&b, &fresh, 0, "10 rounds", &mut |f| leaked(&mut wb, 0, &mut wf, 0, f));
}

/// A round: node 0 mints A with its account as admin, keeping 10 minutes of history whose
/// strongs hold their targets (`history_holds_targets`), and B, held by A alone: A's strong to B
/// is removed (B held by A's history), then the root's to A.
fn history_round(w: &mut World) {
    use osis_schema::core_types::{self as ct, HOLDS};
    let d = w.node(0).account.unwrap();
    let strong = |m: &mut Mutation, from: Tid, to: Tid, on: bool| {
        let v = Value::Strong(to);
        let op = if on { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
        m.op(from, &HOLDS, osis_crdt::PathOp { path: vec![], op }).unwrap();
    };
    let keep = osis_schema::History::Keep { until: None, after: Some(10 * 60_000) };
    let setting = ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(keep), ..Default::default() }), history_holds_targets: true, ..Default::default() };
    let (a, b) = w.write(0, |e| {
        let mut m = Mutation::new();
        let a = m.create(e.thing_record(d, None));
        strong(&mut m, d, a, true);
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        m.set(a, &ct::RETENTION, &setting).unwrap();
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        let b = m.create(e.thing_record(d, None));
        strong(&mut m, a, b, true);
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        m.set(b, &value_ak(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        strong(&mut m, a, b, false);
        e.commit(m).unwrap();
        (a, b)
    });
    w.run();
    assert!(w.engine(0).closure_holds(&b), "B held by A's history");
    w.write(0, |e| {
        let mut m = Mutation::new();
        strong(&mut m, d, a, false);
        e.commit(m).unwrap();
    });
    w.run();
    for t in [a, b] {
        if w.engine(0).core.created(&t).is_some() {
            panic!("released: {t:?} keeps its record\n{}", why_kept(w, 0, &t));
        }
    }
    w.advance(1_000);
}

// Releasing everything, its history arm, spec/data-model.md §8 What counts, spec/sync-set.md
// §3: a thing whose history holds its strongs' targets, released with what only its history
// held, leaves its rows and blobs as a fresh node's, at 1 and 10 rounds: but the root's set
// tombstones (one removal a round).
#[test]
fn releasing_held_history_returns_storage_to_a_fresh_nodes_spec_data_model_8() {
    let (mut wf, fresh) = fresh_node();
    let [(mut wa, a), (mut wb, b)] = one_and_ten(world_of(0, 1, 1), |w, _| history_round(w), aged);
    as_fresh(&a, &fresh, 1, "1 round", &mut |f| leaked(&mut wa, 0, &mut wf, 0, f));
    as_fresh(&b, &fresh, 10, "10 rounds", &mut |f| leaked(&mut wb, 0, &mut wf, 0, f));
    assert_eq!(a.0.get("cv/"), b.0.get("cv/"), "cv/ flat");
}

/// Each node's roots snapshotted (`snapshot_roots`), then the inbox lifetime, the role keep and the
/// tombstone lifetime and two days: what each node holds.
fn settled(w: &mut World) -> Vec<Held> {
    use osis_base::format::{INBOX_LIFETIME_MS, ROLE_KEEP_MS};
    for i in 0..w.len() {
        snapshot_roots(w, i);
    }
    w.run();
    w.advance(INBOX_LIFETIME_MS.max(ROLE_KEEP_MS) + TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    (0..w.len()).map(|i| held(w, i)).collect()
}

/// What read does in a round, both nodes together: judgements of a body (`read: judged`), store
/// rows it reads (`store rows read <- read`) and judgements giving the value already held (`read:
/// judged unchanged`: a read moved under the answer).
type Work = [u64; 3];

/// Round `k`: node 0 mints a thing with its account as admin, writes it, and gives node 1's
/// account read on it: node 1 holds it (`held`, a strong from its account) or declines (no
/// strong, the fire left in its inbox); node 0 writes again, removes node 1's account, and both
/// let the thing go (each its strong). The first by `redeem_round` with
/// `redeem`. 1 and 10 rounds (`one_and_ten`), each ended by `settled`, with read's work per round
/// of the ten. Each round starts and ends with a `costs::take`, which resets every counter: a
/// `take` around the call reads only the last round and the settle tail; the whole call's work is
/// the sum of the rounds' `Work`.
fn grant_rounds(held: bool, redeem: bool) -> ([(World, Vec<Held>); 2], Vec<Work>) {
    use crate::harness::history::Holder;
    let mut work = Vec::new();
    let round = |w: &mut World, k: usize| {
        osis_base::costs::take();
        if redeem && k == 0 {
            redeem_round(w);
        } else {
            let give = if held { Grant(0, k, 1, Gives::Reads) } else { Give(0, k, Holder::Node(1), Gives::Reads) };
            let mut steps = vec![New(0), Write(0, k), give, Run, Write(0, k), Run, Remove(0, k, 1), Run];
            if held {
                steps.push(Unstrong(1, None, k));
            }
            steps.extend([Unstrong(0, None, k), Run]);
            let _ = play(w, &steps, String::new());
            w.advance(1_000);
        }
        work.push(round_work());
    };
    let worlds = one_and_ten(world_of(0, 2, 2), round, settled);
    (worlds, work)
}

/// Read's work since the last `costs::take` (`Work`), taken: every `osis_base::costs` counter
/// starts again from 0.
fn round_work() -> Work {
    let taken = osis_base::costs::take();
    let n = |name: &str| taken.iter().filter(|(k, ..)| *k == name).map(|(.., n)| n).sum::<u64>();
    [n("read: judged"), n("store rows read <- read"), n("read: judged unchanged")]
}

/// spec/requirements.md Scale (each operation costs in proportion to what it changes, never to
/// history): every round plays the same steps, so read's work over three rounds of the tenth's
/// history is no more than over three of the first's. A body of an earlier round is judged again
/// only where something deciding it moved: a snapshot extending its chain of covers moves its
/// carriers, read only where an entry of it would leave (`Ground::carriers`); a removal stamp
/// pruned in a store table moves no reader of an absent row, its own included
/// (`memo::Effects::due`); a body at S reads S's bodies of its commit alone (`Engine::sync_body`),
/// and asks other sync IDs' entries of its blobs only where they may decide what it may log
/// (`Ground::may_log`). One round's count varies by about a tenth either way, so windows of three
/// are compared. `measures`: the indexes of `Work` checked.
fn flat_work(work: &[Work], who: &str, measures: &[usize]) {
    let window = |r: std::ops::Range<usize>| -> Work {
        let w = &work[r];
        std::array::from_fn(|i| w.iter().map(|x| x[i]).sum())
    };
    let (early, late) = (window(1..4), window(work.len() - 3..work.len()));
    for (i, what) in ["judgements", "store rows read", "judgements giving the value held"].iter().enumerate().filter(|(i, _)| measures.contains(i)) {
        assert!(late[i] <= early[i], "{who}: read's {what} per round grow with the rounds played: rounds 2-4 {}, the last three {} ({work:?})", early[i], late[i]);
    }
}

/// `grant_rounds`' first holding round, by a link: node 0 makes thing 0, writes it and makes a
/// read link to it, which node 1 redeems; node 0 writes again, ends the link (its seed thing goes
/// with it) and takes K off the thing (node 1's account leaves K), and both let everything go:
/// node 0 the thing and K, node 1 the strongs its redeem wrote to both (spec/sync-set.md §4:
/// a redeem writes them).
fn redeem_round(w: &mut World) {
    use osis_schema::core_types::HOLDS;
    let strongs = |w: &mut World, i: usize| -> std::collections::BTreeSet<Tid> {
        let d = w.node(i).account.unwrap();
        w.engine(i).get_typed(&d, &HOLDS).unwrap().unwrap_or_default().into_iter().filter_map(|r| match r {
            osis_base::Ref::Strong(s) => Some(s.0),
            _ => None,
        }).collect()
    };
    let _ = play(w, &[New(0), Write(0, 0), Run], String::new());
    let t = w.history.things[0].0;
    let before = strongs(w, 0);
    let link = w.make_link(0, t, Role::Read);
    // the thing keeping the link's seed, held from D beside K
    let seed: Vec<Tid> = strongs(w, 0).difference(&before).copied().filter(|x| *x != link.k).collect();
    assert_eq!(seed.len(), 1, "one seed thing");
    w.redeem(1, &link);
    w.run();
    assert_eq!(w.redeem(1, &link), osis_sync::types::Waiting::Done, "redeemed");
    let _ = play(w, &[Write(0, 0), Run], String::new());
    let l = osis_engine::identity::link_key_tid(&link.seed, link.k);
    w.write(0, |e| {
        e.finalize_link(&link.k, &l)?;
        e.demote(&t, &Demotion { holder: link.k, new: None, retain: None })
    })
    .unwrap();
    w.run();
    assert!(strongs(w, 0).is_disjoint(&seed.iter().copied().collect()), "the seed thing goes with the link's end");
    for i in [0, 1] {
        let held = strongs(w, i);
        let go: Vec<Tid> = [t, link.k].into_iter().filter(|x| held.contains(x)).collect();
        let d = w.node(i).account.unwrap();
        w.write(i, |e| {
            let mut m = Mutation::new();
            for x in &go {
                m.op(d, &HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(Value::Strong(*x)) }).unwrap();
            }
            e.commit(m).unwrap();
        });
    }
    w.run();
    w.advance(1_000);
}

/// `grant_rounds` at 1 and 10 rounds: each node as a fresh world's (`as_fresh`: `world_of(0, 2, 2)`
/// `settled` at 0 rounds, the same for every arm, built once per process), each round's set
/// removals at most `removals` a node, and nothing listed for `flows::retake` beyond what a fresh
/// node lists (an in-memory row owned by its actor's `secrets.0` state).
fn grants_as_fresh(held: bool, redeem: bool, removals: usize) -> Vec<Work> {
    let (mut wf, fresh) = fixture_with("growth grants fresh", || {
        let mut w = world_of(0, 2, 2);
        let held = settled(&mut w);
        (w, held)
    });
    let ([(mut wa, a), (mut wb, b)], work) = grant_rounds(held, redeem);
    // the redeem round's set removals: the link's seed thing's and K's strongs beside the thing's
    let extra = if redeem { 4 } else { 0 };
    for (i, who) in ["the minting node", "the grantee"].iter().enumerate() {
        as_fresh(&a[i], &fresh[i], removals + extra, &format!("{who}, 1 round"), &mut |f| leaked(&mut wa, i, &mut wf, i, f));
        as_fresh(&b[i], &fresh[i], 10 * removals + extra, &format!("{who}, 10 rounds"), &mut |f| leaked(&mut wb, i, &mut wf, i, f));
        assert_eq!(a[i].0.get("cv/"), b[i].0.get("cv/"), "{who}: cv/ flat");
        let listed = wf.engine(i).retake_listed();
        assert_eq!((wa.engine(i).retake_listed(), wb.engine(i).retake_listed()), (listed, listed), "{who}: actors listed for retake, 1 and 10 rounds");
    }
    work
}

// spec/requirements.md Scale, spec/sync-judgement.md §2: over the grant and redeem arm's grant
// rounds alone (`grant_rounds(true, false)`), read's work per round does not grow with the rounds
// played (`flat_work`).
#[test]
#[ignore = "issues/many-sync-ids-cost.md"]
fn granting_costs_read_what_the_grant_changed_spec_requirements_scale() {
    let (_, work) = grant_rounds(true, false);
    flat_work(&work, "held", &[0, 1, 2]);
}

// spec: none (internal: notes/test-harnesses.md, Counts beside neighbours). By hand: the decline
// arm's state and counts alone, during and after the module's default tests (`OSIS_NEIGHBOURS`
// picks some) are the same.
#[cfg(debug_assertions)]
#[test]
#[ignore = "by hand"]
fn declined_grants_count_alike_beside_neighbours() {
    macro_rules! named {
        ($($f:ident),* $(,)?) => { [$((stringify!($f), $f as fn())),*] };
    }
    osis_base::costs::beside(
        || {
            // what each node holds, both worlds: every row's key and size
            let (mut worlds, _) = grant_rounds(false, false);
            let mut out = String::new();
            for (w, _) in worlds.iter_mut() {
                for i in 0..w.len() {
                    for (d, r) in w.rows(i, "", None) {
                        out += &format!("n{i} {d} {}{} {}\n", r.family, r.key, r.bytes);
                    }
                }
            }
            out
        },
        &named![
            a_declined_grant_returns_storage_to_a_fresh_worlds_spec_sync_set_3,
            a_dependent_make_keeps_no_blob_bytes_once_its_holds_part_is_covered_spec_sync_ids_5,
            a_dependent_thing_leaving_goes_while_its_sync_id_stays_spec_sync_set_3,
            a_lowered_writers_invalid_writes_leave_nothing_and_return_on_regrant_spec_commits_5,
            a_node_restored_from_a_backup_is_counted_holding_nothing_it_lacks_spec_sync_streams_4,
            a_released_things_forgotten_commits_leave_no_own_entry_spec_sync_judgement_3,
            a_request_given_force_again_reaches_a_node_that_forgot_it_spec_perm_6,
            a_thing_another_node_makes_pulls_nothing_anew_spec_sync_judgement_3,
            a_write_valid_again_before_its_author_hears_comes_from_a_store_spec_permissions_6,
            an_independent_thing_another_node_makes_pulls_nothing_anew_spec_sync_judgement_3,
            card_rewrites_grow_nothing_spec_commits_5,
            each_write_crosses_each_pair_on_one_connection_spec_sync_opens_1,
            expired_things_return_storage_to_a_fresh_nodes_spec_commits_5,
            granted_and_redeemed_things_return_storage_to_a_fresh_worlds_spec_sync_set_3,
            record_blobs_at_a_store_stay_flat_spec_sync_ids_6,
            releasing_a_disputed_thing_returns_storage_to_a_fresh_worlds_spec_permissions_3,
            releasing_a_purged_thing_returns_storage_to_a_fresh_worlds_spec_commits_5,
            releasing_a_retained_copy_returns_storage_to_a_fresh_worlds_spec_permissions_3,
            releasing_held_history_returns_storage_to_a_fresh_nodes_spec_data_model_8,
            releasing_own_things_returns_storage_to_a_fresh_nodes_spec_sync_set_3,
            rotations_keep_keysets_flat_spec_commits_5,
            several_writers_grow_nothing_spec_commits_5,
            single_writer_replace_grows_nothing_spec_commits_5,
        ],
    );
}

// Its decline arm (spec/sync-set.md §4: nothing else makes a node hold a thing it is granted a
// role on; spec/sync-inbox.md §5): as the grant and redeem arm's grant rounds, the grant never
// held from the grantee's account: what its fire carried goes with the fire, and the stranded
// report it sent with its sync ID being read. And spec/requirements.md Scale, spec/sync-judgement.md §2: read judges no
// more bodies per round as the rounds' sync IDs add up, each still read at the grantee
// (stranded) while its fire is kept (`flat_work`, judgements; the rows it reads:
// issues/many-sync-ids-cost.md).
#[test]
fn a_declined_grant_returns_storage_to_a_fresh_worlds_spec_sync_set_3() {
    let work = grants_as_fresh(false, false, 4);
    flat_work(&work, "declined", &[0, 2]);
}

// Releasing everything, its grant and redeem arm (spec/sync-set.md §3, §4, spec/sync-inbox.md §5):
// the first round grants by a link, redeemed and ended (`redeem_round`: the link's seed thing goes
// with its end); each later round a thing granted to another account, held there, written, the
// grantee removed and both sides letting it go. Each node is as a fresh world's once the inbox
// lifetime, the role keep and tombstones have passed, at 1 round (the redeem alone) and 10 (the
// redeem and nine grants).
#[test]
fn granted_and_redeemed_things_return_storage_to_a_fresh_worlds_spec_sync_set_3() {
    grants_as_fresh(true, true, 4);
}

/// `grants_as_fresh`'s check of one world of `world_of(0, 2, 2)` after `settled`: each node as a
/// fresh world's, with at most `removals` set removals a node.
fn two_as_fresh(mut w: World, removals: usize, what: &str) {
    let (mut wf, fresh) = fixture_with("growth grants fresh", || {
        let mut w = world_of(0, 2, 2);
        let held = settled(&mut w);
        (w, held)
    });
    let held = settled(&mut w);
    for (i, who) in ["the minting node", "the other"].iter().enumerate() {
        as_fresh(&held[i], &fresh[i], removals, &format!("{what}: {who}"), &mut |f| leaked(&mut w, i, &mut wf, i, f));
        assert_eq!(w.engine(i).retake_listed(), wf.engine(i).retake_listed(), "{what}: {who}: actors listed for retake");
    }
}

// Releasing everything, its purge arm (spec/commits.md §5 Purge, spec/sync-set.md §3): node 0
// writes thing 0, replaces the write and purges it; node 1's account reads it and holds it; then
// both let it go: each node as a fresh world's, the purge request gone with its thing.
#[test]
fn releasing_a_purged_thing_returns_storage_to_a_fresh_worlds_spec_commits_5() {
    use osis_schema::core_types as ct;
    let mut w = world_of(0, 2, 2);
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let c = w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("purged".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    let _ = play(&mut w, &[Run, Write(0, 0), Run], String::new());
    w.write(0, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge_commit(c, t, value_ak());
        e.commit(m).unwrap().unwrap();
    });
    w.run();
    assert_eq!(w.engine(1).value_held_of(&c, &t, &value_ak()).unwrap(), None, "the purged write is gone at the reader");
    let _ = play(&mut w, &[Unstrong(1, None, 0), Unstrong(0, None, 0), Run], String::new());
    two_as_fresh(w, 2, "purged");
}

// Its admin dispute arm (spec/permissions.md §3, forks are permanent): nodes 0 and 1, of two
// accounts each admin of thing 0, each remove the other's account while apart, then meet and
// both let it go: each node as a fresh world's, whichever side it is on.
#[test]
fn releasing_a_disputed_thing_returns_storage_to_a_fresh_worlds_spec_permissions_3() {
    let mut w = world_of(0, 2, 2);
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Run], String::new());
    let t = w.history.things[0].0;
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    w.write(0, |e| e.grant(&t, &a1, &grant(Role::Admin))).unwrap();
    let _ = play(&mut w, &[Run, Partition(0, 1)], String::new());
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    w.write(1, |e| e.demote(&t, &Demotion { holder: a0, new: None, retain: None })).unwrap();
    let _ = play(&mut w, &[Run, Heal, Run, Unstrong(1, None, 0), Unstrong(0, None, 0), Run], String::new());
    two_as_fresh(w, 2, "disputed");
}

// Its retained copy arm (spec/permissions.md §3 Retain: the user may erase a copy at any time,
// with what is kept only through it): node 0 removes node 1's account from thing 0 saying
// retain, so node 1 keeps a copy; both let it go and node 1 erases its copy: each node as a
// fresh world's.
#[test]
fn releasing_a_retained_copy_returns_storage_to_a_fresh_worlds_spec_permissions_3() {
    let mut w = world_of(0, 2, 2);
    let _ = play(&mut w, &[New(0), Write(0, 0), Grant(0, 0, 1, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: Some(true) })).unwrap();
    w.run();
    assert_eq!(w.engine(1).kept_copies(), vec![t], "node 1 keeps a copy");
    let _ = play(&mut w, &[Unstrong(1, None, 0), Unstrong(0, None, 0), Run], String::new());
    w.write(1, |e| e.forget_lost(osis_engine::rotation::LostScope::Kept(&[t]))).unwrap();
    w.run();
    assert!(w.engine(1).kept_copies().is_empty(), "the copy erased");
    two_as_fresh(w, 2, "retained");
}

// Its dependent arm (spec/sync-set.md §3 Released: a thing leaving the node closure goes though
// the sync ID that carried it stays): node 0 mints U with thing 0 as admin, held from thing 0,
// which node 1's account reads and holds; thing 0 lets U go: at node 1 no row names U while
// thing 0's sync ID stays; then both let thing 0 go, each node as a fresh world's.
#[test]
fn a_dependent_thing_leaving_goes_while_its_sync_id_stays_spec_sync_set_3() {
    let mut w = world_of(0, 2, 2);
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), NewIn(0, 0), Write(0, 1), Run], String::new());
    let (t, u) = (w.history.things[0].0, w.history.things[1].0);
    assert!(w.engine(1).closure_holds(&u), "node 1 holds U");
    let _ = play(&mut w, &[Unstrong(0, Some(0), 1), Run], String::new());
    assert!(w.engine(1).closure_holds(&t) && !w.engine(1).closure_holds(&u), "U left, thing 0 stays");
    #[cfg(debug_assertions)]
    {
        let named: Vec<String> = w.rows(1, "", Some(&u)).into_iter().filter(|(_, r)| r.key.contains(&format!("t:{u}"))).map(|(d, r)| format!("{d} {}{}", r.family, r.key)).collect();
        assert!(named.is_empty(), "rows naming U at node 1: {named:?}\n{}", why_kept(&mut w, 1, &u));
    }
    let _ = play(&mut w, &[Unstrong(1, None, 0), Unstrong(0, None, 0), Run], String::new());
    two_as_fresh(w, 2, "dependent");
}

// spec/sync-judgement.md §3 (Restart and forgetting: an own entry logs a commit held here),
// spec/sync-set.md §3 (Nothing of R stays): node 0 makes an independent thing under its
// account, held from D, grants the account admin on it by a grant write and releases it; no own
// entry of a commit forgotten then stays under any sync ID, D's included (the grant's commit goes
// there as a grant naming the account, spec/sync-judgement.md §2, until nothing held needs the
// thing).
#[test]
fn a_released_things_forgotten_commits_leave_no_own_entry_spec_sync_judgement_3() {
    use osis_schema::core_types::HOLDS;
    let mut w = world_of(0, 1, 1);
    let d = w.node(0).account.unwrap();
    let t = w.write(0, |e| {
        let t = e.create_with_admin(&d).unwrap().0;
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap();
        e.grant(&t, &d, &grant(Role::Admin)).unwrap();
        t
    });
    w.run();
    let ds = w.engine(0).sync_id_of(&d).unwrap().unwrap();
    // the own entries of commits with a part on t, under every sync ID
    let mut logged = Vec::new();
    for (s, _) in w.store(0).syncs() {
        for e in w.store(0).entries(&s).unwrap() {
            let on_t = w.engine(0).blob_of(&e.blob).and_then(|x| w.engine(0).header(&x.commit)).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t));
            if e.own && on_t {
                logged.push((s, e.blob));
            }
        }
    }
    assert!(logged.iter().any(|(s, _)| *s == ds), "a commit on the thing is logged under D's sync ID");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.op(d, &HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(w.engine(0).core.created(&t).is_none(), "released");
    let forgotten: Vec<_> = logged.iter().filter(|(_, b)| w.engine(0).blob_of(b).is_none()).collect();
    assert!(forgotten.iter().any(|(s, _)| *s == ds), "a commit logged under D's sync ID is forgotten");
    for (s, b) in forgotten {
        assert!(w.store(0).entry(s, b).unwrap().is_none(), "an own entry of a forgotten commit under {s:?}");
    }
}



// spec/sync-ids.md §6 (Delete: a record or list blob losing to another there is deleted at a
// store once it shows the winner), spec/permissions.md §4 (Logging certificates): writers each
// logging a record blob of the same records every round leave a store keeping S unread holding
// as many entries after n rounds as after 10n. On deletes.rs's `four`: nodes 0 (admin), 2 and 3
// write thing 0, node 1 keeps its sync ID S unread; each round every writer seals a record blob
// of S's records at once, its own store holding no other (as each logs one before it holds
// another's).
#[test]
fn record_blobs_at_a_store_stay_flat_spec_sync_ids_6() {
    let (mut w, _, s) = crate::deletes::four();
    let records: std::collections::BTreeSet<Tid> = w.engine(0).certificate_records(&s).unwrap().iter().copied().collect();
    assert!(!records.is_empty(), "S carries records");
    let writers = [0, 2, 3];
    let mut held = Vec::new();
    for round in 0..10 {
        for i in writers {
            let noted = w.engine(i).cert_blobs(&s);
            for b in noted.keys() {
                w.store(i).clone().unlog_entry(&s, b).unwrap();
            }
            let mut rng = osis_crypto::SeededRng::from_u64(osis_base::testenv::seed_at(&[round as u64, i as u64]));
            let (blob, bytes, wrap) = w.engine(i).seal_records(&s, &records, &mut rng).unwrap().expect("sealed");
            let e = osis_sync::types::Entry { blob, wrap, stamp: None, deposited: false, own: true, role: false, class: osis_blob::Class::Durable, expires: None };
            w.store(i).clone().log(&s, e, Some(bytes), None).unwrap();
        }
        for i in writers {
            w.deliver(i, osis_sync::Input::Tick);
        }
        w.run();
        held.push(w.store(1).entries(&s).unwrap().len());
    }
    assert_eq!(held[0], held[9], "store entries after 1 and 10 rounds: {held:?}");
}

/// Node 1's first sync of `k` things of node 0's account, granted it read; `held`: node 2's
/// account holds read on each as well, so each unit carries account 2's public key record
/// (spec/sync-inbox.md §1). (bytes every other node sent it, distinct blobs fetched, fetches.)
fn key_record_wire(k: usize, held: bool) -> (u64, u64, u64) {
    let mut w = world_of(0, 3, 3);
    let mut steps = Vec::new();
    for t in 0..k {
        steps.push(New(0));
        if held {
            steps.push(Give(0, t, history::Holder::Node(2), Gives::Reads));
        }
    }
    steps.push(Run);
    let _ = play(&mut w, &steps, String::new());
    let sum = |f: &BTreeMap<(usize, usize, &'static str), (u64, u64)>| f.iter().filter(|((a, b, _), _)| *b == 1 && *a != 1).map(|(_, v)| v.1).sum::<u64>();
    let before = sum(&w.net.frames);
    w.net.count_fetched = true;
    let grants: Vec<_> = (0..k).map(|t| Grant(0, t, 1, Gives::Reads)).chain([Run]).collect();
    let _ = play(&mut w, &grants, String::new());
    let mut per_blob: BTreeMap<osis_base::BlobId, u64> = BTreeMap::new();
    for ((_, to), m) in &w.net.fetched {
        if *to == 1 {
            for (b, n) in m {
                *per_blob.entry(*b).or_default() += n.len() as u64;
            }
        }
    }
    (sum(&w.net.frames) - before, per_blob.len() as u64, per_blob.values().sum())
}

// spec/permissions.md §4 (Copies: one blob per distinct cut), spec/sync-inbox.md §1 (Public key
// record): a reader of
// k things another account holds a role on fetches that account's public key record once, not
// once per thing. Printed: bytes sent to the reader, distinct blobs and fetches, with and without
// the holder, at 1 and 4 things.
#[test]
#[ignore = "by hand: prints counts (four worlds, about 10 s)"]
fn a_holders_key_record_crosses_the_wire_once_spec_permissions_4() {
    for k in [1, 4] {
        let (with, without) = (key_record_wire(k, true), key_record_wire(k, false));
        eprintln!("{k} things: (bytes, distinct blobs, fetches) to the reader: {with:?} with the holder, {without:?} without");
    }
}

/// Frames between nodes 0 and 1 by (from, kind): count, bytes.
type Frames = BTreeMap<(usize, &'static str), (u64, u64)>;

/// Node 0 makes `n` things of its account A by `make` (each held by A's `holds.0`, a small value),
/// run to quiet after each: the frames between it and A's second node, node 1, and the sync IDs
/// node 1 pulled anew.
fn makes(w: &mut World, n: u64, make: impl FnMut(&mut osis_engine::Engine, Tid)) -> (Frames, u64) {
    let (f, anew, _) = makes_counting(w, n, make);
    (f, anew)
}

/// `makes` with the filters' false positives the makes met (Hits on nothing shown, each declined).
fn makes_counting(w: &mut World, n: u64, mut make: impl FnMut(&mut osis_engine::Engine, Tid)) -> (Frames, u64, u64) {
    let a = w.node(0).account.unwrap();
    let frames = |w: &World| -> Frames { w.net.frames.iter().filter(|((x, y, _), _)| (*x, *y) == (0, 1) || (*x, *y) == (1, 0)).map(|((x, _, k), v)| ((*x, *k), *v)).collect() };
    osis_base::costs::take();
    let before = frames(w);
    for _ in 0..n {
        w.write(0, |e| make(e, a));
        w.run();
        w.advance(1_000);
    }
    let costs = osis_base::costs::take();
    let sum = |name: &str| costs.iter().filter(|(k, ..)| *k == name).map(|(.., n)| n).sum::<u64>();
    let mut out = frames(w);
    for (k, v) in &mut out {
        let b = before.get(k).copied().unwrap_or((0, 0));
        *v = (v.0 - b.0, v.1 - b.1);
    }
    out.retain(|_, v| v.0 > 0);
    (out, sum("sync IDs pulled anew"), sum("opens: hits on nothing shown"))
}

/// Frame counts by kind with what filter false positives add taken out (at most `fp` of them):
/// each Head asked after a declined Hit (spec/sync-ids.md §6 Head), its answer, and the Offer
/// testing again once it is answered.
fn less_false_positives(f: &Frames, fp: u64) -> BTreeMap<(usize, &'static str), u64> {
    let mut out: BTreeMap<(usize, &'static str), u64> = f.iter().map(|(k, v)| (*k, v.0)).collect();
    for x in [0, 1] {
        let heads = out.remove(&(x, "Head")).unwrap_or(0);
        assert!(heads <= fp, "node {x} asked {heads} Heads beside {fp} false positives");
        out.remove(&(1 - x, "HeadReply"));
        if let Some(o) = out.get_mut(&(x, "Offer")) {
            *o -= heads.min(*o);
        }
    }
    out
}

// spec/sync-judgement.md §3 Dropped bodies, spec/requirements.md Scale: a thing another node of
// the account makes reaches its second node in the commit minting it, which brings its record
// (taken alone from the thing's sealed section, the thing not yet held): nothing of the thing was
// forgotten, so its unit is not pulled anew. Each make, 3 and 30 of them after 3, crosses as its
// stream frames alone, the same at n and 10n, with no Pull listing the unit. (A's `holds.0`
// grows a strong a make: its compaction snapshot grows with it, so bytes are not compared.)
#[test]
fn a_thing_another_node_makes_pulls_nothing_anew_spec_sync_judgement_3() {
    let mut w = World::new(0);
    w.add_node();
    w.pair(0);
    w.run();
    makes(&mut w, 3, a_dependent);
    let ((n, a), (n10, a10)) = (makes(&mut w, 3, a_dependent), makes(&mut w, 30, a_dependent));
    assert_eq!((a, a10), (0, 0), "sync IDs pulled anew at n and 10n");
    let kinds = |f: &Frames| f.iter().map(|(k, v)| (*k, v.0)).collect::<BTreeMap<_, _>>();
    let per = |f: &Frames, by: u64| kinds(f).into_iter().map(|(k, c)| (k, c / by)).collect::<BTreeMap<_, _>>();
    assert_eq!(per(&n, 3), per(&n10, 30), "frames per make: {n:?} at n, {n10:?} at 10n");
    assert!(!n10.keys().any(|k| k.1.starts_with("Pull")), "no pull: {n10:?}");
}

// spec/sync-streams.md §4 (Reports: a server counts what its peer reported applied, the count
// anchored in the peer's log), spec/sync-judgement.md §3 (`known`), NetStream S_echorestore:
// node 1, A's second node, is restored from a backup taken before three makes it took from
// node 0, and reconnects. At no step after is node 0, caught up with it on a sync ID, counting
// it holding an entry of that sync ID it lacks; at quiet it holds again what node 0 counts. This
// world passes without the anchor too (being caught up waits for node 1 to have pulled node 0's
// stream to its end); the anchor's own case: streams::a_restored_store_is_not_counted_*.
#[test]
fn a_node_restored_from_a_backup_is_counted_holding_nothing_it_lacks_spec_sync_streams_4() {
    let mut w = World::new(0);
    w.add_node();
    w.pair(0);
    w.run();
    makes(&mut w, 1, a_dependent);
    let backup = w.backup(1);
    makes(&mut w, 3, a_dependent);
    let counted = |w: &World| w.node(0).node.streams().known().rows_all().unwrap();
    let lacked = |w: &World, caught_only: bool| -> Vec<(osis_sync::store::Source, osis_base::SyncId, osis_base::BlobId)> {
        let status = w.node(0).node.status();
        counted(w).into_iter().filter(|(_, s, b)| (!caught_only || status.get(s).is_some_and(|st| st.sources.values().any(|x| x.caught_up))) && w.store(1).entry(s, b).unwrap().is_none()).collect()
    };
    assert!(!counted(&w).is_empty());
    w.restore(1, &backup);
    w.power_on(1);
    let mut steps = 0;
    while w.step_or_wake() {
        steps += 1;
        assert!(steps < 100_000, "settles");
        let l = lacked(&w, true);
        assert!(l.is_empty(), "step {steps}: node 0 caught up counts node 1 holding what it lacks: {l:?}");
    }
    assert!(lacked(&w, false).is_empty(), "at quiet");
}

// spec/sync-ids.md §5 (Across sync IDs: a commit blob held as what makes it again), notes/slim-design.md B
// (a part leaving the record keeps its section in the seal), spec/requirements.md Scale: a dependent make's commit writes the thing's value and A's `holds.0` part; a compaction
// snapshot of A's `holds.0` covers that part, which leaves the record, while the value stays live.
// Over 10 makes after 3, A's compactions among them, neither node keeps any blob's bytes: each
// blob is made again from its record and seal.
#[test]
fn a_dependent_make_keeps_no_blob_bytes_once_its_holds_part_is_covered_spec_sync_ids_5() {
    let mut w = World::new(0);
    w.add_node();
    w.pair(0);
    w.run();
    makes(&mut w, 3, a_dependent);
    let before = [w.disk_use(0), w.disk_use(1)];
    makes(&mut w, 10, a_dependent);
    for (i, b) in before.iter().enumerate() {
        let a = w.disk_use(i);
        for d in [0, 1] {
            assert_eq!((a[d].2, a[d].3), (b[d].2, b[d].3), "node {i} disk {d}: blobs (count, bytes) after 10 makes, before");
        }
    }
}

/// A dependent of `a` held by `a`'s `holds.0` (`Engine::new_thing`), with a small value.
fn a_dependent(e: &mut osis_engine::Engine, a: Tid) {
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, a);
    m.set(t, &value_ak(), &Value::Str("new".into())).unwrap();
    e.commit(m).unwrap();
}

/// An independent thing minted with admin `a` (`Engine::mint_independent`): its own-secrets
/// rotation carrying its record, then a commit of its small value and `a`'s strong to it in
/// `holds.0`.
fn an_independent(e: &mut osis_engine::Engine, a: Tid) {
    use osis_schema::core_types::HOLDS;
    e.mint_independent(&[osis_engine::MintAdmin::Thing(a)], |ts| {
        let mut m = Mutation::new();
        m.op(a, &HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(ts[0])) })?;
        m.set(ts[0], &value_ak(), &Value::Str("new".into()))?;
        Ok(vec![m])
    })
    .unwrap();
}

/// One unit of notes/slim-design.md's Today table in a world of its own (`World::new(0)`,
/// `add_node`, `pair(0)`): three warm-up makes by `make`, then per make over 10, A's `holds.0`
/// compactions included. Printed: frames each way (count, bytes, by kind), stored rows at the
/// minting node (node 0) and the second node (node 1), engine local rows (`local_census`: no index
/// rows or states) plus sync store rows (`scan_local`), with the families moving most, and blob
/// bytes on each node's disks.
fn today_row(name: &str, mut make: impl FnMut(&mut World) -> Box<dyn FnMut(&mut osis_engine::Engine, Tid)>) {
    let mut w = World::new(0);
    w.add_node();
    w.pair(0);
    w.run();
    let mut m = make(&mut w);
    makes(&mut w, 3, &mut m);
    let before = [held(&mut w, 0), held(&mut w, 1)];
    let (f, _) = makes(&mut w, 10, &mut m);
    let after = [held(&mut w, 0), held(&mut w, 1)];
    let per = |x: i64| x as f64 / 10.0;
    eprintln!("{name}, per make:");
    for x in [0, 1] {
        let (c, b): (u64, u64) = f.iter().filter(|(k, _)| k.0 == x).fold((0, 0), |a, (_, v)| (a.0 + v.0, a.1 + v.1));
        let mut kinds: Vec<_> = f.iter().filter(|(k, _)| k.0 == x).map(|(k, v)| (v.1, v.0, k.1)).collect();
        kinds.sort_unstable_by(|a, b| b.cmp(a));
        let kinds: Vec<String> = kinds.iter().map(|(b, c, k)| format!("{k} {}/{}", per(*c as i64), per(*b as i64))).collect();
        eprintln!("  wire {x}->{}: {} frames, {} B ({})", 1 - x, per(c as i64), per(b as i64), kinds.join(", "));
    }
    for (x, who) in [(0, "minting"), (1, "second")] {
        let (b, a) = (&before[x], &after[x]);
        let mut fams: Vec<(i64, String)> = Vec::new();
        for (side, (cb, ca)) in [("", (&b.0, &a.0)), ("sync ", (&b.1, &a.1))] {
            for k in cb.keys().chain(ca.keys()).collect::<std::collections::BTreeSet<_>>() {
                let d = ca.get(k).map_or(0, |v| v.1 as i64) - cb.get(k).map_or(0, |v| v.1 as i64);
                if d != 0 {
                    fams.push((d, format!("{side}{k}")));
                }
            }
        }
        let total: i64 = fams.iter().map(|f| f.0).sum();
        fams.sort_unstable_by(|p, q| q.0.abs().cmp(&p.0.abs()).then(p.1.cmp(&q.1)));
        let fams: Vec<String> = fams.iter().map(|(d, k)| format!("{k} {}", per(*d))).collect();
        let blobs = |d: usize| format!("{}/{} B", per(a.2[d].0 as i64 - b.2[d].0 as i64), per(a.2[d].1 as i64 - b.2[d].1 as i64));
        eprintln!("  stored, {who}: {} B ({}); blobs (count/bytes): engine disk {}, sync store disk {}", per(total), fams.join(", "), blobs(0), blobs(1));
    }
}

// spec: none (measurement: spec/requirements.md Scale; notes/slim-design.md, Today).
// What a dependent make, a 1-byte change and an independent make cost per make over real sync
// (`today_row`), so a slimming job and its base are each one run.
#[test]
#[ignore = "by hand: prints notes/slim-design.md's Today table (three worlds)"]
fn today_table() {
    today_row("one dependent, one small value, alone", |_| Box::new(a_dependent));
    today_row("a 1-byte change on one dependent", |w| {
        let a = w.node(0).account.unwrap();
        let t = w.write(0, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            m.set(t, &value_ak(), &Value::Str("a".into())).unwrap();
            e.commit(m).unwrap();
            t
        });
        w.run();
        let mut i = 0u8;
        Box::new(move |e, _| {
            i += 1;
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(char::from(b'a' + i % 26).to_string())).unwrap();
            e.commit(m).unwrap();
        })
    });
    today_row("one independent (`mint_independent`, held by A's `holds.0`)", |_| Box::new(an_independent));
}

// spec/sync-judgement.md §3 Dropped bodies, spec/requirements.md Scale: an independent thing
// another node of the account makes reaches its second node as its rotation (its minting) and
// then its content commit, carrying A's strong to it, in a later transaction of the same pass:
// nothing of the thing was forgotten between them, so A's unit is not pulled anew. At 3 and 30
// makes after 3 no sync ID is pulled anew, and the frames (but what filter false positives add)
// and PullReply bytes per make (the new thing's own sync ID's first sync) are the same at n and 10n.
#[test]
fn an_independent_thing_another_node_makes_pulls_nothing_anew_spec_sync_judgement_3() {
    let mut w = World::new(0);
    w.add_node();
    w.pair(0);
    w.run();
    makes(&mut w, 3, an_independent);
    let ((n, a, fp), (n10, a10, fp10)) = (makes_counting(&mut w, 3, an_independent), makes_counting(&mut w, 30, an_independent));
    assert_eq!((a, a10), (0, 0), "sync IDs pulled anew at n and 10n");
    // a filter's false positive costs a declined Hit and a Head: chance, not growth
    let per = |f: &Frames, fp: u64, by: u64| less_false_positives(f, fp).into_iter().map(|(k, c)| (k, c / by)).collect::<BTreeMap<_, _>>();
    assert_eq!(per(&n, fp, 3), per(&n10, fp10, 30), "frames per make: {n:?} at n, {n10:?} at 10n");
    // a Pull each way per make: the new thing's own sync ID's first sync, the same bytes each make
    let pulled = |f: &Frames, by: u64| f.iter().filter(|(k, _)| k.1 == "PullReply").map(|(k, v)| (k.0, v.1 / by)).collect::<BTreeMap<_, _>>();
    assert_eq!(pulled(&n, 3), pulled(&n10, 30), "PullReply bytes per make at n and 10n");
}
