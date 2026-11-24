//! A first sync of many sync IDs (spec/sync-streams.md §4 Costs, Joining; spec/sync.md §2): node 0
//! makes a root with `n` independent members (each minted with the root as admin, then made
//! independent), node 1's account keeps the root unread; node 2's account is granted read on the root and
//! syncs the closure for the first time. Counted at n and 5n members, never timed.

use crate::harness::Step::*;
use crate::harness::history::{Gives, Holder, world_of};
use crate::harness::{World, fixture, fixture_with, play};
use osis_base::BlobId;
use std::collections::BTreeMap;
use std::sync::Mutex;

const N: usize = 1;
/// The larger size: growth shows at any size past n, and each member adds to the run.
const LARGE: usize = 5 * N;

/// Node 0 has made thing 0 (the root) and `n` members minted with it as admin, each independent, node 1 keeps
/// the root unread, quiet (built on the world of `N` members).
fn closure(n: usize) -> World {
    fixture(&format!("first closure {n}"), || {
        let mut w = if n == N { world_of(0, 3, 3) } else { closure(N) };
        w.cap = 2_000_000;
        let mut steps = Vec::new();
        if n == N {
            steps.extend([New(0), Grant(0, 0, 1, Gives::Syncs)]);
        }
        for k in w.history.things.len().max(1)..=n {
            steps.extend([NewIn(0, 0), Rotate(0, k)]);
        }
        steps.extend([Run, Cut(0, 1), Run]);
        let _ = play(&mut w, &steps, String::new());
        w
    })
}

/// Counts exact from here (`idle::exact`).
fn exact() {
    osis_base::memo::check_effects(false);
    osis_base::costs::take();
}

/// What node 2's first sync of the closure costs: deliveries, the frames each node sent each other
/// node per kind (count, bytes), each blob fetched per node pair (with how many times), and the
/// named counters.
#[derive(Clone)]
struct Cost {
    deliveries: u64,
    frames: BTreeMap<(usize, usize, &'static str), (u64, u64)>,
    fetched: BTreeMap<(usize, usize), BTreeMap<BlobId, u64>>,
    /// Blobs a node fetched and holds no entry of at the end (under any sync ID), per fetcher.
    unkept: BTreeMap<usize, Vec<BlobId>>,
    /// Per node, the sync IDs it holds entries of, and those of them with no head logged.
    heads: Vec<(usize, Vec<osis_base::SyncId>)>,
    costs: Vec<(&'static str, u64)>,
}

impl Cost {
    /// Frames of `kind` node `a` sent node `b`: (count, bytes).
    fn sent(&self, a: usize, b: usize, kind: &str) -> (u64, u64) {
        self.frames.iter().find(|((x, y, k), _)| (*x, *y, *k) == (a, b, kind)).map_or((0, 0), |(_, v)| *v)
    }
}

/// Node 2's account granted read on the root, then run to quiet: what it cost (`Cost`).
fn first(w: &mut World) -> Cost {
    exact();
    let (d, frames) = (w.deliveries, w.net.frames.clone());
    w.net.count_fetched = true;
    w.net.fetched.clear();
    let _ = play(w, &[Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let mut out = w.net.frames.clone();
    for (k, (n, b)) in frames {
        let e = out.get_mut(&k).unwrap();
        e.0 -= n;
        e.1 -= b;
    }
    out.retain(|_, v| v.0 > 0);
    let costs = osis_base::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
    let mut unkept: BTreeMap<usize, Vec<BlobId>> = BTreeMap::new();
    for ((_, to), blobs) in &w.net.fetched {
        for b in blobs.keys() {
            if w.store(*to).naming(b).unwrap().is_empty() {
                unkept.entry(*to).or_default().push(*b);
            }
        }
    }
    let heads = (0..3)
        .map(|i| {
            let store = w.store(i).clone();
            let held: Vec<_> = store.syncs().into_keys().filter(|s| !store.entries(s).unwrap().is_empty()).collect();
            (held.len(), held.into_iter().filter(|s| store.head_at(s).unwrap().is_none()).collect())
        })
        .collect();
    Cost { deliveries: w.deliveries - d, frames: out, fetched: w.net.fetched.clone(), unkept, heads, costs }
}

/// `first` over the closure of `n` members, once per process (a world is a function of its seed).
fn cost(n: usize) -> Cost {
    // held while it runs: the tests asking for the same size wait for it, not run it again
    static COSTS: Mutex<BTreeMap<usize, Cost>> = Mutex::new(BTreeMap::new());
    let mut costs = COSTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    costs.entry(n).or_insert_with(|| first(&mut closure(n))).clone()
}

// spec/sync-judgement.md §3 (Own store: an entry of the body under S it pulled stands as that
// log, another's body or certificate logged only once S's first sync here ended or a complete
// pass of S did), spec/permissions.md §4 (Logging certificates: except what an entry under the
// sync ID already holds): a new reader syncing a closure from its maker logs no copy of
// what the maker holds under each member's sync ID, so the maker fetches nothing back from it:
// as many bodies at 5n members as at n.
#[test]
fn a_new_reader_logs_no_copy_of_what_its_source_holds_spec_sync_judgement_3() {
    let (small, large) = (cost(N), cost(LARGE));
    let (asked, answered) = ((small.sent(0, 2, "Fetch"), large.sent(0, 2, "Fetch")), (small.sent(2, 0, "FetchReply"), large.sent(2, 0, "FetchReply")));
    assert!(asked.1.0 <= asked.0.0, "the maker fetched from the reader {} times at n, {} at 5n", asked.0.0, asked.1.0);
    assert!(answered.1.1 <= answered.0.1, "the reader sent the maker {} bytes of bodies at n, {} at 5n", answered.0.1, answered.1.1);
}

// spec/sync-streams.md §4 (Joining: opens from one Offer batch join in one Pull; Bodies: a
// requester fetches every body announced without bytes), spec/wire.md §11.2 (Fetch: blob IDs
// grouped by sync ID): the members' opens go in one Offer, their joins in one Pull, their bodies
// in Fetches of up to `MAX_FETCH_IDS` whatever sync IDs they are under, so a first sync's round
// trips do not grow per member: 113 deliveries at n, 121 at 5n and at 10n (`probe_first`); one
// Fetch per sync ID cost 3 to 6 deliveries per member (137 at 5n, 153 at 10n).
#[test]
#[ignore = "sync rewrite: copies per (commit, thing)"]
fn a_first_sync_of_n_sync_ids_takes_the_same_round_trips_spec_sync_streams_4() {
    const MEMBERS: u64 = (LARGE - N) as u64;
    let (small, large) = (cost(N), cost(LARGE));
    assert!(large.deliveries <= small.deliveries + 2 * MEMBERS, "{} deliveries at n members, {} at 5n", small.deliveries, large.deliveries);
    let (a, b) = (small.sent(2, 0, "Fetch").0, large.sent(2, 0, "Fetch").0);
    assert!(b <= a + 1, "the reader sent {a} Fetches at n members, {b} at 5n");
}

// spec/sync-streams.md §4 (Bodies: only blob IDs its store lacks are fetched; an entry whose
// blob's bytes it holds under another sync ID is taken with them, under the entry's wrap; a
// blob counts as asked while a fetch of it from some source is unanswered): a blob carried under
// every member's sync ID (a certificate copy of the root's roles) is fetched once, whatever the
// number of sync IDs announcing it.
#[test]
fn a_blob_is_fetched_once_whatever_sync_ids_carry_it_spec_sync_streams_4() {
    let large = cost(LARGE);
    for ((a, b), blobs) in &large.fetched {
        let again: Vec<_> = blobs.iter().filter(|(_, n)| **n > 1).collect();
        assert!(again.is_empty(), "node {b} fetched from node {a} again: {again:?}");
    }
    assert!(!large.fetched.is_empty(), "nothing fetched: the closure is not first synced");
}

// spec/permissions.md §4 (Logging certificates: a record or list blob counts once opened, while
// held here or at a source, and one losing to another leaves the own store), spec/sync-streams.md §4
// (Bodies: nor one it counts is fetched): what a new reader fetches and does not keep is only
// what it could judge by opening it alone (the maker's record blob that the grant made lose, which
// the store keeping the root unread still lists until the maker's Delete reaches it), once each
// and as many at 5n members as at n.
#[test]
fn what_a_reader_fetches_and_drops_does_not_grow_spec_permissions_4() {
    let (small, large) = (cost(N), cost(LARGE));
    let count = |c: &Cost| c.unkept.values().map(Vec::len).sum::<usize>();
    assert!(count(&large) <= count(&small), "fetched and not kept: {:?} at n, {:?} at 5n", small.unkept, large.unkept);
    for (to, blobs) in &large.unkept {
        for b in blobs {
            let n: u64 = large.fetched.iter().filter(|((_, t), _)| t == to).filter_map(|(_, m)| m.get(b)).sum();
            assert_eq!(n, 1, "node {to} fetched {b:?}, which it does not keep, {n} times");
        }
    }
}

// spec/sync-streams.md §4 (Reading: a server reads its log after its served heads are logged;
// Pushes: ephemeral entries go only in a message with a cursor): a node holding an entry of S has
// S's head logged, so its log names a position whenever it serves S and no ephemeral entry is
// held back for one (streams::ephemeral_entries_wait_for_a_log_position builds that case on a
// bare store): the maker, the node keeping the closure unread and the new reader alike.
#[test]
fn a_node_holding_an_entry_of_s_has_its_head_logged_spec_sync_streams_4() {
    let c = cost(N);
    for (i, (held, missing)) in c.heads.iter().enumerate() {
        assert!(*held > 0, "node {i} holds entries");
        assert!(missing.is_empty(), "node {i} holds entries of {missing:?} with no head logged");
    }
}

/// `world_of(0, 2, 3)` where node 2 has made thing t, then node 0 is cut off from both peers;
/// built once per process (`fixture_with`).
fn cut_off() -> (World, osis_base::Tid) {
    fixture_with("first cut off", || {
        let mut w = world_of(0, 2, 3);
        let _ = play(&mut w, &[New(2), Run, Partition(0, 1), Partition(0, 2)], String::new());
        let t = w.history.things[0].0;
        (w, t)
    })
}

/// Node 2's bodies are must-hold under S at node 0, and node 0 logs each.
fn must_hold_logged(w: &mut World, s: &osis_base::SyncId) {
    let must: Vec<_> = w.engine(0).commit_ids().into_iter().filter(|c| w.node(0).node.verdict(s, c) == Some(osis_sync::read::Verdict::Must)).collect();
    assert!(!must.is_empty(), "node 2's bodies must-hold under S");
    assert!(must.iter().all(|c| w.engine(0).commit_blobs(c).unwrap().iter().any(|b| w.store(0).entry(s, b).unwrap().is_some())), "logged");
}

// spec/sync-judgement.md §3 (Own store: another's body logged only once S's first sync here ended
// or a complete pass of S did), spec/sync-status.md §1 (PASS_WAIT_MS: a complete pass with no
// source waits for a peer to be waited for): node 0, cut off from both peers, gives node 1's
// account sync on node 2's thing, a new sync ID S. Its log of node 2's bodies under S waits for
// the pass, still under way when a run's horizon, shorter than `PASS_WAIT_MS`, is reached (as at
// a pass begun late in a run, after a failed step restarted the node); quiet waits it out, so
// every must-hold body is logged (`World::run`'s quiet check).
#[test]
#[ignore = "accounts: pairing"]
fn a_log_waits_out_its_pass_spec_sync_judgement_3() {
    let (mut w, t) = cut_off();
    w.horizon_ms = osis_proto::limits::PASS_WAIT_MS / 2;
    let _ = play(&mut w, &[Give(0, 0, Holder::Node(1), Gives::Syncs), Run], String::new());
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    assert!(w.node(0).node.status_of(&s).is_some_and(|x| x.pass_waits.is_none()), "the pass ended");
    must_hold_logged(&mut w, &s);
}

// spec/sync-status.md §1 (PASS_WAIT_MS: a pass's start is dated durably), spec/sync-streams.md §1
// (Waits: a pass's start outlives a restart): node 0, cut off from both peers, gives node 1's
// account sync on node 2's thing (a new sync ID S, its log of node 2's bodies held back for the
// pass) and restarts every quarter of `PASS_WAIT_MS`; the pass ends `PASS_WAIT_MS` after it first
// began all the same, and the bodies are logged. Fails with a pass's wait counted from each start.
#[test]
#[ignore = "accounts: pairing"]
fn restarts_hold_no_pass_past_its_wait_spec_sync_status_1() {
    use osis_proto::limits::PASS_WAIT_MS;
    let (mut w, t) = cut_off();
    let _ = play(&mut w, &[Give(0, 0, Holder::Node(1), Gives::Syncs)], String::new());
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    for _ in 0..3 {
        w.advance(PASS_WAIT_MS / 4);
        assert!(w.node(0).node.status_of(&s).is_some_and(|x| x.pass_waits.is_some()), "under way");
        w.power_off(0);
        w.power_on(0);
    }
    w.advance(PASS_WAIT_MS / 4 + 60_000);
    assert!(w.node(0).node.status_of(&s).is_some_and(|x| x.pass_waits.is_none()), "the pass ended");
    must_hold_logged(&mut w, &s);
}

/// By hand: every counter and the frame census of the first sync at n and 10n members
/// (`--ignored --nocapture`). What issues/many-sync-ids-cost.md counts.
#[test]
#[ignore = "by hand: prints counts"]
fn probe_first() {
    for n in [N, LARGE, 10 * N] {
        let mut w = closure(n);
        let c = first(&mut w);
        println!("F{n} deliveries {}", c.deliveries);
        println!("F{n} unkept {:?}", c.unkept);
        println!("F{n} fetched twice {:?}", c.fetched.iter().map(|(k, v)| (k, v.values().filter(|x| **x > 1).count())).collect::<Vec<_>>());
        for ((a, b, k), (count, bytes)) in &c.frames {
            println!("  F{n} {a}->{b} {k} {count} {bytes}");
        }
        for (k, v) in &c.costs {
            println!("  F{n} {k} {v}");
        }
    }
}
