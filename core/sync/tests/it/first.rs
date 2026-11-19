//! A first sync of many sync IDs (spec/sync-streams.md §4 Costs, Joining; spec/sync.md §2): node 0
//! makes a root with `n` independent members (each minted under it, then given secrets of its
//! own), node 1's account keeps the root unread; node 2's account is granted read on the root and
//! syncs the closure for the first time. Counted at n and 5n members, never timed.

use crate::harness::Step::*;
use crate::harness::history::{Gives, world};
use crate::harness::{World, fixture, play};
use osis_base::BlobId;
use std::collections::BTreeMap;
use std::sync::Mutex;

const N: usize = 1;
/// The larger size: growth shows at any size past n, and each member adds to the run.
const LARGE: usize = 5 * N;

/// Node 0 has made thing 0 (the root) and `n` members under it, each independent, node 1 keeps
/// the root unread, quiet (built on the world of `N` members).
fn closure(n: usize) -> World {
    fixture(&format!("first closure {n}"), || {
        let mut w = if n == N { world(0, 3) } else { closure(N) };
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
    Cost { deliveries: w.deliveries - d, frames: out, fetched: w.net.fetched.clone(), costs }
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

/// By hand: every counter and the frame census of the first sync at n and 10n members
/// (`--ignored --nocapture`). What issues/many-sync-ids-cost.md counts.
#[test]
#[ignore = "by hand: prints counts"]
fn probe_first() {
    for n in [N, 10 * N] {
        let mut w = closure(n);
        let c = first(&mut w);
        println!("F{n} deliveries {}", c.deliveries);
        for ((a, b, k), (count, bytes)) in &c.frames {
            println!("  F{n} {a}->{b} {k} {count} {bytes}");
        }
        for (k, v) in &c.costs {
            println!("  F{n} {k} {v}");
        }
    }
}
