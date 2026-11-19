//! Work per sync ID held at idle (spec/sync-streams.md §4 Costs; spec/sync.md §2): node 0 makes
//! `n` things, node 1's account keeps each unread, node 2's reads each; what an idle reconnect
//! costs, counted at n and 10n things, never timed.

use crate::harness::Step::*;
use crate::harness::history::{Gives, world};
use crate::harness::{World, fixture, play};

const N: usize = 2;

/// Node 0 has made `n` things, each kept unread by node 1 and read by node 2, quiet, each pair
/// reconnected once since (built on the world of `N` things). The first reconnect after first
/// contact proves other actors than the record names (the cards' key actors), so it tests every
/// credential again (spec/sync-opens.md §3): not an idle one.
fn things(n: usize) -> World {
    fixture(&format!("idle things {n}"), || {
        let mut w = if n == N { world(0, 3) } else { things(N) };
        w.cap = 2_000_000;
        let mut steps = Vec::new();
        for k in w.history.things.len()..n {
            steps.extend([New(0), Grant(0, k, 1, Gives::Syncs), Grant(0, k, 2, Gives::Reads)]);
        }
        steps.extend([Run, Cut(0, 1), Run, Cut(0, 2), Run]);
        let _ = play(&mut w, &steps, String::new());
        w
    })
}

/// What one idle reconnect of `a` and `b` costs: bytes sent, and the named counters.
fn reconnect(w: &mut World, a: usize, b: usize) -> (u64, Vec<(&'static str, u64)>) {
    osis_base::costs::take();
    let bytes = w.net.bytes;
    w.cut(a, b);
    w.run();
    let costs = osis_base::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect();
    (w.net.bytes - bytes, costs)
}

// spec/sync-streams.md §4 (Costs: bytes that do not grow with the number of sync IDs shared;
// Joining: no join for a member at the stream's cursor), spec/sync-opens.md §5 (filter: additions
// of the sync IDs whose `changed_at` is past `acked_pos`): an idle reconnect of the writer and a
// reader, and of the writer and a node keeping every thing unread, sends the same bytes at n and
// 10n shared sync IDs (but for the widths of the integers it names). Both pairs dial at once, so
// one connection closes with a filter generation unanswered on it.
#[test]
fn an_idle_reconnect_sends_the_same_at_10n_spec_sync_streams_4() {
    let at = |n| {
        let mut w = things(n);
        [reconnect(&mut w, 0, 2).0, reconnect(&mut w, 0, 1).0]
    };
    let (small, large) = (at(N), at(10 * N));
    for (i, who) in ["a reader", "a node keeping them unread"].iter().enumerate() {
        assert!(large[i] <= small[i] + 32, "with {who}: {} bytes at n, {} at 10n", small[i], large[i]);
    }
}
