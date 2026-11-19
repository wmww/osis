//! Work per sync ID held at idle (spec/sync-streams.md §4 Costs; spec/sync.md §2): node 0 makes
//! `n` things, node 1's account keeps each unread, node 2's reads each; what an idle reconnect
//! and one small commit cost, counted at n and 10n things, never timed.

use crate::harness::Step::*;
use crate::harness::history::{Gives, world};
use crate::harness::{World, fixture, play};

const N: usize = 1;

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

/// Counts exact from here: no memo debug comparison (the history world turns them on) runs
/// in place of a settle.
fn exact() {
    osis_base::memo::check_effects(false);
    osis_base::costs::take();
}

/// What one idle reconnect of `a` and `b` costs: bytes sent, and the named counters.
fn reconnect(w: &mut World, a: usize, b: usize) -> (u64, Vec<(&'static str, u64)>) {
    exact();
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

/// The named counters' sum in `costs`.
fn sum(costs: &[(&'static str, u64)], named: &[&str]) -> u64 {
    costs.iter().filter(|(k, _)| named.contains(k)).map(|(_, n)| n).sum()
}

// spec/sync.md §2 (Work in proportion to change: Each event re-judges only what it touches): an
// idle reconnect judges no member's stranding again, with a reader or with a node keeping every
// thing unread (S's sources are read only where the engine's word could strand it), and no
// register plan with a reader (only a store keeping S unread registers steps): as many at n as
// at 10n shared sync IDs. Not yet flat (issues/many-sync-ids-cost.md): standing, certificate blobs and store rows.
#[test]
fn an_idle_reconnect_judges_no_stranding_again_spec_sync_2() {
    let at = |n| {
        let mut w = things(n);
        let (_, reader) = reconnect(&mut w, 0, 2);
        let (_, store) = reconnect(&mut w, 0, 1);
        [sum(&reader, &["status: stranded", "inbox: register judged"]), sum(&store, &["status: stranded"])]
    };
    let (small, large) = (at(N), at(10 * N));
    for (i, who) in ["a reader", "a node keeping them unread"].iter().enumerate() {
        assert!(large[i] <= small[i], "with {who}: {} judged at n, {} at 10n", small[i], large[i]);
    }
}

/// The named counters' sum over one small commit by node 0 on thing 0, run to quiet.
fn commit(w: &mut World, named: &[&str]) -> u64 {
    exact();
    let _ = play(w, &[Write(0, 0), Run], String::new());
    osis_base::costs::take().into_iter().filter(|(k, ..)| named.contains(k)).map(|(.., n)| n).sum()
}

// spec/sync.md §2 (Work in proportion to change: No rule re-derives a whole sync ID, store or
// connection on a timer): time passing re-judges no held actor's duties (a role commit owed, a
// lost access to drop) unless a grant's `until` or a role commit's `ts` falls due on what reaches
// it: a small commit after an hour with nothing due judges as many at n as at 10n things.
#[test]
fn time_passing_rejudges_no_duty_per_thing_spec_sync_2() {
    let at = |n| {
        let mut w = things(n);
        w.jump(3_600_000);
        commit(&mut w, &["life: role duty owed", "life: lost access"])
    };
    let (small, large) = (at(N), at(10 * N));
    assert!(large <= small, "duties judged: {small} at n, {large} at 10n");
}

// spec/sync.md §2 (Work in proportion to change: Each event re-judges only what it touches),
// spec/sync-status.md §1 (caught up: another sync ID's traffic on the connection moves
// nothing of S's caught up): a small commit on one sync ID re-judges as many strandings at n as at 10n
// shared sync IDs.
#[test]
fn a_commit_judges_one_stranding_spec_sync_status_1() {
    let at = |n| commit(&mut things(n), &["status: stranded"]);
    let (small, large) = (at(N), at(10 * N));
    assert!(large <= small, "strandings judged: {small} at n, {large} at 10n");
}

/// By hand: every counter of an idle reconnect with a reader (R), with a node keeping every
/// thing unread (S) and of one small commit (C), at n and 10n things (`--ignored --nocapture`).
/// What issues/many-sync-ids-cost.md counts.
#[test]
#[ignore = "by hand: prints counts"]
fn probe_counts() {
    for n in [N, 10 * N] {
        let mut w = things(n);
        for (tag, b) in [("R", 2), ("S", 1)] {
            let (bytes, costs) = reconnect(&mut w, 0, b);
            println!("{tag}{n} bytes {bytes}");
            for (k, v) in costs {
                println!("  {tag}{n} {k} {v}");
            }
        }
        exact();
        let _ = play(&mut w, &[Write(0, 0), Run], String::new());
        for (k, _, v) in osis_base::costs::take() {
            println!("  C{n} {k} {v}");
        }
    }
}
