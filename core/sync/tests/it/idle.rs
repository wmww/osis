//! Work per sync ID held at idle (spec/sync-streams.md §4 Costs; spec/sync.md §2): node 0 makes
//! `n` things, node 1's account keeps each unread, node 2's reads each; what an idle reconnect
//! and one small commit cost, counted at n and 10n things, never timed.

use crate::harness::Step::*;
use crate::harness::history::shared;
use crate::harness::{World, play};

const N: usize = 1;

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

/// The named counters' sum in `costs`.
fn sum(costs: &[(&'static str, u64)], named: &[&str]) -> u64 {
    costs.iter().filter(|(k, _)| named.contains(k)).map(|(_, n)| n).sum()
}

// spec/sync-streams.md §4 (Costs: bytes that do not grow with the number of sync IDs shared;
// Joining: no join for a member at the stream's cursor), spec/sync-opens.md §5 (filter: additions
// of the sync IDs whose `changed_at` is past `acked_pos`): an idle reconnect of the writer and a
// reader, and of the writer and a node keeping every thing unread, sends the same bytes at n and
// 10n shared sync IDs (but for the widths of the integers it names). Both pairs dial at once, so
// one connection closes with a filter generation unanswered on it.
//
// spec/sync.md §2 (Work in proportion to change: Each event re-judges only what it touches): the
// same reconnects judge nothing of a member again: no stranding (S's sources are read only where
// the engine's word could strand it), no register plan with a reader (only a store keeping S
// unread registers steps), no member's standing (followed per record, across its connections:
// spec/sync-opens.md §6), no certificate blobs (S's sources read only where a blob loses to
// another), no register plan or lacking count at a store (kept per record, the connection read
// only where a step is to go or an entry lacks by the record's rows), and no thing enters the
// sync set: as many at n as at 10n shared sync IDs. Not yet flat (issues/many-sync-ids-cost.md):
// store rows.
//
// spec/sync-streams.md §4 (Joining: a connection that takes a record pulls its members from where
// the record holds them, with no join for a member at the stream's cursor; Costs),
// spec/sync-judgement.md §3 (what is owed at a source is judged from `known` alone, connected or
// not), spec/sync-status.md §1 (sources), spec/sync-inbox.md §3 (Sending): the same reconnects
// read no row per member in streams (the place and what the source showed are the record's),
// read, status or inbox (what each keeps is the record's, a take moving only its connection): as
// many store rows by each at n as at 10n shared sync IDs, but for a settle round more or fewer.
// Opens reads its peer filter's entries again at the take (dropped while no connection holds the
// record: notes/sync-opens.md, Durability), under a row per member. The rest are per input the
// node handles, not per sync ID (about 15 each: `Store::next_wake`'s scans 8, the driver's store
// step 5, flush 1), and an idle reconnect at 10n handles about as many inputs as at n.
#[test]
#[ignore = "sync rewrite: copies per (commit, thing)"]
fn an_idle_reconnect_sends_reads_and_judges_the_same_at_10n_spec_sync_streams_4() {
    const READER: &[&str] = &["opens: members judged", "status: stranded", "inbox: register judged", "opens standing", "perm: roles walked", "read: certificate blobs", "sync set: entered", "status: members moved", "inbox: members moved", "inbox: offer judged"];
    const STORE: &[&str] = &["opens: members judged", "status: stranded", "opens standing", "perm: roles walked", "read: certificate blobs", "inbox: register judged", "status: lacking", "status: members moved", "inbox: members moved", "inbox: offer judged"];
    const MEMBERS: u64 = (10 * N - N) as u64;
    let at = |n| {
        let mut w = shared(n);
        [reconnect(&mut w, 0, 2), reconnect(&mut w, 0, 1)]
    };
    let (small, large) = (at(N), at(10 * N));
    for (i, (who, named)) in [("a reader", READER), ("a node keeping them unread", STORE)].into_iter().enumerate() {
        let ((sa, ca), (sb, cb)) = (&small[i], &large[i]);
        assert!(*sb <= sa + 32, "with {who}: {sa} bytes at n, {sb} at 10n");
        for k in named {
            let (a, b) = (sum(ca, &[k]), sum(cb, &[k]));
            assert!(b <= a, "with {who}: {k} {a} at n, {b} at 10n");
        }
        for module in ["store rows read <- streams", "store rows read <- read", "store rows read <- status", "store rows read <- inbox"] {
            let (a, b) = (sum(ca, &[module]), sum(cb, &[module]));
            assert!(b <= a + 8, "with {who}: {module} {a} at n, {b} at 10n");
        }
        let (a, b) = (sum(ca, &["store rows read <- opens"]), sum(cb, &["store rows read <- opens"]));
        assert!(b < a + MEMBERS, "with {who}: opens reads {a} rows at n, {b} at 10n: a row or more per member");
        let (a, b) = (sum(ca, &["store rows read"]), sum(cb, &["store rows read"]));
        assert!(b <= a + MEMBERS + 4 * 16, "with {who}: {a} rows at n, {b} at 10n");
    }
}

/// The named counters' sum over one small commit by node 0 on thing 0, run to quiet.
fn commit(w: &mut World, named: &[&str]) -> u64 {
    exact();
    let _ = play(w, &[Write(0, 0), Run], String::new());
    osis_base::costs::take().into_iter().filter(|(k, ..)| named.contains(k)).map(|(.., n)| n).sum()
}

// spec/sync.md §2 (Work in proportion to change: Each event re-judges only what it touches),
// spec/sync-status.md §1 (caught up: another sync ID's traffic on the connection moves
// nothing of S's caught up): a small commit on one sync ID re-judges as many strandings at n as at 10n
// shared sync IDs.
//
// spec/sync.md §2 (Work in proportion to change: No rule re-derives a whole sync ID, store or
// connection on a timer): time passing re-judges no held actor's duties (a role commit owed, a
// lost access to drop) unless a grant's `until` or a role commit's `ts` falls due on what reaches
// it: a small commit after an hour with nothing due judges as many at n as at 10n things.
#[test]
#[ignore = "accounts: making an account"]
fn a_commit_judges_one_stranding_and_time_passing_no_duty_per_thing_spec_sync_status_1() {
    let at = |n| {
        let mut w = shared(n);
        let stranded = commit(&mut w, &["status: stranded"]);
        w.jump(3_600_000);
        (stranded, commit(&mut w, &["life: role duty owed", "life: lost access"]))
    };
    let (small, large) = (at(N), at(10 * N));
    assert!(large.0 <= small.0, "strandings judged: {} at n, {} at 10n", small.0, large.0);
    assert!(large.1 <= small.1, "duties judged: {} at n, {} at 10n", small.1, large.1);
}

/// By hand: every counter of an idle reconnect with a reader (R), with a node keeping every
/// thing unread (S) and of one small commit (C), at n and 10n things (`--ignored --nocapture`).
/// What issues/many-sync-ids-cost.md counts.
#[test]
#[ignore = "by hand: prints counts"]
fn probe_counts() {
    for n in [N, 10 * N] {
        let mut w = shared(n);
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
