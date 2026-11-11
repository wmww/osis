#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A leaver's self-removal placed by a co-reader's report (spec/sync.md §5 Placed, §10 Reports):
//! with no host, the removal counts as placed once a co-reader that reads the label reported
//! (Applied) a position past where the leaver's log first held it; the report is kept across a
//! restart; a peer that does not read the label reports nothing for it. A node whose access an
//! `until` ended hears such a label out by its co-readers (spec/permissions.md §2).

use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{Role, Tid};
use osis_node::flows::Demotion;
use osis_store::{Fault, Faults};

/// Co-readers `a` (dialable) and `b` (`faults` on its device) of `a`'s group `g`, no host;
/// `b` left `g` while `a` was offline: its removal waits to be placed.
fn left_while_apart(faults: &Faults) -> (Net, usize, usize, Tid, osis_base::LabelId) {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.forensic_node(2, &[], faults);
    reach_ed(&mut net, a);
    let g = net.group_seeded(a, &[(b, Role::Write)], vec![], 11);
    net.run();
    let l = net.group_labels(b).into_iter().find(|(x, _)| *x == g).map(|(_, gl)| gl.id).unwrap();
    net.set_online(a, false);
    let holder = net.tid(b);
    let done = net.engine(b).demote(&g, &Demotion { holder, new: None, retain: None }).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.advance(60_000);
    assert!(leaving(&mut net, b), "nobody has the removal");
    (net, a, b, g, l)
}

fn leaving(net: &mut Net, n: usize) -> bool {
    net.sync(n).leaving().next().is_some()
}

// spec/sync.md §5 (Placed: reported by a co-reader sharing the label), §10 (Reports): a removal a
// co-reader with no host pulled and reported is placed: the leaver drops what it lost.
#[test]
fn a_removal_a_co_reader_reported_is_placed_spec_sync_5() {
    let (mut net, a, b, g, _) = left_while_apart(&Faults::new());
    net.set_online(a, true);
    net.advance(60_000);
    assert!(!leaving(&mut net, b), "the co-reader's report placed the removal");
    assert!(net.engine(b).epochs(&g).is_none_or(|e| e.read.held().next().is_none()), "the leaver dropped what it lost");
}

// spec/sync.md §5 (Placed): a report the leaver took stands across a crash before it forgot:
// restarted with the co-reader gone for good, it drops what it lost. Every crash point from the
// report on is tried: once a crash point leaves the leaver able to forget, every later one does,
// and some crash point falls after the report's step and before the forget.
#[test]
fn a_co_readers_report_survives_a_restart_spec_sync_5() {
    let (mut between, mut cleared_before) = (false, false);
    for k in 0..64 {
        let faults = Faults::new();
        let (mut net, a, b, _, _) = left_while_apart(&faults);
        // the crash plan starts when `a` sends its first Applied to `b`
        let armed = std::rc::Rc::new(std::cell::Cell::new(false));
        let arm = armed.clone();
        let plan = faults.clone();
        net.tamper_link = Some((a, b));
        net.tamper = Some(Box::new(move |m| {
            if matches!(m, osis_proto::Message::Applied { .. }) && !arm.replace(true) {
                plan.at(k, Fault::Crash);
            }
            None
        }));
        net.set_online(a, true);
        net.advance(60_000);
        if !faults.crashed() {
            assert!(armed.get() && cleared_before, "a reported, and the run reached the forget");
            break;
        }
        net.tamper = None;
        net.set_online(a, false);
        net.set_online(b, false);
        faults.revive();
        net.restart(b, 30 + k);
        net.set_online(b, true);
        let unforgotten = !net.engine(b).lost_leaving().unwrap().actors.is_empty();
        net.advance(60_000);
        let cleared = !leaving(&mut net, b);
        assert!(cleared || !cleared_before, "crash at write {k}: still leaving though an earlier crash point was not");
        cleared_before |= cleared;
        between |= unforgotten && cleared;
    }
    assert!(between, "some crash point fell between the report and the forget");
}

// spec/sync.md §5 (Placed: only a co-reader sharing the label), §10: a peer that does not read
// the label reports nothing for it, though it asks to join it and reports what it is served.
#[test]
fn a_strangers_report_counts_for_nothing_spec_sync_5() {
    let (mut net, a, b, _, l) = left_while_apart(&Faults::new());
    let c = net.node(3, &[]);
    reach_ed(&mut net, c);
    let other = net.group_seeded(c, &[(b, Role::Write)], vec![], 12);
    net.run();
    net.tamper_link = Some((c, b));
    net.tamper = Some(Box::new(move |m| match m {
        osis_proto::Message::Pull(p) if !p.joins.iter().any(|(x, _)| *x == l) => {
            let mut p = (**p).clone();
            p.joins.push((l, None));
            Some(osis_proto::Message::Pull(Box::new(p)))
        }
        _ => None,
    }));
    net.item(c, other, other, "pushes to report");
    net.advance(60_000);
    assert!(net.peer_sent(c, 41) > 0, "the stranger pulls the leaver");
    assert!(leaving(&mut net, b), "the stranger's reports place nothing");
    net.tamper = None;
    net.set_online(a, true);
    net.advance(60_000);
    assert!(!leaving(&mut net, b), "the co-reader's do");
}

/// Under `a`'s group `g` with no host: `b` writes `g` until an hour from now, `c` reads it (`a`
/// and `c` dialable). `b` wrote item `t` while `a` and `c` were offline; the `until` has passed.
fn timed_while_apart() -> (Net, [usize; 3], Tid, Tid) {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, c);
    let g = net.group_seeded(a, &[(b, Role::Write), (c, Role::Read)], vec![], 13);
    let until = osis_base::WallMs(net.now() + 3_600_000);
    let tb = net.tid(b);
    let edge = osis_schema::core_types::Edge { role: Role::Write, until: Some(until), invite: None, tied: None };
    let done = net.engine(a).grant(&g, &tb, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    net.set_online(a, false);
    net.set_online(c, false);
    let t = net.item(b, g, g, "unsent");
    net.advance(3_600_000 + 60_000);
    (net, [a, b, c], g, t)
}

fn holds(net: &mut Net, n: usize, g: Tid) -> bool {
    net.engine(n).epochs(&g).is_some_and(|e| e.read.held().next().is_some())
}

// spec/permissions.md §2 (an `until` passing, a label with no host heard out): the node keeps
// what it lost while its writes from before the `until` reached nobody; a co-reader takes them
// and reports them (spec/sync.md §5 Placed), the node reads its log to the end; then it drops.
#[test]
fn an_until_under_no_host_waits_for_a_co_reader_to_hold_its_writes_spec_perm_2() {
    let (mut net, [_, b, c], g, t) = timed_while_apart();
    assert!(holds(&mut net, b, g), "its write reached nobody: kept");
    net.set_online(c, true);
    net.advance(60_000);
    assert_eq!(net.read(c, t), Some(s("unsent")), "the co-reader took the write");
    assert!(!holds(&mut net, b, g), "reported: dropped");
}

// spec/permissions.md §2: a renewal held before the label was heard out keeps the role.
#[test]
fn an_until_under_no_host_kept_by_a_renewal_spec_perm_2() {
    let (mut net, [a, b, c], g, t) = timed_while_apart();
    let tb = net.tid(b);
    net.grant(a, g, tb, Role::Write);
    net.pair(a, b);
    net.advance(60_000);
    net.set_online(c, true);
    net.advance(60_000);
    assert!(holds(&mut net, b, g), "renewed: kept");
    assert_eq!(net.read(b, t), Some(s("unsent")));
    assert_eq!(net.read(c, t), Some(s("unsent")));
}

// spec/permissions.md §2: a co-reader that judges the node departed (here the admin, which
// finalizes the ended grant on its first pass) refuses the label, as a host refusing it does:
// the node drops though that co-reader never took its write.
#[test]
fn an_until_under_no_host_refused_by_a_co_reader_drops_spec_perm_2() {
    let (mut net, [a, b, _], g, t) = timed_while_apart();
    net.set_online(a, true);
    net.advance(60_000);
    assert_eq!(net.read(a, t), None, "the finalizing co-reader took nothing");
    assert!(!holds(&mut net, b, g), "refused: dropped");
}

// spec/permissions.md §2: with no co-reader reachable, it drops `LOST_HEARD_WAIT_MS` after it
// found the role gone.
#[test]
fn an_until_under_no_host_with_no_co_reader_drops_at_the_wait_spec_perm_2() {
    let (mut net, [_, b, _], g, _) = timed_while_apart();
    net.advance(osis_node::rotation::LOST_HEARD_WAIT_MS - 3_600_000);
    assert!(holds(&mut net, b, g), "before the wait: kept");
    net.advance(3_600_000);
    assert!(!holds(&mut net, b, g), "the wait ended: dropped");
}
