#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A leaver's self-removal placed by a co-reader's report (spec/sync.md §5 Placed, §10 Reports):
//! with no host, the removal counts as placed once a co-reader that reads the label reported
//! (Applied) a position past where the leaver's log first held it; the report is kept across a
//! restart; a peer that does not read the label reports nothing for it.

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
