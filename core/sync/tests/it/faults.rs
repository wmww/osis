//! The harness's faults (notes/sync-test-harness.md, The seam): content-blind network faults
//! (lost, arrived-then-reset, held-back sends), clock skew per node, device faults with restart in place,
//! hostile peers as lies over an honest node's frames, all replayable from the seed and the
//! script. What a fault does to sync is the simulations' (sims) and the differential's
//! (convergence); these check the faults themselves on what runs today: connections, Hello,
//! proofs and pings between world nodes.

use crate::harness::history::Gives;
use crate::harness::lies::Lie;
use crate::harness::{DiskFault, Loss, Seen, Step, World, fixture, play, two_nodes};
use osis_base::{Ak, Value, WallMs};
use osis_engine::Mutation;
use osis_sync::session::STALL_TIMEOUT_MS;
use osis_sync::{ConnId, Out};

/// Two bare nodes, quiet, no connection.
fn bare_pair() -> World {
    fixture("faults_bare_pair", || {
        let mut w = World::new(0);
        w.add_bare_node();
        w.add_bare_node();
        w.run();
        w
    })
}

/// Node 0 dials node 1 on conn 1.
fn dial(w: &mut World) {
    let to = w.address(1);
    w.apply_as(0, vec![Out::Dial(ConnId(1), to)]);
}

/// Bytes delivered to `node` in order, per connection.
fn bytes_to(seen: &[Seen], node: usize) -> Vec<(ConnId, usize)> {
    seen.iter().filter_map(|s| match s {
        Seen::Bytes { node: n, conn, len } if *n == node => Some((*conn, *len)),
        _ => None,
    }).collect()
}

fn closed(seen: &[Seen], node: usize) -> bool {
    seen.iter().any(|s| matches!(s, Seen::Closed { node: n, .. } if *n == node))
}

// spec: none (test harness): with every send held back up to 5 s, a connection's Hello, proofs
// and pings still arrive whole and in order: it goes quiet as on a clean network, closing (or
// not) as there, and each end receives every byte a clean network carries.
#[test]
fn held_back_sends_keep_each_connection_in_order() {
    let clean = {
        let mut w = bare_pair();
        w.trace = true;
        dial(&mut w);
        w.run();
        w.seen.clone()
    };
    let mut w = bare_pair();
    w.trace = true;
    w.net.loss = Loss { delay: 1000, delay_ms: 5_000, ..Loss::NONE };
    dial(&mut w);
    w.run();
    assert!(w.net.faulted.2 > 0, "sends were held back");
    for n in [0, 1] {
        assert_eq!(closed(&w.seen, n), closed(&clean, n), "node {n} closes as on a clean network: {:?}", w.seen);
    }
    for n in [0, 1] {
        assert_eq!(bytes_to(&w.seen, n), bytes_to(&clean, n), "node {n} received what a clean network carries, in its order");
    }
}

// spec: none (test harness): sends held back at random still arrive in the order sent on their
// connection (each waits behind the one before it).
#[test]
fn held_back_sends_never_reorder_within_a_connection() {
    let mut w = bare_pair();
    dial(&mut w);
    w.flush();
    w.trace = true;
    w.net.loss = Loss { delay: 500, delay_ms: 5_000, ..Loss::NONE };
    let sends: Vec<Out> = (1..=40).map(|n| Out::Send(ConnId(1), vec![0xff; n])).collect();
    w.apply_as(0, sends);
    w.run();
    assert!(w.net.faulted.2 > 0, "sends were held back");
    let got: Vec<usize> = bytes_to(&w.seen, 1).iter().map(|x| x.1).filter(|n| *n <= 40).collect();
    assert_eq!(got, (1..=40).collect::<Vec<_>>());
}

// spec: none (test harness): a lost send resets its connection (an ordered stream never delivers
// past a hole): both ends are told it closed, and nothing after it arrives.
#[test]
fn a_lost_send_resets_its_connection() {
    let mut w = bare_pair();
    w.trace = true;
    w.net.loss = Loss { drop: 1000, ..Loss::NONE };
    dial(&mut w);
    w.run();
    assert!(w.net.faulted.0 >= 1);
    assert!(closed(&w.seen, 0) && closed(&w.seen, 1), "both ends told: {:?}", w.seen);
    assert!(bytes_to(&w.seen, 0).is_empty() && bytes_to(&w.seen, 1).is_empty(), "no byte arrives");
}

// spec: none (test harness): a repeated send arrives, then its connection resets (both ends
// told), so its sender sends it again only on a later connection: nothing arrives twice on one
// connection.
#[test]
fn a_repeated_send_arrives_then_its_connection_resets() {
    let mut w = bare_pair();
    w.trace = true;
    w.net.loss = Loss { dup: 1000, ..Loss::NONE };
    dial(&mut w);
    w.run();
    assert!(w.net.faulted.1 >= 1);
    let got = bytes_to(&w.seen, 1);
    assert_eq!(got.len(), 1, "the dialer's Hello arrives once: {got:?}");
    assert!(closed(&w.seen, 0) && closed(&w.seen, 1), "both ends told: {:?}", w.seen);
    let at = |n: usize| w.seen.iter().position(|s| matches!(s, Seen::Closed { node, .. } if *node == n));
    let bytes_at = w.seen.iter().position(|s| matches!(s, Seen::Bytes { node: 1, .. }));
    assert!(bytes_at < at(1), "it arrives before the close: {:?}", w.seen);
}

// spec: none (test harness): faults are drawn from the world's seed in send order: one seed and
// one script replay the same deliveries, faults included.
#[test]
fn faults_replay_from_the_seed_and_script() {
    let script = [Step::Lossy(Loss { drop: 50, dup: 100, delay: 300, delay_ms: 2_000 }), Step::Run];
    let trace = || {
        let mut w = World::new(7);
        w.add_bare_node();
        w.add_bare_node();
        w.add_bare_node();
        w.trace = true;
        play(&mut w, &script, "faults::faults_replay_from_the_seed_and_script".into());
        for to in [1, 2] {
            let a = w.address(to);
            w.apply_as(0, vec![Out::Dial(ConnId(to as u64), a)]);
        }
        w.run();
        (w.seen.clone(), w.net.faulted, w.now())
    };
    let a = trace();
    assert!(a.1 != (0, 0, 0), "some send faulted: {:?}", a.1);
    assert_eq!(a, trace());
}

// spec: none (test harness): a node's clock runs by its skew: it is ticked in its own time at the
// wake it asked in its own time, which the world reaches that much earlier or later.
#[test]
fn a_skewed_node_ticks_in_its_own_time() {
    for skew in [90_000i64, -90_000] {
        let mut w = two_nodes();
        w.skew(1, skew);
        assert_eq!(w.node_now(1).0 as i64, w.now().0 as i64 + skew);
        let at = WallMs(w.node_now(1).0 + 5_000);
        let start = w.now();
        w.trace = true;
        w.apply_as(1, vec![Out::Wake(at)]);
        w.advance(5_000);
        assert!(w.seen.contains(&Seen::Tick { node: 1, at }), "skew {skew}: {:?}", w.seen);
        assert_eq!(w.now(), WallMs(start.0 + 5_000));
    }
}

fn set(w: &mut World, i: usize, v: &str) -> osis_engine::Result<()> {
    let me = w.node(i).account.expect("account");
    let ak = Ak::new("u:v.0").expect("ak");
    w.write(i, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        m.set(t, &ak, &Value::Str(v.into()))?;
        e.commit(m).map(|_| ())
    })
}

// spec: none (test harness): a device fault fails the planned durable write alone; later writes
// work.
#[test]
fn a_failed_write_fails_once() {
    let mut w = two_nodes();
    w.disk_fault(0, 0, DiskFault::Fail);
    assert!(set(&mut w, 0, "a").is_err(), "the planned write fails");
    assert!(set(&mut w, 0, "b").is_ok(), "the next one works");
    assert_eq!(w.crashes, 0);
}

// spec: none (test harness): a crash at a durable write is a power loss there: the node restarts
// in place over its disks (its account read again), its peers are told its connections closed,
// and it writes again.
#[test]
fn a_crash_restarts_the_node_in_place() {
    let mut w = two_nodes();
    let to = w.address(1);
    w.apply_as(0, vec![Out::Dial(ConnId(1), to)]);
    w.flush();
    let account = w.node(1).account;
    w.trace = true;
    w.disk_fault(1, 0, DiskFault::Crash);
    assert!(set(&mut w, 1, "a").is_err());
    w.flush();
    assert_eq!(w.crashes, 1);
    assert!(w.online(1));
    assert_eq!(w.engine(1).account_tid(), account, "reopened over its disks");
    assert!(closed(&w.seen, 0), "its peer is told: {:?}", w.seen);
    assert!(set(&mut w, 1, "b").is_ok());
}

// spec: none (test harness): a node holding every request open (a lie dropping its replies) is
// closed by its peer at the stall bound, as a deaf one is.
#[test]
fn a_peer_holding_requests_open_is_closed_at_the_stall() {
    let mut w = bare_pair();
    w.lie(1, Some(Lie::Hold));
    w.trace = true;
    dial(&mut w);
    w.flush();
    assert!(!bytes_to(&w.seen, 0).is_empty(), "its Hello still goes");
    w.advance(STALL_TIMEOUT_MS - 1);
    assert!(!closed(&w.seen, 1), "kept until the bound");
    w.advance(1);
    assert!(closed(&w.seen, 1), "closed at the bound");
}

// spec: none (test harness): a lie re-encodes through the real encoder: frames it does not
// change arrive as the honest node sent them, so a connection with no stream to lie in runs as
// an honest one, delivery for delivery.
#[test]
fn a_lie_leaves_other_frames_as_sent() {
    let run = |lie: Option<Lie>| {
        let mut w = bare_pair();
        w.lie(1, lie);
        w.trace = true;
        dial(&mut w);
        w.run();
        w.seen.clone()
    };
    let honest = run(None);
    for lie in [Lie::Withhold, Lie::Forget, Lie::Full, Lie::RefuseRoles] {
        assert_eq!(run(Some(lie)), honest, "{lie:?}");
    }
}

// spec: none (test harness): shrinking reaches a fixpoint: every simpler form of a step is
// smaller by a measure that cannot fall forever.
#[test]
fn simpler_steps_are_smaller() {
    let size = |s: &Step| -> u128 {
        match s {
            Step::Advance(ms) => u128::from(*ms),
            Step::Lossy(l) => u128::from(l.drop) + u128::from(l.dup) + u128::from(l.delay) + u128::from(l.delay_ms),
            Step::Skew(_, ms) => u128::from(ms.unsigned_abs()),
            Step::Disk(_, n, f) => u128::from(*n) * 3 + *f as u128,
            Step::Grant(_, _, _, g) => *g as u128,
            _ => 0,
        }
    };
    let steps = [
        Step::Advance(1 << 40),
        Step::Lossy(Loss { drop: 1000, dup: 7, delay: 1000, delay_ms: 1 << 30 }),
        Step::Skew(0, -(1 << 40)),
        Step::Disk(0, 1 << 30, DiskFault::Crash),
        Step::Disk(0, 0, DiskFault::Unsynced),
        Step::Grant(0, 0, 1, Gives::Writes),
        Step::Run,
    ];
    for s in steps {
        for x in s.simpler() {
            assert!(size(&x) < size(&s), "{x:?} is no smaller than {s:?}");
        }
    }
}
