//! The harness itself: worlds run to quiet, and every output a node makes reaches the network.

use crate::harness::{Seen, World, two_nodes};
use osis_base::WallMs;
use osis_label::Address;
use osis_sync::{ConnId, Links, Out, apply};

// spec: none (test harness): a world of two nodes, each with its account, runs to quiet: nothing
// in flight, no wake within the horizon.
#[test]
fn two_nodes_run_to_quiet() {
    let mut w = two_nodes();
    w.run();
    assert_eq!(w.len(), 2);
    assert!(w.node(0).account.is_some() && w.node(1).account.is_some());
    assert_ne!(w.node(0).account, w.node(1).account);
    assert!(w.deliveries < 10, "an idle world does almost nothing: {} deliveries", w.deliveries);
}

// spec: none (test harness): each kind of output is carried out: a dial comes up at both ends (or
// down at the dialer for a key nobody listens with), bytes reach the peer and the sender learns the
// transport took them, a close reaches the peer, a wake ticks the node at its time.
#[test]
fn every_output_reaches_the_network() {
    let mut w = World::new(0);
    w.add_bare_node();
    w.add_bare_node();
    w.trace = true;
    let to = w.address(1);
    let nobody = Address { url: to.url.clone(), key: [9; 32] };
    let c = ConnId(1);
    w.apply_as(0, vec![Out::Dial(c, to), Out::Send(c, vec![1, 2, 3]), Out::Close(c), Out::Dial(ConnId(2), nobody)]);
    w.flush();
    // rank 1: node 1's address lists its public address, a direct route
    let acc = ConnId(ConnId::ACCEPTED | 1);
    let want = [
        Seen::Up { node: 0, conn: c, dialed: true, rank: 1 },
        Seen::Up { node: 1, conn: acc, dialed: false, rank: 1 },
        Seen::Bytes { node: 1, conn: acc, len: 3, digest: osis_base::hash::hash(&[1, 2, 3])[..8].try_into().unwrap() },
        Seen::Taken { node: 0, conn: c, bytes: 3 },
        Seen::Down { node: 0, conn: ConnId(2) },
        Seen::Closed { node: 1, conn: acc },
    ];
    assert_eq!(w.seen, want);
    w.run();
    w.seen.clear();
    let at = WallMs(w.now().0 + 5_000);
    w.apply_as(0, vec![Out::Wake(at)]);
    w.run();
    assert_eq!(w.seen, [Seen::Tick { node: 0, at }]);
}

#[derive(Default)]
struct Record(Vec<String>);

impl Links for Record {
    fn dial(&mut self, conn: ConnId, _: &Address) {
        self.0.push(format!("dial {}", conn.0));
    }
    fn send(&mut self, conn: ConnId, _: &[u8]) {
        self.0.push(format!("send {}", conn.0));
    }
    fn close(&mut self, conn: ConnId) {
        self.0.push(format!("close {}", conn.0));
    }
    fn wake(&mut self, at: WallMs) {
        self.0.push(format!("wake {}", at.0));
    }
}

// spec: none (sync's one place of outputs, notes/sync-driver.md, The step): sends and dials leave
// in the order made, closes after them, then one wake, the earliest.
#[test]
fn apply_orders_closes_and_the_wake_last() {
    let a = Address { url: String::new(), key: [0; 32] };
    let mut r = Record::default();
    apply(vec![Out::Wake(WallMs(9)), Out::Close(ConnId(1)), Out::Send(ConnId(2), vec![]), Out::Wake(WallMs(4)), Out::Dial(ConnId(3), a), Out::Send(ConnId(1), vec![])], &mut r);
    assert_eq!(r.0, ["send 2", "dial 3", "send 1", "close 1", "wake 4"]);
}

// spec: none (test harness): a script plays on a fixture copy; partitions, power loss (the node
// reopens over its disks) and time leave the world quiet and its nodes as they were.
#[test]
fn a_script_plays_on_a_fixture() {
    use crate::harness::{Step, play};
    let mut w = two_nodes();
    let accounts = (w.node(0).account, w.node(1).account);
    let steps = [Step::Partition(0, 1), Step::Run, Step::PowerOff(1), Step::Advance(60_000), Step::PowerOn(1), Step::Heal, Step::Run];
    play(&mut w, &steps, "world::a_script_plays_on_a_fixture".into());
    assert_eq!((w.node(0).account, w.node(1).account), accounts);
    assert_eq!(w.engine(1).account_tid(), accounts.1, "the reopened node reads its own account");
}

// spec: none (test harness): a shrink finds a planted failure among real steps in few candidates
// (counted, not timed): node 1 skewed and left off, among 20 steps that play on a fixture copy.
#[test]
fn a_shrink_finds_a_planted_failure_in_few_candidates() {
    use crate::harness::{Step::*, play};
    let steps = vec![Advance(1_000), Run, Skew(0, 300), Cut(0, 1), Skew(1, 4_000), Run, PowerOff(1), Advance(5_000), PowerOn(1), Heal, Skew(0, 0), Run, Partition(0, 1), Advance(2_000), Run, Heal, PowerOff(1), Advance(500), Skew(0, -200), Run];
    let fails = |h: &[crate::harness::Step]| {
        let mut w = two_nodes();
        let _script = play(&mut w, h, String::new());
        w.node_now(1) != w.now() && !w.online(1)
    };
    assert!(fails(&steps));
    let s = osis_base::testenv::shrink(steps, osis_base::testenv::SHRINK_CANDIDATES, fails, crate::harness::Step::simpler, |_: &[crate::harness::Step], _| {});
    assert_eq!(s.steps, vec![Skew(1, 1), PowerOff(1)]);
    assert!(s.candidates < 60, "{} candidates", s.candidates);
}

// spec: none (test harness): a shrink candidate past its delivery cap stops and counts as not
// failing (`capped`); under the cap it runs as ever, and a world's own lower cap still panics as
// a storm.
#[test]
fn a_shrink_candidate_past_its_cap_does_not_fail() {
    use crate::harness::{Step::*, capped, contacts, play};
    let steps = [PowerOff(1), PowerOn(1), Run];
    let run = || {
        let mut w = contacts();
        let _script = play(&mut w, &steps, String::new());
        w.deliveries
    };
    let made = capped(u64::MAX, run).expect("uncapped");
    assert!(made > 3, "{made} deliveries");
    assert_eq!(capped(3, run), None);
    assert_eq!(capped(made, run), Some(made));
    let storm = std::panic::catch_unwind(|| {
        capped(made, || {
            let mut w = contacts();
            w.cap = 2;
            let _ = play(&mut w, &steps, String::new());
        })
    });
    let e = storm.expect_err("the world's own cap");
    assert!(e.downcast_ref::<String>().is_some_and(|m| m.contains("storm")));
}
