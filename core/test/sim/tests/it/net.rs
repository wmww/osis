#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase B (sync engines and hosts engine to engine): what the sweeps (every scenario at 15 seeds at the
//! gate, 150 periodic) do not check: that a scenario's faults happen, replay exactness, and examples.
//! A failure prints its seeds and the `osis_sim::replay` call that reproduces it. Runs use setup 0.

use osis_sim::{Report, replay};

fn ok(name: &str, seed: u64) -> Report {
    let r = replay(name, 0, seed).unwrap_or_else(|f| panic!("{f}"));
    eprintln!("{name} {seed}: {r:?}");
    r
}

// spec/sync.md §2, §6; spec/commits.md §4: two nodes of one account through one host
// under cut, delayed, reordered and duplicated messages and crashes mid-write.
#[test]
fn two_nodes_host() {
    let r = ok("two_nodes_host", 0);
    assert!(r.writes > 5 && r.crashes > 0 && r.held_checked > 0, "{r:?}");
    // every link cut in every window: the run surely loses messages on the way
    let faults = osis_sim::net::LinkFaults { cut_pct: 100, ..osis_sim::net::scenarios::lossy() };
    let r = osis_sim::net::scenarios::two_nodes_host_under(osis_sim::Seeds { setup: 0, seed: 0 }, faults).unwrap_or_else(|f| panic!("{f}"));
    assert!(r.writes > 5 && r.crashes > 0 && r.dropped > 0 && r.held_checked > 0, "{r:?}");
}

// spec/sync.md §5, §6; spec/sync.md §3 (grants by inbox): three accounts share a group through
// two hosts, joined only by the admin reaching both, with host crashes and partitions.
#[test]
#[ignore = "by hand"]
fn three_accounts_two_hosts() {
    let r = ok("three_accounts_two_hosts", 0);
    assert!(r.writes > 10 && r.held_checked > 0 && r.partitions > 0, "{r:?}");
}

// spec: none (replay): the same (scenario, setup, seed) gives the same run, digest included;
// seeds over one setup run apart (the seed drives everything after it), and a run of another
// seed between two runs of one seed leaves the shared setup as it was.
#[test]
fn replay_is_exact() {
    let r = ok("two_nodes_host", 0);
    assert_ne!(r.digest, ok("two_nodes_host", 1).digest);
    assert_eq!(r, ok("two_nodes_host", 0));
}

// notes/ephemeral.md, spec/sync.md §9: ephemeral (expiring ones included) and signal writes on a
// window and a durable item under faults; holders converge, a refreshed cursor stays up while its
// author is there and goes by its expiry after, signals once.
#[test]
fn ephemeral() {
    let r = ok("ephemeral", 0);
    assert!(r.writes > 20 && r.crashes > 0, "{r:?}");
}

// spec/commits.md §4, spec/sync.md §3, §6: a reader of two labels, one host out of reach, applies a
// commit across them whole from the other label's blob, across a restart, and stays so once that
// host is back.
#[test]
fn commit_across_labels_applies_from_one_label_across_restart_spec_commits_4() {
    use osis_base::{Role, Value};
    use osis_node::Mutation;
    use osis_sim::dice::Dice;
    use osis_sim::net::Party;
    use osis_sim::net::scenarios::{clock, persons, shared_group, sim};
    use osis_sim::workload::REG;

    let mut d = Dice::new(0);
    let mut s = sim("across_labels", 0, Default::default());
    let (s0, s1) = (s.add_host().unwrap(), s.add_host().unwrap());
    let a = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    let r = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    // a third reader on one group only: different readers, so a body per label
    let b = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    let [pa, pr, pb] = persons(&mut s, [a, r, b], [s0, s0, s0]).unwrap();
    let g0 = shared_group(&mut s, a, pa, &[s0], &[(pr, Role::Read)]).unwrap();
    let g1 = shared_group(&mut s, a, pa, &[s1], &[(pr, Role::Read), (pb, Role::Read)]).unwrap();
    let (i0, i1) = (s.item(a, g0).unwrap(), s.item(a, g1).unwrap());
    s.quiet(40).unwrap();

    s.partition(Party::N(r), Party::S(s1));
    let word = Value::Str("both".into());
    let mut m = Mutation::new();
    m.set(i0, &REG, &word).unwrap();
    m.set(i1, &REG, &word).unwrap();
    let id = s.commit(a, m).unwrap().unwrap();
    // one blob per commit (spec/sync.md §3): the blob under g0's label carries both parts, and
    // r, reading both groups, applies the commit whole from that label alone, across a restart
    for restart in [false, true] {
        if restart {
            s.restart_node(r).unwrap();
        }
        s.advance(61_000).unwrap();
        s.settle().unwrap();
        let e = s.engine(r).unwrap();
        assert!(!e.pending().iter().any(|p| p.0 == id), "restart {restart}: nothing waits: {:?}", e.pending());
        assert_eq!(e.commit_parts_missing().get(&id).map(|g| g.len()), Some(0), "restart {restart}: whole");
        assert_eq!(e.get_typed(&i0, &REG).unwrap(), Some(word.clone()), "restart {restart}: both parts read");
        assert_eq!(e.get_typed(&i1, &REG).unwrap(), Some(word.clone()), "restart {restart}: both parts read");
    }

    s.heal(Party::N(r), Party::S(s1));
    s.run_until_quiescent(60).unwrap();
    let e = s.engine(r).unwrap();
    assert_eq!(e.commit_parts_missing().get(&id).map(|g| g.len()), Some(0), "whole");
    assert_eq!(e.get_typed(&i0, &REG).unwrap(), Some(word.clone()));
    assert_eq!(e.get_typed(&i1, &REG).unwrap(), Some(word.clone()));
    s.finish().unwrap();
}

// harness (power loss): a host whose store crashed mid-write is down from that call on, whichever
// part of it made the write (its hub, or its node sync storing what it pulled from a node's
// stream); never left up on a dead store (its connections stall) nor revived in place by
// quiescence. The writer comes back from a partition with a commit only it holds; each round the
// host crashes at the next of the writes that follow, until they run out.
#[test]
fn host_store_crash_takes_host_down() {
    use osis_base::{Role, Value};
    use osis_node::Mutation;
    use osis_sim::dice::Dice;
    use osis_sim::net::Party;
    use osis_sim::net::scenarios::{clock, persons, shared_group, sim};
    use osis_sim::workload::REG;
    use osis_store::Fault;

    let mut d = Dice::new(0);
    let mut s = sim("host_store_crash", 0, Default::default());
    let (s0, s1) = (s.add_host().unwrap(), s.add_host().unwrap());
    let a = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    let w = s.add_node(&[s0], clock(&mut d)).unwrap();
    let c = s.add_node(&[s1], clock(&mut d)).unwrap();
    s.sever(Party::N(w), Party::S(s1));
    s.sever(Party::N(c), Party::S(s0));
    let [pa, pw, pc] = persons(&mut s, [a, w, c], [s0, s0, s1]).unwrap();
    let g = shared_group(&mut s, a, pa, &[s0, s1], &[(pw, Role::Write), (pc, Role::Read)]).unwrap();
    let i = s.item(w, g).unwrap();
    s.quiet(40).unwrap();
    let mut at = 0;
    loop {
        s.partition(Party::N(w), Party::S(s0));
        let mut m = Mutation::new();
        m.set(i, &REG, &Value::Str(format!("{at}"))).unwrap();
        s.commit(w, m).unwrap();
        s.settle().unwrap();
        s.hosts[s0].faults.at(at, Fault::Crash);
        s.heal(Party::N(w), Party::S(s0));
        for _ in 0..3 {
            s.advance(61_000).unwrap();
            s.settle().unwrap();
            let h = &s.hosts[s0];
            assert!(!(h.up && h.faults.crashed()), "crash at write {at}: host left up on a dead store");
        }
        if s.hosts[s0].up {
            break;
        }
        s.restart_host(s0).unwrap();
        at += 1;
        assert!(at < 32, "a host write per round, at least");
    }
    assert!(at > 0, "no planned crash reached");
    s.hosts[s0].faults.revive();
    s.run_until_quiescent(60).unwrap();
    s.finish().unwrap();
}
