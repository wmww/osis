#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase B (sync engines and hosts engine to engine): what the sweeps (every scenario at 15 seeds at the
//! gate, 150 periodic) do not check: that a scenario's faults happen, replay exactness, and examples.
//! A failure prints its seed and the `osis_sim::replay` call that reproduces it.

use osis_sim::{Report, replay};

fn ok(name: &str, seed: u64) -> Report {
    let r = replay(name, seed).unwrap_or_else(|f| panic!("{f}"));
    eprintln!("{name} {seed}: {r:?}");
    r
}

// spec/sync.md §2, §6; spec/commits.md §4: two nodes of one account through one host
// under cut, delayed, reordered and duplicated messages and crashes mid-write.
#[test]
fn two_nodes_host() {
    let r = ok("two_nodes_host", 1);
    assert!(r.writes > 5 && r.crashes > 0 && r.dropped > 0 && r.held_checked > 0, "{r:?}");
}

// spec/sync.md §5 (replication, push only), §6; spec/sync.md §3 (grants by inbox): three
// accounts share a group through two replicating hosts with host crashes and partitions.
#[test]
#[ignore = "by hand"]
fn three_accounts_two_hosts() {
    let r = ok("three_accounts_two_hosts", 1);
    assert!(r.writes > 10 && r.held_checked > 0 && r.partitions > 0, "{r:?}");
}

// spec: none (replay): the same (scenario, seed) gives the same run, digest included.
#[test]
fn replay_is_exact() {
    assert_eq!(ok("two_nodes_host", 2), ok("two_nodes_host", 2));
}

// notes/ephemeral.md, spec/sync.md §9: ephemeral (expiring ones included) and signal writes on a
// window and a durable item under faults; holders converge, a refreshed cursor stays up while its
// author is there and goes by its expiry after, signals once.
#[test]
fn ephemeral() {
    let r = ok("ephemeral", 1);
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

    let mut d = Dice::new(1);
    let mut s = sim("across_labels", 1, Default::default());
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
