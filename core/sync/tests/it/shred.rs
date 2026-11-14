//! Forensic deletion at a synced node (spec/requirements.md Deletion: forward secure; spec/commits.md
//! §5: dropping a body destroys every local copy): after a purge reaches a reader through sync, an
//! attacker holding its device (every row and blob its engine's and store's disks were given, the
//! keys its current store trees yield, its current read secrets; notes/test-security.md) recovers
//! nothing of the purged value, its store entry under S included.

use crate::metadata::{MARK_B, scenario_b, value_ak};
use osis_base::Value;
use osis_engine::Mutation;

fn recoverable(w: &mut crate::harness::World, i: usize, marker: &[u8]) -> bool {
    w.forensic(i).iter().any(|r| r.plain.windows(marker.len()).any(|x| x == marker))
}

// spec/commits.md §5 (Dropping a body: every local copy), spec/sync-judgement.md §2 (must-not-hold:
// its entries leave the own store): node 2's value is purged by node 0 (admin of t); once synced,
// neither node 2 (its author, a reader) nor node 0 yields it to an attacker holding its device,
// and no entry of the commit stays under S at node 1 (keeping S unread). Control: before the
// purge node 2's device yields it.
#[test]
#[ignore = "by hand: three forensic attacks on synced nodes, about 700 G instructions in debug"]
fn a_purge_leaves_nothing_recoverable_at_synced_nodes_spec_commits_5() {
    let (mut w, t, s, b) = scenario_b();
    assert!(recoverable(&mut w, 2, MARK_B.as_bytes()), "the attack finds live content");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("public".into())).unwrap();
        m.purge_commit(b, t, value_ak());
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(2).get(&t, &value_ak()).unwrap(), Some(Value::Str("public".into())));
    for i in [0, 2] {
        assert!(!recoverable(&mut w, i, MARK_B.as_bytes()), "node {i}: purged content recovered");
    }
    let left: Vec<_> = w.store(1).entries(&s).unwrap().into_iter().filter(|e| w.engine(0).blob_commit(&e.blob).ok().flatten() == Some(b)).collect();
    assert!(left.is_empty(), "an entry of the purged commit at node 1: {left:?}");
}

// spec/commits.md §5 (Dropping a body), spec/requirements.md Deletion (purge is prompt; forward
// secure): as above with node 2 away while node 0 purges: once back and synced, node 2 yields
// nothing of the value.
#[test]
#[ignore = "by hand: a forensic attack on a synced node, about 250 G instructions in debug"]
fn a_purge_reaching_a_node_that_was_away_leaves_nothing_recoverable_spec_commits_5() {
    let (mut w, t, _, b) = scenario_b();
    w.power_off(2);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("public".into())).unwrap();
        m.purge_commit(b, t, value_ak());
        e.commit(m).unwrap();
    });
    w.run();
    w.power_on(2);
    w.run();
    assert_eq!(w.engine(2).get(&t, &value_ak()).unwrap(), Some(Value::Str("public".into())));
    assert!(!recoverable(&mut w, 2, MARK_B.as_bytes()), "purged content recovered at node 2");
}
