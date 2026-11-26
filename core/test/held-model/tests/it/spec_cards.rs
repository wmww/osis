//! Cards over time (held_model::closure::cards; spec/sync-inbox.md §1 Card). Findings:
//! notes/public-and-cards-brief.md, Models.
use held_model::closure::cards::{random, Rule, Step, World};

// Two hosts both written by node 0 through A, host 1 also by node 1. A's keys are written twice
// (a rotation, then an inbox move), synced between: every card ends carrying the newest.
#[test]
fn a_keys_write_spreads_to_every_card() {
    let w = World { nodes: 2, may: vec![vec![2, 0], vec![2, 2]], steps: vec![Step::Keys, Step::Sync, Step::Keys] };
    let r = w.run(Rule::Newest, 16);
    assert!(r.cards.iter().all(|c| *c == 2));
    assert_eq!(w.breaks(Rule::Newest), (false, false, false));
}

// Control: a node that may write a host only along a path not through A writes A's card there
// invalid (spec/permissions.md §5.2): "may write C" in the rewrite rule must read "along a path
// through A".
#[test]
fn a_rewrite_off_a_path_through_a_is_invalid() {
    let w = World { nodes: 2, may: vec![vec![1, 2]], steps: vec![Step::Keys] };
    assert_eq!(w.breaks(Rule::Newest), (false, false, false));
    assert!(w.breaks(Rule::AnyWriter).1);
}

// Random worlds: the rule converges, writes only valid cards and stops; the control breaks its
// own properties.
#[test]
fn cards_explore() {
    let rules = [Rule::Newest, Rule::AnyWriter];
    let mut found = [(0usize, 0usize, 0usize); 2];
    for seed in 0..20_000 {
        let w = random(seed);
        for (i, &rule) in rules.iter().enumerate() {
            let (c, v, q) = w.breaks(rule);
            found[i].0 += c as usize;
            found[i].1 += v as usize;
            found[i].2 += q as usize;
        }
    }
    assert_eq!(found[0], (0, 0, 0), "newest");
    assert!(found[1].1 > 0 && found[1].2 > 0, "any writer: valid, quiet");
}
