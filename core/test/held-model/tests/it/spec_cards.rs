//! Cards over time (held_model::closure::cards; spec/sync-inbox.md §1 Card). Findings:
//! notes/public-and-cards-brief.md, Models.
use held_model::closure::cards::{random, Rule, Step, World};

// Two hosts both written by node 0 through A, host 1 also by node 1. Node 1 moves A's inbox on
// host 1 as A rotates; node 0 refreshes keys on host 0 before it reads host 1. With `since` kept
// by a keys rewrite, the move reaches host 0 and stays; restamped, node 0's refresh names the old
// inbox later than the move, and the move is undone everywhere.
#[test]
fn an_inbox_move_spreads_and_a_keys_refresh_does_not_undo_it() {
    let w = World { nodes: 2, may: vec![vec![2, 0], vec![2, 2]], steps: vec![Step::Move(1, 1), Step::Rotate(0)] };
    assert_eq!(w.run(Rule::Restamp, 16).cards[1].inbox, 0);
    let r = w.run(Rule::Newest, 16);
    assert!(r.cards.iter().all(|c| c.inbox == 1 && c.keys == 1));
    assert_eq!(w.breaks(Rule::Newest), (false, false, false));
    assert!(w.breaks(Rule::Restamp).0);
    // keys only: the move stays on host 1
    let r = w.run(Rule::KeysOnly, 16);
    assert_eq!((r.cards[0].inbox, r.cards[1].inbox), (0, 1));
}

// Control: a node that may write a host only along a path not through A writes A's card there
// invalid (spec/permissions.md §5.2): "may write C" in the rewrite rule must read "along a path
// through A".
#[test]
fn a_rewrite_off_a_path_through_a_is_invalid() {
    let w = World { nodes: 2, may: vec![vec![1, 2]], steps: vec![Step::Rotate(0)] };
    assert_eq!(w.breaks(Rule::Newest), (false, false, false));
    assert!(w.breaks(Rule::AnyWriter).1);
}

// Random worlds: the rule converges, writes only valid cards and stops; each control breaks its
// own property.
#[test]
fn cards_explore() {
    let rules = [Rule::Newest, Rule::Restamp, Rule::KeysOnly, Rule::AnyWriter];
    let mut found = [(0usize, 0usize, 0usize); 4];
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
    assert!(found[1].0 > 0, "restamp: converge");
    assert!(found[2].0 > 0, "keys only: converge");
    assert!(found[3].1 > 0 && found[3].2 > 0, "any writer: valid, quiet");
}
