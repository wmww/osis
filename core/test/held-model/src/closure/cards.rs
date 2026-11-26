//! Cards over time (spec/sync-inbox.md §1 Card; spec/permissions.md §5.2 `card.0`), a greenfield
//! model: A's cards on several host things, A's `keys.0` written (a rotation, or an admin moving
//! A's inbox, which is a field of it), A's nodes rewriting the cards they may write as they sync
//! the hosts. Properties and hand worlds in tests/it/spec_cards.rs; findings in
//! notes/public-and-cards-brief.md (Models).
//!
//! A card is the version of A's `keys.0` it carries. A node of A holds A's newest keys once they
//! are written (it syncs A); it may write some hosts along a path through A (a card it writes there
//! is valid) and others only along other paths (a card written there is invalid: its entry keyed
//! by A needs A among the path's members). Sync is reduced to passes: a node reads a host's valid
//! card and applies the rewrite rule there.
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// A node that may write the host along a path through A writes A's card there again when it
    /// holds keys newer than the card carries.
    Newest,
    /// `Newest`, by any node that may write the host, along A or not (control: its writes off a
    /// path through A are invalid and change nothing; nodes keep rewriting).
    AnyWriter,
}

#[derive(Clone, Debug)]
pub struct World {
    pub nodes: usize,
    /// Per host, per node: 2 may write it along a path through A, 1 along another path only, 0 not.
    pub may: Vec<Vec<u8>>,
    /// Steps: `Keys` (A's `keys.0` written: a rotation or an inbox move; every node of A holds
    /// it), `Sync` (a round of passes).
    pub steps: Vec<Step>,
}

#[derive(Clone, Copy, Debug)]
pub enum Step {
    Keys,
    /// A round of passes: each host, then each node, in order.
    Sync,
}

#[derive(Clone, Debug)]
pub struct Run {
    /// Per host, the keys version its card carries.
    pub cards: Vec<u32>,
    /// Card writes judged invalid (written off a path through A).
    pub invalid: usize,
    /// Rewrites made by the passes after the last step.
    pub rewrites: usize,
    pub keys: u32,
}

impl World {
    /// Runs the steps, then rounds of passes until nothing changes (at most `cap`).
    pub fn run(&self, rule: Rule, cap: usize) -> Run {
        let hosts = self.may.len();
        let mut cards = vec![0u32; hosts];
        let mut keys = vec![0u32; self.nodes];
        let mut top = 0u32;
        let (mut invalid, mut rewrites) = (0, 0);
        // a round's rewrites, and whether any node learned something
        let round = |cards: &mut Vec<u32>, keys: &mut Vec<u32>, invalid: &mut usize| -> (usize, bool) {
            let (mut n, mut learned) = (0, false);
            for h in 0..hosts {
                for v in 0..self.nodes {
                    let may = self.may[h][v];
                    if may == 0 {
                        continue;
                    }
                    if cards[h] > keys[v] {
                        keys[v] = cards[h];
                        learned = true;
                    }
                    if keys[v] > cards[h] && (may == 2 || rule == Rule::AnyWriter) {
                        n += 1;
                        match may {
                            2 => cards[h] = keys[v],
                            _ => *invalid += 1,
                        }
                    }
                }
            }
            (n, learned)
        };
        for &s in &self.steps {
            match s {
                Step::Keys => {
                    top += 1;
                    keys.iter_mut().for_each(|k| *k = top);
                }
                Step::Sync => {
                    round(&mut cards, &mut keys, &mut invalid);
                }
            }
        }
        for _ in 0..cap {
            let (n, learned) = round(&mut cards, &mut keys, &mut invalid);
            rewrites += n;
            if n == 0 && !learned {
                break;
            }
        }
        Run { cards, invalid, rewrites, keys: top }
    }

    /// The hosts some node may write along a path through A (a card on any other host stays as
    /// written: nobody may rewrite it).
    pub fn live_hosts(&self) -> BTreeSet<usize> {
        (0..self.may.len()).filter(|&h| self.may[h].contains(&2)).collect()
    }

    /// `converge`: every host some node may write through A ends with A's newest keys (its inbox
    /// among them); `valid`: no card write is invalid; `quiet`: passes stop.
    pub fn breaks(&self, rule: Rule) -> (bool, bool, bool) {
        let cap = 4 * (self.may.len() + 2);
        let r = self.run(rule, cap);
        let converge = self.live_hosts().iter().any(|&h| r.cards[h] != r.keys);
        (converge, r.invalid > 0, r.rewrites >= cap)
    }
}

/// A random world from `seed`: 2-3 nodes, 2-4 hosts, up to 7 steps. Every node syncs A, so holds
/// its newest keys once written.
pub fn random(seed: u64) -> World {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = |m: usize| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        (s % m as u64) as usize
    };
    let nodes = 2 + next(2);
    let hosts = 2 + next(3);
    let may: Vec<Vec<u8>> = (0..hosts).map(|_| (0..nodes).map(|_| next(3) as u8).collect()).collect();
    let steps = (0..next(8)).map(|_| if next(2) == 0 { Step::Keys } else { Step::Sync }).collect();
    World { nodes, may, steps }
}
