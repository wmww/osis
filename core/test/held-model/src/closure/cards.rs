//! Cards over time (spec/sync-inbox.md §1 Card; spec/permissions.md §5.2 `card.0`), a greenfield
//! model: A's cards on several host things, A's `keys.0` rotating and its inbox moving, A's nodes
//! rewriting the cards they may write as they sync the hosts. Properties and hand worlds in
//! tests/it/spec_cards.rs; findings in notes/public-and-cards-brief.md (Models).
//!
//! A card is (keys version, inbox, since). A node of A holds A's newest keys once A rotates (it
//! syncs A); it may write some hosts
//! along a path through A (a card it writes there is valid) and others only along other paths (a
//! card written there is invalid: its entry keyed by A needs A among the path's members). A move
//! of A's inbox is a card written on one host naming the new inbox. Sync is reduced to passes:
//! a node reads a host's valid card and applies the rewrite rule there.
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card {
    pub keys: u32,
    pub inbox: u32,
    /// When the inbox was chosen: a move writes one above every `since` its writer holds; a
    /// rewrite for keys keeps the card's (under `Rule::Restamp`, the rewrite's own stamp).
    pub since: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// A node that may write the host along a path through A writes A's card there again when it
    /// holds keys newer than the card carries, or a card of A with a greater `since` (A's inbox at
    /// a node: the one the card of A with the greatest `since` it holds names).
    Newest,
    /// `Newest`, with `since` the stamp of the card's last write (control: a node refreshing keys
    /// before it sees a move writes the old inbox later, and the move is undone).
    Restamp,
    /// Keys only: a card is rewritten for newer keys, keeping the inbox it names (control: an
    /// inbox move reaches only the host it was written on).
    KeysOnly,
    /// `Newest`, by any node that may write the host, along A or not (control: its writes off a
    /// path through A are invalid and change nothing; nodes keep rewriting).
    AnyWriter,
}

#[derive(Clone, Debug)]
pub struct World {
    pub nodes: usize,
    /// Per host, per node: 2 may write it along a path through A, 1 along another path only, 0 not.
    pub may: Vec<Vec<u8>>,
    /// Steps: `Rotate(node)` (A rotates; the node holds the new keys), `Move(node, host)` (the node
    /// moves A's inbox by a card on the host, which it may write through A), `Sync` (a round of
    /// passes).
    pub steps: Vec<Step>,
}

#[derive(Clone, Copy, Debug)]
pub enum Step {
    Rotate(usize),
    Move(usize, usize),
    /// A round of passes: each host, then each node, in order.
    Sync,
}

#[derive(Clone, Debug)]
pub struct Run {
    pub cards: Vec<Card>,
    /// Card writes judged invalid (written off a path through A).
    pub invalid: usize,
    /// Rewrites made by the passes after the last step.
    pub rewrites: usize,
    pub keys: u32,
    /// The inbox the last move named.
    pub inbox: u32,
}

impl World {
    /// Runs the steps, then rounds of passes until nothing changes (at most `cap`).
    pub fn run(&self, rule: Rule, cap: usize) -> Run {
        let hosts = self.may.len();
        let mut cards = vec![Card { keys: 0, inbox: 0, since: 0 }; hosts];
        // per node: newest keys held, its latest card (since, inbox)
        let mut keys = vec![0u32; self.nodes];
        let mut latest = vec![(0u32, 0u32); self.nodes];
        let (mut now, mut top, mut inboxes, mut moved) = (0u32, 0u32, 0u32, 0u32);
        let (mut invalid, mut rewrites) = (0, 0);
        // a round's rewrites, and whether any node learned something
        let round = |cards: &mut Vec<Card>, keys: &mut Vec<u32>, latest: &mut Vec<(u32, u32)>, now: &mut u32, invalid: &mut usize| -> (usize, bool) {
            let (mut n, mut learned) = (0, false);
            for h in 0..hosts {
                for v in 0..self.nodes {
                    let may = self.may[h][v];
                    if may == 0 {
                        continue;
                    }
                    let c = cards[h];
                    if c.keys > keys[v] {
                        keys[v] = c.keys;
                        learned = true;
                    }
                    if c.since > latest[v].0 {
                        latest[v] = (c.since, c.inbox);
                        learned = true;
                    }
                    let stale = keys[v] > c.keys || (rule != Rule::KeysOnly && latest[v].1 != c.inbox);
                    let allowed = may == 2 || rule == Rule::AnyWriter;
                    if stale && allowed {
                        *now += 1;
                        let (since, inbox) = match rule {
                            Rule::KeysOnly => (c.since, c.inbox),
                            Rule::Restamp => (*now, latest[v].1),
                            _ => latest[v],
                        };
                        let w = Card { keys: keys[v], inbox, since };
                        n += 1;
                        if may == 2 {
                            cards[h] = w;
                            latest[v] = (w.since, w.inbox);
                        } else {
                            *invalid += 1;
                        }
                    }
                }
            }
            (n, learned)
        };
        for &s in &self.steps {
            match s {
                Step::Rotate(_) => {
                    top += 1;
                    keys.iter_mut().for_each(|k| *k = top);
                }
                Step::Move(v, h) => {
                    if self.may[h][v] == 2 {
                        inboxes += 1;
                        now += 1;
                        moved = inboxes;
                        let w = Card { keys: keys[v], inbox: inboxes, since: now };
                        cards[h] = w;
                        latest[v] = (w.since, w.inbox);
                    }
                }
                Step::Sync => {
                    round(&mut cards, &mut keys, &mut latest, &mut now, &mut invalid);
                }
            }
        }
        for _ in 0..cap {
            let (n, learned) = round(&mut cards, &mut keys, &mut latest, &mut now, &mut invalid);
            rewrites += n;
            if n == 0 && !learned {
                break;
            }
        }
        Run { cards, invalid, rewrites, keys: top, inbox: moved }
    }

    /// The hosts some node may write along a path through A (a card on any other host stays as
    /// written: nobody may rewrite it).
    pub fn live_hosts(&self) -> BTreeSet<usize> {
        (0..self.may.len()).filter(|&h| self.may[h].contains(&2)).collect()
    }

    /// The hosts a move on `h` spreads to: read by a node that may write, along a path through A,
    /// a host it spreads to.
    fn reach(&self, h: usize) -> BTreeSet<usize> {
        let mut out = BTreeSet::from([h]);
        loop {
            let more: BTreeSet<usize> = (0..self.may.len())
                .filter(|&h2| (0..self.nodes).any(|v| self.may[h2][v] == 2 && out.iter().any(|&h1| self.may[h1][v] > 0)))
                .collect();
            if more.is_subset(&out) {
                return out;
            }
            out.extend(more);
        }
    }

    /// `converge`: every host some node may write through A ends with A's newest keys, and with
    /// the last move's inbox where the move spreads to it; `valid`: no card write is invalid;
    /// `quiet`: passes stop.
    pub fn breaks(&self, rule: Rule) -> (bool, bool, bool) {
        let cap = 4 * (self.may.len() + 2);
        let r = self.run(rule, cap);
        let moved = self.steps.iter().rev().find_map(|s| match *s {
            Step::Move(v, h) if self.may[h][v] == 2 => Some(h),
            _ => None,
        });
        let spread = moved.map_or(BTreeSet::new(), |h| self.reach(h));
        let converge = self.live_hosts().iter().any(|&h| r.cards[h].keys != r.keys || (spread.contains(&h) && r.cards[h].inbox != r.inbox));
        (converge, r.invalid > 0, r.rewrites >= cap)
    }
}

/// A random world from `seed`: 2-3 nodes, 2-4 hosts, up to 7 steps. Every node syncs A, so holds
/// its newest keys once it rotates.
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
    let steps = (0..next(8))
        .map(|_| match next(3) {
            0 => Step::Rotate(next(nodes)),
            1 => Step::Move(next(nodes), next(hosts)),
            _ => Step::Sync,
        })
        .collect();
    World { nodes, may, steps }
}
