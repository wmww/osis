//! Which things count as independent at a node (spec/sync-set.md §2 Counts as independent).
//! Greenfield: the question is what a node holding some of Y's parts may take as "Y has role
//! secrets of its own", when the rotation making Y independent (its keyset) may not be among
//! them. A reader's stub of Y carries Y's keyset (spec/permissions.md §4 Stub: its public key
//! record); a sync-only cut does not, so a node keeping Y unread holds a sync box and a step.
//!
//! The world: P is independent; Y is minted with admin P. Parties: A, an admin of P (so of Y, by
//! the record grant); W, a writer of P; W2, a writer of P removed before it writes; X, a stranger.
//! Y may be made independent by A (a rotation: the keyset, a box to P at epoch 1, a `sync.0` step
//! bearing epoch 1's sync key) and A may grant G and G2 read on Y (a grant write and a box each)
//! and K sync (a sync-only box: K keeps Y unread). Hostile parts: W, W2 or X boxing R, P or G at a
//! made-up epoch, or writing a step bearing one; A planting a box and a step with no keyset.
//! Validity is judged at each part's point: a box needs write on Y, a keyset, a step or an edge
//! write admin (A demoted after its plant changes nothing). Sync and read share one epoch
//! counter: a read box gives both secrets of its epoch, a sync box the sync secret alone.
//! A node holds any subset of the parts (a stub carries no keyset) and opens the boxes to
//! the holders it acts for or holds secrets of.
use std::collections::BTreeSet;

pub type Id = u32;

pub const P: Id = 1;
pub const A: Id = 2;
pub const W: Id = 3;
pub const W2: Id = 4;
pub const X: Id = 5;
pub const R: Id = 6;
pub const G: Id = 7;
pub const G2: Id = 8;
pub const K: Id = 9;

/// One part on Y, with its commit's signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Part {
    /// a `keys.0` part writing a keyset: the rotation making Y independent
    Keyset { signer: Id },
    /// a `secrets.0` box to `holder` at `epoch`, giving read (and sync) or only sync
    Box { signer: Id, holder: Id, epoch: u32, read: bool },
    /// a `sync.0` step bearing `epoch`'s sync key, verified to its genesis
    Step { signer: Id, epoch: u32 },
    /// a grant write naming `holder`
    Edge { signer: Id, holder: Id },
}

/// The epochs a rotation of Y makes; a made-up one is any other.
pub const MADE: u32 = 1;

/// Each party's role on Y when its part is judged: A admin (record grant of P), W write, the
/// others none (W2 removed before it writes).
fn role(signer: Id) -> u8 {
    match signer {
        A => 3,
        W => 2,
        _ => 0,
    }
}

pub fn valid(p: &Part) -> bool {
    match *p {
        Part::Box { signer, .. } => role(signer) >= 2,
        Part::Keyset { signer } | Part::Step { signer, .. } | Part::Edge { signer, .. } => role(signer) >= 3,
    }
}

/// How a node judges Y's independence from what it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// The spec: a held valid keyset, or, at a node reading nothing of Y (no read box opened,
    /// not opening P), a secret a held valid box gave whose sync key a held valid step bears.
    Spec,
    /// Control: the box and step clause at every node, readers included.
    StepAnywhere,
    /// Control: any secret a held valid box gave (the rule before).
    BoxAlone,
    /// Control: a held valid keyset alone.
    KeysetOnly,
    /// Control: a box counts only where the node does not open Y as dependent (it opens P).
    NotOpenedDependent,
    /// Control: a box counts only beside a held valid grant write on Y.
    BesideEdge,
}

/// Whether a node holding `held` and opening the boxes to `opens` counts Y independent.
pub fn counts(rule: Rule, held: &BTreeSet<Part>, opens: &BTreeSet<Id>) -> bool {
    let held: Vec<&Part> = held.iter().filter(|p| valid(p)).collect();
    if held.iter().any(|p| matches!(p, Part::Keyset { .. })) {
        return true;
    }
    let secrets: BTreeSet<u32> = held.iter().filter_map(|p| if let Part::Box { holder, epoch, .. } = p { opens.contains(holder).then_some(*epoch) } else { None }).collect();
    if secrets.is_empty() {
        return false;
    }
    let stepped = || held.iter().any(|p| matches!(p, Part::Step { epoch, .. } if secrets.contains(epoch)));
    match rule {
        Rule::Spec => !reads(&held, opens) && stepped(),
        Rule::StepAnywhere => stepped(),
        Rule::BoxAlone => true,
        Rule::KeysetOnly => false,
        Rule::NotOpenedDependent => !opens.contains(&P),
        Rule::BesideEdge => held.iter().any(|p| matches!(p, Part::Edge { .. })),
    }
}

/// Whether a node holding `held` and opening the boxes to `opens` reads Y: it opens P (Y's
/// secrets derive from P's) or a valid read box.
fn reads(held: &[&Part], opens: &BTreeSet<Id>) -> bool {
    opens.contains(&P) || held.iter().any(|p| matches!(p, Part::Box { holder, read: true, .. } if opens.contains(holder)))
}

/// A world: Y's honest parts (empty: Y stays dependent) and the hostile ones.
#[derive(Clone, Debug)]
pub struct World {
    pub honest: Vec<Part>,
    pub hostile: Vec<Part>,
}

impl World {
    /// Whether Y has role secrets of its own: some valid keyset part exists anywhere.
    pub fn independent(&self) -> bool {
        self.honest.iter().chain(&self.hostile).any(|p| valid(p) && matches!(p, Part::Keyset { .. }))
    }

    pub fn parts(&self) -> Vec<Part> {
        self.honest.iter().chain(&self.hostile).copied().collect()
    }
}

/// A's rotation making Y independent, and its grants to G and G2.
pub fn made_independent() -> Vec<Part> {
    vec![
        Part::Keyset { signer: A },
        Part::Box { signer: A, holder: P, epoch: MADE, read: true },
        Part::Step { signer: A, epoch: MADE },
        Part::Edge { signer: A, holder: G },
        Part::Box { signer: A, holder: G, epoch: MADE, read: true },
        Part::Edge { signer: A, holder: G2 },
        Part::Box { signer: A, holder: G2, epoch: MADE, read: true },
        Part::Edge { signer: A, holder: K },
        Part::Box { signer: A, holder: K, epoch: MADE, read: false },
    ]
}

/// A's plant: a step and boxes to R (read) and K (sync) on Y at a made-up epoch, no keyset.
pub fn planted() -> World {
    let hostile = vec![Part::Box { signer: A, holder: R, epoch: 9, read: true }, Part::Box { signer: A, holder: K, epoch: 9, read: false }, Part::Step { signer: A, epoch: 9 }];
    World { honest: Vec::new(), hostile }
}

/// Every world: Y dependent or made independent, beside each set of up to two hostile parts by
/// a party below admin (a box to R, P or G, or a step, at made-up epoch 9 or at `MADE`).
pub fn worlds() -> Vec<World> {
    let mut hostile = Vec::new();
    for signer in [W, W2, X] {
        for epoch in [9, MADE] {
            for holder in [R, P, G] {
                hostile.push(Part::Box { signer, holder, epoch, read: true });
            }
            hostile.push(Part::Step { signer, epoch });
        }
    }
    let mut sets: Vec<Vec<Part>> = vec![Vec::new()];
    for (i, a) in hostile.iter().enumerate() {
        sets.push(vec![*a]);
        for b in &hostile[i + 1..] {
            sets.push(vec![*a, *b]);
        }
    }
    let mut out = Vec::new();
    for honest in [Vec::new(), made_independent()] {
        for h in &sets {
            out.push(World { honest: honest.clone(), hostile: h.clone() });
        }
    }
    out
}

/// The nodes judged, each with what it opens: R (a reader of P: boxes to R and P), G (a grantee
/// of Y alone), G2 (a grantee of Y reading P) and K (keeping Y unread).
pub fn nodes() -> Vec<(Id, BTreeSet<Id>)> {
    vec![(R, [R, P].into()), (G, [G].into()), (G2, [G2, P].into()), (K, [K].into())]
}

/// Every subset of `parts`.
pub fn subsets(parts: &[Part]) -> impl Iterator<Item = BTreeSet<Part>> + '_ {
    (0u32..1 << parts.len()).map(move |m| parts.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, p)| *p).collect())
}

/// The honest holdings that must count Y independent, each with what its node opens: G's stub
/// of Y (its grant, its box, Y's `sync.0`, Y's keyset); a reader of P's unit, which references Y
/// (Y's stub there: the rotation's box to P, Y's `sync.0` and keyset); G2, a reader of P granted
/// on Y after Y left P's sync unit, holding Y's stub; K's sync-only cut (its sync box and Y's
/// `sync.0`, no keyset).
pub fn honest_holdings() -> Vec<(&'static str, BTreeSet<Part>, BTreeSet<Id>)> {
    let (step, keyset) = (Part::Step { signer: A, epoch: MADE }, Part::Keyset { signer: A });
    vec![
        ("grantee", [Part::Edge { signer: A, holder: G }, Part::Box { signer: A, holder: G, epoch: MADE, read: true }, step, keyset].into(), [G].into()),
        ("stub in the mint admin's unit", [Part::Box { signer: A, holder: P, epoch: MADE, read: true }, step, keyset].into(), [P].into()),
        ("late reader of the mint admin", [Part::Edge { signer: A, holder: G2 }, Part::Box { signer: A, holder: G2, epoch: MADE, read: true }, step, keyset].into(), [G2, P].into()),
        ("sync-only cut", [Part::Edge { signer: A, holder: K }, Part::Box { signer: A, holder: K, epoch: MADE, read: false }, step].into(), [K].into()),
    ]
}

/// The first (node, held set) of A's plant (`planted`) where `rule` counts Y independent at a
/// node reading Y: a read split, which nothing reconciles. K keeping Y unread may count it
/// (it splits storage, not reads).
pub fn split_case(rule: Rule) -> Option<(Id, BTreeSet<Part>)> {
    let parts = planted().parts();
    for (n, opens) in nodes() {
        if let Some(h) = subsets(&parts).find(|h| reads(&h.iter().collect::<Vec<_>>(), &opens) && counts(rule, h, &opens)) {
            return Some((n, h));
        }
    }
    None
}

/// The first (world, node, held set) where `rule` counts Y independent and Y is not.
pub fn unsafe_case(rule: Rule) -> Option<(World, Id, BTreeSet<Part>)> {
    for w in worlds() {
        if w.independent() {
            continue;
        }
        let parts = w.parts();
        for (n, opens) in nodes() {
            if let Some(h) = subsets(&parts).find(|h| counts(rule, h, &opens)) {
                return Some((w, n, h));
            }
        }
    }
    None
}

/// The honest holdings `rule` does not count independent.
pub fn stuck(rule: Rule) -> Vec<&'static str> {
    honest_holdings().into_iter().filter(|(_, h, o)| !counts(rule, h, o)).map(|(n, _, _)| n).collect()
}
