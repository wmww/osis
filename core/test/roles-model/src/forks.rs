//! Account forks and sides (spec/permissions.md §5.4): which of an account's signing-chain
//! rotations a node follows when the chain forks, as the first-seen rule. Independent of
//! `epochs` (no thing lists, cutoff or witnesses: commits at a closed epoch count only by
//! their author's own listing, the one word every honest node writes for itself).
//!
//! The rule under test. Each node places the held rotations in the order it came to hold them
//! (a rotation is held only with its chain, every fork it names and every revocation it takes,
//! so a line is whole when placed; a rotation the node's user chose has its line placed first). A placed rotation is
//! **disregarded** when a rotation on its line rejects or is rejected by a followed one, or
//! when a followed rotation is beside it (neither on the other's line); otherwise it is
//! followed with its whole line (a merge naming a disregarded fork brings it back). That is
//! the rule outside the account, where a removed device's fork looks like any other. A node of
//! the account reads who signed each rotation and each D grant (the inner signature) and whom
//! each rotation removes, with the removal's frontier (the removed node's D commits its remover
//! held): the revocations take effect in the order it came to hold them, each only while its
//! own line stands (every rotation on it minted by a node, none by a node an earlier revocation
//! removed, off that removal's rotation's line), and it follows every rotation whose line
//! stands: two of its devices' rotations made at once both count, and a plain fork of a removed
//! device never outweighs its removal. A rotation stands with the revocations on its line and
//! those a rotation on its line takes (its maker took them off its line); one standing with a
//! revocation not taken is that other side, whoever signed it: never followed, nor taken if it is
//! a revocation itself (a rotation is held only once what it takes is). The nodes: those paired before the world, and every
//! holder of a grant by another node no removal hits (a removal hits its node's grants its
//! frontier does not cover); a rotation is placed no earlier than its minter came to be known as
//! a node.
//! D's roster (whom an honest rotation boxes) is the nodes but the removed. Followed rotations
//! count; nothing else does (at P's nodes a followed rotation may reject another, when a device
//! that sided otherwise supersedes a line this node follows: counted, `View::cross`). A
//! disregarded rotation rejecting or rejected by a counting one is the warning ("the account
//! has forked"). Nothing reads `ts`; checks read only what was placed before, so a later
//! arrival never reopens a decision.
//!
//! Parties: account P with nodes A (honest, may rotate at time 0, removes X at time 1), B (honest, may be offline
//! until it reconnects: unaware of the removal, it writes, rotates, boxes X), X (removed: from
//! time 1 it forks from any epoch whose seed it holds, any number of times, may revoke A or B
//! in its forks, claims to take any revocation or one it keeps to itself, may counter-merge,
//! writes and lists its writes; it signs as itself or as Z, a
//! key actor it makes up, and writes D grants at any epoch it holds, backdated or at B's:
//! pairing Z, re-adding itself, Z re-adding it; in some worlds it paired Z in plain sight
//! before), T (a node of P that only reads, offline through the fight); outside readers R1, R2
//! (R2's user may switch). Honest
//! policy (not an input of judgment): a node of P signs at its preferred head; whenever it
//! acts it rotates if it holds a counting head other than its preferred one whose seed it
//! holds (naming it: a merge; one it cannot sign at is left to a node that can, as superseding
//! it unnamed would reject a line it follows) or a rotation that does not count, that no
//! counting one rejects on its line and that it has not superseded before (superseding it
//! unnamed: a rejection; one answer per line), takes the revocations it took off the new line,
//! and lists its own writes at every other epoch. A node of P on X's side switches to the honest
//! line in the settle phase (its user, told): A and T at once, B in a given round or never.
//!
//! Properties, at every node and every prefix of its receipts:
//! - Revocation holds: where A's removal of X counts, no rotation X made after it counts, and
//!   no write of X's does at a node outside P (at P's nodes a write at an open epoch an
//!   unaware sibling boxed to X counts until the merge: counted).
//! - No flip: outside P the followed set only grows (but at a switch); at P's nodes a removal
//!   followed stops counting only once a node on its rotation's line is removed (a removed
//!   node removes no one).
//! - No false alarm: with no rotation by X there is never a warning.
//! - Seeds stay away from X: no rotation an honest node of P makes while X's removal counts
//!   there boxes X or Z (Z paired in plain sight, its grant on the removal's frontier, aside:
//!   stated limit), and once settled no honest-side head's seed is X's.
//! - Settled (everything delivered, honest nodes acted in turn, none rotating in the last round):
//!   every node but X holds the warning
//!   when X made a rotation after its removal; every node on the honest side (A's removal
//!   counts) has one head, the same one, and counts every honest write (B's writes made
//!   unaware, at the first epoch and at its own rotation, among them).
//!
//! Negative controls: `forks-stand` (nothing disregarded: X's forks count beside its removal),
//! `forks-blind` (P's nodes judge as outsiders: two honest rotations made at once read as a
//! fight, warnings with no thief, nodes that never converge).

use crate::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub const A: usize = 0;
pub const B: usize = 1;
pub const X: usize = 2;
pub const T: usize = 3;
pub const R1: usize = 4;
pub const R2: usize = 5;
/// A key actor X makes up (no observer): it seals inner signatures as Z with its old epochs'
/// inner keys. Paired by X in plain sight before its removal in some worlds.
pub const Z: usize = 6;
pub const N: usize = 7;
/// Nodes `0..OWN` are P's.
pub const OWN: usize = 4;
pub const NEVER: u32 = u32::MAX;

/// Negative controls: 1 forks stand (nothing is disregarded, the rule before this one); 2 P's
/// nodes judge as outsiders do (every beside rotation ends another); 3 any key actor that signs
/// is a node and D's roster reads every grant at a counting epoch (a removed node's own
/// included); 4 first-seen grants: a removed node's grant is hit only when held after its
/// removal or signed beside it (notes/engine-validity-epochs.md, Sides: rejected); 5 nodes
/// ignore what a rotation takes (P's read only the revocations on its line); 6 a node answers
/// every disregarded rotation no counting one rejects, not one per line.
pub static CONTROL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const NAMES: [&str; N] = ["A", "B", "X", "T", "R1", "R2", "Z"];

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Signed at `at` (and at each fork it names), superseding `sup`, accepting the forks
    /// `names`, carrying the removal of `removes` from the devices list (signed at `at`) with
    /// its frontier `covers`: the removed node's D commits its remover held. `takes`: the
    /// revocations its maker took that are not on its line (held only once these are; it stands
    /// with them, read only at P's nodes).
    Rot { at: u32, names: Vec<u32>, sup: Vec<u32>, removes: Option<usize>, covers: Vec<u32>, takes: Vec<u32> },
    /// A grant of D to `to` (pairing), signed at `epoch` by `signer`.
    Grant { to: usize },
    /// A commit creating D that grants it to `to`: the account's first nodes are paired by the
    /// real one; one made again (X holds the first epoch's key) is forged.
    Creation { to: usize },
    Content,
    /// The author's word that its writes `names` count.
    Listing { names: Vec<u32> },
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub kind: Kind,
    pub author: usize,
    /// Whose inner signature it carries: its author, or a key actor X made up.
    pub signer: usize,
    /// The epoch it is signed at (a rotation: its `at`); 0 the first.
    pub epoch: u32,
    pub t: u32,
    pub recv: [u32; N],
    /// Made by X after its removal.
    pub hostile: bool,
    /// A rotation's seed holders.
    pub boxed: [bool; N],
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub items: Vec<Item>,
    /// (node, time, rotation): the node's user chooses that rotation's line.
    pub switches: Vec<(usize, u32, u32)>,
    /// A's removal of X.
    pub removal: u32,
    /// The settle round in which B's user switches to A's removal when B took X's side first
    /// (`None`: never, B stays on X's side for good).
    pub b_switch: Option<u32>,
    /// Set by `settle`: an honest node still rotated in its last round.
    pub restless: bool,
    /// Items X keeps to itself for good (a revocation it claims to take that no one else holds):
    /// the settle delivers them to no one.
    pub withheld: BTreeSet<u32>,
}

impl World {
    fn item(&self, id: u32) -> &Item {
        &self.items[id as usize - 1]
    }
    fn rot(&self, id: u32) -> Option<(u32, &[u32], &[u32], Option<usize>)> {
        match &self.item(id).kind {
            Kind::Rot { at, names, sup, removes, .. } => Some((*at, names, sup, *removes)),
            _ => None,
        }
    }
    fn covers(&self, id: u32) -> &[u32] {
        match &self.item(id).kind {
            Kind::Rot { covers, .. } => covers,
            _ => &[],
        }
    }
    fn takes(&self, id: u32) -> &[u32] {
        match &self.item(id).kind {
            Kind::Rot { takes, .. } => takes,
            _ => &[],
        }
    }
    pub fn add(&mut self, kind: Kind, author: usize, epoch: u32, t: u32, boxed: [bool; N]) -> u32 {
        self.add_as(kind, author, author, epoch, t, boxed)
    }
    /// `add` with the inner signature sealed as `signer`.
    pub fn add_as(&mut self, kind: Kind, author: usize, signer: usize, epoch: u32, t: u32, boxed: [bool; N]) -> u32 {
        let id = self.items.len() as u32 + 1;
        let mut recv = [NEVER; N];
        recv[author] = t;
        let hostile = author == X && self.removal != 0 && t >= self.item(self.removal).t;
        self.items.push(Item { id, kind, author, signer, epoch, t, recv, hostile, boxed });
        id
    }
    /// Z was paired by X before its removal and the removal's frontier covers that grant: Z is
    /// a node as any other (stated limit: a thief's device paired in plain sight stays until it
    /// is removed too).
    pub fn z_paired(&self) -> bool {
        self.removal != 0 && self.covers(self.removal).iter().any(|g| matches!(self.item(*g).kind, Kind::Grant { to: Z }) && self.item(*g).signer == X)
    }
    /// Made by X after its removal, signed as X or as a made-up key actor no removal covers.
    pub fn hostile(&self, id: u32) -> bool {
        let i = self.item(id);
        i.hostile && !(i.signer == Z && self.z_paired())
    }
}

/// One node's judgment of P's chain at one time.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub held: BTreeSet<u32>,
    /// Rotations held with their chain.
    pub chain: BTreeSet<u32>,
    pub lines: BTreeMap<u32, BTreeSet<u32>>,
    pub followed: BTreeSet<u32>,
    pub disregarded: BTreeSet<u32>,
    pub counting: BTreeSet<u32>,
    pub heads: BTreeSet<u32>,
    pub preferred: u32,
    /// At P's nodes: (node, epoch) removals the counting rotations carry.
    pub removed: BTreeSet<(usize, u32)>,
    /// At P's nodes: D's roster, whom an honest rotation boxes.
    pub roster: BTreeSet<usize>,
    pub warning: bool,
    /// Held rotations a counting one rejects.
    pub rejected: BTreeSet<u32>,
    /// Writes (content, listings) that count.
    pub valid: BTreeSet<u32>,
    pub chosen: Option<u32>,
    /// At a node of P: a followed rotation rejects another (a device that sided otherwise).
    pub cross: bool,
    /// At a node of P: the revocations it takes, in the order taken.
    pub taken: Vec<u32>,
}

impl View {
    pub fn removed_node(&self, n: usize) -> bool {
        self.removed.iter().any(|(x, _)| *x == n)
    }
    fn line(&self, r: u32) -> &BTreeSet<u32> {
        &self.lines[&r]
    }
    fn on(&self, r: u32, x: u32) -> bool {
        r == 0 || self.lines.get(&x).is_some_and(|l| l.contains(&r))
    }
}


pub fn judge(w: &World, v: usize, now: u32) -> View {
    let own = v < OWN;
    let mut j = View::default();
    j.held = w.items.iter().filter(|i| i.recv[v] <= now).map(|i| i.id).collect();
    // at a node of P, when each key actor came to be known as a node: paired before the world,
    // or the holder of a held grant by one known, once both are (removals aside: those decide
    // what stands, not what is held)
    let control = CONTROL.load(std::sync::atomic::Ordering::Relaxed);
    // (receipts are (time, id): one tick's by ID)
    let mut known: BTreeMap<usize, (u32, u32)> = (0..OWN).map(|m| (m, (0, 0))).collect();
    if own && control == 0 {
        loop {
            let mut changed = false;
            for g in j.held.iter().map(|id| w.item(*id)) {
                if let Kind::Creation { to } = g.kind {
                    if known.get(&to).is_none_or(|k| (g.recv[v], g.id) < *k) {
                        known.insert(to, (g.recv[v], g.id));
                        changed = true;
                    }
                    continue;
                }
                let Kind::Grant { to } = g.kind else { continue };
                let Some(t) = known.get(&g.signer).filter(|_| g.signer != to).map(|t| (*t).max((g.recv[v], g.id))) else { continue };
                if known.get(&to).is_none_or(|k| t < *k) {
                    known.insert(to, t);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
    // with its chain (a merge with every fork it names) and every revocation it takes held so
    // (at every node: one taking what P's nodes never hold would be followed outside, never
    // answered) and, at a node of P, its minter known; and when it came to be held so: the
    // latest receipt on its line, of a revocation it takes or of its minter's grant
    let holds_takes = control != 5;
    let reads_takes = own && holds_takes;
    let mut when: BTreeMap<u32, (u32, u32)> = BTreeMap::new();
    when.insert(0, (0, 0));
    // and its depth: one more than the deepest of what it needs (ties ancestors first)
    let mut depth: BTreeMap<u32, usize> = BTreeMap::new();
    depth.insert(0, 0);
    loop {
        let more: Vec<(u32, (u32, u32))> = j.held.iter().filter(|id| !when.contains_key(id)).filter_map(|id| {
            let (at, names, ..) = w.rot(*id)?;
            let i = w.item(*id);
            let first = known.get(&i.signer).map_or((i.recv[v], i.id), |k| (i.recv[v], i.id).max(*k));
            let takes = if holds_takes { w.takes(*id) } else { &[] };
            std::iter::once(&at).chain(names).chain(takes).map(|p| when.get(p).copied()).try_fold(first, |a, t| t.map(|t| a.max(t))).map(|t| (*id, t))
        }).collect();
        if more.is_empty() {
            break;
        }
        for (id, _) in &more {
            let (at, names, ..) = w.rot(*id).unwrap();
            let takes = if holds_takes { w.takes(*id) } else { &[] };
            let d = std::iter::once(&at).chain(names).chain(takes).filter_map(|p| depth.get(p)).max().copied().unwrap_or(0);
            depth.insert(*id, d + 1);
        }
        when.extend(more);
    }
    j.chain = when.keys().copied().filter(|r| *r != 0).collect();
    for &r in &j.chain {
        // names point at earlier items, so lines build in ID order
        let (at, names, ..) = w.rot(r).unwrap();
        let mut l: BTreeSet<u32> = [r].into();
        for p in std::iter::once(&at).chain(names.iter()).filter(|p| j.chain.contains(p)) {
            l.extend(j.lines[p].iter().copied());
        }
        j.lines.insert(r, l);
    }
    j.chosen = w.switches.iter().filter(|(n, t, c)| *n == v && *t <= now && j.chain.contains(c)).last().map(|x| x.2);
    let jr = j.clone();
    let j0 = &jr;
    let signed_at = |s: u32| -> BTreeSet<u32> {
        let (at, names, ..) = w.rot(s).unwrap();
        std::iter::once(at).chain(names.iter().copied().filter(|n| j0.chain.contains(n))).collect()
    };
    // m rejects r: m supersedes r unnamed, and no held rotation signed at m's epoch shares a
    // line with r (contested only from below)
    let rejects = |m: u32, r: u32| -> bool {
        let (at, _, sup, _) = w.rot(m).unwrap();
        m != r && sup.contains(&r) && j0.chain.contains(&r) && !j0.chain.iter().any(|s| signed_at(*s).contains(&at) && (j0.on(r, *s) || j0.on(*s, r)))
    };
    // the chosen rotation's line first and, at a node of P, what it stands with (what a rotation
    // on it takes, and that one's line); ties by depth, then id
    let mut chosen_needs: BTreeSet<u32> = j.chosen.into_iter().collect();
    let mut work: Vec<u32> = chosen_needs.iter().copied().collect();
    while let Some(x) = work.pop() {
        let (at, names, ..) = w.rot(x).unwrap();
        let takes = if reads_takes { w.takes(x) } else { &[] };
        for p in std::iter::once(&at).chain(names).chain(takes).filter(|p| j.chain.contains(p)) {
            if chosen_needs.insert(*p) {
                work.push(*p);
            }
        }
    }
    let mut order: Vec<u32> = j.chain.iter().copied().collect();
    order.sort_by_key(|r| (!chosen_needs.contains(r), when[r], depth[r], *r));
    // Placed in order. A rotation is held only with every rotation on its line, so lines are
    // whole when placed; rejections read only what was placed before, so a later arrival never
    // reopens an earlier decision.
    let mut placed: BTreeSet<u32> = BTreeSet::new();
    let mut followed: BTreeSet<u32> = BTreeSet::new();
    // what a node of P reads of D: the grants it holds (pairings), who signed each
    let grants: Vec<&Item> = j0.held.iter().map(|id| w.item(*id)).filter(|i| matches!(i.kind, Kind::Grant { .. })).collect();
    let creations: Vec<&Item> = j0.held.iter().map(|id| w.item(*id)).filter(|i| matches!(i.kind, Kind::Creation { .. })).collect();
    let to_of = |g: &Item| match g.kind { Kind::Grant { to } | Kind::Creation { to } => to, _ => unreachable!() };
    // removal (node, epoch, rotation carrying it) hits grant g by that node unless its frontier
    // covers g (control 4: unless held before the removal and signed at an epoch strictly
    // before the removal's, or at it)
    let hit = |g: &Item, (y, e, rr): (usize, u32, u32)| -> bool {
        y == g.signer && match control {
            4 => if g.epoch == e { (g.recv[v], g.id) > when[&rr] } else { !j0.on(g.epoch, e) },
            _ => !w.covers(rr).contains(&g.id),
        }
    };
    // the nodes: those paired before the world, and every holder of a grant no removal hits by
    // a node other than itself (least fixpoint). Control 3: any key actor that signs.
    let nodes_of = |removals: &[(usize, u32, u32)]| -> BTreeSet<usize> {
        let mut nodes: BTreeSet<usize> = (0..OWN).collect();
        // a commit creating D pairs its node while every removal's frontier lists it (a remover
        // lists the creating commits it holds)
        nodes.extend(creations.iter().filter(|c| removals.iter().all(|(_, _, rr)| w.covers(*rr).contains(&c.id))).map(|c| to_of(c)));
        if control == 3 {
            nodes.insert(Z);
            return nodes;
        }
        loop {
            let more: Vec<usize> = grants.iter().filter(|g| to_of(g) != g.signer && nodes.contains(&g.signer) && !nodes.contains(&to_of(g)) && !removals.iter().any(|r| hit(g, *r))).map(|g| to_of(g)).collect();
            if more.is_empty() {
                return nodes;
            }
            nodes.extend(more);
        }
    };
    let node_rule = own && matches!(control, 0 | 3 | 4 | 5);
    if node_rule {
        // a node of P reads who made each rotation and whom it removes. The revocations it
        // takes are a consistent set, built in the order it came to hold them: one is taken
        // when no revocation taken (nor itself) hits a rotation on its line nor it one on theirs
        // (hits: removes its minter, the rotation beside that removal; a rotation whose minter
        // is no node stands by none). It follows every rotation whose line no revocation taken
        // hits and holds no revocation not taken
        let stands = |r: u32, removals: &[(usize, u32, u32)]| {
            let nodes = nodes_of(removals);
            j0.line(r).iter().all(|q| {
                let m = w.item(*q).signer;
                // made before the removal: on the line of the rotation carrying it (signed at
                // the removal's epoch and at every fork it accepts)
                nodes.contains(&m) && removals.iter().filter(|(y, ..)| *y == m).all(|(_, _, rr)| *q != *rr && j0.on(*q, *rr))
            })
        };
        // the revocations r stands with: those on its line and those a rotation on its line
        // takes (its maker took them; control 5: those on its line only)
        let revocation = |q: &u32| matches!(w.rot(*q), Some((_, _, _, Some(_))));
        let with_of = |r: u32| -> BTreeSet<u32> {
            j0.line(r).iter().flat_map(|q| std::iter::once(*q).filter(|q| revocation(q)).chain(if reads_takes { w.takes(*q).to_vec() } else { vec![] })).collect()
        };
        let mut taken: Vec<u32> = Vec::new();
        let mut removals: Vec<(usize, u32, u32)> = Vec::new();
        for &r in &order {
            let Some((at, _, _, Some(y))) = w.rot(r) else { continue };
            let mine = [(y, at, r)];
            let with: Vec<(usize, u32, u32)> = removals.iter().chain(&mine).copied().collect();
            if stands(r, &with) && taken.iter().all(|q| stands(*q, &mine)) && with_of(r).iter().all(|q| *q == r || taken.contains(q)) {
                taken.push(r);
                removals.push((y, at, r));
                j.removed.insert((y, at));
            }
        }
        for &r in &order {
            // a rotation standing with a revocation not taken here is a side taken otherwise
            // (its maker took that revocation): it never counts here
            if stands(r, &removals) && with_of(r).iter().all(|q| taken.contains(q)) {
                followed.insert(r);
            } else {
                j.disregarded.insert(r);
            }
        }
        j.taken = taken;
    }
    for &r in order.iter().filter(|_| !node_rule) {
        placed.insert(r);
        if followed.contains(&r) {
            continue;
        }
        let on = |a: u32, b: u32| j0.on(a, b);
        let rej = |m: u32, x: u32| -> bool {
            let (at, _, sup, _) = w.rot(m).unwrap();
            m != x && sup.contains(&x) && !placed.iter().any(|s| signed_at(*s).contains(&at) && (on(x, *s) || on(*s, x)))
        };
        // at a node of P: k's line removes the minter of a rotation on x's line beside that
        // removal, or a rotation on k's line rejects one on x's
        let conflict = |k: u32, x: u32| -> bool {
            j0.line(k).iter().any(|q| {
                let removal = w.rot(*q).and_then(|(at, _, _, y)| y.map(|y| (y, at)));
                j0.line(x).iter().any(|p| rej(*q, *p) || removal.is_some_and(|(y, e)| w.item(*p).author == y && !(e != 0 && on(*p, e))))
            })
        };
        let blind = !own || control == 2;
        // a line rejecting or rejected by a followed rotation ends it too: a merge cannot carry
        // a rejection of the followed line in (nor a fork the followed line rejects)
        let rejected = j0.line(r).iter().any(|q| followed.iter().any(|k| rej(*q, *k) || rej(*k, *q)));
        let ends = control != 1 && (rejected || followed.iter().any(|k| !on(*k, r) && !on(r, *k) && (blind || conflict(*k, r) || conflict(r, *k))));
        if ends {
            j.disregarded.insert(r);
            continue;
        }
        for &q in j0.line(r) {
            if followed.insert(q) {
                if let Some((at, _, _, Some(y))) = w.rot(q) {
                    j.removed.insert((y, at));
                }
            }
        }
    }
    j.disregarded.retain(|r| !followed.contains(r));
    j.followed = followed;
    // counting among the followed, as §5.4: seeded by the chosen line, then well-founded
    let mut status: BTreeMap<u32, Option<bool>> = j.followed.iter().map(|r| (*r, None)).collect();
    if let Some(c) = j.chosen {
        for &m in &j.followed {
            if j.line(c).iter().any(|r| rejects(m, *r)) {
                status.insert(m, Some(false));
            }
        }
    }
    loop {
        let mut changed = false;
        for &r in &j.followed {
            if status[&r].is_some() {
                continue;
            }
            let (at, ..) = w.rot(r).unwrap();
            let parent = if at == 0 { Some(true) } else { status.get(&at).copied().unwrap_or(Some(false)) };
            let rej: Vec<Option<bool>> = j.followed.iter().filter(|m| rejects(**m, r)).map(|m| status[m]).collect();
            let d = if parent == Some(false) || rej.contains(&Some(true)) {
                Some(false)
            } else if parent == Some(true) && rej.iter().all(|s| *s == Some(false)) {
                Some(true)
            } else {
                None
            };
            if d.is_some() {
                status.insert(r, d);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let fix: BTreeSet<u32> = status.into_iter().filter(|(_, s)| *s == Some(true)).map(|(r, _)| r).collect();
    // at a node of P, every followed rotation counts (spec/permissions.md §5.4): its devices
    // may side otherwise and supersede one it follows unnamed (counted, `View::cross`)
    j.cross = node_rule && fix != j.followed;
    j.counting = if node_rule { j.followed.clone() } else { fix };
    if own {
        let removals: Vec<(usize, u32, u32)> = j.counting.iter().filter_map(|q| w.rot(*q).and_then(|(at, _, _, y)| y.map(|y| (y, at, *q)))).collect();
        j.removed = removals.iter().map(|(y, e, _)| (*y, *e)).collect();
        // D's roster: the nodes (control 3: holders of any grant at a counting epoch) but those
        // removed, a removed node back by a grant at an epoch descending from (and not) its
        // removal's, by another node no removal hits (control 3: any grant, its own included)
        let nodes = if control == 3 {
            (0..OWN).chain(grants.iter().filter(|g| g.epoch == 0 || j.counting.contains(&g.epoch)).map(|g| to_of(g))).collect()
        } else {
            nodes_of(&removals)
        };
        let back = |m: usize, e: u32| grants.iter().any(|g| {
            to_of(g) == m && g.epoch != e && j.on(e, g.epoch) && (g.epoch == 0 || j.counting.contains(&g.epoch))
                && (control == 3 || g.signer != m && nodes.contains(&g.signer) && !removals.iter().any(|r| hit(g, *r)))
        });
        let roster = nodes.iter().copied().filter(|m| removals.iter().filter(|(y, ..)| y == m).all(|(_, e, _)| back(*m, *e))).collect();
        j.roster = roster;
    }
    j.heads = j.counting.iter().copied().filter(|h| !j.counting.iter().any(|x| x != h && j.on(*h, *x))).collect();
    if j.heads.is_empty() {
        j.heads.insert(0);
    }
    let pos: BTreeMap<u32, usize> = order.iter().enumerate().map(|(i, r)| (*r, i)).collect();
    j.preferred = j.heads.iter().copied().min_by(|a, b| {
        let la = j.lines.get(a).cloned().unwrap_or_default();
        let lb = j.lines.get(b).cloned().unwrap_or_default();
        match la.symmetric_difference(&lb).min_by_key(|r| (pos[r], **r)) {
            Some(r) if la.contains(r) => std::cmp::Ordering::Less,
            Some(_) => std::cmp::Ordering::Greater,
            None => a.cmp(b),
        }
    }).unwrap();
    j.rejected = j.chain.iter().copied().filter(|q| j.counting.iter().any(|m| rejects(*m, *q))).collect();
    j.warning = j.chain.iter().filter(|q| !j.counting.contains(q)).any(|q| j.counting.iter().any(|m| rejects(*m, *q) || rejects(*q, *m)));
    // writes: open epoch, or named by a counting listing (a least fixpoint)
    let epoch_held = |e: u32| e == 0 || j.chain.contains(&e);
    let mut named: BTreeSet<u32> = BTreeSet::new();
    loop {
        let valid: BTreeSet<u32> = j.held.iter().copied().filter(|id| {
            let i = w.item(*id);
            !matches!(i.kind, Kind::Rot { .. }) && epoch_held(i.epoch) && (j.heads.contains(&i.epoch) || named.contains(id))
        }).collect();
        let more: Vec<u32> = valid.iter().filter_map(|id| match &w.item(*id).kind {
            Kind::Listing { names } => Some(names.iter().copied().filter(|n| w.item(*n).author == w.item(*id).author).collect::<Vec<_>>()),
            _ => None,
        }).flatten().filter(|n| !named.contains(n)).collect();
        if more.is_empty() {
            j.valid = valid;
            break;
        }
        named.extend(more);
    }
    j
}

/// Who holds the seed of epoch `e` at node `n` now (X: also through Z, whose key it holds).
fn has_seed(w: &World, j: &View, n: usize, e: u32) -> bool {
    e == 0 || j.chain.contains(&e) && (w.item(e).boxed[n] || n == X && w.item(e).boxed[Z])
}

/// The revocations a rotation of a node judging `j`, signed at `h` and naming `names`, takes:
/// those it took that are not on that rotation's line.
pub fn takes_of(j: &View, h: u32, names: &[u32]) -> Vec<u32> {
    let on = |t: u32| std::iter::once(h).chain(names.iter().copied()).any(|p| j.on(t, p));
    j.taken.iter().copied().filter(|t| !on(*t)).collect()
}

/// Honest node `n` acts at `now`: rotates if owed (a removal, a fork among counting heads, an
/// unanswered rotation that does not count), writes, lists its own writes elsewhere.
pub fn act(w: &mut World, n: usize, now: u32, removes: Option<usize>, write: bool) -> Vec<u32> {
    let j = judge(w, n, now);
    if j.removed_node(n) {
        return vec![];
    }
    let mut made = vec![];
    let h = j.preferred;
    // a counting head it cannot sign at (its seed not boxed here) is left to a node that can:
    // superseding it unnamed would reject a line this node follows
    let others: Vec<u32> = j.heads.iter().copied().filter(|x| *x != h && *x != 0 && has_seed(w, &j, n, *x)).collect();
    // answered: a counting rotation rejects one on its line (every reader following it holds
    // that rejection: one answer per line, so two sides never answer each other's answers), or
    // this node superseded it already (a rotation contested from below cannot be rejected from
    // there: once is enough)
    let unanswered: Vec<u32> = j.chain.iter().copied().filter(|q| !j.counting.contains(q) && !(if CONTROL.load(std::sync::atomic::Ordering::Relaxed) == 6 { j.rejected.contains(q) } else { j.line(*q).iter().any(|x| j.rejected.contains(x)) }) && !w.items.iter().any(|i| i.author == n && i.recv[n] <= now && matches!(&i.kind, Kind::Rot { sup, .. } if sup.contains(q)))).collect();
    let mut head = h;
    if removes.is_some() || !others.is_empty() || !unanswered.is_empty() {
        let names = others.clone();
        let sup: Vec<u32> = std::iter::once(h).chain(others.iter().copied()).chain(unanswered.iter().copied()).collect();
        let mut boxed = [false; N];
        for (m, b) in boxed.iter_mut().enumerate() {
            *b = j.roster.contains(&m) && Some(m) != removes;
        }
        // the removal's frontier: the removed node's D commits held here, and the commits creating D
        let covers = removes.map(|y| w.items.iter().filter(|i| i.recv[n] <= now && (i.signer == y && matches!(i.kind, Kind::Grant { .. }) || matches!(i.kind, Kind::Creation { .. }))).map(|i| i.id).collect()).unwrap_or_default();
        let takes = takes_of(&j, h, &names);
        head = w.add(Kind::Rot { at: h, names, sup, removes, covers, takes }, n, h, now, boxed);
        made.push(head);
    }
    if write {
        made.push(w.add(Kind::Content, n, head, now, [false; N]));
    }
    let own: Vec<u32> = w.items.iter().filter(|i| i.author == n && i.epoch != head && matches!(i.kind, Kind::Content | Kind::Listing { .. }) && i.recv[n] <= now).map(|i| i.id).collect();
    if !own.is_empty() {
        made.push(w.add(Kind::Listing { names: own }, n, head, now, [false; N]));
    }
    made
}

/// Deliver `ids` to every node but the author: at `now + delay` each (`None`: never, until
/// the settle), never before `floor[node]` (an offline node).
fn deliver(w: &mut World, ids: &[u32], rng: &mut Rng, floor: &[u32; N]) {
    for id in ids {
        let i = &mut w.items[*id as usize - 1];
        let off = if i.author == B { floor[B] } else { 0 };
        // D's commits go to P's nodes only
        let d = matches!(i.kind, Kind::Grant { .. } | Kind::Creation { .. });
        for m in 0..N {
            if m == i.author || m == Z || d && m >= OWN {
                continue;
            }
            let d = match rng.below(6) {
                0 => NEVER,
                k => i.t + k as u32,
            };
            i.recv[m] = if d == NEVER { NEVER } else { d.max(floor[m]).max(off) };
        }
    }
}

pub fn random_world(rng: &mut Rng) -> World {
    let mut w = World::default();
    let all = [true; N];
    let mut floor = [0u32; N];
    w.b_switch = [None, Some(0), Some(1), Some(3)][rng.below(4)];
    // B offline until it reconnects
    let b_off = rng.below(3) > 0;
    if b_off {
        floor[B] = 3 + rng.below(6) as u32;
    }
    // X's own rotation just before its removal, sometimes
    if rng.below(4) == 0 {
        let mut bx = all;
        bx[R1] = false;
        bx[R2] = false;
        let id = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, X, 0, 0, bx);
        deliver(&mut w, &[id], rng, &floor);
    }
    // X pairs Z in plain sight, sometimes (the removal's frontier covers it if A holds it by then)
    if rng.below(5) == 0 {
        let id = w.add(Kind::Grant { to: Z }, X, 0, 0, [false; N]);
        deliver(&mut w, &[id], rng, &floor);
    }
    // A rotates plainly before the removal, sometimes
    if rng.below(3) == 0 {
        let mut bx = all;
        bx[R1] = false;
        bx[R2] = false;
        bx[Z] = false;
        let id = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, A, 0, 0, bx);
        deliver(&mut w, &[id], rng, &floor);
    }
    // A writes, then removes X at 1
    let mut ids = act(&mut w, A, 0, None, true);
    deliver(&mut w, &ids, rng, &floor);
    ids = act(&mut w, A, 1, Some(X), rng.below(2) == 0);
    let removal = ids[0];
    w.removal = removal;
    // X never receives anything of the honest line after its removal (it holds no new seed)
    for id in &ids {
        w.items[*id as usize - 1].recv[X] = NEVER;
    }
    deliver(&mut w, &ids[1..], rng, &floor);
    for id in &ids {
        w.items[*id as usize - 1].recv[X] = NEVER;
    }
    let steps = 4 + rng.below(6) as u32;
    let settle = 12;
    for t in 2..settle {
        if t - 2 >= steps {
            break;
        }
        match rng.below(5) {
            0 | 1 => {
                // X: fork from any epoch it holds, revoking someone or not, maybe a
                // counter-merge; or a write at any epoch it holds, listed in its fork
                let j = judge(&w, X, t);
                let held: Vec<u32> = std::iter::once(0).chain(j.chain.iter().copied().filter(|e| has_seed(&w, &j, X, *e))).collect();
                let e = held[rng.below(held.len())];
                let mut made = vec![];
                match rng.below(9) {
                    0..=3 => {
                        let removes = [None, Some(A), Some(B)][rng.below(3)];
                        let names: Vec<u32> = if rng.below(4) == 0 { held.iter().copied().filter(|x| *x != e && *x != 0).take(1).collect() } else { vec![] };
                        let mut sup = vec![e];
                        sup.extend(names.iter().copied());
                        let mut bx = [false; N];
                        bx[X] = true;
                        // signed as X, or as Z, a key actor it made up
                        // (Z paired in plain sight is a node: what it signs is the stated limit)
                        let signer = if rng.below(2) == 0 || w.z_paired() { X } else { Z };
                        let covers = removes.map(|y| w.items.iter().filter(|i| i.signer == y && matches!(i.kind, Kind::Grant { .. }) || matches!(i.kind, Kind::Creation { .. })).map(|i| i.id).collect()).unwrap_or_default();
                        // it may claim to take any revocation it holds (A's removal of it
                        // among them, to pass as the honest side), or one it keeps to itself
                        let revs: Vec<u32> = j.chain.iter().copied().filter(|r| matches!(w.rot(*r), Some((_, _, _, Some(_))))).chain([w.removal]).collect();
                        let takes = match rng.below(6) {
                            0 | 1 => vec![revs[rng.below(revs.len())]],
                            2 => {
                                let k = w.add(Kind::Rot { at: e, names: vec![], sup: vec![e], removes: Some(A), covers: vec![], takes: vec![] }, X, e, t, bx);
                                w.withheld.insert(k);
                                vec![k]
                            }
                            _ => vec![],
                        };
                        let r = w.add_as(Kind::Rot { at: e, names, sup, removes, covers, takes }, X, signer, e, t, bx);
                        made.push(r);
                        if rng.below(2) == 0 {
                            made.push(w.add(Kind::Content, X, r, t, [false; N]));
                        }
                    }
                    4 | 5 => {
                        let c = w.add(Kind::Content, X, e, t, [false; N]);
                        made.push(c);
                        if e != 0 && rng.below(2) == 0 {
                            made.push(w.add(Kind::Listing { names: vec![c] }, X, e, t, [false; N]));
                        }
                    }
                    // D edits at an epoch it holds (the first, backdated; an unaware sibling's):
                    // pairing Z, re-adding itself, or Z re-adding it
                    k => {
                        let (to, signer) = [(Z, X), (X, X), (X, if w.z_paired() { X } else { Z })][k - 6];
                        if k == 6 && !w.z_paired() && rng.below(3) == 0 {
                            // a commit creating D made again, pairing Z
                            made.push(w.add_as(Kind::Creation { to: Z }, X, Z, 0, t, [false; N]));
                        } else {
                            made.push(w.add_as(Kind::Grant { to }, X, signer, e, t, [false; N]));
                        }
                    }
                }
                deliver(&mut w, &made, rng, &floor);
            }
            2 => {
                let made = act(&mut w, A, t, None, rng.below(2) == 0);
                deliver(&mut w, &made, rng, &floor);
            }
            _ => {
                // B: before it reconnects it holds nothing new and may rotate unaware
                let removes = if t < floor[B] && rng.below(3) == 0 { Some(T) } else { None };
                let made = if removes.is_some() || t >= floor[B] || rng.below(2) == 0 {
                    act(&mut w, B, t, removes, true)
                } else {
                    act(&mut w, B, t, None, true)
                };
                let unaware_rot = made.iter().any(|id| matches!(w.item(*id).kind, Kind::Rot { .. }));
                if t < floor[B] && !unaware_rot && rng.below(3) == 0 {
                    // a plain rotation B makes unaware, boxing X
                    let j = judge(&w, B, t);
                    let h = j.preferred;
                    let mut bx = [false; N];
                    for m in &j.roster {
                        bx[*m] = true;
                    }
                    let takes = takes_of(&j, h, &[]);
                    let r = w.add(Kind::Rot { at: h, names: vec![], sup: vec![h], removes: None, covers: vec![], takes }, B, h, t, bx);
                    let c = w.add(Kind::Content, B, r, t, [false; N]);
                    deliver(&mut w, &[r, c], rng, &floor);
                }
                deliver(&mut w, &made, rng, &floor);
            }
        }
        if rng.below(6) == 0 {
            // R2's user switches to any rotation it holds
            let j = judge(&w, R2, t);
            if let Some(c) = j.chain.iter().nth(rng.below(j.chain.len().max(1))) {
                w.switches.push((R2, t, *c));
            }
        }
    }
    w
}

/// Rounds of `settle`: enough for B's latest switch and the merges after it, and one more to
/// see nothing is owed.
pub const ROUNDS: u32 = 6;

/// Everything delivered at `settle`, then honest nodes of P act in turn, `ROUNDS` rounds (A and
/// T on X's side switch to A's removal at once, B in round `b_switch` or never: users told)
/// until none owes anything.
pub fn settle(w: &mut World, settle: u32) -> u32 {
    for i in w.items.iter_mut().filter(|i| !w.withheld.contains(&i.id)) {
        let d = matches!(i.kind, Kind::Grant { .. } | Kind::Creation { .. });
        for (m, r) in i.recv.iter_mut().enumerate() {
            if m != Z && !(d && m >= OWN) {
                *r = (*r).min(settle.max(i.t));
            }
        }
    }
    let mut t = settle;
    for round in 0..ROUNDS {
        for n in [A, B, T] {
            t += 1;
            let j = judge(w, n, t);
            let switches = if n == B { w.b_switch.is_some_and(|k| round >= k) } else { true };
            if !j.counting.contains(&w.removal) && switches {
                w.switches.push((n, t, w.removal));
            }
            if n == T {
                continue;
            }
            let made = act(w, n, t, None, false);
            if round + 1 == ROUNDS && made.iter().any(|id| matches!(w.item(*id).kind, Kind::Rot { .. })) {
                w.restless = true;
            }
            for id in made {
                w.items[id as usize - 1].recv = [t; N];
            }
        }
    }
    t + 1
}

#[derive(Default, Debug)]
pub struct Stats {
    pub worlds: u64,
    pub fail: Vec<(String, World)>,
    /// Failing (node, prefix) checks.
    pub failures: u64,
    pub forks: u64,
    pub fights: u64,
    pub own_window: u64,
    pub outside_window: u64,
    pub on_x_side_final: u64,
    pub warned_final: u64,
    pub disregarded_honest: u64,
    pub races: u64,
    /// Worlds where X signs as a key actor it made up after its removal.
    pub forged: u64,
    /// Node-prefixes of P where a followed rotation rejects another.
    pub cross: u64,
    /// Failing checks by node and kind.
    pub kinds: BTreeMap<String, u64>,
    /// A rotation arriving that stops another rejecting (one signed at its epoch on a line
    /// with the rejected): the warning goes until a rotation rejects again.
    pub warning_went: u64,
    /// Worlds where an honest rotation takes a revocation off its line; of those, one X made.
    pub taking: u64,
    pub taking_x: u64,
    /// Worlds settled with B on X's side for good (its user never switching), and with B
    /// switching after a settle round in which it acted on X's side.
    pub b_stays: u64,
    pub b_late: u64,
    /// Worlds where X claims to take a revocation it keeps to itself.
    pub withholding: u64,
}

pub fn check(w0: &World, st: &mut Stats) {
    let mut w = w0.clone();
    let end = settle(&mut w, 12);
    st.worlds += 1;
    // a rotation X made after its removal that some node but X holds with its chain
    let x_rot = (0..N).filter(|v| *v != X && *v != Z).any(|v| judge(&w, v, end).chain.iter().any(|r| w.hostile(*r)));
    let x_any_rot = w.items.iter().any(|i| i.author == X && matches!(i.kind, Kind::Rot { .. }));
    if x_rot {
        st.forks += 1;
    }
    if w.items.iter().any(|i| w.hostile(i.id) && matches!(i.kind, Kind::Rot { removes: Some(_), .. })) {
        st.fights += 1;
    }
    if !w.withheld.is_empty() {
        st.withholding += 1;
    }
    if w.items.iter().any(|i| i.signer == Z && w.hostile(i.id)) {
        st.forged += 1;
    }
    let fail = |s: String, st: &mut Stats| {
        st.failures += 1;
        // by node and kind (the message up to its first number after the node)
        let (node, rest) = s.split_once(':').unwrap_or(("", &s));
        let node = node.split(" at ").next().unwrap_or(node);
        let kind: String = rest.chars().take_while(|c| !c.is_ascii_digit() && *c != '{' && *c != '(').collect();
        let k = st.kinds.entry(format!("{node}:{kind}")).or_default();
        *k += 1;
        if *k == 1 && st.fail.len() < 8 {
            st.fail.push((s, w.clone()));
        }
    };
    let takes_x = |i: &Item| matches!(&i.kind, Kind::Rot { takes, .. } if takes.iter().any(|t| w.item(*t).author == X));
    if w.items.iter().any(|i| !i.hostile && i.author != X && !w.takes(i.id).is_empty()) {
        st.taking += 1;
        if w.items.iter().any(|i| !i.hostile && i.author != X && takes_x(i)) {
            st.taking_x += 1;
        }
    }
    let b_x_side = |t: u32| !judge(&w, B, t).counting.contains(&w.removal);
    match w.b_switch {
        None if b_x_side(end) => st.b_stays += 1,
        Some(k) if k > 0 && b_x_side(12 + 3 * k) => st.b_late += 1,
        _ => {}
    }
    if w.restless {
        fail(format!("honest nodes still rotating after {ROUNDS} settle rounds"), st);
    }
    // seeds stay away from X: a rotation an honest node makes while X's removal counts there
    // boxes neither X nor a key actor X made up (Z paired in plain sight aside: stated limit)
    let leaks = |b: &[bool; N]| b[X] || b[Z] && !w.z_paired();
    for r in w.items.iter().filter(|i| matches!(i.kind, Kind::Rot { .. }) && [A, B, T].contains(&i.author)) {
        let j = judge(&w, r.author, r.t);
        if j.counting.contains(&w.removal) && leaks(&r.boxed) {
            fail(format!("node {}: rotation {} boxes X ({:?}) where X's removal counts", NAMES[r.author], r.id, r.boxed), st);
        }
    }
    for v in (0..N).filter(|v| *v != Z) {
        let mut prev: Option<View> = None;
        for now in 0..=end {
            let j = judge(&w, v, now);
            let switched = w.switches.iter().any(|(n, t, _)| *n == v && *t == now);
            if j.counting != j.followed && CONTROL.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                fail(format!("node {} at {now}: a followed rotation does not count {:?} {:?}", NAMES[v], j.followed, j.counting), st);
            }
            if j.cross {
                st.cross += 1;
            }
            // revocation holds
            if j.counting.contains(&w.removal) {
                if let Some(r) = j.counting.iter().find(|r| w.hostile(**r)) {
                    fail(format!("node {} at {now}: X's rotation {r} counts beside its removal", NAMES[v]), st);
                }
                if let Some(c) = j.valid.iter().find(|c| w.hostile(**c)) {
                    if v < OWN {
                        st.own_window += 1;
                    } else {
                        fail(format!("node {} at {now}: X's write {c} counts beside its removal", NAMES[v]), st);
                    }
                }
            } else if j.valid.iter().any(|c| w.hostile(*c)) && v >= OWN && j.held.contains(&w.removal) {
                st.outside_window += 1;
            }
            if !x_any_rot && j.warning {
                fail(format!("node {} at {now}: a warning with no rotation by X", NAMES[v]), st);
            }
            if let Some(p) = &prev {
                if !switched {
                    if v >= OWN && !p.followed.is_subset(&j.followed) {
                        fail(format!("node {} at {now}: followed shrank {:?} -> {:?}", NAMES[v], p.followed, j.followed), st);
                    }
                    // a removal stops counting only with its remover's removal (a removed node
                    // removes no one): never back and forth between two nodes' revocations
                    let remover_gone = |(y, e): &(usize, u32)| w.items.iter().any(|i| matches!(i.kind, Kind::Rot { at, removes: Some(z), .. } if at == *e && z == *y) && j.lines.get(&i.id).is_some_and(|l| l.iter().any(|q| j.removed_node(w.item(*q).signer))));
                    if v < OWN && !p.removed.iter().all(|r| j.removed.contains(r) || remover_gone(r)) {
                        fail(format!("node {} at {now}: removals followed shrank {:?} -> {:?}", NAMES[v], p.removed, j.removed), st);
                    }
                }
                if p.warning && !j.warning {
                    st.warning_went += 1;
                }
            }
            prev = Some(j);
        }
        let j = prev.unwrap();
        if j.disregarded.iter().any(|r| !w.hostile(*r) && w.item(*r).author != X) {
            st.disregarded_honest += 1;
        }
        // (X's own view aside: it judges its own forks as it likes)
        if x_rot && v != X {
            if j.warning {
                st.warned_final += 1;
            } else {
                fail(format!("node {}: settled without the warning", NAMES[v]), st);
            }
        }
        if !j.counting.contains(&w.removal) {
            st.on_x_side_final += 1;
            continue;
        }
        if j.heads.len() != 1 {
            fail(format!("node {}: settled with heads {:?}", NAMES[v], j.heads), st);
        }
        if let Some(h) = j.heads.iter().find(|h| **h != 0 && leaks(&w.item(**h).boxed)) {
            fail(format!("node {}: settled at head {h}, whose seed X holds", NAMES[v]), st);
        }
        // a node of P left on X's side (its user not switching) writes on that side
        if v < OWN {
            if let Some(c) = j.valid.iter().find(|c| w.hostile(**c)) {
                fail(format!("node {}: settled counting X's write {c}", NAMES[v]), st);
            }
        }
        let x_side = |n: usize| !judge(&w, n, end).counting.contains(&w.removal);
        let honest: Vec<u32> = w.items.iter().filter(|i| i.author != X && !(i.author < OWN && x_side(i.author)) && matches!(i.kind, Kind::Content)).map(|i| i.id).collect();
        if let Some(c) = honest.iter().find(|c| !j.valid.contains(c)) {
            fail(format!("node {}: settled without honest write {c}", NAMES[v]), st);
        }
    }
    let heads: BTreeSet<BTreeSet<u32>> = (0..N).map(|v| judge(&w, v, end)).filter(|j| j.counting.contains(&w.removal)).map(|j| j.heads).collect();
    if heads.len() > 1 {
        fail(format!("honest-side nodes settled on different heads {heads:?}"), st);
    }
    let merges = w.items.iter().filter(|i| !i.hostile && matches!(&i.kind, Kind::Rot { names, .. } if !names.is_empty())).count();
    if merges > 1 {
        st.races += 1;
    }
}

pub fn print_world(w: &World) {
    for i in &w.items {
        let recv: Vec<String> = i.recv.iter().map(|r| if *r == NEVER { "-".into() } else { r.to_string() }).collect();
        println!("  #{} {:?} by {} as {} at e{} t{} recv [{}] boxed {:?}{}", i.id, i.kind, NAMES[i.author], NAMES[i.signer], i.epoch, i.t, recv.join(" "), i.boxed, if w.hostile(i.id) { " hostile" } else { "" });
    }
    for (n, t, c) in &w.switches {
        println!("  switch {} at {t} to {c}", NAMES[*n]);
    }
}

pub fn run(samples: u64) -> u64 {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let per = samples / threads as u64;
    let out: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads).map(|th| s.spawn(move || {
            let mut st = Stats::default();
            let mut rng = Rng(0xf0c5 ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
            for _ in 0..per {
                check(&random_world(&mut rng), &mut st);
            }
            st
        })).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for st in out {
        all.worlds += st.worlds;
        all.forks += st.forks;
        all.fights += st.fights;
        all.own_window += st.own_window;
        all.outside_window += st.outside_window;
        all.on_x_side_final += st.on_x_side_final;
        all.warned_final += st.warned_final;
        all.disregarded_honest += st.disregarded_honest;
        all.races += st.races;
        all.forged += st.forged;
        all.cross += st.cross;
        for (k, n) in st.kinds {
            *all.kinds.entry(k).or_default() += n;
        }
        all.failures += st.failures;
        all.warning_went += st.warning_went;
        all.taking += st.taking;
        all.taking_x += st.taking_x;
        all.b_stays += st.b_stays;
        all.b_late += st.b_late;
        all.withholding += st.withholding;
        all.fail.extend(st.fail);
    }
    let fails = all.failures;
    let shown = std::mem::take(&mut all.fail);
    println!("forks: {fails} failing checks; {all:?}");
    for (s, w) in shown.iter().filter(|(s, _)| std::env::var("FORKS_SHOW").map_or(true, |f| s.contains(&f))).take(3) {
        println!("FAIL {s}");
        print_world(w);
        let mut vs: Vec<usize> = NAMES.iter().position(|n| s.starts_with(&format!("node {n}:")) || s.starts_with(&format!("node {n} "))).into_iter().collect();
        if std::env::var_os("FORKS_ALL").is_some() {
            vs = (0..N).collect();
        }
        for v in vs {
            let mut w = w.clone();
            let end = settle(&mut w, 12);
            for now in 0..=end {
                let j = judge(&w, v, now);
                println!("  {} t{now}: followed {:?} disregarded {:?} counting {:?} heads {:?} removed {:?} roster {:?} warn {} chosen {:?}", NAMES[v], j.followed, j.disregarded, j.counting, j.heads, j.removed, j.roster, j.warning, j.chosen);
            }
        }
    }
    fails
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_at(w: &mut World, ids: &[u32], t: u32) {
        for id in ids {
            let i = &mut w.items[*id as usize - 1];
            for n in 0..N {
                if n != i.author {
                    i.recv[n] = t;
                }
            }
        }
    }
    fn to(w: &mut World, id: u32, n: usize, t: u32) {
        w.items[id as usize - 1].recv[n] = t;
    }
    fn fork(w: &mut World, at: u32, t: u32, removes: Option<usize>) -> u32 {
        let mut bx = [false; N];
        bx[X] = true;
        w.add(Kind::Rot { at, names: vec![], sup: vec![at], removes, covers: vec![], takes: vec![] }, X, at, t, bx)
    }

    // A removes X; R1 holds the removal first. X forks from the first epoch again and again,
    // writing at each fork: none counts at R1, and once A rejects them R1 is warned.
    #[test]
    fn a_removed_devices_forks_never_count_after_the_removal() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 2);
        let mut forks = vec![];
        for t in 3..6 {
            let f = fork(&mut w, 0, t, Some(A));
            let c = w.add(Kind::Content, X, f, t, [false; N]);
            all_at(&mut w, &[f, c], t + 1);
            forks.push(f);
            let j = judge(&w, R1, t + 1);
            assert!(j.counting.contains(&w.removal) && !j.counting.contains(&f) && !j.valid.contains(&c), "fork {f}");
        }
        assert!(!judge(&w, R1, 7).warning, "no rejection yet");
        let ans = act(&mut w, A, 8, None, false);
        all_at(&mut w, &ans, 9);
        let j = judge(&w, R1, 9);
        assert!(j.warning && j.counting.contains(&ans[0]));
        // T, a node of P offline through it all, takes the removal too and is warned
        assert!(judge(&w, T, 9).warning && judge(&w, T, 9).counting.contains(&w.removal));
    }

    // X forks (revoking A) claiming to take a revocation it keeps to itself, and R2 gets the
    // fork before A's removal. No node holds the fork (it waits for what it takes), so R2 never
    // follows a line P's nodes never answer: it follows A's removal, and A owes nothing.
    #[test]
    fn a_rotation_taking_what_no_one_holds_is_held_nowhere() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        let k = fork(&mut w, 0, 1, Some(B));
        w.withheld.insert(k);
        let f = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: Some(A), covers: vec![], takes: vec![k] }, X, 0, 1, [false, false, true, false, false, false, false]);
        all_at(&mut w, &[f], 2);
        all_at(&mut w, &made, 3);
        for n in [A, B, T, R1, R2] {
            let j = judge(&w, n, 3);
            assert!(!j.chain.contains(&f) && j.counting.contains(&w.removal) && !j.warning, "{}: {j:?}", NAMES[n]);
        }
        assert!(act(&mut w, A, 4, None, false).is_empty(), "nothing to answer");
    }

    // R2 holds X's fork (revoking A) before A's removal of X: it stays with X, is warned once
    // A's answer arrives, and a switch to A's line holds.
    #[test]
    fn a_reader_that_saw_the_thief_first_stays_and_is_warned_until_it_switches() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        let f = fork(&mut w, 0, 1, Some(A));
        all_at(&mut w, &[f], 2);
        all_at(&mut w, &made, 3);
        let j = judge(&w, R2, 3);
        assert!(j.counting.contains(&f) && !j.counting.contains(&w.removal) && !j.warning);
        let ans = act(&mut w, A, 4, None, false);
        all_at(&mut w, &ans, 5);
        let j = judge(&w, R2, 5);
        assert!(j.counting.contains(&f) && j.warning, "stays with X, warned");
        w.switches.push((R2, 6, w.removal));
        let later = fork(&mut w, f, 7, None);
        all_at(&mut w, &[later], 8);
        let j = judge(&w, R2, 8);
        assert!(j.counting.contains(&ans[0]) && !j.counting.contains(&f) && !j.counting.contains(&later));
    }

    // B, offline, writes and rotates unaware of X's removal (boxing X). Once it catches up,
    // a merge names its rotation and its listing names its writes: R1, which followed A's
    // line, counts them all, and no warning is raised.
    #[test]
    fn an_offline_devices_writes_are_kept_on_the_honest_line() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 2);
        for id in &made {
            to(&mut w, *id, B, 10);
        }
        let c1 = w.add(Kind::Content, B, 0, 3, [false; N]);
        let mut bx = [false; N];
        bx[..OWN].fill(true);
        let b = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, B, 0, 4, bx);
        let c2 = w.add(Kind::Content, B, b, 5, [false; N]);
        all_at(&mut w, &[c1, b, c2], 10);
        let j = judge(&w, R1, 10);
        assert!(j.disregarded.contains(&b) && !j.valid.contains(&c2), "until the merge");
        let m = act(&mut w, B, 11, None, false);
        all_at(&mut w, &m, 12);
        let j = judge(&w, R1, 12);
        assert!(j.valid.contains(&c1) && j.valid.contains(&c2) && j.heads.len() == 1 && !j.warning, "{j:?}");
    }

    // T, a node of P, holds X's plain fork (revoking no one) before A's removal of X: the
    // removal is the first revocation it sees, so it disregards the fork; R1, outside, cannot
    // tell the fork from any rotation and follows it
    #[test]
    fn a_node_of_the_account_takes_a_removal_over_a_plain_fork_held_first() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        let f = fork(&mut w, 0, 1, None);
        all_at(&mut w, &[f], 2);
        all_at(&mut w, &made, 3);
        let j = judge(&w, T, 3);
        assert!(j.counting.contains(&w.removal) && !j.counting.contains(&f));
        let j = judge(&w, R1, 3);
        assert!(j.counting.contains(&f) && !j.counting.contains(&w.removal));
    }

    fn boxed_to(ms: &[usize]) -> [bool; N] {
        let mut bx = [false; N];
        for m in ms {
            bx[*m] = true;
        }
        bx
    }

    // A removed node holds its old epochs' inner key, so it seals inner signatures as Z, a key
    // actor it makes up, and backdates a grant of D to Z at the first epoch, reaching B (offline)
    // before the removal does. The removal's frontier does not cover that grant, so once a node
    // of P holds the removal Z is no node there: its revocation of A stands nowhere and no
    // honest rotation boxes it (spec/permissions.md §5.4, Following, at a node of P)
    #[test]
    fn a_key_actor_the_removed_node_makes_up_is_no_node() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 5);
        to(&mut w, made[0], X, NEVER);
        let g = w.add_as(Kind::Grant { to: Z }, X, X, 0, 2, [false; N]);
        all_at(&mut w, &[g], 3);
        assert!(judge(&w, B, 3).roster.contains(&Z), "before the removal B takes Z as a node");
        let f = w.add_as(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: Some(A), covers: vec![], takes: vec![] }, X, Z, 0, 6, boxed_to(&[X]));
        all_at(&mut w, &[f], 7);
        for n in [A, B, T] {
            let j = judge(&w, n, 7);
            assert!(j.counting.contains(&w.removal) && !j.counting.contains(&f) && !j.roster.contains(&Z), "{}: {j:?}", NAMES[n]);
        }
        // B answers the forged fork; its rotation boxes neither X nor Z
        let m = act(&mut w, B, 8, None, false);
        let r = w.item(m[0]);
        assert!(matches!(&r.kind, Kind::Rot { sup, .. } if sup.contains(&f)) && !r.boxed[X] && !r.boxed[Z], "{r:?}");
    }

    // B, unaware of X's removal, rotates and boxes X (stated limit). X grants D to itself at B's
    // epoch, and again sealed as a key actor it made up: neither puts it back on D's roster,
    // so the merge joining B's rotation to the removal boxes the honest nodes alone
    #[test]
    fn a_removed_node_granting_itself_at_an_unaware_siblings_epoch_stays_off_the_roster() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 2);
        for id in &made {
            to(&mut w, *id, B, 6);
            to(&mut w, *id, X, NEVER);
        }
        let rb = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, B, 0, 3, boxed_to(&[A, B, X, T]));
        all_at(&mut w, &[rb], 4);
        let g1 = w.add_as(Kind::Grant { to: X }, X, X, rb, 5, [false; N]);
        let g2 = w.add_as(Kind::Grant { to: X }, X, Z, rb, 5, [false; N]);
        all_at(&mut w, &[g1, g2], 6);
        for n in [A, B, T] {
            let j = judge(&w, n, 7);
            assert!(j.counting.contains(&w.removal) && j.counting.contains(&rb) && !j.roster.contains(&X), "{}: {j:?}", NAMES[n]);
        }
        let m = act(&mut w, A, 8, None, false);
        let r = w.item(m[0]);
        assert!(matches!(&r.kind, Kind::Rot { names, .. } if names.contains(&rb)) && !r.boxed[X] && !r.boxed[Z], "{r:?}");
    }

    // A device the removed node paired in plain sight stays a node when the removal's frontier
    // covers its grant (stated limit: it goes with its own removal); one the remover had not
    // received is no node, as a removed writer's word its demotion's frontier leaves out is lost
    // (spec/permissions.md §5.3)
    #[test]
    fn a_device_the_removed_node_paired_is_a_node_as_its_remover_held_it() {
        for covered in [true, false] {
            let mut w = World::default();
            let g = w.add_as(Kind::Grant { to: Z }, X, X, 0, 0, [false; N]);
            all_at(&mut w, &[g], if covered { 0 } else { 2 });
            let made = act(&mut w, A, 1, Some(X), false);
            w.removal = made[0];
            all_at(&mut w, &made, 2);
            assert_eq!(w.z_paired(), covered);
            let f = w.add_as(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, X, Z, 0, 3, boxed_to(&[X, Z]));
            all_at(&mut w, &[f], 4);
            for n in [A, B, T] {
                let j = judge(&w, n, 4);
                assert_eq!((j.roster.contains(&Z), j.counting.contains(&f)), (covered, covered), "{} covered {covered}", NAMES[n]);
            }
        }
    }

    // X rotated offline before its removal, and A merges that rotation in the rotation carrying
    // the removal (it holds its seed): X's rotation is on the removal's line, made before it, so
    // the removal stands at every node (a removal hits only what is beside the rotation
    // carrying it)
    #[test]
    fn a_removal_merging_its_targets_earlier_rotation_stands() {
        let mut w = World::default();
        let a0 = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, A, 0, 0, boxed_to(&[A, B, X, T]));
        let x0 = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, X, 0, 0, boxed_to(&[A, B, X, T]));
        all_at(&mut w, &[a0, x0], 0);
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        assert!(matches!(&w.item(made[0]).kind, Kind::Rot { at, names, .. } if *at == a0 && names.contains(&x0)));
        all_at(&mut w, &made, 2);
        for n in [A, B, T, R1] {
            let j = judge(&w, n, 2);
            assert!(j.counting.contains(&w.removal) && j.heads == [w.removal].into(), "{}: {j:?}", NAMES[n]);
        }
    }

    // A rotation counts as held at a node of P only once its minter is known as a node: B holds
    // a revocation of A sealed as Z before any grant to Z, then the grant and A's removal of X
    // together. Placed when Z came to be known, the revocation follows the removal, which
    // leaves Z no node: B takes the removal (placed at its receipt, Z's revocation would come
    // first and win)
    #[test]
    fn a_rotation_is_placed_once_its_minter_is_known() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 5);
        to(&mut w, made[0], X, NEVER);
        let f = w.add_as(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: Some(A), covers: vec![], takes: vec![] }, X, Z, 0, 2, boxed_to(&[X]));
        all_at(&mut w, &[f], 3);
        let g = w.add_as(Kind::Grant { to: Z }, X, X, 0, 2, [false; N]);
        all_at(&mut w, &[g], 5);
        let j = judge(&w, B, 5);
        assert!(j.counting.contains(&w.removal) && !j.counting.contains(&f), "{j:?}");
    }

    // X holds the first epoch's key, so it makes a commit creating D again, pairing Z, and B
    // (offline) holds it before the removal. The removal's frontier lists the commits creating
    // D its maker held, which this one is not among: once B holds the removal, Z is no node
    #[test]
    fn a_commit_creating_d_made_again_pairs_no_one() {
        let mut w = World::default();
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 5);
        to(&mut w, made[0], X, NEVER);
        let c = w.add_as(Kind::Creation { to: Z }, X, Z, 0, 2, [false; N]);
        all_at(&mut w, &[c], 3);
        assert!(judge(&w, B, 3).roster.contains(&Z));
        let f = w.add_as(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, X, Z, 0, 6, boxed_to(&[X, Z]));
        all_at(&mut w, &[f], 7);
        for n in [A, B, T] {
            let j = judge(&w, n, 7);
            assert!(!j.roster.contains(&Z) && !j.counting.contains(&f), "{}: {j:?}", NAMES[n]);
        }
    }

    // A rotates (r1), then removes X (r3); B rotated unaware at the first epoch (r10) and takes
    // X's revocation of A (r6) first, so its next rotation (rb) supersedes A's line unnamed: a
    // rejection. A and T disregard rb (it stands with r6, which they do not take); once B's
    // user switches, B disregards rb too, so its merge names its own r10 only and rejects rb:
    // R1, on A's line, follows the merge and counts B's write at rb by its listing
    #[test]
    fn a_device_that_switches_carries_no_rejection_of_its_new_side() {
        let mut w = World::default();
        let r1 = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, A, 0, 0, boxed_to(&[A, B, X, T]));
        all_at(&mut w, &[r1], 0);
        let r10 = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, B, 0, 1, boxed_to(&[A, B, X, T]));
        all_at(&mut w, &[r10], 6);
        let made = act(&mut w, A, 2, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 3);
        for id in &made {
            to(&mut w, *id, B, 10);
            to(&mut w, *id, X, NEVER);
        }
        let r6 = fork(&mut w, 0, 3, Some(A));
        all_at(&mut w, &[r6], 4);
        let b = act(&mut w, B, 5, None, true);
        let rb = b[0];
        assert!(matches!(&w.item(rb).kind, Kind::Rot { sup, .. } if sup.contains(&r1)), "B answers A's line");
        all_at(&mut w, &b, 6);
        let cb = b[1];
        for n in [A, T] {
            let j = judge(&w, n, 6);
            assert!(j.counting.contains(&w.removal) && !j.counting.contains(&rb) && !j.valid.contains(&cb) && !j.cross, "{}: {j:?}", NAMES[n]);
        }
        w.switches.push((B, 11, w.removal));
        let m = act(&mut w, B, 12, None, false);
        assert!(matches!(&w.item(m[0]).kind, Kind::Rot { names, sup, .. } if !names.contains(&rb) && sup.contains(&rb)), "{:?}", w.item(m[0]));
        all_at(&mut w, &m, 13);
        for n in [A, B, T, R1] {
            let j = judge(&w, n, 13);
            assert!(j.counting.contains(&m[0]) && j.valid.contains(&cb) && j.heads.len() == 1, "{}: {j:?}", NAMES[n]);
        }
    }

    // B, offline, rotates unaware (rb0), then holds X's revocation of A (f) before A's removal of
    // X, so it takes f, and removes T unaware (rb1, signed at its own rb0, boxing B and X):
    // rb1 supersedes nothing of A's, but it takes f. A and T (on A's side) never follow it, so no
    // head of theirs is boxed to X; A answers it once, B answers once, and neither answers an
    // answer again. Once B's user switches, B follows A's line and its listing there saves its write
    // at rb1
    #[test]
    fn a_device_that_took_the_thiefs_revocation_is_that_side_whoever_signs() {
        let mut w = World::default();
        let rb0 = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None, covers: vec![], takes: vec![] }, B, 0, 0, boxed_to(&[A, B, X, T]));
        all_at(&mut w, &[rb0], 0);
        let made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        all_at(&mut w, &made, 2);
        for id in &made {
            to(&mut w, *id, B, 10);
            to(&mut w, *id, X, NEVER);
        }
        let f = fork(&mut w, 0, 2, Some(A));
        all_at(&mut w, &[f], 3);
        let b = act(&mut w, B, 4, Some(T), true);
        let (rb1, cb) = (b[0], b[1]);
        assert!(matches!(&w.item(rb1).kind, Kind::Rot { at, sup, takes, .. } if *at == rb0 && *sup == vec![rb0] && *takes == vec![f]), "{:?}", w.item(rb1));
        assert!(w.item(rb1).boxed[X] && !w.item(rb1).boxed[A]);
        all_at(&mut w, &b, 5);
        for n in [A, T] {
            let j = judge(&w, n, 5);
            assert!(j.counting.contains(&w.removal) && !j.counting.contains(&rb1) && !j.heads.contains(&rb1), "{}: {j:?}", NAMES[n]);
        }
        // the test reaches the case: read without what rb1 takes, A follows it, a head boxed to X
        let mut blind = w.clone();
        if let Kind::Rot { takes, .. } = &mut blind.items[rb1 as usize - 1].kind {
            takes.clear();
        }
        assert!(judge(&blind, A, 5).heads.contains(&rb1));
        let a1 = act(&mut w, A, 6, None, false);
        assert!(matches!(&w.item(a1[0]).kind, Kind::Rot { sup, names, .. } if sup.contains(&rb1) && names.is_empty()) && !w.item(a1[0]).boxed[X]);
        all_at(&mut w, &a1, 7);
        let b2 = act(&mut w, B, 11, None, false);
        assert!(matches!(&w.item(b2[0]).kind, Kind::Rot { sup, takes, .. } if sup.contains(&a1[0]) && *takes == vec![f]), "{:?}", w.item(b2[0]));
        all_at(&mut w, &b2, 12);
        let rots = |w: &World, made: &[u32]| made.iter().filter(|id| matches!(w.item(**id).kind, Kind::Rot { .. })).count();
        let a2 = act(&mut w, A, 13, None, false);
        let b3 = act(&mut w, B, 13, None, false);
        assert_eq!((rots(&w, &a2), rots(&w, &b3)), (0, 0), "one answer per line");
        for n in [A, T] {
            let j = judge(&w, n, 13);
            assert!(j.heads == [a1[0]].into() && j.warning, "{}: {j:?}", NAMES[n]);
        }
        w.switches.push((B, 14, w.removal));
        // A's answer already rejects B's old side: B owes no rotation, only its listing at A's head
        let m = act(&mut w, B, 15, None, false);
        assert!(rots(&w, &m) == 0 && m.iter().all(|id| w.item(*id).epoch == a1[0]), "{m:?}");
        all_at(&mut w, &m, 16);
        for n in [A, B, T, R1] {
            let j = judge(&w, n, 16);
            assert!(j.heads == [a1[0]].into() && j.valid.contains(&cb), "{}: {j:?}", NAMES[n]);
        }
    }
}
