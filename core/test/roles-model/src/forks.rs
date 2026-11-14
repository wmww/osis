//! Account forks and sides (spec/permissions.md §5.4): which of an account's signing-chain
//! rotations a node follows when the chain forks, as the first-seen rule. Independent of
//! `epochs` (no thing lists, cutoff or witnesses: commits at a closed epoch count only by
//! their author's own listing, the one word every honest node writes for itself).
//!
//! The rule under test. Each node places the held rotations in the order it came to hold them
//! (a rotation is held only with its chain and every fork it names, so a line is whole when
//! placed; a rotation the node's user chose has its line placed first). A placed rotation is
//! **disregarded** when a rotation on its line rejects or is rejected by a followed one, or
//! when a followed rotation is beside it (neither on the other's line); otherwise it is
//! followed with its whole line (a merge naming a disregarded fork brings it back). That is
//! the rule outside the account, where a removed device's fork looks like any other. A node of
//! the account reads who minted each rotation and whom each removes (the devices list): the
//! revocations take effect in the order it came to hold them, each only while its own line
//! stands (no rotation on it minted by a node an earlier revocation removed, beside that
//! removal), and it follows every rotation whose line stands: two of its devices' rotations
//! made at once both count, and a plain fork of a removed device never outweighs its removal. Followed rotations count; nothing else does (checked: the §5.4 rejection fixpoint
//! over the followed ones voids none). A disregarded rotation rejecting or rejected by a
//! counting one is the warning ("the account has forked"). Nothing reads `ts`; checks read
//! only what was placed before, so a later arrival never reopens a decision.
//!
//! Parties: account P with nodes A (honest, removes X at time 1), B (honest, may be offline
//! until it reconnects: unaware of the removal, it writes, rotates, boxes X), X (removed: from
//! time 1 it forks from any epoch whose seed it holds, any number of times, may revoke A or B
//! in its forks, may counter-merge, writes and lists its writes), T (a node of P that only
//! reads, offline through the fight); outside readers R1, R2 (R2's user may switch). Honest
//! policy (not an input of judgment): a node of P signs at its preferred head; whenever it
//! acts it rotates if it holds a counting head other than its preferred one whose seed it
//! holds (naming it: a merge; one it cannot sign at is left to a node that can, as superseding
//! it unnamed would reject a line it follows) or a rotation that does not count, that no
//! counting one rejects and that it has not superseded before (superseding it unnamed: a
//! rejection), and lists its own writes at every other epoch. A node of P on X's side
//! switches to the honest line in the settle phase (its user, told).
//!
//! Properties, at every node and every prefix of its receipts:
//! - Revocation holds: where A's removal of X counts, no rotation X made after it counts, and
//!   no write of X's does at a node outside P (at P's nodes a write at an open epoch an
//!   unaware sibling boxed to X counts until the merge: counted).
//! - No flip: outside P the followed set only grows (but at a switch); at P's nodes a removal
//!   followed stops counting only once a node on its rotation's line is removed (a removed
//!   node removes no one).
//! - No false alarm: with no rotation by X there is never a warning.
//! - Settled (everything delivered, honest nodes acted in turn): every node but X holds the warning
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
pub const N: usize = 6;
/// Nodes `0..OWN` are P's.
pub const OWN: usize = 4;
pub const NEVER: u32 = u32::MAX;

/// Negative controls: 1 forks stand (nothing is disregarded, the rule before this one); 2 P's
/// nodes judge as outsiders do (every beside rotation ends another).
pub static CONTROL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const NAMES: [&str; N] = ["A", "B", "X", "T", "R1", "R2"];

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Signed at `at` (and at each fork it names), superseding `sup`, accepting the forks
    /// `names`, carrying the removal of `removes` from the devices list (signed at `at`).
    Rot { at: u32, names: Vec<u32>, sup: Vec<u32>, removes: Option<usize> },
    Content,
    /// The author's word that its writes `names` count.
    Listing { names: Vec<u32> },
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub kind: Kind,
    pub author: usize,
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
}

impl World {
    fn item(&self, id: u32) -> &Item {
        &self.items[id as usize - 1]
    }
    fn rot(&self, id: u32) -> Option<(u32, &[u32], &[u32], Option<usize>)> {
        match &self.item(id).kind {
            Kind::Rot { at, names, sup, removes } => Some((*at, names, sup, *removes)),
            _ => None,
        }
    }
    pub fn add(&mut self, kind: Kind, author: usize, epoch: u32, t: u32, boxed: [bool; N]) -> u32 {
        let id = self.items.len() as u32 + 1;
        let mut recv = [NEVER; N];
        recv[author] = t;
        let hostile = author == X && self.removal != 0 && t >= self.item(self.removal).t;
        self.items.push(Item { id, kind, author, epoch, t, recv, hostile, boxed });
        id
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
    pub warning: bool,
    /// Held rotations a counting one rejects.
    pub rejected: BTreeSet<u32>,
    /// Writes (content, listings) that count.
    pub valid: BTreeSet<u32>,
    pub chosen: Option<u32>,
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
    // with its chain (a merge with every fork it names), and when it came to be held so
    let mut when: BTreeMap<u32, u32> = BTreeMap::new();
    when.insert(0, 0);
    loop {
        let more: Vec<(u32, u32)> = j.held.iter().filter(|id| !when.contains_key(id)).filter_map(|id| {
            let (at, names, ..) = w.rot(*id)?;
            std::iter::once(&at).chain(names).map(|p| when.get(p).copied()).try_fold(w.item(*id).recv[v], |a, t| t.map(|t| a.max(t))).map(|t| (*id, t))
        }).collect();
        if more.is_empty() {
            break;
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
    let mut order: Vec<u32> = j.chain.iter().copied().collect();
    order.sort_by_key(|r| (!j.chosen.is_some_and(|c| j.on(*r, c)), when[r], *r));
    // Placed in order. A rotation is held only with every rotation on its line, so lines are
    // whole when placed; rejections read only what was placed before, so a later arrival never
    // reopens an earlier decision.
    let mut placed: BTreeSet<u32> = BTreeSet::new();
    let mut followed: BTreeSet<u32> = BTreeSet::new();
    let control = CONTROL.load(std::sync::atomic::Ordering::Relaxed);
    if own && control == 0 {
        // a node of P reads who made each rotation and whom it removes. The revocations it
        // takes are a consistent set, built in the order it came to hold them: one is taken
        // when no revocation taken (nor itself) hits a rotation on its line nor it one on theirs (hits: removes
        // its minter, the rotation beside that removal). It follows every rotation whose line no
        // revocation taken hits and holds no revocation not taken
        let stands = |r: u32, removed: &BTreeSet<(usize, u32)>| {
            j0.line(r).iter().all(|q| {
                let m = w.item(*q).author;
                removed.iter().filter(|(y, _)| *y == m).all(|(_, e)| *e != 0 && j0.on(*q, *e))
            })
        };
        let mut taken: Vec<u32> = Vec::new();
        for &r in &order {
            let Some((at, _, _, Some(y))) = w.rot(r) else { continue };
            let mine: BTreeSet<(usize, u32)> = [(y, at)].into();
            let with: BTreeSet<(usize, u32)> = j.removed.union(&mine).copied().collect();
            if stands(r, &with) && taken.iter().all(|q| stands(*q, &mine)) {
                taken.push(r);
                j.removed.insert((y, at));
            }
        }
        let revocation = |q: &u32| matches!(w.rot(*q), Some((_, _, _, Some(_))));
        for &r in &order {
            if stands(r, &j.removed) && j0.line(r).iter().filter(|q| revocation(q)).all(|q| taken.contains(q)) {
                followed.insert(r);
            } else {
                j.disregarded.insert(r);
            }
        }
    }
    for &r in order.iter().filter(|_| !(own && control == 0)) {
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
    j.counting = status.into_iter().filter(|(_, s)| *s == Some(true)).map(|(r, _)| r).collect();
    if own {
        let counting = &j.counting;
        j.removed = j.counting.iter().filter_map(|q| w.rot(*q).and_then(|(at, _, _, y)| y.map(|y| (y, at)))).collect();
        let _ = counting;
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

/// Who holds the seed of epoch `e` at node `n` now.
fn has_seed(w: &World, j: &View, n: usize, e: u32) -> bool {
    e == 0 || j.chain.contains(&e) && w.item(e).boxed[n]
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
    // answered: a counting rotation rejects it, or this node superseded it already (a
    // rotation contested from below cannot be rejected from there: once is enough)
    let unanswered: Vec<u32> = j.chain.iter().copied().filter(|q| !j.counting.contains(q) && !j.rejected.contains(q) && !w.items.iter().any(|i| i.author == n && i.recv[n] <= now && matches!(&i.kind, Kind::Rot { sup, .. } if sup.contains(q)))).collect();
    let mut head = h;
    if removes.is_some() || !others.is_empty() || !unanswered.is_empty() {
        let names = others.clone();
        let sup: Vec<u32> = std::iter::once(h).chain(others.iter().copied()).chain(unanswered.iter().copied()).collect();
        let mut boxed = [false; N];
        for (m, b) in boxed.iter_mut().enumerate().take(OWN) {
            *b = !j.removed_node(m) && Some(m) != removes;
        }
        head = w.add(Kind::Rot { at: h, names, sup, removes }, n, h, now, boxed);
        made.push(head);
    }
    if write {
        made.push(w.add(Kind::Content, n, head, now, [false; N]));
    }
    let own: Vec<u32> = w.items.iter().filter(|i| i.author == n && i.epoch != head && !matches!(i.kind, Kind::Rot { .. }) && i.recv[n] <= now).map(|i| i.id).collect();
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
        for m in 0..N {
            if m == i.author {
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
        let id = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None }, X, 0, 0, bx);
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
                if rng.below(3) > 0 {
                    let removes = [None, Some(A), Some(B)][rng.below(3)];
                    let names: Vec<u32> = if rng.below(4) == 0 { held.iter().copied().filter(|x| *x != e && *x != 0).take(1).collect() } else { vec![] };
                    let mut sup = vec![e];
                    sup.extend(names.iter().copied());
                    let mut bx = [false; N];
                    bx[X] = true;
                    let r = w.add(Kind::Rot { at: e, names, sup, removes }, X, e, t, bx);
                    made.push(r);
                    if rng.below(2) == 0 {
                        made.push(w.add(Kind::Content, X, r, t, [false; N]));
                    }
                } else {
                    let c = w.add(Kind::Content, X, e, t, [false; N]);
                    made.push(c);
                    if e != 0 && rng.below(2) == 0 {
                        made.push(w.add(Kind::Listing { names: vec![c] }, X, e, t, [false; N]));
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
                    bx[..OWN].fill(true);
                    let r = w.add(Kind::Rot { at: h, names: vec![], sup: vec![h], removes: None }, B, h, t, bx);
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

/// Everything delivered at `settle`, then honest nodes of P act in turn (a node of P on X's
/// side first switches to A's removal, its user told) until none owes anything.
pub fn settle(w: &mut World, settle: u32) -> u32 {
    for i in w.items.iter_mut() {
        for r in i.recv.iter_mut() {
            *r = (*r).min(settle.max(i.t));
        }
    }
    let mut t = settle;
    for _ in 0..4 {
        for n in [A, B, T] {
            t += 1;
            let j = judge(w, n, t);
            if !j.counting.contains(&w.removal) {
                w.switches.push((n, t, w.removal));
            }
            if n == T {
                continue;
            }
            let made = act(w, n, t, None, false);
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
    /// A rotation arriving that stops another rejecting (one signed at its epoch on a line
    /// with the rejected): the warning goes until a rotation rejects again.
    pub warning_went: u64,
}

pub fn check(w0: &World, st: &mut Stats) {
    let mut w = w0.clone();
    let end = settle(&mut w, 12);
    st.worlds += 1;
    let x_rot = w.items.iter().any(|i| i.hostile && matches!(i.kind, Kind::Rot { .. }));
    let x_any_rot = w.items.iter().any(|i| i.author == X && matches!(i.kind, Kind::Rot { .. }));
    if x_rot {
        st.forks += 1;
    }
    if w.items.iter().any(|i| i.hostile && matches!(i.kind, Kind::Rot { removes: Some(_), .. })) {
        st.fights += 1;
    }
    let fail = |s: String, st: &mut Stats| {
        st.failures += 1;
        if st.fail.len() < 3 {
            st.fail.push((s, w.clone()));
        }
    };
    for v in 0..N {
        let mut prev: Option<View> = None;
        for now in 0..=end {
            let j = judge(&w, v, now);
            let switched = w.switches.iter().any(|(n, t, _)| *n == v && *t == now);
            if j.counting != j.followed && CONTROL.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                fail(format!("node {} at {now}: a followed rotation does not count {:?} {:?}", NAMES[v], j.followed, j.counting), st);
            }
            // revocation holds
            if j.counting.contains(&w.removal) {
                if let Some(r) = j.counting.iter().find(|r| w.item(**r).hostile) {
                    fail(format!("node {} at {now}: X's rotation {r} counts beside its removal", NAMES[v]), st);
                }
                if let Some(c) = j.valid.iter().find(|c| w.item(**c).hostile) {
                    if v < OWN {
                        st.own_window += 1;
                    } else {
                        fail(format!("node {} at {now}: X's write {c} counts beside its removal", NAMES[v]), st);
                    }
                }
            } else if j.valid.iter().any(|c| w.item(*c).hostile) && v >= OWN && j.held.contains(&w.removal) {
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
                    let remover_gone = |(y, e): &(usize, u32)| w.items.iter().any(|i| matches!(i.kind, Kind::Rot { at, removes: Some(z), .. } if at == *e && z == *y) && j.lines.get(&i.id).is_some_and(|l| l.iter().any(|q| j.removed_node(w.item(*q).author))));
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
        if j.disregarded.iter().any(|r| !w.item(*r).hostile && w.item(*r).author != X) {
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
        let honest: Vec<u32> = w.items.iter().filter(|i| i.author != X && matches!(i.kind, Kind::Content)).map(|i| i.id).collect();
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
        println!("  #{} {:?} by {} at e{} t{} recv [{}]{}", i.id, i.kind, NAMES[i.author], i.epoch, i.t, recv.join(" "), if i.hostile { " hostile" } else { "" });
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
        all.failures += st.failures;
        all.warning_went += st.warning_went;
        all.fail.extend(st.fail);
    }
    let fails = all.failures;
    let shown = std::mem::take(&mut all.fail);
    println!("forks: {fails} failing checks; {all:?}");
    for (s, w) in shown.iter().take(3) {
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
                println!("  {} t{now}: followed {:?} disregarded {:?} counting {:?} heads {:?} removed {:?} warn {} chosen {:?}", NAMES[v], j.followed, j.disregarded, j.counting, j.heads, j.removed, j.warning, j.chosen);
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
        w.add(Kind::Rot { at, names: vec![], sup: vec![at], removes }, X, at, t, bx)
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
        let b = w.add(Kind::Rot { at: 0, names: vec![], sup: vec![0], removes: None }, B, 0, 4, bx);
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
}
