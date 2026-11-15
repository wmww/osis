//! Account custody (notes/account-forks-design.md): seed custody follows holding, the chain is
//! D's roster, a merge is only a join. Greenfield: shares no code with `forks`.
//!
//! The design under test.
//! - **Custody.** A plain rotation boxes its fresh seed to each device on its maker's roster; any
//!   holder may re-seal a seed to a device (a box); a merge certificate boxes the merge seed to
//!   devices that cannot derive it. A node holds a seed iff it holds a box to its own key (X also
//!   Z's: a key it made up) or derives it (a merge epoch from every tip's seed), whether or not
//!   the item counts. Inner signatures open with the seed of the epoch signed at (or the item's
//!   own; a certificate's with any epoch it joins). Thing t's epochs are boxed to P at a P epoch and to its outside holder R1: a node of P
//!   opens a t epoch with any held seed of that P epoch. Judging decides only what counts and
//!   where a node signs and what it encrypts under.
//! - **The chain is the roster.** An epoch is its line: the downward-closed set of plain
//!   rotations it descends from (`Line`). The nodes on a line: the creation devices plus the
//!   additions minus the removals its rotations carry; a removal of y carried by r hits every
//!   rotation (and certificate) minted by y not on r's line, unless it descends from a re-add of y
//!   after r by a rotation not hit. A rotation stands under removals R iff every rotation on its
//!   line is minted by a node of the line before it and none is hit (R plus the removals on the
//!   line). D's roster at a node: the nodes of its preferred head's line under its taken
//!   revocations. No removal exists apart from its rotation.
//! - **Merges.** A merge carries nothing but the join: its epoch is the union of the joined
//!   lines, its seed derives from its tips' seeds (the plain rotations maximal on it), so only a
//!   holder of every tip's seed makes one, and two nodes merging the same tips mint one epoch.
//!   An epoch counts iff some certificate of it is followed (its maker a node not hit).
//! - **Sides (Tess's rule).** A node of P takes revocations (plain rotations carrying removals)
//!   in the order it came to hold them, its user's chosen line first: one is taken iff its line
//!   and every taken one's still stand with it. It follows each rotation whose line stands under
//!   the taken revocations, standing with no revocation it did not take (on its line or taken by
//!   a rotation on it), whose base epoch counts. An outside reader follows one line: placed in
//!   the order held (the chosen line first), a rotation or merge epoch is followed iff it
//!   descends from everything followed and nothing on its line rejects or is rejected by a
//!   followed rotation (a plain rotation rejects the rotations it answers, contested only from
//!   below). The warning: a held rotation outside the counting set rejecting or rejected by a
//!   counting one. A switch is the user's choice and sticks; nothing switches by itself.
//! - **Honest policy** (`act`): a node on its own roster holding its preferred head's seed owes a
//!   plain rotation for a removal, for an answer (a held rotation that does not stand or stands
//!   with a revocation not taken, on no line a counting rotation answered, that it has not
//!   answered), or for a taken revocation its preferred line does not carry when it cannot merge;
//!   then, following several heads and holding every tip's seed, it certifies the merge of them
//!   all; it re-seals its heads' tip seeds to roster devices it sees without them; after a
//!   removal it rotates t at the new epoch; it writes at its preferred head (on t under its
//!   newest t epoch) and lists its own writes at every other epoch.
//!
//! Parties: account P with A (removes X at tick 1, may rotate plainly at 0), B (may be offline,
//! unaware: rotates boxing X), C (may be apart: removes T at tick 1 and rotates t at that epoch,
//! the listing-cycle shape), X (the thief, holding every old key and every header: forks from
//! any epoch whose seed it holds, revokes A, B or C, signs as X or as Z, adds Z or itself, claims
//! to take a revocation (A's removal of it, or one it keeps to itself for good), answers honest
//! rotations, certifies merges of any epochs whose seeds it holds, re-seals its seeds to honest
//! nodes, writes and lists), T (reads only, offline through the fight); outside readers R1 (the
//! holder of t) and R2 (its user may switch). Schedules: random (one actor a tick, random
//! delays) and lockstep (every honest node acts on the same deliveries each tick). The settle
//! delivers everything but what X withholds; P's users on X's side switch to A's removal (A, C,
//! T at once, B in a given round or never) and the honest nodes act `ROUNDS` rounds.
//!
//! Properties, at every node and every prefix of its receipts (`check`):
//! - Held keys only grow (seeds and t epoch secrets).
//! - A switch takes: once a user's chosen rotation is held, on a line the node is a node of, it
//!   is followed and the preferred head descends from it (a node whose own removal it took first
//!   included).
//! - One roster source: an honest rotation leaves out of its boxes only devices removed by a
//!   revocation its maker took (one held, even with its chain, but not taken removes no one).
//! - Rotations are bounded: no honest node carries one event (removal, take, answer) in two plain
//!   rotations, none makes an empty one, and none rotates in the settle's last round.
//! - Merge secrecy: X holds the seed (or t epoch) of no epoch minted by an honest node that had
//!   taken X's removal; an honest rotation made where the removal is taken boxes neither X nor Z.
//! - Revocation holds, no flip (P's taken revocations and outsiders' followed rotations only
//!   grow but at a switch), no false alarm (no rotation by X, no warning), warned (a node holding
//!   a rotation X made after its removal is warned once settled).
//! - Settled, at every node on the honest side (A's removal taken, or followed outside P) and on
//!   its own roster: one head, the same at every such node, whose seed X lacks; every honest
//!   write counts (on t too, at P's nodes and R1: the thing listing opens); X's writes do not.
//! - Certificates of one epoch judge alike: dropping all but one held certificate of a merge
//!   epoch that stands there, received when the first was, changes nothing a node reads.
//!
//! Negative controls (`Control`), each expected to fail.

use crate::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub const A: usize = 0;
pub const B: usize = 1;
pub const C: usize = 2;
pub const X: usize = 3;
pub const T: usize = 4;
/// Outside readers; R1 also holds thing t (its holder outside P).
pub const R1: usize = 5;
pub const R2: usize = 6;
/// A key actor X makes up: its boxes open to X, it observes nothing.
pub const Z: usize = 7;
pub const N: usize = 8;
/// Nodes `0..OWN` are P's devices at creation.
pub const OWN: usize = 5;
pub const NEVER: u32 = u32::MAX;
pub const NAMES: [&str; N] = ["A", "B", "C", "X", "T", "R1", "R2", "Z"];
/// Rounds of the settle: B's latest switch (round 3) and the merges after it, and one more
/// to see nothing is owed.
pub const ROUNDS: u32 = 7;
/// The tick the settle delivers everything at.
pub const SETTLE: u32 = 12;

/// An epoch: the plain rotations it descends from, itself included (empty: the first epoch).
pub type Line = BTreeSet<u32>;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Control {
    #[default]
    None,
    /// Seeds come only from boxes in counting items: judgment gates custody.
    CustodyJudged,
    /// A held revocation acts on D's roster at a node where its maker is a node, apart from its
    /// rotation being held with its chain.
    RosterBare,
    /// A merge certificate mints its own epoch with a fresh seed.
    MergeRandom,
    /// A box of a t epoch to P at a closed P epoch is unread, as is one in a commit not counting.
    StaleShut,
    /// A merge carries its maker's takes and answers.
    MergeCarries,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Sched {
    #[default]
    Random,
    Lockstep,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Signed at epoch `at`; a fresh seed; carries `removes` and `adds` (D's membership),
    /// `takes` (revocations its maker took off its line; held only with them), `answers`
    /// (rotations it supersedes unnamed).
    Plain { at: Line, removes: Vec<usize>, adds: Vec<usize>, takes: Vec<u32>, answers: Vec<u32> },
    /// A certificate of the merge of `joined`, signed at `joined[0]`. `takes` and `answers` only
    /// under `MergeCarries`.
    Cert { joined: Vec<Line>, takes: Vec<u32>, answers: Vec<u32> },
    /// A box of epoch `e`'s seed to the device it is boxed to.
    Reseal { e: Line },
    Content,
    /// The author's word that its writes `names` count.
    Listing { names: Vec<u32> },
    /// A rotation of thing t, signed at P epoch `epoch` and boxing t's new epoch to P there and to
    /// R1 (`boxed[R1]`).
    TRot,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub kind: Kind,
    pub author: usize,
    /// Whose inner signature it carries.
    pub signer: usize,
    /// The P epoch it is signed at.
    pub epoch: Line,
    /// On thing t, encrypted under this t epoch (0 t's first, else a `TRot`'s id).
    pub on_t: Option<u32>,
    pub t: u32,
    pub recv: [u32; N],
    pub boxed: [bool; N],
    /// A plain rotation the world's script made (no policy event).
    pub script: bool,
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub items: Vec<Item>,
    /// (node, time, rotation): the node's user chooses that rotation's line.
    pub switches: Vec<(usize, u32, u32)>,
    /// A's removal of X.
    pub removal: u32,
    /// The settle round B's user switches in, when B is on X's side (`None`: never).
    pub b_switch: Option<u32>,
    /// What X keeps to itself for good.
    pub withheld: BTreeSet<u32>,
    pub control: Control,
    pub sched: Sched,
    /// Set by `settle`: an honest node rotated in the last round.
    pub restless: bool,
}

impl World {
    pub fn item(&self, id: u32) -> &Item {
        &self.items[id as usize - 1]
    }
    /// Bears a seed of its own (a plain rotation; a certificate under `MergeRandom`): an element
    /// of lines.
    pub fn seedy(&self, id: u32) -> bool {
        match self.item(id).kind {
            Kind::Plain { .. } => true,
            Kind::Cert { .. } => self.control == Control::MergeRandom,
            _ => false,
        }
    }
    /// A line element's epoch before it.
    pub fn base(&self, id: u32) -> Line {
        match &self.item(id).kind {
            Kind::Plain { at, .. } => at.clone(),
            Kind::Cert { joined, .. } => joined.iter().flatten().copied().collect(),
            _ => Line::new(),
        }
    }
    pub fn line(&self, id: u32) -> Line {
        let mut l = self.base(id);
        l.insert(id);
        l
    }
    /// The epoch a rotation or certificate mints.
    pub fn mints(&self, id: u32) -> Line {
        if self.seedy(id) {
            self.line(id)
        } else {
            self.base(id)
        }
    }
    pub fn is_rot(&self, id: u32) -> bool {
        matches!(self.item(id).kind, Kind::Plain { .. } | Kind::Cert { .. })
    }
    pub fn removes(&self, id: u32) -> &[usize] {
        match &self.item(id).kind {
            Kind::Plain { removes, .. } => removes,
            _ => &[],
        }
    }
    pub fn adds(&self, id: u32) -> &[usize] {
        match &self.item(id).kind {
            Kind::Plain { adds, .. } => adds,
            _ => &[],
        }
    }
    pub fn takes(&self, id: u32) -> &[u32] {
        match &self.item(id).kind {
            Kind::Plain { takes, .. } | Kind::Cert { takes, .. } => takes,
            _ => &[],
        }
    }
    pub fn answers(&self, id: u32) -> &[u32] {
        match &self.item(id).kind {
            Kind::Plain { answers, .. } | Kind::Cert { answers, .. } => answers,
            _ => &[],
        }
    }
    /// The plain rotations maximal on epoch `e`.
    pub fn tips(&self, e: &Line) -> Vec<u32> {
        e.iter().copied().filter(|m| !e.iter().any(|x| x != m && self.base(*x).contains(m))).collect()
    }
    /// Epoch `e` is minted by one line element (or is the first): its seed is boxed, not derived.
    pub fn single(&self, e: &Line) -> bool {
        self.tips(e).len() <= 1
    }
    /// Made by X after its removal.
    pub fn hostile(&self, id: u32) -> bool {
        let i = self.item(id);
        i.author == X && self.removal != 0 && i.t >= self.item(self.removal).t
    }
    pub fn add(&mut self, kind: Kind, author: usize, signer: usize, epoch: Line, on_t: Option<u32>, t: u32, boxed: [bool; N]) -> u32 {
        let id = self.items.len() as u32 + 1;
        let mut recv = [NEVER; N];
        recv[author] = t;
        self.items.push(Item { id, kind, author, signer, epoch, on_t, t, recv, boxed, script: false });
        id
    }
}

/// The seeds a node holds: epochs boxed to it (the first epoch at P's devices); a merge epoch's
/// derives from its tips'.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Keys {
    pub boxes: BTreeSet<Line>,
}

impl Keys {
    /// From the held items `ok` admits (every one but under `CustodyJudged`).
    fn of(w: &World, v: usize, held: &BTreeSet<u32>, ok: &dyn Fn(u32) -> bool) -> Keys {
        let mut boxes = BTreeSet::new();
        if v < OWN {
            boxes.insert(Line::new());
        }
        for id in held {
            let i = w.item(*id);
            if !(i.boxed[v] || v == X && i.boxed[Z]) || !ok(*id) {
                continue;
            }
            match &i.kind {
                Kind::Plain { .. } | Kind::Cert { .. } => {
                    boxes.insert(w.mints(*id));
                }
                Kind::Reseal { e } => {
                    boxes.insert(e.clone());
                }
                _ => {}
            }
        }
        Keys { boxes }
    }
    pub fn holds(&self, w: &World, e: &Line) -> bool {
        self.boxes.contains(e) || !w.single(e) && w.tips(e).iter().all(|m| self.boxes.contains(&w.line(*m)))
    }
}

/// One node's judgment at one time.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub held: BTreeSet<u32>,
    pub keys: Keys,
    /// t epochs whose secret it holds (0: t's first).
    pub tkeys: BTreeSet<u32>,
    /// Line elements held with their chain.
    pub chain: BTreeSet<u32>,
    /// Merge epochs held with their chain (a certificate and every element).
    pub merges: BTreeSet<Line>,
    pub followed: BTreeSet<u32>,
    pub counting: BTreeSet<Line>,
    pub heads: BTreeSet<Line>,
    pub preferred: Line,
    /// At P's nodes: the revocations taken, in order.
    pub taken: Vec<u32>,
    /// At P's nodes: whom it boxes.
    pub roster: BTreeSet<usize>,
    pub warning: bool,
    /// Held line elements a counting rotation rejects.
    pub rejected: BTreeSet<u32>,
    pub valid: BTreeSet<u32>,
    pub chosen: Option<u32>,
    /// Held certificates of chain-held merge epochs that stand here (at P's nodes: by a node of
    /// the line no taken removal hits).
    pub standing: BTreeSet<u32>,
    /// Inner signatures as read here (`None`: does not open).
    pub signers: BTreeMap<u32, Option<usize>>,
}

impl View {
    pub fn epoch_counts(&self, e: &Line) -> bool {
        self.counting.contains(e)
    }
    /// A node of P removed in its own view: it signs nothing.
    pub fn out(&self, v: usize) -> bool {
        v < OWN && !self.roster.contains(&v)
    }
    pub fn honest_side(&self, w: &World, v: usize) -> bool {
        if v < OWN {
            self.taken.contains(&w.removal)
        } else {
            self.followed.contains(&w.removal)
        }
    }
    /// A taken revocation is carried by line `l`: on it, or taken by a rotation on it.
    fn carries(&self, w: &World, l: &Line, r: u32) -> bool {
        l.contains(&r) || l.iter().any(|q| w.takes(*q).contains(&r))
    }
}

/// `judge` holding, of the certificates `certs` (of one epoch), only `keep`, received when the
/// first of them was.
pub fn judge_one_cert(w: &World, v: usize, now: u32, certs: &[u32], keep: u32) -> View {
    let mut w = w.clone();
    let first = certs.iter().map(|c| w.item(*c).recv[v]).min().unwrap_or(NEVER);
    for c in certs {
        w.items[*c as usize - 1].recv[v] = if *c == keep { first } else { NEVER };
    }
    judge(&w, v, now)
}

pub fn judge(w: &World, v: usize, now: u32) -> View {
    let held: BTreeSet<u32> = w.items.iter().filter(|i| i.recv[v] <= now).map(|i| i.id).collect();
    if w.control == Control::CustodyJudged {
        // judgment and custody one fixpoint: seeds only from items that count
        let mut keys = Keys::of(w, v, &held, &|_| false);
        let mut j = judge_with(w, v, now, &held, keys.clone());
        for _ in 0..8 {
            let next = Keys::of(w, v, &held, &|id| match &w.item(id).kind {
                Kind::Reseal { e } => j.epoch_counts(e),
                _ => j.epoch_counts(&w.mints(id)),
            });
            if next == keys {
                break;
            }
            keys = next;
            j = judge_with(w, v, now, &held, keys.clone());
        }
        return j;
    }
    judge_with(w, v, now, &held, Keys::of(w, v, &held, &|_| true))
}

fn judge_with(w: &World, v: usize, now: u32, held: &BTreeSet<u32>, keys: Keys) -> View {
    let own = v < OWN;
    let mut j = View { held: held.clone(), keys, ..View::default() };
    let recv = |id: u32| w.item(id).recv[v];
    // certificates held, by the epoch they certify (merge epochs only: a seedy certificate is a
    // line element)
    let mut certs: BTreeMap<Line, Vec<u32>> = BTreeMap::new();
    for id in held.iter().copied().filter(|id| matches!(w.item(*id).kind, Kind::Cert { .. }) && !w.seedy(*id)) {
        certs.entry(w.mints(id)).or_default().push(id);
    }
    // held with chain, in ID order (everything an item needs is older): when and depth
    let mut when: BTreeMap<u32, u32> = BTreeMap::new();
    let mut depth: BTreeMap<u32, usize> = BTreeMap::new();
    let epoch_when = |e: &Line, when: &BTreeMap<u32, u32>| -> Option<u32> {
        let mut t = 0;
        for x in e {
            t = t.max(*when.get(x)?);
        }
        if !w.single(e) {
            t = t.max(certs.get(e)?.iter().map(|c| recv(*c)).min()?);
        }
        Some(t)
    };
    for id in held.iter().copied().filter(|id| w.seedy(*id)) {
        let base = w.base(id);
        let Some(mut t) = epoch_when(&base, &when) else { continue };
        let mut ok = true;
        for q in w.takes(id) {
            match when.get(q) {
                Some(tq) => t = t.max(*tq),
                None => ok = false,
            }
        }
        if !ok {
            continue;
        }
        let d = base.iter().chain(w.takes(id)).map(|q| depth[q]).max().unwrap_or(0) + 1;
        when.insert(id, t.max(recv(id)));
        depth.insert(id, d);
    }
    j.chain = when.keys().copied().collect();
    j.merges = certs.keys().filter(|e| e.iter().all(|x| j.chain.contains(x))).cloned().collect();
    j.chosen = w.switches.iter().filter(|(n, t, c)| *n == v && *t <= now && held.contains(c) && j.chain.contains(c)).last().map(|x| x.2);
    // inner signatures: open with the seed of the epoch signed at, or the item's own
    for id in held {
        let i = w.item(*id);
        // a certificate carries its maker's inner signature under each epoch it joins
        let joined = match &i.kind {
            Kind::Cert { joined, .. } => joined.iter().any(|e| j.keys.holds(w, e)),
            _ => false,
        };
        let opens = joined || j.keys.holds(w, &i.epoch) || w.is_rot(*id) && j.keys.holds(w, &w.mints(*id));
        j.signers.insert(*id, opens.then_some(i.signer));
    }
    // order of placing: the chosen line (and at P's nodes what it stands with) first, then when
    // held, depth, ID
    let mut needs: BTreeSet<u32> = BTreeSet::new();
    if let Some(c) = j.chosen {
        let mut work = vec![c];
        while let Some(x) = work.pop() {
            for p in w.line(x).into_iter().chain(if own { w.takes(x).to_vec() } else { vec![] }) {
                if j.chain.contains(&p) && needs.insert(p) {
                    work.push(p);
                }
            }
        }
    }
    let key = |x: u32| (!needs.contains(&x), when[&x], depth[&x], x);
    let mut order: Vec<u32> = j.chain.iter().copied().collect();
    order.sort_by_key(|x| key(*x));
    let pos: BTreeMap<u32, usize> = order.iter().enumerate().map(|(i, x)| (*x, i)).collect();
    // rejections: (rejector's epoch, the epoch it is signed at, rejected element); contested only
    // from below: no rejection of an element descending from the rejector's signed-at epoch
    let mut rejs: Vec<(Line, Line, u32)> = vec![];
    for id in held.iter().copied() {
        let rejector = match w.item(id).kind {
            Kind::Plain { .. } if j.chain.contains(&id) => w.line(id),
            Kind::Cert { .. } if j.chain.contains(&id) || j.merges.contains(&w.mints(id)) => w.mints(id),
            _ => continue,
        };
        for q in w.answers(id).iter().copied().filter(|q| j.chain.contains(q)) {
            let lq = w.line(q);
            if !w.item(id).epoch.is_subset(&lq) && !rejector.contains(&q) {
                rejs.push((rejector.clone(), w.item(id).epoch.clone(), q));
            }
        }
    }
    if own {
        judge_own(w, &mut j, &certs, &order, &depth);
    } else {
        // one line, grown in the order held: a rotation or merge epoch is followed iff it
        // descends from everything followed and no rejection runs between its line and it
        let mut placeables: Vec<(Line, (bool, u32, usize, u32))> = order.iter().map(|x| (w.line(*x), key(*x))).collect();
        for e in &j.merges {
            let t = epoch_when(e, &when).unwrap();
            let d = e.iter().map(|x| depth[x]).max().unwrap_or(0) + 1;
            let first = !e.iter().all(|x| needs.contains(x));
            placeables.push((e.clone(), (first, t, d, u32::MAX)));
        }
        placeables.sort_by_key(|p| p.1);
        let mut fol: Line = Line::new();
        for (p, _) in placeables {
            if !fol.is_subset(&p) {
                continue;
            }
            let rejected = rejs.iter().any(|(r, _, q)| r.is_subset(&p) && fol.contains(q) || r.is_subset(&fol) && p.contains(q));
            if !rejected {
                fol = p;
            }
        }
        j.followed = fol;
        j.standing = j.merges.iter().flat_map(|e| certs[e].iter().copied()).collect();
        j.counting.insert(Line::new());
        for x in &j.followed {
            j.counting.insert(w.line(*x));
        }
        for e in &j.merges {
            if e.is_subset(&j.followed) {
                j.counting.insert(e.clone());
            }
        }
    }
    j.heads = j.counting.iter().filter(|h| !j.counting.iter().any(|x| x != *h && h.is_subset(x))).cloned().collect();
    // preferred: of two lines, the one holding the earliest-placed element on exactly one
    let cands: Vec<Line> = j.heads.iter().filter(|h| j.chosen.is_none_or(|c| h.contains(&c))).cloned().collect();
    let cands = if cands.is_empty() { j.heads.iter().cloned().collect() } else { cands };
    j.preferred = cands.into_iter().min_by(|a, b| match a.symmetric_difference(b).min_by_key(|x| pos[x]) {
        Some(x) if a.contains(x) => std::cmp::Ordering::Less,
        Some(_) => std::cmp::Ordering::Greater,
        None => std::cmp::Ordering::Equal,
    }).unwrap_or_default();
    if own {
        j.roster = roster(w, &j, &j.preferred.clone());
    }
    // the warning: a rejection between a counting rotation and one not counting
    let fol_elem = |q: u32| j.counting.contains(&w.line(q));
    j.rejected = rejs.iter().filter(|(r, _, _)| j.counting.contains(r)).map(|(_, _, q)| *q).collect();
    j.warning = rejs.iter().any(|(r, _, q)| j.counting.contains(r) != fol_elem(*q));
    // t epochs and writes: custody first, then validity (a least fixpoint; under `StaleShut` the
    // t epochs open only at open P epochs or by a counting commit, one fixpoint with validity)
    let mut valid: BTreeSet<u32> = BTreeSet::new();
    loop {
        let tkeys: BTreeSet<u32> = std::iter::once(0).filter(|_| own || v == R1).chain(held.iter().copied().filter(|k| {
            let i = w.item(*k);
            matches!(i.kind, Kind::TRot) && (v == R1 || i.author == v || j.keys.holds(w, &i.epoch) && (w.control != Control::StaleShut || j.heads.contains(&i.epoch) || valid.contains(k)))
        })).collect();
        let mut named: BTreeSet<u32> = BTreeSet::new();
        let mut next: BTreeSet<u32>;
        loop {
            next = held.iter().copied().filter(|id| {
                let i = w.item(*id);
                matches!(i.kind, Kind::Content | Kind::Listing { .. } | Kind::TRot) && i.on_t.is_none_or(|te| tkeys.contains(&te)) && (j.heads.contains(&i.epoch) || named.contains(id))
            }).collect();
            let more: Vec<u32> = next.iter().filter_map(|id| match &w.item(*id).kind {
                Kind::Listing { names } => Some(names.iter().copied().filter(|n| w.item(*n).author == w.item(*id).author).collect::<Vec<_>>()),
                _ => None,
            }).flatten().filter(|n| !named.contains(n)).collect();
            if more.is_empty() {
                break;
            }
            named.extend(more);
        }
        j.tkeys = tkeys;
        if next == valid {
            break;
        }
        valid = next;
    }
    j.valid = valid;
    j
}

/// The P-node rule: removals read from the chain alone.
struct Rule<'a> {
    w: &'a World,
    sig: &'a BTreeMap<u32, Option<usize>>,
}

impl Rule<'_> {
    fn sig(&self, id: u32) -> Option<usize> {
        self.sig.get(&id).copied().flatten()
    }
    /// Removal r (of its node y) hits element q minted by y: q is not on r's line before it,
    /// and descends from no re-add of y after r by a rotation not hit.
    fn hit(&self, q: u32, rs: &[u32]) -> bool {
        let Some(y) = self.sig(q) else { return false };
        let lq = self.w.line(q);
        rs.iter().any(|r| *r != q && self.w.removes(*r).contains(&y) && !self.w.base(*r).contains(&q) && !self.readd(y, *r, &lq, rs))
    }
    fn readd(&self, y: usize, r: u32, l: &Line, rs: &[u32]) -> bool {
        l.iter().any(|a| self.w.adds(*a).contains(&y) && self.w.base(*a).contains(&r) && self.sig(*a) != Some(y) && !self.hit(*a, rs))
    }
    /// A certificate of merge epoch `e` by its maker is hit by removal r beside it.
    fn cert_hit(&self, c: u32, e: &Line, rs: &[u32]) -> bool {
        let Some(y) = self.sig(c) else { return true };
        rs.iter().any(|r| self.w.removes(*r).contains(&y) && !e.contains(r) && !e.is_subset(&self.w.base(*r)))
    }
    /// The nodes on line `l`: creation devices and additions (by rotations not hit), less
    /// removals carried on it without a re-add after.
    fn nodes(&self, l: &Line, rs: &[u32]) -> BTreeSet<usize> {
        (0..N).filter(|y| *y < OWN || *y == Z).filter(|y| {
            let added = *y < OWN || l.iter().any(|a| self.w.adds(*a).contains(y) && self.sig(*a) != Some(*y) && !self.hit(*a, rs));
            added && l.iter().filter(|r| self.w.removes(**r).contains(y)).all(|r| self.readd(*y, *r, l, rs))
        }).collect()
    }
    fn revs(&self, l: &Line) -> Vec<u32> {
        l.iter().copied().filter(|q| !self.w.removes(*q).is_empty()).collect()
    }
    /// Every element on `l` minted by a node of the line before it, none hit by `rs` or the
    /// removals on `l`.
    fn stands(&self, l: &Line, rs: &[u32]) -> bool {
        let mut all: Vec<u32> = rs.to_vec();
        all.extend(self.revs(l));
        l.iter().all(|q| self.sig(*q).is_some_and(|m| self.nodes(&self.w.base(*q), &all).contains(&m)) && !self.hit(*q, &all))
    }
    /// The revocations element x stands with: on its line, and taken by an element on it.
    fn with(&self, x: u32) -> BTreeSet<u32> {
        self.w.line(x).iter().flat_map(|q| std::iter::once(*q).filter(|q| !self.w.removes(*q).is_empty()).chain(self.w.takes(*q).iter().copied())).collect()
    }
}

fn judge_own(w: &World, j: &mut View, certs: &BTreeMap<Line, Vec<u32>>, order: &[u32], depth: &BTreeMap<u32, usize>) {
    let rule = Rule { w, sig: &j.signers };
    // revocations taken in the order held: each while its line and every taken one's stand
    let mut taken: Vec<u32> = vec![];
    for &r in order.iter().filter(|r| !w.removes(**r).is_empty()) {
        let mut with = taken.clone();
        with.push(r);
        if rule.stands(&w.line(r), &with) && taken.iter().all(|q| rule.stands(&w.line(*q), &with)) && rule.with(r).iter().all(|q| *q == r || taken.contains(q)) {
            taken.push(r);
        }
    }
    let mut by_depth: Vec<u32> = order.to_vec();
    by_depth.sort_by_key(|x| (depth[x], *x));
    let mut followed: BTreeSet<u32> = BTreeSet::new();
    let cert_ok = |c: u32, e: &Line| rule.sig(c).is_some_and(|m| rule.nodes(e, &[taken.clone(), rule.revs(e)].concat()).contains(&m)) && !rule.cert_hit(c, e, &taken) && w.takes(c).iter().all(|q| taken.contains(q));
    let counts = |e: &Line, followed: &BTreeSet<u32>| -> bool {
        e.is_empty() || e.is_subset(followed) && (w.single(e) || certs.get(e).is_some_and(|cs| cs.iter().any(|c| cert_ok(*c, e))))
    };
    for x in by_depth {
        if counts(&w.base(x), &followed) && rule.stands(&w.line(x), &taken) && rule.with(x).iter().all(|q| taken.contains(q)) {
            followed.insert(x);
        }
    }
    j.counting.insert(Line::new());
    for x in &followed {
        j.counting.insert(w.line(*x));
    }
    for e in j.merges.clone() {
        if counts(&e, &followed) {
            j.counting.insert(e.clone());
        }
        j.standing.extend(certs[&e].iter().copied().filter(|c| cert_ok(*c, &e)));
    }
    j.followed = followed;
    j.taken = taken;
}

/// D's roster at a node of P: the nodes of line `l` under the taken revocations (a removal taken
/// off `l` holds unless `l` re-adds after it). Control `RosterBare`: also less every node a held
/// revocation by a node of `l` removes, its rotation held with its chain or not.
fn roster(w: &World, j: &View, l: &Line) -> BTreeSet<usize> {
    let rule = Rule { w, sig: &j.signers };
    let mut nodes = rule.nodes(l, &j.taken);
    for r in &j.taken {
        for y in w.removes(*r) {
            if !l.contains(r) && !rule.readd(*y, *r, l, &j.taken) {
                nodes.remove(y);
            }
        }
    }
    if w.control == Control::RosterBare {
        let makers = nodes.clone();
        for id in &j.held {
            if rule.sig(*id).is_some_and(|m| makers.contains(&m)) {
                for y in w.removes(*id) {
                    nodes.remove(y);
                }
            }
        }
    }
    nodes
}

/// Who `n` (judging `j`) sees holding epoch `e`'s seed: boxed to it in an item `n` holds, or
/// derivable from those.
fn seen_holding(w: &World, j: &View, d: usize, e: &Line) -> bool {
    let boxed = |e: &Line| e.is_empty() && d < OWN || j.held.iter().any(|id| {
        let i = w.item(*id);
        i.boxed[d] && match &i.kind {
            Kind::Plain { .. } | Kind::Cert { .. } => w.mints(*id) == *e,
            Kind::Reseal { e: f } => f == e,
            _ => false,
        }
    });
    boxed(e) || !w.single(e) && w.tips(e).iter().all(|m| boxed(&w.line(*m)))
}

/// The t epoch node `n` encrypts under: of the t epochs it holds whose rotation counts there or
/// is its own, the newest.
fn t_epoch(w: &World, j: &View, n: usize) -> Option<u32> {
    j.tkeys.iter().copied().filter(|k| *k == 0 || j.valid.contains(k) || w.item(*k).author == n).max()
}

/// Honest node `n` acts at `now` (the policy in the module doc). `removes`: the world's script
/// has it remove that node.
pub fn act(w: &mut World, n: usize, now: u32, removes: Option<usize>, write: bool) -> Vec<u32> {
    let mut made = vec![];
    let j = judge(w, n, now);
    if j.out(n) || !j.keys.holds(w, &j.preferred) {
        return made;
    }
    let h = j.preferred.clone();
    let rule = Rule { w, sig: &j.signers };
    // answers due: held rotations that do not stand or stand with a revocation not taken, on no
    // line a counting rotation answered, not answered by this node before
    let answered_by_me: BTreeSet<u32> = j.held.iter().filter(|i| w.item(**i).author == n).flat_map(|i| w.answers(*i).to_vec()).collect();
    let answers: Vec<u32> = j.chain.iter().copied().filter(|q| {
        !j.followed.contains(q) && (!rule.stands(&w.line(*q), &j.taken) || !rule.with(*q).iter().all(|r| j.taken.contains(r))) && !w.line(*q).iter().any(|x| j.rejected.contains(x)) && !answered_by_me.contains(q)
    }).collect();
    let union: Line = j.heads.iter().flatten().copied().collect();
    let mergeable = j.heads.len() > 1 && j.keys.holds(w, &union) || w.control == Control::MergeRandom && j.heads.len() > 1 && j.heads.iter().all(|e| j.keys.holds(w, e));
    let takes: Vec<u32> = j.taken.iter().copied().filter(|r| !j.carries(w, &h, *r)).collect();
    let carries = w.control == Control::MergeCarries && mergeable && removes.is_none();
    let mut boxed = [false; N];
    for m in &j.roster {
        boxed[*m] = Some(*m) != removes;
    }
    let mut head = h.clone();
    let mut rotated_for_removal = false;
    if !carries && (removes.is_some() || !answers.is_empty() || !takes.is_empty() && !mergeable) {
        let id = w.add(Kind::Plain { at: h.clone(), removes: removes.into_iter().collect(), adds: vec![], takes: takes.clone(), answers: answers.clone() }, n, n, h.clone(), None, now, boxed);
        made.push(id);
        head = w.line(id);
        rotated_for_removal = removes.is_some();
    }
    // the merge of every head, by a holder of every tip's seed
    let j2 = if made.is_empty() { j.clone() } else { judge(w, n, now) };
    let union: Line = j2.heads.iter().flatten().copied().collect();
    let can = if w.control == Control::MergeRandom { j2.heads.iter().all(|e| j2.keys.holds(w, e)) } else { j2.keys.holds(w, &union) };
    if j2.heads.len() > 1 && can {
        let mut joined: Vec<Line> = vec![j2.preferred.clone()];
        joined.extend(j2.heads.iter().filter(|e| **e != j2.preferred).cloned());
        let e: Line = union.clone();
        let mut bx = [false; N];
        for m in &j2.roster {
            bx[*m] = w.control == Control::MergeRandom || !seen_holding(w, &j2, *m, &e);
        }
        let (tk, an) = if carries { (takes.clone(), answers.clone()) } else { (vec![], vec![]) };
        let id = w.add(Kind::Cert { joined, takes: tk, answers: an }, n, n, j2.preferred.clone(), None, now, bx);
        made.push(id);
        head = w.mints(id);
    }
    // re-seals: its heads' tip seeds to roster devices it sees without them
    let j3 = if made.is_empty() { j2 } else { judge(w, n, now) };
    let mine: BTreeSet<Line> = j3.held.iter().filter_map(|i| match &w.item(*i).kind {
        Kind::Reseal { e } if w.item(*i).author == n => Some(e.clone()),
        _ => None,
    }).collect();
    for hd in j3.heads.clone() {
        for m in w.tips(&hd) {
            let e = w.line(m);
            if !j3.keys.holds(w, &e) || mine.contains(&e) {
                continue;
            }
            let lacking: Vec<usize> = j3.roster.iter().copied().filter(|d| *d != n && *d < OWN && !seen_holding(w, &j3, *d, &e)).collect();
            for d in lacking {
                let mut bx = [false; N];
                bx[d] = true;
                made.push(w.add(Kind::Reseal { e: e.clone() }, n, n, head.clone(), None, now, bx));
            }
        }
    }
    // after a removal, t rotates at the new epoch (boxed to P there and to R1)
    let j4 = if made.is_empty() { j3 } else { judge(w, n, now) };
    if rotated_for_removal {
        let prev = t_epoch(w, &j4, n);
        let mut bx = [false; N];
        bx[R1] = true;
        made.push(w.add(Kind::TRot, n, n, head.clone(), prev, now, bx));
    }
    if write {
        made.push(w.add(Kind::Content, n, n, head.clone(), None, now, [false; N]));
        let j5 = judge(w, n, now);
        if let Some(te) = t_epoch(w, &j5, n) {
            made.push(w.add(Kind::Content, n, n, head.clone(), Some(te), now, [false; N]));
        }
    }
    // listings: its own writes at every other epoch, at the head (P's, and t's under its newest
    // t epoch), unless an own listing at the head already names them
    let jl = judge(w, n, now);
    for on_t in [false, true] {
        let names: Vec<u32> = jl.held.iter().copied().filter(|i| {
            let it = w.item(*i);
            it.author == n && it.epoch != head && it.on_t.is_some() == on_t && (matches!(it.kind, Kind::Content) || on_t && matches!(it.kind, Kind::TRot))
        }).collect();
        if names.is_empty() {
            continue;
        }
        let done = jl.held.iter().any(|i| {
            let it = w.item(*i);
            it.author == n && it.epoch == head && it.on_t.is_some() == on_t && matches!(&it.kind, Kind::Listing { names: ns } if *ns == names)
        });
        if done {
            continue;
        }
        let te = if on_t { t_epoch(w, &jl, n) } else { None };
        if on_t && te.is_none() {
            continue;
        }
        made.push(w.add(Kind::Listing { names }, n, n, head.clone(), te, now, [false; N]));
    }
    made
}

/// Whether item `id` reaches observer `m` at all: t's items reach P's devices and R1 only;
/// nothing reaches Z.
fn reaches(w: &World, id: u32, m: usize) -> bool {
    let i = w.item(id);
    m != Z && m != i.author && !(m == R2 && (i.on_t.is_some() || matches!(i.kind, Kind::TRot)))
}

/// The choices a world is built from: random, or enumerated (`Odometer`).
pub trait Pick {
    fn pick(&mut self, n: usize) -> usize;
}

impl Pick for Rng {
    fn pick(&mut self, n: usize) -> usize {
        if n <= 1 {
            0
        } else {
            self.below(n)
        }
    }
}

/// Every choice sequence in turn: `pick` replays the script and extends it with zeros, `advance`
/// moves to the next sequence (choices before `fixed` stay).
#[derive(Default, Clone)]
pub struct Odometer {
    pub script: Vec<usize>,
    arity: Vec<usize>,
    pos: usize,
    fixed: usize,
}

impl Odometer {
    pub fn with_prefix(prefix: Vec<usize>) -> Odometer {
        let fixed = prefix.len();
        Odometer { arity: vec![usize::MAX; fixed], script: prefix, pos: 0, fixed }
    }
    pub fn advance(&mut self) -> bool {
        self.script.truncate(self.pos);
        self.arity.truncate(self.pos);
        self.pos = 0;
        while self.script.len() > self.fixed {
            let i = self.script.len() - 1;
            if self.script[i] + 1 < self.arity[i] {
                self.script[i] += 1;
                return true;
            }
            self.script.pop();
            self.arity.pop();
        }
        false
    }
}

impl Pick for Odometer {
    fn pick(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        let i = self.pos;
        self.pos += 1;
        if i == self.script.len() {
            self.script.push(0);
            self.arity.push(n);
        } else if i >= self.fixed {
            self.arity[i] = n;
        }
        self.script[i].min(n - 1)
    }
}

/// Deliver `ids` made at `now`: honest items to everyone at `now + 1` in lockstep and in the
/// small family, else at a random delay each (or not before the settle); X's items by a pattern
/// (everyone next tick; only B, C and R1 next tick; no one before the settle). Never before an
/// offline node's (or offline author's) `floor`.
fn deliver(w: &mut World, ids: &[u32], p: &mut impl Pick, now: u32, floor: &[u32; N], small: bool) {
    for id in ids.iter().copied() {
        let author = w.item(id).author;
        if w.withheld.contains(&id) {
            continue;
        }
        let pattern = if author == X { p.pick(3) } else { 0 };
        for m in 0..N {
            if !reaches(w, id, m) {
                continue;
            }
            let at = if author == X {
                match pattern {
                    0 => now + 1,
                    1 if m == B || m == C || m == R1 => now + 1,
                    _ => NEVER,
                }
            } else if w.sched == Sched::Lockstep || small {
                now + 1
            } else {
                match p.pick(6) {
                    0 => NEVER,
                    k => now + k as u32,
                }
            };
            w.items[id as usize - 1].recv[m] = if at == NEVER { NEVER } else { at.max(floor[m]).max(floor[author]) };
        }
    }
}

/// X's move at `now` (it holds every header, every old key and whatever is boxed to it or Z).
fn x_step(w: &mut World, p: &mut impl Pick, now: u32, small: bool) -> Vec<u32> {
    let j = judge(w, X, now);
    let mut eps: Vec<Line> = std::iter::once(Line::new()).chain(j.chain.iter().map(|x| w.line(*x))).chain(j.merges.iter().cloned()).filter(|e| j.keys.holds(w, e)).collect();
    eps.dedup();
    let e = eps[p.pick(eps.len())].clone();
    let honest_rots: Vec<u32> = j.chain.iter().copied().filter(|q| w.item(*q).author != X && !e.contains(q)).collect();
    let revs: Vec<u32> = j.chain.iter().copied().filter(|q| !w.removes(*q).is_empty()).collect();
    let mut made = vec![];
    let all_p: [bool; N] = std::array::from_fn(|m| m < OWN);
    let only = |ms: &[usize]| -> [bool; N] { std::array::from_fn(|m| ms.contains(&m)) };
    let fork = |w: &mut World, removes: Vec<usize>, adds: Vec<usize>, signer: usize, takes: Vec<u32>, answers: Vec<u32>, boxed: [bool; N]| -> u32 {
        w.add(Kind::Plain { at: e.clone(), removes, adds, takes, answers }, X, signer, e.clone(), None, now, boxed)
    };
    let action = if small { [1, 2, 3, 4, 5, 6, 8, 9, 10][p.pick(9)] } else { [0, 8, 9, 10][p.pick(4)] };
    match action {
        // forks, from a menu (small) or composed (random)
        0..=7 => {
            let (removes, adds, signer, takes, answers, boxed): (Vec<usize>, Vec<usize>, usize, Vec<u32>, Vec<u32>, [bool; N]) = if small {
                match action {
                    0 => (vec![], vec![], X, vec![], vec![], all_p),
                    1 => (vec![A], vec![], X, vec![], vec![], all_p),
                    2 => (vec![B], vec![], X, vec![], vec![], only(&[X, B])),
                    3 => (vec![A], vec![], X, vec![w.removal], vec![], all_p),
                    4 => {
                        let k = fork(w, vec![A], vec![], X, vec![], vec![], only(&[X]));
                        w.withheld.insert(k);
                        (vec![A], vec![], X, vec![k], vec![], all_p)
                    }
                    5 => (vec![], vec![Z], Z, vec![], vec![], all_p),
                    6 => (vec![], vec![], X, vec![], honest_rots.last().into_iter().copied().collect(), all_p),
                    _ => (vec![A], vec![X], Z, vec![], vec![], all_p),
                }
            } else {
                let removes = [vec![], vec![A], vec![B], vec![C]][p.pick(4)].clone();
                let signer = [X, Z][p.pick(2)];
                let adds = [vec![], vec![Z], vec![X]][p.pick(3)].clone();
                let takes = match p.pick(4) {
                    0 if !revs.is_empty() => vec![revs[p.pick(revs.len())]],
                    1 => vec![w.removal],
                    2 => {
                        let k = fork(w, vec![A], vec![], X, vec![], vec![], only(&[X]));
                        w.withheld.insert(k);
                        vec![k]
                    }
                    _ => vec![],
                };
                let answers = if p.pick(3) == 0 { honest_rots.last().into_iter().copied().collect() } else { vec![] };
                let boxed = [all_p, only(&[X]), only(&[X, B]), only(&[X, A, C])][p.pick(4)];
                (removes, adds, signer, takes, answers, boxed)
            };
            let r = fork(w, removes, adds, signer, takes, answers, boxed);
            made.push(r);
            if small || p.pick(2) == 0 {
                made.push(w.add(Kind::Content, X, X, w.line(r), None, now, [false; N]));
            }
        }
        // a write at e, on P or on a t epoch it holds, maybe listed
        8 => {
            let te = j.tkeys.iter().copied().max();
            let on_t = if p.pick(2) == 0 { te } else { None };
            let c = w.add(Kind::Content, X, X, e.clone(), on_t, now, [false; N]);
            made.push(c);
            if p.pick(2) == 0 {
                made.push(w.add(Kind::Listing { names: vec![c] }, X, X, e.clone(), on_t, now, [false; N]));
            }
        }
        // a certificate of the merge of two epochs whose seeds it holds, not on one line
        9 => {
            let pairs: Vec<(Line, Line)> = eps.iter().flat_map(|a| eps.iter().map(move |b| (a.clone(), b.clone()))).filter(|(a, b)| a < b && !a.is_subset(b) && !b.is_subset(a)).collect();
            if !pairs.is_empty() {
                let (a, b) = pairs[p.pick(pairs.len())].clone();
                let signer = [X, Z][p.pick(2)];
                made.push(w.add(Kind::Cert { joined: vec![a.clone(), b], takes: vec![], answers: vec![] }, X, signer, a, None, now, all_p));
            }
        }
        // a re-seal of a seed it holds to an honest node
        _ => {
            let to = [A, B, C, T][p.pick(4)];
            if !e.is_empty() {
                made.push(w.add(Kind::Reseal { e: e.clone() }, X, X, e.clone(), None, now, only(&[to])));
            }
        }
    }
    made
}

/// A world: setup choices, then the fight (`steps` ticks), ending before the settle.
/// `small`: the enumerable family (fewer, coarser choices).
pub fn gen_world(p: &mut impl Pick, small: bool, control: Control) -> World {
    let mut w = World { control, ..World::default() };
    w.sched = [Sched::Random, Sched::Lockstep][p.pick(2)];
    w.b_switch = if small { [None, Some(1)][p.pick(2)] } else { [None, Some(0), Some(1), Some(3)][p.pick(4)] };
    let mut floor = [0u32; N];
    if p.pick(2) == 1 {
        floor[B] = if small { 4 } else { 3 + p.pick(5) as u32 };
    }
    // C: online; apart, removing T at 1 (and rotating t there); apart
    let c_mode = p.pick(if small { 2 } else { 3 });
    if c_mode > 0 {
        floor[C] = if small { 4 } else { 3 + p.pick(5) as u32 };
    }
    // T reads only, offline through the fight
    floor[T] = SETTLE;
    let x0 = p.pick(2) == 1;
    let a0 = !small && p.pick(2) == 1;
    let steps = if small { 2 } else { 3 + p.pick(5) as u32 };
    // tick 0: X's own rotation (made offline, boxing P), A's plain rotation, A writes
    if x0 {
        let id = w.add(Kind::Plain { at: Line::new(), removes: vec![], adds: vec![], takes: vec![], answers: vec![] }, X, X, Line::new(), None, 0, std::array::from_fn(|m| m < OWN));
        w.items[id as usize - 1].script = true;
        deliver(&mut w, &[id], p, 0, &floor, small);
    }
    if a0 {
        let id = w.add(Kind::Plain { at: Line::new(), removes: vec![], adds: vec![], takes: vec![], answers: vec![] }, A, A, Line::new(), None, 0, std::array::from_fn(|m| m < OWN));
        w.items[id as usize - 1].script = true;
        deliver(&mut w, &[id], p, 0, &floor, small);
    }
    let ids = act(&mut w, A, 0, None, true);
    deliver(&mut w, &ids, p, 0, &floor, small);
    // tick 1: A removes X; C, apart, removes T
    let ids = act(&mut w, A, 1, Some(X), true);
    w.removal = ids[0];
    deliver(&mut w, &ids, p, 1, &floor, small);
    // the removal reaching B and C only in the settle (they may take X's revocation first)
    if p.pick(2) == 1 {
        for id in &ids {
            for m in [B, C] {
                w.items[*id as usize - 1].recv[m] = NEVER;
            }
        }
    }
    if c_mode == 1 {
        let ids = act(&mut w, C, 1, Some(T), true);
        deliver(&mut w, &ids, p, 1, &floor, small);
    }
    for t in 2..2 + steps {
        let mut made = vec![];
        // the small family: X moves at tick 2, the honest nodes at tick 3
        let x_acts = match (small, w.sched) {
            (true, _) => t == 2,
            (false, Sched::Random) => p.pick(5) < 2,
            (false, Sched::Lockstep) => p.pick(2) == 0,
        };
        if x_acts {
            let ids = x_step(&mut w, p, t, small);
            deliver(&mut w, &ids, p, t, &floor, small);
        }
        let actors: Vec<usize> = match w.sched {
            Sched::Lockstep => vec![A, B, C],
            _ if small && t == 2 => vec![],
            Sched::Random if x_acts => vec![],
            Sched::Random => vec![[A, B, C][p.pick(3)]],
        };
        for n in actors {
            let mut ids = act(&mut w, n, t, None, true);
            // B, unaware of X's removal, may rotate plainly (boxing X)
            if n == B && p.pick(2) == 0 {
                let j = judge(&w, B, t);
                if !j.taken.contains(&w.removal) && !j.out(B) && j.keys.holds(&w, &j.preferred) {
                    let bx: [bool; N] = std::array::from_fn(|m| j.roster.contains(&m));
                    let h = j.preferred.clone();
                    let r = w.add(Kind::Plain { at: h.clone(), removes: vec![], adds: vec![], takes: vec![], answers: vec![] }, B, B, h, None, t, bx);
                    w.items[r as usize - 1].script = true;
                    ids.push(r);
                    ids.push(w.add(Kind::Content, B, B, w.line(r), None, t, [false; N]));
                }
            }
            made.extend(ids);
        }
        deliver(&mut w, &made, p, t, &floor, small);
        if !small && p.pick(6) == 0 {
            // R2's user switches to any rotation it holds
            let j = judge(&w, R2, t);
            if !j.chain.is_empty() {
                let c = *j.chain.iter().nth(p.pick(j.chain.len())).unwrap();
                w.switches.push((R2, t, c));
            }
        }
    }
    w
}

pub fn random_world(rng: &mut Rng, control: Control) -> World {
    gen_world(rng, false, control)
}

/// Everything but what X withholds delivered at `SETTLE`; P's users on X's side switch to A's
/// removal (A, C, T at once, B in round `b_switch` or never); the honest nodes act `ROUNDS`
/// rounds, in turn (random) or on the same deliveries (lockstep). Returns the last tick.
pub fn settle(w: &mut World) -> u32 {
    for id in 1..=w.items.len() as u32 {
        if w.withheld.contains(&id) {
            continue;
        }
        for m in 0..N {
            if reaches(w, id, m) {
                let i = &mut w.items[id as usize - 1];
                i.recv[m] = i.recv[m].min(SETTLE.max(i.t));
            }
        }
    }
    let mut t = SETTLE;
    let switch = |w: &mut World, n: usize, round: u32, t: u32| {
        let j = judge(w, n, t);
        let user = if n == B { w.b_switch.is_some_and(|k| round >= k) } else { true };
        if user && !j.taken.contains(&w.removal) && j.chosen != Some(w.removal) {
            w.switches.push((n, t, w.removal));
        }
    };
    for round in 0..ROUNDS {
        let mut made: Vec<u32> = vec![];
        match w.sched {
            Sched::Random => {
                for n in [A, B, C, T] {
                    t += 1;
                    switch(w, n, round, t);
                    if n == T {
                        continue;
                    }
                    let ids = act(w, n, t, None, false);
                    for id in &ids {
                        for m in 0..N {
                            if reaches(w, *id, m) {
                                w.items[*id as usize - 1].recv[m] = t;
                            }
                        }
                    }
                    made.extend(ids);
                }
            }
            Sched::Lockstep => {
                t += 1;
                for n in [A, B, C, T] {
                    switch(w, n, round, t);
                }
                for n in [A, B, C] {
                    made.extend(act(w, n, t, None, false));
                }
                for id in &made {
                    for m in 0..N {
                        if reaches(w, *id, m) {
                            w.items[*id as usize - 1].recv[m] = t + 1;
                        }
                    }
                }
                t += 1;
            }
        }
        if round + 1 == ROUNDS && made.iter().any(|id| w.is_rot(*id)) {
            w.restless = true;
        }
    }
    t + 1
}

#[derive(Default, Debug)]
pub struct Stats {
    pub worlds: u64,
    pub failures: u64,
    /// Failing checks by kind.
    pub kinds: BTreeMap<String, u64>,
    pub fail: Vec<(String, World)>,
    pub lockstep: u64,
    /// Worlds where a node of P took X's revocation first; of those, one whose own removal.
    pub x_side: u64,
    pub own_removal: u64,
    /// Worlds where a switch was checked taking; settled with B on X's side for good.
    pub switched: u64,
    pub b_stays: u64,
    /// Worlds with two honest certificates of one epoch; with merges of several tips.
    pub twin_certs: u64,
    pub merges: u64,
    /// Worlds with C's t rotation at its epoch closed by a merge, and C's writes on t counting at A.
    pub cycle: u64,
    pub withheld: u64,
    pub forged: u64,
    /// Node-prefixes of P where X's write at an open epoch an unaware sibling boxed to X counts.
    pub own_window: u64,
    /// Worlds where X holds an honest seed minted by an unaware node (the stated limit).
    pub unaware_leak: u64,
}

impl Stats {
    pub fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        self.failures += o.failures;
        for (k, n) in o.kinds {
            *self.kinds.entry(k).or_default() += n;
        }
        if self.fail.len() < 4 {
            self.fail.extend(o.fail.into_iter().take(4 - self.fail.len()));
        }
        self.lockstep += o.lockstep;
        self.x_side += o.x_side;
        self.own_removal += o.own_removal;
        self.switched += o.switched;
        self.b_stays += o.b_stays;
        self.twin_certs += o.twin_certs;
        self.merges += o.merges;
        self.cycle += o.cycle;
        self.withheld += o.withheld;
        self.forged += o.forged;
        self.own_window += o.own_window;
        self.unaware_leak += o.unaware_leak;
    }
    pub fn print(&self, name: &str) {
        println!("{name}: {} worlds, {} failing checks", self.worlds, self.failures);
        for (k, n) in &self.kinds {
            println!("  {k}: {n}");
        }
        println!(
            "  lockstep {}, X's side taken first {} (own removal {}), switches checked {}, B on X's side for good {}, twin certificates {}, multi-tip merges {}, listing-cycle shape {}, withholding {}, signing as Z {}, own window {}, unaware-sibling seeds at X {}",
            self.lockstep, self.x_side, self.own_removal, self.switched, self.b_stays, self.twin_certs, self.merges, self.cycle, self.withheld, self.forged, self.own_window, self.unaware_leak
        );
    }
}

/// Every seed and t epoch secret a view holds, over the world's epochs.
fn secrets(w: &World, j: &View) -> (BTreeSet<Line>, BTreeSet<u32>) {
    let mut s: BTreeSet<Line> = BTreeSet::new();
    if j.keys.holds(w, &Line::new()) {
        s.insert(Line::new());
    }
    for i in &w.items {
        if w.is_rot(i.id) && j.keys.holds(w, &w.mints(i.id)) {
            s.insert(w.mints(i.id));
        }
    }
    (s, j.tkeys.clone())
}

pub fn check(w0: &World, st: &mut Stats) {
    let mut w = w0.clone();
    let end = settle(&mut w);
    st.worlds += 1;
    let w = &w;
    let mut fails: Vec<String> = vec![];
    if w.sched == Sched::Lockstep {
        st.lockstep += 1;
    }
    if !w.withheld.is_empty() {
        st.withheld += 1;
    }
    if w.items.iter().any(|i| i.signer == Z) {
        st.forged += 1;
    }
    if w.restless {
        fails.push(format!("restless: honest nodes still rotating after {ROUNDS} settle rounds"));
    }
    let honest = |id: u32| w.item(id).author != X;
    // views at every node and prefix
    // (a view changes only at a receipt or a switch)
    let changes = |v: usize, t: u32| t == 0 || w.items.iter().any(|i| i.recv[v] == t) || w.switches.iter().any(|s| s.0 == v && s.1 == t);
    let views: Vec<Vec<View>> = (0..N).map(|v| {
        let mut vs: Vec<View> = vec![];
        for t in (0..=end).filter(|_| v != Z) {
            let j = if changes(v, t) { judge(w, v, t) } else { vs[t as usize - 1].clone() };
            vs.push(j);
        }
        vs
    }).collect();
    let fin = |v: usize| &views[v][end as usize];
    // bounded: one event per node per plain rotation, none empty
    for n in [A, B, C] {
        let mut seen: BTreeSet<(u8, u32)> = BTreeSet::new();
        for i in w.items.iter().filter(|i| i.author == n && matches!(i.kind, Kind::Plain { .. }) && !i.script) {
            let evs: Vec<(u8, u32)> = w.removes(i.id).iter().map(|y| (0, *y as u32)).chain(w.takes(i.id).iter().map(|r| (1, *r))).chain(w.answers(i.id).iter().map(|q| (2, *q))).collect();
            if evs.is_empty() {
                fails.push(format!("bounded: node {}'s rotation {} carries no event", NAMES[n], i.id));
            }
            for e in evs {
                if !seen.insert(e) {
                    fails.push(format!("bounded: node {} carries event {e:?} twice (rotation {})", NAMES[n], i.id));
                }
            }
        }
    }
    // per honest rotation: one roster source, seeds away from X, merge secrecy
    let x_secrets = secrets(w, fin(X));
    for i in w.items.iter().filter(|i| [A, B, C].contains(&i.author) && (w.is_rot(i.id) || matches!(i.kind, Kind::TRot))) {
        let j = &views[i.author][i.t as usize];
        let aware = j.taken.contains(&w.removal);
        if matches!(i.kind, Kind::Plain { .. }) {
            for d in 0..OWN {
                let taken_removal = j.taken.iter().any(|r| w.removes(*r).contains(&d));
                if !i.boxed[d] && !w.removes(i.id).contains(&d) && !taken_removal {
                    fails.push(format!("roster: node {}'s rotation {} leaves out {} with no removal of it taken", NAMES[i.author], i.id, NAMES[d]));
                }
            }
            if aware && (i.boxed[X] || i.boxed[Z]) {
                fails.push(format!("secrecy: node {}'s rotation {} boxes X or Z where X's removal is taken", NAMES[i.author], i.id));
            }
        }
        let leaks = if matches!(i.kind, Kind::TRot) { x_secrets.1.contains(&i.id) } else { x_secrets.0.contains(&w.mints(i.id)) };
        if leaks {
            if aware {
                fails.push(format!("secrecy: X holds the secret of {} by node {}, made where X's removal is taken", i.id, NAMES[i.author]));
            } else {
                st.unaware_leak += 1;
            }
        }
    }
    let x_rot_any = w.items.iter().any(|i| i.author == X && w.is_rot(i.id));
    if (0..OWN).any(|v| v != X && views[v].iter().any(|j| !j.taken.contains(&w.removal) && j.taken.iter().any(|r| w.item(*r).author == X))) {
        st.x_side += 1;
    }
    if [A, B, C].iter().any(|v| views[*v].iter().any(|j| j.out(*v))) {
        st.own_removal += 1;
    }
    let mut switched = false;
    for v in (0..N).filter(|v| *v != Z) {
        let vs = &views[v];
        for now in 0..=end as usize {
            let j = &vs[now];
            let is_switch = w.switches.iter().any(|(n, t, _)| *n == v && *t as usize == now);
            // held keys only grow
            if now > 0 {
                let (a, ta) = secrets(w, &vs[now - 1]);
                let (b, tb) = secrets(w, j);
                if !a.is_subset(&b) || !ta.is_subset(&tb) {
                    fails.push(format!("custody: node {} at {now} lost a key", NAMES[v]));
                }
                let p = &vs[now - 1];
                if !is_switch {
                    if v < OWN && !p.taken.iter().all(|r| j.taken.contains(r)) {
                        fails.push(format!("flip: node {} at {now} dropped a taken revocation {:?} -> {:?}", NAMES[v], p.taken, j.taken));
                    }
                    if v >= OWN && !p.followed.is_subset(&j.followed) {
                        fails.push(format!("flip: node {} at {now} followed shrank", NAMES[v]));
                    }
                }
            }
            // a switch takes
            if let Some(c) = j.chosen {
                let rule = Rule { w, sig: &j.signers };
                let node = v >= OWN || rule.nodes(&w.line(c), &[]).contains(&v);
                if node {
                    if v < OWN && c == w.removal {
                        switched = true;
                    }
                    if !j.followed.contains(&c) || !j.preferred.contains(&c) {
                        fails.push(format!("switch: node {} at {now} chose {c} but does not follow it (preferred {:?})", NAMES[v], j.preferred));
                    }
                }
            }
            // revocation holds
            if j.honest_side(w, v) {
                if let Some(r) = j.followed.iter().find(|r| w.hostile(**r)) {
                    fails.push(format!("revocation: node {} at {now} follows X's rotation {r}", NAMES[v]));
                }
                if let Some(c) = j.valid.iter().find(|c| w.hostile(**c)) {
                    if v < OWN {
                        st.own_window += 1;
                    } else if !w.item(*c).epoch.iter().any(|q| !w.item(*q).boxed[X] && w.item(*q).author != X) && fin(v).valid.contains(c) {
                        fails.push(format!("revocation: node {} counts X's write {c} once settled", NAMES[v]));
                    }
                }
            }
            if !x_rot_any && j.warning && !j.out(v) {
                fails.push(format!("alarm: node {} at {now} warned with no rotation by X", NAMES[v]));
            }
        }
        let j = fin(v);
        if v == X || j.out(v) {
            continue;
        }
        if j.chain.iter().any(|r| w.hostile(*r)) && !j.warning {
            fails.push(format!("warned: node {} settled holding X's rotation without the warning", NAMES[v]));
        }
        if !j.honest_side(w, v) {
            if v == B {
                st.b_stays += 1;
            }
            continue;
        }
        if j.heads.len() != 1 {
            fails.push(format!("settled: node {} with heads {:?}", NAMES[v], j.heads));
        }
        if j.heads.iter().any(|h| x_secrets.0.contains(h) && !h.is_empty()) {
            fails.push(format!("secrecy: node {} settled at a head whose seed X holds", NAMES[v]));
        }
        if let Some(c) = j.valid.iter().find(|c| w.hostile(**c) && matches!(w.item(**c).kind, Kind::Content)) {
            fails.push(format!("settled: node {} counts X's write {c}", NAMES[v]));
        }
        let reads_t = v < OWN || v == R1;
        for i in w.items.iter().filter(|i| honest(i.id) && matches!(i.kind, Kind::Content) && (reads_t || i.on_t.is_none())) {
            let a = fin(i.author);
            if a.out(i.author) || !a.honest_side(w, i.author) {
                continue;
            }
            if !j.valid.contains(&i.id) {
                fails.push(format!("writes: node {} settled without {}'s write {}{}", NAMES[v], NAMES[i.author], i.id, if i.on_t.is_some() { " on t" } else { "" }));
            }
        }
    }
    if switched {
        st.switched += 1;
    }
    // honest nodes on one side agree
    let sides: BTreeSet<BTreeSet<Line>> = (0..N).filter(|v| *v != Z && *v != X).filter(|v| !fin(*v).out(*v) && fin(*v).honest_side(w, *v)).map(|v| fin(v).heads.clone()).collect();
    if sides.len() > 1 {
        fails.push(format!("agree: honest-side nodes settled on different heads {sides:?}"));
    }
    // certificates of one epoch judge alike
    let mut by_epoch: BTreeMap<Line, Vec<u32>> = BTreeMap::new();
    for i in w.items.iter().filter(|i| matches!(i.kind, Kind::Cert { .. }) && honest(i.id) && !w.seedy(i.id)) {
        by_epoch.entry(w.mints(i.id)).or_default().push(i.id);
    }
    for cs in by_epoch.values().filter(|cs| cs.len() > 1) {
        st.twin_certs += 1;
        for v in (0..N).filter(|v| *v != Z && *v != X) {
            let j = fin(v);
            let cs: Vec<u32> = cs.iter().copied().filter(|c| j.standing.contains(c)).collect();
            if cs.len() < 2 {
                continue;
            }
            for keep in &cs {
                let k = judge_one_cert(w, v, end, &cs, *keep);
                if k.counting != j.counting || k.warning != j.warning || k.valid != j.valid {
                    fails.push(format!("certs: node {} reads otherwise holding only certificate {keep} of {cs:?}", NAMES[v]));
                }
            }
        }
    }
    if !by_epoch.is_empty() {
        st.merges += 1;
    }
    // the listing-cycle shape: C's t rotation at its own epoch, closed at A once settled
    if let Some(tc) = w.items.iter().find(|i| i.author == C && matches!(i.kind, Kind::TRot)) {
        let a = fin(A);
        if !a.heads.contains(&tc.epoch) && a.tkeys.contains(&tc.id) {
            st.cycle += 1;
        }
    }
    for f in fails {
        st.failures += 1;
        let kind = f.split(':').next().unwrap_or("").to_string();
        let n = st.kinds.entry(kind).or_default();
        *n += 1;
        if *n == 1 && st.fail.len() < 4 {
            st.fail.push((f, w0.clone()));
        }
    }
}

pub fn print_world(w: &World) {
    println!("  {:?} {:?} b_switch {:?} removal {} withheld {:?}", w.sched, w.control, w.b_switch, w.removal, w.withheld);
    for i in &w.items {
        let recv: Vec<String> = i.recv.iter().map(|r| if *r == NEVER { "-".into() } else { r.to_string() }).collect();
        let bx: Vec<&str> = (0..N).filter(|m| i.boxed[*m]).map(|m| NAMES[m]).collect();
        println!("  #{} {:?} by {} as {} at {:?}{} t{} recv [{}] boxed {:?}", i.id, i.kind, NAMES[i.author], NAMES[i.signer], i.epoch, i.on_t.map(|t| format!(" on t@{t}")).unwrap_or_default(), i.t, recv.join(" "), bx);
    }
    for (n, t, c) in &w.switches {
        println!("  switch {} at {t} to {c}", NAMES[*n]);
    }
}

/// Prints a failing world's views at the node its message names (every node with
/// `CUSTODY_ALL`).
pub fn explain(msg: &str, w0: &World) {
    println!("FAIL {msg}");
    print_world(w0);
    let mut w = w0.clone();
    let end = settle(&mut w);
    println!("  after settle:");
    for i in &w.items[w0.items.len()..] {
        println!("  #{} {:?} by {} at {:?}{} t{} boxed {:?}", i.id, i.kind, NAMES[i.author], i.epoch, i.on_t.map(|t| format!(" on t@{t}")).unwrap_or_default(), i.t, (0..N).filter(|m| i.boxed[*m]).map(|m| NAMES[m]).collect::<Vec<_>>());
    }
    for (n, t, c) in &w.switches {
        println!("  switch {} at {t} to {c}", NAMES[*n]);
    }
    let vs: Vec<usize> = (0..N).filter(|v| *v != Z && (std::env::var_os("CUSTODY_ALL").is_some() || msg.contains(&format!("node {} ", NAMES[*v])))).collect();
    for v in vs {
        for now in 0..=end {
            let j = judge(&w, v, now);
            println!("  {} t{now}: taken {:?} followed {:?} heads {:?} pref {:?} roster {:?} warn {} chosen {:?} tkeys {:?}", NAMES[v], j.taken, j.followed, j.heads, j.preferred, j.roster, j.warning, j.chosen, j.tkeys);
        }
    }
}

fn parallel(f: impl Fn(usize, usize, &mut Stats) + Sync) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let out: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads).map(|th| {
            let f = &f;
            s.spawn(move || {
                let mut st = Stats::default();
                f(th, threads, &mut st);
                st
            })
        }).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for st in out {
        all.merge(st);
    }
    all
}

/// The setup prefixes of the small family (`gen_world`'s first choices: schedule, B's switch,
/// B offline, C apart removing T, X's tick-0 rotation).
pub fn small_prefixes() -> Vec<Vec<usize>> {
    let arities = [2, 2, 2, 2, 2];
    // (then the removal late to B and C or not, and the fight)
    let mut out = vec![vec![]];
    for a in arities {
        out = out.into_iter().flat_map(|p: Vec<usize>| (0..a).map(move |k| [p.clone(), vec![k]].concat())).collect();
    }
    out
}

/// Every world of the small family under setup prefix `prefix`.
pub fn small_family(prefix: Vec<usize>, control: Control, st: &mut Stats) {
    let mut od = Odometer::with_prefix(prefix);
    loop {
        let w = gen_world(&mut od, true, control);
        check(&w, st);
        if !od.advance() {
            break;
        }
    }
}

/// `random` worlds (`samples`, split over every core), or `exh` (the small family).
pub fn run(samples: u64, mode: &str, control: Control) -> u64 {
    let st = if mode == "exh" {
        let prefixes = small_prefixes();
        let next = std::sync::atomic::AtomicUsize::new(0);
        parallel(|_, _, st| loop {
            let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Some(p) = prefixes.get(k) else { break };
            small_family(p.clone(), control, st);
        })
    } else {
        parallel(|th, threads, st| {
            let mut rng = Rng(0xc057 ^ (th as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            for _ in 0..samples / threads as u64 {
                check(&random_world(&mut rng, control), st);
            }
        })
    };
    st.print(&format!("custody {mode} {control:?}"));
    for (m, w) in st.fail.iter().take(2) {
        explain(m, w);
    }
    st.failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_random(n: u64, seed: u64, control: Control) -> Stats {
        let mut rng = Rng(seed);
        let mut st = Stats::default();
        for _ in 0..n {
            check(&random_world(&mut rng, control), &mut st);
        }
        st
    }

    fn plain(w: &mut World, author: usize, signer: usize, at: &Line, removes: &[usize], takes: &[u32], boxed: &[usize], t: u32) -> u32 {
        let bx: [bool; N] = std::array::from_fn(|m| boxed.contains(&m));
        let id = w.add(Kind::Plain { at: at.clone(), removes: removes.to_vec(), adds: vec![], takes: takes.to_vec(), answers: vec![] }, author, signer, at.clone(), None, t, bx);
        w.items[id as usize - 1].script = true;
        id
    }
    fn to(w: &mut World, ids: &[u32], ns: &[usize], t: u32) {
        for id in ids {
            for n in ns {
                w.items[*id as usize - 1].recv[*n] = t;
            }
        }
    }
    const PS: [usize; 5] = [A, B, C, X, T];
    const HONEST: [usize; 4] = [A, B, C, T];

    /// B takes X's revocation of A first (A's line minted from A's own plain rotation a0, which
    /// that revocation hits), then its user switches to A's removal: B reads A's line by the seeds
    /// boxed to it, follows it and signs at its head. With seeds only from counting rotations
    /// (`CustodyJudged`) B never opens a0's seed, reads A's removal as minted by no one, and the
    /// switch cannot take.
    fn switch_back(control: Control, revoked: usize) -> (View, View) {
        let mut w = World { control, ..World::default() };
        let a0 = plain(&mut w, A, A, &Line::new(), &[], &[], &PS, 0);
        let l0 = w.line(a0);
        let a = plain(&mut w, A, A, &l0, &[X], &[], &HONEST, 1);
        w.removal = a;
        let rx = plain(&mut w, X, X, &Line::new(), &[revoked], &[], &[X, B], 1);
        to(&mut w, &[rx], &[B], 2);
        to(&mut w, &[a0, a], &[B], 3);
        let before = judge(&w, B, 3);
        w.switches.push((B, 4, a));
        (before, judge(&w, B, 4))
    }

    #[test]
    fn a_switch_back_opens_by_the_boxes_held() {
        let (before, after) = switch_back(Control::None, A);
        assert_eq!(before.taken.len(), 1, "B took X's revocation first");
        assert!(!before.taken.contains(&2));
        assert!(after.followed.contains(&2) && after.preferred.contains(&2), "{after:?}");
        assert!(after.roster.contains(&B) && !after.roster.contains(&X));
        let (_, judged) = switch_back(Control::CustodyJudged, A);
        assert!(!judged.followed.contains(&2), "custody-judged: the switch takes");
    }

    #[test]
    fn a_node_that_took_its_own_removal_first_switches_back() {
        let (before, after) = switch_back(Control::None, B);
        assert!(before.out(B), "B took X's revocation of itself");
        assert!(!after.out(B) && after.followed.contains(&2) && after.preferred.contains(&2), "{after:?}");
    }

    /// A removes X while C, apart, removes T; both merge the two heads on the same deliveries:
    /// one epoch, one head. With fresh merge seeds (`MergeRandom`) the two merges are two heads,
    /// and merging those makes two more.
    fn lockstep_merge(control: Control) -> (World, usize) {
        let mut w = World { control, sched: Sched::Lockstep, ..World::default() };
        let a = plain(&mut w, A, A, &Line::new(), &[X], &[], &[A, B, C, T], 1);
        w.removal = a;
        let c = plain(&mut w, C, C, &Line::new(), &[T], &[], &[A, B, C, X], 1);
        to(&mut w, &[a, c], &[A, B, C], 2);
        let mut rounds = 0;
        for t in [2, 3, 4] {
            let made: Vec<u32> = [A, C].iter().flat_map(|n| act(&mut w, *n, t, None, false)).collect();
            if made.iter().any(|id| w.is_rot(*id)) {
                rounds += 1;
            }
            to(&mut w, &made, &[A, B, C], t + 1);
        }
        (w, rounds)
    }

    #[test]
    fn merges_made_at_once_of_one_tip_set_are_one_epoch() {
        let (w, rounds) = lockstep_merge(Control::None);
        assert_eq!(rounds, 1);
        let heads = judge(&w, A, 5).heads;
        assert_eq!(heads.len(), 1);
        let certs: Vec<u32> = w.items.iter().filter(|i| matches!(i.kind, Kind::Cert { .. })).map(|i| i.id).collect();
        assert_eq!(certs.len(), 2);
        for v in [A, B, C, R1] {
            let full = judge(&w, v, 5);
            for keep in &certs {
                let k = judge_one_cert(&w, v, 5, &certs, *keep);
                assert!(k.counting == full.counting && k.warning == full.warning, "{}", NAMES[v]);
            }
        }
        assert_eq!(judge(&w, C, 5).heads, heads);
        let (w, rounds) = lockstep_merge(Control::MergeRandom);
        assert_eq!(rounds, 3, "merge-random: lockstep merges settle");
        assert!(judge(&w, A, 5).heads.len() > 1);
    }

    /// C, apart, removes T and rotates t at its own epoch c, writing on t under it; A merges c
    /// closed. C's listing at the merge names its writes, under the t epoch boxed to P at c: A
    /// opens it with c's seed, closed or not, so C's writes count. Reading only boxes at open
    /// epochs (`StaleShut`), the listing waits on the t rotation counting, which waits on the
    /// listing.
    fn thing_listing(control: Control) -> (World, u32) {
        let mut w = World { control, sched: Sched::Lockstep, ..World::default() };
        let mut made = act(&mut w, A, 1, Some(X), false);
        w.removal = made[0];
        let cs = act(&mut w, C, 1, Some(T), true);
        let w1 = *cs.iter().find(|id| w.item(**id).on_t.is_some() && matches!(w.item(**id).kind, Kind::Content)).unwrap();
        made.extend(cs);
        // A merges at once on receipt, so c is closed at A before it reads C's t epoch
        to(&mut w, &made, &[A, C, R1], 2);
        for t in [2, 3, 4] {
            let made: Vec<u32> = [A, C].iter().flat_map(|n| act(&mut w, *n, t, None, false)).collect();
            to(&mut w, &made, &[A, C, R1], t + 1);
        }
        (w, w1)
    }

    #[test]
    fn a_siblings_thing_listing_opens_at_a_closed_epoch() {
        let (w, w1) = thing_listing(Control::None);
        let j = judge(&w, A, 5);
        assert_eq!(j.heads.len(), 1);
        assert!(!j.heads.contains(&w.item(w1).epoch), "C's epoch is closed at A");
        assert!(j.valid.contains(&w1), "{j:?}");
        assert!(judge(&w, R1, 5).valid.contains(&w1));
        let (w, w1) = thing_listing(Control::StaleShut);
        assert!(!judge(&w, A, 5).valid.contains(&w1), "stale-shut: the listing opens");
    }

    /// X revokes A in a rotation taking one it keeps to itself, so no node holds it with its
    /// chain: unaware B, removing T, still boxes A. Acting on held removals apart from their
    /// rotations (`RosterBare`), B boxes A out.
    fn bare(control: Control) -> [bool; N] {
        let mut w = World { control, ..World::default() };
        w.removal = plain(&mut w, A, A, &Line::new(), &[X], &[], &[A, B, C, T], 1);
        let k = plain(&mut w, X, X, &Line::new(), &[A], &[], &[X], 1);
        w.withheld.insert(k);
        let rx = plain(&mut w, X, X, &Line::new(), &[A], &[k], &PS, 1);
        to(&mut w, &[rx], &[B], 2);
        let made = act(&mut w, B, 2, Some(T), false);
        w.item(made[0]).boxed
    }

    #[test]
    fn a_removal_acts_on_the_roster_only_inside_its_rotation() {
        assert!(bare(Control::None)[A]);
        assert!(!bare(Control::RosterBare)[A], "roster-bare: B boxes A");
    }

    /// X also merges a fork it signed as a made-up key actor into its revocation's line: the
    /// revocation is held with its chain but not taken (that fork's minter is no node), so it
    /// removes no one from D at B.
    #[test]
    fn a_held_revocation_not_taken_removes_no_one() {
        let mut w = World::default();
        w.removal = plain(&mut w, A, A, &Line::new(), &[X], &[], &[A, B, C, T], 1);
        let z = plain(&mut w, X, Z, &Line::new(), &[], &[], &PS, 1);
        let f = plain(&mut w, X, X, &Line::new(), &[], &[], &PS, 1);
        let bx: [bool; N] = std::array::from_fn(|m| PS.contains(&m));
        let joined = vec![w.line(f), w.line(z)];
        let lf = w.line(f);
        let m = w.add(Kind::Cert { joined, takes: vec![], answers: vec![] }, X, X, lf, None, 1, bx);
        let lm = w.mints(m);
        let rx = plain(&mut w, X, X, &lm, &[A], &[], &PS, 1);
        to(&mut w, &[z, f, m, rx], &[B], 2);
        let j = judge(&w, B, 2);
        assert!(j.chain.contains(&rx) && j.taken.is_empty());
        assert!(j.roster.contains(&A));
        let made = act(&mut w, B, 2, Some(T), false);
        assert!(w.item(made[0]).boxed[A]);
    }

    /// Unaware B and C rotate boxing X; A, having removed X, merges all three heads: the merge's
    /// seed derives from a's, which X lacks, while X derives the merge of B's and C's alone.
    #[test]
    fn the_thief_derives_no_merge_seed_an_aware_node_makes() {
        let mut w = World::default();
        let a = plain(&mut w, A, A, &Line::new(), &[X], &[], &[A, B, C, T], 1);
        w.removal = a;
        let b = plain(&mut w, B, B, &Line::new(), &[], &[], &PS, 1);
        let c = plain(&mut w, C, C, &Line::new(), &[], &[], &PS, 1);
        to(&mut w, &[a, b, c], &[A, B, C, X], 2);
        let made = act(&mut w, A, 2, None, false);
        let cert = *made.iter().find(|id| matches!(w.item(**id).kind, Kind::Cert { .. })).unwrap();
        to(&mut w, &made, &[A, B, C, X], 3);
        let x = judge(&w, X, 3);
        assert!(!x.keys.holds(&w, &w.mints(cert)));
        assert!(x.keys.holds(&w, &[b, c].into()));
    }

    /// A answers X's fork while A and C merge their heads on the same deliveries. A merge carrying
    /// its maker's answer (`MergeCarries`) makes two certificates of one epoch that read
    /// otherwise: an outside reader holding X's fork first is warned holding A's, not C's.
    fn carries(control: Control) -> (World, Vec<u32>) {
        let mut w = World { control, sched: Sched::Lockstep, ..World::default() };
        let a = plain(&mut w, A, A, &Line::new(), &[X], &[], &[A, B, C, T], 1);
        w.removal = a;
        let c = plain(&mut w, C, C, &Line::new(), &[T], &[], &[A, B, C, X], 1);
        let f = plain(&mut w, X, X, &Line::new(), &[], &[], &PS, 1);
        to(&mut w, &[f], &[A, R2], 1);
        to(&mut w, &[a, c], &[A, C, R2], 2);
        let made: Vec<u32> = [A, C].iter().flat_map(|n| act(&mut w, *n, 2, None, false)).collect();
        to(&mut w, &made, &[A, C, R2], 3);
        let certs = made.iter().copied().filter(|id| matches!(w.item(*id).kind, Kind::Cert { .. })).collect();
        (w, certs)
    }

    #[test]
    fn certificates_of_one_epoch_read_alike() {
        let alike = |w: &World, certs: &[u32]| {
            let full = judge(w, R2, 3);
            certs.iter().all(|keep| {
                let k = judge_one_cert(w, R2, 3, certs, *keep);
                k.warning == full.warning && k.counting == full.counting
            })
        };
        // A answers in a plain rotation of its own (then merges it in): the certificates carry
        // nothing (twin certificates of one tip set: `merges_made_at_once_of_one_tip_set_are_one_epoch`)
        let (w, certs) = carries(Control::None);
        assert!(w.items.iter().any(|i| i.author == A && matches!(&i.kind, Kind::Plain { answers, .. } if !answers.is_empty())));
        assert!(certs.iter().all(|c| w.answers(*c).is_empty()));
        let (w, certs) = carries(Control::MergeCarries);
        assert_eq!(certs.len(), 2);
        assert_eq!(w.mints(certs[0]), w.mints(certs[1]));
        assert!(!alike(&w, &certs), "merge-carries: certificates read alike");
    }

    fn assert_holds(st: &Stats, what: &str) {
        for (m, w) in st.fail.iter().take(1) {
            explain(m, w);
        }
        assert_eq!(st.failures, 0, "{what}: {:?}", st.kinds);
    }

    /// 40 random worlds: both schedules, X's side taken first, switches, twin certificates.
    #[test]
    fn random_worlds_hold() {
        let st = run_random(40, 1, Control::None);
        assert!(st.lockstep > 0 && st.twin_certs > 0 && st.cycle > 0, "{st:?}");
        assert_holds(&st, "random");
    }

    /// Every 40th world of the small family under two setups (random and lockstep; B offline,
    /// C apart removing T, X's tick-0 rotation).
    #[test]
    fn small_family_sample_holds() {
        let mut st = Stats::default();
        for prefix in [vec![0, 0, 1, 1, 1], vec![1, 1, 1, 1, 0]] {
            let mut od = Odometer::with_prefix(prefix);
            let mut k = 0u64;
            loop {
                let w = gen_world(&mut od, true, Control::None);
                if k % 40 == 0 {
                    check(&w, &mut st);
                }
                k += 1;
                if !od.advance() {
                    break;
                }
            }
        }
        assert_holds(&st, "small family sample");
    }

    fn var(k: &str) -> Option<u64> {
        std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")))
    }

    /// Worlds from `OSIS_ROLES_START` (default 0), `OSIS_ROLES_SEEDS` many (2000, 20000 under
    /// `OSIS_FULL=1`), a thread per core.
    #[test]
    #[ignore = "property"]
    fn random_worlds_hold_large() {
        let start = var("OSIS_ROLES_START").unwrap_or(0);
        let n = var("OSIS_ROLES_SEEDS").unwrap_or(if var("OSIS_FULL") == Some(1) { 20_000 } else { 2000 });
        eprintln!("custody::random_worlds_hold_large: {n} worlds from {start}");
        let st = parallel(|th, threads, st| {
            let mut rng = Rng((start ^ (th as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1);
            for _ in 0..n.div_ceil(threads as u64) {
                check(&random_world(&mut rng, Control::None), st);
            }
        });
        st.print("custody");
        assert_holds(&st, &format!("OSIS_ROLES_START={start}"));
    }

    /// The whole small family (`roles-model -- 0 custody-exh`).
    #[test]
    #[ignore = "property"]
    fn small_family_holds_large() {
        let prefixes = small_prefixes();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let st = parallel(|_, _, st| loop {
            let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Some(p) = prefixes.get(k) else { break };
            small_family(p.clone(), Control::None, st);
        });
        st.print("custody-exh");
        assert_holds(&st, "small family");
    }
}
