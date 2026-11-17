//! Account epochs, layer 2 (spec/permissions.md §5.5) over `custody`'s chain: which commits of
//! account P count at a node, as a function of the chain the node judges (custody's `View`: the
//! counting epochs, heads, sides) and the held words naming P's commits. The chain world, its
//! parties and the fight are custody's (`custody::random_world`, `custody::settle`); this module
//! adds P's commits on several things in sync IDs, the rotators' thing lists, listings, outside
//! writers' addenda, and the bound, written by the cutoff after the chain world is made (nothing
//! here moves the chain).
//!
//! The rule under test.
//! - **Epochs.** An epoch (a custody `Line`) is held at a node with its chain; it is open iff it
//!   is a head. A counting rotation closes every held epoch that does not descend from it (a plain
//!   rotation not on its line, a merge whose tips are not all on it): its closers. A held epoch is
//!   revoked once a closer carries a removal.
//! - **Epoch rule.** A commit of P at held epoch e counts iff e is open, or not revoked, or the
//!   commit is named on its thing: by a thing list of a counting rotation (within the bound: a
//!   longer list is bad input), or by a counting listing (a least fixpoint: a listing at a closed
//!   epoch speaks once named). An addendum by a writer of the thing against a counting closer of
//!   e saves a plain commit's delta there. A commit at an epoch not held is pending.
//! - **Cutoff** (one rule for every lister: rotator, listing node, witness): a word names another
//!   party's commit at epoch e only if its writer received it before the earliest closer of e it
//!   holds that ends e (at a node of P: one descending from e, or whose line removes a node the
//!   roster does not hold again that e's line does not remove; elsewhere every closer); its own
//!   commits always, its own listings only where it names each commit they name. Receipts in one
//!   tick come before the receiver's own acts that tick and after nothing else (`dt`).
//! - **Honest policy.** A plain rotation's maker lists, per thing under a sync ID it opens, the
//!   commits at the epochs it closes it holds and names (role-class commits first, plain ones in
//!   receipt order up to the bound; plain ones past it its later listings name by the cutoff; role-class ones
//!   alone past it refuse the rotation, which the chain world cannot undo: such a world's
//!   liveness is not checked). A node of P on its roster holding its preferred head's seed writes,
//!   per thing it reads, a listing at that head naming the commits at closed epochs it names that
//!   no held word names. A writer of a thing outside P answers each counting rotation with an
//!   addendum naming P's plain commits there at the epochs it closes it names that no held list or
//!   listing names. X writes at any epoch whose seed it holds and lists its own writes.
//! - **Covers** (half the worlds): outside writers and X snapshot a thing (P's honest nodes too in
//!   half of those); a cover carries every write showing at its writer. A node forgets another's
//!   write a standing cover it holds carries (another's own cover aside), as if never received
//!   (spec/commits.md §5 Forgetting); once no such cover carries it, it comes again from a holder,
//!   received anew. An outside writer's covers fall at a random tick or never (its demotion on
//!   the thing by an admin whose frontier names none: the role layer's, abstracted).
//! - **Own cover** (spec/permissions.md §5.5): before its plain rotation an honest rotator
//!   snapshots, signed at the epoch the rotation is signed at and marked as its own cover, each
//!   thing where a write stamped since that epoch opened shows only through a cover; the
//!   rotation's list names it.
//! - **Carrying** (spec/permissions.md §5.5): an honest node writes a snapshot (an own cover
//!   among them) only where every write showing on the thing lasts there: shows with an open
//!   epoch counting only for what a word or its cutoff names (`judge_as`), as once the head
//!   closes; else it waits. So a cover carries nothing that counts only at an open head.
//!
//! Parties: custody's (A, B, C, X, T of P; R1 and R2 outside, each maybe a writer of one thing).
//! Things sit in one or both of two sync IDs; every node opens one or both and receives what is
//! on a thing it reads. A list or listing on a thing reaches its readers; rotations reach as
//! custody delivers them. Honest commits until the settle; after custody's settle two more rounds
//! of listings and addenda, everything delivered, then the final reading.
//!
//! Properties (`check`):
//! - Safety, at every final reading on the honest side (custody's `honest_side`, not removed): a
//!   write X made after its removal counts only where an honest party's word names it (or a
//!   listing of X's naming it) that the party wrote off the honest side, or after receiving what
//!   it names before it held the removal with its chain (the unaware-reader limit,
//!   spec/permissions.md §5.5: a reader following another line, by its user's choice or first).
//! - Liveness, there: every write of a node of P whose own final reading is on the honest side
//!   counts, and every other write of P but X's after its removal that such a node's or such a
//!   writer's cutoff names at its final reading.
//! - Monotone, at every final reading: dropping an honest list, listing or addendum never makes
//!   more count.
//! - Own cover, there, where the rotation counts and its rotator ends on the honest side: every
//!   write but X's after its removal that showed at the rotator as it rotated only through a cover
//!   (stamped since the epoch it rotates opened) shows.
//! Safety and liveness read "shows": counts, saved by an addendum, or carried by a standing cover
//! (one carrying X's write after its removal only by a limit: `allowed`; the open-head limit
//! holds only while the head is open, so a cover carries nothing by it).
//!
//! Negative controls (`Control`), each expected to fail.

use crate::custody::{self as cu, Line, A, B, C, N, NEVER, OWN, R1, R2, SETTLE, T, X, Z};
use crate::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub type Thing = usize;
pub type SyncId = usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Control {
    #[default]
    None,
    /// Listers name every held commit at a closed epoch: no cutoff.
    NoCutoff,
    /// Listers name only their own commits.
    OwnOnly,
    /// A rotator writes no own cover for what it forgot.
    NoOwnCover,
    /// A commit at an epoch that does not count never counts, named or not.
    VoidUncounted,
    /// Honest snapshots carry what counts only at an open head (no Carrying).
    OpenCarried,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// A commit of P with a delta on `thing`: plain content, or role-class (`plain` false).
    Content { thing: Thing, plain: bool },
    /// A listing of P (a role commit) naming commits on `thing`.
    Listing { thing: Thing, names: Vec<u32> },
    /// Custody plain rotation `rot`'s thing list on `thing`.
    List { rot: u32, thing: Thing, names: Vec<u32> },
    /// An outside writer's addendum on `thing` against custody plain rotation `against`.
    Addendum { against: u32, thing: Thing, names: Vec<u32> },
    /// A compaction snapshot of `thing` carrying the writes `carries` (what showed at its
    /// writer). `p`: a commit of P (signed at its item's epoch), else an outside writer's, which
    /// stands until the writer's demotion (`World::fall`). `own`: its writer's own cover at a
    /// rotation (only its writer forgets under it). `legit`: the writes of X after its removal
    /// it carries by the unaware-reader limit, or that counted at its writer at an open epoch (an
    /// unaware sibling's head boxed to X, until a merge closes it): bookkeeping for safety.
    Cover { thing: Thing, carries: Vec<u32>, p: bool, own: bool, legit: Vec<u32> },
}

impl Kind {
    pub fn thing(&self) -> Thing {
        match self {
            Kind::Content { thing, .. } | Kind::Listing { thing, .. } | Kind::List { thing, .. } | Kind::Addendum { thing, .. } | Kind::Cover { thing, .. } => *thing,
        }
    }
    /// A commit of P, signed at its item's epoch.
    pub fn is_commit(&self) -> bool {
        matches!(self, Kind::Content { .. } | Kind::Listing { .. } | Kind::Cover { p: true, .. })
    }
    /// A role-class commit: listed whatever the bound (a refused rotation past it).
    pub fn special(&self) -> bool {
        matches!(self, Kind::Content { plain: false, .. } | Kind::Listing { .. })
    }
    pub fn plain(&self) -> bool {
        matches!(self, Kind::Content { plain: true, .. })
    }
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub kind: Kind,
    pub author: usize,
    /// The P epoch a commit is signed at.
    pub epoch: Line,
    pub t: u32,
    pub recv: [u32; N],
}

/// A chain world (custody's, settled) with P's commits and the words naming them.
#[derive(Clone, Debug)]
pub struct World {
    pub c: cu::World,
    /// Custody's last tick: every chain view from here on is final.
    pub end: u32,
    /// Per node and tick up to `end`, custody's view.
    pub views: Vec<Vec<cu::View>>,
    pub items: Vec<Item>,
    /// Per thing, the sync IDs it sits in; per node, those it opens.
    pub things: Vec<Vec<SyncId>>,
    pub opens: [Vec<SyncId>; N],
    /// Per outside node, the thing it writes on.
    pub writer: [Option<Thing>; N],
    /// IDs per thing list.
    pub bound: Option<usize>,
    pub control: Control,
    /// An honest rotation's role-class commits alone passed the bound.
    pub refused: bool,
    /// (rotator, commit): plain content its rotation left out past the bound (its later listings
    /// name it by the cutoff, as anything else: after a switch the cutoff may not).
    pub overflow: Vec<(usize, u32)>,
    /// Nodes forget what a standing cover carries (spec/commits.md §5 Forgetting) and rotators
    /// write own covers; `snapshots`: outside writers and X write snapshots at random, and P's
    /// honest nodes too where `p_snapshots`.
    pub covers: bool,
    pub snapshots: bool,
    pub p_snapshots: bool,
    /// Per outside writer, the tick from which its covers count for nothing (its demotion on
    /// the thing, by an admin whose frontier lists none: the role layer's, abstracted).
    pub fall: [u32; N],
    /// (rotation, rotator, write): a write that showed at the rotator as it rotated only through
    /// a cover, stamped since the epoch it rotates opened (spec/permissions.md §5.5 Own cover).
    pub obliged: Vec<(u32, usize, u32)>,
    /// (node, write): forgotten there and not received again.
    pub forgot: BTreeSet<(usize, u32)>,
    /// (node, write, its receipt then, the tick it was forgotten): receipts forgetting undid.
    pub undone: Vec<(usize, u32, u32, u32)>,
    /// Per node, per plain rotation and merge epoch held with its chain, the tick it came to be.
    since: Vec<BTreeMap<Line, u32>>,
}

/// Merge epochs' ties (`cu::World::merge_tie`) start here, past every item ID.
pub const MERGE_TIE: u64 = 1 << 32;

/// The tick of the final reading.
pub fn fin(w: &World) -> u32 {
    w.end + 2
}

impl World {
    pub fn item(&self, id: u32) -> &Item {
        &self.items[id as usize - 1]
    }
    pub fn view(&self, v: usize, t: u32) -> &cu::View {
        &self.views[v][t.min(self.end) as usize]
    }
    pub fn reads(&self, v: usize, thing: Thing) -> bool {
        v != Z && self.opens[v].iter().any(|s| self.things[thing].contains(s))
    }
    /// The layer-2 items `v` holds at `t`.
    pub fn held(&self, v: usize, t: u32) -> Vec<bool> {
        self.items.iter().map(|i| i.recv[v] <= t).collect()
    }
    /// A write X made after its removal.
    pub fn hostile(&self, id: u32) -> bool {
        let i = self.item(id);
        i.author == X && i.t >= self.c.item(self.c.removal).t
    }
    /// When `v` came to hold item `id`, in half ticks: a receipt before the node's own acts that
    /// tick.
    fn dt(&self, v: usize, id: u32) -> u32 {
        let i = self.item(id);
        i.recv[v].saturating_mul(2).saturating_add(u32::from(i.author == v))
    }
    /// `dt` of the receipt `v` held at tick `at` (one forgetting undid later included).
    fn dt_at(&self, v: usize, id: u32, at: u32) -> u32 {
        let i = self.item(id);
        let r = if i.recv[v] <= at { i.recv[v] } else { self.undone.iter().find(|u| u.0 == v && u.1 == id && u.2 <= at && at < u.3).map_or(NEVER, |u| u.2) };
        r.saturating_mul(2).saturating_add(u32::from(i.author == v))
    }
    /// When `v` came to hold epoch `e` with its chain, in half ticks (`dt`): own when a rotation
    /// or certificate of `v`'s made then completed it.
    fn held_dt(&self, v: usize, e: &Line) -> u32 {
        let Some(t) = self.since[v].get(e).copied() else { return u32::MAX };
        let own = self.c.items.iter().any(|i| i.author == v && i.t == t && self.c.is_rot(i.id) && self.c.mints(i.id) == *e);
        2 * t + u32::from(own)
    }
    fn add(&mut self, kind: Kind, author: usize, epoch: Line, t: u32) -> u32 {
        let id = self.items.len() as u32 + 1;
        let mut recv = [NEVER; N];
        recv[author] = t;
        self.items.push(Item { id, kind, author, epoch, t, recv });
        id
    }
}

/// What one node's chain says of an epoch.
pub struct Epoch<'a> {
    w: &'a cu::World,
    j: &'a cu::View,
}

impl Epoch<'_> {
    pub fn held(&self, e: &Line) -> bool {
        e.is_empty() || e.iter().all(|x| self.j.chain.contains(x)) && (self.w.single(e) || self.j.merges.contains(e))
    }
    pub fn open(&self, e: &Line) -> bool {
        self.j.heads.contains(e)
    }
    /// The counting rotations closing held epoch `e`, as the epochs they mint.
    pub fn closers(&self, e: &Line) -> Vec<Line> {
        let plain = self.j.followed.iter().filter(|q| !e.contains(q)).map(|q| self.w.line(*q));
        let merges = self.j.counting.iter().filter(|m| !self.w.single(m) && !m.is_subset(e)).cloned();
        plain.chain(merges).collect()
    }
    pub fn revoked(&self, e: &Line) -> bool {
        self.j.followed.iter().any(|q| !e.contains(q) && !self.w.removes(*q).is_empty())
    }
    /// At a node of P: closer `q` ends `e` for the cutoff.
    fn ends(&self, e: &Line, q: &Line) -> bool {
        e.is_subset(q) || q.iter().any(|x| self.j.followed.contains(x) && self.w.removes(*x).iter().any(|y| !self.j.roster.contains(y) && !e.iter().any(|z| self.w.removes(*z).contains(y))))
    }
}

/// One node's layer-2 judgment.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    /// (commit, thing): a counting list or listing names it.
    pub named: BTreeSet<(u32, Thing)>,
    pub pending: Vec<bool>,
    /// Counts whole.
    pub counts: Vec<bool>,
    /// Counts whole, or a counting addendum saves its plain delta.
    pub saved: Vec<bool>,
}

/// The epoch rule at a node whose chain is `j`, holding `held`.
pub fn judge(w: &World, j: &cu::View, held: &[bool]) -> Verdict {
    judge_as(w, j, held, None)
}

/// `judge`, or (`lasting` the node's ID) what lasts there: an open epoch counts only for what its
/// cutoff names or a word names, as once that head closes (Carrying).
fn judge_as(w: &World, j: &cu::View, held: &[bool], lasting: Option<usize>) -> Verdict {
    let ep = Epoch { w: &w.c, j };
    let n = w.items.len();
    let mut named: BTreeSet<(u32, Thing)> = BTreeSet::new();
    for i in w.items.iter().filter(|i| held[i.id as usize - 1]) {
        if let Kind::List { rot, thing, names } = &i.kind {
            if j.followed.contains(rot) && w.bound.is_none_or(|b| names.len() <= b) {
                named.extend(names.iter().map(|c| (*c, *thing)));
            }
        }
    }
    let counts_now = |named: &BTreeSet<(u32, Thing)>, i: &Item| -> bool {
        let e = &i.epoch;
        held[i.id as usize - 1] && i.kind.is_commit() && ep.held(e) && (w.control != Control::VoidUncounted || j.counting.contains(e)) && (ep.open(e) && lasting.is_none_or(|n| nameable(w, n, j, i.id, w.control, 0)) || !ep.revoked(e) || named.contains(&(i.id, i.kind.thing())))
    };
    loop {
        let more: Vec<(u32, Thing)> = w.items.iter().filter(|i| counts_now(&named, i)).filter_map(|i| match &i.kind {
            Kind::Listing { thing, names } => Some(names.iter().map(|c| (*c, *thing)).collect::<Vec<_>>()),
            _ => None,
        }).flatten().filter(|x| !named.contains(x)).collect();
        if more.is_empty() {
            break;
        }
        named.extend(more);
    }
    let counts: Vec<bool> = w.items.iter().map(|i| counts_now(&named, i)).collect();
    let pending = w.items.iter().map(|i| held[i.id as usize - 1] && i.kind.is_commit() && !ep.held(&i.epoch)).collect();
    let saved = (0..n).map(|k| {
        let i = &w.items[k];
        counts[k] || held[k] && i.kind.plain() && ep.held(&i.epoch) && w.items.iter().any(|a| match &a.kind {
            Kind::Addendum { against, thing, names } => held[a.id as usize - 1] && *thing == i.kind.thing() && w.writer[a.author] == Some(*thing) && names.contains(&i.id) && j.followed.contains(against) && !i.epoch.contains(against),
            _ => false,
        })
    }).collect();
    Verdict { named, pending, counts, saved }
}

/// Whether cover `k`, held, stands at a node judging `vd` at `t`: a commit of P while it counts,
/// an outside writer's until its writer's demotion.
fn stands(w: &World, vd: &Verdict, t: u32, k: u32) -> bool {
    match &w.item(k).kind {
        Kind::Cover { p: true, .. } => vd.counts[k as usize - 1],
        Kind::Cover { p: false, .. } => t < w.fall[w.item(k).author],
        _ => false,
    }
}

/// The covers standing at a node (`held`, `vd`) at `t` that carry write `c`.
fn covers_of<'a>(w: &'a World, held: &'a [bool], vd: &'a Verdict, t: u32, c: u32) -> impl Iterator<Item = &'a Item> + 'a {
    w.items.iter().filter(move |k| held[k.id as usize - 1] && matches!(&k.kind, Kind::Cover { carries, .. } if carries.contains(&c)) && stands(w, vd, t, k.id))
}

/// Per item, whether it shows at a node (`held`, `vd`) at `t`: it counts or an addendum saves it,
/// or (a write) a standing cover carries it.
pub fn shows(w: &World, held: &[bool], vd: &Verdict, t: u32) -> Vec<bool> {
    w.items.iter().map(|i| vd.saved[i.id as usize - 1] || matches!(i.kind, Kind::Content { .. }) && covers_of(w, held, vd, t, i.id).next().is_some()).collect()
}

/// An honest word names X's write `c` (or a listing of X's naming it) that its writer wrote off
/// the honest side or after receiving what it names before it held the removal with its chain
/// (the unaware-reader limit).
fn word_limit(w: &World, c: u32) -> bool {
    let removal = w.c.line(w.c.removal);
    let carriers: Vec<u32> = std::iter::once(c).chain(w.items.iter().filter(|l| l.author == X && matches!(&l.kind, Kind::Listing { names, .. } if names.contains(&c))).map(|l| l.id)).collect();
    w.items.iter().filter(|d| d.author != X).any(|d| {
        let names = match &d.kind {
            Kind::Listing { names, .. } | Kind::List { names, .. } | Kind::Addendum { names, .. } => names,
            Kind::Content { .. } | Kind::Cover { .. } => return false,
        };
        let p = d.author;
        carriers.iter().any(|k| names.contains(k) && (!w.view(p, d.t).honest_side(&w.c, p) || w.dt_at(p, *k, d.t) < w.held_dt(p, &removal)))
    })
}

/// Whether X's write `c` after its removal, showing at a node (chain `j`, `held`, `vd`) at `t`,
/// shows by a limit: a word by the unaware-reader limit (`word_limit`), its epoch an open head
/// (an unaware sibling's boxed to X, until a merge closes it), or a cover carrying it so (`legit`;
/// an X cover counting so itself).
fn allowed(w: &World, j: &cu::View, held: &[bool], vd: &Verdict, t: u32, c: u32) -> bool {
    allowed_as(w, j, held, vd, t, c, true)
}

/// `allowed`, with the open-head limit (`open`) or without it: a cover carries a write by a
/// limit only where it would hold once every head closes.
fn allowed_as(w: &World, j: &cu::View, held: &[bool], vd: &Verdict, t: u32, c: u32, open: bool) -> bool {
    let open = |k: u32| open && j.heads.contains(&w.item(k).epoch) && vd.counts[k as usize - 1];
    vd.saved[c as usize - 1] && (word_limit(w, c) || open(c)) || covers_of(w, held, vd, t, c).any(|k| matches!(&k.kind, Kind::Cover { legit, .. } if legit.contains(&c)) || k.author == X && (word_limit(w, k.id) || open(k.id)))
}

/// `n`'s snapshot of `thing` at `t` signed at `epoch` (`p`: as P): it carries every write showing
/// there; of X's after its removal, those it carries by the unaware-reader limit go in `legit`.
/// An honest node writes one only where every write showing there lasts (`judge_as`, Carrying):
/// else it waits (`None`), as the engine's snapshot does.
fn cover(w: &mut World, n: usize, thing: Thing, epoch: Line, t: u32, p: bool, own: bool) -> Option<u32> {
    let removal = w.c.line(w.c.removal);
    let j = w.view(n, t).clone();
    let held = w.held(n, t);
    let vd = judge(w, &j, &held);
    let sh = shows(w, &held, &vd, t);
    let on = |i: &Item| matches!(i.kind, Kind::Content { .. }) && i.kind.thing() == thing;
    if n != X && w.control != Control::OpenCarried {
        let lasts = shows(w, &held, &judge_as(w, &j, &held, Some(n)), t);
        if w.items.iter().any(|i| on(i) && sh[i.id as usize - 1] && !lasts[i.id as usize - 1]) {
            return None;
        }
    }
    let carries: Vec<u32> = w.items.iter().filter(|i| on(i) && sh[i.id as usize - 1]).map(|i| i.id).collect();
    let legit = carries.iter().copied().filter(|c| {
        n != X && w.hostile(*c) && (!j.honest_side(&w.c, n) || held[*c as usize - 1] && w.dt(n, *c) < w.held_dt(n, &removal) || allowed_as(w, &j, &held, &vd, t, *c, false))
    }).collect();
    Some(w.add(Kind::Cover { thing, carries, p, own, legit }, n, epoch, t))
}

/// Forgetting at `t` (spec/commits.md §5): each node drops a write of another a standing cover it
/// holds carries (another's own cover aside), as if never received; a forgotten write no such
/// cover carries any more comes again from a node holding it, received anew.
fn forget(w: &mut World, t: u32) {
    let helds: Vec<Vec<bool>> = (0..N).map(|v| w.held(v, t)).collect();
    for v in (0..N).filter(|v| *v != Z) {
        let held = &helds[v];
        let vd = judge(w, w.view(v, t), held);
        let covered = |c: u32| covers_of(w, held, &vd, t, c).any(|k| !matches!(k.kind, Kind::Cover { own: true, .. }) || k.author == v);
        let drop: Vec<u32> = w.items.iter().filter(|i| held[i.id as usize - 1] && matches!(i.kind, Kind::Content { .. }) && i.author != v && covered(i.id)).map(|i| i.id).collect();
        let back: Vec<u32> = w.forgot.iter().filter(|(m, c)| *m == v && w.item(*c).recv[v] == NEVER && !covered(*c) && (0..N).any(|o| o != v && helds[o][*c as usize - 1])).map(|x| x.1).collect();
        for c in drop {
            w.undone.push((v, c, w.items[c as usize - 1].recv[v], t));
            w.items[c as usize - 1].recv[v] = NEVER;
            w.forgot.insert((v, c));
        }
        for c in back {
            w.items[c as usize - 1].recv[v] = t + 1;
            w.forgot.remove(&(v, c));
        }
    }
}

/// Whether lister `n` (its chain `j`) names commit `c` by the cutoff (under `control`'s policy).
fn nameable(w: &World, n: usize, j: &cu::View, c: u32, control: Control, depth: u32) -> bool {
    let i = w.item(c);
    if i.author == n {
        return match &i.kind {
            Kind::Listing { names, .. } => depth < 4 && names.iter().all(|m| nameable(w, n, j, *m, control, depth + 1)),
            _ => true,
        };
    }
    let ep = Epoch { w: &w.c, j };
    if !ep.held(&i.epoch) || control == Control::OwnOnly {
        return false;
    }
    if control == Control::NoCutoff {
        return true;
    }
    let tau = ep.closers(&i.epoch).into_iter().filter(|q| n >= OWN || ep.ends(&i.epoch, q)).map(|q| w.held_dt(n, &q)).min();
    tau.is_none_or(|t| w.dt(n, c) < t)
}

/// The commits on `thing` `n` holds at a closed epoch it names that no held word names.
fn owed(w: &World, n: usize, t: u32, thing: Thing) -> Vec<u32> {
    let j = w.view(n, t);
    let ep = Epoch { w: &w.c, j };
    let held = w.held(n, t);
    let v = judge(w, j, &held);
    w.items.iter().filter(|i| held[i.id as usize - 1] && i.kind.is_commit() && i.kind.thing() == thing).filter(|i| {
        let e = &i.epoch;
        ep.held(e) && !ep.open(e) && !ep.closers(e).is_empty() && !v.named.contains(&(i.id, thing)) && !v.saved[i.id as usize - 1] && nameable(w, n, j, i.id, w.control, 0)
    }).map(|i| i.id).collect()
}

/// `n`'s thing lists for its plain rotation `r`, made at `t`.
fn lists(w: &mut World, n: usize, r: u32, t: u32) -> Vec<u32> {
    // own cover (spec/permissions.md §5.5): per thing where a write stamped since the epoch the
    // rotation is signed at opened shows only through a cover, a snapshot signed there, named
    let mut own = vec![];
    if w.covers && !w.c.hostile(r) {
        let at = match &w.c.item(r).kind {
            cu::Kind::Plain { at, .. } => at.clone(),
            _ => Line::new(),
        };
        let opened = at.iter().map(|q| w.c.item(*q).t).max().unwrap_or(0);
        let (j, held) = (w.view(n, t).clone(), w.held(n, t));
        let vd = judge(w, &j, &held);
        let sh = shows(w, &held, &vd, t);
        let read: Vec<Thing> = (0..w.things.len()).filter(|th| w.reads(n, *th)).collect();
        for thing in read {
            let only: Vec<u32> = w.items.iter().filter(|i| matches!(i.kind, Kind::Content { .. }) && i.kind.thing() == thing && !held[i.id as usize - 1] && sh[i.id as usize - 1] && i.t >= opened).map(|i| i.id).collect();
            if only.is_empty() {
                continue;
            }
            let owed: Vec<(u32, usize, u32)> = only.iter().filter(|c| !w.hostile(**c)).map(|c| (r, n, *c)).collect();
            w.obliged.extend(owed);
            if w.control != Control::NoOwnCover {
                own.extend(cover(w, n, thing, at.clone(), t, true, true));
            }
        }
    }
    let j = w.view(n, t).clone();
    let held = w.held(n, t);
    let (mut out, mut over, mut refused) = (vec![], vec![], false);
    {
        let w: &World = w;
        let ep = Epoch { w: &w.c, j: &j };
        for thing in (0..w.things.len()).filter(|th| w.reads(n, *th)) {
            let cands: Vec<&Item> = w.items.iter().filter(|i| held[i.id as usize - 1] && i.kind.is_commit() && i.kind.thing() == thing && ep.held(&i.epoch) && !i.epoch.contains(&r)).collect();
            let names: Vec<u32> = if w.c.hostile(r) {
                cands.iter().filter(|i| i.author == X).map(|i| i.id).collect()
            } else {
                let mut ns: Vec<&Item> = cands.into_iter().filter(|i| nameable(w, n, &j, i.id, w.control, 0)).collect();
                ns.sort_by_key(|i| (!i.kind.special(), i.recv[n], i.id));
                let special = ns.iter().filter(|i| i.kind.special()).count();
                let room = match w.bound {
                    Some(b) if special > b => {
                        refused = true;
                        ns.len()
                    }
                    Some(b) => b.min(ns.len()),
                    None => ns.len(),
                };
                over.extend(ns[room..].iter().map(|i| (n, i.id)));
                ns[..room].iter().map(|i| i.id).collect()
            };
            if !names.is_empty() {
                out.push((thing, names));
            }
        }
    }
    w.refused |= refused;
    w.overflow.extend(over);
    own.extend(out.into_iter().map(|(thing, names)| w.add(Kind::List { rot: r, thing, names }, n, Line::new(), t)));
    own
}

/// What `n` writes at tick `t` (lists of the plain rotations it made then first).
fn act(w: &mut World, rng: &mut Rng, n: usize, t: u32) -> Vec<u32> {
    let mut made = vec![];
    let rots: Vec<u32> = w.c.items.iter().filter(|i| i.author == n && i.t == t && matches!(i.kind, cu::Kind::Plain { .. })).map(|i| i.id).collect();
    for r in rots {
        made.extend(lists(w, n, r, t));
    }
    let things: Vec<Thing> = (0..w.things.len()).filter(|th| w.reads(n, *th)).collect();
    let j = w.view(n, t).clone();
    if n >= OWN {
        // an outside writer's addenda
        let Some(thing) = w.writer[n] else { return made };
        let held = w.held(n, t);
        let mut out = vec![];
        {
            let w: &World = w;
            let ep = Epoch { w: &w.c, j: &j };
            let v = judge(w, &j, &held);
            for r in j.followed.iter().copied() {
                let names: Vec<u32> = w.items.iter().filter(|i| held[i.id as usize - 1] && i.kind.plain() && i.kind.thing() == thing && ep.held(&i.epoch) && !i.epoch.contains(&r) && !v.named.contains(&(i.id, thing)) && nameable(w, n, &j, i.id, w.control, 0)).map(|i| i.id).collect();
                let done = w.items.iter().any(|a| a.author == n && held[a.id as usize - 1] && matches!(&a.kind, Kind::Addendum { against, names: ns, .. } if *against == r && names.iter().all(|c| ns.contains(c))));
                if !names.is_empty() && !done {
                    out.push((r, names));
                }
            }
        }
        made.extend(out.into_iter().map(|(against, names)| w.add(Kind::Addendum { against, thing, names }, n, Line::new(), t)));
        if w.snapshots && t < SETTLE && rng.below(3) == 0 {
            made.extend(cover(w, n, thing, Line::new(), t, false, false));
        }
        return made;
    }
    if things.is_empty() {
        return made;
    }
    if n == X && t >= w.c.item(w.c.removal).t {
        // X: a write at any epoch whose seed it holds, maybe listed
        if t >= SETTLE || rng.below(3) != 0 {
            return made;
        }
        let eps: Vec<Line> = std::iter::once(Line::new()).chain(j.chain.iter().map(|x| w.c.line(*x))).chain(j.merges.iter().cloned()).filter(|e| j.keys.holds(&w.c, e)).collect();
        let e = eps[rng.below(eps.len())].clone();
        let thing = things[rng.below(things.len())];
        let c = w.add(Kind::Content { thing, plain: rng.below(3) != 0 }, X, e.clone(), t);
        made.push(c);
        if rng.below(2) == 0 {
            made.push(w.add(Kind::Listing { thing, names: vec![c] }, X, e.clone(), t));
        }
        if w.snapshots && rng.below(2) == 0 {
            made.extend(cover(w, X, thing, e, t, true, false));
        }
        return made;
    }
    if j.out(n) || !j.keys.holds(&w.c, &j.preferred) {
        return made;
    }
    let h = j.preferred.clone();
    if n != T && t < SETTLE && rng.below(4) == 0 {
        let thing = things[rng.below(things.len())];
        made.push(w.add(Kind::Content { thing, plain: rng.below(3) != 0 }, n, h.clone(), t));
    }
    if w.p_snapshots && n != T && t < SETTLE && rng.below(10) == 0 {
        let thing = things[rng.below(things.len())];
        made.extend(cover(w, n, thing, h.clone(), t, true, false));
    }
    for thing in things {
        let names = owed(w, n, t, thing);
        if !names.is_empty() {
            made.push(w.add(Kind::Listing { thing, names }, n, h.clone(), t));
        }
    }
    made
}

/// Deliver `ids` made at `t` to the readers of their things: before the settle at a random delay
/// or not until it, from then on the next tick.
fn deliver(w: &mut World, rng: &mut Rng, ids: &[u32], t: u32) {
    for id in ids {
        let (author, thing) = (w.item(*id).author, w.item(*id).kind.thing());
        let to: Vec<usize> = (0..N).filter(|m| *m != author && w.reads(*m, thing)).collect();
        for m in to {
            let at = if t >= SETTLE {
                t + 1
            } else {
                match rng.below(6) {
                    0 => NEVER,
                    k => t + k as u32,
                }
            };
            w.items[*id as usize - 1].recv[m] = at;
        }
    }
}

/// Layer 2 over chain world `c` (settled by `custody::settle`, its last tick `end`).
pub fn build(mut c: cu::World, end: u32, rng: &mut Rng, control: Control, covers: bool) -> World {
    // merges held in one tick place after its plain rotations, among themselves by epoch (a
    // differential's IDs: `MERGE_TIE` past the place among the world's merge epochs)
    let merges: BTreeSet<Line> = c.items.iter().filter(|i| matches!(i.kind, cu::Kind::Cert { .. }) && !c.seedy(i.id)).map(|i| c.mints(i.id)).collect();
    c.merge_tie = merges.into_iter().enumerate().map(|(k, e)| (e, MERGE_TIE + k as u64)).collect();
    let views: Vec<Vec<cu::View>> = (0..N).map(|v| {
        let mut vs: Vec<cu::View> = vec![];
        for t in (0..=end).filter(|_| v != Z) {
            let moved = t == 0 || c.items.iter().any(|i| i.recv[v] == t) || c.switches.iter().any(|s| s.0 == v && s.1 == t);
            let j = if moved { cu::judge(&c, v, t) } else { vs[t as usize - 1].clone() };
            vs.push(j);
        }
        vs
    }).collect();
    let mut since: Vec<BTreeMap<Line, u32>> = vec![BTreeMap::new(); N];
    for (v, vs) in views.iter().enumerate() {
        for (t, j) in vs.iter().enumerate() {
            for e in j.chain.iter().map(|x| c.line(*x)).chain(j.merges.iter().cloned()) {
                since[v].entry(e).or_insert(t as u32);
            }
        }
    }
    let nthings = 1 + rng.below(3);
    let sub = |rng: &mut Rng| [vec![0], vec![1], vec![0, 1]][rng.below(3)].clone();
    let things: Vec<Vec<SyncId>> = (0..nthings).map(|_| sub(rng)).collect();
    let mut opens: [Vec<SyncId>; N] = std::array::from_fn(|_| vec![]);
    for (v, o) in opens.iter_mut().enumerate().filter(|(v, _)| *v != Z) {
        *o = if v == A && rng.below(2) == 0 { vec![0, 1] } else { sub(rng) };
    }
    let mut writer: [Option<Thing>; N] = [None; N];
    for r in [R1, R2] {
        if rng.below(2) == 0 {
            let th = rng.below(nthings);
            writer[r] = Some(th);
            if !opens[r].iter().any(|s| things[th].contains(s)) {
                opens[r].push(things[th][0]);
            }
        }
    }
    let bound = [None, None, Some(2), Some(3)][rng.below(4)];
    let mut fall = [NEVER; N];
    let p_snapshots = covers && rng.below(2) == 0;
    if covers {
        for r in [R1, R2] {
            if rng.below(2) == 0 {
                fall[r] = 1 + rng.below(SETTLE as usize) as u32;
            }
        }
    }
    let mut w = World { c, end, views, items: vec![], things, opens, writer, bound, control, refused: false, overflow: vec![], covers, snapshots: covers, p_snapshots, fall, obliged: vec![], forgot: BTreeSet::new(), undone: vec![], since };
    for t in 0..fin(&w) {
        if t == SETTLE {
            for i in w.items.iter_mut() {
                for r in i.recv.iter_mut() {
                    *r = (*r).min(SETTLE);
                }
            }
            for k in 0..w.items.len() {
                let (author, thing) = (w.items[k].author, w.items[k].kind.thing());
                for m in 0..N {
                    if m != author && !w.reads(m, thing) {
                        w.items[k].recv[m] = NEVER;
                    }
                }
            }
        }
        if w.covers {
            forget(&mut w, t);
        }
        for n in [A, B, C, T, X, R1, R2] {
            let made = act(&mut w, rng, n, t);
            deliver(&mut w, rng, &made, t);
        }
    }
    w
}

pub fn random_world(rng: &mut Rng, control: Control) -> World {
    let mut c = cu::random_world(rng, cu::Control::None);
    let end = cu::settle(&mut c);
    let covers = rng.below(2) == 0;
    build(c, end, rng, control, covers)
}

#[derive(Default, Debug)]
pub struct Stats {
    pub worlds: u64,
    pub failures: u64,
    pub kinds: BTreeMap<String, u64>,
    pub fail: Vec<(String, World)>,
    /// Worlds whose liveness is not checked: an honest rotation refused by the bound.
    pub refused: u64,
    /// Final readings on the honest side where an X write counts by the unaware-reader limit.
    pub unaware: u64,
    /// Final readings where a commit at a revoked epoch counts by a word; by an addendum alone.
    pub named: u64,
    pub vouched: u64,
    /// Liveness checks of commits whose own writer's word does not stand there.
    pub by_others: u64,
    /// Worlds with covers; (node, write) forgotten at the final reading; own covers written;
    /// final readings where a write a rotator held only through a cover shows (the own-cover
    /// checks); where only an own cover carries it.
    pub covered: u64,
    pub forgotten: u64,
    pub own_covers: u64,
    pub obliged: u64,
    pub by_own_cover: u64,
}

impl crate::Tally for Stats {
    fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        self.failures += o.failures;
        for (k, n) in o.kinds {
            *self.kinds.entry(k).or_default() += n;
        }
        if self.fail.len() < 4 {
            self.fail.extend(o.fail.into_iter().take(4 - self.fail.len()));
        }
        self.refused += o.refused;
        self.unaware += o.unaware;
        self.named += o.named;
        self.vouched += o.vouched;
        self.by_others += o.by_others;
        self.covered += o.covered;
        self.forgotten += o.forgotten;
        self.own_covers += o.own_covers;
        self.obliged += o.obliged;
        self.by_own_cover += o.by_own_cover;
    }
}

impl Stats {
    pub fn print(&self, name: &str) {
        println!("{name}: {} worlds, {} failing checks", self.worlds, self.failures);
        for (k, n) in &self.kinds {
            println!("  {k}: {n}");
        }
        println!("  refused {}, unaware-reader limit {}, named at a revoked epoch {}, vouched {}, liveness by others' words {}", self.refused, self.unaware, self.named, self.vouched, self.by_others);
        println!("  with covers {}: forgotten {}, own covers {}, own-cover checks {} (shown by an own cover alone {})", self.covered, self.forgotten, self.own_covers, self.obliged, self.by_own_cover);
    }
}

pub fn check(w: &World, st: &mut Stats) {
    st.worlds += 1;
    st.refused += u64::from(w.refused);
    st.covered += u64::from(w.covers);
    st.forgotten += w.forgot.len() as u64;
    st.own_covers += w.items.iter().filter(|i| matches!(i.kind, Kind::Cover { own: true, .. })).count() as u64;
    let f = fin(w);
    let mut fails: Vec<String> = vec![];
    // the honest words, for monotone
    let honest_words: Vec<u32> = w.items.iter().filter(|i| !w.hostile(i.id) && (matches!(i.kind, Kind::List { .. } | Kind::Addendum { .. }) || matches!(i.kind, Kind::Listing { .. }) && i.author != X)).map(|i| i.id).collect();
    let honest_final = |p: usize| p != X && p != Z && !w.view(p, f).out(p) && w.view(p, f).honest_side(&w.c, p);
    for v in (0..N).filter(|v| *v != Z) {
        let j = w.view(v, f);
        let held = w.held(v, f);
        let vd = judge(w, j, &held);
        let sh = shows(w, &held, &vd, f);
        for d in &honest_words {
            let mut h = held.clone();
            h[*d as usize - 1] = false;
            let less = judge(w, j, &h);
            if let Some(k) = (0..w.items.len()).find(|k| *k != *d as usize - 1 && less.saved[*k] && !vd.saved[*k]) {
                fails.push(format!("monotone: node {} counts #{} without honest word #{d}", cu::NAMES[v], k + 1));
            }
        }
        let ep = Epoch { w: &w.c, j };
        for i in w.items.iter().filter(|i| vd.saved[i.id as usize - 1] && ep.revoked(&i.epoch) && !ep.open(&i.epoch)) {
            if vd.counts[i.id as usize - 1] {
                st.named += 1;
            } else {
                st.vouched += 1;
            }
        }
        if !honest_final(v) {
            continue;
        }
        for i in w.items.iter().filter(|i| matches!(i.kind, Kind::Content { .. }) && (held[i.id as usize - 1] || w.forgot.contains(&(v, i.id)))) {
            let (k, thing) = (i.id as usize - 1, i.kind.thing());
            if w.hostile(i.id) {
                if !sh[k] {
                    continue;
                }
                if allowed(w, j, &held, &vd, f, i.id) {
                    st.unaware += 1;
                } else {
                    fails.push(format!("safety: node {} shows X's write #{} after its removal", cu::NAMES[v], i.id));
                }
                continue;
            }
            let own = i.author != X && honest_final(i.author);
            let by = |p: usize| honest_final(p) && w.reads(p, thing) && (p < OWN || w.writer[p] == Some(thing) && i.kind.plain()) && i.recv[p] != NEVER && {
                let jp = w.view(p, f);
                let ep = Epoch { w: &w.c, j: jp };
                ep.held(&i.epoch) && !ep.open(&i.epoch) && nameable(w, p, jp, i.id, Control::None, 0)
            };
            let others = !own && [A, B, C, T, R1, R2].iter().any(|p| by(*p));
            st.by_others += u64::from(others);
            if (own || others) && !sh[k] && !w.refused {
                fails.push(format!("liveness: node {} without {}'s write #{}{}", cu::NAMES[v], cu::NAMES[i.author], i.id, if own { "" } else { " (named by another's cutoff)" }));
            }
        }
        // what a counting rotation's rotator showed only through a cover shows (its own cover)
        for (r, n, c) in &w.obliged {
            if w.refused || !honest_final(*n) || !w.reads(v, w.item(*c).kind.thing()) || !j.followed.contains(r) {
                continue;
            }
            st.obliged += 1;
            let k = *c as usize - 1;
            if !sh[k] {
                fails.push(format!("own cover: node {} without #{} that {}'s rotation #{r} showed only through a cover", cu::NAMES[v], c, cu::NAMES[*n]));
            } else if !vd.saved[k] && covers_of(w, &held, &vd, f, *c).all(|x| matches!(x.kind, Kind::Cover { own: true, .. })) {
                st.by_own_cover += 1;
            }
        }
    }
    for m in fails {
        st.failures += 1;
        let kind = m.split(':').next().unwrap_or("").to_string();
        let n = st.kinds.entry(kind).or_default();
        *n += 1;
        if *n == 1 && st.fail.len() < 4 {
            st.fail.push((m, w.clone()));
        }
    }
}

pub fn print_world(w: &World) {
    cu::print_world(&w.c);
    println!("  end {} things {:?} opens {:?} writer {:?} bound {:?} refused {} overflow {:?}", w.end, w.things, w.opens, w.writer, w.bound, w.refused, w.overflow);
    for i in &w.items {
        let recv: Vec<String> = i.recv.iter().map(|r| if *r == NEVER { "-".into() } else { r.to_string() }).collect();
        println!("  l{} {:?} by {} at {:?} t{} recv [{}]", i.id, i.kind, cu::NAMES[i.author], i.epoch, i.t, recv.join(" "));
    }
}

/// `samples` random worlds over every core.
pub fn run(samples: u64, control: Control) -> u64 {
    let st = crate::on_every_core(|th, threads, st: &mut Stats| {
        let mut rng = Rng::thread(0xe90c, th);
        for _ in 0..samples / threads as u64 {
            check(&random_world(&mut rng, control), st);
        }
    });
    st.print(&format!("epochs {control:?}"));
    for (m, w) in st.fail.iter().take(1) {
        println!("FAIL {m}");
        print_world(w);
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

    /// A chain world: A removes X at tick 1, signed at the first epoch, delivered at 2; nothing
    /// else.
    fn removal_world() -> (cu::World, u32) {
        let mut c = cu::World::default();
        let bx: [bool; N] = std::array::from_fn(|m| [A, B, C, T].contains(&m));
        let r = c.add(cu::Kind::Plain { at: Line::new(), removes: vec![X], adds: vec![], takes: vec![], answers: vec![] }, A, A, Line::new(), None, 1, bx);
        c.removal = r;
        for m in (0..N).filter(|m| *m != A && *m != Z) {
            c.items[r as usize - 1].recv[m] = 2;
        }
        (c, 4)
    }

    /// A hand-built world over `c`: one thing in sync ID 0, every node opening it, R1 its writer.
    fn hand(c: cu::World, end: u32, control: Control) -> World {
        let mut w = build(c, end, &mut Rng(0), control, false);
        w.items.clear();
        w.overflow.clear();
        w.things = vec![vec![0]];
        w.opens = std::array::from_fn(|m| if m == Z { vec![] } else { vec![0] });
        w.writer = [None; N];
        w.writer[R1] = Some(0);
        w.bound = None;
        w
    }

    fn write(w: &mut World, author: usize, t: u32, recv: &[(usize, u32)]) -> u32 {
        let id = w.add(Kind::Content { thing: 0, plain: true }, author, Line::new(), t);
        for (m, at) in recv {
            w.items[id as usize - 1].recv[*m] = *at;
        }
        id
    }

    /// The honest acts of every tick to the final reading, delivered at once.
    fn play(w: &mut World, from: u32) {
        let mut rng = Rng(0);
        for t in from..fin(w) {
            if w.covers {
                forget(w, t);
            }
            for n in [A, B, C, T, R1, R2] {
                let made = act(w, &mut rng, n, t);
                for id in made {
                    for m in (0..N).filter(|m| *m != n && *m != Z) {
                        w.items[id as usize - 1].recv[m] = t + 1;
                    }
                }
            }
        }
    }

    /// X writes at the first epoch before its removal reaches B (#1, received by B at 1) and
    /// after (#2, at 3; both reach A and R2 at 3): B's listing names the first only; at R2 and A the second never counts.
    /// With no cutoff (`NoCutoff`) B names the second too.
    fn cutoff(control: Control) -> (World, u32, u32) {
        let (c, end) = removal_world();
        let mut w = hand(c, end, control);
        let first = write(&mut w, X, 0, &[(B, 1), (A, 3), (R2, 3)]);
        let second = write(&mut w, X, 2, &[(B, 3), (A, 3), (R2, 3)]);
        play(&mut w, 1);
        (w, first, second)
    }

    #[test]
    fn a_write_received_before_the_removal_counts_a_later_one_does_not() {
        let (w, first, second) = cutoff(Control::None);
        for v in [A, R2] {
            let vd = judge(&w, w.view(v, fin(&w)), &w.held(v, fin(&w)));
            assert!(!vd.saved[second as usize - 1], "{}", cu::NAMES[v]);
        }
        let a = judge(&w, w.view(A, fin(&w)), &w.held(A, fin(&w)));
        assert!(a.counts[first as usize - 1]);
        let mut st = Stats::default();
        check(&w, &mut st);
        assert_eq!(st.failures, 0, "{:?}", st.fail.first().map(|f| &f.0));
        let (w, _, second) = cutoff(Control::NoCutoff);
        let a = judge(&w, w.view(A, fin(&w)), &w.held(A, fin(&w)));
        assert!(a.counts[second as usize - 1], "no-cutoff: B names X's later write");
        let mut st = Stats::default();
        check(&w, &mut st);
        assert!(st.kinds.contains_key("safety"));
    }

    /// X's write before its removal reaches only R1 (the thing's writer) in time: R1's addendum
    /// against the removal saves it at every node on the honest side. With listers naming only
    /// their own (`OwnOnly`) it is lost.
    fn witness(control: Control) -> (World, u32) {
        let (c, end) = removal_world();
        let mut w = hand(c, end, control);
        let id = write(&mut w, X, 0, &[(R1, 1), (A, 3), (B, 3), (C, 3), (T, 3), (R2, 3)]);
        play(&mut w, 1);
        (w, id)
    }

    #[test]
    fn a_write_only_a_witness_received_in_time_counts_by_its_addendum() {
        let (w, id) = witness(Control::None);
        for v in [A, B, R2] {
            let vd = judge(&w, w.view(v, fin(&w)), &w.held(v, fin(&w)));
            assert!(vd.saved[id as usize - 1] && !vd.counts[id as usize - 1], "{}", cu::NAMES[v]);
        }
        let mut st = Stats::default();
        check(&w, &mut st);
        assert_eq!(st.failures, 0, "{:?}", st.fail.first().map(|f| &f.0));
        let (w, _) = witness(Control::OwnOnly);
        let mut st = Stats::default();
        check(&w, &mut st);
        assert!(st.kinds.contains_key("liveness"), "own-only: the witness's word saves X's write");
    }

    /// B rotates plainly at the first epoch before A's removal reaches it and writes a role-class
    /// commit at its epoch; A merges the two heads: the write counts everywhere once settled, B's
    /// epoch closed and revoked by the removal beside it, by B's listing at the merge.
    /// X's write before its removal reaches A and R1 (the thing's writer) only, R1 snapshots it
    /// and both forget it under that snapshot; R1 is demoted as A's removal reaches the others
    /// (R1 then fetches the write again, too late to name it).
    /// A's removal cannot list the write: its own cover carries it, named by the removal, so it
    /// shows at every node on the honest side. With no own cover (`NoOwnCover`) it is lost.
    fn forgotten(control: Control) -> (World, u32) {
        let (c, end) = removal_world();
        let mut w = hand(c, end, control);
        (w.covers, w.fall[R1]) = (true, 2);
        let id = write(&mut w, X, 0, &[(A, 0), (R1, 0)]);
        let k = cover(&mut w, R1, 0, Line::new(), 0, false, false).unwrap();
        w.items[k as usize - 1].recv = std::array::from_fn(|m| if m == Z { NEVER } else { 0 });
        play(&mut w, 0);
        (w, id)
    }

    #[test]
    fn a_write_the_remover_forgot_shows_by_its_own_cover() {
        let (w, id) = forgotten(Control::None);
        assert!(w.forgot.contains(&(A, id)) && w.undone.iter().any(|u| u.0 == R1 && u.1 == id), "{:?}", w.forgot);
        for v in [B, C, T, R2] {
            let (j, held) = (w.view(v, fin(&w)), w.held(v, fin(&w)));
            let vd = judge(&w, j, &held);
            assert!(!held[id as usize - 1] && shows(&w, &held, &vd, fin(&w))[id as usize - 1], "{}", cu::NAMES[v]);
        }
        let mut st = Stats::default();
        check(&w, &mut st);
        assert_eq!(st.failures, 0, "{:?}", st.fail.first().map(|f| &f.0));
        assert!(st.by_own_cover > 0);
        let (w, _) = forgotten(Control::NoOwnCover);
        let mut st = Stats::default();
        check(&w, &mut st);
        assert!(st.kinds.contains_key("own cover"), "no own cover: the write is lost: {:?}", st.kinds);
    }

    #[test]
    fn a_siblings_write_at_its_epoch_counts_once_listed_after_the_merge() {
        let (mut c, _) = removal_world();
        let bx: [bool; N] = std::array::from_fn(|m| [A, B, C, X, T].contains(&m));
        let b = c.add(cu::Kind::Plain { at: Line::new(), removes: vec![], adds: vec![], takes: vec![], answers: vec![] }, B, B, Line::new(), None, 1, bx);
        for m in (0..N).filter(|m| *m != B && *m != Z) {
            c.items[b as usize - 1].recv[m] = 2;
        }
        // A merges at 2 (it holds both heads' seeds), delivered at 3
        let made = cu::act(&mut c, A, 2, None, false);
        for id in &made {
            for m in (0..N).filter(|m| *m != A && *m != Z) {
                c.items[*id as usize - 1].recv[m] = 3;
            }
        }
        let mut w = hand(c, 4, Control::None);
        let lb = w.c.line(b);
        let id = w.add(Kind::Content { thing: 0, plain: false }, B, lb, 1);
        for m in (0..N).filter(|m| *m != B && *m != Z) {
            w.items[id as usize - 1].recv[m] = 2;
        }
        play(&mut w, 2);
        for v in [A, C, R1, R2] {
            let j = w.view(v, fin(&w));
            assert_eq!(j.heads.len(), 1, "{}", cu::NAMES[v]);
            let vd = judge(&w, j, &w.held(v, fin(&w)));
            assert!(vd.counts[id as usize - 1], "{}", cu::NAMES[v]);
        }
        let mut st = Stats::default();
        check(&w, &mut st);
        assert_eq!(st.failures, 0, "{:?}", st.fail.first().map(|f| &f.0));
    }

    /// B rotates at the first epoch unaware of A's removal of X (both at 1, delivered at 2); A
    /// merges the two heads at 5. X writes at B's head at 2, after its removal, reaching every
    /// node at 3: it counts at P's nodes only while B's head is open. C snapshots the thing at 3:
    /// it waits (Carrying), as the write lasts at C by nothing (C's cutoff does not name it, no
    /// word does), so once the merge closes B's head the write shows nowhere on the honest side.
    /// With honest snapshots carrying it (`OpenCarried`), C's snapshot (at an epoch no removal
    /// revokes, or named as C's own) carries it on after the merge.
    fn open_head(control: Control) -> (World, Option<u32>, u32) {
        let (mut c, _) = removal_world();
        let bx: [bool; N] = std::array::from_fn(|m| [A, B, C, X, T].contains(&m));
        let b = c.add(cu::Kind::Plain { at: Line::new(), removes: vec![], adds: vec![], takes: vec![], answers: vec![] }, B, B, Line::new(), None, 1, bx);
        for m in (0..N).filter(|m| *m != B && *m != Z) {
            c.items[b as usize - 1].recv[m] = 2;
        }
        let made = cu::act(&mut c, A, 5, None, false);
        assert!(!made.is_empty());
        for id in &made {
            for m in (0..N).filter(|m| *m != A && *m != Z) {
                c.items[*id as usize - 1].recv[m] = 6;
            }
        }
        let mut w = hand(c, 7, control);
        let lb = w.c.line(b);
        let x = w.add(Kind::Content { thing: 0, plain: true }, X, lb.clone(), 2);
        for m in (0..N).filter(|m| *m != X && *m != Z) {
            w.items[x as usize - 1].recv[m] = 3;
        }
        let j = w.view(C, 3).clone();
        assert!(j.heads.contains(&lb) && judge(&w, &j, &w.held(C, 3)).counts[x as usize - 1], "X's write counts at C at B's open head");
        let k = cover(&mut w, C, 0, j.preferred.clone(), 3, true, false);
        if let Some(k) = k {
            w.items[k as usize - 1].recv = std::array::from_fn(|m| if m == Z { NEVER } else { 4 });
        }
        play(&mut w, 1);
        (w, k, x)
    }

    #[test]
    fn an_open_heads_write_lasts_in_no_snapshot() {
        let (w, k, x) = open_head(Control::None);
        assert!(k.is_none(), "C's snapshot waits");
        let mut st = Stats::default();
        check(&w, &mut st);
        assert_eq!(st.failures, 0, "{:?}", st.fail.first().map(|f| &f.0));
        for v in [A, B, C, R1] {
            let (j, held) = (w.view(v, fin(&w)), w.held(v, fin(&w)));
            assert_eq!(j.heads.len(), 1, "{}", cu::NAMES[v]);
            assert!(!shows(&w, &held, &judge(&w, j, &held), fin(&w))[x as usize - 1], "{}", cu::NAMES[v]);
        }
        let (w, k, _) = open_head(Control::OpenCarried);
        assert!(k.is_some());
        let mut st = Stats::default();
        check(&w, &mut st);
        assert!(st.kinds.contains_key("safety"), "open-carried: C's snapshot carries X's write past the merge: {:?}", st.kinds);
    }

    fn assert_holds(st: &Stats, what: &str) {
        for (m, w) in st.fail.iter().take(1) {
            println!("FAIL {m}");
            print_world(w);
        }
        assert_eq!(st.failures, 0, "{what}: {:?}", st.kinds);
    }

    /// 20 random worlds reaching commits named and vouched for at revoked epochs, the
    /// unaware-reader limit, writes saved by others' words and own covers.
    #[test]
    fn random_worlds_hold() {
        let st = run_random(20, 5, Control::None);
        assert!(st.named > 0 && st.vouched > 0 && st.unaware > 0 && st.by_others > 0 && st.own_covers > 0 && st.obliged > 0, "{st:?}");
        assert_holds(&st, "random");
    }

    fn control_fails(control: Control, kind: &str) {
        let st = run_random(20, 1, control);
        assert!(st.kinds.contains_key(kind), "{control:?}: {:?}", st.kinds);
    }

    #[test]
    fn no_cutoff_fails_safety() {
        control_fails(Control::NoCutoff, "safety");
    }

    #[test]
    fn own_only_fails_liveness() {
        control_fails(Control::OwnOnly, "liveness");
    }

    #[test]
    fn void_uncounted_fails_liveness() {
        control_fails(Control::VoidUncounted, "liveness");
    }

    fn var(k: &str) -> Option<u64> {
        std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")))
    }

    /// Worlds from `OSIS_ROLES_START` (default 0), `OSIS_ROLES_SEEDS` many (2000), a thread per
    /// core.
    #[test]
    #[ignore = "property"]
    fn random_worlds_hold_large() {
        let start = var("OSIS_ROLES_START").unwrap_or(0);
        let n = var("OSIS_ROLES_SEEDS").unwrap_or(2000);
        let st = crate::on_every_core(|th, threads, st| {
            let mut rng = Rng(Rng::thread(start, th).0 | 1);
            for _ in 0..n.div_ceil(threads as u64) {
                check(&random_world(&mut rng, Control::None), st);
            }
        });
        st.print("epochs");
        assert_holds(&st, &format!("OSIS_ROLES_START={start}"));
    }
}
