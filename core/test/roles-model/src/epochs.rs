//! Account signing epochs (issues/account-signing.md): one account P whose nodes sign as P at
//! a signing epoch. Removing a node is a rotation of the signing epoch; what still counts of
//! a closed epoch is decided as for any ended standing (the demoter-frontier rule with addenda,
//! spec/permissions.md §5): by what the rotator had received (the rotation's list), by what
//! other writers of the thing had received by the rotation's `ts` (addenda, as built), and by
//! P's own later word at a counting epoch (a listing, as a re-grant revives a holder's).
//! Nothing reads the author's `ts`, nothing reads the inner (node) signature: it only guides
//! what P's honest nodes list.
//!
//! The chain: rotations form a DAG; a rotation's line is it and every rotation it descends
//! from, through the epoch it is signed at and the forks it names (a merge is signed at each
//! named fork's epoch too, so only a holder of that epoch can accept the fork). A counting
//! rotation closes every epoch that does not descend from it: its own, those it supersedes,
//! and every epoch minted beside it (a concurrent rotation's, made without it, which may box
//! the node it removes); an epoch is open only where it descends from every counting
//! rotation held. Concurrent rotations at one epoch fork and both count, each closing the
//! other's epoch until a merge. A rotation supersedes its own epoch and epochs of other
//! lines; a merge names the forks it accepts, and a rotation it supersedes without naming is
//! rejected with everything below it, if the merge itself counts (counting is decided
//! well-foundedly: once a rotation's parent and every rotation rejecting it are decided). A
//! line is contested from below: a rotation signed at e rejects nothing on a line through e
//! (a line holding a rotation signed at e), so a removed node holding a closed epoch, or a
//! sibling's epoch a merge has joined, cannot void its removal, only fork. Two lines each
//! rejecting the other are an account-level dispute, settled per node by its side, as admin
//! disputes are (notes/disputes.md): the trust set names a line; the default is the line
//! holding the first-received contested rotation; P's own nodes side with node 0's line
//! (node 0 is never removed: it is the remover, reading the devices actor's roster).
//!
//! Labels: things sit in one or more labels (a thing in two groups). Every node opens some
//! labels and receives what is on a thing in one of them. A rotation's list is one part per
//! label the rotator opens, each naming the closed-epoch commits with an entry under that
//! label; within the parts, the list is per thing (`Kind::List`), a chain certificate that
//! reaches every reader of the thing, also under a label the rotator did not open. Parts are
//! bounded (`World::bound`, IDs per part): a part whose special commits (anything but plain
//! content) pass it refuses the rotation (the removal cannot be written); plain content past
//! it, received last first, goes into the rotator's later listings. A list over the bound is
//! bad input. Listings are per thing as well, P items on that thing (a later rotation lists
//! a listing at an epoch it closes by ID, like any of P's commits).
//!
//! Membership: node 0 removes X (node 1) and, in some worlds, then Y (node 2); X may be
//! re-added later (a devices-actor grant, no rotation: it reads every epoch seed again).
//! A node writes hostile items while removed (between its removal and its re-add). A removed
//! node signs at the newest epoch it was boxed, open or closed: its own forks, else rotations
//! made before its removal or by a sibling that had not received the removal (it boxes the
//! whole roster).
//!
//! Honest policies (what the generator's parties write; none is a judgment input): node 0
//! rotates at each removal and merges out every fork it receives, superseding the other
//! line whole, signed at its own line's tip. One cutoff for every lister: others' commits at
//! epoch e count in a list, listing or addendum only if received before the earliest
//! rotation closing e (the rotator's or a listing node's view: any counting closer it holds;
//! a witness answering rotation r: a closer on r's line); a node's own commits always. Each
//! member node of P, whenever what it holds changes and while it holds an open epoch, writes
//! per thing it reads a listing at that epoch naming the commits at closed counting epochs
//! that no counting list it holds names: its own (judged by inner signature), every commit
//! of a re-added node, and others' by the cutoff (plain content its own rotation left out
//! past the bound among them), leaving out commits a snapshot it judges valid covers when
//! `omit_covered`. A witness writer answers
//! every rotation whose chain it holds (its receipts are facts, whatever its side) by the
//! cutoff (a later concurrent closer's window is today's stated limit), again whenever what
//! it holds changes.
//! A witness's snapshot may fall (`Kind::Fall`, a held event standing for its author's
//! demotion).
//!
//! Every node is also an observer with its own receipts and labels. Judgment is a pure
//! function of the held set and the side; worlds are checked at every observer and every
//! prefix of its receipts.
//!
//! Search: `roles-model -- N epochs` (random), `-- 0 epochs-exh` (three exhaustive families).

use crate::shrink::LATE;
use crate::Rng;
use std::collections::HashSet;

/// Epoch ids: 0 the first; rotations mint the rest, increasing.
pub type Epoch = u32;
pub type Label = usize;
pub type Thing = usize;

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Plain content, or a special write (role-class, admin-only, purge: witnesses never
    /// list it).
    Content { thing: Thing, plain: bool },
    /// Compaction snapshot carrying these content items.
    Snap { thing: Thing, carries: Vec<u32> },
    /// A witness's snapshot (by item id) turning invalid everywhere this is held (its author
    /// demoted by a frontier that missed it).
    Fall { snap: u32 },
    /// Signed at `at`, supersedes `supersedes` (a plain rotation: just `at`), accepts the
    /// fork rotations `names` (by item id), mints `new`. Its list is its `List` items.
    Rotation { at: Epoch, new: Epoch, supersedes: Vec<Epoch>, names: Vec<u32> },
    /// Rotation `rot`'s list for one thing: P's commits on it at the epochs `rot` closes.
    List { rot: u32, thing: Thing, lists: Vec<u32> },
    /// A listing's list for one thing: P's word at epoch `at` that these commits count.
    Listing { at: Epoch, thing: Thing, lists: Vec<u32> },
    /// A witness writer's addendum on `thing` against a rotation or a demotion (by item id).
    Addendum { against: u32, thing: Thing, lists: Vec<u32> },
    /// A's explicit demotion of P below write on `thing`, with A's frontier.
    Demotion { thing: Thing, frontier: Vec<u32> },
}

impl Kind {
    pub fn thing(&self) -> Option<Thing> {
        match self {
            Kind::Content { thing, .. } | Kind::Snap { thing, .. } | Kind::List { thing, .. } | Kind::Listing { thing, .. } | Kind::Addendum { thing, .. } | Kind::Demotion { thing, .. } => Some(*thing),
            Kind::Fall { .. } | Kind::Rotation { .. } => None,
        }
    }
    fn is_rot(&self) -> bool {
        matches!(self, Kind::Rotation { .. })
    }
    fn plain(&self) -> bool {
        matches!(self, Kind::Content { plain: true, .. })
    }
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub kind: Kind,
    pub author: usize,
    /// The signing epoch, for P's commits (a rotation's `List` items have none: they are
    /// parts of it).
    pub epoch: Option<Epoch>,
    /// Real time it was made.
    pub t: u32,
    /// Its own stamp (a hostile write may backdate).
    pub ts: u32,
    /// [node] receipt time (the author's its `t`); `LATE` never.
    pub recv: Vec<u32>,
    /// Written by a node of P while removed.
    pub hostile: bool,
}

#[derive(Clone, Debug)]
pub struct World {
    /// P's nodes are 0..np; node 0 the remover, X = 1, Y = 2.
    pub np: usize,
    pub nodes: usize,
    /// Per thing: the labels it sits in.
    pub things: Vec<Vec<Label>>,
    /// Per node: the labels it opens.
    pub opens: Vec<Vec<Label>>,
    /// Per node: the thing it writes on, for a writer from another account.
    pub writer: Vec<Option<Thing>>,
    pub admin: Option<usize>,
    /// Per node: real time of its removal (node 0's rotation), `LATE` never.
    pub left: Vec<u32>,
    /// Per node: real time of its re-add, `LATE` never.
    pub readded: Vec<u32>,
    /// IDs per rotation part.
    pub bound: Option<usize>,
    pub items: Vec<Item>,
    /// Lists leave out commits a snapshot the lister holds valid covers.
    pub omit_covered: bool,
    /// Honest rotations the bound refused (a removal or merge that could not be written).
    pub refused: u32,
    /// (rotator, commit id): plain content its rotation left out past the bound.
    pub overflow: Vec<(usize, u32)>,
}

pub const X: usize = 1;
pub const Y: usize = 2;

/// Item ids are their index plus one.
fn idx(id: u32) -> usize {
    id as usize - 1
}

#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub counting: Vec<bool>,
    /// Epochs a counting rotation closes: every held epoch some counting rotation does not
    /// descend from.
    pub closed: Vec<Epoch>,
    pub as_p: Vec<bool>,
    pub valid: Vec<bool>,
    pub visible: Vec<bool>,
    /// Two held merges reject each other.
    pub dispute: bool,
}

impl World {
    /// The shape of a world with no items yet.
    pub fn shape(np: usize, things: Vec<Vec<Label>>, opens: Vec<Vec<Label>>, writer: Vec<Option<Thing>>, admin: Option<usize>, bound: Option<usize>, omit_covered: bool) -> World {
        let nodes = opens.len();
        assert_eq!(writer.len(), nodes);
        World { np, nodes, things, opens, writer, admin, left: vec![LATE; nodes], readded: vec![LATE; nodes], bound, items: vec![], omit_covered, refused: 0, overflow: vec![] }
    }

    fn is_p(&self, i: usize) -> bool {
        self.items[i].epoch.is_some()
    }

    /// Node n is a member of P at t.
    pub fn member(&self, n: usize, t: u32) -> bool {
        n < self.np && !(self.left[n] <= t && t < self.readded[n])
    }

    /// Node n is a member of P once everything happened.
    pub fn final_member(&self, n: usize) -> bool {
        n < self.np && (self.left[n] >= LATE || self.readded[n] < LATE)
    }

    /// Node n was removed and re-added by t.
    fn readded_by(&self, n: usize, t: u32) -> bool {
        n < self.np && self.left[n] < self.readded[n] && self.readded[n] <= t
    }

    /// Node n opens a label of the thing.
    pub fn reads(&self, n: usize, thing: Thing) -> bool {
        self.things[thing].iter().any(|l| self.opens[n].contains(l))
    }

    /// Item i reaches node n: it is on a thing n reads, or on none (rotations, falls).
    pub fn reaches(&self, i: usize, n: usize) -> bool {
        self.items[i].kind.thing().map_or(true, |t| self.reads(n, t))
    }

    /// The removal of node a: node 0's rotation at its removal time.
    fn removal_of(&self, a: usize) -> Option<usize> {
        let tl = self.left[a];
        self.items.iter().position(|i| i.author == 0 && i.kind.is_rot() && i.t == tl)
    }

    /// Rotations in a mutual contest among the held ones: a rejects a rotation on b's chain
    /// and b one on a's.
    pub fn parties(&self, held: &[bool]) -> Vec<usize> {
        let n = self.items.len();
        let lines = self.lines(held);
        let contests = |a: usize, b: usize| self.line_of(held, b).iter().any(|&c| c != a && self.rejects(held, &lines, a, c));
        let rots: Vec<usize> = (0..n).filter(|&i| held[i] && self.items[i].kind.is_rot()).collect();
        rots.iter().copied().filter(|&a| rots.iter().any(|&b| a != b && contests(a, b) && contests(b, a))).collect()
    }

    /// The side an observer takes: P's nodes side with node 0's line as far as they hold it
    /// (they read the devices actor's roster); anyone else with the party it received first.
    pub fn default_side(&self, o: usize, held: &[bool]) -> Option<usize> {
        if o < self.np {
            // Node 0's newest rotation whose chain it holds whole.
            let rooted = |i: usize| self.verified(held, i);
            return (0..self.items.len()).filter(|&i| held[i] && self.items[i].author == 0 && self.items[i].kind.is_rot() && rooted(i)).max_by_key(|&i| self.items[i].t);
        }
        let parties = self.parties(held);
        if parties.is_empty() {
            return None;
        }
        // The party whose line holds the first-received rotation not common to every party.
        let chains: Vec<Vec<usize>> = parties.iter().map(|&p| self.line_of(held, p)).collect();
        let common = |i: usize| chains.iter().all(|c| c.contains(&i));
        parties
            .iter()
            .copied()
            .zip(chains.iter())
            .min_by_key(|(_, c)| c.iter().copied().filter(|&i| !common(i)).map(|i| (self.items[i].recv[o], self.items[i].id)).min().unwrap_or((LATE, u32::MAX)))
            .map(|(p, _)| p)
    }

    /// A rotation and the rotations minting its ancestors, among the held ones.
    pub fn chain_of(&self, held: &[bool], s: usize) -> Vec<usize> {
        let at = |i: usize| match &self.items[i].kind {
            Kind::Rotation { at, .. } => *at,
            _ => 0,
        };
        let minted = |e: Epoch| (0..self.items.len()).find(|&i| held[i] && matches!(&self.items[i].kind, Kind::Rotation { new, .. } if *new == e));
        let mut chain = vec![s];
        let mut e = at(s);
        while e != 0 {
            match minted(e) {
                Some(p) if !chain.contains(&p) => {
                    chain.push(p);
                    e = at(p);
                }
                _ => break,
            }
        }
        chain
    }

    /// Rotation s's chain is held back to epoch 0: only then can a node verify it, so nobody
    /// answers, merges out or sides with a rotation before (a witness, node 0, a member).
    pub fn verified(&self, held: &[bool], s: usize) -> bool {
        self.chain_of(held, s).last().map_or(false, |&c| matches!(self.items[c].kind, Kind::Rotation { at: 0, .. }))
    }

    /// A rotation and every held rotation it descends from: through the epoch it is signed
    /// at and the fork rotations it names (a merge accepts them).
    pub fn line_of(&self, held: &[bool], s: usize) -> Vec<usize> {
        let minted = |e: Epoch| (0..self.items.len()).find(|&i| held[i] && matches!(&self.items[i].kind, Kind::Rotation { new, .. } if *new == e));
        let mut line = vec![s];
        let mut k = 0;
        while k < line.len() {
            let Kind::Rotation { at, names, .. } = &self.items[line[k]].kind else { unreachable!() };
            let mut next: Vec<usize> = names.iter().map(|&id| idx(id)).filter(|&i| i < self.items.len() && held[i] && self.items[i].kind.is_rot()).collect();
            next.extend(minted(*at));
            for p in next {
                if !line.contains(&p) {
                    line.push(p);
                }
            }
            k += 1;
        }
        line
    }

    /// Per item: its line if it is a held rotation, else empty.
    fn lines(&self, held: &[bool]) -> Vec<Vec<usize>> {
        (0..self.items.len()).map(|i| if held[i] && self.items[i].kind.is_rot() { self.line_of(held, i) } else { vec![] }).collect()
    }

    /// The epochs a rotation is signed at: the one it rotates, and, for a merge, the epoch of
    /// each fork it names (a merge is signed with every key it joins, so only a holder of a
    /// fork's epoch can accept that fork).
    fn signed_at(&self, held: &[bool], s: usize) -> Vec<Epoch> {
        let Kind::Rotation { at, names, .. } = &self.items[s].kind else { return vec![] };
        let mut e = vec![*at];
        for &id in names {
            let i = idx(id);
            if i < self.items.len() && held[i] {
                if let Kind::Rotation { new, .. } = &self.items[i].kind {
                    e.push(*new);
                }
            }
        }
        e
    }

    /// m rejects r: m supersedes r's epoch without naming r. A rotation never rejects its
    /// own line, and one signed at e rejects nothing on a line through e: r on the line of a
    /// rotation signed at e, or one on r's (forks only fork; a line is contested from below,
    /// by a merge signed under the other fork).
    fn rejects(&self, held: &[bool], lines: &[Vec<usize>], m: usize, r: usize) -> bool {
        let (Kind::Rotation { at, supersedes, names, .. }, Kind::Rotation { new: rnew, .. }) = (&self.items[m].kind, &self.items[r].kind) else { return false };
        *rnew != *at
            && supersedes.contains(rnew)
            && !names.contains(&self.items[r].id)
            && !lines[m].contains(&r)
            && !(0..self.items.len()).any(|s| held[s] && self.items[s].kind.is_rot() && self.signed_at(held, s).contains(at) && (lines[s].contains(&r) || lines[r].contains(&s)))
    }

    /// Epoch e descends from held rotation r: r is on the line of e's minting rotation
    /// (epoch 0 descends from none).
    pub fn descends(&self, held: &[bool], e: Epoch, r: usize) -> bool {
        e != 0 && (0..self.items.len()).find(|&i| held[i] && matches!(&self.items[i].kind, Kind::Rotation { new, .. } if *new == e)).map_or(false, |m| self.line_of(held, m).contains(&r))
    }

    /// The counting rotations that close epoch e: every one e does not descend from.
    pub fn closers(&self, held: &[bool], v: &Verdict, e: Epoch) -> Vec<usize> {
        (0..self.items.len()).filter(|&r| v.counting[r] && !self.descends(held, e, r)).collect()
    }

    /// Validity as a pure function of the held set and the side (`trust`: the rotation
    /// sided with, if any).
    pub fn judge(&self, held: &[bool], trust: Option<usize>) -> Verdict {
        let n = self.items.len();
        let rot = |i: usize| match &self.items[i].kind {
            Kind::Rotation { at, new, supersedes, names } => Some((*at, *new, supersedes, names)),
            _ => None,
        };
        // Epoch e is minted by this held rotation.
        let minted = |e: Epoch| (0..n).find(|&i| held[i] && rot(i).map_or(false, |r| r.1 == e));
        let lines = self.lines(held);
        let rejects = |m: usize, r: usize| self.rejects(held, &lines, m, r);
        // Status: None undetermined, Some(true) counting, Some(false) void. Seeds: siding
        // with s, whatever rejects a rotation on s's chain is void. Then a rotation is
        // decided once its parent and every held rotation that rejects it are: void if the
        // parent is void or a counting one rejects it, else counting. A contest no side
        // settles stays undetermined, and counts for nothing.
        let mut status: Vec<Option<bool>> = (0..n).map(|i| if held[i] && rot(i).is_some() { None } else { Some(false) }).collect();
        if let Some(s) = trust {
            let chain = self.line_of(held, s);
            for m in 0..n {
                if held[m] && rot(m).is_some() && chain.iter().any(|&c| c != m && rejects(m, c)) {
                    status[m] = Some(false);
                }
            }
        }
        loop {
            let mut changed = false;
            for r in 0..n {
                if status[r].is_some() {
                    continue;
                }
                let at = rot(r).unwrap().0;
                let parent = if at == 0 { Some(true) } else { minted(at).map_or(Some(false), |p| status[p]) };
                if parent == Some(false) {
                    status[r] = Some(false);
                    changed = true;
                    continue;
                }
                let rejectors: Vec<usize> = (0..n).filter(|&m| held[m] && m != r && rot(m).is_some() && rejects(m, r)).collect();
                if rejectors.iter().any(|&m| status[m] == Some(true)) {
                    status[r] = Some(false);
                    changed = true;
                } else if parent == Some(true) && rejectors.iter().all(|&m| status[m] == Some(false)) {
                    status[r] = Some(true);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let counting: Vec<bool> = (0..n).map(|i| held[i] && rot(i).is_some() && status[i] == Some(true)).collect();
        let epoch_counts = |e: Epoch| e == 0 || minted(e).map_or(false, |r| counting[r]);
        // A counting rotation closes every epoch that does not descend from it: its own, the
        // ones it supersedes, and every epoch minted beside it (a concurrent rotation's, which
        // may box the node it removes). An epoch is open only where it descends from every
        // counting rotation held.
        let descends = |e: Epoch, r: usize| e != 0 && minted(e).map_or(false, |m| lines[m].contains(&r));
        let closes = |r: usize, e: Epoch| counting[r] && !descends(e, r);
        let closed_list: Vec<Epoch> = {
            let mut c: Vec<Epoch> = std::iter::once(0).chain((0..n).filter_map(|i| if held[i] { rot(i).map(|r| r.1) } else { None })).filter(|&e| (0..n).any(|r| closes(r, e))).collect();
            c.sort_unstable();
            c.dedup();
            c
        };
        let closed = |e: Epoch| closed_list.contains(&e);
        let dispute = !self.parties(held).is_empty();
        // A's demotion (at most one held).
        let dem = (0..n).find(|&i| held[i] && matches!(self.items[i].kind, Kind::Demotion { .. }));
        let thing = |i: usize| self.items[i].kind.thing();
        // Witness addendum a (held, by a writer of i's thing, on it) lists i against
        // `against`, i stamped before it and a after it, i plain content.
        let vouched_by_witness = |i: usize, against: usize| {
            self.items[i].kind.plain()
                && (0..n).any(|a| {
                    held[a] && match &self.items[a].kind {
                        Kind::Addendum { against: ag, thing: at, lists } => {
                            Some(*at) == thing(i) && self.writer[self.items[a].author] == Some(*at) && *ag == self.items[against].id && lists.contains(&self.items[i].id) && self.items[i].ts < self.items[against].ts && self.items[against].ts < self.items[a].ts
                        }
                        _ => false,
                    }
                })
        };
        let over = |l: &Vec<u32>| self.bound.map_or(false, |b| l.len() > b);
        // (thing, id) a counting rotation's list names; a list over the bound is bad input.
        let rot_listed: HashSet<(Thing, u32)> = (0..n)
            .filter(|&i| held[i])
            .flat_map(|i| match &self.items[i].kind {
                Kind::List { rot, thing, lists } if counting[idx(*rot)] && !over(lists) => lists.iter().map(|&c| (*thing, c)).collect(),
                _ => vec![],
            })
            .collect();
        // Counts as P's: least fixpoint over listings (a listing at a closed epoch needs one).
        let mut as_p = vec![false; n];
        loop {
            let next: Vec<bool> = (0..n)
                .map(|i| {
                    if !held[i] {
                        return false;
                    }
                    let Some(e) = self.items[i].epoch else { return true };
                    if !epoch_counts(e) {
                        return false;
                    }
                    if !closed(e) || rot(i).is_some() {
                        return true;
                    }
                    let id = self.items[i].id;
                    let t = thing(i).unwrap();
                    rot_listed.contains(&(t, id))
                        || (0..n).any(|v| as_p[v] && matches!(&self.items[v].kind, Kind::Listing { thing: lt, lists, .. } if *lt == t && lists.contains(&id)))
                        || (0..n).any(|r| closes(r, e) && vouched_by_witness(i, r))
                })
                .collect();
            if next == as_p {
                break;
            }
            as_p = next;
        }
        // Standing on the demoted thing against A's demotion (P's content and snapshots).
        let standing = |i: usize| match dem {
            Some(d) if self.is_p(i) && matches!(self.items[i].kind, Kind::Content { .. } | Kind::Snap { .. }) && thing(i) == thing(d) => {
                if self.items[i].ts >= self.items[d].ts {
                    return false;
                }
                let Kind::Demotion { frontier, .. } = &self.items[d].kind else { unreachable!() };
                frontier.contains(&self.items[i].id) || vouched_by_witness(i, d)
            }
            _ => true,
        };
        let fallen = |i: usize| (0..n).any(|f| held[f] && matches!(&self.items[f].kind, Kind::Fall { snap } if *snap == self.items[i].id));
        let valid: Vec<bool> = (0..n)
            .map(|i| {
                held[i] && match &self.items[i].kind {
                    Kind::Snap { .. } if fallen(i) => false,
                    _ if self.is_p(i) => as_p[i] && standing(i),
                    _ => true,
                }
            })
            .collect();
        let visible: Vec<bool> = (0..n)
            .map(|i| {
                matches!(self.items[i].kind, Kind::Content { .. })
                    && (valid[i] || (0..n).any(|s| valid[s] && matches!(&self.items[s].kind, Kind::Snap { carries, .. } if carries.contains(&self.items[i].id))))
            })
            .collect();
        Verdict { counting, closed: closed_list, as_p, valid, visible, dispute }
    }

    /// What observer o holds by `tau`.
    pub fn held_at(&self, o: usize, tau: u32) -> Vec<bool> {
        self.items.iter().map(|i| i.recv[o] <= tau).collect()
    }

    /// Honest attestations: rotation lists, listings by members, witnesses' addenda.
    fn honest_attestation(&self, i: usize) -> bool {
        !self.items[i].hostile && matches!(self.items[i].kind, Kind::Listing { .. } | Kind::Addendum { .. } | Kind::List { .. })
    }

    /// The side taken is an honest line, or there is nothing to side on.
    fn owner_sided(&self, trust: Option<usize>) -> bool {
        trust.map_or(true, |s| !self.items[s].hostile)
    }

    /// A hostile commit (or a listing naming it) listed by an honest sibling's rotation, or
    /// named by its listing, made before the removal of the commit's author reached that
    /// sibling (today's concurrent-demoter limit; the listing case cued by the removed node's
    /// own fork, the only closer the sibling holds).
    fn listed_by_unaware_closer(&self, c: usize) -> bool {
        let r0 = self.removal_of(self.items[c].author);
        let id = self.items[c].id;
        let unaware_listing = |id: u32| {
            self.items.iter().any(|l| !l.hostile && l.author < self.np && matches!(&l.kind, Kind::Listing { lists, .. } if lists.contains(&id)) && r0.map_or(true, |r0| self.items[r0].recv[l.author] > l.t))
        };
        if unaware_listing(id) || self.items.iter().any(|l| l.hostile && matches!(&l.kind, Kind::Listing { lists, .. } if lists.contains(&id)) && unaware_listing(l.id)) {
            return true;
        }
        (0..self.items.len()).any(|r| {
            let it = &self.items[r];
            !it.hostile
                && it.author != 0
                && it.kind.is_rot()
                && r0.map_or(true, |r0| self.items[r0].recv[it.author] >= it.t)
                && self.items.iter().any(|a| match &a.kind {
                    Kind::List { rot, lists, .. } => *rot == it.id && lists.contains(&id),
                    Kind::Addendum { against, lists, .. } => *against == it.id && lists.contains(&id),
                    _ => false,
                })
        })
    }

    /// Hostile item c reads valid at `held` because of something its author signed at an
    /// epoch minted by an honest rotation that does not descend from its removal (a
    /// sibling's, concurrent with the removal, boxing the removed node): c itself is signed
    /// there, or c reads invalid once the hostile items signed there are dropped.
    fn at_concurrent_epoch(&self, c: usize, held: &[bool], trust: Option<usize>) -> bool {
        let all = vec![true; self.items.len()];
        let r0 = self.removal_of(self.items[c].author);
        let concurrent = |e: Option<Epoch>| {
            e.map_or(false, |e| {
                self.items.iter().enumerate().any(|(r, ri)| !ri.hostile && matches!(&ri.kind, Kind::Rotation { new, .. } if *new == e) && r0.map_or(false, |r0| !self.line_of(&all, r).contains(&r0)))
            })
        };
        if concurrent(self.items[c].epoch) {
            return true;
        }
        let mut less = held.to_vec();
        for (l, li) in self.items.iter().enumerate() {
            if li.hostile && concurrent(li.epoch) {
                less[l] = false;
            }
        }
        !self.judge(&less, trust).valid[c]
    }

    /// Epoch e is minted by an honest rotation (or is the first).
    fn honest_epoch(&self, e: Epoch) -> bool {
        e == 0 || self.items.iter().any(|r| !r.hostile && matches!(&r.kind, Kind::Rotation { new, .. } if *new == e))
    }

    /// Expected final visibility of a legitimate P item c (content or listing), from the
    /// history alone: some party whose word stands received it in time at every level that
    /// ended its standing. `at_least`: the lower bound (received before the earliest honest
    /// closer); else the upper bound (before any honest closer's `ts`).
    fn expected(&self, c: usize, at_least: bool, depth: u32) -> bool {
        let it = &self.items[c];
        let Some(e) = it.epoch else { return true };
        if !self.honest_epoch(e) || depth > 6 {
            return false;
        }
        let thing = it.kind.thing().unwrap();
        let plain = it.kind.plain();
        let witness_by = |cut: u32| plain && (0..self.nodes).any(|w| self.writer[w] == Some(thing) && it.recv[w] < cut);
        // Rotations ending e's standing: every one e does not descend from.
        let all = vec![true; self.items.len()];
        let ends = |r: usize| self.items[r].kind.is_rot() && !self.descends(&all, e, r);
        let closers: Vec<usize> = (0..self.items.len()).filter(|&r| !self.items[r].hostile && ends(r)).collect();
        let chain = if closers.is_empty() {
            true
        } else {
            let earliest = closers.iter().map(|&r| self.items[r].ts).min().unwrap();
            let latest = closers.iter().map(|&r| self.items[r].ts).max().unwrap();
            // Saved by receipts before `cut`: the author's own word as a member at the end,
            // a final member's receipt, a witness's, a rotator's list, or an honest listing
            // by a node that received it in time and whose own word survives.
            let saved_by = |cut: u32| {
                self.final_member(it.author)
                    || (0..self.np).any(|n| n != it.author && self.final_member(n) && it.recv[n] < cut)
                    || witness_by(cut)
                    || closers.iter().any(|&r| it.recv[self.items[r].author] < cut.min(self.items[r].ts + 1) && self.items.iter().any(|l| matches!(&l.kind, Kind::List { rot, lists, .. } if *rot == self.items[r].id && lists.contains(&it.id))))
                    || (0..self.items.len()).any(|l| {
                        let li = &self.items[l];
                        !li.hostile && matches!(&li.kind, Kind::Listing { lists, .. } if lists.contains(&it.id)) && (li.author == it.author || it.recv[li.author] < cut) && self.expected(l, at_least, depth + 1)
                    })
            };
            // A member that had not yet received the removal takes a removed node's fork as
            // the closer: its cutoff is that fork's `ts`.
            let any_latest = (0..self.items.len()).filter(|&r| ends(r)).map(|r| self.items[r].ts).max().unwrap();
            if at_least {
                saved_by(earliest)
            } else {
                saved_by(latest.max(any_latest)) || closers.iter().any(|&r| it.recv[self.items[r].author] < self.items[r].t || witness_by(self.items[r].ts))
            }
        };
        let level1 = match (0..self.items.len()).find(|&i| matches!(self.items[i].kind, Kind::Demotion { .. })) {
            Some(d) if matches!(it.kind, Kind::Content { .. }) && self.items[d].kind.thing() == Some(thing) => {
                let td = self.items[d].ts;
                it.ts < td && (it.recv[self.items[d].author] < td || witness_by(td))
            }
            _ => true,
        };
        chain && level1
    }
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub worlds: u64,
    pub hostile_valid_owner_sided: u64,
    pub hostile_valid_fork_window: u64,
    pub hostile_valid_unaware_closer: u64,
    /// Hostile valid, signed at a sibling's concurrent epoch the removal did not close.
    pub hostile_valid_concurrent_epoch: u64,
    pub hostile_revived_by_readd: u64,
    pub hostile_visible_through_witness_snapshot: u64,
    pub liveness_fail: u64,
    pub upper_fail: u64,
    pub saved_by_later_closer: u64,
    pub monotone_fail: u64,
    /// A removal void at an observer where every removed node's rotation it holds is signed
    /// at an epoch node 0's line (the removal and node 0's later rotations) is signed at.
    pub removal_voided: u64,
    pub dispute_worlds: u64,
    pub thief_sided_observers: u64,
    pub side_changes_reading: u64,
    pub omit_loses: u64,
    pub omit_loses_snapshot_fallen: u64,
    pub omit_saves_ids: u64,
    pub list_all_ids: u64,
    /// A listed write reads invalid while the observer holds the rotation but not that
    /// thing's list yet.
    pub part_pending: u64,
    // New dimensions, counted per world.
    pub w_multi_label: u64,
    pub w_two_group_thing: u64,
    pub w_unopened_label: u64,
    pub w_successive: u64,
    pub w_readd: u64,
    pub w_overflow: u64,
    pub w_refused: u64,
    /// Final readings beyond the upper bound while a removed node's fork counts (its merge
    /// refused by the bound).
    pub final_fork_counts: u64,
    /// Worlds with an honest rotation by a node other than the remover (a sibling's
    /// concurrent rotation, or the removed node's own before its removal).
    pub w_sibling_rotation: u64,
    /// Worlds failing a hard check without such a rotation.
    pub failed_without_sibling_rotation: u64,
    /// Worlds whose final readings are not checked: a fork stands whose merge the bound refused.
    pub unsettled: u64,
    pub w_bad_list: u64,
    /// Final readings: a listing at a closed epoch counting (listed by ID or named).
    pub closed_listing_counts: u64,
    /// Final readings: P content on a thing in no label the rotator opened, at a closed
    /// epoch, visible.
    pub unopened_saved: u64,
    /// Final readings: a re-added node's write from while it was removed, visible.
    pub readd_revived: u64,
    /// Final readings: content past the bound, visible.
    pub overflow_saved: u64,
    pub fail: Option<World>,
    pub fail_live: Option<World>,
}

impl Stats {
    pub fn merge(&mut self, o: Stats) {
        macro_rules! add {
            ($($f:ident),*) => { $( self.$f += o.$f; )* };
        }
        add!(worlds, hostile_valid_owner_sided, hostile_valid_fork_window, hostile_valid_unaware_closer, hostile_valid_concurrent_epoch, hostile_revived_by_readd, hostile_visible_through_witness_snapshot, liveness_fail, upper_fail, saved_by_later_closer, monotone_fail, removal_voided, dispute_worlds, thief_sided_observers, side_changes_reading, omit_loses, omit_loses_snapshot_fallen, omit_saves_ids, list_all_ids, part_pending, w_multi_label, w_two_group_thing, w_unopened_label, w_successive, w_readd, w_overflow, w_refused, final_fork_counts, w_sibling_rotation, failed_without_sibling_rotation, unsettled, w_bad_list, closed_listing_counts, unopened_saved, readd_revived, overflow_saved);
        if self.fail.is_none() {
            self.fail = o.fail;
        }
        if self.fail_live.is_none() {
            self.fail_live = o.fail_live;
        }
    }
    pub fn hard_failures(&self) -> u64 {
        self.hostile_valid_owner_sided + self.hostile_valid_concurrent_epoch + self.liveness_fail + self.upper_fail + self.monotone_fail + self.removal_voided
    }
    pub fn print(&self, name: &str) {
        println!(
            "{name}: {} worlds; hard failures {} (hostile valid at owner-sided observer {}, of it signed at a sibling's concurrent epoch {}, liveness {}, valid beyond the upper bound {}, monotone {}, removal voided after the merge {})",
            self.worlds,
            self.hard_failures(),
            self.hostile_valid_owner_sided + self.hostile_valid_concurrent_epoch,
            self.hostile_valid_concurrent_epoch,
            self.liveness_fail,
            self.upper_fail,
            self.monotone_fail,
            self.removal_voided
        );
        println!("  worlds with a sibling's rotation {}; worlds failing a hard check without one {}", self.w_sibling_rotation, self.failed_without_sibling_rotation);
        println!(
            "  dimensions (worlds): several labels {}, a thing in two labels {}, rotator missing a label with P content {}, successive removals {}, re-add {}, part past the bound {}, a rotation refused by the bound {} (unsettled: a fork stands, final readings unchecked {}), thief list over the bound {}",
            self.w_multi_label, self.w_two_group_thing, self.w_unopened_label, self.w_successive, self.w_readd, self.w_overflow, self.w_refused, self.unsettled, self.w_bad_list
        );
        println!(
            "  final readings: closed-epoch listing counts {}, saved under a label the rotator did not open {}, re-added node's removed-time write revived {}, plain content past the bound saved {}",
            self.closed_listing_counts, self.unopened_saved, self.readd_revived, self.overflow_saved
        );
        println!(
            "  counted: saved only by a later concurrent closer's receipts {}; fork window: hostile valid {}; listed by an unaware sibling's concurrent rotation (stated limit) {}; revived by a re-add {}; hostile visible via a witness snapshot (stated limit) {}; final reading through a removed node's unmerged fork {}; listed write pending its part {}; disputes {} worlds, thief-sided observers {}, side changes the reading {}; omit-covered loses a write in {} worlds ({} with the snapshot fallen), ids listed {} vs {} listing all",
            self.saved_by_later_closer,
            self.hostile_valid_fork_window,
            self.hostile_valid_unaware_closer,
            self.hostile_revived_by_readd,
            self.hostile_visible_through_witness_snapshot,
            self.final_fork_counts,
            self.part_pending,
            self.dispute_worlds,
            self.thief_sided_observers,
            self.side_changes_reading,
            self.omit_loses,
            self.omit_loses_snapshot_fallen,
            self.omit_saves_ids,
            self.list_all_ids,
        );
    }
}

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Failure details on stdout (`EPOCHS_DEBUG`, rechecking the first failing worlds).
fn debug() -> bool {
    DEBUG.load(std::sync::atomic::Ordering::Relaxed)
}

/// Every check on one world.
pub fn check(w: &World, st: &mut Stats) {
    st.worlds += 1;
    count_dimensions(w, st);
    let n = w.items.len();
    let mut failed = false;
    let times: Vec<u32> = {
        let mut t: Vec<u32> = w.items.iter().flat_map(|i| i.recv.iter().copied()).filter(|&t| t < LATE).collect();
        t.push(LATE);
        t.sort_unstable();
        t.dedup();
        t
    };
    let removed = |o: usize| o < w.np && w.left[o] < LATE;
    let mut disputed = false;
    for o in (0..w.nodes).filter(|&o| !removed(o)) {
        for &tau in &times {
            let held = w.held_at(o, tau);
            let trust = w.default_side(o, &held);
            let v = w.judge(&held, trust);
            // A removed node cannot void its removal where every removed node's rotation it
            // holds is signed at an epoch node 0's line is signed at (the removal's own, or a
            // sibling's fork node 0's merge accepted): it can only fork. Rotations signed at a
            // removed node's own fork epochs (counter-merges) contest node 0's line: a dispute.
            for a in (0..w.np).filter(|&a| removed(a)) {
                let Some(r0) = w.removal_of(a) else { continue };
                if !held[r0] || !w.verified(&held, r0) {
                    continue;
                }
                let merges: Vec<usize> = (0..n).filter(|&m| m != r0 && held[m] && !w.items[m].hostile && w.items[m].author == 0 && w.items[m].kind.is_rot() && w.line_of(&held, m).contains(&r0)).collect();
                let forks: Vec<usize> = (0..n).filter(|&h| held[h] && w.items[h].hostile && w.items[h].kind.is_rot()).collect();
                let at_of = |i: usize| match &w.items[i].kind { Kind::Rotation { at, .. } => *at, _ => unreachable!() };
                let line0: Vec<usize> = std::iter::once(r0).chain(merges.iter().copied()).collect();
                // Epochs node 0's line is signed at, from the history: each rotation's own, and
                // the epoch of each fork a merge names.
                let joined = |m: usize, e: Epoch| match &w.items[m].kind {
                    Kind::Rotation { at, names, .. } => *at == e || names.iter().any(|&id| matches!(&w.items[idx(id)].kind, Kind::Rotation { new, .. } if *new == e)),
                    _ => false,
                };
                if forks.is_empty() || !forks.iter().all(|&h| line0.iter().any(|&m| joined(m, at_of(h)))) {
                    continue;
                }
                if !v.counting[r0] {
                    st.removal_voided += 1;
                    failed = true;
                    if debug() {
                        println!("removal voided: observer n{o} tau {tau} removal #{} side {:?} counting {:?} dispute {}", w.items[r0].id, trust.map(|t| w.items[t].id), v.counting, v.dispute);
                    }
                }
            }
            if v.dispute {
                disputed = true;
                if !w.owner_sided(trust) {
                    st.thief_sided_observers += 1;
                }
                // The side decides the reading.
                let other = w.parties(&held).into_iter().find(|&i| Some(i) != trust && trust.map_or(true, |t| w.items[i].author != w.items[t].author));
                if other.is_some() && w.judge(&held, other) != v {
                    st.side_changes_reading += 1;
                }
            }
            for i in 0..n {
                let it = &w.items[i];
                if !matches!(it.kind, Kind::Content { .. }) || !w.is_p(i) {
                    continue;
                }
                if !it.hostile {
                    // Listed by a counting rotation whose list for its thing is not held yet.
                    if held[i] && !v.valid[i] && (0..n).any(|l| !held[l] && matches!(&w.items[l].kind, Kind::List { rot, lists, .. } if v.counting[idx(*rot)] && lists.contains(&it.id))) {
                        st.part_pending += 1;
                    }
                    continue;
                }
                if v.valid[i] {
                    // The observer holds the author's removal with its chain (a reader that
                    // cannot place it is unaware: the stated limit).
                    let holds_r = w.removal_of(it.author).map_or(false, |r0| held[r0] && w.verified(&held, r0));
                    if w.owner_sided(trust) && holds_r {
                        // A removed node's fork counts (until node 0's merge arrives) and is
                        // why the commit reads valid: it reads invalid once the removed nodes'
                        // rotations, their lists and the post-re-add listings are dropped.
                        let mut fork_counts = (0..n).any(|r| v.counting[r] && w.items[r].hostile);
                        if fork_counts {
                            let mut less = held.clone();
                            for l in 0..n {
                                if (w.items[l].hostile && matches!(w.items[l].kind, Kind::Rotation { .. } | Kind::List { .. })) || (!w.items[l].hostile && w.items[l].t >= w.readded[it.author] && matches!(w.items[l].kind, Kind::Listing { .. })) {
                                    less[l] = false;
                                }
                            }
                            fork_counts = !w.judge(&less, trust).valid[i];
                        }
                        let ta = w.readded[it.author];
                        if ta < LATE && {
                            let mut less = held.clone();
                            for l in 0..n {
                                if !w.items[l].hostile && w.items[l].t >= ta && matches!(w.items[l].kind, Kind::Listing { .. }) {
                                    less[l] = false;
                                }
                            }
                            !w.judge(&less, trust).valid[i]
                        } {
                            st.hostile_revived_by_readd += 1;
                        } else if fork_counts {
                            st.hostile_valid_fork_window += 1;
                        } else if w.at_concurrent_epoch(i, &held, trust) {
                            st.hostile_valid_concurrent_epoch += 1;
                            failed = true;
                            if debug() {
                                println!("concurrent: observer n{o} tau {tau} item #{} valid; side {:?}", it.id, trust.map(|t| w.items[t].id));
                            }
                        } else if w.listed_by_unaware_closer(i) {
                            st.hostile_valid_unaware_closer += 1;
                        } else {
                            st.hostile_valid_owner_sided += 1;
                            failed = true;
                            if debug() {
                                println!("safety: observer n{o} tau {tau} item #{} valid; side {:?}", it.id, trust.map(|t| w.items[t].id));
                            }
                        }
                    }
                } else if v.visible[i] {
                    st.hostile_visible_through_witness_snapshot += 1;
                }
            }
        }
    }
    if disputed {
        st.dispute_worlds += 1;
    }
    // Final state at observers that received everything an honest party holds that reaches
    // them, unless
    // the bound refused a rotation while a removed node's fork stands (the merge that would
    // void it could not be written: the world has not settled).
    let all: Vec<bool> = w.items.iter().map(|_| true).collect();
    // Or an honest fork stays unmerged: no epoch reopens.
    let unsettled = w.refused > 0 && {
        let side = w.default_side(0, &all);
        let line = side.map_or(vec![], |s| w.line_of(&all, s));
        w.items.iter().enumerate().any(|(i, r)| r.kind.is_rot() && (r.hostile || !line.contains(&i)))
    };
    st.unsettled += u64::from(unsettled);
    for o in (0..w.nodes).filter(|&o| !removed(o) && !unsettled) {
        let held = w.held_at(o, LATE - 1);
        // Everything under its labels that an honest party holds (holders serve it) reaches it.
        let served = |i: usize| !w.items[i].hostile || (0..w.nodes).any(|m| m != o && !removed(m) && w.items[i].recv[m] < LATE);
        if (0..n).any(|i| !held[i] && served(i) && w.reaches(i, o)) {
            continue;
        }
        let trust = w.default_side(o, &held);
        if !w.owner_sided(trust) {
            continue;
        }
        let v = w.judge(&held, trust);
        for i in 0..n {
            let it = &w.items[i];
            if !held[i] || !w.is_p(i) {
                continue;
            }
            if matches!(it.kind, Kind::Listing { .. }) && !it.hostile && v.as_p[i] && v.closed.contains(&it.epoch.unwrap()) {
                st.closed_listing_counts += 1;
            }
            // Legitimate content: honest, or a re-added node's from while it was removed.
            let legit = !it.hostile || w.readded[it.author] < LATE;
            if !legit || !matches!(it.kind, Kind::Content { .. }) {
                continue;
            }
            if v.visible[i] && v.closed.contains(&it.epoch.unwrap()) {
                let thing = it.kind.thing().unwrap();
                if (0..n).any(|r| !w.items[r].hostile && w.items[r].kind.is_rot() && matches!(&w.items[r].kind, Kind::Rotation { supersedes, .. } if supersedes.contains(&it.epoch.unwrap())) && !w.reads(w.items[r].author, thing)) {
                    st.unopened_saved += 1;
                }
                if it.hostile {
                    st.readd_revived += 1;
                }
                if w.overflow.iter().any(|&(_, id)| id == it.id) {
                    st.overflow_saved += 1;
                }
            }
            let carried = (0..n).any(|s| v.valid[s] && matches!(&w.items[s].kind, Kind::Snap { carries, .. } if carries.contains(&it.id)));
            let (lo, hi) = (w.expected(i, true, 0) || carried, w.expected(i, false, 0) || carried);
            // While a removed node's fork counts its lists name its own commits.
            let fork_counts = (0..n).any(|r| v.counting[r] && w.items[r].hostile);
            if v.visible[i] && !hi && fork_counts {
                st.final_fork_counts += 1;
            } else if v.visible[i] && !hi {
                st.upper_fail += 1;
                failed = true;
                if debug() {
                    println!("upper: observer n{o} item #{} visible beyond the upper bound", it.id);
                }
            } else if v.visible[i] && !lo {
                st.saved_by_later_closer += 1;
            }
            if lo && !v.visible[i] {
                st.liveness_fail += 1;
                failed = true;
                if debug() {
                    println!("liveness: observer n{o} item #{} invalid; side {:?}; counting {:?}; as_p {:?}", it.id, trust.map(|t| w.items[t].id), v.counting, v.as_p);
                }
                if st.fail_live.is_none() {
                    st.fail_live = Some(w.clone());
                }
            }
        }
        // Monotone: dropping an honest attestation never makes more valid.
        for a in 0..n {
            if !held[a] || !w.honest_attestation(a) {
                continue;
            }
            let mut less = held.clone();
            less[a] = false;
            let v2 = w.judge(&less, trust);
            if (0..n).any(|i| v2.valid[i] && !v.valid[i]) {
                st.monotone_fail += 1;
                failed = true;
            }
        }
        // Omit-covered against listing everything, at the fully informed owner-sided observer.
        if o == 0 && w.omit_covered {
            let mut full = w.clone();
            full.omit_covered = false;
            relist(&mut full);
            let v2 = full.judge(&all, full.default_side(0, &all));
            let va = w.judge(&all, w.default_side(0, &all));
            if (0..n).any(|i| v2.visible[i] && !va.visible[i]) {
                st.omit_loses += 1;
                if w.items.iter().any(|i| matches!(i.kind, Kind::Fall { .. })) {
                    st.omit_loses_snapshot_fallen += 1;
                }
            }
            let ids = |w: &World| w.items.iter().map(|i| match &i.kind { Kind::List { lists, .. } if !i.hostile => lists.len() as u64, _ => 0 }).sum::<u64>();
            st.omit_saves_ids += ids(w);
            st.list_all_ids += ids(&full);
        }
    }
    let sibling_rotation = w.items.iter().any(|r| !r.hostile && r.author != 0 && r.kind.is_rot());
    if failed && st.fail.is_none() {
        st.fail = Some(w.clone());
    }
    st.w_sibling_rotation += u64::from(sibling_rotation);
    if failed && !sibling_rotation {
        st.failed_without_sibling_rotation += 1;
    }
}

fn count_dimensions(w: &World, st: &mut Stats) {
    let p_on = |t: Thing| w.items.iter().any(|i| i.epoch.is_some() && matches!(i.kind, Kind::Content { thing, .. } if thing == t));
    let labels: HashSet<Label> = w.things.iter().flatten().copied().collect();
    st.w_multi_label += u64::from(labels.len() > 1);
    st.w_two_group_thing += u64::from((0..w.things.len()).any(|t| w.things[t].len() > 1 && p_on(t)));
    st.w_unopened_label += u64::from(w.items.iter().any(|r| !r.hostile && r.kind.is_rot() && (0..w.things.len()).any(|t| p_on(t) && !w.reads(r.author, t))));
    st.w_successive += u64::from(w.left[..w.np].iter().filter(|&&l| l < LATE).count() > 1);
    st.w_readd += u64::from(w.readded.iter().zip(&w.left).any(|(&a, &l)| l < LATE && a < LATE));
    st.w_overflow += u64::from(!w.overflow.is_empty());
    st.w_refused += u64::from(w.refused > 0);
    st.w_bad_list += u64::from(w.items.iter().any(|i| matches!(&i.kind, Kind::List { lists, .. } if w.bound.map_or(false, |b| lists.len() > b))));
}

/// Recomputes every honest rotation's lists from its author's receipts under
/// `w.omit_covered`.
pub fn relist(w: &mut World) {
    for r in 0..w.items.len() {
        if w.items[r].hostile {
            continue;
        }
        let Kind::Rotation { supersedes, .. } = &w.items[r].kind else { continue };
        let (author, t, supersedes, rid) = (w.items[r].author, w.items[r].t, supersedes.clone(), w.items[r].id);
        let Some((lists, _)) = rotation_lists(w, author, t, &supersedes) else { continue };
        for l in 0..w.items.len() {
            if let Kind::List { rot, thing, lists: ls } = &mut w.items[l].kind {
                if *rot == rid {
                    *ls = lists.iter().find(|(t, _)| t == thing).map(|(_, v)| v.clone()).unwrap_or_default();
                }
            }
        }
    }
}

/// P's commits at `closing` epochs that `author` had received before `t` (rotations and
/// their lists aside): its own, and others' received before the earliest counting rotation
/// it holds closing their epoch (the cutoff every lister uses); less, when `omit_covered`,
/// those a snapshot it holds valid covers.
fn rotation_candidates(w: &World, author: usize, t: u32, closing: &[Epoch]) -> Vec<usize> {
    let covered: HashSet<u32> = if w.omit_covered { covered_at(w, author, t) } else { HashSet::new() };
    let held: Vec<bool> = w.items.iter().map(|i| i.recv[author] < t).collect();
    let v = w.judge(&held, w.default_side(author, &held));
    let cutoff = |e: Epoch| w.closers(&held, &v, e).iter().map(|&r| w.items[r].ts).min().unwrap_or(t).min(t);
    (0..w.items.len())
        .filter(|&i| {
            let it = &w.items[i];
            it.recv[author] < t && !it.kind.is_rot() && it.epoch.map_or(false, |e| closing.contains(&e) && (it.author == author || it.recv[author] < cutoff(e))) && !covered.contains(&it.id)
        })
        .collect()
}

/// A rotation's lists, per thing the rotator reads (empty ones included), and the plain
/// content left out past the bound; None when a part's special commits alone pass it (the
/// rotation is refused). A commit sits in the part of every opened label of its thing; past
/// the bound, a part leaves out the plain content received last.
fn rotation_lists(w: &World, author: usize, t: u32, closing: &[Epoch]) -> Option<(Vec<(Thing, Vec<u32>)>, Vec<u32>)> {
    let cands = rotation_candidates(w, author, t, closing);
    let mut dropped: HashSet<u32> = HashSet::new();
    if let Some(b) = w.bound {
        for l in &w.opens[author] {
            let part: Vec<usize> = cands.iter().copied().filter(|&i| w.things[w.items[i].kind.thing().unwrap()].contains(l)).collect();
            let specials = part.iter().filter(|&&i| !w.items[i].kind.plain()).count();
            if specials > b {
                return None;
            }
            let mut plain: Vec<usize> = part.iter().copied().filter(|&i| w.items[i].kind.plain()).collect();
            plain.sort_by_key(|&i| (w.items[i].recv[author], w.items[i].id));
            for &i in plain.iter().skip(b - specials) {
                dropped.insert(w.items[i].id);
            }
        }
    }
    let lists = (0..w.things.len())
        .filter(|&th| w.reads(author, th))
        .map(|th| (th, cands.iter().filter(|&&i| w.items[i].kind.thing() == Some(th) && !dropped.contains(&w.items[i].id)).map(|&i| w.items[i].id).collect()))
        .collect();
    let mut dropped: Vec<u32> = dropped.into_iter().collect();
    dropped.sort_unstable();
    Some((lists, dropped))
}

/// Commits a snapshot `node` holds valid at `t` (received before `t`, by its own judgment
/// then) carries.
fn covered_at(w: &World, node: usize, t: u32) -> HashSet<u32> {
    let held: Vec<bool> = w.items.iter().map(|i| i.recv[node] < t).collect();
    let v = w.judge(&held, w.default_side(node, &held));
    (0..w.items.len())
        .filter(|&s| held[s] && v.valid[s])
        .flat_map(|s| match &w.items[s].kind {
            Kind::Snap { carries, .. } => carries.clone(),
            _ => vec![],
        })
        .collect()
}

/// Receipt delays: per node, `None` never.
pub type Delay<'a> = &'a dyn Fn(usize) -> Option<u32>;
/// Receipt delays of a rotation's per-thing lists: per (node, thing).
pub type ListDelay<'a> = &'a dyn Fn(usize, Thing) -> Option<u32>;

pub struct Builder {
    pub w: World,
    next_epoch: Epoch,
    /// Per node: answers cover receipts before this.
    answered: Vec<u32>,
}

impl Builder {
    pub fn new(w: World) -> Builder {
        let nodes = w.nodes;
        Builder { w, next_epoch: 0, answered: vec![0; nodes] }
    }

    fn fresh(&mut self) -> Epoch {
        self.next_epoch += 1;
        self.next_epoch
    }

    pub fn add(&mut self, kind: Kind, author: usize, epoch: Option<Epoch>, t: u32, ts: u32, recv: Vec<u32>, hostile: bool) -> usize {
        let id = self.w.items.len() as u32 + 1;
        let mut recv = recv;
        recv[author] = t;
        self.w.items.push(Item { id, kind, author, epoch, t, ts, recv, hostile });
        self.w.items.len() - 1
    }

    /// Receipts of an item on `thing` (or on none) made at `t`: readers at `t + d`, `LATE`
    /// when `delay` says or for nodes it does not reach.
    pub fn recv(&self, thing: Option<Thing>, t: u32, delay: Delay) -> Vec<u32> {
        (0..self.w.nodes).map(|n| if thing.map_or(true, |th| self.w.reads(n, th)) { delay(n).map_or(LATE, |d| t + d) } else { LATE }).collect()
    }

    fn rotations_held_by(&self, n: usize, t: u32) -> Vec<bool> {
        self.w.items.iter().map(|i| i.recv[n] <= t && i.kind.is_rot()).collect()
    }

    /// The newest counting epoch minted by a held rotation `boxed` allows, open ones only
    /// when `open`.
    fn newest_epoch(&self, n: usize, t: u32, open: bool, boxed: impl Fn(usize) -> bool) -> Option<Epoch> {
        let held = self.rotations_held_by(n, t);
        let v = self.w.judge(&held, self.w.default_side(n, &held));
        (0..self.w.items.len())
            .filter_map(|i| match &self.w.items[i].kind {
                Kind::Rotation { new, .. } if v.counting[i] && boxed(i) && !(open && v.closed.contains(new)) => Some(*new),
                _ => None,
            })
            .max()
    }

    /// A member's signing epoch at `t`: the newest counting open epoch in what it holds the
    /// key of (removed nodes' forks box nobody else); with none open (concurrent rotations
    /// close each other's epochs), the tip of its side's line, the line the devices actor
    /// authorizes.
    pub fn epoch_of(&self, n: usize, t: u32) -> Epoch {
        let honest = |i: usize| !self.w.items[i].hostile;
        if let Some(e) = self.newest_epoch(n, t, true, honest) {
            return e;
        }
        let held = self.rotations_held_by(n, t);
        if let Some(s) = self.w.default_side(n, &held) {
            if let Kind::Rotation { new, .. } = &self.w.items[s].kind {
                return *new;
            }
        }
        let any = self.newest_epoch(n, t, false, honest);
        if self.w.judge(&held, None).counting.iter().any(|&c| c) {
            return any.unwrap_or(0);
        }
        0
    }

    /// A removed node's epoch at `t`: its own newest fork its own line has not superseded,
    /// else the newest it was boxed, open or closed (a rotation before its removal, or by a
    /// sibling that had not received the removal).
    pub fn epoch_known(&self, n: usize, t: u32) -> Epoch {
        let items = &self.w.items;
        let own = items.iter().filter_map(|i| match &i.kind {
            Kind::Rotation { new, .. } if i.author == n && i.hostile && i.t <= t && !items.iter().any(|r| r.author == n && r.t <= t && matches!(&r.kind, Kind::Rotation { supersedes, .. } if supersedes.contains(new))) => Some(*new),
            _ => None,
        });
        if let Some(e) = own.max() {
            return e;
        }
        let r0 = self.w.removal_of(n);
        self.newest_epoch(n, t, false, |i| {
            let r = &items[i];
            !r.hostile && (r.t < self.w.left[n] || r0.map_or(true, |r0| r.author != 0 && items[r0].recv[r.author] > r.t))
        })
        .unwrap_or(0)
    }

    /// Held verified rotations off n's own line (its side's chain) whose epoch no rotation of
    /// n's supersedes: the forks n has not merged out (one whose chain has not arrived waits,
    /// so the merge can be signed at the fork's root).
    fn unmerged(&self, n: usize, t: u32) -> Vec<usize> {
        let held = self.rotations_held_by(n, t);
        let Some(side) = self.w.default_side(n, &held) else { return vec![] };
        let own = self.w.line_of(&held, side);
        (0..self.w.items.len())
            .filter(|&i| {
                held[i] && !own.contains(&i) && self.w.verified(&held, i) && matches!(&self.w.items[i].kind, Kind::Rotation { new, .. } if !self.w.items.iter().any(|r| r.author == n && r.t <= t && matches!(&r.kind, Kind::Rotation { supersedes, .. } if supersedes.contains(new))))
            })
            .collect()
    }

    /// Node n holds a fork it has not merged out.
    pub fn holds_unmerged_fork(&self, n: usize, t: u32) -> bool {
        !self.unmerged(n, t).is_empty()
    }

    /// Node n received something since its last answer.
    fn changed(&self, n: usize, t: u32) -> bool {
        self.w.items.iter().any(|i| i.recv[n] >= self.answered[n] && i.recv[n] <= t)
    }

    /// Member n's listings at `t`, one per thing it reads with something to name: commits at
    /// closed counting epochs that no counting list it holds names, that are its own, a
    /// re-added node's, or others' it received before the earliest counting rotation it holds
    /// closing their epoch (its own rotation's overflow among them).
    pub fn listings(&mut self, n: usize, t: u32, delay: ListDelay) {
        self.answered[n] = t;
        let w = &self.w;
        let ni = w.items.len();
        let held: Vec<bool> = w.items.iter().map(|i| i.recv[n] <= t).collect();
        let v = w.judge(&held, w.default_side(n, &held));
        let over = |l: &Vec<u32>| w.bound.map_or(false, |b| l.len() > b);
        let mut named: HashSet<u32> = HashSet::new();
        for i in 0..ni {
            if !held[i] {
                continue;
            }
            match &w.items[i].kind {
                Kind::List { rot, lists, .. } if v.counting[idx(*rot)] && !over(lists) => named.extend(lists.iter().copied()),
                Kind::Listing { lists, .. } if v.as_p[i] => named.extend(lists.iter().copied()),
                _ => {}
            }
        }
        let counts = |e: Epoch| e == 0 || (0..ni).any(|r| v.counting[r] && matches!(&w.items[r].kind, Kind::Rotation { new, .. } if *new == e));
        let cutoff = |e: Epoch| w.closers(&held, &v, e).iter().map(|&r| w.items[r].ts).min().unwrap_or(0);
        let covered = if w.omit_covered { covered_at(w, n, t + 1) } else { HashSet::new() };
        let mut out: Vec<(Thing, Vec<u32>)> = vec![];
        for th in (0..w.things.len()).filter(|&th| w.reads(n, th)) {
            let lists: Vec<u32> = (0..ni)
                .filter(|&i| {
                    let it = &w.items[i];
                    let Some(e) = it.epoch else { return false };
                    held[i]
                        && !it.kind.is_rot()
                        && it.kind.thing() == Some(th)
                        && v.closed.contains(&e)
                        && counts(e)
                        && !named.contains(&it.id)
                        && !covered.contains(&it.id)
                        && (it.author == n || w.readded_by(it.author, t) || it.recv[n] < cutoff(e))
                })
                .map(|i| w.items[i].id)
                .collect();
            if !lists.is_empty() {
                out.push((th, lists));
            }
        }
        if out.is_empty() {
            return;
        }
        // Only at an open epoch: one at a closed epoch counts only once a rotation lists it,
        // and no merge's cutoff admits it (it postdates the closer). With none open (concurrent
        // rotations close each other) the node waits for the merge.
        let honest = |i: usize| !self.w.items[i].hostile;
        let opened = self.newest_epoch(n, t, true, honest);
        if opened.is_none() && v.counting.iter().any(|&c| c) {
            return;
        }
        let at = opened.unwrap_or(0);
        for (th, lists) in out {
            let recv = self.recv(Some(th), t, &|m| delay(m, th));
            self.add(Kind::Listing { at, thing: th, lists }, n, Some(at), t, t, recv, false);
        }
    }

    /// Witness wn answers every rotation it holds, and A's demotion on its thing, listing
    /// P's plain content on its thing it received before the answered write's `ts` that
    /// neither the write's list it holds nor its own earlier answers name.
    pub fn addenda(&mut self, wn: usize, t: u32, delay: Delay) {
        self.answered[wn] = t;
        let Some(th) = self.w.writer[wn] else { return };
        let w = &self.w;
        let held = |i: usize| w.items[i].recv[wn] <= t;
        let covered = if w.omit_covered { covered_at(w, wn, t + 1) } else { HashSet::new() };
        let mut out: Vec<(u32, Vec<u32>)> = vec![];
        let hv: Vec<bool> = (0..w.items.len()).map(held).collect();
        for ag in (0..w.items.len()).filter(|&i| held(i)) {
            let agi = &w.items[ag];
            let rotation = match &agi.kind {
                // Only a rotation whose chain it holds whole (it can verify nothing else).
                Kind::Rotation { .. } if w.verified(&hv, ag) => true,
                Kind::Rotation { .. } => continue,
                Kind::Demotion { thing, .. } if *thing == th => false,
                _ => continue,
            };
            // Against a rotation: commits at a held epoch it closes (one that does not descend
            // from it), received before the earliest rotation on its line closing that epoch.
            let line = if rotation { w.line_of(&hv, ag) } else { vec![] };
            let known = |e: Epoch| e == 0 || (0..w.items.len()).any(|i| hv[i] && matches!(&w.items[i].kind, Kind::Rotation { new, .. } if *new == e));
            let cutoff = |e: Epoch| -> Option<u32> {
                if !rotation {
                    return Some(agi.ts);
                }
                if !known(e) {
                    return None;
                }
                line.iter().filter(|&&r| !w.descends(&hv, e, r)).map(|&r| w.items[r].ts).min()
            };
            let mut named: HashSet<u32> = HashSet::new();
            if let Kind::Demotion { frontier, .. } = &agi.kind {
                named.extend(frontier.iter().copied());
            }
            for i in (0..w.items.len()).filter(|&i| held(i)) {
                match &w.items[i].kind {
                    Kind::List { rot, thing, lists } if *rot == agi.id && *thing == th => named.extend(lists.iter().copied()),
                    Kind::Addendum { against, lists, .. } if *against == agi.id && w.items[i].author == wn => named.extend(lists.iter().copied()),
                    _ => {}
                }
            }
            let lists: Vec<u32> = (0..w.items.len())
                .filter(|&i| {
                    let it = &w.items[i];
                    matches!(it.kind, Kind::Content { thing, plain: true } if thing == th) && it.epoch.and_then(cutoff).map_or(false, |c| it.recv[wn] < c) && !named.contains(&it.id) && !covered.contains(&it.id)
                })
                .map(|i| w.items[i].id)
                .collect();
            if !lists.is_empty() {
                out.push((agi.id, lists));
            }
        }
        for (against, lists) in out {
            let recv = self.recv(Some(th), t, delay);
            self.add(Kind::Addendum { against, thing: th, lists }, wn, None, t, t, recv, false);
        }
    }

    /// Member n's rotation (or merge) at `t`: closes the epochs it holds current, names the
    /// forks it accepts (every honest one), lists what it received; None when the bound
    /// refuses it.
    pub fn rotate(&mut self, n: usize, t: u32, delay: Delay, ldelay: ListDelay) -> Option<usize> {
        let at = self.epoch_of(n, t);
        let held = self.rotations_held_by(n, t);
        // Every epoch current in the rotator's own view (its side), and every epoch of a
        // held fork it has not merged out: the other line whole. It names the honest ones.
        let v = self.w.judge(&held, self.w.default_side(n, &held));
        let unmerged = self.unmerged(n, t);
        let mut supersedes = vec![at];
        let mut names = vec![];
        for i in 0..self.w.items.len() {
            if let Kind::Rotation { new: e, .. } = &self.w.items[i].kind {
                let hostile = self.w.items[i].hostile;
                let current = held[i] && ((v.counting[i] && !v.closed.contains(e)) || unmerged.contains(&i));
                if current && *e != at {
                    supersedes.push(*e);
                    if !hostile {
                        names.push(self.w.items[i].id);
                    }
                }
            }
        }
        supersedes.sort_unstable();
        supersedes.dedup();
        let Some((lists, dropped)) = rotation_lists(&self.w, n, t, &supersedes) else {
            self.w.refused += 1;
            return None;
        };
        let new = self.fresh();
        let recv = self.recv(None, t, delay);
        let r = self.add(Kind::Rotation { at, new, supersedes, names }, n, Some(at), t, t, recv, false);
        let rid = self.w.items[r].id;
        for (th, l) in lists {
            let recv = self.recv(Some(th), t, &|m| ldelay(m, th));
            self.add(Kind::List { rot: rid, thing: th, lists: l }, n, None, t, t, recv, false);
        }
        self.w.overflow.extend(dropped.into_iter().map(|d| (n, d)));
        Some(r)
    }

    /// Removed node n's rotation at `t`: a fork at its epoch, rejecting every rotation of the
    /// others it holds; it lists its own commits.
    pub fn rotate_thief(&mut self, n: usize, t: u32, delay: Delay) -> usize {
        let at = self.epoch_known(n, t);
        let mut supersedes = vec![at];
        let mut names = vec![];
        for i in &self.w.items {
            if let Kind::Rotation { new: e, .. } = &i.kind {
                if i.recv[n] <= t && *e != at {
                    supersedes.push(*e);
                }
                if i.author == n && *e == at {
                    names.push(i.id);
                }
            }
        }
        supersedes.sort_unstable();
        supersedes.dedup();
        let lists: Vec<(Thing, Vec<u32>)> = (0..self.w.things.len())
            .filter(|&th| self.w.reads(n, th))
            .map(|th| (th, self.w.items.iter().filter(|i| i.author == n && i.kind.thing() == Some(th) && i.epoch.map_or(false, |e| supersedes.contains(&e)) && !i.kind.is_rot()).map(|i| i.id).collect()))
            .collect();
        let new = self.fresh();
        let recv = self.recv(None, t, delay);
        let hostile = !self.w.member(n, t);
        let r = self.add(Kind::Rotation { at, new, supersedes, names }, n, Some(at), t, t, recv, hostile);
        let rid = self.w.items[r].id;
        for (th, l) in lists {
            let recv = self.recv(Some(th), t, delay);
            self.add(Kind::List { rot: rid, thing: th, lists: l }, n, None, t, t, recv, hostile);
        }
        r
    }

    /// Removed node n's listings at its epoch for its hostile writes, per thing.
    pub fn thief_listing(&mut self, n: usize, t: u32, delay: Delay) {
        let e = self.epoch_known(n, t);
        for th in 0..self.w.things.len() {
            let lists: Vec<u32> = self.w.items.iter().filter(|i| i.hostile && i.author == n && matches!(i.kind, Kind::Content { thing, .. } if thing == th)).map(|i| i.id).collect();
            if !lists.is_empty() {
                let recv = self.recv(Some(th), t, delay);
                self.add(Kind::Listing { at: e, thing: th, lists }, n, Some(e), t, t, recv, true);
            }
        }
    }

    /// P node `author` writes content at `t` (hostile when removed: at its known epoch or,
    /// `old`, epoch 0, stamped `ts`).
    pub fn write(&mut self, author: usize, thing: Thing, plain: bool, t: u32, ts: u32, old: bool, delay: Delay) -> usize {
        let hostile = !self.w.member(author, t);
        let epoch = if !hostile {
            self.epoch_of(author, t)
        } else if old {
            0
        } else {
            self.epoch_known(author, t)
        };
        let recv = self.recv(Some(thing), t, delay);
        self.add(Kind::Content { thing, plain }, author, Some(epoch), t, if hostile { ts } else { t }, recv, hostile)
    }

    /// A snapshot on `thing` by `by` at `t` carrying P's content it received; maybe falling.
    pub fn snapshot(&mut self, by: usize, thing: Thing, t: u32, delay: Delay, fall: Option<(u32, Delay)>) {
        let carries: Vec<u32> = self.w.items.iter().filter(|i| i.epoch.is_some() && i.recv[by] < t && matches!(i.kind, Kind::Content { thing: th, .. } if th == thing)).map(|i| i.id).collect();
        if carries.is_empty() {
            return;
        }
        let (epoch, hostile) = if by < self.w.np {
            let hostile = !self.w.member(by, t);
            (Some(if hostile { self.epoch_known(by, t) } else { self.epoch_of(by, t) }), hostile)
        } else {
            (None, false)
        };
        let recv = self.recv(Some(thing), t, delay);
        let si = self.add(Kind::Snap { thing, carries }, by, epoch, t, t, recv, hostile);
        if let Some((ft, fd)) = fall {
            let id = self.w.items[si].id;
            let recv = self.recv(None, ft, fd);
            self.add(Kind::Fall { snap: id }, by, None, ft, ft, recv, false);
        }
    }

    /// Honest answers at `t` by every node whose receipts changed.
    pub fn answer(&mut self, t: u32, delay: Delay, ldelay: ListDelay) {
        for n in 0..self.w.nodes {
            if !self.changed(n, t) {
                continue;
            }
            if self.w.member(n, t) {
                self.listings(n, t, ldelay);
            } else if self.w.writer[n].is_some() {
                self.addenda(n, t, delay);
            }
        }
    }

    /// Final honest answers after every receipt (delivered at once): node 0 merges, members
    /// list, witnesses answer, until nothing new is written.
    pub fn settle(&mut self, t0: u32) {
        for round in 0..6 {
            let t = t0 + round;
            let before = self.w.items.len();
            if self.holds_unmerged_fork(0, t) {
                self.rotate(0, t, &|_| Some(0), &|_, _| Some(0));
            }
            self.answer(t, &|_| Some(0), &|_, _| Some(0));
            if self.w.items.len() == before {
                break;
            }
        }
    }

    /// Node 0 removes node n at `t`; a refused removal does not happen.
    pub fn remove(&mut self, n: usize, t: u32, delay: Delay, ldelay: ListDelay) -> Option<usize> {
        let r = self.rotate(0, t, delay, ldelay);
        if r.is_none() {
            self.w.left[n] = LATE;
        }
        r
    }
}

fn subset(rng: &mut Rng, of: &[Label]) -> Vec<Label> {
    loop {
        let s: Vec<Label> = of.iter().copied().filter(|_| rng.below(2) == 0).collect();
        if !s.is_empty() {
            return s;
        }
    }
}

/// A random world.
pub fn random_world(rng: &mut Rng) -> World {
    let np = 2 + rng.below(3);
    let nlabels = 1 + rng.below(2);
    let things: Vec<Vec<Label>> = if nlabels == 1 {
        vec![vec![0]; 1 + rng.below(2)]
    } else {
        let pool = [vec![0], vec![1], vec![0, 1]];
        let mut t: Vec<Vec<Label>> = pool.iter().filter(|_| rng.below(2) == 0).cloned().collect();
        if t.is_empty() {
            t.push(pool[rng.below(3)].clone());
        }
        t
    };
    let labels: Vec<Label> = (0..nlabels).collect();
    let mut opens: Vec<Vec<Label>> = vec![];
    let mut writer: Vec<Option<Thing>> = vec![];
    for _ in 0..np {
        let mut s = subset(rng, &labels);
        if !things.iter().any(|ls| ls.iter().any(|l| s.contains(l))) {
            s = things[0].clone();
        }
        opens.push(s);
        writer.push(None);
    }
    for _ in 0..rng.below(3) {
        let th = rng.below(things.len());
        opens.push(subset(rng, &things[th]));
        writer.push(Some(th));
    }
    let admin = if rng.below(3) == 0 {
        opens.push(subset(rng, &things[0]));
        writer.push(None);
        Some(opens.len() - 1)
    } else {
        None
    };
    opens.push(subset(rng, &labels));
    writer.push(None);
    let bound = [None, None, Some(1), Some(2)][rng.below(4)];
    let mut w = World::shape(np, things, opens, writer, admin, bound, rng.below(2) == 0);
    let nodes = w.nodes;
    let ntw = w.things.len();
    let tr = 3 + rng.below(5) as u32;
    let successive = np >= 3 && rng.below(2) == 0;
    let tr2 = tr + 1 + rng.below(5) as u32;
    let ta = if rng.below(3) == 0 { tr + 1 + rng.below(6) as u32 } else { LATE };
    w.left[X] = tr;
    w.readded[X] = ta;
    if successive {
        w.left[Y] = tr2;
    }
    let t_max = 14u32;
    let mut b = Builder::new(w);
    let readers: Vec<Vec<Thing>> = (0..np).map(|n| (0..ntw).filter(|&th| b.w.reads(n, th)).collect()).collect();
    let rand_delay = |rng: &mut Rng, never: &dyn Fn(usize) -> bool| -> Vec<Option<u32>> { (0..nodes).map(|n| if never(n) && rng.below(4) == 0 { None } else { Some(rng.below(4) as u32) }).collect() };
    // A re-added node reads every rotation through the devices actor once back.
    let removable = |n: usize| (n == X && ta == LATE) || (successive && n == Y);
    // Content: any receipt may never come. Honest role changes reach every honest party;
    // removed nodes' rotations go under P's labels, so P's members get them when they sync.
    let delay = |rng: &mut Rng| rand_delay(rng, &|_| true);
    let honest_delay = |rng: &mut Rng| rand_delay(rng, &|n| removable(n));
    let thief_delay = |rng: &mut Rng| rand_delay(rng, &|n| n >= np);
    let list_delay = |rng: &mut Rng| -> Vec<Vec<Option<u32>>> { (0..nodes).map(|n| (0..ntw).map(|_| if removable(n) && rng.below(4) == 0 { None } else { Some(rng.below(5) as u32) }).collect()).collect() };
    let mut pending: Vec<(usize, Thing, u32)> = vec![];
    for _ in 0..1 + rng.below(5) {
        let author = rng.below(np);
        let th = readers[author][rng.below(readers[author].len())];
        pending.push((author, th, 1 + rng.below(t_max as usize) as u32));
    }
    pending.sort_by_key(|p| p.2);
    let fork_x = rng.below(2) == 0;
    let tx = tr + rng.below(4) as u32;
    let fork_y = successive && rng.below(4) == 0;
    let ty = tr2 + rng.below(3) as u32;
    let sibling = if np == 4 { Some(3) } else if np == 3 && !successive { Some(2) } else { None };
    let honest_fork = sibling.is_some() && rng.below(4) == 0;
    let t2 = (tr as i32 - 1 + rng.below(3) as i32).max(1) as u32;
    let owner_merge_t = tr + 2 + rng.below(3) as u32;
    let thief_merge = fork_x && rng.below(2) == 0;
    let thief_merge_t = owner_merge_t + rng.below(3) as u32;
    let thief_listing: Vec<u8> = (0..np).map(|_| rng.below(3) as u8).collect();
    let demotion_t = b.w.admin.map(|_| 2 + rng.below(10) as u32);
    let snap_t = if rng.below(2) == 0 { Some(2 + rng.below(10) as u32) } else { None };
    let witnesses: Vec<usize> = (0..nodes).filter(|&n| b.w.writer[n].is_some()).collect();
    let snap_by = if rng.below(2) == 0 && !witnesses.is_empty() { witnesses[rng.below(witnesses.len())] } else { rng.below(np) };
    let snap_thing = match b.w.writer[snap_by] {
        Some(th) => th,
        None => readers[snap_by][rng.below(readers[snap_by].len())],
    };
    let snap_fallen = b.w.writer[snap_by].is_some() && rng.below(3) == 0;
    for t in 1..=t_max {
        if t == ta && b.w.member(X, t) {
            for i in 0..b.w.items.len() {
                if !b.w.items[i].hostile && b.w.items[i].kind.is_rot() {
                    b.w.items[i].recv[X] = b.w.items[i].recv[X].min(t);
                }
            }
        }
        // Honest answers to what arrived by now (before anything else at t).
        let d = delay(rng);
        let ld = list_delay(rng);
        b.answer(t, &|n| d[n], &|n, th| ld[n][th]);
        if demotion_t == Some(t) {
            let a = b.w.admin.unwrap();
            let frontier: Vec<u32> = b.w.items.iter().filter(|i| i.epoch.is_some() && i.recv[a] < t && matches!(i.kind, Kind::Content { thing: 0, .. } | Kind::Snap { thing: 0, .. })).map(|i| i.id).collect();
            let dl = honest_delay(rng);
            let r = b.recv(Some(0), t, &|n| dl[n]);
            b.add(Kind::Demotion { thing: 0, frontier }, a, None, t, t, r, false);
        }
        while let Some(&(author, th, pt)) = pending.first() {
            if pt != t {
                break;
            }
            pending.remove(0);
            let ts = rng.below(t_max as usize) as u32;
            let plain = rng.below(4) != 0;
            let old = rng.below(3) == 0;
            let dl = delay(rng);
            b.write(author, th, plain, t, ts, old, &|n| dl[n]);
        }
        if snap_t == Some(t) {
            let dl = delay(rng);
            let fd = honest_delay(rng);
            let ft = t + 1 + rng.below(6) as u32;
            b.snapshot(snap_by, snap_thing, t, &|n| dl[n], snap_fallen.then_some((ft, &|n: usize| fd[n] as Option<u32>)));
        }
        if let Some(s) = sibling {
            if honest_fork && t2 == t && !b.w.items.iter().any(|i| i.author == 0 && i.kind.is_rot() && i.recv[s] <= t) {
                let dl = honest_delay(rng);
                let ld = list_delay(rng);
                b.rotate(s, t, &|n| dl[n], &|n, th| ld[n][th]);
            }
        }
        for (n, tn) in [(X, tr), (Y, tr2)] {
            if tn == t && b.w.left[n] == t {
                let dl = honest_delay(rng);
                let ld = list_delay(rng);
                b.remove(n, t, &|m| dl[m], &|m, th| ld[m][th]);
            }
        }
        for (n, fork, tf) in [(X, fork_x, tx), (Y, fork_y, ty)] {
            if fork && tf == t && !b.w.member(n, t) {
                let dl = thief_delay(rng);
                b.rotate_thief(n, t, &|m| dl[m]);
            }
        }
        // Node 0 merges whenever it holds a fork its own line has not superseded, within a
        // tick or two of receiving it.
        if t + 2 >= owner_merge_t && b.holds_unmerged_fork(0, t) && (t >= owner_merge_t || rng.below(2) == 0) {
            let dl = honest_delay(rng);
            let ld = list_delay(rng);
            b.rotate(0, t, &|n| dl[n], &|n, th| ld[n][th]);
        }
        if thief_merge && t >= thief_merge_t && !b.w.member(X, t) && b.w.items.iter().any(|i| i.author == 0 && i.recv[X] <= t && matches!(&i.kind, Kind::Rotation { new, .. } if !b.w.items.iter().any(|r| r.author == X && matches!(&r.kind, Kind::Rotation { supersedes, .. } if supersedes.contains(new))))) && rng.below(2) == 0 {
            let dl = thief_delay(rng);
            b.rotate_thief(X, t, &|n| dl[n]);
        }
        // A removed node's own listing for its hostile writes, while removed.
        for n in [X, Y] {
            if n < np && thief_listing[n] == 1 && b.w.left[n] < LATE && t == b.w.left[n] + 2 && !b.w.member(n, t) {
                let dl = thief_delay(rng);
                b.thief_listing(n, t, &|m| dl[m]);
            }
        }
    }
    // Final honest answers, everyone having received everything that arrives (receipts
    // run to t_max + 4).
    // Honest role changes reach every final member (a removal the bound refused leaves Y one).
    for i in 0..b.w.items.len() {
        if !b.w.items[i].hostile && matches!(b.w.items[i].kind, Kind::Rotation { .. } | Kind::List { .. }) {
            let to: Vec<usize> = (0..np).filter(|&n| b.w.final_member(n) && b.w.reaches(i, n)).collect();
            for n in to {
                b.w.items[i].recv[n] = b.w.items[i].recv[n].min(t_max + 4);
            }
        }
    }
    b.settle(t_max + 5);
    for n in [X, Y] {
        if n < np && thief_listing[n] == 2 && b.w.left[n] < LATE && !b.w.member(n, t_max + 12) {
            b.thief_listing(n, t_max + 12, &|_| Some(0));
        }
    }
    b.w
}

/// Family A, one label and thing: 2 P nodes, 1 witness, 1 outsider, tr = 3, one or two
/// content commits (author, time 1..4, backdated or not, each other node's receipt
/// immediate, late or never), X's fork before or after the removal or none (the owner merges
/// out every fork it holds), X's counter-merge or not, a snapshot none / by node 0 / by the
/// witness (falling or not), covered commits omitted or listed. Honest answers always.
pub fn family_a(shard: usize, shards: usize, f: &mut impl FnMut(World)) -> u64 {
    let mut count = 0;
    let recv_opts = [0u32, 2, LATE];
    let item_choices: Vec<(usize, u32, bool, [u32; 4])> = {
        let mut v = vec![];
        for author in [0usize, X] {
            for t in 1..=4u32 {
                for backdated in [false, true] {
                    if backdated && !(author == X && t >= 3) {
                        continue;
                    }
                    for a in recv_opts {
                        for b in recv_opts {
                            for c in recv_opts {
                                let mut r = [0u32; 4];
                                let others: Vec<usize> = (0..4).filter(|&n| n != author).collect();
                                r[others[0]] = a;
                                r[others[1]] = b;
                                r[others[2]] = c;
                                v.push((author, t, backdated, r));
                            }
                        }
                    }
                }
            }
        }
        v
    };
    let mut item_sets: Vec<Vec<(usize, u32, bool, [u32; 4])>> = item_choices.iter().map(|c| vec![*c]).collect();
    for (i, a) in item_choices.iter().enumerate() {
        for b in item_choices.iter().skip(i) {
            if a.3.iter().all(|&r| r != LATE) && b.3.iter().all(|&r| r != LATE) || (a.1 <= b.1 && (a.0 == X || b.0 == X)) {
                item_sets.push(vec![*a, *b]);
            }
        }
    }
    for items in item_sets.iter().skip(shard).step_by(shards) {
        for thief in 0..3u8 {
            for merges in 0..3u8 {
                // The owner merges out every fork it holds; `merges` 2 adds X's counter-merge.
                if (merges > 0) != (thief > 0) || merges == 1 && thief == 0 {
                    continue;
                }
                for snap in 0..4u8 {
                    for omit in [false, true] {
                        if !omit && snap == 0 {
                            continue;
                        }
                        count += 1;
                        let mut w = World::shape(2, vec![vec![0]], vec![vec![0]; 4], vec![None, None, Some(0), None], None, None, omit);
                        w.left[X] = 3;
                        let mut b = Builder::new(w);
                        let tx = if thief == 1 { 2 } else { 4 };
                        for t in 1..=8u32 {
                            b.answer(t, &|_| Some(0), &|_, _| Some(0));
                            for &(author, it, backdated, r) in items {
                                if it != t {
                                    continue;
                                }
                                let hostile = author == X && t >= 3;
                                let epoch = if hostile { b.epoch_known(X, t) } else { b.epoch_of(author, t) };
                                let recv: Vec<u32> = r.iter().map(|&d| if d >= LATE { LATE } else { t + d }).collect();
                                b.add(Kind::Content { thing: 0, plain: true }, author, Some(epoch), t, if backdated { 1 } else { t }, recv, hostile);
                            }
                            if snap > 0 && t == 3 {
                                let by = if snap == 1 { 0 } else { 2 };
                                b.snapshot(by, 0, t, &|_| Some(0), (snap == 3).then_some((t + 2, &|_: usize| Some(0u32) as Option<u32>)));
                            }
                            if thief > 0 && tx == t {
                                // Before the removal X is a member: its rotation is an honest fork.
                                if b.w.member(X, t) {
                                    b.rotate(X, t, &|_| Some(1), &|_, _| Some(1));
                                } else {
                                    b.rotate_thief(X, t, &|_| Some(1));
                                }
                            }
                            if t == 3 {
                                b.remove(X, t, &|_| Some(1), &|_, _| Some(1));
                            }
                            if t >= 5 && b.holds_unmerged_fork(0, t) {
                                b.rotate(0, t, &|_| Some(1), &|_, _| Some(1));
                            }
                            if merges == 2 && t == 7 {
                                b.rotate_thief(X, t, &|n| Some(if n == 2 { 0 } else { 2 }));
                            }
                        }
                        b.settle(11);
                        f(b.w);
                    }
                }
            }
        }
    }
    count
}

/// Family B, the new dimensions: 3 P nodes (0 the remover, X, Y), labels L0 and L1, things
/// T0 in L0, T1 in both, T2 in L1; X opens both. Node 0 opens L0 or both, Y one or both;
/// one witness on T1 or T2 opening L1; the outsider one label or both. Scenario: X removed
/// at 3 then Y at 6; X removed at 3 and re-added at 6; X removed at 3, Y at 5 and X re-added
/// at 7. Part bound none or 1. One content commit (author, thing it reads, time 2/4/7, plain
/// or not, receipts of node 0, the other P node and the witness immediate, late or never),
/// alone or with one of four companions. A removed author's commit is hostile, stamped 1.
pub fn family_b(shard: usize, shards: usize, f: &mut impl FnMut(World)) -> u64 {
    let things = vec![vec![0], vec![0, 1], vec![1]];
    let recv_opts = [0u32, 2, LATE];
    // (author, thing, t, plain, [recv node 0, other P node, witness])
    type C = (usize, Thing, u32, bool, [u32; 3]);
    let mut choices: Vec<C> = vec![];
    for author in [0usize, X, Y] {
        for th in 0..3 {
            for t in [2u32, 4, 7] {
                for plain in [true, false] {
                    for a in recv_opts {
                        for b in recv_opts {
                            for c in recv_opts {
                                choices.push((author, th, t, plain, [a, b, c]));
                            }
                        }
                    }
                }
            }
        }
    }
    let companions: [Option<C>; 5] = [None, Some((0, 1, 2, true, [0, 0, 0])), Some((X, 1, 2, false, [0, 0, 0])), Some((Y, 2, 4, true, [LATE, 0, 0])), Some((X, 0, 2, true, [LATE, 2, 0]))];
    let opens0 = [vec![0], vec![0, 1]];
    let opens_y = [vec![0], vec![1], vec![0, 1]];
    let mut count = 0;
    let mut k = 0usize;
    for o0 in &opens0 {
        for oy in &opens_y {
            for wt in [1usize, 2] {
                for oo in &opens_y {
                    for scenario in 0..3u8 {
                        for bound in [None, Some(1)] {
                            for c in &choices {
                                for comp in &companions {
                                    k += 1;
                                    if k % shards != shard {
                                        continue;
                                    }
                                    let opens = vec![o0.clone(), vec![0, 1], oy.clone(), vec![1], oo.clone()];
                                    let w = World::shape(3, things.clone(), opens, vec![None, None, None, Some(wt), None], None, bound, false);
                                    let reads = |n: usize, th: Thing| w.reads(n, th);
                                    let mut items: Vec<C> = vec![*c];
                                    items.extend(comp.iter().copied());
                                    if items.iter().any(|it| !reads(it.0, it.1)) {
                                        continue;
                                    }
                                    let mut w = w;
                                    let (tr2, ta) = match scenario {
                                        0 => (6, LATE),
                                        1 => (LATE, 6),
                                        _ => (5, 7),
                                    };
                                    w.left[X] = 3;
                                    w.readded[X] = ta;
                                    w.left[Y] = tr2;
                                    count += 1;
                                    let mut b = Builder::new(w);
                                    for t in 1..=9u32 {
                                        b.answer(t, &|_| Some(0), &|_, th| Some(if th == 1 { 2 } else { 1 }));
                                        for &(author, th, it, plain, r) in &items {
                                            if it != t {
                                                continue;
                                            }
                                            let other = if author == 0 { X } else if author == X { Y } else { X };
                                            let d = |n: usize| -> Option<u32> {
                                                let v = if n == 0 { r[0] } else if n == other { r[1] } else if n == 3 { r[2] } else { 0 };
                                                (v < LATE).then_some(v)
                                            };
                                            b.write(author, th, plain, t, 1, false, &d);
                                        }
                                        if t == 3 {
                                            b.remove(X, t, &|_| Some(1), &|_, th| Some(th as u32));
                                        }
                                        if t == tr2 {
                                            b.remove(Y, t, &|_| Some(1), &|_, th| Some(2 - th as u32));
                                        }
                                    }
                                    b.settle(12);
                                    f(b.w);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    count
}

/// Family C, a sibling rotating after a removal it has not received: 3 P nodes (0 the
/// remover, X, S = 2), a witness (node 3, writer of the thing), an outsider (node 4), one
/// label and thing. Node 0 removes X at 3; the removal reaches S at 7, everyone else at 4.
/// S rotates at 3, 4 or 5 (boxing X), reaching node 0 after 1 or 3 ticks, everyone else
/// after 1. X does nothing, forks at 6 from the newest epoch it holds, or also counter-merges
/// at 9; X lists its own writes at 7 or not. One content commit (author node 0, S, or X at
/// its newest epoch or epoch 0, time 2/5/7, each other node's receipt immediate, late or
/// never), alone or with one of four companions. Node 0 merges out every fork it holds from
/// 6 on; honest answers every tick.
pub fn family_c(shard: usize, shards: usize, f: &mut impl FnMut(World)) -> u64 {
    const S: usize = 2;
    let recv_opts = [0u32, 2, LATE];
    // (author, old epoch, t, receipts of the four other nodes in order)
    type C = (usize, bool, u32, [u32; 4]);
    let mut choices: Vec<C> = vec![];
    for (author, old) in [(0, false), (S, false), (X, false), (X, true)] {
        for t in [2u32, 5, 7] {
            if old && t < 3 {
                continue;
            }
            for a in recv_opts {
                for b in recv_opts {
                    for c in recv_opts {
                        for d in recv_opts {
                            choices.push((author, old, t, [a, b, c, d]));
                        }
                    }
                }
            }
        }
    }
    let companions: [Option<C>; 5] = [None, Some((S, false, 5, [0, 0, 0, 0])), Some((X, false, 5, [LATE, 0, 0, 0])), Some((0, false, 5, [0, 0, 0, 0])), Some((X, false, 7, [0, 0, LATE, 0]))];
    let mut count = 0;
    let mut k = 0usize;
    for ts in [3u32, 4, 5] {
        for s_to_0 in [1u32, 3] {
            for thief in 0..3u8 {
                for listing in [false, true] {
                    for c in &choices {
                        for comp in &companions {
                            k += 1;
                            if k % shards != shard {
                                continue;
                            }
                            count += 1;
                            let mut w = World::shape(3, vec![vec![0]], vec![vec![0]; 5], vec![None, None, None, Some(0), None], None, None, false);
                            w.left[X] = 3;
                            let mut b = Builder::new(w);
                            let mut items: Vec<C> = vec![*c];
                            items.extend(comp.iter().copied());
                            for t in 1..=11u32 {
                                b.answer(t, &|_| Some(0), &|_, _| Some(0));
                                for &(author, old, it, r) in &items {
                                    if it != t {
                                        continue;
                                    }
                                    let d = |n: usize| -> Option<u32> {
                                        let others: Vec<usize> = (0..5).filter(|&m| m != author).collect();
                                        let v = r[others.iter().position(|&m| m == n).unwrap_or(0)];
                                        (v < LATE).then_some(v)
                                    };
                                    b.write(author, 0, true, t, 1, old, &d);
                                }
                                if t == 3 {
                                    b.remove(X, t, &|n| Some(if n == S { 4 } else { 1 }), &|n, _| Some(if n == S { 4 } else { 1 }));
                                }
                                if t == ts {
                                    let d = |n: usize| Some(if n == 0 { s_to_0 } else { 1 });
                                    b.rotate(S, t, &d, &|n, _| d(n));
                                }
                                if thief > 0 && t == 6 {
                                    b.rotate_thief(X, t, &|_| Some(1));
                                }
                                if thief == 2 && t == 9 {
                                    b.rotate_thief(X, t, &|_| Some(1));
                                }
                                if listing && t == 7 {
                                    b.thief_listing(X, t, &|_| Some(1));
                                }
                                if t >= 6 && b.holds_unmerged_fork(0, t) {
                                    b.rotate(0, t, &|_| Some(1), &|_, _| Some(1));
                                }
                            }
                            b.settle(14);
                            f(b.w);
                        }
                    }
                }
            }
        }
    }
    count
}

fn print_world(w: &World) {
    println!("np {} nodes {} things {:?} opens {:?} writers {:?} admin {:?} left {:?} readded {:?} bound {:?} omit_covered {}", w.np, w.nodes, w.things, w.opens, w.writer, w.admin, w.left, w.readded, w.bound, w.omit_covered);
    for i in &w.items {
        println!("  #{} {:?} by n{} epoch {:?} t {} ts {} recv {:?}{}", i.id, i.kind, i.author, i.epoch, i.t, i.ts, i.recv, if i.hostile { " HOSTILE" } else { "" });
    }
}

fn parallel(f: impl Fn(usize, usize, &mut Stats) -> u64 + Sync) -> (u64, Stats) {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let results: Vec<(u64, Stats)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                let f = &f;
                s.spawn(move || {
                    let mut st = Stats::default();
                    let n = f(th, threads, &mut st);
                    (n, st)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut st = Stats::default();
    let mut n = 0;
    for (c, s) in results {
        n += c;
        st.merge(s);
    }
    (n, st)
}

pub fn run(samples: u64, exhaustive_family: bool) {
    let mut fails = vec![];
    if exhaustive_family {
        let (n, st) = parallel(|th, threads, st| family_a(th, threads, &mut |w| check(&w, st)));
        println!("family A (one label): {n} worlds");
        st.print("epochs-exh A");
        fails.push(st);
        let (n, st) = parallel(|th, threads, st| family_b(th, threads, &mut |w| check(&w, st)));
        println!("family B (labels, successive removals, re-add, bound): {n} worlds");
        st.print("epochs-exh B");
        fails.push(st);
        let (n, st) = parallel(|th, threads, st| family_c(th, threads, &mut |w| check(&w, st)));
        println!("family C (a sibling rotating after a removal it has not received): {n} worlds");
        st.print("epochs-exh C");
        fails.push(st);
    } else {
        let (_, st) = parallel(|th, threads, st| {
            let mut rng = Rng(0x5eed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
            for _ in 0..samples / threads as u64 {
                check(&random_world(&mut rng), st);
            }
            0
        });
        st.print("epochs");
        fails.push(st);
    }
    for st in fails {
        if let Some(w) = &st.fail {
            println!("first failing world:");
            print_world(w);
        }
        if let Some(w) = &st.fail_live {
            println!("first liveness failure:");
            print_world(w);
        }
        if std::env::var_os("EPOCHS_DEBUG").is_some() {
            DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
            for w in st.fail.iter().chain(&st.fail_live) {
                check(w, &mut Stats::default());
            }
            DEBUG.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 3 P nodes, one witness (node 3, writer of thing 0), one outsider (node 4); one label,
    /// one thing.
    fn world(f: impl FnOnce(&mut Builder)) -> World {
        let mut w = World::shape(3, vec![vec![0]], vec![vec![0]; 5], vec![None, None, None, Some(0), None], None, None, false);
        w.left[X] = 3;
        let mut b = Builder::new(w);
        f(&mut b);
        b.w
    }

    fn all(w: &World) -> Vec<bool> {
        vec![true; w.items.len()]
    }

    fn at(n: u32) -> Vec<u32> {
        vec![n; 5]
    }

    fn content(b: &mut Builder, author: usize, epoch: Epoch, t: u32, ts: u32, recv: Vec<u32>) -> usize {
        let hostile = !b.w.member(author, t);
        b.add(Kind::Content { thing: 0, plain: true }, author, Some(epoch), t, ts, recv, hostile)
    }

    fn rot(b: &mut Builder, author: usize, at: Epoch, new: Epoch, supersedes: Vec<Epoch>, names: Vec<u32>, t: u32) -> usize {
        b.add(Kind::Rotation { at, new, supersedes, names }, author, Some(at), t, t, vec![t; b.w.nodes], false)
    }

    /// Step 5: X's backdated write after its removal never counts once the rotation is held;
    /// its write before it, received by the rotator, counts (the rotator's list).
    #[test]
    fn rotator_received_write_counts_later_write_does_not() {
        let w = world(|b| {
            content(b, X, 0, 1, 1, at(1));
            b.remove(X, 3, &|_| Some(0), &|_, _| Some(0));
            content(b, X, 0, 4, 2, at(4));
        });
        // content, rotation, its list, X's later write
        let v = w.judge(&all(&w), None);
        assert_eq!(v.valid, vec![true, true, true, false]);
        assert!(w.judge(&w.held_at(4, 2), None).valid[0]);
    }

    /// Step 5: a sibling's offline write at the closed epoch counts once its listing names it.
    #[test]
    fn sibling_listing_revives_its_offline_write() {
        let w = world(|b| {
            b.remove(X, 3, &|n| if n == 2 { Some(3) } else { Some(0) }, &|n, _| if n == 2 { Some(3) } else { Some(0) });
            content(b, 2, 0, 4, 4, vec![6, 6, 4, 6, 6]);
            b.listings(2, 7, &|_, _| Some(0));
        });
        // rotation, list, content, listing
        assert_eq!(w.items.len(), 4);
        assert!(w.judge(&all(&w), None).valid[2]);
        assert!(!w.judge(&[true, true, true, false], None).valid[2]);
    }

    /// Step 5: a write only a witness received in time counts; X's later write the witness
    /// received after the removal's `ts` is not listed.
    #[test]
    fn write_only_a_witness_received_counts() {
        let w = world(|b| {
            content(b, X, 0, 1, 1, vec![LATE, 1, LATE, 1, LATE]);
            b.remove(X, 3, &|_| Some(0), &|_, _| Some(0));
            content(b, X, 0, 4, 1, vec![LATE, 4, LATE, 4, LATE]);
            b.addenda(3, 5, &|_| Some(0));
        });
        // content, rotation, its (empty) list, X's later write, the addendum
        let v = w.judge(&all(&w), None);
        assert!(v.valid[0] && !v.valid[3]);
        assert_eq!(w.items[4].kind, Kind::Addendum { against: 2, thing: 0, lists: vec![1] });
    }

    /// Step 4: the thief's fork counts until the owner's merge, its epoch closed by the
    /// removal; two merges are a dispute,
    /// read by side; the default side is the line holding the first-received contested
    /// rotation.
    #[test]
    fn thief_fork_and_dispute() {
        let w = world(|b| {
            let r0 = rot(b, 0, 0, 1, vec![0], vec![], 3);
            b.w.items[r0].recv[X] = LATE;
            let rx = rot(b, X, 0, 10, vec![0], vec![], 4);
            b.w.items[rx].hostile = true;
            content(b, X, 10, 5, 5, at(5));
            rot(b, 0, 1, 30, vec![1, 10], vec![], 6);
            let m = rot(b, X, 10, 40, vec![1, 10], vec![2], 7);
            b.w.items[m].hostile = true;
            b.w.items[m].recv[4] = 8;
            // the thief's merge lists its own write at the epoch it closes
            b.add(Kind::List { rot: 5, thing: 0, lists: vec![3] }, X, None, 7, 7, at(8), true);
        });
        let fork_only = vec![true, true, true, false, false, false];
        let v = w.judge(&fork_only, None);
        assert!(v.counting[0] && v.counting[1] && !v.valid[2], "the fork counts before the merge, but the removal closes its epoch");
        assert!(w.judge(&[false, true, true, false, false, false], None).valid[2], "without the removal its write counts (unaware reader)");
        let merged = vec![true, true, true, true, false, false];
        assert!(!w.judge(&merged, None).valid[2], "a removed node's fork is void once the owner's merge is held");
        let both = all(&w);
        let v = w.judge(&both, Some(3));
        assert!(v.dispute && !v.valid[2] && v.counting[0] && !v.counting[1]);
        let vx = w.judge(&both, Some(4));
        assert!(vx.dispute && vx.valid[2] && !vx.counting[3] && vx.counting[1] && vx.counting[4]);
        // The outsider received the owner's merge (6) before the thief's (8).
        assert_eq!(w.default_side(4, &both), Some(3));
    }

    /// Step 4: concurrent rotations at one epoch both count; a merge naming one and
    /// superseding the other rejects the unnamed one with its line; a rotation from above
    /// (signed under a line) rejects nothing on it; an ill-formed supersedes entry (an epoch
    /// on its own chain, or one never minted) rejects nothing.
    #[test]
    fn forks_merges_and_supersedes_entries() {
        let w = world(|b| {
            rot(b, 0, 0, 1, vec![0], vec![], 3); // #1
            rot(b, 2, 0, 2, vec![0], vec![], 3); // #2: concurrent fork
            rot(b, 0, 1, 3, vec![1, 2], vec![], 5); // #3: merge, #2 unnamed
            rot(b, 0, 1, 4, vec![1, 2], vec![2], 5); // #4: merge naming #2
            rot(b, 2, 2, 5, vec![0, 2], vec![], 6); // #5: under #2's line, supersedes 0 from above
            rot(b, 0, 1, 6, vec![1, 0, 99], vec![], 6); // #6: ancestor and unknown entries
        });
        let held = |ids: &[usize]| -> Vec<bool> { (1..=6).map(|i| ids.contains(&i)).collect() };
        let v = w.judge(&held(&[1, 2]), None);
        assert!(v.counting[0] && v.counting[1], "fork rotations both count");
        let v = w.judge(&held(&[1, 2, 3]), None);
        assert!(v.counting[2] && !v.counting[1], "the merge rejects the unnamed line");
        let v = w.judge(&held(&[1, 2, 4]), None);
        assert!(v.counting[3] && v.counting[1] && v.closed.contains(&2), "a named fork counts and is closed");
        let v = w.judge(&held(&[1, 2, 5]), None);
        assert!(v.counting[0] && v.counting[4], "a rotation from above rejects nothing");
        let v = w.judge(&held(&[1, 6]), None);
        assert!(v.counting[0] && v.counting[5], "ill-formed entries are ignored");
    }

    /// Account-level demotion and the epoch filter are independent conjuncts.
    #[test]
    fn demotion_and_epoch_independent() {
        let mut w = World::shape(2, vec![vec![0]], vec![vec![0]; 4], vec![None; 4], Some(2), None, false);
        w.left[X] = 3;
        let mut b = Builder::new(w);
        // listed by the rotation, but not by A's demotion
        b.add(Kind::Content { thing: 0, plain: true }, 0, Some(0), 1, 1, vec![1, 1, LATE, 1], false);
        b.remove(X, 3, &|_| Some(0), &|_, _| Some(0));
        b.add(Kind::Demotion { thing: 0, frontier: vec![] }, 2, None, 5, 5, vec![5; 4], false);
        let w = b.w;
        let v = w.judge(&all(&w), None);
        assert!(v.as_p[0] && !v.valid[0]);
    }

    /// Step 5, successive removals: a listing at epoch 1 that the second rotation closes
    /// counts once that rotation lists it by ID; unlisted, its own words fall with it.
    #[test]
    fn listing_at_a_closed_epoch_counts_once_listed() {
        let mut w = World::shape(3, vec![vec![0]], vec![vec![0]; 5], vec![None; 5], None, None, false);
        w.left[X] = 3;
        w.left[Y] = 6;
        let mut b = Builder::new(w);
        // Y's write node 0 never receives; Y lists it at epoch 1 after X's removal.
        b.add(Kind::Content { thing: 0, plain: true }, Y, Some(0), 1, 1, vec![LATE, 1, 1, LATE, 1], false); // #1
        b.remove(X, 3, &|_| Some(0), &|_, _| Some(0)); // #2 rotation 0 -> 1, #3 its list
        b.listings(Y, 4, &|_, _| Some(0)); // #4
        assert!(matches!(&b.w.items[3].kind, Kind::Listing { at: 1, lists, .. } if lists == &vec![1]));
        b.remove(Y, 6, &|_| Some(0), &|_, _| Some(0)); // #5 rotation 1 -> 2, #6 its list
        let w = b.w.clone();
        assert!(matches!(&w.items[5].kind, Kind::List { lists, .. } if lists == &vec![4]));
        let v = w.judge(&all(&w), None);
        assert!(v.valid[0] && v.as_p[3]);
        // Without the second rotation's list the listing at the closed epoch falls, and so does the write.
        let mut held = all(&w);
        held[5] = false;
        let v = w.judge(&held, None);
        assert!(!v.as_p[3] && !v.valid[0]);
    }

    /// Labels: node 0 opens L0 only. A sibling's write on a thing only in L1 counts only
    /// once a listing names it (no part for L1); a write on a thing in both labels is named
    /// in L0's part, and that per-thing list reaches a reader of L1 alone.
    #[test]
    fn unopened_label_and_thing_in_two_groups() {
        let things = vec![vec![0], vec![0, 1], vec![1]];
        // node 0 L0, X both, node 2 L1, node 3 an outsider reading L1 only
        let w = World::shape(3, things, vec![vec![0], vec![0, 1], vec![1], vec![1]], vec![None; 4], None, None, false);
        let mut w = w;
        w.left[X] = 3;
        let mut b = Builder::new(w);
        b.add(Kind::Content { thing: 2, plain: true }, X, Some(0), 1, 1, vec![LATE, 1, 1, 1], false); // #1 on T2
        b.add(Kind::Content { thing: 1, plain: true }, X, Some(0), 1, 1, vec![1, 1, LATE, 1], false); // #2 on T1
        b.remove(X, 3, &|_| Some(0), &|_, _| Some(0)); // #3 rotation; lists for T0 (#4), T1 (#5)
        assert!(matches!(&b.w.items[4].kind, Kind::List { thing: 1, lists, .. } if lists == &vec![2]));
        assert_eq!(b.w.items[4].recv[3], 3, "T1's list reaches a reader of L1 alone");
        let before = b.w.judge(&b.w.held_at(3, 3), None);
        assert!(!before.valid[0] && before.valid[1]);
        b.listings(2, 4, &|_, _| Some(0)); // #6: node 2 names X's T2 write it received in time
        let w = b.w;
        let v = w.judge(&w.held_at(3, 4), None);
        assert!(v.valid[0] && v.valid[1]);
    }

    /// Re-add: X's write while removed counts only once P's later word names it (every
    /// node lists a re-added node's commits), never before.
    #[test]
    fn readd_revives_by_listing() {
        let mut w = World::shape(2, vec![vec![0]], vec![vec![0]; 3], vec![None; 3], None, None, false);
        w.left[X] = 3;
        w.readded[X] = 6;
        let mut b = Builder::new(w);
        b.remove(X, 3, &|_| Some(0), &|_, _| Some(0)); // #1, #2
        b.write(X, 0, true, 4, 1, false, &|_| Some(0)); // #3 hostile, epoch 0
        assert!(b.w.items[2].hostile && b.w.items[2].epoch == Some(0));
        b.listings(0, 5, &|_, _| Some(0));
        assert_eq!(b.w.items.len(), 3, "before the re-add nobody names it");
        b.listings(0, 6, &|_, _| Some(0)); // #4
        let w = b.w;
        assert!(w.judge(&all(&w), None).valid[2]);
        assert!(!w.judge(&[true, true, true, false], None).valid[2]);
    }

    /// Bound: plain content past a part's bound goes into the rotator's later listing; a
    /// part whose special commits pass it refuses the rotation; a list over the bound is bad
    /// input.
    #[test]
    fn bound_overflow_refusal_and_bad_list() {
        let mut w = World::shape(2, vec![vec![0]], vec![vec![0]; 3], vec![None; 3], None, Some(1), false);
        w.left[X] = 3;
        let mut b = Builder::new(w);
        b.add(Kind::Content { thing: 0, plain: true }, X, Some(0), 1, 1, vec![1, 1, LATE], false); // #1
        b.add(Kind::Content { thing: 0, plain: true }, X, Some(0), 2, 2, vec![2, 2, LATE], false); // #2
        b.remove(X, 3, &|_| Some(0), &|_, _| Some(0)); // #3, #4 lists [1]
        assert!(matches!(&b.w.items[3].kind, Kind::List { lists, .. } if lists == &vec![1]));
        assert!(!b.w.judge(&all(&b.w), None).valid[1]);
        b.listings(0, 4, &|_, _| Some(0)); // #5 names #2
        let v = b.w.judge(&all(&b.w), None);
        assert!(v.valid[0] && v.valid[1]);
        // Two special commits under a bound of 1: the removal cannot be written.
        let mut w = World::shape(2, vec![vec![0]], vec![vec![0]; 3], vec![None; 3], None, Some(1), false);
        w.left[X] = 3;
        let mut b = Builder::new(w);
        for t in 1..=2 {
            b.add(Kind::Content { thing: 0, plain: false }, X, Some(0), t, t, vec![t, t, LATE], false);
        }
        assert!(b.remove(X, 3, &|_| Some(0), &|_, _| Some(0)).is_none());
        assert_eq!(b.w.left[X], LATE);
        // A list over the bound lists nothing.
        let mut w = b.w.clone();
        let r = Builder::new(w.clone()).w.items.len();
        w.items.push(Item { id: r as u32 + 1, kind: Kind::Rotation { at: 0, new: 1, supersedes: vec![0], names: vec![] }, author: 0, epoch: Some(0), t: 3, ts: 3, recv: vec![3; 3], hostile: false });
        w.items.push(Item { id: r as u32 + 2, kind: Kind::List { rot: r as u32 + 1, thing: 0, lists: vec![1, 2] }, author: 0, epoch: None, t: 3, ts: 3, recv: vec![3; 3], hostile: false });
        let v = w.judge(&all(&w), None);
        assert!(!v.valid[0] && !v.valid[1]);
    }

    /// Covered commits: a list leaves out a commit a valid snapshot it holds covers; the
    /// write still reads through the snapshot, and once the snapshot falls a lister answering
    /// again names it.
    #[test]
    fn covered_commits_omitted_then_named_after_the_fall() {
        let mut w = World::shape(2, vec![vec![0]], vec![vec![0]; 4], vec![None, None, Some(0), None], None, None, true);
        w.left[X] = 3;
        let mut b = Builder::new(w);
        b.add(Kind::Content { thing: 0, plain: true }, X, Some(0), 1, 1, vec![1, 1, 1, 1], false); // #1
        b.snapshot(2, 0, 2, &|_| Some(0), None); // #2 witness snapshot
        b.remove(X, 3, &|_| Some(0), &|_, _| Some(0)); // #3, #4
        assert!(matches!(&b.w.items[3].kind, Kind::List { lists, .. } if lists.is_empty()));
        let v = b.w.judge(&all(&b.w), None);
        assert!(!v.valid[0] && v.visible[0]);
        b.add(Kind::Fall { snap: 2 }, 2, None, 4, 4, vec![4; 4], false); // #5
        b.listings(0, 5, &|_, _| Some(0)); // #6
        let v = b.w.judge(&all(&b.w), None);
        assert!(v.valid[0]);
    }

    /// Step 4/5: node 2 rotates before X's removal reaches it, boxing X epoch 1. The removal
    /// closes epoch 1 (it does not descend from the removal), so X's write there after its
    /// removal does not count; node 0's merge is signed at epoch 1 too (it names node 2's
    /// fork), so X's fork from epoch 1 cannot reject the removal once the merge is held, and
    /// the merge's list leaves out what node 0 received at epoch 1 after the removal.
    #[test]
    fn removed_node_holding_a_sibling_epoch() {
        let mut w = World::shape(3, vec![vec![0]], vec![vec![0]; 5], vec![None, None, None, Some(0), None], None, None, false);
        w.left[X] = 4;
        let mut b = Builder::new(w);
        let s = b.rotate(2, 3, &|n| Some(if n == 0 { 3 } else { 0 }), &|_, _| Some(0)).unwrap(); // #1 0 -> 1 boxes X, #2 its list
        let r = b.remove(X, 4, &|n| Some(if n == 2 { 3 } else { 0 }), &|_, _| Some(0)).unwrap(); // #3 0 -> 2, #4
        let x = b.write(X, 0, true, 5, 5, false, &|_| Some(0)); // #5 X, removed, at epoch 1
        assert!(b.w.items[x].hostile && b.w.items[x].epoch == Some(1));
        let alone = b.w.held_at(4, 5);
        let v = b.w.judge(&alone, None);
        assert!(v.counting[s] && v.counting[r] && v.closed.contains(&1) && v.closed.contains(&2), "concurrent rotations close each other's epochs: {v:?}");
        assert!(!v.valid[x], "the removal closes the sibling's epoch");
        let f = b.rotate_thief(X, 5, &|_| Some(0)); // #6 X's fork from epoch 1, superseding 2 unnamed; #7 its list names #5
        let window = b.w.held_at(4, 5);
        let v = b.w.judge(&window, None);
        assert!(v.counting[f] && !v.counting[r] && v.valid[x], "until the merge arrives, X's fork rejects the removal (the fork window)");
        let m = b.rotate(0, 6, &|_| Some(0), &|_, _| Some(0)).unwrap(); // node 0 merges: at 2, names #1, supersedes X's fork
        assert!(matches!(&b.w.items[m].kind, Kind::Rotation { at: 2, names, .. } if names == &vec![1]));
        assert!(b.w.items.iter().all(|i| !matches!(&i.kind, Kind::List { rot, lists, .. } if *rot == b.w.items[m].id && lists.contains(&b.w.items[x].id))), "the merge's list leaves out X's write after the removal");
        b.addenda(3, 7, &|_| Some(0));
        b.listings(2, 7, &|_, _| Some(0));
        let w = b.w;
        let all = all(&w);
        for o in [0, 2, 3, 4] {
            let v = w.judge(&all, w.default_side(o, &all));
            assert!(v.counting[r] && v.counting[m] && !v.counting[f] && !v.dispute && !v.valid[x], "observer {o}: {v:?}");
        }
    }

    #[test]
    fn random_worlds_hold() {
        let mut rng = Rng(7);
        let mut st = Stats::default();
        for _ in 0..3000 {
            let w = random_world(&mut rng);
            check(&w, &mut st);
        }
        if let Some(w) = &st.fail {
            print_world(w);
        }
        assert_eq!(st.hard_failures(), 0, "{st:?}");
    }
}
