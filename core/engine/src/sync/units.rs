//! Sync units and the node closure (spec/sync-set.md §2): what a sync ID carries, walked by
//! strongs within what the root may read; the node closure, walked sync unit by sync unit from
//! the node root.
//!
//! One structure holds both (`Closure`): a spanning tree over vertices (context, thing) rooted at
//! (local, node root). A context is the node root's local part, a sync unit read (`Ctx::Read`),
//! one kept unread (`Ctx::Unread`), or a stub held (`Ctx::Stub`). A vertex's out-list
//! (`given_by`) is what the walk takes from it by each of its thing's references: in the local
//! part its strongs to dependent things; in T's read sync unit its strongs to things T's keys
//! open; from either, a strong to an independent thing the context does not follow enters that
//! thing's sync unit by the secrets the node holds of it where the unit carries it, and so does a
//! strong to an independent thing inside a read sync unit (its own sync unit is part of the one
//! it is in, so entering it holds nothing more and records which sync units hold what); and the
//! stubs the unit carries (spec/sync-set.md §2 Stubs): a weak's target, and the holders on the
//! unit's chains to what the reference brings. A sync unit kept unread is its root alone: the node
//! cannot read what it holds; a stub is its thing alone, its role entries held. So T's sync unit
//! is the things of context `Read(T)`, and the node closure is every thing of a context other
//! than a stub.
//!
//! Work follows change (spec/sync-set.md §2 Cost): each held vertex's edge to each target of its
//! strongs is followed by an `Effects` key, due when what its judgement read moved (whether the target
//! is independent, the roles and secrets it is judged by); a strong appearing or going is told by the
//! reference index (`note_row`). A settle at each transaction's end diffs the due
//! edges into the tree. An edge added costs what it brings in. An edge removed that is no tree
//! edge costs O(1); a tree edge removed runs two searches in step, stopping at the first answer
//! (notes/closure-model.md, P5 counts): the removed target's other referrers walked up their
//! tree paths (one outside the target's subtree re-attaches it), and the target's subtree, which
//! once whole re-attaches each member a held referrer outside it still reaches, and what that
//! reaches, and drops the rest. So a removal costs at most twice the smaller search, never the
//! target's fan-in from outside its subtree.

use crate::engine::journal::{JMap, JSet, JSetMap, Journaled};
use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::memo::Effects;
use osis_base::{RefKind, Role, SyncId, Tid};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

/// Where the walk is: the node root's local part, or a sync unit entered read or kept unread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ctx {
    Local,
    Read(Tid),
    Unread(Tid),
    /// The thing held as a stub (spec/sync-set.md §2 Holding a stub): its role entries alone.
    Stub(Tid),
}

/// A vertex of the walk: a thing reached in a context.
pub type Vx = (Ctx, Tid);

/// A spanning tree over held vertices rooted at (local, node root), its edges the closure's
/// out-lists (`Edges`). Two follow the same out-lists: the node closure's, and the sync set's,
/// where an edge into a thing sourced at another node leads nowhere (spec/sync-set.md §5).
#[derive(Clone, Debug, Default)]
struct Tree {
    /// The held vertices.
    vx: JSet<Vx>,
    /// Each held vertex but the root: the referrer it hangs from.
    parent: JMap<Vx, Vx>,
    children: JSetMap<Vx, Vx>,
    /// Per held thing, the contexts it is held in.
    held: JSetMap<Tid, Ctx>,
}

impl Journaled for Tree {
    type Mark = [usize; 4];
    fn commit(&mut self) {
        self.vx.commit();
        self.parent.commit();
        self.children.commit();
        self.held.commit();
    }
    fn mark(&mut self) -> Self::Mark {
        [self.vx.mark(), self.parent.mark(), self.children.mark(), self.held.mark()]
    }
    fn rollback_to(&mut self, m: Self::Mark) {
        self.vx.rollback_to(m[0]);
        self.parent.rollback_to(m[1]);
        self.children.rollback_to(m[2]);
        self.held.rollback_to(m[3]);
    }
    fn name(&mut self, name: &'static str) {
        self.held.name(name);
    }
    #[cfg(test)]
    fn contents(&self) -> String {
        self.vx.contents()
    }
}

/// The edges a tree follows: the held vertices' out-lists, an edge into a vertex of a thing of
/// `cut` leading nowhere.
#[derive(Clone, Copy)]
struct Edges<'a> {
    out: &'a JSetMap<Vx, Vx>,
    inn: &'a JSetMap<Vx, Vx>,
    cut: Option<&'a JSet<Tid>>,
    root: Vx,
}

impl Edges<'_> {
    /// Whether an edge into `v` leads to it.
    fn admits(&self, v: &Vx) -> bool {
        *v == self.root || self.cut.is_none_or(|c| !c.contains(&v.1))
    }
}

/// The node closure as a spanning tree over vertices (module doc), and the sync set's tree over
/// the same out-lists. Journaled: a failed transaction undoes its changes; derived, so an open
/// builds it again.
#[derive(Clone, Debug)]
pub struct Closure {
    /// The node closure's tree.
    tree: Tree,
    /// The sync set's tree (`settle_synced`): what the walk reaches through no thing of `cut`.
    synced: Tree,
    /// Each held vertex's out-list as last settled.
    out: JSetMap<Vx, Vx>,
    /// Per vertex, the held vertices whose out-list holds it.
    inn: JSetMap<Vx, Vx>,
    /// Out-list edges added or removed since the sync set's tree followed them.
    moved: JSet<(Vx, Vx)>,
    /// Strongs that appeared or went since the last settle, per target its sources (`note_row`):
    /// by target, as `targeted` reads one target's.
    rows: JSetMap<Tid, Tid>,
    /// Per thing, the held vertices of a context that reads strongs (the local part, a read sync
    /// unit) whose strong reaches it, as last judged: the things the walk reaches at a strong.
    targeted: JSetMap<Tid, Vx>,
    /// Per thing whose record the node does not hold, the held vertices whose strong reaches it,
    /// as last judged: each awaits the record (spec/commits.md §4 Records), which decides whether
    /// the strong brings the thing in, so a record blob's record of it is learned
    /// (`apply::waits::awaits_record`).
    unknown: JSetMap<Tid, Vx>,
    /// Per context, its things: a read context's are its root's sync unit.
    members: JSetMap<Ctx, Tid>,
    /// The things that left the node closure and are not released yet, each with the contexts it
    /// was in when it left (`Engine::left_closure`).
    left: JMap<Tid, BTreeSet<Ctx>>,
    /// The things sourced at another node whose paths the sync set's walk takes not
    /// (`Engine::set_sourced`, spec/sync-set.md §5).
    cut: JSet<Tid>,
    /// Per out-list edge (vertex, given vertex), the targets of the vertex's references giving it
    /// (`given_by`): several references may give one vertex (a Dependent entry by several
    /// dependents, a chain holder's stub by several things it opens the way to), which goes with
    /// the last of them.
    by: JSetMap<(Vx, Vx), Tid>,
    /// Per (vertex, target), what its edge gives as last settled (`by` read back).
    gave: JMap<(Vx, Tid), BTreeSet<Vx>>,
}

impl Default for Closure {
    fn default() -> Closure {
        Closure {
            tree: Tree::default(),
            synced: Tree::default(),
            out: JSetMap::default(),
            inn: JSetMap::default(),
            moved: JSet::default(),
            rows: JSetMap::default(),
            targeted: JSetMap::default(),
            unknown: JSetMap::default(),
            members: JSetMap::by_element(),
            left: JMap::default(),
            cut: JSet::default(),
            by: JSetMap::default(),
            gave: JMap::default(),
        }
    }
}

/// An edge followed: a held vertex and a target of its thing's strongs.
type Edge = (Vx, Tid);

/// The follower of each held vertex's edges (`Closure`), outside the journal: a rollback
/// moves the stamps of what it restores, and `reset` follows every held vertex's edges afresh.
#[derive(Clone)]
pub(crate) struct Follow {
    fx: Effects<Edge, BTreeSet<Vx>>,
    reset: bool,
    /// A settle ran in the open transaction: a rollback of it undoes what the follower acted on.
    acted: bool,
    /// Per thing a vertex of which the running settle dropped, those vertices' contexts.
    gone: std::collections::BTreeMap<Tid, BTreeSet<Ctx>>,
    /// The edges followed before this settle's refollow (`reset` after a rollback), so an edge
    /// is new only when neither follows it (`refetch`). `known` false: an open's first settle,
    /// whose edges are all old (a refetch was durable before the transaction adding its strong).
    before: Option<Effects<Edge, BTreeSet<Vx>>>,
    known: bool,
}

impl Default for Follow {
    fn default() -> Follow {
        Follow { fx: Effects::new("closure: edges"), reset: true, acted: false, gone: Default::default(), before: None, known: false }
    }
}

impl Follow {
    /// A rollback: when it undoes a settle of the open transaction, every held vertex is
    /// followed afresh, O(the node closure). A rollback of what ran before the settle (a step, a
    /// refused write) leaves the follower right: what it restores stamps what it read.
    pub(crate) fn rolled_back(&mut self) {
        if std::mem::take(&mut self.acted) {
            self.reset = true;
        }
    }

    /// The open transaction committed.
    pub(crate) fn committed(&mut self) {
        self.acted = false;
    }
}

impl Journaled for Closure {
    type Mark = ([usize; 4], [usize; 4], [usize; 11]);
    fn commit(&mut self) {
        self.targeted.commit();
        self.unknown.commit();
        self.tree.commit();
        self.synced.commit();
        self.out.commit();
        self.inn.commit();
        self.moved.commit();
        self.rows.commit();
        self.members.commit();
        self.left.commit();
        self.cut.commit();
        self.by.commit();
        self.gave.commit();
    }
    fn mark(&mut self) -> Self::Mark {
        (self.tree.mark(), self.synced.mark(), [self.out.mark(), self.inn.mark(), self.moved.mark(), self.rows.mark(), self.members.mark(), self.left.mark(), self.cut.mark(), self.unknown.mark(), self.targeted.mark(), self.by.mark(), self.gave.mark()])
    }
    fn rollback_to(&mut self, (t, s, m): Self::Mark) {
        self.tree.rollback_to(t);
        self.synced.rollback_to(s);
        self.out.rollback_to(m[0]);
        self.inn.rollback_to(m[1]);
        self.moved.rollback_to(m[2]);
        self.rows.rollback_to(m[3]);
        self.members.rollback_to(m[4]);
        self.left.rollback_to(m[5]);
        self.cut.rollback_to(m[6]);
        self.unknown.rollback_to(m[7]);
        self.targeted.rollback_to(m[8]);
        self.by.rollback_to(m[9]);
        self.gave.rollback_to(m[10]);
    }
    fn name(&mut self, _name: &'static str) {
        self.tree.name("index: closure held");
        self.synced.name("index: sync set held");
        self.members.name("index: closure members");
        self.left.name("index: closure left");
        self.cut.name("index: closure cut");
        self.targeted.name("index: closure targeted");
        self.unknown.name("index: closure unknown");
    }
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{} {} {} {}", self.tree.contents(), self.synced.contents(), self.out.contents(), self.left.contents())
    }
}

impl Tree {
    fn is_held(&self, v: &Vx) -> bool {
        self.vx.contains(v)
    }

    fn set_parent(&mut self, x: Vx, p: Vx) {
        if let Some(old) = self.parent.insert(x, p) {
            self.children.remove(&old, &x);
        }
        self.children.insert(p, x);
    }

    /// `x` held, hanging from `p` (none: the root).
    fn hold(&mut self, x: Vx, p: Option<Vx>) {
        if let Some(p) = p {
            self.set_parent(x, p);
        }
        self.vx.insert(x);
        self.held.insert(x.1, x.0);
    }

    /// `x` held no more.
    fn drop_vertex(&mut self, x: Vx) {
        if let Some(p) = self.parent.remove(&x) {
            self.children.remove(&p, &x);
        }
        for c in self.children.get(&x).cloned().unwrap_or_default() {
            self.children.remove(&x, &c);
        }
        self.vx.remove(&x);
        self.held.remove(&x.1, &x.0);
    }

    /// `w`'s tree edge went (module doc): the two searches in step; then `w` hangs from another
    /// held referrer, or its subtree is re-attached where held referrers outside it reach. The
    /// rest is returned for the caller to drop.
    fn detach(&mut self, g: Edges<'_>, w: Vx) -> BTreeSet<Vx> {
        if let Some(p) = self.parent.remove(&w) {
            self.children.remove(&p, &w);
        }
        // search A: each other referrer's tree path, up to the root (outside) or to `w` (below)
        let mut last_ref: Option<Vx> = None;
        let mut at: Option<(Vx, Vx)> = None;
        let mut a_live = g.admits(&w);
        // search B: `w`'s subtree
        let mut sub: Vec<Vx> = vec![w];
        let mut sub_set: BTreeSet<Vx> = BTreeSet::from([w]);
        let mut pending: VecDeque<Vx> = VecDeque::new();
        let mut expanding = 0;
        loop {
            if a_live {
                osis_base::costs::count("closure: removal steps", 1);
                match at {
                    None => {
                        // the next referrer, read one at a time: never a copy of `w`'s fan-in
                        let next = g.inn.get(&w).and_then(|s| match last_ref {
                            None => s.iter().next().copied(),
                            Some(l) => s.range((std::ops::Bound::Excluded(l), std::ops::Bound::Unbounded)).next().copied(),
                        });
                        match next {
                            Some(r) => {
                                at = self.is_held(&r).then_some((r, r));
                                last_ref = Some(r);
                            }
                            None => a_live = false,
                        }
                    }
                    Some((_, c)) if c == w => at = None,
                    Some((r, c)) if c == g.root => {
                        // `r` is outside `w`'s subtree: `w` hangs from it, its subtree as it was
                        self.set_parent(w, r);
                        return BTreeSet::new();
                    }
                    Some((r, c)) => at = self.parent.get(&c).map(|p| (r, *p)),
                }
            }
            // one step of B
            osis_base::costs::count("closure: removal steps", 1);
            match pending.pop_front() {
                Some(c) => {
                    if sub_set.insert(c) {
                        sub.push(c);
                    }
                }
                None => match sub.get(expanding) {
                    Some(x) => {
                        pending.extend(self.children.get(x).into_iter().flatten().copied());
                        expanding += 1;
                    }
                    None => break,
                },
            }
        }
        // the subtree whole: re-attach what a held referrer outside it still reaches
        let mut q = VecDeque::new();
        for x in sub.iter().filter(|x| g.admits(x)) {
            for r in g.inn.get(x).into_iter().flatten() {
                osis_base::costs::count("closure: removal steps", 1);
                if !sub_set.contains(r) && self.is_held(r) {
                    q.push_back((*x, *r));
                    break;
                }
            }
        }
        let mut rest = sub_set;
        for (x, _) in &q {
            rest.remove(x);
        }
        while let Some((x, r)) = q.pop_front() {
            self.set_parent(x, r);
            for y in g.out.get(&x).into_iter().flatten() {
                osis_base::costs::count("closure: removal steps", 1);
                if g.admits(y) && rest.remove(y) {
                    q.push_back((*y, x));
                }
            }
        }
        for x in &rest {
            osis_base::costs::count("closure: dropped", 1);
            self.drop_vertex(*x);
        }
        rest
    }
}

/// A tree grown by `spread`: how a vertex is held, and the out-list it follows once held.
trait Grow {
    fn grown(&self) -> &Tree;
    fn hold(&mut self, x: Vx, p: Vx);
    /// The vertices `x`'s out-list leads to (`x` just held).
    fn out(&mut self, x: Vx) -> Result<Vec<Vx>>;
}

/// Holds each of `fresh` (vertex, referrer) not held yet, and what it reaches.
fn spread(g: &mut impl Grow, fresh: Vec<(Vx, Vx)>) -> Result<()> {
    let mut q: VecDeque<(Vx, Vx)> = fresh.into();
    while let Some((x, p)) = q.pop_front() {
        if g.grown().is_held(&x) {
            continue;
        }
        g.hold(x, p);
        for w in g.out(x)? {
            if !g.grown().is_held(&w) {
                q.push_back((w, x));
            }
        }
    }
    Ok(())
}

/// The sync set's tree grown over the out-lists as they stand.
struct GrowSynced<'a>(&'a mut Closure, Vx);

impl Grow for GrowSynced<'_> {
    fn grown(&self) -> &Tree {
        &self.0.synced
    }
    fn hold(&mut self, x: Vx, p: Vx) {
        self.0.synced.hold(x, Some(p));
    }
    fn out(&mut self, x: Vx) -> Result<Vec<Vx>> {
        let cl = &*self.0;
        let g = Edges { out: &cl.out, inn: &cl.inn, cut: Some(&cl.cut), root: self.1 };
        let out: Vec<Vx> = cl.out.get(&x).into_iter().flatten().filter(|y| g.admits(y)).copied().collect();
        osis_base::costs::count("closure: synced edges", out.len() as u64);
        Ok(out)
    }
}

/// Whether contexts `cs` read their thing: the local part or a read sync unit.
fn reading(cs: &BTreeSet<Ctx>) -> bool {
    cs.iter().any(|c| matches!(c, Ctx::Local | Ctx::Read(_)))
}

impl Closure {
    /// Whether the node closure holds `t`, in any context but a stub's.
    pub(crate) fn holds(&self, t: &Tid) -> bool {
        self.tree.held.get(t).is_some_and(|cs| cs.iter().any(|c| !matches!(c, Ctx::Stub(_))))
    }

    /// Whether the node holds `t` as a stub alone (spec/sync-set.md §2 Holding a stub): a unit it
    /// reads carries `t`'s stub and the node closure does not hold `t`.
    pub(crate) fn stub_only(&self, t: &Tid) -> bool {
        !self.holds(t) && self.tree.held.get(t).is_some_and(|cs| !cs.is_empty())
    }

    /// Whether the node holds `t` at all: in the node closure or as a stub.
    pub(crate) fn holds_any(&self, t: &Tid) -> bool {
        self.tree.held.get(t).is_some_and(|cs| !cs.is_empty())
    }

    /// Whether the node closure reads `t`: holds it, or holds it leaving, in the local part or a
    /// read sync unit (spec/sync-set.md §2: a sync unit kept unread is its root alone, the node
    /// cannot read what it holds).
    pub(crate) fn reads(&self, t: &Tid) -> bool {
        self.reads_held(t) || self.left.get(t).is_some_and(reading)
    }

    /// Whether the node closure holds `t` now (not leaving) in the local part or a read sync
    /// unit.
    fn reads_held(&self, t: &Tid) -> bool {
        self.tree.held.get(t).is_some_and(reading)
    }

    /// Whether a held vertex's strong reaches `t`, as last judged.
    pub(crate) fn targeted(&self, t: &Tid) -> bool {
        self.targeted.get(t).is_some_and(|v| !v.is_empty())
    }

    /// The node closure's tree parent of held vertex `v` (none for the root).
    fn parent_of(&self, v: &Vx) -> Option<&Vx> {
        self.tree.parent.get(v)
    }

    /// Held vertex `v`'s out-list as last settled.
    fn out_of(&self, v: &Vx) -> impl Iterator<Item = &Vx> {
        self.out.get(v).into_iter().flatten()
    }

    /// The held vertices whose strong reaches `t`, as last judged.
    pub(crate) fn targeting(&self, t: &Tid) -> impl Iterator<Item = &Vx> {
        self.targeted.get(t).into_iter().flatten()
    }

    /// Notes whether `v`'s strong to `t` counts for `targeted`; whether `t` lost its last.
    fn set_targeted(&mut self, t: Tid, v: Vx, on: bool) -> bool {
        let set = |c: &Closure| c.targeted.get(&t).is_some_and(|v| !v.is_empty());
        let was = set(self);
        match on {
            true => drop(self.targeted.insert(t, v)),
            false => drop(self.targeted.remove(&t, &v)),
        }
        was && !set(self)
    }

    /// Whether a held vertex's strong reaches `t`, whose record was not held when it was judged
    /// (`unknown`).
    pub(crate) fn awaits_record(&self, t: &Tid) -> bool {
        self.unknown.get(t).is_some_and(|v| !v.is_empty())
    }

    /// Sets whether `v`'s strong to `t` counts for `awaits_record`.
    fn set_unknown(&mut self, t: Tid, v: Vx, on: bool) {
        if on {
            self.unknown.insert(t, v);
        } else {
            self.unknown.remove(&t, &v);
        }
    }

    /// Tests and debugging (`Engine::why_kept`): the node closure's tree path to `t`, from the
    /// node root, by one context holding it.
    #[cfg(debug_assertions)]
    pub(crate) fn path(&self, t: &Tid) -> Option<Vec<Vx>> {
        let cs = self.tree.held.get(t)?;
        let c = cs.iter().next()?;
        let mut path = vec![(*c, *t)];
        while let Some(p) = self.tree.parent.get(path.last()?) {
            if path.contains(p) {
                break;
            }
            path.push(*p);
        }
        path.reverse();
        Some(path)
    }

    /// The contexts holding `t`.
    pub(crate) fn contexts(&self, t: &Tid) -> BTreeSet<Ctx> {
        self.tree.held.get(t).cloned().unwrap_or_default()
    }

    /// The things of context `c` (a read of them whole).
    pub(crate) fn members(&self, c: &Ctx) -> Option<&BTreeSet<Tid>> {
        self.members.get(c)
    }

    /// Whether unit `c` carries independent `h` whole (spec/sync-set.md §2 Stubs: then no stub of
    /// it): `h` is in it, or a vertex of it enters `h` read. Read by `given_by`: an edge judged
    /// before `h` came in is judged again as it does.
    pub(crate) fn carries_whole(&self, c: Ctx, h: &Tid) -> bool {
        self.members.contains(&c, h) || self.inn.get(&(Ctx::Read(*h), *h)).is_some_and(|vs| vs.iter().any(|v| v.0 == c))
    }

    /// The independent things outside `g`'s sync unit that the walk gives from it (its entries
    /// and the stubs it carries, spec/sync-set.md §2 Stubs): what `g`'s sync ID carries the stubs
    /// of (`Engine::stub_certificates`). O(the unit's out-lists).
    pub(crate) fn unit_stubs(&self, g: &Tid) -> BTreeSet<Tid> {
        let c = Ctx::Read(*g);
        let Some(ms) = self.members.get(&c) else { return BTreeSet::new() };
        let mut out = BTreeSet::new();
        for m in ms {
            for w in self.out.get(&(c, *m)).into_iter().flatten() {
                if w.1 != *g && !ms.contains(&w.1) && matches!(w.0, Ctx::Stub(x) | Ctx::Read(x) | Ctx::Unread(x) if x == w.1) {
                    out.insert(w.1);
                }
            }
        }
        out
    }

    /// Whether `t` is in `g`'s sync unit (`Engine::sync_unit`): a read of that member alone.
    pub(crate) fn unit_holds(&self, g: &Tid, t: &Tid) -> bool {
        t == g || self.members.contains(&Ctx::Read(*g), t)
    }

    /// A cursor over the (context, thing) members added from now on.
    pub(crate) fn member_feed(&self) -> osis_base::memo::Feed<(Ctx, Tid)> {
        self.members.element_feed()
    }

    /// Every thing of the node closure (a read of it whole).
    pub(crate) fn things(&self) -> impl Iterator<Item = &Tid> {
        self.tree.held.keys_held()
    }

    /// Whether the sync set's walk reaches `t` (spec/sync-set.md §5 Sourced away): the node
    /// closure through no thing sourced at another node.
    pub(crate) fn synced(&self, t: &Tid) -> bool {
        self.synced.held.contains_key(t)
    }

    /// Every thing the sync set's walk reaches (a read of it whole).
    pub(crate) fn synced_things(&self) -> impl Iterator<Item = &Tid> {
        self.synced.held.keys_held()
    }

    /// A cursor over the things entering the sync set's walk from now on.
    pub(crate) fn synced_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.synced.held.feed()
    }

    /// The things the sync set's walk takes no path through.
    pub(crate) fn cut(&self) -> &JSet<Tid> {
        &self.cut
    }

    /// The things that left and are not released yet (a stamped read, whole).
    pub(crate) fn left(&self) -> &std::collections::BTreeMap<Tid, BTreeSet<Ctx>> {
        &self.left
    }

    /// `t` released: it is no longer noted as left.
    pub(crate) fn released(&mut self, t: &Tid) {
        self.left.remove(t);
    }

    /// The reference index: a row of `source`'s strong to `target` appeared or went
    /// (`refs::note`).
    pub(crate) fn note_row(&mut self, source: Tid, target: Tid) {
        if self.tree.held.contains_key(&source) {
            self.rows.insert(target, source);
        }
    }

    /// The held vertices.
    fn vertices(&self) -> Vec<Vx> {
        self.tree.vx.iter().copied().collect()
    }

    fn is_held(&self, v: &Vx) -> bool {
        self.tree.is_held(v)
    }

    fn link(&mut self, v: Vx, w: Vx) {
        osis_base::costs::count("closure: edges examined", 1);
        self.out.insert(v, w);
        self.inn.insert(w, v);
        self.moved.insert((v, w));
    }

    fn unlink(&mut self, v: Vx, w: Vx) {
        osis_base::costs::count("closure: edges examined", 1);
        self.out.remove(&v, &w);
        self.inn.remove(&w, &v);
        self.moved.insert((v, w));
        for y in self.by.get(&(v, w)).cloned().unwrap_or_default() {
            self.by.remove(&(v, w), &y);
            self.gave.remove(&(v, y));
        }
    }

    /// Sets what `v`'s edge to `y` gives to `now`: each vertex given linked while some edge of
    /// `v` gives it (`by`). The vertices newly linked and those no edge of `v` gives any more.
    fn set_given(&mut self, v: Vx, y: Tid, now: BTreeSet<Vx>) -> (Vec<Vx>, Vec<Vx>) {
        let old = self.gave.get(&(v, y)).cloned().unwrap_or_default();
        let (mut linked, mut gone) = (Vec::new(), Vec::new());
        for w in now.difference(&old) {
            if !self.by.get(&(v, *w)).is_some_and(|s| !s.is_empty()) {
                self.link(v, *w);
                linked.push(*w);
            }
            self.by.insert((v, *w), y);
        }
        for w in old.difference(&now) {
            self.by.remove(&(v, *w), &y);
            if !self.by.get(&(v, *w)).is_some_and(|s| !s.is_empty()) {
                self.out.remove(&v, w);
                self.inn.remove(w, &v);
                self.moved.insert((v, *w));
                osis_base::costs::count("closure: edges examined", 1);
                gone.push(*w);
            }
        }
        match now.is_empty() {
            true => drop(self.gave.remove(&(v, y))),
            false => drop(self.gave.insert((v, y), now)),
        }
        (linked, gone)
    }

    /// `x` held, hanging from `p` (none: the root), with no out-list yet.
    fn hold(&mut self, x: Vx, p: Option<Vx>) {
        self.tree.hold(x, p);
        self.members.insert(x.0, x.1);
        self.left.remove(&x.1);
    }

    /// `x` dropped from the tree (`Tree::detach`): its out-list goes.
    fn dropped(&mut self, x: Vx) {
        for y in self.out.get(&x).cloned().unwrap_or_default() {
            self.unlink(x, y);
        }
        self.members.remove(&x.0, &x.1);
    }

    /// The node closure's tree edge into `w` went (`Tree::detach`); the vertices dropped.
    fn detach(&mut self, rv: Vx, w: Vx) -> BTreeSet<Vx> {
        let g = Edges { out: &self.out, inn: &self.inn, cut: None, root: rv };
        let rest = self.tree.detach(g, w);
        for x in &rest {
            self.dropped(*x);
        }
        rest
    }

    /// Brings the sync set's tree up to the out-lists' edges that moved (`moved`), as the node
    /// closure's tree follows them: a removed tree edge detached, an edge added from a held
    /// vertex spread. Work in proportion to what moved and what it brings in or drops.
    fn settle_synced(&mut self, rv: Vx) -> Result<()> {
        let moved: Vec<(Vx, Vx)> = self.moved.iter().copied().collect();
        for e in &moved {
            self.moved.remove(e);
        }
        for (v, w) in &moved {
            if self.synced.parent.get(w) == Some(v) && !self.out.get(v).is_some_and(|o| o.contains(w)) {
                let g = Edges { out: &self.out, inn: &self.inn, cut: Some(&self.cut), root: rv };
                self.synced.detach(g, *w);
            }
        }
        if self.tree.is_held(&rv) && !self.synced.is_held(&rv) {
            self.synced.hold(rv, None);
        }
        let g = Edges { out: &self.out, inn: &self.inn, cut: Some(&self.cut), root: rv };
        let fresh: Vec<(Vx, Vx)> = moved.into_iter().filter(|(v, w)| self.synced.is_held(v) && !self.synced.is_held(w) && g.admits(w) && self.out.get(v).is_some_and(|o| o.contains(w))).map(|(v, w)| (w, v)).collect();
        spread(&mut GrowSynced(self, rv), fresh)
    }

    /// Sets the things the sync set's walk takes no path through (spec/sync-set.md §5 Sourced
    /// away), between transactions: each thing cut detaches its vertices from the sync set's tree
    /// (work in proportion to what is below it), each uncut one spreads from its held referrers.
    pub(crate) fn set_cut(&mut self, root: Option<Tid>, cut: BTreeSet<Tid>) -> Result<()> {
        let gone: Vec<Tid> = self.cut.iter().filter(|t| !cut.contains(*t)).copied().collect();
        let new: Vec<Tid> = cut.iter().filter(|t| !self.cut.contains(*t)).copied().collect();
        for t in &gone {
            self.cut.remove(t);
        }
        self.cut.extend(new.iter().copied());
        let Some(root) = root else { return Ok(()) };
        let rv = (Ctx::Local, root);
        for t in &new {
            for c in self.synced.held.get(t).cloned().unwrap_or_default() {
                let w = (c, *t);
                if w != rv && self.synced.is_held(&w) {
                    let g = Edges { out: &self.out, inn: &self.inn, cut: Some(&self.cut), root: rv };
                    self.synced.detach(g, w);
                }
            }
        }
        let mut fresh = Vec::new();
        for t in &gone {
            for c in self.tree.held.get(t).into_iter().flatten() {
                let w = (*c, *t);
                if let Some(r) = self.inn.get(&w).into_iter().flatten().find(|r| self.synced.is_held(r)) {
                    fresh.push((w, *r));
                }
            }
        }
        spread(&mut GrowSynced(self, rv), fresh)
    }
}

impl Core {
    /// Whether `t`'s keys open `x` (spec/sync-set.md §2): `x`'s secrets derive from `t`'s (`t` is
    /// `x`'s independent, the actor they derive from), or `t` holds read or above on that actor,
    /// by chains of grants with key access (`reads_now`), or the public does by its own grant on
    /// that actor (`public_reads`). `t`'s own role: a thing reads as itself.
    /// Invariant: a thing above an independent `a` on its record chain opens `a` only by its role
    /// there (a record edge is a grant), never by being its mint admin: once that edge is lowered
    /// or removed `a` leaves `t`'s sync unit, so whatever entry of `a`'s parts later arrives under
    /// `t`'s sync ID (sealed under `t`'s epochs from before `a` was keyed) waits outside the node
    /// closure (`retention::needed::applies_on`), as one that arrived before the loss went.
    pub(crate) fn keys_open(&self, t: &Tid, x: &Tid) -> bool {
        let Some(a) = self.secret_actor(x) else { return false };
        a == *t || self.reads_now(t, &a) || self.public_reads(&a)
    }

    /// Whether the public reads independent `a` by its own grant there (spec/sync-set.md §2 T's
    /// keys open), as `a`'s role commits held here show it: its bodies where the node holds `a`,
    /// else what a unit reaching it carries of it. Never through holders. Who writes it: `a`'s admins (a grant on `a`);
    /// what anyone may read is what `a`'s admins made public, nothing a unit's writers decide.
    pub(crate) fn public_reads(&self, a: &Tid) -> bool {
        self.roster_of(a).get(&Tid::PUBLIC).is_some_and(|e| e.role >= Role::Read)
    }

    /// Whether the public holds a role on `a` (sync or read) as this node knows it: by its own
    /// grant there, as `a`'s role commits held here show it (`public_reads`), or by a head of
    /// `a`'s sync ID listing the public entry (`public_listed`); its sync ID's steps list it
    /// (spec/sync-ids.md §3).
    pub(crate) fn public_syncs(&self, a: &Tid) -> bool {
        self.roster_of(a).get(&Tid::PUBLIC).is_some_and(|e| e.role >= Role::Sync) || self.public_listed(a).is_some()
    }

    /// The public's role on `a` by the heads of `a`'s sync IDs, as this node holds them, listing
    /// the public entry with a box whose sync secret the head's sync key comes from
    /// (`Indexes::public_listed`): the role the box gives, the best of them (spec/sync.md §3
    /// Holders by copies), each while it is the node's word of the public's role: while `a`'s
    /// `sync.0` as held here does not place its head. A node holding the write that placed a step
    /// holds the grants that step reflects, and has the public's role by them: a reader's head
    /// moves on unseen (its step under read epochs it may lack), its grants do not. Who writes
    /// it: `a`'s admins, the step (a path verified from genesis).
    pub(crate) fn public_listed(&self, a: &Tid) -> Option<Role> {
        let placed = |h: &osis_blob::StepId| self.ix.steps.get(a).is_some_and(|r| r.steps.contains_key(h));
        self.ix.public_listed.get(a).and_then(|m| m.values().filter(|l| !placed(&l.head)).map(|l| l.role).max())
    }

    /// Whether the head of `a`'s sync ID `s` lists the public entry here (`public_listed`).
    pub(crate) fn public_listed_on(&self, a: &Tid, s: &SyncId) -> bool {
        self.ix.public_listed.get(a).is_some_and(|m| m.contains_key(s))
    }

    /// Whether the node opens dependent thing `y` (spec/sync-set.md §2 local part): it holds a read
    /// secret of the independent thing `y`'s secrets derive from. A tid the node holds no record
    /// of opens nothing.
    pub(crate) fn opens_dependent(&self, y: &Tid) -> bool {
        let Some(a) = self.secret_actor(y) else { return false };
        self.epochs(&a).is_some_and(|e| e.role(Role::Read).holds_any())
    }

    /// Whether `y` is independent here (spec/sync-set.md §2): by the role commits held of it, or by
    /// a secret of its own a held valid box gave, a step of its `sync.0` bearing a sync secret
    /// so given (`Core::own_record`; not one derived from its mint admin's, nor a reading-only
    /// one). Established or not: a grantee holds the grant's box before it syncs `y`, where the
    /// rotation that made the epoch is.
    pub(crate) fn counts_independent(&self, y: &Tid) -> bool {
        self.is_independent(y) || self.public_listed(y).is_some() || self.own_record(y).is_some_and(|e| Role::ALL.iter().any(|r| e.role(*r).held().next().is_some())) || self.unread(y).holds_any()
    }

    /// How the walk enters independent thing `y` at a strong from a context that does not
    /// follow it (spec/sync-set.md §2): read where the node holds a read secret of it, kept
    /// unread where it holds a sync secret only, else not at all. Its own secrets only, given
    /// it by a box: never the reading-only ones read through its mint admin's (`Core::epochs`), so
    /// a reader of the mint admin enters it by no secret of its own, whatever arrived first.
    pub(crate) fn enter(&self, y: &Tid) -> Option<Ctx> {
        let e = self.own_record(y).and_then(|_| self.epochs(y));
        if e.as_ref().is_some_and(|e| e.role(Role::Read).holds_any()) {
            Some(Ctx::Read(*y))
        } else if e.as_ref().is_some_and(|e| e.role(Role::Sync).holds_any()) || self.unread(y).holds_any() || self.public_listed(y).is_some() && self.ix.secrets.get(y).is_some_and(|e| e.role(Role::Sync).holds_any()) {
            // kept unread: a sync secret alone, given by a box applied, a sync copy
            // (`sync_ids::unread`) or the public entry its head lists (`public_listed`)
            Some(Ctx::Unread(*y))
        } else {
            None
        }
    }
}

/// What `x` references, `x` aside, each with whether a strong does: its current values'
/// strongs and weaks (a fire's are history) and its held history's, held fires included
/// (`refs::kept`).
fn refs_from(tx: &mut Tx<'_>, x: &Tid) -> Result<std::collections::BTreeMap<Tid, bool>> {
    let mut out = std::collections::BTreeMap::new();
    for r in crate::engine::refs::from(tx, x)? {
        if crate::engine::refs::holds_target(r.kind, &r.ak) {
            out.insert(r.target, true);
        } else if crate::engine::refs::holds_stub(r.kind, &r.ak) {
            out.entry(r.target).or_insert(false);
        }
    }
    for (t, k, _) in crate::engine::refs::kept::from(tx, x)? {
        match k {
            RefKind::Strong => drop(out.insert(t, true)),
            RefKind::Weak => drop(out.entry(t).or_insert(false)),
        }
    }
    out.remove(x);
    Ok(out)
}

/// Whether `x` references `y` now (`refs_from`): `Some(true)` by a strong, `Some(false)` by a
/// weak alone.
fn ref_to(tx: &mut Tx<'_>, x: &Tid, y: &Tid) -> Result<Option<bool>> {
    if x == y {
        return Ok(None);
    }
    let kept = |tx: &mut Tx<'_>, k| crate::engine::refs::kept::holds_from(tx, x, y, k);
    if crate::engine::refs::strong_from(tx, x, y)? || kept(tx, RefKind::Strong)? {
        return Ok(Some(true));
    }
    Ok((crate::engine::refs::weak_from(tx, x, y)? || kept(tx, RefKind::Weak)?).then_some(false))
}

/// Whether `x` holds a strong to `y` now, in a current value or its held history.
fn strong_to(tx: &mut Tx<'_>, x: &Tid, y: &Tid) -> Result<bool> {
    Ok(ref_to(tx, x, y)? == Some(true))
}

/// The owners of the unit vertex `v` is in (spec/sync-set.md §2 Stubs): a read sync unit's
/// thing; the local part's, the node's own things (its node thing, each held link key).
fn owners(core: &Core, c: Ctx) -> Vec<Tid> {
    match c {
        Ctx::Read(t) => vec![t],
        Ctx::Local => std::iter::once(core.tid()).chain(core.link_keys.keys().copied()).collect(),
        Ctx::Unread(_) | Ctx::Stub(_) => Vec::new(),
    }
}

/// What the walk takes from vertex `v` by a reference of its thing to `y`, a strong where
/// `strong` (module doc; spec/sync-set.md §2).
/// - A strong: within the unit what its keys open (a dependent in the local part the node
///   opens), with a Dependent entry; an independent thing the unit carries (`edge_carries`) or
///   an own thing, entered by the node's secrets of it (`Core::enter`).
/// - The stubs the unit carries by the reference (`stubs_by`).
fn given_by(core: &Core, v: Vx, y: Tid, strong: bool) -> BTreeSet<Vx> {
    let (c, x) = v;
    let mut out = BTreeSet::new();
    if matches!(c, Ctx::Unread(_) | Ctx::Stub(_)) || x == y {
        return out;
    }
    let independent = core.counts_independent(&y);
    if strong {
        let follows = match c {
            Ctx::Local => !independent && core.opens_dependent(&y),
            Ctx::Read(t) => core.keys_open(&t, &y),
            Ctx::Unread(_) | Ctx::Stub(_) => false,
        };
        if follows {
            out.insert((c, y));
            // Dependent entry (spec/sync-set.md §2): a dependent of another independent thing that
            // `t`'s keys open enters that thing's unit, read, whose sync ID carries it with no bridge
            if let Ctx::Read(t) = c
                && !independent
                && let Some(a) = core.secret_actor(&y)
                && a != t
                && a != y
                && core.enter(&a) == Some(Ctx::Read(a))
            {
                out.insert((Ctx::Read(a), a));
            }
        }
        if independent && Ctx::Read(y) != c && let Some(e) = core.enter(&y) && (core.is_own(&y) || edge_carries(core, v, &y)) {
            out.insert((e, y));
        }
    }
    stubs_by(core, v, y, independent, strong, &mut out);
    out
}

/// The stubs a reference of thing `x` of unit `c` to `y` brings (spec/sync-set.md §2 Stubs), as
/// vertices the node holds whatever secrets it holds of their things (Holding a stub), added to
/// `out`. Of `y`'s independent X (a reference to a dependent counts as one to the thing its
/// secrets derive from), unless an owner is X: a weak's, or a strong's to a dependent of an X
/// the unit's keys do not open, where the unit's keys open X or it holds sync or above there (any
/// other strong brings X whole or enters it, never a stub), or where the weak is the fire of a
/// grant signal on `x` the node follows (First entry: X named by its sync ID, record or none); and,
/// where the unit's keys open X, the stub of each holder on an owner's chains of read grants to X.
fn stubs_by(core: &Core, (c, x): Vx, y: Tid, independent: bool, strong: bool, out: &mut BTreeSet<Vx>) {
    // a held signal followed names its thing as independent (by its sync ID), record or none
    let fired = !strong && core.followed_links.fired_on(&y, &x);
    let Some(a) = (if independent || fired { Some(y) } else { core.secret_actor(&y) }) else { return };
    // the unit's own thing, or the node's: no stub (read before the link keys, which the local
    // part's other owners are)
    if matches!(c, Ctx::Read(t) if t == a) || matches!(c, Ctx::Local if a == core.tid()) {
        return;
    }
    let own = owners(core, c);
    if own.contains(&a) || own.is_empty() {
        return;
    }
    let cl = &core.ix.closure;
    let stub = |h: Tid| (!cl.carries_whole(c, &h)).then_some((Ctx::Stub(h), h));
    let opens: Vec<Tid> = own.iter().copied().filter(|o| core.keys_open(o, &a)).collect();
    // a strong brings X whole or enters it where it names X or the unit's keys open X; one to a
    // dependent of an X they do not open names nothing the unit's readers know of X (spec/sync-ids.md
    // §2 What a sync holder learns), so it brings X's stub as a weak does
    let enters = strong && (independent || !opens.is_empty());
    if !enters && (!opens.is_empty() || own.iter().any(|o| core.keyed_role_now(o, &a) >= Some(Role::Sync)) || fired) {
        out.extend(stub(a));
    }
    for o in &opens {
        out.extend(chain_holders(core, o, &a).into_iter().filter_map(stub));
    }
}

/// The independent holders on `o`'s chains of read grants with key access to independent `a`
/// (spec/sync-set.md §2 Stubs), neither `o` nor `a`: each reads `a` and `o` reads it, by `a`'s
/// and its grants as the node holds them (`Core::keyed_role_now`). The public is no holder.
pub(crate) fn chain_holders(core: &Core, o: &Tid, a: &Tid) -> BTreeSet<Tid> {
    let roles = core.time.at(|now| {
        let (r, until) = core.timelines().roles_now(a, crate::flows::ts_at(now));
        (r, until.map(|u| u.0))
    });
    roles.iter().filter(|(h, r)| **r >= Role::Read && *h != o && *h != a && **h != Tid::PUBLIC && core.is_independent(h) && core.reads_now(o, h) && core.reads_now(h, a)).map(|(h, _)| *h).collect()
}

/// Whether a held strong reaches `y` where First entry carries it (spec/sync-set.md §2 Own
/// things), on a path avoiding `y` (`founded`), or the node holds `y` as a stub: its grants
/// count there, and nowhere a strong alone reaches (a thing nothing the node syncs carries is
/// held as certificates at most, whose grants give no role).
pub(crate) fn reached_carried(core: &Core, y: &Tid) -> bool {
    let cl = &core.ix.closure;
    let avoid = [*y];
    cl.contexts(y).iter().any(|c| matches!(c, Ctx::Stub(_))) || cl.targeted(y) && (core.is_own(y) || cl.targeting(y).any(|v| edge_carries(core, *v, y) && founded(core, *v, &avoid)))
}

/// Whether held vertex `v`'s unit carries `y`, a target of its thing's strongs (spec/sync-set.md
/// §2 Stubs): `v` is in the read sync unit of a thing `u` other than `y`, or in the local part
/// with `u` an own thing, whose keys open `y` (whole) or whose effective role on `y` is sync or
/// above, the public's sync (by its grant or a head's listing, `public_syncs`) counting as every
/// party's (its stub), as the role entries the node holds show it. Local to the edge, so the tree
/// founds it: an entry by `u`'s unit goes when `u`'s does, whatever `u` reaches back.
/// Invariant: `y`'s own unit never carries it (`u != y`).
fn edge_carries(core: &Core, v: Vx, y: &Tid) -> bool {
    owners(core, v.0).iter().any(|u| u != y && (core.keys_open(u, y) || core.keyed_role_now(u, y) >= Some(Role::Sync) || core.public_syncs(y) || core.syncs_by_copies(u, y)))
}

/// Whether the node closure holds `t` within the local part or another thing's sync unit
/// (`founded`; spec/sync-set.md §2 Own things).
pub(crate) fn holds_within(core: &Core, t: &Tid) -> bool {
    let cs = core.ix.closure.contexts(t);
    cs.into_iter().any(|c| !matches!(c, Ctx::Read(u) | Ctx::Unread(u) if u == *t) && founded(core, (c, *t), &[]))
}

/// Whether held vertex `v` stays held with `y` out of the node closure: its tree path avoids
/// `y`, else a search from the root over the out-lists avoiding `y` reaches it. Its tree reads
/// make what asked judged again as the path moves.
fn founded(core: &Core, start: Vx, y: &[Tid]) -> bool {
    let cl = &core.ix.closure;
    if y.contains(&start.1) || !cl.is_held(&start) {
        return false;
    }
    let mut v = start;
    let mut clear = true;
    while let Some(p) = cl.parent_of(&v) {
        if y.contains(&p.1) {
            clear = false;
            break;
        }
        v = *p;
    }
    if clear {
        return true;
    }
    let Some(root) = core.node_root else { return false };
    let root = (Ctx::Local, root);
    let mut seen = BTreeSet::from([root]);
    let mut todo = vec![root];
    while let Some(u) = todo.pop() {
        for w in cl.out_of(&u) {
            if !y.contains(&w.1) && seen.insert(*w) {
                todo.push(*w);
            }
        }
    }
    seen.contains(&start)
}

/// Brings the node closure up to date with what moved since the last settle (module doc): at
/// each transaction's end, and after an open.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<()> {
    // the strongs held history holds, as its bodies moved (`refs::kept`)
    crate::engine::refs::kept::settle(tx)?;
    let Some(root) = tx.core.node_root else { return Ok(()) };
    let rv = (Ctx::Local, root);
    loop {
        let mut f = std::mem::take(&mut tx.core.closure_follow);
        let r = settle_with(tx, &mut f, rv);
        tx.core.closure_follow = f;
        r?;
        // the grants of what the node newly syncs count (`rotation::grants_count`: a thing a
        // strong reaches where it is carried), so a box its roles had kept out opens, and
        // the walk enters by the secret it gives: the two settle together
        if !crate::flows::retake(tx)? {
            return Ok(());
        }
    }
}

fn settle_with(tx: &mut Tx<'_>, f: &mut Follow, rv: Vx) -> Result<()> {
    f.acted = true;
    f.gone.clear();
    if std::mem::take(&mut f.reset) {
        let was = std::mem::replace(&mut f.fx, Effects::new("closure: edges"));
        f.before = f.known.then_some(was);
        let all = tx.core.ix.closure.vertices();
        osis_base::costs::count("closure: refollowed", all.len() as u64);
        for v in all {
            want_edges(tx, f, v)?;
        }
    }
    if !tx.core.ix.closure.is_held(&rv) {
        tx.core.ix.closure.hold(rv, None);
        want_edges(tx, f, rv)?;
    }
    loop {
        // the strongs that appeared, followed from each vertex of their source
        let rows: Vec<(Tid, Tid)> = tx.core.ix.closure.rows.iter().flat_map(|(y, xs)| xs.iter().map(|x| (*x, *y))).collect();
        for (x, y) in &rows {
            tx.core.ix.closure.rows.remove(y, x);
            for c in tx.core.ix.closure.contexts(x) {
                let v = (c, *x);
                if tx.core.ix.closure.is_held(&v) {
                    let now = judge(tx, f, v, *y)?;
                    apply(tx, f, rv, v, *y, now)?;
                }
            }
        }
        let due = f.fx.due();
        if due.is_empty() && tx.core.ix.closure.rows.is_empty() {
            // each thing out of the node closure now, noted with every context it was dropped
            // from in this transaction: the sync units that carried it when it left
            let cl = &mut tx.core.ix.closure;
            for (t, cs) in std::mem::take(&mut f.gone) {
                if !cl.holds_any(&t) {
                    let mut was = cl.left.get(&t).cloned().unwrap_or_default();
                    was.extend(cs);
                    cl.left.insert(t, was);
                }
            }
            f.before = None;
            f.known = true;
            return cl.settle_synced(rv);
        }
        for (v, y) in due {
            if !tx.core.ix.closure.is_held(&v) {
                f.fx.unwant(&(v, y));
                continue;
            }
            let now = judge(tx, f, v, y)?;
            apply(tx, f, rv, v, y, now)?;
        }
    }
}

/// Follows every edge of held vertex `v`: O(its thing's strongs).
fn want_edges(tx: &mut Tx<'_>, f: &mut Follow, v: Vx) -> Result<()> {
    if matches!(v.0, Ctx::Unread(_) | Ctx::Stub(_)) {
        return Ok(());
    }
    for y in refs_from(tx, &v.1)?.into_keys() {
        f.fx.want((v, y));
    }
    Ok(())
}

/// What `v`'s edge to `y` gives: nothing without a reference (the edge followed no more), else
/// what `given_by` says, recorded as what the edge follows.
fn judge(tx: &mut Tx<'_>, f: &mut Follow, v: Vx, y: Tid) -> Result<BTreeSet<Vx>> {
    let r = if matches!(v.0, Ctx::Unread(_) | Ctx::Stub(_)) { None } else { ref_to(tx, &v.1, &y)? };
    let Some(strong) = r else {
        f.fx.unwant(&(v, y));
        set_targeted(tx, y, v, false);
        tx.core.ix.closure.set_unknown(y, v, false);
        return Ok(BTreeSet::new());
    };
    set_targeted(tx, y, v, strong);
    // a strong to a thing whose record is not held awaits it: a record blob's copy of it, kept
    // loose, is learned (spec/commits.md §4 Records)
    let unknown = !tx.core.exists(&y);
    tx.core.ix.closure.set_unknown(y, v, unknown);
    if unknown {
        tx.core.waits.loose.want(&y);
    }
    let new = f.known && !f.before.as_ref().unwrap_or(&f.fx).wants(&(v, y));
    f.fx.want((v, y));
    if new {
        let held = f.gone.contains_key(&y);
        refetch(tx, v, y, held)?;
    }
    let core = &*tx.core;
    let mut got = BTreeSet::new();
    f.fx.settle(&(v, y), || {
        got = given_by(core, v, y, strong);
        got.clone()
    });
    Ok(got)
}

/// A new edge of read unit `v` to `y`, which the node held as
/// certificates alone or not at all when the transaction began (`retention::needed::Holding`:
/// not in the node closure, nor leaving it, nor dropped from it in this transaction, `was_held`),
/// unless the pass in flight brought a minting of `y` while the node held none and nothing of
/// `y` was forgotten since (`Core::brought`): the unit's sync IDs are pulled anew from
/// every source, so what was forgotten of `y` (its content outside the node closure, a body
/// judged outside the required set before the strong arrived) is fetched again
/// (spec/sync-judgement.md §3 Dropped bodies). Once per new edge, durable before the
/// transaction adding it commits.
fn refetch(tx: &mut Tx<'_>, v: Vx, y: Tid, was_held: bool) -> Result<()> {
    let Ctx::Read(t) = v.0 else { return Ok(()) };
    let cl = &tx.core.ix.closure;
    if was_held || cl.holds(&y) || cl.left().contains_key(&y) || tx.core.brought.contains(&y) {
        return Ok(());
    }
    // a held commit minting `y` whose part on it was never taken: nothing keeps its blobs out
    let minting: Vec<osis_base::BlobId> = tx.core.mintings(&y).flat_map(|(c, _)| tx.core.ix.commit_blobs.get(&c).into_iter().flatten().copied().collect::<Vec<_>>()).collect();
    for b in minting {
        tx.blobs.unreceived(&b);
    }
    crate::flows::sync_ids::pull_anew(tx, &t)
}

/// Notes whether `v`'s strong to `y` counts for `Closure::targeted`; `y` losing its last is
/// judged for what it still needs (`retention::needed`).
fn set_targeted(tx: &mut Tx<'_>, y: Tid, v: Vx, on: bool) {
    if tx.core.ix.closure.set_targeted(y, v, on) {
        tx.core.note_lost(y);
    }
}

/// Sets what held vertex `v`'s edge to `y` gives to `now`, moving the tree.
fn apply(tx: &mut Tx<'_>, f: &mut Follow, rv: Vx, v: Vx, y: Tid, now: BTreeSet<Vx>) -> Result<()> {
    let cl = &mut tx.core.ix.closure;
    let (linked, gone) = cl.set_given(v, y, now);
    let fresh: Vec<(Vx, Vx)> = linked.into_iter().filter(|w| !cl.is_held(w)).map(|w| (w, v)).collect();
    for w in gone {
        if tx.core.ix.closure.tree.parent.get(&w) == Some(&v) {
            for x in tx.core.ix.closure.detach(rv, w) {
                f.gone.entry(x.1).or_default().insert(x.0);
                // its edges are followed no more
                if !matches!(x.0, Ctx::Unread(_) | Ctx::Stub(_)) {
                    for y in refs_from(tx, &x.1)?.into_keys() {
                        f.fx.unwant(&(x, y));
                        set_targeted(tx, y, x, false);
                    }
                }
            }
        }
    }
    spread(&mut GrowClosure(tx, f), fresh)
}

/// The node closure's tree grown by judging each held vertex's edges.
struct GrowClosure<'t, 'a>(&'t mut Tx<'a>, &'t mut Follow);

impl Grow for GrowClosure<'_, '_> {
    fn grown(&self) -> &Tree {
        &self.0.core.ix.closure.tree
    }
    fn hold(&mut self, x: Vx, p: Vx) {
        self.0.core.ix.closure.hold(x, Some(p));
    }
    fn out(&mut self, x: Vx) -> Result<Vec<Vx>> {
        let mut out = Vec::new();
        if matches!(x.0, Ctx::Unread(_) | Ctx::Stub(_)) {
            return Ok(out);
        }
        for y in refs_from(self.0, &x.1)?.into_keys() {
            let now = judge(self.0, self.1, x, y)?;
            out.extend(self.0.core.ix.closure.set_given(x, y, now).0);
        }
        Ok(out)
    }
}

/// Adds the target of every strong at any depth of `v` to `out` (the reference index's reading,
/// spec/data-model.md §8 What counts).
pub fn strongs_in(v: &osis_base::Value, out: &mut BTreeSet<Tid>) {
    crate::engine::refs::references(v, &mut |k, t, _| {
        if k == osis_base::RefKind::Strong {
            out.insert(t);
        }
    });
}

/// Debug: the node closure as followed equals one walked afresh from the node root by
/// `given_by` over every strong, and so does the sync set's tree, walked so with every edge into
/// a thing of the cut leading nowhere; each tree hangs every held vertex from a held referrer
/// (`Engine::check_index`, `Engine::check_closure`).
pub(crate) fn check_whole(tx: &mut Tx<'_>) -> Result<()> {
    let Some(root) = tx.core.node_root else { return Ok(()) };
    let rv = (Ctx::Local, root);
    let cut: BTreeSet<Tid> = tx.core.ix.closure.cut.iter().copied().collect();
    for (name, cut) in [("the node closure", None), ("the sync set's walk", Some(&cut))] {
        let mut seen = BTreeSet::from([rv]);
        let mut stack = vec![rv];
        while let Some(v) = stack.pop() {
            if matches!(v.0, Ctx::Unread(_) | Ctx::Stub(_)) {
                continue;
            }
            for (y, strong) in refs_from(tx, &v.1)? {
                for w in given_by(tx.core, v, y, strong) {
                    if cut.is_none_or(|c| !c.contains(&w.1)) && seen.insert(w) {
                        stack.push(w);
                    }
                }
            }
        }
        let cl = &tx.core.ix.closure;
        let tree = if cut.is_some() { &cl.synced } else { &cl.tree };
        let held: BTreeSet<Vx> = tree.vx.iter().copied().collect();
        assert_eq!(held, seen, "{name} differs from one walked afresh");
        for v in &held {
            if *v != rv {
                let p = tree.parent.get(v);
                assert!(p.is_some_and(|p| tree.is_held(p) && cl.out.get(p).is_some_and(|o| o.contains(v))), "{name}: {v:?} hangs from {p:?}, which does not reach it");
            }
        }
    }
    Ok(())
}

/// A thing a transaction's own commits made or wrote, as it must be held at its end.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Written {
    /// In the node closure.
    Held(Tid),
    /// Made with its role entries alone: in the node closure, or a holder with a role now on a
    /// thing in it, held as any holder of what the node syncs (its record and public key record
    /// go under that thing's sync ID, spec/sync-inbox.md §1).
    Holder(Tid),
}

/// The things this transaction's own commits made or wrote, each held at its end as `Written`
/// says, or the transaction is refused (spec/sync-set.md §2 Writing, Making a thing: a node writes
/// only what it holds; it fires at what it does not). A node with no node root yet (its first
/// start) checks nothing, nor a hostile writer (`skip_writer_rules`): a writer's rule.
pub(crate) fn check_written(tx: &mut Tx<'_>) -> Result<()> {
    if tx.core.node_root.is_none() || tx.core.skip_writer_rules {
        tx.core.wrote_on.clear();
        return Ok(());
    }
    let written = std::mem::take(&mut tx.core.wrote_on);
    let core = &*tx.core;
    let holder = |t: &Tid| core.ix.held.named_on(t).any(|y| core.ix.closure.holds(y) && core.keyed_role_now(t, y).is_some());
    for w in written {
        let (t, held) = match w {
            Written::Held(t) => (t, core.ix.closure.holds(&t)),
            Written::Holder(t) => (t, core.ix.closure.holds(&t) || holder(&t)),
        };
        if core.created(&t).is_some() && !held {
            return Err(crate::error::Error::NotHeld(t));
        }
    }
    Ok(())
}

impl Engine {
    /// The sync unit of `t` (spec/sync-set.md §2): `t` and what it reaches by strongs and itself
    /// may read, stopping at the first thing it may not read. Of a thing this node reads in no
    /// sync unit: `t` alone.
    pub fn sync_unit(&self, t: &Tid) -> Arc<BTreeSet<Tid>> {
        self.core.unit_of.get(t, || Arc::new(self.core.ix.closure.members(&Ctx::Read(*t)).cloned().unwrap_or_else(|| BTreeSet::from([*t]))))
    }

    /// Whether `t`'s sync unit is known whole here: no thing in it holds a part that may hold a
    /// strong as a header only (spec/sync-judgement.md §2).
    pub fn unit_settled(&mut self, t: &Tid) -> crate::error::Result<bool> {
        let unit = self.sync_unit(t);
        Ok(!self.core.ix.missing.keys().any(|(_, x)| unit.contains(x)))
    }

    /// The things whose sync unit holds `t`, read here (spec/sync-set.md §2).
    pub fn units_holding(&self, t: &Tid) -> BTreeSet<Tid> {
        self.core.ix.closure.contexts(t).into_iter().filter_map(|c| if let Ctx::Read(u) = c { Some(u) } else { None }).collect()
    }

    /// The targets of `x`'s strongs that are neither carried where the strong is nor held
    /// otherwise (spec/sync-set.md §2 Not carried): none when the node closure
    /// does not hold `x`. O(`x`'s strongs).
    pub fn not_carried_from(&mut self, x: &Tid) -> Result<Vec<Tid>> {
        if !self.core.ix.closure.holds(x) {
            return Ok(Vec::new());
        }
        let x = *x;
        let ys: Vec<Tid> = self.run(|tx| refs_from(tx, &x))?.into_iter().filter(|r| r.1).map(|r| r.0).collect();
        Ok(ys.into_iter().filter(|y| !self.core.ix.closure.holds(y)).collect())
    }

    /// Those of `ys` that `x` strongly references and `not_carried_from` would name: O(`ys`).
    pub fn not_carried_among(&mut self, x: &Tid, ys: &BTreeSet<Tid>) -> Result<Vec<Tid>> {
        if !self.core.ix.closure.holds(x) {
            return Ok(Vec::new());
        }
        let x = *x;
        let ys: Vec<Tid> = ys.iter().filter(|y| !self.core.ix.closure.holds(y)).copied().collect();
        self.run(|tx| {
            let mut out = Vec::new();
            for y in ys {
                if strong_to(tx, &x, &y)? {
                    out.push(y);
                }
            }
            Ok(out)
        })
    }

    /// Every strong of the node closure `not_carried_from` names, (thing, target): O(the node
    /// closure's strongs).
    pub fn not_carried(&mut self) -> Result<Vec<(Tid, Tid)>> {
        let things: Vec<Tid> = self.core.ix.closure.things().copied().collect();
        let mut out = Vec::new();
        for t in things {
            out.extend(self.not_carried_from(&t)?.into_iter().map(|y| (t, y)));
        }
        Ok(out)
    }

    /// Tests: panics unless the node closure as followed equals one walked afresh.
    #[doc(hidden)]
    pub fn check_closure(&mut self) {
        let r = self.checked_closure();
        assert!(r.is_ok(), "node closure walked afresh: {:?}", r.err());
    }

    /// `check_closure`, a failing read returned.
    pub(crate) fn checked_closure(&mut self) -> crate::Result<()> {
        osis_base::costs::paused(|| osis_base::memo::unrecorded(|| self.read(check_whole)))
    }

    /// Whether the node closure holds `t` (spec/sync-set.md §2).
    pub fn closure_holds(&self, t: &Tid) -> bool {
        self.core.ix.closure.holds(t)
    }

    /// Whether `t` is kept unread: in the node closure by a sync secret alone (spec/sync-set.md
    /// §2).
    pub(crate) fn kept_unread(&self, t: &Tid) -> bool {
        let c = self.core.ix.closure.contexts(t);
        c.contains(&Ctx::Unread(*t)) && !c.contains(&Ctx::Read(*t))
    }
}
