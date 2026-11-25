//! Sync units and the node closure (spec/sync-set.md §2): what a sync ID carries, walked by
//! strongs within what the root may read; the node closure, walked sync unit by sync unit from
//! the node root.
//!
//! One structure holds both (`Closure`): a spanning tree over vertices (context, thing) rooted at
//! (local, node root). A context is the node root's local part, a sync unit read (`Ctx::Read`),
//! or one kept unread (`Ctx::Unread`). A
//! vertex's out-list (`given_by`) is what the walk takes from
//! it: in the local part its strongs to dependent things; in T's read sync unit its strongs to
//! things T's keys open; from either, a strong to an independent thing the context does not
//! follow enters that thing's sync unit by the secrets the node holds of it, and so does a strong
//! to an independent thing inside a read sync unit (its own sync unit is part of the one it is
//! in, so entering it holds nothing more and records which sync units hold what). A sync unit kept
//! unread is its root alone: the node cannot read what it holds. So T's sync unit is the things of
//! context `Read(T)`, and the node closure is every thing of any context.
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
use osis_base::{Role, Tid};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

/// Where the walk is: the node root's local part, or a sync unit entered read or kept unread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ctx {
    Local,
    Read(Tid),
    Unread(Tid),
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
    /// unit) whose strong reaches it, as last judged: the things the walk reaches at a strong
    /// (spec/sync-set.md §2 Held for keys).
    targeted: JSetMap<Tid, Vx>,
    /// Per read context, each (target, source) of a strong of a thing of it whose target the
    /// context does not follow (its keys do not open it), as last judged: what its stubs are
    /// found among (`Engine::stubs_of`), never its whole unit.
    beyond: JSetMap<Ctx, (Tid, Tid)>,
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
    /// The holders held for keys (`held_for_keys`), as last settled.
    keys: JSet<Tid>,
    /// Each edge (referrer, entry vertex) whose entry rests on a read thing's piece, as last
    /// judged (`founded` walks these alone; every other entry is carried on its edge or by what
    /// needs no founding).
    pieced: JSet<(Vx, Vx)>,
    /// Each such edge whose entry gives no role either: `pieced`, or resting on a piece kept only
    /// while a loss is carried out (`founded` for the role).
    loose: JSet<(Vx, Vx)>,
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
            beyond: JSetMap::default(),
            unknown: JSetMap::default(),
            members: JSetMap::by_element(),
            left: JMap::default(),
            cut: JSet::default(),
            keys: JSet::default(),
            pieced: JSet::default(),
            loose: JSet::default(),
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
    /// Per thing the node holds secrets of: whether it is held for keys (`held_for_keys`).
    keys: Effects<Tid, bool>,
}

impl Default for Follow {
    fn default() -> Follow {
        Follow { fx: Effects::new("closure: edges"), reset: true, acted: false, gone: Default::default(), before: None, known: false, keys: Effects::new("closure: held for keys") }
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
    type Mark = ([usize; 4], [usize; 4], [usize; 13]);
    fn commit(&mut self) {
        self.targeted.commit();
        self.beyond.commit();
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
        self.keys.commit();
        self.pieced.commit();
        self.loose.commit();
    }
    fn mark(&mut self) -> Self::Mark {
        (self.tree.mark(), self.synced.mark(), [self.out.mark(), self.inn.mark(), self.moved.mark(), self.rows.mark(), self.members.mark(), self.left.mark(), self.cut.mark(), self.unknown.mark(), self.targeted.mark(), self.keys.mark(), self.pieced.mark(), self.loose.mark(), self.beyond.mark()])
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
        self.keys.rollback_to(m[9]);
        self.pieced.rollback_to(m[10]);
        self.loose.rollback_to(m[11]);
        self.beyond.rollback_to(m[12]);
    }
    fn name(&mut self, _name: &'static str) {
        self.tree.name("index: closure held");
        self.synced.name("index: sync set held");
        self.members.name("index: closure members");
        self.left.name("index: closure left");
        self.cut.name("index: closure cut");
        self.targeted.name("index: closure targeted");
        self.unknown.name("index: closure unknown");
        self.keys.name("index: held for keys");
        self.pieced.name("index: closure pieced");
        self.loose.name("index: closure loose");
        self.beyond.name("index: closure beyond");
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

impl Closure {
    /// Whether the node closure holds `t`, in any context.
    pub(crate) fn holds(&self, t: &Tid) -> bool {
        self.tree.held.get(t).is_some_and(|cs| !cs.is_empty())
    }

    /// Whether the node closure reads `t`: holds it, or holds it leaving, in the local part or a
    /// read sync unit (spec/sync-set.md §2: a sync unit kept unread is its root alone, the node
    /// cannot read what it holds).
    pub(crate) fn reads(&self, t: &Tid) -> bool {
        let reading = |cs: &BTreeSet<Ctx>| cs.iter().any(|c| matches!(c, Ctx::Local | Ctx::Read(_)));
        self.tree.held.get(t).is_some_and(reading) || self.left.get(t).is_some_and(reading)
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
        if !on {
            self.set_beyond(t, v, false);
        }
        was && !set(self)
    }

    /// Notes whether `v`'s strong to `t` reaches beyond its read context (`beyond`).
    fn set_beyond(&mut self, t: Tid, v: Vx, on: bool) {
        if !matches!(v.0, Ctx::Read(_)) || self.beyond.contains(&v.0, &(t, v.1)) == on {
            return;
        }
        match on {
            true => drop(self.beyond.insert(v.0, (t, v.1))),
            false => drop(self.beyond.remove(&v.0, &(t, v.1))),
        }
    }

    /// The targets of strongs of `g`'s sync unit that its keys do not follow, as last judged.
    pub(crate) fn beyond(&self, g: &Tid) -> BTreeSet<Tid> {
        self.beyond.get(&Ctx::Read(*g)).into_iter().flatten().map(|(t, _)| *t).collect()
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

    /// Whether `t` is held for keys (`held_for_keys`, as last settled).
    pub(crate) fn for_keys(&self, t: &Tid) -> bool {
        self.keys.contains(t)
    }

    /// The holders held for keys (a read of them whole).
    pub(crate) fn keys(&self) -> impl Iterator<Item = &Tid> {
        self.keys.iter()
    }

    /// A cursor over the things coming to be held for keys from now on.
    pub(crate) fn keys_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.keys.feed()
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

    /// The vertices of `v`'s out-list that its edge to `y` gives.
    fn given(&self, v: &Vx, y: &Tid) -> BTreeSet<Vx> {
        let Some(out) = self.out.get(v) else { return BTreeSet::new() };
        [(v.0, *y), (Ctx::Read(*y), *y), (Ctx::Unread(*y), *y)].into_iter().filter(|w| out.contains(w)).collect()
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
    /// else the public pieces a unit reaching it carries (`Engine::public_pieced`). Never through
    /// holders: a reader of a unit could not found such a chain from what the unit carries
    /// (notes/public-and-cards-brief.md, Rejected). Who writes it: `a`'s admins (a grant on `a`);
    /// what anyone may read is what `a`'s admins made public, nothing a unit's writers decide.
    pub(crate) fn public_reads(&self, a: &Tid) -> bool {
        self.roster_of(a).get(&Tid::PUBLIC).is_some_and(|e| e.role >= Role::Read)
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
    /// rotation that made the epoch is (spec/permissions.md §4 Key part).
    pub(crate) fn counts_independent(&self, y: &Tid) -> bool {
        self.is_independent(y) || self.own_record(y).is_some_and(|e| Role::ALL.iter().any(|r| e.role(*r).held().next().is_some()))
    }

    /// How the walk enters independent thing `y` at a strong from a context that does not
    /// follow it (spec/sync-set.md §2): read where the node holds a read secret of it, kept
    /// unread where it holds a sync secret only, else not at all. Its own secrets only, given
    /// it by a box: never the reading-only ones read through its mint admin's (`Core::epochs`), so
    /// a reader of the mint admin enters it by no secret of its own, whatever arrived first.
    pub(crate) fn enter(&self, y: &Tid) -> Option<Ctx> {
        self.own_record(y)?;
        let e = self.epochs(y)?;
        if e.role(Role::Read).holds_any() {
            Some(Ctx::Read(*y))
        } else if e.role(Role::Sync).holds_any() {
            Some(Ctx::Unread(*y))
        } else {
            None
        }
    }
}

/// The targets of `x`'s strongs, `x` aside: its current values' and its held history's, held
/// fires included (`refs::kept`).
fn strongs_from(tx: &mut Tx<'_>, x: &Tid) -> Result<BTreeSet<Tid>> {
    let mut out: BTreeSet<Tid> = crate::engine::refs::from(tx, x)?.into_iter().filter(|r| crate::engine::refs::holds_target(r.kind, &r.ak)).map(|r| r.target).collect();
    out.extend(crate::engine::refs::kept::from(tx, x)?.into_iter().map(|r| r.0));
    out.remove(x);
    Ok(out)
}

/// Whether `x` holds a strong to `y` now, in a current value or its held history.
fn strong_to(tx: &mut Tx<'_>, x: &Tid, y: &Tid) -> Result<bool> {
    Ok(x != y && (crate::engine::refs::strong_from(tx, x, y)? || crate::engine::refs::kept::strong_from(tx, x, y)?))
}

/// What the walk takes from vertex `v` by a strong of its thing to `y` (module doc).
fn given_by(core: &Core, v: Vx, y: Tid) -> BTreeSet<Vx> {
    given(core, v, y).0
}

/// How an entry is carried (`given`): on its edge or by what needs no founding (`Plain`), by a
/// piece kept only while a loss is carried out (`Pending`: no role), or by a read thing's piece
/// (`Pieced`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Carry {
    Plain,
    Pending,
    Pieced,
}

/// `given_by`, with how its entry, if any, is carried.
///
/// First entry (spec/sync-set.md §2): an entry is carried by the unit its strong is in
/// (`edge_carries`), an edge piece in the key part of an own thing, a link the node follows or a
/// thing the node closure reads, or an offer of `y` the node holds. A piece carries while its edge is current (a holder on `y` now, its record edge
/// included), or while the node still holds a read secret of `y`: a loss not carried out yet
/// (spec/permissions.md §3 Lost access), so a removed holder syncs `y` until its loss is, and
/// once it is the removal's piece carries nothing. A read thing's piece carries only where that
/// thing is read without `y` (`founded_without`): entry is founded, so nothing is kept for
/// supporting itself. Who writes each input: `y`'s grants, judged by the walk (an edge write by
/// anyone without the right to it sets no edge); `y`'s record (its mint admin's edge); the
/// offers, held only valid on an inbox the node reads; the secrets, taken only from boxes the
/// node's role lets it take and dropped by lost access. A holder held for keys alone carries
/// nothing: an entry hanging on an unrelated reference would not be founded
/// (notes/accounts-switch-brief.md, Models).
fn given(core: &Core, v: Vx, y: Tid) -> (BTreeSet<Vx>, Carry) {
    let (c, x) = v;
    let mut out = BTreeSet::new();
    if matches!(c, Ctx::Unread(_)) || x == y {
        return (out, Carry::Plain);
    }
    let independent = core.counts_independent(&y);
    let follows = match c {
        Ctx::Local => !independent && core.opens_dependent(&y),
        Ctx::Read(t) => core.keys_open(&t, &y),
        Ctx::Unread(_) => false,
    };
    if follows {
        out.insert((c, y));
    }
    let mut how = Carry::Plain;
    if independent && Ctx::Read(y) != c && let Some(e) = core.enter(&y) {
        let carry = if core.is_own(&y) || edge_carries(core, v, &y) || own_carried(core, &y, false) {
            Some(Carry::Plain)
        } else if own_carried(core, &y, true) {
            Some(Carry::Pending)
        } else if read_carriers(core, &y, true).any(|h| founded_without(core, &h, &[y], true)) {
            Some(Carry::Pieced)
        } else {
            None
        };
        if let Some(k) = carry {
            out.insert((e, y));
            how = k;
        }
    }
    (out, how)
}

/// Whether a held strong reaches `y` where First entry carries it (spec/sync-set.md §2 Own
/// things): its grants count there, and nowhere a strong alone reaches (a thing nothing the node
/// syncs carries is held as certificates at most, whose grants give no role).
/// Judged on paths giving a role (`founded`): a piece kept only while a loss is carried out
/// carries nothing here.
pub(crate) fn reached_carried(core: &Core, y: &Tid) -> bool {
    let cl = &core.ix.closure;
    let avoid = [*y];
    let by_unit = || cl.targeting(y).any(|v| edge_carries(core, *v, y) && founded(core, *v, &avoid, false));
    let by_read = || read_carriers(core, y, false).any(|h| founded_without(core, &h, &avoid, false));
    cl.targeted(y) && (core.is_own(y) || own_carried(core, y, false) || by_unit() || by_read())
}

/// Whether held vertex `v`'s unit carries `y`, a target of its thing's strongs (spec/sync-set.md
/// §2 First entry): `v` is in the read sync unit of a thing `u` other than `y` whose keys open
/// `y` (whole) or whose effective role on `y` is sync or above (its stub). Local to the edge, so
/// the tree founds it: an entry by `u`'s unit goes when `u`'s does, whatever `u` reaches back.
/// Invariant: `y`'s own unit never carries it (`u != y`).
fn edge_carries(core: &Core, v: Vx, y: &Tid) -> bool {
    match v.0 {
        Ctx::Read(u) if u != *y => core.keys_open(&u, y) || core.keyed_role_now(&u, y) >= Some(Role::Sync),
        _ => false,
    }
}

/// Whether an offer of `y` or an edge piece in the key part of an own thing or a followed link
/// carries `y` (`given`): needing no founding, the node holding these whatever it reads.
fn own_carried(core: &Core, y: &Tid, pending: bool) -> bool {
    crate::flows::inbox::granted_on(core, y).next().is_some() || pieces_on(core, y, pending).any(|h| core.is_own(&h) || core.followed_links.contains(&h))
}

/// The things the node closure reads whose edge piece on `y` carries it, founding aside
/// (`given`).
fn read_carriers<'a>(core: &'a Core, y: &Tid, pending: bool) -> impl Iterator<Item = Tid> + use<'a> {
    pieces_on(core, y, pending).filter(|h| core.ix.closure.contexts(h).contains(&Ctx::Read(*h)))
}

/// The holders whose edge piece on `y` carries it (`given`): its holders now, or every
/// holder named on it while the node holds a read secret of `y`.
fn pieces_on(core: &Core, y: &Tid, pending: bool) -> std::vec::IntoIter<Tid> {
    let pending = pending && core.ix.secrets.get(y).is_some_and(|e| e.role(Role::Read).holds_any());
    let current: BTreeSet<Tid> = core.edge_holders(y).into_iter().map(|(h, _)| h).collect();
    let named: Vec<Tid> = core.ix.held.holders_of(y).copied().filter(|h| h != y && (pending || current.contains(h))).collect();
    named.into_iter()
}

/// Whether read thing `h` stays read with `y` out of the node closure (`founded`): a read
/// thing's piece carries `y` only where that thing is read without `y` (spec/sync-set.md §2
/// First entry: entry is founded, so nothing is kept for supporting itself).
fn founded_without(core: &Core, h: &Tid, y: &[Tid], pending: bool) -> bool {
    founded(core, (Ctx::Read(*h), *h), y, pending)
}

/// Whether the node closure holds `t` within the local part or another thing's sync unit, on a
/// path giving a role (`founded`: no entry on the way kept only while a loss is carried out, nor
/// resting on a piece unfounded so; spec/sync-set.md §2 Own things, judged on the least state).
pub(crate) fn holds_within(core: &Core, t: &Tid) -> bool {
    let cs = core.ix.closure.contexts(t);
    cs.into_iter().any(|c| !matches!(c, Ctx::Read(u) | Ctx::Unread(u) if u == *t) && founded(core, (c, *t), &[], false))
}

/// Whether held vertex `v` stays held with `y` out of the node closure: the least state the
/// out-lists give without `y` holds it, each entry on the way carried by something other than a
/// read thing's piece, or by such a piece of a thing reached so (`pending`: a piece kept only
/// while a loss is carried out counts too). Its tree path answers where it avoids `y` and enters
/// each thing on it so; else a search from the root over the out-lists avoiding `y`: brute
/// force, for the rare vertex resting on a read thing's piece or below or beside `y`. Its tree
/// reads make what asked judged again as the path moves.
fn founded(core: &Core, start: Vx, y: &[Tid], pending: bool) -> bool {
    let cl = &core.ix.closure;
    let plain = |p: &Vx, w: &Vx| !if pending { &cl.pieced } else { &cl.loose }.contains(&(*p, *w));
    if y.contains(&start.1) || !cl.is_held(&start) {
        return false;
    }
    // the tree path, each entry on it plain or by the piece of a read thing whose own tree path
    // answers so without the thing it carries: O(the paths walked)
    let fast = || {
        let mut stack: Vec<(Vx, Vec<Tid>)> = vec![(start, Vec::new())];
        let mut tried = BTreeSet::from([start.1]);
        while let Some((mut v, out)) = stack.pop() {
            while let Some(p) = cl.parent_of(&v) {
                if y.contains(&p.1) || out.contains(&p.1) {
                    return false;
                }
                if !plain(p, &v) {
                    let Some(c) = read_carriers(core, &v.1, pending).find(|c| !y.contains(c) && !out.contains(c) && !tried.contains(c)) else { return false };
                    tried.insert(c);
                    stack.push(((Ctx::Read(c), c), out.iter().copied().chain([v.1]).collect()));
                }
                v = *p;
            }
        }
        true
    };
    if fast() {
        return true;
    }
    let Some(root) = core.node_root else { return false };
    let root = (Ctx::Local, root);
    let mut seen = BTreeSet::from([root]);
    let mut todo = vec![root];
    let mut waiting: Vec<Vx> = Vec::new();
    loop {
        while let Some(u) = todo.pop() {
            for w in cl.out_of(&u) {
                if y.contains(&w.1) || seen.contains(w) {
                    continue;
                }
                if plain(&u, w) {
                    seen.insert(*w);
                    todo.push(*w);
                } else {
                    waiting.push(*w);
                }
            }
        }
        let read = |w: &Vx| read_carriers(core, &w.1, pending).any(|c| seen.contains(&(Ctx::Read(c), c)));
        let (now, rest): (Vec<Vx>, Vec<Vx>) = std::mem::take(&mut waiting).into_iter().filter(|w| !seen.contains(w)).partition(read);
        waiting = rest;
        if now.is_empty() {
            return seen.contains(&start);
        }
        for w in now {
            if seen.insert(w) {
                todo.push(w);
            }
        }
    }
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
        // strong reaches where it is carried, a holder held for keys), so a box its roles had kept out opens, and
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
        f.keys = Effects::new("closure: held for keys");
        for t in tx.core.ix.secrets.keys_held() {
            f.keys.want(*t);
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
                if !cl.holds(&t) {
                    let mut was = cl.left.get(&t).cloned().unwrap_or_default();
                    was.extend(cs);
                    cl.left.insert(t, was);
                }
            }
            f.before = None;
            f.known = true;
            cl.settle_synced(rv)?;
            return settle_keys(tx, f);
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

/// Whether the node holds `t` for keys (spec/sync-set.md §2 Held for keys): a holder the grants
/// of a thing the node syncs name, found from that thing up (`named_up`), which the node closure
/// does not read and the node can open (`opened_holder`).
fn held_for_keys(core: &Core, t: &Tid) -> bool {
    opened_holder(core, t) && named_up(core, t)
}

/// Whether `t` is a holder the node opens without reading it in the node closure: an independent
/// thing of which the node holds a read secret of its own (a box to an own actor
/// or to a holder it opens gave it; the lost-access rule keeps it only while the node's role
/// reads `t`, `rotation::lost`).
fn opened_holder(core: &Core, t: &Tid) -> bool {
    core.enter(t) == Some(Ctx::Read(*t)) && !core.ix.closure.reads(t)
}

/// Whether the grants of a thing the node closure holds (read, or kept unread: its edge piece is
/// in `t`'s key part) name `t`, or those of a holder so named
/// in turn that the node opens (`opened_holder`): each hop an edge write the node holds naming
/// its holder on its target, the holder holding a role there now with key access, any role on a
/// read thing and read or above on a holder (a hop that opens that holder's keys). The walk up
/// from a read thing through the holders its grants name, asked of one holder: O(what `t` is
/// named on by such hops).
fn named_up(core: &Core, t: &Tid) -> bool {
    let mut seen = BTreeSet::from([*t]);
    let mut todo = vec![*t];
    while let Some(x) = todo.pop() {
        for y in core.ix.held.named_on(&x) {
            if core.ix.closure.holds(y) {
                if core.keyed_role_now(&x, y).is_some() {
                    return true;
                }
            } else if opened_holder(core, y) && core.keyed_role_now(&x, y) >= Some(Role::Read) && seen.insert(*y) {
                todo.push(*y);
            }
        }
    }
    false
}

/// Brings the holders held for keys up to date (`held_for_keys`): each thing whose secrets moved
/// in this transaction is followed or let go, and each followed one whose judgement moved is
/// judged again. One coming to be held for keys wakes what waits for it (`apply::wake_entered`);
/// one held so no more is judged for what it still needs (`retention::needed`). Work in
/// proportion to the things whose secrets or holding moved.
fn settle_keys(tx: &mut Tx<'_>, f: &mut Follow) -> Result<()> {
    for t in tx.core.ix.secrets.logged() {
        if tx.core.ix.secrets.contains_key(&t) {
            f.keys.want(t);
        } else {
            f.keys.unwant(&t);
            if tx.core.ix.closure.keys.remove(&t) {
                tx.core.note_lost(t);
            }
        }
    }
    for t in f.keys.due() {
        if !tx.core.ix.secrets.contains_key(&t) {
            f.keys.unwant(&t);
            continue;
        }
        let core = &*tx.core;
        let mut now = false;
        f.keys.settle(&t, || {
            now = held_for_keys(core, &t);
            now
        });
        if now == tx.core.ix.closure.keys.contains(&t) {
            continue;
        }
        if now {
            tx.core.ix.closure.keys.insert(t);
            tx.core.keys_came.insert(t);
        } else {
            tx.core.ix.closure.keys.remove(&t);
            tx.core.note_lost(t);
        }
    }
    Ok(())
}

/// Follows every edge of held vertex `v`: O(its thing's strongs).
fn want_edges(tx: &mut Tx<'_>, f: &mut Follow, v: Vx) -> Result<()> {
    if matches!(v.0, Ctx::Unread(_)) {
        return Ok(());
    }
    for y in strongs_from(tx, &v.1)? {
        f.fx.want((v, y));
    }
    Ok(())
}

/// What `v`'s edge to `y` gives: nothing without a strong (the edge followed no more), else what
/// `given_by` says, recorded as what the edge follows.
fn judge(tx: &mut Tx<'_>, f: &mut Follow, v: Vx, y: Tid) -> Result<BTreeSet<Vx>> {
    if matches!(v.0, Ctx::Unread(_)) || !strong_to(tx, &v.1, &y)? {
        f.fx.unwant(&(v, y));
        set_carry(tx, v, y, &BTreeSet::new(), Carry::Plain);
        set_targeted(tx, y, v, false);
        tx.core.ix.closure.set_unknown(y, v, false);
        return Ok(BTreeSet::new());
    }
    set_targeted(tx, y, v, true);
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
    let mut how = None;
    f.fx.settle(&(v, y), || {
        let (g, k) = given(core, v, y);
        how = Some(k);
        got = g.clone();
        g
    });
    if let Some(k) = how {
        set_carry(tx, v, y, &got, k);
    }
    tx.core.ix.closure.set_beyond(y, v, !got.contains(&(v.0, y)));
    // a thing whose record is not held may be independent: its piece may be what was dropped
    if new && !got.iter().any(|w| w.1 == y) && (unknown || tx.core.counts_independent(&y)) {
        refetch_holders(tx)?;
    }
    Ok(got)
}

/// A new strong to independent (or unknown) `y` that nothing carries (spec/sync-set.md §2 First
/// entry): an edge piece on `y` in the key part of an own or read thing may have been dropped
/// while the node synced neither `y` nor an offer of it (spec/permissions.md §4 Key part: a piece is kept
/// only so far), and nothing local says which holder names `y`; so the sync IDs of every own
/// and read thing are pulled anew, fetching any such piece again (spec/sync-judgement.md §3
/// Dropped bodies). Rare-path brute force: one pull of those sync IDs per such strong, also
/// where nothing names `y`.
fn refetch_holders(tx: &mut Tx<'_>) -> Result<()> {
    let core = &*tx.core;
    let mut hs: BTreeSet<Tid> = core.ix.closure.tree.parent.keys().filter_map(|(c, t)| matches!(c, Ctx::Read(u) if u == t).then_some(*t)).collect();
    hs.insert(core.me());
    hs.extend(core.link_keys.keys().copied());
    for h in hs {
        crate::flows::sync_ids::pull_anew(tx, &h)?;
    }
    Ok(())
}

/// Records how `v`'s edge to `y` carries its entry (`Closure::pieced`, `loose`), none where it
/// gives none.
fn set_carry(tx: &mut Tx<'_>, v: Vx, y: Tid, got: &BTreeSet<Vx>, k: Carry) {
    let cl = &mut tx.core.ix.closure;
    for w in [(Ctx::Read(y), y), (Ctx::Unread(y), y)] {
        let entry = got.contains(&w);
        let (pieced, loose) = (entry && k == Carry::Pieced, entry && k != Carry::Plain);
        if pieced != cl.pieced.contains(&(v, w)) {
            match pieced {
                true => drop(cl.pieced.insert((v, w))),
                false => drop(cl.pieced.remove(&(v, w))),
            }
        }
        if loose != cl.loose.contains(&(v, w)) {
            match loose {
                true => drop(cl.loose.insert((v, w))),
                false => drop(cl.loose.remove(&(v, w))),
            }
        }
    }
}

/// A new edge of read unit `v` to `y`, which the node held as
/// certificates alone or not at all when the transaction began (`retention::needed::Holding`:
/// not in the node closure, nor leaving it, nor dropped from it in this transaction, `was_held`),
/// unless its record was learned in this transaction: the unit's sync IDs are pulled anew from
/// every source, so what was forgotten of `y` (its content outside the node closure, a body
/// judged outside the required set before the strong arrived) is fetched again
/// (spec/sync-judgement.md §3 Dropped bodies). Once per new edge, durable before the
/// transaction adding it commits.
fn refetch(tx: &mut Tx<'_>, v: Vx, y: Tid, was_held: bool) -> Result<()> {
    let Ctx::Read(t) = v.0 else { return Ok(()) };
    let cl = &tx.core.ix.closure;
    if was_held || cl.holds(&y) || cl.left().contains_key(&y) || tx.core.learned.contains(&y) {
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
/// judged for what it still needs (`retention::needed`): what was held for keys on the paths to
/// it goes with the strong (spec/sync-set.md §2 Held for keys).
fn set_targeted(tx: &mut Tx<'_>, y: Tid, v: Vx, on: bool) {
    if tx.core.ix.closure.set_targeted(y, v, on) {
        tx.core.note_lost(y);
    }
}

/// Sets what held vertex `v`'s edge to `y` gives to `now`, moving the tree.
fn apply(tx: &mut Tx<'_>, f: &mut Follow, rv: Vx, v: Vx, y: Tid, now: BTreeSet<Vx>) -> Result<()> {
    let cl = &mut tx.core.ix.closure;
    let old = cl.given(&v, &y);
    if old == now {
        return Ok(());
    }
    let mut fresh = Vec::new();
    for w in now.difference(&old) {
        cl.link(v, *w);
        if !cl.is_held(w) {
            fresh.push((*w, v));
        }
    }
    let gone: Vec<Vx> = old.difference(&now).copied().collect();
    for w in &gone {
        cl.unlink(v, *w);
    }
    for w in gone {
        if tx.core.ix.closure.tree.parent.get(&w) == Some(&v) {
            for x in tx.core.ix.closure.detach(rv, w) {
                f.gone.entry(x.1).or_default().insert(x.0);
                // its edges are followed no more
                if !matches!(x.0, Ctx::Unread(_)) {
                    for y in strongs_from(tx, &x.1)? {
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
        if matches!(x.0, Ctx::Unread(_)) {
            return Ok(out);
        }
        for y in strongs_from(self.0, &x.1)? {
            for w in judge(self.0, self.1, x, y)? {
                self.0.core.ix.closure.link(x, w);
                out.push(w);
            }
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
            if matches!(v.0, Ctx::Unread(_)) {
                continue;
            }
            for y in strongs_from(tx, &v.1)? {
                for w in given_by(tx.core, v, y) {
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
    let core = &*tx.core;
    let keys: BTreeSet<Tid> = core.ix.secrets.keys().filter(|t| held_for_keys(core, t)).copied().collect();
    assert_eq!(core.ix.closure.keys.iter().copied().collect::<BTreeSet<Tid>>(), keys, "the holders held for keys differ from those judged afresh");
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
        let ys = self.run(|tx| strongs_from(tx, &x))?;
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

    /// Whether `t` is held for keys (spec/sync-set.md §2), as last settled.
    pub fn held_for_keys(&self, t: &Tid) -> bool {
        self.core.ix.closure.keys.contains(t)
    }

    /// Whether `t` is kept unread: in the node closure by a sync secret alone (spec/sync-set.md
    /// §2).
    pub(crate) fn kept_unread(&self, t: &Tid) -> bool {
        let c = self.core.ix.closure.contexts(t);
        c.contains(&Ctx::Unread(*t)) && !c.contains(&Ctx::Read(*t))
    }
}
