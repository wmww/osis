//! Sync units and the node closure (spec/sync-set.md §2): what a sync ID carries, walked by
//! strongs within what the root may read; the node closure, walked sync unit by sync unit from
//! the node root.
//!
//! One structure holds both (`Closure`): a spanning tree over vertices (context, thing) rooted at
//! (local, node root). A context is the node root's local part, a sync unit read (`Ctx::Read`) or
//! one kept unread (`Ctx::Unread`). A vertex's out-list (`out_of`) is what the walk takes from
//! it: in the local part its strongs to plain things; in T's read sync unit its strongs to
//! things T's keys open; from either, a strong to a thing with own keys the context does not
//! follow enters that thing's sync unit by the secrets the node holds of it, and so does a strong
//! to a thing with own keys inside a read sync unit (its own sync unit is part of the one it is
//! in, so entering it holds nothing more and records which sync units hold what). A sync unit kept
//! unread is its root alone: the node cannot read what it holds. So T's sync unit is the things of
//! context `Read(T)`, and the node closure is every thing of any context.
//!
//! Work follows change (spec/sync-set.md §2 Cost): each held vertex's edge to each target of its
//! strongs is followed by an `Effects` key, due when what its judgement read moved (the target's
//! own keys, the roles and secrets it is judged by); a strong appearing or going is told by the
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

/// Where the walk is: the node root's local part, a sync unit entered read or kept unread, or a
/// thing entered on a ticket's word (`Ticket`: no own keys here, synced under its tickets' sync
/// IDs to fetch its role commits, none of its data held for it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ctx {
    Local,
    Read(Tid),
    Unread(Tid),
    Ticket(Tid),
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
    /// Strongs that appeared or went since the last settle, (source, target) (`note_row`).
    rows: JSet<(Tid, Tid)>,
    /// Things whose edges into them are judged again at the next settle (`rejudge`).
    rejudge: JSet<Tid>,
    /// Per thing a held strong reaches whose read secret is not established here, the sync IDs
    /// and roles of the held tickets for it the node can open, as last judged (`judge`).
    ticket_ids: JMap<Tid, BTreeSet<(osis_base::SyncId, Role)>>,
    /// Per sync ID, the things whose `ticket_ids` name it.
    by_ticket_id: JSetMap<osis_base::SyncId, Tid>,
    /// The ticket step's openers: per thing whose held tickets the walk last took, the holders
    /// those tickets are boxed to, opened or not (`judge`).
    openers: JSetMap<Tid, Tid>,
    /// Per holder, the things whose `openers` name it: the edges into them are judged again when
    /// the holder can open more (`opener_moved`).
    by_opener: JSetMap<Tid, Tid>,
    /// Per thing, the held vertices whose strong reaches it, the thing not followed by their
    /// keys, while the node holds a ticket for it that opens here, as last judged: the role
    /// commits that judge those tickets stay while any does (`retention::needed`), whether or not
    /// they enter it.
    accepted: JSetMap<Tid, Vx>,
    /// Fires whose role parts the walk's ticket step would take, not taken yet
    /// (`tickets::take_in`, `Engine::take_ticket_fires`).
    pub(crate) fires_due: JSet<osis_base::CommitId>,
    /// Per context, its things: a read context's are its root's sync unit.
    members: JSetMap<Ctx, Tid>,
    /// The things that left the node closure and are not released yet, each with the contexts it
    /// was in when it left (`Engine::left_closure`).
    left: JMap<Tid, BTreeSet<Ctx>>,
    /// The things sourced at another node whose paths the sync set's walk takes not
    /// (`Engine::set_sourced`, spec/sync-set.md §5), the account root never among them.
    cut: JSet<Tid>,
}

impl Default for Closure {
    fn default() -> Closure {
        Closure {
            tree: Tree::default(),
            synced: Tree::default(),
            out: JSetMap::default(),
            inn: JSetMap::default(),
            moved: JSet::default(),
            rows: JSet::default(),
            rejudge: JSet::default(),
            ticket_ids: JMap::default(),
            by_ticket_id: JSetMap::default(),
            openers: JSetMap::default(),
            by_opener: JSetMap::default(),
            accepted: JSetMap::default(),
            fires_due: JSet::default(),
            members: JSetMap::by_element(),
            left: JMap::default(),
            cut: JSet::default(),
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
}

impl Default for Follow {
    fn default() -> Follow {
        Follow { fx: Effects::new("closure: edges"), reset: true, acted: false, gone: Default::default() }
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
    type Mark = ([usize; 4], [usize; 4], [usize; 14]);
    fn commit(&mut self) {
        self.ticket_ids.commit();
        self.by_ticket_id.commit();
        self.openers.commit();
        self.by_opener.commit();
        self.accepted.commit();
        self.fires_due.commit();
        self.tree.commit();
        self.synced.commit();
        self.out.commit();
        self.inn.commit();
        self.moved.commit();
        self.rows.commit();
        self.rejudge.commit();
        self.members.commit();
        self.left.commit();
        self.cut.commit();
    }
    fn mark(&mut self) -> Self::Mark {
        (self.tree.mark(), self.synced.mark(), [self.out.mark(), self.inn.mark(), self.moved.mark(), self.rows.mark(), self.rejudge.mark(), self.members.mark(), self.left.mark(), self.cut.mark(), self.ticket_ids.mark(), self.by_ticket_id.mark(), self.fires_due.mark(), self.openers.mark(), self.by_opener.mark(), self.accepted.mark()])
    }
    fn rollback_to(&mut self, (t, s, m): Self::Mark) {
        self.tree.rollback_to(t);
        self.synced.rollback_to(s);
        self.out.rollback_to(m[0]);
        self.inn.rollback_to(m[1]);
        self.moved.rollback_to(m[2]);
        self.rows.rollback_to(m[3]);
        self.rejudge.rollback_to(m[4]);
        self.members.rollback_to(m[5]);
        self.left.rollback_to(m[6]);
        self.cut.rollback_to(m[7]);
        self.ticket_ids.rollback_to(m[8]);
        self.by_ticket_id.rollback_to(m[9]);
        self.fires_due.rollback_to(m[10]);
        self.openers.rollback_to(m[11]);
        self.by_opener.rollback_to(m[12]);
        self.accepted.rollback_to(m[13]);
    }
    fn name(&mut self, _name: &'static str) {
        self.tree.name("index: closure held");
        self.synced.name("index: sync set held");
        self.members.name("index: closure members");
        self.left.name("index: closure left");
        self.cut.name("index: closure cut");
        self.ticket_ids.name("index: closure ticket ids");
        self.by_ticket_id.name("index: closure by ticket id");
        self.openers.name("index: closure ticket openers");
        self.by_opener.name("index: closure by ticket opener");
        self.accepted.name("index: closure accepted");
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
    /// Whether the node closure holds `t`: in a context other than on a ticket's word alone,
    /// which holds none of its data (`Ctx::Ticket`).
    pub(crate) fn holds(&self, t: &Tid) -> bool {
        self.tree.held.get(t).is_some_and(|cs| cs.iter().any(|c| !matches!(c, Ctx::Ticket(_))))
    }

    /// Whether `t` is entered on a ticket's word (`Ctx::Ticket`).
    pub(crate) fn on_ticket(&self, t: &Tid) -> bool {
        self.tree.held.get(t).is_some_and(|cs| cs.contains(&Ctx::Ticket(*t)))
    }

    /// The sync IDs and roles of the held tickets for `t` the node can open, as last judged.
    pub(crate) fn ticket_ids(&self, t: &Tid) -> BTreeSet<(osis_base::SyncId, Role)> {
        self.ticket_ids.get(t).cloned().unwrap_or_default()
    }

    /// The things whose held tickets name sync ID `s`.
    pub(crate) fn naming_ticket_id(&self, s: &osis_base::SyncId) -> BTreeSet<Tid> {
        self.by_ticket_id.get(s).cloned().unwrap_or_default()
    }

    /// Whether a held vertex's strong reaches `t` with a ticket for it held (`accepted`).
    pub(crate) fn accepted(&self, t: &Tid) -> bool {
        self.accepted.get(t).is_some_and(|v| !v.is_empty())
    }

    /// Sets whether `v`'s strong to `t` is one `accepted` counts; whether `t` lost its last.
    fn set_accepted(&mut self, t: Tid, v: Vx, on: bool) -> bool {
        if on {
            self.accepted.insert(t, v);
            return false;
        }
        let had = self.accepted(&t);
        self.accepted.remove(&t, &v);
        had && !self.accepted(&t)
    }

    /// Sets `t`'s ticket sync IDs (`ticket_ids`) to `ids`.
    fn set_ticket_ids(&mut self, t: Tid, ids: BTreeSet<(osis_base::SyncId, Role)>) {
        let old = self.ticket_ids(&t);
        if old == ids {
            return;
        }
        for (s, _) in &old {
            self.by_ticket_id.remove(s, &t);
        }
        for (s, _) in &ids {
            self.by_ticket_id.insert(*s, t);
        }
        match ids.is_empty() {
            true => drop(self.ticket_ids.remove(&t)),
            false => drop(self.ticket_ids.insert(t, ids)),
        }
    }

    /// Sets the holders `t`'s held tickets are boxed to (`openers`) to `holders`.
    fn set_openers(&mut self, t: Tid, holders: BTreeSet<Tid>) {
        let old = self.openers.get(&t).cloned().unwrap_or_default();
        for h in old.difference(&holders) {
            self.openers.remove(&t, h);
            self.by_opener.remove(h, &t);
        }
        for h in holders.difference(&old) {
            self.openers.insert(t, *h);
            self.by_opener.insert(*h, t);
        }
    }

    /// Holder `h` can open more (taken up, or its secrets grew): the edges into each thing with a
    /// held ticket boxed to it are judged again at the next settle, O(those things).
    pub(crate) fn opener_moved(&mut self, h: &Tid) {
        for t in self.by_opener.get(h).cloned().unwrap_or_default() {
            osis_base::costs::count("closure: opener rejudged", 1);
            self.rejudge.insert(t);
        }
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

    /// A cursor over the things entering the node closure from now on.
    pub(crate) fn feed(&self) -> osis_base::memo::Feed<Tid> {
        self.tree.held.feed()
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
            self.rows.insert((source, target));
        }
    }

    /// The role `t` is entered at by a strong outside the node root's local part (spec/sync-set.md
    /// §1 The account's tickets): read where its read sync unit hangs from a vertex of a sync
    /// unit, else sync where it is kept unread so; `None` where it is entered from the local
    /// part alone, or not entered.
    pub(crate) fn entered_outside(&self, t: &Tid) -> Option<Role> {
        let outside = |c: Ctx| self.inn.get(&(c, *t)).is_some_and(|i| i.iter().any(|w| w.0 != Ctx::Local));
        if outside(Ctx::Read(*t)) {
            Some(Role::Read)
        } else if outside(Ctx::Unread(*t)) {
            Some(Role::Sync)
        } else {
            None
        }
    }

    /// Each held vertex's edge to `target` is judged again at the next settle: a ticket for it
    /// appeared among the known references (`judge` takes its secret), or a sync ID a ticket for
    /// it names closed (`Engine::close_kept`).
    pub(crate) fn rejudge(&mut self, target: Tid) {
        self.rejudge.insert(target);
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
        [(v.0, *y), (Ctx::Read(*y), *y), (Ctx::Unread(*y), *y), (Ctx::Ticket(*y), *y)].into_iter().filter(|w| out.contains(w)).collect()
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
    /// Whether `t`'s keys open `x` (spec/sync-set.md §2): `x`'s secrets derive from `t`'s (`t`
    /// is on the record chain of the actor they derive from), or `t` holds read or above on
    /// that actor, by chains of grants with key access (`reads_now`). `t`'s own role: the account
    /// root reads as itself.
    pub(crate) fn keys_open(&self, t: &Tid, x: &Tid) -> bool {
        let Some(a) = self.secret_actor(x) else { return false };
        if self.record_chain(&a).filter_map(|s| s.thing()).any(|c| c == *t) {
            return true;
        }
        self.reads_now(t, &a)
    }

    /// Whether the node opens plain thing `y` (spec/sync-set.md §2 local part): it holds a read
    /// secret of the thing with own keys `y`'s secrets derive from, or the keys of the key actor
    /// they derive from (itself, its account, a key actor it holds). A tid the node holds no
    /// record of opens nothing.
    pub(crate) fn opens_plain(&self, y: &Tid) -> bool {
        let Some(a) = self.secret_actor(y) else { return false };
        if self.has_own_secrets(&a) {
            return self.epochs(&a).is_some_and(|e| e.role(Role::Read).holds_any());
        }
        a == self.id.tid() || Some(a) == self.member() || self.key_actors.contains_key(&a)
    }

    /// Whether context `c` follows a strong to `y` by its own keys: the local part a plain
    /// thing the node opens, a read sync unit what its root's keys open.
    pub(crate) fn keys_open_from(&self, c: Ctx, y: &Tid) -> bool {
        match c {
            Ctx::Local => !self.has_own_secrets(y) && self.opens_plain(y),
            Ctx::Read(t) => self.keys_open(&t, y),
            Ctx::Unread(_) | Ctx::Ticket(_) => false,
        }
    }

    /// Whether `y` has own keys here (spec/sync-set.md §2): by the role commits held of it, or by
    /// an established secret of its own (not one derived from its first admin's). A ticket's
    /// secret establishes nothing (it may be anyone's): a thing without own keys whose tickets the
    /// walk took is entered on their word (`given_by`), read fetching under their sync IDs
    /// (`Ctx::Ticket`) until the role commits arrive, sync kept unread (`Ctx::Unread`).
    pub(crate) fn keyed(&self, y: &Tid) -> bool {
        self.has_own_secrets(y) || self.ix.secrets.get(y).is_some_and(|e| Role::ALL.iter().any(|r| e.role(*r).held_established().next().is_some()))
    }

    /// Whether the node holds an established read secret of `y`'s own (not one derived from its
    /// first admin's, which a thing whose keyset the node lacks reads as): until then a held ticket's
    /// secret is taken at each strong reaching it, since a secret held but not established may be
    /// anyone's (a ticket's epoch is its maker's to choose) and must not keep an honest one out.
    pub(crate) fn reads_established(&self, y: &Tid) -> bool {
        self.ix.secrets.get(y).is_some_and(|e| e.role(Role::Read).held_established().next().is_some())
    }

    /// How the walk enters thing `y` with own keys at a strong from a context that does not
    /// follow it (spec/sync-set.md §2): read where the node holds a read secret of it, kept
    /// unread where it holds a sync secret only and no held ticket for it names a closed sync ID
    /// (`closed`, from `closed_kept`), else not at all.
    pub(crate) fn enter(&self, y: &Tid, closed: bool) -> Option<Ctx> {
        let e = self.epochs(y)?;
        if e.role(Role::Read).holds_any() {
            Some(Ctx::Read(*y))
        } else if e.role(Role::Sync).holds_any() && !closed {
            Some(Ctx::Unread(*y))
        } else {
            None
        }
    }
}

/// The targets of `x`'s strongs, `x` aside.
fn strongs_from(tx: &mut Tx<'_>, x: &Tid) -> Result<BTreeSet<Tid>> {
    Ok(crate::engine::refs::from(tx, x)?.into_iter().filter(|r| r.kind == osis_base::RefKind::Strong).map(|r| r.target).filter(|t| t != x).collect())
}

/// Whether `x` holds a strong to `y` now.
fn strong_to(tx: &mut Tx<'_>, x: &Tid, y: &Tid) -> Result<bool> {
    Ok(x != y && crate::engine::refs::strong_from(tx, x, y)?)
}

/// Whether `y` is one the walk would enter kept unread and a held ticket for it names a sync ID
/// whose stored path ends at a closing step (spec/sync-judgement.md §6 Closes): read from the
/// store's path, which it keeps while such a ticket is held (spec/sync-set.md §3). Unstamped:
/// a close re-judges the edges into `y` (`Engine::close_kept`).
fn closed_kept(tx: &mut Tx<'_>, y: &Tid) -> Result<bool> {
    if !tx.core.epochs(y).is_some_and(|e| !e.role(Role::Read).holds_any() && e.role(Role::Sync).holds_any()) {
        return Ok(false);
    }
    for k in super::tickets::held_in(tx, y)? {
        if tx.blobs.closed(&k.sync_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the walk takes from vertex `v` by a strong of its thing to `y` (module doc), `closed`
/// as `closed_kept` says of `y`.
fn given_by(core: &Core, v: Vx, y: Tid, closed: bool) -> BTreeSet<Vx> {
    let (c, x) = v;
    let mut out = BTreeSet::new();
    // the walk does not enter a key actor: it has no sync unit
    if matches!(c, Ctx::Unread(_) | Ctx::Ticket(_)) || x == y || core.is_key_actor(&y) {
        return out;
    }
    let keyed = core.keyed(&y);
    let follows = match c {
        Ctx::Local => !keyed && core.opens_plain(&y),
        Ctx::Read(t) => core.keys_open(&t, &y),
        Ctx::Unread(_) | Ctx::Ticket(_) => false,
    };
    if follows {
        out.insert((c, y));
    }
    if keyed && Ctx::Read(y) != c && let Some(e) = core.enter(&y, closed) {
        out.insert((e, y));
    }
    // no own keys here: entered on a ticket's word, where a ticket was taken, at the node's
    // role (`tickets::entry_role`, read again here so a role change judges the edge again), by a
    // secret of that role held: read fetches under the tickets' sync IDs (spec/sync-inbox.md §5
    // Ticket sync IDs), none of its data held for it; sync keeps them unread, which a close ends
    if !keyed {
        let best = core.ix.closure.ticket_ids(&y).into_iter().map(|(_, r)| r).max();
        let role = best.and_then(|k| super::tickets::entry_role(core, &y, k));
        let holds = |r: Role| core.ix.secrets.get(&y).is_some_and(|e| e.role(r).holds_any());
        if role >= Some(Role::Read) && holds(Role::Read) {
            out.insert((Ctx::Ticket(y), y));
        } else if role.is_some() && holds(Role::Sync) && !closed {
            out.insert((Ctx::Unread(y), y));
        }
    }
    out
}

/// Brings the node closure up to date with what moved since the last settle (module doc): at
/// each transaction's end, and after an open.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<()> {
    let Some(root) = tx.core.node_root else { return Ok(()) };
    let rv = (Ctx::Local, root);
    let mut f = std::mem::take(&mut tx.core.closure_follow);
    let r = settle_with(tx, &mut f, rv);
    tx.core.closure_follow = f;
    r
}

fn settle_with(tx: &mut Tx<'_>, f: &mut Follow, rv: Vx) -> Result<()> {
    f.acted = true;
    f.gone.clear();
    if std::mem::take(&mut f.reset) {
        f.fx = Effects::new("closure: edges");
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
        let rows: Vec<(Tid, Tid)> = tx.core.ix.closure.rows.iter().copied().collect();
        for (x, y) in &rows {
            tx.core.ix.closure.rows.remove(&(*x, *y));
            for c in tx.core.ix.closure.contexts(x) {
                let v = (c, *x);
                if tx.core.ix.closure.is_held(&v) {
                    let now = judge(tx, f, v, *y)?;
                    apply(tx, f, rv, v, *y, now)?;
                }
            }
        }
        // a ticket arrived for a thing a held strong reaches, or a sync ID one names closed: those
        // edges judged again
        let again: Vec<Tid> = tx.core.ix.closure.rejudge.iter().copied().collect();
        for y in again {
            tx.core.ix.closure.rejudge.remove(&y);
            if tx.core.reads_established(&y) {
                continue;
            }
            let from: Vec<Tid> = crate::engine::refs::to(tx, &y)?.into_iter().filter(|r| r.kind == osis_base::RefKind::Strong).map(|r| r.source).collect();
            for x in from {
                for c in tx.core.ix.closure.contexts(&x) {
                    let v = (c, x);
                    if tx.core.ix.closure.is_held(&v) {
                        let now = judge(tx, f, v, y)?;
                        apply(tx, f, rv, v, y, now)?;
                    }
                }
            }
        }
        let due = f.fx.due();
        if due.is_empty() && tx.core.ix.closure.rows.is_empty() && tx.core.ix.closure.rejudge.is_empty() {
            // each thing out of the node closure now, noted with every context it was dropped
            // from in this transaction: the sync units that carried it when it left
            let cl = &mut tx.core.ix.closure;
            for (t, cs) in std::mem::take(&mut f.gone) {
                // its ticket step's inputs go with its last vertex, judged at the settle's end: a
                // thing moving between contexts is dropped from one before it is held in the next
                if !cl.tree.held.contains_key(&t) {
                    cl.set_ticket_ids(t, BTreeSet::new());
                    cl.set_openers(t, BTreeSet::new());
                }
                if !cl.holds(&t) {
                    let mut was = cl.left.get(&t).cloned().unwrap_or_default();
                    was.extend(cs);
                    cl.left.insert(t, was);
                }
            }
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
    if matches!(v.0, Ctx::Unread(_) | Ctx::Ticket(_)) {
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
    if matches!(v.0, Ctx::Unread(_) | Ctx::Ticket(_)) || !strong_to(tx, &v.1, &y)? {
        f.fx.unwant(&(v, y));
        set_accepted(tx, y, v, false);
        return Ok(BTreeSet::new());
    }
    f.fx.want((v, y));
    // a thing the context does not follow by its keys, whose read secret is not established
    // here: each held ticket for it the node can open has its secret taken now the strong reaches
    // it, and its sync ID noted (spec/sync-set.md §2, spec/sync-inbox.md §5 Nothing before the
    // strong): O(its tickets)
    let ticketed = !tx.core.is_key_actor(&y) && !tx.core.reads_established(&y) && !tx.core.keys_open_from(v.0, &y);
    let mut any = false;
    if ticketed {
        let taken = super::tickets::take_in(tx, &y)?;
        tx.core.ix.closure.set_ticket_ids(y, taken.ids);
        tx.core.ix.closure.set_openers(y, taken.openers);
        any = taken.opened;
    }
    set_accepted(tx, y, v, any);
    let closed = closed_kept(tx, &y)?;
    let core = &*tx.core;
    let mut got = BTreeSet::new();
    f.fx.settle(&(v, y), || {
        got = given_by(core, v, y, closed);
        got.clone()
    });
    Ok(got)
}

/// Notes whether `v`'s strong to `y` counts for `Closure::accepted`; `y` losing its last is
/// judged for what it still needs (`retention::needed`).
fn set_accepted(tx: &mut Tx<'_>, y: Tid, v: Vx, on: bool) {
    if tx.core.ix.closure.set_accepted(y, v, on) {
        tx.core.note_pass_due(y);
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
                if !matches!(x.0, Ctx::Unread(_) | Ctx::Ticket(_)) {
                    for y in strongs_from(tx, &x.1)? {
                        f.fx.unwant(&(x, y));
                        set_accepted(tx, y, x, false);
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
        if matches!(x.0, Ctx::Unread(_) | Ctx::Ticket(_)) {
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
            if matches!(v.0, Ctx::Unread(_) | Ctx::Ticket(_)) {
                continue;
            }
            for y in strongs_from(tx, &v.1)? {
                let closed = closed_kept(tx, &y)?;
                for w in given_by(tx.core, v, y, closed) {
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

/// The things this transaction's own commits made, each in the node closure at its end, or the
/// transaction is refused (spec/sync-set.md §2 Making a thing). A node with no node root yet
/// (its first start) checks nothing, nor a hostile writer (`skip_writer_rules`): a writer's rule.
pub(crate) fn check_made(tx: &mut Tx<'_>) -> Result<()> {
    if tx.core.node_root.is_none() || tx.core.skip_writer_rules {
        tx.core.made.clear();
        return Ok(());
    }
    for t in std::mem::take(&mut tx.core.made) {
        if tx.core.created(&t).is_some() && !tx.core.ix.closure.holds(&t) {
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
    /// otherwise (spec/sync-set.md §2 Not carried), key actors aside: none when the node closure
    /// does not hold `x`. O(`x`'s strongs).
    pub fn not_carried_from(&mut self, x: &Tid) -> Result<Vec<Tid>> {
        if !self.core.ix.closure.holds(x) {
            return Ok(Vec::new());
        }
        let x = *x;
        let ys = self.run(|tx| strongs_from(tx, &x))?;
        Ok(ys.into_iter().filter(|y| !self.core.is_key_actor(y) && !self.core.ix.closure.holds(y)).collect())
    }

    /// Those of `ys` that `x` strongly references and `not_carried_from` would name: O(`ys`).
    pub fn not_carried_among(&mut self, x: &Tid, ys: &BTreeSet<Tid>) -> Result<Vec<Tid>> {
        if !self.core.ix.closure.holds(x) {
            return Ok(Vec::new());
        }
        let x = *x;
        let ys: Vec<Tid> = ys.iter().filter(|y| !self.core.is_key_actor(y) && !self.core.ix.closure.holds(y)).copied().collect();
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
        let r = osis_base::costs::paused(|| osis_base::memo::unrecorded(|| self.read(check_whole)));
        assert!(r.is_ok(), "node closure walked afresh: {:?}", r.err());
    }

    /// Whether the node closure holds `t` (spec/sync-set.md §2).
    pub fn closure_holds(&self, t: &Tid) -> bool {
        self.core.ix.closure.holds(t)
    }

    /// Kept-unread `s` reached a closing head (spec/sync-judgement.md §6 Closes): the edges into
    /// its thing are judged again, which enter it kept unread no more while a held ticket names
    /// `s` (`closed_kept`, from the store's path), so it leaves the node closure
    /// (spec/sync-set.md §3).
    pub fn close_kept(&mut self, s: &osis_base::SyncId) -> Result<()> {
        let Some((things, _)) = self.sync_holder(s)? else { return Ok(()) };
        self.run(|tx| {
            for t in things {
                tx.core.ix.closure.rejudge(t);
            }
            Ok(())
        })
    }

    /// Whether `t` is kept unread: in the node closure by a sync secret alone (spec/sync-set.md
    /// §2).
    pub(crate) fn kept_unread(&self, t: &Tid) -> bool {
        let c = self.core.ix.closure.contexts(t);
        c.contains(&Ctx::Unread(*t)) && !c.contains(&Ctx::Read(*t))
    }
}
