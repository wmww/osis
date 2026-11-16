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

/// Where the walk is: the node root's local part, or a sync unit entered read or kept unread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ctx {
    Local,
    Read(Tid),
    Unread(Tid),
}

/// A vertex of the walk: a thing reached in a context.
pub type Vx = (Ctx, Tid);

/// The node closure as a spanning tree over vertices (module doc). Journaled: a failed
/// transaction undoes its changes; derived, so an open builds it again.
#[derive(Clone, Debug, Default)]
pub struct Closure {
    /// The held vertices.
    vx: JSet<Vx>,
    /// Each held vertex's out-list as last settled.
    out: JSetMap<Vx, Vx>,
    /// Strongs that appeared or went since the last settle, (source, target) (`note_row`).
    rows: JSet<(Tid, Tid)>,
    /// Targets of tickets that appeared since the last settle (`note_ticket`).
    tickets: JSet<Tid>,
    /// Per vertex, the held vertices whose out-list holds it.
    inn: JSetMap<Vx, Vx>,
    /// Each held vertex but the root: the referrer it hangs from.
    parent: JMap<Vx, Vx>,
    children: JSetMap<Vx, Vx>,
    /// Per held thing, the contexts it is held in: the node closure's things.
    held: JSetMap<Tid, Ctx>,
    /// Per context, its things: a read context's are its root's sync unit.
    members: JSetMap<Ctx, Tid>,
    /// The things that left the node closure and are not released yet, each with the contexts it
    /// was in when it left (`Engine::left_closure`).
    left: JMap<Tid, BTreeSet<Ctx>>,
    /// Things kept unread whose sync ID reached a closing head (`Engine::close_kept`): entered
    /// kept unread no more. Not persisted: a start judges each such sync ID closed again.
    closed: JSet<Tid>,
    /// The things sourced at another node whose paths the sync set's walk takes not
    /// (`Engine::set_sourced`, spec/sync-set.md §5), the account root never among them.
    pub(crate) cut: JSet<Tid>,
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
    type Mark = [usize; 12];
    fn commit(&mut self) {
        self.closed.commit();
        self.vx.commit();
        self.rows.commit();
        self.tickets.commit();
        self.out.commit();
        self.inn.commit();
        self.parent.commit();
        self.children.commit();
        self.held.commit();
        self.members.commit();
        self.left.commit();
        self.cut.commit();
    }
    fn mark(&mut self) -> Self::Mark {
        [self.out.mark(), self.inn.mark(), self.parent.mark(), self.children.mark(), self.held.mark(), self.members.mark(), self.left.mark(), self.cut.mark(), self.vx.mark(), self.rows.mark(), self.closed.mark(), self.tickets.mark()]
    }
    fn rollback_to(&mut self, m: Self::Mark) {
        self.closed.rollback_to(m[10]);
        self.vx.rollback_to(m[8]);
        self.rows.rollback_to(m[9]);
        self.tickets.rollback_to(m[11]);
        self.out.rollback_to(m[0]);
        self.inn.rollback_to(m[1]);
        self.parent.rollback_to(m[2]);
        self.children.rollback_to(m[3]);
        self.held.rollback_to(m[4]);
        self.members.rollback_to(m[5]);
        self.left.rollback_to(m[6]);
        self.cut.rollback_to(m[7]);
    }
    fn name(&mut self, _name: &'static str) {
        self.held.name("index: closure held");
        self.members.name("index: closure members");
        self.left.name("index: closure left");
        self.cut.name("index: closure cut");
    }
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{} {} {}", self.vx.contents(), self.out.contents(), self.left.contents())
    }
}

impl Closure {
    /// Whether the node closure holds `t`.
    pub(crate) fn holds(&self, t: &Tid) -> bool {
        self.held.contains_key(t)
    }

    /// The contexts holding `t`.
    pub(crate) fn contexts(&self, t: &Tid) -> BTreeSet<Ctx> {
        self.held.get(t).cloned().unwrap_or_default()
    }

    /// The things of context `c`.
    pub(crate) fn members(&self, c: &Ctx) -> Option<&BTreeSet<Tid>> {
        self.members.get(c)
    }

    /// Every thing of the node closure (a read of it whole).
    pub(crate) fn things(&self) -> impl Iterator<Item = &Tid> {
        self.held.keys_held()
    }

    /// A cursor over the things entering the node closure from now on.
    pub(crate) fn feed(&self) -> osis_base::memo::Feed<Tid> {
        self.held.feed()
    }

    /// The things that left and are not released yet (a stamped read, whole).
    pub(crate) fn left(&self) -> &std::collections::BTreeMap<Tid, BTreeSet<Ctx>> {
        &self.left
    }

    /// The things the walk reaches from `root` through no thing of `cut` (spec/sync-set.md §5
    /// Sourced away): O(the node closure), asked only while something is cut.
    pub(crate) fn uncut(&self, root: Option<Tid>) -> BTreeSet<Tid> {
        let Some(root) = root else { return BTreeSet::new() };
        let mut seen = BTreeSet::from([(Ctx::Local, root)]);
        let mut stack = vec![(Ctx::Local, root)];
        while let Some(v) = stack.pop() {
            for w in self.out.get(&v).into_iter().flatten() {
                if !self.cut.contains(&w.1) && seen.insert(*w) {
                    stack.push(*w);
                }
            }
        }
        seen.into_iter().map(|(_, t)| t).collect()
    }

    /// `t` released: it is no longer noted as left.
    pub(crate) fn released(&mut self, t: &Tid) {
        self.left.remove(t);
    }

    /// The reference index: a row of `source`'s strong to `target` appeared or went
    /// (`refs::note`).
    pub(crate) fn note_row(&mut self, source: Tid, target: Tid) {
        if self.held.contains_key(&source) {
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

    /// A ticket for `target` appeared among the known references: each held vertex's edge to
    /// it is judged again (`judge` takes its secret).
    pub(crate) fn note_ticket(&mut self, target: Tid) {
        self.tickets.insert(target);
    }

    /// The held vertices.
    fn vertices(&self) -> Vec<Vx> {
        self.vx.iter().copied().collect()
    }

    fn is_held(&self, v: &Vx) -> bool {
        self.vx.contains(v)
    }

    fn set_parent(&mut self, x: Vx, p: Vx) {
        if let Some(old) = self.parent.insert(x, p) {
            self.children.remove(&old, &x);
        }
        self.children.insert(p, x);
    }

    /// `x` held, hanging from `p` (none: the root), with no out-list yet.
    fn hold(&mut self, x: Vx, p: Option<Vx>) {
        if let Some(p) = p {
            self.set_parent(x, p);
        }
        self.vx.insert(x);
        self.held.insert(x.1, x.0);
        self.members.insert(x.0, x.1);
        self.left.remove(&x.1);
    }

    /// `x` dropped: no longer held in its context.
    fn drop_vertex(&mut self, x: Vx) {
        for y in self.out.get(&x).cloned().unwrap_or_default() {
            self.out.remove(&x, &y);
            self.inn.remove(&y, &x);
        }
        if let Some(p) = self.parent.remove(&x) {
            self.children.remove(&p, &x);
        }
        for c in self.children.get(&x).cloned().unwrap_or_default() {
            self.children.remove(&x, &c);
        }
        self.vx.remove(&x);
        self.held.remove(&x.1, &x.0);
        self.members.remove(&x.0, &x.1);
    }

    /// The vertices of `v`'s out-list that its edge to `y` gives.
    fn given(&self, v: &Vx, y: &Tid) -> BTreeSet<Vx> {
        let Some(out) = self.out.get(v) else { return BTreeSet::new() };
        [(v.0, *y), (Ctx::Read(*y), *y), (Ctx::Unread(*y), *y)].into_iter().filter(|w| out.contains(w)).collect()
    }
}

impl Core {
    /// Whether `t`'s keys open `x` (spec/sync-set.md §2): `x`'s secrets derive from `t`'s (`t`
    /// is on the record chain of the actor they derive from), or `t` holds read or above on
    /// that actor, by chains of grants. `t`'s own role: the account root reads as itself.
    pub(crate) fn keys_open(&self, t: &Tid, x: &Tid) -> bool {
        let Some(a) = self.secret_actor(x) else { return false };
        if self.record_chain(&a).filter_map(|s| s.thing()).any(|c| c == *t) {
            return true;
        }
        self.role_now(t, &a) >= Some(Role::Read)
    }

    /// Whether context `c` follows a strong to `y` by its own keys: the local part a plain
    /// thing, a read sync unit what its root's keys open.
    pub(crate) fn keys_open_from(&self, c: Ctx, y: &Tid) -> bool {
        match c {
            Ctx::Local => !self.has_own_secrets(y),
            Ctx::Read(t) => self.keys_open(&t, y),
            Ctx::Unread(_) => false,
        }
    }

    /// Whether the node holds an established read secret of `y`: until then a held ticket's
    /// secret is taken at each strong reaching it, since a secret held but not established may be
    /// anyone's (a ticket's epoch is its maker's to choose) and must not keep an honest one out.
    pub(crate) fn reads_established(&self, y: &Tid) -> bool {
        self.epochs(y).is_some_and(|e| e.role(Role::Read).held_established().next().is_some())
    }

    /// How the walk enters thing `y` with own keys at a strong from a context that does not
    /// follow it (spec/sync-set.md §2): read where the node holds a read secret of it, kept
    /// unread where it holds a sync secret only, else not at all.
    pub(crate) fn enter(&self, y: &Tid) -> Option<Ctx> {
        let e = self.epochs(y)?;
        if e.role(Role::Read).holds_any() {
            Some(Ctx::Read(*y))
        } else if e.role(Role::Sync).holds_any() && !self.ix.closure.closed.contains(y) {
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

/// What the walk takes from vertex `v` by a strong of its thing to `y` (module doc).
fn given_by(core: &Core, v: Vx, y: Tid) -> BTreeSet<Vx> {
    let (c, x) = v;
    let mut out = BTreeSet::new();
    // the walk does not enter a key actor: it has no sync unit
    if matches!(c, Ctx::Unread(_)) || x == y || core.is_key_actor(&y) {
        return out;
    }
    // own keys by the role commits held, or by secrets of its own held (a ticket's, taken before
    // any of its role commits arrive)
    let keyed = core.has_own_secrets(&y) || core.ix.secrets.get(&y).is_some_and(|e| e.holds_any());
    let follows = match c {
        Ctx::Local => !keyed,
        Ctx::Read(t) => core.keys_open(&t, &y),
        Ctx::Unread(_) => false,
    };
    if follows {
        out.insert((c, y));
    }
    if keyed && Ctx::Read(y) != c && let Some(e) = core.enter(&y) {
        out.insert((e, y));
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
        // a ticket arrived for a thing a held strong reaches: those edges judged again
        let tickets: Vec<Tid> = tx.core.ix.closure.tickets.iter().copied().collect();
        for y in tickets {
            tx.core.ix.closure.tickets.remove(&y);
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
        if due.is_empty() && tx.core.ix.closure.rows.is_empty() && tx.core.ix.closure.tickets.is_empty() {
            // each thing out of the node closure now, noted with every context it was dropped
            // from in this transaction: the sync units that carried it when it left
            let cl = &mut tx.core.ix.closure;
            for (t, cs) in std::mem::take(&mut f.gone) {
                if !cl.held.contains_key(&t) {
                    let mut was = cl.left.get(&t).cloned().unwrap_or_default();
                    was.extend(cs);
                    cl.left.insert(t, was);
                }
            }
            return Ok(());
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
        return Ok(BTreeSet::new());
    }
    f.fx.want((v, y));
    // a thing with own keys the secrets held do not enter: entered by a held ticket for it the
    // node can open, its secret taken now the strong reaches it (spec/sync-set.md §2,
    // spec/sync-inbox.md §5 Nothing before the strong)
    if !tx.core.is_key_actor(&y) && !tx.core.reads_established(&y) && !tx.core.keys_open_from(v.0, &y) {
        super::tickets::take_in(tx, &y)?;
    }
    let core = &*tx.core;
    let mut got = BTreeSet::new();
    f.fx.settle(&(v, y), || {
        got = given_by(core, v, y);
        got.clone()
    });
    Ok(got)
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
        osis_base::costs::count("closure: edges examined", 1);
        cl.out.insert(v, *w);
        cl.inn.insert(*w, v);
        if !cl.is_held(w) {
            fresh.push((*w, v));
        }
    }
    let gone: Vec<Vx> = old.difference(&now).copied().collect();
    for w in &gone {
        osis_base::costs::count("closure: edges examined", 1);
        cl.out.remove(&v, w);
        cl.inn.remove(w, &v);
    }
    for w in gone {
        if tx.core.ix.closure.parent.get(&w) == Some(&v) {
            for x in detach(tx, rv, w) {
                f.gone.entry(x.1).or_default().insert(x.0);
                // its edges are followed no more
                if !matches!(x.0, Ctx::Unread(_)) {
                    for y in strongs_from(tx, &x.1)? {
                        f.fx.unwant(&(x, y));
                    }
                }
            }
        }
    }
    reach(tx, f, fresh)
}

/// Holds each of `fresh` (vertex, referrer) not held yet, and what it reaches.
fn reach(tx: &mut Tx<'_>, f: &mut Follow, fresh: Vec<(Vx, Vx)>) -> Result<()> {
    let mut q: VecDeque<(Vx, Vx)> = fresh.into();
    while let Some((x, p)) = q.pop_front() {
        if tx.core.ix.closure.is_held(&x) {
            continue;
        }
        tx.core.ix.closure.hold(x, Some(p));
        if matches!(x.0, Ctx::Unread(_)) {
            continue;
        }
        for y in strongs_from(tx, &x.1)? {
            for w in judge(tx, f, x, y)? {
                osis_base::costs::count("closure: edges examined", 1);
                let cl = &mut tx.core.ix.closure;
                cl.out.insert(x, w);
                cl.inn.insert(w, x);
                if !cl.is_held(&w) {
                    q.push_back((w, x));
                }
            }
        }
    }
    Ok(())
}

/// `w`'s tree edge went (module doc): the two searches in step; then `w` hangs from another held
/// referrer, or its subtree is re-attached where held referrers outside it reach and the rest is
/// dropped.
fn detach(tx: &mut Tx<'_>, rv: Vx, w: Vx) -> Vec<Vx> {
    let cl = &mut tx.core.ix.closure;
    if let Some(p) = cl.parent.remove(&w) {
        cl.children.remove(&p, &w);
    }
    // search A: each other referrer's tree path, up to the root (outside) or to `w` (below)
    let mut last_ref: Option<Vx> = None;
    let mut at: Option<(Vx, Vx)> = None;
    let mut a_live = true;
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
                    let next = cl.inn.get(&w).and_then(|s| match last_ref {
                        None => s.iter().next().copied(),
                        Some(l) => s.range((std::ops::Bound::Excluded(l), std::ops::Bound::Unbounded)).next().copied(),
                    });
                    match next {
                        Some(r) => {
                            at = Some((r, r));
                            last_ref = Some(r);
                        }
                        None => a_live = false,
                    }
                }
                Some((_, c)) if c == w => at = None,
                Some((r, c)) if c == rv => {
                    // `r` is outside `w`'s subtree: `w` hangs from it, its subtree as it was
                    cl.set_parent(w, r);
                    return Vec::new();
                }
                Some((r, c)) => at = cl.parent.get(&c).map(|p| (r, *p)),
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
                    pending.extend(cl.children.get(x).into_iter().flatten().copied());
                    expanding += 1;
                }
                None => break,
            },
        }
    }
    // the subtree whole: re-attach what a held referrer outside it still reaches
    let mut q = VecDeque::new();
    for x in &sub {
        for r in cl.inn.get(x).into_iter().flatten() {
            osis_base::costs::count("closure: removal steps", 1);
            if !sub_set.contains(r) {
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
        cl.set_parent(x, r);
        for y in cl.out.get(&x).cloned().unwrap_or_default() {
            osis_base::costs::count("closure: removal steps", 1);
            if rest.remove(&y) {
                q.push_back((y, x));
            }
        }
    }
    for x in &rest {
        osis_base::costs::count("closure: dropped", 1);
        cl.drop_vertex(*x);
    }
    rest.into_iter().collect()
}

/// Adds the target of every strong at any depth of `v` to `out` (the reference index's reading,
/// spec/data-model.md §8 What counts).
pub fn strongs_in(v: &osis_base::Value, out: &mut BTreeSet<Tid>) {
    crate::engine::refs::references(v, &mut |k, t| {
        if k == osis_base::RefKind::Strong {
            out.insert(t);
        }
    });
}

/// Debug: the node closure as followed equals one walked afresh from the node root by
/// `given_by` over every strong, and its tree hangs every held vertex from a held referrer
/// (`Engine::check_index`, `Engine::check_closure`).
pub(crate) fn check_whole(tx: &mut Tx<'_>) -> Result<()> {
    let Some(root) = tx.core.node_root else { return Ok(()) };
    let rv = (Ctx::Local, root);
    let mut seen = BTreeSet::from([rv]);
    let mut stack = vec![rv];
    while let Some(v) = stack.pop() {
        if matches!(v.0, Ctx::Unread(_)) {
            continue;
        }
        for y in strongs_from(tx, &v.1)? {
            for w in given_by(tx.core, v, y) {
                if seen.insert(w) {
                    stack.push(w);
                }
            }
        }
    }
    let cl = &tx.core.ix.closure;
    let held: BTreeSet<Vx> = cl.vx.iter().copied().collect();
    assert_eq!(held, seen, "the node closure differs from one walked afresh");
    for v in &held {
        if *v != rv {
            let p = cl.parent.get(v);
            assert!(p.is_some_and(|p| cl.out.get(p).is_some_and(|o| o.contains(v))), "{v:?} hangs from {p:?}, which does not reach it");
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

    /// Kept-unread `s` reached a closing head (spec/sync-judgement.md §6 Closes): its thing is
    /// entered kept unread no more, so it leaves the node closure (spec/sync-set.md §3).
    pub fn close_kept(&mut self, s: &osis_base::SyncId) -> Result<()> {
        let Some((t, _)) = self.sync_holder(s)? else { return Ok(()) };
        self.run(|tx| {
            tx.core.ix.closure.closed.insert(t);
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
