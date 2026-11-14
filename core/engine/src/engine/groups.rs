//! `groups.0` (spec/data-model.md §8): every group whose items, directly or through subgroups
//! (cycles allowed), contain the thing. The index holds each listing edge both ways and is kept
//! by edits: a join refreshes the listing of the tids it touches (`touched`, `refresh`), reading
//! only their records; what derives from it is walked when asked or edited in place (`Groups`).

use super::Engine;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_crdt::{Dot, DotRange, Fragment, PathSeg};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A `group.0` definition: (items, subgroups).
pub(crate) type Def = (BTreeSet<Tid>, BTreeSet<Tid>);

/// `group.0` field ids (spec/data-model.md §8).
pub(crate) const ITEMS: u64 = 0;
pub(crate) const SUBGROUPS: u64 = 1;

/// The definition a `group.0` state holds: its items and subgroups read field by field.
pub(crate) fn def_of(f: &Fragment) -> Option<Def> {
    let tids = |field: u64| -> BTreeSet<Tid> {
        match f.at(&[PathSeg::Field(field)]).and_then(|x| x.read()) {
            Some(Value::Set(s)) => s.into_iter().filter_map(|v| if let Value::Tid(t) = v { Some(t) } else { None }).collect(),
            _ => BTreeSet::new(),
        }
    };
    let present = f.present();
    let d = (tids(ITEMS), tids(SUBGROUPS));
    (present || !d.0.is_empty() || !d.1.is_empty()).then_some(d)
}

/// What `delta` newly lists when joined into a group's state `before`.
pub(crate) fn gains(before: Option<&Fragment>, delta: &Fragment) -> BTreeSet<Tid> {
    let def = |f: &Fragment| def_of(f).unwrap_or_default();
    let (items, subs) = before.map(def).unwrap_or_default();
    let mut after = before.cloned().unwrap_or_default();
    after.join(delta.clone());
    let (i, s) = def(&after);
    i.difference(&items).chain(s.difference(&subs)).copied().collect()
}

/// The tids whose listing in group `g`'s `group.0` a join of `delta` may change: those its
/// elements hold and those of the state's records at its reach (`Fragment::reach`: an element it
/// resets, a record of a tid it removes), read from the pages the join touches anyway. `None`
/// where it resets a position (read the whole state after).
pub(crate) fn touched(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak, delta: &Fragment) -> Result<Option<BTreeSet<Tid>>> {
    if delta.has_position_reset() {
        return Ok(None);
    }
    tx.load_lazy(g, ak)?;
    let touch = super::pages::touch_of(delta, tx.core.pages.get(&(*g, ak.clone())));
    tx.ensure_touch(g, ak, &touch)?;
    let mut out = tids_in(delta);
    if let Some(st) = tx.cached(g, ak) {
        out.extend(tids_in(&st.reach(delta)));
    }
    Ok(Some(out))
}

/// The tids `f`'s records hold.
fn tids_in(f: &Fragment) -> BTreeSet<Tid> {
    let mut out = BTreeSet::new();
    f.each_value(&mut |v| {
        if let Value::Tid(t) = v {
            out.insert(*t);
        }
    });
    out
}

/// Which of `tids` group `g`'s `group.0` lists, (as items, as subgroups), reading only their
/// records (a paged state's value index: `ensure_paths` loads every record of each).
fn listed_of(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak, tids: &BTreeSet<Tid>) -> Result<(BTreeSet<Tid>, BTreeSet<Tid>)> {
    let paths: Vec<Vec<PathSeg>> = tids.iter().flat_map(|t| [ITEMS, SUBGROUPS].map(|f| vec![PathSeg::Field(f), PathSeg::Key(Value::Tid(*t))])).collect();
    tx.ensure_paths(g, ak, &paths)?;
    let live = |f: u64| -> BTreeSet<Tid> {
        match tx.cached(g, ak).and_then(|s| s.read_at(&[PathSeg::Field(f)])) {
            Some(Value::Set(s)) => s.into_iter().filter_map(|v| if let Value::Tid(t) = v { Some(t) } else { None }).filter(|t| tids.contains(t)).collect(),
            _ => BTreeSet::new(),
        }
    };
    Ok((live(ITEMS), live(SUBGROUPS)))
}

/// Refreshes group `g`'s listing in the index for the tids `tids` (`touched`) after a join,
/// reading only their records: O(the change), not O(the group). A join without a position
/// reset leaves a present state present, so a group defined stays defined; one not defined yet
/// is read whole.
pub(crate) fn refresh(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak, tids: &BTreeSet<Tid>) -> Result<()> {
    if !tx.core.ix.groups.is_defined(g) {
        return crate::apply::observe_state(tx, g, ak);
    }
    let (items, subs) = listed_of(tx, g, ak, tids)?;
    let ix = &tx.core.ix.groups;
    let edits: Vec<Edit> = tids.iter().flat_map(|t| [(ITEMS, &items), (SUBGROUPS, &subs)].map(|(f, now)| (f, *t, now.contains(t)))).filter(|(f, t, on)| ix.listed(g, *f, t) != *on).collect();
    if !edits.is_empty() {
        // an ephemeral membership carries nothing durable away (`Core::note_cut`)
        if !tx.core.memory_tx {
            let cut: Vec<Tid> = edits.iter().filter(|(f, _, on)| *f == SUBGROUPS && !on).map(|e| e.1).collect();
            tx.core.note_cut(g, &cut);
        }
        tx.core.ix.groups.change(*g, &edits);
    }
    #[cfg(debug_assertions)]
    check_refreshed(tx, g, ak)?;
    Ok(())
}

/// At open: group `g`'s definition into the index, a page at a time (`pages::page_keys`): each
/// page's tids read with all their records (`listed_of`), the pages dropped again, so no whole
/// definition is held but the index's.
pub(crate) fn load(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak) -> Result<()> {
    tx.load_lazy(g, ak)?;
    let k = (*g, ak.clone());
    let keys = match tx.core.pages.get(&k) {
        Some(idx) => super::pages::page_keys(&mut tx.txn, g, ak, idx)?,
        None => None,
    };
    let Some(keys) = keys else {
        // unpaged (small), or paged in a way read only whole
        let def = crate::apply::atomic::group_def(tx.state(g, ak)?.and_then(Fragment::read));
        if let Some(d) = def {
            tx.core.ix.groups.load(*g, true, d.0.iter(), d.1.iter());
        }
        tx.evict_pages(g, ak);
        return Ok(());
    };
    // the collections left unpaged are in the skeleton whole
    let skeleton = tx.cached(g, ak).and_then(def_of);
    let (items, subs) = skeleton.clone().unwrap_or_default();
    tx.core.ix.groups.load(*g, skeleton.is_some(), items.iter(), subs.iter());
    for key in keys {
        let page = super::pages::page_at(&mut tx.txn, g, ak, &key)?;
        let (items, subs) = listed_of(tx, g, ak, &tids_in(&page))?;
        tx.core.ix.groups.load(*g, !items.is_empty() || !subs.is_empty(), items.iter(), subs.iter());
        tx.evict_pages(g, ak);
    }
    #[cfg(debug_assertions)]
    check_refreshed(tx, g, ak)?;
    Ok(())
}

/// Debug builds: `g`'s listing in the index equals the whole state's definition, the index
/// derived from it agrees (each member lists `g` back), and every closure kept of a group above
/// `g` equals one derived anew (unseen: the cache as it was, no cost recorded).
#[cfg(debug_assertions)]
fn check_refreshed(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak) -> Result<()> {
    let k = (*g, ak.clone());
    let cached = (tx.core.states.get(&k).cloned(), tx.core.pages.get(&k).cloned());
    let whole = osis_base::costs::paused(|| -> Result<_> { Ok(crate::apply::atomic::group_def(tx.state(g, ak)?.and_then(Fragment::read))) })?;
    match cached.0 {
        Some(s) => tx.core.states.insert(k.clone(), s),
        None => tx.core.states.remove(&k),
    };
    match cached.1 {
        Some(p) => tx.core.pages.insert(k, p),
        None => tx.core.pages.remove(&k),
    };
    osis_base::costs::paused(|| {
        let ix = &tx.core.ix.groups;
        debug_assert_eq!(ix.def(g), whole, "the group index of {g:?} refreshed from a join differs from its whole state");
        ix.check_around(g);
    });
    Ok(())
}

impl Engine {
    /// Groups containing the thing, transitively (`groups.0`).
    pub fn groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.ix.groups.groups_of(tid)
    }

    /// The groups whose closure holds the thing (spec/sync.md §3): itself, the groups containing
    /// it, and the groups above it through subgroup lists.
    pub fn enclosing(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.ix.groups.enclosing(tid)
    }

    /// The groups whose `group.0` lists the thing directly: (as an item, as a subgroup). From
    /// the in-memory group index, loaded from the definitions at open.
    pub fn listed_in(&self, tid: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        self.core.ix.groups.listed_in(tid)
    }
}

impl Engine {
    /// Whether `g`'s closure is known whole here: no group in it holds a part of its `group.0` as
    /// a header only (`partial_groups`), whose list may hold any thing (spec/sync.md §6).
    pub fn closure_whole(&mut self, g: &Tid) -> Result<bool> {
        let closure = self.closure(g);
        let missing = missing_groups(&self.core, |x| closure.contains(x))?;
        // no store read where nothing is missing (the usual case)
        if missing.is_empty() {
            return Ok(true);
        }
        self.read(|tx| Ok(partial_groups(tx, missing)?.is_empty()))
    }

    /// The groups whose `group.0` may list `t`, as an item and as a subgroup: what a delete of `t`
    /// removes it from (spec/crdt.md §5.5, §4.6). `listed_in`, and every group with a part of its
    /// `group.0` held as a header only (`header_only_parts`), in both: what that part lists is not
    /// known here.
    pub fn listing_groups(&mut self, t: &Tid) -> Result<(BTreeSet<Tid>, BTreeSet<Tid>)> {
        let t = *t;
        self.read(|tx| listing_groups(tx, &t))
    }
}

/// `Engine::listing_groups`.
pub(crate) fn listing_groups(tx: &mut super::Tx<'_>, t: &Tid) -> Result<(BTreeSet<Tid>, BTreeSet<Tid>)> {
    let (mut items, mut subs) = tx.core.ix.groups.listed_in(t);
    let missing = missing_groups(tx.core, |g| g != t && !(items.contains(g) && subs.contains(g)))?;
    for g in partial_groups(tx, missing)? {
        items.insert(g);
        subs.insert(g);
    }
    Ok((items, subs))
}

/// The groups `of` picks with a part of their `group.0` not held (`Hold::Missing`).
fn missing_groups(core: &super::Core, of: impl Fn(&Tid) -> bool) -> Result<Vec<Tid>> {
    let gak = group_ak()?;
    Ok(core.ix.missing.range((gak.clone(), Tid::from_bytes([0; 15]))..).take_while(|((ak, _), _)| *ak == gak).map(|((_, g), _)| *g).filter(|g| of(g)).collect())
}

/// Of `groups`, those holding a part of their `group.0` as a header only (`header_only_parts`):
/// what that part lists is not known here.
fn partial_groups(tx: &mut super::Tx<'_>, groups: Vec<Tid>) -> Result<Vec<Tid>> {
    let gak = group_ak()?;
    let mut out = Vec::new();
    for g in groups {
        if !header_only_parts(tx, &g, &gak)?.is_empty() {
            out.push(g);
        }
    }
    Ok(out)
}

fn group_ak() -> Result<Ak> {
    Ak::new(osis_schema::RawKey::ak(&osis_schema::core_types::GROUP)).map_err(|_| crate::error::Error::Misuse("ak"))
}

/// `w` for ops `ops` on aspect `(tid, ak)`: a removal of a tid among them covers the parts held
/// as headers only too (`header_only_parts`, spec/crdt.md §5.5).
pub(crate) fn seeing(tx: &mut super::Tx<'_>, tid: &Tid, ak: &Ak, ops: &[osis_crdt::PathOp], w: osis_crdt::Writer) -> Result<osis_crdt::Writer> {
    if !ops.iter().any(|o| matches!(o.op, osis_crdt::Op::Remove(Value::Tid(_)))) {
        return Ok(w);
    }
    Ok(w.seen_headers(header_only_parts(tx, tid, ak)?))
}

/// The parts of aspect `(tid, ak)` this node holds as headers only, by their dots (spec/crdt.md
/// §2.4): valid here, not received yet (`Hold::Missing`, but one forgotten with its released
/// thing), and not stamped below a held root reset, which leaves them nothing. What a removal of
/// a tid there covers beside the elements held (§5.5).
pub(crate) fn header_only_parts(tx: &mut super::Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<DotRange>> {
    let cs: Vec<CommitId> = tx.core.ix.missing.get(&(ak.clone(), *tid)).into_iter().flatten().copied().collect();
    if cs.is_empty() {
        return Ok(Vec::new());
    }
    // the root's reset, held whatever pages are loaded
    tx.load_lazy(tid, ak)?;
    let reset = tx.cached(tid, ak).and_then(Fragment::reset).map(|r| r.ts);
    let mut out = Vec::new();
    for c in cs {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let Some(a) = m.aspect(tid, ak).filter(|ai| m.valid_at(*ai) && m.missing(*ai) && m.missing_as(*ai) != Some(super::Missing::Forgot)).and_then(|ai| m.view.aspects.get(ai)) else { continue };
        if a.lo < a.hi && reset.is_none_or(|r| m.view.ts >= r) {
            out.push(DotRange { first: Dot::new(m.view.form.own_source(m.view.author, c), a.lo), hi: a.hi });
        }
    }
    Ok(out)
}

impl Engine {
    /// Whether a synced group carries `t`: a labeled group's closure holds it (`enclosing`).
    pub fn carried(&self, t: &Tid) -> bool {
        self.core.carried(t)
    }
}

impl super::Core {
    /// `Engine::carried`.
    pub(crate) fn carried(&self, t: &Tid) -> bool {
        self.ix.groups.enclosing(t).iter().any(|g| self.ix.labeled.contains(g))
    }

    /// Before group `g` stops listing the subgroups `cut`: those cut while a synced group
    /// carries `g` (`cut_subs`), whatever cut them (a write here or elsewhere, an expiry).
    pub(crate) fn note_cut(&mut self, g: &Tid, cut: &[Tid]) {
        if !cut.is_empty() && self.ix.groups.above(g).iter().any(|a| self.ix.labeled.contains(a)) {
            self.cut_subs.extend(cut.iter().copied());
        }
    }

    /// At the end of a transaction (before its journal is committed): the things the closures
    /// of the subgroups it cut held when it began (each subgroup itself included) that no synced
    /// group carries now, destroyed ones aside (`Engine::report_cut`).
    pub(crate) fn stranded_by_cut(&mut self) -> Vec<Tid> {
        let cut = std::mem::take(&mut self.cut_subs);
        if cut.is_empty() {
            return Vec::new();
        }
        let held = self.ix.groups.closures_at_start(&cut);
        held.into_iter().filter(|t| !self.carried(t) && !self.destroyed(t)).collect()
    }
}

impl Engine {
    /// After a transaction: a `NotSynced` diagnostic for each thing of `stranded`
    /// (`Core::stranded_by_cut`) that holds content (spec/requirements.md, Offline and network):
    /// it stays on this node. A deleted thing stays as nothing.
    pub(crate) fn report_cut(&mut self, stranded: Vec<Tid>, now: osis_base::WallMs) {
        for t in stranded {
            if self.has_content(&t).unwrap_or(true) {
                let detail = "a subgroup left the synced group that held it: this stays on this node".into();
                self.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::NotSynced, tids: vec![t], commit: None, peer: None, detail }, now);
            }
        }
    }
}

/// A listing edit of a group: (field, tid, listed after).
pub(crate) type Edit = (u64, Tid, bool);

/// An edit of the index as it was before (`Journaled`): a group defined or not, a tid listed in
/// a group's field or not.
#[derive(Clone, Copy, Debug)]
enum Logged {
    Defined(Tid, bool),
    Listed(Tid, u64, Tid, bool),
}

/// The `group.0` index (spec/data-model.md §8), kept by membership edits, each O(the change)
/// (spec/requirements.md Scale): the groups defined, each group's items and subgroups and the
/// reverse of both. What derives from it is walked when asked (`above`, `groups_of`,
/// `enclosing`, a closure the first time); closures asked for are kept and edited in place.
#[derive(Default)]
pub struct Groups {
    /// Groups with a `group.0` state.
    defined: BTreeSet<Tid>,
    /// Group -> its items.
    items: Edges,
    /// Thing -> the groups listing it as an item.
    item_of: Edges,
    /// Group -> its subgroups.
    subs: Edges,
    /// Subgroup -> the groups listing it.
    parents: Edges,
    /// Closures asked for (`closure`, spec/sync.md §3), edited in place as they change: the same
    /// `Arc` while unchanged, so node-sync reuses what it derived from it (`Arc::ptr_eq`). One
    /// still held elsewhere is copied by its first change.
    closures: Mutex<BTreeMap<Tid, Arc<BTreeSet<Tid>>>>,
    /// Edits made by the running transaction (`Journaled`).
    log: Vec<Logged>,
    /// Things whose `groups_of` answer the running transaction changed, and groups whose
    /// closure it changed (`Event::Groups`).
    pub(crate) moved: BTreeSet<Tid>,
    /// Stamps the index as one (`osis_base::memo`): every read reads it whole, every change of
    /// a listing or a definition moves it.
    stamps: osis_base::memo::Stamps,
}

impl Clone for Groups {
    fn clone(&self) -> Groups {
        Groups {
            defined: self.defined.clone(),
            items: self.items.clone(),
            item_of: self.item_of.clone(),
            subs: self.subs.clone(),
            parents: self.parents.clone(),
            closures: Mutex::new(self.kept().clone()),
            log: self.log.clone(),
            moved: self.moved.clone(),
            stamps: self.stamps.clone(),
        }
    }
}

/// The index's contents (`Core::same_index`, the index check); kept closures and the journal
/// aside.
impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groups").field("defined", &self.defined).field("items", &self.items).field("item_of", &self.item_of).field("subs", &self.subs).field("parents", &self.parents).finish()
    }
}

/// The index's contents, as `Debug` shows them.
impl PartialEq for Groups {
    fn eq(&self, o: &Groups) -> bool {
        (&self.defined, &self.items, &self.item_of, &self.subs, &self.parents) == (&o.defined, &o.items, &o.item_of, &o.subs, &o.parents)
    }
}

/// Tid -> tids: one direction of a listing.
type Edges = BTreeMap<Tid, BTreeSet<Tid>>;

/// The bounds of a range over every tid.
const TID_MIN: Tid = Tid::from_bytes([0; 15]);
const TID_MAX: Tid = Tid::from_bytes([0xff; 15]);

impl Groups {
    fn kept(&self) -> MutexGuard<'_, BTreeMap<Tid, Arc<BTreeSet<Tid>>>> {
        self.closures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The listing of field `f` (`ITEMS` or `SUBGROUPS`): group -> tids, tid -> groups.
    fn maps(&self, f: u64) -> (&Edges, &Edges) {
        if f == ITEMS { (&self.items, &self.item_of) } else { (&self.subs, &self.parents) }
    }

    /// Whether `g` has a `group.0` state.
    pub(crate) fn is_defined(&self, g: &Tid) -> bool {
        self.stamps.read_all();
        self.defined.contains(g)
    }

    /// The groups with a `group.0` state.
    pub(crate) fn defined(&self) -> impl Iterator<Item = &Tid> {
        self.stamps.read_all();
        self.defined.iter()
    }

    /// Whether `g`'s field `f` lists `t`.
    pub(crate) fn listed(&self, g: &Tid, f: u64, t: &Tid) -> bool {
        self.stamps.read_all();
        self.maps(f).0.get(g).is_some_and(|s| s.contains(t))
    }

    /// What `g`'s field `f` lists.
    pub(crate) fn listing(&self, g: &Tid, f: u64) -> impl Iterator<Item = &Tid> {
        self.stamps.read_all();
        self.maps(f).0.get(g).into_iter().flatten()
    }

    /// `g`'s whole definition: O(the group), for checks.
    pub(crate) fn def(&self, g: &Tid) -> Option<Def> {
        self.defined.contains(g).then(|| (self.listing(g, ITEMS).copied().collect(), self.listing(g, SUBGROUPS).copied().collect()))
    }

    /// The groups listing `t` directly: (as an item, as a subgroup).
    pub(crate) fn listed_in(&self, t: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        self.stamps.read_all();
        let of = |m: &Edges| m.get(t).cloned().unwrap_or_default();
        (of(&self.item_of), of(&self.parents))
    }

    /// Lists or unlists `t` in `g`'s field `f`, both ways; whether that changed it.
    fn link(&mut self, g: Tid, f: u64, t: Tid, on: bool) -> bool {
        let stamps = &self.stamps;
        let (fwd, rev) = if f == ITEMS { (&mut self.items, &mut self.item_of) } else { (&mut self.subs, &mut self.parents) };
        if on {
            if !fwd.entry(g).or_default().insert(t) {
                return false;
            }
            rev.entry(t).or_default().insert(g);
            stamps.moved();
            return true;
        }
        let Some(s) = fwd.get_mut(&g) else { return false };
        if !s.remove(&t) {
            return false;
        }
        stamps.moved();
        if s.is_empty() {
            fwd.remove(&g);
        }
        if let Some(r) = rev.get_mut(&t) {
            r.remove(&g);
            if r.is_empty() {
                rev.remove(&t);
            }
        }
        true
    }

    /// `g` and every group above it through subgroup lists.
    pub(crate) fn above(&self, g: &Tid) -> BTreeSet<Tid> {
        self.stamps.read_all();
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                stack.extend(self.parents.get(&x).into_iter().flatten().copied());
            }
        }
        osis_base::costs::count("group index", seen.len() as u64);
        seen
    }

    /// The groups containing `t` (`groups.0`): above each group listing it as an item.
    pub(crate) fn groups_of(&self, t: &Tid) -> BTreeSet<Tid> {
        self.stamps.read_all();
        self.item_of.get(t).into_iter().flatten().flat_map(|g| self.above(g)).collect()
    }

    /// The groups whose closure holds `t`: `t`, the groups containing it and those above it.
    pub(crate) fn enclosing(&self, t: &Tid) -> BTreeSet<Tid> {
        let mut out = self.above(t);
        out.extend(self.groups_of(t));
        out
    }

    /// The closure of `g` (spec/sync.md §3) by `listing` (a group's field): `g`, the subgroups it
    /// reaches and their items.
    fn reach_by(&self, g: &Tid, listing: &dyn Fn(&Tid, u64) -> Vec<Tid>) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                out.extend(listing(&x, ITEMS));
                stack.extend(listing(&x, SUBGROUPS));
            }
        }
        osis_base::costs::count("group index", (seen.len() + out.len()) as u64);
        out.extend(seen);
        out
    }

    fn reach(&self, g: &Tid) -> BTreeSet<Tid> {
        self.reach_by(g, &|x, f| self.listing(x, f).copied().collect())
    }

    /// The closure of `g`: itself, its subgroups and every thing it contains, transitively.
    /// Derived the first time it is asked for (O(the closure)), then kept.
    pub fn closure(&self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        self.stamps.read_all();
        if let Some(c) = self.kept().get(g) {
            return c.clone();
        }
        let c = Arc::new(self.reach(g));
        self.kept().insert(*g, c.clone());
        c
    }

    /// The closures of `gs` when the running transaction began (its edits undone), together.
    pub(crate) fn closures_at_start(&self, gs: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut was: BTreeMap<(Tid, u64, Tid), bool> = BTreeMap::new();
        for e in &self.log {
            if let Logged::Listed(g, f, t, on) = e {
                was.entry((*g, *f, *t)).or_insert(*on);
            }
        }
        let listing = |x: &Tid, f: u64| -> Vec<Tid> {
            let mut l: BTreeSet<Tid> = self.listing(x, f).copied().collect();
            for ((_, _, t), on) in was.range((*x, f, TID_MIN)..=(*x, f, TID_MAX)) {
                if *on {
                    l.insert(*t);
                } else {
                    l.remove(t);
                }
            }
            l.into_iter().collect()
        };
        gs.iter().flat_map(|g| self.reach_by(g, &listing)).collect()
    }

    /// Makes `edits` (each a change) to `g`'s listing and what derives from it: `moved` and the
    /// kept closures. The things whose enclosing groups may change are the tids edited and the
    /// closure of each subgroup edited, as it was: every edge edited starts at `g`, so what an
    /// added edge makes reachable is an edited tid or under an edited subgroup already.
    fn apply(&mut self, g: Tid, edits: &[Edit]) {
        let mut xs = BTreeSet::new();
        for (f, t, _) in edits {
            xs.insert(*t);
            if *f == SUBGROUPS {
                xs.extend(self.reach(t));
            }
        }
        let before: Vec<(Tid, BTreeSet<Tid>)> = xs.into_iter().map(|x| (x, self.enclosing(&x))).collect();
        for (f, t, on) in edits {
            if self.link(g, *f, *t, *on) {
                self.moved.insert(*t);
            }
        }
        let after: Vec<BTreeSet<Tid>> = before.iter().map(|(x, _)| self.enclosing(x)).collect();
        let mut moved = Vec::new();
        let kept = self.closures.get_mut().unwrap_or_else(PoisonError::into_inner);
        for ((x, was), now) in before.iter().zip(&after) {
            for a in was.symmetric_difference(now) {
                // `x` entered or left `a`'s closure; what `a` holds is an answer too
                moved.extend([*x, *a]);
                if let Some(c) = kept.get_mut(a) {
                    let c = Arc::make_mut(c);
                    if now.contains(a) {
                        c.insert(*x);
                    } else {
                        c.remove(x);
                    }
                }
            }
        }
        self.moved.extend(moved);
        // every path that edits the index (a refresh, a whole set, a rolled-back step)
        #[cfg(debug_assertions)]
        osis_base::costs::paused(|| self.check_around(&g));
    }

    /// Edits `g`'s listing (`refresh`: per tid), logged.
    pub(crate) fn change(&mut self, g: Tid, edits: &[Edit]) {
        let edits: Vec<Edit> = edits.iter().filter(|(f, t, on)| self.listed(&g, *f, t) != *on).copied().collect();
        osis_base::costs::count("group index", edits.len() as u64);
        self.log.extend(edits.iter().map(|(f, t, on)| Logged::Listed(g, *f, *t, !on)));
        self.apply(g, &edits);
    }

    /// Notes `g` defined or not, logged.
    fn define(&mut self, g: Tid, on: bool) {
        let was = self.defined.contains(&g);
        if was != on {
            self.stamps.moved();
            self.log.push(Logged::Defined(g, was));
            if on {
                self.defined.insert(g);
            } else {
                self.defined.remove(&g);
            }
        }
    }

    /// Sets (or with `None` removes) the whole definition of `g`, from a whole read: O(the
    /// group).
    pub fn set(&mut self, g: Tid, def: Option<Def>) {
        let (items, subs) = def.as_ref().map_or((None, None), |d| (Some(&d.0), Some(&d.1)));
        let mut edits = Vec::new();
        for (f, now) in [(ITEMS, items), (SUBGROUPS, subs)] {
            edits.extend(self.listing(&g, f).filter(|t| !now.is_some_and(|n| n.contains(*t))).map(|t| (f, *t, false)));
            edits.extend(now.into_iter().flatten().filter(|t| !self.listed(&g, f, t)).map(|t| (f, *t, true)));
        }
        self.define(g, def.is_some());
        self.change(g, &edits);
    }

    /// At open (`load`): `g` listing `items` and `subs` besides what it lists already, and with
    /// `defined` defined; not logged, nothing told.
    pub(crate) fn load<'a>(&mut self, g: Tid, defined: bool, items: impl Iterator<Item = &'a Tid>, subs: impl Iterator<Item = &'a Tid>) {
        if defined && self.defined.insert(g) {
            self.stamps.moved();
        }
        let mut n = 0;
        for (f, t) in items.map(|t| (ITEMS, t)).chain(subs.map(|t| (SUBGROUPS, t))) {
            self.link(g, f, *t, true);
            n += 1;
        }
        osis_base::costs::count("group index", n);
    }

    /// Debug builds: each tid `g` lists lists `g` back, and every kept closure of a group above
    /// `g` equals one derived anew.
    #[cfg(debug_assertions)]
    pub(crate) fn check_around(&self, g: &Tid) {
        for f in [ITEMS, SUBGROUPS] {
            for t in self.listing(g, f) {
                debug_assert!(self.maps(f).1.get(t).is_some_and(|r| r.contains(g)), "the group index of {g:?}: {t:?} is not listed back");
            }
        }
        let kept: Vec<(Tid, Arc<BTreeSet<Tid>>)> = self.above(g).into_iter().filter_map(|a| self.kept().get(&a).map(|c| (a, c.clone()))).collect();
        for (a, c) in kept {
            debug_assert_eq!(*c, self.reach(&a), "the kept closure of {a:?} differs from one derived anew");
        }
    }
}

impl super::journal::Journaled for Groups {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?} {:?}", self.defined, self.items, self.item_of, self.subs, self.parents)
    }
    type Mark = (usize, BTreeSet<Tid>);
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> Self::Mark {
        (self.log.len(), self.moved.clone())
    }
    fn rollback_to(&mut self, (m, moved): Self::Mark) {
        while self.log.len() > m {
            match self.log.pop() {
                Some(Logged::Defined(g, was)) => {
                    self.stamps.moved();
                    if was {
                        self.defined.insert(g);
                    } else {
                        self.defined.remove(&g);
                    }
                }
                Some(Logged::Listed(g, f, t, was)) => self.apply(g, &[(f, t, was)]),
                None => break,
            }
        }
        // a change rolled back is told by no event; the transaction's earlier steps still are
        self.moved = moved;
    }
}

#[cfg(test)]
mod tests {
    use super::{Def, Groups, ITEMS, SUBGROUPS};
    use crate::engine::journal::Journaled;
    use osis_base::Tid;
    use osis_crypto::{RngCore, SeededRng};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    fn t(n: u8) -> Tid {
        Tid::from_bytes([n; 15])
    }

    /// The reference, from the definitions alone: each group's closure (spec/sync.md §3: the
    /// group, its subgroups at any depth and their items) and each thing's containing groups.
    struct Naive {
        closure: BTreeMap<Tid, BTreeSet<Tid>>,
        of: BTreeMap<Tid, BTreeSet<Tid>>,
    }

    fn naive(defs: &BTreeMap<Tid, Def>, all: &[Tid]) -> Naive {
        let mut closure = BTreeMap::new();
        let mut of: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        for a in all {
            let (mut items, mut seen) = (BTreeSet::new(), BTreeSet::new());
            let mut stack = vec![*a];
            while let Some(x) = stack.pop() {
                if seen.insert(x) && let Some((i, s)) = defs.get(&x) {
                    items.extend(i.iter().copied());
                    stack.extend(s.iter().copied());
                }
            }
            for x in &items {
                of.entry(*x).or_default().insert(*a);
            }
            items.extend(seen);
            closure.insert(*a, items);
        }
        Naive { closure, of }
    }

    /// Every answer of `g` equals the reference's; `moved` holds exactly the things whose
    /// listing or containing groups changed since `was` and the groups whose closure changed.
    fn check(g: &Groups, defs: &BTreeMap<Tid, Def>, all: &[Tid], was: &Naive, listed: &BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>) {
        let now = naive(defs, all);
        let mut moved = BTreeSet::new();
        for x in all {
            let of = now.of.get(x).cloned().unwrap_or_default();
            assert_eq!(g.groups_of(x), of);
            let enclosing: BTreeSet<Tid> = all.iter().filter(|a| now.closure[*a].contains(x)).copied().collect();
            assert_eq!(g.enclosing(x), enclosing);
            assert_eq!(*g.closure(x), now.closure[x]);
            let l = (defs.iter().filter(|(_, d)| d.0.contains(x)).map(|(a, _)| *a).collect(), defs.iter().filter(|(_, d)| d.1.contains(x)).map(|(a, _)| *a).collect());
            assert_eq!(g.listed_in(x), l);
            if listed.get(x) != Some(&l) || was.closure[x] != now.closure[x] || all.iter().any(|a| was.closure[a].contains(x) != now.closure[a].contains(x)) {
                moved.insert(*x);
            }
        }
        assert_eq!(g.moved, moved);
    }

    fn listings(defs: &BTreeMap<Tid, Def>, all: &[Tid]) -> BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)> {
        all.iter().map(|x| (*x, (defs.iter().filter(|(_, d)| d.0.contains(x)).map(|(a, _)| *a).collect(), defs.iter().filter(|(_, d)| d.1.contains(x)).map(|(a, _)| *a).collect()))).collect()
    }

    // spec/data-model.md §8, spec/sync.md §3: the index kept by edits (whole sets, per-tid edits,
    // rolled-back steps; cycles allowed) answers as a derivation from scratch: `groups.0`,
    // listings, closures (kept ones edited in place; an unchanged one the same `Arc`) and what
    // a step tells moved.
    #[test]
    fn incremental_groups_spec_data_model_8() {
        let mut rng = SeededRng::from_u64(0);
        let all: Vec<Tid> = (0..12).chain(20..32).map(t).collect();
        let mut g = Groups::default();
        let mut defs: BTreeMap<Tid, Def> = BTreeMap::new();
        let n = |rng: &mut SeededRng| (rng.next_u32() % 12) as u8;
        // an item: a plain thing, or a quarter of the time a group (its contents stay out)
        let item = |rng: &mut SeededRng| t(n(rng) + if rng.next_u32().is_multiple_of(4) { 0 } else { 20 });
        for step in 0..600 {
            let (was, listed) = (naive(&defs, &all), listings(&defs, &all));
            // closures asked for before (kept), some still held
            let held: Vec<(Tid, Arc<BTreeSet<Tid>>)> = (0..3).map(|_| t(n(&mut rng))).map(|a| (a, g.closure(&a))).collect();
            g.moved.clear();
            let k = t(n(&mut rng));
            let rollback = step % 7 == 3;
            let mark = g.mark();
            let saved = defs.clone();
            match n(&mut rng) {
                0 | 1 => {
                    defs.remove(&k);
                    g.set(k, None);
                }
                2..=6 => {
                    let items: BTreeSet<Tid> = (0..n(&mut rng) % 4).map(|_| item(&mut rng)).collect();
                    let subs: BTreeSet<Tid> = (0..n(&mut rng) % 3).map(|_| t(n(&mut rng))).collect();
                    defs.insert(k, (items.clone(), subs.clone()));
                    g.set(k, Some((items, subs)));
                }
                _ if defs.contains_key(&k) => {
                    let (f, x) = if n(&mut rng) % 2 == 0 { (ITEMS, item(&mut rng)) } else { (SUBGROUPS, t(n(&mut rng))) };
                    let on = n(&mut rng) % 2 == 0;
                    let d = defs.get_mut(&k).unwrap();
                    let s = if f == ITEMS { &mut d.0 } else { &mut d.1 };
                    if on {
                        s.insert(x);
                    } else {
                        s.remove(&x);
                    }
                    g.change(k, &[(f, x, on)]);
                }
                _ => {}
            }
            if rollback {
                g.rollback_to(mark);
                defs = saved;
                g.moved.clear();
                check(&g, &defs, &all, &naive(&defs, &all), &listed);
            } else {
                check(&g, &defs, &all, &was, &listed);
                g.commit();
                for (a, c) in held {
                    assert_eq!(Arc::ptr_eq(&c, &g.closure(&a)), *c == *g.closure(&a), "an unchanged closure is the same Arc");
                }
            }
            assert_eq!(g.defined().copied().collect::<BTreeSet<_>>(), defs.keys().copied().collect());
        }
    }
}
