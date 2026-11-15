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
/// Not a `group.0` field: the things an actor with secrets of its own is the key home of
/// (`Core::key_home`), which its closure holds as items (spec/sync-set.md §2). Kept by
/// `Core::rehome`, never by a `group.0` write; `groups_of` and `listed_in` leave it out.
pub(crate) const DERIVED: u64 = 2;

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

    /// The groups whose closure holds the thing (spec/sync-set.md §2): itself, the groups containing
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
    /// a header only (`partial_groups`), whose list may hold any thing (spec/sync-judgement.md §2).
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
    /// Whether a synced group carries `t`: the closure of a group with a sync ID holds it (`enclosing`).
    pub fn carried(&self, t: &Tid) -> bool {
        self.core.carried(t)
    }
}

impl super::Core {
    /// `t`'s **key home** (spec/sync-set.md §2): the nearest thing above `t` on its record chain
    /// with secrets of its own. While `t` is plain it is the actor `t`'s secrets derive from
    /// (`secret_actor`); it stays so once `t` has secrets of its own (spec/permissions.md §3, Own
    /// secrets add only). `None` where the chain ends first (a key actor, a record not held, too
    /// deep).
    pub(crate) fn derive_home(&self, t: &Tid) -> Option<Tid> {
        for step in self.record_chain(t).skip(1) {
            // a key actor is no key home, whatever keys it has
            let osis_base::ChainStep::Up { thing, .. } = step else { return None };
            if self.ix.own_keys.contains(&thing) {
                return Some(thing);
            }
        }
        None
    }

    /// Derives again the key homes (`Groups::set_home`) a change at each of `roots` (its record
    /// held or forgotten, its secrets of its own gained or lost) may move: its own, and those of
    /// the things below it on record chains through things without secrets of their own. O(the
    /// things walked times their chain depth); none below a key actor, whose children have no key
    /// home through it.
    pub(crate) fn rehome(&mut self, roots: &[Tid]) {
        let mut stack: Vec<Tid> = roots.to_vec();
        let mut seen = BTreeSet::new();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            let h = self.derive_home(&x);
            self.ix.groups.set_home(x, h);
            let own = self.ix.own_keys.contains(&x);
            let key = self.ix.held.created(&x).is_some_and(|r| r.first_admin().is_none());
            if (roots.contains(&x) || !own) && (own || !key) {
                stack.extend(self.ix.held.first_admin_of(&x).copied());
            }
        }
        osis_base::costs::count("group index: rehome", seen.len() as u64);
    }

    /// `Engine::carried`.
    pub(crate) fn carried(&self, t: &Tid) -> bool {
        self.ix.groups.enclosing(t).iter().any(|g| self.ix.sync_recorded.contains(g))
    }

    /// Before group `g` stops listing the subgroups `cut`: those cut while a synced group
    /// carries `g` (`cut_subs`), whatever cut them (a write here or elsewhere, an expiry).
    pub(crate) fn note_cut(&mut self, g: &Tid, cut: &[Tid]) {
        if !cut.is_empty() && self.ix.groups.above(g).iter().any(|a| self.ix.sync_recorded.contains(a)) {
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
    /// Key home -> the things it is the key home of (`DERIVED`).
    derived: Edges,
    /// Thing -> its key home (one at most).
    home: Edges,
    /// Closures asked for (`closure`, spec/sync-set.md §2), edited in place as they change: the same
    /// `Arc` while unchanged, so node-sync reuses what it derived from it (`Arc::ptr_eq`). One
    /// still held elsewhere is copied by its first change.
    closures: Mutex<BTreeMap<Tid, Arc<BTreeSet<Tid>>>>,
    /// The groups a sync closure walks no path through (`set_cut`: groups sourced at another
    /// node, spec/sync-set.md §5). Not journaled: set between transactions.
    cut: BTreeSet<Tid>,
    /// Sync closures asked for (`sync_closure`) while `cut` is not empty, edited in place as
    /// `closures` are; while it is empty a sync closure is the closure.
    cut_closures: Mutex<BTreeMap<Tid, Arc<BTreeSet<Tid>>>>,
    /// Edits made by the running transaction (`Journaled`).
    log: Vec<Logged>,
    /// Things whose `groups_of` answer the running transaction changed, and groups whose
    /// closure it changed (`Event::Groups`).
    pub(crate) moved: BTreeSet<Tid>,
    /// Stamps the index per row read (`Row`): a change moves what read the rows it changed.
    stamps: osis_base::memo::Stamps,
}

/// A row of `Groups` as its stamps name it: a reader of one moves only with it.
#[derive(Hash)]
enum Row {
    /// Whether a group is defined.
    Defined(Tid),
    /// A group's listing of a field.
    Listing(Tid, u64),
    /// The groups listing a tid in a field.
    ListedIn(Tid, u64),
    /// A group's closure, read whole.
    Closure(Tid),
    /// A group's sync closure (`sync_closure`), read whole.
    SyncClosure(Tid),
    /// Whether a group's closure holds a tid.
    Member(Tid, Tid),
}

/// A group's closure as handed out (`Groups::closure_of`): read tid by tid as it is used, so
/// what asks whether it holds a tid moves only when that answer does; walked, it is read whole.
pub struct Closure {
    group: Tid,
    set: Arc<BTreeSet<Tid>>,
    reads: osis_base::memo::Reader,
}

impl Closure {
    pub fn contains(&self, t: &Tid) -> bool {
        self.reads.read(&Row::Member(self.group, *t));
        self.set.contains(t)
    }
    pub fn iter(&self) -> impl Iterator<Item = &Tid> {
        self.reads.read(&Row::Closure(self.group));
        self.set.iter()
    }
}

impl Clone for Groups {
    fn clone(&self) -> Groups {
        Groups {
            defined: self.defined.clone(),
            items: self.items.clone(),
            item_of: self.item_of.clone(),
            subs: self.subs.clone(),
            parents: self.parents.clone(),
            derived: self.derived.clone(),
            home: self.home.clone(),
            closures: Mutex::new(self.kept().clone()),
            cut: self.cut.clone(),
            cut_closures: Mutex::new(self.kept_cut().clone()),
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
        f.debug_struct("Groups").field("defined", &self.defined).field("items", &self.items).field("item_of", &self.item_of).field("subs", &self.subs).field("parents", &self.parents).field("derived", &self.derived).field("home", &self.home).finish()
    }
}

/// The index's contents, as `Debug` shows them.
impl PartialEq for Groups {
    fn eq(&self, o: &Groups) -> bool {
        (&self.defined, &self.items, &self.item_of, &self.subs, &self.parents, &self.derived, &self.home) == (&o.defined, &o.items, &o.item_of, &o.subs, &o.parents, &o.derived, &o.home)
    }
}

/// Tid -> tids: one direction of a listing.
type Edges = BTreeMap<Tid, BTreeSet<Tid>>;

/// `x` entered (`on`) or left kept closure `a`, if `a` is kept (one still held elsewhere is
/// copied first).
fn edit_kept(kept: &mut BTreeMap<Tid, Arc<BTreeSet<Tid>>>, a: &Tid, x: &Tid, on: bool) {
    if let Some(c) = kept.get_mut(a) {
        let c = Arc::make_mut(c);
        if on {
            c.insert(*x);
        } else {
            c.remove(x);
        }
    }
}

/// The bounds of a range over every tid.
const TID_MIN: Tid = Tid::from_bytes([0; 15]);
const TID_MAX: Tid = Tid::from_bytes([0xff; 15]);

impl Groups {
    fn kept(&self) -> MutexGuard<'_, BTreeMap<Tid, Arc<BTreeSet<Tid>>>> {
        self.closures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn kept_cut(&self) -> MutexGuard<'_, BTreeMap<Tid, Arc<BTreeSet<Tid>>>> {
        self.cut_closures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The listing of field `f` (`ITEMS`, `SUBGROUPS` or `DERIVED`): group -> tids, tid -> groups.
    fn maps(&self, f: u64) -> (&Edges, &Edges) {
        match f {
            ITEMS => (&self.items, &self.item_of),
            SUBGROUPS => (&self.subs, &self.parents),
            _ => (&self.derived, &self.home),
        }
    }

    /// Whether `g` has a `group.0` state.
    pub(crate) fn is_defined(&self, g: &Tid) -> bool {
        self.stamps.read(&Row::Defined(*g));
        self.defined.contains(g)
    }

    /// The groups with a `group.0` state.
    pub(crate) fn defined(&self) -> impl Iterator<Item = &Tid> {
        self.stamps.read_all();
        self.defined.iter()
    }

    /// Whether `g`'s field `f` lists `t`.
    pub(crate) fn listed(&self, g: &Tid, f: u64, t: &Tid) -> bool {
        self.stamps.read(&Row::Listing(*g, f));
        self.maps(f).0.get(g).is_some_and(|s| s.contains(t))
    }

    /// What `g`'s field `f` lists.
    pub(crate) fn listing(&self, g: &Tid, f: u64) -> impl Iterator<Item = &Tid> {
        self.stamps.read(&Row::Listing(*g, f));
        self.maps(f).0.get(g).into_iter().flatten()
    }

    /// `g`'s whole definition: O(the group), for checks.
    pub(crate) fn def(&self, g: &Tid) -> Option<Def> {
        self.is_defined(g).then(|| (self.listing(g, ITEMS).copied().collect(), self.listing(g, SUBGROUPS).copied().collect()))
    }

    /// The groups listing `t` directly: (as an item, as a subgroup).
    pub(crate) fn listed_in(&self, t: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        self.stamps.read(&Row::ListedIn(*t, ITEMS));
        self.stamps.read(&Row::ListedIn(*t, SUBGROUPS));
        let of = |m: &Edges| m.get(t).cloned().unwrap_or_default();
        (of(&self.item_of), of(&self.parents))
    }

    /// Lists or unlists `t` in `g`'s field `f`, both ways; whether that changed it.
    fn link(&mut self, g: Tid, f: u64, t: Tid, on: bool) -> bool {
        let stamps = &self.stamps;
        let (fwd, rev) = match f {
            ITEMS => (&mut self.items, &mut self.item_of),
            SUBGROUPS => (&mut self.subs, &mut self.parents),
            _ => (&mut self.derived, &mut self.home),
        };
        if on {
            if !fwd.entry(g).or_default().insert(t) {
                return false;
            }
            rev.entry(t).or_default().insert(g);
            stamps.wrote(&Row::Listing(g, f), true);
            stamps.wrote(&Row::ListedIn(t, f), true);
            return true;
        }
        let Some(s) = fwd.get_mut(&g) else { return false };
        if !s.remove(&t) {
            return false;
        }
        stamps.wrote(&Row::Listing(g, f), true);
        stamps.wrote(&Row::ListedIn(t, f), true);
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
        self.above_avoiding(g, &BTreeSet::new())
    }

    /// `above`, through no group of `cut` (none when `g` is one).
    fn above_avoiding(&self, g: &Tid, cut: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if !cut.contains(&x) && seen.insert(x) {
                self.stamps.read(&Row::ListedIn(x, SUBGROUPS));
                stack.extend(self.parents.get(&x).into_iter().flatten().copied());
            }
        }
        osis_base::costs::count("group index", seen.len() as u64);
        seen
    }

    /// The groups containing `t` (`groups.0`): above each group listing it as an item.
    pub(crate) fn groups_of(&self, t: &Tid) -> BTreeSet<Tid> {
        self.stamps.read(&Row::ListedIn(*t, ITEMS));
        self.item_of.get(t).into_iter().flatten().flat_map(|g| self.above(g)).collect()
    }

    /// The groups whose closure holds `t`: for `t` and each key home up its chain (`homes`),
    /// that thing, the groups containing it and those above them.
    pub(crate) fn enclosing(&self, t: &Tid) -> BTreeSet<Tid> {
        self.enclosing_avoiding(t, &BTreeSet::new())
    }

    /// `enclosing` by paths through no thing of `cut`: the groups whose sync closure holds `t`
    /// (`sync_closure`) when `cut` is the index's.
    fn enclosing_avoiding(&self, t: &Tid, cut: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        for h in self.homes(t) {
            if cut.contains(&h) {
                break;
            }
            out.extend(self.above_avoiding(&h, cut));
            self.stamps.read(&Row::ListedIn(h, ITEMS));
            for g in self.item_of.get(&h).into_iter().flatten() {
                out.extend(self.above_avoiding(g, cut));
            }
        }
        out
    }

    /// `t` and its key homes up the chain (`DERIVED` upward), each once.
    fn homes(&self, t: &Tid) -> Vec<Tid> {
        let mut out = vec![*t];
        while let Some(h) = out.last().and_then(|x| self.key_home(x)) {
            if out.contains(&h) {
                break;
            }
            out.push(h);
        }
        out
    }

    /// The key home `t` is indexed under (`DERIVED`), if any.
    pub(crate) fn key_home(&self, t: &Tid) -> Option<Tid> {
        self.stamps.read(&Row::ListedIn(*t, DERIVED));
        self.home.get(t).and_then(|h| h.first()).copied()
    }

    /// The closure of `g` (spec/sync-set.md §2) by `listing` (a group's field): `g`, the subgroups it
    /// reaches, their items, and below each of these the things it is the key home of
    /// (`DERIVED`), transitively.
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
        let roots: Vec<Tid> = out.iter().copied().collect();
        out.extend(Self::below_by(&roots, listing));
        out
    }

    /// The things below `roots` by key-home edges (`DERIVED`), transitively, by `listing`.
    fn below_by(roots: &[Tid], listing: &dyn Fn(&Tid, u64) -> Vec<Tid>) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<Tid> = roots.iter().flat_map(|x| listing(x, DERIVED)).collect();
        while let Some(x) = stack.pop() {
            if out.insert(x) {
                stack.extend(listing(&x, DERIVED));
            }
        }
        osis_base::costs::count("group index: key homes", out.len() as u64);
        out
    }

    fn reach(&self, g: &Tid) -> BTreeSet<Tid> {
        self.reach_by(g, &|x, f| self.listing(x, f).copied().collect())
    }

    /// `reach` through no thing of `cut` (nothing when `g` is one).
    fn reach_avoiding(&self, g: &Tid, cut: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        if cut.contains(g) {
            return BTreeSet::new();
        }
        self.reach_by(g, &|x, f| self.listing(x, f).filter(|t| !cut.contains(*t)).copied().collect())
    }

    /// The closure of `g`: itself, its subgroups and every thing it contains, transitively.
    /// Derived the first time it is asked for (O(the closure)), then kept.
    pub fn closure(&self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        self.stamps.read(&Row::Closure(*g));
        self.kept_closure(g)
    }

    /// The closure of `g` read as it is used (`Closure`).
    pub fn closure_of(&self, g: &Tid) -> Closure {
        Closure { group: *g, set: self.kept_closure(g), reads: self.stamps.reader() }
    }

    fn kept_closure(&self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        if let Some(c) = self.kept().get(g) {
            return c.clone();
        }
        let c = Arc::new(self.reach(g));
        self.kept().insert(*g, c.clone());
        c
    }

    /// The closure of `g` walked through no group of the cut (`set_cut`; spec/sync-set.md §5: a
    /// group sourced at another node, and what the closure reaches only through it, is left
    /// out). The closure itself while nothing is cut; else derived the first time it is asked for
    /// (O(the closure)), then kept and edited in place as closures are.
    pub fn sync_closure(&self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        self.stamps.read(&Row::SyncClosure(*g));
        if self.cut.is_empty() {
            return self.kept_closure(g);
        }
        if let Some(c) = self.kept_cut().get(g) {
            return c.clone();
        }
        let c = Arc::new(self.reach_avoiding(g, &self.cut));
        self.kept_cut().insert(*g, c.clone());
        c
    }

    /// The groups the sync closure walks no path through (`sync_closure`).
    pub(crate) fn cut(&self) -> &BTreeSet<Tid> {
        &self.cut
    }

    /// Makes `cut` the groups the sync closure walks no path through, moving each sync closure
    /// it changes: O(what is below each group cut or uncut, times the groups above each).
    pub(crate) fn set_cut(&mut self, cut: BTreeSet<Tid>) {
        if cut == self.cut {
            return;
        }
        let mut xs = BTreeSet::new();
        for y in self.cut.symmetric_difference(&cut) {
            xs.insert(*y);
            xs.extend(self.reach(y));
        }
        let before: Vec<(Tid, BTreeSet<Tid>)> = xs.into_iter().map(|x| (x, self.enclosing_avoiding(&x, &self.cut))).collect();
        self.cut = cut;
        let after: Vec<BTreeSet<Tid>> = before.iter().map(|(x, _)| self.enclosing_avoiding(x, &self.cut)).collect();
        let kept = self.cut_closures.get_mut().unwrap_or_else(PoisonError::into_inner);
        if self.cut.is_empty() {
            kept.clear();
        }
        for ((x, was), now) in before.iter().zip(&after) {
            for a in was.symmetric_difference(now) {
                self.stamps.wrote(&Row::SyncClosure(*a), true);
                edit_kept(kept, a, x, now.contains(a));
            }
        }
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

    /// The `group.0` listings the running transaction changed: (group, field, tid, listed now),
    /// each once (`DERIVED` is no listing: no write files a thing there).
    pub(crate) fn changed(&self) -> Vec<(Tid, u64, Tid, bool)> {
        let mut was: BTreeMap<(Tid, u64, Tid), bool> = BTreeMap::new();
        for e in &self.log {
            if let Logged::Listed(g, f, t, on) = e
                && *f != DERIVED
            {
                was.entry((*g, *f, *t)).or_insert(*on);
            }
        }
        was.into_iter().filter(|((g, f, t), w)| self.listed(g, *f, t) != *w).map(|((g, f, t), w)| (g, f, t, !w)).collect()
    }

    /// Whether the closure of one of `roots` holds `t` (`enclosing`): O(the groups above `t`).
    pub(crate) fn under(&self, t: &Tid, roots: &BTreeSet<Tid>) -> bool {
        self.stamps.read_all();
        self.under_by(t, roots, &|f, x| self.maps(f).1.get(x).into_iter().flatten().copied().collect())
    }

    /// `under` as the index stood when the running transaction began (its edits undone), for
    /// each of `ts`: the journal is read once.
    pub(crate) fn under_at_start(&self, ts: &BTreeSet<Tid>, roots: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        self.stamps.read_all();
        let mut was: BTreeMap<(u64, Tid, Tid), bool> = BTreeMap::new();
        for e in &self.log {
            if let Logged::Listed(g, f, x, on) = e {
                was.entry((*f, *x, *g)).or_insert(*on);
            }
        }
        let listed_in = |f: u64, x: &Tid| -> Vec<Tid> {
            let mut l: BTreeSet<Tid> = self.maps(f).1.get(x).into_iter().flatten().copied().collect();
            for ((_, _, g), on) in was.range((f, *x, TID_MIN)..=(f, *x, TID_MAX)) {
                if *on {
                    l.insert(*g);
                } else {
                    l.remove(g);
                }
            }
            l.into_iter().collect()
        };
        ts.iter().filter(|t| self.under_by(t, roots, &listed_in)).copied().collect()
    }

    /// Whether `t` is one of `roots` or under one, by `listed_in` (field, tid -> the groups
    /// listing it there): walks up from `t` and the groups listing it as an item, and so from each key home up its chain (`DERIVED`).
    fn under_by(&self, t: &Tid, roots: &BTreeSet<Tid>, listed_in: &dyn Fn(u64, &Tid) -> Vec<Tid>) -> bool {
        let mut homes = vec![*t];
        while let Some(h) = homes.last().and_then(|x| listed_in(DERIVED, x).first().copied()) {
            if homes.contains(&h) {
                break;
            }
            homes.push(h);
        }
        let mut seen = BTreeSet::new();
        let mut stack: Vec<Tid> = homes.iter().flat_map(|h| listed_in(ITEMS, h)).collect();
        stack.extend(homes);
        while let Some(x) = stack.pop() {
            if roots.contains(&x) {
                return true;
            }
            if seen.insert(x) {
                stack.extend(listed_in(SUBGROUPS, &x));
            }
        }
        osis_base::costs::count("group index: walk up", seen.len() as u64);
        false
    }

    /// Makes `edits` (each a change, at its group) to the listings and what derives from them:
    /// `moved` and the kept closures, from the net change. The things whose enclosing groups may
    /// change are each tid edited with the things below it by key homes, and the closure of each
    /// subgroup edited, as it was: what an added edge makes reachable is its tid or under it
    /// already.
    fn apply(&mut self, edits: &[(Tid, Edit)]) {
        let mut xs = BTreeSet::new();
        for (_, (f, t, _)) in edits {
            xs.insert(*t);
            if *f == SUBGROUPS {
                xs.extend(self.reach(t));
            } else {
                xs.extend(Self::below_by(&[*t], &|x, f| self.listing(x, f).copied().collect()));
            }
        }
        let before: Vec<(Tid, BTreeSet<Tid>)> = xs.into_iter().map(|x| (x, self.enclosing(&x))).collect();
        // while something is cut, the sync closures move apart from the closures
        let cut = !self.cut.is_empty();
        let before_cut: Vec<BTreeSet<Tid>> = if cut { before.iter().map(|(x, _)| self.enclosing_avoiding(x, &self.cut)).collect() } else { Vec::new() };
        for (g, (f, t, on)) in edits {
            // a key home moving changes no `groups_of` answer: only closures it moves tell
            if self.link(*g, *f, *t, *on) && *f != DERIVED {
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
                self.stamps.wrote(&Row::Closure(*a), true);
                self.stamps.wrote(&Row::Member(*a, *x), true);
                if !cut {
                    self.stamps.wrote(&Row::SyncClosure(*a), true);
                }
                edit_kept(kept, a, x, now.contains(a));
            }
        }
        self.moved.extend(moved);
        if cut {
            let after_cut: Vec<BTreeSet<Tid>> = before.iter().map(|(x, _)| self.enclosing_avoiding(x, &self.cut)).collect();
            let kept = self.cut_closures.get_mut().unwrap_or_else(PoisonError::into_inner);
            for (((x, _), was), now) in before.iter().zip(&before_cut).zip(&after_cut) {
                for a in was.symmetric_difference(now) {
                    self.stamps.wrote(&Row::SyncClosure(*a), true);
                    edit_kept(kept, a, x, now.contains(a));
                }
            }
        }
        // every path that edits the index (a refresh, a whole set, a rolled-back step), each
        // group once: a whole set edits it per tid
        #[cfg(debug_assertions)]
        osis_base::costs::paused(|| edits.iter().map(|(g, _)| *g).collect::<BTreeSet<Tid>>().iter().for_each(|g| self.check_around(g)));
    }

    /// Edits `g`'s listing (`refresh`: per tid), logged.
    pub(crate) fn change(&mut self, g: Tid, edits: &[Edit]) {
        let edits: Vec<(Tid, Edit)> = edits.iter().filter(|(f, t, on)| self.listed(&g, *f, t) != *on).map(|e| (g, *e)).collect();
        self.edit(&edits);
    }

    /// Makes `edits`, logged.
    fn edit(&mut self, edits: &[(Tid, Edit)]) {
        osis_base::costs::count("group index", edits.len() as u64);
        self.log.extend(edits.iter().map(|(g, (f, t, on))| Logged::Listed(*g, *f, *t, !on)));
        self.apply(edits);
    }

    /// Indexes `t` under key home `h` (`DERIVED`) in place of the one it had, logged, as one
    /// move (`Core::rehome`).
    pub(crate) fn set_home(&mut self, t: Tid, h: Option<Tid>) {
        let was = self.home.get(&t).and_then(|s| s.first()).copied();
        if was == h {
            return;
        }
        let edits: Vec<(Tid, Edit)> = was.map(|w| (w, (DERIVED, t, false))).into_iter().chain(h.map(|n| (n, (DERIVED, t, true)))).collect();
        self.edit(&edits);
    }

    /// Notes `g` defined or not, logged.
    fn define(&mut self, g: Tid, on: bool) {
        let was = self.defined.contains(&g);
        if was != on {
            self.stamps.wrote(&Row::Defined(g), true);
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
            self.stamps.wrote(&Row::Defined(g), true);
        }
        let mut n = 0;
        for (f, t) in items.map(|t| (ITEMS, t)).chain(subs.map(|t| (SUBGROUPS, t))) {
            self.link(g, f, *t, true);
            n += 1;
        }
        osis_base::costs::count("group index", n);
    }

    /// Debug builds: each tid `g` lists lists `g` back, and every kept closure holding `g`
    /// (`enclosing`) equals one derived anew.
    #[cfg(debug_assertions)]
    pub(crate) fn check_around(&self, g: &Tid) {
        for f in [ITEMS, SUBGROUPS, DERIVED] {
            for t in self.listing(g, f) {
                debug_assert!(self.maps(f).1.get(t).is_some_and(|r| r.contains(g)), "the group index of {g:?}: {t:?} is not listed back");
            }
        }
        let kept: Vec<(Tid, Arc<BTreeSet<Tid>>)> = self.enclosing(g).into_iter().filter_map(|a| self.kept().get(&a).map(|c| (a, c.clone()))).collect();
        for (a, c) in kept {
            debug_assert_eq!(*c, self.reach(&a), "the kept closure of {a:?} differs from one derived anew");
        }
        let kept: Vec<(Tid, Arc<BTreeSet<Tid>>)> = self.enclosing_avoiding(g, &self.cut).into_iter().filter_map(|a| self.kept_cut().get(&a).map(|c| (a, c.clone()))).collect();
        for (a, c) in kept {
            debug_assert_eq!(*c, self.reach_avoiding(&a, &self.cut), "the kept sync closure of {a:?} differs from one derived anew");
        }
    }
}

impl super::journal::Journaled for Groups {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?} {:?} {:?}", self.defined, self.items, self.item_of, self.subs, self.parents, self.derived)
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
                    self.stamps.wrote(&Row::Defined(g), true);
                    if was {
                        self.defined.insert(g);
                    } else {
                        self.defined.remove(&g);
                    }
                }
                Some(Logged::Listed(g, f, t, was)) => self.apply(&[(g, (f, t, was))]),
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

    /// The reference, from the definitions and key homes alone: each group's closure
    /// (spec/sync-set.md §2: the group, its subgroups at any depth, their items and the things
    /// each is the key home of) and each thing's containing groups (listings alone).
    struct Naive {
        closure: BTreeMap<Tid, BTreeSet<Tid>>,
        of: BTreeMap<Tid, BTreeSet<Tid>>,
    }

    fn naive(defs: &BTreeMap<Tid, Def>, homes: &BTreeMap<Tid, Tid>, all: &[Tid]) -> Naive {
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
            // below every member by key homes, transitively
            while let Some(x) = homes.iter().find(|(x, h)| items.contains(*h) && !items.contains(*x)).map(|(x, _)| *x) {
                items.insert(x);
            }
            closure.insert(*a, items);
        }
        Naive { closure, of }
    }

    /// Each closure walked through no thing of `cut` (`Groups::sync_closure`), from the
    /// definitions and key homes alone.
    fn naive_cut(defs: &BTreeMap<Tid, Def>, homes: &BTreeMap<Tid, Tid>, all: &[Tid], cut: &BTreeSet<Tid>) -> BTreeMap<Tid, BTreeSet<Tid>> {
        let mut out = BTreeMap::new();
        for a in all {
            let (mut items, mut seen) = (BTreeSet::new(), BTreeSet::new());
            let mut stack: Vec<Tid> = (!cut.contains(a)).then_some(*a).into_iter().collect();
            while let Some(x) = stack.pop() {
                if seen.insert(x) && let Some((i, s)) = defs.get(&x) {
                    items.extend(i.iter().filter(|t| !cut.contains(*t)).copied());
                    stack.extend(s.iter().filter(|t| !cut.contains(*t)).copied());
                }
            }
            items.extend(seen);
            while let Some(x) = homes.iter().find(|(x, h)| items.contains(*h) && !items.contains(*x) && !cut.contains(*x)).map(|(x, _)| *x) {
                items.insert(x);
            }
            out.insert(*a, items);
        }
        out
    }

    /// Every answer of `g` equals the reference's; `moved` holds exactly the things whose
    /// listing or containing groups changed since `was` and the groups whose closure changed.
    fn check(g: &Groups, defs: &BTreeMap<Tid, Def>, homes: &BTreeMap<Tid, Tid>, all: &[Tid], was: &Naive, listed: &BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>) {
        let now = naive(defs, homes, all);
        let mut moved = BTreeSet::new();
        for x in all {
            let of = now.of.get(x).cloned().unwrap_or_default();
            assert_eq!(g.groups_of(x), of);
            let enclosing: BTreeSet<Tid> = all.iter().filter(|a| now.closure[*a].contains(x)).copied().collect();
            assert_eq!(g.enclosing(x), enclosing);
            assert_eq!(*g.closure(x), now.closure[x]);
            let l = (defs.iter().filter(|(_, d)| d.0.contains(x)).map(|(a, _)| *a).collect(), defs.iter().filter(|(_, d)| d.1.contains(x)).map(|(a, _)| *a).collect());
            assert_eq!(g.listed_in(x), l);
            assert_eq!(g.key_home(x), homes.get(x).copied());
            if listed.get(x) != Some(&l) || was.closure[x] != now.closure[x] || all.iter().any(|a| was.closure[a].contains(x) != now.closure[a].contains(x)) {
                moved.insert(*x);
            }
        }
        assert_eq!(g.moved, moved);
    }

    fn listings(defs: &BTreeMap<Tid, Def>, all: &[Tid]) -> BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)> {
        all.iter().map(|x| (*x, (defs.iter().filter(|(_, d)| d.0.contains(x)).map(|(a, _)| *a).collect(), defs.iter().filter(|(_, d)| d.1.contains(x)).map(|(a, _)| *a).collect()))).collect()
    }

    // spec/data-model.md §8, spec/sync-set.md §2: the index kept by edits (whole sets, per-tid edits,
    // key homes moved, rolled-back steps; cycles allowed) answers as a derivation from scratch:
    // `groups.0`, listings, closures (kept ones edited in place; an unchanged one the same `Arc`)
    // and what a step tells moved; spec/sync-set.md §5 (Sourced away): sync closures walk no path
    // through a group cut, as groups are cut and uncut between steps.
    #[test]
    fn incremental_groups_spec_data_model_8() {
        let mut rng = SeededRng::from_u64(0);
        let all: Vec<Tid> = (0..12).chain(20..32).map(t).collect();
        let mut g = Groups::default();
        let mut defs: BTreeMap<Tid, Def> = BTreeMap::new();
        let mut homes: BTreeMap<Tid, Tid> = BTreeMap::new();
        let n = |rng: &mut SeededRng| (rng.next_u32() % 12) as u8;
        // an item: a plain thing, or a quarter of the time a group (its contents stay out)
        let item = |rng: &mut SeededRng| t(n(rng) + if rng.next_u32().is_multiple_of(4) { 0 } else { 20 });
        // every answer read through the stamps, followed: one that changed is due (`stamped`), so a
        // reader of one row moves when it does
        let read = |g: &Groups, (kind, a, x): &(u8, Tid, Tid)| -> BTreeSet<Tid> {
            match kind {
                0 => g.closure_of(a).contains(x).then_some(*x).into_iter().collect(),
                1 => g.groups_of(a),
                2 => g.enclosing(a),
                3 => (*g.closure(a)).clone(),
                4 => g.is_defined(a).then_some(*a).into_iter().collect(),
                6 => (*g.sync_closure(a)).clone(),
                _ => g.listed_in(a).0.union(&g.listed_in(a).1).copied().collect(),
            }
        };
        // membership asked of the groups (`t(0..12)`) alone: a plain thing's closure is itself
        let keys: Vec<(u8, Tid, Tid)> = all.iter().flat_map(|a| all.iter().filter(|_| *a < t(12)).map(|x| (0, *a, *x)).chain((1..7).map(|k| (k, *a, *a)))).collect();
        let mut fx: osis_base::memo::Effects<(u8, Tid, Tid), BTreeSet<Tid>> = osis_base::memo::Effects::new("test groups");
        let mut stamped = |g: &Groups| {
            for k in &keys {
                fx.want(*k);
            }
            let due: BTreeSet<(u8, Tid, Tid)> = fx.due().into_iter().collect();
            for k in &keys {
                let moved = fx.settle(k, || read(g, k)).is_some_and(|(was, _)| was.is_some());
                assert!(!moved || due.contains(k), "{k:?} changed with no stamp of what it read moving");
            }
        };
        for step in 0..600 {
            // every few steps: a move missed in between is still found
            if step % 6 == 0 {
                stamped(&g);
            }
            let (was, listed) = (naive(&defs, &homes, &all), listings(&defs, &all));
            // closures asked for before (kept), some still held
            let held: Vec<(Tid, Arc<BTreeSet<Tid>>)> = (0..3).map(|_| t(n(&mut rng))).map(|a| (a, g.closure(&a))).collect();
            // sync closures asked for (kept while something is cut)
            for _ in 0..3 {
                g.sync_closure(&t(n(&mut rng)));
            }
            // between transactions, a group cut or uncut (spec/sync-set.md §5)
            if step % 5 == 2 {
                let mut cut = g.cut().clone();
                let y = t(n(&mut rng));
                if !cut.remove(&y) {
                    cut.insert(y);
                }
                g.set_cut(cut);
            }
            g.moved.clear();
            let k = t(n(&mut rng));
            let rollback = step % 7 == 3;
            let mark = g.mark();
            let saved = (defs.clone(), homes.clone());
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
                // a thing's key home moves (to a group or a plain thing, or none): chains of
                // them, cycles included, and homes reached as items
                7 | 8 => {
                    let x = item(&mut rng);
                    let h = (n(&mut rng) % 3 != 0).then(|| if n(&mut rng) % 2 == 0 { k } else { t(20 + n(&mut rng)) });
                    match h {
                        Some(h) => homes.insert(x, h),
                        None => homes.remove(&x),
                    };
                    g.set_home(x, h);
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
                (defs, homes) = saved;
                g.moved.clear();
                check(&g, &defs, &homes, &all, &naive(&defs, &homes, &all), &listed);
            } else {
                check(&g, &defs, &homes, &all, &was, &listed);
                g.commit();
                for (a, c) in held {
                    assert_eq!(Arc::ptr_eq(&c, &g.closure(&a)), *c == *g.closure(&a), "an unchanged closure is the same Arc");
                }
            }
            assert_eq!(g.defined().copied().collect::<BTreeSet<_>>(), defs.keys().copied().collect());
            let cut = naive_cut(&defs, &homes, &all, g.cut());
            for x in &all {
                assert_eq!(*g.sync_closure(x), cut[x], "the sync closure of {x:?} past {:?}", g.cut());
            }
        }
    }
}
