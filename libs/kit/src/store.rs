//! The account's own state (notes/app.md Layers), toolkit-free: its groups, favorites, the look, the
//! open thing, and the universe of things.
//!
//! The account group (found by the app: `Account`) is an item and a subgroup of home: its own
//! aspects sync (favorites, the collections) and so do its items. Every thing the app makes is an
//! item of it; tags are also its subgroups, so their items sync too. Nodes that start before
//! syncing each make one: every group the app reports is read, and writes go to the smallest tid
//! (notes/app.md kit and app).

use std::any::Any;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use crate::view::graph::{Graph, Local, Scope};
use crate::view::{Summary, TICK};
use osis::ReadSet;
use crate::schema::{ARRANGED, Arrange, COLLECTION, Collection, FAVORITES, INTERNAL, MODE, Mode, OPEN, THEME, VIEWED_AS, WINDOWS};
use osis::core::{NAME, TAG};
use osis::{Config, Address, Member, Osis, ReadOnly, Result, Runtime, Store, Tid, p};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Opens the store in `dir`, creating it (with its home group syncing with `peers`) when `dir` holds
/// none; an existing store adds the `peers` it lacks. Sync runs on osis's own runtime over QUIC
/// while the app runs. Watch callbacks run on the UI thread, in `db.settle()`: `wake` arranges for
/// one (`window::Waker`).
pub fn open(dir: &Path, peers: Vec<Address>, wake: Arc<dyn Fn() + Send + Sync>) -> Result<Osis> {
    let mut cfg = Config { runtime: Runtime::Own, ..Config::default() };
    cfg.app.dispatch = osis::Dispatcher::Pump(wake);
    let store = Store::Dir(dir.to_path_buf());
    if dir.join("db.redb").exists() {
        let db = Osis::open(store, cfg)?;
        for p in &peers {
            db.add_peer(p)?;
        }
        Ok(db)
    } else {
        Osis::create(store, &peers, cfg)
    }
}

/// The aspects that are the system's, not the user's: no view accounts for them, raw hides them.
pub const SYSTEM: [&str; 10] = ["created.0", "group.0", "groups.0", "roles.0", "keys.0", "secrets.0", "label.0", "reach.0", "seen.0", "node.0"];

/// The registry of what a Data knows: its facets and view types.
pub use crate::view::registry::Registry;

/// What an app supplies: its account groups (an app-level concept: kit takes the tids).
pub trait Account: Send + Sync {
    /// The account's groups, the main one first.
    fn groups(&self, db: &ReadOnly) -> Result<Vec<Tid>>;
    /// The group writes go to, made on first use.
    fn main_group(&self, db: &Osis) -> Result<Tid>;
}

/// Every read of the view system: what a render, an action or a test asks of a store. It holds
/// `osis::ReadOnly`, which has no write; `Data` adds those (`Deref`). A render's `Reader` is
/// `tracking`, so what it reads is what it depends on; `things`, `favorites`, `groups`, `summary`
/// and `aspects` are shared memos then.
#[derive(Clone)]
pub struct Reader {
    pub db: ReadOnly,
    /// The node this reader's render is; `None` outside one.
    pub(crate) scope: Option<Scope>,
    /// What a read of the time and tracked handles come from. Private: a render has no writes.
    clock: Osis,
    pub account: Arc<dyn Account>,
    pub registry: Arc<Registry>,
}

/// What the view system does with a store: reads (`Reader`, through `Deref`) and writes.
#[derive(Clone)]
pub struct Data {
    pub db: Osis,
    reader: Reader,
}

impl Deref for Data {
    type Target = Reader;
    fn deref(&self) -> &Reader {
        &self.reader
    }
}

impl Data {
    /// Registers the kit's schema, so `db.aspect_key` types its aspects (the raw view).
    pub fn new(db: Osis, account: Arc<dyn Account>, registry: Registry) -> Data {
        // a store error here shows again at the first write
        if let Err(e) = db.register_schema(crate::schema::SCHEMA.file(), crate::schema::SCHEMA.source()) {
            eprintln!("osis-kit: schema: {e}");
        }
        let data = Data::from_parts((db, account, Arc::new(registry)));
        // made at open, never by a read; a store error here shows again at the first write
        if let Err(e) = data.ensure_profile() {
            eprintln!("osis-kit: profile: {e}");
        }
        data
    }

    /// What another thread may hold (`Data` carries the UI thread's graph handles).
    pub fn parts(&self) -> (Osis, Arc<dyn Account>, Arc<Registry>) {
        (self.db.clone(), self.account.clone(), self.registry.clone())
    }

    /// `Data` again, on another thread.
    pub fn from_parts((db, account, registry): (Osis, Arc<dyn Account>, Arc<Registry>)) -> Data {
        Data { reader: Reader { db: ReadOnly::clone(&db), scope: None, clock: db.clone(), account, registry }, db }
    }

    /// Makes this account's profile, if it can have one yet (a peer saved).
    pub fn ensure_profile(&self) -> Result<()> {
        if !self.db.saved_peers()?.is_empty() {
            self.db.profile()?;
        }
        Ok(())
    }

    /// The group writes go to, made on first use.
    pub fn main_group(&self) -> Result<Tid> {
        self.account.main_group(&self.db)
    }
}

impl Reader {
    /// This reader, its reads tracked in `set` under `scope`.
    pub(crate) fn scoped(&self, set: &ReadSet, scope: Scope) -> Reader {
        Reader { db: self.clock.tracking(set), scope: Some(scope), clock: self.clock.clone(), account: self.account.clone(), registry: self.registry.clone() }
    }

    /// `f`, remembered under `key` and re-run only when what it read differs (equal output stops
    /// there). `f` is told the key and nothing else (a plain `fn`, so it captures nothing): a memo
    /// depends on its key and its reads, never on where it is called from. Outside a render it
    /// simply runs.
    pub fn memo<K, V>(&self, key: K, f: fn(&Reader, &K) -> Result<V>) -> Result<Rc<V>>
    where
        K: Any + Debug + Hash + Eq + Clone,
        V: PartialEq + 'static,
    {
        match &self.scope {
            None => f(self, &key).map(Rc::new),
            Some(s) => {
                let k = key.clone();
                Graph::get(&s.graph, s, key, move |r| f(r, &k))
            }
        }
    }

    /// The window this `Reader`'s render belongs to.
    pub(crate) fn window_state(&self) -> Option<crate::view::WindowState> {
        self.scope.as_ref().and_then(|s| s.graph.window())
    }

    /// The time. In a render it depends on the minute tick: what shows a time moves with it.
    pub fn now(&self) -> Result<osis::Time> {
        if let Some(s) = &self.scope {
            Graph::local(&s.graph, s, TICK, "")?;
        }
        self.clock.now()
    }

    /// Now as local wall ms, as `now` moves.
    pub fn now_local(&self) -> Result<i64> {
        self.now()?;
        Ok(crate::time::now_local())
    }

    /// A local cell's value (`Local`): tracked as a read of osis is. Only a render holds them.
    pub fn local<T: Clone + PartialEq + 'static>(&self, cell: Local<T>) -> Result<T> {
        self.local_at(cell, "")
    }

    /// The `at` cell of a many-celled local (a list's window, by its path).
    pub fn local_at<T: Clone + PartialEq + 'static>(&self, cell: Local<T>, at: &str) -> Result<T> {
        match &self.scope {
            None => Err(osis::Error::Invalid("a local cell outside a render".into())),
            Some(s) => Graph::local(&s.graph, s, cell, at),
        }
    }

    /// "5 min ago" for wall ms `at`.
    pub fn ago(&self, at: u64) -> Result<String> {
        Ok(ago(self.now()?.0.saturating_sub(at)))
    }

    /// `t`'s summary through every applying facet, the color first.
    pub fn summary(&self, t: Tid) -> Result<Summary> {
        Ok((*self.memo(("summary", t), |r, &(_, t)| {
            let mut s = Summary { color: r.color(t)?, ..Summary::default() };
            for f in r.registry.facets.iter() {
                if f.applies(r, t)? {
                    f.summarize(r, t, &mut s)?;
                }
            }
            if s.name.is_empty() {
                s.name = r.name(t)?;
            }
            if s.name.is_empty() && r.db.profile_of(r.db.me())? == Some(t) {
                s.name = "You".into();
            }
            Ok(s)
        })?)
        .clone())
    }

    /// The aspect names `t` carries, the system's left out.
    pub fn aspects(&self, t: Tid) -> Result<Rc<Vec<String>>> {
        self.memo(("aspects", t), |r, &(_, t)| {
            Ok(r.db.aspects(t)?.into_iter().map(|a| a.as_str().to_string()).filter(|a| !SYSTEM.contains(&a.as_str())).collect())
        })
    }

    /// Whether the facet `id` applies to `t`.
    pub fn applies(&self, id: &str, t: Tid) -> Result<bool> {
        match self.registry.facet(id) {
            Some(f) => f.applies(self, t),
            None => Ok(false),
        }
    }

    pub fn has(&self, t: Tid, prefix: &str) -> Result<bool> {
        Ok(self.aspects(t)?.iter().any(|a| a.starts_with(prefix)))
    }

    /// Node state on this window: the value of `key` at `node`.
    pub fn state<T: osis::Codec + Clone + PartialEq + 'static>(&self, key: osis::generated::Aspect<BTreeMap<String, T>>, node: &str) -> Result<Option<T>> {
        let Some(w) = self.window_opt()? else { return Ok(None) };
        self.db.at(w, key).path(osis::Path::root().push(node)).get()
    }

    /// The account groups, the main one first.
    pub fn groups(&self) -> Result<Vec<Tid>> {
        Ok((*self.memo(("groups", ()), |r, _| r.account.groups(&r.db))?).clone())
    }

    /// Whether `t` is one of the app's own groups.
    pub fn is_app(&self, t: Tid) -> Result<bool> {
        Ok(self.groups()?.contains(&t))
    }

    /// The account's profile thing, once it is made (`Data::ensure_profile`).
    pub fn you(&self) -> Result<Option<Tid>> {
        self.db.profile_of(self.db.me())
    }

    /// Everything held: the app groups' members, every other group this store syncs, the
    /// profile once made, and through tags what they hold. Racing nodes' seed views count once
    /// (equal `(collection.0, name.0)`, the smallest tid).
    pub fn things(&self) -> Result<Rc<BTreeSet<Tid>>> {
        self.memo(("things", ()), |r, _| r.compute_things())
    }

    fn compute_things(&self) -> Result<BTreeSet<Tid>> {
        let groups = self.groups()?;
        let home = self.db.home();
        let internal = self.internal()?;
        let skip = |t: &Tid| *t == home || groups.contains(t) || internal.contains(t);
        let mut seen = BTreeSet::new();
        let mut todo: Vec<Tid> = Vec::new();
        for g in &groups {
            todo.extend(self.members(*g)?.iter().copied().map(Member::tid).filter(|t| !skip(t)));
        }
        todo.extend(self.db.status()?.groups.into_iter().filter(|(t, g)| !g.leaving && !skip(t)).map(|(t, _)| t));
        todo.extend(self.db.profile_of(home)?);
        while let Some(t) = todo.pop() {
            if !seen.insert(t) {
                continue;
            }
            if self.tag(t)?.is_some() {
                todo.extend(self.members(t)?.iter().copied().map(Member::tid).filter(|x| !skip(x) && !seen.contains(x)));
            }
        }
        let mut keep: BTreeMap<(Collection, String), Tid> = BTreeMap::new();
        let mut dup = Vec::new();
        for t in &seen {
            if let Some(v) = (*self.collection(*t)?).clone()
                && keep.insert((v, self.name(*t)?), *t).is_some()
            {
                dup.push(*t);
            }
        }
        for t in dup {
            seen.remove(&t);
        }
        Ok(seen)
    }

    /// The app's views, one per `(collection.0, name.0)`, the smallest tid where nodes raced.
    pub fn collections(&self) -> Result<Vec<(Collection, Tid)>> {
        let mut out = Vec::new();
        for t in self.things()?.iter().copied() {
            if let Some(v) = (*self.collection(t)?).clone() {
                out.push((v, t));
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn name(&self, t: Tid) -> Result<String> {
        Ok((*self.memo(("name", t), |r, &(_, t)| Ok(r.db.at(t, NAME).get()?.unwrap_or_default()))?).clone())
    }

    /// `t`'s members, shared by what reads them.
    pub fn members(&self, t: Tid) -> Result<Rc<Vec<Member>>> {
        self.memo(("members", t), |r, &(_, t)| r.db.members(t))
    }

    /// `t`'s `tag.0`, shared by what reads it.
    pub fn tag(&self, t: Tid) -> Result<Rc<Option<osis::core::Tag>>> {
        self.memo(("tag", t), |r, &(_, t)| r.db.at(t, TAG).get())
    }

    /// `t`'s `ui:collection.0`, shared by what reads it.
    pub fn collection(&self, t: Tid) -> Result<Rc<Option<Collection>>> {
        self.memo(("collection", t), |r, &(_, t)| r.db.at(t, COLLECTION).get())
    }

    /// A view or a tag: a thing that stands for a set.
    pub fn is_scope(&self, t: Tid) -> Result<bool> {
        Ok(self.collection(t)?.is_some() || self.tag(t)?.is_some())
    }

    /// The thing's own colour: its tag colour.
    pub fn own_color(&self, t: Tid) -> Result<Option<String>> {
        Ok(self.tag(t)?.as_ref().as_ref().and_then(|g| g.color.clone()))
    }

    /// Its own colour, else its first tag's.
    pub fn color(&self, t: Tid) -> Result<Option<String>> {
        if let Some(c) = self.own_color(t)? {
            return Ok(Some(c));
        }
        for g in self.tags_of(t)? {
            if let Some(c) = self.own_color(g)? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// The tags `t` is directly in (not their parents), by name.
    pub fn tags_of(&self, t: Tid) -> Result<Vec<Tid>> {
        Ok((*self.memo(("tags_of", t), |r, &(_, t)| {
            let g = r.db.groups_of(t)?;
            let mut out = Vec::new();
            for x in g.item_of.into_iter().chain(g.subgroup_of).collect::<BTreeSet<_>>() {
                if x != t && r.tag(x)?.is_some() {
                    out.push(x);
                }
            }
            r.sort_by_name(&mut out)?;
            Ok(out)
        })?)
        .clone())
    }

    /// A tag's subtags and items (subtags are not repeated among the items), each by name.
    pub fn tag_contents(&self, tag: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
        let mut subs = Vec::new();
        let mut items = Vec::new();
        for m in self.members(tag)?.iter().copied() {
            match m {
                Member::Subgroup(s) if s != tag && self.tag(s)?.is_some() => subs.push(s),
                Member::Item(t) if t != tag => items.push(t),
                _ => {}
            }
        }
        items.retain(|t| !subs.contains(t));
        self.sort_by_name(&mut subs)?;
        self.sort_by_name(&mut items)?;
        Ok((subs, items))
    }

    /// When `t` last changed: wall ms of its newest content change, else its creation, each at
    /// `min(ts, received)` (a node whose clock runs ahead cannot date a change into the future).
    pub fn changed(&self, t: Tid) -> Result<Option<u64>> {
        Ok(*self.memo(("changed", t), |r, &(_, t)| Ok(r.db.changed(t)?.map(|c| c.shown().0)))?)
    }

    fn sort_by_name(&self, v: &mut [Tid]) -> Result<()> {
        let mut keyed = Vec::with_capacity(v.len());
        for t in v.iter() {
            keyed.push((self.name(*t)?.to_lowercase(), *t));
        }
        keyed.sort();
        for (slot, (_, t)) in v.iter_mut().zip(keyed) {
            *slot = t;
        }
        Ok(())
    }

    /// Every tag, by name.
    pub fn all_tags(&self) -> Result<Vec<Tid>> {
        let mut out = Vec::new();
        for t in self.things()?.iter().copied() {
            if self.tag(t)?.is_some() {
                out.push(t);
            }
        }
        self.sort_by_name(&mut out)?;
        Ok(out)
    }

    /// The viewer's arrangement of `t` (the main group's first; `None`: its own).
    pub fn arranged(&self, t: Tid) -> Result<Option<Arrange>> {
        for g in self.groups()? {
            if let Some(a) = self.db.at(g, ARRANGED).path(p![t]).get()? {
                return Ok(Some(a));
            }
        }
        Ok(None)
    }


    /// Which thing view the viewer chose for `t` (`None`: the default).
    pub fn viewed_as(&self, t: Tid) -> Result<Option<String>> {
        for g in self.groups()? {
            if let Some(v) = self.db.at(g, VIEWED_AS).path(p![t]).get()? {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }





    /// Whether `undo(t)` has a commit to undo; `NotUndoable` when that commit cannot be undone.
    pub fn can_undo(&self, t: Tid) -> Result<bool> {
        let next = self.db.undo_target(&osis::Scope::Thing(t))?.map(|c| c.stamp.id);
        Ok(next.is_some() && next != self.db.created(t)?.map(|c| c.id))
    }

    /// "Edited 5 min ago" for `t` (its newest content commit).
    pub fn edited(&self, t: Tid) -> Result<String> {
        // a memo: what shows the label moves when the label does, not with every commit
        Ok((*self.memo(("edited", t), |r, &(_, t)| {
            Ok(match r.changed(t)? {
                Some(ms) => format!("Edited {}", r.ago(ms)?),
                None => "Not saved yet".into(),
            })
        })?)
        .clone())
    }

    // ---- favorites

    /// The favorites in order: the main group's list, then any others' extras; things gone are
    /// skipped, a duplicate view stands for the one `views` keeps.
    /// Works around issues/app-group-helper.md.
    pub fn favorites(&self) -> Result<Vec<Tid>> {
        Ok((*self.memo(("favorites", ()), |r, _| r.compute_favorites())?).clone())
    }

    fn compute_favorites(&self) -> Result<Vec<Tid>> {
        let mut out: Vec<Tid> = Vec::new();
        let all = self.things()?;
        let views = self.view_map()?;
        for g in self.groups()? {
            for t in self.db.at(g, FAVORITES).get()?.unwrap_or_default() {
                let t = self.shown_as(&views, t)?;
                if !out.contains(&t) && all.contains(&t) {
                    out.push(t);
                }
            }
        }
        Ok(out)
    }

    pub fn is_favorite(&self, t: Tid) -> Result<bool> {
        Ok(self.favorites()?.contains(&t))
    }

    fn view_map(&self) -> Result<BTreeMap<Collection, Tid>> {
        Ok(self.collections()?.into_iter().collect())
    }

    /// The thing a favorites entry shows: a duplicate view stands for the one `views` keeps.
    fn shown_as(&self, views: &BTreeMap<Collection, Tid>, t: Tid) -> Result<Tid> {
        Ok(match (*self.collection(t)?).clone() {
            Some(v) => views.get(&v).copied().unwrap_or(t),
            None => t,
        })
    }




    // ---- the look (per account, on the app group)

    /// The chosen theme id (`None`: the default) and mode.
    pub fn look(&self) -> Result<(Option<String>, Mode)> {
        let mut theme = None;
        let mut mode = None;
        for g in self.groups()? {
            theme = theme.or(self.db.at(g, THEME).get()?);
            mode = mode.or(self.db.at(g, MODE).get()?);
        }
        Ok((theme, mode.unwrap_or(Mode::Auto)))
    }



    // ---- navigation (per-node ephemeral view state on the main group)

    /// The internal groups among the app groups' subgroups, and what they hold.
    fn internal(&self) -> Result<BTreeSet<Tid>> {
        let mut out = BTreeSet::new();
        for g in self.groups()? {
            for m in self.members(g)?.iter().copied() {
                if let Member::Subgroup(x) = m
                    && self.db.at(x, INTERNAL).get()? == Some(true)
                {
                    out.insert(x);
                    out.extend(self.members(x)?.iter().copied().map(Member::tid));
                }
            }
        }
        Ok(out)
    }

    /// This device's window, if it has one (the main group's first).
    pub fn window_opt(&self) -> Result<Option<Tid>> {
        Ok(*self.memo(("window_opt", ()), |r, _| {
            let node = r.db.node();
            for g in r.groups()? {
                if let Some(w) = r.db.at(g, WINDOWS).get()?.and_then(|m| m.get(&node).copied()) {
                    return Ok(Some(w));
                }
            }
            Ok(None)
        })?)
    }


    /// The thing this window has open; `None`: home (also when it was deleted meanwhile).
    pub fn opened(&self) -> Result<Option<Tid>> {
        let Some(w) = self.window_opt()? else { return Ok(None) };
        let Some(t) = self.db.at(w, OPEN).get()? else { return Ok(None) };
        Ok(Some(t).filter(|t| self.things().is_ok_and(|all| all.contains(t))))
    }




}

impl Data {
    /// Remembers how the viewer arranges `t`, on the app group: `t` need not be writable.
    pub fn set_arranged(&self, t: Tid, a: &Arrange) -> Result<()> {
        let g = self.main_group()?;
        let mut w = self.db.write();
        w.at(g, ARRANGED).path(p![t]).set(a)?;
        w.commit()?;
        Ok(())
    }
    pub fn set_viewed_as(&self, t: Tid, id: &str) -> Result<()> {
        let g = self.main_group()?;
        let mut w = self.db.write();
        w.at(g, VIEWED_AS).path(p![t]).set(&id.to_string())?;
        w.commit()?;
        Ok(())
    }
    /// Tags `t` with `tag`: a thing becomes an item of it, a tag is nested in it (a subgroup,
    /// core's sub-tag: notes/tags.md). Membership grants nothing, so tagging shares nothing;
    /// sharing through a tag waits on core (issues/group-access-follows-membership.md).
    pub fn add_tag(&self, t: Tid, tag: Tid) -> Result<()> {
        let nest = self.db.at(t, TAG).get()?.is_some();
        let mut w = self.db.write();
        w.group(tag).add(if nest { Member::Subgroup(t) } else { Member::Item(t) })?;
        w.commit()?;
        Ok(())
    }
    /// Takes `t` out of `tag` (it stays in the app group): removes a thing, un-nests a tag.
    pub fn remove_tag(&self, t: Tid, tag: Tid) -> Result<()> {
        let mut w = self.db.write();
        for m in self.db.members(tag)? {
            if m.tid() == t {
                w.group(tag).remove(m)?;
            }
        }
        w.commit()?;
        Ok(())
    }
    /// Undoes my newest commit to `t` (made on any of my nodes; never someone else's); `false`
    /// when there is none. Its creation is not undone: that commit also added it to the app
    /// group, so reverting it would leave the thing in no group, gone from the app but not deleted.
    /// Works around issues/undo-creation-unplaces.md.
    pub fn undo(&self, t: Tid) -> Result<bool> {
        if !self.can_undo(t)? {
            return Ok(false);
        }
        Ok(self.db.undo(&osis::Scope::Thing(t))?.is_some())
    }
    /// Adds `t` at the end of the main group's favorites, or removes it from every group's list.
    /// Entries stay in the group holding them: copying another group's entries into the main
    /// list would bring back one that a node removes meanwhile.
    pub fn toggle_favorite(&self, t: Tid) -> Result<()> {
        let mut edits = Vec::new();
        if self.is_favorite(t)? {
            let views = self.view_map()?;
            for g in self.groups()? {
                let base = self.db.at(g, FAVORITES).get()?.unwrap_or_default();
                let mut new = Vec::with_capacity(base.len());
                for x in &base {
                    if self.shown_as(&views, *x)? != t {
                        new.push(*x);
                    }
                }
                if new != base {
                    edits.push((g, base, new));
                }
            }
        } else {
            let g = self.main_group()?;
            let base = self.db.at(g, FAVORITES).get()?.unwrap_or_default();
            let mut new = base.clone();
            new.push(t);
            edits.push((g, base, new));
        }
        self.write_favorites(&edits)
    }
    /// Moves the favorite at `from` to `to` (indices into `favorites()`), by a sequence move
    /// inside the list that holds it: a node removing it meanwhile wins (a move never brings
    /// back a deleted element, where delete-and-insert would), and nothing is copied between
    /// groups. An entry moves among its own group's entries only: placed before the first of
    /// them that follows it in the new order, else after their last.
    pub fn move_favorite(&self, from: usize, to: usize) -> Result<()> {
        let mut favs = self.favorites()?;
        if from >= favs.len() || to >= favs.len() || from == to {
            return Ok(());
        }
        let x = favs.remove(from);
        favs.insert(to, x);
        let views = self.view_map()?;
        for g in self.groups()? {
            let list = self.db.at(g, FAVORITES).get()?.unwrap_or_default();
            let mut shown = Vec::with_capacity(list.len());
            for e in &list {
                shown.push(self.shown_as(&views, *e)?);
            }
            let Some(i) = shown.iter().position(|t| *t == x) else { continue };
            // the first entry of this list that comes after `x` in the new order
            let after: Vec<Tid> = favs.iter().skip(to + 1).copied().collect();
            let rest: Vec<Tid> = shown.iter().enumerate().filter(|(k, _)| *k != i).map(|(_, t)| *t).collect();
            let dest = after.iter().find_map(|a| rest.iter().position(|t| t == a)).unwrap_or(rest.len());
            if dest == i {
                return Ok(());
            }
            let mut w = self.db.write();
            w.at(g, FAVORITES).path(p![]).move_range(i..i + 1, dest)?;
            w.commit()?;
            return Ok(());
        }
        Ok(())
    }
    fn write_favorites(&self, edits: &[(Tid, Vec<Tid>, Vec<Tid>)]) -> Result<()> {
        let mut w = self.db.write();
        for (g, base, new) in edits {
            w.at(*g, FAVORITES).edit(base, new)?;
        }
        w.commit()?;
        Ok(())
    }
    pub fn set_theme(&self, id: &str) -> Result<()> {
        let g = self.main_group()?;
        if self.db.at(g, THEME).get()?.as_deref() == Some(id) {
            return Ok(());
        }
        let mut w = self.db.write();
        w.at(g, THEME).set(&id.to_string())?;
        w.commit()?;
        Ok(())
    }
    pub fn set_mode(&self, m: Mode) -> Result<()> {
        let g = self.main_group()?;
        if self.db.at(g, MODE).get()? == Some(m.clone()) {
            return Ok(());
        }
        let mut w = self.db.write();
        w.at(g, MODE).set(&m)?;
        w.commit()?;
        Ok(())
    }
    /// This device's window, made on first use.
    pub fn window(&self) -> Result<Tid> {
        if let Some(w) = self.window_opt()? {
            return Ok(w);
        }
        let g = self.main_group()?;
        let node = self.db.node();
        let mut inner = None;
        for m in self.db.members(g)? {
            if let Member::Subgroup(x) = m
                && self.db.at(x, INTERNAL).get()? == Some(true)
            {
                inner = Some(x);
                break;
            }
        }
        let mut w = self.db.write();
        let inner = match inner {
            Some(x) => x,
            None => {
                let x = w.create()?;
                w.at(x, INTERNAL).set(&true)?;
                w.group(g).add(Member::Item(x))?;
                w.group(g).add(Member::Subgroup(x))?;
                x
            }
        };
        let win = w.create()?;
        w.group(inner).add(Member::Item(win))?;
        w.at(g, WINDOWS).path(p![node]).set(&win)?;
        w.commit()?;
        Ok(win)
    }
    /// Opens `t` in this window (`None`: home).
    pub fn set_open(&self, t: Option<Tid>) -> Result<()> {
        let win = self.window()?;
        let here = self.db.at(win, OPEN).get()?;
        if here == t {
            return Ok(());
        }
        let mut w = self.db.write();
        match t {
            Some(t) => w.at(win, OPEN).set(&t)?,
            None => w.at(win, OPEN).remove()?,
        }
        w.commit()?;
        Ok(())
    }
    /// A new thing in the app group with an empty `name.0` and whatever `start` writes, opened
    /// on this node.
    pub fn create_with(&self, start: impl FnOnce(&Data, &mut osis::Write<'_>, Tid, Tid) -> Result<()>) -> Result<Tid> {
        let g = self.main_group()?;
        let mut w = self.db.write();
        let t = w.create()?;
        w.at(t, NAME).set(&String::new())?;
        start(self, &mut w, t, g)?;
        w.group(g).add(Member::Item(t))?;
        w.commit()?;
        self.set_open(Some(t))?;
        Ok(t)
    }
    /// A new empty note in the app group, opened on this node.
    pub fn create_note(&self) -> Result<Tid> {
        self.create_with(|_, _, _, _| Ok(()))
    }
    /// Deletes `t` (every aspect and membership, as item or subgroup: a deleted tag must not stay in
    /// the app group as an empty thing) and goes home if it was open.
    pub fn delete(&self, t: Tid) -> Result<()> {
        let was = self.opened()? == Some(t);
        let mut w = self.db.write();
        w.delete(t)?;
        w.commit()?;
        if was { self.set_open(None) } else { Ok(()) }
    }
}

/// "just now", "5 min ago", "3 h ago", "2 d ago" for an age in ms.
pub fn ago(ms: u64) -> String {
    let m = ms / 60_000;
    match m {
        0 => "just now".into(),
        1..60 => format!("{m} min ago"),
        60..1440 => format!("{} h ago", m / 60),
        _ => format!("{} d ago", m / 1440),
    }
}

/// How long the app waits to confirm a link: it runs off the UI thread, and a user is waiting.
/// Minor: at 0 every join fails, at infinity one that nobody answers waits for good.
const JOIN_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

impl Data {
    /// Redeems an `osis://` link: the target, once here, so it shows in `things`. Blocks until the
    /// link is confirmed or `JOIN_WAIT` passes, which says so: nothing is left half done. A
    /// target this account already reaches for good at the link's role opens at once (`Osis::redeem`).
    pub fn redeem(&self, link: &str) -> Result<Tid> {
        let l: osis::ShareLink = link.trim().parse().map_err(|e| osis::Error::Invalid(format!("not a link: {e}")))?;
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().map_err(|e| osis::Error::Network(e.to_string()))?;
        let got = rt.block_on(async { tokio::time::timeout(JOIN_WAIT, self.db.redeem(&l)).await }).unwrap_or_else(|_| Err(osis::Error::Network("could not confirm this link yet; trying again is safe".into())))?;
        if !self.things()?.contains(&got) {
            let g = self.main_group()?;
            let mut w = self.db.write();
            w.group(g).add(Member::Item(got))?;
            w.commit()?;
        }
        Ok(got)
    }
}
