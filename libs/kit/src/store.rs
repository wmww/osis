//! The account's own state (notes/app.md Layers), toolkit-free: its home, favorites, the look, the
//! open thing, and the universe of things.
//!
//! Home (found by the app: `Account`) is a plain thing made under the account root and held by
//! its `holds.0`, so it syncs to the account's nodes (favorites, the collections). Every thing the
//! app makes is made under home (its first admin, whose keys it takes) and held by home's
//! `holds.0`; a tag holds what it tags in its own `holds.0`. Nodes that start before syncing each
//! make one: every home the app reports is read, and writes go to the smallest tid (notes/app.md
//! kit and app).

use std::any::Any;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use crate::view::graph::{Graph, Local, Scope};
use crate::view::{Summary, TICK};
use osis::ReadSet;
use crate::schema::{ARRANGED, Arrange, COLLECTION, Collection, FAVORITES, MODE, Mode, OPEN, THEME, VIEWED_AS, WINDOWS};
use osis::core::{HOLDS, NAME, TAG};
use osis::{BacklinkQuery, Codec, Config, Address, Osis, ReadOnly, Ref, Result, Runtime, Step, Store, Strong, Tid, Weak, p};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Opens the store in `dir`, creating it when `dir` holds none, dialing the nodes `dial` names
/// (`Config::dial`). Sync runs on osis's own runtime while the app runs. Watch callbacks run on the UI thread, in `db.settle()`: `wake` arranges for
/// one (`window::Waker`).
pub fn open(dir: &Path, dial: Vec<Address>, wake: Arc<dyn Fn() + Send + Sync>) -> Result<Osis> {
    let mut cfg = Config { runtime: Runtime::Own, dial, ..Config::default() };
    cfg.app.dispatch = osis::Dispatcher::Pump(wake);
    let store = Store::Dir(dir.to_path_buf());
    if dir.join("db.redb").exists() { Osis::open(store, cfg) } else { Osis::create(store, cfg) }
}

/// The aspects that are the system's, not the user's: no view accounts for them, raw hides them.
pub const SYSTEM: [&str; 10] = ["created.0", "holds.0", "tickets.0", "roles.0", "keys.0", "secrets.0", "label.0", "reach.0", "node.0", "retention^.0"];

/// The registry of what a Data knows: its facets and view types.
pub use crate::view::registry::Registry;

/// What an app supplies: its homes (an app-level concept: kit takes the tids).
pub trait Account: Send + Sync {
    /// The account's homes, the main one first.
    fn homes(&self, db: &ReadOnly) -> Result<Vec<Tid>>;
    /// The home writes go to, made on first use.
    fn home(&self, db: &Osis) -> Result<Tid>;
}

/// Every read of the view system: what a render, an action or a test asks of a store. It holds
/// `osis::ReadOnly`, which has no write; `Data` adds those (`Deref`). A render's `Reader` is
/// `tracking`, so what it reads is what it depends on; `things`, `favorites`, `homes`, `summary`
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
        Data::from_parts((db, account, Arc::new(registry)))
    }

    /// What another thread may hold (`Data` carries the UI thread's graph handles).
    pub fn parts(&self) -> (Osis, Arc<dyn Account>, Arc<Registry>) {
        (self.db.clone(), self.account.clone(), self.registry.clone())
    }

    /// `Data` again, on another thread.
    pub fn from_parts((db, account, registry): (Osis, Arc<dyn Account>, Arc<Registry>)) -> Data {
        Data { reader: Reader { db: ReadOnly::clone(&db), scope: None, clock: db.clone(), account, registry }, db }
    }

    /// The home writes go to, made on first use.
    pub fn home(&self) -> Result<Tid> {
        self.account.home(&self.db)
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

    /// Whether the flag `key` is set at `node` on this window.
    pub fn flag(&self, key: crate::view::Flag, node: &str) -> Result<bool> {
        Ok(self.state(key, node)?.unwrap_or(false))
    }

    /// The account's homes, the main one first.
    pub fn homes(&self) -> Result<Vec<Tid>> {
        Ok((*self.memo(("homes", ()), |r, _| r.account.homes(&r.db))?).clone())
    }

    /// Whether `t` is one of the app's homes.
    pub fn is_home(&self, t: Tid) -> Result<bool> {
        Ok(self.homes()?.contains(&t))
    }

    /// The account's profile thing, once it is made (`Osis::profile`).
    pub fn you(&self) -> Result<Option<Tid>> {
        self.db.profile_of(self.db.me())
    }

    /// Everything held: what the homes hold by strongs in `holds.0`, at any depth, and the profile.
    /// Racing nodes' seed views count once (equal `(collection.0, name.0)`, the smallest tid).
    pub fn things(&self) -> Result<Rc<BTreeSet<Tid>>> {
        self.memo(("things", ()), |r, _| r.compute_things())
    }

    fn compute_things(&self) -> Result<BTreeSet<Tid>> {
        let homes = self.homes()?;
        let mut seen = BTreeSet::new();
        let mut todo: Vec<Tid> = Vec::new();
        for h in &homes {
            todo.extend(self.strongs(*h)?.iter().copied());
        }
        todo.extend(self.you()?);
        while let Some(t) = todo.pop() {
            if homes.contains(&t) || !seen.insert(t) {
                continue;
            }
            todo.extend(self.strongs(t)?.iter().copied().filter(|x| !seen.contains(x)));
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

    /// What `t`'s `holds.0` references, strong or weak, each once, shared by what reads it.
    pub fn holds(&self, t: Tid) -> Result<Rc<Vec<Tid>>> {
        self.memo(("holds", t), |r, &(_, t)| {
            let mut out: Vec<Tid> = r.db.at(t, HOLDS).get()?.unwrap_or_default().into_iter().map(Ref::tid).collect();
            out.sort();
            out.dedup();
            Ok(out)
        })
    }

    /// What `t`'s `holds.0` references by strongs: what belongs with it.
    pub fn strongs(&self, t: Tid) -> Result<Rc<Vec<Tid>>> {
        self.memo(("strongs", t), |r, &(_, t)| Ok(r.db.at(t, HOLDS).get()?.unwrap_or_default().into_iter().filter_map(|x| if let Ref::Strong(s) = x { Some(s.0) } else { None }).collect()))
    }

    /// The things whose `holds.0` references `t`, by any kind.
    pub fn held_by(&self, t: Tid) -> Result<Rc<Vec<Tid>>> {
        self.memo(("held_by", t), |r, &(_, t)| {
            let mut out = Vec::new();
            let mut q = BacklinkQuery::default();
            loop {
                let page = r.db.backlinks(t, &q)?;
                out.extend(page.backlinks.iter().filter(|b| b.ak == HOLDS.name()).map(|b| b.tid));
                match page.backlinks.last() {
                    Some(last) if page.more => q.after = Some(last.clone()),
                    _ => break,
                }
            }
            out.dedup();
            Ok(out)
        })
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
            let mut out = Vec::new();
            for x in r.held_by(t)?.iter().copied() {
                if x != t && r.tag(x)?.is_some() {
                    out.push(x);
                }
            }
            r.sort_by_name(&mut out)?;
            Ok(out)
        })?)
        .clone())
    }

    /// What a tag holds: its subtags and its items, each by name.
    pub fn tag_contents(&self, tag: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
        let mut subs = Vec::new();
        let mut items = Vec::new();
        for t in self.holds(tag)?.iter().copied().filter(|t| *t != tag) {
            if self.tag(t)?.is_some() { subs.push(t) } else { items.push(t) }
        }
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
        sort_by(v, |t| Ok(self.name(t)?.to_lowercase()))
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

    /// The viewer's arrangement of `t` (the main home's first; `None`: its own).
    pub fn arranged(&self, t: Tid) -> Result<Option<Arrange>> {
        for g in self.homes()? {
            if let Some(a) = self.db.at(g, ARRANGED).path(p![Weak(t)]).get()? {
                return Ok(Some(a));
            }
        }
        Ok(None)
    }

    /// Which thing view the viewer chose for `t` (`None`: the default).
    pub fn viewed_as(&self, t: Tid) -> Result<Option<String>> {
        for g in self.homes()? {
            if let Some(v) = self.db.at(g, VIEWED_AS).path(p![Weak(t)]).get()? {
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

    /// The favorites in order: the main home's list, then any others' extras; things gone are
    /// skipped, a duplicate view stands for the one `views` keeps.
    /// Works around issues/app-home-helper.md.
    pub fn favorites(&self) -> Result<Vec<Tid>> {
        Ok((*self.memo(("favorites", ()), |r, _| r.compute_favorites())?).clone())
    }

    fn compute_favorites(&self) -> Result<Vec<Tid>> {
        let mut out: Vec<Tid> = Vec::new();
        let all = self.things()?;
        let views = self.view_map()?;
        for g in self.homes()? {
            for t in self.db.at(g, FAVORITES).get()?.unwrap_or_default() {
                let t = self.shown_as(&views, t.0)?;
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

    // ---- the look (per account, on home)

    /// The chosen theme id (`None`: the default) and mode.
    pub fn look(&self) -> Result<(Option<String>, Mode)> {
        let mut theme = None;
        let mut mode = None;
        for g in self.homes()? {
            theme = theme.or(self.db.at(g, THEME).get()?);
            mode = mode.or(self.db.at(g, MODE).get()?);
        }
        Ok((theme, mode.unwrap_or(Mode::Auto)))
    }

    // ---- navigation (per-window state, the window held by the main home)

    /// This device's window, if it has one (the main home's first).
    pub fn window_opt(&self) -> Result<Option<Tid>> {
        Ok(*self.memo(("window_opt", ()), |r, _| {
            let node = r.db.node();
            for g in r.homes()? {
                if let Some(w) = r.db.at(g, WINDOWS).path(p![Weak(node)]).get::<Strong>()? {
                    return Ok(Some(w.0));
                }
            }
            Ok(None)
        })?)
    }

    /// The thing this window has open; `None`: home (also when it is held no more).
    pub fn opened(&self) -> Result<Option<Tid>> {
        let Some(w) = self.window_opt()? else { return Ok(None) };
        let Some(t) = self.db.at(w, OPEN).get()? else { return Ok(None) };
        Ok(Some(t.0).filter(|t| self.things().is_ok_and(|all| all.contains(t))))
    }
}

impl Data {
    /// Remembers how the viewer arranges `t`, on home: `t` need not be writable.
    pub fn set_arranged(&self, t: Tid, a: &Arrange) -> Result<()> {
        let g = self.home()?;
        let mut w = self.db.write();
        w.at(g, ARRANGED).path(p![Weak(t)]).set(a)?;
        w.commit()?;
        Ok(())
    }
    pub fn set_viewed_as(&self, t: Tid, id: &str) -> Result<()> {
        let g = self.home()?;
        let mut w = self.db.write();
        w.at(g, VIEWED_AS).path(p![Weak(t)]).set(&id.to_string())?;
        w.commit()?;
        Ok(())
    }
    /// Tags `t` with `tag`: a strong in the tag's `holds.0` (a tag in a tag is nested: notes/tags.md).
    /// A strong grants nothing, so tagging shares nothing (notes/tags.md, Sharing a tag).
    pub fn add_tag(&self, t: Tid, tag: Tid) -> Result<()> {
        let mut w = self.db.write();
        hold(&mut w, tag, t)?;
        w.commit()?;
        Ok(())
    }
    /// Takes `t` out of `tag` (home still holds it): every reference to it in the tag's `holds.0`.
    pub fn remove_tag(&self, t: Tid, tag: Tid) -> Result<()> {
        let mut w = self.db.write();
        unhold(&mut w, tag, t)?;
        w.commit()?;
        Ok(())
    }
    /// Undoes my newest commit to `t` (made on any of my nodes; never someone else's); `false`
    /// when there is none. Its creation is not undone: that commit also wrote home's strong to
    /// it, so reverting it would release the thing as a side effect of an undo.
    pub fn undo(&self, t: Tid) -> Result<bool> {
        if !self.can_undo(t)? {
            return Ok(false);
        }
        Ok(self.db.undo(&osis::Scope::Thing(t))?.is_some())
    }
    /// Adds `t` at the end of the main home's favorites, or removes it from every home's list.
    /// Entries stay in the home holding them: copying another home's entries into the main
    /// list would bring back one that a node removes meanwhile.
    pub fn toggle_favorite(&self, t: Tid) -> Result<()> {
        let mut edits = Vec::new();
        if self.is_favorite(t)? {
            let views = self.view_map()?;
            for g in self.homes()? {
                let base = self.db.at(g, FAVORITES).get()?.unwrap_or_default();
                let mut new = Vec::with_capacity(base.len());
                for x in &base {
                    if self.shown_as(&views, x.0)? != t {
                        new.push(*x);
                    }
                }
                if new != base {
                    edits.push((g, base, new));
                }
            }
        } else {
            let g = self.home()?;
            let base = self.db.at(g, FAVORITES).get()?.unwrap_or_default();
            let mut new = base.clone();
            new.push(Weak(t));
            edits.push((g, base, new));
        }
        self.write_favorites(&edits)
    }
    /// Moves the favorite at `from` to `to` (indices into `favorites()`), by a sequence move
    /// inside the list that holds it: a node removing it meanwhile wins (a move never brings
    /// back a deleted element, where delete-and-insert would), and nothing is copied between
    /// homes. An entry moves among its own home's entries only: placed before the first of
    /// them that follows it in the new order, else after their last.
    pub fn move_favorite(&self, from: usize, to: usize) -> Result<()> {
        let mut favs = self.favorites()?;
        if from >= favs.len() || to >= favs.len() || from == to {
            return Ok(());
        }
        let x = favs.remove(from);
        favs.insert(to, x);
        let views = self.view_map()?;
        for g in self.homes()? {
            let list = self.db.at(g, FAVORITES).get()?.unwrap_or_default();
            let mut shown = Vec::with_capacity(list.len());
            for e in &list {
                shown.push(self.shown_as(&views, e.0)?);
            }
            // every entry showing `x` (two nodes favoriting it at once leave two): the first
            // moves, the others go in the same write, so `x` lands where it was dropped
            let at: Vec<usize> = shown.iter().enumerate().filter(|(_, t)| **t == x).map(|(k, _)| k).collect();
            let Some(&i) = at.first() else { continue };
            // the first entry of this list that comes after `x` in the new order
            let after: Vec<Tid> = favs.iter().skip(to + 1).copied().collect();
            let rest: Vec<Tid> = shown.iter().filter(|t| **t != x).copied().collect();
            let dest = after.iter().find_map(|a| rest.iter().position(|t| t == a)).unwrap_or(rest.len());
            if dest == i && at.len() == 1 {
                return Ok(());
            }
            let mut w = self.db.write();
            for &j in at.iter().skip(1).rev() {
                w.at(g, FAVORITES).path(p![]).splice(j..j + 1, ())?;
            }
            if dest != i {
                w.at(g, FAVORITES).path(p![]).move_range(i..i + 1, dest)?;
            }
            w.commit()?;
            return Ok(());
        }
        Ok(())
    }
    fn write_favorites(&self, edits: &[(Tid, Vec<Weak>, Vec<Weak>)]) -> Result<()> {
        let mut w = self.db.write();
        for (g, base, new) in edits {
            w.at(*g, FAVORITES).edit(base, new)?;
        }
        w.commit()?;
        Ok(())
    }
    pub fn set_theme(&self, id: &str) -> Result<()> {
        let g = self.home()?;
        if self.db.at(g, THEME).get()?.as_deref() == Some(id) {
            return Ok(());
        }
        let mut w = self.db.write();
        w.at(g, THEME).set(&id.to_string())?;
        w.commit()?;
        Ok(())
    }
    pub fn set_mode(&self, m: Mode) -> Result<()> {
        let g = self.home()?;
        if self.db.at(g, MODE).get()? == Some(m.clone()) {
            return Ok(());
        }
        let mut w = self.db.write();
        w.at(g, MODE).set(&m)?;
        w.commit()?;
        Ok(())
    }
    /// This device's window, made on first use: under home, held by home's `ui:windows.0` (so it
    /// syncs, and is not among the things home holds).
    pub fn window(&self) -> Result<Tid> {
        if let Some(w) = self.window_opt()? {
            return Ok(w);
        }
        let g = self.home()?;
        let mut w = self.db.write();
        let win = w.create_with_admin(g)?;
        w.at(g, WINDOWS).path(p![Weak(self.db.node())]).set(&Strong(win))?;
        w.commit()?;
        Ok(win)
    }
    /// Opens `t` in this window (`None`: home).
    pub fn set_open(&self, t: Option<Tid>) -> Result<()> {
        let win = self.window()?;
        let here = self.db.at(win, OPEN).get()?.map(|w| w.0);
        if here == t {
            return Ok(());
        }
        let mut w = self.db.write();
        match t {
            Some(t) => w.at(win, OPEN).set(&Weak(t))?,
            None => w.at(win, OPEN).remove()?,
        }
        w.commit()?;
        Ok(())
    }
    /// A new thing made under home and held by it, with an empty `name.0` and whatever `start`
    /// writes, opened on this node.
    pub fn create_with(&self, start: impl FnOnce(&Data, &mut osis::Write<'_>, Tid) -> Result<()>) -> Result<Tid> {
        let g = self.home()?;
        let mut w = self.db.write();
        let t = w.create_with_admin(g)?;
        keep_a_day(&mut w, t)?;
        w.at(t, NAME).set(&String::new())?;
        start(self, &mut w, t)?;
        hold(&mut w, g, t)?;
        w.commit()?;
        self.set_open(Some(t))?;
        Ok(t)
    }
    /// A new empty note under home, opened on this node.
    pub fn create_note(&self) -> Result<Tid> {
        self.create_with(|_, _, _| Ok(()))
    }
    /// Deletes `t` as far as this account goes: every reference to it in a `holds.0` this node may
    /// write goes, so it leaves the app (and, held nowhere else, every node); goes home if it was
    /// open. Clearing its aspects is no part of it: a thing goes with its last reference.
    pub fn delete(&self, t: Tid) -> Result<()> {
        let was = self.opened()? == Some(t);
        let mut w = self.db.write();
        for h in self.held_by(t)?.iter().copied() {
            if self.db.role_on(h)? >= Some(osis::Role::Write) {
                unhold(&mut w, h, t)?;
            }
        }
        w.commit()?;
        if was { self.set_open(None) } else { Ok(()) }
    }
}

/// In `w`: a strong to `t` in `holder`'s `holds.0`.
pub fn hold(w: &mut osis::Write<'_>, holder: Tid, t: Tid) -> Result<()> {
    w.at(holder, HOLDS).path(p![]).add(&Ref::Strong(Strong(t)))
}

/// In `w`: every reference to `t` in `holder`'s `holds.0` removed, strong or weak.
pub fn unhold(w: &mut osis::Write<'_>, holder: Tid, t: Tid) -> Result<()> {
    for r in [Ref::Strong(Strong(t)), Ref::Weak(Weak(t))] {
        w.at(holder, HOLDS).path(osis::Path(vec![Step::Elem(r.to_value())])).remove()?;
    }
    Ok(())
}

/// In `w`, by the admin creating `t`: `t`'s setting keeping what any aspect replaces a day after,
/// so Undo can write it back (without a setting nothing replaced is kept).
pub fn keep_a_day(w: &mut osis::Write<'_>, t: Tid) -> Result<()> {
    let day = osis::History::Keep { until: osis::Time(0), after_replaced: std::time::Duration::from_secs(86_400) };
    let entry = osis::core::RetentionEntry { history: Some(day), ..Default::default() };
    w.at(t, osis::core::RETENTION).set(&osis::core::RetentionSetting { default: Some(entry), ..Default::default() })
}

/// `v` ordered by `key`, ties by tid.
pub(crate) fn sort_by<K: Ord>(v: &mut [Tid], mut key: impl FnMut(Tid) -> Result<K>) -> Result<()> {
    let mut keyed = Vec::with_capacity(v.len());
    for t in v.iter() {
        keyed.push((key(*t)?, *t));
    }
    keyed.sort();
    for (slot, (_, t)) in v.iter_mut().zip(keyed) {
        *slot = t;
    }
    Ok(())
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
        // accepting is a strong to the target; the account's ticket for it, which brings it to
        // the account's other nodes, is core's
        // refgraph: (c) the redeem's ticket in the account root's `tickets.0` (`redeem_in`)
        if !self.things()?.contains(&got) {
            let g = self.home()?;
            let mut w = self.db.write();
            hold(&mut w, g, got)?;
            w.commit()?;
        }
        Ok(got)
    }
}
