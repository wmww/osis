//! The actions layer (notes/app.md Layers): toolkit-free, every intent becomes osis reads and
//! writes here, and every screen reads what it shows from here.
//!
//! The app's internal group (marked `/osis-app/app`, no `/tag`) is an item and a subgroup of
//! home: its own aspects sync (favorites, the views) and so do its items. Every thing the app
//! makes is placed in it; tags are also its subgroups, so their items sync too. Two devices that
//! start before syncing each make one: every marked group among home's subgroups is read, and
//! writes go to the smallest tid (notes/app.md kit and app).
//!
//! A thing is whatever its aspects make it (`Kind`); things and scopes (tags, views) are shown
//! alike as tiles (`Tile`).

use crate::schema::{REVOKE, Revoke, APP, COLOR, DEMO, FAVORITES, MODE, Mode, OPEN, THEME, VIEW, View};
use osis::core::{BODY, GROUP, NAME, TAG};
use osis::{AspectKey, ChangeId, CommitKind, CommitQuery, Config, Edge, EdgeOpts, Error, Osis, Result, Role, Runtime, Scope, ServerAddr, Tid, Transport, p};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Opens the store in `dir`, creating it (with its home group on `servers`) when `dir` holds
/// none. Sync runs on osis's own runtime over QUIC while the app runs.
pub fn open(dir: &Path, servers: Vec<ServerAddr>) -> Result<Osis> {
    let mut cfg = Config::dir(dir);
    cfg.runtime = Runtime::Own;
    cfg.transport = Some(Transport::Quic);
    if dir.join("db.redb").exists() {
        Osis::open(cfg)
    } else {
        cfg.servers = servers;
        Ok(Osis::create(cfg)?.0)
    }
}

/// What a thing is, by its aspects: the first that applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One of the app's views (`/osis-app/view`).
    View(View),
    /// A tag (`/tag`).
    Tag,
    /// An event (any `/event/` aspect).
    Event,
    /// A contact (any `/contact/` aspect).
    Contact,
    /// Anything else: a note (`/name`, `/body`) or an empty thing.
    Note,
}

impl Kind {
    pub fn is_scope(&self) -> bool {
        matches!(self, Kind::View(_) | Kind::Tag)
    }
    /// The word the UI shows for it.
    pub fn label(&self) -> &'static str {
        match self {
            Kind::View(_) => "View",
            Kind::Tag => "Tag",
            Kind::Event => "Event",
            Kind::Contact => "Person",
            Kind::Note => "Note",
        }
    }
}

/// The views every app group offers, with their default names and colours.
pub const VIEWS: [(View, &str, &str); 4] =
    [(View::Calendar, "Calendar", "#f97316"), (View::People, "People", "#06b6d4"), (View::Tags, "Tags", "#8b5cf6"), (View::Recent, "Recent", "#64748b")];

/// One thing as a tile: everything a list, grid or rail row shows of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tile {
    pub tid: Tid,
    pub kind: Kind,
    /// `/name`, `""` when unnamed.
    pub name: String,
    /// A line under the name (a note's first line, an event's time, a tag's size, ...).
    pub sub: String,
    /// `#rrggbb`: its own colour, else its first tag's.
    pub color: Option<String>,
}

/// An event (or an occurrence of a repeating one) as a calendar shows it, in local wall ms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub tid: Tid,
    pub start: i64,
    pub end: i64,
    pub all_day: bool,
    /// One occurrence of a repeating event.
    pub repeats: bool,
}

/// What a new thing is made as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewKind {
    Note,
    Event,
    Contact,
    Tag,
}

/// Colours a new tag takes, in turn.
pub const TAG_COLORS: [&str; 8] = ["#ef4444", "#f59e0b", "#22c55e", "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899", "#64748b"];

/// Why taking back a tag's access did not happen.
#[derive(Debug)]
pub enum RevokeError {
    /// The tag still reaches the thing another way (its direct edge may be gone).
    Kept(String),
    Failed(Error),
}

/// Who can see a thing (notes/app.md Model: every thing shows it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reach {
    /// People other than me, by display name.
    pub people: Vec<String>,
    /// The shared tags (actors) it reaches them through.
    pub via: Vec<Tid>,
}

impl Reach {
    /// "Only you", "You, Mara, Jun".
    pub fn who(&self) -> String {
        if self.people.is_empty() { "Only you".into() } else { format!("You, {}", self.people.join(", ")) }
    }
}

/// Search results: scopes whose name matches, things whose name matches, things whose text
/// matches (with a snippet), and the other things in the matching scopes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub scopes: Vec<Tid>,
    pub named: Vec<Tid>,
    pub mentions: Vec<(Tid, String)>,
    pub in_scopes: Vec<Tid>,
}

impl Found {
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty() && self.named.is_empty() && self.mentions.is_empty() && self.in_scopes.is_empty()
    }
}

/// What the app does with a database.
#[derive(Clone)]
pub struct Data {
    pub db: Osis,
}

impl Data {
    pub fn new(db: Osis) -> Data {
        // the schemas the app shows, so `db.key` types their aspects (the fallback view)
        for s in [&crate::schema::SCHEMA, &crate::event::SCHEMA, &crate::contact::SCHEMA] {
            db.register_schema(s.get().clone());
        }
        Data { db }
    }

    /// A typed read where a value of another shape (a synced thing may hold anything, or a
    /// newer revision's enum case) reads as absent, so one odd thing cannot fail a whole screen.
    pub fn get<K: AspectKey>(&self, t: Tid, key: K) -> Result<Option<K::T>> {
        match self.db.get(t, key) {
            Err(Error::Type { .. }) => Ok(None),
            r => r,
        }
    }

    // ---- the app group

    /// The app groups among home's subgroups, smallest tid first.
    pub fn groups(&self) -> Result<Vec<Tid>> {
        let db = &self.db;
        let home = db.home();
        let subs = self.get(home, GROUP)?.map(|g| g.subgroups).unwrap_or_default();
        let mut out = Vec::new();
        for t in subs {
            if t != home && self.get(t, APP)? == Some(true) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// The group writes go to; with its views, created on first use.
    pub fn main_group(&self) -> Result<Tid> {
        if let Some(g) = self.groups()?.first() {
            return Ok(*g);
        }
        let db = &self.db;
        db.write_with(|w| {
            // an item of home (its own aspects sync) and a subgroup (its items sync: a group's
            // members are its items and its subgroups' members, not its items' items)
            let g = w.create(db.me())?;
            w.make_group(g)?;
            w.at(g, APP).set(&true)?;
            w.place(g, db.home())?;
            w.add_subgroup(db.home(), g)?;
            let mut favs = Vec::new();
            for (v, name, color) in VIEWS {
                let t = w.create(db.me())?;
                w.at(t, VIEW).set(&v)?;
                w.at(t, NAME).set(&name.to_string())?;
                w.at(t, COLOR).set(&color.to_string())?;
                w.place(t, g)?;
                favs.push(t);
            }
            w.at(g, FAVORITES).set(&favs)?;
            Ok(g)
        })
    }

    /// Every thing the app can show: the app groups' items and, transitively, the tags' items
    /// and subtags (a tag shared with me holds things not in my app group).
    pub fn things(&self) -> Result<BTreeSet<Tid>> {
        let groups = self.groups()?;
        let mut seen = BTreeSet::new();
        let mut todo: Vec<Tid> = Vec::new();
        for g in &groups {
            if let Some(gr) = self.get(*g, GROUP)? {
                todo.extend(gr.items.iter().chain(gr.subgroups.iter()).filter(|t| !groups.contains(t)));
            }
        }
        while let Some(t) = todo.pop() {
            if !seen.insert(t) {
                continue;
            }
            if self.get(t, TAG)?.is_some()
                && let Some(gr) = self.get(t, GROUP)?
            {
                todo.extend(gr.items.iter().chain(gr.subgroups.iter()).filter(|x| !groups.contains(x) && !seen.contains(x)));
            }
        }
        // one view per kind: where two devices both made the views, the smallest tid
        let mut views = BTreeSet::new();
        let mut dup = Vec::new();
        for t in &seen {
            if let Some(v) = self.get(*t, VIEW)?
                && !views.insert(v)
            {
                dup.push(*t);
            }
        }
        for t in dup {
            seen.remove(&t);
        }
        Ok(seen)
    }

    /// The app's views, one per kind (the smallest tid where two devices both made one).
    pub fn views(&self) -> Result<Vec<(View, Tid)>> {
        let mut out: Vec<(View, Tid)> = Vec::new();
        for t in self.things()? {
            if let Some(v) = self.get(t, VIEW)? {
                out.push((v, t));
            }
        }
        out.sort();
        Ok(out)
    }

    // ---- reading things

    pub fn kind(&self, t: Tid) -> Result<Kind> {
        if let Some(v) = self.get(t, VIEW)? {
            return Ok(Kind::View(v));
        }
        let aks = self.db.aspects(t)?;
        let has = |pre: &str| aks.iter().any(|a| a.as_str().starts_with(pre));
        Ok(if aks.iter().any(|a| a.as_str() == "/tag") {
            Kind::Tag
        } else if has("/event/") {
            Kind::Event
        } else if has("/contact/") {
            Kind::Contact
        } else {
            Kind::Note
        })
    }

    pub fn name(&self, t: Tid) -> Result<String> {
        Ok(self.get(t, NAME)?.unwrap_or_default())
    }

    pub fn body(&self, t: Tid) -> Result<String> {
        Ok(self.get(t, BODY)?.unwrap_or_default())
    }

    /// The thing's own colour: a tag's `/tag.color`, else `/osis-app/color`.
    pub fn own_color(&self, t: Tid) -> Result<Option<String>> {
        if let Some(c) = self.get(t, TAG)?.and_then(|g| g.color) {
            return Ok(Some(c));
        }
        self.get(t, COLOR)
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

    /// The tags `t` is placed in (not their parents), by name.
    pub fn tags_of(&self, t: Tid) -> Result<Vec<Tid>> {
        let mut out = Vec::new();
        // a tag nested in a tag is its subgroup, not a member: `groups_of` does not list the parent
        let mut cands: BTreeSet<Tid> = self.db.groups_of(t).into_iter().collect();
        if self.get(t, TAG)?.is_some() {
            cands.extend(self.all_tags()?);
        }
        for g in cands {
            if g != t && self.get(g, TAG)?.is_some() && self.get(g, GROUP)?.is_some_and(|gr| gr.items.contains(&t) || gr.subgroups.contains(&t)) {
                out.push(g);
            }
        }
        self.sort_by_name(&mut out)?;
        Ok(out)
    }

    /// A tag's subtags and items (subtags are not repeated among the items), each by name.
    pub fn tag_contents(&self, tag: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
        let g = self.get(tag, GROUP)?.unwrap_or_default();
        let mut subs = Vec::new();
        for s in &g.subgroups {
            if *s != tag && self.get(*s, TAG)?.is_some() {
                subs.push(*s);
            }
        }
        let mut items: Vec<Tid> = g.items.iter().copied().filter(|t| !subs.contains(t) && *t != tag).collect();
        self.sort_by_name(&mut subs)?;
        self.sort_by_name(&mut items)?;
        Ok((subs, items))
    }

    /// What a view shows, in its order.
    pub fn view_items(&self, v: &View) -> Result<Vec<Tid>> {
        let mut out = Vec::new();
        for t in self.things()? {
            let k = self.kind(t)?;
            let fits = match v {
                View::Calendar => k == Kind::Event,
                View::People => k == Kind::Contact,
                View::Tags => k == Kind::Tag,
                View::Recent => !matches!(k, Kind::View(_)),
            };
            if fits {
                out.push(t);
            }
        }
        match v {
            View::Recent => {
                let mut by: Vec<(u64, Tid)> = out.into_iter().map(|t| (self.changed(t).unwrap_or(0), t)).collect();
                by.sort_by(|a, b| b.cmp(a));
                Ok(by.into_iter().map(|(_, t)| t).collect())
            }
            _ => {
                self.sort_by_name(&mut out)?;
                Ok(out)
            }
        }
    }

    /// When `t` last changed: wall ms of its newest content change, else its creation, each at
    /// `min(ts, received)` (a device whose clock runs ahead cannot date a change into the future).
    pub fn changed(&self, t: Tid) -> Option<u64> {
        let q = CommitQuery::new().scope(Scope::Thing(t)).kind(CommitKind::Change).kind(CommitKind::Revert).limit(1);
        let newest = self.db.commits(&q).ok().and_then(|c| c.first().map(|e| (e.commit.ts, e.commit.received)));
        let (ts, received) = newest.or_else(|| self.db.created(t).map(|c| (c.ts, c.received)))?;
        Some(ts.wall_ms().0.min(received.0))
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

    /// `t` as a tile.
    pub fn tile(&self, t: Tid) -> Result<Tile> {
        let kind = self.kind(t)?;
        let name = self.name(t)?;
        let sub = match &kind {
            Kind::Note => first_line(&self.body(t)?).unwrap_or("Empty note").to_string(),
            Kind::Event => match self.get(t, crate::event::START)? {
                Some(st) => fmt_when(&st, self.get(t, crate::event::END)?.as_ref()),
                None => self.get(t, crate::event::LOCATION)?.unwrap_or_else(|| "Not scheduled".into()),
            },
            Kind::Contact => {
                let org = self.get(t, crate::contact::ORG)?.map(|o| if o.title.is_empty() { o.name } else { o.title }).filter(|s| !s.is_empty());
                let email = || self.get(t, crate::contact::EMAILS).ok().flatten().and_then(|m| m.keys().next().cloned());
                org.or_else(email).unwrap_or_else(|| "Contact".into())
            }
            Kind::Tag => {
                let (s, i) = self.tag_contents(t)?;
                count(s.len() + i.len(), "item", "items")
            }
            Kind::View(v) => {
                let n = self.view_items(v)?.len();
                match v {
                    View::Calendar => {
                        let monday = crate::time::monday_of(crate::time::now_local());
                        let mut this_week = BTreeSet::new();
                        for (_, evs) in self.week(monday)? {
                            this_week.extend(evs.into_iter().map(|x| x.tid));
                        }
                        format!("{} this week", count(this_week.len(), "event", "events"))
                    }
                    View::People => count(n, "person", "people"),
                    View::Tags => count(n, "tag", "tags"),
                    View::Recent => "Last touched first".into(),
                }
            }
        };
        Ok(Tile { tid: t, kind, name, sub, color: self.color(t)? })
    }

    /// The one main colour of a screen showing `t` (notes/theming.md): its own colour, else the
    /// first among what it holds or links (its tags; a scope's contents).
    pub fn main_color(&self, t: Tid) -> Result<Option<String>> {
        if let Some(c) = self.own_color(t)? {
            return Ok(Some(c));
        }
        let near = match self.kind(t)? {
            Kind::Tag => {
                let (s, i) = self.tag_contents(t)?;
                s.into_iter().chain(i).collect()
            }
            Kind::View(v) => self.view_items(&v)?,
            _ => self.tags_of(t)?,
        };
        for x in near {
            if let Some(c) = self.color(x)? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// Every tag, by name.
    pub fn all_tags(&self) -> Result<Vec<Tid>> {
        let mut out = Vec::new();
        for t in self.things()? {
            if self.get(t, TAG)?.is_some() {
                out.push(t);
            }
        }
        self.sort_by_name(&mut out)?;
        Ok(out)
    }

    /// Who can see `t`: its owner and its roster, through member actors (shared tags, with their
    /// owners) down to people; me and my devices are "you". Edges with an `until` count until it
    /// passes.
    pub fn reach(&self, t: Tid) -> Result<Reach> {
        let db = &self.db;
        let me = db.me();
        let now = db.now();
        let mine: BTreeSet<Tid> = db.roster(me).into_keys().chain([me, db.node()]).collect();
        let mut r = Reach::default();
        let mut seen = BTreeSet::new();
        let mut todo = vec![t];
        if let Some(o) = db.owner_of(t) {
            todo.push(o);
        }
        while let Some(x) = todo.pop() {
            if !seen.insert(x) {
                continue;
            }
            if x != t && mine.contains(&x) {
                continue;
            }
            if x != t && db.knows(x) && self.get(x, TAG)?.is_some() {
                // a shared tag: its members see what it holds, and so does its owner (implicitly
                // its admin, not on its roster)
                r.via.push(x);
                todo.extend(db.owner_of(x));
            } else if x != t {
                let name = self.person_name(x)?;
                if !r.people.contains(&name) {
                    r.people.push(name);
                }
                continue;
            }
            todo.extend(db.roster(x).into_iter().filter(|(_, e)| live(e, now)).map(|(m, _)| m));
        }
        r.people.sort();
        Ok(r)
    }

    /// A person's display name: their profile's `/name`, else a contact naming that profile,
    /// else a short id.
    pub fn person_name(&self, p: Tid) -> Result<String> {
        let db = &self.db;
        if let Some(prof) = db.profile_of(p)? {
            if let Some(n) = self.get(prof, NAME)?.filter(|n| !n.is_empty()) {
                return Ok(n);
            }
            for t in self.things()? {
                if self.get(t, crate::contact::PROFILE)? == Some(prof) {
                    return self.name(t);
                }
            }
        }
        Ok(format!("someone ({})", p.to_string().chars().take(6).collect::<String>()))
    }

    /// Whether placing something in `tag` shows it to anyone else (the share confirmation).
    pub fn tag_reach(&self, tag: Tid) -> Result<Reach> {
        self.reach(tag)
    }

    /// Who placing `t` in `tag` shares it with (the share confirmation): the tag's reach, when it
    /// holds anyone else, `t` is mine to share (admin) and the tag has no edge on it yet. `None`:
    /// placing shares nothing (placement grants no rights, notes/tags.md).
    pub fn share_reach(&self, t: Tid, tag: Tid) -> Result<Option<Reach>> {
        let db = &self.db;
        if db.role_on(t) != Some(Role::Admin) || db.roster(t).get(&tag).is_some_and(|e| live(e, db.now())) {
            return Ok(None);
        }
        let r = self.tag_reach(tag)?;
        Ok((!r.people.is_empty()).then_some(r))
    }

    /// Tags `t` with `tag`: a thing is placed in it (an item), a tag is nested in it (a
    /// subgroup, core's sub-tag: notes/tags.md). Where that shares it (`share_reach`), the tag
    /// gets an edge on `t` (write, capped by each member's role on the tag); a nested tag is
    /// shared recursively, as core shares a tag by default: each thing and sub-tag below it that I
    /// may share gets an edge for its own tag, so the members reach it through the chain. What I
    /// may not share (not admin) stays out.
    pub fn add_tag(&self, t: Tid, tag: Tid) -> Result<()> {
        let share = self.share_reach(t, tag)?.is_some();
        let nest = self.get(t, TAG)?.is_some();
        self.db.write_with(|w| if nest { w.add_subgroup(tag, t) } else { w.place(t, tag) })?;
        if share {
            self.db.grant(t, tag, Role::Write, EdgeOpts::default())?;
            if nest {
                self.share_below(t, &mut BTreeSet::new())?;
            }
        }
        Ok(())
    }

    /// Gives each item and sub-tag of `tag` an edge for `tag` where it lacks one and I may share
    /// it, then the same below each sub-tag (a graph: each tag once).
    fn share_below(&self, tag: Tid, seen: &mut BTreeSet<Tid>) -> Result<()> {
        if !seen.insert(tag) {
            return Ok(());
        }
        let (subs, items) = self.tag_contents(tag)?;
        let now = self.db.now();
        for x in subs.iter().chain(items.iter()) {
            if self.db.role_on(*x) == Some(Role::Admin) && !self.db.roster(*x).get(&tag).is_some_and(|e| live(e, now)) {
                self.db.grant(*x, tag, Role::Write, EdgeOpts::default())?;
            }
        }
        for s in subs {
            self.share_below(s, seen)?;
        }
        Ok(())
    }

    /// Whether `t` is anywhere under `tag` (an item or sub-tag of it or of a tag below it).
    pub fn under(&self, tag: Tid, t: Tid) -> Result<bool> {
        let mut seen = BTreeSet::new();
        let mut todo = vec![tag];
        while let Some(g) = todo.pop() {
            if !seen.insert(g) {
                continue;
            }
            let (subs, items) = self.tag_contents(g)?;
            if subs.contains(&t) || items.contains(&t) {
                return Ok(true);
            }
            todo.extend(subs);
        }
        Ok(false)
    }

    /// After `remove_tag(t, tag)`: whether the access tagging gave should go. Only the tag's own
    /// live edge on `t`, only when that is how the tag reaches `t` (a direct edge, nothing
    /// longer), when `t` is no longer anywhere under the tag, and when it is mine to change.
    pub fn revoke_needed(&self, t: Tid, tag: Tid) -> Result<bool> {
        let db = &self.db;
        let direct = db.roster(t).get(&tag).is_some_and(|e| live(e, db.now()));
        Ok(direct && db.role_on(t) == Some(Role::Admin) && db.member_path(t, tag) == vec![(t, tag)] && !self.under(tag, t)?)
    }

    /// Ends the tag's edge on `t` (async: a pre-sync, then the demotion, and `t` rotates its
    /// secrets). Run off the UI thread (kit `tasks`). When the tag also reaches `t` another way
    /// (through another actor), core removes the direct edge and refuses the rest: `Kept`, the
    /// tag's members still reach `t` that way.
    /// `sync` is core's pre-sync rule (the app passes the default, `Required`: offline, the
    /// removal fails `Unsynced` and nothing changes).
    pub async fn revoke(&self, t: Tid, tag: Tid, sync: osis::WaitForSync) -> std::result::Result<(), RevokeError> {
        match self.db.demote(t, tag, osis::Lower::Remove, osis::Demotion { sync, backdate: None }).await {
            Ok(()) => Ok(()),
            Err(Error::Invalid(m)) if m.contains("reaches") => Err(RevokeError::Kept(m)),
            Err(e) => Err(RevokeError::Failed(e)),
        }
    }

    // ---- revocations still to do (durable, synced on the app group: notes/app.md)

    /// The revocations waiting (thing, tag), from every app group.
    pub fn pending_revokes(&self) -> Result<Vec<(Tid, Tid)>> {
        let mut out = BTreeSet::new();
        for g in self.groups()? {
            for r in self.get(g, REVOKE)?.unwrap_or_default() {
                out.insert((r.thing, r.tag));
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Records that the tag's access to `t` is to be taken back (until `drop_revoke`).
    pub fn queue_revoke(&self, t: Tid, tag: Tid) -> Result<()> {
        let g = self.main_group()?;
        self.db.write_with(|w| w.at(g, REVOKE).path(p![]).add(&Revoke { thing: t, tag }))
    }

    /// Forgets a revocation, on every app group holding it.
    pub fn drop_revoke(&self, t: Tid, tag: Tid) -> Result<()> {
        let r = Revoke { thing: t, tag };
        let mut gs = Vec::new();
        for g in self.groups()? {
            if self.get(g, REVOKE)?.is_some_and(|s| s.contains(&r)) {
                gs.push(g);
            }
        }
        if gs.is_empty() {
            return Ok(());
        }
        self.db.write_with(|w| {
            for g in &gs {
                w.at(*g, REVOKE).path(p![]).remove_elem(&r)?;
            }
            Ok(())
        })
    }

    /// Whether a waiting revocation still applies: the thing exists and the tag still has the
    /// access tagging gave and nothing else keeps it (`revoke_needed`). Re-tagged or deleted
    /// things, and revocations another device already did, do not.
    pub fn revoke_applies(&self, t: Tid, tag: Tid) -> Result<bool> {
        Ok(self.things()?.contains(&t) && self.revoke_needed(t, tag)?)
    }

    /// Takes `t` out of `tag` (it stays in the app group): unplaces a thing, un-nests a tag.
    pub fn remove_tag(&self, t: Tid, tag: Tid) -> Result<()> {
        let g = self.get(tag, GROUP)?.unwrap_or_default();
        self.db.write_with(|w| {
            if g.subgroups.contains(&t) {
                w.remove_subgroup(tag, t)?;
            }
            if g.items.contains(&t) {
                w.unplace(t, tag)?;
            }
            Ok(())
        })
    }

    /// Undoes my newest change to `t` (made on any of my devices; never someone else's); `false`
    /// when there is none. Its creation is not undone: that commit also placed it, so reverting
    /// it would leave the thing in no group, gone from the app but not deleted.
    pub fn undo(&self, t: Tid) -> Result<bool> {
        let scope = Scope::Thing(t);
        if let Some(c) = self.db.created(t).and_then(|c| c.commit)
            && self.next_undo(&scope)? == Some(ChangeId::Commit(c))
        {
            return Ok(false);
        }
        Ok(self.db.undo(&scope)?.is_some())
    }

    /// The change `Osis::undo` would revert in `scope`: my newest change in effect that is not
    /// itself an undo (an even number of reverts deep).
    fn next_undo(&self, scope: &Scope) -> Result<Option<ChangeId>> {
        let mine = self.db.commits(&CommitQuery::new().scope(scope.clone()).actor(self.db.me()))?;
        let reverts: BTreeMap<ChangeId, ChangeId> = mine.iter().filter_map(|e| e.reverts.map(|r| (e.commit.id, r))).collect();
        let depth = |mut id: ChangeId| {
            let mut d = 0usize;
            while let Some(r) = reverts.get(&id) {
                (d, id) = (d + 1, *r);
            }
            d
        };
        Ok(mine
            .iter()
            .filter(|e| matches!(e.kind, CommitKind::Change | CommitKind::Revert | CommitKind::Ephemeral))
            .find(|e| e.in_effect && depth(e.commit.id) % 2 == 0)
            .map(|e| e.commit.id))
    }

    /// "Edited 5 min ago" for `t` (its newest change).
    pub fn edited(&self, t: Tid) -> String {
        match self.changed(t) {
            Some(ms) => format!("Edited {}", ago(self.db.now().0.saturating_sub(ms))),
            None => "Not saved yet".into(),
        }
    }

    // ---- events

    /// An event's span in local wall time (`time::span`); `None` when not scheduled.
    pub fn span(&self, t: Tid) -> Result<Option<(i64, i64, bool)>> {
        let Some(s) = self.get(t, crate::event::START)? else { return Ok(None) };
        Ok(Some(crate::time::span(&s, self.get(t, crate::event::END)?.as_ref())))
    }

    /// The events touching local wall ms `[from, to)`, repeating ones expanded (an occurrence
    /// replaced by an event naming it in `/event/overrides` is left out), by start.
    pub fn events_between(&self, from: i64, to: i64) -> Result<Vec<Shown>> {
        use crate::event::{END, OVERRIDES, REPEAT, START};
        let evs = self.view_items(&View::Calendar)?;
        let mut overridden: BTreeMap<Tid, Vec<crate::event::Occurrence>> = BTreeMap::new();
        for t in &evs {
            if let Some(o) = self.get(*t, OVERRIDES)? {
                overridden.entry(o.series).or_default().push(o.at);
            }
        }
        let mut out = Vec::new();
        for t in evs {
            let Some(start) = self.get(t, START)? else { continue };
            let end = self.get(t, END)?;
            match self.get(t, REPEAT)? {
                Some(r) => {
                    let skip = overridden.get(&t).map(Vec::as_slice).unwrap_or_default();
                    for (_, s, e, all_day) in crate::time::occurrences(&start, end.as_ref(), &r, from, to, skip) {
                        out.push(Shown { tid: t, start: s, end: e, all_day, repeats: true });
                    }
                }
                None => {
                    let (s, e, all_day) = crate::time::span(&start, end.as_ref());
                    if s < to && (e > from || (e == s && s >= from)) {
                        out.push(Shown { tid: t, start: s, end: e, all_day, repeats: false });
                    }
                }
            }
        }
        out.sort_by_key(|x| (x.start, x.tid));
        Ok(out)
    }

    /// The seven days from `monday` (local wall ms), each with the occurrences touching it.
    pub fn week(&self, monday: i64) -> Result<Vec<(i64, Vec<Shown>)>> {
        use crate::time::DAY;
        let evs = self.events_between(monday, monday + 7 * DAY)?;
        Ok((0..7)
            .map(|i| {
                let day = monday + i * DAY;
                let on = evs.iter().filter(|x| x.start < day + DAY && (x.end > day || x.start >= day)).cloned().collect();
                (day, on)
            })
            .collect())
    }

    /// Moves an event's start by `by` ms (its end along with it, in the end's own form) and, for a
    /// nonzero `longer`, sets its length to the current one plus `longer` (not below 15 min; a day
    /// event moves and grows by whole days). Writes through `edit`, so a concurrent change to another
    /// part survives.
    pub fn nudge(&self, t: Tid, by: i64, longer: i64) -> Result<()> {
        use crate::event::{END, End, START, Start};
        use crate::time::{DAY, MINUTE};
        let Some(start) = self.get(t, START)? else { return Ok(()) };
        let end = self.get(t, END)?;
        let (s, e, _) = crate::time::span(&start, end.as_ref());
        let (new_start, new_end) = match &start {
            Start::At(w) => {
                let ns = Start::At(crate::event::Wall { time: w.time.saturating_add(by), zone: w.zone.clone() });
                let ne = if longer == 0 {
                    // a move keeps the end's form: a moment stays one, an end time moves along
                    match &end {
                        Some(End::At(x)) => Some(End::At(crate::event::Wall { time: x.time.saturating_add(by), zone: x.zone.clone() })),
                        other => other.clone(),
                    }
                } else {
                    let len = match &end {
                        Some(End::After(d)) => *d,
                        _ => e.saturating_sub(s),
                    };
                    Some(End::After(len.saturating_add(longer).max(15 * MINUTE)))
                };
                (ns, ne)
            }
            Start::Day(d) => {
                let days = by.div_euclid(DAY);
                let nd = d.saturating_add(days);
                let ne = if longer == 0 {
                    match &end {
                        Some(End::Day(x)) => Some(End::Day(x.saturating_add(days))),
                        other => other.clone(),
                    }
                } else {
                    let span = (e.saturating_sub(s) / DAY).max(1).saturating_add(longer.div_euclid(DAY)).max(1);
                    if span > 1 { Some(End::Day(nd.saturating_add(span - 1))) } else { None }
                };
                (Start::Day(nd), ne)
            }
        };
        self.db.write_with(|w| {
            w.at(t, START).set(&new_start)?;
            match (&end, &new_end) {
                (_, Some(ne)) => w.at(t, END).set(ne),
                (Some(_), None) => w.at(t, END).remove(),
                (None, None) => Ok(()),
            }
        })
    }

    /// Makes an event repeat every period of `freq` from its start (`None`: not at all).
    pub fn set_repeat(&self, t: Tid, freq: Option<crate::event::RepeatFreq>) -> Result<()> {
        use crate::event::{REPEAT, Repeat};
        self.db.write_with(|w| match freq {
            Some(freq) => w.at(t, REPEAT).set(&Repeat { freq, interval: 1, weekdays: Default::default(), monthdays: Default::default(), until: None, count: None, skip: Default::default() }),
            None => w.at(t, REPEAT).remove(),
        })
    }

    /// Top-level tags (in no other tag), each with its subtags; by name.
    pub fn tag_tree(&self) -> Result<Vec<(Tid, Vec<Tid>)>> {
        let tags = self.all_tags()?;
        let mut inner = BTreeSet::new();
        for g in &tags {
            inner.extend(self.tag_contents(*g)?.0);
        }
        // a cycle of tags has no top: show them all then
        let top: Vec<Tid> = if tags.iter().all(|g| inner.contains(g)) { tags.clone() } else { tags.iter().copied().filter(|g| !inner.contains(g)).collect() };
        let mut out = Vec::new();
        for g in top {
            out.push((g, self.tag_contents(g)?.0));
        }
        Ok(out)
    }

    // ---- favorites

    /// The favorites in order: the main group's list, then any others' extras; things gone are
    /// skipped, a duplicate view stands for the one `views` keeps.
    pub fn favorites(&self) -> Result<Vec<Tid>> {
        let mut out: Vec<Tid> = Vec::new();
        let all = self.things()?;
        let views = self.view_map()?;
        for g in self.groups()? {
            for t in self.get(g, FAVORITES)?.unwrap_or_default() {
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

    fn view_map(&self) -> Result<BTreeMap<View, Tid>> {
        Ok(self.views()?.into_iter().collect())
    }

    /// The thing a favorites entry shows: a duplicate view stands for the one `views` keeps.
    fn shown_as(&self, views: &BTreeMap<View, Tid>, t: Tid) -> Result<Tid> {
        Ok(match self.get(t, VIEW)? {
            Some(v) => views.get(&v).copied().unwrap_or(t),
            None => t,
        })
    }

    /// Adds `t` at the end of the main group's favorites, or removes it from every group's list.
    /// Entries stay in the group holding them: copying another group's entries into the main
    /// list would bring back one that a device removes meanwhile.
    pub fn toggle_favorite(&self, t: Tid) -> Result<()> {
        let mut edits = Vec::new();
        if self.is_favorite(t)? {
            let views = self.view_map()?;
            for g in self.groups()? {
                let base = self.get(g, FAVORITES)?.unwrap_or_default();
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
            let base = self.get(g, FAVORITES)?.unwrap_or_default();
            let mut new = base.clone();
            new.push(t);
            edits.push((g, base, new));
        }
        self.write_favorites(&edits)
    }

    /// Moves the favorite at `from` to `to` (indices into `favorites()`), by a sequence move
    /// inside the list that holds it: a device removing it meanwhile wins (a move never brings
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
            let list = self.get(g, FAVORITES)?.unwrap_or_default();
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
            return self.db.write_with(|w| w.at(g, FAVORITES).path(p![]).move_range(i..i + 1, dest));
        }
        Ok(())
    }

    fn write_favorites(&self, edits: &[(Tid, Vec<Tid>, Vec<Tid>)]) -> Result<()> {
        self.db.write_with(|w| {
            for (g, base, new) in edits {
                w.at(*g, FAVORITES).edit(base, new)?;
            }
            Ok(())
        })
    }

    // ---- the look (per person, on the app group)

    /// The chosen theme id (`None`: the default) and mode.
    pub fn look(&self) -> Result<(Option<String>, Mode)> {
        let mut theme = None;
        let mut mode = None;
        for g in self.groups()? {
            theme = theme.or(self.get(g, THEME)?);
            mode = mode.or(self.get(g, MODE)?);
        }
        Ok((theme, mode.unwrap_or(Mode::Auto)))
    }

    pub fn set_theme(&self, id: &str) -> Result<()> {
        let g = self.main_group()?;
        if self.get(g, THEME)?.as_deref() == Some(id) {
            return Ok(());
        }
        self.db.write_with(|w| w.at(g, THEME).set(&id.to_string()))
    }

    pub fn set_mode(&self, m: Mode) -> Result<()> {
        let g = self.main_group()?;
        if self.get(g, MODE)? == Some(m.clone()) {
            return Ok(());
        }
        self.db.write_with(|w| w.at(g, MODE).set(&m))
    }

    // ---- navigation (per-device ephemeral view state on the main group)

    /// This device's entry in the app groups (the main group's first: an entry made before a
    /// smaller group arrived is on another one).
    fn open_entry(&self) -> Result<Option<Tid>> {
        let node = self.db.node();
        for g in self.groups()? {
            if let Some(t) = self.get(g, OPEN)?.and_then(|m| m.get(&node).copied()) {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    /// The thing this device has open; `None`: home (also when it was deleted meanwhile).
    pub fn opened(&self) -> Result<Option<Tid>> {
        let Some(t) = self.open_entry()? else { return Ok(None) };
        Ok(Some(t).filter(|t| self.things().is_ok_and(|all| all.contains(t))))
    }

    /// Opens `t` on this device (`None`: home); the entry lives on the main group only.
    pub fn set_open(&self, t: Option<Tid>) -> Result<()> {
        let main = self.main_group()?;
        let node = self.db.node();
        let mut stale = Vec::new();
        for g in self.groups()? {
            if g != main && self.get(g, OPEN)?.is_some_and(|m| m.contains_key(&node)) {
                stale.push(g);
            }
        }
        let here = self.get(main, OPEN)?.and_then(|m| m.get(&node).copied());
        if here == t && stale.is_empty() {
            return Ok(());
        }
        self.db.write_with(|w| {
            for g in &stale {
                w.at(*g, OPEN).path(p![]).remove_key(&node)?;
            }
            match t {
                Some(t) if here != Some(t) => w.at(main, OPEN).path(p![]).put(&node, &t),
                None if here.is_some() => w.at(main, OPEN).path(p![]).remove_key(&node),
                _ => Ok(()),
            }
        })
    }

    // ---- writes

    /// A new empty note in the app group, opened on this device.
    pub fn create_note(&self) -> Result<Tid> {
        self.create(NewKind::Note)
    }

    /// A new thing of `kind` in the app group, opened on this device. An event starts at the
    /// next full hour for an hour; a contact gets an empty `/contact/names`; a tag the next
    /// colour of `TAG_COLORS`.
    pub fn create(&self, kind: NewKind) -> Result<Tid> {
        let g = self.main_group()?;
        let db = &self.db;
        let node = db.node();
        let n_tags = if kind == NewKind::Tag { self.all_tags()?.len() } else { 0 };
        let now = crate::time::now_local();
        db.write_with(|w| {
            let t = w.create(db.me())?;
            w.at(t, NAME).set(&String::new())?;
            match kind {
                NewKind::Note => {}
                NewKind::Event => {
                    const HOUR: i64 = 3_600_000;
                    let start = (now / HOUR + 1) * HOUR;
                    w.at(t, crate::event::START).set(&crate::event::Start::At(crate::event::Wall { time: start, zone: None }))?;
                    w.at(t, crate::event::END).set(&crate::event::End::After(HOUR))?;
                }
                NewKind::Contact => {
                    w.at(t, crate::contact::NAMES).set(&crate::contact::Names { given: None, family: None, middle: None, prefix: None, suffix: None })?;
                }
                NewKind::Tag => {
                    w.make_group(t)?;
                    let c = TAG_COLORS.get(n_tags % TAG_COLORS.len()).map(|c| c.to_string());
                    w.at(t, TAG).set(&osis::core::Tag { color: c })?;
                    w.add_subgroup(g, t)?;
                }
            }
            w.place(t, g)?;
            w.at(g, OPEN).path(p![]).put(&node, &t)?;
            Ok(t)
        })
    }

    /// Deletes `t` (every aspect, placement and subgroup edge: a deleted tag must not stay in
    /// the app group as an empty thing) and goes home if it was open.
    pub fn delete(&self, t: Tid) -> Result<()> {
        let was = self.opened()? == Some(t);
        let mut parents = Vec::new();
        // `groups_of` follows membership, not subgroup edges: look at every group the app shows
        for g in self.groups()?.into_iter().chain(self.things()?) {
            // a group I cannot edit keeps its edge (to a now empty thing) rather than fail the delete
            let writable = matches!(self.db.role_on(g), Some(osis::Role::Write | osis::Role::Admin));
            if writable && self.get(g, GROUP)?.is_some_and(|gr| gr.subgroups.contains(&t)) {
                parents.push(g);
            }
        }
        self.db.write_with(|w| {
            for g in &parents {
                w.remove_subgroup(*g, t)?;
            }
            w.delete(t)
        })?;
        if was { self.set_open(None) } else { Ok(()) }
    }

    /// Whether demo data was added to this person's app group.
    pub fn has_demo(&self) -> Result<bool> {
        for g in self.groups()? {
            if self.get(g, DEMO)? == Some(true) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ---- search

    /// Scans every thing's name, body and text aspects for `q` (case-folded). Empty `q`: nothing.
    pub fn search(&self, q: &str) -> Result<Found> {
        let q = fold(q.trim());
        let mut f = Found::default();
        if q.is_empty() {
            return Ok(f);
        }
        let all = self.things()?;
        let mut rest = Vec::new();
        for t in &all {
            let kind = self.kind(*t)?;
            let name = fold(&self.name(*t)?);
            if kind.is_scope() {
                if name.contains(&q) {
                    f.scopes.push(*t);
                }
                continue;
            }
            if name.contains(&q) {
                f.named.push(*t);
                continue;
            }
            let text = self.text_of(*t)?;
            match snippet(&text, &q) {
                Some(s) => f.mentions.push((*t, s)),
                None => rest.push(*t),
            }
        }
        for t in rest {
            if self.tags_of(t)?.iter().any(|g| f.scopes.contains(g)) {
                f.in_scopes.push(t);
            }
        }
        // views hold things by kind, not placement
        for (v, vt) in self.views()? {
            if f.scopes.contains(&vt) {
                for t in self.view_items(&v)? {
                    if !f.named.contains(&t) && !f.mentions.iter().any(|(x, _)| *x == t) && !f.in_scopes.contains(&t) && !f.scopes.contains(&t) {
                        f.in_scopes.push(t);
                    }
                }
            }
        }
        for v in [&mut f.scopes, &mut f.named, &mut f.in_scopes] {
            self.sort_by_name(v)?;
        }
        Ok(f)
    }

    /// The searchable text of a thing besides its name: body, place, contact fields.
    fn text_of(&self, t: Tid) -> Result<String> {
        let mut parts = vec![self.body(t)?];
        parts.extend(self.get(t, crate::event::LOCATION)?);
        if let Some(o) = self.get(t, crate::contact::ORG)? {
            parts.extend([o.name, o.department, o.title]);
        }
        parts.extend(self.get(t, crate::contact::EMAILS)?.unwrap_or_default().into_keys());
        parts.extend(self.get(t, crate::contact::PHONES)?.unwrap_or_default().into_keys());
        Ok(parts.into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n"))
    }
}

/// Whether a roster edge is in force at `now` (an `until` ends it).
fn live(e: &Edge, now: osis::WallMs) -> bool {
    e.until.is_none_or(|u| u > now)
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

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The first non-blank line, trimmed.
pub fn first_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

/// Case folding for search, char by char (so indices match the text's and every place folds
/// alike; `str::to_lowercase` maps a final sigma by context).
pub fn fold(s: &str) -> String {
    s.chars().map(|c| c.to_lowercase().next().unwrap_or(c)).collect()
}

/// A one-line excerpt of `text` around the first match of `q` (already `fold`ed), or `None`.
pub fn snippet(text: &str, q: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = fold(text).chars().collect();
    let qc: Vec<char> = q.chars().collect();
    if qc.is_empty() {
        return None;
    }
    let at = lower.windows(qc.len()).position(|w| w == qc.as_slice())?;
    let a = at.saturating_sub(12);
    let b = (at + qc.len() + 40).min(chars.len());
    let mut s: String = chars.get(a..b).unwrap_or_default().iter().collect::<String>().replace('\n', " · ");
    if a > 0 {
        s.insert(0, '…');
    }
    if b < chars.len() {
        s.push('…');
    }
    Some(s)
}

/// (year, month 1-12, day 1-31) of a day count since 1970-01-01 (proleptic Gregorian).
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// "Mon 14 Oct" for a day count.
pub fn fmt_day(days: i64) -> String {
    let (_, m, d) = civil(days);
    let wd = WEEKDAYS.get(days.saturating_add(3).rem_euclid(7) as usize).copied().unwrap_or("");
    format!("{wd} {d} {}", MONTHS.get(m as usize - 1).copied().unwrap_or(""))
}

/// "09:30" for a wall time's ms within its day.
pub fn fmt_time(ms: i64) -> String {
    let m = ms.rem_euclid(86_400_000) / 60_000;
    format!("{:02}:{:02}", m / 60, m % 60)
}

/// An event's time as one line: "Mon 14 Oct · 09:30–09:45", "Mon 14 Oct" for a day.
/// In the viewer's local time (`time::span`).
pub fn fmt_when(start: &crate::event::Start, end: Option<&crate::event::End>) -> String {
    use crate::time::DAY;
    let (s, e, all_day) = crate::time::span(start, end);
    let (sd, ed) = (s.div_euclid(DAY), e.saturating_sub(1).max(s).div_euclid(DAY));
    if all_day {
        return if ed > sd { format!("{} – {}", fmt_day(sd), fmt_day(ed)) } else { fmt_day(sd) };
    }
    let mut out = format!("{} · {}", fmt_day(sd), fmt_time(s));
    if e > s {
        out.push('–');
        if e.div_euclid(DAY) != sd {
            out.push_str(&fmt_day(e.div_euclid(DAY)));
            out.push(' ');
        }
        out.push_str(&fmt_time(e));
    }
    out
}
