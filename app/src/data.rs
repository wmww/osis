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

use crate::schema::{APP, COLOR, DEMO, FAVORITES, OPEN, VIEW, View};
use osis::core::{BODY, GROUP, NAME, TAG};
use osis::{Config, Osis, Result, Runtime, ServerAddr, Tid, Transport, p};
use std::collections::BTreeSet;
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
        Data { db }
    }

    // ---- the app group

    /// The app groups among home's subgroups, smallest tid first.
    pub fn groups(&self) -> Result<Vec<Tid>> {
        let db = &self.db;
        let home = db.home();
        let subs = db.get(home, GROUP)?.map(|g| g.subgroups).unwrap_or_default();
        let mut out = Vec::new();
        for t in subs {
            if t != home && db.get(t, APP)? == Some(true) {
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
        let db = &self.db;
        let groups = self.groups()?;
        let mut seen = BTreeSet::new();
        let mut todo: Vec<Tid> = Vec::new();
        for g in &groups {
            if let Some(gr) = db.get(*g, GROUP)? {
                todo.extend(gr.items.iter().chain(gr.subgroups.iter()).filter(|t| !groups.contains(t)));
            }
        }
        while let Some(t) = todo.pop() {
            if !seen.insert(t) {
                continue;
            }
            if db.get(t, TAG)?.is_some()
                && let Some(gr) = db.get(t, GROUP)?
            {
                todo.extend(gr.items.iter().chain(gr.subgroups.iter()).filter(|x| !groups.contains(x) && !seen.contains(x)));
            }
        }
        Ok(seen)
    }

    /// The app's views, one per kind (the smallest tid where two devices both made one).
    pub fn views(&self) -> Result<Vec<(View, Tid)>> {
        let mut out: Vec<(View, Tid)> = Vec::new();
        for t in self.things()? {
            if let Some(v) = self.db.get(t, VIEW)?
                && !out.iter().any(|(x, _)| *x == v)
            {
                out.push((v, t));
            }
        }
        out.sort();
        Ok(out)
    }

    // ---- reading things

    pub fn kind(&self, t: Tid) -> Result<Kind> {
        if let Some(v) = self.db.get(t, VIEW)? {
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
        Ok(self.db.get(t, NAME)?.unwrap_or_default())
    }

    pub fn body(&self, t: Tid) -> Result<String> {
        Ok(self.db.get(t, BODY)?.unwrap_or_default())
    }

    /// The thing's own colour: a tag's `/tag.color`, else `/osis-app/color`.
    pub fn own_color(&self, t: Tid) -> Result<Option<String>> {
        if let Some(c) = self.db.get(t, TAG)?.and_then(|g| g.color) {
            return Ok(Some(c));
        }
        self.db.get(t, COLOR)
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
        for g in self.db.groups_of(t) {
            if self.db.get(g, TAG)?.is_some() && self.db.get(g, GROUP)?.is_some_and(|gr| gr.items.contains(&t)) {
                out.push(g);
            }
        }
        self.sort_by_name(&mut out)?;
        Ok(out)
    }

    /// A tag's subtags and items (subtags are not repeated among the items), each by name.
    pub fn tag_contents(&self, tag: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
        let g = self.db.get(tag, GROUP)?.unwrap_or_default();
        let mut subs = Vec::new();
        for s in &g.subgroups {
            if *s != tag && self.db.get(*s, TAG)?.is_some() {
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

    /// When `t` last changed (wall ms of its newest change, else its creation).
    pub fn changed(&self, t: Tid) -> Option<u64> {
        let q = osis::CommitQuery::new().scope(osis::Scope::Thing(t)).limit(1);
        let newest = self.db.commits(&q).ok().and_then(|c| c.first().map(|e| e.commit.ts));
        newest.or_else(|| self.db.created(t).map(|c| c.ts)).map(|ts| ts.wall_ms().0)
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
            Kind::Event => match self.db.get(t, crate::event::START)? {
                Some(st) => fmt_when(&st, self.db.get(t, crate::event::END)?.as_ref()),
                None => self.db.get(t, crate::event::LOCATION)?.unwrap_or_else(|| "Not scheduled".into()),
            },
            Kind::Contact => {
                let org = self.db.get(t, crate::contact::ORG)?.map(|o| if o.title.is_empty() { o.name } else { o.title }).filter(|s| !s.is_empty());
                let email = || self.db.get(t, crate::contact::EMAILS).ok().flatten().and_then(|m| m.keys().next().cloned());
                org.or_else(email).unwrap_or_else(|| "Contact".into())
            }
            Kind::Tag => {
                let (s, i) = self.tag_contents(t)?;
                count(s.len() + i.len(), "item", "items")
            }
            Kind::View(v) => {
                let n = self.view_items(v)?.len();
                match v {
                    View::Calendar => count(n, "event", "events"),
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

    // ---- favorites

    /// The favorites in order: the main group's list, then any others' extras; things gone are skipped.
    pub fn favorites(&self) -> Result<Vec<Tid>> {
        let mut out: Vec<Tid> = Vec::new();
        let all = self.things()?;
        for g in self.groups()? {
            for t in self.db.get(g, FAVORITES)?.unwrap_or_default() {
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

    /// Adds `t` at the end of the favorites, or removes it.
    pub fn toggle_favorite(&self, t: Tid) -> Result<()> {
        let mut favs = self.favorites()?;
        match favs.iter().position(|x| *x == t) {
            Some(i) => drop(favs.remove(i)),
            None => favs.push(t),
        }
        self.set_favorites(&favs)
    }

    /// Moves the favorite at `from` to `to` (indices into `favorites()`).
    pub fn move_favorite(&self, from: usize, to: usize) -> Result<()> {
        let mut favs = self.favorites()?;
        if from >= favs.len() || to >= favs.len() {
            return Ok(());
        }
        let t = favs.remove(from);
        favs.insert(to, t);
        self.set_favorites(&favs)
    }

    fn set_favorites(&self, favs: &[Tid]) -> Result<()> {
        let g = self.main_group()?;
        let base = self.db.get(g, FAVORITES)?.unwrap_or_default();
        self.db.write_with(|w| w.at(g, FAVORITES).edit(&base, &favs.to_vec()))
    }

    // ---- navigation (per-device ephemeral view state on the main group)

    /// The thing this device has open; `None`: home.
    pub fn opened(&self) -> Result<Option<Tid>> {
        let Some(g) = self.groups()?.first().copied() else { return Ok(None) };
        let t = self.db.get(g, OPEN)?.and_then(|m| m.get(&self.db.node()).copied());
        Ok(t.filter(|t| self.db.knows(*t)))
    }

    /// Opens `t` on this device (`None`: home).
    pub fn set_open(&self, t: Option<Tid>) -> Result<()> {
        if self.opened()? == t {
            return Ok(());
        }
        let g = self.main_group()?;
        let node = self.db.node();
        self.db.write_with(|w| match t {
            Some(t) => w.at(g, OPEN).path(p![]).put(&node, &t),
            None => w.at(g, OPEN).path(p![]).remove_key(&node),
        })
    }

    // ---- writes

    /// A new empty note in the app group, opened on this device.
    pub fn create_note(&self) -> Result<Tid> {
        let g = self.main_group()?;
        let db = &self.db;
        let node = db.node();
        db.write_with(|w| {
            let t = w.create(db.me())?;
            w.at(t, NAME).set(&String::new())?;
            w.place(t, g)?;
            w.at(g, OPEN).path(p![]).put(&node, &t)?;
            Ok(t)
        })
    }

    /// Deletes `t` (every aspect and placement) and goes home if it was open.
    pub fn delete(&self, t: Tid) -> Result<()> {
        let was = self.opened()? == Some(t);
        self.db.write_with(|w| w.delete(t))?;
        if was { self.set_open(None) } else { Ok(()) }
    }

    /// Whether demo data was added to this person's app group.
    pub fn has_demo(&self) -> Result<bool> {
        for g in self.groups()? {
            if self.db.get(g, DEMO)? == Some(true) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ---- search

    /// Scans every thing's name, body and text aspects for `q` (case-folded). Empty `q`: nothing.
    pub fn search(&self, q: &str) -> Result<Found> {
        let q = q.trim().to_lowercase();
        let mut f = Found::default();
        if q.is_empty() {
            return Ok(f);
        }
        let all = self.things()?;
        let mut rest = Vec::new();
        for t in &all {
            let kind = self.kind(*t)?;
            let name = self.name(*t)?.to_lowercase();
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
        let db = &self.db;
        let mut parts = vec![self.body(t)?];
        parts.extend(db.get(t, crate::event::LOCATION)?);
        if let Some(o) = db.get(t, crate::contact::ORG)? {
            parts.extend([o.name, o.department, o.title]);
        }
        parts.extend(db.get(t, crate::contact::EMAILS)?.unwrap_or_default().into_keys());
        parts.extend(db.get(t, crate::contact::PHONES)?.unwrap_or_default().into_keys());
        Ok(parts.into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n"))
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The first non-blank line, trimmed.
pub fn first_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

/// A one-line excerpt of `text` around the first match of `q` (already lowercase), or `None`.
pub fn snippet(text: &str, q: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = chars.iter().map(|c| c.to_lowercase().next().unwrap_or(*c)).collect();
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
    let z = days + 719_468;
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
    let wd = WEEKDAYS.get((days + 3).rem_euclid(7) as usize).copied().unwrap_or("");
    format!("{wd} {d} {}", MONTHS.get(m as usize - 1).copied().unwrap_or(""))
}

/// "09:30" for a wall time's ms within its day.
pub fn fmt_time(ms: i64) -> String {
    let m = ms.rem_euclid(86_400_000) / 60_000;
    format!("{:02}:{:02}", m / 60, m % 60)
}

/// An event's time as one line: "Mon 14 Oct · 09:30–09:45", "Mon 14 Oct" for a day.
pub fn fmt_when(start: &crate::event::Start, end: Option<&crate::event::End>) -> String {
    use crate::event::{End, Start};
    const DAY: i64 = 86_400_000;
    match start {
        Start::At(w) => {
            let s = format!("{} · {}", fmt_day(w.time.div_euclid(DAY)), fmt_time(w.time));
            match end {
                Some(End::At(e)) => format!("{s}–{}", fmt_time(e.time)),
                Some(End::After(d)) => format!("{s}–{}", fmt_time(w.time + d)),
                _ => s,
            }
        }
        Start::Day(d) => match end {
            Some(End::Day(e)) if e > d => format!("{} – {}", fmt_day(*d), fmt_day(*e)),
            _ => fmt_day(*d),
        },
    }
}
