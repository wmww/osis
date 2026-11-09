//! Who can see a thing, when it changed, undo.

use crate::store::Reader;
use crate::view::{Act, Action, Block, Chip, Cx, Do, Facet, Icon, Input, Section};
use osis::core::{NAME, TAG};
use osis::{Grant, Result, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

pub struct AboutFacet;
pub static FACET: AboutFacet = AboutFacet;

/// Who can see a thing.
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

fn live(e: &Grant, now: osis::Time) -> bool {
    e.until.is_none_or(|u| u > now)
}

/// Who can see `t`: its holders (its first admin among them while that edge stands), through
/// holder actors (shared tags) down to people; me and my nodes are "you". Grants with an `until`
/// count until it passes.
pub fn reach(cx: &Reader, t: Tid) -> Result<Reach> {
    Ok((*cx.memo(("reach", t), |r, &(_, t)| compute_reach(r, t))?).clone())
}

fn compute_reach(cx: &Reader, t: Tid) -> Result<Reach> {
    let db = &cx.db;
    let me = db.me();
    let now = cx.now()?;
    let mine: BTreeSet<Tid> = db.grants(me)?.into_keys().chain([me, db.node()]).collect();
    let mut r = Reach::default();
    let mut seen = BTreeSet::new();
    let mut todo = vec![t];
    while let Some(x) = todo.pop() {
        if !seen.insert(x) {
            continue;
        }
        if x != t && mine.contains(&x) {
            continue;
        }
        if x != t && db.has_content(x)? && db.at(x, TAG).get()?.is_some() {
            // a shared tag: its holders see what it holds
            r.via.push(x);
        } else if x != t {
            let name = account_name(cx, x)?;
            if !r.people.contains(&name) {
                r.people.push(name);
            }
            continue;
        }
        todo.extend(db.grants(x)?.into_iter().filter(|(_, e)| live(e, now)).map(|(m, _)| m));
    }
    r.people.sort();
    Ok(r)
}

/// Who each profile thing stands for, among what is held: one memo over per-item summaries.
fn standing_for(cx: &Reader) -> Result<Rc<BTreeMap<Tid, String>>> {
    cx.memo(("standing for", ()), |r, _| {
        let mut out = BTreeMap::new();
        for t in r.things()?.iter() {
            let s = r.summary(*t)?;
            if let Some(p) = s.profile {
                out.entry(p).or_insert(s.name);
            }
        }
        Ok(out)
    })
}

/// An account's display name: their profile's `name.0`, else a thing that says it stands for that
/// profile, else a short id.
pub fn account_name(cx: &Reader, p: Tid) -> Result<String> {
    let db = &cx.db;
    if let Some(prof) = db.profile_of(p)? {
        if let Some(n) = db.at(prof, NAME).get()?.filter(|n| !n.is_empty()) {
            return Ok(n);
        }
        if let Some(n) = standing_for(cx)?.get(&prof) {
            return Ok(n.clone());
        }
    }
    Ok(format!("someone ({})", p.to_string().chars().take(6).collect::<String>()))
}

/// Undoes my newest change to a thing. Pending typing is the newest change, so it is committed
/// first; open editors show the undo.
#[derive(Clone, Debug, PartialEq)]
struct Undo(Tid);
impl Action for Undo {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.window.sessions.commit(self.0)?;
        act.undo(self.0).map(|_| ())
    }
}

/// The Undo chip: pressable while there is something to undo (pending typing is: Undo commits it
/// first), else inert ("Can't undo" when the newest change cannot be undone).
fn undo_chip(cx: &Cx, t: Tid) -> Result<Chip> {
    let _ = cx.local(crate::view::TYPED)?;
    if cx.window.sessions.pending(cx, t)? {
        return Ok(Chip::action(Icon::Back, "Undo", Do::new(Undo(t))));
    }
    // a memo: a write moves what can be undone, seldom whether it can
    let undoable = cx.memo(("undoable", t), |r, &(_, t)| match r.can_undo(t) {
        Ok(b) => Ok(Some(b)),
        Err(osis::Error::NotUndoable { .. }) => Ok(None),
        Err(e) => Err(e),
    })?;
    Ok(match *undoable {
        Some(true) => Chip::action(Icon::Back, "Undo", Do::new(Undo(t))),
        Some(false) => Chip::info(Icon::Back, "Undo"),
        None => Chip::info(Icon::Back, "Can't undo"),
    })
}

impl Facet for AboutFacet {
    fn id(&self) -> &'static str {
        "about"
    }
    fn claims(&self, _: &str) -> bool {
        false
    }
    fn applies(&self, _: &Reader, _: Tid) -> Result<bool> {
        Ok(true)
    }
    fn universal(&self) -> bool {
        true
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let d = cx;
        let r = reach(cx, t)?;
        let mut who = r.who();
        if !r.via.is_empty() {
            let via: Result<Vec<String>> = r.via.iter().map(|g| d.name(*g)).collect();
            who = format!("{who} · via {}", via?.join(", "));
        }
        Ok(Section::of(vec![Block::Chips(vec![Chip::info(Icon::Eye, &who), Chip::info(Icon::Clock, &d.edited(t)?), undo_chip(cx, t)?])]))
    }
}
