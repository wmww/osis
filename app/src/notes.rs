//! The actions layer for notes (notes/app.md Layers): toolkit-free, every intent becomes osis
//! reads and writes here. A note is a thing with core `/name` and `/body`, placed in the app's
//! internal notes group (an item and subgroup of the home group, marked `/osis-app/notes`, no `/tag`), which is
//! what syncs it to the person's other devices. Each device's selected note is durable view state
//! on that group (`/osis-app/selected`, keyed by the device's node tid).
//!
//! Two devices that start before syncing each create a notes group; every marked group in home
//! is read, so both groups' notes show everywhere; new notes and the selection go to the
//! smallest-tid group.

use crate::schema::{NOTES, SELECTED};
use osis::core::{GROUP, NAME};
use osis::{Config, Osis, Place, Result, Runtime, ServerAddr, Tid, Transport, p};
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

/// What the notes app does with a database.
#[derive(Clone)]
pub struct Notes {
    pub db: Osis,
}

impl Notes {
    pub fn new(db: Osis) -> Notes {
        Notes { db }
    }

    /// The marked notes groups among home's subgroups, smallest tid first.
    pub fn groups(&self) -> Result<Vec<Tid>> {
        let db = &self.db;
        let home = db.home();
        let items = db.get(home, GROUP)?.map(|g| g.subgroups).unwrap_or_default();
        let mut out = Vec::new();
        for t in items {
            if t != home && db.get(t, NOTES)? == Some(true) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// The group new notes and the selection go to; created on first use.
    pub fn main_group(&self) -> Result<Tid> {
        if let Some(g) = self.groups()?.first() {
            return Ok(*g);
        }
        let db = &self.db;
        db.write_with(|w| {
            // an item of home (its own aspects sync) and a subgroup (its items sync: a group's
            // members are its items and its subgroups' members, not its items' items)
            let g = w.create(db.me(), Place::In(db.home()))?;
            w.make_group(g)?;
            w.add_subgroup(db.home(), g)?;
            w.at(g, NOTES).set(&true)?;
            Ok(g)
        })
    }

    /// Every note with its name (`""` when unnamed), sorted by name (case-folded), then tid.
    pub fn list(&self) -> Result<Vec<(Tid, String)>> {
        let db = &self.db;
        let groups = self.groups()?;
        let mut tids = std::collections::BTreeSet::new();
        for g in &groups {
            for t in db.get(*g, GROUP)?.map(|x| x.items).unwrap_or_default() {
                if !groups.contains(&t) {
                    tids.insert(t);
                }
            }
        }
        let mut out = Vec::new();
        for t in tids {
            out.push((t, db.get(t, NAME)?.unwrap_or_default()));
        }
        out.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()).then(a.0.cmp(&b.0)));
        Ok(out)
    }

    /// A new note named `name` in the main group, selected on this device.
    pub fn create(&self, name: &str) -> Result<Tid> {
        let db = &self.db;
        let g = self.main_group()?;
        db.write_with(|w| {
            let t = w.create(db.me(), Place::In(g))?;
            w.at(t, NAME).set(&name.to_string())?;
            w.at(g, SELECTED).path(p![]).put(&db.node(), &t)?;
            Ok(t)
        })
    }

    /// Deletes a note (every aspect and placement); clears this device's selection if it was it.
    pub fn delete(&self, note: Tid) -> Result<()> {
        let db = &self.db;
        let g = self.main_group()?;
        let was = self.selected()? == Some(note);
        db.write_with(|w| {
            w.delete(note)?;
            if was {
                w.at(g, SELECTED).path(p![]).remove_key(&db.node())?;
            }
            Ok(())
        })
    }

    /// Selects `note` on this device (`None`: nothing).
    pub fn select(&self, note: Option<Tid>) -> Result<()> {
        let db = &self.db;
        let g = self.main_group()?;
        if self.selected()? == note {
            return Ok(());
        }
        db.write_with(|w| match note {
            Some(t) => w.at(g, SELECTED).path(p![]).put(&db.node(), &t),
            None => w.at(g, SELECTED).path(p![]).remove_key(&db.node()),
        })
    }

    /// This device's selected note, if it still is a note.
    pub fn selected(&self) -> Result<Option<Tid>> {
        let db = &self.db;
        let Some(g) = self.groups()?.first().copied() else { return Ok(None) };
        let sel = db.get(g, SELECTED)?.and_then(|m| m.get(&db.node()).copied());
        Ok(sel.filter(|t| self.is_note(*t)))
    }

    fn is_note(&self, t: Tid) -> bool {
        let gs = self.db.groups_of(t);
        self.groups().is_ok_and(|mine| mine.iter().any(|g| gs.contains(g)))
    }
}
