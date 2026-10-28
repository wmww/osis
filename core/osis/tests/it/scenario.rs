//! Shared setup for the standard-data scenarios: databases and a blind server in process
//! (osis-sim's `World`: manual clock, in-memory hubs, no sleeps, no network).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use osis::core::{NAME, TAG, Tag};
use osis::{Osis, Place, Result, Tid};
use osis_sim::world::World;

/// A person on server `sv`, settled.
pub fn person(w: &mut World, seed: u64, sv: usize) -> Osis {
    let db = w.person(seed, &[sv]).unwrap().0;
    w.run();
    db
}

/// `db` imports `other`'s contact card; returns `other`'s person actor.
pub fn introduce(w: &mut World, db: &Osis, other: &Osis) -> Tid {
    let card = other.contact_card().unwrap();
    w.run();
    w.until(db.import_contact(&card), 1000, 10).expect("card imported").unwrap()
}

/// A tag owned by the person, synced under its own label (a shareable root, not placed in home).
pub fn new_tag(db: &Osis, name: &str) -> Result<Tid> {
    let t = db.write_with(|w| {
        let t = w.create(db.me(), Place::Unsynced)?;
        w.make_group(t)?;
        w.at(t, TAG).set(&Tag::default())?;
        w.at(t, NAME).set(&name.to_string())?;
        Ok(t)
    })?;
    db.sync(t, &[])?;
    Ok(t)
}

/// A person's private tag: a tag group in its home, so every device has it and nobody else does.
pub fn private_tag(db: &Osis, name: &str) -> Result<Tid> {
    db.write_with(|w| {
        let t = w.create(db.me(), Place::In(db.home()))?;
        w.make_group(t)?;
        w.at(t, TAG).set(&Tag::default())?;
        w.at(t, NAME).set(&name.to_string())?;
        Ok(t)
    })
}

/// The names of the tags a thing is in, as this node knows them.
pub fn tag_names(db: &Osis, thing: Tid) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for g in db.groups_of(thing) {
        if db.get(g, TAG)?.is_some() {
            out.push(db.get(g, NAME)?.unwrap_or_default());
        }
    }
    out.sort();
    Ok(out)
}
