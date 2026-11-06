//! Shared setup for the standard-data scenarios: nodes and a peer in process
//! (osis-sim's `World`: manual clock, in-memory hubs, no sleeps, no network).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::common::TestWrites as _;
use crate::common::CreateIn;
use osis::core::{NAME, TAG, Tag};
use osis::{Osis, Result, Tid};
use osis_sim::world::World;

/// An account on peer `host`, settled.
pub fn account(w: &mut World, seed: u64, host: usize) -> Osis {
    let db = w.account(seed, &[host]);
    w.run();
    db
}

/// `db` imports `other`'s contact card; returns `other`'s account actor.
pub fn introduce(w: &mut World, db: &Osis, other: &Osis) -> Tid {
    let card = other.contact_card().unwrap();
    w.run();
    w.until(db.import_contact(&card), 1000, 10).unwrap()
}

/// A tag under the account, synced under its own label (a shareable root, not added to home).
pub fn new_tag(db: &Osis, name: &str) -> Result<Tid> {
    let mut w = db.write();
    let t = w.create()?;
    w.at(t, TAG).set(&Tag::default())?;
    w.at(t, NAME).set(&name.to_string())?;
    w.commit()?;
    db.sync(t, &[])?;
    Ok(t)
}

/// An account's private tag: a tag group in its home, an item (its own aspects sync) and a
/// subgroup (its items sync), so every node has it and nobody else does.
pub fn private_tag(db: &Osis, name: &str) -> Result<Tid> {
    db.commit_with(|w| {
        let t = w.create_in(db.me(), &[db.me()])?;
        w.group(db.me()).add(osis::Member::Subgroup(t))?;
        w.at(t, TAG).set(&Tag::default())?;
        w.at(t, NAME).set(&name.to_string())?;
        Ok(t)
    })
}

/// The names of the tags a thing is in, as this node knows them.
pub fn tag_names(db: &Osis, thing: Tid) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for g in db.groups_of(thing).unwrap().within {
        if db.at(g, TAG).get()?.is_some() {
            out.push(db.at(g, NAME).get()?.unwrap_or_default());
        }
    }
    out.sort();
    Ok(out)
}
