//! tags: the tag pattern of notes/tags.md over the `osis` API, as scenario functions the tests
//! and the binary drive.
//! - A **tag** is a group with `/tag` and `/name`; any thing can be in any tag, tags nest as a
//!   graph. Internal groups carry no `/tag` and are never listed.
//! - **Sharing a tag** is per item through one roster: the tag gets members, and each thing in it
//!   (sub-tags included) gets an edge for the tag. Rights chain through the edges, so a member of
//!   the tag reaches a sub-tag's things by tag → sub-tag → thing, at the minimum role along the
//!   way. Things keep their tid and owner. A thing only placed in a tag, without an edge, is not
//!   shared: placing it needs write on the tag, the edge needs admin on the thing (only what you
//!   may share).
//! - Writers may also create things **owned by the tag**; moving a thing to another owner is a
//!   copy with a new tid.
#![forbid(unsafe_code)]

use osis::core::{GROUP, NAME, TAG, Tag};
use osis::{Demotion, EdgeOpts, Lower, Osis, Place, Result, Role, Tid};

/// Typed keys generated from tags.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/tags.rs"));
}
pub use schema::TEXT;

/// A new tag owned by the person, synced under its own label (a shareable root; not placed in
/// the home group, notes/api.md `create`).
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

/// A new sub-tag of `parent`, owned by `owner` (the person, or the parent tag for a tag-owned
/// one), with an edge for the parent so the parent's members reach what the sub-tag holds.
pub fn new_sub_tag(db: &Osis, owner: Tid, parent: Tid, name: &str, role: Role) -> Result<Tid> {
    let t = db.write_with(|w| {
        let t = w.create(owner, Place::In(parent))?;
        w.make_group(t)?;
        w.at(t, TAG).set(&Tag::default())?;
        w.at(t, NAME).set(&name.to_string())?;
        w.add_subgroup(parent, t)?;
        Ok(t)
    })?;
    if owner != parent {
        db.grant(t, parent, role, EdgeOpts::default())?;
    }
    Ok(t)
}

/// A new card owned by `owner`, placed nowhere yet.
pub fn new_card(db: &Osis, owner: Tid, text: &str) -> Result<Tid> {
    db.write_with(|w| {
        let c = w.create(owner, Place::Unsynced)?;
        w.at(c, TEXT).set(&text.to_string())?;
        Ok(c)
    })
}

/// Adds a thing the person owns to a tag: places it and gives the tag's actor an edge with `role`,
/// so the tag's members reach it (capped by their role on the tag) and it syncs under the tag's
/// label (spec/sync.md §3, entitlement). Placing alone shares nothing. First-party apps confirm
/// this with the user when the tag is shared (notes/tags.md).
pub fn add(db: &Osis, tag: Tid, thing: Tid, role: Role) -> Result<()> {
    db.write_with(|w| w.place(thing, tag))?;
    db.grant(thing, tag, role, EdgeOpts::default())
}

/// Places a thing in a tag without an edge (a thing the tag's owner may read anyway, or one the
/// person may not share on).
pub fn place(db: &Osis, tag: Tid, thing: Tid) -> Result<()> {
    db.write_with(|w| w.place(thing, tag))
}

/// Removes a thing from a tag and ends the tag's edge on it (the thing's secrets rotate).
pub async fn remove(db: &Osis, tag: Tid, thing: Tid) -> Result<()> {
    db.write_with(|w| w.unplace(thing, tag))?;
    db.demote(thing, tag, Lower::Remove, Demotion::default()).await
}

/// Overwrites a card's text (what the user saw is `shown`).
pub fn edit(db: &Osis, card: Tid, shown: &str, new: &str) -> Result<()> {
    db.write_with(|w| w.at(card, TEXT).edit(&shown.to_string(), &new.to_string()))
}

pub fn text(db: &Osis, card: Tid) -> Result<Option<String>> {
    db.get(card, TEXT)
}

pub fn name(db: &Osis, t: Tid) -> Result<Option<String>> {
    db.get(t, NAME)
}

/// The things in a tag and its sub-tags (subgroups carrying `/tag`); other subgroups are internal.
pub fn list(db: &Osis, tag: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
    let g = db.get(tag, GROUP)?.unwrap_or_default();
    let things = g.items.iter().filter(|t| !g.subgroups.contains(t)).copied().collect();
    let mut subs = Vec::new();
    for s in g.subgroups {
        if db.get(s, TAG)?.is_some() {
            subs.push(s);
        }
    }
    Ok((things, subs))
}

/// The tags a thing is in that this node knows (groups carrying `/tag`).
pub fn tags_of(db: &Osis, thing: Tid) -> Result<Vec<Tid>> {
    let mut out = Vec::new();
    for g in db.groups_of(thing) {
        if db.get(g, TAG)?.is_some() {
            out.push(g);
        }
    }
    Ok(out)
}

/// Gives a person a role on the tag and, through the edges, on everything in it; with `invite`,
/// they may grant up to that role to others themselves.
pub fn share(db: &Osis, tag: Tid, person: Tid, role: Role, invite: Option<Role>) -> Result<()> {
    db.grant(tag, person, role, EdgeOpts { until: None, invite })
}

/// Lowers a person's role on the tag (or removes them) after syncing what they wrote.
pub async fn demote(db: &Osis, tag: Tid, person: Tid, to: Lower) -> Result<()> {
    db.demote(tag, person, to, Demotion::default()).await
}

/// Transfers a thing to another owner, placed in `group`: a copy with a new tid (the old owner
/// keeps the original). Rare; never what "move between tags" means.
pub fn transfer(db: &Osis, thing: Tid, owner: Tid, group: Tid) -> Result<Tid> {
    db.move_thing(thing, owner, Place::In(group))
}
