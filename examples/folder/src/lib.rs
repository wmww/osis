//! folder: shared folders with rights over the `osis` API (notes/permissions.md Patterns,
//! folder with rights), as scenario functions the tests and the binary drive. Rights live on
//! edges, never on grouping, and owners never change:
//! - **Folder actor**: the root folder is a group owned by the person and synced; it owns every
//!   subfolder and file below it, so one edge on the root gives a role on all of them. Members
//!   create new things with the root as owner. Moving a thing out is a copy.
//! - **Mirrored edges** (the other variant): things stay owned by the person; a helper gives
//!   each thing added to the folder an edge for the folder's actor (costly per thing).
#![forbid(unsafe_code)]

use osis::core::GROUP;
use osis::{Demotion, EdgeOpts, Lower, Osis, Place, Result, Role, Tid};

/// Typed keys generated from folder.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/folder.rs"));
}
pub use schema::{CONTENT, NAME};

/// A new root folder: a group owned by the person, in its home group, synced.
pub fn new_root(db: &Osis, name: &str) -> Result<Tid> {
    let mut w = db.write();
    let f = w.create(db.me(), Place::In(db.home()))?;
    w.make_group(f)?;
    w.at(f, NAME).set(&name.to_string())?;
    w.commit()?;
    db.sync(f, &[])?;
    Ok(f)
}

/// A subfolder of `parent`, owned by the root folder actor.
pub fn new_subfolder(db: &Osis, root: Tid, parent: Tid, name: &str) -> Result<Tid> {
    let mut w = db.write();
    let f = w.create(root, Place::In(parent))?;
    w.make_group(f)?;
    w.at(f, NAME).set(&name.to_string())?;
    w.add_subgroup(parent, f)?;
    w.commit()?;
    Ok(f)
}

/// A file in `folder`, owned by the root folder actor (needs write on the root).
pub fn new_file(db: &Osis, root: Tid, folder: Tid, name: &str, content: &str) -> Result<Tid> {
    let mut w = db.write();
    let f = w.create(root, Place::In(folder))?;
    w.at(f, NAME).set(&name.to_string())?;
    w.at(f, CONTENT).set(&content.to_string())?;
    w.commit()?;
    Ok(f)
}

/// Overwrites a file's content (what the user saw is `shown`).
pub fn edit_file(db: &Osis, file: Tid, shown: &str, new: &str) -> Result<()> {
    db.write_with(|w| w.at(file, CONTENT).edit(&shown.to_string(), &new.to_string()))?;
    Ok(())
}

pub fn content(db: &Osis, file: Tid) -> Result<Option<String>> {
    db.get(file, CONTENT)
}

pub fn name(db: &Osis, t: Tid) -> Result<Option<String>> {
    db.get(t, NAME)
}

/// The files of a folder (its items that are not subfolders), and its subfolders.
pub fn list(db: &Osis, folder: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
    let g = db.get(folder, GROUP)?.unwrap_or_default();
    let files = g.items.iter().filter(|t| !g.subgroups.contains(t)).copied().collect();
    Ok((files, g.subgroups.into_iter().collect()))
}

/// Gives a person a role on the whole folder tree; with `invite`, they may grant up to that
/// role to others themselves.
pub fn share(db: &Osis, root: Tid, person: Tid, role: Role, invite: Option<Role>) -> Result<()> {
    db.grant(root, person, role, EdgeOpts { until: None, invite })
}

/// Lowers a person's role on the folder tree (or removes them) after syncing what they wrote.
pub async fn demote(db: &Osis, root: Tid, person: Tid, to: Lower) -> Result<()> {
    db.demote(root, person, to, Demotion::default()).await
}

/// Moves a file out of the folder tree to `owner`, placed in `group`: a copy with a new tid
/// (the folder keeps the original).
pub fn move_out(db: &Osis, file: Tid, owner: Tid, group: Tid) -> Result<Tid> {
    db.move_thing(file, owner, Place::In(group))
}

/// Mirrored-edges variant: places a thing the person owns into a shared group and makes the
/// group's actor a member of the thing with `role`. The group's members reach the thing through
/// that edge, capped by their role on the group, and the thing syncs under the group's label
/// because the group's actor may read it (spec/sync.md §3, entitlement). Per-member edges on
/// the thing would not do: no label the members sync would carry it. Placing alone shares
/// nothing. Costs one edge and the thing's own secrets per thing.
pub fn add_mirrored(db: &Osis, group: Tid, thing: Tid, role: Role) -> Result<()> {
    db.write_with(|w| w.place(thing, group))?;
    db.grant(thing, group, role, EdgeOpts::default())
}
