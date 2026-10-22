//! notes-app: a headless notes app over the `osis` API, as scenario functions the tests and the
//! binary drive. A notebook is a tag (notes/tags.md) owned by the person, synced under its own
//! label; its notes are owned by the notebook (notes/permissions.md Patterns: share a set of
//! things through one actor), so sharing the notebook shares every note in it. Names are the
//! core `/name`; a person's own tags on notes are private groups in its home. Typed keys come
//! from notes.osis by codegen (build.rs).
#![forbid(unsafe_code)]

use osis::core::{GROUP, NAME, TAG, Tag};
use osis::{Demotion, EdgeOpts, Lower, Osis, Path, Place, Result, Role, Tid, UndoScope, ValueStream};
use std::io::Read;

/// Typed keys generated from notes.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/notes.rs"));
}
pub use schema::{ATTACHMENT, BODY};

/// A new notebook named `name`: a tag owned by the person, synced under its own label on the
/// database's servers (not placed in home: its rotations stay out of the home label).
pub fn new_notebook(db: &Osis, name: &str) -> Result<Tid> {
    let nb = db.write_with(|w| {
        let nb = w.create(db.me(), Place::Unsynced)?;
        w.make_group(nb)?;
        w.at(nb, TAG).set(&Tag::default())?;
        w.at(nb, NAME).set(&name.to_string())?;
        Ok(nb)
    })?;
    db.sync(nb, &[])?;
    Ok(nb)
}

/// A new note in `notebook`, owned by it (so the notebook's members read and write it).
pub fn new_note(db: &Osis, notebook: Tid, title: &str) -> Result<Tid> {
    db.write_with(|w| {
        let note = w.create(notebook, Place::In(notebook))?;
        w.at(note, NAME).set(&title.to_string())?;
        Ok(note)
    })
}

/// The notes of a notebook (its group's items), in tid order.
pub fn notes(db: &Osis, notebook: Tid) -> Result<Vec<Tid>> {
    Ok(db.get(notebook, GROUP)?.map(|g| g.items.into_iter().filter(|t| *t != notebook).collect()).unwrap_or_default())
}

pub fn title(db: &Osis, note: Tid) -> Result<Option<String>> {
    db.get(note, NAME)
}

/// Renames a note from what the user saw (`shown`) to `new`: only the change is written, so a
/// concurrent rename elsewhere is merged, not clobbered blindly.
pub fn rename(db: &Osis, note: Tid, shown: &str, new: &str) -> Result<()> {
    db.write_with(|w| w.at(note, NAME).edit(&shown.to_string(), &new.to_string()))
}

/// A person's own tag: a tag group in its home, so every device has it and nobody else does.
pub fn new_tag(db: &Osis, name: &str) -> Result<Tid> {
    db.write_with(|w| {
        let t = w.create(db.me(), Place::In(db.home()))?;
        w.make_group(t)?;
        w.at(t, TAG).set(&Tag::default())?;
        w.at(t, NAME).set(&name.to_string())?;
        Ok(t)
    })
}

/// Tags a note: a placement written on the tag, so it works on notes the person cannot write.
pub fn tag(db: &Osis, note: Tid, tag: Tid) -> Result<()> {
    db.write_with(|w| w.place(note, tag))
}

/// The names of the tags a note is in, as this node knows them (a notebook is a tag too).
pub fn tags(db: &Osis, note: Tid) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for g in db.groups_of(note) {
        if db.get(g, TAG)?.is_some() {
            out.push(db.get(g, NAME)?.unwrap_or_default());
        }
    }
    out.sort();
    Ok(out)
}

/// The body text (empty when unwritten).
pub fn body(db: &Osis, note: Tid) -> Result<String> {
    Ok(db.get(note, BODY)?.unwrap_or_default())
}

/// Types `text` into the body at char `at` in one editing session: one commit for the pause.
pub fn type_text(db: &Osis, note: Tid, at: usize, text: &str) -> Result<()> {
    let s = db.edit_text(note, BODY, Path::root())?;
    s.insert(at, text)?;
    s.commit()?;
    Ok(())
}

/// Attaches a (possibly huge) markdown document from a reader.
pub fn attach(db: &Osis, note: Tid, doc: impl Read) -> Result<()> {
    db.write_with(|w| w.at(note, ATTACHMENT).set_stream(doc))
}

/// The attachment as a stream, never materialized whole.
pub fn attachment(db: &Osis, note: Tid) -> Result<Option<ValueStream>> {
    db.at(note, ATTACHMENT).stream()
}

/// Undoes this person's last change to the note (on any of its devices). False when there is
/// nothing to undo.
pub fn undo(db: &Osis, note: Tid) -> Result<bool> {
    Ok(db.undo(&UndoScope::Thing(note))?.is_some())
}

pub fn redo(db: &Osis, note: Tid) -> Result<bool> {
    Ok(db.redo(&UndoScope::Thing(note))?.is_some())
}

/// Shares the notebook with a person whose contact card was imported.
pub fn share(db: &Osis, notebook: Tid, person: Tid, role: Role) -> Result<()> {
    db.grant(notebook, person, role, EdgeOpts::default())
}

/// Stops sharing: removes the person after syncing what they wrote (the default pre-sync).
pub async fn unshare(db: &Osis, notebook: Tid, person: Tid) -> Result<()> {
    db.demote(notebook, person, Lower::Remove, Demotion::default()).await
}

/// Pairs a new device of the same person: the three texts would travel by QR code or
/// clipboard; here they are passed in memory.
pub fn add_device(existing: &Osis, cfg: osis::Config) -> Result<Osis> {
    let joining = Osis::pair(cfg, &existing.pair_offer()?)?;
    let (_, reply) = existing.pair_accept(joining.request())?;
    joining.finish(&reply)
}
