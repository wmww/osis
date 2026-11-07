//! Notes (notes/std.md): a note is `name.0` plus a markdown `body.0`; a notebook is a tag that is first admin of
//! its notes. Tier 1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use crate::scenario as common;
use common::*;
use crate::common::CreateIn;
use osis::core::{BODY, NAME};
use osis::internals::core_types::{GROUP};
use osis::{Error, Osis, Result, Role, SyncScope, Tid, Scope};
use osis_sim::world::World;

/// A new note in `notebook`, under it (so the notebook's holders read and write it).
fn new_note(db: &Osis, notebook: Tid, title: &str) -> Result<Tid> {
    db.commit_with(|w| {
        let note = w.create_in(notebook, &[notebook])?;
        w.at(note, NAME).set(&title.to_string())?;
        Ok(note)
    })
}

fn notes(db: &Osis, notebook: Tid) -> Result<Vec<Tid>> {
    Ok(db.at(notebook, GROUP).get()?.map(|g| g.items.into_iter().filter(|t| *t != notebook).collect()).unwrap_or_default())
}

fn title(db: &Osis, note: Tid) -> Result<Option<String>> {
    db.at(note, NAME).get()
}

fn rename(db: &Osis, note: Tid, shown: &str, new: &str) -> Result<()> {
    db.commit_with(|w| w.at(note, NAME).edit(&shown.to_string(), &new.to_string()))
}

fn body(db: &Osis, note: Tid) -> Result<String> {
    Ok(db.at(note, BODY).get()?.unwrap_or_default())
}

/// Types `text` into the body at char `at` in one editing session: one commit for the pause.
fn type_text(db: &Osis, note: Tid, at: usize, text: &str) -> Result<()> {
    let s = db.at(note, BODY).path(osis::p![]).edit_text()?;
    s.splice(at..at, text)?;
    s.commit()?;
    Ok(())
}

fn undo(db: &Osis, note: Tid) -> Result<bool> {
    Ok(db.undo(&Scope::Thing(note))?.is_some())
}

fn redo(db: &Osis, note: Tid) -> Result<bool> {
    Ok(db.redo(&Scope::Thing(note))?.is_some())
}

fn add_node(existing: &Osis, cfg: osis::internals::Opening) -> Result<Osis> {
    let joining = osis::internals::pair(cfg, &existing.pair_offer()?)?;
    let (_, reply) = existing.pair_accept(joining.request())?;
    joining.finish(&reply)
}

// spec/requirements.md (Offline and network: every operation completes offline; Data model:
// collaborative text), notes/api.md Undo (per actor, across nodes): two nodes of one account
// see each other's notes; offline edits on both merge on reconnect; undo on one node undoes
// the account's last commit wherever it was made (spec/crdt.md §4.6: undo is per actor, derived
// from its commits).
#[test]
fn two_nodes_offline_edits_and_undo() {
    let mut w = World::new();
    let host = w.add_host();
    let laptop = account(&mut w, 1, host);
    let phone = add_node(&laptop, w.cfg(2, &[])).unwrap();
    let nb = new_tag(&laptop, "Home").unwrap();
    let note = new_note(&laptop, nb, "Groceries").unwrap();
    type_text(&laptop, note, 0, "milk").unwrap();
    w.run();
    assert_eq!(notes(&phone, nb).unwrap(), vec![note]);
    assert_eq!(body(&phone, note).unwrap(), "milk");

    w.set_online(&phone, false);
    type_text(&phone, note, 4, ", eggs").unwrap();
    type_text(&laptop, note, 0, "- ").unwrap();
    w.run();
    assert_eq!(body(&laptop, note).unwrap(), "- milk", "the phone's edit waits for the network");
    w.set_online(&phone, true);
    w.until(phone.wait_synced(SyncScope::AllWithSavedPeers), 1000, 10).unwrap();
    w.run();
    assert_eq!(body(&laptop, note).unwrap(), "- milk, eggs");
    assert_eq!(body(&phone, note).unwrap(), "- milk, eggs");

    rename(&laptop, note, "Groceries", "Shopping").unwrap();
    w.run();
    assert!(undo(&phone, note).unwrap());
    w.run();
    assert_eq!(title(&laptop, note).unwrap().as_deref(), Some("Groceries"));
    assert!(redo(&laptop, note).unwrap());
    w.run();
    assert_eq!(title(&phone, note).unwrap().as_deref(), Some("Shopping"));
}

// spec/permissions.md §2 (grants), §3 (removal), notes/permissions.md Patterns (share a set of
// things through one actor), notes/api.md Writes (edit merges concurrent changes), notes/tags.md
// (a reader's tags are its own): Alice shares a notebook with Bob; both edit one note at once
// without clobbering; Alice's private tag on it stays hers; Bob's new note reaches Alice; after
// Bob's removal he reads nothing new and what he wrote stays.
#[test]
fn share_notebook_with_a_second_account() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = account(&mut w, 1, host);
    let bob = account(&mut w, 2, host);
    let b = introduce(&mut w, &alice, &bob);
    let nb = new_tag(&alice, "Trip").unwrap();
    let plan = new_note(&alice, nb, "Plan").unwrap();
    alice.grant(nb, b, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(title(&bob, plan).unwrap().as_deref(), Some("Plan"));
    assert_eq!(bob.role_on(plan).unwrap(), Some(Role::Write));

    rename(&bob, plan, "Plan", "Plan: Lisbon").unwrap();
    let travel = private_tag(&alice, "travel").unwrap();
    alice.commit_with(|w| w.group(travel).add(osis::Member::Item(plan))).unwrap();
    type_text(&alice, plan, 0, "flights").unwrap();
    w.run();
    for db in [&alice, &bob] {
        assert_eq!(title(db, plan).unwrap().as_deref(), Some("Plan: Lisbon"));
        assert_eq!(body(db, plan).unwrap(), "flights");
    }
    assert_eq!(tag_names(&alice, plan).unwrap(), ["Trip", "travel"]);
    assert_eq!(tag_names(&bob, plan).unwrap(), ["Trip"], "Alice's tag is her own");
    let packing = new_note(&bob, nb, "Packing").unwrap();
    w.run();
    assert!(notes(&alice, nb).unwrap().contains(&packing));

    alice.set_role(nb, b, None, Default::default()).unwrap();
    let secret = new_note(&alice, nb, "Surprise").unwrap();
    w.run();
    assert_eq!(title(&bob, secret).unwrap(), None, "removed: nothing new");
    assert!(matches!(new_note(&bob, nb, "again"), Err(Error::Permission { .. })), "no write any more");
    assert_eq!(title(&alice, packing).unwrap().as_deref(), Some("Packing"), "his earlier note stays");
}

// spec/data-model.md §6 (large atomic values), notes/api.md Large values (materialization bound,
// streams): a large body syncs to the other node, which reads it by stream and length while a
// whole read fails `TooLarge` explicitly.
#[test]
fn large_body_streams() {
    let mut w = World::new();
    let host = w.add_host();
    let laptop = account(&mut w, 1, host);
    let mut cfg = w.cfg(2, &[]);
    cfg.app.read_limit = 64 << 10;
    let phone = add_node(&laptop, cfg).unwrap();
    let nb = new_tag(&laptop, "Books").unwrap();
    let note = new_note(&laptop, nb, "Draft").unwrap();
    // just above `CHUNK_THRESHOLD`: a large value
    let doc: String = (0..13_000).map(|i| format!("line {i}\n")).collect();
    laptop.commit_with(|w| w.at(note, BODY).path(osis::p![]).set_stream(doc.as_bytes())).unwrap();
    w.run();
    assert!(matches!(phone.at(note, BODY).get(), Err(Error::TooLarge { .. })));
    let mut s = phone.at(note, BODY).path(osis::p![]).stream().unwrap().expect("synced");
    assert_eq!(s.len(), doc.len() as u64);
    let mut got = String::new();
    std::io::Read::read_to_string(&mut s, &mut got).unwrap();
    assert!(got == doc, "streamed content equals what was written");
}

// spec/crdt.md §4.6 (undo and redo); notes/api.md Undo (history lists everyone's changes; undo
// and redo own ones), offline: one node without peers keeps a full local history. The stack
// here walks two aspects.
#[test]
fn local_undo_redo_and_history() {
    let db = osis::internals::create(osis::internals::Opening::memory()).unwrap();
    let nb = new_tag(&db, "Local").unwrap();
    let note = new_note(&db, nb, "a").unwrap();
    rename(&db, note, "a", "b").unwrap();
    type_text(&db, note, 0, "x").unwrap();
    assert!(undo(&db, note).unwrap());
    assert_eq!(body(&db, note).unwrap(), "");
    assert!(undo(&db, note).unwrap());
    assert_eq!(title(&db, note).unwrap().as_deref(), Some("a"));
    assert!(redo(&db, note).unwrap());
    assert_eq!(title(&db, note).unwrap().as_deref(), Some("b"));
    type_text(&db, note, 0, "y").unwrap();
    assert!(!redo(&db, note).unwrap(), "a new change clears redo");
    let h = db.commits(&osis::CommitQuery { scope: Some(Scope::Thing(note)), ..Default::default() }).unwrap();
    assert!(h.len() >= 4, "{h:?}");
}
