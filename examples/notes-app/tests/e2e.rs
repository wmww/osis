//! The notes app end to end, tier 1: databases and a blind server in process (osis-sim's
//! `World`: manual clock, in-memory hubs, no sleeps, no network).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use notes_app::*;
use osis::{Error, Osis, Role, SyncScope};
use osis_sim::world::World;
use std::io::Read;
use std::time::Duration;

/// A person on server `sv`, settled.
fn person(w: &mut World, seed: u64, sv: usize) -> Osis {
    let db = w.person(seed, &[sv]).unwrap().0;
    w.run();
    db
}

/// `alice` imports `other`'s contact card; returns `other`'s person actor.
fn introduce(w: &mut World, alice: &Osis, other: &Osis) -> osis::Tid {
    let card = other.contact_card().unwrap();
    w.run();
    w.until(alice.import_contact(&card), 1000, 10).expect("card imported").unwrap()
}

// spec/requirements.md (Offline and network: every operation completes offline; Data model:
// collaborative text), notes/api.md Undo (per actor, across devices): two devices of one person
// see each other's notes; offline edits on both merge on reconnect; undo on one device undoes
// the person's last change wherever it was made.
#[test]
fn two_devices_offline_edits_and_undo() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let laptop = person(&mut w, 1, sv);
    let phone = add_device(&laptop, w.cfg(2, &[])).unwrap();
    let nb = new_notebook(&laptop, "Home").unwrap();
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
    w.until(phone.wait_synced(SyncScope::All, Duration::from_secs(60)), 1000, 10).unwrap().unwrap();
    w.run();
    assert_eq!(body(&laptop, note).unwrap(), "- milk, eggs");
    assert_eq!(body(&phone, note).unwrap(), "- milk, eggs");

    // the laptop's "- " is the person's newest change: the phone may undo it
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
// without clobbering; Alice's tag on it stays hers; Bob's new note reaches Alice; after Bob's
// removal he reads nothing new and what he wrote stays.
#[test]
fn share_notebook_with_a_second_person() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let b = introduce(&mut w, &alice, &bob);
    let nb = new_notebook(&alice, "Trip").unwrap();
    let plan = new_note(&alice, nb, "Plan").unwrap();
    share(&alice, nb, b, Role::Write).unwrap();
    w.run();
    assert_eq!(title(&bob, plan).unwrap().as_deref(), Some("Plan"));
    assert_eq!(bob.role_on(plan), Some(Role::Write));

    rename(&bob, plan, "Plan", "Plan: Lisbon").unwrap();
    let travel = new_tag(&alice, "travel").unwrap();
    tag(&alice, plan, travel).unwrap();
    type_text(&alice, plan, 0, "flights").unwrap();
    w.run();
    for db in [&alice, &bob] {
        assert_eq!(title(db, plan).unwrap().as_deref(), Some("Plan: Lisbon"));
        assert_eq!(body(db, plan).unwrap(), "flights");
    }
    assert_eq!(tags(&alice, plan).unwrap(), ["Trip", "travel"]);
    assert_eq!(tags(&bob, plan).unwrap(), ["Trip"], "Alice's tag is her own");
    let packing = new_note(&bob, nb, "Packing").unwrap();
    w.run();
    assert!(notes(&alice, nb).unwrap().contains(&packing));

    w.until(unshare(&alice, nb, b), 1000, 20).expect("pre-sync").unwrap();
    let secret = new_note(&alice, nb, "Surprise").unwrap();
    w.run();
    assert_eq!(title(&bob, secret).unwrap(), None, "removed: nothing new");
    assert!(matches!(new_note(&bob, nb, "again"), Err(Error::Permission { .. })), "no write any more");
    assert_eq!(title(&alice, packing).unwrap().as_deref(), Some("Packing"), "his earlier note stays");
}

// spec/data-model.md §6 (large atomic values), notes/api.md Large values (materialization bound,
// streams): a large attachment syncs to the other device, which reads it by stream and length
// while a whole read fails `TooLarge` explicitly.
#[test]
fn large_attachment_streams() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let laptop = person(&mut w, 1, sv);
    let mut cfg = w.cfg(2, &[]);
    cfg.materialize_limit = 64 << 10;
    let phone = add_device(&laptop, cfg).unwrap();
    let nb = new_notebook(&laptop, "Books").unwrap();
    let note = new_note(&laptop, nb, "Draft").unwrap();
    let doc: String = (0..20_000).map(|i| format!("line {i}\n")).collect();
    attach(&laptop, note, doc.as_bytes()).unwrap();
    w.run();
    assert!(matches!(phone.get(note, ATTACHMENT), Err(Error::TooLarge { .. })));
    let mut s = attachment(&phone, note).unwrap().expect("synced");
    assert_eq!(s.len(), doc.len() as u64);
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    assert!(got == doc, "streamed content equals what was attached");
}

// notes/api.md Undo (history lists everyone's changes; undo and redo own ones), offline: one
// device without servers keeps a full local history. The stack here walks two aspects.
#[test]
fn local_undo_redo_and_history() {
    let db = Osis::create(osis::Config::memory()).unwrap().0;
    let nb = new_notebook(&db, "Local").unwrap();
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
    let h = db.history(&osis::UndoScope::Thing(note), Default::default()).unwrap();
    assert!(h.len() >= 4, "{h:?}");
}
