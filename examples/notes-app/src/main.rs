//! A local walk through the notes app: one device, no servers.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use std::io::Read;

fn main() {
    let (db, _) = osis::Osis::create(osis::Config::memory()).unwrap();
    let nb = notes_app::new_notebook(&db, "Ideas").unwrap();
    let note = notes_app::new_note(&db, nb, "Groceries").unwrap();
    notes_app::type_text(&db, note, 0, "milk, eggs").unwrap();
    notes_app::type_text(&db, note, 10, ", tea").unwrap();
    notes_app::undo(&db, note).unwrap();
    notes_app::tag(&db, note, "home").unwrap();
    notes_app::attach(&db, note, "# Recipes\n".repeat(10_000).as_bytes()).unwrap();
    let mut head = [0u8; 9];
    notes_app::attachment(&db, note).unwrap().unwrap().read_exact(&mut head).unwrap();
    println!("{}: {:?} {:?}", notes_app::title(&db, note).unwrap().unwrap(), notes_app::body(&db, note).unwrap(), notes_app::tags(&db, note).unwrap());
    println!("attachment starts {:?}", String::from_utf8_lossy(&head));
}
