//! Thing lifetimes through the API (issues/thing-lifetimes.md, API; notes/api.md Lifetimes):
//! `core::RETAINERS`, `AspectWrite::retaining`, `Write::release`, and the writer refusing its own
//! list change that leaves a thing unreachable. The judgment itself is node-sync's (node
//! `lifetimes::`); a thing under no label is judged at once, after each call.
//! spec/commits.md §5 Lifetimes, Ending.

use crate::common::*;
use osis::core::RETAINERS;
use osis::{DynamicAspectKey, Error, Osis, Step, Tid, Value, p};
use std::collections::BTreeSet;

fn files() -> DynamicAspectKey {
    DynamicAspectKey::untyped(ak("t:files.0"))
}

fn retainers(db: &Osis, x: Tid) -> Option<BTreeSet<Tid>> {
    db.at(x, RETAINERS).get().unwrap()
}

fn alive(db: &Osis, x: Tid) -> bool {
    db.created(x).unwrap().is_some()
}

/// A chat holding a file it retains, made in one commit with the chat existing before.
fn chat_with_file(db: &Osis) -> (Tid, Tid) {
    let chat = db.commit_with(|w| w.create()).unwrap();
    let file = db
        .commit_with(|w| {
            let f = w.create()?;
            w.at(chat, files()).retaining(f).path(p![]).add(&Value::Tid(f))?;
            Ok(f)
        })
        .unwrap();
    (chat, file)
}

// issues/thing-lifetimes.md (API, One motion): creating a thing referenced by a retainer is one
// commit; it lives while the reference does, and goes once the reference goes.
#[test]
fn a_thing_created_retained_lives_by_its_reference() {
    let db = db(1);
    let (chat, file) = chat_with_file(&db);
    assert_eq!(retainers(&db, file), Some([chat].into()));
    assert!(alive(&db, file));
    db.commit_with(|w| w.at(chat, files()).path(p![Step::Elem(Value::Tid(file))]).remove()).unwrap();
    assert!(!alive(&db, file), "released");
    assert!(alive(&db, chat));
}

// issues/thing-lifetimes.md (API, One motion): `retaining` with no reference from that aspect after
// the commit is refused, nothing applied; an existing reference is enough.
#[test]
fn retaining_needs_the_reference() {
    let db = db(1);
    let chat = db.commit_with(|w| w.create()).unwrap();
    let mut w = db.write();
    let f = w.create().unwrap();
    w.at(chat, files()).retaining(f);
    // the reference in another aspect is not this aspect's
    w.at(chat, DynamicAspectKey::untyped(ak("t:other.0"))).set(&Value::Tid(f)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("does not reference")));
    assert!(!alive(&db, f), "nothing applied");
    // a standalone thing the chat already references becomes retained
    let f = db.commit_with(|w| w.create()).unwrap();
    db.commit_set(chat, files(), &Value::Set([Value::Tid(f)].into_iter().collect())).unwrap();
    db.commit_with(|w| {
        w.at(chat, files()).retaining(f);
        Ok(())
    })
    .unwrap();
    assert_eq!(retainers(&db, f), Some([chat].into()));
}

// issues/thing-lifetimes.md (API, Move): a move is one `Write`: retained by the new place, out of
// the old; it is never released.
#[test]
fn a_one_commit_move_keeps_the_thing() {
    let db = db(1);
    let (a, file) = chat_with_file(&db);
    let b = db.commit_with(|w| w.create()).unwrap();
    db.commit_with(|w| {
        w.at(b, files()).retaining(file).path(p![]).add(&Value::Tid(file))?;
        w.at(a, files()).path(p![Step::Elem(Value::Tid(file))]).remove()?;
        w.at(file, RETAINERS).path(p![Step::Elem(Value::Tid(a))]).remove()
    })
    .unwrap();
    assert_eq!(retainers(&db, file), Some([b].into()));
    assert!(alive(&db, file));
}

// issues/thing-lifetimes.md (API): a write's own change of a thing's list that leaves it
// unreachable as this node judges it is refused, nothing applied: a list with no referencing
// retainer, an emptied list, a move under a thing that does not reference it. A list naming a
// thing this node does not hold is not judged.
#[test]
fn a_list_leaving_the_thing_unreachable_is_refused() {
    let db = db(1);
    let (chat, file) = chat_with_file(&db);
    let other = db.commit_with(|w| w.create()).unwrap();
    let set = |xs: &[Tid]| xs.iter().copied().collect::<BTreeSet<Tid>>();
    let refused = |r: osis::Result<()>| matches!(r, Err(Error::Invalid(m)) if m.contains("unreachable"));
    assert!(refused(db.commit_set(file, RETAINERS, &set(&[other]))), "moved under a thing not referencing it");
    assert!(refused(db.commit_set(file, RETAINERS, &set(&[]))), "emptied");
    let mut w = db.write();
    let x = w.create().unwrap();
    w.at(x, RETAINERS).set(&set(&[chat])).unwrap();
    assert!(refused(w.commit().map(|_| ())), "created listed, not referenced");
    assert!(!alive(&db, x));
    assert_eq!(retainers(&db, file), Some([chat].into()), "nothing applied");
    // made standalone: kept
    db.commit_with(|w| w.at(file, RETAINERS).remove()).unwrap();
    assert_eq!(retainers(&db, file), None);
    // a retainer not held here keeps
    let unknown = db2_thing();
    db.commit_with(|w| w.at(file, RETAINERS).set(&set(&[unknown]))).unwrap();
    db.commit_with(|w| w.at(chat, files()).remove()).unwrap();
    assert!(alive(&db, file));
}

/// A tid no node of this test holds.
fn db2_thing() -> Tid {
    let other = db(2);
    other.commit_with(|w| w.create()).unwrap()
}

// issues/thing-lifetimes.md (The release, API): `release` releases a retained thing at once, at
// every node it reaches, and it stays released where its referencer is held; a release is a
// commit of its own; a delete leaves the list.
#[test]
fn release_of_a_retained_thing() {
    let (a, b, _) = paired();
    let (chat, file) = chat_with_file(&a);
    deliver(&a, &b);
    assert!(alive(&b, file));
    let mut w = a.write();
    w.release(file).unwrap();
    w.at(chat, DynamicAspectKey::untyped(ak("t:n.0"))).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(m)) if m.contains("commit of its own")));
    a.commit_with(|w| w.release(file)).unwrap();
    assert!(!alive(&a, file), "released at once");
    assert!(!a.has_content(file).unwrap());
    assert!(matches!(a.commit_set(file, files(), &Value::Int(1)), Err(Error::UnknownThing { .. })), "written as an unknown thing");
    deliver(&a, &b);
    assert!(!alive(&b, file), "at every node it reaches");
    // the referencer delivered again keeps it released: the reference reads as gone
    deliver(&a, &b);
    assert!(!alive(&b, file));
    assert_eq!(a.at(chat, files()).get().unwrap(), Some(Value::Set([Value::Tid(file)].into_iter().collect())), "the reference dangles");
    // what only the released thing kept goes after it
    let (chat, file) = chat_with_file(&a);
    a.commit_with(|w| w.release(chat)).unwrap();
    assert!(!alive(&a, chat) && !alive(&a, file));
    // a delete leaves a thing's list: it is judged by its retainers still
    let (chat, file) = chat_with_file(&a);
    a.commit_with(|w| w.delete(file)).unwrap();
    assert_eq!(retainers(&a, file), Some([chat].into()));
    assert!(alive(&a, file));
}

