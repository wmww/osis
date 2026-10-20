//! Folders with rights end to end (notes/permissions.md Patterns), tier 1 (the slower cases tier 2): databases and a blind
//! server in process (osis-sim's `World`: manual clock, in-memory hubs, no sleeps, no network).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use folder::*;
use osis::{Error, Lower, Osis, Place, Role, Tid};
use osis_sim::world::World;

fn person(w: &mut World, seed: u64, sv: usize) -> Osis {
    let db = w.person(seed, &[sv]).unwrap().0;
    w.run();
    db
}

/// `db` imports `other`'s contact card; returns `other`'s person actor.
fn introduce(w: &mut World, db: &Osis, other: &Osis) -> Tid {
    let card = other.contact_card().unwrap();
    w.run();
    w.until(db.import_contact(&card), 1000, 10).expect("card imported").unwrap()
}

/// Alice's root folder with a subfolder holding one file ("v1"): (root, docs, file).
fn tree(alice: &Osis) -> (Tid, Tid, Tid) {
    let root = new_root(alice, "Projects").unwrap();
    let docs = new_subfolder(alice, root, root, "docs").unwrap();
    let spec = new_file(alice, root, docs, "spec.md", "v1").unwrap();
    (root, docs, spec)
}

// spec/permissions.md §2 (roles), §3, §5 (demotion), spec/requirements.md (Permissions:
// grouping grants no rights; readers only read), notes/permissions.md Patterns (folder actor
// owning its things): one edge on the root gives a role on the whole tree, subfolders included;
// a reader reads and cannot write; a writer adds files; a demoted writer writes no more and
// what it wrote stays.
#[test]
#[ignore = "tier 2"]
fn reader_writer_demotion() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let [reader, writer] = [2, 3].map(|s| person(&mut w, s, sv));
    let (root, docs, spec) = tree(&alice);
    let r = introduce(&mut w, &alice, &reader);
    let wr = introduce(&mut w, &alice, &writer);
    share(&alice, root, r, Role::Read, None).unwrap();
    share(&alice, root, wr, Role::Write, None).unwrap();
    w.run();

    assert_eq!(content(&reader, spec).unwrap().as_deref(), Some("v1"), "subfolders inherit through ownership");
    assert_eq!(list(&reader, root).unwrap().1, vec![docs]);
    assert!(matches!(edit_file(&reader, spec, "v1", "hacked"), Err(Error::Permission { .. })));
    assert!(matches!(new_file(&reader, root, docs, "x", "y"), Err(Error::Permission { .. })));

    let notes = new_file(&writer, root, docs, "notes.md", "from the writer").unwrap();
    edit_file(&writer, spec, "v1", "v2").unwrap();
    w.run();
    assert_eq!(content(&alice, notes).unwrap().as_deref(), Some("from the writer"));
    assert_eq!(content(&reader, spec).unwrap().as_deref(), Some("v2"));

    w.until(demote(&alice, root, wr, Lower::To(Role::Read)), 1000, 20).expect("pre-sync").unwrap();
    w.run();
    assert_eq!(writer.role_on(root), Some(Role::Read));
    assert!(matches!(edit_file(&writer, spec, "v2", "v3"), Err(Error::Permission { .. })));
    assert_eq!(content(&reader, notes).unwrap().as_deref(), Some("from the writer"), "earlier writes stay");
}

// spec/permissions.md §2 (invite grants: up to the invite role), notes/permissions.md Patterns
// (folder with rights): an invite holder shares the tree on, not above its invite role.
#[test]
#[ignore = "tier 2"]
fn invite_holder_shares_on() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let [inviter, guest] = [4, 5].map(|s| person(&mut w, s, sv));
    let (root, _, spec) = tree(&alice);
    let iv = introduce(&mut w, &alice, &inviter);
    share(&alice, root, iv, Role::Read, Some(Role::Read)).unwrap();
    w.run();
    let g = introduce(&mut w, &inviter, &guest);
    assert!(matches!(share(&inviter, root, g, Role::Write, None), Err(Error::Permission { .. })), "invite only up to read");
    share(&inviter, root, g, Role::Read, None).unwrap();
    w.run();
    assert_eq!(content(&guest, spec).unwrap().as_deref(), Some("v1"));
    assert_eq!(alice.roster(root).get(&g).map(|e| e.role), Some(Role::Read));
}

// spec/permissions.md §7 (moving is a copy with imported history), notes/permissions.md
// Patterns (moving a thing out of a folder actor): the copy has a new tid and owner, the folder
// keeps the original, and the folder's members do not read the copy.
#[test]
fn move_out_is_a_copy() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let root = new_root(&alice, "Shared").unwrap();
    let f = new_file(&alice, root, root, "diary", "private now").unwrap();
    let b = introduce(&mut w, &alice, &bob);
    share(&alice, root, b, Role::Read, None).unwrap();
    w.run();
    assert_eq!(content(&bob, f).unwrap().as_deref(), Some("private now"));
    let mine = move_out(&alice, f, alice.me(), alice.home()).unwrap();
    assert_ne!(mine, f);
    assert!(alice.same_thing(mine, f));
    w.run();
    assert_eq!(content(&alice, mine).unwrap().as_deref(), Some("private now"));
    assert_eq!(content(&bob, mine).unwrap(), None, "the copy is the person's own");
}

// notes/permissions.md Patterns (folder with rights, mirrored-edges variant), spec/sync.md §3
// (entitlement), spec/requirements.md (Permissions: grouping grants no rights): things owned by
// the person in a shared group, each with an edge for the group's actor: a member reads them
// (also one added after it joined) and cannot write them past its role; a thing only placed
// there stays unshared.
#[test]
fn mirrored_edges_variant() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let b = introduce(&mut w, &alice, &bob);
    let group = new_root(&alice, "Photos").unwrap();
    let mk = |v: &str| {
        let mut wr = alice.write();
        let t = wr.create(alice.me(), Place::Unsynced).unwrap();
        wr.at(t, CONTENT).set(&v.to_string()).unwrap();
        wr.commit().unwrap();
        t
    };
    let first = mk("beach");
    add_mirrored(&alice, group, first, Role::Write).unwrap();
    share(&alice, group, b, Role::Read, None).unwrap();
    w.run();
    let second = mk("mountain");
    add_mirrored(&alice, group, second, Role::Write).unwrap();
    let elsewhere = mk("not shared");
    alice.write_with(|wr| wr.place(elsewhere, group)).unwrap();
    w.run();
    assert_eq!(content(&bob, first).unwrap().as_deref(), Some("beach"));
    assert_eq!(content(&bob, second).unwrap().as_deref(), Some("mountain"));
    assert_eq!(bob.role_on(second), Some(Role::Read), "capped by the role on the group");
    assert!(matches!(edit_file(&bob, second, "mountain", "x"), Err(Error::Permission { .. })));
    assert_eq!(content(&bob, elsewhere).unwrap(), None, "placed without an edge: not shared");
}
