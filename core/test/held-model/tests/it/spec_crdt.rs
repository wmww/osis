//! spec/crdt.md §4.6 (un-merge), §4.8 (death).
use crate::util::*;
use held_model::gen::{MAP, REG, TEXT};
use held_model::*;

fn demoted(mut cs: Vec<Commit>, demote: bool) -> Held {
    cs.insert(0, edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None));
    if demote {
        cs.push(edge(20, FIRST_ADMIN, 3, 1, None, Some(vec![])));
    }
    held(4, cs)
}

// spec/crdt.md §4.6 (Un-merge): an invalid write is removed; what it beat shows again
#[test]
fn unmerge_removes_invalid_register_write_spec_crdt_4_6() {
    let cs = vec![reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1), reg(11, 1, 2, REG, Retention::PLAIN, 2)];
    assert_eq!(read(&demoted(cs.clone(), false), REG), int(2));
    assert_eq!(read(&demoted(cs, true), REG), int(1));
}

// spec/crdt.md §4.6 (Removed): others' writes nested in a record the invalid delta created go
#[test]
fn unmerge_removes_writes_nested_in_invalid_entry_spec_crdt_4_6() {
    let cs = vec![
        content(10, 1, 1, vec![part(MAP, Retention::PLAIN, vec![
            created(1, 10, 3), put(1, 10, 10, 3, 4)
        ])]),
        content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PLAIN, vec![put(2, 11, 10, 3, 9)])]),
    ];
    assert_eq!(read(&demoted(cs.clone(), false), MAP), map(&[(3, 9)]));
    assert_eq!(read(&demoted(cs, true), MAP), None);
}

// spec/crdt.md §4.6 (Seq elements), §6.1: an invalid creation leaves nothing; what anchors at it is placed at its
// virtual anchor on END
#[test]
fn unmerged_text_creation_places_nothing_spec_crdt_4_6() {
    let a = (10, 1);
    let cs = vec![
        content(10, 1, 1, vec![part(TEXT, Retention::PLAIN, vec![ins(1, 10, 1, None, Some(1))])]),
        content(11, FIRST_ADMIN, 2, vec![part(TEXT, Retention::PLAIN, vec![ins(2, 11, 1, Some(a), Some(2))])]),
    ];
    assert_eq!(read(&demoted(cs.clone(), false), TEXT), text(&[1, 2]));
    assert_eq!(read(&demoted(cs, true), TEXT), text(&[2]));
}

// spec/crdt.md §4.8, spec/commits.md §5: a body whose write a valid write superseded is replaced; the winner's is not
#[test]
fn superseded_write_is_replaced_spec_crdt_4_8() {
    let cs = vec![
        reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1),
        reg(11, FIRST_ADMIN, 3, REG, Retention::PLAIN, 2),
        reg(12, FIRST_ADMIN, 2, REG, Retention::PLAIN, 3),
    ];
    let o = evaluate(&held(4, cs));
    assert!(o.replaced.contains(&(10, 0)) && o.replaced.contains(&(12, 0)));
    assert!(!o.replaced.contains(&(11, 0)));
}

// spec/crdt.md §4.8 (Revival): an invalid superseder supersedes nothing
#[test]
fn invalid_superseder_kills_nothing_spec_crdt_4_8() {
    let cs = vec![reg(10, FIRST_ADMIN, 1, REG, Retention::PLAIN, 1), reg(11, 1, 2, REG, Retention::PLAIN, 2)];
    assert!(evaluate(&demoted(cs.clone(), false)).replaced.contains(&(10, 0)));
    assert!(!evaluate(&demoted(cs, true)).replaced.contains(&(10, 0)));
}

// spec/crdt.md §4.5: a text element its own commit inserted and deleted, kept because another
// write of the commit anchors at it, comes as its creation without its char; the delta is
// received whole, so what anchors at it reads
#[test]
fn charless_creation_deleted_in_its_commit_is_received_spec_crdt_4_5() {
    let a = (11, 1);
    let cs = vec![
        content(10, FIRST_ADMIN, 1, vec![part(TEXT, Retention::PLAIN, vec![ins(1, 10, 1, None, Some(1))])]),
        content(11, FIRST_ADMIN, 2, vec![part(TEXT, Retention::PLAIN, vec![
            ins(2, 11, 1, None, None),
            ins(2, 11, 2, Some(a), Some(2)),
        ])]),
    ];
    let h = held(4, cs);
    assert_eq!(read(&h, TEXT), text(&[2, 1]));
    assert_ne!(evaluate(&h).fates.get(&(11, 0)), Some(&Fate::NeverReceived));
}

// spec/crdt.md §5.7: a text element's char is one register over its creation and flag writes, so
// a delete stamped below the creation (forged) loses to it, with or without a reset between them;
// a delete above the creation (honest) hides it as before
#[test]
fn text_flag_below_creation_loses_spec_crdt_5_7() {
    let case = |at_h: u64, reset: Option<u64>| {
        let mut cs = vec![
            content(10, FIRST_ADMIN, 5, vec![part(TEXT, Retention::PLAIN, vec![ins(5, 10, 1, None, Some(1))])]),
            content(11, FIRST_ADMIN, at_h, vec![part(TEXT, Retention::PLAIN, vec![del(at_h, 11, 10)])]),
        ];
        cs.extend(reset.map(|r| content(12, FIRST_ADMIN, r, vec![part(TEXT, Retention::PLAIN, vec![text_reset(r, 12)])])));
        read(&held(9, cs), TEXT)
    };
    assert_eq!(case(2, None), text(&[1]));
    assert_eq!(case(2, Some(3)), text(&[1]));
    assert_eq!(case(7, None), text(&[]));
    assert_eq!(case(7, Some(6)), text(&[]));
}
