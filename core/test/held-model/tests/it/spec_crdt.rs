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
    assert_eq!(read(&demoted(cs.clone(), false), REG), Read::Reg(2));
    assert_eq!(read(&demoted(cs, true), REG), Read::Reg(1));
}

// spec/crdt.md §4.6 (Removed): others' writes nested in a record the invalid delta created go
#[test]
fn unmerge_removes_writes_nested_in_invalid_entry_spec_crdt_4_6() {
    let e = Dot { commit: 10, ctr: 1 };
    let cs = vec![
        content(10, 1, 1, vec![part(MAP, Retention::PLAIN, vec![
            Write { stamp: st(1, 10, 1), op: Op::Create { key: Some(3) } },
            Write { stamp: st(1, 10, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(4) } },
        ])]),
        content(11, FIRST_ADMIN, 2, vec![part(MAP, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(9) } }])]),
    ];
    assert_eq!(read(&demoted(cs.clone(), false), MAP), Read::Map([(3, 9)].into()));
    assert_eq!(read(&demoted(cs, true), MAP), Read::Absent);
}

// spec/crdt.md §4.6 (Seq elements): an invalid creation stays a hidden anchor, so what anchors at it is placed
#[test]
fn unmerged_text_creation_stays_an_anchor_spec_crdt_4_6() {
    let a = Dot { commit: 10, ctr: 1 };
    let cs = vec![
        content(10, 1, 1, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(1, 10, 1), op: Op::Insert { anchor: None, ch: Some(1) } }])]),
        content(11, FIRST_ADMIN, 2, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::Insert { anchor: Some(a), ch: Some(2) } }])]),
    ];
    assert_eq!(read(&demoted(cs.clone(), false), TEXT), Read::Text(vec![1, 2]));
    assert_eq!(read(&demoted(cs, true), TEXT), Read::Text(vec![2]));
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
