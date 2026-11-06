//! spec/crdt.md §4.6 (undo), §4.7 (an undo's copies), spec/commits.md §7.
use crate::util::*;
use held_model::gen::{MAP, REG, TEXT};
use held_model::undo::undo;
use held_model::*;

/// The undo `id` at hour `h` by the first admin, written from the held set as it stands.
fn undo_at(hd: &Held, target: CommitId, id: CommitId, h: u64) -> Option<Commit> {
    let mut at = hd.clone();
    at.now = self::at(h);
    undo(&at, target, id, ts(h), OWNER)
}

fn ins(h: u64, c: CommitId, ctr: u32, anchor: Option<Dot>, ch: Val) -> Write {
    Write { stamp: st(h, c, ctr), op: Op::Insert { anchor, ch: Some(ch) } }
}

// spec/crdt.md §4.6 (restores the prior read): the undo writes the previous value back; redo restores
#[test]
fn undo_writes_previous_register_value_and_redo_restores_spec_crdt_4_6() {
    let mut hd = held(5, vec![reg(10, OWNER, 1, REG, Retention::PLAIN, 1), reg(11, OWNER, 2, REG, Retention::PLAIN, 2)]);
    let u = undo_at(&hd, 11, 20, 3).unwrap();
    assert_eq!(u.undoes, Some(11));
    hd.commits.push(u);
    assert_eq!(read(&hd, REG), Read::Reg(1));
    let redo = undo_at(&hd, 20, 21, 4).unwrap();
    hd.commits.push(redo);
    assert_eq!(read(&hd, REG), Read::Reg(2));
}

// spec/crdt.md §4.6 (restores the prior read): no write once the register no longer reads the undone write
#[test]
fn undo_of_a_beaten_write_writes_nothing_spec_crdt_4_6() {
    let hd = held(5, vec![reg(10, OWNER, 1, REG, Retention::PLAIN, 1), reg(11, OWNER, 2, REG, Retention::PLAIN, 2), reg(12, OWNER, 3, REG, Retention::PLAIN, 3)]);
    assert_eq!(undo_at(&hd, 11, 20, 4), None);
}

// spec/crdt.md §4.6 (restores the prior read): undoing the write that made the aspect present resets it
#[test]
fn undo_of_first_write_resets_the_aspect_spec_crdt_4_6() {
    let mut hd = held(5, vec![reg(10, OWNER, 1, REG, Retention::PLAIN, 1)]);
    let u = undo_at(&hd, 10, 20, 2).unwrap();
    assert_eq!(u.parts[0].body, Body::Held(Delta::Writes(vec![reset(2, 20)])));
    hd.commits.push(u);
    assert_eq!(read(&hd, REG), Read::Absent);
}

// spec/crdt.md §4.6 (restores the prior read): undoing a remove_aspect re-inserts the value with fresh dots
#[test]
fn undo_of_a_map_reset_reinserts_the_value_spec_crdt_4_6() {
    let e = Dot { commit: 10, ctr: 1 };
    let put = content(10, OWNER, 1, vec![part(MAP, Retention::PLAIN, vec![
        Write { stamp: st(1, 10, 1), op: Op::Create { key: Some(3) } },
        Write { stamp: st(1, 10, 1), op: Op::SetIn { entry: e, key: Some(3), value: Some(4) } },
    ])]);
    let rm = content(11, OWNER, 2, vec![part(MAP, Retention::PLAIN, vec![reset(2, 11)])]);
    let mut hd = held(5, vec![put, rm]);
    assert_eq!(read(&hd, MAP), Read::Absent);
    hd.commits.push(undo_at(&hd, 11, 20, 3).unwrap());
    assert_eq!(read(&hd, MAP), Read::Map([(3, 4)].into()));
}

// spec/crdt.md §4.6 (restores the prior read), §5.7: undoing a text delete undeletes with the char
#[test]
fn undo_of_a_text_delete_undeletes_spec_crdt_4_6() {
    let a = Dot { commit: 10, ctr: 1 };
    let ins = content(10, OWNER, 1, vec![part(TEXT, Retention::PLAIN, vec![ins(1, 10, 1, None, 7)])]);
    let del = content(11, OWNER, 2, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::Delete { elem: a } }])]);
    let mut hd = held(5, vec![ins, del]);
    let u = undo_at(&hd, 11, 20, 3).unwrap();
    assert_eq!(u.parts[0].body, Body::Held(Delta::Writes(vec![Write { stamp: st(3, 20, 1), op: Op::Undelete { elem: a, ch: Some(7) } }])));
    hd.commits.push(u);
    assert_eq!(read(&hd, TEXT), Read::Text(vec![7]));
}

// spec/crdt.md §4.6 (undo expiry, undo revives nothing): an undo expires with the delta it copies, and a copy already
// value-less by its time is not written back (here the text was then absent before: a reset)
#[test]
fn undo_takes_the_expiry_of_what_it_copies_spec_crdt_4_6() {
    let a = Dot { commit: 10, ctr: 1 };
    let mut i = content(10, OWNER, 1, vec![part(TEXT, Retention::PLAIN, vec![ins(1, 10, 1, None, 7)])]);
    i.expires = Some(at(5));
    let del = content(11, OWNER, 2, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::Delete { elem: a } }])]);
    let hd = held(3, vec![i, del]);
    assert_eq!(undo_at(&hd, 11, 20, 3).unwrap().expires, Some(at(5)));
    let late = undo_at(&hd, 11, 20, 6).unwrap();
    assert_eq!((late.expires, late.parts[0].body.clone()), (None, Body::Held(Delta::Writes(vec![reset(6, 20)]))));
}

// spec/crdt.md §4.6: writes of deltas the node judges invalid are not undone
#[test]
fn invalid_writes_are_not_undone_spec_crdt_4_6() {
    let hd = held(5, vec![
        edge(5, OWNER, 0, 1, Some(Role::Write), None),
        reg(10, 1, 1, REG, Retention::PLAIN, 1),
        edge(6, OWNER, 2, 1, None, Some(vec![])),
    ]);
    assert_eq!(undo_at(&hd, 10, 20, 3), None);
}

// spec/crdt.md §4.7 (An undelete's char): the char goes with its creator's delta: un-merged with an
// invalid creator, stripped (the undo held as its leftover) with a purged one
#[test]
fn undelete_char_follows_its_creator_spec_crdt_4_7() {
    let a = Dot { commit: 10, ctr: 1 };
    let undel = || {
        Commit { undoes: Some(11), ..content(20, OWNER, 3, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(3, 20, 1), op: Op::Undelete { elem: a, ch: Some(7) } }])]) }
    };
    let base = |demote: bool| {
        let mut cs = vec![
            edge(5, OWNER, 0, 1, Some(Role::Write), None),
            content(10, 1, 1, vec![part(TEXT, Retention::PLAIN, vec![ins(1, 10, 1, None, 7)])]),
            content(11, OWNER, 2, vec![part(TEXT, Retention::PLAIN, vec![Write { stamp: st(2, 11, 1), op: Op::Delete { elem: a } }])]),
            undel(),
        ];
        if demote {
            cs.push(edge(6, OWNER, 4, 1, None, Some(vec![])));
        }
        held(5, cs)
    };
    assert_eq!(read(&base(false), TEXT), Read::Text(vec![7]));
    assert_eq!(read(&base(true), TEXT), Read::Text(vec![]));
    let mut p = base(false);
    p.commits.push(purge(30, OWNER, 4, PurgeItem::Commit { commit: 10, thing: T, aspect: TEXT }));
    assert_eq!(fate(&p, 20), Fate::Leftover(LeftoverWhy::Copy));
    assert_eq!(read(&p, TEXT), Read::Text(vec![]));
}

// spec/commits.md §7: a commit whose body was dropped cannot be undone
#[test]
fn dropped_body_cannot_be_undone_spec_commits_7() {
    let mut c = reg(11, OWNER, 2, REG, Retention::PLAIN, 2);
    c.parts[0].body = Body::Dropped;
    let hd = held(5, vec![reg(10, OWNER, 1, REG, Retention::PLAIN, 1), c]);
    assert_eq!(undo_at(&hd, 11, 20, 3), None);
}
