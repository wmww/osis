//! The actions layer across two nodes of one account (commits delivered by hand, the engine-level
//! path of core's tests) and over malformed synced data.
use osis::internals::Internals as _;
use osis::core::{BODY};
use osis::{Ak, Tid, Value};
use osis::internals::{ManualClock};
use osis_kit::store::Data;
use std::sync::Arc;
use crate::common::{cfg, deliver};

/// Two nodes of one account, paired; nothing synced yet beyond the pairing.
fn two() -> (Data, Data) {
    let (a, b, _) = two_clocked();
    (a, b)
}

/// `two`, with the clock both read.
fn two_clocked() -> (Data, Data, Arc<ManualClock>) {
    let clock = crate::common::clock();
    let a = crate::common::node(1, &clock);
    let offering = osis_account::Account::of(&a).unwrap().unwrap().offer_pairing(&a).unwrap();
    let o = cfg(2, &clock);
    let j = osis_account::pair(o.store, offering.offer(), o.cfg).unwrap();
    let (_, reply) = offering.accept(&a, j.request()).unwrap();
    let b = j.finish(&reply).unwrap().0;
    (osis_app::store::data(a), osis_app::store::data(b), clock)
}

fn sync(a: &Data, b: &Data) {
    deliver(&a.db, &b.db);
    deliver(&b.db, &a.db);
}

fn views_in(d: &Data, v: &[Tid]) -> Vec<String> {
    v.iter().filter(|t| d.is_scope(**t).unwrap()).map(|t| d.name(*t).unwrap()).collect()
}

fn found(d: &Data, q: &str) -> osis_kit::view::search::Found {
    let w = osis_kit::view::WindowState::default();
    osis_kit::view::search::search(&osis_kit::view::Cx::new(d, &w, false), q).unwrap()
}

/// Both nodes make a home before they sync: afterwards both write to the same one, the
/// views and favorites are not doubled, and a favorite made in the other home can be removed.
#[test]
fn two_nodes_race_home() {
    let (a, b) = two();
    let ga = a.home().unwrap();
    let gb = b.home().unwrap();
    assert_ne!(ga, gb);
    let n = b.create_note().unwrap();
    b.toggle_favorite(n).unwrap();
    sync(&a, &b);
    assert_eq!(a.homes().unwrap(), b.homes().unwrap());
    assert_eq!(a.homes().unwrap().len(), 2);
    assert_eq!(a.home().unwrap(), ga.min(gb));
    assert_eq!(b.home().unwrap(), ga.min(gb));
    for d in [&a, &b] {
        assert_eq!(d.collections().unwrap().len(), 4);
        let favs = d.favorites().unwrap();
        assert_eq!(views_in(d, &favs), vec!["Calendar", "People", "Tags", "Recent"], "views once each: {favs:?}");
        assert!(favs.contains(&n));
        assert_eq!(found(d, "calendar").scopes.len(), 1, "one Calendar scope");
    }
    // everything the app shows is held from a home, so it syncs to every node of the account
    assert_eq!(a.things().unwrap(), b.things().unwrap());
    a.toggle_favorite(n).unwrap();
    assert!(!a.is_favorite(n).unwrap(), "unfavorite a favorite kept in the other home");
    sync(&a, &b);
    assert!(!b.is_favorite(n).unwrap());
    // a reorder after the merge keeps one of each
    let len = a.favorites().unwrap().len();
    a.move_favorite(0, len - 1).unwrap();
    sync(&a, &b);
    assert_eq!(a.favorites().unwrap(), b.favorites().unwrap());
    assert_eq!(a.favorites().unwrap().len(), len);
}

/// Concurrent reorders and a concurrent delete merge into one list without duplicates or gone
/// things.
#[test]
fn concurrent_reorder_and_delete() {
    let (a, b) = two();
    a.home().unwrap();
    let ns: Vec<Tid> = (0..3).map(|_| a.create_note().unwrap()).collect();
    for n in &ns {
        a.toggle_favorite(*n).unwrap();
    }
    sync(&a, &b);
    let len = a.favorites().unwrap().len();
    assert_eq!(b.favorites().unwrap().len(), len);
    // both move the same favorite to different ends; b deletes another
    a.move_favorite(len - 1, 0).unwrap();
    b.move_favorite(len - 1, 2).unwrap();
    b.delete(ns[0]).unwrap();
    a.toggle_favorite(ns[1]).unwrap();
    sync(&a, &b);
    let fa = a.favorites().unwrap();
    assert_eq!(fa, b.favorites().unwrap());
    let mut dedup = fa.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), fa.len(), "no duplicates: {fa:?}");
    assert!(!fa.contains(&ns[0]) && !fa.contains(&ns[1]));
    assert!(fa.contains(&ns[2]));
    assert_eq!(fa.len(), len - 2);
}

/// This node's open thing stays open when the other node's home (smaller tid) arrives.
#[test]
fn open_survives_a_merged_home() {
    let (a, b) = two();
    let ga = a.home().unwrap();
    let gb = b.home().unwrap();
    let (late, _) = if ga > gb { (&a, &b) } else { (&b, &a) };
    let n = late.create_note().unwrap();
    assert_eq!(late.opened().unwrap(), Some(n));
    sync(&a, &b);
    assert_eq!(late.opened().unwrap(), Some(n), "still open after the merge");
    late.set_open(None).unwrap();
    assert_eq!(late.opened().unwrap(), None, "home clears it everywhere");
}

/// Demo data once per account: a second node sees it and adds none; existing favorites stay.
#[test]
fn demo_once_per_account() {
    let (a, b) = two();
    let n = a.create_note().unwrap();
    a.toggle_favorite(n).unwrap();
    assert!(osis_app::demo::add(&a).unwrap());
    assert!(a.is_favorite(n).unwrap(), "demo keeps the account's favorites");
    sync(&a, &b);
    assert!(!osis_app::demo::add(&b).unwrap());
    let count = |d: &Data| d.things().unwrap().iter().copied().filter(|t| d.name(*t).unwrap() == "Home").count();
    assert_eq!(count(&b), 1);
}

/// A deleted tag leaves no ghost behind (every strong to it goes too).
#[test]
fn deleted_tag_is_gone() {
    let (a, _) = two();
    osis_app::demo::add(&a).unwrap();
    let by_name = |n: &str| a.things().unwrap().iter().copied().find(|t| a.name(*t).unwrap() == n).unwrap();
    let garden = by_name("Garden");
    let home_tag = by_name("Home");
    a.delete(garden).unwrap();
    assert!(!a.things().unwrap().contains(&garden), "deleted tag still listed");
    assert!(!a.tag_contents(home_tag).unwrap().0.contains(&garden));
}

/// The other node deletes the open thing: this one goes home, and the open editor's sessions,
/// dropped then, do not bring it back.
#[test]
fn remote_delete_of_the_open_thing() {
    let (a, b) = two();
    a.home().unwrap();
    let n = a.create_note().unwrap();
    let s = a.db.at(n, BODY).path(osis::p![]).edit_text().unwrap();
    s.edit("", "hello").unwrap();
    s.commit().unwrap();
    sync(&a, &b);
    b.delete(n).unwrap();
    sync(&a, &b);
    assert_eq!(a.opened().unwrap(), None, "a deleted thing is not open");
    assert!(!a.things().unwrap().contains(&n));
    drop(s);
    assert_eq!(a.db.at(n, BODY).get().unwrap(), None, "no resurrection");
}

/// A synced thing may hold anything: wrong types, unknown enum cases. Every read the screens
/// make treats such an aspect as absent instead of failing the whole screen.
/// (Not core aspects: a commit whose value does not fit a core type is malformed.)
#[test]
fn malformed_aspects_do_not_break_reads() {
    let (a, _) = two();
    osis_app::demo::add(&a).unwrap();
    let g = a.home().unwrap();
    let bad = |w: &mut osis::Write<'_>, ak: &str, v: Value| -> osis::Result<()> {
        let t = w.create(g, None)?;
        w.hold(g, t)?;
        w.at(t, osis::DynamicAspectKey::untyped(Ak::new(ak).unwrap())).set(&v)?;
        Ok(())
    };
    let mut w = a.db.write();
    bad(&mut w, "ui:collection.0", Value::Enum(9, None)).unwrap();
    bad(&mut w, "osis_app:color.0", Value::Int(1)).unwrap();
    bad(&mut w, "event:start.0", Value::Str("tomorrow".into())).unwrap();
    bad(&mut w, "event:start.0", Value::Enum(1, Some(Box::new(Value::Int(i64::MAX))))).unwrap();
    bad(&mut w, "event:end.0", Value::Enum(2, Some(Box::new(Value::Int(i64::MAX))))).unwrap();
    bad(&mut w, "contact:org.0", Value::Str("Acme".into())).unwrap();
    bad(&mut w, "contact:emails.0", Value::List(vec![])).unwrap();
    w.commit().unwrap();
    // an event with a far start and a huge duration
    {
        let mut w = a.db.write();
        let t = w.create(g, None).unwrap();
        w.hold(g, t).unwrap();
        w.at(t, osis_app::event::START).set(&osis_app::event::Start::At(osis_app::event::Wall { time: i64::MAX - 1, zone: None })).unwrap();
        w.at(t, osis_app::event::END).set(&osis_app::event::End::After(i64::MAX)).unwrap();
        w.commit().unwrap();
    }
    let things = a.things().unwrap();
    assert!(things.len() > 40);
    for t in things.iter() {
        let w = osis_kit::view::WindowState::default();
        let cx = osis_kit::view::Cx::new(&a, &w, false);
        cx.summary(*t).unwrap();
        osis_kit::view::source::main_color(&cx, *t).unwrap();
        osis_kit::views::page(&cx, *t).unwrap();
    }
    a.favorites().unwrap();
    a.collections().unwrap();
    for q in ["a", "acme", "tomorrow", "7"] {
        found(&a, q);
    }
    assert!(!a.holds(g).unwrap().is_empty());
}

/// One node empties the other's home into the main one while that node, not yet knowing
/// the main home, favorites something in its own: nothing is lost.
#[test]
fn emptying_a_home_keeps_a_concurrent_favorite() {
    let (a, b) = two();
    let ga = a.home().unwrap();
    let gb = b.home().unwrap();
    // `big` is the node whose home loses; it learns of the other home only at the end
    let (small, big) = if ga < gb { (&a, &b) } else { (&b, &a) };
    let x = big.create_note().unwrap();
    big.toggle_favorite(x).unwrap();
    deliver(&big.db, &small.db);
    let m = small.create_note().unwrap();
    small.toggle_favorite(m).unwrap();
    assert!(small.is_favorite(x).unwrap());
    let y = big.create_note().unwrap();
    big.toggle_favorite(y).unwrap();
    sync(&a, &b);
    for d in [&a, &b] {
        let f = d.favorites().unwrap();
        assert!(f.contains(&x) && f.contains(&y) && f.contains(&m), "{f:?}");
        assert_eq!(views_in(d, &f).len(), 4);
    }
    assert_eq!(a.favorites().unwrap(), b.favorites().unwrap());
}

/// Concurrent first writes after the merge: both nodes settle on one list.
#[test]
fn concurrent_writes_after_the_merge_converge() {
    let (a, b) = two();
    a.home().unwrap();
    b.home().unwrap();
    let na = a.create_note().unwrap();
    let nb = b.create_note().unwrap();
    a.toggle_favorite(na).unwrap();
    b.toggle_favorite(nb).unwrap();
    sync(&a, &b);
    let ma = a.create_note().unwrap();
    let mb = b.create_note().unwrap();
    a.toggle_favorite(ma).unwrap();
    b.toggle_favorite(mb).unwrap();
    sync(&a, &b);
    let f = a.favorites().unwrap();
    assert_eq!(f, b.favorites().unwrap());
    for t in [na, nb, ma, mb] {
        assert!(f.contains(&t), "{f:?}");
    }
    // no writes from reads: another sync round changes nothing
    let before = a.db.engine(|e| e.commit_ids().len());
    let _ = (a.favorites().unwrap(), b.favorites().unwrap(), a.opened().unwrap(), b.opened().unwrap());
    sync(&a, &b);
    assert_eq!(a.db.engine(|e| e.commit_ids().len()), before);
}

/// One node unfavorites a thing still held in the other home while the other node, also
/// writing for the first time since the merge, favorites something else.
#[test]
fn unfavorite_survives_a_concurrent_first_write() {
    let (a, b) = two();
    let ga = a.home().unwrap();
    let gb = b.home().unwrap();
    let (small, big) = if ga < gb { (&a, &b) } else { (&b, &a) };
    let n = big.create_note().unwrap();
    big.toggle_favorite(n).unwrap();
    sync(&a, &b);
    let m = small.create_note().unwrap();
    sync(&a, &b);
    small.toggle_favorite(n).unwrap();
    big.toggle_favorite(m).unwrap();
    sync(&a, &b);
    let f = a.favorites().unwrap();
    assert_eq!(f, b.favorites().unwrap());
    assert!(f.contains(&m));
    assert!(!f.contains(&n), "unfavorite lost: {f:?}");
}

/// The look across two nodes' racing homes and over malformed synced values: both read
/// one choice, a value of another shape or an unknown mode reads as unset, an unknown theme id
/// is only a string (the UI falls back to the default theme).
#[test]
fn look_merges_and_tolerates_odd_values() {
    use osis_kit::schema::Mode;
    let (a, b) = two();
    let ga = a.home().unwrap();
    let gb = b.home().unwrap();
    a.set_theme("velocity").unwrap();
    b.set_theme("slate").unwrap();
    b.set_mode(Mode::Dark).unwrap();
    sync(&a, &b);
    assert_eq!(a.look().unwrap(), b.look().unwrap());
    let want = if ga < gb { "velocity" } else { "slate" };
    assert_eq!(a.look().unwrap(), (Some(want.into()), Mode::Dark), "the main home's theme, the other's mode");
    let main = a.home().unwrap();
    let mut w = a.db.write();
    w.at(main, osis::DynamicAspectKey::untyped(Ak::new("ui:theme.0").unwrap())).set(&Value::Int(3)).unwrap();
    w.at(main, osis::DynamicAspectKey::untyped(Ak::new("ui:mode.0").unwrap())).set(&Value::Enum(7, None)).unwrap();
    w.commit().unwrap();
    // the other home's choice shows through (b's mode lived on gb)
    let other = if main == ga { (Some("slate".into()), Mode::Dark) } else { (Some("velocity".into()), Mode::Auto) };
    assert_eq!(a.look().unwrap(), other, "odd values on the main home read as unset");
    a.set_theme("no-such-theme").unwrap();
    assert_eq!(a.look().unwrap().0.as_deref(), Some("no-such-theme"));
}

/// Reordering is a sequence move: a favorite one node moves while the other removes it stays
/// removed, and both nodes end with the same order.
#[test]
fn reorder_against_concurrent_unfavorite() {
    let (a, b) = two();
    a.home().unwrap();
    let n1 = a.create_note().unwrap();
    let n2 = a.create_note().unwrap();
    a.toggle_favorite(n1).unwrap();
    a.toggle_favorite(n2).unwrap();
    sync(&a, &b);
    let favs = a.favorites().unwrap();
    assert_eq!(b.favorites().unwrap(), favs);
    let i = favs.iter().position(|t| *t == n2).unwrap();
    a.move_favorite(i, 0).unwrap();
    assert_eq!(a.favorites().unwrap()[0], n2);
    b.toggle_favorite(n2).unwrap();
    sync(&a, &b);
    assert!(!a.favorites().unwrap().contains(&n2), "the removal wins over the move");
    assert_eq!(a.favorites().unwrap(), b.favorites().unwrap());
    // concurrent moves of different entries converge
    let f = a.favorites().unwrap();
    a.move_favorite(f.len() - 1, 0).unwrap();
    b.move_favorite(0, 1).unwrap();
    sync(&a, &b);
    assert_eq!(a.favorites().unwrap(), b.favorites().unwrap());
    assert_eq!(a.favorites().unwrap().len(), f.len());
}

/// Two nodes fill in different fields of a contact's absent org (and names) at once: both
/// fields survive, whichever node writes later (a whole-struct write with defaults would
/// overwrite the other's field with an empty one).
#[test]
fn contact_fields_of_an_absent_struct_race() {
    use osis_app::contact::{NAMES, ORG};
    use crate::common::save;
    use osis_app::facets::contact::contact_form;
    for later_is_b in [false, true] {
        let (a, b, clock) = two_clocked();
        a.home().unwrap();
        let c = osis_kit::facets::create(&a, "person").unwrap();
        let mut w = a.db.write();
        w.at(c, NAMES).remove().unwrap();
        w.commit().unwrap();
        sync(&a, &b);
        let row = |d: &Data, label: &str| contact_form(d, c).unwrap().into_iter().find(|r| r.label == label).unwrap();
        let (first, second) = if later_is_b { (&a, &b) } else { (&b, &a) };
        save(first, &row(first, "Title"), "Gardener").unwrap();
        save(first, &row(first, "Given name"), "Theo").unwrap();
        clock.advance(1000);
        save(second, &row(second, "Organisation"), "Acme").unwrap();
        save(second, &row(second, "Family name"), "Lind").unwrap();
        sync(&a, &b);
        for d in [&a, &b] {
            let org = d.db.at(c, ORG).get().unwrap().unwrap();
            assert_eq!((org.title.as_str(), org.name.as_str()), ("Gardener", "Acme"));
            let n = d.db.at(c, NAMES).get().unwrap().unwrap();
            assert_eq!((n.given.as_deref(), n.family.as_deref()), (Some("Theo"), Some("Lind")));
        }
    }
}

/// Renaming an email on one node while the other relabels it: one entry under the new
/// address. (The relabel is a field write into the renamed-away entry, which stays removed:
/// removal is final, notes/crdt.md Tess's decisions.)
#[test]
fn email_rename_against_concurrent_edits() {
    use osis_app::contact::EMAILS;
    use crate::common::save;
    use osis_app::facets::contact::contact_form;
    let (a, b, clock) = two_clocked();
    a.home().unwrap();
    let c = osis_kit::facets::create(&a, "person").unwrap();
    let add = |d: &Data| contact_form(d, c).unwrap().into_iter().find(|r| r.placeholder == "Add an email").unwrap();
    let email = |d: &Data, v: &str| contact_form(d, c).unwrap().into_iter().find(|r| r.value == v).unwrap();
    save(&a, &add(&a), "x@a.org").unwrap();
    sync(&a, &b);
    // both rename the same address: both new ones stay (no data lost)
    save(&a, &email(&a, "x@a.org"), "y@a.org").unwrap();
    clock.advance(10);
    save(&b, &email(&b, "x@a.org"), "z@a.org").unwrap();
    sync(&a, &b);
    let keys = |d: &Data| d.db.at(c, EMAILS).get().unwrap().unwrap_or_default().into_keys().collect::<Vec<_>>();
    assert_eq!(keys(&a), keys(&b));
    assert_eq!(keys(&a), vec!["y@a.org".to_string(), "z@a.org".to_string()]);
    // a stale row (its address removed elsewhere meanwhile) saved: the new address is added
    let stale = email(&a, "y@a.org");
    save(&b, &email(&b, "y@a.org"), "").unwrap();
    sync(&a, &b);
    save(&a, &stale, "w@a.org").unwrap();
    sync(&a, &b);
    assert_eq!(keys(&b), vec!["w@a.org".to_string(), "z@a.org".to_string()]);
}

/// An "All fields" edit of one field and a nudge of the same aspect on the other node: both
/// survive (the nudge's whole-value write diffs against what it read).
#[test]
fn field_edit_and_nudge_merge() {
    use osis_app::event::{START, Start};
    let (a, b, clock) = two_clocked();
    a.home().unwrap();
    let e = osis_kit::facets::create(&a, "event").unwrap();
    sync(&a, &b);
    let Some(Start::At(w0)) = a.db.at(e, START).get().unwrap() else { panic!() };
    let rows = a.field_rows(e).unwrap();
    let zone = rows.iter().find(|r| r.ak == "event:start.0" && r.label == "zone").unwrap().clone();
    a.set_field(e, &zone, "Europe/Berlin").unwrap();
    clock.advance(10);
    osis_app::facets::event_time::nudge(&b, e, osis_app::time::HOUR, 0).unwrap();
    sync(&a, &b);
    for d in [&a, &b] {
        let Some(Start::At(w)) = d.db.at(e, START).get().unwrap() else { panic!() };
        assert_eq!((w.time, w.zone.as_deref()), (w0.time + osis_app::time::HOUR, Some("Europe/Berlin")));
    }
}

/// Adversarial favorites interleavings: concurrent moves of one entry, a move against a
/// remove-and-re-add, moves onto entries held in the other home's list. Both nodes end with
/// one order, without duplicates, and a removal is never undone by a move.
#[test]
fn favorites_moves_adversarial() {
    for round in 0..4 {
        let (a, b, clock) = two_clocked();
        let ga = a.home().unwrap();
        let gb = b.home().unwrap();
        // entries in both homes' lists
        let na: Vec<Tid> = (0..3).map(|_| a.create_note().unwrap()).collect();
        let nb: Vec<Tid> = (0..3).map(|_| b.create_note().unwrap()).collect();
        for n in &na {
            a.toggle_favorite(*n).unwrap();
        }
        for n in &nb {
            b.toggle_favorite(*n).unwrap();
        }
        sync(&a, &b);
        assert_ne!(ga, gb);
        let f = a.favorites().unwrap();
        assert_eq!(f, b.favorites().unwrap());
        let len = f.len();
        let pos = |d: &Data, t: Tid| d.favorites().unwrap().iter().position(|x| *x == t).unwrap();
        match round {
            0 => {
                // the same entry moved both ways at once
                a.move_favorite(pos(&a, nb[0]), 0).unwrap();
                clock.advance(5);
                b.move_favorite(pos(&b, nb[0]), len - 1).unwrap();
            }
            1 => {
                // a moves while b removes then re-adds it (the re-add is a new entry at the end)
                a.move_favorite(pos(&a, na[2]), 0).unwrap();
                b.toggle_favorite(na[2]).unwrap();
                b.toggle_favorite(na[2]).unwrap();
            }
            2 => {
                // every entry dragged to the front on one side, the back on the other
                for t in na.iter().chain(&nb) {
                    a.move_favorite(pos(&a, *t), 0).unwrap();
                    b.move_favorite(pos(&b, *t), len - 1).unwrap();
                    clock.advance(1);
                }
            }
            _ => {
                // b removes an entry a moves past, and a removes one b moves onto
                a.move_favorite(pos(&a, na[0]), len - 1).unwrap();
                b.toggle_favorite(na[1]).unwrap();
                b.move_favorite(pos(&b, nb[2]), pos(&b, na[2])).unwrap();
                a.toggle_favorite(na[2]).unwrap();
            }
        }
        sync(&a, &b);
        let fa = a.favorites().unwrap();
        assert_eq!(fa, b.favorites().unwrap(), "round {round}");
        let mut dedup = fa.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), fa.len(), "round {round}: duplicates {fa:?}");
        match round {
            1 => assert!(fa.contains(&na[2]), "re-added"),
            3 => assert!(!fa.contains(&na[1]) && !fa.contains(&na[2]), "removals win"),
            _ => assert_eq!(fa.len(), len, "round {round}"),
        }
        // the moved order is reachable: moving an entry to the very front puts it there (when
        // it is in the main home's list, which shows first)
        let main = a.home().unwrap();
        let own = if main == ga { na[0] } else { nb[0] };
        if fa.contains(&own) {
            a.move_favorite(pos(&a, own), 0).unwrap();
            assert_eq!(a.favorites().unwrap()[0], own, "round {round}");
        }
    }
}

/// A favorite held in the other home's list cannot move ahead of the main home's entries:
/// the move is limited to its own list (no copying between homes). The order stays put
/// rather than jumping somewhere unasked.
#[test]
fn favorite_from_the_other_home_moves_within_its_list() {
    let (a, b) = two();
    let ga = a.home().unwrap();
    let gb = b.home().unwrap();
    let (small, big) = if ga < gb { (&a, &b) } else { (&b, &a) };
    let m = small.create_note().unwrap();
    small.toggle_favorite(m).unwrap();
    let n = big.create_note().unwrap();
    big.toggle_favorite(n).unwrap();
    sync(&a, &b);
    let f = a.favorites().unwrap();
    let i = f.iter().position(|x| *x == n).unwrap();
    assert!(i > f.iter().position(|x| *x == m).unwrap(), "the other home's extras follow");
    a.move_favorite(i, 0).unwrap();
    let after = a.favorites().unwrap();
    assert_eq!(after.len(), f.len());
}

/// A form saved on focus loss after its thing was deleted (here, or concurrently on the other
/// node) must not bring the thing back into the app.
#[test]
fn form_save_after_a_delete() {
    use crate::common::save;
    use osis_app::facets::contact::contact_form;
    let (a, b) = two();
    a.home().unwrap();
    let c = osis_kit::facets::create(&a, "person").unwrap();
    sync(&a, &b);
    let title = |d: &Data, c| contact_form(d, c).unwrap().into_iter().find(|r| r.label == "Title").unwrap();
    let on_a = title(&a, c);
    // deleted elsewhere, saved here before hearing of it
    b.delete(c).unwrap();
    let _ = save(&a, &on_a, "Gardener");
    sync(&a, &b);
    for d in [&a, &b] {
        assert!(!d.things().unwrap().contains(&c), "a concurrent field write does not revive it");
    }
    // deleted here, the stale form saved afterwards
    let c2 = osis_kit::facets::create(&a, "person").unwrap();
    let on = title(&a, c2);
    a.delete(c2).unwrap();
    let _ = save(&a, &on, "Gardener");
    assert!(!a.things().unwrap().contains(&c2));
    assert!(a.opened().unwrap().is_none());
}

/// A window is per node: a state write on one node's window does not touch another's open thing.
#[test]
fn windows_do_not_interfere() {
    use osis_kit::schema::WEEK;
    use osis_kit::view::{Act, Cx, WindowState};
    let (a, b) = two();
    a.home().unwrap();
    sync(&a, &b);
    let n = a.create_note().unwrap();
    let m = b.create_note().unwrap();
    sync(&a, &b);
    assert_eq!((a.opened().unwrap(), b.opened().unwrap()), (Some(n), Some(m)), "each window keeps its own");
    let (wa, wb) = (WindowState::default(), WindowState::default());
    Act::new(&a, &wa).set_state(WEEK, "cal", &3).unwrap();
    Act::new(&b, &wb).set_state(WEEK, "cal", &-1).unwrap();
    sync(&a, &b);
    let (ca, cb) = (Cx::new(&a, &wa, false), Cx::new(&b, &wb, false));
    assert_eq!(ca.state(WEEK, "cal").unwrap(), Some(3));
    assert_eq!(cb.state(WEEK, "cal").unwrap(), Some(-1));
    assert_eq!((a.opened().unwrap(), b.opened().unwrap()), (Some(n), Some(m)));
    assert_ne!(a.window().unwrap(), b.window().unwrap());
}
