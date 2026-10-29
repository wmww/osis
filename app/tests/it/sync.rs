//! The actions layer across two devices of one person (commits delivered by hand, the engine-level
//! path of core's tests) and over malformed synced data.
use osis::core::{BODY, GROUP};
use osis::{Ak, Config, ManualClock, MemStore, Osis, Path, StoreAt, Tid, Value, WallMs};
use osis_app::data::{Data, Kind};
use osis_app::schema::View;
use std::sync::Arc;

fn cfg(seed: u64, clock: &Arc<ManualClock>) -> Config {
    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
    c.seed = Some(seed);
    c.clock = Some(clock.clone());
    c
}

/// Two devices of one person, paired; nothing synced yet beyond the pairing.
fn two() -> (Data, Data) {
    let (a, b, _) = two_clocked();
    (a, b)
}

/// `two`, with the clock both read.
fn two_clocked() -> (Data, Data, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Osis::create(cfg(1, &clock)).unwrap().0;
    let j = Osis::pair(cfg(2, &clock), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    (Data::new(a), Data::new(b), clock)
}

fn deliver(from: &Osis, to: &Osis) {
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
}

fn sync(a: &Data, b: &Data) {
    deliver(&a.db, &b.db);
    deliver(&b.db, &a.db);
}

fn views_in(d: &Data, v: &[Tid]) -> Vec<View> {
    v.iter().filter_map(|t| match d.kind(*t).unwrap() {
        Kind::View(v) => Some(v),
        _ => None,
    }).collect()
}

/// Both devices make an app group before they sync: afterwards both write to the same one, the
/// views and favorites are not doubled, and a favorite made in the other group can be removed.
#[test]
fn two_devices_race_the_app_group() {
    let (a, b) = two();
    let ga = a.main_group().unwrap();
    let gb = b.main_group().unwrap();
    assert_ne!(ga, gb);
    let n = b.create_note().unwrap();
    b.toggle_favorite(n).unwrap();
    sync(&a, &b);
    assert_eq!(a.groups().unwrap(), b.groups().unwrap());
    assert_eq!(a.groups().unwrap().len(), 2);
    assert_eq!(a.main_group().unwrap(), ga.min(gb));
    assert_eq!(b.main_group().unwrap(), ga.min(gb));
    for d in [&a, &b] {
        assert_eq!(d.views().unwrap().len(), 4);
        let favs = d.favorites().unwrap();
        assert_eq!(views_in(d, &favs), vec![View::Calendar, View::People, View::Tags, View::Recent], "views once each: {favs:?}");
        assert!(favs.contains(&n));
        assert_eq!(d.search("calendar").unwrap().scopes.len(), 1, "one Calendar scope");
        assert_eq!(d.view_items(&View::Tags).unwrap().len(), 0);
        // everything the app shows is a member of home, so it syncs to every device
        for t in d.things().unwrap() {
            assert!(d.db.groups_of(t).contains(&d.db.home()), "{t} not under home");
        }
    }
    a.toggle_favorite(n).unwrap();
    assert!(!a.is_favorite(n).unwrap(), "unfavorite a favorite kept in the other group");
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
    a.main_group().unwrap();
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

/// This device's open thing stays open when the other device's group (smaller tid) arrives.
#[test]
fn open_survives_a_merged_group() {
    let (a, b) = two();
    let ga = a.main_group().unwrap();
    let gb = b.main_group().unwrap();
    let (late, _) = if ga > gb { (&a, &b) } else { (&b, &a) };
    let n = late.create_note().unwrap();
    assert_eq!(late.opened().unwrap(), Some(n));
    sync(&a, &b);
    assert_eq!(late.opened().unwrap(), Some(n), "still open after the merge");
    late.set_open(None).unwrap();
    assert_eq!(late.opened().unwrap(), None, "home clears it everywhere");
}

/// Demo data once per person: a second device sees it and adds none; existing favorites stay.
#[test]
fn demo_once_per_person() {
    let (a, b) = two();
    let n = a.create_note().unwrap();
    a.toggle_favorite(n).unwrap();
    assert!(osis_app::demo::add(&a).unwrap());
    assert!(a.is_favorite(n).unwrap(), "demo keeps the person's favorites");
    sync(&a, &b);
    assert!(!osis_app::demo::add(&b).unwrap());
    let count = |d: &Data| d.things().unwrap().into_iter().filter(|t| d.name(*t).unwrap() == "Home").count();
    assert_eq!(count(&b), 1);
}

/// A deleted tag leaves no ghost behind (its subgroup edges go too).
#[test]
fn deleted_tag_is_gone() {
    let (a, _) = two();
    osis_app::demo::add(&a).unwrap();
    let by_name = |n: &str| a.things().unwrap().into_iter().find(|t| a.name(*t).unwrap() == n).unwrap();
    let garden = by_name("Garden");
    let home_tag = by_name("Home");
    a.delete(garden).unwrap();
    assert!(!a.things().unwrap().contains(&garden), "deleted tag still listed as {:?}", a.kind(garden).unwrap());
    assert!(!a.tag_contents(home_tag).unwrap().0.contains(&garden));
    assert!(!a.view_items(&View::Recent).unwrap().contains(&garden));
}

/// The other device deletes the open thing: this one goes home, and the open editor's sessions,
/// dropped then, do not bring it back.
#[test]
fn remote_delete_of_the_open_thing() {
    let (a, b) = two();
    a.main_group().unwrap();
    let n = a.create_note().unwrap();
    let s = a.db.edit_text(n, BODY, Path::root()).unwrap();
    s.insert(0, "hello").unwrap();
    s.commit().unwrap();
    sync(&a, &b);
    b.delete(n).unwrap();
    sync(&a, &b);
    assert_eq!(a.opened().unwrap(), None, "a deleted thing is not open");
    assert!(!a.things().unwrap().contains(&n));
    drop(s);
    assert_eq!(a.db.get(n, BODY).unwrap(), None, "no resurrection");
}

/// A synced thing may hold anything: wrong types, unknown enum cases. Every read the screens
/// make treats such an aspect as absent instead of failing the whole screen.
#[test]
fn malformed_aspects_do_not_break_reads() {
    let (a, _) = two();
    osis_app::demo::add(&a).unwrap();
    let g = a.main_group().unwrap();
    let bad = |w: &mut osis::Write<'_>, ak: &str, v: Value| -> osis::Result<()> {
        let t = w.create(a.db.me())?;
        w.place(t, g)?;
        w.at(t, Ak::new(ak).unwrap()).set(&v)?;
        Ok(())
    };
    a.db.write_with(|w| {
        bad(w, "/name", Value::Int(7))?;
        bad(w, "/body", Value::Bool(true))?;
        bad(w, "/osis-app/view", Value::Enum(9, None))?;
        bad(w, "/osis-app/color", Value::Int(1))?;
        bad(w, "/event/start", Value::Str("tomorrow".into()))?;
        bad(w, "/event/start", Value::Enum(1, Some(Box::new(Value::Int(i64::MAX)))))?;
        bad(w, "/event/end", Value::Enum(2, Some(Box::new(Value::Int(i64::MAX)))))?;
        bad(w, "/contact/org", Value::Str("Acme".into()))?;
        bad(w, "/contact/emails", Value::List(vec![]))?;
        bad(w, "/tag", Value::Int(3))?;
        Ok(())
    })
    .unwrap();
    // an event with a far start and a huge duration
    a.db.write_with(|w| {
        let t = w.create(a.db.me())?;
        w.place(t, g)?;
        w.at(t, osis_app::event::START).set(&osis_app::event::Start::At(osis_app::event::Wall { time: i64::MAX - 1, zone: None }))?;
        w.at(t, osis_app::event::END).set(&osis_app::event::End::After(i64::MAX))?;
        Ok(())
    })
    .unwrap();
    let things = a.things().unwrap();
    assert!(things.len() > 40);
    for t in &things {
        a.tile(*t).unwrap();
        a.main_color(*t).unwrap();
        a.kind(*t).unwrap();
    }
    a.favorites().unwrap();
    a.views().unwrap();
    for v in [View::Calendar, View::People, View::Tags, View::Recent] {
        a.view_items(&v).unwrap();
    }
    for q in ["a", "acme", "tomorrow", "7"] {
        a.search(q).unwrap();
    }
    assert!(a.db.get(g, GROUP).unwrap().is_some());
}

/// One device empties the other's group into the main one while that device, not yet knowing
/// the main group, favorites something in its own: nothing is lost.
#[test]
fn emptying_a_group_keeps_a_concurrent_favorite() {
    let (a, b) = two();
    let ga = a.main_group().unwrap();
    let gb = b.main_group().unwrap();
    // `big` is the device whose group loses; it learns of the other group only at the end
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

/// Concurrent first writes after the merge: both devices settle on one list.
#[test]
fn concurrent_writes_after_the_merge_converge() {
    let (a, b) = two();
    a.main_group().unwrap();
    b.main_group().unwrap();
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

/// One device unfavorites a thing still held in the other group while the other device, also
/// writing for the first time since the merge, favorites something else.
#[test]
fn unfavorite_survives_a_concurrent_first_write() {
    let (a, b) = two();
    let ga = a.main_group().unwrap();
    let gb = b.main_group().unwrap();
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

/// The look across two devices' racing app groups and over malformed synced values: both read
/// one choice, a value of another shape or an unknown mode reads as unset, an unknown theme id
/// is only a string (the UI falls back to the default theme).
#[test]
fn look_merges_and_tolerates_odd_values() {
    use osis_app::schema::Mode;
    let (a, b) = two();
    let ga = a.main_group().unwrap();
    let gb = b.main_group().unwrap();
    a.set_theme("cel").unwrap();
    b.set_theme("slate").unwrap();
    b.set_mode(Mode::Dark).unwrap();
    sync(&a, &b);
    assert_eq!(a.look().unwrap(), b.look().unwrap());
    let want = if ga < gb { "cel" } else { "slate" };
    assert_eq!(a.look().unwrap(), (Some(want.into()), Mode::Dark), "the main group's theme, the other's mode");
    let main = a.main_group().unwrap();
    a.db.write_with(|w| {
        w.at(main, Ak::new("/osis-app/theme").unwrap()).set(&Value::Int(3))?;
        w.at(main, Ak::new("/osis-app/mode").unwrap()).set(&Value::Enum(7, None))
    })
    .unwrap();
    // the other group's choice shows through (b's mode lived on gb)
    let other = if main == ga { (Some("slate".into()), Mode::Dark) } else { (Some("cel".into()), Mode::Auto) };
    assert_eq!(a.look().unwrap(), other, "odd values on the main group read as unset");
    a.set_theme("no-such-theme").unwrap();
    assert_eq!(a.look().unwrap().0.as_deref(), Some("no-such-theme"));
}

/// Reordering is a sequence move: a favorite one device moves while the other removes it stays
/// removed, and both devices end with the same order.
#[test]
fn reorder_against_concurrent_unfavorite() {
    let (a, b) = two();
    a.main_group().unwrap();
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

/// Two devices fill in different fields of a contact's absent org (and names) at once: both
/// fields survive, whichever device writes later (a whole-struct write with defaults would
/// overwrite the other's field with an empty one).
#[test]
fn contact_fields_of_an_absent_struct_race() {
    use osis_app::contact::{NAMES, ORG};
    use osis_app::data::NewKind;
    use osis_app::fields::FormRow;
    for later_is_b in [false, true] {
        let (a, b, clock) = two_clocked();
        a.main_group().unwrap();
        let c = a.create(NewKind::Contact).unwrap();
        a.db.write_with(|w| w.at(c, NAMES).remove()).unwrap();
        sync(&a, &b);
        let act = |d: &Data, label: &str| d.contact_form(c).unwrap().into_iter().find(|r: &FormRow| r.label == label).unwrap().act;
        let (first, second) = if later_is_b { (&a, &b) } else { (&b, &a) };
        first.form_apply(c, &act(first, "Title"), "Gardener").unwrap();
        first.form_apply(c, &act(first, "Given name"), "Theo").unwrap();
        clock.advance(1000);
        second.form_apply(c, &act(second, "Organisation"), "Acme").unwrap();
        second.form_apply(c, &act(second, "Family name"), "Lind").unwrap();
        sync(&a, &b);
        for d in [&a, &b] {
            let org = d.get(c, ORG).unwrap().unwrap();
            assert_eq!((org.title.as_str(), org.name.as_str()), ("Gardener", "Acme"));
            let n = d.get(c, NAMES).unwrap().unwrap();
            assert_eq!((n.given.as_deref(), n.family.as_deref()), (Some("Theo"), Some("Lind")));
        }
    }
}

/// Renaming an email on one device while the other relabels it: one entry under the new
/// address. (The relabel is a field write into the renamed-away entry, which brings that entry
/// back with the field alone: spec'd CRDT behaviour, notes/crdt.md Known anomalies.)
#[test]
fn email_rename_against_concurrent_edits() {
    use osis_app::contact::EMAILS;
    use osis_app::data::NewKind;
    use osis_app::fields::FormAct;
    let (a, b, clock) = two_clocked();
    a.main_group().unwrap();
    let c = a.create(NewKind::Contact).unwrap();
    let add = |d: &Data| d.contact_form(c).unwrap().into_iter().find(|r| matches!(r.act, FormAct::AddKey { ak: "/contact/emails" })).unwrap().act;
    let email = |d: &Data, v: &str| d.contact_form(c).unwrap().into_iter().find(|r| r.value == v).unwrap().act;
    a.form_apply(c, &add(&a), "x@a.org").unwrap();
    sync(&a, &b);
    // both rename the same address: both new ones stay (no data lost)
    a.form_apply(c, &email(&a, "x@a.org"), "y@a.org").unwrap();
    clock.advance(10);
    b.form_apply(c, &email(&b, "x@a.org"), "z@a.org").unwrap();
    sync(&a, &b);
    let keys = |d: &Data| d.get(c, EMAILS).unwrap().unwrap_or_default().into_keys().collect::<Vec<_>>();
    assert_eq!(keys(&a), keys(&b));
    assert_eq!(keys(&a), vec!["y@a.org".to_string(), "z@a.org".to_string()]);
    // a stale row (its address removed elsewhere meanwhile) saved: the new address is added
    let stale = email(&a, "y@a.org");
    b.form_apply(c, &email(&b, "y@a.org"), "").unwrap();
    sync(&a, &b);
    a.form_apply(c, &stale, "w@a.org").unwrap();
    sync(&a, &b);
    assert_eq!(keys(&b), vec!["w@a.org".to_string(), "z@a.org".to_string()]);
}

/// An "All fields" edit of one field and a nudge of the same aspect on the other device: both
/// survive (the nudge's whole-value write diffs against what it read).
#[test]
fn field_edit_and_nudge_merge() {
    use osis_app::data::NewKind;
    use osis_app::event::{START, Start};
    let (a, b, clock) = two_clocked();
    a.main_group().unwrap();
    let e = a.create(NewKind::Event).unwrap();
    sync(&a, &b);
    let Some(Start::At(w0)) = a.get(e, START).unwrap() else { panic!() };
    let rows = a.field_rows(e).unwrap();
    let zone = rows.iter().find(|r| r.ak == "/event/start" && r.label == "zone").unwrap().clone();
    a.set_field(e, &zone, "Europe/Berlin").unwrap();
    clock.advance(10);
    b.nudge(e, osis_app::time::HOUR, 0).unwrap();
    sync(&a, &b);
    for d in [&a, &b] {
        let Some(Start::At(w)) = d.get(e, START).unwrap() else { panic!() };
        assert_eq!((w.time, w.zone.as_deref()), (w0.time + osis_app::time::HOUR, Some("Europe/Berlin")));
    }
}

/// Adversarial favorites interleavings: concurrent moves of one entry, a move against a
/// remove-and-re-add, moves onto entries held in the other group's list. Both devices end with
/// one order, without duplicates, and a removal is never undone by a move.
#[test]
fn favorites_moves_adversarial() {
    for round in 0..4 {
        let (a, b, clock) = two_clocked();
        let ga = a.main_group().unwrap();
        let gb = b.main_group().unwrap();
        // entries in both groups' lists
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
        // it is in the main group's list, which shows first)
        let main = a.main_group().unwrap();
        let own = if main == ga { na[0] } else { nb[0] };
        if fa.contains(&own) {
            a.move_favorite(pos(&a, own), 0).unwrap();
            assert_eq!(a.favorites().unwrap()[0], own, "round {round}");
        }
    }
}

/// A favorite held in the other group's list cannot move ahead of the main group's entries:
/// the move is limited to its own list (no copying between groups). The order stays put
/// rather than jumping somewhere unasked.
#[test]
fn favorite_from_the_other_group_moves_within_its_list() {
    let (a, b) = two();
    let ga = a.main_group().unwrap();
    let gb = b.main_group().unwrap();
    let (small, big) = if ga < gb { (&a, &b) } else { (&b, &a) };
    let m = small.create_note().unwrap();
    small.toggle_favorite(m).unwrap();
    let n = big.create_note().unwrap();
    big.toggle_favorite(n).unwrap();
    sync(&a, &b);
    let f = a.favorites().unwrap();
    let i = f.iter().position(|x| *x == n).unwrap();
    assert!(i > f.iter().position(|x| *x == m).unwrap(), "the other group's extras follow");
    a.move_favorite(i, 0).unwrap();
    let after = a.favorites().unwrap();
    assert_eq!(after.len(), f.len());
}

/// Both devices favorite the same thing at once (two entries in one list): it shows once, and
/// dragging it to the end puts it at the end.
#[test]
fn favorite_twice_then_moved() {
    let (a, b) = two();
    a.main_group().unwrap();
    let n = a.create_note().unwrap();
    let m = a.create_note().unwrap();
    a.toggle_favorite(m).unwrap();
    sync(&a, &b);
    a.toggle_favorite(n).unwrap();
    b.toggle_favorite(n).unwrap();
    let k = a.create_note().unwrap();
    a.toggle_favorite(k).unwrap();
    sync(&a, &b);
    let f = a.favorites().unwrap();
    assert_eq!(f.iter().filter(|x| **x == n).count(), 1);
    let i = f.iter().position(|x| *x == n).unwrap();
    a.move_favorite(i, f.len() - 1).unwrap();
    assert_eq!(a.favorites().unwrap().last(), Some(&n), "{:?}", a.favorites().unwrap());
}
