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
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Osis::create(cfg(1, &clock)).unwrap().0;
    let j = Osis::pair(cfg(2, &clock), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let b = j.finish(&reply).unwrap();
    (Data::new(a), Data::new(b))
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
