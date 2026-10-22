//! A local walk through tags: one device, no servers.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use osis::Role;

fn main() {
    let (db, _) = osis::Osis::create(osis::Config::memory()).unwrap();
    let work = tags::new_tag(&db, "Work").unwrap();
    let ideas = tags::new_sub_tag(&db, db.me(), work, "Ideas", Role::Write).unwrap();
    let todo = tags::new_card(&db, db.me(), "ship it").unwrap();
    tags::add(&db, work, todo, Role::Write).unwrap();
    let pitch = tags::new_card(&db, db.me(), "hello").unwrap();
    tags::add(&db, ideas, pitch, Role::Write).unwrap();
    tags::add(&db, work, pitch, Role::Read).unwrap();
    tags::edit(&db, pitch, "hello", "hello, world").unwrap();
    for t in [work, ideas] {
        let (things, subs) = tags::list(&db, t).unwrap();
        let names = |v: Vec<osis::Tid>| v.into_iter().map(|t| tags::name(&db, t).unwrap().unwrap_or_else(|| tags::text(&db, t).unwrap().unwrap())).collect::<Vec<_>>();
        println!("{}: {:?}, sub-tags {:?}", tags::name(&db, t).unwrap().unwrap(), names(things), names(subs));
    }
    println!("pitch is in {} tags", tags::tags_of(&db, pitch).unwrap().len());
    let copy = tags::transfer(&db, pitch, db.me(), db.home()).unwrap();
    println!("transferred copy: {:?} (same thing: {})", tags::text(&db, copy).unwrap(), db.same_thing(copy, pitch));
}
