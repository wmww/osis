//! A local walk through a folder tree: one device, no servers.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

fn main() {
    let (db, _) = osis::Osis::create(osis::Config::memory()).unwrap();
    let root = folder::new_root(&db, "Projects").unwrap();
    let docs = folder::new_subfolder(&db, root, root, "docs").unwrap();
    folder::new_file(&db, root, root, "todo.txt", "ship it").unwrap();
    let readme = folder::new_file(&db, root, docs, "README", "hello").unwrap();
    folder::edit_file(&db, readme, "hello", "hello, world").unwrap();
    let mine = folder::move_out(&db, readme, db.me(), db.home()).unwrap();
    for f in [root, docs] {
        let (files, subs) = folder::list(&db, f).unwrap();
        let names = |v: Vec<osis::Tid>| v.into_iter().map(|t| folder::name(&db, t).unwrap().unwrap()).collect::<Vec<_>>();
        println!("{}: files {:?}, folders {:?}", folder::name(&db, f).unwrap().unwrap(), names(files), names(subs));
    }
    println!("moved copy: {:?} (same thing: {})", folder::content(&db, mine).unwrap(), db.same_thing(mine, readme));
}
