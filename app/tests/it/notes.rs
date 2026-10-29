//! The notes actions over an in-memory database.
use osis::core::{BODY, GROUP, NAME};
use osis::{Config, Osis};
use osis_app::notes::Notes;

fn notes() -> Notes {
    Notes::new(Osis::create(Config::memory()).unwrap().0)
}

#[test]
fn create_select_rename_delete() {
    let n = notes();
    assert!(n.list().unwrap().is_empty());
    assert_eq!(n.selected().unwrap(), None);
    let a = n.create("b note").unwrap();
    let b = n.create("A note").unwrap();
    assert_eq!(n.selected().unwrap(), Some(b), "a new note is selected");
    assert_eq!(n.list().unwrap(), vec![(b, "A note".into()), (a, "b note".into())], "sorted case-folded");
    n.select(Some(a)).unwrap();
    assert_eq!(n.selected().unwrap(), Some(a));
    let s = n.db.edit_text(a, BODY, osis::Path::root()).unwrap();
    s.insert(0, "hello").unwrap();
    s.commit().unwrap();
    assert_eq!(n.db.get(a, BODY).unwrap().as_deref(), Some("hello"));
    n.delete(a).unwrap();
    assert_eq!(n.list().unwrap(), vec![(b, "A note".into())]);
    assert_eq!(n.selected().unwrap(), None, "deleting the selected note clears the selection");
    assert_eq!(n.db.get(a, NAME).unwrap(), None);
}

/// The notes group is a subgroup of home (so its items sync, not only its own aspects) and
/// carries no `/tag`; one group however often it is asked for.
#[test]
fn one_internal_group_under_home() {
    let n = notes();
    let g = n.main_group().unwrap();
    assert_eq!(n.main_group().unwrap(), g);
    let home = n.db.get(n.db.home(), GROUP).unwrap().unwrap();
    assert!(home.items.contains(&g) && home.subgroups.contains(&g));
    assert_eq!(n.db.get(g, osis::core::TAG).unwrap(), None);
    let t = n.create("x").unwrap();
    assert!(n.db.groups_of(t).contains(&n.db.home()));
}
