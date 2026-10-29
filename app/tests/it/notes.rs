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

/// Typing spliced into a session whose buffer holds a remote merge the widget does not show yet
/// keeps the merge (`shown` is the widget's text before the keystroke).
#[test]
fn splice_keeps_unshown_remote_merge() {
    use osis_app::ui::splice;
    let n = notes();
    let t = n.create("x").unwrap();
    let s = n.db.edit_text(t, BODY, osis::Path::root()).unwrap();
    let shown = "hello world";
    s.insert(0, shown).unwrap();
    // the "remote" merge, ahead of the widget
    s.insert(6, "brave ").unwrap();
    splice(&s, shown, "hello world!").unwrap();
    assert_eq!(s.text(), "hello brave world!", "after the merge");
    splice(&s, "hello world!", ">hello world!").unwrap();
    assert_eq!(s.text(), ">hello brave world!", "before the merge");
    splice(&s, ">hello world!", ">hellX world!").unwrap();
    assert_eq!(s.text(), ">hellX brave world!", "a replace before the merge");
    // a deletion across the merge point: the merge wins, only what was typed lands, after it
    splice(&s, ">hellX world!", ">hellX_rld!").unwrap();
    assert_eq!(s.text(), ">hellX brave _world!");
    splice(&s, ">hellX brave _world!", ">hellX brave _world").unwrap();
    assert_eq!(s.text(), ">hellX brave _world", "no merge pending: the plain splice");
}
