//! The account's state over an in-memory node.
use osis::core::{NAME, TAG};
use osis::internals::core_types::GROUP;
use osis_app::store::data as make;
use osis_kit::store::Data;
use osis_kit::view::search::{search, snippet};
use osis_kit::view::{Cx, WindowState};
use osis_kit::views::page;

fn data() -> Data {
    make(osis::internals::create(osis::internals::Opening::memory()).unwrap())
}

fn view_of(d: &Data, t: osis::Tid) -> String {
    let w = WindowState::default();
    let cx = Cx::new(d, &w, false);
    let n = page(&cx, t).unwrap();
    n.children.iter().find(|c| c.spec.view_type != "bar").map(|c| c.spec.view_type.clone()).unwrap()
}

pub fn found(d: &Data, q: &str) -> osis_kit::view::search::Found {
    let w = WindowState::default();
    search(&Cx::new(d, &w, false), q).unwrap()
}

/// One account group, an item and subgroup of home with no `tag.0`, holding the four seeds, which
/// start as the favorites.
#[test]
fn app_group_and_seeds() {
    let d = data();
    let g = d.main_group().unwrap();
    assert_eq!(d.main_group().unwrap(), g);
    let home = d.db.at(d.db.home(), GROUP).get().unwrap().unwrap();
    assert!(home.items.contains(&g) && home.subgroups.contains(&g));
    assert_eq!(d.db.at(g, TAG).get().unwrap(), None);
    assert_eq!(d.collections().unwrap().len(), 4);
    let favs: Vec<String> = d.favorites().unwrap().iter().map(|t| d.name(*t).unwrap()).collect();
    assert_eq!(favs, ["Calendar", "People", "Tags", "Recent"]);
    assert_eq!(view_of(&d, d.favorites().unwrap()[0]), "collection");
}

#[test]
fn create_open_favorite_delete() {
    let d = data();
    assert_eq!(d.opened().unwrap(), None);
    let t = d.create_note().unwrap();
    assert_eq!(d.opened().unwrap(), Some(t), "a new note opens");
    assert_eq!(view_of(&d, t), "note");
    assert!(d.things().unwrap().contains(&t));
    d.toggle_favorite(t).unwrap();
    assert_eq!(d.favorites().unwrap().last(), Some(&t));
    let before = d.favorites().unwrap();
    let n = before.len();
    d.move_favorite(n - 1, 0).unwrap();
    assert_eq!(d.favorites().unwrap().first(), Some(&t));
    d.move_favorite(0, 2).unwrap();
    let mut want = before.clone();
    want.pop();
    want.insert(2, t);
    assert_eq!(d.favorites().unwrap(), want, "moved to the middle");
    d.move_favorite(2, n - 1).unwrap();
    assert_eq!(d.favorites().unwrap(), before, "and back to the end");
    d.set_open(None).unwrap();
    assert_eq!(d.opened().unwrap(), None);
    d.set_open(Some(t)).unwrap();
    d.delete(t).unwrap();
    assert_eq!(d.opened().unwrap(), None, "deleting the open thing goes home");
    assert!(!d.favorites().unwrap().contains(&t), "a deleted favorite is skipped");
    assert_eq!(d.db.at(t, NAME).get().unwrap(), None);
}

/// Demo data once; tags, colours, contents and search over it.
#[test]
fn demo_and_search() {
    let d = data();
    assert!(osis_app::demo::add(&d).unwrap());
    assert!(!osis_app::demo::add(&d).unwrap(), "only once");
    let by_name = |n: &str| d.things().unwrap().iter().copied().find(|t| d.name(*t).unwrap() == n).unwrap();
    let garden = by_name("Garden");
    let home = by_name("Home");
    assert_eq!(view_of(&d, garden), "collection");
    assert_eq!(view_of(&d, by_name("Mara Okafor")), "person");
    assert_eq!(view_of(&d, by_name("Seed swap")), "event");
    let tomatoes = by_name("Tomato varieties");
    assert_eq!(view_of(&d, tomatoes), "note");
    assert_eq!(d.tags_of(tomatoes).unwrap(), vec![garden]);
    assert_eq!(d.color(tomatoes).unwrap().as_deref(), Some("#22c55e"), "a thing takes its tag's colour");
    let (subs, items) = d.tag_contents(home).unwrap();
    assert!(subs.contains(&garden) && !items.contains(&garden));
    let f = found(&d, "garden");
    assert_eq!(f.scopes, vec![garden]);
    assert!(f.mentions.iter().any(|(t, _)| *t == tomatoes), "\"Gardener's Delight\"");
    assert!(f.in_scopes.contains(&by_name("Compost notes")), "things in a matching tag");
    let f = found(&d, "walnut");
    assert_eq!(f.mentions.len(), 2, "a body and a contact note: {:?}", f.mentions);
    assert!(found(&d, "  ").is_empty());
}

#[test]
fn snippets() {
    assert_eq!(snippet("hello world", "wor").as_deref(), Some("hello world"));
    assert_eq!(snippet("a\nb", "b").as_deref(), Some("a · b"));
    assert_eq!(snippet("abc", "x"), None);
    assert!(snippet("ΟΔΟΣ ΚΑΙ", &osis_kit::view::search::fold("ΟΔΟΣ")).is_some());
    assert!(snippet("İzmir", &osis_kit::view::search::fold("İZMİR")).is_some());
}

/// The look is per account, on the account group: default until set.
#[test]
fn look_choice() {
    use osis_kit::schema::Mode;
    let d = data();
    d.main_group().unwrap();
    assert_eq!(d.look().unwrap(), (None, Mode::Auto));
    d.set_theme("cel").unwrap();
    d.set_mode(Mode::Dark).unwrap();
    assert_eq!(d.look().unwrap(), (Some("cel".into()), Mode::Dark));
}

/// Offers, tagging, untagging, reach of a private thing, undo.
#[test]
fn offers_tags_reach_undo() {
    use osis_kit::facets::{about::reach, create};
    let d = data();
    assert_eq!(view_of(&d, create(&d, "event").unwrap()), "event");
    assert_eq!(view_of(&d, create(&d, "person").unwrap()), "person");
    let g = create(&d, "tag").unwrap();
    assert_eq!(view_of(&d, g), "collection");
    assert!(d.own_color(g).unwrap().is_some(), "a new tag has a colour");
    assert_eq!(d.all_tags().unwrap(), vec![g]);
    let n = create(&d, "note").unwrap();
    d.add_tag(n, g).unwrap();
    assert_eq!(d.tags_of(n).unwrap(), vec![g]);
    assert_eq!(d.tag_contents(g).unwrap().1, vec![n]);
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    assert_eq!(reach(&cx, n).unwrap().who(), "Only you");
    assert_eq!(reach(&cx, g).unwrap().people, Vec::<String>::new());
    d.remove_tag(n, g).unwrap();
    assert!(d.tags_of(n).unwrap().is_empty());
    assert!(d.things().unwrap().contains(&n), "still in the account group");
    let mut w = d.db.write();
    w.at(n, NAME).set(&"changed".to_string()).unwrap();
    w.commit().unwrap();
    assert!(d.undo(n).unwrap());
    assert_eq!(d.name(n).unwrap(), "");
    assert!(d.edited(n).unwrap().starts_with("Edited "));
}
