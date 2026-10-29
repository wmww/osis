//! The actions layer over an in-memory database.
use osis::core::{GROUP, NAME, TAG};
use osis::{Config, Osis};
use osis_app::data::{Data, Kind, snippet};
use osis_app::schema::View;

fn data() -> Data {
    Data::new(Osis::create(Config::memory()).unwrap().0)
}

/// One app group, an item and subgroup of home with no `/tag`, holding the four views, which
/// start as the favorites.
#[test]
fn app_group_and_views() {
    let d = data();
    let g = d.main_group().unwrap();
    assert_eq!(d.main_group().unwrap(), g);
    let home = d.db.get(d.db.home(), GROUP).unwrap().unwrap();
    assert!(home.items.contains(&g) && home.subgroups.contains(&g));
    assert_eq!(d.db.get(g, TAG).unwrap(), None);
    let views = d.views().unwrap();
    assert_eq!(views.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(), vec![View::Calendar, View::People, View::Tags, View::Recent]);
    assert_eq!(d.favorites().unwrap(), views.iter().map(|(_, t)| *t).collect::<Vec<_>>());
    assert!(matches!(d.kind(views[0].1).unwrap(), Kind::View(View::Calendar)));
}

#[test]
fn create_open_favorite_delete() {
    let d = data();
    assert_eq!(d.opened().unwrap(), None);
    let t = d.create_note().unwrap();
    assert_eq!(d.opened().unwrap(), Some(t), "a new note opens");
    assert_eq!(d.kind(t).unwrap(), Kind::Note);
    assert!(d.things().unwrap().contains(&t));
    d.toggle_favorite(t).unwrap();
    assert_eq!(d.favorites().unwrap().last(), Some(&t));
    let n = d.favorites().unwrap().len();
    d.move_favorite(n - 1, 0).unwrap();
    assert_eq!(d.favorites().unwrap().first(), Some(&t));
    d.set_open(None).unwrap();
    assert_eq!(d.opened().unwrap(), None);
    d.set_open(Some(t)).unwrap();
    d.delete(t).unwrap();
    assert_eq!(d.opened().unwrap(), None, "deleting the open thing goes home");
    assert!(!d.favorites().unwrap().contains(&t), "a deleted favorite is skipped");
    assert_eq!(d.db.get(t, NAME).unwrap(), None);
}

/// Demo data once; kinds, tags, colours, contents and search over it.
#[test]
fn demo_kinds_and_search() {
    let d = data();
    assert!(osis_app::demo::add(&d).unwrap());
    assert!(!osis_app::demo::add(&d).unwrap(), "only once");
    let by_name = |n: &str| d.things().unwrap().into_iter().find(|t| d.name(*t).unwrap() == n).unwrap();
    let garden = by_name("Garden");
    let home = by_name("Home");
    assert_eq!(d.kind(garden).unwrap(), Kind::Tag);
    assert_eq!(d.kind(by_name("Mara Okafor")).unwrap(), Kind::Contact);
    assert_eq!(d.kind(by_name("Seed swap")).unwrap(), Kind::Event);
    let tomatoes = by_name("Tomato varieties");
    assert_eq!(d.kind(tomatoes).unwrap(), Kind::Note);
    assert_eq!(d.tags_of(tomatoes).unwrap(), vec![garden]);
    assert_eq!(d.color(tomatoes).unwrap().as_deref(), Some("#22c55e"), "a thing takes its tag's colour");
    let (subs, items) = d.tag_contents(home).unwrap();
    assert!(subs.contains(&garden) && !items.contains(&garden));
    assert!(d.view_items(&View::People).unwrap().len() == 6);
    let f = d.search("garden").unwrap();
    assert_eq!(f.scopes, vec![garden]);
    assert!(f.mentions.iter().any(|(t, _)| *t == tomatoes), "\"Gardener's Delight\"");
    assert!(f.in_scopes.contains(&by_name("Compost notes")), "things in a matching tag");
    let f = d.search("walnut").unwrap();
    assert_eq!(f.mentions.len(), 2, "a body and a contact note: {:?}", f.mentions);
    assert!(d.search("  ").unwrap().is_empty());
}

#[test]
fn snippets() {
    assert_eq!(snippet("hello world", "wor").as_deref(), Some("hello world"));
    assert_eq!(snippet("a\nb", "b").as_deref(), Some("a · b"));
    assert_eq!(snippet("abc", "x"), None);
    // the query folds like the text: a final sigma, a dotted capital I
    assert!(snippet("ΟΔΟΣ ΚΑΙ", &osis_app::data::fold("ΟΔΟΣ")).is_some());
    assert!(snippet("İzmir", &osis_app::data::fold("İZMİR")).is_some());
}

/// The look is per person, on the app group: default until set.
#[test]
fn look_choice() {
    use osis_app::schema::Mode;
    let d = data();
    assert_eq!(d.look().unwrap(), (None, Mode::Auto));
    d.set_theme("cel").unwrap();
    d.set_mode(Mode::Dark).unwrap();
    assert_eq!(d.look().unwrap(), (Some("cel".into()), Mode::Dark));
}
