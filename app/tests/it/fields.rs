//! The schema fallback view: rows from schema types, edits written at their paths.
use osis::{Config, Osis};
use osis_app::data::{Data, NewKind};
use osis_app::fields::Edit;

#[test]
fn rows_and_edits() {
    let d = Data::new(Osis::create(Config::memory()).unwrap().0);
    let c = d.create(NewKind::Contact).unwrap();
    let rows = d.field_rows(c).unwrap();
    let find = |rows: &[osis_app::fields::Row], ak: &str, label: &str| rows.iter().find(|r| r.ak == ak && r.label == label).cloned().unwrap_or_else(|| panic!("{ak} {label} in {rows:#?}"));
    let given = find(&rows, "/contact/names", "given");
    assert!(given.optional && given.edit == Edit::Text && given.value.is_empty());
    assert!(!rows.iter().any(|r| r.ak == "/created" || r.ak == "/group"), "system aspects are hidden");
    d.set_field(c, &given, "Lena").unwrap();
    let rows = d.field_rows(c).unwrap();
    assert_eq!(find(&rows, "/contact/names", "given").value, "Lena");
    d.set_field(c, &given, "").unwrap();
    assert_eq!(find(&d.field_rows(c).unwrap(), "/contact/names", "given").value, "", "empty writes none");
    let name = find(&rows, "/name", "/name");
    d.set_field(c, &name, "Lena F").unwrap();
    assert_eq!(d.name(c).unwrap(), "Lena F");
    // an event: its start's wall time is an int row under the `at` case
    let e = d.create(NewKind::Event).unwrap();
    let rows = d.field_rows(e).unwrap();
    let time = rows.iter().find(|r| r.ak == "/event/start" && r.label == "time").unwrap().clone();
    assert_eq!(time.edit, Edit::Int);
    d.set_field(e, &time, "60000").unwrap();
    assert!(d.set_field(e, &time, "soon").is_err(), "not a number");
    // a view thing: its kind is a payload-free enum, edited by case name
    let (_, v) = d.views().unwrap()[0].clone();
    let view = find(&d.field_rows(v).unwrap(), "/osis-app/view", "/osis-app/view");
    assert_eq!((view.edit, view.value.as_str()), (Edit::Case, "calendar"));
    assert!(d.set_field(v, &view, "nope").is_err());
}
