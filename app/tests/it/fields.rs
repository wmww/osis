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
    let given = find(&rows, "contact:names.0", "given");
    assert!(given.optional && given.edit == Edit::Text && given.value.is_empty());
    assert!(!rows.iter().any(|r| r.ak == "created.0" || r.ak == "group.0"), "system aspects are hidden");
    d.set_field(c, &given, "Lena").unwrap();
    let rows = d.field_rows(c).unwrap();
    assert_eq!(find(&rows, "contact:names.0", "given").value, "Lena");
    d.set_field(c, &given, "").unwrap();
    assert_eq!(find(&d.field_rows(c).unwrap(), "contact:names.0", "given").value, "", "empty writes none");
    let name = find(&rows, "name.0", "name.0");
    d.set_field(c, &name, "Lena F").unwrap();
    assert_eq!(d.name(c).unwrap(), "Lena F");
    // an event: its start's wall time is an int row under the `at` case
    let e = d.create(NewKind::Event).unwrap();
    let rows = d.field_rows(e).unwrap();
    let time = rows.iter().find(|r| r.ak == "event:start.0" && r.label == "time").unwrap().clone();
    assert_eq!(time.edit, Edit::Int);
    d.set_field(e, &time, "60000").unwrap();
    assert!(d.set_field(e, &time, "soon").is_err(), "not a number");
    // a view thing: its kind is a payload-free enum, edited by case name
    let (_, v) = d.views().unwrap()[0].clone();
    let view = find(&d.field_rows(v).unwrap(), "osis_app:view.0", "osis_app:view.0");
    assert_eq!((view.edit, view.value.as_str()), (Edit::Case, "calendar"));
    assert!(d.set_field(v, &view, "nope").is_err());
}

#[test]
fn contact_form() {
    use osis_app::contact::{EMAILS, NAMES, ORG};
    use osis_app::fields::FormAct;
    let d = Data::new(Osis::create(Config::memory()).unwrap().0);
    // a contact with no names or org yet: fields still save
    let c = d.create(NewKind::Note).unwrap();
    let form = d.contact_form(c).unwrap();
    let row = |form: &[osis_app::fields::FormRow], label: &str| form.iter().find(|r| r.label == label).unwrap().act.clone();
    d.form_apply(c, &row(&form, "Title"), "Gardener").unwrap();
    assert_eq!(d.db.at(c, ORG).get().unwrap().unwrap().title, "Gardener");
    d.form_apply(c, &row(&form, "Given name"), "Theo").unwrap();
    assert_eq!(d.db.at(c, NAMES).get().unwrap().unwrap().given.as_deref(), Some("Theo"));
    let add = form.iter().find(|r| matches!(r.act, FormAct::AddKey { ak: "contact:emails.0" })).unwrap().act.clone();
    d.form_apply(c, &add, "theo@example.org").unwrap();
    let form = d.contact_form(c).unwrap();
    let email = form.iter().find(|r| r.value == "theo@example.org").unwrap().act.clone();
    d.form_apply(c, &email, "theo@posteo.se").unwrap();
    assert_eq!(d.db.at(c, EMAILS).get().unwrap().unwrap().into_keys().collect::<Vec<_>>(), vec!["theo@posteo.se".to_string()]);
    let form = d.contact_form(c).unwrap();
    let email = form.iter().find(|r| r.value == "theo@posteo.se").unwrap().act.clone();
    d.form_apply(c, &email, "").unwrap();
    assert!(d.db.at(c, EMAILS).get().unwrap().unwrap_or_default().is_empty(), "empty removes");
    assert_eq!(d.kind(c).unwrap(), osis_app::data::Kind::Contact, "a note given contact fields is a contact");
}

/// Every editable row writes a value its type accepts; a bool is only one of its spellings; a
/// body (markdown, a text) is not a one-line row.
#[test]
fn edits_are_well_typed() {
    use osis::core::BODY;
    let d = Data::new(Osis::create(Config::memory()).unwrap().0);
    let e = d.create(NewKind::Event).unwrap();
    d.set_repeat(e, Some(osis_app::event::RepeatFreq::Weekly)).unwrap();
    let s = d.db.edit_text(e, BODY, osis::Path::root()).unwrap();
    s.replace(0..0, "line one\nline two\n").unwrap();
    s.commit().unwrap();
    drop(s);
    let rows = d.field_rows(e).unwrap();
    for r in rows.iter().filter(|r| r.edit != Edit::None) {
        let text = match r.edit {
            Edit::Int => "3",
            Edit::Float => "1.5",
            Edit::Bool => "true",
            Edit::Case => "monthly",
            _ => "x",
        };
        if r.ak == "body.0" {
            continue;
        }
        let res = d.set_field(e, r, text);
        if r.edit != Edit::Case || r.label == "freq" {
            res.unwrap_or_else(|err| panic!("{r:?}: {err}"));
        }
    }
    let body = rows.iter().find(|r| r.ak == "body.0").unwrap();
    assert_eq!(body.edit, Edit::None, "a text is edited in its session");
    let b = rows.iter().find(|r| r.edit == Edit::Bool);
    if let Some(b) = b {
        assert!(d.set_field(e, b, "maybe").is_err());
    }
}

/// A value that cannot be read shows as such, read-only: an empty editable row could overwrite it.
#[test]
fn a_value_too_large_to_read_is_no_empty_row() {
    let mut cfg = Config::memory();
    cfg.materialize_limit = 1000;
    let d = Data::new(Osis::create(cfg).unwrap().0);
    let n = d.create(NewKind::Note).unwrap();
    let mut w = d.db.write();
    w.at(n, osis::core::BODY).set(&"x".repeat(2000)).unwrap();
    w.commit().unwrap();
    let rows = d.field_rows(n).unwrap();
    let row = rows.iter().find(|r| r.ak == "body.0").unwrap();
    assert_eq!(row.edit, Edit::None, "{row:?}");
    assert!(row.value.contains("larger"), "{row:?}");
}
