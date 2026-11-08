//! The schema fallback view: rows from schema types, edits written at their paths.
use osis_kit::facets::fields::Edit;

#[test]
fn rows_and_edits() {
    let d = osis_app::store::data(osis::internals::create(osis::internals::Opening::memory()).unwrap());
    let c = osis_kit::facets::create(&d, "person").unwrap();
    let rows = d.field_rows(c).unwrap();
    let find = |rows: &[osis_kit::facets::fields::Row], ak: &str, label: &str| rows.iter().find(|r| r.ak == ak && r.label == label).cloned().unwrap_or_else(|| panic!("{ak} {label} in {rows:#?}"));
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
    let e = osis_kit::facets::create(&d, "event").unwrap();
    let rows = d.field_rows(e).unwrap();
    let time = rows.iter().find(|r| r.ak == "event:start.0" && r.label == "time").unwrap().clone();
    assert_eq!(time.edit, Edit::Int);
    d.set_field(e, &time, "60000").unwrap();
    assert!(d.set_field(e, &time, "soon").is_err(), "not a number");
    // a collection's order is a payload-free enum, edited by case name
    let (_, v) = d.collections().unwrap()[0].clone();
    let rows = d.field_rows(v).unwrap();
    let order = rows.iter().find(|r| r.ak == "ui:collection.0" && r.label == "order").unwrap().clone();
    assert_eq!(order.edit, Edit::Case);
    assert!(d.set_field(v, &order, "nope").is_err());
}

#[test]
fn contact_form() {
    use osis_app::contact::{EMAILS, NAMES, ORG};
    use osis_app::facets::contact::{FormAct, FormRow, contact_form, form_apply};
    let d = osis_app::store::data(osis::internals::create(osis::internals::Opening::memory()).unwrap());
    // a contact with no names or org yet: fields still save
    let c = osis_kit::facets::create(&d, "note").unwrap();
    let form = contact_form(&d, c).unwrap();
    let row = |form: &[FormRow], label: &str| form.iter().find(|r| r.label == label).unwrap().act.clone();
    form_apply(&d, c, &row(&form, "Title"), "Gardener").unwrap();
    assert_eq!(d.db.at(c, ORG).get().unwrap().unwrap().title, "Gardener");
    form_apply(&d, c, &row(&form, "Given name"), "Theo").unwrap();
    assert_eq!(d.db.at(c, NAMES).get().unwrap().unwrap().given.as_deref(), Some("Theo"));
    let add = form.iter().find(|r| matches!(r.act, FormAct::AddKey { ak: "contact:emails.0" })).unwrap().act.clone();
    form_apply(&d, c, &add, "theo@example.org").unwrap();
    let form = contact_form(&d, c).unwrap();
    let email = form.iter().find(|r| r.value == "theo@example.org").unwrap().act.clone();
    form_apply(&d, c, &email, "theo@posteo.se").unwrap();
    assert_eq!(d.db.at(c, EMAILS).get().unwrap().unwrap().into_keys().collect::<Vec<_>>(), vec!["theo@posteo.se".to_string()]);
    let form = contact_form(&d, c).unwrap();
    let email = form.iter().find(|r| r.value == "theo@posteo.se").unwrap().act.clone();
    form_apply(&d, c, &email, "").unwrap();
    assert!(d.db.at(c, EMAILS).get().unwrap().unwrap_or_default().is_empty(), "empty removes");
}

/// Every editable row writes a value its type accepts; a bool is only one of its spellings; a
/// body (markdown, a text) is not a one-line row.
#[test]
fn edits_are_well_typed() {
    use osis::core::BODY;
    let d = osis_app::store::data(osis::internals::create(osis::internals::Opening::memory()).unwrap());
    let e = osis_kit::facets::create(&d, "event").unwrap();
    osis_app::facets::event_time::set_repeat(&d, e, Some(osis_app::event::RepeatFreq::Weekly)).unwrap();
    let s = d.db.at(e, BODY).path(osis::p![]).edit_text().unwrap();
    s.splice(0..0, "line one\nline two\n").unwrap();
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

/// A contact's tile reads its emails for its subtitle: one that cannot be read is told, not shown as no email.
#[test]
fn a_tile_tells_of_emails_it_cannot_read() {
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.read_limit = 1000;
    let d = osis_app::store::data(osis::internals::create(cfg).unwrap());
    let c = osis_kit::facets::create(&d, "person").unwrap();
    let many = (0..100).map(|i| (format!("someone{i}@example.org"), osis_app::contact::Labeled { label: String::new(), pref: false })).collect();
    let mut w = d.db.write();
    w.at(c, osis_app::contact::EMAILS).set(&many).unwrap();
    w.commit().unwrap();
    let w = osis_kit::view::WindowState::default();
    assert!(matches!(osis_kit::view::Cx::new(&d, &w, false).summary(c), Err(osis::Error::TooLarge { .. })));
}

/// A value that cannot be read shows as such, read-only: an empty editable row could overwrite it.
#[test]
fn a_value_too_large_to_read_is_no_empty_row() {
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.read_limit = 1000;
    let d = osis_app::store::data(osis::internals::create(cfg).unwrap());
    let n = osis_kit::facets::create(&d, "note").unwrap();
    let mut w = d.db.write();
    w.at(n, osis::core::BODY).set(&"x".repeat(2000)).unwrap();
    w.commit().unwrap();
    let rows = d.field_rows(n).unwrap();
    let row = rows.iter().find(|r| r.ak == "body.0").unwrap();
    assert_eq!(row.edit, Edit::None, "{row:?}");
    assert!(row.value.contains("larger"), "{row:?}");
}
