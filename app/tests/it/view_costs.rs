//! The cost harness over the app's views.
use osis_kit::testing::check_views;

/// As in kit's: every registered view, app and kit alike, with the app's registry.
#[test]
fn every_view_reads_exactly_what_it_shows() {
    let db = osis::internals::create(osis::internals::Opening::memory()).unwrap();
    let d = osis_app::store::data(db);
    d.main_group().unwrap();
    let fails = check_views(&d);
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}
