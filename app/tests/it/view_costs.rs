//! The cost harness over the app's views.
use osis_kit::testing::check_views;

/// As in kit's: every registered view, app and kit alike, with the app's registry.
#[test]
#[ignore = "accounts: making an account"]
fn every_view_reads_exactly_what_it_shows() {
    let fails = check_views(&crate::common::data());
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}
