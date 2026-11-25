//! The cost harness over the app's views.
use osis_kit::testing::{check_view_scale, check_views};

/// Whether `v` is one of kit's views.
fn kits(v: &osis_kit::views::ViewType) -> bool {
    osis_kit::views::kit().iter().any(|k| k.id == v.id)
}

/// As in kit's: every view the app registers, with the app's registry.
#[test]
fn every_view_reads_exactly_what_it_shows() {
    let fails = check_views(&crate::common::data(), |v| !kits(v));
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

/// Kit's views, with the app's registry: what they show of the app's views and facets.
#[test]
fn every_kit_view_reads_exactly_what_it_shows_in_the_app() {
    let fails = check_views(&crate::common::data(), kits);
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

/// As in kit's: every registered view that grows, with the app's registry.
#[test]
fn every_view_grows_flat() {
    let fails = check_view_scale(&crate::common::data());
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}
