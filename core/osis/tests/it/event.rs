#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Calendar events (notes/std.md): wall-clock times with a zone, civil days, a duration end, a
//! weekly series with a skipped and an overridden occurrence; a calendar is a tag shared like
//! any other. Default tests.

const MIN: i64 = 60_000;
const DAY: i64 = 24 * 60 * MIN;

/// Days since 1970-01-01 of a proleptic Gregorian date (spec/data-model.md §3, `date`).
fn date(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A wall-clock time in ms (spec/data-model.md §3, `localtime`).
fn local(y: i64, m: i64, d: i64, h: i64, min: i64) -> i64 {
    date(y, m, d) * DAY + h * 60 * MIN + min * MIN
}

// spec/data-model.md §3 (`date` = days since 1970-01-01, proleptic Gregorian, no zone).
#[test]
fn civil_dates_are_days_since_the_epoch() {
    assert_eq!(date(1970, 1, 1), 0);
    assert_eq!(date(1969, 12, 31), -1);
    assert_eq!(date(2000, 3, 1), 11_017);
    assert_eq!(local(1970, 1, 2, 1, 30), DAY + 90 * MIN);
}

