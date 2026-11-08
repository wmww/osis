//! Wall-clock helpers the view system needs: the system zone, days and weeks in local wall ms,
//! and short date and time labels.

use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use jiff::{Timestamp, Zoned};

pub const MINUTE: i64 = 60_000;
pub const HOUR: i64 = 60 * MINUTE;
pub const DAY: i64 = 24 * HOUR;

/// A wall time as `localtime` ms (the civil time read as if it were UTC).
fn ms_of(dt: DateTime) -> i64 {
    dt.to_zoned(TimeZone::UTC).map(|z| z.timestamp().as_millisecond()).unwrap_or(0)
}

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// The viewer's zone (UTC when the system's cannot be read).
pub fn system() -> TimeZone {
    TimeZone::try_system().unwrap_or(TimeZone::UTC)
}

/// A moment (UTC ms) as local wall time (`localtime` ms).
pub fn local_of(utc_ms: i64) -> i64 {
    Timestamp::from_millisecond(utc_ms).map_or(utc_ms, |t| ms_of(t.to_zoned(system()).datetime()))
}

/// Now as local wall time (`localtime` ms).
pub fn now_local() -> i64 {
    ms_of(Zoned::now().with_time_zone(system()).datetime())
}

/// Monday 00:00 of the week holding `ms` (local wall ms).
pub fn monday_of(ms: i64) -> i64 {
    let days = ms.div_euclid(DAY);
    // 1970-01-01 was a Thursday
    (days - (days + 3).rem_euclid(7)).saturating_mul(DAY)
}

/// (year, month 1-12, day 1-31) of a day count since 1970-01-01 (proleptic Gregorian).
pub fn civil_of(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// "Mon 14 Oct" for a day count.
pub fn fmt_day(days: i64) -> String {
    let (_, m, d) = civil_of(days);
    let wd = WEEKDAYS.get(days.saturating_add(3).rem_euclid(7) as usize).copied().unwrap_or("");
    format!("{wd} {d} {}", MONTHS.get(m as usize - 1).copied().unwrap_or(""))
}

/// "09:30" for a wall time's ms within its day.
pub fn fmt_time(ms: i64) -> String {
    let m = ms.rem_euclid(86_400_000) / 60_000;
    format!("{:02}:{:02}", m / 60, m % 60)
}
