//! Wall-clock time for calendar views: event times (`localtime` ms, spec/data-model.md §3, with an
//! optional IANA zone or `+HH:MM` offset) as the viewer's local wall time, via jiff and the
//! system time zone. A floating time (no zone) is shown as written.

use crate::event::{End, Start, Wall};
use jiff::civil::DateTime;
use jiff::tz::{Offset, TimeZone};
use jiff::{Timestamp, Zoned};

pub const MINUTE: i64 = 60_000;
pub const HOUR: i64 = 60 * MINUTE;
pub const DAY: i64 = 24 * HOUR;

/// A wall time as `localtime` ms (the civil time read as if it were UTC).
fn ms_of(dt: DateTime) -> i64 {
    dt.to_zoned(TimeZone::UTC).map(|z| z.timestamp().as_millisecond()).unwrap_or(0)
}

/// The civil time of `localtime` ms.
fn civil(ms: i64) -> Option<DateTime> {
    Timestamp::from_millisecond(ms).ok().map(|t| t.to_zoned(TimeZone::UTC).datetime())
}

/// The viewer's zone (UTC when the system's cannot be read).
pub fn system() -> TimeZone {
    TimeZone::try_system().unwrap_or(TimeZone::UTC)
}

/// Now as local wall time (`localtime` ms).
pub fn now_local() -> i64 {
    ms_of(Zoned::now().with_time_zone(system()).datetime())
}

/// A zone name or fixed `+HH:MM` / `-HH:MM` offset.
fn zone(name: &str) -> Option<TimeZone> {
    let b = name.as_bytes();
    if let (Some(sign @ (b'+' | b'-')), Some((h, m))) = (b.first(), name.get(1..).and_then(|r| r.split_once(':'))) {
        let mins = h.parse::<i32>().ok()? * 60 + m.parse::<i32>().ok()?;
        let secs = if *sign == b'-' { -mins * 60 } else { mins * 60 };
        return Offset::from_seconds(secs).ok().map(TimeZone::fixed);
    }
    TimeZone::get(name).ok()
}

/// A wall time as the viewer's local wall time.
pub fn to_local(w: &Wall) -> i64 {
    let Some(z) = w.zone.as_deref().and_then(zone) else { return w.time };
    let Some(dt) = civil(w.time) else { return w.time };
    match dt.to_zoned(z) {
        Ok(zoned) => ms_of(zoned.with_time_zone(system()).datetime()),
        Err(_) => w.time,
    }
}

/// An event's span in local wall time: (start, end, all day). A moment ends at its start, a
/// day event runs whole days.
pub fn span(start: &Start, end: Option<&End>) -> (i64, i64, bool) {
    match start {
        Start::At(w) => {
            let s = to_local(w);
            let e = match end {
                Some(End::At(e)) => to_local(e),
                Some(End::After(d)) => s.saturating_add(*d),
                _ => s,
            };
            (s, e.max(s), false)
        }
        Start::Day(d) => {
            let s = d.saturating_mul(DAY);
            let last = match end {
                Some(End::Day(e)) if e >= d => *e,
                _ => *d,
            };
            (s, last.saturating_add(1).saturating_mul(DAY), true)
        }
    }
}

/// Monday 00:00 of the week holding `ms` (local wall ms).
pub fn monday_of(ms: i64) -> i64 {
    let days = ms.div_euclid(DAY);
    // 1970-01-01 was a Thursday
    (days - (days + 3).rem_euclid(7)) * DAY
}
