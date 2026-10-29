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

// ---- repeating events

use crate::event::{Occurrence, Repeat, RepeatFreq, Weekday};
use jiff::civil::Date;

/// Most periods one expansion steps through: a malformed or very long series (daily since a
/// century) costs at most this much per event and week shown; at 0 nothing would repeat.
const MAX_PERIODS: i64 = 20_000;

fn date_of(days: i64) -> Option<Date> {
    civil(days.checked_mul(DAY)?).map(|d| d.date())
}

fn days_of(d: Date) -> i64 {
    ms_of(d.to_datetime(jiff::civil::Time::midnight())).div_euclid(DAY)
}

fn weekday_index(w: &Weekday) -> i64 {
    match w {
        Weekday::Mon => 0,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    }
}

/// Monday-based weekday of a day count (1970-01-01 was a Thursday).
fn weekday_of(days: i64) -> i64 {
    (days + 3).rem_euclid(7)
}

/// The day counts of one period of the series (the period starting at `first`, a day count),
/// before `until` and `skip` apply.
fn period_days(r: &Repeat, first: i64, anchor: i64) -> Vec<i64> {
    let mut out = Vec::new();
    match r.freq {
        RepeatFreq::Daily => out.push(first),
        RepeatFreq::Weekly => {
            let monday = first - weekday_of(first);
            if r.weekdays.is_empty() {
                out.push(monday + weekday_of(anchor));
            } else {
                out.extend(r.weekdays.iter().map(|w| monday + weekday_index(&w.day)));
            }
        }
        RepeatFreq::Monthly | RepeatFreq::Yearly => {
            let Some(d) = date_of(first) else { return out };
            let (from, len) = if r.freq == RepeatFreq::Monthly {
                (Date::new(d.year(), d.month(), 1).ok(), i64::from(d.days_in_month()))
            } else {
                (Date::new(d.year(), 1, 1).ok(), i64::from(d.days_in_year()))
            };
            let Some(from) = from else { return out };
            let start = days_of(from);
            if !r.monthdays.is_empty() && r.freq == RepeatFreq::Monthly {
                for m in &r.monthdays {
                    // -1 is the last day
                    let idx = if *m > 0 { m - 1 } else { len + m };
                    if (0..len).contains(&idx) {
                        out.push(start + idx);
                    }
                }
            } else if !r.weekdays.is_empty() {
                for w in &r.weekdays {
                    let want = weekday_index(&w.day);
                    let all: Vec<i64> = (0..len).map(|i| start + i).filter(|d| weekday_of(*d) == want).collect();
                    match w.nth {
                        None => out.extend(all),
                        Some(n) if n > 0 => out.extend(all.get(usize::try_from(n - 1).unwrap_or(usize::MAX)).copied()),
                        Some(n) => out.extend(all.len().checked_sub(usize::try_from(-n).unwrap_or(usize::MAX)).and_then(|i| all.get(i)).copied()),
                    }
                }
            } else if let Some(a) = date_of(anchor) {
                // the anchor's day of the month (or of the year); skipped where it does not exist
                let day = if r.freq == RepeatFreq::Monthly { Date::new(d.year(), d.month(), a.day()).ok() } else { Date::new(d.year(), a.month(), a.day()).ok() };
                out.extend(day.map(days_of));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The first day of the period `k` periods after the anchor's.
fn period_start(r: &Repeat, anchor: i64, k: i64) -> Option<i64> {
    let step = r.interval.max(1).checked_mul(k)?;
    match r.freq {
        RepeatFreq::Daily => anchor.checked_add(step),
        RepeatFreq::Weekly => (anchor - weekday_of(anchor)).checked_add(step.checked_mul(7)?),
        RepeatFreq::Monthly | RepeatFreq::Yearly => {
            let a = date_of(anchor)?;
            let first = Date::new(a.year(), if r.freq == RepeatFreq::Monthly { a.month() } else { 1 }, 1).ok()?;
            let span = if r.freq == RepeatFreq::Monthly { jiff::Span::new().try_months(step).ok()? } else { jiff::Span::new().try_years(step).ok()? };
            first.checked_add(span).ok().map(days_of)
        }
    }
}

/// The occurrences of a repeating event that touch local wall ms `[from, to)`: (nominal
/// occurrence, local start, local end, all day). The series starts at the event's start, counts
/// `count` occurrences from there, stops after `until` (a date, inclusive), and leaves out `skip`
/// and the occurrences in `overridden` (replaced by other events).
pub fn occurrences(start: &Start, end: Option<&End>, r: &Repeat, from: i64, to: i64, overridden: &[Occurrence]) -> Vec<(Occurrence, i64, i64, bool)> {
    let (s0, e0, all_day) = span(start, end);
    let len = e0 - s0;
    // the series in nominal (unconverted) terms: day count and time of day
    let (anchor, tod, zone) = match start {
        Start::At(w) => (w.time.div_euclid(DAY), w.time.rem_euclid(DAY), w.zone.clone()),
        Start::Day(d) => (*d, 0, None),
    };
    let mut out = Vec::new();
    let mut n = 0i64;
    for k in 0..MAX_PERIODS {
        let Some(first) = period_start(r, anchor, k) else { break };
        let mut past = false;
        for day in period_days(r, first, anchor) {
            if day < anchor {
                continue;
            }
            if r.until.is_some_and(|u| day > u) || r.count.is_some_and(|c| n >= c) {
                past = true;
                break;
            }
            n += 1;
            let occ = match start {
                Start::At(_) => Occurrence::At(day * DAY + tod),
                Start::Day(_) => Occurrence::Day(day),
            };
            if r.skip.contains(&occ) || overridden.contains(&occ) {
                continue;
            }
            let s = match start {
                Start::At(_) => to_local(&Wall { time: day * DAY + tod, zone: zone.clone() }),
                Start::Day(_) => day * DAY,
            };
            if s >= to {
                past = true;
                break;
            }
            if s + len.max(1) > from || (len == 0 && s >= from) {
                out.push((occ, s, s + len, all_day));
            }
        }
        if past {
            break;
        }
    }
    out
}
