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
    if let Some(rest) = name.strip_prefix('+').map(|r| (1, r)).or_else(|| name.strip_prefix('-').map(|r| (-1, r))) {
        let (sign, rest) = rest;
        let (h, m) = rest.split_once(':')?;
        let digits = |x: &str| !x.is_empty() && x.len() <= 2 && x.bytes().all(|b| b.is_ascii_digit());
        if !digits(h) || !digits(m) {
            return None;
        }
        let mins = h.parse::<i32>().ok()? * 60 + m.parse::<i32>().ok()?;
        return Offset::from_seconds(sign * mins * 60).ok().map(TimeZone::fixed);
    }
    TimeZone::get(name).ok()
}

/// A wall time as the viewer's local wall time.
pub fn to_local(w: &Wall) -> i64 {
    to_local_in(w, &system())
}

/// A wall time as wall time in zone `tz` (the viewer's).
pub fn to_local_in(w: &Wall, tz: &TimeZone) -> i64 {
    let Some(z) = w.zone.as_deref().and_then(zone) else { return w.time };
    let Some(dt) = civil(w.time) else { return w.time };
    match dt.to_zoned(z) {
        Ok(zoned) => ms_of(zoned.with_time_zone(tz.clone()).datetime()),
        Err(_) => w.time,
    }
}

/// The instant of wall time `w`; a floating `w` is in `tz`.
fn instant(w: &Wall, tz: &TimeZone) -> Option<Timestamp> {
    let z = w.zone.as_deref().and_then(zone).unwrap_or_else(|| tz.clone());
    civil(w.time)?.to_zoned(z).ok().map(|z| z.timestamp())
}

/// The wall time in `tz` a duration (elapsed ms) after wall time `w`; a floating `w` is in `tz`.
fn after_in(w: &Wall, d: i64, tz: &TimeZone) -> Option<i64> {
    let at = instant(w, tz)?.checked_add(jiff::SignedDuration::from_millis(d)).ok()?;
    Some(ms_of(at.to_zoned(tz.clone()).datetime()))
}

/// An event's span in local wall time: (start, end, all day). A moment ends at its start, a
/// day event runs whole days, a duration is elapsed time (over a clock change the wall end moves).
pub fn span(start: &Start, end: Option<&End>) -> (i64, i64, bool) {
    span_in(start, end, &system())
}

/// `span` for a viewer in zone `tz`.
pub fn span_in(start: &Start, end: Option<&End>, tz: &TimeZone) -> (i64, i64, bool) {
    match start {
        Start::At(w) => {
            let s = to_local_in(w, tz);
            let e = match end {
                Some(End::At(e)) => to_local_in(e, tz),
                Some(End::After(d)) => after_in(w, *d, tz).unwrap_or_else(|| s.saturating_add(*d)),
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

/// An event's start and end moved by `by` ms of wall time (the end along in its own form) and, for
/// a nonzero `longer`, with its length set to the current one plus `longer` as an elapsed duration
/// (not below 15 min; a day event moves and grows by whole days); a floating time is in `tz`.
pub fn nudged_in(start: &Start, end: Option<&End>, by: i64, longer: i64, tz: &TimeZone) -> (Start, Option<End>) {
    let (s, e, _) = span_in(start, end, tz);
    match start {
        Start::At(w) => {
            let ns = Start::At(Wall { time: w.time.saturating_add(by), zone: w.zone.clone() });
            let ne = if longer == 0 {
                // a move keeps the end's form: a moment stays one, an end time moves along
                match end {
                    Some(End::At(x)) => Some(End::At(Wall { time: x.time.saturating_add(by), zone: x.zone.clone() })),
                    other => other.cloned(),
                }
            } else {
                // elapsed, not wall, length: over a clock change they differ
                let len = match end {
                    Some(End::After(d)) => *d,
                    Some(End::At(x)) => match (instant(w, tz), instant(x, tz)) {
                        (Some(a), Some(b)) => b.as_millisecond().saturating_sub(a.as_millisecond()).max(0),
                        _ => e.saturating_sub(s),
                    },
                    _ => e.saturating_sub(s),
                };
                Some(End::After(len.saturating_add(longer).max(15 * MINUTE)))
            };
            (ns, ne)
        }
        Start::Day(d) => {
            let days = by.div_euclid(DAY);
            let nd = d.saturating_add(days);
            let ne = if longer == 0 {
                match end {
                    Some(End::Day(x)) => Some(End::Day(x.saturating_add(days))),
                    other => other.cloned(),
                }
            } else {
                let span = (e.saturating_sub(s) / DAY).max(1).saturating_add(longer.div_euclid(DAY)).max(1);
                if span > 1 { Some(End::Day(nd.saturating_add(span - 1))) } else { None }
            };
            (Start::Day(nd), ne)
        }
    }
}

/// Monday 00:00 of the week holding `ms` (local wall ms).
pub fn monday_of(ms: i64) -> i64 {
    let days = ms.div_euclid(DAY);
    // 1970-01-01 was a Thursday
    (days - (days + 3).rem_euclid(7)).saturating_mul(DAY)
}

// ---- repeating events

use crate::event::{Occurrence, Repeat, RepeatFreq, Weekday};
use jiff::civil::Date;
use std::collections::BTreeSet;

/// Most periods one expansion steps through (resource bound against a malformed rule): a series
/// with a `count` is walked from its start, so one counting more than this many periods back
/// (daily for 55 years) stops showing; without a count the walk starts just before the window.
/// At 0 nothing would repeat; at infinity a huge count with a tiny interval never ends.
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
    (days.rem_euclid(7) + 3) % 7
}

/// A rule's day choices with what no period can hold dropped (a year has at most 53 of a
/// weekday and a month 31 days), so a synced rule with a huge set costs a bounded amount per period.
struct Days {
    /// Some weekday was given (for an empty choice the start's day applies).
    weekdays: bool,
    monthdays: bool,
    /// Weekly: these weekdays.
    weekly: BTreeSet<i64>,
    /// Monthly and yearly: (weekday, nth); `None` every such day.
    nth: BTreeSet<(i64, Option<i64>)>,
    month: BTreeSet<i64>,
}

impl Days {
    fn of(r: &Repeat) -> Days {
        Days {
            weekdays: !r.weekdays.is_empty(),
            monthdays: !r.monthdays.is_empty(),
            weekly: r.weekdays.iter().map(|w| weekday_index(&w.day)).collect(),
            nth: r.weekdays.iter().filter(|w| w.nth.is_none_or(|n| n != 0 && (-53..=53).contains(&n))).map(|w| (weekday_index(&w.day), w.nth)).collect(),
            month: r.monthdays.iter().copied().filter(|m| *m != 0 && (-31..=31).contains(m)).collect(),
        }
    }
}

/// The day counts of one period of the series (the period starting at `first`, a day count),
/// before `until` and `skip` apply.
fn period_days(r: &Repeat, days: &Days, first: i64, anchor: i64) -> Vec<i64> {
    let mut out = Vec::new();
    match r.freq {
        RepeatFreq::Daily => out.push(first),
        RepeatFreq::Weekly => {
            let monday = first - weekday_of(first);
            if days.weekdays {
                out.extend(days.weekly.iter().map(|w| monday.saturating_add(*w)));
            } else {
                out.push(monday.saturating_add(weekday_of(anchor)));
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
            if days.monthdays && r.freq == RepeatFreq::Monthly {
                for m in &days.month {
                    // -1 is the last day
                    let idx = if *m > 0 { m - 1 } else { len + m };
                    if (0..len).contains(&idx) {
                        out.push(start + idx);
                    }
                }
            } else if days.weekdays {
                for (want, nth) in &days.nth {
                    let first = start + (want - weekday_of(start)).rem_euclid(7);
                    let n = (start + len - first + 6) / 7;
                    match nth {
                        None => out.extend((0..n).map(|i| first + 7 * i)),
                        Some(k) if *k > 0 && *k <= n => out.push(first + 7 * (k - 1)),
                        Some(k) if *k < 0 && -k <= n => out.push(first + 7 * (n + k)),
                        Some(_) => {}
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
        RepeatFreq::Weekly => anchor.checked_sub(weekday_of(anchor))?.checked_add(step.checked_mul(7)?),
        RepeatFreq::Monthly | RepeatFreq::Yearly => {
            let a = date_of(anchor)?;
            let first = Date::new(a.year(), if r.freq == RepeatFreq::Monthly { a.month() } else { 1 }, 1).ok()?;
            let span = if r.freq == RepeatFreq::Monthly { jiff::Span::new().try_months(step).ok()? } else { jiff::Span::new().try_years(step).ok()? };
            first.checked_add(span).ok().map(days_of)
        }
    }
}

/// A period index whose period starts on or before day `day`: every earlier period lies
/// wholly before it (a period lasts at most 1, 7, 31 or 366 days).
fn periods_before(r: &Repeat, anchor: i64, day: i64) -> i64 {
    let longest = match r.freq {
        RepeatFreq::Daily => 1,
        RepeatFreq::Weekly => 7,
        RepeatFreq::Monthly => 31,
        RepeatFreq::Yearly => 366,
    };
    match day.checked_sub(anchor) {
        Some(gap) if gap > 0 => gap / r.interval.max(1).saturating_mul(longest),
        _ => 0,
    }
}

/// `start` and `end` moved by `days` whole days of nominal (unconverted) time.
fn shifted(start: &Start, end: Option<&End>, days: i64) -> Option<(Start, Option<End>)> {
    let ms = days.checked_mul(DAY)?;
    let wall = |w: &Wall| Some(Wall { time: w.time.checked_add(ms)?, zone: w.zone.clone() });
    let s = match start {
        Start::At(w) => Start::At(wall(w)?),
        Start::Day(d) => Start::Day(d.checked_add(days)?),
    };
    let e = match end {
        Some(End::At(w)) => Some(End::At(wall(w)?)),
        Some(End::Day(d)) => Some(End::Day(d.checked_add(days)?)),
        other => other.cloned(),
    };
    Some((s, e))
}

/// The occurrences of a repeating event that touch local wall ms `[from, to)`: (nominal
/// occurrence, local start, local end, all day). The series starts at the event's start, counts
/// `count` occurrences from there, stops after `until` (a date, inclusive), and leaves out `skip`
/// and the occurrences in `overridden` (replaced by other events).
pub fn occurrences(start: &Start, end: Option<&End>, r: &Repeat, from: i64, to: i64, overridden: &[Occurrence]) -> Vec<(Occurrence, i64, i64, bool)> {
    occurrences_in(start, end, r, from, to, overridden, &system())
}

/// `occurrences` for a viewer in zone `tz`.
pub fn occurrences_in(start: &Start, end: Option<&End>, r: &Repeat, from: i64, to: i64, overridden: &[Occurrence], tz: &TimeZone) -> Vec<(Occurrence, i64, i64, bool)> {
    let (s0, e0, _) = span_in(start, end, tz);
    // nominal times before this cannot touch the window: a zone moves a wall time by under a
    // day, and a clock change the length by hours
    let early = from.saturating_sub(e0.saturating_sub(s0)).saturating_sub(2 * DAY);
    let anchor = match start {
        Start::At(w) => w.time.div_euclid(DAY),
        Start::Day(d) => *d,
    };
    let tod = match start {
        Start::At(w) => w.time.rem_euclid(DAY),
        Start::Day(_) => 0,
    };
    let gone: BTreeSet<&Occurrence> = r.skip.iter().chain(overridden).collect();
    let days = Days::of(r);
    // without a count nothing needs counting from the start: begin at the window
    let k0 = if r.count.is_none() { periods_before(r, anchor, early.div_euclid(DAY)) } else { 0 };
    let mut out = Vec::new();
    let mut n = 0i64;
    'periods: for k in k0..k0.saturating_add(MAX_PERIODS) {
        let Some(first) = period_start(r, anchor, k) else { break };
        for day in period_days(r, &days, first, anchor) {
            if day < anchor {
                continue;
            }
            if r.until.is_some_and(|u| day > u) || r.count.is_some_and(|c| n >= c) {
                break 'periods;
            }
            n += 1;
            let Some(nominal) = day.checked_mul(DAY).and_then(|m| m.checked_add(tod)) else { break 'periods };
            if nominal < early {
                continue;
            }
            let occ = match start {
                Start::At(_) => Occurrence::At(nominal),
                Start::Day(_) => Occurrence::Day(day),
            };
            if gone.contains(&occ) {
                continue;
            }
            let Some((s, e)) = day.checked_sub(anchor).and_then(|d| shifted(start, end, d)) else { break 'periods };
            let (s, e, all_day) = span_in(&s, e.as_ref(), tz);
            if s >= to {
                break 'periods;
            }
            if e > from || (e == s && s >= from) {
                out.push((occ, s, e, all_day));
            }
        }
    }
    out
}
