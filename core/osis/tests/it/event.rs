//! Calendar events (notes/std.md): wall-clock times with a zone, civil days, a duration end, a
//! weekly series with a skipped and an overridden occurrence; a calendar is a tag shared like
//! any other. Tier 1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::scenario as common;
use common::*;
use crate::common::CreateIn;
use osis::core::{BODY, NAME};
use osis::{EdgeOpts, Error, Osis, Result, Role, Tid};
use osis_sim::world::World;
use crate::schemas::event::*;
use std::collections::BTreeSet;

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

fn new_event(db: &Osis, calendar: Tid, name: &str, start: Start, end: Option<End>) -> Result<Tid> {
    db.write_with(|w| {
        let e = w.create_in(calendar, &[calendar])?;
        w.at(e, NAME).set(&name.to_string())?;
        w.at(e, START).set(&start)?;
        if let Some(end) = &end {
            w.at(e, END).set(end)?;
        }
        Ok(e)
    })
}

// spec/data-model.md §3 (`date` = days since 1970-01-01, proleptic Gregorian, no zone).
#[test]
fn civil_dates_are_days_since_the_epoch() {
    assert_eq!(date(1970, 1, 1), 0);
    assert_eq!(date(1969, 12, 31), -1);
    assert_eq!(date(2000, 3, 1), 11_017);
    assert_eq!(local(1970, 1, 2, 1, 30), DAY + 90 * MIN);
}

// notes/std.md (events; time kinds), spec/data-model.md §3 (`date`, `localtime`): a timed event
// in a zone with a duration end, an all-day span, a weekly series with one occurrence skipped and
// one overridden, all in a calendar tag shared read-only; the reader sees them typed and cannot
// edit.
#[test]
fn calendar_shared_read_only() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let b = introduce(&mut w, &alice, &bob);
    let work = new_tag(&alice, "Work").unwrap();
    let berlin = || Some("Europe/Berlin".to_string());
    let standup = new_event(&alice, work, "Standup", Start::At(Wall { time: local(2027, 3, 15, 9, 0), zone: berlin() }), Some(End::After(30 * MIN))).unwrap();
    alice
        .write_with(|wr| {
            wr.at(standup, REPEAT).set(&Repeat {
                freq: RepeatFreq::Weekly,
                interval: 1,
                weekdays: BTreeSet::from([RepeatWeekdays { day: Weekday::Mon, nth: None }]),
                monthdays: BTreeSet::new(),
                until: Some(date(2027, 12, 31)),
                count: None,
                skip: BTreeSet::from([Occurrence::At(local(2027, 4, 5, 9, 0))]),
            })?;
            wr.at(standup, ALERTS).set(&BTreeSet::from([10 * MIN]))?;
            wr.at(standup, BODY).set(&"Daily sync, keep it short.".to_string())
        })
        .unwrap();
    // one occurrence moved to the afternoon
    let moved = new_event(&alice, work, "Standup (moved)", Start::At(Wall { time: local(2027, 3, 22, 14, 0), zone: berlin() }), None).unwrap();
    alice.write_with(|wr| wr.at(moved, OVERRIDES).set(&Overrides { series: standup, at: Occurrence::At(local(2027, 3, 22, 9, 0)) })).unwrap();
    // an all-day span, and a flight ending in another zone
    let offsite = new_event(&alice, work, "Offsite", Start::Day(date(2027, 5, 3)), Some(End::Day(date(2027, 5, 5)))).unwrap();
    let flight = new_event(
        &alice,
        work,
        "Flight",
        Start::At(Wall { time: local(2027, 5, 2, 8, 0), zone: berlin() }),
        Some(End::At(Wall { time: local(2027, 5, 2, 9, 10), zone: Some("Europe/London".into()) })),
    )
    .unwrap();
    alice.grant(work, b, Role::Read, EdgeOpts::default()).unwrap();
    w.run();

    assert_eq!(bob.get(standup, START).unwrap(), Some(Start::At(Wall { time: local(2027, 3, 15, 9, 0), zone: berlin() })));
    assert_eq!(bob.get(standup, END).unwrap(), Some(End::After(30 * MIN)));
    let r = bob.get(standup, REPEAT).unwrap().unwrap();
    assert_eq!((r.freq, r.interval, r.skip.len()), (RepeatFreq::Weekly, 1, 1));
    assert_eq!(bob.get(moved, OVERRIDES).unwrap().unwrap().series, standup);
    assert_eq!(bob.get(offsite, END).unwrap(), Some(End::Day(date(2027, 5, 5))));
    match bob.get(flight, END).unwrap() {
        Some(End::At(Wall { zone, .. })) => assert_eq!(zone.as_deref(), Some("Europe/London")),
        other => panic!("{other:?}"),
    }
    assert_eq!(tag_names(&bob, standup).unwrap(), ["Work"]);
    assert!(matches!(bob.write_with(|wr| wr.at(standup, LOCATION).set(&"Room 1".to_string())), Err(Error::Permission { .. })));
}
