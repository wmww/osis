//! Local wall time for calendar views, and the week and nudge actions.
use osis::{Config, Osis};
use osis_app::data::{Data, NewKind, fmt_when};
use osis_app::event::{End, START, Start, Wall};
use osis_app::time::{DAY, HOUR, MINUTE, monday_of, span, to_local};

#[test]
fn monday_and_spans() {
    // 2026-10-29 was a Thursday
    let thu = 20_755 * DAY + 13 * HOUR;
    assert_eq!(monday_of(thu), 20_752 * DAY);
    assert_eq!(monday_of(20_752 * DAY), 20_752 * DAY, "Monday 00:00 is its own week");
    let at = |t| Start::At(Wall { time: t, zone: None });
    assert_eq!(span(&at(thu), Some(&End::After(HOUR))), (thu, thu + HOUR, false));
    assert_eq!(span(&at(thu), None), (thu, thu, false), "a moment");
    assert_eq!(span(&Start::Day(5), Some(&End::Day(6))), (5 * DAY, 7 * DAY, true), "the last day is inclusive");
    assert_eq!(span(&Start::Day(5), Some(&End::Day(3))), (5 * DAY, 6 * DAY, true), "an end before the start is one day");
    assert!(fmt_when(&at(thu), Some(&End::After(30 * MINUTE))).ends_with("13:00–13:30"));
}

/// A fixed offset converts to the local zone; a floating time stays as written.
#[test]
fn zones() {
    let t = 20_755 * DAY + 12 * HOUR;
    assert_eq!(to_local(&Wall { time: t, zone: None }), t);
    let utc = to_local(&Wall { time: t, zone: Some("+00:00".into()) });
    let plus2 = to_local(&Wall { time: t, zone: Some("+02:00".into()) });
    assert_eq!(utc - plus2, 2 * HOUR, "12:00 at +02:00 is two hours before 12:00 UTC, in any local zone");
    assert_eq!(to_local(&Wall { time: t, zone: Some("Nowhere/Nope".into()) }), t, "an unknown zone reads as floating");
    let named = to_local(&Wall { time: t, zone: Some("UTC".into()) });
    assert_eq!(named, utc);
}

#[test]
fn week_and_nudge() {
    let d = Data::new(Osis::create(Config::memory()).unwrap().0);
    let e = d.create(NewKind::Event).unwrap();
    let (s, end, _) = d.span(e).unwrap().unwrap();
    assert_eq!(end - s, HOUR);
    let monday = monday_of(s);
    let week = d.week(monday).unwrap();
    assert_eq!(week.len(), 7);
    let on: Vec<usize> = week.iter().enumerate().filter(|(_, (_, ev))| ev.contains(&e)).map(|(i, _)| i).collect();
    assert_eq!(on, vec![((s - monday) / DAY) as usize]);
    d.nudge(e, DAY, 30 * MINUTE).unwrap();
    assert_eq!(d.span(e).unwrap().unwrap(), (s + DAY, s + DAY + 90 * MINUTE, false));
    d.nudge(e, 0, -10 * HOUR).unwrap();
    let (s2, e2, _) = d.span(e).unwrap().unwrap();
    assert_eq!(e2 - s2, 15 * MINUTE, "never shorter than 15 min");
    d.db.write_with(|w| w.at(e, START).set(&Start::Day(100))).unwrap();
    d.nudge(e, -HOUR, 0).unwrap();
    assert_eq!(d.get(e, START).unwrap(), Some(Start::Day(99)), "a day event moves by whole days");
}
