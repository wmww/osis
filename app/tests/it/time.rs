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
    let on: Vec<usize> = week.iter().enumerate().filter(|(_, (_, ev))| ev.iter().any(|x| x.tid == e)).map(|(i, _)| i).collect();
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

fn rep(freq: osis_app::event::RepeatFreq) -> osis_app::event::Repeat {
    osis_app::event::Repeat { freq, interval: 1, weekdays: Default::default(), monthdays: Default::default(), until: None, count: None, skip: Default::default() }
}

/// Expansion of repeating series over a window.
#[test]
fn repeats() {
    use osis_app::event::{Occurrence, RepeatFreq, RepeatWeekdays, Weekday};
    use osis_app::time::occurrences;
    let mon = 20_752 * DAY; // Monday 2026-10-26
    let start = Start::At(Wall { time: mon + 9 * HOUR, zone: None });
    let end = End::After(HOUR);
    let days = |v: &[(Occurrence, i64, i64, bool)]| v.iter().map(|o| (o.1 - mon).div_euclid(DAY)).collect::<Vec<_>>();
    // daily, this week
    let o = occurrences(&start, Some(&end), &rep(RepeatFreq::Daily), mon, mon + 7 * DAY, &[]);
    assert_eq!(days(&o), vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(o[0].2 - o[0].1, HOUR);
    // every other day, three times
    let mut r = rep(RepeatFreq::Daily);
    r.interval = 2;
    r.count = Some(3);
    assert_eq!(days(&occurrences(&start, Some(&end), &r, mon, mon + 14 * DAY, &[])), vec![0, 2, 4]);
    // weekly on Tue and Thu, next week, skipping Thu
    let mut r = rep(RepeatFreq::Weekly);
    r.weekdays = [Weekday::Tue, Weekday::Thu].into_iter().map(|day| RepeatWeekdays { day, nth: None }).collect();
    r.skip.insert(Occurrence::At(mon + 10 * DAY + 9 * HOUR));
    assert_eq!(days(&occurrences(&start, Some(&end), &r, mon + 7 * DAY, mon + 14 * DAY, &[])), vec![8]);
    // an override replaces Tuesday
    assert!(occurrences(&start, Some(&end), &r, mon + 7 * DAY, mon + 14 * DAY, &[Occurrence::At(mon + 8 * DAY + 9 * HOUR)]).is_empty());
    // until (inclusive)
    let mut r = rep(RepeatFreq::Daily);
    r.until = Some(20_752 + 2);
    assert_eq!(days(&occurrences(&start, Some(&end), &r, mon, mon + 7 * DAY, &[])), vec![0, 1, 2]);
    // monthly on the 31st skips short months; on the last Friday
    let jan31 = Start::Day(20_484); // 2026-01-31
    let m = rep(RepeatFreq::Monthly);
    let o = occurrences(&jan31, None, &m, 20_484 * DAY, 20_484 * DAY + 120 * DAY, &[]);
    assert_eq!(o.len(), 2, "Jan 31 and Mar 31 (no Feb 31, Apr 30 days): {o:?}");
    let mut last_fri = rep(RepeatFreq::Monthly);
    last_fri.weekdays.insert(RepeatWeekdays { day: Weekday::Fri, nth: Some(-1) });
    let o = occurrences(&Start::Day(20_752), None, &last_fri, mon, mon + 7 * DAY, &[]);
    assert_eq!(days(&o), vec![4], "Fri 30 Oct is October's last Friday");
    // yearly
    let o = occurrences(&Start::Day(20_484), None, &rep(RepeatFreq::Yearly), 20_484 * DAY, 20_484 * DAY + 800 * DAY, &[]);
    assert_eq!(o.len(), 3);
    // a series starting before the window shows only in it
    let o = occurrences(&start, Some(&end), &rep(RepeatFreq::Weekly), mon + 70 * DAY, mon + 77 * DAY, &[]);
    assert_eq!(days(&o), vec![70]);
}
