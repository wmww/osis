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

/// Synced times and rules can hold any number: nothing here may panic or run away.
#[test]
fn extreme_values_do_not_panic() {
    use osis_app::event::{RepeatFreq, RepeatWeekdays, Weekday};
    use osis_app::time::occurrences;
    for z in ["+99999999:00", "-2147483647:2147483647", "+:", "-", "+5", "+-5:00"] {
        let _ = to_local(&Wall { time: 0, zone: Some(z.into()) });
    }
    let walls = [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX - 1, i64::MAX];
    let ends = [None, Some(End::After(i64::MAX)), Some(End::After(i64::MIN)), Some(End::At(Wall { time: i64::MAX, zone: None })), Some(End::Day(i64::MIN))];
    let mon = 20_752 * DAY;
    for t in walls {
        for st in [Start::At(Wall { time: t, zone: None }), Start::At(Wall { time: t, zone: Some("Europe/Berlin".into()) }), Start::Day(t), Start::Day(t / DAY)] {
            for e in &ends {
                let _ = span(&st, e.as_ref());
                let _ = fmt_when(&st, e.as_ref());
                for freq in [RepeatFreq::Daily, RepeatFreq::Weekly, RepeatFreq::Monthly, RepeatFreq::Yearly] {
                    for interval in [i64::MIN, 0, 1, i64::MAX / 3, i64::MAX] {
                        let mut r = rep(freq.clone());
                        r.interval = interval;
                        r.count = Some(i64::MAX);
                        r.monthdays = [i64::MIN, -1, 0, 31, i64::MAX].into_iter().collect();
                        r.weekdays = [i64::MIN, -1, 0, 1, i64::MAX].into_iter().map(|n| RepeatWeekdays { day: Weekday::Mon, nth: Some(n) }).collect();
                        let _ = occurrences(&st, e.as_ref(), &r, mon, mon + 7 * DAY, &[]);
                        let _ = occurrences(&st, e.as_ref(), &r, i64::MIN, i64::MAX, &[]);
                    }
                }
            }
        }
    }
}

/// A daily series running for decades still shows today.
#[test]
fn old_daily_series_still_shows() {
    use osis_app::event::RepeatFreq;
    use osis_app::time::occurrences;
    let mon = 20_752 * DAY;
    let start = Start::At(Wall { time: 9 * HOUR - 60 * 365 * DAY, zone: None });
    let o = occurrences(&start, Some(&End::After(HOUR)), &rep(RepeatFreq::Daily), mon, mon + 7 * DAY, &[]);
    assert_eq!(o.len(), 7);
}

/// A timed duration is elapsed time: three hours from 01:00 on the spring-forward night end at
/// 05:00 by the clock; a zoned series keeps its wall time across the change, seen from another zone.
#[test]
fn durations_and_series_over_a_dst_change() {
    use osis_app::event::RepeatFreq;
    use osis_app::time::{occurrences_in, span_in};
    let berlin = jiff::tz::TimeZone::get("Europe/Berlin").unwrap();
    let utc = jiff::tz::TimeZone::UTC;
    // 2026-03-29, clocks go 02:00 -> 03:00 in Berlin
    let day = 20_541;
    let floating = Wall { time: day * DAY + HOUR, zone: None };
    assert_eq!(span_in(&Start::At(floating), Some(&End::After(3 * HOUR)), &berlin), (day * DAY + HOUR, day * DAY + 5 * HOUR, false));
    // 23:00 + 4 h on the autumn night (2026-10-25, 03:00 -> 02:00) is 02:00
    let oct = 20_751;
    let late = Wall { time: (oct - 1) * DAY + 23 * HOUR, zone: Some("Europe/Berlin".into()) };
    assert_eq!(span_in(&Start::At(late), Some(&End::After(4 * HOUR)), &berlin).1, oct * DAY + 2 * HOUR);
    // daily 09:00 Berlin, seen in UTC: 08:00 before, 07:00 after
    let start = Start::At(Wall { time: (day - 2) * DAY + 9 * HOUR, zone: Some("Europe/Berlin".into()) });
    let o = occurrences_in(&start, Some(&End::After(HOUR)), &rep(RepeatFreq::Daily), (day - 1) * DAY, (day + 2) * DAY, &[], &utc);
    let hours: Vec<i64> = o.iter().map(|x| x.1.rem_euclid(DAY) / HOUR).collect();
    assert_eq!(hours, vec![8, 7, 7], "28 Mar CET, 29 and 30 Mar CEST");
    assert!(o.iter().all(|x| x.2 - x.1 == HOUR));
}

/// Moving an event keeps its end's form: a moment stays a moment, an end wall time moves with it.
#[test]
fn nudge_keeps_the_end_form() {
    use osis_app::event::END;
    let d = Data::new(Osis::create(Config::memory()).unwrap().0);
    let e = d.create(NewKind::Event).unwrap();
    let t = 20_752 * DAY + 9 * HOUR;
    d.db.write_with(|w| {
        w.at(e, START).set(&Start::At(Wall { time: t, zone: None }))?;
        w.at(e, END).remove()
    })
    .unwrap();
    d.nudge(e, HOUR, 0).unwrap();
    assert_eq!(d.get(e, END).unwrap(), None, "a moment moved is still a moment");
    let end = End::At(Wall { time: t + 2 * HOUR, zone: Some("+02:00".into()) });
    d.db.write_with(|w| w.at(e, END).set(&end)).unwrap();
    d.nudge(e, DAY, 0).unwrap();
    assert_eq!(d.get(e, END).unwrap(), Some(End::At(Wall { time: t + 2 * HOUR + DAY, zone: Some("+02:00".into()) })));
    // a day event far out: no overflow
    d.db.write_with(|w| {
        w.at(e, START).set(&Start::Day(i64::MAX))?;
        w.at(e, END).remove()
    })
    .unwrap();
    d.nudge(e, DAY, DAY).unwrap();
    d.nudge(e, -DAY, 0).unwrap();
    d.db.write_with(|w| w.at(e, START).set(&Start::At(Wall { time: i64::MIN, zone: None }))).unwrap();
    d.db.write_with(|w| w.at(e, END).set(&End::After(i64::MAX))).unwrap();
    d.nudge(e, -DAY, HOUR).unwrap();
    d.week(monday_of(0)).unwrap();
}
