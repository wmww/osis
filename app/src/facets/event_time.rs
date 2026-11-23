//! `event:start.0` and its family: when a thing happens, and how it repeats.

use osis_kit::store::Reader;
use crate::event::{END, End, LOCATION, OVERRIDES, Occurrence, REPEAT, Repeat, RepeatFreq, START, Start, Wall};
use osis_kit::store::Data;
use crate::time::{DAY, HOUR, MINUTE, fmt_when};
use osis_kit::view::{Act, Action, Block, Chip, Cx, Do, Entry, Facet, Icon, Input, Mark, Offer, Section, Span, Summary};
use osis::{Result, Tid};
use std::collections::BTreeMap;
use std::rc::Rc;

pub struct EventTimeFacet;
pub static FACET: EventTimeFacet = EventTimeFacet;

/// Starts at the next full hour, for an hour.
fn start(data: &Data, w: &mut osis::Write<'_>, t: Tid) -> Result<()> {
    const ONE: i64 = HOUR;
    let at = (data.now_local()? / ONE + 1) * ONE;
    w.at(t, START).set(&Start::At(Wall { time: at, zone: None }))?;
    w.at(t, END).set(&End::After(ONE))
}

/// Moves and lengthens an event as `time::nudged_in` in the system zone. A concurrent change to
/// another part survives.
pub fn nudge(d: &Data, t: Tid, by: i64, longer: i64) -> Result<()> {
    let Some(start) = d.db.at(t, START).get()? else { return Ok(()) };
    let end = d.db.at(t, END).get()?;
    let (new_start, new_end) = crate::time::nudged_in(&start, end.as_ref(), by, longer, &crate::time::system());
    d.commit(|w| {
        w.at(t, START).set(&new_start)?;
        match (&end, &new_end) {
            (_, Some(ne)) => w.at(t, END).set(ne),
            (Some(_), None) => w.at(t, END).remove(),
            (None, None) => Ok(()),
        }
    })
}

/// Makes an event repeat every period of `freq` from its start (`None`: not at all).
pub fn set_repeat(d: &Data, t: Tid, freq: Option<RepeatFreq>) -> Result<()> {
    d.commit(|w| match freq {
        Some(freq) => w.at(t, REPEAT).set(&Repeat { freq, interval: 1, weekdays: Default::default(), monthdays: Default::default(), until: None, count: None, skip: Default::default() }),
        None => w.at(t, REPEAT).remove(),
    })
}

/// Occurrences each series replaced, over everything held: one memo over one per-item memo each.
pub fn overridden(d: &Reader) -> Result<Rc<BTreeMap<Tid, Vec<Occurrence>>>> {
    d.memo(("overridden", ()), |r, _| {
        let mut out: BTreeMap<Tid, Vec<Occurrence>> = BTreeMap::new();
        for t in r.things()?.iter().copied() {
            if let Some(o) = &*r.memo(("overrides", t), |r, &(_, t)| r.db.at(t, OVERRIDES).get())? {
                out.entry(o.series.0).or_default().push(o.at.clone());
            }
        }
        Ok(out)
    })
}

/// `t`'s spans touching local wall ms `[from, to)`.
fn spans_of(d: &Reader, t: Tid, from: i64, to: i64, over: &BTreeMap<Tid, Vec<Occurrence>>) -> Result<Vec<Span>> {
    let Some(start) = d.db.at(t, START).get()? else { return Ok(Vec::new()) };
    let end = d.db.at(t, END).get()?;
    let mut out = Vec::new();
    match d.db.at(t, REPEAT).get()? {
        Some(r) => {
            let skip = over.get(&t).map(Vec::as_slice).unwrap_or_default();
            for (_, s, e, all_day) in crate::time::occurrences(&start, end.as_ref(), &r, from, to, skip) {
                out.push(Span { start: s, end: e, all_day, repeats: true });
            }
        }
        None => {
            let (s, e, all_day) = crate::time::span(&start, end.as_ref());
            if s < to && (e > from || (e == s && s >= from)) {
                out.push(Span { start: s, end: e, all_day, repeats: false });
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq)]
struct Nudge(Tid, i64, i64);

impl Action for Nudge {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        nudge(act.data, self.0, self.1, self.2)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SetRepeat(Tid, Option<RepeatFreq>);

impl Action for SetRepeat {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        set_repeat(act.data, self.0, self.1.clone())
    }
}

impl Facet for EventTimeFacet {
    fn id(&self) -> &'static str {
        "event-time"
    }
    fn claims(&self, ak: &str) -> bool {
        ak.starts_with("event:") && ak != "event:location.0"
    }
    fn summarize(&self, cx: &Reader, t: Tid, s: &mut Summary) -> Result<()> {
        s.words.insert(0, "Event".into());
        s.mark = Mark::Icon(Icon::Event);
        let Some(st) = cx.db.at(t, START).get()? else {
            if s.sub.is_empty() {
                s.sub = "Not scheduled".into();
            }
            return Ok(());
        };
        let end = cx.db.at(t, END).get()?;
        s.time = Some(crate::time::span(&st, end.as_ref()).0);
        if s.sub.is_empty() {
            s.sub = fmt_when(&st, end.as_ref());
        }
        Ok(())
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let Some(s) = cx.db.at(t, START).get()? else { return Ok(Section::default()) };
        let d = |by, longer| Do::new(Nudge(t, by, longer));
        let mut blocks = vec![Block::Line(fmt_when(&s, cx.db.at(t, END).get()?.as_ref()))];
        let mut chips = vec![Chip::action(Icon::Back, "Day earlier", d(-DAY, 0)), Chip::action(Icon::Plus, "Day later", d(DAY, 0))];
        if matches!(s, Start::At(_)) {
            chips.extend([Chip::action(Icon::Clock, "−1 h", d(-HOUR, 0)), Chip::action(Icon::Clock, "+1 h", d(HOUR, 0)), Chip::action(Icon::Clock, "Shorter", d(0, -30 * MINUTE)), Chip::action(Icon::Clock, "Longer", d(0, 30 * MINUTE))]);
        }
        blocks.push(Block::Chips(chips));
        use RepeatFreq as F;
        let cur = cx.db.at(t, REPEAT).get()?;
        let custom = cur.as_ref().is_some_and(|r| r.interval != 1 || !r.weekdays.is_empty() || !r.monthdays.is_empty() || r.until.is_some() || r.count.is_some());
        let mut rep = Vec::new();
        for (label, f) in [("Once", None), ("Daily", Some(F::Daily)), ("Weekly", Some(F::Weekly)), ("Monthly", Some(F::Monthly)), ("Yearly", Some(F::Yearly))] {
            let on = cur.as_ref().map(|r| r.freq.clone()) == f && !custom;
            rep.push(Chip::choice(Icon::Recent, label, on, Do::new(SetRepeat(t, f))));
        }
        if custom {
            rep.push(Chip::info(Icon::List, "Custom"));
        }
        blocks.push(Block::Chips(rep));
        Ok(Section::of(blocks))
    }
    fn entries(&self, cx: &Reader, t: Tid, from: i64, to: i64, out: &mut Vec<Entry>) -> Result<()> {
        let over = overridden(cx)?;
        let s = cx.summary(t)?;
        let place = cx.db.at(t, LOCATION).get()?.filter(|p| !p.is_empty()).unwrap_or_default();
        for span in spans_of(cx, t, from, to, &over)? {
            let mut e = Entry::of(t, &s);
            e.key = format!("{t}/{}", span.start);
            e.text = place.clone();
            e.span = Some(span);
            out.push(e);
        }
        Ok(())
    }
    fn offers(&self, cx: &Reader, t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(match t {
            Some(t) if cx.has(t, "event:start.0")? => Vec::new(),
            Some(_) => vec![Offer { id: "time", label: "Time", icon: Icon::Clock, set: start }],
            None => vec![Offer { id: "event", label: "Event", icon: Icon::Event, set: start }],
        })
    }
}
