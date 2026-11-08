//! Arrangements: how a set of entries is placed, independent of where they came from.

use super::{Cx, Day, Entry, OutlineRun, Placed, Run, Span, Window};
use crate::schema::{Arrange, Collection};
use crate::time::{DAY, fmt_day, fmt_time, monday_of, now_local};
use osis::{Result, Tid};
use std::collections::BTreeSet;

/// Newest per source a stream or a thing's own stream shows (Minor: older ones are not reachable
/// from the window yet; 0 would show nothing, infinity re-read every history at every change).
pub const NEWEST: usize = 200;

/// Nodes in one outline at most (Resource bound: deep sharing of tags is exponential; past it the
/// outline stops and says so; 0 would show none, infinity lets a hostile tag graph hang the UI).
pub const OUTLINE_NODES: usize = 5_000;

/// One entry per thing, from its summary; what cannot be summarized is left out.
pub fn one_each(cx: &Cx<'_>, things: &[Tid]) -> Vec<Entry> {
    things.iter().filter_map(|t| Some(Entry::of(*t, &cx.summary(*t).ok()?))).collect()
}

/// `things` expanded through their facets' entries; a thing nothing expands is one entry, at its
/// change time.
pub fn expand(cx: &Cx<'_>, things: &[Tid], win: &Window) -> Vec<Entry> {
    let mut out = Vec::new();
    for t in things {
        let n = out.len();
        for f in cx.data.registry.facets.iter() {
            if f.applies(cx, *t).unwrap_or(false) {
                // what a facet cannot read it leaves out
                let _ = f.entries(cx, *t, win, &mut out);
            }
        }
        if out.len() == n && let Ok(s) = cx.summary(*t) {
            let mut e = Entry::of(*t, &s);
            e.time = cx.data.changed(*t).ok().flatten();
            out.push(e);
        }
    }
    out
}

/// A stream's entries: oldest first, undated ones first.
pub fn stream(mut v: Vec<Entry>) -> Placed {
    v.sort_by(|a, b| (a.time, &a.key).cmp(&(b.time, &b.key)));
    Placed::Stream(v)
}

/// The seven days from `monday` (local wall ms), admitting only entries with a span.
pub fn days(entries: Vec<Entry>, monday: i64) -> Placed {
    let today = now_local().div_euclid(DAY);
    let mut out = Vec::new();
    for i in 0..7 {
        let day = monday + i * DAY;
        let mut on: Vec<(i64, String, Entry)> = entries
            .iter()
            .filter_map(|e| {
                let s = e.span?;
                if !(s.start < day + DAY && (s.end > day || s.start >= day)) {
                    return None;
                }
                let mut e = e.clone();
                let mut time = when_on(&s, day);
                if s.repeats {
                    time.push_str(" ↻");
                }
                e.text = if e.text.is_empty() { time } else { format!("{time} · {}", e.text) };
                Some((s.start, e.key.clone(), e))
            })
            .collect();
        on.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        out.push(Day { label: fmt_day(day / DAY), today: today == day / DAY, entries: on.into_iter().map(|x| x.2).collect() });
    }
    Placed::Days(out)
}

fn when_on(s: &Span, day: i64) -> String {
    // a timed span from an earlier day: until its end, or all day when it goes on
    if s.all_day || (s.start < day && s.end >= day + DAY) {
        "All day".into()
    } else if s.start < day {
        format!("Until {}", fmt_time(s.end))
    } else {
        fmt_time(s.start)
    }
}

/// `items` nested by subgroup; every source's narrowing applies below the top too; a cycle is cut
/// at a repeat, a thing under two parents appears under both.
pub fn outline(cx: &Cx<'_>, items: &[Tid], view: &Collection) -> Result<Placed> {
    let set: BTreeSet<Tid> = items.iter().copied().collect();
    let children = |t: Tid| -> Result<Vec<Tid>> {
        let (subs, its) = cx.data.tag_contents(t)?;
        let mut v = Vec::new();
        for x in subs.into_iter().chain(its) {
            if super::source::having(cx, x, view)? {
                v.push(x);
            }
        }
        Ok(v)
    };
    let mut inner = BTreeSet::new();
    for t in items {
        inner.extend(children(*t)?.into_iter().filter(|x| set.contains(x)));
    }
    let mut top: Vec<Tid> = items.iter().copied().filter(|t| !inner.contains(t)).collect();
    // what a cycle hides from every top: its first stands for it
    let mut reached = BTreeSet::new();
    let mut todo = top.clone();
    for t in items {
        if todo.is_empty() && !reached.contains(t) {
            top.push(*t);
            todo.push(*t);
        }
        while let Some(x) = todo.pop() {
            if reached.insert(x) {
                todo.extend(children(x)?);
            }
        }
    }
    let mut runs = vec![OutlineRun { parent: None, entries: one_each(cx, &top) }];
    let mut budget = OUTLINE_NODES;
    for t in &top {
        walk(cx, *t, &children, &mut vec![*t], &mut runs, &mut budget)?;
    }
    if budget == 0 {
        runs.push(OutlineRun { parent: Some("More not shown".into()), entries: Vec::new() });
    }
    Ok(Placed::Outline(runs))
}

fn walk(cx: &Cx<'_>, t: Tid, children: &impl Fn(Tid) -> Result<Vec<Tid>>, path: &mut Vec<Tid>, runs: &mut Vec<OutlineRun>, budget: &mut usize) -> Result<()> {
    let kids: Vec<Tid> = children(t)?.into_iter().filter(|x| !path.contains(x)).collect();
    if kids.is_empty() {
        return Ok(());
    }
    let take = kids.len().min(*budget);
    *budget -= take;
    let name = cx.summary(t).map(|s| s.name).unwrap_or_default();
    let kids = kids.get(..take).unwrap_or_default().to_vec();
    runs.push(OutlineRun { parent: Some(format!("In {name}")), entries: one_each(cx, &kids) });
    for k in kids {
        if *budget == 0 {
            break;
        }
        path.push(k);
        walk(cx, k, children, path, runs, budget)?;
        path.pop();
    }
    Ok(())
}

/// The window `arrange` wants, `week` weeks from this one.
pub fn window(arrange: &Arrange, week: i64) -> Option<Window> {
    match arrange {
        Arrange::Days => {
            let from = monday_of(now_local()) + week * 7 * DAY;
            Some(Window::Span { from, to: from + 7 * DAY })
        }
        Arrange::Stream => Some(Window::Newest(NEWEST)),
        _ => None,
    }
}

/// `items` placed as `arrange`. `run` decorates a cards or rows run.
pub fn place(cx: &Cx<'_>, items: &[Tid], view: &Collection, arrange: &Arrange, week: i64, run: Run) -> Result<Placed> {
    let win = window(arrange, week);
    Ok(match (arrange, win) {
        (Arrange::Cards, _) => Placed::Cards(Run { entries: one_each(cx, items), ..run }),
        (Arrange::Rows, _) => Placed::Rows(Run { entries: one_each(cx, items), ..run }),
        (Arrange::Outline, _) => outline(cx, items, view)?,
        (Arrange::Days, Some(w @ Window::Span { from, .. })) => days(expand(cx, items, &w), from),
        (Arrange::Stream, Some(w)) => stream(expand(cx, items, &w)),
        _ => Placed::Rows(Run { entries: one_each(cx, items), ..run }),
    })
}
