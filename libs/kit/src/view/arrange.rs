//! Arrangements: how a set of entries is placed, independent of where they came from. All but Days
//! are `Cx::list`, so what a page holds is at most its window.

use crate::store::Reader;
use super::paged::{At, Item, ListRow, Page, Row, Shape, Style, page_of};
use super::{Block, Cx, Day, Do, Entry, Span, source};
use crate::schema::{Arrange, Collection};
use crate::time::{DAY, fmt_day, fmt_time, monday_of};
use osis::{Result, Tid};
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

/// Nodes in one outline at most (Resource bound: deep sharing of tags is exponential; past it the
/// outline stops and says so; 0 would show none, infinity lets a hostile tag graph hang the UI).
pub const OUTLINE_NODES: usize = 5_000;
/// Entries one day shows (Minor: past it the day says how many more; 0 shows none, infinity makes
/// a day a whole event list).
pub const DAY_ROWS: usize = 24;
/// A thing's newest stream rows, kept per thing (a performance switch: a merge of many things
/// costs a lookup each while its heads cover the window, then a read; 0 would read each thing on
/// every page, infinity would hold every history).
pub const STREAM_HEAD: usize = 64;

/// One entry from a thing's summary.
pub fn one(cx: &Reader, t: Tid) -> Option<Entry> {
    Some(Entry::of(t, &cx.summary(t).ok()?))
}

/// The seven days from `monday` (local wall ms), admitting only entries with a span.
pub fn days(entries: Vec<Entry>, monday: i64, now: i64, see_all: &Do) -> Block {
    let today = now.div_euclid(DAY);
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
        let more = on.len().saturating_sub(DAY_ROWS);
        on.truncate(DAY_ROWS);
        out.push(Day { label: fmt_day(day / DAY), today: today == day / DAY, entries: on.into_iter().map(|x| x.2).collect(), more, see_all: see_all.clone() });
    }
    Block::Days(out)
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

/// One row of a flattened outline.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OutlineRow {
    key: String,
    /// `None`: a label naming what follows; the thing otherwise.
    thing: Option<Tid>,
    label: String,
}

impl Row for OutlineRow {
    fn key(&self) -> String {
        self.key.clone()
    }
}

/// The outline of `items` as rows: the top level, then each subtree under a label. Every source's
/// narrowing applies below the top too; a cycle is cut at a repeat; a thing under two parents
/// appears under both. Built once per `t`, from per-item memos.
fn outline_rows(cx: &Reader, &(_, t): &(&'static str, Tid)) -> Result<(Vec<OutlineRow>, HashMap<String, usize>)> {
    let view = source::of(cx, t)?;
    let items = source::items(cx, t)?;
    let set: BTreeSet<Tid> = items.iter().copied().collect();
    let children = |t: Tid| -> Result<Vec<Tid>> {
        let (subs, its) = cx.tag_contents(t)?;
        let mut v = Vec::new();
        for x in subs.into_iter().chain(its) {
            if source::having(cx, x, &view)? {
                v.push(x);
            }
        }
        Ok(v)
    };
    let mut inner = BTreeSet::new();
    for t in items.iter() {
        inner.extend(children(*t)?.into_iter().filter(|x| set.contains(x)));
    }
    let mut top: Vec<Tid> = items.iter().copied().filter(|t| !inner.contains(t)).collect();
    // what a cycle hides from every top: its first stands for it
    let mut reached = BTreeSet::new();
    let mut todo = top.clone();
    for t in items.iter() {
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
    let mut rows = Vec::new();
    for t in &top {
        rows.push(OutlineRow { key: t.to_string(), thing: Some(*t), label: String::new() });
    }
    let mut budget = OUTLINE_NODES;
    for t in &top {
        walk(cx, *t, &children, &mut vec![*t], &mut rows, &mut budget)?;
    }
    if budget == 0 {
        rows.push(OutlineRow { key: "more".into(), thing: None, label: "More not shown".into() });
    }
    let index = rows.iter().enumerate().map(|(i, x)| (x.key.clone(), i)).collect();
    Ok((rows, index))
}

fn walk(cx: &Reader, t: Tid, children: &impl Fn(Tid) -> Result<Vec<Tid>>, path: &mut Vec<Tid>, rows: &mut Vec<OutlineRow>, budget: &mut usize) -> Result<()> {
    let kids: Vec<Tid> = children(t)?.into_iter().filter(|x| !path.contains(x)).collect();
    if kids.is_empty() {
        return Ok(());
    }
    let take = kids.len().min(*budget);
    *budget -= take;
    let name = cx.summary(t).map(|s| s.name).unwrap_or_default();
    let trail: String = path.iter().map(Tid::to_string).collect::<Vec<_>>().join("/");
    rows.push(OutlineRow { key: format!("in/{trail}"), thing: None, label: format!("In {name}") });
    let kids = kids.get(..take).unwrap_or_default().to_vec();
    for k in &kids {
        rows.push(OutlineRow { key: format!("{trail}/{k}"), thing: Some(*k), label: String::new() });
    }
    for k in kids {
        if *budget == 0 {
            break;
        }
        path.push(k);
        walk(cx, k, children, path, rows, budget)?;
        path.pop();
    }
    Ok(())
}

fn outline(cx: &Cx, t: Tid, mut shape: Shape) -> Result<Block> {
    let rows = cx.memo(("outline", t), outline_rows)?;
    shape.style = Style::Row;
    shape.new = None;
    shape.reorder = None;
    cx.list(
        "outline",
        shape,
        |at, n| Ok(page_of(&rows.0, |k| rows.1.get(k).copied(), at, n)),
        |cx, r: &OutlineRow| {
            Ok(Some(match r.thing {
                None => Item::Label(r.label.clone()),
                Some(t) => Item::Entry(one(cx, t).unwrap_or_else(|| Entry::of(t, &Default::default()))),
            }))
        },
    )
}

/// A thing's rows of a stream, newest first by `sort_key`: its facets', or one entry at its change
/// time if none expands it; at most `n`, those sorting before `before` when given.
fn stream_rows(cx: &Reader, t: Tid, before: Option<&str>, n: usize) -> Vec<Entry> {
    let mut out = Vec::new();
    for f in cx.registry.facets.iter() {
        if f.applies(cx, t).unwrap_or(false) {
            // what a facet cannot read it leaves out
            let _ = f.stream(cx, t, before, n, &mut out);
        }
    }
    if out.is_empty() && let Ok(s) = cx.summary(t) {
        let mut e = Entry::of(t, &s);
        e.time = cx.changed(t).ok().flatten();
        if before.is_none_or(|b| sort_key(&e).as_str() < b) {
            out.push(e);
        }
    }
    out
}

/// A thing's newest rows, shared by whatever merges it: one new row reruns this thing's only.
fn head(cx: &Reader, t: Tid) -> Result<Rc<Vec<Entry>>> {
    cx.memo(("stream head", t), |r, &(_, t)| Ok(stream_rows(r, t, None, STREAM_HEAD)))
}

/// A stream row's place: sorts by time, then key. A facet's rows must sort so newest first
/// (`Facet::stream`).
pub fn sort_key(e: &Entry) -> String {
    format!("{:020}/{}", e.time.unwrap_or(0), e.key)
}

/// A sort key's time and entry key.
pub fn split_sort_key(k: &str) -> Option<(u64, &str)> {
    let (t, key) = k.split_once('/')?;
    Some((t.parse().ok()?, key))
}

/// Rows of `things` merged oldest first. Heads cover what is near the end; deeper a thing is read
/// past the anchor directly, one page (its rows there are in no other page's way).
pub fn stream_page(cx: &Reader, things: &[Tid], at: &At, n: usize) -> Result<Page<Entry>> {
    let mut rows: Vec<(String, Entry)> = Vec::new();
    let mut more = false;
    match at {
        At::End => {
            for t in things {
                let h = head(cx, *t)?;
                more |= h.len() >= STREAM_HEAD;
                rows.extend(h.iter().map(|e| (sort_key(e), e.clone())));
            }
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            more |= rows.len() > n;
            let cut = rows.len().saturating_sub(n);
            rows.drain(..cut);
        }
        At::Before(k, _) => {
            for t in things {
                let h = head(cx, *t)?;
                let older = h.iter().filter(|e| sort_key(e) < *k).count();
                // the head holds a page past the anchor, or all there is
                if h.len() < STREAM_HEAD || older >= n {
                    more |= older > n || h.len() >= STREAM_HEAD;
                    rows.extend(h.iter().filter(|e| sort_key(e) < *k).map(|e| (sort_key(e), e.clone())));
                } else {
                    let got = stream_rows(cx, *t, Some(k), n + 1);
                    more |= got.len() > n;
                    rows.extend(got.into_iter().map(|e| (sort_key(&e), e)));
                }
            }
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            more |= rows.len() > n;
            let cut = rows.len().saturating_sub(n);
            rows.drain(..cut);
        }
        At::From(k, _) => {
            for t in things {
                // heads cover the end; further back asks for more until the anchor is reached
                let mut m = STREAM_HEAD;
                loop {
                    let got = if m == STREAM_HEAD { (*head(cx, *t)?).clone() } else { stream_rows(cx, *t, None, m) };
                    let done = got.len() < m || got.last().is_some_and(|e| sort_key(e) <= *k);
                    if done {
                        rows.extend(got.into_iter().filter(|e| sort_key(e) >= *k).map(|e| (sort_key(&e), e)));
                        break;
                    }
                    m = m.saturating_mul(4);
                }
            }
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            more |= rows.len() > n;
            rows.truncate(n);
        }
        // a stream opens at its end and never asks for its start
        At::Start => {}
    }
    Ok(Page { rows: rows.into_iter().map(|x| x.1).collect(), more, first: None, total: None })
}

/// A stream list over `things`: rows one per entry, decorated per node by their facets. Its keys
/// sort by time (`sort_key`), so the page cursor is positional.
pub fn stream(cx: &Cx, things: Vec<Tid>, id: &str) -> Result<Block> {
    let mut shape = Shape::new(Style::Stream);
    shape.follow_end = true;
    cx.list(
        id,
        shape,
        |at, n| {
            let mut p = stream_page(cx, &things, at, n)?;
            for e in &mut p.rows {
                e.key = sort_key(e);
            }
            Ok(p)
        },
        |cx, e: &Entry| {
            let mut e = e.clone();
            for f in cx.registry.facets.iter() {
                if f.applies(cx, e.thing).unwrap_or(false) {
                    let _ = f.stream_row(cx, &mut e);
                }
            }
            Ok(Some(e))
        },
    )
}

/// The window of a thing's items, through its index.
pub fn items_page(cx: &Reader, t: Tid, at: &At, n: usize) -> Result<Page<Tid>> {
    let all = source::items(cx, t)?;
    let index = source::item_index(cx, t)?;
    Ok(page_of(&all, |k| k.parse::<Tid>().ok().and_then(|x| index.get(&x).copied()), at, n))
}

/// The monday and week arrange's window starts at, `week` weeks from this one.
pub fn week_from(cx: &Reader, week: i64) -> Result<i64> {
    Ok(monday_of(cx.now_local()?) + week * 7 * DAY)
}

/// `t`'s items placed as `arrange`: `shape` says how a list is drawn.
pub fn place(cx: &Cx, t: Tid, view: &Collection, arrange: &Arrange, week: i64, mut shape: Shape, see_all: &Do) -> Result<Block> {
    match arrange {
        Arrange::Days => {
            let from = week_from(cx, week)?;
            let to = from + 7 * DAY;
            let items = source::items(cx, t)?;
            let mut entries = Vec::new();
            for x in items.iter() {
                entries.extend((*spans(cx, *x, from, to)?).iter().cloned());
            }
            Ok(days(entries, from, cx.now_local()?, see_all))
        }
        Arrange::Stream => {
            let items = source::items(cx, t)?;
            stream(cx, (*items).clone(), "stream")
        }
        Arrange::Outline => outline(cx, t, shape),
        Arrange::Cards | Arrange::Rows => {
            shape.style = if matches!(arrange, Arrange::Cards) { Style::Card } else { Style::Row };
            if let Some(e) = &view.element {
                let (vt, cfg) = (e.view_type.clone(), super::Config(e.config.clone()));
                return cx.list(
                    "items",
                    shape,
                    |at, n| items_page(cx, t, at, n),
                    move |_, x: &Tid| Ok(Some(super::ViewSpec { view_type: vt.clone(), subject: *x, config: cfg.clone() })),
                );
            }
            cx.list("items", shape, |at, n| items_page(cx, t, at, n), |cx, x: &Tid| Ok(one(cx, *x)))
        }
    }
}

/// `t`'s entries in `[from, to)`, one memo per thing and range: a week's render asks once per
/// thing, a change reruns that thing's.
fn spans(cx: &Reader, t: Tid, from: i64, to: i64) -> Result<Rc<Vec<Entry>>> {
    cx.memo(("spans", t, from, to), |r, &(_, t, from, to)| {
        let mut out = Vec::new();
        for f in r.registry.facets.iter() {
            if f.applies(r, t).unwrap_or(false) {
                let _ = f.entries(r, t, from, to, &mut out);
            }
        }
        Ok(out)
    })
}

/// The row keys of a list, in order: what a test reads.
pub fn keys(rows: &[ListRow]) -> Vec<String> {
    rows.iter().map(|r| r.key.clone()).collect()
}
