//! Sources: what a view looks at, narrowed by aspects present and ordered.

use crate::store::Reader;
use crate::schema::{CollectionOrder as Order, CollectionSource as Source};
use crate::schema::{COLLECTION, Collection};
use osis::{Result, Tid};
use std::collections::BTreeSet;
use std::rc::Rc;

/// `t`'s view: `collection.0`, else its members, placed as cards.
pub fn of(cx: &Reader, t: Tid) -> Result<Collection> {
    Ok(cx.db.at(t, COLLECTION).get()?.unwrap_or(Collection { source: Source::Members, having: BTreeSet::new().into_iter().collect(), order: Order::Own, arrange: crate::schema::Arrange::Cards, element: None }))
}

/// What `view` holds on `t`, narrowed and ordered, without `t` itself.
pub fn items(cx: &Reader, t: Tid) -> Result<Rc<Vec<Tid>>> {
    cx.memo(("items", t), |r, &(_, t)| compute_items(r, t))
}

fn compute_items(cx: &Reader, t: Tid) -> Result<Vec<Tid>> {
    let view = &of(cx, t)?;
    let mut kept = held(cx, t, view)?;
    sort(cx, &mut kept, view)?;
    Ok(kept)
}

/// How many `view` holds on `t`: what a summary says. No order, so no other thing's summary (two
/// collections of everything each hold the other).
pub fn count(cx: &Reader, t: Tid) -> Result<usize> {
    let view = of(cx, t)?;
    Ok(held(cx, t, &view)?.len())
}

/// What `view` holds on `t`, narrowed, unsorted, without `t` itself.
fn held(cx: &Reader, t: Tid, view: &Collection) -> Result<Vec<Tid>> {
    let mut out: Vec<Tid> = match view.source {
        Source::Members => {
            let (subs, items) = cx.tag_contents(t)?;
            subs.into_iter().chain(items).collect()
        }
        Source::Everything => cx.things()?.iter().copied().collect(),
        Source::Favorites => {
            let mut v = cx.favorites()?;
            v.extend(cx.you()?.filter(|p| !v.contains(p)));
            v
        }
    };
    out.retain(|x| *x != t);
    let mut kept = Vec::with_capacity(out.len());
    for x in out {
        if having(cx, x, view)? {
            kept.push(x);
        }
    }
    Ok(kept)
}

/// Whether `t` passes the view's narrowing.
pub fn having(cx: &Reader, t: Tid, view: &Collection) -> Result<bool> {
    if view.having.is_empty() {
        return Ok(true);
    }
    for p in view.having.iter() {
        if cx.has(t, p)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sort(cx: &Reader, v: &mut Vec<Tid>, view: &Collection) -> Result<()> {
    match view.order {
        Order::Own => {}
        Order::Name => {
            let mut k = Vec::with_capacity(v.len());
            for t in v.iter() {
                k.push((cx.summary(*t).map(|s| s.name.to_lowercase()).unwrap_or_default(), *t));
            }
            k.sort();
            *v = k.into_iter().map(|x| x.1).collect();
        }
        Order::Changed => {
            let mut k = Vec::with_capacity(v.len());
            for t in v.iter() {
                k.push((cx.changed(*t)?.unwrap_or(0), *t));
            }
            k.sort_by(|a, b| b.cmp(a));
            *v = k.into_iter().map(|x| x.1).collect();
        }
        Order::Time => {
            let mut k = Vec::with_capacity(v.len());
            for t in v.iter() {
                k.push((cx.summary(*t).ok().and_then(|s| s.time).unwrap_or(i64::MAX), *t));
            }
            k.sort();
            *v = k.into_iter().map(|x| x.1).collect();
        }
    }
    Ok(())
}

/// The one main colour of a page showing `t` (notes/theming.md): its own, else the first among
/// what it holds or links.
pub fn main_color(cx: &Reader, t: Tid) -> Result<Option<String>> {
    if let Some(c) = cx.own_color(t)? {
        return Ok(Some(c));
    }
    let near = if cx.is_scope(t)? { (*items(cx, t)?).clone() } else { cx.tags_of(t)? };
    for x in near {
        if let Some(c) = cx.color(x)? {
            return Ok(Some(c));
        }
    }
    Ok(None)
}
