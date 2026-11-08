//! Sources: what a view looks at, narrowed by aspects present and ordered.

use super::Cx;
use crate::schema::{CollectionOrder as Order, CollectionSource as Source};
use crate::schema::{COLLECTION, Collection};
use osis::{Result, Tid};
use std::collections::BTreeSet;

/// `t`'s view: `collection.0`, else its members, placed as cards.
pub fn of(cx: &Cx<'_>, t: Tid) -> Result<Collection> {
    Ok(cx.data.db.at(t, COLLECTION).get()?.unwrap_or(Collection { source: Source::Members, having: BTreeSet::new().into_iter().collect(), order: Order::Own, arrange: crate::schema::Arrange::Cards, element: None }))
}

/// What `view` holds on `t`, narrowed and ordered, without `t` itself.
pub fn items(cx: &Cx<'_>, t: Tid, view: &Collection) -> Result<Vec<Tid>> {
    let mut out: Vec<Tid> = match view.source {
        Source::Members => {
            let (subs, items) = cx.data.tag_contents(t)?;
            subs.into_iter().chain(items).collect()
        }
        Source::Everything => cx.things()?.iter().copied().collect(),
        Source::Favorites => {
            let mut v = cx.data.favorites()?;
            v.extend(cx.data.you()?.filter(|p| !v.contains(p)));
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
    sort(cx, &mut kept, view)?;
    Ok(kept)
}

/// Whether `t` passes the view's narrowing.
pub fn having(cx: &Cx<'_>, t: Tid, view: &Collection) -> Result<bool> {
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

fn sort(cx: &Cx<'_>, v: &mut Vec<Tid>, view: &Collection) -> Result<()> {
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
                k.push((cx.data.changed(*t)?.unwrap_or(0), *t));
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
pub fn main_color(cx: &Cx<'_>, t: Tid) -> Result<Option<String>> {
    if let Some(c) = cx.data.own_color(t)? {
        return Ok(Some(c));
    }
    let view = of(cx, t)?;
    let near = if cx.data.is_scope(t)? { items(cx, t, &view)? } else { cx.data.tags_of(t)? };
    for x in near {
        if let Some(c) = cx.data.color(x)? {
            return Ok(Some(c));
        }
    }
    Ok(None)
}
