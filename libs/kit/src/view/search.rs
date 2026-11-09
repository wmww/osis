//! Search over summaries and facets' text: one way to find anything.

use crate::store::Reader;
use osis::{Result, Tid};
use std::rc::Rc;

/// Scopes whose name matches, things whose name matches, things whose text matches (with a
/// snippet), and the other things in the matching scopes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub scopes: Vec<Tid>,
    pub named: Vec<Tid>,
    pub mentions: Vec<(Tid, String)>,
    pub in_scopes: Vec<Tid>,
}

impl Found {
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty() && self.named.is_empty() && self.mentions.is_empty() && self.in_scopes.is_empty()
    }
}

/// What search compares of one thing: a memo per thing, so a keystroke reads nothing and a change
/// reads the thing it was to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Text {
    name: String,
    scope: bool,
    /// The facets' text, unfolded (a snippet shows it as written).
    text: String,
}

fn text_of(cx: &Reader, t: Tid) -> Result<Rc<Text>> {
    cx.memo(("search text", t), |r, &(_, t)| {
        let mut parts = Vec::new();
        for x in r.registry.facets.iter() {
            if x.applies(r, t)? {
                parts.extend(x.search(r, t)?);
            }
        }
        Ok(Text { name: fold(&r.summary(t)?.name), scope: r.is_scope(t)?, text: parts.join("\n") })
    })
}

/// Every thing's name and facet text against `q`, case-folded. Empty `q`: nothing. A thing that
/// cannot be read is left out. A memo per query.
pub fn search(cx: &Reader, q: &str) -> Result<Found> {
    Ok((*cx.memo(("search", q.to_string()), |r, (_, q)| compute(r, q))?).clone())
}

fn compute(cx: &Reader, q: &str) -> Result<Found> {
    let q = fold(q.trim());
    let mut f = Found::default();
    if q.is_empty() {
        return Ok(f);
    }
    let mut rest = Vec::new();
    for t in cx.things()?.iter().copied() {
        let Ok(s) = text_of(cx, t) else { continue };
        if s.scope {
            if s.name.contains(&q) {
                f.scopes.push(t);
            }
            continue;
        }
        if s.name.contains(&q) {
            f.named.push(t);
            continue;
        }
        match snippet(&s.text, &q) {
            Some(sn) => f.mentions.push((t, sn)),
            None => rest.push(t),
        }
    }
    for t in rest {
        if cx.tags_of(t)?.iter().any(|g| f.scopes.contains(g)) {
            f.in_scopes.push(t);
        }
    }
    // a view's members are its source's, not memberships
    for (_, vt) in cx.collections()? {
        if f.scopes.contains(&vt) {
            for t in super::source::items(cx, vt)?.iter().copied() {
                if !f.named.contains(&t) && !f.mentions.iter().any(|(x, _)| *x == t) && !f.in_scopes.contains(&t) && !f.scopes.contains(&t) {
                    f.in_scopes.push(t);
                }
            }
        }
    }
    let by_name = |v: &mut Vec<Tid>| {
        let mut k: Vec<(String, Tid)> = v.iter().map(|t| (cx.summary(*t).map(|s| s.name.to_lowercase()).unwrap_or_default(), *t)).collect();
        k.sort();
        *v = k.into_iter().map(|x| x.1).collect();
    };
    by_name(&mut f.scopes);
    by_name(&mut f.named);
    by_name(&mut f.in_scopes);
    Ok(f)
}

/// Case folding, char by char (so indices match the text's and every place folds alike;
/// `str::to_lowercase` maps a final sigma by context).
pub fn fold(s: &str) -> String {
    s.chars().map(|c| c.to_lowercase().next().unwrap_or(c)).collect()
}

/// A one-line excerpt of `text` around the first match of `q` (already `fold`ed), or `None`.
pub fn snippet(text: &str, q: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = fold(text).chars().collect();
    let qc: Vec<char> = q.chars().collect();
    if qc.is_empty() {
        return None;
    }
    let at = lower.windows(qc.len()).position(|w| w == qc.as_slice())?;
    let a = at.saturating_sub(12);
    let b = (at + qc.len() + 40).min(chars.len());
    let mut s: String = chars.get(a..b).unwrap_or_default().iter().collect::<String>().replace('\n', " · ");
    if a > 0 {
        s.insert(0, '…');
    }
    if b < chars.len() {
        s.push('…');
    }
    Some(s)
}

/// What the search field holds beyond a query.
pub enum Paste {
    Link,
    Peer,
    Query,
}

/// What is pasted into the search field.
pub fn classify(q: &str) -> Paste {
    if q.starts_with("osis://") {
        Paste::Link
    } else if q.parse::<osis::Address>().is_ok() {
        Paste::Peer
    } else {
        Paste::Query
    }
}
