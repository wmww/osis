//! Search over summaries and facets' text: one way to find anything.

use crate::store::Reader;
use osis::{Result, Tid};

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

/// Every thing's name and facet text against `q`, case-folded. Empty `q`: nothing. A thing that
/// cannot be read is left out.
pub fn search(cx: &Reader, q: &str) -> Result<Found> {
    let q = fold(q.trim());
    let mut f = Found::default();
    if q.is_empty() {
        return Ok(f);
    }
    let mut rest = Vec::new();
    for t in cx.things()?.iter().copied() {
        let Ok(s) = cx.summary(t) else { continue };
        let name = fold(&s.name);
        if cx.is_scope(t)? {
            if name.contains(&q) {
                f.scopes.push(t);
            }
            continue;
        }
        if name.contains(&q) {
            f.named.push(t);
            continue;
        }
        let mut parts = Vec::new();
        for x in cx.registry.facets.iter() {
            if x.applies(cx, t)? {
                parts.extend(x.search(cx, t)?);
            }
        }
        match snippet(&parts.join("\n"), &q) {
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
