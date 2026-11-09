//! Signal edits (notes/signal-edits-design.md, the design, not the engine). A part with `replaces` is
//! honored when the named commit is listed on the same (thing, aspect), valid or a purge tombstone,
//! has no `replaces` itself, has the same verified actor and sorts before it by (ts, ID); else it is a
//! fire of its own. An original reads as its newest listed honored version (valid versions only);
//! stamp, place and order stay the original's. A purge takes only the commits it names. Listing
//! is judged from headers: an original whose body is not here is listed and its versions fold
//! under it; a version reads only where its body (or tombstone) is here.
use crate::model::{evaluate, expired, kept_until, signal_kept, Outcome};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// A listed entry: an original with what it reads as.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// `(ts, ID)` of the original.
    pub place: (u64, CommitId),
    /// The newest listed honored version (the original when none).
    pub version: CommitId,
    pub shows: Shows,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shows {
    Value(Value),
    Purged,
    /// The original's header is held, its body not, and no version's body is here.
    NotFetched,
}

/// What the node's listing of each signal reads, in place order. Own invalid parts (spec/commits.md
/// §7) are not here: they are marked and read as themselves.
pub fn listing(h: &Held) -> BTreeMap<(ThingId, Aspect), Vec<Entry>> {
    let o = evaluate(h);
    let by_id: BTreeMap<CommitId, &Commit> = h.commits.iter().map(|c| (c.id, c)).collect();
    let mut listed: BTreeMap<(ThingId, Aspect), Vec<(&Commit, usize)>> = BTreeMap::new();
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            if status(h, &o, &by_id, c, i).is_some() {
                listed.entry((p.thing, p.aspect)).or_default().push((c, i));
            }
        }
    }
    listed.into_iter().map(|(k, parts)| (k, entries(h, &o, &by_id, &parts))).collect()
}

/// The commits with a listed part (a version folded under a newer one has no entry of its own).
pub fn listed(h: &Held) -> BTreeSet<CommitId> {
    let o = evaluate(h);
    let by_id: BTreeMap<CommitId, &Commit> = h.commits.iter().map(|c| (c.id, c)).collect();
    h.commits.iter().filter(|c| (0..c.parts.len()).any(|i| status(h, &o, &by_id, c, i).is_some())).map(|c| c.id).collect()
}

/// What is here of a listed part.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Here {
    Body,
    Purged,
    /// Its header is held, its body not (never received).
    NotFetched,
}

/// Whether part `i` of `c` is listed, judged from its header (spec/commits.md §7): what is here of it.
fn status(h: &Held, o: &Outcome, by_id: &BTreeMap<CommitId, &Commit>, c: &Commit, i: usize) -> Option<Here> {
    let p = &c.parts[i];
    if !p.aspect.signal || c.kind != CommitKind::Content || o.ended.contains(&p.thing) || o.valid.get(&(c.id, i)) != Some(&true) || expired(c, h.now) {
        return None;
    }
    if let Some(q) = o.purged.get(&(c.id, i)) {
        // spec/commits.md §7: listed while its keep rule would keep it, counted from the request
        let after = p.retention.kept_after();
        let kept = h.now < kept_until(c, p) || (after > 0 && h.now < wall(by_id[q].ts).saturating_add(after));
        return kept.then_some(Here::Purged);
    }
    let here = match p.body {
        Body::Held(_) => Here::Body,
        Body::Missing => Here::NotFetched,
        _ => return None,
    };
    signal_kept(c, p, h.now).then_some(here)
}

/// The commit `v` names, when it is `v`'s original but for being listed: same (thing, aspect), valid
/// or a purge tombstone's, no `replaces` of its own, same verified actor, sorting before `v`.
fn named<'a>(o: &Outcome, by_id: &BTreeMap<CommitId, &'a Commit>, v: &Commit, i: usize) -> Option<(&'a Commit, usize)> {
    let p = &v.parts[i];
    let x = *by_id.get(&p.replaces?)?;
    let j = x.parts.iter().position(|q| q.thing == p.thing && q.aspect == p.aspect)?;
    let ok = o.valid.get(&(x.id, j)) == Some(&true) && x.parts[j].replaces.is_none() && x.actor == v.actor && (x.ts, x.id) < (v.ts, v.id);
    ok.then_some((x, j))
}

/// The original `v` is honored against, if any.
fn original<'a>(h: &Held, o: &Outcome, by_id: &BTreeMap<CommitId, &'a Commit>, v: &Commit, i: usize) -> Option<&'a Commit> {
    let (x, j) = named(o, by_id, v, i)?;
    status(h, o, by_id, x, j).is_some().then_some(x)
}

fn entries(h: &Held, o: &Outcome, by_id: &BTreeMap<CommitId, &Commit>, parts: &[(&Commit, usize)]) -> Vec<Entry> {
    let mut out = vec![];
    for &(c, i) in parts.iter().filter(|&&(c, i)| original(h, o, by_id, c, i).is_none()) {
        // honored versions read only where their body (or tombstone) is here
        let honored = parts.iter().filter(|&&(v, j)| original(h, o, by_id, v, j).is_some_and(|x| x.id == c.id) && status(h, o, by_id, v, j) != Some(Here::NotFetched));
        let (nc, ni) = honored.copied().chain([(c, i)]).max_by_key(|&(v, _)| (v.ts, v.id)).unwrap();
        let shows = match status(h, o, by_id, nc, ni) {
            Some(Here::Purged) => Shows::Purged,
            Some(Here::NotFetched) => Shows::NotFetched,
            _ => Shows::Value(value(&nc.parts[ni])),
        };
        out.push(Entry { place: (c.ts, c.id), version: nc.id, shows });
    }
    out.sort();
    out
}

fn value(p: &Part) -> Value {
    match &p.body {
        Body::Held(Delta::Writes(Frag::Register { write: Some((_, Some(v))), .. })) => v.clone(),
        b => panic!("a signal part holds one root register write: {b:?}"),
    }
}
