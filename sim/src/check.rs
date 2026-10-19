//! The invariant library. Each check returns the violated rule as text (the harness turns it
//! into a `Failure` carrying the seed); none panics.
//! - spec/requirements.md (convergence): nodes holding the same commits read the same values.
//! - spec/crdt.md §2.3, spec/commits.md §4: an honest node never reuses a node-form counter.
//! - spec/crdt.md §2.2: a node's own `ts` strictly increases (across restarts) and stays within
//!   `MAX_DRIFT` of its wall clock; no remote commit applies more than `MAX_DRIFT` ahead.
//! - spec/commits.md §4: pending commits drain once their reasons resolve (at quiescence).

use osis_commit::{Form, Header};
use osis_core::format::MAX_DRIFT_MS;
use osis_core::{Ak, CommitId, Tid, Ts, Value};
use osis_node::{Engine, Event, Origin, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Every stored aspect and its read.
pub type Reads = Vec<(Tid, Ak, Option<Value>)>;
type Ranges = BTreeMap<u64, (u64, CommitId)>;

/// State carried across steps.
#[derive(Default)]
pub struct Checker {
    seen: BTreeSet<CommitId>,
    /// Node-form ranges per (author, tid, ak): lo -> (hi, commit).
    ranges: BTreeMap<(Tid, Tid, Ak), Ranges>,
    /// Last own `ts` per node index.
    last_own: BTreeMap<usize, Ts>,
    pub applied: u64,
}

impl Checker {
    /// Feeds one engine event of node `i`.
    pub fn event(&mut self, i: usize, e: &Engine, ev: &Event) -> std::result::Result<(), String> {
        let Event::Applied { id, origin, ts, received, .. } = ev else { return Ok(()) };
        self.applied = self.applied.saturating_add(1);
        let limit = received.0.saturating_add(MAX_DRIFT_MS);
        match origin {
            // spec/crdt.md §2.2: max(wall, last seen) with last seen within MAX_DRIFT; +1 ms for
            // a writer that exhausted `logical`
            Origin::Local => {
                if let Some(prev) = self.last_own.get(&i)
                    && ts <= prev
                {
                    return Err(format!("node {i}: own ts {ts:?} not above previous {prev:?} (HLC monotone)"));
                }
                self.last_own.insert(i, *ts);
                if ts.wall_ms().0 > limit.saturating_add(1) {
                    return Err(format!("node {i}: own ts {ts:?} more than MAX_DRIFT ahead of its wall clock {received:?}"));
                }
            }
            Origin::Remote => {
                if ts.wall_ms().0 > limit {
                    return Err(format!("node {i}: applied {id:?} at {received:?} with ts {ts:?} beyond MAX_DRIFT (must park)"));
                }
            }
        }
        if let Some(h) = e.header(id) {
            self.header(id, &h)?;
        }
        Ok(())
    }

    /// spec/crdt.md §2.3: node-form counter ranges of distinct commits by one author never
    /// overlap on one aspect.
    fn header(&mut self, id: &CommitId, h: &Header) -> std::result::Result<(), String> {
        if !self.seen.insert(*id) || h.form != Form::Node {
            return Ok(());
        }
        for a in &h.aspects {
            if a.lo >= a.hi {
                continue;
            }
            let m = self.ranges.entry((h.author, a.tid, a.ak.clone())).or_default();
            if let Some((lo, (hi, c))) = m.range(..a.hi).next_back()
                && *hi > a.lo
                && c != id
            {
                return Err(format!("counter reuse: {id:?} [{}, {}) overlaps {c:?} [{lo}, {hi}) on {} {} by {}", a.lo, a.hi, a.tid, a.ak.as_str(), h.author));
            }
            m.insert(a.lo, (a.hi, *id));
        }
        Ok(())
    }
}

/// Every stored aspect's read, sorted (the convergence comparand).
pub fn reads(e: &mut Engine) -> Result<Reads> {
    let mut out = Vec::new();
    for (t, a) in e.all_aspects()? {
        let v = e.get(&t, &a)?;
        out.push((t, a, v));
    }
    out.sort_by(|x, y| (x.0, x.1.as_str()).cmp(&(y.0, y.1.as_str())));
    Ok(out)
}

/// The applied commit set of a node.
pub fn held(e: &Engine) -> BTreeSet<CommitId> {
    e.commit_ids().into_iter().collect()
}

/// spec/requirements.md (convergence): within every group of nodes holding the same commits,
/// reads agree. `nodes` are (index, engine) of the nodes that are up.
pub fn convergence(nodes: &mut [(usize, &mut Engine)]) -> std::result::Result<(), String> {
    let mut groups: BTreeMap<BTreeSet<CommitId>, Vec<usize>> = BTreeMap::new();
    for (k, (_, e)) in nodes.iter().enumerate() {
        groups.entry(held(e)).or_default().push(k);
    }
    for members in groups.values() {
        let mut first: Option<(usize, Reads)> = None;
        for k in members {
            let Some((i, e)) = nodes.get_mut(*k) else { continue };
            let r = reads(e).map_err(|x| format!("node {i}: read failed: {x}"))?;
            match &first {
                None => first = Some((*i, r)),
                Some((j, f)) if *f != r => return Err(format!("divergence: nodes {j} and {i} hold the same commits but read differently: {}", diff(f, &r))),
                Some(_) => {}
            }
        }
    }
    Ok(())
}

fn diff(a: &[(Tid, Ak, Option<Value>)], b: &[(Tid, Ak, Option<Value>)]) -> String {
    let am: BTreeMap<(Tid, &str), &Option<Value>> = a.iter().map(|x| ((x.0, x.1.as_str()), &x.2)).collect();
    let bm: BTreeMap<(Tid, &str), &Option<Value>> = b.iter().map(|x| ((x.0, x.1.as_str()), &x.2)).collect();
    for k in am.keys().chain(bm.keys()) {
        let (x, y) = (am.get(k), bm.get(k));
        if x != y {
            return format!("{} {}: {x:?} vs {y:?}", k.0, k.1);
        }
    }
    String::new()
}

/// At quiescence with full delivery: every node holds the same commits and nothing pends.
pub fn quiescent(nodes: &[(usize, &Engine)]) -> std::result::Result<(), String> {
    let mut first: Option<(usize, BTreeSet<CommitId>)> = None;
    for (i, e) in nodes {
        let p = e.pending();
        if !p.is_empty() {
            return Err(format!("node {i}: {} commits still pending at quiescence: {p:?}", p.len()));
        }
        let h = held(e);
        match &first {
            None => first = Some((*i, h)),
            Some((j, f)) if *f != h => return Err(format!("nodes {j} and {i} hold different commits at quiescence ({} vs {})", f.len(), h.len())),
            Some(_) => {}
        }
    }
    Ok(())
}

