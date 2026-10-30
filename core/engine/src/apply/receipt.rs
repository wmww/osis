//! The receipt record (spec/permissions.md §5.1, notes/permissions.md Revocation): per aspect
//! and author node, the counter ranges received with their receipt time, plus commit-form
//! commits by ID. Adjacent ranges merge with the later time (a coarser record only shrinks a
//! frontier). Pending and parked commits are not received. Held snapshots' frontiers (`[1,
//! ctr]`) and `Absorbed` (spec/crdt.md §8) are not recorded: `received` adds those of the
//! snapshots valid now, at their receipt time, so a snapshot turning invalid takes them back
//! whatever the arrival order (spec/permissions.md §5.2); a snapshot dropped other than as
//! covered keeps them in its record (`Dropped::gives`, spec/commits.md §5). Demotions read it "as
//! of T" for their frontier.

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Engine, Tx};
use crate::error::Result;
use osis_commit::{Decoded, Form, Header};
use osis_base::{Ak, CommitId, Tid, WallMs};
use osis_perm::DemotionScope;
use osis_schema::core_types::{Frontier, is_membership_class};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Receipt-time granularity (local policy): adjacent ranges received within one bucket merge.
pub const GRANULARITY_MS: u64 = 60_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// node -> sorted disjoint `(lo, hi, received)`.
    pub nodes: BTreeMap<Tid, Vec<(u64, u64, u64)>>,
    /// commit-form commits: ID -> (author, received).
    pub commits: BTreeMap<CommitId, (Tid, u64)>,
}

impl Receipt {
    pub fn add(&mut self, node: Tid, lo: u64, hi: u64, t: u64) {
        if lo >= hi {
            return;
        }
        let v = self.nodes.entry(node).or_default();
        // counters already held keep their earlier receipt time
        let mut pieces = vec![(lo, hi)];
        for (a, b, _) in v.iter() {
            pieces = pieces.into_iter().flat_map(|(x, y)| [(x, y.min(*a)), (x.max(*b), y)]).filter(|(x, y)| x < y).collect();
        }
        v.extend(pieces.into_iter().map(|(x, y)| (x, y, t)));
        v.sort_unstable();
        let mut out: Vec<(u64, u64, u64)> = Vec::with_capacity(v.len());
        for (a, b, t) in v.drain(..) {
            match out.last_mut() {
                Some(l) if a == l.1 && l.2 / GRANULARITY_MS == t / GRANULARITY_MS => {
                    l.1 = b;
                    l.2 = l.2.max(t);
                }
                _ => out.push((a, b, t)),
            }
        }
        *v = out;
    }

    /// Whether every counter in `[lo, hi)` of `node` was received.
    pub fn holds(&self, node: &Tid, lo: u64, hi: u64) -> bool {
        let mut next = lo;
        for (a, b, _) in self.nodes.get(node).into_iter().flatten() {
            if *a <= next && *b > next {
                next = *b;
            }
        }
        next >= hi
    }

    /// Last counter (inclusive) of `node` received contiguously from 1 by time `t`; 0 if none.
    pub fn contiguous(&self, node: &Tid, t: u64) -> u64 {
        let mut next = 1u64;
        for (lo, hi, at) in self.nodes.get(node).into_iter().flatten() {
            if *lo > next || *at > t {
                break;
            }
            next = next.max(*hi);
        }
        next - 1
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Wr::new().u32(self.nodes.len() as u32);
        for (n, v) in &self.nodes {
            w = w.raw(n.as_bytes()).u32(v.len() as u32);
            for (a, b, t) in v {
                w = w.u64(*a).u64(*b).u64(*t);
            }
        }
        w = w.u32(self.commits.len() as u32);
        for (c, (a, t)) in &self.commits {
            w = w.raw(&c.0).raw(a.as_bytes()).u64(*t);
        }
        w.take()
    }

    fn decode(b: &[u8]) -> Result<Receipt> {
        let mut r = Rd::new(b);
        let mut out = Receipt::default();
        for _ in 0..r.u32()? {
            let n = r.tid()?;
            let mut v = Vec::new();
            for _ in 0..r.u32()? {
                v.push((r.u64()?, r.u64()?, r.u64()?));
            }
            out.nodes.insert(n, v);
        }
        for _ in 0..r.u32()? {
            let c = CommitId(r.arr()?);
            let a = r.tid()?;
            out.commits.insert(c, (a, r.u64()?));
        }
        r.end()?;
        Ok(out)
    }
}

pub(crate) fn get(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Receipt> {
    match tx.txn.get_local(&records::aspect_key(records::RECEIPT, tid, ak))? {
        Some(b) => Receipt::decode(&b),
        None => Ok(Receipt::default()),
    }
}

fn put(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, r: &Receipt) -> Result<()> {
    tx.core.waits.wake(tid, ak);
    Ok(tx.txn.put_local(&records::aspect_key(records::RECEIPT, tid, ak), &r.encode(), Shred::No)?)
}

/// What this node had received of `(tid, ak)` by `as_of`: the record's entries received by
/// then, plus the frontiers and `Absorbed` of the held snapshots (bodies held, or dropped with
/// their frontiers kept) valid now that it received by then (an invalid one's count as not
/// received, spec/permissions.md §5.2). Cost: the aspect's held and kept snapshots.
pub(crate) fn received(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, as_of: u64) -> Result<Receipt> {
    let mut r = get(tx, tid, ak)?;
    for v in r.nodes.values_mut() {
        v.retain(|x| x.2 <= as_of);
    }
    r.commits.retain(|_, x| x.1 <= as_of);
    let core = &*tx.core;
    let k = (*tid, ak.clone());
    // valid ones received by `as_of`, at their part's receipt time (`record`; a late part's,
    // not its header's): held, then dropped ones that kept their frontiers (`Dropped::gives`)
    let at = |s: &CommitId| r.commits.get(s).map(|c| c.1);
    let held = core.ix.snapshots.get(&k).into_iter().flatten().filter_map(|(_, s, fr, abs)| {
        let at = at(s)?;
        super::validity::snapshot_valid(core, s, tid, ak).then_some((at, fr, abs))
    });
    let kept = core.ix.dropped_snapshots.get(&k).into_iter().flatten().filter_map(|s| {
        let at = at(s)?;
        let m = core.ix.commits.get(s)?;
        let ai = m.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)?;
        let (fr, abs) = m.dropped.get(&ai)?.gives.as_ref()?;
        m.valid.get(ai).copied().unwrap_or(false).then_some((at, fr, abs))
    });
    let add: Vec<_> = held.chain(kept).collect();
    for (at, fr, abs) in add {
        for (n, c) in &fr.0 {
            r.add(*n, 1, c.saturating_add(1), at);
        }
        for (c, a) in abs {
            r.commits.entry(*c).or_insert((*a, at));
        }
    }
    Ok(r)
}

/// Records what an applied commit's held parts gave this node (a snapshot: its ID; what it
/// carries counts through `received`).
pub(crate) fn record(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)], received: WallMs) -> Result<()> {
    let held: BTreeSet<usize> = parts.iter().map(|p| p.0).collect();
    for ai in held {
        let Some(a) = h.aspects.get(ai) else { continue };
        let mut r = get(tx, &a.tid, &a.ak)?;
        if h.kind.has_own_writes() {
            match h.form {
                Form::Node => r.add(h.author, a.lo, a.hi, received.0),
                Form::Commit => {
                    r.commits.insert(*id, (h.author, received.0));
                }
            }
        } else {
            // imports count by commit ID (spec/permissions.md §5.1 frontier coverage)
            r.commits.insert(*id, (h.author, received.0));
        }
        put(tx, &a.tid, &a.ak, &r)?;
    }
    Ok(())
}

impl Engine {
    /// What this node received of one aspect, held valid snapshots' frontiers included.
    pub fn receipt(&mut self, tid: &Tid, ak: &Ak) -> Result<Receipt> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| received(tx, &tid, &ak, u64::MAX))
    }

    /// The frontier a demotion stamped now must embed (spec/permissions.md §5.1): per aspect the
    /// scope puts in question and per demoted node, the last counter received contiguously as
    /// of `as_of`, plus that node's commit-form commits received by then. This node's own
    /// receipts only; `as_of` earlier than now gives a backdated revoke's frontier.
    pub fn frontier(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<Frontier> {
        let mut aspects: Vec<(Tid, Tid, Ak)> = Vec::new();
        for (node, things) in &scope.membership {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)).filter(|((_, ak), _)| is_membership_class(ak.as_str())) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        for (node, things) in &scope.content {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        aspects.sort();
        aspects.dedup();
        self.run(|tx| {
            let mut f = Frontier::default();
            for (node, t, ak) in aspects {
                let r = received(tx, &t, &ak, as_of.0)?;
                let c = r.contiguous(&node, as_of.0);
                if c > 0 {
                    f.writes.entry(t).or_default().entry(ak.as_str().to_string()).or_default().insert(node, c);
                }
                for (id, (a, _)) in &r.commits {
                    if *a == node {
                        f.commits.insert(*id);
                    }
                }
            }
            Ok(f)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/permissions.md §5.1: a frontier covers what was received contiguously as of T.
    // spec/permissions.md §5.1 (frontier received)
    #[test]
    fn contiguous_as_of_spec_5_1() {
        let n = Tid::from_bytes([1; 15]);
        let mut r = Receipt::default();
        r.add(n, 1, 3, 10);
        r.add(n, 5, 6, 11);
        assert_eq!(r.contiguous(&n, 100), 2);
        r.add(n, 3, 5, 200_000);
        assert_eq!(r.contiguous(&n, 300_000), 5);
        assert_eq!(r.contiguous(&n, 15), 2);
        // a repeat keeps the earlier time
        r.add(n, 1, 3, 400_000);
        assert_eq!(r.contiguous(&n, 15), 2);
        assert_eq!(Receipt::decode(&r.encode()).unwrap(), r);
    }

    // spec/commits.md §4 (dropped deltas count as held), spec/crdt.md §8 (snapshot frontiers):
    // a counter range is held when received ranges cover it, across time buckets.
    #[test]
    fn holds_range_spec_commits_4() {
        let n = Tid::from_bytes([1; 15]);
        let mut r = Receipt::default();
        r.add(n, 1, 4, 10);
        r.add(n, 4, 9, 200_000);
        assert!(r.holds(&n, 2, 9));
        assert!(!r.holds(&n, 2, 10));
        assert!(!r.holds(&Tid::from_bytes([2; 15]), 1, 2));
    }
}
