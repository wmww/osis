//! The record-chain walk (spec/permissions.md §1): every walk up creation records goes through
//! `record_chain`, so the chain's stop rules and its depth limit live in one place. The chain goes
//! up first-admin links (derivation and the depth cap count them); it says nothing about
//! authority, which is the role timeline's (a record edge may be removed).

use crate::format::MAX_CHAIN_DEPTH;
use crate::ids::{CreationRecord, Tid};

/// What a thing's creation record puts above it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordLink {
    /// An ordinary thing's first admin: the record chain goes on to that actor.
    Admin(Tid),
    /// A key actor: the top of its chain.
    Key,
}

impl CreationRecord {
    /// What the record puts above its thing.
    pub fn record_link(&self) -> RecordLink {
        match self {
            CreationRecord::Thing { admin, .. } => RecordLink::Admin(*admin),
            CreationRecord::KeyActor { .. } => RecordLink::Key,
        }
    }
}

/// One step of a record-chain walk. Every step but `Up` ends the walk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainStep {
    /// `thing`'s first admin is `admin`, where the walk goes on.
    Up { thing: Tid, admin: Tid },
    /// `thing` is a key actor: the top.
    Key(Tid),
    /// `thing`'s creation record is not known to the lookup.
    Unknown(Tid),
    /// The chain goes past `MAX_CHAIN_DEPTH` links: the walk's first thing has no record chain.
    TooDeep,
}

impl ChainStep {
    /// The thing this step is at (none past the depth limit).
    pub fn thing(&self) -> Option<Tid> {
        match *self {
            ChainStep::Up { thing, .. } | ChainStep::Key(thing) | ChainStep::Unknown(thing) => Some(thing),
            ChainStep::TooDeep => None,
        }
    }
}

/// The steps up `t`'s record chain, `t` first, with creation records looked up by `lookup`: one
/// `Up` per link, then the end (a key actor, an unknown record, or `TooDeep` after
/// `MAX_CHAIN_DEPTH` links). At most `MAX_CHAIN_DEPTH + 2` steps, so a cycle ends too.
pub fn record_chain<F: FnMut(&Tid) -> Option<RecordLink>>(t: Tid, lookup: F) -> RecordChain<F> {
    RecordChain { at: Some((t, 0)), lookup }
}

/// See `record_chain`.
pub struct RecordChain<F> {
    /// The next thing and its links below the walk's first thing.
    at: Option<(Tid, usize)>,
    lookup: F,
}

impl<F: FnMut(&Tid) -> Option<RecordLink>> RecordChain<F> {
    /// The step that ends the walk.
    pub fn end(self) -> ChainStep {
        self.last().unwrap_or(ChainStep::TooDeep)
    }
}

impl<F: FnMut(&Tid) -> Option<RecordLink>> Iterator for RecordChain<F> {
    type Item = ChainStep;
    fn next(&mut self) -> Option<ChainStep> {
        let (thing, links) = self.at.take()?;
        if links > MAX_CHAIN_DEPTH {
            return Some(ChainStep::TooDeep);
        }
        Some(match (self.lookup)(&thing) {
            Some(RecordLink::Admin(admin)) => {
                self.at = Some((admin, links + 1));
                ChainStep::Up { thing, admin }
            }
            Some(RecordLink::Key) => ChainStep::Key(thing),
            None => ChainStep::Unknown(thing),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn tid(i: u8) -> Tid {
        Tid::from_bytes([i; crate::format::TID_LEN])
    }

    /// A chain of `n` things below `top`: `tid(1)` deepest, `tid(n)`'s first admin `top`.
    fn chain(n: u8, top: Option<RecordLink>) -> BTreeMap<Tid, RecordLink> {
        let mut m: BTreeMap<Tid, RecordLink> = (1..n).map(|i| (tid(i), RecordLink::Admin(tid(i + 1)))).collect();
        m.insert(tid(n), RecordLink::Admin(tid(0)));
        if let Some(o) = top {
            m.insert(tid(0), o);
        }
        m
    }

    fn walk(m: &BTreeMap<Tid, RecordLink>, t: Tid) -> Vec<ChainStep> {
        record_chain(t, |x| m.get(x).copied()).collect()
    }

    #[test]
    fn each_end() {
        let ups = |n: u8| -> Vec<ChainStep> { (1..=n).map(|i| ChainStep::Up { thing: tid(i), admin: tid(if i == n { 0 } else { i + 1 }) }).collect() };
        let with = |n: u8, end: ChainStep| -> Vec<ChainStep> { ups(n).into_iter().chain([end]).collect() };
        assert_eq!(walk(&chain(3, Some(RecordLink::Key)), tid(1)), with(3, ChainStep::Key(tid(0))));
        assert_eq!(walk(&chain(3, None), tid(1)), with(3, ChainStep::Unknown(tid(0))));
        // the first thing itself a top, or unknown
        assert_eq!(walk(&chain(3, Some(RecordLink::Key)), tid(0)), vec![ChainStep::Key(tid(0))]);
        assert_eq!(walk(&BTreeMap::new(), tid(5)), vec![ChainStep::Unknown(tid(5))]);
        assert_eq!(record_chain(tid(1), |x| chain(2, Some(RecordLink::Key)).get(x).copied()).end(), ChainStep::Key(tid(0)));
    }

    #[test]
    fn depth_limit() {
        let d = u8::try_from(MAX_CHAIN_DEPTH).unwrap_or(u8::MAX);
        // exactly `MAX_CHAIN_DEPTH` links to the top: a chain
        let m = chain(d, Some(RecordLink::Key));
        let steps = walk(&m, tid(1));
        assert_eq!((steps.len(), steps.last()), (MAX_CHAIN_DEPTH + 1, Some(&ChainStep::Key(tid(0)))));
        // one more: too deep, after one `Up` per thing within the limit
        let m = chain(d + 1, Some(RecordLink::Key));
        let steps = walk(&m, tid(1));
        assert_eq!(steps.len(), MAX_CHAIN_DEPTH + 2);
        assert_eq!(steps.last(), Some(&ChainStep::TooDeep));
        assert!(steps[..=MAX_CHAIN_DEPTH].iter().all(|s| matches!(s, ChainStep::Up { .. })));
        assert_eq!(record_chain(tid(1), |x| m.get(x).copied()).end(), ChainStep::TooDeep);
        // a cycle ends too
        let cyc = BTreeMap::from([(tid(1), RecordLink::Admin(tid(2))), (tid(2), RecordLink::Admin(tid(1)))]);
        assert_eq!(record_chain(tid(1), |x| cyc.get(x).copied()).end(), ChainStep::TooDeep);
    }

    #[test]
    fn record_link_of_each_record() {
        let nonce = [7; 32];
        assert_eq!(CreationRecord::Thing { admin: tid(1), nonce, link: false }.record_link(), RecordLink::Admin(tid(1)));
        assert_eq!(CreationRecord::KeyActor { alg: 1, public_key: vec![0; 32], nonce }.record_link(), RecordLink::Key);
    }
}
