//! The owner-chain walk (spec/permissions.md §1): every walk up creation records goes through
//! `owner_chain`, so the chain's stop rules and its depth limit live in one place.

use crate::format::MAX_OWNER_DEPTH;
use crate::ids::{CreationRecord, Tid};

/// What a thing's creation record puts above it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner {
    /// An ordinary thing's owner actor.
    Actor(Tid),
    /// A key actor: the top of its chain.
    Key,
    /// An ownerless thing, the top of its chain; its record's first admin holds an admin edge on
    /// it from the start.
    Ownerless(Tid),
}

impl CreationRecord {
    /// What the record puts above its thing.
    pub fn owner_link(&self) -> Owner {
        match self {
            CreationRecord::Thing { owner, .. } => Owner::Actor(*owner),
            CreationRecord::KeyActor { .. } => Owner::Key,
            CreationRecord::Ownerless { admin, .. } => Owner::Ownerless(*admin),
        }
    }
}

/// One step of an owner-chain walk. Every step but `Up` ends the walk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainStep {
    /// `thing` is owned by `owner`, where the walk goes on.
    Up { thing: Tid, owner: Tid },
    /// `thing` is a key actor: the top.
    Key(Tid),
    /// `thing` is an ownerless thing whose first admin is `admin`: the top.
    Ownerless { thing: Tid, admin: Tid },
    /// `thing`'s creation record is not known to the lookup.
    Unknown(Tid),
    /// The chain goes past `MAX_OWNER_DEPTH` owner links: the walk's first thing has no owner
    /// chain.
    TooDeep,
}

impl ChainStep {
    /// The thing this step is at (none past the depth limit).
    pub fn thing(&self) -> Option<Tid> {
        match *self {
            ChainStep::Up { thing, .. } | ChainStep::Key(thing) | ChainStep::Ownerless { thing, .. } | ChainStep::Unknown(thing) => Some(thing),
            ChainStep::TooDeep => None,
        }
    }
}

/// The steps up `t`'s owner chain, `t` first, with creation records looked up by `lookup`: one
/// `Up` per owner link, then the end (a top, an unknown record, or `TooDeep` after
/// `MAX_OWNER_DEPTH` links). At most `MAX_OWNER_DEPTH + 2` steps, so a cycle ends too.
pub fn owner_chain<F: FnMut(&Tid) -> Option<Owner>>(t: Tid, lookup: F) -> OwnerChain<F> {
    OwnerChain { at: Some((t, 0)), lookup }
}

/// See `owner_chain`.
pub struct OwnerChain<F> {
    /// The next thing and its owner links below the walk's first thing.
    at: Option<(Tid, usize)>,
    lookup: F,
}

impl<F: FnMut(&Tid) -> Option<Owner>> OwnerChain<F> {
    /// The step that ends the walk.
    pub fn end(self) -> ChainStep {
        self.last().unwrap_or(ChainStep::TooDeep)
    }
}

impl<F: FnMut(&Tid) -> Option<Owner>> Iterator for OwnerChain<F> {
    type Item = ChainStep;
    fn next(&mut self) -> Option<ChainStep> {
        let (thing, links) = self.at.take()?;
        if links > MAX_OWNER_DEPTH {
            return Some(ChainStep::TooDeep);
        }
        Some(match (self.lookup)(&thing) {
            Some(Owner::Actor(owner)) => {
                self.at = Some((owner, links + 1));
                ChainStep::Up { thing, owner }
            }
            Some(Owner::Key) => ChainStep::Key(thing),
            Some(Owner::Ownerless(admin)) => ChainStep::Ownerless { thing, admin },
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

    /// A chain of `n` owned things below `top`: `tid(1)` deepest, `tid(n)` owned by `top`.
    fn chain(n: u8, top: Option<Owner>) -> BTreeMap<Tid, Owner> {
        let mut m: BTreeMap<Tid, Owner> = (1..n).map(|i| (tid(i), Owner::Actor(tid(i + 1)))).collect();
        m.insert(tid(n), Owner::Actor(tid(0)));
        if let Some(o) = top {
            m.insert(tid(0), o);
        }
        m
    }

    fn walk(m: &BTreeMap<Tid, Owner>, t: Tid) -> Vec<ChainStep> {
        owner_chain(t, |x| m.get(x).copied()).collect()
    }

    #[test]
    fn each_end() {
        let ups = |n: u8| -> Vec<ChainStep> { (1..=n).map(|i| ChainStep::Up { thing: tid(i), owner: tid(if i == n { 0 } else { i + 1 }) }).collect() };
        let with = |n: u8, end: ChainStep| -> Vec<ChainStep> { ups(n).into_iter().chain([end]).collect() };
        assert_eq!(walk(&chain(3, Some(Owner::Key)), tid(1)), with(3, ChainStep::Key(tid(0))));
        assert_eq!(walk(&chain(3, Some(Owner::Ownerless(tid(9)))), tid(1)), with(3, ChainStep::Ownerless { thing: tid(0), admin: tid(9) }));
        assert_eq!(walk(&chain(3, None), tid(1)), with(3, ChainStep::Unknown(tid(0))));
        // the first thing itself a top, or unknown
        assert_eq!(walk(&chain(3, Some(Owner::Key)), tid(0)), vec![ChainStep::Key(tid(0))]);
        assert_eq!(walk(&BTreeMap::new(), tid(5)), vec![ChainStep::Unknown(tid(5))]);
        assert_eq!(owner_chain(tid(1), |x| chain(2, Some(Owner::Key)).get(x).copied()).end(), ChainStep::Key(tid(0)));
    }

    #[test]
    fn depth_limit() {
        let d = u8::try_from(MAX_OWNER_DEPTH).unwrap_or(u8::MAX);
        // exactly `MAX_OWNER_DEPTH` links to the top: a chain
        let m = chain(d, Some(Owner::Key));
        let steps = walk(&m, tid(1));
        assert_eq!((steps.len(), steps.last()), (MAX_OWNER_DEPTH + 1, Some(&ChainStep::Key(tid(0)))));
        // one more: too deep, after one `Up` per thing within the limit
        let m = chain(d + 1, Some(Owner::Key));
        let steps = walk(&m, tid(1));
        assert_eq!(steps.len(), MAX_OWNER_DEPTH + 2);
        assert_eq!(steps.last(), Some(&ChainStep::TooDeep));
        assert!(steps[..=MAX_OWNER_DEPTH].iter().all(|s| matches!(s, ChainStep::Up { .. })));
        assert_eq!(owner_chain(tid(1), |x| m.get(x).copied()).end(), ChainStep::TooDeep);
        // a cycle ends too
        let cyc = BTreeMap::from([(tid(1), Owner::Actor(tid(2))), (tid(2), Owner::Actor(tid(1)))]);
        assert_eq!(owner_chain(tid(1), |x| cyc.get(x).copied()).end(), ChainStep::TooDeep);
    }

    #[test]
    fn owner_link_of_each_record() {
        let nonce = [7; 32];
        assert_eq!(CreationRecord::Thing { owner: tid(1), nonce }.owner_link(), Owner::Actor(tid(1)));
        assert_eq!(CreationRecord::KeyActor { alg: 1, public_key: vec![0; 32], nonce }.owner_link(), Owner::Key);
        assert_eq!(CreationRecord::Ownerless { admin: tid(2), nonce }.owner_link(), Owner::Ownerless(tid(2)));
    }
}
