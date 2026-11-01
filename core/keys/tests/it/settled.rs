#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Settled rotation commits (spec/crypto.md §4): random claim histories of one role (forks,
//! invalid claims, keysets listing the commits of what they supersede, forged invalid claims no
//! rotator lists, snapshots), the held claims recorded in random orders with validity verdicts
//! flipping on the way, against a direct reading of the spec rule computed from the final held
//! set. Grants and re-seals re-writing boxes do not appear: the rule reads no box record.

use osis_base::CommitId;
use osis_crypto::Epoch;
use osis_keys::{Provenance, RoleEpochs, Superseded};
use proptest::prelude::*;
use std::collections::BTreeSet;

fn ep(n: u64, k: u8) -> Epoch {
    Epoch::new(n, [k; 32]).unwrap()
}

#[derive(Clone, Debug)]
struct Commit {
    id: CommitId,
    claims: Epoch,
    /// Its keyset's list: superseded epoch to the commits of it named.
    lists: Superseded,
    valid: bool,
}

#[derive(Clone, Debug)]
struct History {
    base: bool,
    snapshots: BTreeSet<Epoch>,
    commits: Vec<Commit>,
}

const LEVELS: u64 = 4;
const FORKS: u8 = 2;

fn history() -> impl Strategy<Value = History> {
    let commit = (2..=LEVELS, 0..FORKS, proptest::collection::vec((1..LEVELS, 0..FORKS, proptest::collection::vec(0u8..12, 0..3)), 0..3), proptest::bool::weighted(0.6));
    // forged: invalid claims with nothing listed, under IDs no list names (anyone can sign one)
    let forged = proptest::collection::vec((1..=LEVELS, 0..FORKS), 0..3);
    (any::<bool>(), proptest::collection::btree_set((1..=LEVELS, 0..FORKS), 0..2), proptest::collection::vec(commit, 1..12), forged).prop_map(|(base, snaps, cs, forged)| {
        let id = |i: usize| CommitId([i as u8 + 1; 32]);
        let claimed: Vec<Epoch> = cs.iter().map(|(n, k, _, _)| ep(*n, *k)).collect();
        let commits = cs
            .iter()
            .enumerate()
            .map(|(i, (n, k, rm, valid))| {
                let mut lists = Superseded::new();
                for (sn, sk, names) in rm {
                    let s = ep(*sn, *sk);
                    // mostly a commit claiming s, as an honest rotator lists; else any
                    let of_s: Vec<usize> = (0..claimed.len()).filter(|j| claimed[*j] == s).collect();
                    let named = names.iter().map(|c| match of_s.len() {
                        0 => id(*c as usize),
                        l if *c < 9 => id(of_s[*c as usize % l]),
                        _ => id(*c as usize),
                    });
                    lists.entry(s).or_default().extend(named);
                }
                Commit { id: id(i), claims: ep(*n, *k), lists, valid: *valid }
            })
            .chain(forged.iter().enumerate().map(|(i, (n, k))| Commit { id: CommitId([100 + i as u8; 32]), claims: ep(*n, *k), lists: Superseded::new(), valid: false }))
            .collect();
        History { base, snapshots: snaps.into_iter().map(|(n, k)| ep(n, k)).collect(), commits }
    })
}

/// spec/crypto.md §4 read directly over the final held set.
fn reference(h: &History) -> BTreeSet<Epoch> {
    let mut est: BTreeSet<Epoch> = h.snapshots.clone();
    if h.base {
        est.insert(ep(1, 0));
    }
    let below = |c: &Commit| -> Vec<(Epoch, BTreeSet<CommitId>)> { c.lists.iter().filter(|(s, _)| s.n() < c.claims.n()).map(|(s, n)| (*s, n.clone())).collect() };
    let mut settled: BTreeSet<CommitId> = BTreeSet::new();
    loop {
        let mut grew = false;
        for c in &h.commits {
            if settled.contains(&c.id) {
                continue;
            }
            let ok = below(c).iter().all(|(s, named)| {
                est.contains(s)
                    || (!named.is_empty()
                        && named.iter().all(|n| h.commits.iter().any(|x| x.id == *n && x.claims == *s && !x.valid && settled.contains(&x.id)))
                        && !h.commits.iter().any(|x| x.claims == *s && x.valid))
            });
            if ok {
                settled.insert(c.id);
                grew = true;
                if c.valid {
                    est.insert(c.claims);
                }
            }
        }
        if !grew {
            return est;
        }
    }
}

fn scratch(h: &History) -> RoleEpochs {
    let mut r = RoleEpochs::default();
    if h.base {
        r.set_established(ep(1, 0), Provenance::Fixed);
    }
    for s in &h.snapshots {
        r.set_snapshot(*s);
    }
    for c in &h.commits {
        r.set_claim(c.claims, c.id, c.valid, c.lists.clone());
    }
    r.establish();
    r
}

fn established(r: &RoleEpochs) -> BTreeSet<Epoch> {
    r.epochs().filter(|(_, i)| i.established.is_some()).map(|(e, _)| *e).collect()
}

proptest! {
    // spec/crypto.md §4: establishment is a function of the held claims and their verdicts,
    // whatever order they arrived in and however their verdicts flipped on the way.
    #[test]
    fn settled_claims_order_independent(h in history(), order in Just(()).prop_perturb(|_, mut rng| {
        let mut o: Vec<usize> = (0..16).collect();
        for i in (1..o.len()).rev() { o.swap(i, (rng.next_u32() as usize) % (i + 1)); }
        let flips: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 4) as u8).collect();
        (o, flips)
    })) {
        let (perm, flips) = order;
        let s = scratch(&h);
        prop_assert_eq!(established(&s), reference(&h));
        let mut r = RoleEpochs::default();
        if h.base {
            r.set_established(ep(1, 0), Provenance::Fixed);
        }
        let mut snaps = h.snapshots.iter();
        for &i in perm.iter().filter(|i| **i < h.commits.len()) {
            let c = &h.commits[i];
            // flips: 0 final at once; 1 the other verdict first; 2 valid, invalid, final; 3 twice
            let first = match flips[i] { 0 => c.valid, 1 => !c.valid, _ => true };
            r.set_claim(c.claims, c.id, first, c.lists.clone());
            r.establish();
            if flips[i] >= 2 {
                r.invalidate(&c.id);
                r.establish();
                if c.valid {
                    r.set_claim(c.claims, c.id, true, c.lists.clone());
                    r.establish();
                }
            } else if first != c.valid {
                if c.valid { r.set_claim(c.claims, c.id, true, c.lists.clone()); } else { r.invalidate(&c.id); }
                r.establish();
            }
            if let Some(x) = snaps.next() {
                r.set_snapshot(*x);
                r.establish();
            }
        }
        for x in snaps {
            r.set_snapshot(*x);
        }
        r.establish();
        prop_assert_eq!(established(&r), established(&s));
        prop_assert_eq!(r.current(), s.current(), "current differs: incremental {:?} scratch {:?}", r, s);
    }
}

// spec/crypto.md §4 (a forged claim passes nothing): R_s
// supersedes p, removing reader M; R_e supersedes s, its keyset listing R_s. A node holding R_e
// and F, a forged invalid claim of s (settled: it lists nothing), but not R_s (withheld; a
// granter's re-grant at s, whose removal may name F, counts for nothing) does not establish e,
// so never re-seals e to M, whom only R_s removed. Once R_s is held, valid, e is established;
// held and found invalid, e passes through it.
#[test]
fn forged_claim_passes_nothing() {
    let (p, s, e) = (ep(1, 0), ep(2, 0), ep(3, 0));
    let (rs, f, re) = (CommitId([1; 32]), CommitId([2; 32]), CommitId([3; 32]));
    let mut x = RoleEpochs::default();
    x.set_established(p, Provenance::Fixed);
    x.set_claim(s, f, false, Superseded::new());
    x.set_claim(e, re, true, Superseded::from([(s, BTreeSet::from([rs]))]));
    x.establish();
    assert!(!x.is_established(&e));
    assert_eq!(x.current(), vec![p]);
    let mut y = x.clone();
    y.set_claim(s, rs, true, Superseded::from([(p, BTreeSet::new())]));
    y.establish();
    assert_eq!(y.current(), vec![e]);
    y.invalidate(&rs);
    y.establish();
    assert_eq!(y.current(), vec![p, e]);
}
