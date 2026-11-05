//! Properties over random histories (held_model::gen).
use held_model::gen::{history, shuffle};
use held_model::*;
use std::collections::BTreeMap;

/// Reads with absent aspects left out (an aspect with nothing held is not listed).
pub fn reads(h: &Held) -> BTreeMap<(ThingId, Aspect), Read> {
    evaluate(h).reads.into_iter().filter(|(_, r)| *r != Read::Absent).collect()
}

/// Tier-1 budget; raise locally to hunt (3000 pass).
const SEEDS: u64 = 300;
const LEN: usize = 24;

// spec/commits.md §4 (Order independence), spec/permissions.md §5: a function of the held set
#[test]
fn output_is_a_function_of_the_held_set_spec_commits_4() {
    for seed in 0..SEEDS {
        let h = history(seed, LEN);
        let o = evaluate(&h);
        for k in 0..3 {
            assert_eq!(evaluate(&shuffle(&h, seed * 7 + k)), o, "seed {seed}");
        }
    }
}

/// Carries out every forced fate until nothing changes.
fn settle(mut h: Held, seed: u64) -> Held {
    for round in 0..8 {
        let o = evaluate(&h);
        let n = act(&h, &o, None);
        if n == h {
            return h;
        }
        assert_eq!(reads(&n), reads(&h), "seed {seed} round {round}: forced fates changed a read");
        h = n;
    }
    panic!("seed {seed}: fates did not settle");
}

// spec/commits.md §5 (Never received, Dropping a body), spec/crdt.md §4.7: dropping and stripping
// what the fates say changes no read, and leaves no value of a purged or expired write
#[test]
fn forced_fates_keep_reads_and_leave_no_forbidden_value_spec_commits_5() {
    for seed in 0..SEEDS {
        let h = settle(history(seed, LEN), seed);
        let o = evaluate(&h);
        assert!(o.forbidden.is_empty(), "seed {seed}: {:?}", o.forbidden);
    }
}

// spec/commits.md §5 (Between the bounds, Keep at most): each drop a node may make changes no read
#[test]
fn optional_drops_keep_reads_spec_commits_5() {
    for seed in 0..SEEDS {
        let mut h = settle(history(seed, LEN), seed);
        for _ in 0..12 {
            let o = evaluate(&h);
            let Some((&pr, _)) = o.fates.iter().find(|(_, f)| matches!(f, Fate::MayDrop(_))) else { break };
            let n = act(&h, &o, Some(pr));
            assert_eq!(reads(&n), reads(&h), "seed {seed}: dropping {pr:?} ({:?}) changed a read", o.fates[&pr]);
            h = settle(n, seed);
        }
    }
}

/// Aspects some delta of which has a keep-at-most bound or an expiry.
fn bounded(h: &Held) -> std::collections::BTreeSet<(ThingId, Aspect)> {
    h.commits
        .iter()
        .flat_map(|c| c.parts.iter().filter(move |p| c.expires.is_some() || p.retention.has_most()).map(|p| (p.thing, p.aspect)))
        .collect()
}

// spec/requirements.md (Deterministic; its keep-at-most limit), spec/commits.md §5 (Never received):
// a commit arriving after the node acted on the rest reads as one held from the start, but on
// aspects with a keep-at-most bound or expiry
#[test]
fn late_commit_converges_off_bounded_aspects_spec_commits_5() {
    for seed in 0..SEEDS {
        let full = history(seed, LEN);
        let late = (seed as usize * 7) % full.commits.len();
        let mut early = full.clone();
        let c = early.commits.remove(late);
        let mut a = settle(early, seed);
        a.commits.insert(late, c);
        let a = settle(a, seed);
        let b = settle(full.clone(), seed);
        let skip = bounded(&full);
        let ra: BTreeMap<_, _> = reads(&a).into_iter().filter(|(k, _)| !skip.contains(k)).collect();
        let rb: BTreeMap<_, _> = reads(&b).into_iter().filter(|(k, _)| !skip.contains(k)).collect();
        assert_eq!(ra, rb, "seed {seed}: late {:?}", full.commits[late]);
    }
}

