//! Properties over random histories (held_model::gen).
use held_model::gen::{history, shuffle, Rng};
use held_model::*;
use std::collections::{BTreeMap, BTreeSet};

/// Reads with absent aspects left out (an aspect with nothing held is not listed).
pub fn reads(h: &Held) -> BTreeMap<(ThingId, Aspect), Read> {
    evaluate(h).reads.into_iter().filter(|(_, r)| *r != Read::Absent).collect()
}

/// Tier-1 budget; raise locally to hunt (3000 pass).
const SEEDS: u64 = 300;
const LEN: usize = 24;
/// Commit IDs of the covers `settle` writes (the generator's are below 1_000_001).
const COVER_ID: CommitId = 5_000_000;

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

/// Carries out every forced fate until nothing changes: `act`, the covering snapshots `me` owes
/// (spec/commits.md §5 history purge-on-replace), and, with `full`, the fetch again of bodies whose cover
/// or purge fell (`Outcome::uncovered`, `Fate::NeverReceived`; copies taken from `full`). Each
/// round changes no read. `gone` collects the aspects of parts that went at their expiry while
/// waiting (`DropWhy::Gone`): never fetched again (spec/commits.md §5).
fn settle(mut h: Held, full: Option<&Held>, seed: u64, gone: &mut BTreeSet<(ThingId, Aspect)>) -> Held {
    for round in 0..16 {
        let o = evaluate(&h);
        let mut n = act(&h, &o, None);
        let again: Vec<PartRef> = o.fates.iter().filter(|(_, f)| matches!(f, Fate::NeverReceived)).map(|(pr, _)| *pr).chain(o.uncovered.iter().copied()).collect();
        for (k, p) in h.commits.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| ((c.id, i), p))) {
            if o.fates.get(&k) == Some(&Fate::MustDrop(DropWhy::Gone)) {
                gone.insert((p.thing, p.aspect));
            }
        }
        let mut owed: Vec<(ThingId, Aspect)> = o.owed.iter().map(|&(c, i)| { let p = &h.commits.iter().find(|x| x.id == c).unwrap().parts[i]; (p.thing, p.aspect) }).collect();
        owed.sort();
        owed.dedup();
        let written = h.commits.iter().filter(|c| c.id >= COVER_ID).count() as CommitId;
        for (k, (t, a)) in owed.into_iter().enumerate() {
            let id = COVER_ID + written + k as CommitId;
            n.commits.push(cover(&h, &o, t, a, id, h.now * MS + 1 + written as u64 + k as u64));
        }
        // a part gone at its expiry or purge while waiting can make its commit apply (as a header
        // alone, its purge request with it): then reads may change; a drop or strip changes none
        if n != h && evaluate(&n).applied == o.applied {
            assert_eq!(reads(&n), reads(&h), "seed {seed} round {round}: forced fates changed a read");
        }
        if let Some(full) = full {
            for (c, i) in again {
                let src = &full.commits.iter().find(|x| x.id == c).unwrap().parts[i];
                let dst = &mut n.commits.iter_mut().find(|x| x.id == c).unwrap().parts[i];
                dst.body = src.body.clone();
                dst.stripped.clear();
            }
        }
        if n == h {
            return h;
        }
        h = n;
    }
    let o = evaluate(&h);
    let show: Vec<_> = h.commits.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| (c, i, p))).filter(|(c, i, _)| o.owed.contains(&(c.id, *i)) || o.uncovered.contains(&(c.id, *i)) || matches!(o.fates.get(&(c.id, *i)), Some(Fate::NeverReceived | Fate::MustDrop(_)))).map(|(c, i, p)| (c.id, c.kind, c.expires, p.retention, &p.body, o.fates.get(&(c.id, i)), o.owed.contains(&(c.id, i)), o.uncovered.contains(&(c.id, i)))).collect();
    panic!("seed {seed}: fates did not settle: {show:#?}\nstates {:?}", o.states);
}

// spec/commits.md §5 (Never received, Dropping a body), spec/crdt.md §4.7: dropping and stripping
// what the fates say changes no read, and leaves no value of a purged or expired write
#[test]
fn forced_fates_keep_reads_and_leave_no_forbidden_value_spec_commits_5() {
    for seed in 0..SEEDS {
        let h = settle(history(seed, LEN), None, seed, &mut BTreeSet::new());
        let o = evaluate(&h);
        assert!(o.forbidden.is_empty(), "seed {seed}: {:?}", o.forbidden);
    }
}

// spec/commits.md §5 (Covered): each drop a node may make changes no read
#[test]
fn optional_drops_keep_reads_spec_commits_5() {
    for seed in 0..SEEDS {
        let mut h = settle(history(seed, LEN), None, seed, &mut BTreeSet::new());
        for _ in 0..12 {
            let o = evaluate(&h);
            let Some((&pr, _)) = o.fates.iter().find(|(_, f)| matches!(f, Fate::MayDrop(_))) else { break };
            let n = act(&h, &o, Some(pr));
            assert_eq!(reads(&n), reads(&h), "seed {seed}: dropping {pr:?} ({:?}) changed a read", o.fates[&pr]);
            h = settle(n, None, seed, &mut BTreeSet::new());
        }
    }
}

/// Whether `me` holds the purge right over the body now.
fn right_now(h: &Held, c: &Commit, p: &Part) -> bool {
    timeline(h).right(h.me, h.me, (u64::MAX, h.me, u32::MAX), u32::MAX, p.retention.by, c.actor, p.thing)
}

// spec/commits.md §5 (history purge-on-replace, keep-at-least): once a node holding the right has acted, it
// holds no replaced purge-on-replace body (its covering snapshot dropped it), no body before its absolute
// keep-until is ever dropped but by purge or expiry, and history() shows no body the node may
// drop
#[test]
fn none_gone_once_replaced_and_kept_until_t_spec_commits_5() {
    for seed in 0..SEEDS {
        let h = settle(history(seed, LEN), None, seed, &mut BTreeSet::new());
        let o = evaluate(&h);
        assert!(o.owed.is_empty(), "seed {seed}: owed {:?}", o.owed);
        for c in &h.commits {
            for (i, p) in c.parts.iter().enumerate() {
                // a replaced purge-on-replace body a right holder still holds: a leftover (its own expiry or
                // purge), or before a purge request's floor
                if matches!(p.body, Body::Held(_)) && p.retention.history == History::PurgeOnReplace && o.replaced.contains(&(c.id, i)) && right_now(&h, c, p) {
                    let f = o.fates[&(c.id, i)];
                    assert!(matches!(f, Fate::Leftover(LeftoverWhy::Expired | LeftoverWhy::Purged) | Fate::Keep(KeepWhy::Until)), "seed {seed}: {} part {i} is replaced and held at a right holder as {f:?}", c.id);
                }
                if let Body::Dropped(by) = p.body {
                    let purged = h.commits.iter().any(|q| q.id == by && !q.purge.is_empty());
                    assert!(purged || h.now >= kept_until(c, p), "seed {seed}: {} part {i} dropped before its keep-until", c.id);
                }
                // history() shows a replaced write only while its body's bound keeps it, at every
                // node alike: no body the node may drop has an entry
                if matches!(o.fates.get(&(c.id, i)), Some(Fate::MayDrop(_) | Fate::MustDrop(_))) {
                    let entries = o.history.get(&(p.thing, p.aspect));
                    assert!(entries.is_none_or(|e| !e.iter().any(|x| x.1 == c.id)), "seed {seed}: {} part {i} may drop and is in history()", c.id);
                }
            }
        }
    }
}

/// Reads off the aspects in `gone`.
fn reads_off(h: &Held, gone: &BTreeSet<(ThingId, Aspect)>) -> BTreeMap<(ThingId, Aspect), Read> {
    reads(h).into_iter().filter(|(k, _)| !gone.contains(k)).collect()
}

// spec/requirements.md (Deterministic), spec/commits.md §5 (Covered), spec/permissions.md §5.2: a
// commit arriving after the node acted on the rest reads as one held from the start, once a body
// whose cover or purge fell is fetched again; a part gone at its expiry while waiting excepted
#[test]
fn late_commit_converges_after_repair_spec_commits_5() {
    for seed in 0..SEEDS {
        let full = history(seed, LEN);
        let late = (seed as usize * 7) % full.commits.len();
        let mut early = full.clone();
        let c = early.commits.remove(late);
        let mut gone = BTreeSet::new();
        let mut a = settle(early, Some(&full), seed, &mut gone);
        a.commits.insert(late, c);
        let a = settle(a, Some(&full), seed, &mut gone);
        let b = settle(full.clone(), Some(&full), seed, &mut gone);
        assert_eq!(reads_off(&a, &gone), reads_off(&b, &gone), "seed {seed}: late {:?}", full.commits[late]);
    }
}

// spec/requirements.md (Deterministic), spec/commits.md §5: nodes given the same commits one at a
// time in any order, each acting as they come, read alike once bodies whose cover or purge fell
// are fetched again; aspects where a part went at its expiry while waiting excepted
#[test]
fn arrival_orders_read_alike_after_repair_spec_commits_5() {
    for seed in 0..SEEDS / 3 {
        let full = history(seed, LEN);
        let mut gone = BTreeSet::new();
        let settled = settle(full.clone(), Some(&full), seed, &mut gone);
        for k in 0..2 {
            let mut order: Vec<usize> = (0..full.commits.len()).collect();
            Rng::new(seed * 5 + k).shuffle(&mut order);
            let mut h = Held { commits: vec![], ..full.clone() };
            for i in order {
                h.commits.push(full.commits[i].clone());
                h = settle(h, Some(&full), seed, &mut gone);
            }
            let want = reads_off(&settled, &gone);
            let got = reads_off(&h, &gone);
            if got != want {
                let diff: Vec<_> = got.keys().chain(want.keys()).filter(|k| got.get(k) != want.get(k)).map(|k| (k, got.get(k), want.get(k))).collect();
                let o = evaluate(&h);
                let bodies: Vec<_> = h.commits.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| (c, i, p))).filter(|(_, _, p)| diff.iter().any(|d| *d.0 == (p.thing, p.aspect))).map(|(c, i, p)| (c.id, c.kind, c.ts / MS - 1_000_000_000, p.retention, p.body.clone(), o.fates.get(&(c.id, i)).copied(), o.valid.get(&(c.id, i)).copied())).collect();
                panic!("seed {seed} order {k}: {diff:?}\n{bodies:#?}");
            }
        }
    }
}

// spec/commits.md §5, §6, spec/crdt.md §2.2: the clock changes the output only at the deadlines it
// lists (unparking, expiry, keep-until), so an adapter checking at each sees every change
#[test]
fn output_changes_only_at_its_deadlines_spec_commits_5() {
    for seed in 0..SEEDS {
        let h = settle(history(seed, LEN), None, seed, &mut BTreeSet::new());
        let mut o = evaluate(&h);
        let next = o.deadlines.first().copied();
        let mut later = h.clone();
        later.now = next.map_or(h.now + 1000 * HOUR, |d| h.now + (d - h.now - 1) / 2);
        let ol = evaluate(&later);
        o.deadlines.retain(|&d| d > later.now);
        assert_eq!(ol, o, "seed {seed}: output changed before its first deadline {next:?}");
    }
}



