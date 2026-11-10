//! Properties over random histories (held_model::gen).
use held_model::gen::{history, shuffle, Rng};
use held_model::*;
use std::collections::{BTreeMap, BTreeSet};

/// Reads with absent aspects left out (an aspect with nothing held is not listed).
pub fn reads(h: &Held) -> BTreeMap<(ThingId, Aspect), Value> {
    evaluate(h).reads.into_iter().filter_map(|(k, r)| Some((k, r?))).collect()
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
/// or purge fell (`Outcome::uncovered`, `Fate::NeverReceived`) or that turned valid again after
/// their drop as invalid (copies taken from `full`). Each
/// round changes no read. Commits thrown out whole are fetched again from `full` each round
/// (`Outcome::revisit`), as are an ended thing's parts: an ending that falls (a demotion of its
/// purger arriving later) is repaired like any purge that falls.
fn settle(mut h: Held, full: Option<&Held>, seed: u64, seen: &mut Seen) -> Held {
    for round in 0..16 {
        let o = evaluate(&h);
        let mut n = act(&h, &o, None);
        seen.revisit.extend(o.revisit.iter().copied());
        let again: Vec<PartRef> = o.fates.iter().filter(|(_, f)| matches!(f, Fate::NeverReceived)).map(|(pr, _)| *pr).chain(o.uncovered.iter().copied()).collect();
        for (k, p) in h.commits.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| ((c.id, i), p))) {
            if o.fates.get(&k) == Some(&Fate::MustDrop(DropWhy::Gone)) {
                seen.gone.insert((p.thing, p.aspect));
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
            // a body dropped as invalid is missing from then on, so fetched again once it turns
            // valid (spec/permissions.md §6): a valid part of an applied commit `full` holds,
            // unless held it would go again (expired, purged past its bound, covered)
            let mut again = again;
            for c in h.commits.iter().filter(|c| o.applied.contains(&c.id)) {
                // the covers `settle` wrote are not in `full`, and never missing
                let Some(fc) = full.commits.iter().find(|x| x.id == c.id) else { continue };
                for (i, p) in c.parts.iter().enumerate() {
                    let src = &fc.parts[i];
                    if p.body == Body::Missing && matches!(src.body, Body::Held(_)) && o.valid.get(&(c.id, i)) == Some(&true) {
                        let mut t = h.clone();
                        t.commits.iter_mut().find(|x| x.id == c.id).unwrap().parts[i].body = src.body.clone();
                        if !matches!(evaluate(&t).fates.get(&(c.id, i)), Some(Fate::MustDrop(_) | Fate::NeverReceived)) {
                            again.push((c.id, i));
                        }
                    }
                }
            }
            for (c, i) in again {
                let src = &full.commits.iter().find(|x| x.id == c).unwrap().parts[i];
                let Some(dst) = n.commits.iter_mut().find(|x| x.id == c) else { continue };
                let dst = &mut dst.parts[i];
                dst.body = src.body.clone();
                dst.stripped.clear();
            }
            for &id in &seen.revisit {
                let Some(c) = full.commits.iter().find(|x| x.id == id) else { continue };
                if !n.commits.iter().any(|x| x.id == id) {
                    n.commits.push(c.clone());
                }
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
        let h = settle(history(seed, LEN), None, seed, &mut Seen::default());
        let o = evaluate(&h);
        assert!(o.forbidden.is_empty(), "seed {seed}: {:?}", o.forbidden);
    }
}

// spec/commits.md §5 (Covered, Signals): each drop a node may make changes no read and no
// history(): a covered body, and a signal's past its keep bound, read alike held or not
#[test]
fn optional_drops_keep_reads_spec_commits_5() {
    let mut past_bound = 0;
    for seed in 0..SEEDS {
        let mut h = settle(history(seed, LEN), None, seed, &mut Seen::default());
        for _ in 0..12 {
            let o = evaluate(&h);
            let Some((&pr, _)) = o.fates.iter().find(|(_, f)| matches!(f, Fate::MayDrop(_))) else { break };
            past_bound += usize::from(o.fates[&pr] == Fate::MayDrop(DropWhy::PastBound));
            let n = act(&h, &o, Some(pr));
            let on = evaluate(&n);
            let some = |o: &Outcome| o.reads.iter().filter(|(_, r)| r.is_some()).map(|(k, r)| (*k, r.clone())).collect::<BTreeMap<_, _>>();
            assert_eq!(some(&on), some(&o), "seed {seed}: dropping {pr:?} ({:?}) changed a read", o.fates[&pr]);
            assert_eq!(on.history, o.history, "seed {seed}: dropping {pr:?} ({:?}) changed history()", o.fates[&pr]);
            h = settle(n, None, seed, &mut Seen::default());
        }
    }
    assert!(past_bound > 0, "no signal dropped past its bound");
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
        let h = settle(history(seed, LEN), None, seed, &mut Seen::default());
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

/// What a node has seen across settles: the aspects of parts that went at their expiry while
/// waiting (`DropWhy::Gone`), never fetched again (spec/commits.md §5); the commits it threw out
/// whole, to fetch again.
#[derive(Default)]
struct Seen {
    gone: BTreeSet<(ThingId, Aspect)>,
    revisit: BTreeSet<CommitId>,
}

/// Reads off the aspects in `gone`.
fn reads_off(h: &Held, gone: &BTreeSet<(ThingId, Aspect)>) -> BTreeMap<(ThingId, Aspect), Value> {
    reads(h).into_iter().filter(|(k, _)| !gone.contains(k)).collect()
}

/// `history()` of the signals off the aspects in `gone`: what a signal shows instead of a
/// read (spec/commits.md §5 Signals).
fn signal_history(h: &Held, gone: &BTreeSet<(ThingId, Aspect)>) -> BTreeMap<(ThingId, Aspect), BTreeSet<(Stamp, CommitId)>> {
    evaluate(h).history.into_iter().filter(|(k, _)| k.1.signal && !gone.contains(k)).collect()
}

// spec/requirements.md (Deterministic), spec/commits.md §5 (Covered, Signals), spec/permissions.md §5.2: a
// commit arriving after the node acted on the rest reads as one held from the start, once a body
// whose cover or purge fell is fetched again; a part gone at its expiry while waiting excepted
#[test]
fn late_commit_converges_after_repair_spec_commits_5() {
    for seed in 0..SEEDS {
        let full = history(seed, LEN);
        let late = (seed as usize * 7) % full.commits.len();
        let mut early = full.clone();
        let c = early.commits.remove(late);
        let mut seen = Seen::default();
        let mut a = settle(early, Some(&full), seed, &mut seen);
        if !a.commits.iter().any(|x| x.id == c.id) {
            a.commits.insert(late.min(a.commits.len()), c);
        }
        let a = settle(a, Some(&full), seed, &mut seen);
        let mut other = Seen::default();
        let b = settle(full.clone(), Some(&full), seed, &mut other);
        seen.gone.extend(other.gone);
        assert_eq!(reads_off(&a, &seen.gone), reads_off(&b, &seen.gone), "seed {seed}: late {:?}", full.commits[late]);
        assert_eq!(signal_history(&a, &seen.gone), signal_history(&b, &seen.gone), "seed {seed}: late {:?}", full.commits[late]);
    }
}

// spec/requirements.md (Deterministic), spec/commits.md §5 (Signals): nodes given the same commits one at a
// time in any order, each acting as they come, read alike once bodies whose cover or purge fell
// are fetched again; aspects where a part went at its expiry while waiting excepted
#[test]
fn arrival_orders_read_alike_after_repair_spec_commits_5() {
    for seed in 0..SEEDS / 3 {
        let full = history(seed, LEN);
        let mut first = Seen::default();
        let settled = settle(full.clone(), Some(&full), seed, &mut first);
        let mut gone = first.gone;
        for k in 0..2 {
            let mut order: Vec<usize> = (0..full.commits.len()).collect();
            Rng::new(seed * 5 + k).shuffle(&mut order);
            let mut h = Held { commits: vec![], ..full.clone() };
            let mut seen = Seen::default();
            for i in order {
                // a commit thrown out whole was fetched again already
                if !h.commits.iter().any(|c| c.id == full.commits[i].id) {
                    h.commits.push(full.commits[i].clone());
                }
                h = settle(h, Some(&full), seed, &mut seen);
            }
            gone.extend(seen.gone);
            assert_eq!(signal_history(&h, &gone), signal_history(&settled, &gone), "seed {seed} order {k}");
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
        let h = settle(history(seed, LEN), None, seed, &mut Seen::default());
        let mut o = evaluate(&h);
        let next = o.deadlines.first().copied();
        let mut later = h.clone();
        later.now = next.map_or(h.now + 1000 * HOUR, |d| h.now + (d - h.now - 1) / 2);
        let ol = evaluate(&later);
        o.deadlines.retain(|&d| d > later.now);
        assert_eq!(ol, o, "seed {seed}: output changed before its first deadline {next:?}");
    }
}




// notes/expiry-creation-design.md §3 (Throw out and revisit), spec/commits.md §4: a node given
// every write before the creations of their things reads, once the creations come and it fetches
// again what it threw out, as one given the creations first
#[test]
fn creations_last_read_like_creations_first_spec_commits_4() {
    for seed in 0..SEEDS / 3 {
        let full = history(seed, LEN);
        let (made, rest): (Vec<Commit>, Vec<Commit>) = full.commits.iter().cloned().partition(held_model::gen::creates);
        let mut seen = Seen::default();
        let mut h = settle(Held { commits: rest, ..full.clone() }, Some(&full), seed, &mut seen);
        assert!(evaluate(&h).reads.values().all(|r| r.is_none()), "seed {seed}: nothing exists before its creation");
        let more: Vec<Commit> = made.into_iter().filter(|c| !h.commits.iter().any(|x| x.id == c.id)).collect();
        h.commits.extend(more);
        let h = settle(h, Some(&full), seed, &mut seen);
        let mut other = Seen::default();
        let first = settle(full.clone(), Some(&full), seed, &mut other);
        seen.gone.extend(other.gone);
        assert_eq!(reads_off(&h, &seen.gone), reads_off(&first, &seen.gone), "seed {seed}");
    }
}

// spec: none (the generator's reach): the histories end things by expiry and by purge, and
// throw parts out on things a node holds no creation of, in a share of seeds that does not
// depend on the run's size
#[test]
fn histories_reach_endings_and_unknown_things() {
    let (mut expired, mut purged, mut thrown) = (0, 0, 0);
    for seed in 0..SEEDS {
        let h = history(seed, LEN);
        let o = evaluate(&h);
        for &t in &o.ended {
            let c = h.commits.iter().find(|c| c.id == held_model::gen::CREATION_ID + t).unwrap();
            if c.expires.is_some_and(|x| h.now >= x) {
                expired += 1;
            } else {
                purged += 1;
            }
        }
        thrown += o.fates.values().any(|f| *f == Fate::MustDrop(DropWhy::Unknown)) as u64;
    }
    eprintln!("of {SEEDS}: {expired} ended by expiry, {purged} by purge, {thrown} throwing parts out");
    for (what, n) in [("expiry", expired), ("purge", purged), ("unknown", thrown)] {
        assert!(n * 100 >= SEEDS, "{what}: {n} of {SEEDS}");
    }
}

