//! Properties over random histories (held_model::gen).
use held_model::gen::{history, shuffle, Rng};
use held_model::*;
use std::collections::{BTreeMap, BTreeSet};

/// Reads with absent aspects left out (an aspect with nothing held is not listed).
pub fn reads(h: &Held) -> BTreeMap<(ThingId, Aspect), Value> {
    evaluate(h).reads.into_iter().filter_map(|(k, r)| Some((k, r?))).collect()
}

/// The default tests' seeds before `covering` adds the generator's rarer shapes: a tenth of the
/// `_large` twins' small size.
const SEEDS: u64 = 30;
const LEN: usize = 24;
/// The `_large` twins' seeds: from `OSIS_HELD_START` (default 0), `OSIS_HELD_SEEDS` many, else 300,
/// 3000 under `OSIS_FULL=1` (notes/testing.md, Sizes). This crate reads the environment itself:
/// it depends on no osis crate.
fn large() -> Vec<u64> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")));
    let start = var("OSIS_HELD_START").unwrap_or(0);
    let n = var("OSIS_HELD_SEEDS").unwrap_or(if var("OSIS_FULL") == Some(1) { 3000 } else { 300 });
    assert!(n > 0, "zero seeds");
    eprintln!("held-model props: seeds {start}..{}", start + n);
    (start..start + n).collect()
}

/// Runs `f` on every seed of `seeds`, a thread per core; a failing seed's panic names it.
fn each(seeds: Vec<u64>, f: impl Fn(u64) + Sync) {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(seeds.len()).max(1);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(&seed) = seeds.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                f(seed);
            });
        }
    });
}

/// Commit IDs of the covers `settle` writes (the generator's are below 1_000_001).
const COVER_ID: CommitId = 5_000_000;

// spec/commits.md §4 (Order independence), spec/permissions.md §5: a function of the held set
#[test]
fn output_is_a_function_of_the_held_set_spec_commits_4() {
    output_is_a_function_of_the_held_set(covering(SEEDS, false));
}

#[test]
#[ignore = "property"]
fn output_is_a_function_of_the_held_set_large_spec_commits_4() {
    output_is_a_function_of_the_held_set(large());
}

fn output_is_a_function_of_the_held_set(seeds: Vec<u64>) {
    each(seeds, |seed| {
        let h = history(seed, LEN);
        let o = evaluate(&h);
        for k in 0..3 {
            assert_eq!(evaluate(&shuffle(&h, seed.wrapping_mul(7).wrapping_add(k))), o, "seed {seed}");
        }
    });
}

/// Carries out every forced fate until nothing changes: `act`, the covering snapshots `me` owes
/// (spec/commits.md §5 Purge on replace), and, with `full`, the fetch again of bodies whose cover
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
            // valid (spec/permissions.md §6), and one thrown out as unknown once it is known
            // (notes/expiry-creation-design.md §3): a part `full` holds of any held commit, valid
            // where its commit applied, unless held it would go again (expired, purged past its
            // bound, covered, still unknown)
            let mut again = again;
            for c in &h.commits {
                // the covers `settle` wrote are not in `full`, and never missing
                let Some(fc) = full.commits.iter().find(|x| x.id == c.id) else { continue };
                for (i, p) in c.parts.iter().enumerate() {
                    let src = &fc.parts[i];
                    let valid = !o.applied.contains(&c.id) || o.valid.get(&(c.id, i)) == Some(&true);
                    if p.body == Body::Missing && matches!(src.body, Body::Held(_)) && valid {
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

/// Whether `me` holds the purge right over the body now.
fn right_now(h: &Held, c: &Commit, p: &Part) -> bool {
    timeline(h).right(h.me, h.me, (u64::MAX, h.me, u32::MAX), u32::MAX, p.retention.by, c.actor, p.thing)
}

// One settled history per seed, four properties of it:
// spec/commits.md §5 (Never received, Dropping a body), spec/crdt.md §4.7: dropping and stripping
// what the fates say changes no read, and leaves no value of a purged or expired write.
// spec/commits.md §5 (purge on replace, keep at least; The setting): once a node
// holding the right has acted, it holds no body under purge on replace (its covering snapshot
// dropped it), no body is dropped before a purge request's floor but by purge, and history()
// shows no body the node may drop.
// spec/commits.md §5, §6, spec/crdt.md §2.2: the clock changes the output only at the deadlines it
// lists (unparking, expiry, a body leaving history), so an adapter checking at each sees every change.
// spec/commits.md §5 (Covered, Signals): each drop a node may make changes no read and no
// history(): a covered body, and a signal's out of history, read alike held or not.
#[test]
fn settled_histories_keep_their_laws_spec_commits_5() {
    settled_histories_keep_their_laws(covering(SEEDS, false));
}

#[test]
#[ignore = "property"]
fn settled_histories_keep_their_laws_large_spec_commits_5() {
    settled_histories_keep_their_laws(large());
}

fn settled_histories_keep_their_laws(seeds: Vec<u64>) {
    let past_bound = std::sync::atomic::AtomicUsize::new(0);
    each(seeds, |seed| {
        let h = settle(history(seed, LEN), None, seed, &mut Seen::default());
        let o = evaluate(&h);
        assert!(o.forbidden.is_empty(), "seed {seed}: {:?}", o.forbidden);
        purge_on_replace_gone(&h, &o, seed);
        changes_only_at_deadlines(&h, o, seed);
        past_bound.fetch_add(optional_drops_keep_reads(h, seed), std::sync::atomic::Ordering::Relaxed);
    });
    assert!(past_bound.into_inner() > 0, "no signal dropped past its bound");
}

/// Once a node holding the right has acted, no body under purge on replace is held, none dropped
/// before its floor but by purge, none it may drop in history().
fn purge_on_replace_gone(h: &Held, o: &Outcome, seed: u64) {
    assert!(o.owed.is_empty(), "seed {seed}: owed {:?}", o.owed);
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            // a body under purge on replace a right holder still holds: a leftover (its own
            // expiry or purge), or before a purge request's floor
            if matches!(p.body, Body::Held(_)) && o.under_purge.contains(&(c.id, i)) && right_now(h, c, p) {
                let f = o.fates[&(c.id, i)];
                assert!(matches!(f, Fate::Leftover(LeftoverWhy::Expired | LeftoverWhy::Purged) | Fate::Keep(KeepWhy::Until)), "seed {seed}: {} part {i} is replaced and held at a right holder as {f:?}", c.id);
            }
            if let Body::Dropped(by) = p.body {
                let purged = h.commits.iter().any(|q| q.id == by && !q.purge.is_empty());
                assert!(purged || h.now >= kept_until(c), "seed {seed}: {} part {i} dropped before its purge floor", c.id);
            }
            // history() shows a replaced write only while the settings keep it, at every node
            // alike: no body the node may drop has an entry
            if matches!(o.fates.get(&(c.id, i)), Some(Fate::MayDrop(_) | Fate::MustDrop(_))) {
                let entries = o.history.get(&(p.thing, p.aspect));
                assert!(entries.is_none_or(|e| !e.iter().any(|x| x.1 == c.id)), "seed {seed}: {} part {i} may drop and is in history()", c.id);
            }
        }
    }
}

/// The output is unchanged just before its first deadline.
fn changes_only_at_deadlines(h: &Held, mut o: Outcome, seed: u64) {
    let next = o.deadlines.first().copied();
    let mut later = h.clone();
    later.now = next.map_or(h.now + 1000 * HOUR, |d| h.now + (d - h.now - 1) / 2);
    let ol = evaluate(&later);
    o.deadlines.retain(|&d| d > later.now);
    assert_eq!(ol, o, "seed {seed}: output changed before its first deadline {next:?}");
}

/// Each optional drop in turn changes no read and no history(); the drops past their bound.
fn optional_drops_keep_reads(mut h: Held, seed: u64) -> usize {
    let mut past_bound = 0;
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
    past_bound
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
    late_commit_converges_after_repair(covering(SEEDS, true));
}

#[test]
#[ignore = "property"]
fn late_commit_converges_after_repair_large_spec_commits_5() {
    late_commit_converges_after_repair(large());
}

fn late_commit_converges_after_repair(seeds: Vec<u64>) {
    each(seeds, |seed| {
        let full = history(seed, LEN);
        let late = late_of(seed, &full);
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
    });
}

// spec/requirements.md (Deterministic), spec/commits.md §5 (Signals): nodes given the same commits one at a
// time in any order, each acting as they come, read alike once bodies whose cover or purge fell
// are fetched again; aspects where a part went at its expiry while waiting excepted
#[test]
fn arrival_orders_read_alike_after_repair_spec_commits_5() {
    arrival_orders_read_alike_after_repair(covering(SEEDS / 3, false));
}

#[test]
#[ignore = "property"]
fn arrival_orders_read_alike_after_repair_large_spec_commits_5() {
    let seeds = large();
    arrival_orders_read_alike_after_repair(seeds[..seeds.len().div_ceil(3)].to_vec());
}

fn arrival_orders_read_alike_after_repair(seeds: Vec<u64>) {
    each(seeds, |seed| {
        let full = history(seed, LEN);
        let mut first = Seen::default();
        let settled = settle(full.clone(), Some(&full), seed, &mut first);
        let mut gone = first.gone;
        for k in 0..2 {
            let mut order: Vec<usize> = (0..full.commits.len()).collect();
            Rng::new(seed.wrapping_mul(5).wrapping_add(k)).shuffle(&mut order);
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
    });
}

// notes/expiry-creation-design.md §3 (Throw out and revisit), spec/commits.md §4: a node given
// every write before the creations of their things reads, once the creations come and it fetches
// again what it threw out, as one given the creations first
#[test]
fn creations_last_read_like_creations_first_spec_commits_4() {
    creations_last_read_like_creations_first(covering(SEEDS / 3, false));
}

#[test]
#[ignore = "property"]
fn creations_last_read_like_creations_first_large_spec_commits_4() {
    let seeds = large();
    creations_last_read_like_creations_first(seeds[..seeds.len().div_ceil(3)].to_vec());
}

fn creations_last_read_like_creations_first(seeds: Vec<u64>) {
    each(seeds, |seed| {
        let full = history(seed, LEN);
        let (made, rest): (Vec<Commit>, Vec<Commit>) = full.commits.iter().cloned().partition(held_model::gen::creates);
        let mut seen = Seen::default();
        let mut h = settle(Held { commits: rest, ..full.clone() }, Some(&full), seed, &mut seen);
        // a thing known by a raw record (the account) exists before its creation: a record is identity
        let raw = |t: &ThingId| full.records.iter().any(|r| r.id == *t);
        assert!(evaluate(&h).reads.iter().all(|((t, _), r)| r.is_none() || raw(t)), "seed {seed}: nothing exists before its creation");
        let more: Vec<Commit> = made.into_iter().filter(|c| !h.commits.iter().any(|x| x.id == c.id)).collect();
        h.commits.extend(more);
        let h = settle(h, Some(&full), seed, &mut seen);
        let mut other = Seen::default();
        let first = settle(full.clone(), Some(&full), seed, &mut other);
        seen.gone.extend(other.gone);
        assert_eq!(reads_off(&h, &seen.gone), reads_off(&first, &seen.gone), "seed {seed}");
    });
}

/// The shapes `histories_reach_endings_unknown_things_and_settings` asks the generator for.
const SHAPES: [&str; 8] = ["expiry", "purge", "unknown", "late setting", "invalid setting", "history", "signal history", "purge on replace"];

/// The commit `late_commit_converges_after_repair` withholds from `h`, seed's history.
fn late_of(seed: u64, h: &Held) -> usize {
    (seed % h.commits.len() as u64 * 7) as usize % h.commits.len()
}

/// What seed's history reaches, by name: each of `SHAPES` (things ended by expiry and by purge,
/// parts thrown out as unknown, a late and an invalid setting, a body in history, a signal's, a
/// body under purge on replace), a body a node may drop as covered, and the fate of each part of
/// the commit `late_of` withholds.
fn kinds(seed: u64) -> BTreeSet<String> {
    let h = history(seed, LEN);
    let o = evaluate(&h);
    let settings = || h.commits.iter().enumerate().filter(|(_, c)| c.parts.iter().any(|p| p.aspect == Aspect::RETENTION));
    let ended = |by_expiry: bool| {
        o.ended.iter().any(|&t| {
            let c = h.commits.iter().find(|c| c.id == held_model::gen::CREATION_ID + t).unwrap();
            c.expires.is_some_and(|x| h.now >= x) == by_expiry
        })
    };
    let reached = [
        ended(true),
        ended(false),
        o.fates.values().any(|f| *f == Fate::MustDrop(DropWhy::Unknown)),
        // late: stamped before a commit written before it
        settings().any(|(i, c)| h.commits[..i].iter().any(|x| x.ts > c.ts)),
        settings().any(|(_, c)| o.valid.get(&(c.id, 0)) == Some(&false)),
        o.history.keys().any(|k| !k.1.signal),
        o.history.keys().any(|k| k.1.signal),
        !o.under_purge.is_empty(),
    ];
    let mut k: BTreeSet<String> = SHAPES.iter().zip(reached).filter(|x| x.1).map(|x| x.0.to_string()).collect();
    let kind = |f: &Fate| match f {
        Fate::MayDrop(DropWhy::Covered { .. }) => "MayDrop(Covered)".to_string(),
        Fate::MustDrop(DropWhy::Covered { .. }) => "MustDrop(Covered)".to_string(),
        f => format!("{f:?}"),
    };
    if o.fates.values().any(|f| matches!(f, Fate::MayDrop(DropWhy::Covered { .. }))) {
        k.insert("covered drop".into());
    }
    let late = h.commits[late_of(seed, &h)].id;
    k.extend(o.fates.iter().filter(|(r, _)| r.0 == late).map(|(_, f)| format!("withheld {}", kind(f))));
    k
}

/// `kinds` of seeds 0..300, the `_large` twins' small size.
fn reach() -> &'static [BTreeSet<String>] {
    static REACH: std::sync::OnceLock<Vec<BTreeSet<String>>> = std::sync::OnceLock::new();
    REACH.get_or_init(|| {
        let out = std::sync::Mutex::new(vec![BTreeSet::new(); 300]);
        each((0..300).collect(), |seed| {
            let k = kinds(seed);
            out.lock().unwrap_or_else(|e| e.into_inner())[seed as usize] = k;
        });
        out.into_inner().unwrap_or_else(|e| e.into_inner())
    })
}

/// A default test's seeds: 0..n, then the first seeds below `10 * n` (the width its `_large` twin
/// runs at small size) that bring every kind those seeds reach (`kinds`; the withheld commit's
/// fates only with `late`) to two seeds, or to as many as reach it: the default test meets every
/// shape the twin's first seeds meet.
fn covering(n: u64, late: bool) -> Vec<u64> {
    let seen: Vec<BTreeSet<&String>> = reach()[..10 * n as usize].iter().map(|k| k.iter().filter(|k| late || !k.starts_with("withheld ")).collect()).collect();
    let mut left: BTreeMap<&String, usize> = BTreeMap::new();
    for &k in seen.iter().flatten() {
        *left.entry(k).or_default() += 1;
    }
    left.values_mut().for_each(|v| *v = (*v).min(2));
    let mut set = Vec::new();
    for (seed, here) in seen.iter().enumerate() {
        if (seed as u64) < n || here.iter().any(|k| left[k] > 0) {
            set.push(seed as u64);
            here.iter().for_each(|k| *left.get_mut(k).unwrap() = left[k].saturating_sub(1));
        }
    }
    set
}

// spec: none (the generator's reach): the histories end things by expiry and by purge, throw
// parts out on things a node holds no creation of, and hold settings (late ones, invalid ones),
// bodies in history (signals too) and bodies under purge on replace, each in at least one seed in
// a hundred
#[test]
fn histories_reach_endings_unknown_things_and_settings() {
    let seen = &reach()[..100];
    let count = |what: &str| seen.iter().filter(|k| k.contains(what)).count();
    eprintln!("of 100: {:?}", SHAPES.iter().map(|w| (w, count(w))).collect::<Vec<_>>());
    for what in SHAPES {
        assert!(count(what) > 0, "{what}: none of 100");
    }
}
