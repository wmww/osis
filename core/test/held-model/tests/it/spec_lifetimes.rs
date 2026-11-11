//! Thing lifetimes by reference (issues/thing-lifetimes.md, held_model::lifetimes): the
//! judgment's properties, each over every small world, so a failure names a minimal counterexample.
use held_model::lifetimes::*;

fn set(xs: &[T]) -> Set {
    xs.iter().copied().collect()
}

fn subsets(of: &[T]) -> Vec<Set> {
    (0..1u32 << of.len()).map(|m| of.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, x)| *x).collect()).collect()
}

/// Every state of thing `x` among `n`: unknown, ended, or known with any list and references
/// (`own`: its own tid may be in either).
fn states(n: usize, x: T, own: bool, unknown: bool) -> Vec<Held> {
    let of: Vec<T> = (0..n).filter(|y| own || *y != x).collect();
    let mut out = vec![Held::Ended];
    if unknown {
        out.push(Held::Unknown);
    }
    for refs in subsets(&of) {
        out.push(Held::Known { list: None, refs: refs.clone() });
        for list in subsets(&of) {
            out.push(Held::Known { list: Some(list), refs: refs.clone() });
        }
    }
    out
}

fn views(n: usize, own: bool, unknown: bool) -> Vec<View> {
    let mut all: Vec<View> = vec![vec![]];
    for x in 0..n {
        let s = states(n, x, own, unknown);
        all = all.iter().flat_map(|v| s.iter().map(move |h| [v.clone(), vec![h.clone()]].concat())).collect();
    }
    all
}

fn known(list: Option<&[T]>, refs: &[T]) -> Held {
    Held::Known { list: list.map(set), refs: set(refs) }
}

#[test]
fn the_walk_up_judges_as_the_rule() {
    for v in views(3, true, true) {
        let u = unreachable(&v);
        for x in 0..3 {
            assert_eq!(walk(&v, x), u.contains(&x), "{v:?} thing {x}");
        }
    }
}

#[test]
fn with_everything_held_kept_is_what_standalone_things_reach() {
    for v in views(3, true, false) {
        assert_eq!(kept(&v), reached_down(&v), "{v:?}");
    }
}

#[test]
fn a_node_missing_things_never_drops_what_the_whole_view_keeps() {
    // also a retainer lost (read access gone, forgotten) or ended with nothing left to show it
    for v in views(3, false, true) {
        let u = unreachable(&v);
        for x in 0..3 {
            let mut less = v.clone();
            less[x] = Held::Unknown;
            let lu = unreachable(&less);
            assert!(lu.is_subset(&u), "{v:?} without {x}: drops {lu:?}, whole view {u:?}");
        }
    }
}

#[test]
fn cycles_drop_unless_a_standalone_thing_reaches_them() {
    // 1 and 2 keep each other; 0 is standalone
    let island = vec![known(None, &[]), known(Some(&[2]), &[2]), known(Some(&[1]), &[1])];
    assert_eq!(unreachable(&island), set(&[1, 2]));
    let reached = vec![known(None, &[1]), known(Some(&[0, 2]), &[2]), known(Some(&[1]), &[1])];
    assert_eq!(unreachable(&reached), set(&[]));
    // two concurrent rewrites, each fine alone, close a cycle: 1 moves under 2 while 2 moves under 1
    let before = vec![known(None, &[1, 2]), known(Some(&[0]), &[]), known(Some(&[0]), &[])];
    assert_eq!(unreachable(&before), set(&[]));
    let both = vec![known(None, &[]), known(Some(&[2]), &[2]), known(Some(&[1]), &[1])];
    assert_eq!(unreachable(&both), set(&[1, 2]));
    // a thing listing itself, and one with an empty list
    assert_eq!(unreachable(&vec![known(Some(&[0]), &[0]), known(Some(&[]), &[])]), set(&[0, 1]));
}

#[test]
fn an_ended_retainer_drops_and_an_unknown_one_keeps() {
    let v = |r: Held| vec![r, known(Some(&[0]), &[]), known(Some(&[1]), &[])];
    assert_eq!(unreachable(&v(Held::Ended)), set(&[1, 2]));
    assert_eq!(unreachable(&v(Held::Unknown)), set(&[2]));
    assert_eq!(unreachable(&v(known(None, &[1]))), set(&[2]));
}

fn commit(ts: u64, parts: &[Part]) -> Commit {
    Commit { ts, parts: parts.to_vec() }
}

fn held_subsets(c: &[Commit]) -> Vec<Vec<&Commit>> {
    (0..1u32 << c.len()).map(|m| c.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, c)| c).collect()).collect()
}

#[test]
fn a_move_in_one_commit_is_safe_part_received_and_in_two_is_not() {
    // 0, 1 standalone; 2 created under 0 in one commit; then moved under 1
    let base = [
        commit(1, &[Part::Create(0), Part::Create(1)]),
        commit(2, &[Part::Create(2), Part::List(2, Some(set(&[0]))), Part::Refs(0, set(&[2]))]),
    ];
    let one = [base.to_vec(), vec![commit(3, &[Part::List(2, Some(set(&[1]))), Part::Refs(1, set(&[2])), Part::Refs(0, set(&[]))])]].concat();
    for held in held_subsets(&one) {
        assert!(!unreachable(&view_of(3, &held)).contains(&2), "{held:?}");
    }
    let two = [
        base.to_vec(),
        vec![commit(3, &[Part::List(2, Some(set(&[0, 1]))), Part::Refs(1, set(&[2]))]), commit(4, &[Part::Refs(0, set(&[]))])],
    ]
    .concat();
    assert!(!unreachable(&view_of(3, &two.iter().collect::<Vec<_>>())).contains(&2));
    // the removal received before the earlier addition: judged now, 2 is dropped
    let part = [&two[0], &two[1], &two[3]];
    assert_eq!(unreachable(&view_of(3, &part)), set(&[2]));
}

#[test]
fn a_drop_is_final() {
    let c = [
        commit(1, &[Part::Create(0), Part::Create(1), Part::List(1, Some(set(&[0]))), Part::Refs(0, set(&[1]))]),
        commit(2, &[Part::Refs(0, set(&[]))]),
        commit(3, &[Part::End(1)]),
        // a re-reference written without the end, and a new retainer
        commit(4, &[Part::Refs(0, set(&[1])), Part::List(1, None)]),
    ];
    for held in held_subsets(&c) {
        if held.iter().any(|h| h.ts == 3) {
            assert_eq!(view_of(2, &held)[1], Held::Ended);
        }
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
    fn set(&mut self, n: usize) -> Set {
        let m = self.next(1 << n);
        (0..n).filter(|i| m & (1 << i) != 0).collect()
    }
    fn list(&mut self, n: usize) -> Option<Set> {
        (self.next(3) != 0).then(|| self.set(n))
    }
}

fn event(r: &mut Rng, n: usize) -> Event {
    let x = r.next(n);
    match r.next(13) {
        0 | 1 => Event::List(x, r.list(n)),
        2 | 3 => Event::Refs(x, r.set(n)),
        4 => Event::End(x),
        5 => Event::Expire(x),
        6 => Event::Released(x),
        7 => Event::Release(x),
        8 => Event::Forget(x),
        9 => Event::Lose(x),
        10 => Event::Learn(x, r.list(n), r.set(n)),
        11 => Event::Mint(x),
        _ => Event::Right(x, r.next(2) == 0),
    }
}

/// Over random runs of every change (lists, references, purges, expiries, release requests
/// received and written, forgetting, lost and learned things, stale copies, mintings, rights):
/// judging only what each change touches ends exactly what a from-scratch judgment says the
/// node may end, and `pending` is exactly the rest.
#[test]
fn judging_what_a_change_touches_matches_judging_everything() {
    const N: usize = 5;
    for seed in 1..=4000u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let mut node = Node::new(N);
        let mut log = Vec::new();
        for _ in 0..10 {
            // several changes judged together, as a node heard out judges its work list
            let mut own = Set::new();
            for _ in 0..1 + r.next(3) {
                let e = event(&mut r, N);
                log.push(e.clone());
                if let Event::Release(x) = e {
                    if matches!(node.view[x], Held::Known { .. }) && node.rights.contains(&x) {
                        own.insert(x);
                    }
                }
                node.apply(e);
            }
            log.push(Event::Right(usize::MAX, false)); // marks a settle in the log
            let before = unreachable(&node.view);
            let ended = node.settle();
            let want: Set = before.intersection(&node.rights).copied().chain(own).collect();
            assert_eq!(ended.iter().copied().collect::<Set>(), want, "seed {seed}: {log:?}");
            assert_eq!(node.pending, unreachable(&node.view), "seed {seed}: {log:?}");
            assert!(node.pending.is_disjoint(&node.rights), "seed {seed}: {log:?}");
        }
    }
}

/// Forgetting an ending never changes a judgment: it is forgotten only where no held thing lists
/// or references the thing, and nothing else reads it. So a node forgetting a request never
/// releases more, and never keeps what a node holding the request would release.
#[test]
fn forgetting_an_ending_changes_no_judgment() {
    const N: usize = 5;
    for seed in 1..=4000u64 {
        let mut r = Rng(seed.wrapping_mul(0x2545F4914F6CDD1D) | 1);
        let mut node = Node::new(N);
        let mut log = Vec::new();
        for _ in 0..14 {
            let e = event(&mut r, N);
            log.push(e.clone());
            let before = (unreachable(&node.view), kept(&node.view));
            let was = node.view.clone();
            node.apply(e.clone());
            if let Event::Forget(x) = e {
                assert_eq!((unreachable(&node.view), kept(&node.view)), before, "seed {seed}: {log:?}");
                if was[x] == Held::Ended && node.needs_evidence(x) {
                    assert_eq!(node.view[x], Held::Ended, "seed {seed}: {log:?}");
                }
            }
            node.settle();
        }
    }
}

/// A node losing a thing (access lost, forgotten) releases only what it released holding it.
#[test]
fn losing_a_thing_never_adds_a_release() {
    const N: usize = 5;
    for seed in 1..=4000u64 {
        let mut r = Rng(seed.wrapping_mul(0xD1B54A32D192ED03) | 1);
        let mut node = Node::new(N);
        for _ in 0..14 {
            let e = event(&mut r, N);
            let before = unreachable(&node.view);
            let lose = matches!(e, Event::Lose(_));
            node.apply(e);
            if lose {
                assert!(unreachable(&node.view).is_subset(&before), "seed {seed}");
            }
            node.settle();
        }
    }
}

/// An ending held is final against any later list, reference, stale copy or minting until it is
/// forgotten; a purge is never forgotten.
#[test]
fn an_ending_held_is_final_until_forgotten() {
    const N: usize = 4;
    for seed in 1..=4000u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 7 | 1);
        let mut node = Node::new(N);
        let mut ended: Vec<Option<bool>> = vec![None; N]; // Some(purged)
        let mut log = Vec::new();
        for _ in 0..16 {
            let e = event(&mut r, N);
            log.push(e.clone());
            node.apply(e.clone());
            for x in node.settle() {
                ended[x].get_or_insert(false);
            }
            match e {
                Event::End(x) => ended[x] = Some(true),
                Event::Expire(x) | Event::Released(x) => {
                    ended[x].get_or_insert(false);
                }
                Event::Lose(x) => ended[x] = None,
                Event::Forget(x) if ended[x] == Some(false) && node.view[x] != Held::Ended => ended[x] = None,
                _ => {}
            }
            for x in 0..N {
                if ended[x].is_some() {
                    assert_eq!(node.view[x], Held::Ended, "seed {seed} thing {x}: {log:?}");
                }
            }
        }
    }
}

#[test]
fn an_expired_retainers_child_is_released_where_the_child_is_held() {
    // 0 expires; 1 lists and is referenced by 0; 2 lists and is referenced by 1
    let mut node = Node::new(3);
    node.apply(Event::Learn(0, None, set(&[1])));
    node.apply(Event::Learn(1, Some(set(&[0])), set(&[2])));
    node.apply(Event::Learn(2, Some(set(&[1])), set(&[])));
    node.apply(Event::Right(1, true));
    node.apply(Event::Right(2, true));
    assert!(node.settle().is_empty());
    node.apply(Event::Expire(0));
    // the expiry's evidence is kept while 1 lists 0, so 1 reads 0 ended, not unknown
    node.apply(Event::Forget(0));
    assert_eq!(node.view[0], Held::Ended);
    assert_eq!(node.settle().into_iter().collect::<Set>(), set(&[1, 2]));
    // nothing holds 1 and 2 now (their own requests aside), so 0's evidence goes
    node.apply(Event::Forget(0));
    assert_eq!(node.view[0], Held::Unknown);
}

#[test]
fn an_explicit_release_takes_the_thing_and_what_only_it_kept_and_stays_while_referenced() {
    // 0 standalone references 1 (listing 0) and 3 (listing 0); 1 references 2 (listing 1) and 3
    let mut node = Node::new(4);
    node.apply(Event::Learn(0, None, set(&[1, 3])));
    node.apply(Event::Learn(1, Some(set(&[0])), set(&[2, 3])));
    node.apply(Event::Learn(2, Some(set(&[1])), set(&[])));
    node.apply(Event::Learn(3, Some(set(&[0])), set(&[])));
    for x in 1..4 {
        node.apply(Event::Right(x, true));
    }
    assert!(node.settle().is_empty());
    node.apply(Event::Release(1));
    assert_eq!(node.settle().into_iter().collect::<Set>(), set(&[1, 2]));
    // 0 still references 1: the request is kept, and a stale copy of 1 stays gone
    node.apply(Event::Forget(1));
    node.apply(Event::Learn(1, Some(set(&[0])), set(&[2])));
    node.apply(Event::Mint(1));
    assert_eq!(node.view[1], Held::Ended);
    // 0 drops the reference: the request is forgotten, and a stale copy comes back and is
    // released again
    node.apply(Event::Refs(0, set(&[3])));
    assert!(node.settle().is_empty());
    node.apply(Event::Forget(1));
    assert_eq!(node.view[1], Held::Unknown);
    node.apply(Event::Learn(1, Some(set(&[0])), set(&[])));
    assert_eq!(node.settle(), vec![1]);
    // a bare minting after the request is forgotten reads as standalone and lives
    node.apply(Event::Forget(1));
    node.apply(Event::Mint(1));
    assert!(node.settle().is_empty());
    assert_eq!(node.view[1], Held::Known { list: None, refs: set(&[]) });
}

#[test]
fn a_change_judges_what_it_touches() {
    // a standalone root over n single-retainer children, each with a child of its own:
    // unreferencing one child judges it and its child, at n and 10n alike
    let count = |n: usize| {
        let mut node = Node::new(1 + 2 * n);
        let kids: Set = (1..=n).collect();
        node.apply(Event::Learn(0, None, kids.clone()));
        for k in 1..=n {
            node.apply(Event::Learn(k, Some(set(&[0])), set(&[n + k])));
            node.apply(Event::Learn(n + k, Some(set(&[k])), set(&[])));
            node.apply(Event::Right(k, true));
            node.apply(Event::Right(n + k, true));
        }
        assert!(node.settle().is_empty());
        let at = node.judged;
        let mut less = kids;
        less.remove(&1);
        node.apply(Event::Refs(0, less));
        assert_eq!(node.settle(), vec![1, n + 1]);
        node.judged - at
    };
    assert_eq!(count(10), 2);
    assert_eq!(count(100), 2);
}

/// Changes judged together: 1 is pending (its retainer 0 does not reference it) when 0 starts
/// referencing it and 2, under 1, arrives; a walk from 2 reading pending 1 as failed would release
/// 2 before 1 is judged kept.
#[test]
fn a_stale_pending_thing_is_walked_through() {
    let mut node = Node::new(3);
    node.apply(Event::Learn(0, None, set(&[])));
    node.apply(Event::Learn(1, Some(set(&[0])), set(&[2])));
    node.apply(Event::Right(2, true));
    node.settle();
    assert_eq!(node.pending, set(&[1]));
    node.apply(Event::Refs(0, set(&[1])));
    node.apply(Event::Learn(2, Some(set(&[1])), set(&[])));
    assert_eq!(node.settle(), vec![]);
}
