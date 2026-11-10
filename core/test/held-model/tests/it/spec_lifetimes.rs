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

#[test]
fn judging_what_a_change_touches_matches_judging_everything() {
    const N: usize = 5;
    for seed in 1..=4000u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let mut node = Node::new(N);
        let mut log = Vec::new();
        for _ in 0..14 {
            let x = r.next(N);
            let e = match r.next(8) {
                0 | 1 => Event::List(x, r.list(N)),
                2 | 3 => Event::Refs(x, r.set(N)),
                4 => Event::End(x),
                5 => Event::Lose(x),
                6 => Event::Learn(x, r.list(N), r.set(N)),
                _ => Event::Right(x, r.next(2) == 0),
            };
            log.push(e.clone());
            node.apply(e);
            let before = unreachable(&node.view);
            let ended = node.settle();
            // it ends exactly what it may end of what the whole view judges unreachable, and
            // remembers the rest
            let want: Set = before.intersection(&node.rights).copied().collect();
            assert_eq!(ended.iter().copied().collect::<Set>(), want, "seed {seed}: {log:?}");
            assert_eq!(node.pending, unreachable(&node.view), "seed {seed}: {log:?}");
            assert!(node.pending.is_disjoint(&node.rights), "seed {seed}: {log:?}");
        }
    }
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
