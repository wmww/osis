//! Phase timers for scale tests. A thread records spans once it has called `take` (tests call it
//! to reset before measuring); until then every span is one thread-local read. Always compiled, so
//! test and non-test builds share one set of artifacts. Spans nest and count inclusively, per thread.
//!
//! A world stepping many nodes on one thread splits each phase by node: the harness holds `node(i)`
//! while it steps node `i`, and each phase is also recorded under `"{name} @node {i}"`. `by_caller`
//! splits chosen phases by the call path that reached them (`"{name} <- f <- g"`), the answer a
//! backtrace probe gave.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    /// `paused` calls running on this thread.
    static PAUSED: Cell<u32> = const { Cell::new(0) };
    static COSTS: RefCell<BTreeMap<&'static str, (Duration, u64)>> = const { RefCell::new(BTreeMap::new()) };
    static SCOPE: Cell<Option<&'static str>> = const { Cell::new(None) };
    static NODE: Cell<Option<usize>> = const { Cell::new(None) };
    static CALLERS: RefCell<Vec<(&'static str, usize)>> = const { RefCell::new(Vec::new()) };
    static LABELS: RefCell<HashMap<(&'static str, Label), &'static str>> = RefCell::default();
}

/// What a phase's split label adds to its name.
#[derive(PartialEq, Eq, Hash)]
enum Label {
    Node(usize),
    By(&'static str),
    Callers(String),
}

/// The interned `&'static str` naming phase `name` split by `key` (each made once per thread).
fn label(name: &'static str, key: Label) -> &'static str {
    LABELS.with(|l| {
        *l.borrow_mut().entry((name, key)).or_insert_with_key(|(n, k)| {
            Box::leak(match k {
                Label::Node(i) => format!("{n} @node {i}"),
                Label::By(by) => format!("{n} <- {by}"),
                Label::Callers(path) => format!("{n}{path}"),
            }.into_boxed_str())
        })
    })
}

/// Records `f` on phase `name`, then on its node's and caller's labels when those are on.
fn record(name: &'static str, f: impl Fn(&mut (Duration, u64))) {
    COSTS.with(|c| {
        let mut c = c.borrow_mut();
        f(c.entry(name).or_default());
        if let Some(i) = NODE.with(Cell::get) {
            f(c.entry(label(name, Label::Node(i))).or_default());
        }
    });
    let depth = CALLERS.with(|c| c.borrow().iter().find(|x| x.0 == name).map(|x| x.1));
    if let Some(depth) = depth {
        let path = callers(depth);
        COSTS.with(|c| f(c.borrow_mut().entry(label(name, Label::Callers(path))).or_default()));
    }
}

/// `" <- f <- g"`: the `depth` functions calling the one that recorded, innermost first. A
/// backtrace's frames, each a name line and an `at FILE:LINE` line; this module's recording
/// functions and std's are skipped, as are symbol hashes. A tail call leaves no frame.
fn callers(depth: usize) -> String {
    const OWN: &[&str] = &["callers", "record", "count", "peak", "count_by", "count_scoped", "drop"];
    let bt = std::backtrace::Backtrace::force_capture().to_string();
    let mut frames = Vec::new();
    for l in bt.lines().map(str::trim_start) {
        if let Some(at) = l.strip_prefix("at ") {
            if let Some((_, file)) = frames.last_mut() {
                *file = at;
            }
        } else if let Some((n, name)) = l.split_once(": ")
            && n.chars().all(|c| c.is_ascii_digit())
        {
            let name = name.rsplit_once("::h").filter(|(_, h)| h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit())).map_or(name, |x| x.0);
            frames.push((name, ""));
        }
    }
    let short = |name: &str| name.split("::<").next().unwrap_or(name).rsplit("::").next().unwrap_or(name).to_string();
    let std = |name: &str, file: &str| file.starts_with("/rustc/") || ["std::", "core::", "alloc::", "<core::", "<alloc::", "<std::"].iter().any(|p| name.starts_with(p));
    let own = |name: &str, file: &str| file.split(':').next().is_some_and(|f| f.ends_with("src/costs.rs")) && OWN.contains(&short(name).as_str());
    frames.iter().skip_while(|(n, f)| own(n, f) || std(n, f)).filter(|(n, f)| !std(n, f)).skip(1).take(depth).fold(String::new(), |s, (n, _)| s + " <- " + n)
}

/// While the returned guard lives, every phase this thread records is also recorded under
/// `"{name} @node {i}"`. Set where a harness steps node `i`; nests (the inner node wins).
pub fn node(i: usize) -> NodeGuard {
    NodeGuard(on().then(|| NODE.with(|n| n.replace(Some(i)))))
}

pub struct NodeGuard(Option<Option<usize>>);

impl Drop for NodeGuard {
    fn drop(&mut self) {
        if let Some(was) = self.0 {
            NODE.with(|n| n.set(was));
        }
    }
}

/// From now on this thread records phase `name` also under `"{name} <- f <- g"`, the `depth`
/// functions calling the one that recorded it: a backtrace per record, so for a probe, not a
/// suite. `take` keeps the choice.
pub fn by_caller(name: &'static str, depth: usize) {
    CALLERS.with(|c| c.borrow_mut().push((name, depth)));
}

pub struct Span(Option<(&'static str, Instant)>);

#[inline]
pub fn span(name: &'static str) -> Span {
    Span(ON.with(Cell::get).then(|| (name, Instant::now())))
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some((name, start)) = self.0 {
            let d = start.elapsed();
            record(name, |e| {
                e.0 += d;
                e.1 += 1;
            });
        }
    }
}

/// Adds `n` to phase `name`'s count, with no time: work counted by size, not by call.
pub fn count(name: &'static str, n: u64) {
    if ON.with(Cell::get) {
        record(name, |e| e.1 += n);
    }
}

/// Raises phase `name`'s count to `n` where below it: the most held at once, not a sum.
pub fn peak(name: &'static str, n: u64) {
    if ON.with(Cell::get) {
        record(name, |e| e.1 = e.1.max(n));
    }
}

/// Whether this thread records (tests that `take`): a diagnostic costing more than a count runs
/// only then.
pub fn on() -> bool {
    ON.with(Cell::get)
}

/// `count` under `"{name} <- {by}"`: what moved a phase, per cause (each label made once).
pub fn count_by(name: &'static str, by: &'static str, n: u64) {
    if on() {
        count(label(name, Label::By(by)), n);
    }
}

/// Runs `f` with `count_scoped` counting under its innermost scope too: which module's work a
/// shared counter (store rows) is.
pub fn scoped<T>(scope: &'static str, f: impl FnOnce() -> T) -> T {
    if !on() {
        return f();
    }
    let was = SCOPE.with(|c| c.replace(Some(scope)));
    let r = f();
    SCOPE.with(|c| c.set(was));
    r
}

/// `count`, and `count_by` under the innermost `scoped` scope if any.
pub fn count_scoped(name: &'static str, n: u64) {
    count(name, n);
    if let Some(scope) = SCOPE.with(Cell::get) {
        count_by(name, scope, n);
    }
}

/// The time and count per phase since the last `take` on this thread; the first call turns
/// recording on for this thread (and returns nothing).
pub fn take() -> Vec<(&'static str, Duration, u64)> {
    ON.with(|on| on.set(true));
    COSTS.with(|c| std::mem::take(&mut *c.borrow_mut()).into_iter().map(|(k, (d, n))| (k, d, n)).collect())
}

/// Runs `f` with this thread's recording off (debug checks: their work is not the measured code's).
pub fn paused<T>(f: impl FnOnce() -> T) -> T {
    struct Unpause(bool);
    impl Drop for Unpause {
        fn drop(&mut self) {
            ON.with(|on| on.set(self.0));
            PAUSED.with(|p| p.set(p.get() - 1));
        }
    }
    PAUSED.with(|p| p.set(p.get() + 1));
    let _r = Unpause(ON.with(|on| on.replace(false)));
    f()
}

/// Whether this thread runs inside `paused` (a debug check): what it does there changes no count
/// of the measured code's, including which follows that code's own writes owe (`memo::Quiet`).
pub fn pausing() -> bool {
    PAUSED.with(|p| p.get() > 0)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn counted() -> BTreeMap<&'static str, u64> {
        take().into_iter().map(|(k, _, n)| (k, n)).collect()
    }

    // each call followed by more work, so none is a tail call (which leaves no frame)
    #[inline(never)]
    fn work() {
        count("work", 1);
        std::hint::black_box(());
    }

    #[inline(never)]
    fn from_a() {
        work();
        std::hint::black_box(());
    }

    #[inline(never)]
    fn from_b() {
        work();
        std::hint::black_box(());
    }

    // spec: none (internal: notes/test-harnesses.md, Counting)
    /// One thread stepping two nodes: each phase split by the node stepped, outside any node only
    /// the total; a span counts like a count.
    #[test]
    fn counts_split_by_node() {
        take();
        count("work", 1);
        {
            let _n = node(0);
            count("work", 2);
            let _s = span("step");
        }
        {
            let _n = node(1);
            count("work", 5);
            let _inner = node(0);
            count("work", 7);
        }
        count("work", 1);
        assert_eq!(counted(), BTreeMap::from([("step", 1), ("step @node 0", 1), ("work", 16), ("work @node 0", 9), ("work @node 1", 5)]));
        // off until `take`: no node is recorded
        std::thread::spawn(|| {
            let _n = node(3);
            count("work", 1);
            assert_eq!(NODE.with(Cell::get), None);
        })
        .join()
        .unwrap();
    }

    // spec: none (internal: notes/test-harnesses.md, Counting)
    /// `by_caller` splits a phase by the functions calling the one that recorded it.
    #[test]
    fn counts_split_by_caller() {
        take();
        by_caller("work", 1);
        from_a();
        from_a();
        from_b();
        count("other", 1);
        let got = counted();
        let by: BTreeMap<_, _> = got.iter().filter(|(k, _)| k.starts_with("work <- ")).map(|(k, n)| (k.rsplit([' ', ':']).next().unwrap(), *n)).collect();
        assert_eq!((got["work"], by), (3, BTreeMap::from([("from_a", 2), ("from_b", 1)])), "{got:?}");
        CALLERS.with(|c| c.borrow_mut().clear());
    }
}
