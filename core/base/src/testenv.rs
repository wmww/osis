//! Test support (doc-hidden): the `OSIS_*` environment variables tests and harnesses read, and
//! seed ranges from them. Reading the environment is this crate's one exception to "no I/O"; only
//! tests call it.

use std::ops::Range;

/// The file listing every `OSIS_*` variable anything in the repo reads (tests, harnesses,
/// tools, binaries), one per line; tools/policy.py checks it against the sources. Read at run
/// time so adding a name rebuilds nothing.
pub const KNOWN_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testenv-known.txt");

/// The names in `KNOWN_FILE`, read once per process. A set variable not listed is a typo.
pub fn known() -> &'static [String] {
    static KNOWN: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    KNOWN.get_or_init(|| {
        let text = std::fs::read_to_string(KNOWN_FILE).unwrap_or_else(|e| panic!("reading {KNOWN_FILE}: {e}"));
        text.split_whitespace().map(String::from).collect()
    })
}

fn is_known(var: &str) -> bool {
    known().iter().any(|k| k == var)
}

/// Panics if a set `OSIS_*` variable is not in `known()` (a typo would silently run defaults).
/// The environment is scanned once per process.
pub fn check_known() {
    static UNKNOWN: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let unknown = UNKNOWN.get_or_init(|| {
        std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).filter(|k| k.starts_with("OSIS_") && !is_known(k)).collect()
    });
    assert!(unknown.is_empty(), "unknown environment variables {unknown:?} (known: core/base/testenv-known.txt)");
}

/// `var` as a decimal u64, `None` when unset or empty; panics when unparsable or not in `known()`,
/// and on any unknown `OSIS_*` variable. A set value is printed once per process, past libtest's
/// capture.
pub fn u64_var(var: &str) -> Option<u64> {
    assert!(is_known(var), "{var} is not in core/base/testenv-known.txt");
    check_known();
    let v = std::env::var(var).ok().filter(|v| !v.is_empty())?;
    let n = v.parse().unwrap_or_else(|_| panic!("{var}={v:?} is not a decimal u64"));
    static SEEN: std::sync::Mutex<std::collections::BTreeSet<String>> = std::sync::Mutex::new(std::collections::BTreeSet::new());
    if SEEN.lock().unwrap_or_else(|e| e.into_inner()).insert(var.to_string()) {
        visible(true, &format!("testenv: {var}={n}"));
    }
    Some(n)
}

/// A harness's seed range: `default`, or from `start_var` (first seed) and `seeds_var` (how
/// many). Panics on an unparsable value or zero seeds. `Display` says the range and which
/// variables set it; `announce` prints that.
#[derive(Clone, Debug)]
pub struct Seeds {
    pub range: Range<u64>,
    /// Either variable was set.
    pub overridden: bool,
    vars: String,
}

impl Seeds {
    pub fn from_env(start_var: &str, seeds_var: &str, default: Range<u64>) -> Seeds {
        let (start, n) = (u64_var(start_var), u64_var(seeds_var));
        let first = start.unwrap_or(default.start);
        let count = n.unwrap_or(default.end.saturating_sub(default.start));
        assert!(count > 0, "zero seeds ({seeds_var}={n:?}, default {default:?})");
        let set: Vec<String> = [(start_var, start), (seeds_var, n)].iter().filter_map(|(k, v)| v.map(|v| format!("{k}={v}"))).collect();
        let vars = if set.is_empty() { "defaults".to_string() } else { set.join(" ") };
        Seeds { range: first..first.checked_add(count).expect("seed range overflows u64"), overridden: start.is_some() || n.is_some(), vars }
    }

    /// Prints `name: <self>` on stderr; when overridden, past libtest's capture, so a passing run
    /// shows the range without `--nocapture`.
    pub fn announce(&self, name: &str) {
        visible(self.overridden, &format!("{name}: {self}"));
    }
}

impl std::fmt::Display for Seeds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} seeds from {} ({})", self.range.end - self.range.start, self.range.start, self.vars)
    }
}

/// `line` on stderr: written straight to the stream when `uncaptured` (libtest captures only
/// `eprintln!`), else through `eprintln!`.
pub fn visible(uncaptured: bool, line: &str) {
    if uncaptured {
        use std::io::Write;
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    } else {
        eprintln!("{line}");
    }
}

impl Seeds {
    /// `run_seeds` over this range, announced (`announce`), its summary past libtest's capture
    /// when overridden.
    pub fn run<T: Send>(&self, name: &str, replay: impl Fn(u64) -> String + Sync, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
        self.announce(name);
        let seeds: Vec<u64> = self.range.clone().collect();
        run_seeds(name, &seeds, self.overridden, replay, f)
    }
}

// The seed runner (notes/testing.md, Seed runners).

/// A thread per core, or the number in env `var`.
pub fn threads(var: &str) -> usize {
    u64_var(var).map_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()), |n| n as usize).max(1)
}

/// `f` over `items` on up to `threads` threads, results in order.
pub fn par_map<T: Send>(items: &[u64], threads: usize, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let threads = threads.clamp(1, items.len().max(1));
    let next = AtomicUsize::new(0);
    let (f, next) = (&f, &next);
    let mut out: Vec<(usize, T)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&x) = items.get(i) else { break };
                        mine.push((i, f(x)));
                    }
                    mine
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().expect("par_map thread")).collect()
    });
    out.sort_by_key(|x| x.0);
    out.into_iter().map(|x| x.1).collect()
}

/// `f`, a panic as an error.
pub fn caught<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|e| {
        let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
        Err(format!("panicked: {msg}"))
    })
}

/// Seconds one seed of `run_seeds` may run before it is marked hung (`OSIS_SEED_TIMEOUT_SECS`
/// overrides; 0 is refused). Minor consequence, test-only: near 0 every seed is hung; at
/// infinity a hung seed hangs the run silently. 600 s is far past any seed's cost (the slowest
/// take seconds even at load 30).
pub const SEED_TIMEOUT_SECS: u64 = 600;

/// Seconds between `run_seeds` progress lines. At 0 a line per wake; at infinity a long run is
/// silent until its summary.
const PROGRESS_SECS: u64 = 60;

/// Seconds `run_seeds` waits, before exiting on hung seeds, for each to print its backtrace at a
/// checkpoint. At 0 a seed marked hung just before the end never prints one; at infinity a seed
/// stuck below every checkpoint holds the exit. Checkpoints come per sync round (milliseconds).
const TRACE_GRACE_SECS: u64 = 10;

/// The seed a runner thread is on, for `checkpoint`.
struct SeedCtx {
    label: String,
    hung: std::sync::atomic::AtomicBool,
    traced: std::sync::atomic::AtomicBool,
    last: std::sync::Mutex<Option<(&'static std::panic::Location<'static>, std::time::Instant)>>,
}

impl SeedCtx {
    fn last(&self) -> String {
        match *self.last.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((at, t)) => format!("last checkpoint {at}, {} s ago", t.elapsed().as_secs()),
            None => "no checkpoint reached".to_string(),
        }
    }
}

thread_local! {
    static CURRENT: std::cell::RefCell<Option<std::sync::Arc<SeedCtx>>> = const { std::cell::RefCell::new(None) };
}

/// A point a harness passes often (a sync round, a settle loop). Inside a `run_seeds` seed it
/// records where the seed is; once the seed is marked hung, the first checkpoint it passes prints
/// its thread's backtrace past libtest's capture (another thread's stack cannot be read).
/// Outside a runner it does nothing.
#[track_caller]
pub fn checkpoint() {
    let at = std::panic::Location::caller();
    CURRENT.with(|c| {
        let Some(ctx) = c.borrow().clone() else { return };
        *ctx.last.lock().unwrap_or_else(|e| e.into_inner()) = Some((at, std::time::Instant::now()));
        if ctx.hung.load(std::sync::atomic::Ordering::Relaxed) && !ctx.traced.swap(true, std::sync::atomic::Ordering::Relaxed) {
            visible(true, &format!("{} (hung) at {at}:\n{}", ctx.label, std::backtrace::Backtrace::force_capture()));
        }
    });
}

/// `f(seed)` for every seed on `threads("OSIS_SEED_THREADS")` threads, a panic as its seed's
/// failure; results in seed order. Panics on no seeds. A seed running past
/// `SEED_TIMEOUT_SECS` is marked hung (named with `replay(seed)`; its backtrace at its next
/// `checkpoint`) and a new thread takes its place; a hung seed that ends later is still a failure.
/// Each failing or hung seed is printed with `replay(seed)` as it happens, a progress line every
/// `PROGRESS_SECS`, all past libtest's capture; then a summary line (past it when `visible`).
/// Then a panic listing every failure and hung seed in seed order. A hung thread cannot be
/// stopped or joined: if hung seeds are still running when the rest is done, or as many seeds
/// are hung as there are threads, the runner prints that list and exits the process (101).
pub fn run_seeds<T: Send>(name: &str, seeds: &[u64], visible_summary: bool, replay: impl Fn(u64) -> String + Sync, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};
    assert!(!seeds.is_empty(), "{name}: no seeds to run");
    let threads = threads("OSIS_SEED_THREADS").min(seeds.len());
    let limit_secs = u64_var("OSIS_SEED_TIMEOUT_SECS").unwrap_or(SEED_TIMEOUT_SECS);
    assert!(limit_secs > 0, "OSIS_SEED_TIMEOUT_SECS=0: every seed would be hung");
    let limit = Duration::from_secs(limit_secs);
    let t0 = Instant::now();
    let label = |seed: u64| format!("seed {seed} (replay: {})", replay(seed));
    struct State<T> {
        next: usize,
        /// index -> start, context
        running: BTreeMap<usize, (Instant, Arc<SeedCtx>)>,
        results: Vec<Option<Result<T, String>>>,
        /// marked hung (running or ended since)
        hung: BTreeSet<usize>,
        failed: usize,
        /// workers not on a hung seed
        live: usize,
        stop: bool,
    }
    let state = Mutex::new(State { next: 0, running: BTreeMap::new(), results: (0..seeds.len()).map(|_| None).collect(), hung: BTreeSet::new(), failed: 0, live: threads, stop: false });
    let lock = || state.lock().unwrap_or_else(|e| e.into_inner());
    let wake = Condvar::new();
    let (f, label, lock, wake) = (&f, &label, &lock, &wake);
    let worker = move || loop {
        let (i, seed, ctx) = {
            let mut g = lock();
            let i = g.next;
            let Some(&seed) = seeds.get(i).filter(|_| !g.stop) else {
                g.live -= 1;
                wake.notify_all();
                return;
            };
            g.next += 1;
            let ctx = Arc::new(SeedCtx { label: label(seed), hung: false.into(), traced: false.into(), last: Mutex::new(None) });
            g.running.insert(i, (Instant::now(), ctx.clone()));
            (i, seed, ctx)
        };
        CURRENT.with(|c| *c.borrow_mut() = Some(ctx.clone()));
        let r = caught(|| Ok(f(seed)));
        CURRENT.with(|c| *c.borrow_mut() = None);
        let mut g = lock();
        let (start, _) = g.running.remove(&i).expect("running");
        let was_hung = g.hung.contains(&i);
        let r = if was_hung {
            let end = match &r {
                Ok(_) => "passed".to_string(),
                Err(e) => format!("failed: {e}"),
            };
            Err(format!("hung: ran past {limit_secs} s; ended after {} s, {end}", start.elapsed().as_secs()))
        } else {
            r
        };
        if let Err(e) = &r {
            g.failed += usize::from(!was_hung);
            visible(true, &format!("{name}: {}: {e}\n", ctx.label));
        }
        if let Some(slot) = g.results.get_mut(i) {
            *slot = Some(r);
        }
        wake.notify_all();
        if was_hung {
            // replaced when it was marked
            return;
        }
    };
    let worker = &worker;
    let summary = |g: &State<T>| {
        let done = g.results.iter().filter(|r| r.is_some()).count();
        format!("{name}: {done} of {} seeds from {} run, {} failing, {} hung, {threads} threads, {:.1} s", seeds.len(), seeds.first().copied().unwrap_or(0), g.failed, g.hung.len(), t0.elapsed().as_secs_f64())
    };
    // every failure in seed order, with its replay line
    // `running`: the hung seeds still running
    let failures = |rs: &[Option<Result<T, String>>], running: &BTreeMap<usize, (Instant, Arc<SeedCtx>)>| -> Vec<String> {
        let why = |i: usize, r: &Option<Result<T, String>>| match r {
            Some(Ok(_)) => None,
            Some(Err(e)) => Some(e.clone()),
            None if running.contains_key(&i) => Some(format!("hung: ran past {limit_secs} s, still running")),
            None => Some("not run: the run stopped with every thread on a hung seed".to_string()),
        };
        rs.iter().zip(seeds).enumerate().filter_map(|(i, (r, s))| why(i, r).map(|e| format!("{}: {e}", label(*s)))).collect()
    };
    let results = std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(worker);
        }
        let mut g = lock();
        let mut progress = t0 + Duration::from_secs(PROGRESS_SECS);
        while g.live > 0 {
            let now = Instant::now();
            let late: Vec<(usize, Arc<SeedCtx>)> = g.running.iter().filter(|(i, (t, _))| !g.hung.contains(i) && now.duration_since(*t) >= limit).map(|(i, (_, ctx))| (*i, ctx.clone())).collect();
            for (i, ctx) in late {
                ctx.hung.store(true, Relaxed);
                g.hung.insert(i);
                g.live -= 1;
                visible(true, &format!("{name}: {} ran past {limit_secs} s (OSIS_SEED_TIMEOUT_SECS): hung, moving on ({}; its backtrace prints at its next checkpoint)\n", ctx.label, ctx.last()));
                let stuck = g.running.keys().filter(|i| g.hung.contains(i)).count();
                if stuck >= threads {
                    g.stop = true;
                } else {
                    g.live += 1;
                    s.spawn(worker);
                }
            }
            if now >= progress {
                visible(true, &format!("{} (running)", summary(&g)));
                progress += Duration::from_secs(PROGRESS_SECS);
            }
            let due = g.running.iter().filter(|(i, _)| !g.hung.contains(i)).map(|(_, (t, _))| *t + limit).min().map_or(progress, |d| d.min(progress));
            g = wake.wait_timeout(g, due.saturating_duration_since(Instant::now())).unwrap_or_else(|e| e.into_inner()).0;
        }
        if g.running.values().any(|(_, ctx)| !ctx.traced.load(Relaxed)) {
            // let the hung seeds reach a checkpoint and print their backtraces
            drop(g);
            let until = Instant::now() + Duration::from_secs(TRACE_GRACE_SECS);
            while Instant::now() < until && lock().running.values().any(|(_, ctx)| !ctx.traced.load(Relaxed)) {
                std::thread::sleep(Duration::from_millis(100));
            }
            g = lock();
        }
        let summary = summary(&g);
        let stuck: Vec<String> = g.running.values().map(|(t, ctx)| format!("  {} running {} s, {}", ctx.label, t.elapsed().as_secs(), ctx.last())).collect();
        if !stuck.is_empty() {
            let fails = failures(&g.results, &g.running);
            visible(true, &format!("{summary}\nfailures:\n{}\nstill running (hung; a thread cannot be stopped, so the process exits):\n{}", fails.join("\n\n"), stuck.join("\n")));
            std::process::exit(101);
        }
        visible(visible_summary, &summary);
        (std::mem::take(&mut g.results), summary)
    });
    let (results, summary) = results;
    let fails = failures(&results, &BTreeMap::new());
    if !fails.is_empty() {
        panic!("{summary}\n{} of {} seeds failed or hung:\n{}", fails.len(), seeds.len(), fails.join("\n\n"));
    }
    results.into_iter().flatten().flatten().collect()
}
