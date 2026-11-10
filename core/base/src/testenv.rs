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

/// A property's small size, the gate's (notes/testing.md, Sizes): a tenth of its large size, at
/// least 1; the large size under `OSIS_FULL=1` (periodic runs). Breadth belongs to periodic runs:
/// per-branch runs at large size found few bugs for their cost (notes/testing.md, What finds bugs).
pub fn large_n(full: u64) -> u64 {
    if u64_var("OSIS_FULL") == Some(1) { full } else { (full / 10).max(1) }
}

/// [`large_n`] for a default seed range: the same start, a tenth of the seeds unless `OSIS_FULL=1`.
pub fn large(full: Range<u64>) -> Range<u64> {
    full.start..full.start + large_n(full.end.saturating_sub(full.start))
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

/// A job of `run_jobs` (a seed of `run_seeds`) is marked hung once its thread has used this many CPU-seconds on it
/// (a livelock), or has used no CPU at all for this many seconds (a deadlock); where a thread's
/// CPU time cannot be read (not Linux), once it has run this many seconds of wall time.
/// `OSIS_SEED_TIMEOUT_SECS` overrides; 0 is refused. CPU time, not wall time: a seed starved by
/// load (a `nice 19` run beside others at load 30-50 took 701 s for a 5 CPU-s seed) is not
/// hung. Only the seed's thread counts: a seed waiting on threads it spawned reads as blocked
/// (seeds are single-threaded). Minor consequence, test-only: near 0 every seed is hung; at
/// infinity a hung seed hangs the run silently. 600 is far past any seed's cost (the slowest
/// take seconds).
pub const SEED_TIMEOUT_SECS: u64 = 600;

/// The calling thread's CPU clock: its `/proc` schedstat file, `None` where there is none.
fn thread_clock() -> Option<std::path::PathBuf> {
    let task = std::fs::read_link("/proc/thread-self").ok()?;
    let clock = std::path::Path::new("/proc").join(task).join("schedstat");
    cpu_ns(&clock).map(|_| clock)
}

/// Nanoseconds the thread of `clock` (from `thread_clock`) has run on a CPU; `None` once the
/// thread is gone.
fn cpu_ns(clock: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(clock).ok()?.split_whitespace().next()?.parse().ok()
}

/// Seconds between `run_jobs` progress lines. At 0 a line per wake; at infinity a long run is
/// silent until its summary.
const PROGRESS_SECS: u64 = 60;

/// Seconds `run_jobs` waits, before exiting on hung jobs, for each to print its backtrace at a
/// checkpoint. At 0 a job marked hung just before the end never prints one; at infinity a job
/// stuck below every checkpoint holds the exit. Checkpoints come per sync round (milliseconds).
const TRACE_GRACE_SECS: u64 = 10;

/// The job a runner thread is on, for `checkpoint`.
struct JobCtx {
    label: String,
    hung: std::sync::atomic::AtomicBool,
    traced: std::sync::atomic::AtomicBool,
    last: std::sync::Mutex<Option<(&'static std::panic::Location<'static>, std::time::Instant)>>,
}

impl JobCtx {
    fn last(&self) -> String {
        match *self.last.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((at, t)) => format!("last checkpoint {at}, {} s ago", t.elapsed().as_secs()),
            None => "no checkpoint reached".to_string(),
        }
    }
}

thread_local! {
    static CURRENT: std::cell::RefCell<Option<std::sync::Arc<JobCtx>>> = const { std::cell::RefCell::new(None) };
}

/// A point a harness passes often (a sync round, a settle loop). Inside a `run_jobs` job it
/// records where the job is; once the job is marked hung, the first checkpoint it passes prints
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

/// A job being run.
struct Run {
    start: std::time::Instant,
    ctx: std::sync::Arc<JobCtx>,
    /// its thread's CPU clock (`thread_clock`), and that clock at the start
    clock: Option<(std::path::PathBuf, u64)>,
    /// the CPU clock last read, and when it was last seen to move
    cpu: u64,
    moved: std::time::Instant,
}

impl Run {
    /// Why the job is hung at `now`, or else the earliest instant it could be: CPU time
    /// grows no faster than wall time, and a clock unmoved since `moved` stays so at best.
    fn judge(&mut self, now: std::time::Instant, limit: std::time::Duration) -> Result<std::time::Instant, String> {
        let limit_secs = limit.as_secs();
        let Some(cpu) = self.clock.as_ref().and_then(|(c, _)| cpu_ns(c)) else {
            return if now >= self.start + limit { Err(format!("ran past {limit_secs} s")) } else { Ok(self.start + limit) };
        };
        if cpu != self.cpu {
            (self.cpu, self.moved) = (cpu, now);
        }
        let used = std::time::Duration::from_nanos(cpu.saturating_sub(self.clock.as_ref().map_or(0, |c| c.1)));
        if used >= limit {
            return Err(format!("used {limit_secs} CPU-s"));
        }
        if now >= self.moved + limit {
            return Err(format!("used no CPU for {limit_secs} s"));
        }
        Ok((now + (limit - used)).min(self.moved + limit))
    }
}

/// `f(seed)` for every seed on `threads("OSIS_SEED_THREADS")` threads, a panic as its seed's
/// failure; results in seed order (`run_jobs`, each seed named with `replay(seed)`). Panics on no
/// seeds, then, after the summary, with every failure and hung seed in seed order.
pub fn run_seeds<T: Send>(name: &str, seeds: &[u64], visible_summary: bool, replay: impl Fn(u64) -> String + Sync, f: impl Fn(u64) -> T + Sync) -> Vec<T> {
    let label = |seed: &u64| format!("seed {seed} (replay: {})", replay(*seed));
    let results = run_jobs(name, seeds, threads("OSIS_SEED_THREADS"), visible_summary, label, |seed| f(*seed));
    let fails: Vec<String> = results.iter().zip(seeds).filter_map(|(r, s)| r.as_ref().err().map(|e| format!("{}: {e}", label(s)))).collect();
    if !fails.is_empty() {
        panic!("{name}: {} of {} seeds failed or hung:\n{}", fails.len(), seeds.len(), fails.join("\n\n"));
    }
    results.into_iter().flatten().collect()
}

/// `f(job)` for every job on `threads` threads, a panic as its job's failure; results in job
/// order, `Err` for a failed or hung job. Panics on no jobs. A job past `SEED_TIMEOUT_SECS` (CPU
/// time, or no CPU at all; see there) is marked hung (named with `label(job)`; its backtrace at
/// its next `checkpoint`) and a new thread takes its place; a hung job that ends later is still a
/// failure. Each failing or hung job is printed with its label as it happens, a progress line
/// every `PROGRESS_SECS`, all past libtest's capture; then a summary line (past it when
/// `visible_summary`). A hung thread cannot be stopped or joined: if hung jobs are still running
/// when the rest is done, or as many jobs are hung as there are threads, the runner prints every
/// failure and hung job and exits the process (101).
pub fn run_jobs<J: Sync, T: Send>(name: &str, jobs: &[J], threads: usize, visible_summary: bool, label: impl Fn(&J) -> String + Sync, f: impl Fn(&J) -> T + Sync) -> Vec<Result<T, String>> {
    use std::collections::BTreeMap;
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};
    assert!(!jobs.is_empty(), "{name}: no jobs to run");
    let threads = threads.clamp(1, jobs.len());
    let limit_secs = u64_var("OSIS_SEED_TIMEOUT_SECS").unwrap_or(SEED_TIMEOUT_SECS);
    assert!(limit_secs > 0, "OSIS_SEED_TIMEOUT_SECS=0: every seed would be hung");
    let limit = Duration::from_secs(limit_secs);
    let t0 = Instant::now();
    struct State<T> {
        next: usize,
        /// by job index
        running: BTreeMap<usize, Run>,
        results: Vec<Option<Result<T, String>>>,
        /// marked hung (running or ended since), and why
        hung: BTreeMap<usize, String>,
        failed: usize,
        /// workers not on a hung job
        live: usize,
        stop: bool,
    }
    let state = Mutex::new(State { next: 0, running: BTreeMap::new(), results: (0..jobs.len()).map(|_| None).collect(), hung: BTreeMap::new(), failed: 0, live: threads, stop: false });
    let lock = || state.lock().unwrap_or_else(|e| e.into_inner());
    let wake = Condvar::new();
    let (f, label, lock, wake) = (&f, &label, &lock, &wake);
    let worker = move || {
        let clock = thread_clock();
        loop {
            let (i, job, ctx) = {
                let mut g = lock();
                let i = g.next;
                let Some(job) = jobs.get(i).filter(|_| !g.stop) else {
                    g.live -= 1;
                    wake.notify_all();
                    return;
                };
                g.next += 1;
                let ctx = Arc::new(JobCtx { label: label(job), hung: false.into(), traced: false.into(), last: Mutex::new(None) });
                let clock = clock.as_ref().and_then(|c| Some((c.clone(), cpu_ns(c)?)));
                let now = Instant::now();
                g.running.insert(i, Run { start: now, ctx: ctx.clone(), cpu: clock.as_ref().map_or(0, |c| c.1), clock, moved: now });
                (i, job, ctx)
            };
            CURRENT.with(|c| *c.borrow_mut() = Some(ctx.clone()));
            let r = caught(|| Ok(f(job)));
            CURRENT.with(|c| *c.borrow_mut() = None);
            let mut g = lock();
            let run = g.running.remove(&i).expect("running");
            let why = g.hung.get(&i).cloned();
            let r = match &why {
                Some(why) => {
                    let end = match &r {
                        Ok(_) => "passed".to_string(),
                        Err(e) => format!("failed: {e}"),
                    };
                    Err(format!("hung: {why}; ended after {} s, {end}", run.start.elapsed().as_secs()))
                }
                None => r,
            };
            if let Err(e) = &r {
                g.failed += usize::from(why.is_none());
                visible(true, &format!("{name}: {}: {e}\n", ctx.label));
            }
            if let Some(slot) = g.results.get_mut(i) {
                *slot = Some(r);
            }
            wake.notify_all();
            if why.is_some() {
                // replaced when it was marked
                return;
            }
        }
    };
    let worker = &worker;
    let summary = |g: &State<T>| {
        let done = g.results.iter().filter(|r| r.is_some()).count();
        format!("{name}: {done} of {} run, {} failing, {} hung, {threads} threads, {:.1} s", jobs.len(), g.failed, g.hung.len(), t0.elapsed().as_secs_f64())
    };
    // every failure in job order, with its replay line
    let failures = |g: &State<T>| -> Vec<String> {
        let why = |i: usize, r: &Option<Result<T, String>>| match r {
            Some(Ok(_)) => None,
            Some(Err(e)) => Some(e.clone()),
            None => Some(match g.hung.get(&i) {
                Some(why) => format!("hung: {why}, still running"),
                None => "not run: the run stopped with every thread on a hung job".to_string(),
            }),
        };
        g.results.iter().zip(jobs).enumerate().filter_map(|(i, (r, s))| why(i, r).map(|e| format!("{}: {e}", label(s)))).collect()
    };
    let results = std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(worker);
        }
        let mut g = lock();
        let mut progress = t0 + Duration::from_secs(PROGRESS_SECS);
        while g.live > 0 {
            let now = Instant::now();
            let mut due = progress;
            let mut late = Vec::new();
            let st = &mut *g;
            for (i, run) in st.running.iter_mut().filter(|(i, _)| !st.hung.contains_key(i)) {
                match run.judge(now, limit) {
                    Ok(t) => due = due.min(t),
                    Err(why) => late.push((*i, run.ctx.clone(), why)),
                }
            }
            for (i, ctx, why) in late {
                ctx.hung.store(true, Relaxed);
                visible(true, &format!("{name}: {} {why} (OSIS_SEED_TIMEOUT_SECS): hung, moving on ({}; its backtrace prints at its next checkpoint)\n", ctx.label, ctx.last()));
                g.hung.insert(i, why);
                g.live -= 1;
                let stuck = g.running.keys().filter(|i| g.hung.contains_key(i)).count();
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
            g = wake.wait_timeout(g, due.saturating_duration_since(Instant::now())).unwrap_or_else(|e| e.into_inner()).0;
        }
        if g.running.values().any(|r| !r.ctx.traced.load(Relaxed)) {
            // let the hung jobs reach a checkpoint and print their backtraces
            drop(g);
            let until = Instant::now() + Duration::from_secs(TRACE_GRACE_SECS);
            while Instant::now() < until && lock().running.values().any(|r| !r.ctx.traced.load(Relaxed)) {
                std::thread::sleep(Duration::from_millis(100));
            }
            g = lock();
        }
        let summary = summary(&g);
        let fails = failures(&g);
        let stuck: Vec<String> = g.running.values().map(|r| format!("  {} running {} s, {}", r.ctx.label, r.start.elapsed().as_secs(), r.ctx.last())).collect();
        if !stuck.is_empty() {
            visible(true, &format!("{summary}\nfailures:\n{}\nstill running (hung; a thread cannot be stopped, so the process exits):\n{}", fails.join("\n\n"), stuck.join("\n")));
            std::process::exit(101);
        }
        visible(visible_summary, &summary);
        std::mem::take(&mut g.results)
    });
    results.into_iter().map(|r| r.unwrap_or_else(|| Err("not run".to_string()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn run_on(clock: Option<std::path::PathBuf>, start: Instant) -> Run {
        let ctx = std::sync::Arc::new(JobCtx { label: String::new(), hung: false.into(), traced: false.into(), last: std::sync::Mutex::new(None) });
        let clock = clock.map(|c| {
            let n = cpu_ns(&c).unwrap();
            (c, n)
        });
        Run { start, ctx, cpu: clock.as_ref().map_or(0, |c| c.1), clock, moved: start }
    }

    // a seed is hung by the CPU its thread used, not by the wall time it took (a starved seed
    // is not hung), or by using none at all (blocked); wall time only without a CPU clock
    // (spec: none, test infrastructure)
    #[test]
    fn seed_hung_by_cpu_time() {
        let Some(clock) = thread_clock() else { return };
        let limit = Duration::from_millis(30);
        // busy: hung once its CPU time passes the limit
        let mut run = run_on(Some(clock.clone()), Instant::now());
        assert!(run.judge(Instant::now(), limit).is_ok());
        let mut x = 0u64;
        while cpu_ns(&clock).unwrap() < run.clock.as_ref().unwrap().1 + 40_000_000 {
            x = std::hint::black_box(x.wrapping_add(1));
        }
        assert_eq!(run.judge(Instant::now(), limit), Err("used 0 CPU-s".to_string()));
        // long past the limit in wall time but with little CPU used, moving since last read:
        // not hung
        let long_ago = Instant::now() - Duration::from_secs(5);
        let mut run = run_on(Some(clock.clone()), long_ago);
        run.cpu -= 1;
        let due = run.judge(Instant::now(), Duration::from_secs(1)).unwrap();
        assert!(due > Instant::now());
        // a thread that uses no CPU (blocked) for the limit: hung
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (ctx, crx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            ctx.send(thread_clock().unwrap()).unwrap();
            rx.recv().unwrap();
        });
        let blocked = crx.recv().unwrap();
        let mut run = run_on(Some(blocked), long_ago);
        let mut judged = run.judge(Instant::now(), Duration::from_secs(1));
        if judged.is_ok() {
            // it was still on its way into recv: judged from now on, a moment later
            run.moved = long_ago;
            judged = run.judge(Instant::now(), Duration::from_secs(1));
        }
        assert_eq!(judged, Err("used no CPU for 1 s".to_string()));
        tx.send(()).unwrap();
        h.join().unwrap();
        // no CPU clock: wall time
        let mut run = run_on(None, long_ago);
        assert_eq!(run.judge(Instant::now(), Duration::from_secs(1)), Err("ran past 1 s".to_string()));
        assert!(run_on(None, Instant::now()).judge(Instant::now(), Duration::from_secs(1)).is_ok());
    }
}
