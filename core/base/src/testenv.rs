//! Test support (doc-hidden): the `OSIS_*` environment variables tests and harnesses read, and
//! seed ranges from them. Reading the environment is this crate's one exception to "no I/O"; only
//! tests call it.

use std::ops::Range;

/// Every `OSIS_*` variable anything in the repo reads (tests, harnesses, tools, binaries);
/// tools/policy.py checks it against the sources. A set variable not listed is a typo.
pub const KNOWN: &[&str] = &[
    "OSIS_BENCH_DURABLE",
    "OSIS_BENCH_MS",
    "OSIS_BENCH_N",
    "OSIS_CRDT_SEED",
    "OSIS_EPH_SEEDS",
    "OSIS_EPH_START",
    "OSIS_EPH_THREADS",
    "OSIS_INDEX_RULES",
    "OSIS_LARGE_MIB",
    "OSIS_LOG",
    "OSIS_ORDER_ALL_HELD",
    "OSIS_ORDER_LEN",
    "OSIS_ORDER_SEED",
    "OSIS_ORDER_SEEDS",
    "OSIS_ORDER_START",
    "OSIS_ORDER_STATS",
    "OSIS_ORDER_THREADS",
    "OSIS_PERM_SEED",
    "OSIS_PERM_THREADS",
    "OSIS_REGEN_VECTORS",
    "OSIS_SCALE_BATCH",
    "OSIS_SCALE_CLOSURE",
    "OSIS_SCALE_DEMOTE",
    "OSIS_SCALE_EDGES",
    "OSIS_SCALE_LABEL",
    "OSIS_SCALE_MAX",
    "OSIS_SCALE_N",
    "OSIS_SCALE_PER",
    "OSIS_SCALE_ROWS",
    "OSIS_SHRINK",
    "OSIS_SIM_FROM",
    "OSIS_SIM_ONLY",
    "OSIS_SIM_SEEDS",
    "OSIS_SIM_TRACE",
    "OSIS_SLOW",
    "OSIS_STORE",
    "OSIS_STRAYS_SEEDS",
    "OSIS_STRAYS_START",
    "OSIS_STRAYS_THREADS",
    "OSIS_SYNC_TRACE",
    "OSIS_TEST_DIAG",
    "OSIS_TEST_TRACE",
    "OSIS_TEXT_TRACE",
    "OSIS_TRACE_UPLOADS",
    "OSIS_WALKS_FORGED_SEEDS",
    "OSIS_WALKS_FORGED_START",
    "OSIS_WALKS_MOVES_DOUBLES",
    "OSIS_WALKS_MOVES_SEEDS",
    "OSIS_WALKS_SECRETS_START",
    "OSIS_WALKS_SECRETS_SEEDS",
    "OSIS_WALKS_MOVES_START",
    "OSIS_WALKS_SEEDS",
    "OSIS_WALKS_START",
    "OSIS_WALKS_THREADS",
];

/// Panics if a set `OSIS_*` variable is not in `KNOWN` (a typo would silently run defaults).
/// The environment is scanned once per process.
pub fn check_known() {
    static UNKNOWN: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let unknown = UNKNOWN.get_or_init(|| {
        std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).filter(|k| k.starts_with("OSIS_") && !KNOWN.contains(&k.as_str())).collect()
    });
    assert!(unknown.is_empty(), "unknown environment variables {unknown:?} (known: osis_base::testenv::KNOWN)");
}

/// `var` as a decimal u64, `None` when unset or empty; panics when unparsable or not in `KNOWN`,
/// and on any unknown `OSIS_*` variable. A set value is printed once per process, past libtest's
/// capture.
pub fn u64_var(var: &str) -> Option<u64> {
    assert!(KNOWN.contains(&var), "{var} is not in osis_base::testenv::KNOWN");
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
