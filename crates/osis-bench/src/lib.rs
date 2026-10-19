//! osis-bench: a dependency-free bench harness (benches/, `cargo bench -p osis-bench`) and the
//! size budgets (tests/budgets.rs, tier 2). Numbers are tracked by the nightly workflow, never
//! gated; budgets are. Conventions: notes/testing.md.
//! Layer 9 (notes/architecture.md). Plan: plans/test-infra.md.
#![forbid(unsafe_code)]

pub mod text;

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Time per sample; `OSIS_BENCH_MS` overrides.
fn sample_time() -> Duration {
    let ms = std::env::var("OSIS_BENCH_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    Duration::from_millis(ms)
}

/// Runs `f` in 11 samples of about `OSIS_BENCH_MS` each and prints one line
/// `bench <name> <median ns/iter> ns/iter [<MB/s>]`; `bytes` is the input size per call, if any.
/// Returns the median ns per iteration.
pub fn bench<T>(name: &str, bytes: Option<usize>, mut f: impl FnMut() -> T) -> f64 {
    // Calibrate: iterations per sample.
    let mut iters: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            black_box(f());
        }
        if t.elapsed() >= sample_time() / 4 || iters >= 1 << 30 {
            break;
        }
        iters *= 2;
    }
    let iters = iters.saturating_mul(4);
    let mut samples: Vec<f64> = (0..11)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(f());
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    let median = samples.get(5).copied().unwrap_or(0.0);
    let rate = bytes.map(|b| format!(" {:.1} MB/s", b as f64 / median * 1e3)).unwrap_or_default();
    println!("bench {name} {median:.0} ns/iter{rate}");
    median
}

/// Asserts a byte budget (tests/budgets.rs): `actual <= budget`, printing both so the nightly log
/// tracks the margin.
pub fn assert_budget(name: &str, actual: usize, budget: usize) {
    println!("budget {name} {actual} / {budget} bytes");
    assert!(actual <= budget, "budget {name}: {actual} bytes exceeds {budget}");
}
