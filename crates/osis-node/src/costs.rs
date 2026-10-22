//! Phase timers for scale tests (feature `cost-stats`; without it every span is a no-op).
//! Spans nest and count inclusively, per thread.

#[cfg(feature = "cost-stats")]
mod imp {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    thread_local! {
        static COSTS: RefCell<BTreeMap<&'static str, (Duration, u64)>> = const { RefCell::new(BTreeMap::new()) };
    }

    pub struct Span(&'static str, Instant);

    pub fn span(name: &'static str) -> Span {
        Span(name, Instant::now())
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let d = self.1.elapsed();
            COSTS.with(|c| {
                let mut c = c.borrow_mut();
                let e = c.entry(self.0).or_default();
                e.0 += d;
                e.1 += 1;
            });
        }
    }

    /// The time and count per phase since the last `take` on this thread.
    pub fn take() -> Vec<(&'static str, Duration, u64)> {
        COSTS.with(|c| std::mem::take(&mut *c.borrow_mut()).into_iter().map(|(k, (d, n))| (k, d, n)).collect())
    }
}

#[cfg(not(feature = "cost-stats"))]
mod imp {
    pub struct Span;

    #[inline(always)]
    pub fn span(_: &'static str) -> Span {
        Span
    }

    /// Empty without the `cost-stats` feature.
    pub fn take() -> Vec<(&'static str, std::time::Duration, u64)> {
        Vec::new()
    }
}

pub use imp::take;
pub(crate) use imp::span;
