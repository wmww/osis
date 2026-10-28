//! Phase timers for scale tests. A thread records spans once it has called `take` (tests call it
//! to reset before measuring); until then every span is one thread-local read. Always compiled, so
//! test and non-test builds share one set of artifacts. Spans nest and count inclusively, per thread.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static COSTS: RefCell<BTreeMap<&'static str, (Duration, u64)>> = const { RefCell::new(BTreeMap::new()) };
}

pub(crate) struct Span(Option<(&'static str, Instant)>);

#[inline]
pub(crate) fn span(name: &'static str) -> Span {
    Span(ON.with(Cell::get).then(|| (name, Instant::now())))
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some((name, start)) = self.0 {
            let d = start.elapsed();
            COSTS.with(|c| {
                let mut c = c.borrow_mut();
                let e = c.entry(name).or_default();
                e.0 += d;
                e.1 += 1;
            });
        }
    }
}

/// The time and count per phase since the last `take` on this thread; the first call turns
/// recording on for this thread (and returns nothing).
pub fn take() -> Vec<(&'static str, Duration, u64)> {
    ON.with(|on| on.set(true));
    COSTS.with(|c| std::mem::take(&mut *c.borrow_mut()).into_iter().map(|(k, (d, n))| (k, d, n)).collect())
}
