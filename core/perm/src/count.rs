//! Work counters for scale checks, per thread, debug builds only (notes/principles.md: scaling
//! is checked by counting work in a debug test).

#[cfg(debug_assertions)]
thread_local! {
    /// Parts the walk stepped through on this thread; `None` while a debug check walks.
    static WALKED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(Some(0)) };
    /// Things role walks reached on this thread.
    static REACHED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Counts `n` parts a pass of the walk took.
pub(crate) fn walked(n: u64) {
    #[cfg(debug_assertions)]
    WALKED.with(|w| w.set(w.get().map(|x| x + n)));
    #[cfg(not(debug_assertions))]
    let _ = n;
}

/// Parts the walk stepped through on this thread so far, every update counted, debug-only checks
/// not. Debug builds only: release builds keep no count, so this panics there rather than report
/// none.
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn commits_walked() -> u64 {
    #[cfg(debug_assertions)]
    return WALKED.with(|w| w.get().unwrap_or(0));
    #[cfg(not(debug_assertions))]
    panic!("commits_walked counts in debug builds only");
}

/// Counts `n` things a role walk reached (`graph::View`).
pub(crate) fn reached(n: usize) {
    #[cfg(debug_assertions)]
    REACHED.with(|m| m.set(m.get() + n as u64));
    #[cfg(not(debug_assertions))]
    let _ = n;
}

/// Things every role walk on this thread reached so far. Debug builds only, as `commits_walked`.
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn roles_reached() -> u64 {
    #[cfg(debug_assertions)]
    return REACHED.with(|m| m.get());
    #[cfg(not(debug_assertions))]
    panic!("roles_reached counts in debug builds only");
}

/// Runs `f` with this thread's walk count off (debug checks: their work is not the measured
/// code's).
#[doc(hidden)]
pub fn uncounted<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(debug_assertions)]
    let was = WALKED.with(|w| w.take());
    let r = f();
    #[cfg(debug_assertions)]
    WALKED.with(|w| w.set(was));
    r
}
