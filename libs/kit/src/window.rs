//! Running the UI: the `Waker` every shell gives it, and the desktop shell over masonry_winit (one
//! window). Android's shell is osis-android.

use std::sync::Arc;

#[cfg(not(target_os = "android"))]
mod desktop;
#[cfg(not(target_os = "android"))]
pub use desktop::App;

/// Wakes the UI thread from any thread; the shell then calls `Ui::wake` there.
#[derive(Clone)]
pub struct Waker(Arc<dyn Fn() + Send + Sync>);

impl Waker {
    pub fn new(f: impl Fn() + Send + Sync + 'static) -> Waker {
        Waker(Arc::new(f))
    }

    /// Wakes the UI thread, from any thread.
    pub fn wake(&self) {
        (self.0)();
    }
}
