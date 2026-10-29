//! Async work off the UI thread (notes/app.md Layers, Driver): the osis API's futures are
//! runtime-agnostic (sync runs on osis's own runtime), so a task is a plain thread polling one
//! future with a park/unpark waker; its result goes to `done`, which posts it to the UI's
//! mailbox (`marshal`). One thread per task: tasks are rare user actions (revoking a share),
//! not a stream.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls `f` on this thread until it is ready.
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// Runs the future `make` returns on a new thread named `name` and hands its output to `done`
/// (on that thread). The future is made there, so it need not be `Send`. `false` when the
/// thread could not start (`done` is not called).
pub fn spawn<F, Fut>(name: &str, make: F, done: impl FnOnce(Fut::Output) + Send + 'static) -> bool
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future,
{
    std::thread::Builder::new().name(format!("task {name}")).spawn(move || done(block_on(make()))).is_ok()
}
