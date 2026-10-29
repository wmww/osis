//! Marshaling osis watch callbacks onto the UI thread (notes/app.md Layers, Driver). osis runs
//! callbacks on its dispatcher thread; widgets may only be touched on the UI thread. A callback
//! posts a message into a `Mailbox`; the first post since the last drain wakes the UI loop once
//! (`Wake`); the UI thread drains its `Inbox` and applies the messages in post order. Until osis
//! has a mode where the app pumps the dispatcher itself (notes/app.md State in osis), this is the
//! one cross-thread hop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

/// Wakes the UI loop so it drains its inbox. Called at most once per drain, from any thread.
pub trait Wake: Send + Sync + 'static {
    fn wake(&self);
}

impl<F: Fn() + Send + Sync + 'static> Wake for F {
    fn wake(&self) {
        self()
    }
}

/// The posting side: cheap to clone, `Send`, usable from osis callbacks.
pub struct Mailbox<M> {
    tx: Sender<M>,
    pending: Arc<AtomicBool>,
    waker: Arc<dyn Wake>,
}

impl<M> Clone for Mailbox<M> {
    fn clone(&self) -> Self {
        Mailbox { tx: self.tx.clone(), pending: self.pending.clone(), waker: self.waker.clone() }
    }
}

impl<M: Send + 'static> Mailbox<M> {
    /// Queues `m` for the UI thread; `false` once the inbox is gone (the UI has exited).
    pub fn post(&self, m: M) -> bool {
        if self.tx.send(m).is_err() {
            return false;
        }
        if !self.pending.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
        true
    }
}

/// The UI side.
pub struct Inbox<M> {
    rx: Receiver<M>,
    pending: Arc<AtomicBool>,
}

impl<M> Inbox<M> {
    /// Every message posted so far, in post order. A post racing with the drain is either
    /// returned now or wakes the loop again: nothing is left behind unwoken.
    pub fn drain(&self) -> Vec<M> {
        self.pending.store(false, Ordering::Release);
        self.rx.try_iter().collect()
    }
}

/// A mailbox and its inbox; `waker` is called when the inbox goes from drained to non-empty.
pub fn mailbox<M>(waker: impl Wake) -> (Mailbox<M>, Inbox<M>) {
    let (tx, rx) = channel();
    let pending = Arc::new(AtomicBool::new(false));
    (Mailbox { tx, pending: pending.clone(), waker: Arc::new(waker) }, Inbox { rx, pending })
}
