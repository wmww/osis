//! Async work off the UI thread: a future that waits on another thread completes, and its
//! result reaches the inbox.
use osis_kit::marshal::mailbox;
use osis_kit::tasks::spawn;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Ready once another thread sets the value and wakes it.
struct Later(Arc<Mutex<(Option<u32>, Option<Waker>)>>);

impl Future for Later {
    type Output = u32;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u32> {
        let mut s = self.0.lock().unwrap();
        match s.0 {
            Some(v) => Poll::Ready(v),
            None => {
                s.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[test]
fn a_task_reports_through_the_mailbox() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (mb, inbox) = mailbox::<u32>(move || {
        let _ = tx.send(());
    });
    let shared = Arc::new(Mutex::new((None, None)));
    let s2 = shared.clone();
    assert!(spawn("test", move || Later(s2), move |v| {
        mb.post(v);
    }));
    let w = {
        let mut s = shared.lock().unwrap();
        s.0 = Some(7);
        s.1.take()
    };
    if let Some(w) = w {
        w.wake();
    }
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(inbox.drain(), vec![7]);
}
