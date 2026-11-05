//! Marshaling: posts from other threads arrive in order, and the loop is woken once per drain.
use osis_kit::marshal::mailbox;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn one_wake_per_drain_and_order_kept() {
    let wakes = Arc::new(AtomicUsize::new(0));
    let w = wakes.clone();
    let (mb, inbox) = mailbox::<u32>(move || {
        w.fetch_add(1, Ordering::SeqCst);
    });
    for i in 0..3 {
        assert!(mb.post(i));
    }
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(inbox.drain(), vec![0, 1, 2]);
    assert!(inbox.drain().is_empty());
    mb.post(7);
    assert_eq!(wakes.load(Ordering::SeqCst), 2, "a post after a drain wakes again");
    assert_eq!(inbox.drain(), vec![7]);
    drop(inbox);
    assert!(!mb.post(8), "the UI is gone");
}

/// Many threads post while the UI drains whenever woken: nothing is lost and every post made
/// after a drain is followed by a wake.
#[test]
fn concurrent_posts_lose_nothing() {
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
    let wake_tx = std::sync::Mutex::new(wake_tx);
    let (mb, inbox) = mailbox::<(usize, usize)>(move || {
        let _ = wake_tx.lock().unwrap().send(());
    });
    let threads: Vec<_> = (0..4)
        .map(|t| {
            let mb = mb.clone();
            std::thread::spawn(move || {
                for i in 0..500 {
                    mb.post((t, i));
                }
            })
        })
        .collect();
    let mut got: Vec<Vec<usize>> = vec![Vec::new(); 4];
    let mut n = 0;
    while n < 2000 {
        wake_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("woken");
        for (t, i) in inbox.drain() {
            got[t].push(i);
            n += 1;
        }
    }
    for t in threads {
        t.join().unwrap();
    }
    for g in got {
        assert_eq!(g, (0..500).collect::<Vec<_>>(), "per-thread order kept");
    }
}
