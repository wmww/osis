//! Connection helpers for node and server drivers: reconnect with backoff, graceful close.
//! Runtime-free: the caller passes its sleep (`tokio::time::sleep`, `Net::sleep`).
//! One connection serves many labels: proto multiplexes them on a session stream by message id.

use crate::util::Rng;
use crate::{Address, Connection, Error, RecvStream, SendStream, Transport};
use osis_base::{Classified, ErrorClass};
use std::future::Future;

/// Exponential backoff with seeded jitter: delay `n` is uniform in `[d/2, d]`, `d = min(base * 2^n, max)`.
#[derive(Clone, Debug)]
pub struct Backoff {
    base_ms: u64,
    max_ms: u64,
    attempt: u32,
    rng: Rng,
}

impl Backoff {
    /// Defaults for reconnecting to a server (provisional): 500 ms doubling to 60 s.
    pub fn new(seed: u64) -> Backoff {
        Backoff::with(500, 60_000, seed)
    }

    pub fn with(base_ms: u64, max_ms: u64, seed: u64) -> Backoff {
        Backoff { base_ms, max_ms, attempt: 0, rng: Rng::new(seed) }
    }

    pub fn next_delay_ms(&mut self) -> u64 {
        let d = self.base_ms.saturating_mul(1u64.checked_shl(self.attempt).unwrap_or(u64::MAX)).min(self.max_ms);
        self.attempt = self.attempt.saturating_add(1);
        d - self.rng.below(d / 2 + 1).min(d / 2)
    }

    /// After a connection that worked.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Dials until connected. Errors the peer or the address caused (key mismatch, bad URL,
/// unknown scheme: not `Local`) are returned at once; network failures are retried after
/// `sleep(next_delay_ms)`, at most `max_attempts` times in total.
pub async fn connect<T, S, F>(t: &T, addr: &Address, backoff: &mut Backoff, max_attempts: u32, mut sleep: S) -> Result<T::Conn, Error>
where
    T: Transport,
    S: FnMut(u64) -> F,
    F: Future<Output = ()>,
{
    let mut tries = 0u32;
    loop {
        match t.dial(addr).await {
            Ok(c) => {
                backoff.reset();
                return Ok(c);
            }
            Err(e) if e.class() != ErrorClass::Local => return Err(e),
            Err(e) => {
                tries = tries.saturating_add(1);
                if tries >= max_attempts {
                    return Err(e);
                }
                sleep(backoff.next_delay_ms()).await;
            }
        }
    }
}

/// Graceful end of a session, for the dialer: finish ours (the peer got it all), read the peer's
/// rest until it finishes (handing each piece to `rest`), then close. The dialer closes: the
/// accepting side finishes and then waits for the close (`accept_stream` fails) or its own
/// timeout, since closing first can cut the dialer's read of its tail.
pub async fn close_gracefully<C: Connection>(
    c: &C,
    send: &mut C::Send,
    recv: &mut C::Recv,
    mut rest: impl FnMut(&[u8]),
) -> Result<(), Error> {
    send.finish().await?;
    let mut buf = [0u8; 4096];
    loop {
        let n = recv.read(&mut buf).await?;
        match buf.get(..n) {
            Some([]) | None => break,
            Some(b) => rest(b),
        }
    }
    c.close();
    Ok(())
}
