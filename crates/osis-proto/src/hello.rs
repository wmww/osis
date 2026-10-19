//! Hello and version negotiation (spec/wire.md §11.1), clock offset estimation (spec/sync.md §6).

use crate::Error;
use crate::dec::{Fields, b, u, uint};
use osis_core::{Limits, Value, cbor};

/// The protocol version this build speaks (spec/wire.md §11; separate from the format version).
pub const PROTOCOL_VERSION: u64 = 1;
/// Versions a Hello may list.
pub const MAX_HELLO_VERSIONS: usize = 16;
/// Clock offsets beyond this are reported as a diagnostic (spec/sync.md §6: "a few seconds").
pub const OFFSET_DIAGNOSTIC_MS: u64 = 5_000;

/// `Hello := ["osis", [version+], wall_ms, challenge]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// Strictly ascending, 1 to 16 entries.
    pub versions: Vec<u64>,
    pub wall_ms: u64,
    pub challenge: [u8; 32],
}

impl Hello {
    pub fn new(wall_ms: u64, challenge: [u8; 32]) -> Hello {
        Hello { versions: vec![PROTOCOL_VERSION], wall_ms, challenge }
    }

    pub fn to_value(&self) -> Value {
        Value::List(vec![
            Value::Str("osis".into()),
            Value::List(self.versions.iter().map(|v| u(*v)).collect()),
            u(self.wall_ms),
            b(&self.challenge),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    pub fn decode(body: &[u8]) -> Result<Hello, Error> {
        let v = cbor::decode(body, &Limits { max_depth: 2, max_bytes: body.len() })?;
        let mut f = Fields::exact(v, 4, "hello")?;
        match f.next()? {
            Value::Str(s) if s == "osis" => {}
            _ => return Err(Error::Malformed("hello magic")),
        }
        let mut versions = Vec::new();
        for v in f.list(1, MAX_HELLO_VERSIONS, "hello versions")? {
            let v = uint(v, "hello versions")?;
            if versions.last().is_some_and(|l| *l >= v) {
                return Err(Error::Malformed("hello versions"));
            }
            versions.push(v);
        }
        let wall_ms = f.uint()?;
        let challenge = f.fixed()?;
        f.end()?;
        Ok(Hello { versions, wall_ms, challenge })
    }
}

/// The greatest version both list.
pub fn negotiate(ours: &[u64], theirs: &[u64]) -> Result<u64, Error> {
    ours.iter().rev().find(|v| theirs.contains(v)).copied().ok_or(Error::NoCommonVersion)
}

/// One round trip: local send and receive times around the peer's wall clock reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffsetSample {
    pub sent: u64,
    pub peer: u64,
    pub received: u64,
}

impl OffsetSample {
    /// Peer clock minus local clock, assuming symmetric delay.
    pub fn offset(&self) -> i64 {
        let mid = self.sent / 2 + self.received / 2 + (self.sent % 2 + self.received % 2) / 2;
        (self.peer as i128 - mid as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }
}

/// Clock offset (peer minus local, ms) from round-trip samples: the median of the per-sample
/// offsets, so one outlier among three samples moves nothing. Samples received before they were
/// sent are dropped. `None` without a usable sample.
pub fn estimate_offset(samples: &[OffsetSample]) -> Option<i64> {
    let mut offsets: Vec<i64> = samples.iter().filter(|s| s.received >= s.sent).map(|s| s.offset()).collect();
    offsets.sort_unstable();
    offsets.get(offsets.len().checked_sub(1)? / 2).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/wire.md §11.1: Hello layout and the greatest common version
    #[test]
    fn hello_round_trip_and_negotiation() {
        let h = Hello { versions: vec![1, 3], wall_ms: 1_700_000_000_000, challenge: [7; 32] };
        assert_eq!(Hello::decode(&h.encode()), Ok(h));
        assert_eq!(negotiate(&[1, 2, 3], &[1, 3, 9]), Ok(3));
        assert_eq!(negotiate(&[1], &[2]), Err(Error::NoCommonVersion));
    }

    // spec/wire.md §11.1: versions ascending, at most 16; challenge 32 bytes
    #[test]
    fn hello_rejects() {
        let bad = |v: Value| Hello::decode(&cbor::encode(&v)).is_err();
        let mk = |vs: Vec<u64>, c: usize| {
            Value::List(vec![Value::Str("osis".into()), Value::List(vs.into_iter().map(u).collect()), u(5), Value::Bytes(vec![0; c])])
        };
        assert!(!bad(mk(vec![1], 32)));
        assert!(bad(mk(vec![], 32)));
        assert!(bad(mk(vec![2, 1], 32)));
        assert!(bad(mk(vec![1, 1], 32)));
        assert!(bad(mk((1..=17).collect(), 32)));
        assert!(bad(mk(vec![1], 31)));
        assert!(bad(Value::List(vec![Value::Str("osiz".into()), Value::List(vec![u(1)]), u(5), Value::Bytes(vec![0; 32])])));
    }

    // spec/sync.md §6: round-trip corrected, robust to an outlier
    #[test]
    fn offset_median() {
        let s = |sent, peer, received| OffsetSample { sent, peer, received };
        assert_eq!(estimate_offset(&[]), None);
        assert_eq!(estimate_offset(&[s(100, 1150, 200)]), Some(1000));
        let est = estimate_offset(&[s(100, 1150, 200), s(300, 1340, 360), s(400, 90_000, 402)]).unwrap();
        assert_eq!(est, 1010);
        assert_eq!(estimate_offset(&[s(200, 5, 100)]), None);
    }
}
