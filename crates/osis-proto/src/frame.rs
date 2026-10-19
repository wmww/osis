//! Frames over an ordered byte stream (spec/wire.md §11.1): 4-byte big-endian length
//! `1..=MAX_MESSAGE`, then one canonical CBOR item.

use crate::Error;
use osis_core::format::MAX_MESSAGE;

/// Frames `body` (one encoded CBOR item). The caller keeps bodies within `MAX_MESSAGE`.
pub fn encode_frame(body: &[u8]) -> Vec<u8> {
    debug_assert!(!body.is_empty() && body.len() <= MAX_MESSAGE);
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Incremental frame splitter. Holds at most one frame plus the last pushed chunk.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Bytes of `buf` already handed out.
    start: usize,
    failed: Option<u64>,
}

impl FrameDecoder {
    pub fn new() -> FrameDecoder {
        FrameDecoder::default()
    }

    /// Appends received stream bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame body, `None` while incomplete. After an error frame boundaries
    /// are lost and every later call repeats it.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if let Some(n) = self.failed {
            return Err(Error::FrameLength(n));
        }
        let rest = self.buf.get(self.start..).unwrap_or(&[]);
        let Some(head) = rest.first_chunk::<4>() else { return Ok(None) };
        let len = u32::from_be_bytes(*head) as usize;
        if len == 0 || len > MAX_MESSAGE {
            self.failed = Some(len as u64);
            return Err(Error::FrameLength(len as u64));
        }
        let Some(body) = rest.get(4..4 + len) else { return Ok(None) };
        let body = body.to_vec();
        self.start += 4 + len;
        Ok(Some(body))
    }

    /// Buffered bytes not yet returned.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/wire.md §11.1: length prefix big-endian, frames split across pushes
    #[test]
    fn split_and_rejoin() {
        let mut d = FrameDecoder::new();
        let a = encode_frame(&[0x80]);
        let b = encode_frame(&[0x82, 1, 2]);
        assert_eq!(a, [0, 0, 0, 1, 0x80]);
        let all = [a, b].concat();
        for chunk in all.chunks(2) {
            d.push(chunk);
        }
        assert_eq!(d.next_frame(), Ok(Some(vec![0x80])));
        assert_eq!(d.next_frame(), Ok(Some(vec![0x82, 1, 2])));
        assert_eq!(d.next_frame(), Ok(None));
        assert_eq!(d.pending(), 0);
    }

    // spec/wire.md §11.1: 1 <= len <= MAX_MESSAGE
    #[test]
    fn bad_lengths() {
        let mut d = FrameDecoder::new();
        d.push(&[0, 0, 0, 0]);
        assert_eq!(d.next_frame(), Err(Error::FrameLength(0)));
        assert_eq!(d.next_frame(), Err(Error::FrameLength(0)));
        let mut d = FrameDecoder::new();
        d.push(&((MAX_MESSAGE + 1) as u32).to_be_bytes());
        assert!(d.next_frame().is_err());
        let mut d = FrameDecoder::new();
        d.push(&(MAX_MESSAGE as u32).to_be_bytes());
        assert_eq!(d.next_frame(), Ok(None));
    }
}
