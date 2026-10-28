//! Frames over an ordered byte stream (spec/wire.md §11.1): 4-byte big-endian length
//! `1..=MAX_MESSAGE`, then one canonical CBOR item.

use crate::Error;
use osis_base::format::MAX_MESSAGE;

/// Frames `body` (one encoded CBOR item). The caller keeps bodies within `MAX_MESSAGE`.
pub fn encode_frame(body: &[u8]) -> Vec<u8> {
    debug_assert!(!body.is_empty() && body.len() <= MAX_MESSAGE);
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Frames `msg` as an engine output.
pub(crate) fn send<O: From<Vec<u8>>>(out: &mut Vec<O>, msg: crate::Message) {
    out.push(O::from(encode_frame(&msg.encode())));
}

/// A Hello is at most about 200 bytes (spec/wire.md §11.1: 16 versions); a first frame above
/// this is malformed.
pub const MAX_HELLO_BYTES: usize = 256;

/// Incremental frame splitter. Holds at most one frame plus the last pushed chunk.
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Bytes of `buf` already handed out.
    start: usize,
    failed: Option<u64>,
    /// Largest frame body accepted.
    max: usize,
}

impl Default for FrameDecoder {
    fn default() -> FrameDecoder {
        FrameDecoder { buf: Vec::new(), start: 0, failed: None, max: MAX_MESSAGE }
    }
}

impl FrameDecoder {
    pub fn new() -> FrameDecoder {
        FrameDecoder::default()
    }

    /// Accepts frame bodies up to `max` (at most `MAX_MESSAGE`) from now on: a peer's first
    /// frame is its Hello (`MAX_HELLO_BYTES`).
    pub fn set_max(&mut self, max: usize) {
        self.max = max.min(MAX_MESSAGE);
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
        if len == 0 || len > self.max {
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

    // spec/wire.md §11.1 (Hello: at most 16 versions, so a small first frame), spec/requirements.md
    // (no unbounded allocation): a declared length above the cap fails before any body arrives
    #[test]
    fn capped_first_frame() {
        let mut d = FrameDecoder::new();
        d.set_max(MAX_HELLO_BYTES);
        d.push(&((MAX_HELLO_BYTES + 1) as u32).to_be_bytes());
        assert!(d.next_frame().is_err());
        let mut d = FrameDecoder::new();
        d.set_max(MAX_HELLO_BYTES);
        d.push(&encode_frame(&[0x80; MAX_HELLO_BYTES]));
        assert_eq!(d.next_frame().map(|f| f.map(|b| b.len())), Ok(Some(MAX_HELLO_BYTES)));
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
