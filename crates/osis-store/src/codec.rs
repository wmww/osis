//! Byte layouts of the store's own records: fixed-width big-endian integers, u32-length-prefixed
//! byte strings. Local format only (never on the wire).

use crate::Error;

#[derive(Default)]
pub(crate) struct W(pub Vec<u8>);

impl W {
    pub fn new() -> W {
        W(Vec::new())
    }
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
    pub fn u8(&mut self, v: u8) -> &mut W {
        self.0.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut W {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut W {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut W {
        self.0.extend_from_slice(b);
        self
    }
    /// Length-prefixed bytes; callers check lengths fit a u32 (`put_aspect` does; keys and inline
    /// values are bounded by the page size).
    pub fn bytes(&mut self, b: &[u8]) -> &mut W {
        debug_assert!(u32::try_from(b.len()).is_ok());
        self.u32(u32::try_from(b.len()).unwrap_or(u32::MAX));
        self.raw(b)
    }
}

pub(crate) struct R<'a>(&'a [u8]);

const BAD: Error = Error::Corrupt("layout");

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> R<'a> {
        R(b)
    }
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(BAD);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.raw(N)?.try_into().map_err(|_| BAD)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()?;
        self.raw(usize::try_from(n).map_err(|_| BAD)?)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() { Ok(()) } else { Err(BAD) }
    }
}
