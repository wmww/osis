//! Errors (notes/architecture.md §3).

use crate::page::PageError;
use osis_core::{Classified, DecodeError, ErrorClass};

#[derive(Debug)]
pub enum Error {
    /// Not canonical CBOR, or outside the decoder limits. BadInput.
    Cbor(DecodeError),
    /// Violates the delta grammar or a rule of spec/crdt.md §2.3, §3.3. BadInput.
    Malformed(&'static str),
    /// An encoding ID this build does not know (§3.1). Parked.
    UnknownEncoding(u64),
    /// An op or value that does not fit the state or view it was applied to (caller error). Local.
    Mismatch(&'static str),
    /// A page could not be written or read.
    Page(PageError),
}

osis_core::impl_error!(Error {
    Cbor(e) => ("delta: {e}"),
    Malformed(m) => ("malformed delta: {m}"),
    UnknownEncoding(id) => ("unknown merge encoding {id}"),
    Mismatch(m) => ("op does not fit: {m}"),
    Page(e) => ("page: {e}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Cbor(_) | Error::Malformed(_) => ErrorClass::BadInput,
            Error::UnknownEncoding(_) => ErrorClass::Parked,
            Error::Mismatch(_) => ErrorClass::Local,
            Error::Page(e) => e.class(),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Cbor(e)
    }
}

impl From<PageError> for Error {
    fn from(e: PageError) -> Error {
        Error::Page(e)
    }
}
