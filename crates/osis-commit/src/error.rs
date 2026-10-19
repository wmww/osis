//! Errors (notes/architecture.md §3).

use osis_core::{Classified, DecodeError, ErrorClass};

#[derive(Debug)]
pub enum Error {
    /// Not canonical CBOR or outside the decoder limits. BadInput.
    Cbor(DecodeError),
    /// Violates a layout of spec/wire.md §4. BadInput.
    Malformed(&'static str),
    /// Violates a rule of spec/commits.md (kinds, retention, expiry, purge). BadInput.
    Invalid(&'static str),
    /// A format version above ours (spec/versioning.md §2). Parked.
    UnknownVersion(u64),
    /// The signature does not verify. BadInput.
    BadSignature,
    /// A delta does not hash to its header entry (spec/commits.md §4). BadInput.
    DeltaHash { ai: usize, di: usize },
    /// A delta failed to decode against its header facts.
    Delta(osis_crdt::Error),
    /// A blob of a linked header list is not held locally. Local (fetch it, then retry).
    Missing,
    /// A blob of a linked header list failed its content hash. BadInput.
    Corrupt,
    /// A blob could not be written or read. Local.
    Storage(&'static str),
    /// The caller's input cannot make a valid commit (a secret not supplied, one delta too large
    /// for a blob, an index out of range). Local.
    Build(&'static str),
}

osis_core::impl_error!(Error {
    Cbor(e) => ("commit: {e}"),
    Malformed(m) => ("malformed commit: {m}"),
    Invalid(m) => ("invalid commit: {m}"),
    UnknownVersion(v) => ("unknown format version {v}"),
    BadSignature => ("commit signature does not verify"),
    DeltaHash { ai, di } => ("delta {ai}/{di} does not match its hash"),
    Delta(e) => ("{e}"),
    Missing => ("header list blob not held"),
    Corrupt => ("header list blob failed its content hash"),
    Storage(m) => ("blob storage: {m}"),
    Build(m) => ("cannot build commit: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Cbor(_) | Error::Malformed(_) | Error::Invalid(_) | Error::BadSignature | Error::DeltaHash { .. } | Error::Corrupt => ErrorClass::BadInput,
            Error::UnknownVersion(_) => ErrorClass::Parked,
            Error::Delta(e) => e.class(),
            Error::Missing | Error::Storage(_) | Error::Build(_) => ErrorClass::Local,
        }
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Cbor(e)
    }
}

impl From<osis_crdt::Error> for Error {
    fn from(e: osis_crdt::Error) -> Error {
        Error::Delta(e)
    }
}
