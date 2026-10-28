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
    /// A signature or key failed to parse (an unknown agility case parks).
    Crypto(osis_crypto::Error),
    /// A blob of a chunk tree (a linked header list, a large value) is not held locally. Local
    /// (fetch it, then retry).
    Missing,
    /// A chunk-tree blob failed its content hash or level. BadInput.
    Corrupt,
    /// Beyond a local bound (a tree read above the caller's size bound, a tree too deep). Local.
    TooLarge(&'static str),
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
    Crypto(e) => ("{e}"),
    Missing => ("blob not held"),
    Corrupt => ("blob failed its content hash"),
    TooLarge(m) => ("too large: {m}"),
    Storage(m) => ("blob storage: {m}"),
    Build(m) => ("cannot build commit: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Cbor(_) | Error::Malformed(_) | Error::Invalid(_) | Error::BadSignature | Error::DeltaHash { .. } | Error::Corrupt => ErrorClass::BadInput,
            Error::UnknownVersion(_) => ErrorClass::Parked,
            Error::Delta(e) => e.class(),
            Error::Crypto(e) => e.class(),
            Error::Missing | Error::TooLarge(_) | Error::Storage(_) | Error::Build(_) => ErrorClass::Local,
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

impl From<osis_crypto::Error> for Error {
    fn from(e: osis_crypto::Error) -> Error {
        Error::Crypto(e)
    }
}
