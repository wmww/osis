//! Errors of commits, chunk trees and label objects (osis-label uses this type; notes/architecture.md §3).

use osis_base::{Classified, DecodeError, ErrorClass};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not canonical CBOR or outside the decoder limits. BadInput.
    Cbor(DecodeError),
    /// Violates a layout of spec/wire.md. BadInput.
    Malformed(&'static str),
    /// Violates a rule of spec/commits.md (kinds, retention, expiry, purge). BadInput.
    Invalid(&'static str),
    /// A format version above ours (a commit, link, card, bundle; spec/versioning.md §2). Parked.
    UnknownVersion(u64),
    /// A blob framing version this build does not know: store and relay it as a blob with no
    /// expiry and no commitments (spec/wire.md §5). Parked.
    UnknownFraming(u8),
    /// A blob ID, signature or path check of a label object failed. BadInput.
    Verify(&'static str),
    /// The signature does not verify. BadInput.
    BadSignature,
    /// A delta does not hash to its header entry (spec/commits.md §4). BadInput.
    DeltaHash { ai: usize },
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

osis_base::impl_error!(Error {
    Cbor(e) => ("cbor: {e}"),
    Malformed(m) => ("malformed: {m}"),
    Invalid(m) => ("invalid commit: {m}"),
    UnknownVersion(v) => ("unknown format version {v}"),
    UnknownFraming(v) => ("unknown blob framing version {v}"),
    Verify(what) => ("verification failed: {what}"),
    BadSignature => ("commit signature does not verify"),
    DeltaHash { ai } => ("delta of aspect {ai} does not match its hash"),
    Delta(e) => ("{e}"),
    Crypto(e) => ("{e}"),
    Missing => ("blob missing"),
    Corrupt => ("blob failed its content hash"),
    TooLarge(m) => ("too large: {m}"),
    Storage(m) => ("blob storage: {m}"),
    Build(m) => ("cannot build commit: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Cbor(_) | Error::Malformed(_) | Error::Invalid(_) | Error::BadSignature | Error::DeltaHash { .. } | Error::Corrupt | Error::Verify(_) => ErrorClass::BadInput,
            Error::UnknownVersion(_) | Error::UnknownFraming(_) => ErrorClass::Parked,
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

/// Label stores behind osis-crdt's page plugs: what a page read or write of a label blob reports.
impl From<Error> for osis_crdt::PageError {
    fn from(e: Error) -> osis_crdt::PageError {
        match e {
            Error::Missing => osis_crdt::PageError::Missing,
            Error::Storage(_) | Error::TooLarge(_) => osis_crdt::PageError::Storage,
            _ => osis_crdt::PageError::Corrupt,
        }
    }
}
