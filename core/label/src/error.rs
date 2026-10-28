//! Label errors and their classes (notes/architecture.md §3).

use osis_core::{Classified, DecodeError, ErrorClass};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Bytes outside a layout of spec/wire.md. BadInput.
    Malformed(&'static str),
    /// Not canonical CBOR or beyond the decoder limits. BadInput.
    Cbor(DecodeError),
    /// From osis-crypto; its class.
    Crypto(osis_crypto::Error),
    /// A blob framing version this build does not know: store and relay it as a blob with no
    /// expiry and no commitments (spec/wire.md §5). Parked.
    UnknownFraming(u8),
    /// A format number this build does not know (link, card, bundle). Parked.
    UnknownFormat(u64),
    /// A content hash, blob ID, signature or path check failed. BadInput.
    Verify(&'static str),
    /// The caller asked for something beyond a format limit. Local.
    TooLarge(&'static str),
    /// A blob is not available locally. Local.
    Missing,
    /// Storage failure behind a blob store. Local.
    Storage,
}

osis_core::impl_error!(Error {
    Malformed(what) => ("malformed: {what}"),
    Cbor(e) => ("cbor: {e}"),
    Crypto(e) => ("crypto: {e}"),
    UnknownFraming(v) => ("unknown blob framing version {v}"),
    UnknownFormat(v) => ("unknown format {v}"),
    Verify(what) => ("verification failed: {what}"),
    TooLarge(what) => ("too large: {what}"),
    Missing => ("blob missing"),
    Storage => ("storage failure"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Malformed(_) | Error::Cbor(_) | Error::Verify(_) => ErrorClass::BadInput,
            Error::Crypto(e) => e.class(),
            Error::UnknownFraming(_) | Error::UnknownFormat(_) => ErrorClass::Parked,
            Error::TooLarge(_) | Error::Missing | Error::Storage => ErrorClass::Local,
        }
    }
}

impl From<osis_crypto::Error> for Error {
    fn from(e: osis_crypto::Error) -> Error {
        Error::Crypto(e)
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Cbor(e)
    }
}

impl From<Error> for osis_crdt::PageError {
    fn from(e: Error) -> osis_crdt::PageError {
        match e {
            Error::Missing => osis_crdt::PageError::Missing,
            Error::Storage | Error::TooLarge(_) => osis_crdt::PageError::Storage,
            _ => osis_crdt::PageError::Corrupt,
        }
    }
}

/// Chunk-tree errors (osis-commit's `tree`) into label errors, class kept.
impl From<osis_commit::Error> for Error {
    fn from(e: osis_commit::Error) -> Error {
        use osis_commit::Error as C;
        match e {
            C::Cbor(e) => Error::Cbor(e),
            C::Malformed(m) | C::Invalid(m) => Error::Malformed(m),
            C::UnknownVersion(v) => Error::UnknownFormat(v),
            C::Crypto(e) => Error::Crypto(e),
            C::Missing => Error::Missing,
            C::Corrupt => Error::Verify("content hash"),
            C::BadSignature => Error::Verify("signature"),
            C::DeltaHash { .. } => Error::Verify("delta hash"),
            C::TooLarge(m) | C::Build(m) => Error::TooLarge(m),
            C::Storage(_) => Error::Storage,
            C::Delta(e) => match e.class() {
                ErrorClass::BadInput => Error::Malformed("delta"),
                ErrorClass::Parked => Error::UnknownFormat(0),
                ErrorClass::Local => Error::Storage,
            },
        }
    }
}

/// Label errors out of `TreeSink`/`LinkSource` impls (blob framing, the store), class kept.
impl From<Error> for osis_commit::Error {
    fn from(e: Error) -> osis_commit::Error {
        use osis_commit::Error as C;
        match e {
            Error::Malformed(m) => C::Malformed(m),
            Error::Cbor(e) => C::Cbor(e),
            Error::Crypto(e) => C::Crypto(e),
            Error::UnknownFraming(v) => C::UnknownVersion(u64::from(v)),
            Error::UnknownFormat(v) => C::UnknownVersion(v),
            Error::Verify(_) => C::Corrupt,
            Error::TooLarge(m) => C::TooLarge(m),
            Error::Missing => C::Missing,
            Error::Storage => C::Storage("blob store"),
        }
    }
}
