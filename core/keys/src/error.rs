//! Errors and their classes (notes/architecture.md §3).

use osis_core::{Classified, ErrorClass, Role};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A primitive failed (decryption, malformed payload, unknown suite).
    Crypto(osis_crypto::Error),
    /// A box or history box whose contents contradict its key.
    Mismatch(&'static str),
    /// A role with no epoch to rotate from (the caller passes the derived epochs of a plain thing).
    NoEpoch(Role),
    /// The writer lacks a secret it must box or seal under.
    NoSecret(Role),
    /// A suite this build does not know.
    UnknownSuite(u64),
}

osis_core::impl_error!(Error {
    Crypto(e) => ("crypto: {e}"),
    Mismatch(what) => ("box contents contradict its key: {what}"),
    NoEpoch(r) => ("no epoch of role {r:?}"),
    NoSecret(r) => ("no secret held for role {r:?}"),
    UnknownSuite(s) => ("unknown suite {s}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Crypto(e) => e.class(),
            Error::Mismatch(_) => ErrorClass::BadInput,
            Error::UnknownSuite(_) => ErrorClass::Parked,
            Error::NoEpoch(_) | Error::NoSecret(_) => ErrorClass::Local,
        }
    }
}

impl From<osis_crypto::Error> for Error {
    fn from(e: osis_crypto::Error) -> Error {
        Error::Crypto(e)
    }
}
