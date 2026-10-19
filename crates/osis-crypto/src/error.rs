//! Crypto errors and their classes (notes/architecture.md §3).

use osis_core::{Classified, ErrorClass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong length or layout.
    Malformed(&'static str),
    /// AEAD tag mismatch: wrong key, AD or tampered bytes.
    Decrypt,
    /// X25519 result all zero (low-order peer key).
    NonContributory,
    /// Key bytes that are not a valid key (non-canonical, small order, ML-KEM modulus check).
    BadKey,
    BadSignature,
    /// Padmé padding rule broken (spec/wire.md §5).
    BadPadding,
    /// Agility enum case this build does not know.
    UnknownCase(u64),
    /// Suite this build does not know.
    UnknownSuite(u64),
    /// The caller asked to encrypt more than `MAX_BLOB`, or a number beyond the encoding.
    TooLarge,
}

osis_core::impl_error!(Error {
    Malformed(what) => ("malformed: {what}"),
    Decrypt => ("decryption failed"),
    NonContributory => ("non-contributory key exchange"),
    BadKey => ("invalid key"),
    BadSignature => ("invalid signature"),
    BadPadding => ("invalid padding"),
    UnknownCase(c) => ("unknown agility case {c}"),
    UnknownSuite(s) => ("unknown suite {s}"),
    TooLarge => ("input too large"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::UnknownCase(_) | Error::UnknownSuite(_) => ErrorClass::Parked,
            Error::TooLarge => ErrorClass::Local,
            _ => ErrorClass::BadInput,
        }
    }
}
