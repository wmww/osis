//! Protocol errors and their classes (notes/architecture.md §3).

use osis_core::{Classified, DecodeError, ErrorClass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Frame length 0 or above `MAX_MESSAGE` (spec/wire.md §11.1).
    FrameLength(u64),
    /// Frame body outside the CBOR profile.
    Cbor(DecodeError),
    /// Decodes but breaks a layout rule of spec/wire.md §11.
    Malformed(&'static str),
    /// A list longer than its cap (spec/wire.md §11.2).
    Cap(&'static str),
    /// A message kind this build does not know (answered by Error 11).
    UnknownKind(u64),
    /// The Hellos share no protocol version.
    NoCommonVersion,
}

osis_core::impl_error!(Error {
    FrameLength(n) => ("proto: frame length {n} outside 1..=MAX_MESSAGE"),
    Cbor(e) => ("proto: {e}"),
    Malformed(what) => ("proto: malformed {what}"),
    Cap(what) => ("proto: {what} over its cap"),
    UnknownKind(k) => ("proto: unknown message kind {k}"),
    NoCommonVersion => ("proto: no common protocol version"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::UnknownKind(_) | Error::NoCommonVersion => ErrorClass::Parked,
            _ => ErrorClass::BadInput,
        }
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Cbor(e)
    }
}
