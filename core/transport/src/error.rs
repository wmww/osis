//! Transport errors and their classes (notes/architecture.md §3).

use osis_base::{Classified, ErrorClass};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer authenticated with a key other than the pinned one (spec/sync.md §10).
    KeyMismatch,
    /// The peer broke the transport protocol (handshake, key form).
    Protocol(String),
    /// URL scheme this build has no transport for (feature off or a newer scheme).
    UnknownScheme(String),
    /// URL this transport cannot parse.
    BadUrl(String),
    /// Nobody listens there, or the network refused or timed out.
    Unreachable(String),
    /// Connection, stream or listener closed or reset.
    Closed,
    /// Local I/O or setup failure.
    Io(String),
}

osis_base::impl_error!(Error {
    KeyMismatch => ("peer key does not match the pinned key"),
    Protocol(m) => ("transport protocol error: {m}"),
    UnknownScheme(s) => ("unknown transport scheme {s}"),
    BadUrl(u) => ("bad transport url {u}"),
    Unreachable(m) => ("unreachable: {m}"),
    Closed => ("closed"),
    Io(m) => ("transport i/o: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::KeyMismatch | Error::Protocol(_) | Error::BadUrl(_) => ErrorClass::BadInput,
            Error::UnknownScheme(_) => ErrorClass::Parked,
            Error::Unreachable(_) | Error::Closed | Error::Io(_) => ErrorClass::Local,
        }
    }
}
