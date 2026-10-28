//! Store errors (notes/architecture.md §3). All are Local: the store holds only the node's own
//! data, so nothing here is attributed to a peer.

use crate::backend::BackendError;
use osis_base::{Classified, ErrorClass};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Backend(BackendError),
    /// Root storage failed.
    Root(BackendError),
    /// Stored bytes fail decryption or their layout: damaged storage or a bug.
    Corrupt(&'static str),
    /// A commit failed after it began writing; reopen the store to recover.
    Broken,
    /// No store here (open), or a store already exists (create).
    NoStore,
    Exists,
    /// Caller misuse: bad config, unknown table, a value that cannot be stored.
    Misuse(&'static str),
}

osis_base::impl_error!(Error {
    Backend(e) => ("{e}"),
    Root(e) => ("root storage: {e}"),
    Corrupt(what) => ("store corrupt: {what}"),
    Broken => ("store needs reopening after a failed commit"),
    NoStore => ("no store"),
    Exists => ("store exists"),
    Misuse(what) => ("store misuse: {what}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        ErrorClass::Local
    }
}

impl From<BackendError> for Error {
    fn from(e: BackendError) -> Error {
        Error::Backend(e)
    }
}
