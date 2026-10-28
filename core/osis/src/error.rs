//! The one `Error` of the API (notes/api.md Errors). Absent aspects and unknown tids read as
//! `None`, never as errors; peer-caused problems are diagnostics, never errors.

use crate::undo::DropReason;
use osis_base::{CommitId, Role, Tid};
use osis_schema::{Path, PathError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A write or call names a thing whose `/created` is not held.
    UnknownThing { tid: Tid },
    /// An actor whose `/keys` is not held (grants need it).
    UnknownActor { tid: Tid },
    /// The acting node lacks `needs` on `tid` (checked locally before signing).
    Permission { tid: Tid, needs: Role },
    /// A typed read or write failed at `path` (unknown case, mismatch, missing field).
    Type { path: Path, reason: String },
    /// The value exceeds the materialization bound; read it by path or stream.
    TooLarge { limit: usize },
    /// The newest change in an undo or redo scope cannot be undone (its body was dropped, or a
    /// register it wrote is no longer its winner). Nothing older is undone instead.
    NotUndoable { commit: CommitId, reason: DropReason },
    /// A demotion's pre-sync could not reach these groups.
    Unsynced { groups: Vec<Tid> },
    /// A malformed argument: value, link, card, path, op, retention.
    Invalid(String),
    /// Local storage failed (or a local record is corrupt).
    Storage(String),
    /// Another node could not be reached in time.
    Network(String),
    /// Not provided by this build yet (issues/api-deferred.md).
    Unsupported(&'static str),
    /// The database is closed.
    Closed,
}

osis_base::impl_error!(Error {
    UnknownThing { tid } => ("unknown thing {tid}"),
    UnknownActor { tid } => ("unknown actor {tid}"),
    Permission { tid, needs } => ("needs {needs:?} on {tid}"),
    Type { path, reason } => ("type error at {path}: {reason}"),
    TooLarge { limit } => ("value larger than the materialization bound ({limit} bytes)"),
    NotUndoable { commit, reason } => ("cannot undo {commit:?}: {reason:?}"),
    Unsynced { groups } => ("could not sync {} group(s)", groups.len()),
    Invalid(m) => ("invalid: {m}"),
    Storage(m) => ("storage: {m}"),
    Network(m) => ("network: {m}"),
    Unsupported(m) => ("not supported yet: {m}"),
    Closed => ("database closed"),
});

pub type Result<T> = std::result::Result<T, Error>;

impl From<PathError> for Error {
    fn from(e: PathError) -> Error {
        Error::Type { path: e.path.clone(), reason: e.to_string() }
    }
}

impl From<osis_node::Error> for Error {
    fn from(e: osis_node::Error) -> Error {
        use osis_node::Error as N;
        match e {
            N::Permission { tid } => Error::Permission { tid, needs: Role::Write },
            N::UnknownThing(tid) => Error::UnknownThing { tid },
            N::Path(p) => p.into(),
            N::Store(e) => Error::Storage(e.to_string()),
            N::Corrupt(m) => Error::Storage(m.into()),
            N::Misuse(m) => Error::Invalid(m.into()),
            e => Error::Invalid(e.to_string()),
        }
    }
}
