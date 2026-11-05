//! The one `Error` of the API (notes/api.md Errors). Absent aspects, unknown tids and stored
//! values of another type read as `None`, never as errors; peer-caused problems are diagnostics, never errors.

use crate::commits::DropReason;
use osis_base::{Role, Tid};
use osis_node::ChangeId;
use osis_schema::{Path, PathError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A write or call names a thing whose `created.0` is not held.
    UnknownThing { tid: Tid },
    /// An actor whose `keys.0` is not held (grants need it).
    UnknownActor { tid: Tid },
    /// The acting node lacks `needs` on `tid` (checked locally before signing).
    Permission { tid: Tid, needs: Role },
    /// A typed write's value failed validation at `path` (unknown case, mismatch, missing
    /// field), or a typed path read named a path the key's schema does not have. Stored data
    /// never fails a read on typed grounds: it reads as absent (`DiagnosticKind::Mismatch`).
    Type { path: Path, reason: String },
    /// The value exceeds the materialization bound; read it by path or stream.
    TooLarge { limit: usize },
    /// The newest change in an undo or redo scope cannot be undone (its body was dropped, or a
    /// register it wrote is no longer its winner). Nothing older is undone instead.
    NotUndoable { commit: ChangeId, reason: DropReason },
    /// Catching up before lowering a role (`SyncFirst`) could not reach these groups.
    Unsynced { groups: Vec<Tid> },
    /// A malformed argument: value, link, card, path, op, retention.
    Invalid(String),
    /// Local storage failed (or a local record is corrupt).
    Storage(String),
    /// Another node could not be reached in time.
    Network(String),
    /// A write through another node may or may not have applied (its reply was lost and the node
    /// cannot tell). Repeating it is a new write: read first, repeat only if it is not there.
    OutcomeUnknown,
    /// This kind of handle does not carry this call: an attached handle asked for what needs its
    /// process to be the node, a thin client for an owner's call. Trying again will not help.
    Unsupported(String),
    /// The node at the other end will not take this session: it refused the client secret or the
    /// uid, or the address serves no client port.
    Refused(String),
    /// The database is closed.
    Closed,
}

osis_base::impl_error!(Error {
    UnknownThing { tid } => ("unknown thing {tid}"),
    UnknownActor { tid } => ("unknown actor {tid}"),
    Permission { tid, needs } => ("needs {needs:?} on {tid}"),
    Type { path, reason } => ("type error at {path}: {reason}"),
    TooLarge { limit } => ("value larger than the materialization bound ({limit} bytes)"),
    NotUndoable { commit, reason } => ("cannot revert {commit:?}: {reason:?}"),
    Unsynced { groups } => ("could not sync {} group(s)", groups.len()),
    Invalid(m) => ("invalid: {m}"),
    Storage(m) => ("storage: {m}"),
    Network(m) => ("network: {m}"),
    OutcomeUnknown => ("outcome unknown: the write may have applied, read before repeating it"),
    Unsupported(m) => ("not available on this handle: {m}"),
    Refused(m) => ("refused by the node: {m}"),
    Closed => ("database closed"),
});

pub type Result<T> = std::result::Result<T, Error>;

impl From<PathError> for Error {
    fn from(e: PathError) -> Error {
        Error::Type { reason: e.kind.to_string(), path: e.path }
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
            N::Unsynced { tid, group } => Error::Invalid(format!("{tid} placed in {group}, whose own aspects sync but whose items reach no synced group: add {group} as a subgroup of a synced group (add_subgroup, same batch or before), or place {tid} elsewhere")),
            e => Error::Invalid(e.to_string()),
        }
    }
}
