//! The one `Error` of the API (notes/api.md Errors).

use crate::commits::NotUndoableReason;
use osis_base::{Role, Tid};
use crate::commit_id::CommitId;
use osis_schema::{Path, PathError};

/// What a call can fail with. What is absent reads as `None`, and what another node does wrong is a
/// `Diagnostic`: neither is an error.
#[derive(Clone, Debug, PartialEq, Eq)]
// each variant's doc says what its fields are
#[allow(missing_docs)]
pub enum Error {
    /// A write or call names a thing not known here.
    UnknownThing { tid: Tid },
    /// An actor whose keys are not known here (grants need them: a contact card, a shared group).
    UnknownActor { tid: Tid },
    /// The acting actor lacks `needs` on `tid`, or this node cannot write `tid` yet (`role_on`
    /// reads `Read` meanwhile). Checked locally before signing.
    Permission { tid: Tid, needs: Role },
    /// A typed write's value failed validation at `path` (unknown case, mismatch, missing
    /// field), or a typed path read named a path the key's schema does not have. Stored data
    /// never fails a read on typed grounds: it reads as absent (`Diagnostic::Mismatch`).
    Type { path: Path, reason: String },
    /// The value is above `AppConfig::read_limit`; read it by path or stream.
    TooLarge { limit: usize },
    /// The newest commit in an undo or redo scope cannot be undone (its body was dropped, or a
    /// register it wrote is no longer its winner). Nothing older is undone instead.
    NotUndoable { commit: CommitId, reason: NotUndoableReason },
    /// These groups cannot catch up, and waiting would not help: stranded, or, for a wait that needs
    /// a saved peer to confirm anything, with none (`wait_synced`, `set_role`, `group_source`).
    Unsynced { groups: Vec<Tid> },
    /// What was asked cannot be done as asked: a malformed argument (value, link, card, path, op,
    /// retention), or writes that cannot share a commit. The text says which.
    Invalid(String),
    /// Local storage failed (or a local record is corrupt).
    Storage(String),
    /// Another node could not be reached, or this one has no network (`Runtime::None`).
    Network(String),
    /// A write through another node may or may not have applied (its reply was lost and the node
    /// cannot tell). Repeating it is a new write: read first, repeat only if it is not there.
    OutcomeUnknown,
    /// This kind of handle does not carry this call: a handle with no store asked for what needs
    /// its process to be the node, or a client with its own actor for what only the node's account
    /// may do. Trying again will not help.
    Unsupported(String),
    /// The node at the other end will not take this session: it refused the client secret or the
    /// uid, or the address serves no client port.
    Refused(String),
    /// The node is closed.
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
    Closed => ("node closed"),
});

/// A result whose failure is an `Error`.
pub type Result<T> = std::result::Result<T, Error>;

impl From<PathError> for Error {
    fn from(e: PathError) -> Error {
        Error::Type { reason: e.kind.to_string(), path: e.path }
    }
}

#[doc(hidden)]
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
            N::Clash(m) => Error::Invalid(m),
            N::Unsynced { tid, group } => Error::Invalid(format!("{tid} is in {group}, whose own aspects sync but whose items reach no synced group: add {group} as a subgroup of a synced group (same commit or before), or add {tid} elsewhere")),
            e => Error::Invalid(e.to_string()),
        }
    }
}
