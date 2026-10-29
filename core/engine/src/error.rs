//! The node's error, with the three classes of notes/architecture.md §3.

use osis_base::{Classified, CommitId, ErrorClass, Tid};

#[derive(Debug)]
pub enum Error {
    Store(osis_store::Error),
    Commit(osis_commit::Error),
    Crdt(osis_crdt::Error),
    Keys(osis_keys::Error),
    Label(osis_label::Error),
    Crypto(osis_crypto::Error),
    Path(osis_schema::PathError),
    /// This node may not write that aspect (local writes, checked before signing).
    Permission { tid: Tid },
    /// The thing's `/created` record is not held.
    UnknownThing(Tid),
    /// A placement left `tid` in no synced group while `group`'s own data syncs
    /// (`Mutation::require_synced`). Local.
    Unsynced { tid: Tid, group: Tid },
    /// No commit with this ID is held (or its body was dropped).
    UnknownCommit(CommitId),
    /// Peer data violating a rule node-core checks. BadInput.
    BadInput(&'static str),
    /// Caller misuse or an unsupported request. Local.
    Misuse(&'static str),
    /// Stored data this node wrote fails to read back. Local.
    Corrupt(&'static str),
}

osis_base::impl_error!(Error {
    Store(e) => ("store: {e}"),
    Commit(e) => ("commit: {e}"),
    Crdt(e) => ("crdt: {e}"),
    Keys(e) => ("keys: {e}"),
    Label(e) => ("label: {e}"),
    Crypto(e) => ("crypto: {e}"),
    Path(e) => ("value: {e}"),
    Permission { tid } => ("no permission to write {tid}"),
    UnknownThing(t) => ("unknown thing {t}"),
    Unsynced { tid, group } => ("{tid} placed in {group}, whose own data syncs but whose items reach no synced group"),
    UnknownCommit(c) => ("unknown commit {c:?}"),
    BadInput(m) => ("bad input: {m}"),
    Misuse(m) => ("misuse: {m}"),
    Corrupt(m) => ("corrupt local record: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Store(e) => e.class(),
            Error::Commit(e) => e.class(),
            Error::Crdt(e) => e.class(),
            Error::Keys(e) => e.class(),
            Error::Label(e) => e.class(),
            Error::Crypto(e) => e.class(),
            Error::Path(e) => e.class(),
            Error::BadInput(_) => ErrorClass::BadInput,
            Error::Permission { .. } | Error::UnknownThing(_) | Error::Unsynced { .. } | Error::UnknownCommit(_) | Error::Misuse(_) | Error::Corrupt(_) => ErrorClass::Local,
        }
    }
}

macro_rules! from {
    ($t:ty, $v:ident) => {
        impl From<$t> for Error {
            fn from(e: $t) -> Error {
                Error::$v(e)
            }
        }
    };
}
from!(osis_store::Error, Store);
from!(osis_commit::Error, Commit);
from!(osis_crdt::Error, Crdt);
from!(osis_keys::Error, Keys);
from!(osis_label::Error, Label);
from!(osis_crypto::Error, Crypto);
from!(osis_schema::PathError, Path);

pub type Result<T> = std::result::Result<T, Error>;
