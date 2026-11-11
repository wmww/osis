//! The node's error, with the three classes of notes/architecture.md §3.

use osis_base::{Classified, CommitId, ErrorClass, Tid};

#[derive(Debug)]
pub enum Error {
    Store(osis_store::Error),
    /// A commit, chunk tree, label object or blob failed to decode, verify, read or write
    /// (osis-commit's error, which osis-label shares).
    Data(osis_commit::Error),
    Crdt(osis_crdt::Error),
    Keys(osis_keys::Error),
    Crypto(osis_crypto::Error),
    Path(osis_schema::PathError),
    /// This node may not write that aspect (local writes, checked before signing).
    Permission { tid: Tid },
    /// The thing's `created.0` record is not held.
    UnknownThing(Tid),
    /// A placement left `tid` in no synced group while `group`'s own data syncs
    /// (`Mutation::require_synced`). Local.
    Unsynced { tid: Tid, group: Tid },
    /// No commit with this ID is held (or its body was dropped).
    UnknownCommit(CommitId),
    /// Undoing this commit writes back content no kept history holds (spec/crdt.md §4.6). Local.
    ContentGone(CommitId),
    /// Peer data violating a rule node-core checks. BadInput.
    BadInput(&'static str),
    /// Caller misuse or an unsupported request. Local.
    Misuse(&'static str),
    /// A write that cannot be one commit (spec/commits.md §5, §6), saying what clashed. Local.
    Clash(String),
    /// Stored data this node wrote fails to read back. Local.
    Corrupt(&'static str),
}

osis_base::impl_error!(Error {
    Store(e) => ("store: {e}"),
    Data(e) => ("{e}"),
    Crdt(e) => ("crdt: {e}"),
    Keys(e) => ("keys: {e}"),
    Crypto(e) => ("crypto: {e}"),
    Path(e) => ("value: {e}"),
    Permission { tid } => ("no permission to write {tid}"),
    UnknownThing(t) => ("unknown thing {t}"),
    Unsynced { tid, group } => ("{tid} placed in {group}, whose own data syncs but whose items reach no synced group"),
    UnknownCommit(c) => ("unknown commit {c:?}"),
    ContentGone(c) => ("undoing {c:?} writes back content no kept history holds"),
    BadInput(m) => ("bad input: {m}"),
    Misuse(m) => ("misuse: {m}"),
    Clash(m) => ("{m}"),
    Corrupt(m) => ("corrupt local record: {m}"),
});

impl Classified for Error {
    fn class(&self) -> ErrorClass {
        match self {
            Error::Store(e) => e.class(),
            Error::Data(e) => e.class(),
            Error::Crdt(e) => e.class(),
            Error::Keys(e) => e.class(),
            Error::Crypto(e) => e.class(),
            Error::Path(e) => e.class(),
            Error::BadInput(_) => ErrorClass::BadInput,
            Error::Permission { .. } | Error::UnknownThing(_) | Error::Unsynced { .. } | Error::UnknownCommit(_) | Error::ContentGone(_) | Error::Misuse(_) | Error::Clash(_) | Error::Corrupt(_) => ErrorClass::Local,
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
from!(osis_commit::Error, Data);
from!(osis_crdt::Error, Crdt);
from!(osis_keys::Error, Keys);
from!(osis_crypto::Error, Crypto);
from!(osis_schema::PathError, Path);

pub type Result<T> = std::result::Result<T, Error>;
