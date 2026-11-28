//! The node's error, with the three classes of notes/architecture.md §3.

use osis_base::{Classified, CommitId, ErrorClass, Role, Tid};

#[derive(Debug)]
pub enum Error {
    Store(osis_store::Error),
    /// A commit, chunk tree, sync ID object or blob failed to decode, verify, read or write
    /// (osis-commit's error, which osis-blob shares).
    Data(osis_commit::Error),
    Crdt(osis_crdt::Error),
    Keys(osis_keys::Error),
    Crypto(osis_crypto::Error),
    Path(osis_schema::PathError),
    /// This node may not write that aspect (local writes, checked before signing): it needs
    /// `needs` on `tid`.
    Permission { tid: Tid, needs: Role },
    /// A fire of external signal `ak` on `tid` by this node, which holds no write there, while
    /// `tid`'s current setting does not enable the signal (spec/permissions.md §5.2 External
    /// fires). Local.
    NotEnabled { tid: Tid, ak: String },
    /// The thing's `created.0` record is not held.
    UnknownThing(Tid),
    /// No commit with this ID is held (or its body was dropped).
    UnknownCommit(CommitId),
    /// Undoing this commit needs a part or content not in kept history (spec/commits.md §7, spec/crdt.md §4.6). Local.
    NotKept(CommitId),
    /// Peer data violating a rule node-core checks. BadInput.
    BadInput(&'static str),
    /// Caller misuse or an unsupported request. Local.
    Misuse(&'static str),
    /// A write that cannot be one commit (spec/commits.md §5, §6), saying what clashed. Local.
    Clash(String),
    /// Stored data this node wrote fails to read back. Local.
    Corrupt(&'static str),
    /// A bounded read (`get_within`, `get_at_within`, `aspects_within`, `read_large_max`) would
    /// hold more than `bound`, the bound it was given. Local.
    PastBound { bound: usize },
    /// A transaction would leave a thing it minted outside the node closure (spec/sync-set.md §2
    /// Minting a thing). Local.
    NotHeld(Tid),
    /// A role commit would leave this thing, which has a standing admin, with none, and does not
    /// carry the adminless mark (spec/permissions.md §1, The last admin). Local.
    LeavesNoAdmin(Tid),
}

osis_base::impl_error!(Error {
    Store(e) => ("store: {e}"),
    Data(e) => ("{e}"),
    Crdt(e) => ("crdt: {e}"),
    Keys(e) => ("keys: {e}"),
    Crypto(e) => ("crypto: {e}"),
    Path(e) => ("value: {e}"),
    Permission { tid, needs } => ("needs {needs:?} on {tid}"),
    NotEnabled { tid, ak } => ("{tid} takes {ak} only from its writers: its retention setting has no entry for it"),
    UnknownThing(t) => ("unknown thing {t}"),
    UnknownCommit(c) => ("unknown commit {c:?}"),
    NotKept(c) => ("undoing {c:?} needs content not in kept history"),
    BadInput(m) => ("bad input: {m}"),
    Misuse(m) => ("misuse: {m}"),
    Clash(m) => ("{m}"),
    Corrupt(m) => ("corrupt local record: {m}"),
    PastBound { bound } => ("past the read bound ({bound} bytes)"),
    NotHeld(t) => ("{t} would be held by nothing: write a strong to it from a held thing in the same write"),
    LeavesNoAdmin(t) => ("this would leave {t} with no admin"),
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
            Error::Permission { .. } | Error::NotEnabled { .. } | Error::UnknownThing(_) | Error::UnknownCommit(_) | Error::NotKept(_) | Error::Misuse(_) | Error::Clash(_) | Error::Corrupt(_) | Error::PastBound { .. } | Error::NotHeld(_) | Error::LeavesNoAdmin(_) => ErrorClass::Local,
        }
    }
}

impl Error {
    /// A local error that is no store failure: a broken invariant of this build, or damage read
    /// back as one. Received commit data never causes one (spec/commits.md §4 No local error from
    /// peer bytes), so applying a received commit, it sets the commit aside
    /// (`apply::Reason::Fault`) where a store failure fails the transaction, to be tried again.
    pub fn is_fault(&self) -> bool {
        self.class() == ErrorClass::Local && !self.is_store()
    }

    /// Local storage failed: the store, or a blob or page written or read through it.
    pub fn is_store(&self) -> bool {
        use osis_crdt::{Error as C, PageError::Storage};
        matches!(self, Error::Store(_) | Error::Data(osis_commit::Error::Storage(_) | osis_commit::Error::Delta(C::Page(Storage))) | Error::Crdt(C::Page(Storage)))
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
