//! `Diagnostic`: what osis tells an app about things nobody asked (`Osis::on_diagnostic`), from the
//! engine's kinds. No correctness depends on one; each says what happened and to what.

use osis_base::Tid;
use crate::commit_id::CommitId;
use osis_node::DiagnosticKind as K;

/// Something an app may want to log, or tell its user. All but `Handled` name what an app could do
/// something about; more kinds may come.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
// each variant's doc says what its fields are
#[allow(missing_docs)]
pub enum Diagnostic {
    /// `thing` reaches no other node: no synced group holds it, or `group`, which was to, has holders
    /// who may not read it. Add it to a synced group, `sync` it, or grant the group a role on it.
    NotSynced { thing: Tid, group: Option<Tid>, detail: String },
    /// A background write could not commit (a text session, a kept-alive value), and is still waiting.
    Uncommitted { thing: Tid, detail: String },
    /// A write of this node turned invalid after it was written: it no longer reads, and nothing
    /// sends it again. Write it again if it still matters.
    OwnWriteInvalid { commit: CommitId, things: Vec<Tid>, detail: String },
    /// A stored value did not match the reader's type, and read as absent.
    Mismatch { thing: Tid, detail: String },
    /// A large value could not be read (not fetched yet, or failing verification), and read as absent.
    Unreadable { thing: Tid, detail: String },
    /// This node lost read access to `actor` and dropped its secrets (a copy may stay: `retained_copies`).
    LostAccess { actor: Tid, detail: String },
    /// This node cannot open `group`'s sync (`SyncState::Stranded`) until a holder gives it the keys.
    Stranded { group: Tid, detail: String },
    /// Ephemeral data was not synced or not applied: a cap was reached.
    EphemeralRefused { things: Vec<Tid>, detail: String },
    /// Something about the local store, such as a file others can read.
    Storage { detail: String },
    /// An app callback panicked.
    Callback { detail: String },
    /// Background sync died: nothing syncs until the node is opened again, and waits fail
    /// `Network`.
    SyncStopped { detail: String },
    /// A commit from a newer format than this build reads: it waits here, and an update may read it.
    Parked { things: Vec<Tid>, commit: Option<CommitId>, peer: Option<Tid>, detail: String },
    /// Data from another node was refused, is waiting for what it depends on or was repaired, all
    /// without any part for an app: for a log.
    Handled { things: Vec<Tid>, commit: Option<CommitId>, peer: Option<Tid>, detail: String },
}

#[doc(hidden)]
impl From<osis_node::Diagnostic> for Diagnostic {
    fn from(d: osis_node::Diagnostic) -> Diagnostic {
        let osis_node::Diagnostic { kind, tids, commit, peer, detail } = d;
        let first = tids.first().copied();
        match (kind, first, tids.get(1).copied(), commit) {
            (K::NotSynced, Some(thing), group, _) => Diagnostic::NotSynced { thing, group, detail },
            (K::Uncommitted, Some(thing), ..) => Diagnostic::Uncommitted { thing, detail },
            (K::OwnWriteInvalid, _, _, Some(c)) => Diagnostic::OwnWriteInvalid { commit: c.into(), things: tids, detail },
            (K::Mismatch, Some(thing), ..) => Diagnostic::Mismatch { thing, detail },
            (K::Unreadable, Some(thing), ..) => Diagnostic::Unreadable { thing, detail },
            (K::Removed, Some(actor), ..) => Diagnostic::LostAccess { actor, detail },
            (K::Stranded, Some(group), ..) => Diagnostic::Stranded { group, detail },
            (K::EphemeralRefused, ..) => Diagnostic::EphemeralRefused { things: tids, detail },
            (K::Storage, ..) => Diagnostic::Storage { detail },
            (K::Callback, ..) => Diagnostic::Callback { detail },
            (K::SyncStopped, ..) => Diagnostic::SyncStopped { detail },
            (K::Parked, ..) => Diagnostic::Parked { things: tids, commit: commit.map(Into::into), peer, detail },
            _ => Diagnostic::Handled { things: tids, commit: commit.map(Into::into), peer, detail: format!("{kind:?}: {detail}") },
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (what, detail) = match self {
            Diagnostic::NotSynced { detail, .. } => ("not synced", detail),
            Diagnostic::Uncommitted { detail, .. } => ("uncommitted", detail),
            Diagnostic::OwnWriteInvalid { detail, .. } => ("own write invalid", detail),
            Diagnostic::Mismatch { detail, .. } => ("mismatch", detail),
            Diagnostic::Unreadable { detail, .. } => ("unreadable", detail),
            Diagnostic::LostAccess { detail, .. } => ("lost access", detail),
            Diagnostic::Stranded { detail, .. } => ("stranded", detail),
            Diagnostic::EphemeralRefused { detail, .. } => ("ephemeral refused", detail),
            Diagnostic::Storage { detail } => ("storage", detail),
            Diagnostic::Callback { detail } => ("callback", detail),
            Diagnostic::SyncStopped { detail } => ("sync stopped", detail),
            Diagnostic::Parked { detail, .. } => ("from a newer format", detail),
            Diagnostic::Handled { detail, .. } => ("handled", detail),
        };
        write!(f, "{what}: {detail}")
    }
}
