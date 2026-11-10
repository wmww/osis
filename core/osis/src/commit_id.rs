//! `CommitId` and `CommitPos`: opaque names an app keeps, compares and passes back. What they hold
//! (a commit's hash, a hybrid clock value) stays inside.

use crate::error::{Error, Result};
use osis_base::hex;
use osis_base::{CommitId as RawCommitId, Ts, Time};
use osis_node::engine::listing as engine;

/// Names one commit: a `Commit`'s, what a commit listener names, and what `revert` or
/// `Purge::Commit` takes. Its text form (`Display`, `FromStr`) keeps it anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitId(pub(crate) RawCommitId);

#[doc(hidden)]
impl From<RawCommitId> for CommitId {
    fn from(c: RawCommitId) -> CommitId {
        CommitId(c)
    }
}

impl std::fmt::Display for CommitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0.0))
    }
}

impl std::str::FromStr for CommitId {
    type Err = Error;
    fn from_str(s: &str) -> Result<CommitId> {
        let bad = || Error::Invalid(format!("not a commit id: {s:?}"));
        let c = hex::decode(s).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(bad)?;
        Ok(CommitId(RawCommitId(c)))
    }
}

/// A place among commits, for `CommitFrom::Before` and `After`: a commit's (`Commit::pos`) or a
/// time's. Places order as listings do, and the text form (`Display`, `FromStr`) keeps one
/// anywhere and sorts as they do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitPos(pub(crate) engine::CommitPos);

impl CommitPos {
    /// The place before everything written at `t` or later.
    pub fn time(t: Time) -> CommitPos {
        CommitPos(engine::CommitPos::time(ts_at(t)))
    }

    /// The time of this place.
    pub fn at(&self) -> Time {
        self.0.ts.wall_ms()
    }

    /// The commit at this place (none at a time's).
    pub fn commit(&self) -> Option<CommitId> {
        (self.0 != engine::CommitPos::time(self.0.ts)).then_some(CommitId(self.0.id))
    }

    pub(crate) fn of(ts: Ts, id: CommitId) -> CommitPos {
        CommitPos(engine::CommitPos { ts, id: id.0 })
    }
}

/// The first hybrid time at `t`; past the last one it can name, the last.
fn ts_at(t: Time) -> Ts {
    Ts::make(t, 0).unwrap_or_else(|| Ts::make(Time(Ts::WALL_LIMIT - 1), 0xffff).unwrap_or_default())
}

impl std::fmt::Display for CommitPos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the time padded: texts sort as places do
        write!(f, "{:020}/{}", self.0.ts.to_u64(), CommitId(self.0.id))
    }
}

impl std::str::FromStr for CommitPos {
    type Err = Error;
    fn from_str(s: &str) -> Result<CommitPos> {
        let bad = || Error::Invalid(format!("not a commit place: {s:?}"));
        let (ts, id) = s.split_once('/').ok_or_else(bad)?;
        let ts = ts.parse().ok().and_then(Ts::from_u64).ok_or_else(bad)?;
        Ok(CommitPos::of(ts, id.parse()?))
    }
}

/// Where a page of commits starts, and which way it goes: `Newest` and `Before` towards older
/// commits, `Oldest` and `After` towards newer ones. Neither bound counts itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommitFrom {
    /// The newest commit, going older.
    #[default]
    Newest,
    /// The oldest commit, going newer.
    Oldest,
    /// Before this place, going older.
    Before(CommitPos),
    /// After this place, going newer.
    After(CommitPos),
}

impl CommitFrom {
    /// Whether it goes towards newer commits.
    pub(crate) fn newer(&self) -> bool {
        matches!(self, CommitFrom::Oldest | CommitFrom::After(_))
    }
}

#[doc(hidden)]
impl From<CommitFrom> for engine::CommitFrom {
    fn from(f: CommitFrom) -> engine::CommitFrom {
        match f {
            CommitFrom::Newest => engine::CommitFrom::Newest,
            CommitFrom::Oldest => engine::CommitFrom::Oldest,
            CommitFrom::Before(p) => engine::CommitFrom::Before(p.0),
            CommitFrom::After(p) => engine::CommitFrom::After(p.0),
        }
    }
}
