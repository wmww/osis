//! `CommitId` and `HistoryPos`: opaque names an app keeps, compares and passes back. What they hold
//! (a commit's hash, a hybrid clock value) stays inside.

use crate::error::{Error, Result};
use osis_base::hex;
use osis_base::{CommitId as RawCommitId, Ts, Time};
use osis_node::engine::history as engine;

/// Names one commit: what `Write::commit` returns, a history entry or watch names, and `revert` or
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

/// A place in an aspect's history, for `HistoryFrom::Before` and `After`: an entry's or a commit's
/// (`HistoryEntry::pos`, `Commit::pos`), or a time's. Places order as the history does, and the
/// text form (`Display`, `FromStr`) keeps one anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryPos(pub(crate) engine::HistoryPos);

impl HistoryPos {
    /// The place before everything written at `t` or later.
    pub fn time(t: Time) -> HistoryPos {
        HistoryPos(engine::HistoryPos::time(ts_at(t)))
    }

    /// The time of this place.
    pub fn at(&self) -> Time {
        self.0.ts.wall_ms()
    }

    /// The commit at this place (none at a time's).
    pub fn commit(&self) -> Option<CommitId> {
        (self.0 != engine::HistoryPos::time(self.0.ts)).then_some(CommitId(self.0.id))
    }

    pub(crate) fn of(ts: Ts, id: CommitId) -> HistoryPos {
        HistoryPos(engine::HistoryPos { ts, id: id.0 })
    }
}

/// The first hybrid time at `t`; past the last one it can name, the last.
fn ts_at(t: Time) -> Ts {
    Ts::make(t, 0).unwrap_or_else(|| Ts::make(Time(Ts::WALL_LIMIT - 1), 0xffff).unwrap_or_default())
}

impl std::fmt::Display for HistoryPos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.0.ts.to_u64(), CommitId(self.0.id))
    }
}

impl std::str::FromStr for HistoryPos {
    type Err = Error;
    fn from_str(s: &str) -> Result<HistoryPos> {
        let bad = || Error::Invalid(format!("not a history place: {s:?}"));
        let (ts, id) = s.split_once('/').ok_or_else(bad)?;
        let ts = ts.parse().ok().and_then(Ts::from_u64).ok_or_else(bad)?;
        Ok(HistoryPos::of(ts, id.parse()?))
    }
}

/// Where a page of history starts, and which way it goes: `Newest` and `Before` towards older
/// entries, `Oldest` and `After` towards newer ones. Neither bound counts itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryFrom {
    /// The newest entry, going older.
    Newest,
    /// The oldest entry, going newer.
    Oldest,
    /// Before this place, going older.
    Before(HistoryPos),
    /// After this place, going newer.
    After(HistoryPos),
}

#[doc(hidden)]
impl From<HistoryFrom> for engine::HistoryFrom {
    fn from(f: HistoryFrom) -> engine::HistoryFrom {
        match f {
            HistoryFrom::Newest => engine::HistoryFrom::Newest,
            HistoryFrom::Oldest => engine::HistoryFrom::Oldest,
            HistoryFrom::Before(p) => engine::HistoryFrom::Before(p.0),
            HistoryFrom::After(p) => engine::HistoryFrom::After(p.0),
        }
    }
}
