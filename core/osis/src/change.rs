//! `ChangeId` and `HistoryPos`: opaque names an app keeps, compares and passes back. What they hold
//! (a commit or an ephemeral batch, a hybrid clock value) stays inside.

use crate::error::{Error, Result};
use osis_base::hex;
use osis_base::{CommitId, Ts, Time};
use osis_node::EphemeralId;
use osis_node::engine::history as engine;

/// One change: what `Write::commit` returns, a history entry or watch names, and `revert` or
/// `Purge::Change` takes. Its text form (`Display`, `FromStr`) keeps it anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeId(pub(crate) osis_node::ChangeId);

impl ChangeId {
    pub(crate) fn commit(c: CommitId) -> ChangeId {
        ChangeId(osis_node::ChangeId::Commit(c))
    }
}

#[doc(hidden)]
impl From<osis_node::ChangeId> for ChangeId {
    fn from(c: osis_node::ChangeId) -> ChangeId {
        ChangeId(c)
    }
}

#[doc(hidden)]
impl From<CommitId> for ChangeId {
    fn from(c: CommitId) -> ChangeId {
        ChangeId::commit(c)
    }
}

impl std::fmt::Display for ChangeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            osis_node::ChangeId::Commit(c) => f.write_str(&hex::encode(&c.0)),
            osis_node::ChangeId::Ephemeral(e) => write!(f, "ephemeral:{}:{}", hex::encode(&e.session), e.n),
        }
    }
}

impl std::str::FromStr for ChangeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<ChangeId> {
        let bad = || Error::Invalid(format!("not a change id: {s:?}"));
        if let Some(rest) = s.strip_prefix("ephemeral:") {
            let (session, n) = rest.split_once(':').ok_or_else(bad)?;
            let session = hex::decode(session).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
            return Ok(ChangeId(osis_node::ChangeId::Ephemeral(EphemeralId { session, n: n.parse().map_err(|_| bad())? })));
        }
        let c = hex::decode(s).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(bad)?;
        Ok(ChangeId::commit(CommitId(c)))
    }
}

/// A place in an aspect's history, for `HistoryFrom::Before` and `After`: an entry's or a batch's
/// (`HistoryEntry::pos`, `Committed::pos`), or a time's. Places order as the history does, and the
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

    /// The change at this place (none at a time's).
    pub fn change(&self) -> Option<ChangeId> {
        (self.0 != engine::HistoryPos::time(self.0.ts)).then_some(ChangeId(self.0.id))
    }

    pub(crate) fn of(ts: Ts, id: ChangeId) -> HistoryPos {
        HistoryPos(engine::HistoryPos { ts, id: id.0 })
    }
}

/// The first hybrid time at `t`; past the last one it can name, the last.
fn ts_at(t: Time) -> Ts {
    Ts::make(t, 0).unwrap_or_else(|| Ts::make(Time(Ts::WALL_LIMIT - 1), 0xffff).unwrap_or_default())
}

impl std::fmt::Display for HistoryPos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.0.ts.to_u64(), ChangeId(self.0.id))
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
    Newest,
    Oldest,
    Before(HistoryPos),
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
