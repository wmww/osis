//! Disputes, which every node settles for itself: two admins removed each other without having
//! seen the other's removal (spec/permissions.md §5.1, Trust set), or an account's history forked
//! (spec/permissions.md §5.4).

use crate::commit_id::CommitId;
use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::Tid;
use osis_node::sides::DisputeInfo;

/// Which side a node follows in a dispute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Of a removal: its author, so the removal counts, and what the holder wrote that the
    /// author had not seen does not.
    Author,
    /// Of a removal: the removed holder, so the removal does not count.
    Holder,
    /// Of an account's history: the version that ends in this change of the account's.
    Line(CommitId),
}

/// Names a dispute (`Osis::disputes`). Its text form (`Display`, `FromStr`) keeps it anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisputeId(Key);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Key {
    /// A removal: the commit, the write in it, whom it removes.
    Removal { commit: osis_base::CommitId, op: u32, holder: Tid },
    Account(Tid),
}

impl std::fmt::Display for DisputeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Key::Removal { commit, op, holder } => write!(f, "{}:{}:{}", osis_base::hex::encode(&commit.0), op, holder.to_uri()),
            Key::Account(a) => write!(f, "{}", a.to_uri()),
        }
    }
}

impl std::str::FromStr for DisputeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<DisputeId> {
        if let Ok(a) = Tid::parse(s) {
            return Ok(DisputeId(Key::Account(a)));
        }
        let bad = || Error::Invalid(format!("not a dispute id: {s}"));
        let mut it = s.splitn(3, ':');
        let (c, op, h) = (it.next().ok_or_else(bad)?, it.next().ok_or_else(bad)?, it.next().ok_or_else(bad)?);
        let commit = osis_base::CommitId(osis_base::hex::decode(c).and_then(|b| b.try_into().ok()).ok_or_else(bad)?);
        Ok(DisputeId(Key::Removal { commit, op: op.parse().map_err(|_| bad())?, holder: h.parse().map_err(|_| bad())? }))
    }
}

/// A fight this node settles for itself. `side` is this node's: taken by default when the
/// dispute was found, or by `choose_side` (`chosen`). Other nodes may stand on another side
/// until they switch: what they read then differs.
#[derive(Clone, Debug, PartialEq, Eq)]
// each field is said above
#[allow(missing_docs)]
pub enum Dispute {
    /// Between admins over `target`: `author` removed (or lowered) `holder` in `commit` without
    /// having seen writes of `holder`'s side that make the removal not count, so `holder` stays
    /// unless a node takes `author`'s side. By default a node takes the side its own role
    /// exists on, else whichever write it held first.
    Removal { id: DisputeId, target: Tid, author: Tid, holder: Tid, commit: CommitId, side: Side, chosen: bool },
    /// Over `account`'s history, which forked into versions ending in `lines` (as when a device
    /// removed from the account keeps writing as it): the node reads one, by default the one it
    /// received first. Told only when that may be wrong; the account's own devices read the
    /// version their device list holds.
    Account { id: DisputeId, account: Tid, lines: Vec<CommitId>, side: Side, chosen: bool },
}

/// Candidates `disputes` examines at most (each costs a walk of the role history: a removed
/// admin can sign any number); the rest are counted. A resource bound: at 0 the list is empty
/// and everything counted, at infinity a hostile flood of k writes costs k walks per call.
const LIST_MAX: usize = 64;

impl Dispute {
    pub(crate) fn of(d: &DisputeInfo) -> Dispute {
        let (side, chosen) = match d.side {
            Some(s) => (if s.trust { Side::Author } else { Side::Holder }, s.chosen),
            None => (Side::Holder, false),
        };
        Dispute::Removal { id: DisputeId(Key::Removal { commit: d.commit, op: d.op, holder: d.holder }), target: d.target, author: d.author, holder: d.holder, commit: CommitId(d.commit), side, chosen }
    }

    pub(crate) fn of_account(account: Tid, lines: &[osis_base::CommitId], side: osis_base::CommitId, chosen: bool) -> Dispute {
        Dispute::Account { id: DisputeId(Key::Account(account)), account, lines: lines.iter().map(|l| CommitId(*l)).collect(), side: Side::Line(CommitId(side)), chosen }
    }

    /// Its name.
    pub fn id(&self) -> DisputeId {
        match self {
            Dispute::Removal { id, .. } | Dispute::Account { id, .. } => *id,
        }
    }

    /// The side this node follows.
    pub fn side(&self) -> Side {
        match self {
            Dispute::Removal { side, .. } | Dispute::Account { side, .. } => *side,
        }
    }

    /// Whether the side was chosen (`Osis::choose_side`), not taken by default.
    pub fn chosen(&self) -> bool {
        match self {
            Dispute::Removal { chosen, .. } | Dispute::Account { chosen, .. } => *chosen,
        }
    }
}

impl Osis {
    /// The open disputes this node knows of, with the side it stands on in each. Finding them
    /// costs a walk of a thing's role history per contestable removal, so a hostile flood of
    /// them leaves some uncounted here: the second value is how many were not examined.
    /// `Unsupported` on a thin client.
    pub fn disputes(&self) -> Result<(Vec<Dispute>, usize)> {
        if !self.has_store() {
            return Err(Error::Unsupported("disputes".into()));
        }
        self.locked(|l| {
            let (ds, left) = l.engine().disputes(LIST_MAX);
            let mut out: Vec<Dispute> = ds.iter().map(Dispute::of).collect();
            out.extend(l.engine().account_disputes().iter().map(|a| Dispute::of_account(a.account, &a.lines, a.side, a.chosen)));
            Ok((out, left))
        })
    }

    /// Calls `f` with every dispute as this node finds one, with the side it took by default.
    /// `Unsupported` on a thin client.
    pub fn on_dispute(&self, mut f: impl FnMut(&Osis, Dispute) + Send + 'static) -> Result<Subscription> {
        if !self.has_store() {
            return Err(Error::Unsupported("on_dispute".into()));
        }
        Ok(self.subscribe(Filter::Disputes, false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Dispute(x) = d {
                    f(db, x)
                }
            })
        }))
    }

    /// Takes a side in a dispute, for this node, until chosen again: `Author` or `Holder` of a
    /// removal, a `Line` of an account's history (one of its `lines`, or any change of the
    /// account's ending a version). Switching may re-read everything the dispute touches and is
    /// slow on a long history. `Invalid` when no such removal or change is held, or the side is
    /// of another kind of dispute; `Unsupported` on a thin client.
    pub fn choose_side(&self, id: DisputeId, side: Side) -> Result<()> {
        if !self.has_store() {
            return Err(Error::Unsupported("choose_side".into()));
        }
        let misfit = || Error::Invalid(format!("{side:?} is no side of dispute {id}"));
        self.locked(|l| match (id.0, side) {
            (Key::Removal { commit, op, holder }, Side::Author | Side::Holder) => Ok(l.engine().choose(commit, op, holder, side == Side::Author)?),
            (Key::Account(a), Side::Line(c)) => Ok(l.engine().choose_line(a, c.0)?),
            _ => Err(misfit()),
        })
    }
}
