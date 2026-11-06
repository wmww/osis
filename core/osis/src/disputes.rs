//! Admin disputes: two admins removed each other without having seen the other's removal, and
//! every node settles the fight for itself (spec/permissions.md §5.1, Trust set).

use crate::commit_id::CommitId;
use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::Tid;
use osis_node::sides::DisputeInfo;

/// Which admin a node follows in a dispute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The removal's author: its removal counts, and what the holder wrote that the author had
    /// not seen does not.
    Author,
    /// The removed holder: the author's removal does not count.
    Holder,
}

/// Names a dispute (`Osis::disputes`): the removal and whom it removes. Its text form
/// (`Display`, `FromStr`) keeps it anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisputeId {
    commit: osis_base::CommitId,
    op: u32,
    holder: Tid,
}

impl std::fmt::Display for DisputeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", osis_base::hex::encode(&self.commit.0), self.op, self.holder.to_uri())
    }
}

impl std::str::FromStr for DisputeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<DisputeId> {
        let bad = || Error::Invalid(format!("not a dispute id: {s}"));
        let mut it = s.splitn(3, ':');
        let (c, op, h) = (it.next().ok_or_else(bad)?, it.next().ok_or_else(bad)?, it.next().ok_or_else(bad)?);
        let commit = osis_base::CommitId(osis_base::hex::decode(c).and_then(|b| b.try_into().ok()).ok_or_else(bad)?);
        Ok(DisputeId { commit, op: op.parse().map_err(|_| bad())?, holder: h.parse().map_err(|_| bad())? })
    }
}

/// A fight between admins over `target`: `author` removed (or lowered) `holder` without having
/// seen writes of `holder`'s side that make the removal not count, so `holder` stays unless a
/// node takes `author`'s side. `side` is this node's: taken by default when the dispute was
/// found (the side its own role exists on, else whichever write it held first), or by
/// `choose_side` (`chosen`). Other nodes may stand on the other side until they switch: data
/// under `target` then differs between them.
#[derive(Clone, Debug, PartialEq, Eq)]
// each field is said above
#[allow(missing_docs)]
pub struct Dispute {
    pub id: DisputeId,
    pub target: Tid,
    pub author: Tid,
    pub holder: Tid,
    /// The removal's commit.
    pub commit: CommitId,
    pub side: Side,
    pub chosen: bool,
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
        Dispute { id: DisputeId { commit: d.commit, op: d.op, holder: d.holder }, target: d.target, author: d.author, holder: d.holder, commit: CommitId::commit(d.commit), side, chosen }
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
            Ok((ds.iter().map(Dispute::of).collect(), left))
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

    /// Takes a side in a dispute, for this node, until chosen again. Switching may re-read
    /// everything under the thing and is slow on a long history. `Invalid` when no such
    /// removal is held; `Unsupported` on a thin client.
    pub fn choose_side(&self, id: DisputeId, side: Side) -> Result<()> {
        if !self.has_store() {
            return Err(Error::Unsupported("choose_side".into()));
        }
        self.locked(|l| Ok(l.engine().choose(id.commit, id.op, id.holder, side == Side::Author)?))
    }
}
