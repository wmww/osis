//! Disputes, which every node settles for itself: two admins removed each other without having
//! seen the other's removal (spec/permissions.md §5.1, Trust set).

use crate::commit_id::CommitId;
use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::Tid;
use osis_engine::sides::DisputeInfo;

/// Which side a node follows in a dispute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Of a removal: its author, so the removal counts, and what the holder wrote that the
    /// author had not seen does not.
    Author,
    /// Of a removal: the removed holder, so the removal does not count.
    Holder,
}

/// Names a dispute (`Osis::disputes`). Its text form (`Display`, `FromStr`) keeps it anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisputeId(Key);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Key {
    /// A removal: the commit, the write in it, whom it removes.
    Removal { commit: osis_base::CommitId, op: u32, holder: Tid },
}

impl std::fmt::Display for DisputeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Key::Removal { commit, op, holder } => write!(f, "{}:{}:{}", osis_base::hex::encode(&commit.0), op, holder.to_uri()),
        }
    }
}

impl std::str::FromStr for DisputeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<DisputeId> {
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
}

/// Whether `on_dispute` tells of `d`: as `disputes` lists them, over a thing this node reads.
pub(crate) fn shown(db: &Osis, d: &Dispute) -> bool {
    !matches!(d, Dispute::Removal { target, .. } if db.role_on(*target).ok().flatten() < Some(osis_base::Role::Read))
}

/// Open removal disputes `disputes` lists at most beside those with a recorded side (a removed
/// admin can sign any number); the rest are counted. A resource bound: at 0 only recorded sides
/// are listed and the rest counted, at infinity a hostile flood of k removals lists k per call.
const LIST_MAX: usize = 64;

impl Dispute {
    /// Interim (issues/key-grant-disputes-unlisted.md): `None` for a dispute over a key's grant,
    /// until the API names keys.
    pub(crate) fn of(d: &DisputeInfo) -> Option<Dispute> {
        let osis_base::Holder::Thing(holder) = d.holder else { return None };
        let (side, chosen) = match d.side {
            Some(s) => (if s.trust { Side::Author } else { Side::Holder }, s.chosen),
            None => (Side::Holder, false),
        };
        Some(Dispute::Removal { id: DisputeId(Key::Removal { commit: d.commit, op: d.op, holder }), target: d.target, author: d.author, holder, commit: CommitId(d.commit), side, chosen })
    }

    /// Its name.
    pub fn id(&self) -> DisputeId {
        match self {
            Dispute::Removal { id, .. } => *id,
        }
    }

    /// The side this node follows.
    pub fn side(&self) -> Side {
        match self {
            Dispute::Removal { side, .. } => *side,
        }
    }

    /// Whether the side was chosen (`Osis::choose_side`), not taken by default.
    pub fn chosen(&self) -> bool {
        match self {
            Dispute::Removal { chosen, .. } => *chosen,
        }
    }
}

impl Osis {
    /// The open disputes this node knows of, with the side it stands on in each. Every one is
    /// found, but a hostile flood of them could make the list as long as the flood, so only some
    /// are listed (always those a side was chosen in): the second value is how many were left out.
    /// `Unsupported` on a client with a thing of its own.
    pub fn disputes(&self) -> Result<(Vec<Dispute>, usize)> {
        if let Some(at) = self.process_at("disputes")? {
            return self.forward(&at, crate::port::method::DISPUTES, ());
        }
        self.locked(|l| {
            let (ds, left) = l.engine().disputes(LIST_MAX);
            // over a thing this node reads: another's roster is not its to show (`grants`)
            let out: Vec<Dispute> = ds.iter().filter(|d| l.engine().role_on(&d.target) >= Some(osis_base::Role::Read)).filter_map(Dispute::of).collect();
            Ok((out, left))
        })
    }

    /// Calls `f` with every dispute as this node finds one, with the side it took by default.
    /// `Unsupported` on a client with a thing of its own.
    pub fn on_dispute(&self, mut f: impl FnMut(&Osis, Dispute) + Send + 'static) -> Result<Subscription> {
        if let Some(at) = self.process_at("on_dispute")? {
            return self.remote_disputes(&at, f);
        }
        Ok(self.subscribe(Filter::Disputes, false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Dispute(x) = d
                    && shown(db, &x)
                {
                    f(db, x)
                }
            })
        }))
    }

    /// Takes a side in a dispute, for this node, until chosen again: `Author` or `Holder` of a
    /// removal. Switching may re-read everything the dispute touches and is slow on a long
    /// history. `Invalid` when no such removal is held; `Unsupported` on a client with a thing of its own.
    pub fn choose_side(&self, id: DisputeId, side: Side) -> Result<()> {
        if let Some(at) = self.process_at("choose_side")? {
            return self.forward(&at, crate::port::method::CHOOSE_SIDE, (id, side));
        }
        let Key::Removal { commit, op, holder } = id.0;
        self.locked(|l| Ok(l.engine().choose(commit, op, osis_base::Holder::Thing(holder), side == Side::Author)?))
    }
}
