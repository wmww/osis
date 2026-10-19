//! Sharing, devices, links, cards and sync (notes/api.md Sharing and membership, Sync
//! configuration and status). The surface is fixed here; the bodies arrive with
//! membership-flows and node-sync (plans/api.md second half) and return `Unsupported` until
//! then. `move_thing` and `same_thing` work now.

use crate::error::{Error, Result};
use crate::handle::{Config, Osis};
use crate::write::Place;
use osis_core::{Role, Tid, WallMs};
use osis_schema::core_types::MOVED;
use std::collections::BTreeMap;
use std::time::Duration;

const LATER: &str = "sharing and sync (plans/api.md second half)";

/// `until` and `invite` of an edge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EdgeOpts {
    pub until: Option<WallMs>,
    pub invite: Option<Role>,
}

/// Whether a demotion waits for its pre-sync (spec/permissions.md §5.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WaitForSync {
    /// Fail with `Unsynced` when a group cannot be synced.
    #[default]
    Required,
    /// Proceed after the timeout, with a diagnostic.
    Try(Duration),
    /// Stamp now (a stolen device).
    Skip,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Demotion {
    pub sync: WaitForSync,
    pub backdate: Option<WallMs>,
}

/// The role after a demotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lower {
    To(Role),
    Remove,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkOpts {
    pub until: Option<WallMs>,
    pub single_use: bool,
}

macro_rules! text_type {
    ($(#[$m:meta])* $n:ident) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $n(String);
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                if s.trim().is_empty() { Err(Error::Invalid(concat!("empty ", stringify!($n)).into())) } else { Ok($n(s.trim().to_string())) }
            }
        }
        impl std::fmt::Display for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

text_type!(
    /// A server: transport URL plus its key.
    ServerAddr
);
text_type!(
    /// A share link (URL form).
    ShareLink
);
text_type!(
    /// A contact card.
    ContactCard
);
text_type!(
    /// A recovery card (holds the recovery seed: show or store it, osis keeps none of it).
    RecoveryCard
);
text_type!(
    /// A short-lived device pairing offer.
    PairOffer
);

/// A device of the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    pub node: Tid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    Synced,
    Syncing,
    Unreachable,
    /// Waiting for a re-seal (spec/permissions.md §3).
    Stranded,
    NoServers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupSync {
    pub state: SyncState,
    pub pending_uploads: usize,
    pub last_sync: Option<WallMs>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub groups: BTreeMap<Tid, GroupSync>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    All,
    Group(Tid),
}

impl Osis {
    /// Restores a person on a fresh device from its recovery card.
    pub async fn restore(_cfg: Config, _card: &RecoveryCard) -> Result<Osis> {
        Err(Error::Unsupported(LATER))
    }
    /// Joins as a new device of the person that made `offer`.
    pub async fn pair(_cfg: Config, _offer: &PairOffer) -> Result<Osis> {
        Err(Error::Unsupported(LATER))
    }

    /// Grants `member` `role` on `target` (needs the member's `/keys`).
    pub fn grant(&self, _target: Tid, _member: Tid, _role: Role, _opts: EdgeOpts) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    /// Changes `until`/`invite` or raises the role of an edge.
    pub fn change_edge(&self, _target: Tid, _member: Tid, _role: Role, _opts: EdgeOpts) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    /// Lowers or removes an edge after the pre-sync.
    pub async fn demote(&self, _target: Tid, _member: Tid, _to: Lower, _d: Demotion) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    /// Removes this person's own edge on `target`.
    pub fn leave(&self, _target: Tid) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    pub fn make_link(&self, _target: Tid, _role: Role, _opts: LinkOpts) -> Result<ShareLink> {
        Err(Error::Unsupported(LATER))
    }
    pub async fn redeem(&self, _link: &ShareLink) -> Result<Tid> {
        Err(Error::Unsupported(LATER))
    }
    pub fn contact_card(&self) -> Result<ContactCard> {
        Err(Error::Unsupported(LATER))
    }
    pub fn import_contact(&self, _card: &ContactCard) -> Result<Tid> {
        Err(Error::Unsupported(LATER))
    }
    pub fn pair_offer(&self) -> Result<PairOffer> {
        Err(Error::Unsupported(LATER))
    }
    pub fn devices(&self) -> Result<Vec<Device>> {
        Err(Error::Unsupported(LATER))
    }
    pub async fn remove_device(&self, _node: Tid, _d: Demotion) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    pub fn servers(&self) -> Result<Vec<ServerAddr>> {
        Err(Error::Unsupported(LATER))
    }
    pub fn add_server(&self, _s: &ServerAddr) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    pub fn remove_server(&self, _s: &ServerAddr) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    /// Makes `group` synced through `servers` (admin of the group).
    pub fn sync(&self, _group: Tid, _servers: &[ServerAddr]) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    pub fn unsync(&self, _group: Tid) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    pub fn status(&self) -> Result<Status> {
        Err(Error::Unsupported(LATER))
    }
    pub async fn wait_synced(&self, _scope: SyncScope, _timeout: Duration) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }
    pub fn sync_now(&self) -> Result<()> {
        Err(Error::Unsupported(LATER))
    }

    /// Moves `tid` to `owner` (spec/permissions.md §7): a copy with a new tid and the held
    /// history imported, `/was` on the copy, `/moved` on the old thing when this node is its
    /// admin; the copy is placed per `place`. Reads and writes through the old tid then reach
    /// the copy. Re-granting the old roster on the copy comes with membership flows.
    pub fn move_thing(&self, tid: Tid, owner: Tid, place: Place) -> Result<Tid> {
        let tid = self.read(|r| r.resolve(tid));
        if !self.knows(owner) {
            return Err(Error::UnknownThing { tid: owner });
        }
        let admin = self.role_on(tid) == Some(Role::Admin);
        let copy = self.engine(|e| -> Result<Tid> {
            let (copy, _) = e.move_thing(&tid, owner)?;
            if admin {
                let mut m = osis_node::Mutation::new();
                m.set(tid, &MOVED, &copy)?;
                e.commit(m)?;
            }
            Ok(copy)
        })?;
        let groups = match place {
            Place::In(g) => vec![g],
            Place::InAll(gs) => gs,
            Place::Unsynced => Vec::new(),
        };
        if !groups.is_empty() {
            self.write_with(|w| {
                for g in groups {
                    w.place(copy, g)?;
                }
                Ok(())
            })?;
        }
        Ok(copy)
    }
}
