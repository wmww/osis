//! Ownerless things (spec/permissions.md §1, §3): no owner and no key, so no node ever acts
//! through an owner chain on them; their record names the first admin.

use super::{Done, recipient};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::rotation;
use crate::Mutation;
use osis_base::{CommitId, CreationRecord, Role, Tid};
use osis_keys::{ActorEpochs, ROLES};
use osis_schema::core_types as ct;

impl Engine {
    /// Creates an ownerless thing whose first admin is `admin` (this node, or an actor it is an
    /// admin of): one commit carries its record, its secrets of its own (spec/crypto.md §3:
    /// random, boxed to `admin` alone), its `keys.0` with a deposit seed and `admin`'s edge. Another `admin` gets
    /// the commit by inbox, as no label holds it yet.
    pub fn create_ownerless(&mut self, admin: &Tid) -> Result<(Tid, Done)> {
        let a = *admin;
        if a != self.tid() && self.role_on(&a) != Some(Role::Admin) {
            return Err(Error::Permission { tid: a });
        }
        let (t, c) = self.run(|tx| create_in(tx, a))?;
        let mut done = Done::default();
        done.add(c);
        if a != self.tid() {
            let d = self.run(|tx| rotation::deliver_rotation(tx, t, c, &[a]))?;
            done.deliveries.extend(d);
        }
        Ok((t, done))
    }
}

fn create_in(tx: &mut Tx<'_>, admin: Tid) -> Result<(Tid, Option<CommitId>)> {
    let mut nonce = [0u8; 32];
    tx.rng.fill_bytes(&mut nonce);
    let mut m = Mutation::new();
    let t = m.create(CreationRecord::Ownerless { admin, nonce });
    // no epoch to rotate from: the first of each role
    let held = ActorEpochs::default();
    let holders = [recipient(tx, admin, Role::Admin)?];
    let rot = rotation::rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &holders, &[])?;
    if !rot.secrets.boxes.keys().any(|k| k.holder == admin && k.role == Role::Read) {
        return Err(Error::Misuse("the first admin cannot be boxed"));
    }
    m.first.insert(t, rot.preview(&held)?);
    rotation::fresh_deposit_seed(tx, &mut m, t)?;
    // the record's edge as a `roles.0` entry too, so a removal has an entry to reset
    // (spec/crdt.md §5.6); applied through the record's edge itself
    let edge = ct::Edge { role: Role::Admin, until: None, invite: None, since: None, tied: None };
    super::put_edge(&mut m, t, admin, &edge)?;
    let c = Engine::commit_tx(tx, m)?;
    rotation::record(tx, t, &rot)?;
    Ok((t, c))
}
