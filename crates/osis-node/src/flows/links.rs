//! Share links (spec/permissions.md §9, spec/wire.md §10): K an actor owned by the sharer with
//! secrets of its own, a member of the target with the link's role; L a key actor from the
//! link's seed with (r, invite r) on K, listed in K's label steps by static entry. Redeem (an
//! invite grant signed as L, single use with L's self-removal in the same commit), bearer use,
//! finalization and revoking a joiner are demotions by a sharer device.

use super::labels::{ReaderKey, new_label};
use super::person::key_actor_keys;
use super::{Delivery, Done, put_edge, secrets_in};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::edges::grant_in;
use crate::identity::key_actor_record;
use crate::rotation;
use crate::Mutation;
use osis_core::{Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{KeyActorKeys, Secret32};
use osis_keys::{MemberKeys, Recipient, box_member, roles_up_to};
use osis_label::{Address, ShareLink};
use osis_schema::Codec;
use osis_schema::core_types::{self as ct, Edge, Inbox};

/// The untyped aspect of the sharer-only thing that keeps a link's seed.
pub const LINK_SEED: &str = "/link/seed";

/// What a sharer asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSpec {
    pub target: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
    pub servers: Vec<Address>,
    pub peers: Vec<osis_label::Peer>,
}

impl Engine {
    /// Creates a link to `spec.target` for actor `sharer` (an actor this node is admin of):
    /// K (owned by `sharer`, secrets of its own, home label on `spec.servers` listing L by
    /// static entry), L (key actor from a fresh seed, `/created` and `/keys` signed by itself),
    /// L's edge (r, invite r, `until`) on K with its boxes, K's edge on the target, and a
    /// sharer-only thing keeping the seed. Returns the link and the seed thing.
    pub fn create_link(&mut self, sharer: &Tid, spec: &LinkSpec) -> Result<(ShareLink, Tid, Done)> {
        let mut sb = [0u8; 32];
        self.run(|tx| {
            tx.rng.fill_bytes(&mut sb);
            Ok(())
        })?;
        let seed = Secret32::from_bytes(sb);
        let l = self.hold_key_actor(seed.clone())?;
        let res = self.run(|tx| create_link_in(tx, *sharer, spec, l, &seed));
        self.drop_key_actor(&l);
        let (k, k_label, keep, done) = res?;
        Ok((ShareLink { seed, target: spec.target, k, k_label, servers: spec.servers.clone(), peers: spec.peers.clone() }, keep, done))
    }

    /// Redeems a link once K's label was claimed by L's static entry and downloaded (node-sync;
    /// `hold_key_actor(link.seed)` came first so L's boxes open): signing as L, an invite grant
    /// of `grantee` (this node's actor, or this node) to K with the link's role and K's boxes;
    /// `single_use` also removes L's own edge in the same commit. Deposited under K's label
    /// unless the role is write or above. The seed is dropped afterwards.
    pub fn redeem(&mut self, link: &ShareLink, grantee: &Tid, single_use: bool) -> Result<Done> {
        let l = self.hold_key_actor(link.seed.clone())?;
        let res = self.redeem_in(l, link, *grantee, single_use);
        self.drop_key_actor(&l);
        res
    }

    fn redeem_in(&mut self, l: Tid, link: &ShareLink, grantee: Tid, single_use: bool) -> Result<Done> {
        let k = link.k;
        let edge = self.roster(&k).get(&l).copied().ok_or(Error::Misuse("the link is no member of K (finalized or unknown)"))?;
        if !edge.alive_at(Some(osis_core::Ts::make(self.now(), 0).unwrap_or_default())) {
            return Err(Error::Misuse("the link expired"));
        }
        let grant = Edge { role: edge.role, until: None, invite: None, since: None };
        let mut done = self.run(|tx| grant_in(tx, Some(l), k, grantee, &grant, single_use))?;
        if edge.role >= Role::Write {
            done.deliveries.retain(|d| !matches!(d, Delivery::Deposit { .. }));
        }
        Ok(done)
    }

    /// Finalizes a link (spec/permissions.md §9): a sharer device's plain removal of L from K,
    /// an explicit demotion (frontier, K's rotation), after `until` passed or to revoke the
    /// link. A single-use link whose L already removed itself has no edge left to remove
    /// (issues/link-finalization.md): an error.
    pub fn finalize_link(&mut self, k: &Tid, l: &Tid) -> Result<Done> {
        let has = self.core.timelines.get(k).is_some_and(|tl| tl.edges_at(None).get(l, k).is_some());
        if !has {
            return Err(Error::Misuse("no edge of the link key left to remove (issues/link-finalization.md)"));
        }
        self.demote(k, &crate::flows::Demotion { member: *l, new: None, presync: crate::flows::PreSync::Synced })
    }

    /// Revokes one joiner of a link (spec/permissions.md §9): removes it and L from K (it may
    /// still hold the seed); the remaining joiners need a new link.
    pub fn revoke_joiner(&mut self, k: &Tid, l: &Tid, joiner: &Tid, presync: crate::flows::PreSync) -> Result<Done> {
        let mut done = self.demote(k, &crate::flows::Demotion { member: *joiner, new: None, presync })?;
        if self.core.timelines.get(k).is_some_and(|tl| tl.edges_at(None).get(l, k).is_some()) {
            done.extend(self.demote(k, &crate::flows::Demotion { member: *l, new: None, presync })?);
        }
        Ok(done)
    }

    /// Bearer use (spec/permissions.md §9): act as L without writing anything; reads open
    /// through L's boxes once K's label is downloaded. Returns L.
    pub fn bear(&mut self, link: &ShareLink) -> Result<Tid> {
        self.hold_key_actor(link.seed.clone())
    }
}

fn create_link_in(tx: &mut Tx<'_>, sharer: Tid, spec: &LinkSpec, l: Tid, seed: &Secret32) -> Result<(Tid, osis_core::LabelId, Tid, Done)> {
    let me = tx.core.id.tid();
    if tx.core.role_now(&me, &sharer) != Some(Role::Admin) {
        return Err(Error::Permission { tid: sharer });
    }
    let mut done = Done::default();
    // L: creation and /keys, signed by itself
    let lkeys = KeyActorKeys::from_seed(seed);
    let mut m = Mutation::new();
    m.create(key_actor_record(&lkeys, seed));
    m.sign_as(l);
    key_actor_keys(&mut m, l, &lkeys)?;
    done.add(Engine::commit_tx(tx, m)?);
    // K, with secrets of its own
    let mut m = Mutation::new();
    let k = m.create(crate::identity::thing_record(sharer, &mut *tx.rng));
    done.add(Engine::commit_tx(tx, m)?);
    done.add(rotation::own_secrets(tx, k)?);
    // L's edge (r, invite r, until) with its boxes, K's home label listing L, K's inbox
    let epochs = tx.core.epochs(&k).ok_or(Error::Misuse("K's secrets"))?;
    let secrets = secrets_in(tx, &k)?;
    let rcpt = Recipient { member: l, role: spec.role, keys: MemberKeys::KeyActor { kem: lkeys.kem.public().clone(), seed: None } };
    let boxes = box_member(&k, &epochs, &secrets, &rcpt, &roles_up_to(spec.role), &mut *tx.rng)?.ok_or(Error::Misuse("L's keys"))?;
    let mut m = Mutation::new();
    put_edge(&mut m, k, l, &Edge { role: spec.role, until: spec.until, invite: Some(spec.role), since: None })?;
    super::put_secrets(&mut m, k, &boxes)?;
    done.add(Engine::commit_tx(tx, m)?);
    let epochs = tx.core.epochs(&k).ok_or(Error::Misuse("K's secrets"))?;
    let (re, _) = epochs.role(Role::Read).newest_held().ok_or(Error::Misuse("K's read secret"))?;
    let readers: Vec<ReaderKey> = super::labels::readers(tx, &k, &re)?;
    let deposit = osis_crypto::Secret32::from_bytes(super::super::flows::deposit_of(tx, &k)?);
    let mut m = Mutation::new();
    let label = new_label(tx, &mut m, k, &epochs, &readers, &deposit, &spec.servers)?;
    m.op(k, &ct::KEYS, PathOp { path: vec![PathSeg::Field(4)], op: Op::Set(Some(Inbox { label, servers: spec.servers.clone() }).to_value()) })?;
    done.add(Engine::commit_tx(tx, m)?);
    // K on the target
    let target_edge = Edge { role: spec.role, until: None, invite: None, since: None };
    done.extend(grant_in(tx, None, spec.target, k, &target_edge, false)?);
    // the seed on a thing only the sharer's actor reads (derived secrets)
    let mut m = Mutation::new();
    let keep = m.create(crate::identity::thing_record(sharer, &mut *tx.rng));
    m.op(keep, &super::ak(LINK_SEED)?, PathOp { path: Vec::new(), op: Op::Set(Value::Map([(Value::Int(0), Value::Tid(k)), (Value::Int(1), Value::Bytes(seed.expose().to_vec()))].into_iter().collect())) })?;
    done.add(Engine::commit_tx(tx, m)?);
    Ok((k, label, keep, done))
}
