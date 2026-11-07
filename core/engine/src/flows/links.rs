//! Share links (spec/permissions.md §7, spec/wire.md §10): K an actor whose first admin is the sharer's actor, with
//! secrets of its own, a holder of the target with the link's role; L a key actor from the
//! link's seed with (r, invite r) on K, listed in K's label steps by static entry. Redeem (an
//! invite grant signed as L, single use with L's self-removal in the same commit), bearer use,
//! finalization and revoking a joiner are demotions by a sharer node.

use super::labels::{ReaderKey, name_inbox, new_label};
use super::person::key_actor_keys;
use super::{Delivery, Done, put_edge};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::edges::grant_in;
use crate::identity::key_actor_record;
use crate::rotation;
use crate::Mutation;
use osis_base::{Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_crypto::{KeyActorKeys, Secret32};
use osis_keys::{HolderKeys, Recipient, box_holder, roles_up_to};
use osis_label::{Address, ShareLink};
use osis_schema::core_types::{self as ct, Edge};
use std::sync::Arc;

/// The untyped aspect of the sharer-only thing that keeps a link's seed.
pub const LINK_SEED: &str = "link:seed.0";

/// A link whose seed this node holds (`Engine::held_links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HeldLink {
    pub k: Tid,
    pub l: Tid,
    /// The seed thing's first admin (the sharer's actor): only a K with that first admin counts
    /// (a seed thing a co-reader made and placed in a shared group names no link of ours).
    pub first_admin: Tid,
    pub target: Tid,
    pub single_use: bool,
    /// This node wrote the seed: it made the link, so a redeemer of a link without hosts
    /// reached this node.
    pub here: bool,
}

/// What a sharer asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSpec {
    pub target: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
    pub hosts: Vec<Address>,
    pub peers: Vec<osis_label::Peer>,
    /// The link's `flags` bit 0: its redemption removes L (spec/permissions.md §7).
    pub single_use: bool,
}

impl Engine {
    /// Creates a link to `spec.target` for actor `sharer` (an actor this node is admin of):
    /// K (first admin `sharer`, secrets of its own, home label on `spec.hosts` listing L by
    /// static entry), L (key actor from a fresh seed, `created.0` and `keys.0` signed by itself),
    /// L's edge (r, invite r, `until`) on K with its boxes, K's edge on the target, and a
    /// sharer-only thing keeping the seed. Returns the link and the seed thing.
    pub fn create_link(&mut self, sharer: &Tid, spec: &LinkSpec) -> Result<(ShareLink, Tid, Done)> {
        // a fresh seed, never copied to an unwiped stack array
        let seed = self.run(|tx| Ok(Secret32::random(&mut *tx.rng)))?;
        let l = self.hold_key_actor(seed.clone())?;
        let res = self.run(|tx| create_link_in(tx, *sharer, spec, l, &seed));
        self.drop_key_actor(&l);
        let (k, k_label, keep, done) = res?;
        Ok((ShareLink { seed, target: spec.target, k, k_label, hosts: spec.hosts.clone(), peers: spec.peers.clone(), single_use: spec.single_use }, keep, done))
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
        let edge = self.roster(&k).get(&l).copied().ok_or(Error::Misuse("the link is no holder of K (finalized or unknown)"))?;
        if !edge.alive_at(Some(osis_base::Ts::make(self.now(), 0).unwrap_or_default())) {
            return Err(Error::Misuse("the link expired"));
        }
        let grant = Edge { role: edge.role, until: None, invite: None, tied: None };
        // L signs with its own role, so `grant_in` deposits only below write
        self.run(|tx| grant_in(tx, Some(l), k, grantee, &grant, single_use))
    }

    /// Whether the held role history shows `holder` put on `thing` and its edge over: removed, or
    /// past `until` (spec/permissions.md §7). A holder not seen yet says nothing: its edge may be
    /// on its way.
    pub fn edge_gone(&mut self, thing: &Tid, holder: &Tid) -> bool {
        let ts = super::now_ts(&self.core);
        self.core.timelines.get(thing).is_some_and(|tl| tl.ended(thing, ts).contains_key(holder))
    }

    /// Finalizes a link (spec/permissions.md §7): a sharer node's plain removal of L from K,
    /// an explicit demotion with the sharer's frontier, after `until` passed, after a single-use
    /// redemption (L's edge already gone: its entry is reset again, spec/permissions.md §2), or
    /// to revoke the link. K rotates before its next encryption (L's departure).
    pub fn finalize_link(&mut self, k: &Tid, l: &Tid) -> Result<Done> {
        self.demote(k, &crate::flows::Demotion { holder: *l, new: None, presync: crate::flows::PreSync::Synced, retain: Some(false) })
    }

    /// The links whose seed this node holds (a sharer-only thing's `link:seed.0`, readable on
    /// every node of the sharer). Cached until a `link:seed.0` changes.
    pub fn held_links(&mut self) -> Result<Arc<Vec<HeldLink>>> {
        if let Some(l) = &self.core.links {
            return Ok(l.clone());
        }
        let keep: Vec<Tid> = self.core.ix.by_aspect.keys().filter(|(_, a)| a.as_str() == LINK_SEED).map(|(t, _)| *t).collect();
        let ak = super::ak(LINK_SEED)?;
        let me = self.tid();
        let mut out = Vec::new();
        for t in keep {
            if let Some(Value::Map(m)) = self.get(&t, &ak)?
                && let (Some(Value::Tid(k)), Some(Value::Bytes(b))) = (m.get(&Value::Int(0)), m.get(&Value::Int(1)))
                && let Ok(seed) = <[u8; 32]>::try_from(b.as_slice())
                && let (Some(Value::Tid(target)), Some(Value::Bool(single_use))) = (m.get(&Value::Int(2)), m.get(&Value::Int(3)))
                && let Some(first_admin) = self.first_admin(&t)
            {
                let ids: Vec<osis_base::CommitId> = self.core.on_thing(&t).collect();
                let here = ids.iter().any(|c| self.header(c).is_some_and(|h| h.author == me && h.aspects.iter().any(|a| a.tid == t && a.ak.as_str() == LINK_SEED)));
                out.push(HeldLink { k: *k, l: crate::identity::Identity::from_seed(Secret32::from_bytes(seed)).tid(), first_admin, target: *target, single_use: *single_use, here });
            }
        }
        out.sort();
        out.dedup();
        let out = Arc::new(out);
        self.core.links = Some(out.clone());
        Ok(out)
    }

    /// The links this node should finalize now (spec/permissions.md §7): it holds the seed and
    /// admin on K, and L's edge on K expired (`until`, given) or was removed by a single-use
    /// redemption, with no explicit write on it since. The caller finalizes each after a
    /// complete pass of K's labels, so the frontier covers the grants made while the link
    /// worked that reached them. Idempotent across nodes: a finalization by any of them is
    /// that explicit write.
    pub fn links_due(&mut self) -> Result<Vec<(HeldLink, Option<WallMs>)>> {
        let me = self.tid();
        let ts = super::now_ts(&self.core);
        let mut out = Vec::new();
        for h in self.held_links()?.iter() {
            let (k, l) = (&h.k, &h.l);
            let Some(tl) = self.core.timelines.get(k).filter(|_| self.first_admin(k) == Some(h.first_admin)) else { continue };
            let due = match tl.edges_at(None).get(l, k) {
                Some(e) => (!e.alive_at(Some(ts))).then_some(e.until),
                None => tl.lowered_unaudited(l, k).then_some(None),
            };
            if let Some(until) = due
                && self.core.role_now(&me, k) == Some(Role::Admin)
            {
                out.push((*h, until));
            }
        }
        Ok(out)
    }

    /// When the next link this node may finalize expires (corrected wall ms): the earliest
    /// `until` of a live L edge on a K it is admin of.
    pub fn next_link_expiry(&mut self) -> Result<Option<u64>> {
        let me = self.tid();
        let ts = super::now_ts(&self.core);
        let mut next: Option<u64> = None;
        for h in self.held_links()?.iter() {
            let (k, l) = (&h.k, &h.l);
            let Some(tl) = self.core.timelines.get(k).filter(|_| self.first_admin(k) == Some(h.first_admin)) else { continue };
            if let Some(e) = tl.edges_at(None).get(l, k)
                && let Some(u) = e.until
                && e.alive_at(Some(ts))
                && self.core.role_now(&me, k) == Some(Role::Admin)
            {
                next = Some(next.map_or(u.0, |n| n.min(u.0)));
            }
        }
        Ok(next)
    }

    /// Revokes one joiner of a link (spec/permissions.md §7): removes the joiner and L (the
    /// joiner may still hold the seed) in one commit under one rotation of K (spec/commits.md
    /// §2); the remaining joiners need a new link. L already gone (a used single-use link):
    /// the joiner alone.
    pub fn revoke_joiner(&mut self, k: &Tid, l: &Tid, joiner: &Tid, presync: crate::flows::PreSync, retain: Option<bool>) -> Result<Done> {
        let d = crate::flows::Demotion { holder: *joiner, new: None, presync, retain };
        let with_l = self.core.timelines.get(k).is_some_and(|tl| tl.edges_at(None).get(l, k).is_some());
        self.remove_signed(None, k, &d, if with_l { std::slice::from_ref(l) } else { &[] })
    }

    /// Bearer use (spec/permissions.md §7): act as L without writing anything; reads open
    /// through L's boxes once K's label is downloaded. Returns L.
    pub fn bear(&mut self, link: &ShareLink) -> Result<Tid> {
        self.hold_key_actor(link.seed.clone())
    }
}

fn create_link_in(tx: &mut Tx<'_>, sharer: Tid, spec: &LinkSpec, l: Tid, seed: &Secret32) -> Result<(Tid, osis_base::LabelId, Tid, Done)> {
    let me = tx.core.id.tid();
    if tx.core.role_now(&me, &sharer) != Some(Role::Admin) {
        return Err(Error::Permission { tid: sharer });
    }
    let mut done = Done::default();
    // L: creation and keys.0, signed by itself
    let lkeys = KeyActorKeys::from_seed(seed);
    let mut m = Mutation::new();
    m.create(key_actor_record(&lkeys, seed));
    m.sign_as(l);
    key_actor_keys(&mut m, l, &lkeys)?;
    let lc = Engine::commit_tx(tx, m)?;
    done.add(lc);
    // K, with secrets of its own
    let mut m = Mutation::new();
    let k = m.create(crate::identity::thing_record(sharer, &mut *tx.rng));
    done.add(Engine::commit_tx(tx, m)?);
    rotation::own_secrets(tx, k, &mut done)?;
    // L's edge (r, invite r, until) with its boxes, K's home label listing L, K's inbox
    let epochs = tx.core.epochs(&k).ok_or(Error::Misuse("K's secrets"))?;
    let rcpt = Recipient { holder: l, role: spec.role, keys: HolderKeys::KeyActor { kem: lkeys.kem.public().clone(), seed: None } };
    let hist = crate::rotation::history_boxes(tx, &k)?;
    let boxes = box_holder(&k, &epochs, &hist, &rcpt, &roles_up_to(spec.role), &mut *tx.rng)?.ok_or(Error::Misuse("L's keys"))?;
    let mut m = Mutation::new();
    put_edge(&mut m, k, l, &Edge { role: spec.role, until: spec.until, invite: Some(spec.role), tied: None })?;
    super::put_secrets(&mut m, k, &boxes, false)?;
    done.add(Engine::commit_tx(tx, m)?);
    let epochs = tx.core.epochs(&k).ok_or(Error::Misuse("K's secrets"))?;
    let (re, _) = epochs.role(Role::Read).newest_held().ok_or(Error::Misuse("K's read secret"))?;
    let readers: Vec<ReaderKey> = super::labels::readers(tx, &k, &re)?;
    let deposit = osis_crypto::Secret32::from_bytes(super::super::flows::deposit_of(tx, &k)?);
    let mut m = Mutation::new();
    let label = new_label(tx, &mut m, k, &epochs, &readers, &deposit, &spec.hosts)?;
    name_inbox(&mut m, k, label, &spec.hosts)?;
    done.add(Engine::commit_tx(tx, m)?);
    // L's card under K's label: a redeemer holds only the seed, and verifiers of L's commits
    // need L's `created.0`
    if let Some(c) = lc {
        done.deliveries.push(super::owe(tx, Delivery::Certificate { commits: vec![c], under: k })?);
    }
    // a joiner's removal from K reads K's default: the target's now
    if crate::apply::validity::retain_now(tx.core, &spec.target) {
        let mut m = Mutation::new();
        m.set(k, &ct::REQUIRED, &ct::RequiredRules { rules: Default::default(), retain: true })?;
        done.add(Engine::commit_tx(tx, m)?);
    }
    // K on the target
    let target_edge = Edge { role: spec.role, until: None, invite: None, tied: None };
    done.extend(grant_in(tx, None, spec.target, k, &target_edge, false)?);
    // the seed on a thing only the sharer's actor reads (derived secrets)
    let mut m = Mutation::new();
    let keep = m.create(crate::identity::thing_record(sharer, &mut *tx.rng));
    m.op(keep, &super::ak(LINK_SEED)?, PathOp { path: Vec::new(), op: Op::Set(Value::Map([(Value::Int(0), Value::Tid(k)), (Value::Int(1), Value::Bytes(seed.expose().to_vec())), (Value::Int(2), Value::Tid(spec.target)), (Value::Int(3), Value::Bool(spec.single_use))].into_iter().collect())) })?;
    done.add(Engine::commit_tx(tx, m)?);
    Ok((k, label, keep, done))
}
