//! Share links (spec/permissions.md §7, spec/wire.md §10): K an actor whose mint admin is the sharer's actor, with
//! secrets of its own, a holder of the target with the link's role; L a key actor from the
//! link's seed with (r, may-grant) on K, listed in K's sync ID steps by static entry. Redeem (a
//! may-grant grant signed as L, single use with L's self-removal in the same commit), bearer use,
//! finalization and revoking a joiner are demotions by a sharer node.

use super::sync_ids::ReaderKey;
use super::{Done, put_edge};
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
use osis_blob::ShareLink;
use osis_schema::core_types::{self as ct, Edge};
use std::sync::Arc;

/// The untyped aspect of the thing minted with the account root as admin that keeps a link's seed.
pub const LINK_SEED: &str = "link:seed.0";

/// A link whose seed this node holds (`Engine::held_links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HeldLink {
    pub k: Tid,
    pub l: Tid,
    /// K's mint admin (the sharer's actor). Only a seed thing minted with this node's account as admin
    /// root counts: its readers are the account's nodes alone.
    pub mint_admin: Tid,
    pub target: Tid,
    pub single_use: bool,
    /// The thing keeping the seed (`LINK_SEED`), held from the account root while the link works.
    pub keep: Tid,
    /// This node wrote the seed: it made the link, so its redeemer dials this node (the link's
    /// peers, spec/wire.md §10).
    pub here: bool,
}

/// What a sharer asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSpec {
    pub target: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
    pub peers: Vec<osis_blob::DialHint>,
    /// The link's `flags` bit 0: its redemption removes L (spec/permissions.md §7).
    pub single_use: bool,
}

impl Engine {
    /// Creates a link to `spec.target` for actor `sharer` (an actor this node is admin of):
    /// K (mint admin `sharer`, secrets of its own, its sync ID listing L by
    /// static entry), L (key actor from a fresh seed, `created.0` and `keys.0` signed by itself),
    /// L's edge (r, may-grant, `until`) on K with its boxes, K's edge on the target, and a
    /// thing minted with the account root as admin keeping the seed. Returns the link and the seed thing.
    pub fn create_link(&mut self, sharer: &Tid, spec: &LinkSpec) -> Result<(ShareLink, Tid, Done)> {
        // redeeming reads K's sync ID as L (its roster shows K's grant on the target), which a
        // role below read does not give (spec/permissions.md §7)
        if spec.role < Role::Read {
            return Err(Error::Misuse("a link gives read or above: grant sync to the holder's account instead"));
        }
        // a fresh seed, never copied to an unwiped stack array
        let seed = self.run(|tx| Ok(Secret32::random(&mut *tx.rng)))?;
        let l = self.hold_key_actor(seed.clone())?;
        let res = self.run(|tx| create_link_in(tx, *sharer, spec, l, &seed));
        self.drop_key_actor(&l);
        let (k, k_sync_id, keep, done) = res?;
        Ok((ShareLink { seed, target: spec.target, k, k_sync_id, peers: spec.peers.clone(), single_use: spec.single_use }, keep, done))
    }

    /// Redeems a link once K's sync ID was claimed by L's static entry and downloaded (node-sync;
    /// `hold_key_actor(link.seed)` came first so L's boxes open): signing as L, a may-grant grant
    /// of `grantee` (this node's actor, or this node) to K with the link's role and K's boxes;
    /// `single_use` also removes L's own edge in the same commit. Deposited under K's sync ID
    /// unless the role is write or above. Leaves the seed held as it was: a caller holding it
    /// keeps it (a redeemer proves L until its join is at a source, spec/permissions.md §7).
    pub fn redeem(&mut self, link: &ShareLink, grantee: &Tid, single_use: bool) -> Result<Done> {
        let l = crate::identity::key_actor_tid(&link.seed);
        let held = self.core.key_actors.contains_key(&l);
        if !held {
            self.hold_key_actor(link.seed.clone())?;
        }
        let res = self.redeem_in(l, link, *grantee, single_use);
        if !held {
            self.drop_key_actor(&l);
        }
        res
    }

    /// Whether this node can write a link's join now (spec/permissions.md §7, Redeem steps 3-4):
    /// the target's roster here lists K, K's lists L, both alive, and K's keyset is held (the join seals K's secrets to the
    /// grantee). K's sync ID brings L's grant and K's keyset as separate bodies, the keyset's
    /// wrapped under the epoch it supersedes and so fetched last: L listed says nothing of it.
    pub fn redeemable(&mut self, link: &ShareLink) -> bool {
        let l = crate::identity::key_actor_tid(&link.seed);
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
        // the target is the link text's word: K's grant on it held first (step 3)
        let on_target = self.roster(&link.target).get(&link.k).is_some_and(|e| e.alive_at(Some(ts)));
        on_target && self.roster(&link.k).get(&l).is_some_and(|e| e.alive_at(Some(ts))) && self.core.is_independent(&link.k)
    }

    fn redeem_in(&mut self, l: Tid, link: &ShareLink, grantee: Tid, single_use: bool) -> Result<Done> {
        let k = link.k;
        let edge = self.roster(&k).get(&l).copied().ok_or(Error::Misuse("the link is no holder of K (finalized or unknown)"))?;
        if !edge.alive_at(Some(osis_base::Ts::make(self.now(), 0).unwrap_or_default())) {
            return Err(Error::Misuse("the link expired"));
        }
        if !self.core.is_independent(&k) {
            return Err(Error::Misuse("K's keyset is not held here yet"));
        }
        if !self.roster(&link.target).get(&k).is_some_and(|e| e.alive_at(Some(osis_base::Ts::make(self.now(), 0).unwrap_or_default()))) {
            return Err(Error::Misuse("K's grant on the link's target is not held here"));
        }
        let grant = Edge { role: edge.role, until: None, may_grant: false, retain: false, floor: None };
        // L signs with its own role, so the grant deposits only below write; a redeem is an
        // accept (spec/sync-set.md §4): strongs to K and the target in the account root, unless
        // the node closure holds them, and so D's tickets for both (`inbox::write_account_ticket`)
        let target = link.target;
        self.grant_signed_then(Some(l), k, grantee, &grant, single_use, crate::flows::edges::History::All, move |tx| {
            let Some((_, d)) = tx.core.account_and_root() else { return Ok(()) };
            let mut m = Mutation::new();
            for t in [k, target].into_iter().filter(|t| !tx.core.ix.closure.holds(t)) {
                m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) })?;
            }
            if !m.is_empty() {
                Engine::commit_tx(tx, m)?;
            }
            Ok(())
        })
    }

    /// Whether the held role history shows `holder` put on `thing` and its edge over: removed, or
    /// past `until` (spec/permissions.md §7). A holder not seen yet says nothing: its edge may be
    /// on its way.
    pub fn edge_gone(&mut self, thing: &Tid, holder: &Tid) -> bool {
        let ts = super::now_ts(&self.core);
        self.core.timelines().get(thing).is_some_and(|tl| tl.ended(thing, ts).contains_key(holder))
    }

    /// Whether a link being redeemed has ended here (spec/permissions.md §7): the held role history
    /// shows L's edge on K, or K's on the target the link names, removed or past `until`. Reads
    /// the clock up to the next `until` or role commit of K's and the target's components, so an
    /// `until` passing moves it.
    pub fn link_ended(&mut self, link: &ShareLink) -> bool {
        let l = crate::identity::key_actor_tid(&link.seed);
        let _horizon = self.core.bound_to_horizon([link.k, link.target].into_iter());
        self.edge_gone(&link.k, &l) || self.edge_gone(&link.target, &link.k)
    }

    /// Whether `k` is a link this account joined that has ended (spec/permissions.md §7, Joiner's
    /// leave): it holds K by a grant (the sharer holds it by K's record), and the held role
    /// history shows K's edge on the target K's record names removed or past `until`. The caller
    /// leaves K (`leave_link`): sync's duty follows it per thing (`osis_sync::life`). Only K's
    /// creator wrote that target, and it may remove any joiner anyway. Reads the clock up to the
    /// next `until` or role commit of K's and the target's components.
    pub fn joined_link_ended(&mut self, k: &Tid) -> bool {
        let Some(target) = self.core.created(k).and_then(|r| r.link_target()) else { return false };
        let _horizon = self.core.bound_to_horizon([*k, target].into_iter());
        self.joined_link(k) && self.edge_gone(&target, k)
    }

    /// Whether this account holds link actor `k` by a live grant (a join, its own or a sibling's;
    /// K's mint admin holds it by K's record): a redeem of its link writes no other
    /// (spec/permissions.md §7). Reads the clock up to that grant's `until`.
    pub fn joined_link(&mut self, k: &Tid) -> bool {
        let Some(me) = self.core.me() else { return false };
        if self.mint_admin(k) == Some(me) {
            return false;
        }
        let edge = self.core.timelines().get(k).and_then(|tl| tl.edges_at(None).get(&me, k).copied());
        self.core.time.at(|now| (edge.is_some_and(|e| e.alive_at(Some(super::ts_at(now)))), edge.and_then(|e| e.until).map(|u| u.0)))
    }

    /// This account's leave of link actor `k` (`joined_link_ended`): a self-removal of its grant
    /// on K. Idempotent across the account's nodes: once one's leave is here, the grant is gone.
    pub fn leave_link(&mut self, k: &Tid) -> Result<Done> {
        let me = self.core.me().ok_or(Error::Misuse("no account"))?;
        self.demote(k, &crate::flows::Demotion { holder: me, new: None, retain: None })
    }

    /// Finalizes a link (spec/permissions.md §7): a sharer node's plain removal of L from K,
    /// an explicit demotion with the sharer's frontier, after `until` passed, after a single-use
    /// redemption (L's edge already gone: its entry is reset again, spec/permissions.md §2), or
    /// to revoke the link. K rotates before its next encryption (L's departure). The link ends
    /// with it, and so does its seed (`let_seeds_go`).
    pub fn finalize_link(&mut self, k: &Tid, l: &Tid) -> Result<Done> {
        let keeps = self.link_seeds(k, l)?;
        self.remove_signed_then(None, k, &crate::flows::Demotion { holder: *l, new: None, retain: Some(false) }, &[], move |tx| let_seeds_go(tx, &keeps))
    }

    /// The things keeping the seed of link (K `k`, L `l`) held here (`HeldLink::keep`).
    fn link_seeds(&mut self, k: &Tid, l: &Tid) -> Result<Vec<Tid>> {
        Ok(self.held_links()?.iter().filter(|h| h.k == *k && h.l == *l).map(|h| h.keep).collect())
    }

    /// The links whose seed this node holds (a `link:seed.0` on a thing minted with the account root as admin, readable on
    /// every node of the sharer; `Core::links`).
    pub fn held_links(&mut self) -> Result<Arc<Vec<HeldLink>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.links, &(), Self::held_links_read)
    }

    fn held_links_read(&mut self) -> Result<Arc<Vec<HeldLink>>> {
        let ak = super::ak(LINK_SEED)?;
        let keep: Vec<Tid> = self.core.ix.aspect_things.get(&ak).into_iter().flatten().copied().collect();
        let mut out = Vec::new();
        for t in keep {
            if let Some(Value::Map(m)) = self.get(&t, &ak)?
                && let (Some(Value::Weak(k)), Some(Value::Bytes(b))) = (m.get(&Value::Int(0)), m.get(&Value::Int(1)))
                && let Ok(seed) = <[u8; 32]>::try_from(b.as_slice())
                && let (Some(Value::Weak(target)), Some(Value::Bool(single_use))) = (m.get(&Value::Int(2)), m.get(&Value::Int(3)))
                && self.mint_admin(&t).is_some_and(|a| Some(a) == self.account_root())
                && let Some(mint_admin) = self.mint_admin(k)
            {
                let ids: Vec<osis_base::CommitId> = self.core.on_thing(&t).collect();
                let here = ids.iter().any(|c| self.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local && m.view.aspect(&t, LINK_SEED).is_some()));
                out.push(HeldLink { k: *k, l: crate::identity::key_actor_tid(&Secret32::from_bytes(seed)), mint_admin, target: *target, single_use: *single_use, keep: t, here });
            }
        }
        out.sort();
        out.dedup();
        Ok(Arc::new(out))
    }

    /// The links this node should finalize now (spec/permissions.md §7): it holds the seed and
    /// admin on K, and L's edge on K expired (`until`, given) or was removed by a single-use
    /// redemption, with no explicit write on it since. The caller finalizes each after a
    /// complete pass of K's sync IDs, so the frontier covers the grants made while the link
    /// worked that reached them. Idempotent across nodes: a finalization by any of them is
    /// that explicit write.
    pub fn links_due(&mut self) -> Result<Vec<(HeldLink, Option<WallMs>)>> {
        // a node that has joined no account is admin of no K
        let Some(me) = self.core.me() else { return Ok(Vec::new()) };
        let ts = super::now_ts(&self.core);
        let mut out = Vec::new();
        for h in self.held_links()?.iter() {
            let (k, l) = (&h.k, &h.l);
            let Some(tl) = self.core.timelines().get(k) else { continue };
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

    /// When the next link this node may finalize expires (wall ms): the earliest
    /// `until` of a live L edge on a K it is admin of.
    pub fn next_link_expiry(&mut self) -> Result<Option<u64>> {
        let Some(me) = self.core.me() else { return Ok(None) };
        let ts = super::now_ts(&self.core);
        let mut next: Option<u64> = None;
        for h in self.held_links()?.iter() {
            let (k, l) = (&h.k, &h.l);
            let Some(tl) = self.core.timelines().get(k) else { continue };
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
    /// §2); the remaining joiners need a new link. L unknown (the link ended, its seed gone) or
    /// already gone from K (a used single-use link): the joiner alone.
    pub fn revoke_joiner(&mut self, k: &Tid, l: Option<&Tid>, joiner: &Tid, retain: Option<bool>) -> Result<Done> {
        let d = crate::flows::Demotion { holder: *joiner, new: None, retain };
        let Some(l) = l.filter(|l| self.core.timelines().get(k).is_some_and(|tl| tl.edges_at(None).get(l, k).is_some())) else {
            return self.remove_signed(None, k, &d, &[]);
        };
        let keeps = self.link_seeds(k, l)?;
        self.remove_signed_then(None, k, &d, std::slice::from_ref(l), move |tx| let_seeds_go(tx, &keeps))
    }

    /// Bearer use (spec/permissions.md §7): act as L without writing anything; reads open
    /// through L's boxes once K's sync ID is downloaded. Returns L.
    pub fn bear(&mut self, link: &ShareLink) -> Result<Tid> {
        self.hold_key_actor(link.seed.clone())
    }
}

/// A link ends with L's removal from K: the things keeping its seed, which serve only a working
/// link, lose the account root's strong to them, so each goes as any thing whose last
/// reference goes (spec/sync-set.md §3).
fn let_seeds_go(tx: &mut Tx<'_>, keeps: &[Tid]) -> Result<()> {
    let Some((_, d)) = tx.core.account_and_root() else { return Ok(()) };
    let mut m = Mutation::new();
    for t in keeps {
        if crate::engine::refs::strong_from(tx, &d, t)? {
            m.op(d, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Remove(Value::Strong(*t)) })?;
        }
    }
    if !m.is_empty() {
        Engine::commit_tx(tx, m)?;
    }
    Ok(())
}

/// A key actor's `keys.0`: its KEM key (spec/crypto.md §3).
fn key_actor_keys(m: &mut Mutation, t: Tid, keys: &KeyActorKeys) -> Result<()> {
    let k = ct::Keys { key: Some(ct::KemKey::X25519MlKem768(keys.kem.public().as_bytes().to_vec())), ..Default::default() };
    m.set(t, &ct::KEYS, &k)?;
    Ok(())
}

fn create_link_in(tx: &mut Tx<'_>, sharer: Tid, spec: &LinkSpec, l: Tid, seed: &Secret32) -> Result<(Tid, osis_base::SyncId, Tid, Done)> {
    let me = tx.core.writer()?;
    if crate::engine::secrets::usable_role_now(tx, &me, &sharer)? != Some(Role::Admin) {
        return Err(Error::Permission { tid: sharer, needs: Role::Admin });
    }
    let mut done = Done::default();
    // L: creation and keys.0, signed by itself
    let lkeys = KeyActorKeys::from_seed(seed);
    let mut m = Mutation::new();
    m.create(key_actor_record(&lkeys.signing.verifying_key(), seed));
    m.sign_as(l);
    key_actor_keys(&mut m, l, &lkeys)?;
    let lc = Engine::commit_tx(tx, m)?;
    done.add(lc);
    // K, independent
    let mut m = Mutation::new();
    let k = m.create(crate::identity::link_record(sharer, spec.target, &mut *tx.rng));
    done.add(Engine::commit_tx(tx, m)?);
    // K's secrets, its sync ID listing L, its inbox: one commit
    let lvk = lkeys.signing.verifying_key();
    rotation::own_secrets_listing(tx, k, &[ReaderKey::Static(lvk, lkeys.kem.public().clone())], &mut done)?;
    // L's edge (r, may-grant, until) with its boxes
    let epochs = tx.core.epochs(&k).ok_or(Error::Misuse("K's secrets"))?;
    let rcpt = Recipient { holder: l, role: spec.role, keys: HolderKeys::KeyActor { kem: lkeys.kem.public().clone(), seed: None }, floor: 0 };
    let hist = crate::rotation::history_boxes(tx, &sharer, &k)?;
    let boxes = box_holder(&k, &epochs, &hist, &rcpt, &roles_up_to(spec.role), &mut *tx.rng)?.ok_or(Error::Misuse("L's keys"))?;
    let mut m = Mutation::new();
    // its `until` passing says what the target's default says now (spec/permissions.md §3, Retain)
    let retain = spec.until.is_some() && crate::apply::validity::retain_default(tx.core, &spec.target);
    put_edge(&mut m, k, l, &Edge { role: spec.role, until: spec.until, may_grant: true, retain, floor: None })?;
    super::put_secrets(&mut m, k, &boxes, false)?;
    done.add(Engine::commit_tx(tx, m)?);
    let sync_id = super::sync_id_of(tx, &k)?.ok_or(Error::Misuse("K's sync ID"))?;
    // a joiner's removal from K reads K's default: the target's now
    if crate::apply::validity::retain_default(tx.core, &spec.target) {
        let mut m = Mutation::new();
        m.set(k, &ct::RETENTION, &ct::RetentionSetting { retain: true, ..Default::default() })?;
        done.add(Engine::commit_tx(tx, m)?);
    }
    // K on the target, which K holds by a strong: K's sync unit carries the target, and so K's
    // grant on it, to a redeemer (spec/permissions.md §7 Redeem step 3)
    let target_edge = Edge { role: spec.role, until: None, may_grant: false, retain: false, floor: None };
    // K is new: the grant demotes nobody, so it carries no frontier
    done.extend(grant_in(tx, None, spec.target, k, &target_edge, false, None)?);
    let mut m = Mutation::new();
    m.op(k, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(spec.target)) })?;
    done.add(Engine::commit_tx(tx, m)?);
    // the seed on a thing minted with the account root as admin, which holds it and K by strongs: every
    // node of the account holds the seed, may finalize and serves K's sync ID to redeemers
    // (spec/permissions.md §7)
    let d = tx.core.account_and_root().map(|(_, d)| d).ok_or(Error::Misuse("not a node of an account"))?;
    let mut m = Mutation::new();
    let keep = m.create(crate::identity::thing_record(d, None, &mut *tx.rng));
    for t in [keep, k] {
        m.op(d, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(t)) })?;
    }
    m.op(keep, &super::ak(LINK_SEED)?, PathOp { path: Vec::new(), op: Op::Set(Value::Map([(Value::Int(0), Value::Weak(k)), (Value::Int(1), Value::Bytes(seed.expose().to_vec())), (Value::Int(2), Value::Weak(spec.target)), (Value::Int(3), Value::Bool(spec.single_use))].into_iter().collect())) })?;
    done.add(Engine::commit_tx(tx, m)?);
    Ok((k, sync_id, keep, done))
}
