//! Person actors (spec/permissions.md §1, §9): a recovery key owns the person actor and this
//! node is its admin; pairing a device (a direct grant, or a re-seal of a device already a
//! member, plus the commits it needs); recovery from a card on a fresh device.

use super::labels::{ReaderKey, new_label};
use super::{Delivery, Done, put_edge};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::edges::{Demotion, PreSync, grant_in};
use crate::identity::{key_actor_record, thing_record};
use crate::rotation;
use crate::Mutation;
use osis_core::{CommitId, Role, Tid};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{KeyActorKeys, Secret32};
use osis_keys::{ActorEpochs, MemberKeys, ROLES, Recipient};
use osis_label::{Address, RecoveryCard};
use osis_schema::Codec;
use osis_schema::core_types::{self as ct, Edge, Inbox, KemKey, Keys};
use std::collections::BTreeSet;

/// A person actor this node created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub person: Tid,
    /// The recovery card (spec/wire.md §10): the only copy of the recovery key's seed.
    pub card: RecoveryCard,
}

fn admin_edge() -> Edge {
    Edge { role: Role::Admin, until: None, invite: None, since: None }
}

/// A key actor's `/keys`: its KEM key (spec/crypto.md §3).
pub(crate) fn key_actor_keys(m: &mut Mutation, t: Tid, keys: &KeyActorKeys) -> Result<()> {
    let k = Keys { key: Some(KemKey::X25519MlKem768(keys.kem.public().as_bytes().to_vec())), ..Default::default() };
    m.set(t, &ct::KEYS, &k)?;
    Ok(())
}

/// The commits a device or redeemer needs to verify and read `tids` (their creation, membership
/// and `/keys` commits, the chains above them), as held here.
pub(crate) fn commits_touching(e: &Engine, tids: &BTreeSet<Tid>) -> Vec<CommitId> {
    let mut ids: Vec<(osis_core::Ts, CommitId)> = e
        .core
        .commits
        .iter()
        .filter(|(_, m)| m.header.aspects.iter().any(|a| tids.contains(&a.tid)))
        .map(|(id, m)| (m.header.ts, *id))
        .collect();
    ids.sort();
    ids.into_iter().map(|x| x.1).collect()
}

impl Engine {
    /// Creates a person actor (spec/permissions.md §1): a fresh recovery key owns it; in one
    /// commit signed by that key: both creation records, the key's `/keys`, the person's
    /// secrets of its own (boxed to the key and to this node), its `/keys` with inbox (its home
    /// label) and deposit seed, the home label's genesis step on `servers` (the key listed by
    /// static entry) and this node's admin edge. The seed leaves only in the card.
    pub fn create_person(&mut self, servers: &[Address]) -> Result<(Person, Done)> {
        // a fresh seed, never copied to an unwiped stack array
        let seed = self.run(|tx| Ok(Secret32::random(&mut *tx.rng)))?;
        let r = self.hold_key_actor(seed.clone())?;
        let res = self.run(|tx| create_person_in(tx, r, &seed, servers));
        self.drop_key_actor(&r);
        let (p, label, c) = res?;
        let mut done = Done::default();
        done.add(c);
        Ok((Person { person: p, card: RecoveryCard { seed, person: p, home_label: label, servers: servers.to_vec() } }, done))
    }

    /// Pairing, existing device side (spec/sync.md §2: the only way a node receives a grant):
    /// `node`'s card (`/created`, `/keys`) was received over the direct connection. A device
    /// that is not a member of `person` is granted admin; one that is (stranded, notes/sync.md
    /// Limits) is re-sealed. Returns the commits to send it directly: the grant or re-seal and
    /// the person's certificates and current `/label`.
    pub fn pair(&mut self, person: &Tid, node: &Tid) -> Result<Done> {
        let (p, n) = (*person, *node);
        if !self.knows(&n) {
            return Err(Error::UnknownThing(n));
        }
        let member = self.roster(&p).get(&n).is_some_and(|e| e.alive_at(Some(osis_core::Ts::make(self.now(), 0).unwrap_or_default())));
        let mut done = if member { self.reshare(&p, &n)? } else { self.grant(&p, &n, &admin_edge())? };
        let mut tids: BTreeSet<Tid> = [p, self.tid(), n].into_iter().collect();
        if let Some(o) = self.core.owner(&p) {
            tids.insert(o);
        }
        let mut all = commits_touching(self, &tids);
        for d in &done.deliveries {
            if let Delivery::Direct { to, commits } = d
                && *to == n
            {
                all.extend(commits.iter().copied());
            }
        }
        // each commit once, in the order collected (the store's `ts` order first)
        let mut seen = BTreeSet::new();
        all.retain(|c| seen.insert(*c));
        done.deliveries.retain(|d| !matches!(d, Delivery::Direct { to, .. } if *to == n));
        done.deliveries.push(Delivery::Direct { to: n, commits: all });
        Ok(done)
    }

    /// Pairing, new device side, after applying what `pair` sent: checks the grant made it an
    /// admin of `person` and returns the certificate copy of `grant` to place under the
    /// person's home label (spec/sync.md §3).
    pub fn paired(&mut self, person: &Tid, grant: &CommitId) -> Result<Done> {
        if self.role_on(person) != Some(Role::Admin) {
            return Err(Error::Permission { tid: *person });
        }
        Ok(Done { deliveries: vec![Delivery::Certificate { commits: vec![*grant], under: *person }], ..Done::default() })
    }

    /// Recovery from a card on this (fresh) device (spec/permissions.md §9), once the home label
    /// was claimed by the key's static entry and downloaded (node-sync; `hold_key_actor` with
    /// the card's seed came first so the key's boxes open): signing as the recovery key, grants
    /// this node admin on the person, then removes each `lost` device (an explicit demotion by
    /// the owner, with the person's rotation; `presync` as for any demotion, a backdated revoke
    /// to cancel a stolen device's backdated writes). The seed is dropped afterwards.
    pub fn recover(&mut self, card: &RecoveryCard, lost: &[Tid], presync: PreSync) -> Result<Done> {
        let r = self.hold_key_actor(card.seed.clone())?;
        let res = self.recover_in(r, card.person, lost, presync);
        self.drop_key_actor(&r);
        res
    }

    fn recover_in(&mut self, r: Tid, p: Tid, lost: &[Tid], presync: PreSync) -> Result<Done> {
        if self.core.owner(&p) != Some(r) {
            return Err(Error::Misuse("the card's key does not own the person"));
        }
        let me = self.tid();
        let mut done = Done::default();
        if !self.roster(&p).contains_key(&me) {
            done.extend(self.run(|tx| grant_in(tx, Some(r), p, me, &admin_edge(), false))?);
        }
        for d in lost {
            done.extend(self.demote_as(&r, &p, &Demotion { member: *d, new: None, presync })?);
        }
        Ok(done)
    }
}

fn create_person_in(tx: &mut Tx<'_>, r: Tid, seed: &Secret32, servers: &[Address]) -> Result<(Tid, osis_core::LabelId, Option<CommitId>)> {
    let rkeys = KeyActorKeys::from_seed(seed);
    let mut m = Mutation::new();
    m.create(key_actor_record(&rkeys, seed));
    let p = m.create(thing_record(r, &mut *tx.rng));
    m.sign_as(r);
    key_actor_keys(&mut m, r, &rkeys)?;
    let me = tx.core.id.tid();
    let node_kem = tx.core.id.keys().kem.public().clone();
    let held = ActorEpochs::derived(&ActorEpochs::key_actor(seed), &p);
    let members = [
        Recipient { member: r, role: Role::Admin, keys: MemberKeys::KeyActor { kem: rkeys.kem.public().clone(), seed: None } },
        Recipient { member: me, role: Role::Admin, keys: MemberKeys::KeyActor { kem: node_kem.clone(), seed: None } },
    ];
    let rot = rotation::rotation_into(tx, &mut m, p, &ROLES.into_iter().collect(), &held, &members)?;
    let mut after = held.clone();
    rot.record(&mut after);
    let mut dep = [0u8; 32];
    tx.rng.fill_bytes(&mut dep);
    let deposit = Secret32::from_bytes(dep);
    let rvk = rkeys.signing.verifying_key();
    let readers = [ReaderKey::Static(rvk, rkeys.kem.public().clone()), ReaderKey::Dh(node_kem.x25519())];
    let label = new_label(tx, &mut m, p, &after, &readers, &deposit, servers)?;
    m.op(p, &ct::KEYS, PathOp { path: vec![PathSeg::Field(4)], op: Op::Set(Some(Inbox { label, servers: servers.to_vec() }).to_value()) })?;
    m.op(p, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Set(Some(dep).to_value()) })?;
    put_edge(&mut m, p, me, &admin_edge())?;
    let c = Engine::commit_tx(tx, m)?;
    rotation::record(tx, p, &rot)?;
    Ok((p, label, c))
}
