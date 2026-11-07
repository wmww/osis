//! Person actors (spec/permissions.md §1, §7): this node is the person actor's first admin and
//! a recovery key holds a plain admin edge on it; pairing a node (a direct grant, or a re-seal
//! of a node already a holder, plus the commits it needs); recovery from a card on a fresh node.

use super::labels::{ReaderKey, name_inbox, new_label};
use super::{Delivery, Done, put_edge};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::edges::{Demotion, PreSync};
use crate::identity::{key_actor_record, thing_record};
use crate::rotation;
use crate::Mutation;
use osis_base::{CommitId, Role, Tid};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{KeyActorKeys, Secret32};
use osis_keys::{ActorEpochs, HolderKeys, ROLES, Recipient};
use osis_label::{Address, RecoveryCard};
use osis_schema::Codec;
use osis_schema::core_types::{self as ct, Edge, KemKey, Keys};
use std::collections::BTreeSet;

/// A person actor this node created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub person: Tid,
    /// The recovery card (spec/wire.md §10): the only copy of the recovery key's seed.
    pub card: RecoveryCard,
}

fn admin_edge() -> Edge {
    Edge { role: Role::Admin, until: None, invite: None, tied: None }
}

/// A key actor's `keys.0`: its KEM key (spec/crypto.md §3).
pub(crate) fn key_actor_keys(m: &mut Mutation, t: Tid, keys: &KeyActorKeys) -> Result<()> {
    let k = Keys { key: Some(KemKey::X25519MlKem768(keys.kem.public().as_bytes().to_vec())), ..Default::default() };
    m.set(t, &ct::KEYS, &k)?;
    Ok(())
}

impl Engine {
    /// Creates a person actor (spec/permissions.md §1): this node is its first admin, a fresh
    /// recovery key its admin by a plain edge. Two commits: the key's card (its creation record
    /// and `keys.0`, signed by itself), then by this node the person's creation record, its
    /// secrets of its own (boxed to the key and to this node), its `keys.0` with inbox (its home
    /// label) and deposit seed, the home label's genesis step on `hosts` (the key listed by
    /// static entry) and the key's admin edge. The seed leaves only in the card.
    pub fn create_person(&mut self, hosts: &[Address]) -> Result<(Person, Done)> {
        // a fresh seed, never copied to an unwiped stack array
        let seed = self.run(|tx| Ok(Secret32::random(&mut *tx.rng)))?;
        let r = self.hold_key_actor(seed.clone())?;
        let res = self.run(|tx| create_person_in(tx, r, &seed, hosts));
        self.drop_key_actor(&r);
        let (p, label, cs) = res?;
        let mut done = Done::default();
        for c in cs {
            done.add(c);
        }
        Ok((Person { person: p, card: RecoveryCard { seed, person: p, home_label: label, hosts: hosts.to_vec() } }, done))
    }

    /// Pairing, existing node side (spec/sync.md §2: the only way a node receives a grant):
    /// `node`'s card (`created.0`, `keys.0`) was received over the direct connection. A node
    /// that is not a holder of `person` is granted admin; one that is (stranded, notes/label-access.md
    /// Limits) is re-sealed. Returns the commits to send it directly: the grant or re-seal, the
    /// person's certificates and its `label.0` commits (a few KB plus the grant's boxes, whatever
    /// the account holds: the new node downloads the rest under the home label).
    pub fn pair(&mut self, person: &Tid, node: &Tid) -> Result<Done> {
        let (p, n) = (*person, *node);
        if !self.knows(&n) {
            return Err(Error::UnknownThing(n));
        }
        let holder = self.roster(&p).get(&n).is_some_and(|e| e.alive_at(Some(osis_base::Ts::make(self.now(), 0).unwrap_or_default())));
        let mut done = if holder { self.reshare(&p, &n)? } else { self.grant(&p, &n, &admin_edge())? };
        // the person's certificates (this node's card, the chain to the person and its edges)
        // and its `label.0` commits, never its content: the new node downloads the rest from
        // the home label
        let mut all: Vec<CommitId> = self.certificates(&p).into_keys().collect();
        let label = osis_base::Ak::new("label.0").map_err(|_| Error::Misuse("ak"))?;
        all.extend(self.core.ix.by_aspect.get(&(p, label)).into_iter().flatten().map(|(_, c)| *c));
        all.sort_by_key(|c| self.header(c).map(|h| h.ts));
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
        // the grant's own direct send is replaced (crash-safe like the grant: `flows::owe`)
        let (gone, kept): (Vec<Delivery>, Vec<Delivery>) = std::mem::take(&mut done.deliveries).into_iter().partition(|d| matches!(d, Delivery::Direct { to, .. } if *to == n));
        done.deliveries = kept;
        let d = self.run(|tx| {
            super::unowe(tx, &gone)?;
            super::owe(tx, Delivery::Direct { to: n, commits: all })
        })?;
        done.deliveries.push(d);
        Ok(done)
    }

    /// Pairing, new node side, after applying what `pair` sent: checks the grant made it an
    /// admin of `person` and returns the certificate copy of `grant` to place under the
    /// person's home label (spec/sync.md §3).
    pub fn paired(&mut self, person: &Tid, grant: &CommitId) -> Result<Done> {
        if self.role_on(person) != Some(Role::Admin) {
            return Err(Error::Permission { tid: *person });
        }
        let (g, p) = (*grant, *person);
        let d = self.run(|tx| super::owe(tx, Delivery::Certificate { commits: vec![g], under: p }))?;
        Ok(Done { deliveries: vec![d], ..Done::default() })
    }

    /// Recovery from a card on this (fresh) node (spec/permissions.md §7), once the home label
    /// was claimed by the key's static entry and downloaded (node-sync; `hold_key_actor` with
    /// the card's seed came first so the key's boxes open): signing as the recovery key, an
    /// admin of the account by its edge, grants this node admin on the account, then removes
    /// each `lost` node (an explicit demotion, with the person's rotation; `presync` as for any
    /// demotion). The seed is dropped afterwards.
    pub fn recover(&mut self, card: &RecoveryCard, lost: &[Tid], presync: PreSync) -> Result<Done> {
        let r = self.hold_key_actor(card.seed.clone())?;
        let res = self.recover_in(r, card.person, lost, presync);
        self.drop_key_actor(&r);
        res
    }

    fn recover_in(&mut self, r: Tid, p: Tid, lost: &[Tid], presync: PreSync) -> Result<Done> {
        if self.core.role_now(&r, &p) != Some(Role::Admin) {
            return Err(Error::Misuse("the card's key is no admin of the person"));
        }
        let me = self.tid();
        let mut done = Done::default();
        if !self.roster(&p).contains_key(&me) {
            done.extend(self.grant_as(&r, &p, &me, &admin_edge())?);
        }
        for d in lost {
            done.extend(self.demote_as(&r, &p, &Demotion { holder: *d, new: None, presync, retain: Some(false) })?);
        }
        Ok(done)
    }
}

fn create_person_in(tx: &mut Tx<'_>, r: Tid, seed: &Secret32, hosts: &[Address]) -> Result<(Tid, osis_base::LabelId, Vec<Option<CommitId>>)> {
    let rkeys = KeyActorKeys::from_seed(seed);
    // the key's card, signed by itself
    let mut card = Mutation::new();
    card.create(key_actor_record(&rkeys, seed));
    card.sign_as(r);
    key_actor_keys(&mut card, r, &rkeys)?;
    let c0 = Engine::commit_tx(tx, card)?;
    // the person, by its first admin
    let me = tx.core.id.tid();
    let mut m = Mutation::new();
    let p = m.create(thing_record(me, &mut *tx.rng));
    let node_kem = tx.core.id.keys().kem.public().clone();
    let held = ActorEpochs::derived(&tx.core.id.epochs(), &p);
    let holders = [
        Recipient { holder: r, role: Role::Admin, keys: HolderKeys::KeyActor { kem: rkeys.kem.public().clone(), seed: None } },
        Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: node_kem.clone(), seed: None } },
    ];
    let rot = rotation::rotation_into(tx, &mut m, p, &ROLES.into_iter().collect(), &held, &holders, false)?;
    let after = rot.preview(&held)?;
    let mut dep = [0u8; 32];
    tx.rng.fill_bytes(&mut dep);
    let deposit = Secret32::from_bytes(dep);
    let rvk = rkeys.signing.verifying_key();
    let readers = [ReaderKey::Static(rvk, rkeys.kem.public().clone()), ReaderKey::Dh(node_kem.x25519())];
    let label = new_label(tx, &mut m, p, &after, &readers, &deposit, hosts)?;
    name_inbox(&mut m, p, label, hosts)?;
    m.op(p, &ct::KEYS, PathOp { path: vec![PathSeg::Field(5)], op: Op::Set(Some(dep).to_value()) })?;
    put_edge(&mut m, p, r, &admin_edge())?;
    let c = Engine::commit_tx(tx, m)?;
    rotation::record(tx, p, &rot)?;
    // the key's card goes under the home label with every admin's certificates
    // (`Engine::certificates`): a recovering node verifies the key's writes by it
    Ok((p, label, vec![c0, c]))
}
