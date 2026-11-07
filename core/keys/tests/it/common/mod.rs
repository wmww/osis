#![allow(dead_code)]
//! Shared fixtures: actors with explicit epochs, key actors, recipients.

use osis_base::{Role, Tid};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::aspects::keyset;
use osis_keys::{ActorEpochs, HolderKeys, Provenance, ROLES, Recipient};
use osis_schema::core_types::{KemKey, Keys};

pub fn tid(b: u8) -> Tid {
    Tid::from_bytes([b; 15])
}

pub fn ep(n: u64, nonce: u8) -> Epoch {
    Epoch::new(n, [nonce; 32]).unwrap()
}

pub fn rng(seed: u64) -> SeededRng {
    SeededRng::from_u64(seed)
}

/// An actor holding one explicit secret per role at epoch (1, b).
pub fn person(b: u8) -> ActorEpochs {
    let mut a = ActorEpochs::default();
    for (i, r) in ROLES.into_iter().enumerate() {
        a.role_mut(r).set_secret(ep(1, b), Secret32::from_bytes([b.wrapping_add(i as u8); 32]));
        a.role_mut(r).set_established(ep(1, b), Provenance::Fixed);
    }
    a
}

/// `keys.0` of an actor from its newest held secrets.
pub fn keys_of(a: &ActorEpochs) -> Keys {
    let mut k = Keys::default();
    for r in ROLES {
        if let Some((e, s)) = a.role(r).newest_held() {
            let ks = Some(keyset(&e, s, &Default::default(), &Default::default()));
            match r {
                Role::Read => k.read = ks,
                Role::Write => k.write = ks,
                Role::Admin => k.admin = ks,
            }
        }
    }
    k
}

pub fn key_actor_keys(seed: &Secret32) -> Keys {
    let kem = KeyActorKeys::from_seed(seed).kem;
    Keys { key: Some(KemKey::X25519MlKem768(kem.public().as_bytes().to_vec())), ..Keys::default() }
}

pub fn actor_rcpt(holder: Tid, role: Role, a: &ActorEpochs) -> Recipient {
    Recipient { holder, role, keys: HolderKeys::from_keys(&keys_of(a)).unwrap() }
}

pub fn key_rcpt(holder: Tid, role: Role, seed: &Secret32) -> Recipient {
    Recipient { holder, role, keys: HolderKeys::from_keys(&key_actor_keys(seed)).unwrap() }
}

/// `view` after the rotator applies its own rotation commit `rot` under ID `[id; 32]`: what a
/// later rotation by it lists (spec/crypto.md §4) names the ID other nodes hold the commit by,
/// which `Rotation::preview`'s placeholder does not.
pub fn applied(rot: &osis_keys::Rotation, view: &ActorEpochs, id: u8) -> ActorEpochs {
    let mut a = view.clone();
    rot.record(&mut a);
    rot.secrets.applied(&mut a, osis_base::CommitId([id; 32]), &rot.keys).unwrap();
    a
}

/// A held valid rotation commit applied, then the view established with every name held (the
/// fixtures hold every departure).
pub trait Applied {
    fn applied(&self, v: &mut ActorEpochs, commit: osis_base::CommitId, keys: &osis_keys::KeysWrite) -> Result<bool, osis_keys::Error>;
}

impl Applied for osis_keys::SecretsWrite {
    fn applied(&self, v: &mut ActorEpochs, commit: osis_base::CommitId, keys: &osis_keys::KeysWrite) -> Result<bool, osis_keys::Error> {
        let new = self.rotated(v, commit, keys)?;
        Ok(v.establish(&osis_keys::AllHeld) | new)
    }
}


/// What `box_holder` writes as history: this node's history boxes from `view` and `s`, every
/// name met (`AllHeld`).
pub fn hist(a: &Tid, view: &ActorEpochs, s: &osis_schema::core_types::Secrets) -> osis_keys::HistoryBoxes {
    osis_keys::history_boxes(a, view, s, &osis_keys::HistoryAlts::new(), &osis_keys::AllHeld)
}
