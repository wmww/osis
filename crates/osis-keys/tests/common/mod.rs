#![allow(dead_code)]
//! Shared fixtures: actors with explicit epochs, key actors, recipients.

use osis_core::{Role, Tid};
use osis_crypto::{Epoch, KeyActorKeys, Secret32, SeededRng};
use osis_keys::aspects::keyset;
use osis_keys::{ActorEpochs, MemberKeys, ROLES, Recipient};
use osis_schema::core_types::{KemKey, Keys};

pub fn tid(b: u8) -> Tid {
    Tid::from_bytes([b; 15])
}

pub fn ep(n: u64, nonce: u8) -> Epoch {
    Epoch::new(n, [nonce; 16]).unwrap()
}

pub fn rng(seed: u64) -> SeededRng {
    SeededRng::from_u64(seed)
}

/// An actor holding one explicit secret per role at epoch (1, b).
pub fn person(b: u8) -> ActorEpochs {
    let mut a = ActorEpochs::default();
    for (i, r) in ROLES.into_iter().enumerate() {
        a.role_mut(r).set_secret(ep(1, b), Secret32::from_bytes([b.wrapping_add(i as u8); 32]));
    }
    a
}

/// `/keys` of an actor from its newest held secrets.
pub fn keys_of(a: &ActorEpochs) -> Keys {
    let mut k = Keys::default();
    for r in ROLES {
        if let Some((e, s)) = a.role(r).newest_held() {
            let ks = Some(keyset(&e, s));
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

pub fn actor_rcpt(member: Tid, role: Role, a: &ActorEpochs) -> Recipient {
    Recipient { member, role, keys: MemberKeys::from_keys(&keys_of(a)).unwrap() }
}

pub fn key_rcpt(member: Tid, role: Role, seed: &Secret32) -> Recipient {
    Recipient { member, role, keys: MemberKeys::from_keys(&key_actor_keys(seed)).unwrap() }
}
