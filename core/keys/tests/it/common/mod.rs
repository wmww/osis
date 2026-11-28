//! Shared fixtures: actors with explicit epochs, recipients.

use osis_base::{Role, Tid};
use osis_crypto::{Epoch, Secret32, SeededRng};
use osis_keys::aspects::keyset;
use osis_keys::{ActorEpochs, HolderKeys, Provenance, ROLES, Recipient};
use std::collections::BTreeSet;
use osis_schema::core_types::Keys;

pub fn tid(b: u8) -> Tid {
    Tid::from_bytes([b; 15])
}

pub fn ep(n: u64, nonce: u8) -> Epoch {
    Epoch::new(n, [nonce; 32]).unwrap()
}

pub fn rng(seed: u64) -> SeededRng {
    SeededRng::from_u64(seed)
}

pub fn cid(b: u8) -> osis_base::CommitId {
    osis_base::CommitId([b; 32])
}

pub fn roles(r: &[Role]) -> BTreeSet<Role> {
    r.iter().copied().collect()
}

/// An actor holding one explicit secret per role at epoch (1, b).
pub fn actor_epochs(b: u8) -> ActorEpochs {
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
            let ks = Some(keyset(&e, s, &Default::default(), &Default::default(), true));
            match r {
                Role::Sync => k.sync = ks,
                Role::Read => k.read = ks,
                Role::Write => k.write = ks,
                Role::Admin => k.admin = ks,
            }
        }
    }
    k
}

pub fn actor_rcpt(holder: Tid, role: Role, a: &ActorEpochs) -> Recipient {
    Recipient { holder, role, keys: HolderKeys::from_keys(&keys_of(a)).unwrap(), floor: 0 }
}

/// Mint admin `p` holding `pe`, with its own secrets.
pub fn admin_rcpt(p: Tid, pe: &ActorEpochs) -> Recipient {
    Recipient { holder: p, role: Role::Admin, keys: HolderKeys::from_keys(&keys_of(pe)).unwrap().with_own(pe), floor: 0 }
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

/// Actor A (mint admin P) after its own-secrets switch, boxing `extra` too.
pub fn switched(extra: &[Recipient], rg: &mut osis_crypto::SeededRng) -> (Tid, Tid, ActorEpochs, ActorEpochs, osis_schema::core_types::Secrets) {
    let (a, p, pe) = (tid(1), tid(2), actor_epochs(0x20));
    let mut view = ActorEpochs::derived(&pe, &a);
    let mut holders = vec![admin_rcpt(p, &pe)];
    holders.extend_from_slice(extra);
    let r = osis_keys::rotate(&a, &osis_keys::roles_up_to(Role::Admin), &view, &osis_schema::core_types::Secrets::default(), &holders, &osis_keys::Names::default(), &mut *rg).unwrap();
    let mut s = osis_schema::core_types::Secrets::default();
    r.secrets.apply(&mut s);
    view = applied(&r, &view, 1);
    (a, p, pe, view, s)
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

/// A `Held` meeting the names whose key `.0` takes and the departs marks whose `ts` `.1` takes; a
/// departs mark marks the held commit of its `ts` and author, and every rotator holds its role.
pub struct Judge<M, D>(pub M, pub D);

impl<M: Fn(&osis_keys::Key) -> bool, D: Fn(u64) -> bool> osis_keys::Held for Judge<M, D> {
    fn met(&self, n: &osis_keys::Name) -> bool {
        (self.0)(&n.key)
    }
    fn holds(&self, _: &Tid, _: Role) -> bool {
        true
    }
    fn departed(&self, o: &osis_keys::Own) -> bool {
        (self.1)(o.ts)
    }
    fn marks(&self, o: &osis_keys::Own, k: &osis_keys::Key) -> bool {
        o.ts == k.ts && o.author == k.node
    }
    fn publishes(&self, _: Role, _: &Epoch, _: &osis_keys::NamesDigest) -> bool {
        true
    }
}
