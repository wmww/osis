//! A sync ID's secrets and steps, as an admin issues them (the store's and streams' tests).

use osis_base::{SyncId, Tid};
use osis_blob::{Step, StepKeys};
use osis_crypto::{RoleKey, Secret32, SigningSecret, X25519Secret, role_key};

/// A sync ID's role secrets and the steps issued so far, from its genesis step: one secret is its
/// genesis seed and its first secret of every role, so the genesis step bears its first keys.
#[derive(Clone)]
pub struct Sid {
    pub id: SyncId,
    pub sync: Secret32,
    pub write: Secret32,
    pub admin: Secret32,
    pub deposit: Secret32,
    pub steps: Vec<Step>,
}

pub const THING: Tid = Tid::from_bytes([0x51; 15]);

/// A step key standing for step `n`'s.
fn step_key(n: u64) -> [u8; 32] {
    X25519Secret::from_secret(&Secret32::from_bytes([n as u8 ^ 0x3c; 32])).public()
}

impl Sid {
    pub fn new(b: u8) -> Sid {
        let g = Secret32::from_bytes([b; 32]);
        let id = osis_blob::genesis_sync_id(&g);
        Sid { id, sync: g.clone(), write: g.clone(), admin: g.clone(), deposit: g.clone(), steps: vec![osis_blob::genesis(&g)] }
    }
    pub fn keys(&self) -> StepKeys {
        StepKeys::derive(&self.sync, &self.write, &self.admin, &self.deposit, &self.id)
    }
    pub fn delete(&self) -> SigningSecret {
        role_key(RoleKey::Delete, &self.admin)
    }
    pub fn write_key(&self) -> SigningSecret {
        role_key(RoleKey::Write, &self.write)
    }
    pub fn sync_key(&self) -> SigningSecret {
        role_key(RoleKey::Sync, &self.sync)
    }
    /// The next step (a child of the last).
    pub fn issue(&self) -> Step {
        self.issue_by(&self.delete())
    }
    /// The next step, signed by `d` (the parent's delete key).
    pub fn issue_by(&self, d: &SigningSecret) -> Step {
        let parent = self.steps.last().unwrap();
        osis_blob::register(parent, d, self.keys(), step_key(self.steps.len() as u64)).unwrap()
    }
    /// Rotates the write and sync secrets and issues the next step.
    pub fn rotate(&mut self, b: u8) -> Step {
        self.write = Secret32::from_bytes([b; 32]);
        self.sync = Secret32::from_bytes([b + 1; 32]);
        let st = self.issue();
        self.steps.push(st.clone());
        st
    }
    /// Step `n`, a child of `parent`, whose write secret is `[w; 32]` (the other secrets as
    /// they are; nothing issued here changes).
    pub fn child(&self, parent: &Step, n: u64, w: u8) -> Step {
        let write = Secret32::from_bytes([w; 32]);
        let keys = StepKeys::derive(&self.sync, &write, &self.admin, &self.deposit, &self.id);
        osis_blob::register(parent, &self.delete(), keys, step_key(n)).unwrap()
    }
    pub fn genesis(&self) -> &Step {
        &self.steps[0]
    }
    pub fn head(&self) -> &Step {
        self.steps.last().unwrap()
    }
}

/// `Store::take_register` of `steps` under `s`'s sync ID, with no endorsement, at monotonic 0.
pub trait Register {
    fn reg(&mut self, s: &Sid, steps: &[Step]) -> osis_proto::Code;
}

impl Register for osis_sync::Store {
    fn reg(&mut self, s: &Sid, steps: &[Step]) -> osis_proto::Code {
        self.take_register(&s.id, steps, None, osis_base::Mono(0)).unwrap()
    }
}
