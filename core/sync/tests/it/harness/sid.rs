//! A sync ID's secrets and steps, as an admin issues them (the store's and streams' tests).

use osis_base::{SyncId, Tid};
use osis_blob::{ClaimSet, Parent, Reader, Step, StepKeys};
use osis_crypto::{Epoch, RoleKey, Secret32, SeededRng, SigningSecret, role_key};

/// A sync ID's role secrets and the steps issued so far.
#[derive(Clone)]
pub struct Sid {
    pub id: SyncId,
    pub sync: Secret32,
    pub write: Secret32,
    pub admin: Secret32,
    pub deposit: Secret32,
    pub steps: Vec<(Step, ClaimSet)>,
}

pub const THING: Tid = Tid::from_bytes([0x51; 15]);

impl Sid {
    pub fn new(b: u8) -> Sid {
        let (sync, write, admin, deposit) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
        let id = osis_blob::genesis_sync_id(&admin);
        let mut s = Sid { id, sync, write, admin, deposit, steps: Vec::new() };
        let g = s.issue(&[]);
        s.steps.push(g);
        s
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
    /// The next step (a child of the last), listing `readers`.
    pub fn issue(&self, readers: &[Reader]) -> (Step, ClaimSet) {
        self.issue_by(readers, &self.delete())
    }
    /// The next step, signed by `d` (the parent's delete key).
    pub fn issue_by(&self, readers: &[Reader], d: &SigningSecret) -> (Step, ClaimSet) {
        let mut rng = SeededRng::from_u64(self.steps.len() as u64 + 99);
        let n = self.steps.len() as u64;
        let read = Epoch::derive(&THING, osis_base::Role::Read, n, &self.write).unwrap();
        let sync = Epoch::derive(&THING, osis_base::Role::Sync, n, &self.sync).unwrap();
        let parent = match self.steps.last() {
            None => Parent::Genesis(d),
            Some((p, _)) => Parent::Child { step: p, delete: d },
        };
        osis_blob::register(parent, self.keys(), readers, (&THING, read, &self.write), (sync, &self.sync), &mut rng).unwrap()
    }
    /// Rotates the write and sync secrets and issues the next step.
    pub fn rotate(&mut self, b: u8) -> (Step, ClaimSet) {
        self.write = Secret32::from_bytes([b; 32]);
        self.sync = Secret32::from_bytes([b + 1; 32]);
        let st = self.issue(&[]);
        self.steps.push(st.clone());
        st
    }
    /// Step `n`, a child of `parent`, whose write secret is `[w; 32]` (the other secrets as
    /// they are; nothing issued here changes).
    pub fn child(&self, parent: &Step, n: u64, w: u8) -> (Step, ClaimSet) {
        let write = Secret32::from_bytes([w; 32]);
        let keys = StepKeys::derive(&self.sync, &write, &self.admin, &self.deposit, &self.id);
        let read = Epoch::derive(&THING, osis_base::Role::Read, n, &write).unwrap();
        let se = Epoch::derive(&THING, osis_base::Role::Sync, n, &self.sync).unwrap();
        osis_blob::register(Parent::Child { step: parent, delete: &self.delete() }, keys, &[], (&THING, read, &write), (se, &self.sync), &mut SeededRng::from_u64(99 + n)).unwrap()
    }
    pub fn genesis(&self) -> &(Step, ClaimSet) {
        &self.steps[0]
    }
    pub fn head(&self) -> &Step {
        &self.steps.last().unwrap().0
    }
}

/// `Store::take_register` of `steps` under `s`'s sync ID, with no endorsement, at monotonic 0.
pub trait Register {
    fn reg(&mut self, s: &Sid, steps: &[(&Step, Option<&ClaimSet>)]) -> osis_proto::Code;
}

impl Register for osis_sync::Store {
    fn reg(&mut self, s: &Sid, steps: &[(&Step, Option<&ClaimSet>)]) -> osis_proto::Code {
        self.take_register(&s.id, steps, None, osis_base::Mono(0)).unwrap()
    }
}
