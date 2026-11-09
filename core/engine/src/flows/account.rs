//! Accounts (spec/permissions.md §1, spec/crypto.md §3, §9): creating one (the account, its
//! devices actor D, its profile), holding its epoch seeds from D's `account.0`, and what signing
//! as it and sealing to it read from the held signing chain.

use super::labels::{ReaderKey, new_label};
use super::{Done, put_edge};
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::identity::thing_record;
use crate::rotation;
use crate::Mutation;
use osis_base::{CommitId, CreationRecord, Role, Tid, SIGNING_KEY_ED25519};
use osis_commit::{CommitBlob, FIRST_EPOCH};
use osis_crypto::{AccountEpochKeys, Epoch, KemPublicKey, Secret32, VerifyingKey, open_inner, verify_inner};
use osis_keys::{ActorEpochs, HolderKeys, Keysets, ROLES, Recipient, account_epoch, account_keysets};
use osis_label::Address;
use osis_perm::chain::{Chain, Rotation};
use osis_schema::core_types::{self as ct, Edge, KemKey, Keys, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An account this node signs as (`Engine::hold_account`).
#[derive(Clone, Debug)]
pub struct HeldAccount {
    pub devices: Tid,
    /// The first epoch's signing key (the creation record's).
    pub first: [u8; 32],
    /// Epoch seeds held, by signing public key.
    pub seeds: BTreeMap<[u8; 32], Secret32>,
}

/// An account this node created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedAccount {
    pub account: Tid,
    pub devices: Tid,
    pub profile: Tid,
}

struct EpochPublic {
    height: u64,
    signing: VerifyingKey,
    kem: Option<KemPublicKey>,
    supersedes: Vec<CommitId>,
}

/// An account's signing chain as this node holds it.
pub(crate) struct AccountView {
    chain: Chain<CommitId>,
    epochs: BTreeMap<CommitId, EpochPublic>,
}

impl AccountView {
    fn name(&self, e: &EpochPublic) -> Option<Epoch> {
        account_epoch(e.height, &e.signing).ok()
    }

    /// The account's keysets as the seal and stale rules read them (spec/crypto.md §4).
    pub(crate) fn keysets(&self) -> Keysets {
        let named = self.epochs.iter().filter_map(|(id, e)| Some((*id, self.name(e)?))).collect();
        account_keysets(&self.chain, &named)
    }

    /// The newest open epoch that `held` admits, ties by the greater signing key.
    fn newest_open(&self, held: impl Fn(&EpochPublic) -> bool) -> Option<(&CommitId, &EpochPublic)> {
        self.epochs.iter().filter(|(id, e)| self.chain.open(id) && held(e)).max_by_key(|(_, e)| (e.height, e.signing.to_bytes()))
    }
}

/// Height of rotation `id` (spec/crypto.md §3): 1 plus the greatest height of what it supersedes.
fn height(id: CommitId, supersedes: &BTreeMap<CommitId, Vec<CommitId>>, memo: &mut BTreeMap<CommitId, u64>) -> u64 {
    if let Some(h) = memo.get(&id) {
        return *h;
    }
    let Some(sup) = supersedes.get(&id) else { return 0 };
    let h = sup.iter().map(|s| height(*s, supersedes, memo)).max().unwrap_or(0).saturating_add(1);
    memo.insert(id, h);
    h
}

impl Core {
    pub(crate) fn is_account(&self, t: &Tid) -> bool {
        self.created(t).is_some_and(CreationRecord::is_account)
    }

    /// The signing chain of account `p` from the rotations held (`None`: `p` is not known as an
    /// account here). A merge's forks stand unaccepted until merges are written: the chain is
    /// given no verified merge signature.
    pub(crate) fn account_view(&self, p: &Tid) -> Option<AccountView> {
        let first = match self.created(p) {
            Some(CreationRecord::KeyActor { public_key, account: true, .. }) => VerifyingKey::from_slice(public_key).ok()?,
            Some(_) => return None,
            None => VerifyingKey::from_bytes(&self.accounts.get(p)?.first).ok()?,
        };
        let ak = osis_base::Ak::new("keys.0").ok()?;
        let rots: Vec<(CommitId, CommitId, osis_commit::RotationHeader)> = self.ix.by_aspect.get(&(*p, ak)).into_iter().flatten().filter_map(|(_, c)| {
            let m = self.ix.commits.get(c).filter(|m| m.view.author == *p)?;
            Some((*c, m.header.epoch?, m.header.rotation.clone()?))
        }).collect();
        let sup: BTreeMap<CommitId, Vec<CommitId>> = rots.iter().map(|(id, _, r)| (*id, r.supersedes.clone())).collect();
        let mut memo = BTreeMap::new();
        let mut epochs = BTreeMap::new();
        epochs.insert(FIRST_EPOCH, EpochPublic { height: 0, signing: first, kem: None, supersedes: Vec::new() });
        for (id, _, r) in &rots {
            epochs.insert(*id, EpochPublic { height: height(*id, &sup, &mut memo), signing: r.signing_key, kem: Some(r.kem_key.clone()), supersedes: r.supersedes.clone() });
        }
        let chain = Chain::new(FIRST_EPOCH, rots.iter().map(|(id, at, r)| Rotation { id: *id, at: *at, supersedes: r.supersedes.iter().copied().collect(), names: r.names.iter().copied().collect(), signed: BTreeSet::new() }), None);
        Some(AccountView { chain, epochs })
    }

    /// The epoch this node signs as `p` at and its keys: the newest open one it holds a seed of
    /// (spec/permissions.md §5.5). `None` when `p` is no account held here.
    pub(crate) fn account_signing(&self, p: &Tid) -> Result<Option<(CommitId, AccountEpochKeys)>> {
        let Some(a) = self.accounts.get(p) else { return Ok(None) };
        let v = self.account_view(p).ok_or(Error::Misuse("no signing chain for the account"))?;
        let (id, e) = v.newest_open(|e| a.seeds.contains_key(&e.signing.to_bytes())).ok_or(Error::Misuse("no open epoch of the account held"))?;
        let seed = a.seeds.get(&e.signing.to_bytes()).ok_or(Error::Misuse("no open epoch of the account held"))?;
        Ok(Some((*id, AccountEpochKeys::from_seed(seed))))
    }

    /// The role epochs of account `p` this node holds seeds of (spec/crypto.md §3), internal to
    /// its nodes.
    pub(crate) fn account_epochs(&self, p: &Tid) -> Option<ActorEpochs> {
        let a = self.accounts.get(p)?;
        let v = self.account_view(p)?;
        let seed = |e: &EpochPublic| a.seeds.get(&e.signing.to_bytes()).cloned();
        let held: Vec<_> = v.epochs.values().filter_map(|e| {
            let sup = e.supersedes.iter().filter_map(|s| v.epochs.get(s)).filter_map(|x| Some((x.height, seed(x)?))).collect();
            Some((e.height, seed(e)?, sup))
        }).collect();
        ActorEpochs::account(p, &held).ok()
    }

    /// The seeds of `p` held, by epoch name (spec/crypto.md §3).
    pub(crate) fn account_seeds_by_name(&self, p: &Tid) -> BTreeMap<Epoch, Secret32> {
        let (Some(a), Some(v)) = (self.accounts.get(p), self.account_view(p)) else { return BTreeMap::new() };
        v.epochs.values().filter_map(|e| Some((v.name(e)?, a.seeds.get(&e.signing.to_bytes())?.clone()))).collect()
    }

    /// An account's delete key (spec/crypto.md §7): the signing key of its newest open epoch
    /// held, else of its newest open epoch.
    pub(crate) fn account_delete_key(&self, p: &Tid) -> Option<VerifyingKey> {
        let v = self.account_view(p)?;
        let held = self.accounts.get(p);
        let newest = v.newest_open(|e| held.is_some_and(|a| a.seeds.contains_key(&e.signing.to_bytes()))).or_else(|| v.newest_open(|_| true))?;
        Some(newest.1.signing)
    }
}

/// How a box to account `p` is sealed (spec/crypto.md §3, §4): at its newest open epoch, the
/// first epoch's KEM key from `keys.0` of that signing key, a rotation's from its header.
pub(crate) fn holder_keys(tx: &mut Tx<'_>, p: &Tid) -> Result<HolderKeys> {
    let v = tx.core.account_view(p).ok_or(Error::UnknownThing(*p))?;
    let (_, e) = v.newest_open(|_| true).ok_or(Error::Misuse("no open epoch of the account"))?;
    let kem = match &e.kem {
        Some(k) => k.clone(),
        None => first_kem(Core::keys_in(tx, p)?, &e.signing).ok_or(Error::Misuse("no keys.0 of the account's epoch held"))?,
    };
    let epoch = v.name(e).ok_or(Error::Misuse("account epoch"))?;
    let seed = tx.core.accounts.get(p).and_then(|a| a.seeds.get(&e.signing.to_bytes()).cloned());
    Ok(HolderKeys::Account { epoch, kem, seed })
}

/// The KEM key of an account's first epoch: `keys.0`'s `key` when its `signing` is that epoch's.
fn first_kem(keys: Option<Keys>, signing: &VerifyingKey) -> Option<KemPublicKey> {
    let k = keys?;
    let SigningKey::Ed25519(s) = k.signing?;
    if s != signing.to_bytes() {
        return None;
    }
    let KemKey::X25519MlKem768(b) = k.key?;
    KemPublicKey::from_slice(&b).ok()
}

fn admin_edge() -> Edge {
    Edge { role: Role::Admin, until: None, invite: None, tied: None }
}

impl Engine {
    /// Creates an account (spec/permissions.md §1): the account at its first epoch, its devices
    /// actor D (secrets of its own boxed to this node, its home label on `hosts`, the epoch's
    /// seed in `account.0`) and its profile, one commit signed as the account.
    pub fn create_account(&mut self, hosts: &[Address]) -> Result<(CreatedAccount, Done)> {
        let (seed, nonce, nonce_d) = self.run(|tx| {
            let mut n = [0u8; 32];
            tx.rng.fill_bytes(&mut n);
            Ok((Secret32::random(&mut *tx.rng), n, thing_record(Tid::from_bytes([0; 15]), &mut *tx.rng)))
        })?;
        let keys = AccountEpochKeys::from_seed(&seed);
        let signing = keys.signing.verifying_key().to_bytes();
        let record = CreationRecord::KeyActor { alg: SIGNING_KEY_ED25519, public_key: signing.to_vec(), nonce, account: true };
        let p = record.tid();
        let d_record = CreationRecord::Thing { admin: p, nonce: *nonce_d.nonce(), link: false };
        let d = d_record.tid();
        self.core.accounts.insert(p, Arc::new(HeldAccount { devices: d, first: signing, seeds: [(signing, seed.clone())].into() }));
        self.core.role_changed();
        let res = self.run(|tx| create_account_in(tx, record, d_record, &keys, &seed, hosts));
        if res.is_err() {
            self.core.accounts.remove(&p);
        }
        let (profile, c) = res?;
        let mut done = Done::default();
        done.add(c);
        Ok((CreatedAccount { account: p, devices: d, profile }, done))
    }

    /// Takes up account `p` from the seeds on its devices actor `d` (`account.0`, readable here
    /// as a node of the account): this node signs as it (`Mutation::sign_as`) and its boxes
    /// open. In memory only.
    pub fn hold_account(&mut self, p: &Tid, d: &Tid) -> Result<()> {
        let Some(CreationRecord::KeyActor { public_key, account: true, .. }) = self.core.created(p).cloned() else { return Err(Error::UnknownThing(*p)) };
        let first: [u8; 32] = public_key.as_slice().try_into().map_err(|_| Error::Misuse("account key"))?;
        let stored = self.get_typed(d, &ct::ACCOUNT)?.ok_or(Error::UnknownThing(*d))?;
        let mut seeds = BTreeMap::new();
        for (k, v) in stored.seeds {
            let (Ok(k), Ok(v)) = (<[u8; 32]>::try_from(k), <[u8; 32]>::try_from(v)) else { continue };
            let seed = Secret32::from_bytes(v);
            // an entry that is not its epoch's seed opens and signs nothing
            if AccountEpochKeys::from_seed(&seed).signing.verifying_key().to_bytes() == k {
                seeds.insert(k, seed);
            }
        }
        if seeds.is_empty() {
            return Err(Error::Misuse("no seed of the account readable here"));
        }
        self.core.accounts.insert(*p, Arc::new(HeldAccount { devices: *d, first, seeds }));
        self.core.role_changed();
        Ok(())
    }

    /// The node whose inner signature `blob` carries, when this node holds the seed of the epoch
    /// it is signed at and the signature verifies under that node's key (spec/crypto.md §3).
    pub fn open_inner(&self, blob: &CommitBlob) -> Option<Tid> {
        let (h, inner) = (&blob.header, blob.sigs.inner.as_ref()?);
        let a = self.core.accounts.get(&h.author)?;
        let v = self.core.account_view(&h.author)?;
        let e = v.epochs.get(&h.epoch?)?;
        let keys = AccountEpochKeys::from_seed(a.seeds.get(&e.signing.to_bytes())?);
        let id = h.id();
        let (node, sig) = open_inner(&keys.inner, &id.0, inner)?;
        let CreationRecord::KeyActor { public_key, .. } = self.core.created(&node)? else { return None };
        verify_inner(&VerifyingKey::from_slice(public_key).ok()?, &id.0, &sig).then_some(node)
    }
}

fn create_account_in(tx: &mut Tx<'_>, record: CreationRecord, d_record: CreationRecord, keys: &AccountEpochKeys, seed: &Secret32, hosts: &[Address]) -> Result<(Tid, Option<CommitId>)> {
    let p = record.tid();
    let me = tx.core.id.tid();
    let mut m = Mutation::new();
    m.create(record);
    let d = m.create(d_record);
    let profile = m.create(thing_record(p, &mut *tx.rng));
    m.sign_as(p);
    let held = ActorEpochs::derived(&tx.core.account_epochs(&p).ok_or(Error::Misuse("account not held"))?, &d);
    let node_kem = tx.core.id.keys().kem.public().clone();
    let holders = [Recipient { holder: me, role: Role::Admin, keys: HolderKeys::KeyActor { kem: node_kem.clone(), seed: None } }];
    let rot = rotation::rotation_into(tx, &mut m, d, &ROLES.into_iter().collect(), &held, &holders, false)?;
    let after = rot.preview(&held)?;
    let mut dep = [0u8; 32];
    tx.rng.fill_bytes(&mut dep);
    let label = new_label(tx, &mut m, d, &after, &[ReaderKey::Dh(node_kem.x25519())], &Secret32::from_bytes(dep), hosts)?;
    m.set(p, &ct::KEYS, &Keys { inbox: Some(ct::Inbox { label, hosts: hosts.to_vec() }), deposit_seed: Some(dep), ..osis_keys::aspects::account_keys(keys) })?;
    put_edge(&mut m, d, me, &admin_edge())?;
    let signing = keys.signing.verifying_key().to_bytes().to_vec();
    m.set(d, &ct::ACCOUNT, &ct::Account { seeds: [(signing, seed.expose().to_vec())].into() })?;
    let c = Engine::commit_tx(tx, m)?;
    rotation::record(tx, d, &rot)?;
    Ok((profile, c))
}
