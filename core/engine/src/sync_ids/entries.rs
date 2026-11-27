//! Entries (spec/sync-ids.md §3): the entry blocks an encryption of a commit boxing holders on an
//! independent thing carries, and the claim keys and claims they are found by.

use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{Role, SyncId, Tid};
use osis_blob::{Entry, EntryBlock};
use osis_commit::{CommitBlob, Header, SectionSeal};
use osis_crypto::{CryptoRngCore, EntryKeys, Epoch, KemPublicKey, RoleKey, Secret32, X25519Secret, role_key};
use std::collections::BTreeMap;

/// What an encryption of a commit holds of one thing its role parts are on: the thing, its sync
/// ID, the key of the section holding those parts (none where it went verbatim) and the boxes
/// they put, per holder the (role, epoch) of each.
pub(crate) struct Boxing {
    thing: Tid,
    sync_id: SyncId,
    section: Option<Secret32>,
    boxes: BTreeMap<Tid, Vec<(Role, Epoch)>>,
}

impl Core {
    /// The claim key of sync epoch `e` of `x` (spec/sync-ids.md §3), where this node holds `e`'s
    /// sync secret and the roles secret of the read epoch `e`'s keyset names: readers alone.
    pub(crate) fn claim_key(&self, x: &Tid, e: &Epoch) -> Option<X25519Secret> {
        let epochs = self.epochs(x)?;
        let sync = epochs.sync.reading_secret(e)?;
        let r = self.keyset(x, Role::Sync, e)?.claim?;
        let roles = epochs.read.checked_roles(&r).or_else(|| epochs.read.reading_secret(&r).map(|s| osis_crypto::roles_secret(s.secret())))?;
        Some(osis_crypto::claim_key(sync.secret(), &roles))
    }

    /// Holder `m`'s read KEM key as a writer of its entry holds it (spec/sync-ids.md §3): that of
    /// `m`'s newest held read keyset carrying one.
    fn holder_kem(&self, m: &Tid) -> Option<Epoch> {
        let read = self.keysets_of(m).filter(|(r, _, k)| *r == Role::Read && k.kem_in.is_some()).map(|(_, e, _)| e).collect::<Vec<_>>();
        osis_keys::newest_of(&read)
    }
}

impl Engine {
    /// What commit `c` (header `h`, its sections as `seals` keep them) boxes on each independent
    /// thing its held role parts are on, by its owner sync ID (spec/sync-ids.md §4 Owner).
    pub(crate) fn boxing(&mut self, c: &CommitBlob, h: &Header, seals: &[SectionSeal]) -> Result<Vec<Boxing>> {
        let id = c.id();
        let mut by: BTreeMap<Tid, Vec<usize>> = BTreeMap::new();
        for p in &c.parts {
            if let Some(a) = h.aspects.get(p.ai).filter(|a| osis_keys::under_roles(a.ak.as_str())) {
                by.entry(a.tid).or_default().push(p.ai);
            }
        }
        let mut out = Vec::new();
        for (x, ais) in by {
            if !self.core.ix.independent.contains(&x) {
                continue;
            }
            let Some((sync_id, false)) = self.core.named_sync_id(&x).flatten() else { continue };
            let section = seals.iter().find_map(|s| match s {
                SectionSeal::Keyed { ais: sa, key, .. } if sa.iter().any(|a| ais.contains(a)) => Some(key.clone()),
                _ => None,
            });
            let secrets: Vec<usize> = ais.iter().copied().filter(|ai| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "secrets.0")).collect();
            let mut boxes: BTreeMap<Tid, Vec<(Role, Epoch)>> = BTreeMap::new();
            if !secrets.is_empty()
                && let Some(f) = self.read(|tx| crate::apply::held_joined(tx, &id, secrets))?
            {
                for k in crate::apply::keys::secrets_write(&f).boxes.keys() {
                    if let Ok(e) = osis_keys::aspects::from_schema(&k.epoch) {
                        boxes.entry(k.holder.0).or_default().push((k.role, e));
                    }
                }
            }
            out.push(Boxing { thing: x, sync_id, section, boxes });
        }
        Ok(out)
    }

    /// The entry blocks of an encryption of blob key `blob_key` and salt `salt` (spec/sync-ids.md
    /// §3 Entry block): per thing of `boxing`, per current sync epoch of it whose secret this node
    /// holds, an entry for each holder boxed at a read epoch or at sync at that epoch (the public
    /// among them; a holder with no held KEM key left out), signed by that epoch's sync key; a
    /// block of dummies alone where this node holds no claim key of the epoch.
    pub(crate) fn entry_blocks(&mut self, boxing: &[Boxing], blob_key: &Secret32, salt: &[u8; 16], rng: &mut dyn CryptoRngCore) -> Result<Vec<EntryBlock>> {
        let mut out = Vec::new();
        for b in boxing {
            let Some(epochs) = self.core.epochs(&b.thing) else { continue };
            for e in epochs.sync.current() {
                let Some(secret) = epochs.sync.reading_secret(&e) else { continue };
                let sync_key = role_key(RoleKey::Sync, secret.secret());
                let mut entries = Vec::new();
                if let Some(ck) = self.core.claim_key(&b.thing, &e) {
                    for (m, at) in &b.boxes {
                        let read = at.iter().any(|(r, _)| *r == Role::Read);
                        let keys = match (read, &b.section) {
                            (true, Some(s)) => EntryKeys::Read { blob_key: blob_key.clone(), section_key: s.clone() },
                            (true, None) => continue,
                            (false, _) if at.iter().any(|(r, x)| *r == Role::Sync && *x == e) => EntryKeys::Sync { n: e.n(), secret: secret.secret().clone() },
                            (false, _) => continue,
                        };
                        if let Some(entry) = self.entry_of(m, &ck, &b.sync_id, &keys, rng)? {
                            entries.push(entry);
                        }
                    }
                }
                out.push(EntryBlock::sign(&sync_key, &b.sync_id, salt, entries, rng)?);
            }
        }
        Ok(out)
    }

    /// Holder `m`'s entry under claim key `ck`, carrying `keys`: none where `m` has no read KEM
    /// key held here or the DH is non-contributory.
    fn entry_of(&mut self, m: &Tid, ck: &X25519Secret, sync_id: &SyncId, keys: &EntryKeys, rng: &mut dyn CryptoRngCore) -> Result<Option<Entry>> {
        let step_key = ck.public();
        if m.is_public() {
            let claim = osis_crypto::public_claim(sync_id, &step_key).verifying_key().to_bytes();
            return Ok(Some(Entry { claim, w: osis_crypto::public_entry(keys) }));
        }
        let Some(kem) = self.holder_kem_key(m)? else { return Ok(None) };
        let Ok(claim) = osis_crypto::claim(ck, &kem.x25519(), sync_id, &step_key) else { return Ok(None) };
        let claim = claim.verifying_key().to_bytes();
        let w = osis_crypto::seal_entry(&kem, sync_id, &claim, keys, rng)?;
        Ok(Some(Entry { claim, w }))
    }

    /// `Core::holder_kem`'s key, read from the body noting it.
    fn holder_kem_key(&mut self, m: &Tid) -> Result<Option<KemPublicKey>> {
        let Some(e) = self.core.holder_kem(m) else { return Ok(None) };
        self.read(|tx| crate::apply::keys::keyset_kem(tx, m, Role::Read, &e))
    }
}

/// The claims of holder `m` at a step of key `step_key` of sync ID `sync_id`, one per read epoch
/// of `m` whose secret `epochs` holds, newest first (spec/sync-ids.md §3: `m` tries each).
pub(crate) fn claims_of(epochs: &osis_keys::ActorEpochs, sync_id: &SyncId, step_key: &[u8; 32]) -> Vec<osis_crypto::SigningSecret> {
    epochs.read.held_newest_first().into_iter().filter_map(|(_, s)| osis_crypto::claim(s.kem().x25519(), step_key, sync_id, step_key).ok()).collect()
}
