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
/// they put, per holder the (role, epoch) of each with the holder's keyset it is to.
pub(crate) struct Boxing {
    thing: Tid,
    sync_id: SyncId,
    section: Option<Secret32>,
    boxes: BTreeMap<Tid, Vec<(Role, Epoch, Option<To>)>>,
}

/// The keyset of the holder a box is to (spec/crypto.md §4): a sealed box's keyset (a joint
/// box's last), or a symmetric box's epoch, whose KEM key the writer derives from the secret.
#[derive(Clone, Copy)]
enum To {
    Sealed(Epoch),
    Symmetric(Epoch),
}

impl To {
    fn of(b: &osis_schema::core_types::SecretBox) -> Option<To> {
        use osis_keys::aspects::from_schema;
        use osis_schema::core_types::SecretBox;
        match b {
            SecretBox::Sealed(x) => x.keyset.as_ref().and_then(|e| from_schema(e).ok()).map(To::Sealed),
            SecretBox::Joint(x) => x.keysets.iter().next_back().and_then(|e| from_schema(e).ok()).map(To::Sealed),
            SecretBox::Symmetric(x) => from_schema(&x.epoch).ok().map(To::Symmetric),
            SecretBox::Open(_) => None,
        }
    }
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
            let mut boxes: BTreeMap<Tid, Vec<(Role, Epoch, Option<To>)>> = BTreeMap::new();
            if !secrets.is_empty()
                && let Some(f) = self.read(|tx| crate::apply::held_joined(tx, &id, secrets))?
            {
                for (k, b) in crate::apply::keys::secrets_write(&f).boxes {
                    if let Ok(e) = osis_keys::aspects::from_schema(&k.epoch) {
                        boxes.entry(k.holder.0).or_default().push((k.role, e, To::of(&b)));
                    }
                }
            }
            out.push(Boxing { thing: x, sync_id, section, boxes });
        }
        Ok(out)
    }

    /// The entry blocks of an encryption of blob key `blob_key` and salt `salt` (spec/sync-ids.md
    /// §3 Entry block): per thing of `boxing`, per current sync epoch of it whose secret this node
    /// holds, each holder's entries: a read entry where it is boxed at a read epoch, a sync entry
    /// where at sync at that epoch (the public's one), each sealed to the KEM key of the keyset
    /// its box of that role is to (the newest read box's; one with no KEM key here left out),
    /// signed by that epoch's sync key; a block of dummies alone where this node holds no claim
    /// key of the epoch; paged where they are more than an entry page holds (`frame` makes each
    /// page).
    pub(crate) fn entry_blocks(&mut self, boxing: &[Boxing], blob_key: &Secret32, salt: &[u8; 16], frame: &mut crate::sync_ids::blobs::PageFrame<'_>, rng: &mut dyn CryptoRngCore) -> Result<Vec<EntryBlock>> {
        let mut out = Vec::new();
        for b in boxing {
            let Some(epochs) = self.core.epochs(&b.thing) else { continue };
            for e in epochs.sync.current() {
                let Some(secret) = epochs.sync.reading_secret(&e) else { continue };
                let sync_key = role_key(RoleKey::Sync, secret.secret());
                let mut entries = Vec::new();
                if let Some(ck) = self.core.claim_key(&b.thing, &e) {
                    for (m, at) in &b.boxes {
                        // a read entry by its newest read box, a sync entry by its box at `e`; the
                        // public's one entry, in clear, by its read box where it has one
                        let newest = osis_keys::newest_of(at.iter().filter(|(r, _, _)| *r == Role::Read).map(|(_, x, _)| x));
                        let read = at.iter().find(|(r, x, _)| *r == Role::Read && Some(*x) == newest).zip(b.section.as_ref());
                        let sync = at.iter().find(|(r, x, _)| *r == Role::Sync && *x == e).filter(|_| !(m.is_public() && read.is_some()));
                        let read = read.map(|((_, _, to), s)| (EntryKeys::Read { blob_key: blob_key.clone(), section_key: s.clone() }, (Role::Read, *to)));
                        let sync = sync.map(|(_, _, to)| (EntryKeys::Sync { n: e.n(), secret: secret.secret().clone() }, (Role::Sync, *to)));
                        for (keys, to) in read.into_iter().chain(sync) {
                            if let Some(entry) = self.entry_of(m, to, &ck, &b.sync_id, &keys, rng)? {
                                entries.push(entry);
                            }
                        }
                    }
                }
                out.push(EntryBlock::sign_paged(&sync_key, &b.sync_id, salt, entries, self.core.entry_page, frame, rng)?.block);
            }
        }
        Ok(out)
    }

    /// Holder `m`'s entry under claim key `ck`, carrying `keys`, sealed to the KEM key of `m`'s
    /// keyset of role `to.0` its box is to: none where that key is not held here or the DH is
    /// non-contributory.
    fn entry_of(&mut self, m: &Tid, to: (Role, Option<To>), ck: &X25519Secret, sync_id: &SyncId, keys: &EntryKeys, rng: &mut dyn CryptoRngCore) -> Result<Option<Entry>> {
        let step_key = ck.public();
        if m.is_public() {
            let claim = osis_crypto::public_claim(sync_id, &step_key).verifying_key().to_bytes();
            return Ok(Some(Entry { claim, w: osis_crypto::public_entry(keys) }));
        }
        let (r, Some(to)) = to else { return Ok(None) };
        let Some(kem) = self.holder_kem_key(m, r, to)? else { return Ok(None) };
        let Ok(claim) = osis_crypto::claim(ck, &kem.x25519(), sync_id, &step_key) else { return Ok(None) };
        let claim = claim.verifying_key().to_bytes();
        let w = osis_crypto::seal_entry(&kem, sync_id, &claim, keys, rng)?;
        Ok(Some(Entry { claim, w }))
    }

    /// The KEM key of `m`'s keyset of role `r` a box is to: a sealed box's, read from the body
    /// noting it; a symmetric box's, derived from the held secret.
    fn holder_kem_key(&mut self, m: &Tid, r: Role, to: To) -> Result<Option<KemPublicKey>> {
        match to {
            To::Sealed(e) => self.read(|tx| crate::apply::keys::keyset_kem(tx, m, r, &e)),
            To::Symmetric(e) => Ok(self.core.epochs(m).and_then(|x| x.role(r).secret(&e).map(|s| s.kem().public().clone()))),
        }
    }
}

/// The step key of each sync key on a known path (`Engine::step_keys`).
type StepKeys = BTreeMap<[u8; 32], [u8; 32]>;

/// What the entries of a blob under S give this node (spec/sync-ids.md §3 Taking an entry): every
/// entry of a holder it reaches S's thing through is taken, so one holder's entry never hides
/// another's (an account's sync entry beside the public's read one).
#[derive(Default)]
pub(crate) struct Took {
    /// A read holder's (the public's alike): S's thing, the blob key and the key of the section
    /// holding the commit's role parts on it.
    pub(crate) read: Option<(Tid, Secret32, Secret32)>,
    /// Each sync holder's (none: a link's key) whose sync secret of S's thing's epoch the block is
    /// bound to was taken, with the thing.
    pub(crate) sync: Vec<(Tid, Option<Tid>)>,
}

impl Engine {
    /// Takes a path a Head answer gave for `s` (`Core::heard`; verified from genesis by the
    /// caller): the steps this node computes claims at and finds entries by while it records no
    /// path of `s` of its own. The same again moves nothing.
    pub fn hear_path(&mut self, s: &SyncId, steps: Vec<osis_blob::Step>) {
        if self.core.heard.get(s).is_some_and(|p| **p == steps) {
            return;
        }
        self.core.heard.insert(*s, std::sync::Arc::new(steps));
    }

    /// The length of the path heard for `s` (`hear_path`).
    pub fn heard_len(&self, s: &SyncId) -> usize {
        self.core.heard.get(s).map_or(0, |p| p.len())
    }

    /// The step key of each sync key on a path of `s` this node knows: the recorded paths of `s`'s
    /// things, the heard one, and `more` (a store's path), by sync key.
    /// With the sync key of the head: the last step of the longest of those paths.
    fn step_keys(&mut self, s: &SyncId, things: &[Tid], more: &[osis_blob::Step]) -> Result<(StepKeys, Option<[u8; 32]>)> {
        let mut out = BTreeMap::new();
        let mut head: (usize, Option<[u8; 32]>) = (0, None);
        let mut take = |out: &mut StepKeys, steps: &[osis_blob::Step]| {
            out.extend(steps.iter().map(|st| (st.keys.sync.to_bytes(), st.step_key)));
            if steps.len() > head.0 {
                head = (steps.len(), steps.last().map(|st| st.keys.sync.to_bytes()));
            }
        };
        for t in things {
            for o in self.owned_sync_ids(t)?.iter().filter(|o| o.id == *s) {
                take(&mut out, &o.path.steps);
            }
        }
        let heard = self.core.heard.get(s).cloned().unwrap_or_default();
        take(&mut out, &heard);
        take(&mut out, more);
        Ok((out, head.1))
    }

    /// Every entry of a holder this node reaches `s`'s thing through (`claimants`) in blob `bytes`
    /// under `s`, opened and taken (spec/sync-ids.md §3 Taking an entry): each found by its claim at the
    /// step key of the sync key its block is bound to (a block that does not verify under `s`
    /// counts for nothing); a sync holder's secret kept only where it derives that sync key; the
    /// public's, where this node holds `s` without reading it, only in a block bound to its head.
    /// `path`: a path of `s` known beside this node's own (a store's); `pages`: the bytes of the
    /// blob's entry pages held (spec/wire.md §5 Entry pages), an entry in a page not given not
    /// found.
    pub(crate) fn take_entry(&mut self, s: &SyncId, bytes: &[u8], path: &[osis_blob::Step], pages: &[Vec<u8>]) -> Result<Took> {
        let mut took = Took::default();
        let Ok(Some(prefix)) = osis_blob::clear_prefix(bytes) else { return Ok(took) };
        if prefix.blocks().is_empty() || osis_blob::is_entry_page(bytes) {
            return Ok(took);
        }
        // the entry pages at hand, by blob ID (spec/wire.md §5 Entry pages)
        let pages: BTreeMap<osis_base::BlobId, (EntryBlock, [u8; 16])> = pages.iter().filter_map(|p| osis_blob::read_page(p)).map(|(id, b, salt)| (id, (b, salt))).collect();
        let things = self.sync_things_of(s)?;
        let Some(thing) = things.first().copied() else { return Ok(took) };
        let (steps, head) = self.step_keys(s, &things, path)?;
        let claimants = self.claimants(s, &things);
        for block in prefix.blocks() {
            let Some(step_key) = steps.get(block.sync_pk()) else { continue };
            if !block.verifies(s, prefix.salt()) {
                continue;
            }
            // the public's claim held without reading S: in the blocks bound to the head alone
            let public = claimants.public || (claimants.public_at_head && head.as_ref() == Some(block.sync_pk()));
            // its entries: inline, or those of each page it names that verifies under S by the
            // same sync key
            let paged = block.pages().iter().filter_map(|id| pages.get(id)).filter(|(b, salt)| b.sync_pk() == block.sync_pk() && b.verifies(s, salt));
            let entries: Vec<&osis_blob::Entry> = block.entries().iter().chain(paged.flat_map(|(b, _)| b.entries())).collect();
            let mut found: Vec<(Option<Tid>, EntryKeys)> = Vec::new();
            for (holder, k) in claimants.each().filter(|(_, k)| k.is_some() || public) {
                let Some(claim) = crate::sync::claim_at(k, s, step_key) else { continue };
                let claim = claim.verifying_key().to_bytes();
                let Some(e) = entries.iter().find(|e| e.claim == claim) else { continue };
                let keys = match k {
                    Some(kem) => osis_crypto::open_entry(kem, s, &e.claim, &e.w),
                    None => osis_crypto::read_public_entry(&e.w),
                };
                found.extend(keys.map(|k| (holder, k)));
            }
            // a holder's sync entry is for a node holding its sync secrets alone: one that opens
            // its read entry takes that (spec/sync-ids.md §3 Entries)
            let read: Vec<Option<Tid>> = found.iter().filter(|(_, k)| matches!(k, EntryKeys::Read { .. })).map(|(h, _)| *h).collect();
            for (holder, keys) in found {
                match keys {
                    EntryKeys::Read { blob_key, section_key } => took.read = took.read.or(Some((thing, blob_key, section_key))),
                    EntryKeys::Sync { .. } if read.contains(&holder) => {}
                    EntryKeys::Sync { n, secret } if derives(&secret, block.sync_pk()) => {
                        let Ok(epoch) = Epoch::derive(&thing, Role::Sync, n, &secret) else { continue };
                        self.run(|tx| {
                            crate::apply::keys::edit_epochs(tx, thing, |ep| ep.role_mut(Role::Sync).set_secret(epoch, osis_crypto::RoleSecret::new(secret.clone())));
                            tx.core.touch();
                            Ok(())
                        })?;
                        took.sync.push((thing, holder));
                    }
                    _ => {}
                }
            }
        }
        Ok(took)
    }
}

/// Whether a sync holder's secret from an entry is kept: only where it derives the sync key of
/// the block the entry is in (spec/sync-ids.md §3 Taking an entry), so an entry names no secret
/// of another epoch, nor one a block's signer did not hold.
pub(crate) fn derives(secret: &Secret32, sync_pk: &[u8; 32]) -> bool {
    role_key(RoleKey::Sync, secret).verifying_key().to_bytes() == *sync_pk
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/sync-ids.md §3 Taking an entry: a sync secret is kept only where it derives the
    // block's sync key
    #[test]
    fn a_sync_secret_is_kept_only_where_it_derives_the_blocks_key_spec_sync_ids_3() {
        let (a, b) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]));
        let pk = role_key(RoleKey::Sync, &a).verifying_key().to_bytes();
        assert!(derives(&a, &pk));
        assert!(!derives(&b, &pk), "another epoch's secret");
        // the key of another role from the same secret is no sync key
        assert!(!derives(&a, &role_key(RoleKey::Write, &a).verifying_key().to_bytes()));
    }
}
