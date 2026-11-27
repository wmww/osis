//! Entry blocks in a blob's clear prefix (spec/sync-ids.md §3, spec/wire.md §5 Entry blocks).

use crate::Error;
use osis_base::SyncId;
use osis_crypto::{CryptoRngCore, Signature, SigningSecret, VerifyingKey, W_LEN, sign_entry_block, verify_entry_block};

/// Bytes of one entry: `claim (32) || W (1201)`.
pub const ENTRY_LEN: usize = 32 + W_LEN;
/// The most entries one block's le16 count names that is a power of two.
const MAX_ENTRIES: usize = 1 << 15;

/// One entry: a claim's raw public key and its W (a dummy's: random bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    pub claim: [u8; 32],
    pub w: Vec<u8>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Entry({:02x?})", self.claim.get(..4).unwrap_or_default())
    }
}

/// An entry block: entries bound to the sync epoch of `sync_pk`, signed by it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryBlock {
    sync_pk: [u8; 32],
    entries: Vec<Entry>,
    sig: [u8; 64],
}

/// The entry count a block of `real` entries pads to: the least power of two above `real`, at
/// least 2 (so at least one dummy).
pub fn padded_count(real: usize) -> usize {
    (real + 1).next_power_of_two().max(2)
}

impl EntryBlock {
    /// A block of `entries` under the sync key `sync_key` for a blob of salt `salt` of sync ID
    /// `sync_id`: padded with dummies to `padded_count`, in random order, signed.
    pub fn sign(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], mut entries: Vec<Entry>, rng: &mut dyn CryptoRngCore) -> Result<EntryBlock, Error> {
        let k = padded_count(entries.len());
        if k > MAX_ENTRIES {
            return Err(Error::TooLarge("entries in one entry block"));
        }
        while entries.len() < k {
            let mut claim = [0u8; 32];
            rng.fill_bytes(&mut claim);
            let mut w = vec![0u8; W_LEN];
            rng.fill_bytes(&mut w);
            entries.push(Entry { claim, w });
        }
        // Fisher-Yates; the bias of `% (i + 1)` over a u64 is negligible
        for i in (1..entries.len()).rev() {
            let j = usize::try_from(rng.next_u64() % (i as u64 + 1)).unwrap_or(0);
            entries.swap(i, j);
        }
        let mut b = EntryBlock { sync_pk: sync_key.verifying_key().to_bytes(), entries, sig: [0; 64] };
        b.sig = sign_entry_block(sync_key, sync_id, salt, &b.unsigned()).0;
        Ok(b)
    }

    /// The raw sync key whose epoch it is bound to, where its signature verifies.
    pub fn sync_pk(&self) -> &[u8; 32] {
        &self.sync_pk
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry of `claim`, if any.
    pub fn find(&self, claim: &[u8; 32]) -> Option<&Entry> {
        self.entries.iter().find(|e| e.claim == *claim)
    }

    /// Its signature verifies under `sync_pk` for `sync_id` and the blob's salt: else it counts
    /// for nothing under that sync ID.
    pub fn verifies(&self, sync_id: &SyncId, salt: &[u8; 16]) -> bool {
        VerifyingKey::from_bytes(&self.sync_pk).is_ok_and(|pk| verify_entry_block(&pk, sync_id, salt, &self.unsigned(), &Signature(self.sig)).is_ok())
    }

    /// Encoded length.
    pub fn len(&self) -> usize {
        32 + 2 + ENTRY_LEN * self.entries.len() + 64
    }

    /// Never empty; for clippy's `len` convention.
    pub fn is_empty(&self) -> bool {
        false
    }

    fn unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&self.sync_pk);
        // at most MAX_ENTRIES by construction
        out.extend_from_slice(&u16::try_from(self.entries.len()).unwrap_or(u16::MAX).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.claim);
            out.extend_from_slice(&e.w);
        }
        out
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.unsigned());
        out.extend_from_slice(&self.sig);
    }

    /// Parses a block at the start of `b`, returning it and its length; a count that is not a
    /// power of two at least 2, or bytes short of it, is bad input.
    pub fn parse(b: &[u8]) -> Result<(EntryBlock, usize), Error> {
        let short = || Error::Malformed("short entry block");
        let sync_pk: [u8; 32] = b.get(..32).and_then(|x| x.try_into().ok()).ok_or_else(short)?;
        let k = usize::from(u16::from_le_bytes(b.get(32..34).and_then(|x| x.try_into().ok()).ok_or_else(short)?));
        if k < 2 || !k.is_power_of_two() {
            return Err(Error::Malformed("entry count not a power of two at least 2"));
        }
        let body = b.get(34..34 + ENTRY_LEN * k).ok_or_else(short)?;
        let entries = body.chunks_exact(ENTRY_LEN).map(|c| {
            let (claim, w) = c.split_at(32);
            Entry { claim: claim.try_into().unwrap_or([0; 32]), w: w.to_vec() }
        });
        let entries = entries.collect();
        let at = 34 + ENTRY_LEN * k;
        let sig: [u8; 64] = b.get(at..at + 64).and_then(|x| x.try_into().ok()).ok_or_else(short)?;
        Ok((EntryBlock { sync_pk, entries, sig }, at + 64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::{Secret32, SeededRng};

    // spec/sync-ids.md §3: a block pads to a power of two with at least one dummy
    #[test]
    fn a_block_pads_to_a_power_of_two_with_a_dummy_spec_sync_ids_3() {
        assert_eq!([0, 1, 2, 3, 4, 7, 8].map(padded_count), [2, 2, 4, 4, 8, 8, 16]);
        let mut rng = SeededRng::from_u64(0);
        let k = SigningSecret::from_seed(&Secret32::from_bytes([1; 32]));
        let real: Vec<Entry> = (0..3u8).map(|i| Entry { claim: [i; 32], w: vec![i; W_LEN] }).collect();
        let b = EntryBlock::sign(&k, &SyncId([7; 16]), &[2; 16], real.clone(), &mut rng).unwrap();
        assert_eq!(b.entries().len(), 4);
        for e in &real {
            assert_eq!(b.find(&e.claim), Some(e));
        }
        assert!(b.verifies(&SyncId([7; 16]), &[2; 16]));
        assert!(!b.verifies(&SyncId([8; 16]), &[2; 16]));
        let mut out = Vec::new();
        b.write(&mut out);
        assert_eq!(out.len(), b.len());
        assert_eq!(EntryBlock::parse(&out).unwrap(), (b.clone(), out.len()));
        // a count of 3, or one, is bad input
        for k in [1u16, 3] {
            let mut bad = out.clone();
            bad[32..34].copy_from_slice(&k.to_le_bytes());
            assert!(EntryBlock::parse(&bad).is_err());
        }
        assert!(EntryBlock::parse(&out[..out.len() - 1]).is_err());
    }
}
