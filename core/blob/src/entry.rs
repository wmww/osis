//! Entry blocks in a blob's clear prefix (spec/sync-ids.md §3, spec/wire.md §5 Entry blocks).

use crate::{Error, Prefix};
use osis_base::{BlobId, SyncId};
use osis_crypto::{CryptoRngCore, Signature, SigningSecret, VerifyingKey, W_LEN, sign_entry_block, verify_entry_block};

/// Bytes of one entry: `claim (32) || W (1201)`.
pub const ENTRY_LEN: usize = 32 + W_LEN;
/// The most entries one block's le16 count names that is a power of two.
const MAX_ENTRIES: usize = 1 << 15;
/// The most pages one block's le32 count names that is a power of two (a commit's header bounds
/// its holders far below it, spec/wire.md §2 `MAX_LIST_BYTES`).
const MAX_PAGES: usize = 1 << 31;
/// Entries per entry page (spec/wire.md §5 Entry pages): the most, a power of two, whose bytes
/// stay within `PAGE_TARGET`, as a delta's pages do.
pub const ENTRY_PAGE: usize = {
    let n = osis_base::format::PAGE_TARGET / ENTRY_LEN;
    1 << (usize::BITS - 1 - n.leading_zeros())
};

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

/// An entry block: entries bound to the sync epoch of `sync_pk`, inline or in entry pages
/// (spec/wire.md §5 Entry pages), signed by it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryBlock {
    sync_pk: [u8; 32],
    body: Body,
    sig: [u8; 64],
}

/// What a block holds: its entries, or the blob IDs of the entry pages holding them.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Body {
    Entries(Vec<Entry>),
    Pages(Vec<BlobId>),
}

/// Frames one entry page (its salt, its block) and gives its blob ID (`frame_page`).
pub type PageFrame<'a> = dyn FnMut(&[u8; 16], &EntryBlock) -> Result<BlobId, Error> + 'a;

/// The entries of one encryption bound to one sync epoch: the block its prefix carries and,
/// where they page, each page's salt and block (`EntryBlock::sign_paged`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paged {
    pub block: EntryBlock,
    pub pages: Vec<([u8; 16], EntryBlock)>,
}

/// The entry count a block of `real` entries pads to: the least power of two above `real`, at
/// least 2 (so at least one dummy).
pub fn padded_count(real: usize) -> usize {
    (real + 1).next_power_of_two().max(2)
}

impl EntryBlock {
    /// A block of `entries` under the sync key `sync_key` for a blob of salt `salt` of sync ID
    /// `sync_id`: padded with dummies to `padded_count`, in random order, signed.
    pub fn sign(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], entries: Vec<Entry>, rng: &mut dyn CryptoRngCore) -> Result<EntryBlock, Error> {
        let entries = padded(entries, rng);
        if entries.len() > MAX_ENTRIES {
            return Err(Error::TooLarge("entries in one entry block"));
        }
        Ok(EntryBlock::signed(sync_key, sync_id, salt, Body::Entries(entries)))
    }

    /// `sign`, paged where the padded entries are more than `per_page` (a power of two at least
    /// 2; `ENTRY_PAGE` but in tests): the entries, in random order, split into pages of
    /// `per_page`, each a block under its own random salt, and the block for the blob of salt
    /// `salt` naming the pages framed by `frame` (`frame_page`) in order (spec/wire.md §5 Entry
    /// pages).
    pub fn sign_paged(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], entries: Vec<Entry>, per_page: usize, frame: &mut PageFrame<'_>, rng: &mut dyn CryptoRngCore) -> Result<Paged, Error> {
        let per_page = per_page.clamp(2, MAX_ENTRIES).next_power_of_two();
        let mut entries = padded(entries, rng);
        if entries.len() <= per_page {
            return Ok(Paged { block: EntryBlock::signed(sync_key, sync_id, salt, Body::Entries(entries)), pages: Vec::new() });
        }
        let (mut pages, mut ids) = (Vec::new(), Vec::new());
        while !entries.is_empty() {
            let rest = entries.split_off(per_page.min(entries.len()));
            let page_salt = Prefix::random_salt(rng);
            let block = EntryBlock::signed(sync_key, sync_id, &page_salt, Body::Entries(std::mem::replace(&mut entries, rest)));
            ids.push(frame(&page_salt, &block)?);
            pages.push((page_salt, block));
        }
        if ids.len() > MAX_PAGES {
            return Err(Error::TooLarge("entry pages in one entry block"));
        }
        Ok(Paged { block: EntryBlock::signed(sync_key, sync_id, salt, Body::Pages(ids)), pages })
    }

    fn signed(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], body: Body) -> EntryBlock {
        let mut b = EntryBlock { sync_pk: sync_key.verifying_key().to_bytes(), body, sig: [0; 64] };
        b.sig = sign_entry_block(sync_key, sync_id, salt, &b.unsigned()).0;
        b
    }

    /// The raw sync key whose epoch it is bound to, where its signature verifies.
    pub fn sync_pk(&self) -> &[u8; 32] {
        &self.sync_pk
    }

    /// Its entries: none where they are in pages.
    pub fn entries(&self) -> &[Entry] {
        match &self.body {
            Body::Entries(e) => e,
            Body::Pages(_) => &[],
        }
    }

    /// The blob IDs of the entry pages holding its entries: none where they are inline.
    pub fn pages(&self) -> &[BlobId] {
        match &self.body {
            Body::Entries(_) => &[],
            Body::Pages(p) => p,
        }
    }

    /// The entry of `claim` among its inline entries, if any.
    pub fn find(&self, claim: &[u8; 32]) -> Option<&Entry> {
        self.entries().iter().find(|e| e.claim == *claim)
    }

    /// Its signature verifies under `sync_pk` for `sync_id` and the blob's salt: else it counts
    /// for nothing under that sync ID.
    pub fn verifies(&self, sync_id: &SyncId, salt: &[u8; 16]) -> bool {
        VerifyingKey::from_bytes(&self.sync_pk).is_ok_and(|pk| verify_entry_block(&pk, sync_id, salt, &self.unsigned(), &Signature(self.sig)).is_ok())
    }

    /// Encoded length.
    pub fn len(&self) -> usize {
        32 + 2
            + match &self.body {
                Body::Entries(e) => ENTRY_LEN * e.len(),
                Body::Pages(p) => 4 + 32 * p.len(),
            }
            + 64
    }

    /// Never empty; for clippy's `len` convention.
    pub fn is_empty(&self) -> bool {
        false
    }

    fn unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&self.sync_pk);
        match &self.body {
            Body::Entries(entries) => {
                // at most MAX_ENTRIES by construction
                out.extend_from_slice(&u16::try_from(entries.len()).unwrap_or(u16::MAX).to_le_bytes());
                for e in entries {
                    out.extend_from_slice(&e.claim);
                    out.extend_from_slice(&e.w);
                }
            }
            Body::Pages(pages) => {
                out.extend_from_slice(&0u16.to_le_bytes());
                // at most MAX_PAGES by construction
                out.extend_from_slice(&u32::try_from(pages.len()).unwrap_or(u32::MAX).to_le_bytes());
                for p in pages {
                    out.extend_from_slice(&p.0);
                }
            }
        }
        out
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.unsigned());
        out.extend_from_slice(&self.sig);
    }

    /// Parses a block at the start of `b`, returning it and its length; an entry count that is
    /// neither 0 (paged) nor a power of two at least 2, a page count that is not a power of two
    /// at least 2, or bytes short of it, is bad input.
    pub fn parse(b: &[u8]) -> Result<(EntryBlock, usize), Error> {
        let short = || Error::Malformed("short entry block");
        let sync_pk: [u8; 32] = b.get(..32).and_then(|x| x.try_into().ok()).ok_or_else(short)?;
        let k = usize::from(u16::from_le_bytes(b.get(32..34).and_then(|x| x.try_into().ok()).ok_or_else(short)?));
        let (body, at) = if k == 0 {
            let m = u32::from_le_bytes(b.get(34..38).and_then(|x| x.try_into().ok()).ok_or_else(short)?);
            let m = usize::try_from(m).map_err(|_| short())?;
            if m < 2 || !m.is_power_of_two() || m > MAX_PAGES {
                return Err(Error::Malformed("entry page count not a power of two at least 2"));
            }
            let ids = b.get(38..38 + 32 * m).ok_or_else(short)?;
            (Body::Pages(ids.as_chunks::<32>().0.iter().map(|x| BlobId(*x)).collect()), 38 + 32 * m)
        } else {
            if k < 2 || !k.is_power_of_two() {
                return Err(Error::Malformed("entry count not a power of two at least 2"));
            }
            let body = b.get(34..34 + ENTRY_LEN * k).ok_or_else(short)?;
            let entries = body.as_chunks::<ENTRY_LEN>().0.iter().map(|c| {
                let (claim, w) = c.split_at(32);
                Entry { claim: claim.try_into().unwrap_or([0; 32]), w: w.to_vec() }
            });
            (Body::Entries(entries.collect()), 34 + ENTRY_LEN * k)
        };
        let sig: [u8; 64] = b.get(at..at + 64).and_then(|x| x.try_into().ok()).ok_or_else(short)?;
        Ok((EntryBlock { sync_pk, body, sig }, at + 64))
    }
}

/// `entries` padded with dummies to `padded_count`, in random order.
fn padded(mut entries: Vec<Entry>, rng: &mut dyn CryptoRngCore) -> Vec<Entry> {
    let k = padded_count(entries.len());
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
    entries
}

/// An entry page (spec/wire.md §5 Entry pages): `prefix` (its commit blob's, under the page's own
/// salt, no blocks) carrying `block`, its ciphertext the empty plaintext under
/// `kdf("entry page", blob key, salt)`. Returns the page's bytes.
pub fn frame_page(prefix: Prefix, block: &EntryBlock, blob_key: &osis_crypto::Secret32) -> Result<Vec<u8>, Error> {
    let salt = *prefix.salt();
    let prefix = prefix.with_blocks(vec![block.clone()])?;
    Ok(crate::frame_under(osis_crypto::BlobKey::entry_page(blob_key, &salt), &prefix, &[])?.1)
}

/// Whether `bytes` are shaped as an entry page: one block of entries in the prefix and the
/// ciphertext of an empty plaintext (17 bytes), which no commit blob has. A page counts only as
/// one its blob names; this keeps a page from being taken as a blob of its own.
pub fn is_entry_page(bytes: &[u8]) -> bool {
    crate::clear_prefix(bytes).ok().flatten().is_some_and(|p| bytes.len() == p.len() + 17 && matches!(p.blocks(), [b] if b.pages().is_empty()))
}

/// The entry page `bytes` as a holder reads it (spec/wire.md §5 Entry pages): its blob ID,
/// its prefix's one block, and the salt that block is signed under; `None` for any other blob.
pub fn read_page(bytes: &[u8]) -> Option<(BlobId, EntryBlock, [u8; 16])> {
    if !is_entry_page(bytes) {
        return None;
    }
    let p = crate::clear_prefix(bytes).ok()??;
    match p.blocks() {
        [b] if b.pages().is_empty() => Some((crate::blob_id(bytes), b.clone(), *p.salt())),
        _ => None,
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

    // spec/wire.md §5 Entry pages: padded entries above a page go as pages of a page each, each
    // page a blob carrying one block under its own salt; the block names them in order
    #[test]
    fn entries_above_a_page_go_as_pages_spec_wire_5() {
        const { assert!(ENTRY_PAGE * ENTRY_LEN <= osis_base::format::PAGE_TARGET && 2 * ENTRY_PAGE * ENTRY_LEN > osis_base::format::PAGE_TARGET) };
        let mut rng = SeededRng::from_u64(0);
        let k = SigningSecret::from_seed(&Secret32::from_bytes([1; 32]));
        let (s, salt, key) = (SyncId([7; 16]), [2; 16], Secret32::from_bytes([9; 32]));
        let real: Vec<Entry> = (0..5u8).map(|i| Entry { claim: [i; 32], w: vec![i; W_LEN] }).collect();
        let mut blobs = Vec::new();
        let mut frame = |ps: &[u8; 16], b: &EntryBlock| {
            let page = frame_page(Prefix::new(*ps, None, Vec::new())?, b, &key)?;
            let id = crate::blob_id(&page);
            blobs.push(page);
            Ok(id)
        };
        let p = EntryBlock::sign_paged(&k, &s, &salt, real.clone(), 2, &mut frame, &mut rng).unwrap();
        assert!(p.block.entries().is_empty());
        assert_eq!(p.block.pages().len(), 4, "8 padded entries, 2 a page");
        assert!(p.block.verifies(&s, &salt));
        let mut found = 0;
        for (page, id) in blobs.iter().zip(p.block.pages()) {
            let (pid, b, ps) = read_page(page).unwrap();
            assert_eq!(pid, *id);
            assert!(is_entry_page(page));
            assert_eq!(b.entries().len(), 2);
            assert!(b.verifies(&s, &ps) && b.sync_pk() == p.block.sync_pk());
            found += real.iter().filter(|e| b.find(&e.claim) == Some(e)).count();
        }
        assert_eq!(found, real.len());
        let mut out = Vec::new();
        p.block.write(&mut out);
        assert_eq!(out.len(), p.block.len());
        assert_eq!(EntryBlock::parse(&out).unwrap(), (p.block.clone(), out.len()));
        // a page count of 1 or 3 is bad input
        for m in [1u32, 3] {
            let mut bad = out.clone();
            bad[34..38].copy_from_slice(&m.to_le_bytes());
            assert!(EntryBlock::parse(&bad).is_err());
        }
        // at or below a page, inline
        let p = EntryBlock::sign_paged(&k, &s, &salt, real, 8, &mut |_, _| unreachable!(), &mut rng).unwrap();
        assert!(p.pages.is_empty() && p.block.entries().len() == 8);
    }

}
