//! Claim blocks in a blob's clear prefix (spec/sync-ids.md §3, spec/wire.md §5 Claim blocks).

use crate::{Error, Prefix};
use osis_base::{BlobId, SyncId};
use osis_crypto::{CryptoRngCore, Signature, SigningSecret, VerifyingKey, W_LEN, sign_claim_block, verify_claim_block};

/// Bytes of one claim: `claim_key (32) || W (1201)`.
pub const CLAIM_LEN: usize = 32 + W_LEN;
/// The most claims one block's le16 count names that is a power of two.
const MAX_CLAIMS: usize = 1 << 15;
/// The most pages one block's le32 count names that is a power of two (a commit's header bounds
/// its holders far below it, spec/wire.md §2 `MAX_LIST_BYTES`).
const MAX_PAGES: usize = 1 << 31;
/// Claims per claim page (spec/wire.md §5 Claim pages): the most, a power of two, whose bytes
/// stay within `PAGE_TARGET`, as a delta's pages do.
pub const CLAIM_PAGE: usize = {
    let n = osis_base::format::PAGE_TARGET / CLAIM_LEN;
    1 << (usize::BITS - 1 - n.leading_zeros())
};

/// One claim: its claim key's raw public key and its W (a dummy's: random bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Claim {
    pub key: [u8; 32],
    pub w: Vec<u8>,
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Claim({:02x?})", self.key.get(..4).unwrap_or_default())
    }
}

/// A claim block: claims bound to the sync epoch of `sync_pk`, inline or in claim pages
/// (spec/wire.md §5 Claim pages), signed by it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimBlock {
    sync_pk: [u8; 32],
    body: Body,
    sig: [u8; 64],
}

/// What a block holds: its claims, or the blob IDs of the claim pages holding them.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Body {
    Claims(Vec<Claim>),
    Pages(Vec<BlobId>),
}

/// Frames one claim page (its salt, its block) and gives its blob ID (`frame_page`).
pub type PageFrame<'a> = dyn FnMut(&[u8; 16], &ClaimBlock) -> Result<BlobId, Error> + 'a;

/// The claims of one encryption bound to one sync epoch: the block its prefix carries and,
/// where they page, each page's salt and block (`ClaimBlock::sign_paged`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paged {
    pub block: ClaimBlock,
    pub pages: Vec<([u8; 16], ClaimBlock)>,
}

/// The claim count a block of `real` claims pads to: the least power of two above `real`, at
/// least 2 (so at least one dummy).
pub fn padded_count(real: usize) -> usize {
    (real + 1).next_power_of_two().max(2)
}

impl ClaimBlock {
    /// A block of `claims` under the sync key `sync_key` for a blob of salt `salt` of sync ID
    /// `sync_id`: padded with dummies to `padded_count`, in random order, signed.
    pub fn sign(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], claims: Vec<Claim>, rng: &mut dyn CryptoRngCore) -> Result<ClaimBlock, Error> {
        let claims = padded(claims, rng);
        if claims.len() > MAX_CLAIMS {
            return Err(Error::TooLarge("claims in one claim block"));
        }
        Ok(ClaimBlock::signed(sync_key, sync_id, salt, Body::Claims(claims)))
    }

    /// `sign`, paged where the padded claims are more than `per_page` (a power of two at least
    /// 2; `CLAIM_PAGE` but in tests): the claims, in random order, split into pages of
    /// `per_page`, each a block under its own random salt, and the block for the blob of salt
    /// `salt` naming the pages framed by `frame` (`frame_page`) in order (spec/wire.md §5 Claim
    /// pages).
    pub fn sign_paged(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], claims: Vec<Claim>, per_page: usize, frame: &mut PageFrame<'_>, rng: &mut dyn CryptoRngCore) -> Result<Paged, Error> {
        let per_page = per_page.clamp(2, MAX_CLAIMS).next_power_of_two();
        let mut claims = padded(claims, rng);
        if claims.len() <= per_page {
            return Ok(Paged { block: ClaimBlock::signed(sync_key, sync_id, salt, Body::Claims(claims)), pages: Vec::new() });
        }
        let (mut pages, mut ids) = (Vec::new(), Vec::new());
        while !claims.is_empty() {
            let rest = claims.split_off(per_page.min(claims.len()));
            let page_salt = Prefix::random_salt(rng);
            let block = ClaimBlock::signed(sync_key, sync_id, &page_salt, Body::Claims(std::mem::replace(&mut claims, rest)));
            ids.push(frame(&page_salt, &block)?);
            pages.push((page_salt, block));
        }
        if ids.len() > MAX_PAGES {
            return Err(Error::TooLarge("claim pages in one claim block"));
        }
        Ok(Paged { block: ClaimBlock::signed(sync_key, sync_id, salt, Body::Pages(ids)), pages })
    }

    fn signed(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], body: Body) -> ClaimBlock {
        let mut b = ClaimBlock { sync_pk: sync_key.verifying_key().to_bytes(), body, sig: [0; 64] };
        b.sig = sign_claim_block(sync_key, sync_id, salt, &b.unsigned()).0;
        b
    }

    /// The raw sync key whose epoch it is bound to, where its signature verifies.
    pub fn sync_pk(&self) -> &[u8; 32] {
        &self.sync_pk
    }

    /// Its claims: none where they are in pages.
    pub fn claims(&self) -> &[Claim] {
        match &self.body {
            Body::Claims(e) => e,
            Body::Pages(_) => &[],
        }
    }

    /// The blob IDs of the claim pages holding its claims: none where they are inline.
    pub fn pages(&self) -> &[BlobId] {
        match &self.body {
            Body::Claims(_) => &[],
            Body::Pages(p) => p,
        }
    }

    /// The claim of claim key `key` among its inline claims, if any.
    pub fn find(&self, key: &[u8; 32]) -> Option<&Claim> {
        self.claims().iter().find(|e| e.key == *key)
    }

    /// Its signature verifies under `sync_pk` for `sync_id` and the blob's salt: else it counts
    /// for nothing under that sync ID.
    pub fn verifies(&self, sync_id: &SyncId, salt: &[u8; 16]) -> bool {
        VerifyingKey::from_bytes(&self.sync_pk).is_ok_and(|pk| verify_claim_block(&pk, sync_id, salt, &self.unsigned(), &Signature(self.sig)).is_ok())
    }

    /// Encoded length.
    pub fn len(&self) -> usize {
        32 + 2
            + match &self.body {
                Body::Claims(e) => CLAIM_LEN * e.len(),
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
            Body::Claims(claims) => {
                // at most MAX_CLAIMS by construction
                out.extend_from_slice(&u16::try_from(claims.len()).unwrap_or(u16::MAX).to_le_bytes());
                for e in claims {
                    out.extend_from_slice(&e.key);
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

    /// Parses a block at the start of `b`, returning it and its length; a claim count that is
    /// neither 0 (paged) nor a power of two at least 2, a page count that is not a power of two
    /// at least 2, or bytes short of it, is bad input.
    pub fn parse(b: &[u8]) -> Result<(ClaimBlock, usize), Error> {
        let short = || Error::Malformed("short claim block");
        let sync_pk: [u8; 32] = b.get(..32).and_then(|x| x.try_into().ok()).ok_or_else(short)?;
        let k = usize::from(u16::from_le_bytes(b.get(32..34).and_then(|x| x.try_into().ok()).ok_or_else(short)?));
        let (body, at) = if k == 0 {
            let m = u32::from_le_bytes(b.get(34..38).and_then(|x| x.try_into().ok()).ok_or_else(short)?);
            let m = usize::try_from(m).map_err(|_| short())?;
            if m < 2 || !m.is_power_of_two() || m > MAX_PAGES {
                return Err(Error::Malformed("claim page count not a power of two at least 2"));
            }
            let ids = b.get(38..38 + 32 * m).ok_or_else(short)?;
            (Body::Pages(ids.as_chunks::<32>().0.iter().map(|x| BlobId(*x)).collect()), 38 + 32 * m)
        } else {
            if k < 2 || !k.is_power_of_two() {
                return Err(Error::Malformed("claim count not a power of two at least 2"));
            }
            let body = b.get(34..34 + CLAIM_LEN * k).ok_or_else(short)?;
            let claims = body.as_chunks::<CLAIM_LEN>().0.iter().map(|c| {
                let (key, w) = c.split_at(32);
                Claim { key: key.try_into().unwrap_or([0; 32]), w: w.to_vec() }
            });
            (Body::Claims(claims.collect()), 34 + CLAIM_LEN * k)
        };
        let sig: [u8; 64] = b.get(at..at + 64).and_then(|x| x.try_into().ok()).ok_or_else(short)?;
        Ok((ClaimBlock { sync_pk, body, sig }, at + 64))
    }
}

/// `claims` padded with dummies to `padded_count`, in random order.
fn padded(mut claims: Vec<Claim>, rng: &mut dyn CryptoRngCore) -> Vec<Claim> {
    let k = padded_count(claims.len());
    while claims.len() < k {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mut w = vec![0u8; W_LEN];
        rng.fill_bytes(&mut w);
        claims.push(Claim { key, w });
    }
    // Fisher-Yates; the bias of `% (i + 1)` over a u64 is negligible
    for i in (1..claims.len()).rev() {
        let j = usize::try_from(rng.next_u64() % (i as u64 + 1)).unwrap_or(0);
        claims.swap(i, j);
    }
    claims
}

/// A claim page (spec/wire.md §5 Claim pages): `prefix` (its commit blob's, under the page's own
/// salt, no blocks) carrying `block`, its ciphertext the empty plaintext under
/// `kdf("claim page", blob key, salt)`. Returns the page's bytes.
pub fn frame_page(prefix: Prefix, block: &ClaimBlock, blob_key: &osis_crypto::Secret32) -> Result<Vec<u8>, Error> {
    let salt = *prefix.salt();
    let prefix = prefix.with_blocks(vec![block.clone()])?;
    Ok(crate::frame_under(osis_crypto::BlobKey::claim_page(blob_key, &salt), &prefix, &[])?.1)
}

/// Whether `bytes` are shaped as a claim page: one block of claims in the prefix and the
/// ciphertext of an empty plaintext (17 bytes), which no commit blob has. A page counts only as
/// one its blob names; this keeps a page from being taken as a blob of its own.
pub fn is_claim_page(bytes: &[u8]) -> bool {
    crate::clear_prefix(bytes).ok().flatten().is_some_and(|p| bytes.len() == p.len() + 17 && matches!(p.blocks(), [b] if b.pages().is_empty()))
}

/// The claim page `bytes` as a holder reads it (spec/wire.md §5 Claim pages): its blob ID,
/// its prefix's one block, and the salt that block is signed under; `None` for any other blob.
pub fn read_page(bytes: &[u8]) -> Option<(BlobId, ClaimBlock, [u8; 16])> {
    if !is_claim_page(bytes) {
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
        let real: Vec<Claim> = (0..3u8).map(|i| Claim { key: [i; 32], w: vec![i; W_LEN] }).collect();
        let b = ClaimBlock::sign(&k, &SyncId([7; 16]), &[2; 16], real.clone(), &mut rng).unwrap();
        assert_eq!(b.claims().len(), 4);
        for e in &real {
            assert_eq!(b.find(&e.key), Some(e));
        }
        assert!(b.verifies(&SyncId([7; 16]), &[2; 16]));
        assert!(!b.verifies(&SyncId([8; 16]), &[2; 16]));
        let mut out = Vec::new();
        b.write(&mut out);
        assert_eq!(out.len(), b.len());
        assert_eq!(ClaimBlock::parse(&out).unwrap(), (b.clone(), out.len()));
        // a count of 3, or one, is bad input
        for k in [1u16, 3] {
            let mut bad = out.clone();
            bad[32..34].copy_from_slice(&k.to_le_bytes());
            assert!(ClaimBlock::parse(&bad).is_err());
        }
        assert!(ClaimBlock::parse(&out[..out.len() - 1]).is_err());
    }

    // spec/wire.md §5 Claim pages: padded claims above a page go as pages of a page each, each
    // page a blob carrying one block under its own salt; the block names them in order
    #[test]
    fn claims_above_a_page_go_as_pages_spec_wire_5() {
        const { assert!(CLAIM_PAGE * CLAIM_LEN <= osis_base::format::PAGE_TARGET && 2 * CLAIM_PAGE * CLAIM_LEN > osis_base::format::PAGE_TARGET) };
        let mut rng = SeededRng::from_u64(0);
        let k = SigningSecret::from_seed(&Secret32::from_bytes([1; 32]));
        let (s, salt, key) = (SyncId([7; 16]), [2; 16], Secret32::from_bytes([9; 32]));
        let real: Vec<Claim> = (0..5u8).map(|i| Claim { key: [i; 32], w: vec![i; W_LEN] }).collect();
        let mut blobs = Vec::new();
        let mut frame = |ps: &[u8; 16], b: &ClaimBlock| {
            let page = frame_page(Prefix::new(*ps, None, Vec::new())?, b, &key)?;
            let id = crate::blob_id(&page);
            blobs.push(page);
            Ok(id)
        };
        let p = ClaimBlock::sign_paged(&k, &s, &salt, real.clone(), 2, &mut frame, &mut rng).unwrap();
        assert!(p.block.claims().is_empty());
        assert_eq!(p.block.pages().len(), 4, "8 padded claims, 2 a page");
        assert!(p.block.verifies(&s, &salt));
        let mut found = 0;
        for (page, id) in blobs.iter().zip(p.block.pages()) {
            let (pid, b, ps) = read_page(page).unwrap();
            assert_eq!(pid, *id);
            assert!(is_claim_page(page));
            assert_eq!(b.claims().len(), 2);
            assert!(b.verifies(&s, &ps) && b.sync_pk() == p.block.sync_pk());
            found += real.iter().filter(|e| b.find(&e.key) == Some(e)).count();
        }
        assert_eq!(found, real.len());
        let mut out = Vec::new();
        p.block.write(&mut out);
        assert_eq!(out.len(), p.block.len());
        assert_eq!(ClaimBlock::parse(&out).unwrap(), (p.block.clone(), out.len()));
        // a page count of 1 or 3 is bad input
        for m in [1u32, 3] {
            let mut bad = out.clone();
            bad[34..38].copy_from_slice(&m.to_le_bytes());
            assert!(ClaimBlock::parse(&bad).is_err());
        }
        // at or below a page, inline
        let p = ClaimBlock::sign_paged(&k, &s, &salt, real, 8, &mut |_, _| unreachable!(), &mut rng).unwrap();
        assert!(p.pages.is_empty() && p.block.claims().len() == 8);
    }

}
