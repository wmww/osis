//! The claim keys of the claim blocks of S's entries, by the sync key each block is bound to
//! (spec/sync-ids.md §3 Bound, §5 Entries): derived from an entry's blob when its bytes are
//! here, each block verified once, kept and dropped with the entry.
//!
//! - `Q/ s pk b` the claim keys (32 bytes each) of entry `b`'s blocks bound to sync key `pk` under S,
//!   those of its claim pages included (spec/wire.md §5 Claim pages).
//! - `q/ s b` the sync keys entry `b` has rows of under S (what its removal drops).
//! - `J/ s b` the claim pages entry `b`'s blocks verifying under S name (32 bytes each): what goes
//!   with it (`pages_of`).
//! - `j/ p s b` page `p` of entry `b` under S whose bytes were not here when `b` was indexed,
//!   its claim keys taken into `b`'s as they arrive, under the sync key `b`'s block names (the value).
//!
//! - `i/ s p` the entry of S whose blocks name page `p` (its blob ID): what a page arriving late
//!   wakes (`page_owner`).
//!
//! A page is no entry of its own here: its claim keys count only as its blob's.

use crate::types::Result;
use osis_base::{BlobId, SyncId};
use osis_store::{Shred, Transaction};
use std::collections::BTreeMap;

const CLAIMS: &[u8] = b"Q/";
const KEYS: &[u8] = b"q/";
const PAGES: &[u8] = b"J/";
const AWAITED: &[u8] = b"j/";
const OWNER: &[u8] = b"i/";

fn claims_key(s: &SyncId, pk: &[u8; 32], b: &BlobId) -> Vec<u8> {
    [CLAIMS, &s.0, pk, &b.0].concat()
}

fn keys_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [KEYS, &s.0, &b.0].concat()
}

fn pages_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [PAGES, &s.0, &b.0].concat()
}

fn owner_key(s: &SyncId, p: &BlobId) -> Vec<u8> {
    [OWNER, &s.0, &p.0].concat()
}

fn awaited_key(p: &BlobId, s: &SyncId, b: &BlobId) -> Vec<u8> {
    [AWAITED, &p.0, &s.0, &b.0].concat()
}

/// Indexes entry `b` of S from its bytes `blob`: per block verifying under S, its claim keys under its
/// sync key, a paged block's from each of its pages held here (one not here noted as awaited).
/// Once per entry: an entry indexed already is left as it is. A claim page's bytes index none of
/// its own: they fill the claim keys of each entry awaiting them.
pub(crate) fn index(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId, blob: &[u8]) -> Result<()> {
    if t.is_memory() {
        return Ok(());
    }
    if osis_blob::is_claim_page(blob) {
        return page_arrived(t, s, b, blob);
    }
    if t.get_local(&keys_key(s, b))?.is_some() {
        return Ok(());
    }
    let Ok(Some(prefix)) = osis_blob::clear_prefix(blob) else { return Ok(()) };
    let mut by: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    let mut pages = Vec::new();
    for block in prefix.blocks().iter().filter(|x| x.verifies(s, prefix.salt())) {
        osis_base::costs::count("store: claim blocks verified", 1);
        let v = by.entry(*block.sync_pk()).or_default();
        for c in block.claims() {
            v.extend_from_slice(&c.key);
        }
        for p in block.pages() {
            pages.extend_from_slice(&p.0);
            t.put_local(&owner_key(s, p), &b.0, Shred::No)?;
            match t.get_blob(p)?.and_then(|bytes| page_claims(s, block.sync_pk(), &bytes)) {
                Some(claims) => v.extend_from_slice(&claims),
                None => t.put_local(&awaited_key(p, s, b), block.sync_pk(), Shred::No)?,
            }
        }
    }
    let mut keys = Vec::with_capacity(by.len() * 32);
    for (pk, claims) in by {
        t.put_local(&claims_key(s, &pk, b), &claims, Shred::No)?;
        keys.extend_from_slice(&pk);
    }
    t.put_local(&keys_key(s, b), &keys, Shred::No)?;
    if !pages.is_empty() {
        t.put_local(&pages_key(s, b), &pages, Shred::No)?;
    }
    Ok(())
}

/// The claim keys of claim page `bytes` where its one block is bound to `pk` and verifies under S.
fn page_claims(s: &SyncId, pk: &[u8; 32], bytes: &[u8]) -> Option<Vec<u8>> {
    let (_, block, salt) = osis_blob::read_page(bytes)?;
    if block.sync_pk() != pk || !block.verifies(s, &salt) {
        return None;
    }
    osis_base::costs::count("store: claim blocks verified", 1);
    Some(block.claims().iter().flat_map(|c| c.key).collect())
}

/// Page `p` of S arrived (`bytes`): its claim keys join those of each entry awaiting it.
fn page_arrived(t: &mut Transaction<'_>, s: &SyncId, p: &BlobId, bytes: &[u8]) -> Result<()> {
    let prefix = [AWAITED, &p.0, &s.0].concat();
    for (k, pk) in t.scan_local(&prefix, b"", usize::MAX)? {
        t.remove_local(&k, Shred::No)?;
        let (Some(b), Ok(pk)) = (k.get(prefix.len()..).and_then(|x| x.try_into().ok()).map(BlobId), <[u8; 32]>::try_from(pk.as_slice())) else { continue };
        let Some(claims) = page_claims(s, &pk, bytes) else { continue };
        let mut v = t.get_local(&claims_key(s, &pk, &b))?.unwrap_or_default();
        v.extend_from_slice(&claims);
        t.put_local(&claims_key(s, &pk, &b), &v, Shred::No)?;
        let mut keys = t.get_local(&keys_key(s, &b))?.unwrap_or_default();
        if !keys.as_chunks::<32>().0.contains(&pk) {
            keys.extend_from_slice(&pk);
            t.put_local(&keys_key(s, &b), &keys, Shred::No)?;
        }
    }
    Ok(())
}

/// The entry of S whose blocks name claim page `p`, if one is indexed here.
pub(crate) fn page_owner(t: &mut Transaction<'_>, s: &SyncId, p: &BlobId) -> Result<Option<BlobId>> {
    Ok(t.get_local(&owner_key(s, p))?.and_then(|v| Some(BlobId(v.as_slice().try_into().ok()?))))
}

/// The claim pages entry `b` of S names (spec/wire.md §5 Claim pages): they go with it.
pub(crate) fn pages_of(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId) -> Result<Vec<BlobId>> {
    Ok(t.get_local(&pages_key(s, b))?.map(|v| v.as_chunks::<32>().0.iter().map(|x| BlobId(*x)).collect()).unwrap_or_default())
}

/// Entry `b` of S left: its rows go.
pub(crate) fn drop_entry(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId) -> Result<()> {
    for p in pages_of(t, s, b)? {
        t.remove_local(&awaited_key(&p, s, b), Shred::No)?;
        t.remove_local(&owner_key(s, &p), Shred::No)?;
    }
    t.remove_local(&pages_key(s, b), Shred::No)?;
    let Some(keys) = t.get_local(&keys_key(s, b))? else { return Ok(()) };
    t.remove_local(&keys_key(s, b), Shred::No)?;
    for pk in keys.as_chunks::<32>().0 {
        t.remove_local(&claims_key(s, pk, b), Shred::No)?;
    }
    Ok(())
}

/// S's entries with a block bound to sync key `pk` (a head move to `pk` looks for its entries there).
pub(crate) fn entries_bound_to(t: &mut Transaction<'_>, s: &SyncId, pk: &[u8; 32]) -> Result<Vec<BlobId>> {
    let prefix = [CLAIMS, &s.0, pk].concat();
    Ok(t.scan_local(&prefix, b"", usize::MAX)?.into_iter().filter_map(|(k, _)| Some(BlobId(k.get(prefix.len()..)?.try_into().ok()?))).collect())
}

/// The claim keys of S's entries' blocks bound to sync key `pk` (spec/sync-ids.md §3: at the
/// head's, its head claim keys), in blob order.
pub(crate) fn bound_to(t: &mut Transaction<'_>, s: &SyncId, pk: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    for (_, v) in t.scan_local(&[CLAIMS, &s.0, pk].concat(), b"", usize::MAX)? {
        out.extend(v.as_chunks::<32>().0.iter().copied());
    }
    Ok(out)
}
