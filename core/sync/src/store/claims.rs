//! The claims of the entry blocks of S's entries, by the sync key each block is bound to
//! (spec/sync-ids.md §3 Bound, §5 Entries): derived from an entry's blob when its bytes are
//! here, each block verified once, kept and dropped with the entry.
//!
//! - `Q/ s pk b` the claims (32 bytes each) of entry `b`'s blocks bound to sync key `pk` under S.
//! - `q/ s b` the sync keys entry `b` has rows of under S (what its removal drops).

use crate::types::Result;
use osis_base::{BlobId, SyncId};
use osis_store::{Shred, Transaction};
use std::collections::BTreeMap;

const CLAIMS: &[u8] = b"Q/";
const KEYS: &[u8] = b"q/";

fn claims_key(s: &SyncId, pk: &[u8; 32], b: &BlobId) -> Vec<u8> {
    [CLAIMS, &s.0, pk, &b.0].concat()
}

fn keys_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [KEYS, &s.0, &b.0].concat()
}

/// Indexes entry `b` of S from its bytes `blob`: per block verifying under S, its claims under its
/// sync key. Once per entry: an entry indexed already is left as it is.
pub(crate) fn index(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId, blob: &[u8]) -> Result<()> {
    if t.is_memory() || t.get_local(&keys_key(s, b))?.is_some() {
        return Ok(());
    }
    let Ok(Some(prefix)) = osis_blob::clear_prefix(blob) else { return Ok(()) };
    let mut by: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for block in prefix.blocks().iter().filter(|x| x.verifies(s, prefix.salt())) {
        osis_base::costs::count("store: entry blocks verified", 1);
        let v = by.entry(*block.sync_pk()).or_default();
        for e in block.entries() {
            v.extend_from_slice(&e.claim);
        }
    }
    let mut keys = Vec::with_capacity(by.len() * 32);
    for (pk, claims) in by {
        t.put_local(&claims_key(s, &pk, b), &claims, Shred::No)?;
        keys.extend_from_slice(&pk);
    }
    t.put_local(&keys_key(s, b), &keys, Shred::No)?;
    Ok(())
}

/// Entry `b` of S left: its rows go.
pub(crate) fn drop_entry(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId) -> Result<()> {
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

/// The claims of S's entries' blocks bound to sync key `pk` (spec/sync-ids.md §3: at the head's,
/// its head claims), in blob order.
pub(crate) fn bound_to(t: &mut Transaction<'_>, s: &SyncId, pk: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    let mut out = Vec::new();
    for (_, v) in t.scan_local(&[CLAIMS, &s.0, pk].concat(), b"", usize::MAX)? {
        out.extend(v.as_chunks::<32>().0.iter().copied());
    }
    Ok(out)
}
