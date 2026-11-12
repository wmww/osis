//! The one rule for releasing a chunk, tree-node or page blob because a commit listing it went
//! (spec/sync.md §7): lost access (`forget`), a memory commit gone (`apply::unindex_commit`). A
//! chunk list is its writer's word, so an entry may name a blob of another thing; only an entry
//! the blob's prefix bears says whose it is (spec/crypto.md §7).

use crate::engine::Tx;
use crate::error::Result;
use osis_base::{BlobId, CommitId, Tid};
use osis_commit::{ChunkEntry, Header};
use std::collections::{BTreeMap, BTreeSet};

/// Whether blob `ch.blob`'s prefix bears a commitment chunk entry `ch` of header `h` names: one
/// of its keys blinded by the prefix salt and the entry's link blind bound to its aspect's thing
/// (spec/crypto.md §7); `None` when the blob is not held here. An entry naming a blob of another
/// thing names none (spec/sync.md §7).
pub(crate) fn entry_borne(tx: &mut Tx<'_>, h: &Header, ch: &ChunkEntry) -> Result<Option<bool>> {
    let Some(head) = tx.blobs.read(&ch.blob, 0, osis_label::LINKED_PREFIX_MAX)? else { return Ok(None) };
    let Ok(prefix) = osis_label::Prefix::parse(&head) else { return Ok(Some(false)) };
    let Some(a) = h.aspects.get(ch.ai) else { return Ok(Some(false)) };
    let blind = osis_crypto::thing_blind(&ch.blind, a.tid.as_bytes());
    let theirs: BTreeSet<&[u8; 33]> = prefix.commitments().collect();
    Ok(Some(ch.keys.iter().filter_map(|i| h.keys.get(*i)).any(|k| k.verifying_key().ok().and_then(|vk| osis_crypto::commitment(k.level, &vk, prefix.salt(), &blind).ok()).is_some_and(|c| theirs.contains(&c)))))
}

/// Of the blobs held here that the chunk lists of `going` (commits leaving this node, out of
/// `ix.by_chunk` or not) name, those this node releases: listed by no other held commit, through
/// an entry of `going` the blob's prefix bears, and linked by no tree of that entry's thing's
/// live states or held bodies (a tree not all held may link it: kept). `trees`: whether a thing's
/// trees may link what no held commit lists (false for a thing erased here, which holds no state
/// or body, and for memory data: a memory commit lists every blob it links, spec/wire.md §4).
pub(crate) fn released(tx: &mut Tx<'_>, going: &[(CommitId, &Header)], trees: &dyn Fn(&Tid) -> bool) -> Result<BTreeSet<BlobId>> {
    let ids: BTreeSet<CommitId> = going.iter().map(|(c, _)| *c).collect();
    let mut judged: BTreeSet<BlobId> = BTreeSet::new();
    let mut by_thing: BTreeMap<Tid, BTreeSet<BlobId>> = BTreeMap::new();
    for (_, h) in going {
        for ch in &h.chunks {
            if judged.contains(&ch.blob) {
                continue;
            }
            if tx.core.ix.by_chunk.get(&ch.blob).is_some_and(|cs| cs.iter().any(|c| !ids.contains(c))) {
                judged.insert(ch.blob);
                continue;
            }
            // an entry it does not bear names a blob of another thing: another entry may bear it
            if entry_borne(tx, h, ch)? == Some(true)
                && let Some(a) = h.aspects.get(ch.ai)
            {
                judged.insert(ch.blob);
                by_thing.entry(a.tid).or_default().insert(ch.blob);
            }
        }
    }
    let mut out = BTreeSet::new();
    for (t, bs) in by_thing {
        if !trees(&t) {
            out.extend(bs);
            continue;
        }
        let linked = crate::engine::tree_refs::tree_refs_in(tx, &t, &bs)?;
        if linked.missing.is_empty() {
            out.extend(bs.difference(&linked.blobs).copied());
        }
    }
    Ok(out)
}
