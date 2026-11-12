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
/// live states or held bodies (a tree not all held may link it: kept). `trees`: whether trees may
/// link what no held commit lists (false for memory data: a memory commit lists every blob of its
/// class it links, spec/wire.md §4). A thing erased for lost access keeps the states of its
/// role-class aspects, which may link pages: its trees are walked too.
pub(crate) fn released(tx: &mut Tx<'_>, going: &[(CommitId, &Header)], trees: bool) -> Result<BTreeSet<BlobId>> {
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
        if !trees {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::flows::Demotion;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value};
    use osis_schema::core_types::Edge;

    // spec/sync.md §7 (a chunk goes only through an entry its prefix bears), spec/permissions.md
    // §3 (a node drops what it lost read access to, nothing it still reads), with no node-sync: an
    // admin of t1 and t2 lists t2's chunks in a t1 commit. A reader of both whose own listing of
    // most of them went under t2's own replaces, removed from t1, keeps them and reads t2.
    #[test]
    fn losing_a_thing_keeps_chunks_a_forged_listing_named_spec_sync_7() {
        let mut lp = LocalPeer::fresh(2, osis_base::WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (me, v) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let mut m = Mutation::new();
        let t1 = lp.peers[0].engine.new_thing(&mut m, me);
        let t2 = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let read = Edge { role: Role::Read, until: None, invite: None, tied: None };
        for t in [t1, t2] {
            lp.peers[0].engine.grant(&t, &v, &read).unwrap();
        }
        lp.sync_all().unwrap();
        // t2's value by own replaces reusing the first one's chunks
        let a = Ak::new("x:b.0").unwrap();
        let mut x = vec![0u8; 1 << 20];
        osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(1), &mut x);
        let mut cs = Vec::new();
        for i in 0..3 {
            lp.advance(1000);
            x.splice(1000 * (i + 1)..1000 * (i + 1), [i as u8; 50]);
            let mut m = Mutation::new();
            m.set(t2, &a, &Value::Bytes(x.clone())).unwrap();
            cs.push(lp.peers[0].commit(m).unwrap().unwrap());
        }
        lp.sync_all().unwrap();
        let tree = lp.peers[0].engine.live_trees(&t2).unwrap().blobs;
        assert!(tree.iter().all(|b| lp.peers[1].engine.has_blob(b)), "v holds t2's tree");
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t1, &a, &Value::Int(1)).unwrap();
        let forged = lp.peers[0].engine.commit_listing(m, &t2).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&forged).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
        // v forgets the first replace under the two after it: the forged commit alone lists most
        let e = &mut lp.peers[1].engine;
        e.drop_body(&cs[0], &t2, &a).unwrap();
        assert!(e.forgettable(&cs[0]));
        e.forget_commits(&[cs[0]]).unwrap();
        let alone = tree.iter().filter(|b| e.core.ix.by_chunk.get(b).is_some_and(|l| l.iter().all(|c| *c == forged))).count();
        assert!(alone > 0, "the forged commit alone lists some of t2's chunks");
        lp.advance(1000);
        let removal = lp.peers[0].engine.demote(&t1, &Demotion { holder: v, new: None, retain: None }).unwrap().commits;
        for c in removal {
            let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        e.drop_lost_due().unwrap();
        assert_eq!(e.get(&t1, &a).unwrap(), None, "v forgot t1");
        assert!(e.header(&forged).is_none(), "the forged commit went");
        let held = tree.iter().filter(|b| e.has_blob(b)).count();
        assert_eq!(held, tree.len(), "v keeps t2's chunks");
        assert_eq!(e.get_full(&t2, &a).unwrap(), Some(Value::Bytes(x)), "v reads t2");
    }
}
