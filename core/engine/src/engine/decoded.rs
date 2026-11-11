//! Stored commit records (their blobs, spec/wire.md §4) decoded once per write of the record (`Core::decoded`).
//!
//! A record's blob and each of its decoded parts are functions of the record's bytes alone (a
//! part also of its header and its thing's dedup secret, both fixed by the commit's ID, and of
//! the pages its links name, fixed by each link's blob ID and hash), so they are kept from the
//! first read until the record is written again or removed (`Tx::put_commit`,
//! `Tx::remove_commit`: the only writers) or a changing transaction rolls back.
//!
//! Debug builds keep with each entry the bytes it was decoded from and compare them at every hit
//! with the bytes read now: the record's stored bytes, the part in the record read. A stale or
//! misfiled entry differs; decoding the same bytes again would only repeat a pure function, and
//! an entry is never changed in place (`Arc`). Whether a part's pages are still held is not this
//! cache's to check: `apply::check_rebuilt` reads held bodies with their pages past it.

use osis_base::CommitId;
use osis_commit::{CommitBlob, Decoded, Part};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Bytes `DecodedCommits` may hold: records by their stored bytes, decoded parts by
/// `Fragment::approx_bytes`, each with the bytes debug builds keep beside it. Performance switch: past it everything kept is forgotten. 0: every
/// read decodes its record and parts from the store; infinity: every commit read since the
/// open stays decoded in memory.
const DECODED_MAX: usize = 16 << 20;

#[derive(Clone)]
struct KeptRecord {
    blob: Arc<CommitBlob>,
    /// Debug builds: the stored bytes it was decoded from.
    #[cfg(debug_assertions)]
    stored: Vec<u8>,
}

#[derive(Clone)]
struct KeptPart {
    decoded: Arc<Decoded>,
    /// Debug builds: the part it was decoded from.
    #[cfg(debug_assertions)]
    from: Part,
}

#[derive(Clone, Default)]
pub(crate) struct DecodedCommits {
    records: HashMap<CommitId, KeptRecord>,
    parts: HashMap<CommitId, BTreeMap<usize, KeptPart>>,
    bytes: usize,
}

impl DecodedCommits {
    /// The kept blob of `id`. Debug builds: `_stored` reads the record's stored bytes now, which
    /// must be those it was decoded from.
    pub(crate) fn record<E>(&self, id: &CommitId, _stored: impl FnOnce() -> Result<Option<Vec<u8>>, E>) -> Result<Option<Arc<CommitBlob>>, E> {
        let Some(k) = self.records.get(id) else { return Ok(None) };
        #[cfg(debug_assertions)]
        assert!(_stored()?.as_ref() == Some(&k.stored), "decoded record of {id:?} went stale");
        Ok(Some(k.blob.clone()))
    }

    /// The kept decode of `p`, a part of the record of `id` as read now. Debug builds: it must
    /// have been decoded from `p`.
    pub(crate) fn part(&self, id: &CommitId, p: &Part) -> Option<Arc<Decoded>> {
        let k = self.parts.get(id)?.get(&p.ai)?;
        #[cfg(debug_assertions)]
        assert!(k.from == *p, "decoded part {} of {id:?} went stale", p.ai);
        Some(k.decoded.clone())
    }

    /// Keeps `blob`, decoded from the record's stored bytes `stored`.
    pub(crate) fn keep_record(&mut self, id: CommitId, blob: Arc<CommitBlob>, stored: &[u8]) {
        if self.room(stored.len().saturating_add(Self::debug_copy(stored.len()))) {
            self.records.insert(id, KeptRecord { blob, #[cfg(debug_assertions)] stored: stored.to_vec() });
        }
    }

    /// Keeps `decoded`, decoded from `p`.
    pub(crate) fn keep_part(&mut self, id: CommitId, p: &Part, decoded: Arc<Decoded>) {
        if self.room(decoded.fragment().approx_bytes().saturating_add(Self::debug_copy(p.delta.len()))) {
            self.parts.entry(id).or_default().insert(p.ai, KeptPart { decoded, #[cfg(debug_assertions)] from: p.clone() });
        }
    }

    /// The bytes debug builds keep beside an entry decoded from `n` bytes (none in release).
    fn debug_copy(n: usize) -> usize {
        if cfg!(debug_assertions) { n } else { 0 }
    }

    /// Whether `n` more bytes are kept, forgetting everything first when they do not fit beside
    /// what is.
    fn room(&mut self, n: usize) -> bool {
        if n > DECODED_MAX {
            return false;
        }
        if self.bytes.saturating_add(n) > DECODED_MAX {
            self.clear();
        }
        self.bytes = self.bytes.saturating_add(n);
        true
    }

    /// The record of `id` is written or removed. The bytes it held stay counted until the next
    /// `clear`: the count only decides when to forget, so it may run ahead.
    pub(crate) fn forget(&mut self, id: &CommitId) {
        self.records.remove(id);
        self.parts.remove(id);
    }

    pub(crate) fn clear(&mut self) {
        *self = DecodedCommits::default();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use osis_base::{Ak, Value, WallMs};

    // A stored commit's record and parts are decoded once per write of the record: reading it
    // again, and other commits arriving, decode nothing of it; a write of its record does, and a
    // removal leaves nothing to read.
    #[test]
    fn a_stored_commit_is_decoded_once_per_record_write() {
        let mut lp = crate::local_peer::LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        let write = |e: &mut crate::Engine, n: i64| {
            let mut m = Mutation::new();
            m.set(t, &ak, &Value::Int(n)).unwrap();
            e.commit(m).unwrap().unwrap()
        };
        let c = write(e, 1);
        let decodes = |e: &mut crate::Engine| {
            crate::costs::take();
            let part = e.run(|tx| crate::apply::held_part(tx, &c, 0)).unwrap();
            assert!(part.is_some());
            let costs = crate::costs::take();
            let n = |name: &str| costs.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
            (n("commit read"), n("part decode"))
        };
        e.core.decoded.clear();
        assert_eq!(decodes(e), (1, 1), "the first read decodes");
        assert_eq!(decodes(e), (0, 0), "a second read decodes nothing");
        write(e, 2);
        assert_eq!(decodes(e), (0, 0), "another commit leaves it decoded");
        let (blob, meta) = (e.run(|tx| tx.get_commit(&c)).unwrap().unwrap(), e.core.ix.commits.get(&c).cloned().unwrap());
        e.run(|tx| tx.put_commit(&c, &blob, &meta, osis_store::Shred::No, None)).unwrap();
        assert_eq!(decodes(e), (1, 1), "a write of its record decodes again");
        let gone = e.probe(|tx| {
            tx.remove_commit(&c)?;
            crate::apply::held_part(tx, &c, 0)
        });
        assert!(gone.unwrap().is_none(), "a removed record reads as gone");
        assert_eq!(decodes(e), (1, 1), "a removal rolled back decodes again");
    }
}
