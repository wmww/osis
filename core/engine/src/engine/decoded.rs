//! Stored commit records (their blobs, spec/wire.md §4) decoded once per write of the record (`Core::decoded`).
//!
//! A record's blob and each of its decoded parts are functions of the record's bytes alone (a
//! part also of its header, its thing's dedup secret and the blobs its pages name, all fixed by
//! the commit's ID), so they are kept from the first read until the record is written again or
//! removed (`Tx::put_commit`, `Tx::remove_commit`: the only writers) or a changing transaction
//! rolls back.

use osis_base::CommitId;
use osis_commit::{CommitBlob, Decoded};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Bytes `DecodedCommits` may hold: records by their blob's encoded parts, decoded parts by
/// `Fragment::approx_bytes`. Performance switch: past it everything kept is forgotten. 0: every
/// read decodes its record and parts from the store; infinity: every commit read since the
/// open stays decoded in memory.
const DECODED_MAX: usize = 16 << 20;

#[derive(Default)]
pub(crate) struct DecodedCommits {
    records: HashMap<CommitId, Arc<CommitBlob>>,
    parts: HashMap<CommitId, BTreeMap<usize, Arc<Decoded>>>,
    bytes: usize,
}

impl DecodedCommits {
    pub(crate) fn record(&self, id: &CommitId) -> Option<Arc<CommitBlob>> {
        self.records.get(id).cloned()
    }

    pub(crate) fn part(&self, id: &CommitId, ai: usize) -> Option<Arc<Decoded>> {
        self.parts.get(id)?.get(&ai).cloned()
    }

    pub(crate) fn keep_record(&mut self, id: CommitId, blob: Arc<CommitBlob>) {
        let n = blob.parts.iter().fold(0usize, |n, p| n.saturating_add(p.delta.len()));
        if self.room(n) {
            self.records.insert(id, blob);
        }
    }

    pub(crate) fn keep_part(&mut self, id: CommitId, ai: usize, part: Arc<Decoded>) {
        if self.room(part.fragment().approx_bytes()) {
            self.parts.entry(id).or_default().insert(ai, part);
        }
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
    // again, and other commits arriving, decode nothing of it; a write of its record does.
    #[test]
    fn a_stored_commit_is_decoded_once_per_record_write() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 977, WallMs(1_700_000_000_000)).unwrap();
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
    }
}
