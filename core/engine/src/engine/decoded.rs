//! Stored commit records (their blobs, spec/wire.md §4) decoded once per write of the record (`Core::decoded`).
//!
//! A record's blob and each of its decoded parts are functions of the record's bytes alone (a
//! part also of its header and its thing's dedup secret, both fixed by the commit's ID, and of
//! the pages its links name, fixed by each link's blob ID and hash), so they are kept from the
//! first read until the record is written again or removed (`Tx::put_commit`,
//! `Tx::remove_commit`: the only writers) or a changing transaction rolls back.
//!
//! Debug builds keep with each entry the bytes it was decoded from and compare them with the
//! bytes read now: the part in the record read at every hit, the record's stored bytes at its
//! hits 1, 2, 4, 8 and so on (a read of the record costs its size, and a commit on n things reads
//! it once per part: n² at every hit). A stale or misfiled entry differs, and stays stale, so a
//! later sample still sees it; decoding the same bytes again would only repeat a pure function,
//! and an entry is never changed in place (`Arc`). Whether a part's pages are still held is not this
//! cache's to check: `apply::check_rebuilt` reads held bodies with their pages past it.
//!
//! Beside them, a paged part's page index (`osis_crdt::PageIndex`, one entry per leaf page),
//! found by its first read, so a read at some positions (`apply::held_part_at`) fetches only
//! the pages holding them.

use osis_base::CommitId;
use osis_commit::{CommitBlob, Decoded, Part};
use std::collections::{BTreeMap, HashMap};
use osis_crdt::PageIndex;
use std::sync::Arc;

/// Bytes `DecodedCommits` may hold: records by their stored bytes, decoded parts by
/// `Fragment::approx_bytes`, each with the bytes debug builds keep beside it. Performance switch: past it everything kept is forgotten. 0: every
/// read decodes its record and parts from the store; infinity: every commit read since the
/// open stays decoded in memory.
const DECODED_MAX: usize = 16 << 20;

struct KeptRecord {
    blob: Arc<CommitBlob>,
    /// Debug builds: the stored bytes it was decoded from, and its hits so far.
    #[cfg(debug_assertions)]
    stored: Vec<u8>,
    #[cfg(debug_assertions)]
    hits: std::sync::atomic::AtomicU64,
}

impl Clone for KeptRecord {
    fn clone(&self) -> KeptRecord {
        KeptRecord {
            blob: self.blob.clone(),
            #[cfg(debug_assertions)]
            stored: self.stored.clone(),
            #[cfg(debug_assertions)]
            hits: std::sync::atomic::AtomicU64::new(self.hits.load(std::sync::atomic::Ordering::Relaxed)),
        }
    }
}

#[derive(Clone)]
struct KeptPart {
    decoded: Arc<Decoded>,
    /// Debug builds: the part it was decoded from.
    #[cfg(debug_assertions)]
    from: Part,
}

#[derive(Clone)]
struct KeptIndex {
    index: Arc<PageIndex>,
    /// Debug builds: the part it was streamed from.
    #[cfg(debug_assertions)]
    from: Part,
}

#[derive(Clone, Default)]
pub(crate) struct DecodedCommits {
    records: HashMap<CommitId, KeptRecord>,
    parts: HashMap<CommitId, BTreeMap<usize, KeptPart>>,
    indexes: HashMap<CommitId, BTreeMap<usize, KeptIndex>>,
    bytes: usize,
}

impl DecodedCommits {
    /// The kept blob of `id`. Debug builds, sampled (the module doc): `_stored` reads the
    /// record's stored bytes now, which must be those it was decoded from.
    pub(crate) fn record<E>(&self, id: &CommitId, _stored: impl FnOnce() -> Result<Option<Vec<u8>>, E>) -> Result<Option<Arc<CommitBlob>>, E> {
        let Some(k) = self.records.get(id) else { return Ok(None) };
        #[cfg(debug_assertions)]
        if (k.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1).is_power_of_two() {
            assert!(_stored()?.as_ref() == Some(&k.stored), "decoded record of {id:?} went stale");
        }
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
            self.records.insert(id, KeptRecord { blob, #[cfg(debug_assertions)] stored: stored.to_vec(), #[cfg(debug_assertions)] hits: Default::default() });
        }
    }

    /// Keeps `decoded`, decoded from `p`.
    pub(crate) fn keep_part(&mut self, id: CommitId, p: &Part, decoded: Arc<Decoded>) {
        if self.room(decoded.fragment().approx_bytes().saturating_add(Self::debug_copy(p.delta.len()))) {
            self.parts.entry(id).or_default().insert(p.ai, KeptPart { decoded, #[cfg(debug_assertions)] from: p.clone() });
        }
    }

    /// The kept page index of `p`, a part of the record of `id` as read now.
    pub(crate) fn page_index(&self, id: &CommitId, p: &Part) -> Option<Arc<PageIndex>> {
        let k = self.indexes.get(id)?.get(&p.ai)?;
        #[cfg(debug_assertions)]
        assert!(k.from == *p, "page index of part {} of {id:?} went stale", p.ai);
        Some(k.index.clone())
    }

    /// Keeps `index`, streamed from `p`.
    pub(crate) fn keep_page_index(&mut self, id: CommitId, p: &Part, index: Arc<PageIndex>) {
        if self.room(index.approx_bytes().saturating_add(Self::debug_copy(p.delta.len()))) {
            self.indexes.entry(id).or_default().insert(p.ai, KeptIndex { index, #[cfg(debug_assertions)] from: p.clone() });
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
        self.indexes.remove(id);
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
            osis_base::costs::take();
            let part = e.run(|tx| crate::apply::held_part(tx, &c, 0)).unwrap();
            assert!(part.is_some());
            let costs = osis_base::costs::take();
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
        let failed = e.run(|tx| {
            tx.remove_commit(&c)?;
            assert!(crate::apply::held_part(tx, &c, 0)?.is_none(), "a removed record reads as gone");
            Err::<(), _>(crate::Error::Misuse("rolled back"))
        });
        assert!(failed.is_err());
        assert_eq!(decodes(e), (1, 1), "a removal rolled back decodes again");
    }

    // A cover judgment reads of a snapshot its root and the pages holding the body's positions
    // (spec/commits.md §5 Covered), found by the snapshot's page index, which its first read
    // builds and keeps per write of its record: past that read, a judgment's work is flat in the
    // snapshot's size and judging every body is O(snapshot + bodies). The index holds one entry
    // per page.
    #[test]
    fn cover_judgments_read_the_bodys_pages_spec_commits_5() {
        use osis_crdt::{Op, PathOp, PathSeg};
        const BODIES: i64 = 100;
        // per size: (bytes streamed by the first judgment, by the rest, pieces streamed by the
        // rest, the snapshot's part walked by the rest, the index kept)
        let judge = |n: i64| -> (u64, u64, u64, u64, usize) {
            let mut lp = crate::local_peer::LocalPeer::fresh(1, WallMs(1_700_000_000_000));
            let e = &mut lp.peers[0].engine;
            let me = e.me();
            let ak = Ak::new("x:m.0").unwrap();
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, me);
            m.set(t, &ak, &Value::Map((0..n).map(|i| (Value::Int(i), Value::Str(format!("value-{i:08}-{}", "x".repeat(200))))).collect())).unwrap();
            e.commit(m).unwrap();
            let bodies: Vec<_> = (0..BODIES)
                .map(|i| {
                    let mut m = Mutation::new();
                    m.op(t, &ak, PathOp { path: vec![PathSeg::Key(Value::Int(n + i))], op: Op::Set(Value::Str(format!("body-{i:08}"))) }).unwrap();
                    e.commit(m).unwrap().unwrap()
                })
                .collect();
            let s = e.snapshot(&t, &ak).unwrap().unwrap();
            e.core.decoded.clear();
            let mut judge = |c| assert_eq!(e.run(|tx| crate::retention::snapshot::covered(tx, &s, c, &t, &ak)).unwrap(), Some(true));
            let count = |costs: &[(&str, std::time::Duration, u64)], name: &str| costs.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
            osis_base::costs::take();
            judge(&bodies[0]);
            let first = osis_base::costs::take();
            bodies[1..].iter().for_each(&mut judge);
            let rest = osis_base::costs::take();
            let blob = e.run(|tx| tx.get_commit(&s)).unwrap().unwrap();
            let index = e.core.decoded.page_index(&s, &blob.parts[0]).unwrap().approx_bytes();
            (count(&first, "stream: bytes"), count(&rest, "stream: bytes"), count(&rest, "apply: piece"), count(&rest, "covered: snapshot part bytes"), index)
        };
        let (small, large) = (judge(500), judge(5_000));
        let each = (BODIES - 1) as u64;
        assert!(small.0 > 0 && large.0 > 5 * small.0, "the first judgment streams the snapshot whole: {small:?} {large:?}");
        assert_eq!((small.2, large.2), (2 * each, 2 * each), "the rest stream the skeleton and the body's page");
        assert!(large.1 / each < large.0 / 4, "a page and the root, far below the snapshot: {large:?}");
        assert_eq!(small.3, large.3, "the part walked is flat in the snapshot's size");
        assert!(large.4 > 5 * small.4 && large.4 < large.0 as usize / 100, "the index grows with the pages, far below the snapshot: {small:?} {large:?}");
    }
}
