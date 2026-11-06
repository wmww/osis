//! Suspect aspects (spec/permissions.md §4 heartbeat, spec/commits.md §5): an aspect whose
//! state this node may have computed from less than another holder, because it dropped data a
//! validity flip or a late creation record would have needed: a validity flip, either way, on
//! an aspect where it holds a body dropped for its keep bounds (the body joins again if a copy
//! comes, §5), a body dropped while invalid that turned valid, a body dropped as covered missing again (spec/permissions.md §5.2), a part held pending
//! at its expiry (counts as never received). The node reports them in its heartbeats; a writer
//! re-snapshots such an aspect (spec/sync.md §7). A flag names the bodies it is about; an entry
//! goes as its body comes back (held again: what the aspect lacked for it is in). A Flip or
//! Uncovered entry is dormant while a held snapshot valid here is stamped after its commit
//! (`receipt::settled`), judged when the flags are read, from what is held then: a snapshot that
//! turns invalid gives nothing (spec/permissions.md §5.2), so the flag it had settled shows
//! again. A snapshot's author that lacked the delta leaves a node that holds it richer until a
//! writer holding it compacts (notes/engine-suspects.md). A PendingExpiry entry is never
//! dormant: its part's writes reach this node only as a snapshot's copies, and no test on what a
//! snapshot holds tells whether they repaired it (a listing snapshot may carry nothing of the part;
//! a copy key-erased at expiry, spec/crdt.md §4.7, lands outside the entry the part wrote; writes
//! of one delta share a dot). The heartbeat's digests say whether nodes agree; such an entry goes
//! only with its thing (`forget`), yields to any flag raised after it (`suspects_under`: most
//! recent first) and so cannot keep a newer one out of a heartbeat.

use crate::engine::records;
use crate::engine::{Core, DropFor, Engine, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;

/// Why an aspect is suspect (bits of an entry's last byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A write flipped on an aspect where a body dropped for its keep bounds may have gone for
    /// it, or a body dropped while invalid turned valid.
    Flip = 1,
    /// A body dropped as covered is missing again (its cover turned invalid).
    Uncovered = 2,
    /// A part held pending at its expiry was dropped (counts as never received).
    PendingExpiry = 4,
}

/// A body a flag is about: its commit, aspect index and `Why` bits.
type Entry = (CommitId, u8, u8);

/// The flag record: le64 corrected wall ms last raised, then per body a 32-byte commit ID, the
/// aspect index and the `Why` bits.
fn read(v: &[u8]) -> (u64, Vec<Entry>) {
    let (at, rest) = v.split_first_chunk::<8>().map_or((0, &[][..]), |(a, r)| (u64::from_le_bytes(*a), r));
    let (chunks, _) = rest.as_chunks::<34>();
    let bodies = chunks
        .iter()
        .filter_map(|e| {
            let (c, tail) = e.split_first_chunk::<32>()?;
            Some((CommitId(*c), *tail.first()?, *tail.get(1)?))
        })
        .collect();
    (at, bodies)
}

fn write(at: u64, bodies: &[Entry]) -> Vec<u8> {
    let mut v = at.to_le_bytes().to_vec();
    for (c, ai, why) in bodies {
        v.extend_from_slice(&c.0);
        v.push(*ai);
        v.push(*why);
    }
    v
}

fn load(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<(u64, Vec<Entry>)>> {
    Ok(tx.txn.get_local(&records::aspect_key(records::SUSPECT, tid, ak))?.map(|v| read(&v)))
}

fn store(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, at: u64, bodies: &[Entry]) -> Result<()> {
    let key = records::aspect_key(records::SUSPECT, tid, ak);
    if bodies.is_empty() {
        tx.txn.remove_local(&key, Shred::No)?;
    } else {
        tx.txn.put_local(&key, &write(at, bodies), Shred::No)?;
    }
    Ok(())
}

/// Flags `(tid, ak)` suspect from now for `why`, about `bodies` (parts of it, by commit and
/// aspect index; none flags nothing). A memory aspect never: it vanishes whole, as at a node
/// that never held it.
pub(crate) fn raise(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, why: Why, bodies: &[(CommitId, usize)]) -> Result<()> {
    if bodies.is_empty() || tx.txn.is_memory_aspect(tid, ak) {
        return Ok(());
    }
    let (_, mut all) = load(tx, tid, ak)?.unwrap_or_default();
    for (c, ai) in bodies {
        let ai = u8::try_from(*ai).unwrap_or(u8::MAX);
        match all.iter_mut().find(|e| e.0 == *c && e.1 == ai) {
            Some(e) => e.2 |= why as u8,
            None => all.push((*c, ai, why as u8)),
        }
    }
    let now = tx.now().0;
    store(tx, tid, ak, now, &all)
}

/// Part `ai` of `c` on `(tid, ak)` is held again: the flag is no longer about it.
pub(crate) fn body_back(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some((at, mut all)) = load(tx, tid, ak)? else { return Ok(()) };
    let n = all.len();
    all.retain(|e| !(e.0 == *c && usize::from(e.1) == ai));
    if all.len() != n {
        store(tx, tid, ak, at, &all)?;
    }
    Ok(())
}

/// Whether flag entry `e` is dormant: not about a part that went pending at its expiry, and a
/// held snapshot valid here is stamped after its commit.
fn dormant(core: &Core, e: &Entry) -> bool {
    e.2 & Why::PendingExpiry as u8 == 0 && core.ix.commits.get(&e.0).is_some_and(|m| crate::apply::receipt::settled(core, &m.header, usize::from(e.1)))
}

/// The parts of `(tid, ak)` dropped for their keep bounds: their writes are in the state alone
/// (or nowhere), so an un-merge there may differ from a node that kept the body (a leftover
/// is a held body).
pub(crate) fn keep_dropped(core: &Core, tid: &Tid, ak: &Ak) -> Vec<(CommitId, usize)> {
    core.ix
        .by_aspect
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        .filter_map(|(_, c)| {
            let m = core.ix.commits.get(c)?;
            let ai = m.aspect(tid, ak)?;
            (!m.view.memory && m.dropped.get(&ai).is_some_and(|d| d.why == DropFor::Other) && !super::valueless(core, c, ai)).then_some((*c, ai))
        })
        .collect()
}

impl Engine {
    /// The aspects this node flags suspect, with when each was last flagged (corrected wall ms)
    /// and why (`Why` bits over the bodies it is about that are not dormant).
    pub fn suspects(&mut self) -> Result<Vec<(Tid, Ak, u64, u8)>> {
        self.run(|tx| {
            let mut flags = Vec::new();
            tx.scan(records::SUSPECT, |k, v| {
                let mut r = records::Rd::new(k);
                let (tid, ak) = (r.tid()?, r.ak()?);
                let (at, bodies) = read(&v);
                flags.push((tid, ak, at, bodies));
                Ok(())
            })?;
            Ok(flags
                .into_iter()
                .filter_map(|(tid, ak, at, bodies)| {
                    let why = bodies.iter().filter(|e| !dormant(tx.core, e)).fold(0, |w, e| w | e.2);
                    (why != 0).then_some((tid, ak, at, why))
                })
                .collect())
        })
    }

    /// The keyed digest of `(tid, ak)`'s state (spec/permissions.md §4): the first 16 bytes of
    /// `kdf("state", dedup secret of tid, ak || state bytes)`, the state bytes its encoding as a
    /// snapshot fragment with its pages, none for an aspect holding no state. `None` while the
    /// thing's creation record is unknown. Nodes holding the same bodies get the same digest; a
    /// host, lacking the dedup secret, learns nothing from it.
    pub fn state_digest(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<[u8; 16]>> {
        let Some(r) = self.core.created(tid) else { return Ok(None) };
        let d = osis_crypto::dedup_secret(r.nonce());
        let (tid, ak) = (*tid, ak.clone());
        let bytes = self.run(|tx| tx.state(&tid, &ak)?.map(crate::engine::state::encode).transpose())?.unwrap_or_default();
        Ok(Some(osis_crypto::state_digest(&d, ak.as_str(), &bytes)))
    }
}
