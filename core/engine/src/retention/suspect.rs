//! Suspect aspects (spec/permissions.md §4 heartbeat, spec/commits.md §5): an aspect whose
//! state this node may have computed from less than another holder, because it dropped data a
//! validity flip or a late creation record would have needed: a validity flip on an aspect
//! where it holds a body dropped for its keep bounds (the body joins again if a copy comes,
//! §5), a body dropped as covered missing again (spec/permissions.md §5.2), a part held pending
//! at its expiry (counts as never received). The node reports them in its heartbeats; a writer
//! re-snapshots such an aspect (spec/sync.md §7). A flag names the bodies it is about and goes
//! as each comes back: held again, or listed as included by a valid snapshot of the aspect
//! (`receipt::listed_by`: it carried that delta's writes, value-less copies of an expired one).
//! A snapshot that lists none of them (any writer's compaction, stamped whenever) clears
//! nothing: it repaired nothing.

use crate::engine::records;
use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;

/// Why an aspect is suspect (bits of an entry's last byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A write fell on an aspect where a body dropped for its keep bounds may have died for it.
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
    let at = v.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()).map_or(0, u64::from_le_bytes);
    let bodies = v.get(8..).unwrap_or_default().chunks_exact(34).map(|e| (CommitId(e[..32].try_into().unwrap()), e[32], e[33])).collect();
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

/// Valid snapshot `s` of `(tid, ak)` joined: the flag is no longer about the bodies it lists as
/// included (spec/commits.md §4: it carried their writes).
pub(crate) fn settled_by(tx: &mut Tx<'_>, s: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some((at, all)) = load(tx, tid, ak)? else { return Ok(()) };
    let mut kept = Vec::new();
    for e in all {
        let h = match tx.core.ix.commits.get(&e.0) {
            Some(m) => Some(osis_commit::Header::clone(&m.header)),
            // a part dropped while pending: its header is in the stored copy
            None => tx.txn.get_pending(&e.0)?.and_then(|(_, b)| osis_commit::CommitBlob::decode(&b).ok()).map(|b| b.header),
        };
        if !h.is_some_and(|h| crate::apply::receipt::listed_by(tx.core, s, &h, &e.0, usize::from(e.1))) {
            kept.push(e);
        }
    }
    store(tx, tid, ak, at, &kept)
}

/// The parts of `(tid, ak)` dropped other than as covered, at expiry or by a purge: their
/// writes are in the state alone (or nowhere), so an un-merge there may differ from a node
/// that kept the body.
pub(crate) fn keep_dropped(core: &Core, tid: &Tid, ak: &Ak) -> Vec<(CommitId, usize)> {
    core.ix
        .by_aspect
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        .filter_map(|(_, c)| {
            let m = core.ix.commits.get(c)?;
            let ai = m.aspect(tid, ak)?;
            (!m.view.memory && m.dropped.get(&ai).is_some_and(|d| !d.as_cover) && !super::valueless(core, c, ai)).then_some((*c, ai))
        })
        .collect()
}

impl Engine {
    /// The aspects this node flags suspect, with when each was last flagged (corrected wall ms)
    /// and why (`Why` bits over the bodies it is about).
    pub fn suspects(&mut self) -> Result<Vec<(Tid, Ak, u64, u8)>> {
        self.run(|tx| {
            let mut out = Vec::new();
            tx.scan(records::SUSPECT, |k, v| {
                let mut r = records::Rd::new(k);
                let (tid, ak) = (r.tid()?, r.ak()?);
                let (at, bodies) = read(&v);
                out.push((tid, ak, at, bodies.iter().fold(0, |w, e| w | e.2)));
                Ok(())
            })?;
            Ok(out)
        })
    }

    /// The keyed digest of `(tid, ak)`'s state (spec/permissions.md §4): the first 16 bytes of
    /// `kdf("state", dedup secret of tid, ak || state bytes)`, the state bytes its encoding as a
    /// snapshot fragment with its pages. `None` while the thing's creation record is unknown or
    /// the aspect holds no state. Nodes holding the same bodies get the same digest; a host,
    /// lacking the dedup secret, learns nothing from it.
    pub fn state_digest(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<[u8; 16]>> {
        let Some(r) = self.core.created(tid) else { return Ok(None) };
        let d = osis_crypto::dedup_secret(r.nonce());
        let (tid, ak) = (*tid, ak.clone());
        let Some(bytes) = self.run(|tx| tx.state(&tid, &ak)?.map(crate::engine::state::encode).transpose())? else { return Ok(None) };
        Ok(Some(osis_crypto::state_digest(&d, ak.as_str(), &bytes)))
    }
}
