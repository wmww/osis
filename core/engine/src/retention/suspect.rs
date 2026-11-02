//! Suspect aspects (spec/permissions.md §4 heartbeat, spec/commits.md §5): an aspect whose
//! state this node may have computed from less than another holder, because it dropped data a
//! validity flip or a late creation record would have needed: a validity flip on an aspect
//! where it holds a body dropped for its keep bounds (the body joins again if a copy comes,
//! §5), a body dropped as covered missing again (spec/permissions.md §5.2), a part held pending
//! at its expiry (counts as never received). The node reports them in its heartbeats; a writer
//! re-snapshots such an aspect (spec/sync.md §7). A flag goes when a valid compaction snapshot
//! of the aspect stamped at or after it applies, or when a body dropped there joins again.

use crate::engine::records;
use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;

/// Why an aspect is suspect (bits of the record's last byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A write fell on an aspect where a body dropped for its keep bounds may have died for it.
    Flip = 1,
    /// A body dropped as covered is missing again (its cover turned invalid).
    Uncovered = 2,
    /// A part held pending at its expiry was dropped (counts as never received).
    PendingExpiry = 4,
}

/// The flag record: when last raised (corrected wall ms), and the `Why` bits.
fn read(v: &[u8]) -> (u64, u8) {
    let at = v.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()).map_or(0, u64::from_le_bytes);
    (at, v.get(8).copied().unwrap_or(0))
}

/// Flags `(tid, ak)` suspect from now for `why` (a memory aspect never: it vanishes whole, as at
/// a node that never held it).
pub(crate) fn raise(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, why: Why) -> Result<()> {
    if tx.txn.is_memory_aspect(tid, ak) {
        return Ok(());
    }
    let key = records::aspect_key(records::SUSPECT, tid, ak);
    let bits = tx.txn.get_local(&key)?.map_or(0, |v| read(&v).1) | why as u8;
    let mut v = tx.now().0.to_le_bytes().to_vec();
    v.push(bits);
    tx.txn.put_local(&key, &v, Shred::No)?;
    Ok(())
}

/// Clears the flag on `(tid, ak)`.
pub(crate) fn clear(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    tx.txn.remove_local(&records::aspect_key(records::SUSPECT, tid, ak), Shred::No)?;
    Ok(())
}

/// Valid snapshot `s` of `(tid, ak)` joined: the flag goes if `s` is stamped at or after it.
pub(crate) fn settled_by(tx: &mut Tx<'_>, s: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(ts) = tx.core.ix.commits.get(s).map(|m| m.header.ts.wall_ms().0) else { return Ok(()) };
    let key = records::aspect_key(records::SUSPECT, tid, ak);
    if let Some(v) = tx.txn.get_local(&key)?
        && ts >= read(&v).0
    {
        tx.txn.remove_local(&key, Shred::No)?;
    }
    Ok(())
}

/// Whether `(tid, ak)` has a part dropped other than as covered, at expiry or by a purge: its
/// writes are in the state alone (or nowhere), so an un-merge there may differ from a node
/// that kept the body.
pub(crate) fn keep_dropped(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().any(|(_, c)| {
        let Some(m) = core.ix.commits.get(c) else { return false };
        let Some(ai) = m.aspect(tid, ak) else { return false };
        !m.view.memory && m.dropped.get(&ai).is_some_and(|d| !d.as_cover) && !super::valueless(core, c, ai)
    })
}

impl Engine {
    /// The aspects this node flags suspect, with when each was last flagged (corrected wall ms)
    /// and why (`Why` bits).
    pub fn suspects(&mut self) -> Result<Vec<(Tid, Ak, u64, u8)>> {
        self.run(|tx| {
            let mut out = Vec::new();
            tx.scan(records::SUSPECT, |k, v| {
                let mut r = records::Rd::new(k);
                let (tid, ak) = (r.tid()?, r.ak()?);
                let (at, why) = read(&v);
                out.push((tid, ak, at, why));
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
