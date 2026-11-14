//! Fall marks (spec/sync-judgement.md §4 Logged again once): per aspect, how many times a held
//! part on it has fallen here (turned invalid), durable, so a stand of "logged again once" compares
//! the mark it was taken at with the mark now and a restart is no change of ground.

use crate::engine::{Engine, Tx, records};
use crate::error::{Error, Result};
use osis_base::{Ak, Tid};
use osis_store::Shred;

/// `fm/` + aspect key: the aspect's fall mark (u64, big-endian).
pub(crate) const FALLS: &[u8] = b"fm/";

/// Loads the fall marks (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(FALLS, |k, v| {
        let mut r = records::Rd::new(k);
        let (t, ak) = (r.tid()?, r.ak()?);
        let n = u64::from_be_bytes(v.as_slice().try_into().map_err(|_| Error::Corrupt("fall mark"))?);
        rows.push(((t, ak), n));
        Ok(())
    })?;
    tx.core.ix.falls.extend(rows);
    Ok(())
}

/// A held part on `(t, ak)` fell here: its mark moves, in the running transaction.
pub(crate) fn fell(tx: &mut Tx<'_>, t: &Tid, ak: &Ak) -> Result<()> {
    let n = tx.core.ix.falls.get(&(*t, ak.clone())).copied().unwrap_or(0) + 1;
    tx.txn.put_local(&records::aspect_key(FALLS, t, ak), &n.to_be_bytes(), Shred::No)?;
    tx.core.ix.falls.insert((*t, ak.clone()), n);
    Ok(())
}

impl Engine {
    /// The fall mark of `(t, ak)`; reads only its key.
    pub(crate) fn fall_mark_now(&self, t: &Tid, ak: &Ak) -> u64 {
        self.core.ix.falls.get(&(*t, ak.clone())).copied().unwrap_or(0)
    }
}
