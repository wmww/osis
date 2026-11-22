//! How long a writer waits for a setting it knows of and does not hold (spec/commits.md §5
//! Waiting for it): per valid `retention^.0` part of a held header not received, a wait placed
//! at the pass place (`Core::place`) it began at, that ends once a complete pass of every sync
//! ID this node reads carrying the thing, begun after it, is noted (spec/sync-status.md §1;
//! none read: at once). Bounded by the pass, never by a timer. A part whose body arrives leaves
//! its wait with it, so the setting applies from then on as any late setting.
//!
//! The waits follow the held headers: placed and dropped at the end of the transaction that
//! moved a part of `retention^.0` in `Indexes::missing` (`judge_due`); whether each has ended is
//! judged again after every transaction while any is held (`Engine::rejudge_setting_waits`), so a
//! thing that comes to be carried by a sync ID waits for that one's pass too. Rows `sw/` keep
//! each wait's place across a restart; an open judges them again.

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;

/// `sw/` + thing + commit: a setting wait's place (u64 BE).
const ROWS: &[u8] = b"sw/";

/// A wait for one setting part not received (`Indexes::setting_waits`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    /// The pass place it began at: a pass counts only begun above it.
    pub at: u64,
    /// A complete pass of each read sync ID carrying the thing, begun after it, is noted (none:
    /// at once), as last judged (`Engine::rejudge_setting_waits`).
    pub ended: bool,
}

fn key(t: &Tid, c: &CommitId) -> Vec<u8> {
    [ROWS, t.as_bytes(), &c.0].concat()
}

fn put(tx: &mut Tx<'_>, t: Tid, c: CommitId, at: u64) -> Result<()> {
    tx.txn.put_local(&key(&t, &c), &at.to_be_bytes(), Shred::No)?;
    tx.core.ix.setting_waits.insert((t, c), Wait { at, ended: false });
    Ok(())
}

/// Loads the setting waits (an open or reload); the pass place goes on from the highest stored.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("setting wait");
    let mut rows = Vec::new();
    tx.scan(ROWS, |k, v| {
        let (t, c) = k.split_at_checked(15).ok_or_else(bad)?;
        let t = Tid::from_bytes(t.try_into().map_err(|_| bad())?);
        let c = CommitId(c.try_into().map_err(|_| bad())?);
        let at = u64::from_be_bytes(v.as_slice().try_into().map_err(|_| bad())?);
        rows.push(((t, c), Wait { at, ended: false }));
        Ok(())
    })?;
    tx.core.place = tx.core.place.max(rows.iter().map(|(_, w)| w.at).max().unwrap_or(0));
    tx.core.ix.setting_waits.extend(rows);
    Ok(())
}

/// The valid `retention^.0` parts on `t` of headers held here whose bodies are not.
pub(crate) fn unreceived(core: &Core, t: &Tid) -> BTreeSet<CommitId> {
    let Ok(ak) = osis_base::Ak::new(osis_commit::retention::RETENTION) else { return BTreeSet::new() };
    core.ix.missing.get(&(ak.clone(), *t)).into_iter().flatten().filter(|c| {
        core.ix.commits.get(c).and_then(|m| Some((m, m.aspect(t, &ak)?))).is_some_and(|(m, ai)| m.valid_at(ai) && m.missing_as(ai) == Some(crate::engine::Missing::Plain))
    }).copied().collect()
}

/// `t`'s waits (`unreceived`'s parts) as held now.
fn waits_on(core: &Core, t: &Tid) -> Vec<(CommitId, Wait)> {
    let lo = (*t, CommitId([0; 32]));
    let hi = (*t, CommitId([0xff; 32]));
    core.ix.setting_waits.range(lo..=hi).map(|((_, c), w)| (*c, *w)).collect()
}

/// Whether some part of `t`'s setting not received is still waited for (`awaits_setting`).
pub(crate) fn waiting(core: &Core, t: &Tid) -> bool {
    let ended: BTreeSet<CommitId> = waits_on(core, t).into_iter().filter(|(_, w)| w.ended).map(|(c, _)| c).collect();
    unreceived(core, t).iter().any(|c| !ended.contains(c))
}

/// At a transaction's end: each thing whose setting parts moved in `Indexes::missing`
/// (`Core::setting_waits_due`) waits for each part not received from the place now, a wait
/// already placed kept, and a part received or no longer valid leaves its wait.
pub(crate) fn judge_due(tx: &mut Tx<'_>) -> Result<()> {
    let due = std::mem::take(&mut tx.core.setting_waits_due);
    for t in due {
        let now = unreceived(tx.core, &t);
        let had = waits_on(tx.core, &t);
        for (c, _) in had.iter().filter(|(c, _)| !now.contains(c)) {
            tx.txn.remove_local(&key(&t, c), Shred::No)?;
            tx.core.ix.setting_waits.remove(&(t, *c));
        }
        for c in now.iter().filter(|c| !had.iter().any(|(x, _)| x == *c)) {
            put(tx, t, *c, tx.core.place)?;
        }
    }
    Ok(())
}

impl Engine {
    /// The open setting waits (`judge_due`), each with the read sync IDs carrying its thing.
    pub(crate) fn setting_wait_ids(&mut self) -> Result<Vec<(u64, BTreeSet<osis_base::SyncId>)>> {
        let open: Vec<(Tid, u64)> = self.core.ix.setting_waits.iter().filter(|(_, w)| !w.ended).map(|((t, _), w)| (*t, w.at)).collect();
        let mut out = Vec::with_capacity(open.len());
        for (t, at) in open {
            out.push((at, self.carrying_now(&t, true)?));
        }
        Ok(out)
    }

    /// Judges again whether each setting wait has ended (`Wait::ended`): a complete pass of
    /// every read sync ID carrying its thing now, begun after it, is noted (none: ended). After
    /// every transaction while any wait is held, and at an open: O(waits held), none in the
    /// common case.
    pub(crate) fn rejudge_setting_waits(&mut self) -> Result<()> {
        if self.core.ix.setting_waits.is_empty() {
            return Ok(());
        }
        let waits: Vec<((Tid, CommitId), Wait)> = self.core.ix.setting_waits.iter().map(|(k, w)| (*k, *w)).collect();
        let mut moved = Vec::new();
        for ((t, c), w) in waits {
            let ids = self.carrying_now(&t, true)?;
            let ended = self.passed_after(ids.iter(), w.at);
            if ended != w.ended {
                moved.push(((t, c), Wait { ended, ..w }));
            }
        }
        if moved.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            for (k, w) in moved {
                tx.core.ix.setting_waits.insert(k, w);
            }
            Ok(())
        })
    }
}
