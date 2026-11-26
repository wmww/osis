//! A forgotten coverer's covers (spec/permissions.md §5.2: a forgotten coverer carries a body as
//! the covers it dropped under do). A coverer forgotten while a held part's `Dropped::covered_by`
//! names it keeps, per aspect, the covers its own part dropped under (`Indexes::handed`), so the
//! chain of covers (`retention::coverers`) runs past it as it did while it was known; nothing
//! naming it is rewritten. One that no held part names is spliced out: each kept covers naming
//! it names its covers instead (`splice`). So every kept entry is named by a held part (rows are
//! bounded by the held parts dropped as covered), and a forget costs the kept covers naming it:
//! O(1) along a chain. An entry goes, spliced, once no held part names it, or as it is held again
//! (its meta decides then), judged at the transaction's end (`settle_due`). Rows
//! `records::HANDED`, a memory coverer's in memory.
//!
//! Rejected: handing each named part down to the forgotten one's covers (a meta and record write
//! per part dropped under it, so every snapshot of a growing aspect rewrote every earlier body);
//! keeping an entry while only other entries name it (a chain under a lasting body grew one row
//! per snapshot for good).

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// What a forgotten coverer dropped under, per aspect it had a part on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handed {
    /// Its commit was memory class: its row is in memory.
    pub memory: bool,
    pub covers: Vec<(Tid, Ak, BTreeSet<CommitId>)>,
}

impl Handed {
    /// The covers it dropped under on `(tid, ak)`.
    pub(crate) fn on(&self, tid: &Tid, ak: &Ak) -> impl Iterator<Item = &CommitId> {
        self.covers.iter().filter(move |x| x.0 == *tid && x.1 == *ak).flat_map(|x| x.2.iter())
    }

    fn targets(&self) -> BTreeSet<CommitId> {
        self.covers.iter().flat_map(|x| x.2.iter().copied()).collect()
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Wr::new().u8(u8::from(self.memory)).u32(self.covers.len() as u32);
        for (tid, ak, cs) in &self.covers {
            w = w.raw(tid.as_bytes()).bytes(ak.as_str().as_bytes()).u32(cs.len() as u32);
            for c in cs {
                w = w.raw(&c.0);
            }
        }
        w.take()
    }

    fn decode(b: &[u8]) -> Result<Handed> {
        let bad = || Error::Corrupt("handed covers");
        let mut r = Rd::new(b);
        let memory = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(bad()),
        };
        let mut covers = Vec::new();
        for _ in 0..r.u32()? {
            let tid = r.tid()?;
            let ak = Ak::new(std::str::from_utf8(r.bytes()?).map_err(|_| bad())?).map_err(|_| bad())?;
            let mut cs = BTreeSet::new();
            for _ in 0..r.u32()? {
                cs.insert(CommitId(r.arr()?));
            }
            covers.push((tid, ak, cs));
        }
        r.end()?;
        Ok(Handed { memory, covers })
    }
}

fn key(id: &CommitId) -> Vec<u8> {
    [records::HANDED, &id.0].concat()
}

impl Core {
    /// Whether a held part names `id` as a cover.
    fn named_as_cover(&self, id: &CommitId) -> bool {
        self.ix.covered_under.contains_key(id)
    }

    fn put_handed(&mut self, id: CommitId, h: Arc<Handed>) {
        for t in h.targets() {
            self.ix.handed_under.insert(t, id);
        }
        if let Some(old) = self.ix.handed.insert(id, h) {
            self.unindex_handed(&id, &old);
        }
    }

    fn unindex_handed(&mut self, id: &CommitId, h: &Handed) {
        let now = self.ix.handed.get(id).map(|x| x.targets()).unwrap_or_default();
        for t in h.targets().difference(&now) {
            self.ix.handed_under.remove(t, id);
        }
    }
}

/// Coverer `id`, being forgotten (its meta still held): where a held part names it, what each of
/// its parts dropped under stays as its covers; kept covers naming it take those instead.
pub(crate) fn note(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let named = tx.core.named_as_cover(id);
    if !named && !tx.core.ix.handed_under.contains_key(id) {
        return Ok(());
    }
    let Some(m) = tx.core.ix.commits.get(id) else { return Ok(()) };
    let covers = m.view.aspects.iter().enumerate().map(|(ai, a)| (a.tid, a.ak.clone(), m.dropped(ai).map(|d| d.covered_by.iter().copied().filter(|x| x != id).collect()).unwrap_or_default())).collect();
    let h = Handed { memory: m.view.memory, covers };
    if !named {
        return splice(tx, id, &h);
    }
    put(tx, *id, h)
}

fn put(tx: &mut Tx<'_>, id: CommitId, h: Handed) -> Result<()> {
    // counted: tests read how many kept covers a forget writes
    osis_base::costs::count("forget: covers kept", 1);
    let row = h.encode();
    tx.in_class(h.memory, |tx| Ok(tx.txn.put_local(&key(&id), &row, Shred::No)?))?;
    tx.core.put_handed(id, Arc::new(h));
    Ok(())
}

/// Each kept covers naming `x` names `x`'s covers `h` instead.
fn splice(tx: &mut Tx<'_>, x: &CommitId, h: &Handed) -> Result<()> {
    let namers: Vec<CommitId> = tx.core.ix.handed_under.get(x).into_iter().flatten().copied().collect();
    for y in namers {
        let Some(mut hy) = tx.core.ix.handed.get(&y).map(|v| (**v).clone()) else { continue };
        for (tid, ak, set) in &mut hy.covers {
            if set.remove(x) {
                set.extend(h.on(tid, ak).copied().filter(|c| *c != y));
            }
        }
        put(tx, y, hy)?;
    }
    Ok(())
}

/// Splices out the kept covers of the coverers marked this transaction that no held part names
/// any more, and drops those held again.
pub(crate) fn settle_due(tx: &mut Tx<'_>) -> Result<()> {
    while let Some(id) = tx.core.handed_due.pop_first() {
        let Some(h) = tx.core.ix.handed.get(&id).cloned() else { continue };
        let held = tx.core.ix.commits.contains_key(&id);
        if !held && tx.core.named_as_cover(&id) {
            continue;
        }
        if !held {
            splice(tx, &id, &h)?;
        }
        tx.core.ix.handed.remove(&id);
        tx.core.unindex_handed(&id, &h);
        tx.in_class(h.memory, |tx| Ok(tx.txn.remove_local(&key(&id), Shred::No).map(|_| ())?))?;
    }
    Ok(())
}

/// The covers kept at the last stop.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let rows = tx.scan_rows(records::HANDED, |k, v| {
        let mut r = Rd::new(k);
        let id = CommitId(r.arr()?);
        r.end()?;
        Ok((id, Handed::decode(&v)?))
    })?;
    for (id, h) in rows {
        tx.core.put_handed(id, Arc::new(h));
    }
    Ok(())
}
