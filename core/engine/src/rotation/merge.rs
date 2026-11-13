//! Derived writes merged (spec/crypto.md §4 Current): a node that seals a section of a plain
//! thing under a derived read epoch keeps that epoch, and the derived epoch of each plain thing up
//! the derivation chain it derives through (`records::DERIVED_WRITTEN`). Once such a thing has
//! secrets of its own here, a kept epoch is one of its current epochs (`Core::own_epochs` adopts
//! it, base actor's secret held) until a rotation's history carries it: its rotation is due
//! (`due`), and that rotation's history box carries the derived secret to the thing's holders. So
//! a write made by a node that had not yet heard of the thing's own secrets is read by them.

use crate::engine::{Core, Engine, Tx, records};
use crate::error::{Error, Result};
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use osis_keys::ActorEpochs;
use osis_store::Shred;
use std::collections::BTreeSet;

impl Core {
    /// Whether this node sealed a section under `t`'s derived read epoch `e` (or one deriving
    /// through it) while `t` was plain here, and no rotation of `t` has carried `e` since.
    pub(crate) fn wrote_derived(&self, t: &Tid, e: &Epoch) -> bool {
        self.ix.derived_written.get(t).is_some_and(|s| s.contains(e))
    }
}

impl Engine {
    /// Notes that a section of `t` was sealed under its read epoch `e` (`Engine::seal`): where `t`
    /// is plain here, the derived epochs `e` derives through are written under.
    pub(crate) fn note_sealed(&mut self, t: &Tid, e: &Epoch) -> Result<()> {
        if self.core.reader_of(t) == *t || self.core.wrote_derived(t, e) {
            return Ok(());
        }
        let through = derived_through(&self.core, t, e);
        if through.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            for (x, de) in &through {
                // no view changes: a plain thing's epochs are its derived ones
                if !tx.core.wrote_derived(x, de) {
                    tx.core.ix.derived_written.upsert(*x, BTreeSet::new, |s| {
                        s.insert(*de);
                    });
                    tx.txn.put_local(&key(x, de), &[], Shred::No)?;
                }
            }
            Ok(())
        })
    }
}

/// The derived read epochs `e` of plain thing `t` derives through: `t`'s, then that of each plain
/// thing up its derivation chain, from the base actor epoch whose derivation `e` is (none found:
/// empty).
fn derived_through(core: &Core, t: &Tid, e: &Epoch) -> Vec<(Tid, Epoch)> {
    let Some((base, chain)) = core.derivation(t) else { return Vec::new() };
    if chain.is_empty() {
        return Vec::new();
    }
    for (b, s) in base.read.held() {
        let mut out = Vec::with_capacity(chain.len());
        let (mut ep, mut sec) = (b, s.clone());
        for x in chain.iter().rev() {
            (ep, sec) = ActorEpochs::derived_epoch(x, Role::Read, &ep, &sec);
            out.push((*x, ep));
        }
        if ep == *e {
            return out;
        }
    }
    Vec::new()
}

/// Whether a derived read epoch of `a` this node wrote under (`wrote_derived`) is current here
/// (spec/crypto.md §4 Current): a rotation of read is due. Lets go of those a rotation's history
/// carries (`settle`).
pub(crate) fn due(tx: &mut Tx<'_>, a: &Tid) -> Result<bool> {
    Ok(settle(tx, a)?.is_some_and(|view| tx.core.ix.derived_written.get(a).is_some_and(|w| w.iter().any(|e| view.read.is_current(e)))))
}

/// Lets go of the derived read epochs of `a` this node wrote under that a rotation's history
/// carries here (established, superseded); its view is kept (that history box keys them). Run
/// as this node records its own rotation of `a` (`rotation::record`), so one it made needs no
/// later write. Returns `a`'s view, `None` while `a` is plain here or nothing is kept.
pub(crate) fn settle(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<osis_keys::ActorEpochs>> {
    let Some(written) = tx.core.ix.derived_written.get(a).cloned() else { return Ok(None) };
    // plain here: its epochs are still the derived ones
    let Some(view) = tx.core.own_epochs(a) else { return Ok(None) };
    let carried: Vec<Epoch> = written.iter().filter(|e| view.read.is_established(e) && !view.read.is_current(e)).copied().collect();
    if !carried.is_empty() {
        tx.core.ix.derived_written.upsert(*a, BTreeSet::new, |s| s.retain(|e| !carried.contains(e)));
        for e in &carried {
            tx.txn.remove_local(&key(a, e), Shred::No)?;
        }
    }
    Ok(Some(view))
}

/// Lets go of every derived read epoch of `t` this node wrote under: `t` is gone here (its
/// destruction kept nothing of it, `retention::destroy`), as on a node that never held it.
pub(crate) fn forget(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let Some(written) = tx.core.ix.derived_written.get(t).filter(|s| !s.is_empty()).cloned() else { return Ok(()) };
    // emptied, not removed (`Indexes::derived_written`)
    tx.core.ix.derived_written.upsert(*t, BTreeSet::new, BTreeSet::clear);
    for e in &written {
        tx.txn.remove_local(&key(t, e), Shred::No)?;
    }
    Ok(())
}

/// The `records::DERIVED_WRITTEN` key of (`t`, `e`).
fn key(t: &Tid, e: &Epoch) -> Vec<u8> {
    [records::DERIVED_WRITTEN, t.as_bytes().as_slice(), &e.n().to_be_bytes(), e.nonce()].concat()
}

/// Loads `Indexes::derived_written` from its records.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(records::DERIVED_WRITTEN, |k, _| {
        let bad = || Error::Corrupt("derived written");
        let (t, rest) = k.split_at_checked(15).ok_or_else(bad)?;
        let (n, nonce) = rest.split_at_checked(8).ok_or_else(bad)?;
        let n = u64::from_be_bytes(n.try_into().map_err(|_| bad())?);
        let e = Epoch::new(n, nonce.try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        rows.push((Tid::from_bytes(t.try_into().map_err(|_| bad())?), e));
        Ok(())
    })?;
    for (t, e) in rows {
        tx.core.ix.derived_written.upsert(t, BTreeSet::new, |s| {
            s.insert(e);
        });
    }
    Ok(())
}
