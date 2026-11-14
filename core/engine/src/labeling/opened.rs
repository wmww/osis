//! Content another wrote, encrypted again (spec/crypto.md §5 Passing on): a fresh encryption of
//! another's commit, or a snapshot carrying its writes, puts it under an epoch this node chose.
//! That is safe only where this node knows every departure the epoch it read the content under
//! covered: so only while an epoch it opened a genuine section of that part under is
//! established here.
//!
//! Invariant: no part of a commit another wrote, read under an epoch a holder's removal was
//! known at, is encrypted by this node under an epoch that holder reads. Its writer encrypted
//! it under an epoch covering every departure it knew (spec/crypto.md §4 Encrypting under); an
//! epoch established here has its names met here, so this node knows those departures, and the
//! epochs it encrypts under cover every departure it knows. Content opened only under an epoch
//! not established here (its removal withheld, withdrawn, or planted) travels only as the
//! ciphertext it came in (`Engine::seal`'s verbatim sections).
//!
//! Who writes each input: the opening is this node's own (the secret that unwrapped the
//! section); the section's bytes come from anyone holding that epoch, a removed party
//! included, so a section counts only for the delta its parts carried: its header hash checked
//! where the thing's record is held, else the held body's bytes compared at use. A section
//! forged under an epoch the removed party holds carries no genuine delta it did not already
//! know. Establishment is judged at use, not at the opening: an epoch's names may stop being
//! met (a demotion voiding the removal it names).

use crate::engine::{Core, Engine, Tx, records};
use crate::error::{Error, Result};
use osis_base::{CommitId, Tid};
use osis_crypto::Epoch;
use osis_keys::ActorEpochs;
use osis_store::Shred;

/// `OPENED_UNDER` rows (key, value) of one commit not yet written (`Core::openings`).
pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// A section's opening, per part: its epoch (of the part's thing, derived for a plain thing) and
/// the hash of the delta it carried, checked against the header when `genuine`.
fn key(c: &CommitId, ai: usize, e: &Epoch) -> Vec<u8> {
    [records::OPENED_UNDER, c.0.as_slice(), &u32::try_from(ai).unwrap_or(u32::MAX).to_be_bytes(), &e.n().to_be_bytes(), e.nonce()].concat()
}

fn value(genuine: bool, delta: &[u8]) -> Vec<u8> {
    [&[u8::from(genuine)][..], &osis_base::hash::hash(delta)].concat()
}

impl Core {
    /// Whether read epoch `ep` of thing `t` (own, or derived from its first admin's) is
    /// established here (spec/crypto.md §4).
    fn read_established(&self, t: &Tid, ep: &Epoch) -> bool {
        let own = |e: &ActorEpochs| e.read.is_established(ep);
        if self.epochs(t).or_else(|| self.ix.secrets.get(t).map(|x| std::sync::Arc::new(x.clone()))).is_some_and(|e| own(&e)) {
            return true;
        }
        let Some(up) = self.created(t).and_then(osis_base::CreationRecord::first_admin) else { return false };
        self.epochs(&up).is_some_and(|o| own(&ActorEpochs::derived(&o, t)))
    }
}

impl Engine {
    /// The read epochs of thing `t` held here with their secrets: its own (or its derived ones),
    /// those derived from its first admin's, and those derived down a section's chain
    /// (`chain_epochs`): every secret `open_commit` tries.
    pub(super) fn read_epochs(&self, t: &Tid, chain: &[Tid]) -> Vec<(Epoch, osis_crypto::Secret32)> {
        let mut out: Vec<(Epoch, osis_crypto::Secret32)> = self.epochs(t).map(|e| e.read.held().map(|(ep, s)| (ep, s.clone())).collect()).unwrap_or_default();
        let mut from = |e: &ActorEpochs| {
            for (ep, s) in ActorEpochs::derived(e, t).read.held() {
                if !out.iter().any(|x| x.0 == ep) {
                    out.push((ep, s.clone()));
                }
            }
        };
        if let Some(up) = self.core.created(t).and_then(osis_base::CreationRecord::first_admin)
            && let Some(o) = self.epochs(&up)
        {
            from(&o);
        }
        for e in self.chain_epochs(chain, &mut None) {
            from(&e);
        }
        out
    }

    /// Records the epoch each opened section of a commit another wrote opened under, per part
    /// (`key`), the first time it is seen. A failed write records nothing (opening reads only).
    pub(super) fn note_opened(&mut self, header: &osis_commit::Header, opened: &[(Epoch, Vec<&osis_commit::Part>)]) {
        let id = header.id();
        // its own write, or one held with every opened part: nothing to learn (its first
        // arrival's openings went with its record)
        let held = |m: &crate::engine::Meta| opened.iter().flat_map(|x| &x.1).all(|p| matches!(m.hold.get(p.ai), Some(h) if !matches!(h, crate::engine::Hold::Missing(_))));
        if self.core.ix.commits.get(&id).is_some_and(|m| m.origin == crate::events::Origin::Local || held(m)) {
            return;
        }
        let mut rows = Vec::new();
        for (e, parts) in opened {
            for p in parts {
                // content only: the rest is records, keys and boxes (each box sealed to its own
                // recipient)
                let Some(a) = header.aspects.get(p.ai).filter(|a| osis_schema::core_types::is_content(a.ak.as_str())) else { continue };
                let genuine = self.core.created(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&osis_crypto::dedup_secret(r.nonce()), &p.delta) == a.hash);
                rows.push((key(&id, p.ai, e), value(genuine, &p.delta)));
            }
        }
        if rows.is_empty() {
            return;
        }
        let at = self.core.openings.entry(id).or_default();
        for r in rows {
            if !at.iter().any(|x| x.0 == r.0) {
                at.push(r);
            }
        }
    }

    /// Lets go of commit `c`'s openings not yet written: it was applied (`write` wrote them),
    /// held already, or relayed and kept nowhere.
    pub(crate) fn openings_done(&mut self, c: &CommitId) {
        self.core.openings.remove(c);
    }
}

/// Writes the openings of commit `c` not yet written (`Tx::put_commit`, with its record `m`), and
/// lets go of those of its parts held with no content (dropped, or value-less): `passes_on`
/// reads none of them.
pub(crate) fn write(tx: &mut Tx<'_>, c: &CommitId, m: &crate::engine::Meta) -> Result<()> {
    let empty = |ai: usize| matches!(m.hold.get(ai), Some(crate::engine::Hold::Leftover { valued: false, .. } | crate::engine::Hold::Dropped(_)));
    for (k, v) in tx.core.openings.get(c).cloned().into_iter().flatten() {
        if !part_of(&k).is_some_and(empty) && tx.txn.get_local(&k)?.is_none() {
            tx.txn.put_local(&k, &v, Shred::No)?;
        }
    }
    if (0..m.hold.len()).any(empty) {
        let prefix = [records::OPENED_UNDER, c.0.as_slice()].concat();
        let mut gone = Vec::new();
        tx.scan(&prefix, |k, _| {
            let ai = k.get(..4).and_then(|b| b.try_into().ok()).map(u32::from_be_bytes);
            if ai.is_some_and(|ai| empty(ai as usize)) {
                gone.push([prefix.as_slice(), k].concat());
            }
            Ok(())
        })?;
        for k in gone {
            tx.txn.remove_local(&k, Shred::Yes)?;
        }
    }
    Ok(())
}

/// The aspect index of an `OPENED_UNDER` key.
fn part_of(k: &[u8]) -> Option<usize> {
    let at = records::OPENED_UNDER.len() + 32;
    k.get(at..at + 4).and_then(|b| b.try_into().ok()).map(|b| u32::from_be_bytes(b) as usize)
}

/// Whether this node may encrypt part `ai` of held commit `c` (on thing `t`) under an epoch of
/// its own choosing (the module's invariant): its own write, one it read in no section, or one
/// it opened a genuine section of under an epoch established here now.
pub(crate) fn passes_on(tx: &mut Tx<'_>, c: &CommitId, ai: usize, t: &Tid) -> Result<bool> {
    // its own write, or one of whose content nothing is held (value-less, or dropped)
    if tx.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local || matches!(m.hold.get(ai), Some(crate::engine::Hold::Leftover { valued: false, .. } | crate::engine::Hold::Dropped(_)))) {
        return Ok(true);
    }
    let prefix = [records::OPENED_UNDER, c.0.as_slice(), &u32::try_from(ai).unwrap_or(u32::MAX).to_be_bytes()].concat();
    let mut under: Vec<(Epoch, bool, [u8; 32])> = Vec::new();
    let row = |k: &[u8], v: &[u8]| -> Result<(Epoch, bool, [u8; 32])> {
        let bad = || Error::Corrupt("opened under");
        let (n, nonce) = k.split_at_checked(8).ok_or_else(bad)?;
        let e = Epoch::new(u64::from_be_bytes(n.try_into().map_err(|_| bad())?), nonce.try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let (g, h) = v.split_first().ok_or_else(bad)?;
        Ok((e, *g == 1, h.try_into().map_err(|_| bad())?))
    };
    tx.scan(&prefix, |k, v| {
        under.push(row(k, &v)?);
        Ok(())
    })?;
    for (k, v) in tx.core.openings.get(c).into_iter().flatten() {
        if let Some(k) = k.strip_prefix(prefix.as_slice()) {
            under.push(row(k, v)?);
        }
    }
    // read in no section: it came to this node directly (an inbox payload, a direct connection),
    // under no epoch
    if under.is_empty() {
        return Ok(true);
    }
    under.retain(|(e, ..)| tx.core.read_established(t, e));
    if under.is_empty() {
        return Ok(false);
    }
    if under.iter().any(|(_, g, _)| *g) {
        return Ok(true);
    }
    // no opening checked against the header: the held delta is genuine, compared by its bytes
    let Some(held) = tx.get_commit(c)? else { return Ok(false) };
    let Some(p) = held.parts.iter().find(|p| p.ai == ai) else { return Ok(false) };
    let h = osis_base::hash::hash(&p.delta);
    Ok(under.iter().any(|(_, _, x)| *x == h))
}

/// Removes the openings of commit `c` (`Tx::remove_commit`).
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let prefix = [records::OPENED_UNDER, c.0.as_slice()].concat();
    let mut gone = Vec::new();
    tx.scan(&prefix, |k, _| {
        gone.push([prefix.as_slice(), k].concat());
        Ok(())
    })?;
    for k in gone {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
    Ok(())
}

impl Engine {
    /// `passes_on` for each held part of `ais` of commit `c`, on its own thing.
    pub(super) fn passes_on_parts(&mut self, c: &CommitId, ais: &[usize]) -> Result<bool> {
        let c = *c;
        let Some(h) = self.header(&c) else { return Ok(true) };
        let parts: Vec<(usize, Tid)> = ais.iter().filter_map(|ai| h.aspects.get(*ai).map(|a| (*ai, a.tid))).collect();
        self.read(|tx| {
            for (ai, t) in &parts {
                if !passes_on(tx, &c, *ai, t)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }

    /// `passes_on` for each part of `ais`.
    pub(super) fn passes_on_all(&mut self, c: &CommitId, ais: &[usize], t: &Tid) -> Result<bool> {
        let (c, t) = (*c, *t);
        self.read(|tx| {
            for ai in ais {
                if !passes_on(tx, &c, *ai, &t)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }
}
