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
//!
//! A part read in no section (an inbox payload, a direct connection, the plaintext `ingest`)
//! came under no epoch and passes on as this node's own: delivering it needs its plaintext,
//! which only parties reading its epoch hold (they could hand it to anyone), and node-sync
//! carries no other's content so. Openings are never lost in between: they are written in the
//! ingest that keeps the commit (held or pending), and one that keeps nothing is fetched and
//! opened again.
//!
//! Storage: an opening rides in memory (`Core::openings`) from `Engine::open_commit` to the
//! commit's next ingest, which writes it where the commit is then held or pending
//! (`persist`) and lets go of it whatever the outcome; rows go with the commit's record
//! (`Tx::remove_commit`) or its pending copy thrown out unapplied (`drop_pending`). Memory is
//! bounded by the commits opened and not yet ingested, plus held and pending commits opened
//! again whose rows were not yet written.

use crate::engine::{Core, Engine, Hold, Tx, records};
use crate::error::{Error, Result};
use crate::events::Origin;
use osis_base::{CommitId, Tid};
use osis_crypto::Epoch;
use osis_keys::ActorEpochs;
use osis_schema::core_types::is_content;
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

    /// Records the epoch each opened section of a commit another wrote opened under, per content
    /// part (`key`), unless already written. A failed write records nothing (opening reads only).
    pub(super) fn note_opened(&mut self, header: &osis_commit::Header, opened: &[(Epoch, Vec<&osis_commit::Part>)]) {
        let id = header.id();
        if self.core.ix.commits.get(&id).is_some_and(|m| m.origin == Origin::Local) {
            return;
        }
        let mut rows = Vec::new();
        for (e, parts) in opened {
            for p in parts {
                // content only: the rest is records, keys and boxes (each box sealed to its own
                // recipient)
                let Some(a) = header.aspects.get(p.ai).filter(|a| is_content(a.ak.as_str())) else { continue };
                let genuine = self.core.created(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&osis_crypto::dedup_secret(r.nonce()), &p.delta) == a.hash);
                rows.push((key(&id, p.ai, e), value(genuine, &p.delta)));
            }
        }
        // a held or pending commit opened again: only what its rows lack
        if !rows.is_empty() && (self.core.ix.commits.contains_key(&id) || self.core.ix.pending.contains_key(&id)) {
            let Ok(new) = self.read(|tx| {
                let mut new = Vec::new();
                for r in rows {
                    if tx.txn.get_local(&r.0)?.is_none() {
                        new.push(r);
                    }
                }
                Ok(new)
            }) else {
                return;
            };
            rows = new;
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

    /// Lets go of commit `c`'s openings not yet written: its ingest wrote them (`persist`) or
    /// kept nothing of it, it was relayed and kept nowhere, or the caller opened its blob and
    /// will not ingest it.
    pub fn openings_done(&mut self, c: &CommitId) {
        self.core.openings.remove(c);
    }
}

/// Writes the openings of commit `c` not yet written, where `c` is held or pending (the end of
/// its ingest's transaction).
pub(crate) fn persist(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    if !tx.core.ix.commits.contains_key(c) && !tx.core.ix.pending.contains_key(c) {
        return Ok(());
    }
    for (k, v) in tx.core.openings.get(c).cloned().into_iter().flatten() {
        if tx.txn.get_local(&k)?.is_none() {
            tx.txn.put_local(&k, &v, Shred::No)?;
        }
    }
    Ok(())
}

/// Lets go of the rows of commit `c`'s parts held with no content (dropped, or value-less):
/// nothing of them is encrypted again, and kept they would follow the bodies' churn
/// (`Tx::put_commit`, with its record `m`).
pub(crate) fn prune(tx: &mut Tx<'_>, c: &CommitId, m: &crate::engine::Meta) -> Result<()> {
    let empty = |ai: usize| matches!(m.hold.get(ai), Some(Hold::Leftover { valued: false, .. } | Hold::Dropped(_)));
    if !(0..m.hold.len()).any(empty) {
        return Ok(());
    }
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
    Ok(())
}

/// One opening of a part: the part, its epoch, whether its delta was checked against the
/// header, and the delta's hash.
type Opening = (usize, Epoch, bool, [u8; 32]);

/// The openings of commit `c` recorded here, written or not (`ai`: of that part alone): per
/// row its part, epoch, whether its delta was checked against the header, and the delta's hash.
fn openings(tx: &mut Tx<'_>, c: &CommitId, ai: Option<usize>) -> Result<Vec<Opening>> {
    let mut prefix = [records::OPENED_UNDER, c.0.as_slice()].concat();
    if let Some(ai) = ai {
        prefix.extend_from_slice(&u32::try_from(ai).unwrap_or(u32::MAX).to_be_bytes());
    }
    let whole = [records::OPENED_UNDER, c.0.as_slice()].concat();
    let row = |k: &[u8], v: &[u8]| -> Result<Opening> {
        let bad = || Error::Corrupt("opened under");
        let (ai, rest) = k.split_at_checked(4).ok_or_else(bad)?;
        let (n, nonce) = rest.split_at_checked(8).ok_or_else(bad)?;
        let e = Epoch::new(u64::from_be_bytes(n.try_into().map_err(|_| bad())?), nonce.try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let (g, h) = v.split_first().ok_or_else(bad)?;
        Ok((u32::from_be_bytes(ai.try_into().map_err(|_| bad())?) as usize, e, *g == 1, h.try_into().map_err(|_| bad())?))
    };
    let mut out = Vec::new();
    let skip = whole.len();
    tx.scan(&prefix, |k, v| {
        let full = [prefix.as_slice(), k].concat();
        out.push(row(full.get(skip..).unwrap_or_default(), &v)?);
        Ok(())
    })?;
    for (k, v) in tx.core.openings.get(c).into_iter().flatten() {
        if k.starts_with(&prefix) {
            let r = row(k.get(skip..).unwrap_or_default(), v)?;
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    Ok(out)
}

/// The epochs held commit `c`'s parts on thing `t` opened under here, written or not: the
/// epoch its writer sealed each under, kept through every passing on (spec/crypto.md §5); none
/// for a part read in no section.
pub(crate) fn opened_epochs(tx: &mut Tx<'_>, c: &CommitId, t: &Tid) -> Result<Vec<Epoch>> {
    let Some(view) = tx.core.ix.commits.get(c).map(|m| m.view.clone()) else { return Ok(Vec::new()) };
    let on = |ai: usize| view.aspects.get(ai).is_some_and(|a| a.tid == *t);
    Ok(openings(tx, c, None)?.into_iter().filter(|(ai, ..)| on(*ai)).map(|(_, e, ..)| e).collect())
}

/// Whether one of `under` (part `ai`'s openings) is genuine and under an epoch of `t`
/// established here now: its delta checked against the header, else equal to the held delta.
fn established_genuine(tx: &mut Tx<'_>, c: &CommitId, ai: usize, t: &Tid, mut under: Vec<Opening>) -> Result<bool> {
    under.retain(|(_, e, ..)| tx.core.read_established(t, e));
    if under.iter().any(|(_, _, g, _)| *g) {
        return Ok(true);
    }
    if under.is_empty() {
        return Ok(false);
    }
    let Some(held) = tx.get_commit(c)? else { return Ok(false) };
    let Some(p) = held.parts.iter().find(|p| p.ai == ai) else { return Ok(false) };
    let h = osis_base::hash::hash(&p.delta);
    Ok(under.iter().any(|(.., x)| *x == h))
}

/// Whether this node may encrypt part `ai` (on aspect `ak` of thing `t`) of held commit `c`
/// under an epoch of its own choosing (the module's invariant): not content, its own write,
/// one of whose content nothing is held (value-less, or dropped), or one it opened a genuine
/// section of under an epoch established here now, or read in no section.
pub(crate) fn passes_on(tx: &mut Tx<'_>, c: &CommitId, ai: usize, t: &Tid, ak: &str) -> Result<bool> {
    if !is_content(ak) {
        return Ok(true);
    }
    if tx.core.ix.commits.get(c).is_some_and(|m| m.origin == Origin::Local || matches!(m.hold.get(ai), Some(Hold::Leftover { valued: false, .. } | Hold::Dropped(_)))) {
        return Ok(true);
    }
    let under = openings(tx, c, Some(ai))?;
    // read in no section: it came to this node directly, under no epoch (an inbox payload, a
    // direct connection; neither carries another's content in node-sync)
    if under.is_empty() {
        return Ok(true);
    }
    established_genuine(tx, c, ai, t, under)
}

/// Whether this node may wrap a blob of commit `c` (its header) under an epoch of its own
/// choosing: its own, one with no content part, or one each of whose content parts it opened
/// has a genuine opening under an epoch established here now (a part dropped or held
/// value-less keeps none: Open paths in issues/reseal-under-own-epoch-leaks.md).
fn header_passes(tx: &mut Tx<'_>, c: &CommitId, h: &osis_commit::Header) -> Result<bool> {
    if tx.core.ix.commits.get(c).is_some_and(|m| m.origin == Origin::Local) {
        return Ok(true);
    }
    let content: Vec<(usize, Tid)> = h.aspects.iter().enumerate().filter(|(_, a)| is_content(a.ak.as_str())).map(|(ai, a)| (ai, a.tid)).collect();
    if content.is_empty() {
        return Ok(true);
    }
    let all = openings(tx, c, None)?;
    for (ai, t) in content {
        let under: Vec<_> = all.iter().filter(|r| r.0 == ai).cloned().collect();
        if under.is_empty() {
            continue;
        }
        if !established_genuine(tx, c, ai, &t, under)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Removes the openings of commit `c` (`Tx::remove_commit`, a pending copy thrown out).
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
    /// Whether this node may wrap a blob of commit `c` carrying parts `ais` under an epoch of its
    /// choosing (the wrap gates the header, and a copy's whole content): `passes_on` for each,
    /// and `header_passes`.
    pub(super) fn passes_on_parts(&mut self, c: &CommitId, ais: &[usize]) -> Result<bool> {
        let c = *c;
        let Some(h) = self.header(&c) else { return Ok(true) };
        self.read(|tx| {
            for ai in ais {
                let Some(a) = h.aspects.get(*ai) else { continue };
                if !passes_on(tx, &c, *ai, &a.tid, a.ak.as_str())? {
                    return Ok(false);
                }
            }
            header_passes(tx, &c, &h)
        })
    }

    /// `passes_on` for each part of `ais` of commit `c` (header `h`; a fresh encryption's
    /// section).
    pub(super) fn passes_on_all(&mut self, c: &CommitId, h: &osis_commit::Header, ais: &[usize]) -> Result<bool> {
        let c = *c;
        self.read(|tx| {
            for ai in ais {
                let Some(a) = h.aspects.get(*ai) else { return Ok(false) };
                if !passes_on(tx, &c, *ai, &a.tid, a.ak.as_str())? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }
}
