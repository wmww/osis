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
//! Every path that reads another's content notes the epoch it came under: a section's, a copy's
//! (its entry's wrap), a sealed fire's (the keyset it is sealed to, `open_sealed_fire`). A part
//! of another's with no opening held passes on nowhere (fail closed). Openings are never lost
//! in between: they are written in the ingest that keeps the commit (held or pending), and one
//! that keeps nothing is fetched and opened again.
//!
//! A header is read by whoever unwraps an entry of the commit's blob, so the epoch an entry's wrap
//! opened under (`note_unwrapped`, per thing of the sync ID) is an opening of the header: a
//! header this node read only under epochs not established here is wrapped by it under none of
//! its own (`header_passes`), whether it came header-only or its parts were dropped since.
//!
//! Storage: an opening rides in memory (`Core::openings`) from `Engine::open_commit` to the
//! commit's next ingest, which writes it where the commit is then held or pending and the
//! epoch's thing's record is held (`persist`) and lets go of it whatever the outcome; rows go
//! with the commit's record (`Tx::remove_commit`) or its pending copy thrown out unapplied
//! (`drop_pending`), and those under an epoch of a thing with the thing (`forget_thing`: an epoch
//! of a thing whose record is not held is established nowhere, so its openings are as never
//! made). Rows are indexed by thing (`Indexes::opened_under`). Memory is bounded by the commits
//! opened and not yet ingested, plus held and pending commits opened again whose rows were not
//! yet written.

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

/// A section's opening, per part: its epoch with the thing it is an epoch of (the part's,
/// derived for a dependent thing; a copy's, the sync ID's) and the hash of the delta it carried,
/// checked against the header when `genuine`. An epoch names no thing (a rotation commit's
/// keyset may name another thing's epoch), so the thing is part of the opening.
fn key(c: &CommitId, ai: u32, t: &Tid, e: &Epoch) -> Vec<u8> {
    [records::OPENED_UNDER, c.0.as_slice(), &ai.to_be_bytes(), t.as_bytes(), &e.n().to_be_bytes(), e.nonce()].concat()
}

/// The thing an `OPENED_UNDER` key (past the prefix) names.
fn key_thing(k: &[u8]) -> Option<Tid> {
    k.get(36..51).and_then(|b| <[u8; 15]>::try_from(b).ok()).map(Tid::from_bytes)
}

/// Writes row (`k`, `v`) of commit `c`, indexed by its thing.
fn put(tx: &mut Tx<'_>, c: &CommitId, k: &[u8], v: &[u8]) -> Result<()> {
    tx.txn.put_local(k, v, Shred::No)?;
    if let Some(t) = k.get(records::OPENED_UNDER.len()..).and_then(key_thing) {
        tx.core.ix.opened_under.insert(t, *c);
    }
    Ok(())
}

/// Removes commit `c`'s rows `gone` (whole keys), and the index of each thing no row of `c`
/// stays under.
fn remove(tx: &mut Tx<'_>, c: &CommitId, gone: Vec<Vec<u8>>) -> Result<()> {
    if gone.is_empty() {
        return Ok(());
    }
    let prefix = [records::OPENED_UNDER, c.0.as_slice()].concat();
    let gone: std::collections::BTreeSet<Vec<u8>> = gone.into_iter().collect();
    let mut things = std::collections::BTreeSet::new();
    let mut left = std::collections::BTreeSet::new();
    tx.scan(&prefix, |k, _| {
        let t = k.get(4..19).and_then(|b| <[u8; 15]>::try_from(b).ok()).map(Tid::from_bytes);
        match gone.contains(&[prefix.as_slice(), k].concat()) {
            true => things.extend(t),
            false => left.extend(t),
        }
        Ok(())
    })?;
    for k in &gone {
        tx.txn.remove_local(k, Shred::Yes)?;
    }
    for t in things.difference(&left) {
        tx.core.ix.opened_under.remove(t, c);
    }
    Ok(())
}

/// Loads `Indexes::opened_under` (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(records::OPENED_UNDER, |k, _| {
        let c = k.get(..32).and_then(|b| <[u8; 32]>::try_from(b).ok()).map(CommitId);
        if let (Some(c), Some(t)) = (c, key_thing(k)) {
            rows.push((t, c));
        }
        Ok(())
    })?;
    for (t, c) in rows {
        tx.core.ix.opened_under.insert(t, c);
    }
    Ok(())
}

fn part_index(ai: usize) -> u32 {
    u32::try_from(ai).unwrap_or(u32::MAX)
}

/// The part index a header opening's key carries in place of a part's (`note_unwrapped`).
const HEADER: u32 = u32::MAX;

fn value(genuine: bool, delta: &[u8]) -> Vec<u8> {
    [&[u8::from(genuine)][..], &osis_base::hash::hash(delta)].concat()
}

impl Core {
    /// The floor of read epoch `ep` of thing `t` as this node reads it (spec/crypto.md §4,
    /// Floors; a dependent thing's, its base epoch's): 0 where unknown.
    pub(crate) fn read_floor(&self, t: &Tid, ep: &Epoch) -> u64 {
        self.epochs(t).map_or(0, |e| e.read.floor(ep))
    }

    /// The epoch this node seals `t`'s content under now (its newest current read epoch held,
    /// spec/crypto.md §5) with its floor.
    pub(crate) fn seal_epoch(&self, t: &Tid) -> Option<(Epoch, u64)> {
        let e = self.epochs(t)?;
        let ep = osis_keys::wrap_epoch(&e.read)?;
        Some((ep, e.read.floor(&ep)))
    }

    /// Whether read epoch `ep` of thing `t` (own, or derived from its mint admin's) is
    /// established here (spec/crypto.md §4).
    fn read_established(&self, t: &Tid, ep: &Epoch) -> bool {
        let own = |e: &ActorEpochs| e.read.is_established(ep);
        if self.epochs(t).or_else(|| self.ix.secrets.get(t).map(|x| std::sync::Arc::new(x.clone()))).is_some_and(|e| own(&e)) {
            return true;
        }
        let Some(up) = self.created(t).and_then(osis_base::CreationRecord::mint_admin) else { return false };
        self.epochs(&up).is_some_and(|o| own(&ActorEpochs::derived(&o, t)))
    }
}

impl Engine {
    /// The read epochs of thing `t` held here with their secrets: its own (or its derived ones),
    /// those derived from its mint admin's, and those derived down a section's chain
    /// (`chain_epochs`): every secret `open_commit` tries.
    pub(crate) fn read_epochs(&self, t: &Tid, chain: &[Tid]) -> Vec<(Epoch, osis_crypto::Secret32)> {
        let mut out: Vec<(Epoch, osis_crypto::Secret32)> = self.epochs(t).map(|e| e.read.held().map(|(ep, s)| (ep, s.clone())).collect()).unwrap_or_default();
        let mut from = |e: &ActorEpochs| {
            for (ep, s) in ActorEpochs::derived(e, t).read.held() {
                if !out.iter().any(|x| x.0 == ep) {
                    out.push((ep, s.clone()));
                }
            }
        };
        if let Some(up) = self.core.created(t).and_then(osis_base::CreationRecord::mint_admin)
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
    pub(crate) fn note_opened(&mut self, header: &osis_commit::Header, opened: &[(Tid, Epoch, Vec<&osis_commit::Part>)]) {
        let id = header.id();
        if self.core.ix.commits.get(&id).is_some_and(|m| m.origin == Origin::Local) {
            return;
        }
        let mut rows = Vec::new();
        for (t, e, parts) in opened {
            for p in parts {
                // content and mintings only: the rest is settings, keys and boxes (each box
                // sealed to its own recipient)
                let Some(a) = header.aspects.get(p.ai).filter(|a| floored(a.ak.as_str())) else { continue };
                let genuine = self.core.created(&a.tid).is_some_and(|r| osis_crypto::delta_hash(&osis_crypto::dedup_secret(r.nonce()), &p.delta) == a.hash);
                rows.push((key(&id, part_index(p.ai), t, e), value(genuine, &p.delta)));
            }
        }
        self.keep_openings(&id, rows);
    }

    /// Records that an entry's wrap of a blob of commit `c` (another's) opened under read epoch
    /// `e` of thing `t`, the sync ID's: an opening of its header (`header_passes`), kept like a
    /// section's (`Core::openings` until the commit's next ingest writes it).
    pub(crate) fn note_unwrapped(&mut self, c: &CommitId, t: &Tid, e: &Epoch) {
        if self.core.ix.commits.get(c).is_some_and(|m| m.origin == Origin::Local) {
            return;
        }
        self.keep_openings(c, vec![(key(c, HEADER, t, e), vec![1])]);
    }

    /// Keeps `rows` of commit `id` in memory until its next ingest writes them: of a held or
    /// pending commit opened again, only what its rows lack.
    fn keep_openings(&mut self, id: &CommitId, mut rows: Rows) {
        let id = *id;
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

/// Whether a part of aspect `ak` has its openings recorded (`part_floor`): content, which the
/// floor clause of `passes_on` reads, and a minting, whose floor decides whether its body carries
/// its thing's record to a holder granted without history (`Engine::cert_carriers`).
fn floored(ak: &str) -> bool {
    is_content(ak) || ak == osis_commit::retention::CREATED
}

/// Records the epoch each content part and minting of `c`, this node's own new commit, was made
/// under: the newest current read epoch of its thing, where its floor is above 0 (a part with no
/// record has floor 0, so a node never cut writes nothing here).
pub(crate) fn note_own(tx: &mut Tx<'_>, c: &osis_commit::CommitBlob) -> Result<()> {
    let id = c.id();
    for p in &c.parts {
        let Some(a) = c.header.aspects.get(p.ai).filter(|a| floored(a.ak.as_str())) else { continue };
        let Some((e, f)) = tx.core.seal_epoch(&a.tid) else { continue };
        if f > 0 {
            put(tx, &id, &key(&id, part_index(p.ai), &a.tid, &e), &value(true, &p.delta))?;
        }
    }
    Ok(())
}

/// Writes the openings of commit `c` not yet written, where `c` is held or pending (the end of
/// its ingest's transaction).
pub(crate) fn persist(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    if !tx.core.ix.commits.contains_key(c) && !tx.core.ix.pending.contains_key(c) {
        return Ok(());
    }
    for (k, v) in tx.core.openings.get(c).cloned().into_iter().flatten() {
        let held = k.get(records::OPENED_UNDER.len()..).and_then(key_thing).is_some_and(|t| tx.core.created(&t).is_some());
        if held && tx.txn.get_local(&k)?.is_none() {
            put(tx, c, &k, &v)?;
        }
    }
    Ok(())
}

/// Lets go of the rows of commit `c`'s parts held with no content (dropped, or value-less):
/// nothing of them is encrypted again, and kept they would follow the bodies' churn
/// (`Tx::put_commit`, with its record `m`).
pub(crate) fn prune(tx: &mut Tx<'_>, c: &CommitId, m: &crate::engine::Meta) -> Result<()> {
    let empty = |ai: usize| matches!(m.hold(ai), Some(Hold::Leftover { valued: false, .. } | Hold::Dropped(_)));
    if !(0..m.parts()).any(empty) {
        return Ok(());
    }
    remove_where(tx, c, |k| k.get(..4).and_then(|b| b.try_into().ok()).map(u32::from_be_bytes).is_some_and(|ai| empty(ai as usize)))
}

/// One opening of a part: the part, the thing its epoch is of, the epoch, whether its delta was
/// checked against the header, and the delta's hash.
type Opening = (usize, Tid, Epoch, bool, [u8; 32]);

/// One `OPENED_UNDER` row: its index (a part's, or `HEADER`), thing, epoch and value.
type Row = (u32, Tid, Epoch, Vec<u8>);

/// The `OPENED_UNDER` rows of commit `c` recorded here, written or not (`ai`: of that index
/// alone, `HEADER` for header openings).
fn rows(tx: &mut Tx<'_>, c: &CommitId, ai: Option<u32>) -> Result<Vec<Row>> {
    let whole = [records::OPENED_UNDER, c.0.as_slice()].concat();
    let mut prefix = whole.clone();
    if let Some(ai) = ai {
        prefix.extend_from_slice(&ai.to_be_bytes());
    }
    let row = |k: &[u8], v: &[u8]| -> Result<Row> {
        let bad = || Error::Corrupt("opened under");
        let (ai, rest) = k.split_at_checked(4).ok_or_else(bad)?;
        let (t, rest) = rest.split_at_checked(15).ok_or_else(bad)?;
        let (n, nonce) = rest.split_at_checked(8).ok_or_else(bad)?;
        let e = Epoch::new(u64::from_be_bytes(n.try_into().map_err(|_| bad())?), nonce.try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        Ok((u32::from_be_bytes(ai.try_into().map_err(|_| bad())?), Tid::from_bytes(t.try_into().map_err(|_| bad())?), e, v.to_vec()))
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
            if !out.iter().any(|x| (x.0, x.1, x.2) == (r.0, r.1, r.2)) {
                out.push(r);
            }
        }
    }
    Ok(out)
}

/// The openings of commit `c`'s parts recorded here, written or not (`ai`: of that part alone).
fn openings(tx: &mut Tx<'_>, c: &CommitId, ai: Option<usize>) -> Result<Vec<Opening>> {
    let mut out = Vec::new();
    for (i, t, e, v) in rows(tx, c, ai.map(part_index))? {
        if i == HEADER {
            continue;
        }
        let (g, h) = v.split_first().ok_or(Error::Corrupt("opened under"))?;
        out.push((i as usize, t, e, *g == 1, h.try_into().map_err(|_| Error::Corrupt("opened under"))?));
    }
    Ok(out)
}

/// The header openings of commit `c` recorded here, written or not (`note_unwrapped`): per row
/// the sync ID's thing and the epoch an entry's wrap opened under.
fn header_openings(tx: &mut Tx<'_>, c: &CommitId) -> Result<Vec<(Tid, Epoch)>> {
    Ok(rows(tx, c, Some(HEADER))?.into_iter().map(|(_, t, e, _)| (t, e)).collect())
}

/// Whether one of `under` (part `ai`'s openings) is genuine and under an epoch of `t`
/// established here now: its delta checked against the header, else equal to the held delta.
fn established_genuine(tx: &mut Tx<'_>, c: &CommitId, ai: usize, t: &Tid, mut under: Vec<Opening>) -> Result<bool> {
    under.retain(|o| o.1 == *t && tx.core.read_established(t, &o.2));
    if under.iter().any(|o| o.3) {
        return Ok(true);
    }
    if under.is_empty() {
        return Ok(false);
    }
    let Some(held) = tx.get_commit(c)? else { return Ok(false) };
    let Some(p) = held.parts.iter().find(|p| p.ai == ai) else { return Ok(false) };
    let h = osis_base::hash::hash(&p.delta);
    Ok(under.iter().any(|o| o.4 == h))
}

/// Whether this node may encrypt part `ai` (on aspect `ak` of thing `t`) of held commit `c`
/// under an epoch of its own choosing of floor `floor` (`None`: a snapshot, which carries state:
/// the floor clause binds it not): not content, or one of whose content nothing is held
/// (`holds_no_content`); else, where `floor` is above 0, only by an opening (its own write's
/// record, `note_own`) under an epoch of at least that floor; and its own write, or one it
/// opened a genuine section of under an epoch established here now (the module's invariant).
pub(crate) fn passes_on(tx: &mut Tx<'_>, c: &CommitId, ai: usize, t: &Tid, ak: &str, floor: Option<u64>) -> Result<bool> {
    if !is_content(ak) {
        return Ok(true);
    }
    if holds_no_content(tx, c, ai) {
        return Ok(true);
    }
    let own = tx.core.ix.commits.get(c).is_some_and(|m| m.origin == Origin::Local);
    let under = openings(tx, c, Some(ai))?;
    let Some(under) = above_floor(tx, t, under, floor) else { return Ok(false) };
    Ok(own || established_genuine(tx, c, ai, t, under)?)
}

/// Whether held commit `c` holds no content of part `ai`: dropped, held value-less, or missing
/// (nothing of it to pass on).
fn holds_no_content(tx: &Tx<'_>, c: &CommitId, ai: usize) -> bool {
    tx.core.ix.commits.get(c).is_some_and(|m| matches!(m.hold(ai), Some(Hold::Leftover { valued: false, .. } | Hold::Dropped(_) | Hold::Missing(_))))
}

/// The floor clause: of `under` (a part's openings), those under an epoch of thing `t` whose
/// floor is at least `floor`; `None` where `floor` is above 0 and none is (the part was written
/// below it, or its epoch is unknown). Every opening where `floor` is `None` or 0.
fn above_floor(tx: &Tx<'_>, t: &Tid, mut under: Vec<Opening>, floor: Option<u64>) -> Option<Vec<Opening>> {
    let Some(f) = floor.filter(|f| *f > 0) else { return Some(under) };
    under.retain(|o| o.1 == *t && tx.core.read_floor(t, &o.2) >= f);
    (!under.is_empty()).then_some(under)
}

/// A wrap under an epoch this node chooses: of thing `thing` (the sync ID's), whose independent
/// is `actor`, at that epoch's floor `floor`.
pub(super) struct Wrapping {
    pub thing: Tid,
    pub actor: Tid,
    pub floor: u64,
}

/// Whether part `ai` of commit `c` has a genuine opening under an epoch of the wrap's own thing
/// established here now, of floor at least the wrap's (a copy's section, opened under the epoch
/// its entry's wrap opened under, `Engine::open_entry`): this node knows every departure from
/// that thing the epoch covered, and the epoch it wraps under covers them, so the wrap passes
/// the part on as its epoch's own content would (spec/crypto.md §5 Passing on).
fn opened_under_wrap(tx: &mut Tx<'_>, c: &CommitId, ai: usize, w: &Wrapping) -> Result<bool> {
    let under = openings(tx, c, Some(ai))?;
    match above_floor(tx, &w.thing, under, Some(w.floor)) {
        Some(under) if !under.is_empty() => established_genuine(tx, c, ai, &w.thing, under),
        _ => Ok(false),
    }
}

/// Whether this node may wrap a blob of commit `c` (its header) under an epoch of its own
/// choosing (`w`): one with no content part, or one each of whose content parts it holds content
/// of (its own: any) has a genuine opening under an epoch established here now, of the part's thing or
/// of the wrap's (`opened_under_wrap`; a part dropped or held value-less keeps none); if an
/// entry's wrap of it opened here, one such wrap's epoch is established here now
/// (`note_unwrapped`: kept whatever is dropped); and every content part on a thing whose secrets
/// are the wrap actor's has an opening (or own record) under an epoch of floor at least the
/// wrap's: the header names the part's thing, aspect and delta hash.
fn header_passes(tx: &mut Tx<'_>, c: &CommitId, h: &osis_commit::Header, w: &Wrapping) -> Result<bool> {
    let own = tx.core.ix.commits.get(c).is_some_and(|m| m.origin == Origin::Local);
    let content: Vec<(usize, Tid)> = h.aspects.iter().enumerate().filter(|(_, a)| is_content(a.ak.as_str())).map(|(ai, a)| (ai, a.tid)).collect();
    if content.is_empty() {
        return Ok(true);
    }
    let wraps = header_openings(tx, c)?;
    if !wraps.is_empty() && !wraps.iter().any(|(t, e)| tx.core.read_established(t, e)) {
        return Ok(false);
    }
    let mut all: std::collections::BTreeMap<usize, Vec<Opening>> = std::collections::BTreeMap::new();
    for o in openings(tx, c, None)? {
        all.entry(o.0).or_default().push(o);
    }
    osis_base::costs::count("sync: header parts judged", content.len() as u64);
    for (ai, t) in content {
        let under = all.remove(&ai).unwrap_or_default();
        let f = (tx.core.secret_actor(&t) == Some(w.actor)).then_some(w.floor);
        let passes = match above_floor(tx, &t, under, f) {
            None => false,
            Some(under) => own || holds_no_content(tx, c, ai) || established_genuine(tx, c, ai, &t, under)?,
        };
        if !passes && !opened_under_wrap(tx, c, ai, w)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The floor of part `ai` (on thing `t`) of held commit `c` (spec/crypto.md §4 Floors): the
/// greatest floor of an epoch of `t` it was opened (or, this node's own, made) under, an opening
/// under another thing's (a copy's) counting 0; this node's own with no record has 0
/// (`note_own`), another's opened under no epoch none known.
pub(crate) fn part_floor(tx: &mut Tx<'_>, c: &CommitId, ai: usize, t: &Tid) -> Result<Option<u64>> {
    let under = openings(tx, c, Some(ai))?;
    let own = tx.core.ix.commits.get(c).is_some_and(|m| m.origin == Origin::Local);
    Ok(match under.iter().map(|o| if o.1 == *t { tx.core.read_floor(t, &o.2) } else { 0 }).max() {
        Some(f) => Some(f),
        None => own.then_some(0),
    })
}

/// Removes every opening under an epoch of thing `t`, whose record goes (`retention::needed`):
/// those of the commits that stay are as at a node that never opened them.
pub(crate) fn forget_thing(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let commits: Vec<CommitId> = tx.core.ix.opened_under.get(t).into_iter().flatten().copied().collect();
    for c in commits {
        remove_where(tx, &c, |k| k.get(4..19) == Some(t.as_bytes().as_slice()))?;
    }
    Ok(())
}

/// Removes the openings of commit `c` (`Tx::remove_commit`, a pending copy thrown out).
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    remove_where(tx, c, |_| true)
}

/// Removes the openings of commit `c` whose row key past the commit `drop` names.
fn remove_where(tx: &mut Tx<'_>, c: &CommitId, drop: impl Fn(&[u8]) -> bool) -> Result<()> {
    let prefix = [records::OPENED_UNDER, c.0.as_slice()].concat();
    let mut gone = Vec::new();
    tx.scan(&prefix, |k, _| {
        if drop(k) {
            gone.push([prefix.as_slice(), k].concat());
        }
        Ok(())
    })?;
    remove(tx, c, gone)
}

impl Engine {
    /// Whether this node may wrap a blob of commit `c` under an epoch of its choosing (`w`; the
    /// wrap gates the header, and a copy's whole content): `header_passes`. Every content part a
    /// blob carries is one of the header's, and passing the header's clauses it passes `passes_on`.
    pub(super) fn header_passes(&mut self, c: &CommitId, w: &Wrapping) -> Result<bool> {
        let c = *c;
        let Some(h) = self.header(&c) else { return Ok(true) };
        self.read(|tx| header_passes(tx, &c, &h, w))
    }

    /// `passes_on` for each part of `ais` of commit `c` (header `h`; a fresh encryption's
    /// section under an epoch of floor `floor`).
    pub(super) fn passes_on_all(&mut self, c: &CommitId, h: &osis_commit::Header, ais: &[usize], floor: u64) -> Result<bool> {
        let c = *c;
        self.read(|tx| {
            for ai in ais {
                let Some(a) = h.aspects.get(*ai) else { return Ok(false) };
                if !passes_on(tx, &c, *ai, &a.tid, a.ak.as_str(), Some(floor))? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }
}
