//! Notices (spec/permissions.md §4 Notices): how a holder that lost read on a thing X learns its
//! removal by X's sync ID alone. Per commit c taking read from a holder M of X (the first applied
//! write on M's edge leaving it below read after the newest giving it read), each reader of X
//! judging M departed logs one notice under X's sync ID: c's certificate copy on X (its edge-class
//! parts), the copies of its evidence and their records, under a fresh blob key wrapped as any
//! entry (X's readers open it as they may encrypt now, never by an epoch M or an earlier departed
//! reader holds), that key sealed to M's own read KEM key (`rotation::members::notice_keyset`):
//! only M's readers open it otherwise. A departed member is served the notices of its removals
//! and the public's edge alone (spec/sync-opens.md §6, `departed_shown`).
//!
//! A notice is no entry of its commit: it competes with none, and one is kept per (thing,
//! commit, holder, holder's keyset) as sync copies are (one log of each content, `content`). Rows
//! (`NOTICES`: one per blob, sealed here or opened) name what each is, across a restart, whoever
//! logged it.
//!
//! Who writes the input: c and the giving write are applied edge writes (X's admins); M's keysets
//! are M's rotators'. Any reader of X may seal a notice; one counts as the sealed copy it carries
//! is judged (`Engine::open_notice`): a forged one gives nothing, and a reader holding its key
//! counts it only where its box is that key sealed to the holder it names
//! (`osis_blob::open_notice`), so a forged one keeps no reader from logging the real one.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid};
use osis_crypto::Epoch;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// `nt/` + blob ID: the notice it is (`encode`).
pub(crate) const NOTICES: &[u8] = b"nt/";

/// What a notice blob is: removal `commit` of `holder` from `thing`, sealed to `holder`'s read
/// keyset at `epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Notice {
    pub thing: Tid,
    pub commit: CommitId,
    pub holder: Tid,
    pub epoch: Epoch,
}

impl Notice {
    /// Its content key: one notice of each logged (`Engine::notices_carried`).
    pub fn content(&self) -> [u8; 32] {
        let e = [self.epoch.n().to_be_bytes().as_slice(), self.epoch.nonce()].concat();
        osis_base::hash::hash(&[b"notice".as_slice(), self.thing.as_bytes(), &self.commit.0, self.holder.as_bytes(), &e].concat())
    }
}

fn encode(n: &Notice) -> Vec<u8> {
    [n.thing.as_bytes().as_slice(), &n.commit.0, n.holder.as_bytes(), &n.epoch.n().to_be_bytes(), n.epoch.nonce()].concat()
}

fn decode(v: &[u8]) -> Option<Notice> {
    let (t, rest) = v.split_at_checked(15)?;
    let (c, rest) = rest.split_at_checked(32)?;
    let (h, rest) = rest.split_at_checked(15)?;
    let (n, nonce) = rest.split_at_checked(8)?;
    let epoch = Epoch::new(u64::from_be_bytes(n.try_into().ok()?), nonce.try_into().ok()?).ok()?;
    Some(Notice { thing: Tid::from_bytes(t.try_into().ok()?), commit: CommitId(c.try_into().ok()?), holder: Tid::from_bytes(h.try_into().ok()?), epoch })
}

/// Loads the notice rows (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("notice row");
    let rows = tx.scan_rows(NOTICES, |k, v| {
        let b = BlobId(k.try_into().map_err(|_| bad())?);
        Ok((b, decode(&v).ok_or_else(bad)?))
    })?;
    for (b, n) in rows {
        tx.core.ix.notices.insert(b, n);
    }
    Ok(())
}

pub(crate) fn note(tx: &mut Tx<'_>, b: &BlobId, n: Notice) -> Result<()> {
    if tx.core.ix.notices.get(b) == Some(&n) {
        return Ok(());
    }
    tx.txn.put_local(&[NOTICES, &b.0].concat(), &encode(&n), Shred::No)?;
    tx.core.ix.notices.insert(*b, n);
    Ok(())
}

impl Engine {
    /// The notices sync ID `s` carries here, by content (`Notice::content`): per independent thing
    /// X reading `s` and each departure from X's read this node knows whose edge shows the commit
    /// taking it (`taking`), the notice of that commit to the departed holder's read keyset this
    /// node seals to (`rotation::members::notice_keyset`). None of an own thing's: a node judging
    /// its own removal erases X.
    pub fn notices_carried(&mut self, s: &SyncId) -> Result<BTreeMap<[u8; 32], Notice>> {
        let mut out = BTreeMap::new();
        for t in self.read_things_of(s)? {
            if self.core.secret_actor(&t) != Some(t) {
                continue;
            }
            let deps = self.read(|tx| crate::rotation::departures::departures(tx, &t))?;
            let deps: Vec<_> = deps.iter().filter(|d| d.concerns(Role::Read) && !self.core.is_own(&d.holder)).cloned().collect();
            let mut told: Vec<(CommitId, Tid)> = Vec::new();
            for d in deps {
                let Some(c) = d.edge.as_ref().and_then(taking) else { continue };
                if self.core.ix.commits.contains_key(&c) {
                    told.push((c, d.holder));
                }
            }
            told.extend(self.boxed_unopened(&t)?);
            for (c, holder) in told {
                let Some((epoch, _)) = self.read(|tx| crate::rotation::members::notice_keyset(tx, &t, &holder))? else { continue };
                let n = Notice { thing: t, commit: c, holder, epoch };
                out.insert(n.content(), n);
            }
        }
        Ok(out)
    }

    /// The held role commits on independent thing `t` with each current holder of `t` they box
    /// that cannot open them by their wrap as this node wraps them (`wrapped_at`): one that no
    /// other held commit boxes at read at that epoch (a grantee, a re-sealed holder left out
    /// before, a sync-only holder, one a rotation boxes after leaving it out of the epoch it
    /// supersedes; `t`'s mint admin reads an epoch derived from its own), where no commit boxes
    /// the public there (its box is every party's). Never the public nor an own thing.
    /// Cost: every `secrets.0` piece of `t` held, read once per call.
    fn boxed_unopened(&mut self, t: &Tid) -> Result<Vec<(CommitId, Tid)>> {
        let mut out = Vec::new();
        let current: BTreeSet<Tid> = self.core.key_holders(t).into_iter().map(|(m, _)| m).filter(|m| !m.is_public() && m != t && !self.core.is_own(m)).collect();
        if current.is_empty() {
            return Ok(out);
        }
        let Ok(ak) = osis_base::Ak::new("secrets.0") else { return Ok(out) };
        let cs: Vec<CommitId> = self.core.ix.by_aspect.get(&(*t, ak)).into_iter().flatten().map(|(_, c)| *c).collect();
        // per commit, the read epochs it boxes each holder at
        let mut boxes: BTreeMap<CommitId, BTreeMap<Tid, BTreeSet<Epoch>>> = BTreeMap::new();
        for c in &cs {
            let Some(h) = self.header(c) else { continue };
            let pieces: Vec<usize> = h.aspect_parts(t, "secrets.0").collect();
            let id = *c;
            let at = self.read(|tx| {
                let mut w: BTreeMap<Tid, BTreeSet<Epoch>> = BTreeMap::new();
                for ai in &pieces {
                    let Some(f) = crate::apply::held_fragment(tx, &id, *ai)? else { continue };
                    for k in crate::apply::keys::secrets_write(&f).boxes.keys() {
                        let e = osis_keys::aspects::from_schema(&k.epoch);
                        if let (Role::Read, Ok(e)) = (k.role, e) {
                            w.entry(k.holder.0).or_default().insert(e);
                        }
                    }
                }
                Ok(w)
            })?;
            boxes.insert(id, at);
        }
        // per holder, the newest removal of it from `t` here (its `ts`): a box written before it is
        // no secret it holds (it dropped what the removal took)
        let mut removed: BTreeMap<Tid, osis_base::Ts> = BTreeMap::new();
        if let Some(tl) = self.core.timelines().get(t) {
            for (mc, o) in tl.applied_on(t) {
                if let (Some(h), true) = (o.holder.thing(), o.edge.as_ref().is_none_or(|e| e.role < Role::Read)) {
                    let ts = self.header(&mc.id).map(|x| x.ts);
                    if let Some(ts) = ts {
                        let e = removed.entry(h).or_insert(ts);
                        *e = (*e).max(ts);
                    }
                }
            }
        }
        let ts_of: BTreeMap<CommitId, osis_base::Ts> = boxes.keys().filter_map(|c| Some((*c, self.header(c)?.ts))).collect();
        let boxed_by_another = |c: &CommitId, m: &Tid, e: &Epoch| boxes.iter().any(|(o, w)| o != c && w.get(m).is_some_and(|es| es.contains(e)) && removed.get(m).is_none_or(|r| ts_of.get(o).is_some_and(|ts| ts > r)));
        for c in &cs {
            let named = self.holders_named(c);
            let Some(h) = self.header(c) else { continue };
            let boxed: BTreeSet<Tid> = h.aspect_parts(t, "secrets.0").filter_map(|ai| named.get(&ai)).flatten().filter(|m| current.contains(*m)).copied().collect();
            if boxed.is_empty() {
                continue;
            }
            let Some(e) = self.wrapped_at(t, c)? else { continue };
            // an epoch derived from the mint admin's is no epoch of `t`'s own: its holders read it
            // by derivation
            if boxed_by_another(c, &Tid::PUBLIC, &e) {
                continue;
            }
            // an epoch derived from the mint admin's: the mint admin reads it so
            let up = self.core.created(t).and_then(osis_base::CreationRecord::mint_admin);
            let derived = up.and_then(|up| self.epochs(&up)).is_some_and(|x| osis_keys::ActorEpochs::derived(&x, t).read.secret(&e).is_some());
            out.extend(boxed.into_iter().filter(|m| !boxed_by_another(c, m, &e) && !(derived && Some(*m) == up)).map(|m| (*c, m)));
        }
        Ok(out)
    }

    /// The notice rows of the things reading `s`.
    pub fn notice_rows(&mut self, s: &SyncId) -> BTreeMap<BlobId, Notice> {
        let things = self.read_things_of(s).unwrap_or_default();
        self.core.ix.notices.iter().filter(|(_, n)| things.contains(&n.thing)).map(|(b, n)| (*b, *n)).collect()
    }

    /// The notice blob `b` is, noted here.
    pub fn notice_of(&self, b: &BlobId) -> Option<Notice> {
        self.core.ix.notices.get(b).copied()
    }

    /// A fresh blob of the notice of content `key` that `s` carries (`notices_carried`), its row
    /// taken as this node's, with its wrap under the thing's read epoch this node encrypts under
    /// now (`wrap_secret`): `None` where `s` carries none such, its commit is not applied here or
    /// no epoch may be encrypted under.
    pub fn seal_notice(&mut self, s: &SyncId, key: &[u8; 32], rng: &mut dyn osis_crypto::NodeRng) -> Result<Option<(BlobId, Vec<u8>, crate::sync::Wrap)>> {
        let Some(n) = self.notices_carried(s)?.get(key).copied() else { return Ok(None) };
        let Some(w) = self.wrap_secret(&n.thing, None)? else { return Ok(None) };
        let Some((_, kem)) = self.read(|tx| crate::rotation::members::notice_keyset(tx, &n.thing, &n.holder))? else { return Ok(None) };
        let blob_key = osis_crypto::Secret32::random(rng);
        let Some(blob) = self.sealed_notice(&n, &kem, &blob_key)? else { return Ok(None) };
        let id = osis_blob::blob_id(&blob);
        let wrap = osis_crypto::wrap(&w, &id, &blob_key, 0)?;
        self.run(|tx| note(tx, &id, n))?;
        Ok(Some((id, blob, wrap)))
    }

    /// No store entry names blob `b` any more: its notice row, if any, goes.
    pub(crate) fn unnamed_notice(&mut self, b: &BlobId) -> Result<()> {
        if !self.core.ix.notices.contains_key(b) {
            return Ok(());
        }
        let b = *b;
        self.run(|tx| {
            tx.txn.remove_local(&[NOTICES, &b.0].concat(), Shred::No)?;
            tx.core.ix.notices.remove(&b);
            Ok(())
        })
    }

    /// The removals of `s`'s things whose notices a peer proving `proven` is served
    /// (spec/sync-opens.md §6, `tells`).
    pub fn told(&mut self, s: &SyncId, proven: &BTreeSet<Tid>) -> Result<BTreeSet<CommitId>> {
        Ok(self.notice_rows(s).into_values().filter(|n| self.tells(n, proven)).map(|n| n.commit).collect())
    }

    /// Whether held blob `b` under `s` is a notice telling a peer proving `proven` (`told`).
    pub fn notice_tells(&mut self, s: &SyncId, b: &BlobId, proven: &BTreeSet<Tid>) -> bool {
        let Some(n) = self.notice_of(b) else { return false };
        self.read_things_of(s).is_ok_and(|t| t.contains(&n.thing)) && self.tells(&n, proven)
    }

    /// Whether held blob `b` under `s` is shown a peer proving `proven` that this node judges
    /// departed (spec/sync-opens.md §6): a notice telling it (`notice_tells`), or a blob of a
    /// commit of the public's edge on `s`'s things (`public_edge`): the public's role is every
    /// party's, that peer's too.
    pub fn departed_shown(&mut self, s: &SyncId, b: &BlobId, proven: &BTreeSet<Tid>) -> bool {
        self.notice_tells(s, b, proven) || self.blob_commit(b).is_some_and(|c| self.public_edge(s).is_ok_and(|e| e.contains(&c)))
    }

    /// Whether notice `n`'s commit applies a write leaving its holder below read, and that holder
    /// is among `proven` or a proven thing held read or above on it just before: a peer that
    /// opens it (by the holder's read keys).
    /// Invariant (privacy; spec/sync-hostile.md): a departed peer is told no removal past its own:
    /// one it read the thing through when made, never one of a holder it had left by then. The
    /// holder a notice names is its sealer's word (any reader of the thing may seal one), so it
    /// counts only where the commit removes that holder: a notice naming M on another holder's
    /// removal tells M nothing, nor sets M's `until`.
    fn tells(&self, n: &Notice, proven: &BTreeSet<Tid>) -> bool {
        let Some(tl) = self.core.timelines().get(&n.thing) else { return false };
        let removes = |o: &osis_perm::EdgeOp| o.holder.thing() == Some(n.holder) && o.edge.as_ref().is_none_or(|e| e.role < Role::Read);
        let Some(at) = tl.applied_on(&n.thing).find(|(mc, o)| mc.id == n.commit && removes(o)).map(|(mc, _)| osis_perm::At::before(mc.point())) else { return false };
        proven.contains(&n.holder) || tl.roles_on(&n.holder, at).iter().any(|(p, r)| proven.contains(p) && *r >= Role::Read)
    }
}

/// On a holder's edge log, the commit taking its read: the first applied write leaving it below
/// read after the newest giving it read (or after its start).
fn taking(log: &osis_keys::EdgeLog) -> Option<CommitId> {
    let after = match log.writes.iter().rposition(|w| w.applied && w.role >= Some(Role::Read)) {
        Some(i) => log.writes.get(i + 1..)?,
        None if log.start >= Some(Role::Read) => log.writes.as_slice(),
        None => return None,
    };
    after.iter().find(|w| w.applied && w.role < Some(Role::Read)).map(|w| w.key.commit)
}
