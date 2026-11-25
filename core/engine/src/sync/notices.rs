//! Notices (spec/permissions.md §4 Notices): how a holder that lost read on a thing X learns its
//! removal by X's sync ID alone. Per commit c taking read from a holder M of X (the first applied
//! write on M's edge leaving it below read after the newest giving it read), each reader of X
//! judging M departed logs one notice under X's sync ID: c's certificate copy on X (its edge-class
//! parts), the copies of its evidence and their records, as a sealed copy (spec/wire.md §9 form 1)
//! sealed to X's read key at c's **taking epoch**: the newest read epoch of X held here among
//! those the write giving M read boxed it (X's first epochs where none did: its start). A departed
//! member is served the notices of its removals alone (spec/sync-opens.md §6).
//!
//! A notice is no entry of its commit: it competes with none, and one is kept per (thing,
//! commit, epoch) as sync copies are (one log of each content, `content`). Rows (`NOTICES`: one
//! per blob, sealed here or opened) name what each is, across a restart, whoever logged it.
//!
//! Who writes the input: c and the giving write are applied edge writes (X's admins); the taking
//! epoch is one M holds, opening only c's role parts and the records and evidence judging it. Any
//! holder of that epoch may seal a notice; one counts as the sealed copy it carries is judged
//! (`Engine::open_sealed_fire`): a forged one gives nothing.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid};
use osis_crypto::Epoch;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// `nt/` + blob ID: the notice it is (`encode`).
pub(crate) const NOTICES: &[u8] = b"nt/";

/// What a notice blob is: removal `commit` of `thing`'s holder, sealed to `thing`'s read key at
/// `epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Notice {
    pub thing: Tid,
    pub commit: CommitId,
    pub epoch: Epoch,
}

impl Notice {
    /// Its content key: one notice of each logged (`Engine::notices_carried`).
    pub fn content(&self) -> [u8; 32] {
        let e = [self.epoch.n().to_be_bytes().as_slice(), self.epoch.nonce()].concat();
        osis_base::hash::hash(&[b"notice".as_slice(), self.thing.as_bytes(), &self.commit.0, &e].concat())
    }
}

fn encode(n: &Notice) -> Vec<u8> {
    [n.thing.as_bytes().as_slice(), &n.commit.0, &n.epoch.n().to_be_bytes(), n.epoch.nonce()].concat()
}

fn decode(v: &[u8]) -> Option<Notice> {
    let (t, rest) = v.split_at_checked(15)?;
    let (c, rest) = rest.split_at_checked(32)?;
    let (n, nonce) = rest.split_at_checked(8)?;
    let epoch = Epoch::new(u64::from_be_bytes(n.try_into().ok()?), nonce.try_into().ok()?).ok()?;
    Some(Notice { thing: Tid::from_bytes(t.try_into().ok()?), commit: CommitId(c.try_into().ok()?), epoch })
}

/// Loads the notice rows (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("notice row");
    let mut rows = Vec::new();
    tx.scan(NOTICES, |k, v| {
        let b = BlobId(k.try_into().map_err(|_| bad())?);
        rows.push((b, decode(&v).ok_or_else(bad)?));
        Ok(())
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
    /// taking it (`taking`), the notice of that commit at its taking epoch, where this node holds
    /// the epoch's read secret. None of an own thing's: a node judging its own removal erases X.
    pub fn notices_carried(&mut self, s: &SyncId) -> Result<BTreeMap<[u8; 32], Notice>> {
        let mut out = BTreeMap::new();
        for t in self.read_things_of(s)? {
            if self.core.secret_actor(&t) != Some(t) {
                continue;
            }
            let deps = self.read(|tx| crate::rotation::departures::departures(tx, &t))?;
            let deps: Vec<_> = deps.iter().filter(|d| d.concerns(Role::Read) && !self.core.is_own(&d.holder)).cloned().collect();
            for d in deps {
                let Some((c, giving)) = d.edge.as_ref().and_then(taking) else { continue };
                if !self.core.ix.commits.contains_key(&c) {
                    continue;
                }
                let Some(epoch) = self.taking_epoch(&t, &d.holder, giving)? else { continue };
                let n = Notice { thing: t, commit: c, epoch };
                out.insert(n.content(), n);
            }
        }
        Ok(out)
    }

    /// The taking epoch (module doc) of a removal of `m` from `t`: the newest read epoch of `t`
    /// whose secret is held here among those `giving` (the write giving `m` read; none: `t`'s
    /// start, its epochs of n 0) boxed `m`.
    fn taking_epoch(&mut self, t: &Tid, m: &Tid, giving: Option<CommitId>) -> Result<Option<Epoch>> {
        let held: Vec<Epoch> = self.read_epochs(t, &[]).into_iter().map(|(e, _)| e).collect();
        let boxed: Vec<Epoch> = match giving {
            None => held.iter().copied().filter(|e| e.n() == 0).collect(),
            Some(g) => {
                let Some(h) = self.header(&g) else { return Ok(None) };
                let mut out = Vec::new();
                for ai in h.aspect_parts(t, "secrets.0") {
                    let Some(f) = self.read(|tx| crate::apply::held_fragment(tx, &g, ai))? else { continue };
                    let w = crate::apply::keys::secrets_write(&f);
                    out.extend(w.boxes.keys().filter(|k| k.holder.0 == *m && k.role == Role::Read).filter_map(|k| osis_keys::aspects::from_schema(&k.epoch).ok()));
                }
                out
            }
        };
        Ok(boxed.into_iter().filter(|e| held.contains(e)).max_by_key(|e| (e.n(), *e.nonce())))
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
    /// taken as this node's, with a filler wrap (a sealed copy's, spec/crypto.md §5): `None` where
    /// `s` carries none such or its commit is not applied here.
    pub fn seal_notice(&mut self, s: &SyncId, key: &[u8; 32], rng: &mut dyn osis_crypto::NodeRng) -> Result<Option<(BlobId, Vec<u8>, crate::sync::Wrap)>> {
        let Some(n) = self.notices_carried(s)?.get(key).copied() else { return Ok(None) };
        let Some(secret) = self.read_epochs(&n.thing, &[]).into_iter().find(|(e, _)| *e == n.epoch).map(|(_, s)| s) else { return Ok(None) };
        let Some(blob) = self.sealed_notice(&n, secret.kem().public())? else { return Ok(None) };
        let id = osis_blob::blob_id(&blob);
        self.run(|tx| note(tx, &id, n))?;
        Ok(Some((id, blob, osis_crypto::filler_wrap(rng))))
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

    /// Whether notice `n`'s removal takes read from a holder among `proven`, or one a proven
    /// thing ever held a role on.
    fn tells(&self, n: &Notice, proven: &BTreeSet<Tid>) -> bool {
        let Some(tl) = self.core.timelines().get(&n.thing) else { return false };
        let reached = |h: Tid| proven.iter().any(|p| *p == h || self.core.timelines().get(p).is_some_and(|x| x.roles_ever(p).contains_key(&h)));
        tl.applied_on(&n.thing).filter(|(mc, _)| mc.id == n.commit).filter_map(|(_, o)| o.holder.thing()).any(reached)
    }
}

/// On a holder's edge log, the commit taking its read (the first applied write leaving it below
/// read after the newest giving it read) and the write giving it read (none: its start).
fn taking(log: &osis_keys::EdgeLog) -> Option<(CommitId, Option<CommitId>)> {
    let give = log.writes.iter().rposition(|w| w.applied && w.role >= Some(Role::Read));
    let (after, giving) = match give {
        Some(i) => (log.writes.get(i + 1..)?, log.writes.get(i).map(|w| w.key.commit)),
        None if log.start >= Some(Role::Read) => (log.writes.as_slice(), None),
        None => return None,
    };
    after.iter().find(|w| w.applied && w.role < Some(Role::Read)).map(|w| (w.key.commit, giving))
}
