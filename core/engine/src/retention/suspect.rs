//! Suspect aspects (spec/permissions.md §4 Suspect, spec/commits.md §5): an aspect whose
//! state this node may have computed from less than another holder, because it dropped data a
//! validity flip or a late creation record would have needed: a dropped body missing again (its
//! cover turned invalid, spec/permissions.md §5.2, or its purge fell, spec/permissions.md §6), a
//! part held pending
//! at its expiry (counts as never received). The node reports them in suspect lists to the
//! peers it shares a sync ID with; a writer
//! re-snapshots such an aspect (spec/sync-compaction.md §1). A flag names the bodies it is about; an entry
//! goes as its body comes back (held again: what the aspect lacked for it is in). An
//! Uncovered entry is dormant while a held snapshot valid here is stamped after its commit
//! (`receipt::settled`), judged when the flags are read, from what is held then: a snapshot that
//! turns invalid gives nothing (spec/permissions.md §5.2), so the flag it had settled shows
//! again. A snapshot's author that lacked the delta leaves a node that holds it richer until a
//! writer holding it compacts (notes/engine-suspects.md). A PendingExpiry entry is never
//! dormant: its part's writes reach this node only as a snapshot's copies, and no test on what a
//! snapshot holds tells whether they repaired it (a listing snapshot may carry nothing of the part;
//! a write key-erased at expiry, spec/crdt.md §4.7, lands outside the entry record the part wrote; writes
//! of one delta share a dot). The lists' digests say whether nodes agree; such an entry goes
//! only with its thing (`forget`), yields to any flag raised after it (`suspects_under`: most
//! recent first).
//!
//! The flags are rows `q/` mirrored in `Indexes::suspects`, so a reader of one aspect's flag
//! (`Engine::suspect`) reads that key and the aspect's held snapshots alone: sync follows each
//! flagged aspect by `Effects`, new ones by `suspect_feed`, and a change re-judges only the
//! aspect it moved.

use crate::engine::records;
use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_store::Shred;
use std::sync::Arc;

/// Why an aspect is suspect (bits of an entry's last byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A dropped body is missing again: its cover turned invalid, or its purge fell.
    Uncovered = 2,
    /// A part held pending at its expiry was dropped (counts as never received).
    PendingExpiry = 4,
}

/// A body a flag is about: its commit, aspect index and `Why` bits.
type Entry = (CommitId, u8, u8);

/// An aspect's flag: when it was last raised (wall ms) and the bodies it is about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flag {
    at: u64,
    bodies: Vec<Entry>,
}

/// The flag record: le64 wall ms last raised, then per body a 32-byte commit ID, the
/// aspect index and the `Why` bits.
fn decode(v: &[u8]) -> Flag {
    let (at, rest) = v.split_first_chunk::<8>().map_or((0, &[][..]), |(a, r)| (u64::from_le_bytes(*a), r));
    let (chunks, _) = rest.as_chunks::<34>();
    let bodies = chunks
        .iter()
        .filter_map(|e| {
            let (c, tail) = e.split_first_chunk::<32>()?;
            Some((CommitId(*c), *tail.first()?, *tail.get(1)?))
        })
        .collect();
    Flag { at, bodies }
}

fn encode(f: &Flag) -> Vec<u8> {
    let mut v = f.at.to_le_bytes().to_vec();
    for (c, ai, why) in &f.bodies {
        v.extend_from_slice(&c.0);
        v.push(*ai);
        v.push(*why);
    }
    v
}

/// Loads the flags (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut flags = Vec::new();
    tx.scan(records::SUSPECT, |k, v| {
        let mut r = records::Rd::new(k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        flags.push(((tid, ak), Arc::new(decode(&v))));
        Ok(())
    })?;
    for (k, f) in flags {
        tx.core.ix.suspects.insert(k, f);
    }
    Ok(())
}

fn store(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, f: Flag) -> Result<()> {
    if f.bodies.is_empty() {
        return forget(tx, tid, ak, Shred::No);
    }
    tx.put_aspect_local(records::SUSPECT, tid, ak, &encode(&f))?;
    tx.core.ix.suspects.insert((*tid, ak.clone()), Arc::new(f));
    Ok(())
}

/// `(tid, ak)` is flagged no more (its last entry went, or the aspect is forgotten).
pub(crate) fn forget(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, shred: Shred) -> Result<()> {
    if tx.core.ix.suspects.remove(&(*tid, ak.clone())).is_some() {
        tx.txn.remove_local(&records::aspect_key(records::SUSPECT, tid, ak), shred)?;
    }
    Ok(())
}

/// Flags `(tid, ak)` suspect from now for `why`, about `bodies` (parts of it, by commit and
/// aspect index; none flags nothing). A memory aspect's flag is a memory row (`store`): gone at a
/// restart, with what it is about.
pub(crate) fn raise(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, why: Why, bodies: &[(CommitId, usize)]) -> Result<()> {
    if bodies.is_empty() {
        return Ok(());
    }
    let mut f = tx.core.ix.suspects.get(&(*tid, ak.clone())).map(|f| (**f).clone()).unwrap_or_default();
    for (c, ai) in bodies {
        let ai = u8::try_from(*ai).unwrap_or(u8::MAX);
        match f.bodies.iter_mut().find(|e| e.0 == *c && e.1 == ai) {
            Some(e) => e.2 |= why as u8,
            None => f.bodies.push((*c, ai, why as u8)),
        }
    }
    f.at = tx.now().0;
    store(tx, tid, ak, f)
}

/// Part `ai` of `c` on `(tid, ak)` is held again: the flag is no longer about it.
pub(crate) fn body_back(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(old) = tx.core.ix.suspects.get(&(*tid, ak.clone())).cloned() else { return Ok(()) };
    let mut f = (*old).clone();
    f.bodies.retain(|e| !(e.0 == *c && usize::from(e.1) == ai));
    if f.bodies.len() != old.bodies.len() {
        store(tx, tid, ak, f)?;
    }
    Ok(())
}

/// Whether flag entry `e` is dormant: not about a part that went pending at its expiry, and a
/// held snapshot of its aspect valid here is stamped after its commit.
fn dormant(core: &Core, e: &Entry) -> bool {
    e.2 & Why::PendingExpiry as u8 == 0 && core.ix.commits.get(&e.0).is_some_and(|m| crate::apply::receipt::settled(core, &m.header, usize::from(e.1)))
}

/// `f` as reported: when last raised and the `Why` bits of its bodies not dormant (0 while
/// every one is).
fn judged(core: &Core, f: &Flag) -> (u64, u8) {
    (f.at, f.bodies.iter().filter(|e| !dormant(core, e)).fold(0, |w, e| w | e.2))
}

/// What a writer did with one entry of a peer's suspect list (`Engine::repair_suspect`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repaired {
    /// Not judged: the thing is outside S's closure here, or this node may not snapshot the
    /// aspect or holds no state of it.
    Skipped,
    /// The reporter's digest is this node's own.
    Same,
    /// A snapshot from this state was written for that reporter already.
    Already,
    /// A snapshot written, `from` the digest of the state it was written from.
    Wrote { commit: CommitId, from: [u8; 16] },
}

impl Engine {
    /// The aspects this node flags suspect, with when each was last flagged (wall ms)
    /// and why (`Why` bits over the bodies it is about that are not dormant).
    pub fn suspects(&self) -> Vec<(Tid, Ak, u64, u8)> {
        let core = &self.core;
        core.ix
            .suspects
            .iter()
            .filter_map(|((t, ak), f)| {
                let (at, why) = judged(core, f);
                (why != 0).then(|| (*t, ak.clone(), at, why))
            })
            .collect()
    }

    /// `(tid, ak)`'s flag: when last raised and why, as `suspects` lists it, the `Why` bits 0
    /// while it is dormant (it shows again if its settling snapshot turns invalid); `None` once
    /// it is gone, when a follower lets the key go. Reads that aspect's flag and held snapshots
    /// alone, so a follower (`Effects`, new keys from `suspect_feed`) is due when the flag is
    /// raised or cleared, or a snapshot of the aspect comes, goes or turns valid or invalid here.
    pub fn suspect(&self, tid: &Tid, ak: &Ak) -> Option<(u64, u8)> {
        let core = &self.core;
        core.ix.suspects.get(&(*tid, ak.clone())).map(|f| judged(core, f))
    }

    /// The commits of the bodies `(tid, ak)`'s flag names, dormant ones included (stamped as
    /// `suspect`): a node fetches those its sources show (spec/permissions.md §4 Suspect list).
    pub fn suspect_bodies(&self, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        self.core.ix.suspects.get(&(*tid, ak.clone())).map(|f| f.bodies.iter().map(|e| e.0).collect()).unwrap_or_default()
    }

    /// A cursor over the aspects flagged from now on (`memo::Feed`; one flagged again after its
    /// flag went is given again).
    pub fn suspect_feed(&self) -> osis_base::memo::Feed<(Tid, Ak)> {
        self.core.ix.suspects.feed()
    }

    /// Every flagged aspect, dormant ones included: what a follower starting now follows before
    /// `suspect_feed` gives the new ones.
    pub fn suspect_keys(&self) -> Vec<(Tid, Ak)> {
        self.core.ix.suspects.keys().cloned().collect()
    }

    /// Whether `tid`'s creation record is held (stamped): a suspect list leaves out an aspect
    /// of a thing whose record is unknown (spec/permissions.md §4 Suspect list).
    pub fn record_known(&self, tid: &Tid) -> bool {
        self.core.created(tid).is_some()
    }

    /// Whether `tid` is in sync ID `s`'s closure here and S's actor may read it: the things whose
    /// bodies S carries (spec/sync-judgement.md §1) and whose flagged aspects S's suspect list
    /// names (spec/permissions.md §4 Suspect list). A reader of S learns nothing of the others.
    pub fn suspect_under(&mut self, s: &osis_base::SyncId, tid: &Tid) -> Result<bool> {
        if !self.carrying(tid)?.contains(s) {
            return Ok(false);
        }
        Ok(self.sync_owners(s)?.iter().any(|g| self.reads_in(g, tid)))
    }

    /// Whether this node may repair `(tid, ak)` for a suspect list sent for `s`: the thing is one
    /// S's list may name (`suspect_under`) and this node may snapshot the aspect
    /// (spec/sync-compaction.md §1 Repair).
    pub fn may_repair(&mut self, s: &osis_base::SyncId, tid: &Tid, ak: &Ak) -> Result<bool> {
        if !self.suspect_under(s, tid)? {
            return Ok(false);
        }
        let (t, a) = (*tid, ak.clone());
        self.read(|tx| {
            let ts = tx.core.hlc.peek();
            Ok(super::snapshot::may_snapshot(tx, &t, &a, a.ephemeral(), ts)? == crate::engine::write::MayWrite::Yes)
        })
    }

    /// Judges one entry `(tid, ak, theirs)` of a suspect list `reporter` sent for sync ID `s`
    /// (spec/sync-compaction.md §1 Repair): only for a thing in S's closure here whose aspect this
    /// node may snapshot and holds state of; an equal digest repairs nothing; `wrote_from` is the
    /// digest of the state this node last wrote a snapshot from for `reporter` (the caller keeps
    /// it), and a state still at it is not snapshotted again. Each entry judged is a
    /// `DiagnosticKind::Repair`.
    pub fn repair_suspect(&mut self, s: &osis_base::SyncId, tid: &Tid, ak: &Ak, theirs: &[u8; 16], reporter: &Tid, wrote_from: Option<[u8; 16]>) -> Result<Repaired> {
        let (t, a) = (*tid, ak.clone());
        if !self.may_repair(s, tid, ak)? || !self.read(|tx| tx.has_state(&t, &a))? {
            return Ok(Repaired::Skipped);
        }
        let Some(own) = self.state_digest(tid, ak)? else { return Ok(Repaired::Skipped) };
        let done = if own == *theirs {
            Repaired::Same
        } else if wrote_from == Some(own) {
            Repaired::Already
        } else {
            match self.snapshot(tid, ak) {
                Ok(Some(c)) => Repaired::Wrote { commit: c, from: self.state_digest(tid, ak)?.unwrap_or(own) },
                Ok(None) | Err(crate::Error::Misuse(_) | crate::Error::Permission { .. }) => return Ok(Repaired::Skipped),
                Err(e) => return Err(e),
            }
        };
        let (commit, detail) = match done {
            Repaired::Wrote { commit, .. } => (Some(commit), "re-snapshotted"),
            Repaired::Already => (None, "a snapshot from this state was written for this reporter"),
            _ => (None, "same state"),
        };
        self.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::Repair, tids: vec![*reporter, *tid], commit, peer: Some(*reporter), detail: detail.into() }, self.core.hlc.mono());
        Ok(done)
    }

    /// The keyed digest of `(tid, ak)`'s state (spec/permissions.md §4): the first 16 bytes of
    /// `kdf("state", dedup secret of tid, ak || state bytes)`, the state bytes its encoding as a
    /// snapshot fragment with its pages, none for an aspect holding no state. `None` while the
    /// thing's creation record is unknown. Nodes holding the same bodies get the same digest; a
    /// peer, lacking the dedup secret, learns nothing from it. A memo per aspect
    /// (`Core::state_digests`, stamped by the thing's creation record and the aspect's state): a
    /// suspect list's entry costs a lookup unless its aspect moved, not the aspect's size.
    pub fn state_digest(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<[u8; 16]>> {
        let key = (*tid, ak.clone());
        osis_base::memo::Memo::get_in(self, |e| &e.core.state_digests, &key, |e| {
            let (tid, ak) = &key;
            let Some(r) = e.core.created(tid) else { return Ok(None) };
            let d = osis_crypto::dedup_secret(r.nonce());
            let _s = osis_base::costs::span("state digest: computed");
            let bytes = e.read(|tx| tx.state(tid, ak)?.map(crate::engine::state::encode).transpose())?.unwrap_or_default();
            Ok(Some(osis_crypto::state_digest(&d, ak.as_str(), &bytes)))
        })
    }
}
