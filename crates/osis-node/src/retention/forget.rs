//! Forgetting what this node lost read access to (spec/permissions.md §3: a node that learns it
//! lost read access to an actor drops every local unit it can no longer read by another path;
//! spec/requirements.md, Deletion: forward secure). Runs in the transaction that drops the lost
//! secrets, so it is done whole or not at all.
//!
//! A thing is forgotten when its secret actor is one of the actors just lost and neither the
//! node nor a held key actor may read it now. Of a forgotten thing only the certificate material
//! perm judges others' writes by stays: `/created`, and the membership-class aspects except
//! `/secrets` (edges, ledger, public keysets, labels, moves). Everything else goes, shredded:
//! aspect units (state, undo buffer, pre-reset snapshots, tables, deaths), the deltas in commit
//! records (a commit left with no part is deleted, so a re-grant fetches it again; the others
//! keep their readable parts, the forgotten ones joining late if they come back), pending parts,
//! receipts, value-less lists, purge lists, timers, `/secrets` waits, the sync records of the
//! labels of forgotten groups and of the commit blobs holding forgotten parts, and their blob
//! ciphertexts.

use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::events::{Cause, Event};
use osis_commit::{CommitBlob, Header};
use osis_core::{Ak, BlobId, CommitId, LabelId, Tid};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Aspects of a forgotten thing that stay: what perm judges others' writes by, no content and
/// no secret.
const KEPT: [&str; 7] = ["/created", "/members", "/tenures", "/keys", "/label", "/moved", "/was"];

/// What one forgetting removed.
#[derive(Default)]
pub(crate) struct Forgotten {
    pub things: BTreeSet<Tid>,
    /// Labels of forgotten groups.
    pub labels: BTreeSet<LabelId>,
    /// Commits deleted whole.
    pub commits: BTreeSet<CommitId>,
}

/// Whether `t` is forgotten when the secrets of `lost` are dropped: its secrets derive from a
/// lost actor's and no held path reads it (the node's effective role on it is none).
fn forgets(core: &Core, lost: &BTreeSet<Tid>, t: &Tid) -> bool {
    let Some(a) = core.secret_actor(t) else { return false };
    if !lost.contains(&a) {
        return false;
    }
    let node = core.id.tid();
    !(core.may_read(&node, t) || core.key_actors.keys().any(|k| core.may_read(k, t)))
}

fn forgotten_ak(ak: &Ak) -> bool {
    !KEPT.contains(&ak.as_str())
}

/// Aspect indices of `h` forgotten.
fn lost_aspects(core: &Core, lost: &BTreeSet<Tid>, h: &Header, memo: &mut BTreeMap<Tid, bool>) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if forgotten_ak(&a.ak) && *memo.entry(a.tid).or_insert_with(|| forgets(core, lost, &a.tid)) {
            out.insert(ai);
        }
    }
    out
}

/// Forgets every thing whose reading went with the secrets of `lost` (called after they are
/// dropped from the store, before the engine reloads its indexes).
pub(crate) fn forget(tx: &mut Tx<'_>, lost: &[Tid]) -> Result<Forgotten> {
    let lost: BTreeSet<Tid> = lost.iter().copied().collect();
    let mut out = Forgotten::default();
    if lost.is_empty() {
        return Ok(out);
    }
    // commit records change below the indexes: the reload rebuilds the persisted index
    crate::engine::index::invalidate(tx)?;
    let mut memo: BTreeMap<Tid, bool> = BTreeMap::new();
    // forgotten aspects: held in states or in commits
    let mut aspects: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut indexed = Vec::new();
    tx.scan(b"a/", |k, _| {
        let mut r = Rd::new(k);
        indexed.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    let known: Vec<(Tid, Ak)> = tx.core.by_aspect.keys().cloned().chain(indexed).collect();
    for (t, ak) in known {
        if *memo.entry(t).or_insert_with(|| forgets(tx.core, &lost, &t)) {
            out.things.insert(t);
            if forgotten_ak(&ak) {
                aspects.insert((t, ak));
            }
        }
    }
    // commit records: forgotten parts out, shredded; a commit left with none is deleted
    let mut parts: BTreeMap<CommitId, BTreeSet<usize>> = BTreeMap::new();
    let mut chunks: BTreeSet<BlobId> = BTreeSet::new();
    let ids: Vec<CommitId> = tx.core.commits.keys().copied().collect();
    for id in ids {
        let Some(m) = tx.core.commits.get(&id).cloned() else { continue };
        let ais = lost_aspects(tx.core, &lost, &m.header, &mut memo);
        if ais.is_empty() {
            continue;
        }
        let Some(blob) = tx.get_commit(&id)? else { continue };
        let rest = osis_commit::rewrite(&blob, |ai, _| ais.contains(&ai));
        if rest.parts.is_empty() {
            tx.remove_commit(&id)?;
            chunks.extend(m.header.chunks.iter().map(|c| c.blob));
            out.commits.insert(id);
        } else if rest.parts.len() < blob.parts.len() {
            tx.put_commit(&id, &rest, &m, Shred::Yes, None)?;
        }
        for (ai, a) in m.header.aspects.iter().enumerate() {
            if ais.contains(&ai) {
                aspects.insert((a.tid, a.ak.clone()));
            }
        }
        parts.insert(id, ais);
    }
    // pending and parked commits (and late parts waiting under an applied commit's ID)
    let mut pend = Vec::new();
    let mut after: Option<CommitId> = None;
    loop {
        let page = tx.txn.pending(after.as_ref(), 256)?;
        let n = page.len();
        for (id, k, bytes) in page {
            after = Some(id);
            pend.push((id, k, bytes));
        }
        if n < 256 {
            break;
        }
    }
    for (id, k, bytes) in pend {
        // unreadable by this build: its header names nothing we can judge
        let Ok(blob) = CommitBlob::decode(&bytes) else { continue };
        let ais = lost_aspects(tx.core, &lost, &blob.header, &mut memo);
        if ais.is_empty() || !blob.parts.iter().any(|p| ais.contains(&p.ai)) {
            continue;
        }
        let rest = osis_commit::rewrite(&blob, |ai, _| ais.contains(&ai));
        tx.txn.remove_pending(&id, Shred::Yes)?;
        if !rest.parts.is_empty() {
            tx.txn.put_pending(&id, k, &rest.encode())?;
        }
    }
    // aspect units and per-aspect records
    for (t, ak) in &aspects {
        tx.txn.drop_aspect(t, ak)?;
        for p in [b"a/".as_slice(), records::RECEIPT, records::VALUELESS, records::PURGES] {
            tx.txn.remove_local(&records::aspect_key(p, t, ak), Shred::Yes)?;
        }
    }
    for t in &out.things {
        tx.txn.remove_local(&[records::SYNCING, t.as_bytes()].concat(), Shred::No)?;
    }
    // timers and `/secrets` waits of forgotten parts
    let hit = |c: &CommitId, ai: usize| out.commits.contains(c) || parts.get(c).is_some_and(|s| s.contains(&ai));
    let mut stale = Vec::new();
    tx.scan(records::TIMER, |k, _| {
        let (_, c, ai) = records::parse_timer(k)?;
        if hit(&c, ai) {
            stale.push([records::TIMER, k].concat());
        }
        Ok(())
    })?;
    tx.scan(crate::apply::keys::UNRESOLVED, |k, _| {
        let mut r = Rd::new(k);
        let c = CommitId(r.arr()?);
        if hit(&c, r.u32()? as usize) {
            stale.push([crate::apply::keys::UNRESOLVED, k].concat());
        }
        Ok(())
    })?;
    for k in stale {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
    // labels of forgotten groups, from their `/label` (kept)
    for g in out.things.clone() {
        out.labels.extend(crate::flows::labels::labels_in(tx, &g)?);
    }
    // sync records, then the blob ciphertexts nothing kept names
    let gone = crate::sync::state::forget_records(tx, &out.labels, &out.things, &out.commits, &parts, chunks)?;
    let still: BTreeSet<BlobId> = tx.core.commits.iter().filter(|(c, _)| !out.commits.contains(c)).flat_map(|(_, m)| m.header.chunks.iter().map(|c| c.blob)).collect();
    for b in gone.difference(&still) {
        tx.txn.delete_blob(b);
    }
    // the API's watches see the loss
    if !aspects.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LostAccess, changed: aspects.into_iter().collect() });
    }
    Ok(out)
}
