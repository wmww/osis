//! Forgetting what this node lost read access to (spec/permissions.md §3: a node that learns it
//! lost read access to an actor drops every local unit it can no longer read by another path;
//! spec/requirements.md, Deletion: forward secure). Runs in the transaction that drops the lost
//! secrets, so it is done whole or not at all.
//!
//! A thing is forgotten when its secret actor is one of the actors just lost and neither the
//! node nor a held key actor may read it now. Of a forgotten thing only the certificate material
//! perm judges others' writes by stays: `created.0`, and the role-class aspects except
//! `secrets.0` (edges, public keysets, labels). Everything else goes, shredded:
//! aspect units (state, tables), the deltas in commit
//! records (a commit left with no part is deleted, so a re-grant fetches it again; the others
//! keep their readable parts, the forgotten ones joining late if they come back), pending parts,
//! but a re-grant's boxes that may still apply (`rotation::boxes_kept`),
//! value-less lists, leftovers, purge lists and what they dropped, timers, `secrets.0` waits, the sync records of the
//! labels of forgotten groups and of the commit blobs holding forgotten parts, and their blob
//! ciphertexts.
//!
//! A kept copy (spec/permissions.md §3, Retain) goes the same way but for its content, which stays
//! whole, state and bodies and timers: only `secrets.0`, the labels' sync records and the blob
//! ciphertexts nothing still lists go.

use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::events::{Cause, Event};
use osis_commit::{CommitBlob, Header};
use osis_base::{Ak, CommitId, SyncId, Tid};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Aspects of a forgotten thing that stay: what perm judges others' writes by, no content and
/// no secret.
const KEPT: [&str; 5] = ["created.0", "retention^.0", "roles.0", "keys.0", "sync.0"];

/// What goes of a thing `forget` reaches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// It stays: another path reads it, or its actor was not lost.
    Stays,
    /// A kept copy (`Core::ix.kept`).
    Kept,
    Erased,
}

/// What one forgetting removed.
#[derive(Default)]
pub struct Forgotten {
    pub things: BTreeSet<Tid>,
    /// Labels of forgotten groups.
    pub labels: BTreeSet<SyncId>,
    /// Commits deleted whole.
    pub commits: BTreeSet<CommitId>,
    /// The forgotten aspect indices of each commit with a forgotten part (those of `commits`
    /// too): node sync drops the blobs holding one .
    pub parts: BTreeMap<CommitId, BTreeSet<usize>>,
}

/// Whether a held path reads `t` (the node's or a held key actor's effective role on it).
pub(crate) fn read_path(core: &Core, t: &Tid) -> bool {
    core.member().into_iter().chain([core.id.tid()]).any(|m| core.may_read(&m, t)) || core.key_actors.keys().chain(core.ix.bearers.iter()).any(|k| core.may_read(k, t))
}

/// `t` when the secrets of `lost` are dropped: forgotten when its secrets derive from a lost
/// actor's and no held path reads it.
fn fate(core: &Core, lost: &BTreeSet<Tid>, t: &Tid) -> Fate {
    let Some(a) = core.secret_actor(t) else { return Fate::Stays };
    if !lost.contains(&a) || read_path(core, t) {
        return Fate::Stays;
    }
    if core.ix.kept.contains_key(&a) { Fate::Kept } else { Fate::Erased }
}

fn forgotten_ak(fate: Fate, ak: &Ak) -> bool {
    match fate {
        Fate::Stays => false,
        Fate::Kept => ak.as_str() == "secrets.0",
        Fate::Erased => !KEPT.contains(&ak.as_str()),
    }
}

/// Whether dropping the secrets of `lost` forgets `t` (erased or kept as a copy): its secrets
/// derive from a lost actor's and no held path reads it (node-sync: where this node's writes on
/// what an `until` ended would go).
pub(crate) fn would_forget(core: &Core, lost: &BTreeSet<Tid>, t: &Tid) -> bool {
    fate(core, lost, t) != Fate::Stays
}

/// Whether a part on `(t, ak)` is content of a kept copy, which takes none: everything an erased
/// thing's forgetting would drop but `secrets.0`, where a re-grant's boxes come.
pub(crate) fn frozen(core: &Core, t: &Tid, ak: &Ak) -> bool {
    !KEPT.contains(&ak.as_str()) && ak.as_str() != "secrets.0" && copy_of(core, t).is_some()
}

/// The kept actor `t` is a copy under, unless a held path still reads `t`, which is then no copy.
pub(crate) fn copy_of(core: &Core, t: &Tid) -> Option<Tid> {
    core.secret_actor(t).filter(|a| core.ix.kept.contains_key(a) && !read_path(core, t))
}

/// Aspect indices of `h` forgotten.
fn lost_aspects(core: &Core, lost: &BTreeSet<Tid>, h: &Header, memo: &mut BTreeMap<Tid, Fate>) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if forgotten_ak(*memo.entry(a.tid).or_insert_with(|| fate(core, lost, &a.tid)), &a.ak) {
            out.insert(ai);
        }
    }
    out
}

/// Forgets every thing whose reading went with the secrets of `lost` (called after they are
/// dropped from the store, before the engine reloads its indexes; `held`: the newest read epoch
/// number they held, `rotation::boxes_kept`).
pub(crate) fn forget(tx: &mut Tx<'_>, lost: &[Tid], held: &BTreeMap<Tid, u64>) -> Result<Forgotten> {
    let lost: BTreeSet<Tid> = lost.iter().copied().collect();
    let mut out = Forgotten::default();
    if lost.is_empty() {
        return Ok(out);
    }
    // commit records change below the indexes: the reload rebuilds the persisted index
    crate::engine::index::invalidate(tx)?;
    let mut memo: BTreeMap<Tid, Fate> = BTreeMap::new();
    // forgotten aspects: held in states or in commits
    let mut aspects: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut indexed = Vec::new();
    tx.scan(records::ASPECTS, |k, _| {
        let mut r = Rd::new(k);
        indexed.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    let known: Vec<(Tid, Ak)> = tx.core.ix.by_aspect.keys().cloned().chain(indexed).collect();
    for (t, ak) in known {
        let f = *memo.entry(t).or_insert_with(|| fate(tx.core, &lost, &t));
        if f != Fate::Stays {
            out.things.insert(t);
            if forgotten_ak(f, &ak) {
                aspects.insert((t, ak));
            }
        }
    }
    // commit records: forgotten parts out, shredded; a commit left with none is deleted
    let mut parts: BTreeMap<CommitId, BTreeSet<usize>> = BTreeMap::new();
    // the links of the parts forgotten, by thing: the pieces they reach may go (`freed::lost`)
    let mut links: BTreeMap<Tid, Vec<osis_base::Link>> = BTreeMap::new();
    // rare (lost access): decodes every header
    let ids: Vec<CommitId> = tx.core.ix.commits.keys().copied().collect();
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let ais = lost_aspects(tx.core, &lost, &m.header, &mut memo);
        if ais.is_empty() {
            continue;
        }
        let Some(blob) = tx.get_commit(&id)? else { continue };
        for ai in ais.iter().copied().filter(|ai| m.holds(*ai)) {
            if let Some(a) = m.header.aspects.get(ai) {
                let l = super::freed::part_links(tx, &id, ai)?;
                links.entry(a.tid).or_default().extend(l);
            }
        }
        let rest = osis_commit::rewrite(&blob, |ai| ais.contains(&ai));
        if rest.parts.is_empty() {
            tx.remove_commit(&id)?;
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
    tx.each_pending(|id, k, bytes| pend.push((id, k, bytes)))?;
    for (id, k, bytes) in pend {
        // unreadable by this build: its header names nothing we can judge
        let Ok(blob) = CommitBlob::decode_stored(&bytes) else { continue };
        // a kept copy's content takes nothing new: what waits goes too
        let mut ais: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, a)| frozen(tx.core, &a.tid, &a.ak)).map(|(ai, _)| ai).collect();
        ais.extend(lost_aspects(tx.core, &lost, &blob.header, &mut memo));
        if ais.is_empty() {
            continue;
        }
        // a grant that may still apply keeps its boxes (applied later without them, the node
        // would hold the role and no secret), marked sealed: read as candidates again, they
        // would keep the lost secrets for good
        let grants = crate::rotation::boxes_kept(tx.core, &blob, &id, held);
        let kept: Vec<(usize, Tid)> = ais.iter().filter_map(|ai| blob.header.aspects.get(*ai).filter(|a| a.ak.as_str() == "secrets.0" && grants.contains(&a.tid)).map(|a| (*ai, a.tid))).collect();
        for (ai, x) in kept {
            ais.remove(&ai);
            tx.txn.put_local(&crate::apply::keys::sealed_key(&id, &x), &[], Shred::No)?;
        }
        if ais.is_empty() || !blob.parts.iter().any(|p| ais.contains(&p.ai)) {
            continue;
        }
        let rest = osis_commit::rewrite(&blob, |ai| ais.contains(&ai));
        for ai in &ais {
            if let Some(a) = blob.header.aspects.get(*ai) {
                super::leftover::remove(tx, &a.tid, &a.ak, &id, *ai)?;
            }
        }
        tx.txn.remove_pending(&id, Shred::Yes)?;
        if !rest.parts.is_empty() {
            tx.txn.put_pending(&id, k, &rest.encode())?;
        }
    }
    // aspect units and per-aspect records
    for (t, ak) in &aspects {
        crate::engine::refs::clear(tx, t, ak)?;
        tx.txn.drop_aspect(t, ak)?;
        super::destroy::forget_aspect_rows(tx, t, ak)?;
    }
    for t in &out.things {
        // unknown now: what lists it is judged again
        super::lifetimes::queue_with_listers(tx, t)?;
    }
    // the things' history cursors and rows (`leaving`), and the sync IDs inbox blobs hinted
    super::leaving::forget_things(tx, &out.things)?;
    for t in &out.things {
        crate::sync::inbox::set_hint(tx, t, None)?;
    }
    // timers of forgotten parts
    let hit = |c: &CommitId, ai: usize| out.commits.contains(c) || parts.get(c).is_some_and(|s| s.contains(&ai));
    tx.remove_scanned(records::TIMER, |k| {
        let (_, c, ai) = records::parse_timer(k)?;
        Ok(hit(&c, ai))
    })?;
    // what a purge request dropped there (`retention::lasting`)
    tx.remove_scanned(records::NAMED_PERMANENT, |k| {
        let mut r = Rd::new(k);
        let (c, t) = (CommitId(r.arr()?), r.tid()?);
        Ok(out.commits.contains(&c) || out.things.contains(&t))
    })?;
    // labels of forgotten groups, from their `label.0` (kept), but those a kept group owns
    // (`labeling::actors::owns`; the forgotten ones' secrets are gone, so judged from the owner's
    // side): another's label a forgotten group's admin named takes nothing of its owner's here
    for g in out.things.clone() {
        out.labels.extend(crate::flows::sync_ids::recorded_in(tx, &g)?);
    }
    if !out.labels.is_empty() {
        let kept: Vec<Tid> = tx.core.ix.sync_recorded.iter().filter(|g| !out.things.contains(g)).copied().collect();
        for g in kept {
            for l in crate::flows::sync_ids::owned_in(tx, &g)?.keys() {
                out.labels.remove(l);
            }
        }
    }
    // the pieces the forgotten parts reach that no kept source of their thing links (a link
    // its blob does not bear releases nothing, `freed::lost`; their freed sets go), then the
    // blob ciphertexts nothing kept names (the store per sync ID drops its entries as their
    // bodies leave `sync_bodies`)
    let pieces = super::freed::lost(tx, &out.things, links, &aspects, &parts)?;
    let mut gone = pieces.clone();
    // a blob of a forgotten label that a kept source of a forgotten thing links stays (a kept
    // copy's content, an erased thing's kept aspects): its labels gone, nothing fetches it again
    for t in out.things.clone() {
        if gone.is_empty() {
            break;
        }
        let linked = super::freed::kept_refs(tx, &t, &gone, &aspects, &parts)?;
        gone.retain(|b| !linked.blobs.contains(b));
    }
    for b in &gone {
        tx.blobs.release(b, tx.txn.is_memory())?;
    }
    // the API's watches see the loss
    if !aspects.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::LostAccess, changed: aspects.into_iter().collect() });
    }
    out.parts = parts;
    Ok(out)
}
