//! Forgetting what this node lost read access to (spec/permissions.md §3: a node that learns it
//! lost read access to an actor drops every local unit it can no longer read by another path;
//! spec/requirements.md, Deletion: forward secure). Runs in the transaction that drops the lost
//! secrets, so it is done whole or not at all.
//!
//! A thing is forgotten when its secret actor is one of the actors just lost and neither the
//! node nor a held key actor may read it now. Of a forgotten thing only the certificate material
//! perm judges others' writes by stays: `created.0`, and the role-class aspects except
//! `secrets.0` (edges, public keysets, sync IDs). Everything else goes, shredded:
//! aspect units (state, tables), the deltas in commit
//! records (a commit left with no part is deleted, so a re-grant fetches it again; the others
//! keep their readable parts, the forgotten ones joining late if they come back), pending parts,
//! but a re-grant's boxes that may still apply (`rotation::boxes_kept`),
//! value-less lists, leftovers, purge lists and what they dropped, timers, `secrets.0` waits, the
//! sync IDs of forgotten things and the commit blobs holding forgotten parts, and their blob
//! ciphertexts.
//!
//! Forgetting a local copy (spec/sync-set.md §3, `Engine::forget_local`) goes the same
//! way for the things named, whose secrets stay: `secrets.0` stays with the role-class aspects,
//! so the thing reads again once synced, and what arrives again counts as never received.
//!
//! A kept copy (spec/permissions.md §3, Retain) goes the same way but for its content, which stays
//! whole, state and bodies and timers: only `secrets.0` and the blob ciphertexts nothing still
//! lists go.

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

/// What `forget` forgets.
#[derive(Clone, Copy)]
pub(crate) enum Scope<'a> {
    /// The things whose reading went with the secrets of these actors, just lost.
    Lost(&'a BTreeSet<Tid>),
    /// These things' local copies, their secrets kept.
    Local(&'a BTreeSet<Tid>),
    /// These things whole, role-class aspects and secrets included: nothing held needs them
    /// (`retention::needed`).
    Whole(&'a BTreeSet<Tid>),
}

/// What goes of a thing `forget` reaches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// It stays: another path reads it, or its actor was not lost.
    Stays,
    /// A kept copy (`Core::ix.kept`).
    Kept,
    Erased,
    /// Its local copy goes (`Scope::Local`): everything an erased thing loses but `secrets.0`.
    Local,
    /// Every aspect goes (`Scope::Whole`).
    Whole,
}

/// What one forgetting removed.
#[derive(Default)]
pub struct Forgotten {
    pub things: BTreeSet<Tid>,
    /// Sync IDs of forgotten things with own keys.
    pub sync_ids: BTreeSet<SyncId>,
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
fn fate(core: &Core, scope: Scope<'_>, t: &Tid) -> Fate {
    let lost = match scope {
        Scope::Lost(l) => l,
        Scope::Local(ts) => return if ts.contains(t) { Fate::Local } else { Fate::Stays },
        Scope::Whole(ts) => return if ts.contains(t) { Fate::Whole } else { Fate::Stays },
    };
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
        Fate::Local => !KEPT.contains(&ak.as_str()) && ak.as_str() != "secrets.0",
        Fate::Whole => true,
    }
}

/// Whether dropping the secrets of `lost` forgets `t` (erased or kept as a copy): its secrets
/// derive from a lost actor's and no held path reads it (node-sync: where this node's writes on
/// what an `until` ended would go).
pub(crate) fn would_forget(core: &Core, lost: &BTreeSet<Tid>, t: &Tid) -> bool {
    fate(core, Scope::Lost(lost), t) != Fate::Stays
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

/// Indices of the aspects forgotten, of a commit's `aspects`.
fn lost_aspects<'a>(core: &Core, scope: Scope<'_>, aspects: impl Iterator<Item = (&'a Tid, &'a Ak)>, memo: &mut BTreeMap<Tid, Fate>) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for (ai, (t, ak)) in aspects.enumerate() {
        if forgotten_ak(*memo.entry(*t).or_insert_with(|| fate(core, scope, t)), ak) {
            out.insert(ai);
        }
    }
    out
}

/// The things whose secrets derive from one of `actors` (`Core::secret_actor`): each actor and
/// what lies below it down the record chains, to the next actor with secrets of its own.
/// O(the things found).
pub(crate) fn under(core: &Core, actors: &BTreeSet<Tid>) -> BTreeSet<Tid> {
    let mut out = BTreeSet::new();
    let mut todo: Vec<Tid> = actors.iter().copied().collect();
    while let Some(t) = todo.pop() {
        let Some(a) = core.secret_actor(&t) else { continue };
        if !actors.contains(&a) || !out.insert(t) {
            continue;
        }
        todo.extend(core.ix.held.first_admin_of(&t).copied());
    }
    out
}

/// Per `secrets.0` aspect, a role commit's header and part index on it, and the bodies forgotten.
type BoxesGone = BTreeMap<(Tid, Ak), (std::sync::Arc<Header>, usize, Vec<osis_crdt::Fragment>)>;

/// Parts `ais` of held commit `id` are forgotten (`rest`: its record without them): each held
/// one counts as never received (missing), as an open of the rewritten record reads it.
/// A role commit's `secrets.0` body goes into `boxes` (its aspect's, with the header and index
/// to name it by): what keys noted from them goes once per aspect (`keys::forget_dropped`).
fn unreceive(tx: &mut Tx<'_>, id: &CommitId, ais: &BTreeSet<usize>, rest: Option<&CommitBlob>, boxes: &mut BoxesGone) -> Result<()> {
    let Some(mut m) = tx.core.ix.commits.get(id).cloned() else { return Ok(()) };
    let held: Vec<usize> = ais.iter().copied().filter(|ai| m.holds(*ai)).collect();
    let moved = !held.is_empty();
    for ai in held {
        let Some(a) = m.view.aspects.get(ai).cloned() else { continue };
        if m.view.kind.is_role() && a.ak.as_str() == "secrets.0" {
            let body = crate::apply::held_fragment(tx, id, ai)?;
            let e = boxes.entry((a.tid, a.ak.clone())).or_insert_with(|| (m.header.arc(), ai, Vec::new()));
            e.2.extend(body);
        }
        if m.stripped(ai) {
            super::leftover::remove(tx, &a.tid, &a.ak, id, ai)?;
        }
        if osis_schema::core_types::is_addenda(a.ak.as_str()) {
            crate::apply::validity::forget_addendum_body(tx.core, id, &a.tid);
        }
        if a.ak.as_str() == osis_commit::retention::RETENTION {
            crate::apply::validity::forget_setting(tx.core, &a.tid, id);
        }
        // its validity stands: it reads the author's roles, not the body
        tx.core.touch();
        m.set_hold(ai, crate::engine::Hold::Missing(crate::engine::Missing::Plain));
        crate::apply::unjudge_part(tx.core, id, ai);
        crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, id);
    }
    if !moved {
        return Ok(());
    }
    // what it lost counts as never received: nothing keeps its blobs out (`CipherTx::unreceived`)
    let blobs: Vec<osis_base::BlobId> = tx.core.ix.commit_blobs.get(id).into_iter().flatten().copied().collect();
    for b in blobs {
        tx.blobs.unreceived(&b);
    }
    if let Some(rest) = rest {
        tx.put_commit(id, rest, &m, Shred::Yes, None)?;
    }
    tx.core.put_meta(*id, m);
    crate::apply::note_stands_in(tx.core, id);
    Ok(())
}

/// Forgets what `scope` names (lost: called after the lost secrets are dropped from the store;
/// either way before the engine reloads its indexes; `held`: the newest read epoch number the
/// lost actors held, `rotation::boxes_kept`).
pub(crate) fn forget(tx: &mut Tx<'_>, scope: Scope<'_>, held: &BTreeMap<Tid, u64>) -> Result<Forgotten> {
    let mut out = Forgotten::default();
    if match scope {
        Scope::Lost(x) | Scope::Local(x) | Scope::Whole(x) => x.is_empty(),
    } {
        return Ok(out);
    }
    let mut memo: BTreeMap<Tid, Fate> = BTreeMap::new();
    // the things reached, found down the record chains (`under`), and their aspects forgotten,
    // held in states or in commits
    let cands: BTreeSet<Tid> = match scope {
        Scope::Lost(lost) => under(tx.core, lost),
        Scope::Local(ts) | Scope::Whole(ts) => ts.clone(),
    };
    let mut aspects: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // every aspect held of a thing reached, forgotten or not
    let mut all: Vec<(Tid, Ak)> = Vec::new();
    for t in cands {
        let f = *memo.entry(t).or_insert_with(|| fate(tx.core, scope, &t));
        if f == Fate::Stays {
            continue;
        }
        let mut held: BTreeSet<Ak> = tx.core.aspects_of(&t).map(|((_, ak), _)| ak.clone()).collect();
        tx.scan(&[records::ASPECTS, t.as_bytes()].concat(), |k, _| {
            held.insert(Rd::new(k).ak()?);
            Ok(())
        })?;
        if held.is_empty() {
            continue;
        }
        out.things.insert(t);
        aspects.extend(held.iter().filter(|ak| forgotten_ak(f, ak)).map(|ak| (t, ak.clone())));
        all.extend(held.into_iter().map(|ak| (t, ak)));
    }
    // commit records: forgotten parts out, shredded, counting as never received (missing); a
    // commit left with none is forgotten whole
    let mut parts: BTreeMap<CommitId, BTreeSet<usize>> = BTreeMap::new();
    // the links of the parts forgotten, by thing: the pieces they reach may go (`freed::lost`)
    let mut links: BTreeMap<Tid, Vec<osis_base::Link>> = BTreeMap::new();
    let mut boxes = BoxesGone::new();
    let ids: BTreeSet<CommitId> = aspects.iter().flat_map(|k| tx.core.ix.by_aspect.get(k).into_iter().flatten().map(|x| x.1)).collect();
    osis_base::costs::count("forget: forgettings", u64::from(!out.things.is_empty()));
    osis_base::costs::count("forget: commits scanned", ids.len() as u64);
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let ais = lost_aspects(tx.core, scope, m.view.aspects.iter().map(|a| (&a.tid, &a.ak)), &mut memo);
        // lost access forgets what was read: a commit holding no part it forgets (a header alone,
        // judged by its author's chain) keeps as it is
        if ais.is_empty() || (matches!(scope, Scope::Lost(_)) && !ais.iter().any(|ai| m.holds(*ai))) {
            continue;
        }
        for ai in ais.iter().copied().filter(|ai| m.holds(*ai)) {
            if let Some(a) = m.view.aspects.get(ai) {
                let l = super::freed::part_links(tx, &id, ai)?;
                links.entry(a.tid).or_default().extend(l);
            }
        }
        let blob = tx.get_commit(&id)?;
        let rest = blob.as_ref().map(|b| osis_commit::rewrite(b, |ai| ais.contains(&ai)));
        // whole when no part it keeps stays: a leftover is held outside the blob's parts
        let keeps = (0..m.view.aspects.len()).any(|ai| !ais.contains(&ai) && m.holds(ai));
        if rest.is_some() && !keeps {
            crate::apply::unindex_unreceived(tx, &id)?;
            // a release's blobs go with it, the store's own entries of them too (`bodies::forget`);
            // losing access keeps them: an own entry naming one waits for the access to return
            if matches!(scope, Scope::Local(_) | Scope::Whole(_)) {
                crate::sync::bodies::forget(tx, &id)?;
            }
            out.commits.insert(id);
        } else {
            unreceive(tx, &id, &ais, rest.as_ref(), &mut boxes)?;
        }
        parts.insert(id, ais);
    }
    for (h, ai, bodies) in boxes.into_values() {
        crate::apply::keys::forget_dropped(tx, &h, ai, &bodies)?;
    }
    // pending and parked commits (and late parts waiting under an applied commit's ID)
    let mut pend = Vec::new();
    tx.each_pending(|id, p| pend.push((id, p)))?;
    for (id, p) in pend {
        // unreadable by this build: its header names nothing we can judge
        let Ok(blob) = CommitBlob::decode_stored(&p.bytes) else { continue };
        // a kept copy's content takes nothing new: what waits goes too
        let mut ais: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, a)| frozen(tx.core, &a.tid, &a.ak)).map(|(ai, _)| ai).collect();
        ais.extend(lost_aspects(tx.core, scope, blob.header.aspects.iter().map(|a| (&a.tid, &a.ak)), &mut memo));
        if ais.is_empty() {
            continue;
        }
        // every thing it is on gone whole: it goes, header and all, as never received
        if matches!(scope, Scope::Whole(_)) && ais.len() == blob.header.aspects.len() {
            for (ai, a) in blob.header.aspects.iter().enumerate() {
                super::leftover::remove(tx, &a.tid, &a.ak, &id, ai)?;
            }
            tx.txn.remove_pending(&id, Shred::Yes)?;
            crate::apply::pending_left(tx.core, &id);
            crate::apply::set_pending(tx.core, &id, None);
            continue;
        }
        // a grant that may still apply keeps its boxes (applied later without them, the node
        // would hold the role and no secret), marked sealed: read as candidates again, they
        // would keep the lost secrets for good
        let grants = crate::rotation::boxes_kept(tx.core, &blob, &id, held, crate::apply::kept_verdict(&p));
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
        if rest.parts.is_empty() {
            crate::apply::pending_left(tx.core, &id);
            crate::apply::set_pending(tx.core, &id, None);
        } else {
            tx.txn.put_pending(&id, p.kind, p.verdict, &rest.encode())?;
        }
    }
    // aspect units and per-aspect records: rebuilt from what is held (nothing), so what their
    // states gave goes, then dropped
    for (t, ak) in &aspects {
        crate::apply::rebuild(tx, t, ak)?;
        crate::engine::refs::clear(tx, t, ak)?;
        tx.txn.drop_aspect(t, ak)?;
        super::destroy::forget_aspect_rows(tx, t, ak)?;
    }
    // the things' history cursors and rows (`leaving`)
    super::leaving::forget_aspects(tx, all)?;
    for t in &out.things {
        // its role arrival and loss place: nothing left names it
        crate::sync::held::forget_actor(tx, t)?;
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
    // sync IDs of forgotten things, from their `sync.0` (kept), but those a kept thing owns
    // (`sync_ids::actors::owns`; the forgotten ones' secrets are gone, so judged from the owner's
    // side): another's sync ID a forgotten thing's admin named takes nothing of its owner's here
    for g in out.things.clone() {
        out.sync_ids.extend(crate::flows::sync_ids::recorded_in(tx, &g)?);
    }
    // (each found by the things recording it, `Indexes::sync_recorders`)
    let kept: BTreeSet<Tid> = out.sync_ids.iter().flat_map(|l| tx.core.ix.sync_recorders.get(l).into_iter().flatten().copied()).filter(|g| !out.things.contains(g)).collect();
    for g in kept {
        for l in crate::flows::sync_ids::owned_in(tx, &g)?.keys() {
            out.sync_ids.remove(l);
        }
    }
    // the pieces the forgotten parts reach that no kept source of their thing links (a link
    // its blob does not bear releases nothing, `freed::lost`; their freed sets go), then the
    // blob ciphertexts nothing kept names (the store per sync ID drops its entries as their
    // bodies leave `sync_bodies`)
    let pieces = super::freed::lost(tx, &out.things, links, &aspects, &parts)?;
    let mut gone = pieces.clone();
    // a blob of a forgotten sync ID that a kept source of a forgotten thing links stays (a kept
    // copy's content, an erased thing's kept aspects): its sync IDs gone, nothing fetches it again
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
        let cause = if matches!(scope, Scope::Lost(_)) { Cause::LostAccess } else { Cause::Released };
        tx.core.events.queue(Event::Changed { cause, changed: aspects.into_iter().collect() });
    }
    out.parts = parts;
    // a rotation forgotten whole moves its account's chain: judged again in this transaction
    if tx.core.stale() {
        crate::apply::atomic::rejudged(tx, false)?;
    }
    Ok(out)
}
