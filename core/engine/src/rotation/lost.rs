//! The lost-access trigger (spec/permissions.md §3, "a node that learns it lost read access"):
//! dropping the secrets of actors this node no longer reads, unless a pending grant may yet give
//! them back, and the pending-commit checks that decide it.

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::now_ts;
use crate::retention::forget::Forgotten;
use osis_base::{Role, Tid};
use osis_keys::{ActorEpochs, ROLES};
use osis_perm::At;
use osis_schema::core_types::BoxKey;
use std::collections::{BTreeMap, BTreeSet};

/// The lost-access trigger's work list (spec/permissions.md §3, "a node that learns it lost
/// read access"): `l/` + tid, a roster target of an applied received role commit, or an
/// aspect's thing of a dropped pending one, due now (empty value); or an actor a plausible
/// pending grant kept, due when that grant ages out (`PENDING_GRANT_WAIT_MS`; value: engine ms,
/// u64 BE). The held actors a role on it reaches are re-evaluated once due, in a transaction of
/// their own (node-sync, every step, with a wake for the next due time).
pub(crate) const LOST_DUE: &[u8] = b"l/";

/// Kept copies (spec/permissions.md §3, Keep): `K/` + lost actor; value: the tids of the holders
/// its copy hangs on, concatenated. Not derived: a later roster snapshot may have taken the edge
/// values that decided it out of the walk.
const KEPT_COPY: &[u8] = b"K/";

/// Adds `tids` to the work list, due now.
pub(crate) fn mark_lost_due(tx: &mut Tx<'_>, tids: impl IntoIterator<Item = Tid>) -> Result<()> {
    for t in tids {
        tx.txn.put_local(&[LOST_DUE, t.as_bytes()].concat(), &[], osis_store::Shred::No)?;
        tx.core.ix.lost_due.insert(t, 0);
    }
    Ok(())
}

/// Adds `t` to the work list, due at `at` (an earlier entry stays).
fn arm_lost_due(tx: &mut Tx<'_>, t: Tid, at: u64) -> Result<()> {
    if tx.core.ix.lost_due.get(&t).is_some_and(|x| *x <= at) {
        return Ok(());
    }
    tx.txn.put_local(&[LOST_DUE, t.as_bytes()].concat(), &at.to_be_bytes(), osis_store::Shred::No)?;
    tx.core.ix.lost_due.insert(t, at);
    Ok(())
}

/// Loads the work list.
pub(crate) fn load_lost_due(tx: &mut Tx<'_>) -> Result<()> {
    let mut v = Vec::new();
    tx.scan(LOST_DUE, |k, val| {
        let bad = || Error::Corrupt("lost-access work list");
        let at = match val.len() {
            0 => 0,
            _ => u64::from_be_bytes(val.try_into().map_err(|_| bad())?),
        };
        v.push((Tid::from_bytes(k.try_into().map_err(|_| bad())?), at));
        Ok(())
    })?;
    tx.core.ix.lost_due.extend(v);
    Ok(())
}

/// Loads the kept copies.
pub(crate) fn load_kept(tx: &mut Tx<'_>) -> Result<()> {
    let mut v = Vec::new();
    tx.scan(KEPT_COPY, |k, val| {
        let bad = || Error::Corrupt("kept copies");
        let via = val.chunks(osis_base::format::TID_LEN).map(|c| Ok(Tid::from_bytes(c.try_into().map_err(|_| bad())?))).collect::<Result<BTreeSet<Tid>>>()?;
        v.push((Tid::from_bytes(k.try_into().map_err(|_| bad())?), via));
        Ok(())
    })?;
    tx.core.ix.kept.extend(v);
    Ok(())
}

/// Takes the work list's entries due now (`all`: every entry), returning them.
fn take_due(tx: &mut Tx<'_>, all: bool) -> Result<BTreeSet<Tid>> {
    let now = tx.now().0;
    let due: BTreeSet<Tid> = tx.core.ix.lost_due.iter().filter(|(_, at)| all || **at <= now).map(|(t, _)| *t).collect();
    for t in &due {
        tx.core.ix.lost_due.remove(t);
        tx.txn.remove_local(&[LOST_DUE, t.as_bytes()].concat(), osis_store::Shred::No)?;
    }
    Ok(due)
}

/// Whether the node or a held key actor has a role on `a` now (any path, `until` honoured).
fn readable(core: &Core, a: &Tid) -> bool {
    let node = core.id.tid();
    core.role_now(&node, a).is_some() || core.key_actors.keys().any(|k| core.role_now(k, a).is_some())
}

/// Whether box recipient `m` is this node, a held key actor or an actor it holds and reads now.
fn ours(core: &Core, m: &Tid) -> bool {
    *m == core.id.tid() || core.key_actors.contains_key(m) || (core.ix.secrets.contains_key(m) && readable(core, m))
}

/// Whether a role on `x` gives one on `a`: `x` is `a`, on its owner chain, or holds a role on it.
fn reaches(core: &Core, x: &Tid, a: &Tid) -> bool {
    core.owner_chain(a).filter_map(|s| s.thing()).any(|c| c == *x) || core.role_now(x, a).is_some()
}

/// How long after its `ts` a held pending grant by a plausible granter keeps this node from
/// dropping an actor it holds checked secrets of. Minor consequence: past it the node drops and
/// re-learns the secrets from the grant's own boxes when it applies, re-fetching the content. At
/// 0 every such grant waits that way; at infinity a grant that never applies (a part parked for
/// good) keeps a node that lost access holding the actor's secrets and content for good.
pub const PENDING_GRANT_WAIT_MS: u64 = 24 * 60 * 60 * 1000;

/// A held, not applied role commit's boxes to this node on actor `x`.
struct PendingGrant {
    x: Tid,
    /// Its author may grant on `x` now, as this node sees it (admin or an invite), and its `ts`
    /// is within `PENDING_GRANT_WAIT_MS` before now (and not past `MAX_DRIFT` ahead), checked by
    /// its signature (`authentic`).
    plausible: bool,
    /// When `plausible` ends by age (`ts` + `PENDING_GRANT_WAIT_MS`).
    until: u64,
}

/// Actors a held, not applied role commit (pending, parked readable, or late parts)
/// boxes secrets of to this node, a held key actor or an actor it reads now: grants this node
/// may yet get (their secrets may be read already, spec/crypto.md §4), never a loss.
fn pending_grants(tx: &mut Tx<'_>) -> Result<Vec<PendingGrant>> {
    let mut out = Vec::new();
    let now = tx.now().0;
    let mut after = None;
    loop {
        let page = tx.txn.pending(after.as_ref(), 256)?;
        let n = page.len();
        for (id, _, bytes) in page {
            after = Some(id);
            let Ok(blob) = osis_commit::CommitBlob::decode(&bytes) else { continue };
            let (author, ts) = (blob.header.author, blob.header.ts.wall_ms().0);
            let until = ts.saturating_add(PENDING_GRANT_WAIT_MS);
            let recent = until > now && ts <= now.saturating_add(osis_base::format::MAX_DRIFT_MS);
            for (x, w) in crate::apply::keys::pending_secrets_writes(&blob, &id) {
                let core = &*tx.core;
                if w.boxes.keys().any(|k| ours(core, &k.holder)) {
                    out.push(PendingGrant { x, plausible: recent && may_grant(core, &author, &x) && authentic(core, &blob, &id, &x), until });
                }
            }
        }
        if n < 256 {
            return Ok(out);
        }
    }
}

/// The actors not applied commit `id` boxes to this node, a held key actor or an actor it reads
/// a read epoch newer than any it held checked (`held`: newest checked read epoch number per
/// dropped actor; a grant from after a rotation that left the node out; reading candidates, as
/// a re-grant read before the removal applied gives, do not count), signed (`authentic`) by an
/// author who may grant on them now: forgetting keeps those `secrets.0` parts, whatever the
/// commit's age (spec/permissions.md §3), so a re-grant applied after the loss brings its boxes.
/// A box only at an epoch the node held (a grant from before the removal, which applied gives no
/// role) goes: kept, it would hold the lost secrets for good. Cost: such a re-grant that never
/// applies keeps its sealed box.
pub(crate) fn boxes_kept(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, held: &BTreeMap<Tid, u64>) -> BTreeSet<Tid> {
    if core.ix.commits.contains_key(id) {
        return BTreeSet::new();
    }
    let newer = |x: &Tid, k: &BoxKey| ours(core, &k.holder) && k.role == Role::Read && held.get(x).is_none_or(|n| k.epoch.n > *n);
    crate::apply::keys::pending_secrets_writes(blob, id).into_iter().filter(|(x, w)| w.boxes.keys().any(|k| newer(x, k)) && may_grant(core, &blob.header.author, x) && authentic(core, blob, id, x)).map(|(x, _)| x).collect()
}

impl Engine {
    /// Whether a held, not applied commit (parked ones aside) writes `a`'s `keys.0`, signed
    /// (`authentic`) by an admin of `a` now: a newer deposit seed may be on its way (node-sync
    /// holds back a deposit-only step meanwhile). Anyone can send a pending commit naming any
    /// aspect, so an unsigned one never counts: it would hold the step back for good.
    pub fn keys_write_pending(&mut self, a: &Tid) -> Result<bool> {
        let a = *a;
        let ids: Vec<osis_base::CommitId> = self.core.ix.pending.iter().filter(|(_, r)| **r != crate::Reason::Parked).map(|(c, _)| *c).collect();
        self.run(|tx| {
            for id in ids {
                let Some((_, bytes)) = tx.txn.get_pending(&id)? else { continue };
                let Ok(blob) = osis_commit::CommitBlob::decode(&bytes) else { continue };
                let h = &blob.header;
                if h.aspects.iter().any(|x| x.tid == a && x.ak.as_str() == "keys.0") && tx.core.role_now(&h.author, &a) == Some(Role::Admin) && authentic(tx.core, &blob, &id, &a) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

/// Whether pending `blob` is signed by its author and its `secrets.0` parts on `x` are the ones its
/// header lists: a commit waiting on its author's chain or a creation record is stored unchecked, so its
/// `author` and `ts` could be anyone's.
pub(crate) fn authentic(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, x: &Tid) -> bool {
    let h = &blob.header;
    let Some(osis_base::CreationRecord::KeyActor { public_key, .. }) = core.created(&h.author) else { return false };
    let Ok(vk) = osis_crypto::VerifyingKey::from_slice(public_key) else { return false };
    let mut interner = osis_crdt::Interner::new();
    osis_commit::verify_signature(id, &blob.signature, &vk).is_ok()
        && blob.parts.iter().all(|p| match h.aspects.get(p.ai) {
            Some(a) if a.tid == *x && a.ak.as_str() == "secrets.0" => core.dedup(x).is_some_and(|d| osis_commit::verify_part(h, id, p, &d, &mut interner, None).is_ok()),
            _ => true,
        })
}

/// Whether `author` may grant on `x` now: admin, or an invite (spec/permissions.md §2).
fn may_grant(core: &Core, author: &Tid, x: &Tid) -> bool {
    let at = At::now(now_ts(core));
    core.role_now(author, x) == Some(Role::Admin) || core.timelines.get(x).and_then(|t| t.invite(author, x, at)).is_some()
}

/// Of `cands`, the actors this node holds a secret of and lost read access to
/// (spec/permissions.md §3): no role on them by any path now and no pending grant or
/// `contested` thing reaching them. Each actor is judged on its own, so what the node reached
/// only through a lost one is lost with it. (Epochs observed without a secret are no access.)
/// An actor this node holds checked secrets of is kept only by a plausible grant: anyone can
/// send a pending commit, which is kept until it applies, so any other would keep a node that
/// lost access holding it for good; reading-only candidates go with the commit that gave them.
/// Also returns, for the unread actors a plausible pending grant keeps, the earliest time one of
/// those grants stops counting by age (they may be lost from then on).
fn judge(tx: &mut Tx<'_>, cands: Vec<Tid>) -> Result<(Vec<Tid>, BTreeMap<Tid, u64>)> {
    let unread: Vec<Tid> = cands.into_iter().filter(|a| tx.core.ix.secrets.get(a).is_some_and(ActorEpochs::holds_any) && !readable(tx.core, a)).collect();
    if unread.is_empty() {
        return Ok((unread, BTreeMap::new()));
    }
    let pend = pending_grants(tx)?;
    let core = &*tx.core;
    let checked = |a: &Tid| core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).held().next().is_some()));
    let held: Vec<Tid> = unread.iter().filter(|k| contested(core, k)).copied().collect();
    let kept = |a: &Tid| pend.iter().any(|g| (g.plausible || !checked(a)) && reaches(core, &g.x, a)) || held.iter().any(|x| reaches(core, x, a));
    let ages = |a: &Tid| pend.iter().filter(|g| g.plausible && reaches(core, &g.x, a)).map(|g| g.until).min();
    let (kept, lost): (Vec<Tid>, Vec<Tid>) = unread.into_iter().partition(kept);
    Ok((lost, kept.iter().filter_map(|a| Some((*a, ages(a)?))).collect()))
}

/// This node's own self-removals (`departures_placing`) behind a departure from `a`.
fn own_leaving(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<osis_base::CommitId>> {
    Ok(super::departures_placing(tx, a)?.into_iter().filter_map(|(_, c)| c).collect())
}

/// Whether `k` is a thing where a held single-use redemption granting one of ours stands void
/// only because an applied redemption by the same signer removed the signer's edge first, with
/// no explicit write on that edge since: a link race the sharer has not finalized
/// (spec/permissions.md §3, §9). The finalization may drop the competing redemption and make
/// ours stand, so until it arrives the loser keeps the secrets (and with them follows the
/// labels) it would get back. A redemption is a commit removing its signer's own edge on `k`
/// beside a grant: a plain leave followed by a void grant (a leaver's forgery) defers nothing.
fn contested(core: &Core, k: &Tid) -> bool {
    let Some(tl) = core.timelines.get(k) else { return false };
    let op = |mc: &osis_perm::RoleCommit, i: usize| osis_perm::WriteId::Op(mc.id, i as u32);
    // the index of the redemption's self-removal
    let leave = |mc: &osis_perm::RoleCommit| {
        let j = mc.ops.iter().position(|o| o.target == *k && o.holder == mc.author && o.edge.is_none())?;
        mc.ops.iter().any(|o| o.target == *k && o.holder != mc.author && o.edge.is_some()).then_some(j)
    };
    let reds: Vec<_> = core.ix.by_thing.get(k).into_iter().flatten().filter_map(|c| tl.role_commit(c)).filter_map(|mc| Some((mc, leave(mc)?))).collect();
    reds.iter().any(|(mc, j)| {
        tl.lowered_unaudited(&mc.author, k)
            && mc.ops.iter().enumerate().any(|(i, o)| i != *j && o.target == *k && o.edge.is_some() && ours(core, &o.holder) && !tl.is_applied(&op(mc, i)))
            && reds.iter().any(|(w, jw)| w.author == mc.author && w.id != mc.id && tl.is_applied(&op(w, *jw)))
    })
}

/// One way a lost actor's copy may hang on holder `via`.
#[derive(Clone, Copy)]
struct Way {
    /// An ended edge's last value has `keep`, or the way is alive (an edge or owner link from a
    /// holder that is itself kept).
    keep: bool,
    /// The write that ended it: the node must have read the holder just before it.
    end: Option<osis_perm::Point>,
}

/// The ways to each of `actors` the timeline shows.
fn ways(core: &Core, actors: &BTreeSet<Tid>) -> BTreeMap<Tid, BTreeMap<Tid, Way>> {
    let ts = now_ts(core);
    let live = Way { keep: true, end: None };
    let mut out: BTreeMap<Tid, BTreeMap<Tid, Way>> = BTreeMap::new();
    for a in actors {
        let w = out.entry(*a).or_default();
        if let Some(tl) = core.timelines.get(a) {
            w.extend(tl.ended(a, ts).into_iter().map(|(h, (e, end))| (h, Way { keep: e.keep, end })));
            w.extend(tl.roster(a, At::now(ts)).into_keys().map(|h| (h, live)));
        }
        if let Some(o) = core.owner(a) {
            w.insert(o, live);
        }
    }
    out
}

/// The copies to keep among `lost` and the held copies `marks` (spec/permissions.md §3, Keep), each
/// with the holders it hangs on. A copy hangs on holder H while the node still has H (it is H, or
/// reads H, or keeps H) and the way through H is one that keeps; a holder already recorded goes
/// only on the timeline's word: its edge's last value now says erase. Least fixpoint, so holders
/// cannot keep each other.
fn keeps(core: &Core, lost: &BTreeSet<Tid>, marks: &BTreeMap<Tid, BTreeSet<Tid>>) -> BTreeMap<Tid, BTreeSet<Tid>> {
    let me = core.id.tid();
    let own = |h: &Tid| *h == me || core.key_actors.contains_key(h);
    let all: BTreeSet<Tid> = lost.iter().chain(marks.keys()).copied().collect();
    let ways = ways(core, &all);
    let read_then = |a: &Tid, h: &Tid, end: Option<osis_perm::Point>| {
        let Some(p) = end else { return true };
        own(h) || core.timelines.get(a).is_some_and(|tl| std::iter::once(&me).chain(core.key_actors.keys()).any(|x| tl.role(x, h, At::before(p)).is_some()))
    };
    let mut kept: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
    loop {
        let mut grew = false;
        for a in &all {
            let (w, old) = (ways.get(a), marks.get(a));
            let has = |h: &Tid| own(h) || readable(core, h) || kept.contains_key(h);
            let mut via: BTreeSet<Tid> = w.into_iter().flatten().filter(|(h, x)| x.keep && has(h) && read_then(a, h, x.end)).map(|(h, _)| *h).collect();
            via.extend(old.into_iter().flatten().filter(|h| has(h) && w.and_then(|w| w.get(*h)).is_none_or(|x| x.keep && read_then(a, h, x.end))));
            if !via.is_empty() && kept.get(a) != Some(&via) {
                kept.insert(*a, via);
                grew = true;
            }
        }
        if !grew {
            return kept;
        }
    }
}

/// `blob` without its parts on a kept copy's content (`retention::forget::frozen`).
pub(crate) fn without_frozen(core: &Core, blob: osis_commit::CommitBlob) -> osis_commit::CommitBlob {
    let h = &blob.header;
    let frozen: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).filter(|ai| h.aspects.get(*ai).is_some_and(|a| crate::retention::forget::frozen(core, &a.tid, &a.ak))).collect();
    if frozen.is_empty() {
        return blob;
    }
    osis_commit::rewrite(&blob, |ai, _| frozen.contains(&ai))
}

/// Drops the secrets of `lost` actors (diagnostic each) and forgets what only they read; keeps
/// what the rules keep, and erases the held copies (minus `dropped`, the user's) nothing keeps
/// now. `rejudge`: a role commit may have changed what the held copies hang on.
fn drop_actors(tx: &mut Tx<'_>, lost: Vec<Tid>, dropped: &[Tid], rejudge: bool) -> Result<(Vec<Tid>, Forgotten)> {
    if lost.is_empty() && dropped.is_empty() && !(rejudge && !tx.core.ix.kept.is_empty()) {
        return Ok((lost, Forgotten::default()));
    }
    tx.core.touch();
    // a copy re-granted is a holder's again once a secret came too: with none, a loss would not be
    // judged, and its content would stay with no mark
    let held: Vec<(Tid, BTreeSet<Tid>)> = tx.core.ix.kept.iter().map(|(a, v)| (*a, v.clone())).collect();
    let holder_again = |a: &Tid| readable(tx.core, a) && tx.core.ix.secrets.get(a).is_some_and(ActorEpochs::holds_any);
    let marks: BTreeMap<Tid, BTreeSet<Tid>> = held.iter().filter(|(a, _)| !dropped.contains(a) && !holder_again(a)).cloned().collect();
    let new: BTreeSet<Tid> = lost.iter().copied().collect();
    let kept = keeps(tx.core, &new, &marks);
    // every copy whose mark changes, the ones forgotten below included
    for (a, v) in &held {
        if kept.get(a) != Some(v) {
            tx.core.ix.kept.remove(a);
            tx.txn.remove_local(&[KEPT_COPY, a.as_bytes()].concat(), osis_store::Shred::No)?;
        }
    }
    for (a, v) in &kept {
        if tx.core.ix.kept.get(a) != Some(v) {
            let val: Vec<u8> = v.iter().flat_map(|t| t.as_bytes().iter().copied()).collect();
            tx.txn.put_local(&[KEPT_COPY, a.as_bytes()].concat(), &val, osis_store::Shred::No)?;
            tx.core.ix.kept.insert(*a, v.clone());
        }
    }
    let gone: Vec<Tid> = held.iter().map(|(a, _)| *a).filter(|a| !kept.contains_key(a) && (dropped.contains(a) || marks.contains_key(a))).collect();
    let lost: Vec<Tid> = lost.into_iter().chain(gone).collect();
    let held: BTreeMap<Tid, u64> = lost.iter().filter_map(|a| Some((*a, tx.core.ix.secrets.get(a)?.read.held().map(|(e, _)| e.n()).max()?))).collect();
    for a in &lost {
        tx.core.ix.secrets.remove(a);
        tx.core.role_changed();
        tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: if kept.contains_key(a) { "lost read access: secrets dropped, a read-only copy kept" } else { "lost read access: secrets and what only they read dropped" }.into() }, now);
    }
    let f = crate::retention::forget::forget(tx, &lost, &held)?;
    Ok((lost, f))
}

/// Which lost actors `Engine::forget_lost` drops.
#[derive(Clone, Copy, Debug)]
pub enum LostScope<'a> {
    /// Every held actor this node lost read access to (the work list is done with it).
    All,
    /// The trigger: takes the work list's due entries and drops the held actors a role on one
    /// of their things reaches that this node lost read access to (idempotent: the entries go
    /// in the same transaction), except those lost through its own self-removal
    /// (`Engine::lost_leaving`).
    Due,
    /// Those of these actors this node lost read access to.
    Only(&'a [Tid]),
    /// The user drops these kept copies (`Engine::kept_copies`).
    Kept(&'a [Tid]),
}

/// What `Engine::forget_lost` dropped.
#[derive(Default)]
pub struct Dropped {
    pub actors: Vec<Tid>,
    pub forgotten: Forgotten,
    /// `LostScope::Due` left a lost actor to its own self-removal's placement.
    pub leaving: bool,
}

fn drop_scope(tx: &mut Tx<'_>, scope: LostScope<'_>) -> Result<Dropped> {
    let mut rejudge = false;
    let cands: Vec<Tid> = match scope {
        LostScope::All => {
            take_due(tx, true)?;
            rejudge = true;
            tx.core.ix.secrets.keys().copied().collect()
        }
        LostScope::Only(xs) => xs.to_vec(),
        LostScope::Kept(_) => Vec::new(),
        LostScope::Due => {
            let due = take_due(tx, false)?;
            let core = &*tx.core;
            rejudge = core.ix.kept.iter().any(|(a, via)| due.iter().any(|t| via.contains(t) || reaches(core, t, a)));
            // a box opened late may have given a copy a secret: judged again, it goes
            let copies = core.ix.kept.keys();
            core.ix.secrets.keys().filter(|a| due.iter().any(|t| reaches(core, t, a))).chain(copies).copied().collect()
        }
    };
    let (judged, kept) = judge(tx, cands)?;
    // a grant that never applies stops keeping them once it ages out: judged again then
    for (a, at) in kept {
        arm_lost_due(tx, a, at)?;
    }
    let (lost, leaving) = match scope {
        LostScope::All | LostScope::Only(_) | LostScope::Kept(_) => (judged, false),
        LostScope::Due => {
            let (mut lost, mut leaving) = (Vec::new(), false);
            for a in judged {
                // its removal goes up first (spec/permissions.md §3): node-sync's `drop_left`
                if own_leaving(tx, &a)?.is_empty() {
                    lost.push(a);
                } else {
                    leaving = true;
                }
            }
            (lost, leaving)
        }
    };
    let dropped = match scope {
        LostScope::Kept(xs) => xs,
        _ => &[],
    };
    let (actors, forgotten) = drop_actors(tx, lost, dropped, rejudge)?;
    Ok(Dropped { actors, forgotten, leaving })
}

/// What this node lost read access to through its own self-removals (`Engine::lost_leaving`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Leaving {
    /// Each such lost actor and the self-removals behind it.
    pub actors: BTreeMap<Tid, BTreeSet<osis_base::CommitId>>,
    /// When an actor with a self-removal behind it, kept now by a pending grant, may become
    /// lost as that grant ages out (engine ms).
    pub recheck_at: Option<u64>,
}

impl Engine {
    /// Drops the secrets of actors this node lost read access to, and of what it reached only
    /// through them, and forgets every thing it no longer reads by another path
    /// (spec/permissions.md §3), with a diagnostic per actor. Returns them.
    pub fn drop_lost_secrets(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(LostScope::All)?.actors)
    }

    /// The held actors this node lost read access to with its own self-removals
    /// (`departures_placing`) behind a departure from them. The trigger leaves them; node-sync
    /// drops each (`LostScope::Only`) once its self-removals are placed. From stored state only,
    /// so a restart between a self-removal and its drop finds them.
    pub fn lost_leaving(&mut self) -> Result<Leaving> {
        self.run(|tx| {
            let all: Vec<Tid> = tx.core.ix.secrets.keys().copied().collect();
            let (lost, kept) = judge(tx, all)?;
            let mut out = Leaving::default();
            for a in lost {
                let own = own_leaving(tx, &a)?;
                if !own.is_empty() {
                    out.actors.insert(a, own);
                }
            }
            for (a, t) in kept {
                if !own_leaving(tx, &a)?.is_empty() {
                    out.recheck_at = Some(out.recheck_at.map_or(t, |x| x.min(t)));
                }
            }
            Ok(out)
        })
    }

    /// Whether the lost-access trigger has work due now (`drop_lost_due`).
    pub fn lost_due(&self) -> bool {
        let now = self.now().0;
        self.core.ix.lost_due.values().any(|at| *at <= now)
    }

    /// When the lost-access trigger's next entry not due now comes due (engine ms): a plausible
    /// pending grant keeping an actor ages out. Every scope arms these (a judged actor a
    /// plausible grant keeps), so the trigger drops it then if the grant never applied.
    pub fn next_lost_due(&self) -> Option<u64> {
        let now = self.now().0;
        self.core.ix.lost_due.values().filter(|at| **at > now).min().copied()
    }

    /// The lost-access trigger (spec/permissions.md §3): after received role commits
    /// applied, drops the secrets of the actors they touched that this node lost read access to
    /// by every path, unless a held pending grant reaches them or its own self-removal is
    /// behind the loss (`lost_leaving`), and forgets what only those read. node-sync runs it
    /// every step and wakes at `next_lost_due`; an app driving the engine alone calls it after
    /// ingesting and when `next_lost_due` passes. Returns the actors dropped.
    pub fn drop_lost_due(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(LostScope::Due)?.actors)
    }

    /// The actors whose read-only copy this node keeps (spec/permissions.md §3, Keep): no secret, no
    /// sync, no write; `get` and the rest still read what it held. `drop_kept`-able.
    pub fn kept_copies(&self) -> Vec<Tid> {
        self.core.ix.kept.keys().copied().collect()
    }

    /// Whether a client of this node, `actor`, reads `t` as a kept copy (notes/client-port.md §3):
    /// it is a holder the copy hangs on, or an app of the person, holding a role on the person
    /// that owns it, with a role now on such a holder (through a holder that is itself kept, too).
    /// Invariant: a copy is the person's: a role on a holder alone, as a member of a group the
    /// person is in, reads nothing of it, nor does any other client; no write right follows.
    pub fn copy_readable_by(&self, actor: &Tid, t: &Tid) -> bool {
        let core = &self.core;
        let Some(a) = crate::retention::forget::copy_of(core, t) else { return false };
        let app = core.owner(actor).is_some_and(|p| core.role_now(actor, &p).is_some());
        let mut seen = BTreeSet::from([a]);
        let mut todo = vec![a];
        while let Some(x) = todo.pop() {
            for h in core.ix.kept.get(&x).into_iter().flatten() {
                if h == actor || (app && core.role_now(actor, h).is_some()) {
                    return true;
                }
                if seen.insert(*h) {
                    todo.push(*h);
                }
            }
        }
        false
    }

    /// Drops lost actors (`scope`), with what was forgotten (node-sync drops its label
    /// sessions).
    pub fn forget_lost(&mut self, scope: LostScope<'_>) -> Result<Dropped> {
        let r = self.run(|tx| drop_scope(tx, scope))?;
        if !r.forgotten.things.is_empty() {
            self.reload()?;
            self.reexamine()?;
        }
        Ok(r)
    }
}
