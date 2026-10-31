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
/// read access"): `l/` + tid, a roster target of an applied received membership commit, or an
/// aspect's thing of a dropped pending one. The held actors a role on it reaches are
/// re-evaluated after the apply, in a transaction of their own (node-sync, every step).
pub(crate) const LOST_DUE: &[u8] = b"l/";

/// Adds `tids` to the work list.
pub(crate) fn mark_lost_due(tx: &mut Tx<'_>, tids: impl IntoIterator<Item = Tid>) -> Result<()> {
    for t in tids {
        tx.txn.put_local(&[LOST_DUE, t.as_bytes()].concat(), &[], osis_store::Shred::No)?;
        tx.core.ix.lost_due.insert(t);
    }
    Ok(())
}

/// Loads the work list.
pub(crate) fn load_lost_due(tx: &mut Tx<'_>) -> Result<()> {
    let mut v = Vec::new();
    tx.scan(LOST_DUE, |k, _| {
        v.push(Tid::from_bytes(k.try_into().map_err(|_| Error::Corrupt("lost-access work list"))?));
        Ok(())
    })?;
    tx.core.ix.lost_due.extend(v);
    Ok(())
}

/// Empties the work list, returning it.
fn take_due(tx: &mut Tx<'_>) -> Result<BTreeSet<Tid>> {
    let due: BTreeSet<Tid> = tx.core.ix.lost_due.iter().copied().collect();
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
    let mut cur = *a;
    for _ in 0..64 {
        if cur == *x {
            return true;
        }
        match core.owner(&cur) {
            Some(o) => cur = o,
            None => break,
        }
    }
    core.role_now(x, a).is_some()
}

/// How long after its `ts` a held pending grant by a plausible granter keeps this node from
/// dropping an actor it holds checked secrets of. Minor consequence: past it the node drops and
/// re-learns the secrets from the grant's own boxes when it applies, re-fetching the content. At
/// 0 every such grant waits that way; at infinity a grant that never applies (a part parked for
/// good) keeps a node that lost access holding the actor's secrets and content for good.
pub(crate) const PENDING_GRANT_WAIT_MS: u64 = 24 * 60 * 60 * 1000;

/// A held, not applied membership commit's boxes to this node on actor `x`.
struct PendingGrant {
    x: Tid,
    /// Its author may grant on `x` now, as this node sees it (admin or an invite), and its `ts`
    /// is within `PENDING_GRANT_WAIT_MS` before now (and not past `MAX_DRIFT` ahead), checked by
    /// its signature (`authentic`).
    plausible: bool,
}

/// Actors a held, not applied membership commit (pending, parked readable, or late parts)
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
            let recent = ts.saturating_add(PENDING_GRANT_WAIT_MS) > now && ts <= now.saturating_add(osis_base::format::MAX_DRIFT_MS);
            for (x, w) in crate::apply::keys::pending_secrets_writes(&blob, &id) {
                let core = &*tx.core;
                if w.boxes.keys().any(|k| ours(core, &k.member)) {
                    out.push(PendingGrant { x, plausible: recent && may_grant(core, &author, &x) && authentic(core, &blob, &id, &x) });
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
/// author who may grant on them now: forgetting keeps those `/secrets` parts, whatever the
/// commit's age (spec/permissions.md §3), so a re-grant applied after the loss brings its boxes.
/// A box only at an epoch the node held (a grant from before the removal, which applied gives no
/// role) goes: kept, it would hold the lost secrets for good. Cost: such a re-grant that never
/// applies keeps its sealed box.
pub(crate) fn boxes_kept(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, held: &BTreeMap<Tid, u64>) -> BTreeSet<Tid> {
    if core.ix.commits.contains_key(id) {
        return BTreeSet::new();
    }
    let newer = |x: &Tid, k: &BoxKey| ours(core, &k.member) && k.role == Role::Read && held.get(x).is_none_or(|n| k.epoch.n > *n);
    crate::apply::keys::pending_secrets_writes(blob, id).into_iter().filter(|(x, w)| w.boxes.keys().any(|k| newer(x, k)) && may_grant(core, &blob.header.author, x) && authentic(core, blob, id, x)).map(|(x, _)| x).collect()
}

impl Engine {
    /// Whether a held, not applied commit (parked ones aside) writes `a`'s `/keys`, signed
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
                if h.aspects.iter().any(|x| x.tid == a && x.ak.as_str() == "/keys") && tx.core.role_now(&h.author, &a) == Some(Role::Admin) && authentic(tx.core, &blob, &id, &a) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

/// Whether pending `blob` is signed by its author and its `/secrets` parts on `x` are the ones its
/// header lists: a commit waiting on its author's chain or a creation record is stored unchecked, so its
/// `author` and `ts` could be anyone's.
pub(crate) fn authentic(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, x: &Tid) -> bool {
    let h = &blob.header;
    let Some(osis_base::CreationRecord::KeyActor { public_key, .. }) = core.created(&h.author) else { return false };
    let Ok(vk) = osis_crypto::VerifyingKey::from_slice(public_key) else { return false };
    let mut interner = osis_crdt::Interner::new();
    osis_commit::verify_signature(id, &blob.signature, &vk).is_ok()
        && blob.parts.iter().all(|p| match h.aspects.get(p.ai) {
            Some(a) if a.tid == *x && a.ak.as_str() == "/secrets" => core.dedup(x).is_some_and(|d| osis_commit::verify_part(h, id, p, &d, &mut interner, None).is_ok()),
            _ => true,
        })
}

/// Whether `author` may grant on `x` now: admin, or an invite (spec/permissions.md §2).
fn may_grant(core: &Core, author: &Tid, x: &Tid) -> bool {
    let at = At::now(now_ts(core));
    core.role_now(author, x) == Some(Role::Admin) || core.timelines.get(x).and_then(|t| t.invite(author, x, at)).is_some()
}

/// Of `cands`, the actors this node holds a secret of and lost read access to
/// (spec/permissions.md §3): no role on them by any path now and no pending grant or `contested` thing reaching them.
/// Each actor is judged on its own, so what the node reached only through a lost one is lost
/// with it. (Epochs observed without a secret are no access.) An actor this node holds checked
/// secrets of is kept only by a plausible grant: anyone can send a pending commit, which is kept
/// until it applies, so any other would keep a node that lost access holding it for good;
/// reading-only candidates go with the commit that gave them.
fn lost_among(tx: &mut Tx<'_>, cands: Vec<Tid>) -> Result<Vec<Tid>> {
    let unread: Vec<Tid> = cands.into_iter().filter(|a| tx.core.ix.secrets.get(a).is_some_and(ActorEpochs::holds_any) && !readable(tx.core, a)).collect();
    if unread.is_empty() {
        return Ok(unread);
    }
    let pend = pending_grants(tx)?;
    let core = &*tx.core;
    let checked = |a: &Tid| core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).held().next().is_some()));
    let held: Vec<Tid> = unread.iter().filter(|k| contested(core, k)).copied().collect();
    let kept = |a: &Tid| pend.iter().any(|g| (g.plausible || !checked(a)) && reaches(core, &g.x, a)) || held.iter().any(|x| reaches(core, x, a));
    Ok(unread.into_iter().filter(|a| !kept(a)).collect())
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
    let op = |mc: &osis_perm::MembershipCommit, i: usize| osis_perm::WriteId::Op(mc.id, i as u32);
    // the index of the redemption's self-removal
    let leave = |mc: &osis_perm::MembershipCommit| {
        let j = mc.ops.iter().position(|o| o.target == *k && o.member == mc.author && o.edge.is_none())?;
        mc.ops.iter().any(|o| o.target == *k && o.member != mc.author && o.edge.is_some()).then_some(j)
    };
    let reds: Vec<_> = core.ix.by_thing.get(k).into_iter().flatten().filter_map(|c| tl.membership_commit(c)).filter_map(|mc| Some((mc, leave(mc)?))).collect();
    reds.iter().any(|(mc, j)| {
        tl.lowered_unaudited(&mc.author, k)
            && mc.ops.iter().enumerate().any(|(i, o)| i != *j && o.target == *k && o.edge.is_some() && ours(core, &o.member) && !tl.is_applied(&op(mc, i)))
            && reds.iter().any(|(w, jw)| w.author == mc.author && w.id != mc.id && tl.is_applied(&op(w, *jw)))
    })
}

/// Drops the secrets of `lost` actors (diagnostic each) and forgets what only they read.
fn drop_actors(tx: &mut Tx<'_>, lost: Vec<Tid>) -> Result<(Vec<Tid>, Forgotten)> {
    if lost.is_empty() {
        return Ok((lost, Forgotten::default()));
    }
    tx.core.touch();
    let held: BTreeMap<Tid, u64> = lost.iter().filter_map(|a| Some((*a, tx.core.ix.secrets.get(a)?.read.held().map(|(e, _)| e.n()).max()?))).collect();
    for a in &lost {
        tx.core.ix.secrets.remove(a);
        tx.core.membership_changed();
        tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: "lost read access: secrets and what only they read dropped".into() }, now);
    }
    let f = crate::retention::forget::forget(tx, &lost, &held)?;
    Ok((lost, f))
}

/// Drops every held actor this node lost read access to (the work list is done with it).
pub(crate) fn drop_lost(tx: &mut Tx<'_>) -> Result<(Vec<Tid>, Forgotten)> {
    take_due(tx)?;
    let all: Vec<Tid> = tx.core.ix.secrets.keys().copied().collect();
    let lost = lost_among(tx, all)?;
    drop_actors(tx, lost)
}

/// The trigger: takes the work list and drops the held actors a role on one of its things
/// reaches that this node lost read access to (idempotent: the list goes in the same
/// transaction).
pub(crate) fn drop_lost_due(tx: &mut Tx<'_>) -> Result<(Vec<Tid>, Forgotten)> {
    let due = take_due(tx)?;
    let cands: Vec<Tid> = tx.core.ix.secrets.keys().filter(|a| due.iter().any(|t| reaches(tx.core, t, a))).copied().collect();
    let lost = lost_among(tx, cands)?;
    drop_actors(tx, lost)
}

impl Engine {
    /// Drops the secrets of actors this node lost read access to, and of what it reached only
    /// through them, and forgets every thing it no longer reads by another path
    /// (spec/permissions.md §3), with a diagnostic per actor. Returns them.
    pub fn drop_lost_secrets(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(false)?.0)
    }

    /// Whether the lost-access trigger has work (`drop_lost_due`).
    pub fn lost_due(&self) -> bool {
        !self.core.ix.lost_due.is_empty()
    }

    /// The lost-access trigger (spec/permissions.md §3): after received membership commits
    /// applied, drops the secrets of the actors they touched that this node lost read access to
    /// by every path, unless a held pending grant reaches them, and forgets what only those
    /// read. node-sync runs it every step; an app driving the engine alone calls it after
    /// ingesting. Returns the actors dropped.
    pub fn drop_lost_due(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(true)?.0)
    }

    /// `drop_lost_secrets` (or, `due`, `drop_lost_due`), with what was forgotten (node-sync
    /// drops its label sessions).
    pub fn forget_lost(&mut self, due: bool) -> Result<(Vec<Tid>, Forgotten)> {
        let r = self.run(|tx| if due { drop_lost_due(tx) } else { drop_lost(tx) })?;
        if !r.1.things.is_empty() {
            self.reload()?;
            self.reexamine()?;
        }
        Ok(r)
    }
}
