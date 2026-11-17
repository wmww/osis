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

/// Actors lost by an `until` passing alone (`lost_by_time`), left to node-sync to hear their
/// sync IDs out first (spec/permissions.md §2): `T/` + actor; value: when first judged (engine
/// ms, u64 BE), from which `LOST_HEARD_WAIT_MS` runs. Goes with the actor's drop, or when it
/// reads the actor again.
const TIMED_LOST: &[u8] = b"T/";

/// Kept copies (spec/permissions.md §3, Retain): `K/` + lost actor; value: the tids of the holders
/// its copy hangs on, concatenated, recorded at the drop (durably, spec/permissions.md §3).
const KEPT_COPY: &[u8] = b"K/";

/// Judges each of `tids` held again (its secrets' stamp moves): what made the node read it may
/// be gone with nothing else of it moving (the reading-only secrets a commit dropped as bad input
/// gave, an account it left). The drop follows that value (`Engine::lost_due`).
pub(crate) fn touch_held(tx: &mut Tx<'_>, tids: impl IntoIterator<Item = Tid>) {
    for t in tids {
        if let Some(e) = tx.core.ix.secrets.get(&t).cloned() {
            tx.core.ix.secrets.insert(t, e);
        }
    }
}

/// Loads the timed-loss records.
pub(crate) fn load_lost(tx: &mut Tx<'_>) -> Result<()> {
    let mut v = Vec::new();
    tx.scan(TIMED_LOST, |k, val| {
        let bad = || Error::Corrupt("timed-loss record");
        v.push((Tid::from_bytes(k.try_into().map_err(|_| bad())?), u64::from_be_bytes(val.try_into().map_err(|_| bad())?)));
        Ok(())
    })?;
    tx.core.ix.timed_lost.extend(v);
    Ok(())
}

/// When `a`, lost by the time alone, was first judged so: the record, or a new one at now.
fn timed_since(tx: &mut Tx<'_>, a: Tid) -> Result<u64> {
    if let Some(at) = tx.core.ix.timed_lost.get(&a) {
        return Ok(*at);
    }
    let now = tx.now().0;
    tx.txn.put_local(&[TIMED_LOST, a.as_bytes()].concat(), &now.to_be_bytes(), osis_store::Shred::No)?;
    tx.core.ix.timed_lost.insert(a, now);
    Ok(now)
}

/// Drops the timed-loss records of actors read again or no longer held.
fn prune_timed(tx: &mut Tx<'_>) -> Result<()> {
    let core = &*tx.core;
    let gone: Vec<Tid> = core.ix.timed_lost.keys().filter(|a| !over_held(core, a)).copied().collect();
    for a in gone {
        tx.txn.remove_local(&[TIMED_LOST, a.as_bytes()].concat(), osis_store::Shred::No)?;
        tx.core.ix.timed_lost.remove(&a);
    }
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

/// Whether the node holds `min` or above on `a` now (`tickets::role_on`: what its role commits
/// show, or a held ticket's word where they cannot show its holder's grant).
fn holds_at(core: &Core, a: &Tid, min: Role) -> bool {
    crate::sync::tickets::role_on(core, a) >= Some(min)
}

/// The best role the node or a held key actor holds on `a` now
/// (any path with key access, `until` honoured: `Core::keyed_role_now`).
pub(crate) fn role_here(core: &Core, a: &Tid) -> Option<Role> {
    let at = |m: &Tid| core.keyed_role_now(m, a);
    core.member().into_iter().chain([core.id.tid()]).map(|m| at(&m)).chain(core.key_actors.keys().map(at)).max().flatten()
}

/// Whether the node (`holds_at`) reads `a` now: read or above.
pub(crate) fn readable(core: &Core, a: &Tid) -> bool {
    holds_at(core, a, Role::Read)
}

/// Whether the node's roles on `a` now give it secrets there (spec/permissions.md §3: a node
/// holds no secret of an actor it cannot read): every role's, reading `a`; none else.
fn may_hold(core: &Core, a: &Tid) -> bool {
    readable(core, a)
}

/// Whether a box may give this node secrets of `a` (spec/permissions.md §3: a node holds
/// no secret of an actor it cannot read): its roles give them (`may_hold`), or an unfinalized link
/// race keeps what reaches `a` (`contested`, as `judge` keeps it). Every applied box is opened by
/// this rule (`Core::ingest_view`), so no box gives back what the trigger dropped.
pub(crate) fn may_take(core: &Core, a: &Tid) -> bool {
    may_hold(core, a) || {
        let chain = core.record_chain(a).filter_map(|s| s.thing());
        let holders = core.edge_holders(a).into_iter().map(|(m, _)| m).filter(|m| core.role_now(m, a).is_some());
        chain.chain(holders).any(|k| contested(core, &k))
    }
}

/// Whether a box may give this node `a`'s secret of role `r` (spec/permissions.md §3 No secret
/// taken back): every role's where it may take (`may_take`), the sync secret where its roles
/// give sync alone.
pub(crate) fn may_take_role(core: &Core, a: &Tid, r: Role) -> bool {
    may_take(core, a) || r == Role::Sync && holds_at(core, a, Role::Sync)
}

/// Whether an entry box or a ticket may give this node `a`'s secret of role `r`
/// (spec/sync-ids.md §3): as a box may (`may_take_role`), or while nothing held says the node lost
/// `a`: no ended edge on it of the node, a held key actor or an actor it reads (a link's redeemer
/// opens the sync ID before it holds the grant to its key; the trigger judges `a` once role
/// commits on it apply).
pub(crate) fn may_learn(core: &Core, a: &Tid, r: Role) -> bool {
    may_take_role(core, a, r) || core.timelines.get(a).is_none_or(|tl| !tl.ended(a, now_ts(core)).keys().any(|h| ours(core, h)))
}

/// Whether the node holds secrets of `a` no current role of its there covers (lost access): a
/// sync secret below sync (`holds_at`), any other below read (`may_hold`).
fn over_held(core: &Core, a: &Tid) -> bool {
    let Some(e) = core.ix.secrets.get(a) else { return false };
    let need = |r: Role| if r == Role::Sync { Role::Sync } else { Role::Read };
    ROLES.iter().any(|r| e.role(*r).holds_any() && !holds_at(core, a, need(*r)))
}

/// Whether all that ended the node's (or a held key actor's) role on `a` is an `until` passing:
/// walked with every edge's time ahead and every finalize undone (it counts as the `until` it
/// finalizes, spec/permissions.md §2), a role giving what it holds is there. A removal saying its own retain is written
/// with `until` 0, gone at every clock, so it never counts.
pub(super) fn lost_by_time(core: &Core, a: &Tid) -> bool {
    let ts = osis_base::Ts::default();
    let Some(tl) = core.timelines.get(a) else { return false };
    // a role giving what the node holds: read for read secrets (a lowering to sync with times
    // ahead is no loss by time), sync for a sync-only holder
    let reads = core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| *r != Role::Sync && e.role(*r).holds_any()));
    let need = if reads { Role::Read } else { Role::Sync };
    let role = |x: &Tid| tl.role_unfinalized(x, a, ts).is_some_and(|r| r >= need);
    core.member().as_ref().is_some_and(role) || core.key_actors.keys().any(role)
}

/// How long an actor lost by the time alone waits for node-sync to hear its sync IDs out before
/// it is dropped anyway (spec/permissions.md §2): a peer dead or hostile for good holds no
/// erasure off beyond it. `ROLE_KEEP_MS`, past which a node offline does not sync cleanly
/// anyway. Minor consequence: a node out of reach that long loses its unsent writes on what a
/// renewal it has not heard would have kept, and comes back by a re-seal; a later erase before
/// it. At 0 every offline holder loses those; at infinity one dead peer keeps every expired
/// share on the node for good.
pub const LOST_HEARD_WAIT_MS: u64 = osis_base::format::ROLE_KEEP_MS;

/// Whether box recipient `m` is this node, a held key actor or an actor it holds and reads now.
fn ours(core: &Core, m: &Tid) -> bool {
    Some(*m) == core.member() || *m == core.id.tid() || core.key_actors.contains_key(m) || (core.ix.secrets.contains_key(m) && readable(core, m))
}

/// Whether a role on `x` gives one on `a`: `x` is `a`, on its record chain, or holds a role on it.
fn reaches(core: &Core, x: &Tid, a: &Tid) -> bool {
    core.record_chain(a).filter_map(|s| s.thing()).any(|c| c == *x) || core.role_now(x, a).is_some()
}

/// The actors not applied commit `id` boxes to this node, a held key actor or an actor it reads
/// a read epoch newer than any it held checked (`held`: newest checked read epoch number per
/// dropped actor; a grant from after a rotation that left the node out; reading candidates, as
/// a re-grant read before the removal applied gives, do not count), signed (`authentic`) by an
/// author who may grant on them now: forgetting keeps those `secrets.0` parts, whatever the
/// commit's age (spec/permissions.md §3), so a re-grant applied after the loss brings its boxes.
/// A box only at an epoch the node held (a grant from before the removal, which applied gives no
/// role) goes: kept, it would hold the lost secrets for good. Cost: such a re-grant that never
/// applies keeps its sealed box. `known`: the verdict its stored copy keeps (`apply::kept_verdict`).
pub(crate) fn boxes_kept(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, held: &BTreeMap<Tid, u64>, known: Option<osis_commit::Signed>) -> BTreeSet<Tid> {
    if core.ix.commits.contains_key(id) {
        return BTreeSet::new();
    }
    let newer = |x: &Tid, k: &BoxKey| ours(core, &k.holder.0) && k.role == Role::Read && held.get(x).is_none_or(|n| k.epoch.n > *n);
    crate::apply::keys::pending_secrets_writes(blob, id).into_iter().filter(|(x, w)| w.boxes.keys().any(|k| newer(x, k)) && may_grant(core, &blob.header.author, x) && authentic(core, blob, id, x, known)).map(|(x, _)| x).collect()
}

impl Engine {
    /// Whether a `keys.0` write deciding `g`'s role keys is held but not applied: a pending
    /// commit (parked ones aside) writing the `keys.0` of the actor `g`'s secrets derive from,
    /// signed (`authentic`) by an admin of it now, or a held commit whose valid `keys.0` part on
    /// a thing from `g` up to that actor is missing (its body to be fetched: it may give that
    /// thing secrets of its own). A newer deposit seed, or another actor's, may be on its way
    /// (node-sync holds back a deposit-only step meanwhile). Anyone can send a pending commit
    /// naming any aspect, so an unsigned one never counts: it would hold the step back for good.
    pub fn keys_write_unapplied(&mut self, g: &Tid) -> Result<bool> {
        let g = *g;
        self.read(|tx| keys_write_unapplied(tx, &g))
    }
}

/// `Engine::keys_write_unapplied` inside a transaction.
pub(crate) fn keys_write_unapplied(tx: &mut crate::engine::Tx<'_>, g: &Tid) -> Result<bool> {
    let a = tx.core.secret_actor(g).unwrap_or(*g);
    let keys = osis_base::Ak::new("keys.0").map_err(|_| crate::Error::Misuse("ak"))?;
    let core = &*tx.core;
    let missing = |x: &Tid| {
        let part = |m: &crate::engine::Meta| m.aspect(x, &keys).is_some_and(|ai| m.valid_at(ai) && matches!(m.missing_as(ai), Some(crate::engine::Missing::Plain | crate::engine::Missing::ToFetch)));
        core.ix.by_aspect.get(&(*x, keys.clone())).into_iter().flatten().any(|(_, c)| core.ix.commits.get(c).is_some_and(part))
    };
    let below: Vec<Tid> = core.record_chain(g).map_while(|s| s.thing()).take_while(|x| *x != a).collect();
    if below.iter().chain([&a]).any(missing) {
        return Ok(true);
    }
    let ids: Vec<osis_base::CommitId> = core.ix.pending.iter().filter(|(_, r)| **r != crate::Reason::Parked).map(|(c, _)| *c).collect();
    for id in ids {
        let Some(p) = tx.txn.get_pending(&id)? else { continue };
        let Ok(blob) = osis_commit::CommitBlob::decode_stored(&p.bytes) else { continue };
        let h = &blob.header;
        if h.aspect_index(&a, "keys.0").is_some() && tx.core.role_now(&h.author, &a) == Some(Role::Admin) && authentic(tx.core, &blob, &id, &a, crate::apply::kept_verdict(&p)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether pending `blob` is signed by its author and its `secrets.0` parts on `x` are the ones its
/// header lists: a commit waiting on its author's chain or a creation record is stored unchecked, so its
/// `author` and `ts` could be anyone's. `known`: the verdict its stored copy keeps, if any.
pub(crate) fn authentic(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, x: &Tid, known: Option<osis_commit::Signed>) -> bool {
    let h = &blob.header;
    let mut interner = osis_crdt::Interner::new();
    crate::apply::signed_by_author(core, blob, id, core.created(&h.author), known) == Some(true)
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
/// Reading-only secrets of an actor (spec/permissions.md §3) are no loss of it while their source
/// commit may still be judged: a grant it may yet get.
fn judge(core: &Core, cands: Vec<Tid>) -> Vec<Tid> {
    let unread: Vec<Tid> = cands.into_iter().filter(|a| over_held(core, a)).collect();
    if unread.is_empty() {
        return unread;
    }
    let sourced: Vec<Tid> = core.ix.secrets.iter().filter(|(_, e)| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.sources().any(|u| core.waits.read_any(&u.commit))))).map(|(t, _)| *t).collect();
    let checked = |a: &Tid| core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).held().next().is_some()));
    let held: Vec<Tid> = unread.iter().filter(|k| contested(core, k)).copied().collect();
    let kept = |a: &Tid| (!checked(a) && sourced.iter().any(|x| reaches(core, x, a))) || held.iter().any(|x| reaches(core, x, a));
    unread.into_iter().filter(|a| !kept(a)).collect()
}

/// This node's own self-removals (`departures_placing`) from `a` or from an actor holding a role
/// on it, transitively over the edges (`edge_holders`: a destroyed actor it left before the destruction
/// included): what made it lose `a` (a node that left a holder actor loses what that actor reads).
fn own_leaving(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<osis_base::CommitId>> {
    let mut out = BTreeSet::new();
    let mut seen = BTreeSet::from([*a]);
    let mut work = vec![*a];
    while let Some(t) = work.pop() {
        out.extend(super::departures_placing(tx, &t)?.into_iter().filter_map(|(_, c)| c));
        for (m, _) in tx.core.edge_holders(&t) {
            if !tx.core.is_key_actor(&m) && seen.insert(m) {
                work.push(m);
            }
        }
    }
    Ok(out)
}

/// Whether `k` is a thing where a held single-use redemption granting one of ours stands void
/// only because an applied redemption by the same signer removed the signer's edge first, with
/// no explicit write on that edge since: a link race the sharer has not finalized
/// (spec/permissions.md §3, §7). The finalization may drop the competing redemption and make
/// ours stand, so until it arrives the loser keeps the secrets (and with them follows the
/// sync IDs) it would get back. A redemption is a commit removing its signer's own edge on `k`
/// beside a grant: a plain leave followed by a void grant (a leaver's forgery) defers nothing.
fn contested(core: &Core, k: &Tid) -> bool {
    let Some(tl) = core.timelines.get(k) else { return false };
    let op = |mc: &osis_perm::RoleCommit, i: usize| osis_perm::WriteId(mc.id, i as u32);
    // the index of the redemption's self-removal
    let leave = |mc: &osis_perm::RoleCommit| {
        let j = mc.ops.iter().position(|o| o.target == *k && o.holder == mc.author && o.edge.is_none())?;
        mc.ops.iter().any(|o| o.target == *k && o.holder != mc.author && o.edge.is_some()).then_some(j)
    };
    let reds: Vec<_> = core.on_thing(k).filter_map(|c| tl.role_commit(&c)).filter_map(|mc| Some((mc, leave(mc)?))).collect();
    reds.iter().any(|(mc, j)| {
        tl.lowered_unaudited(&mc.author, k)
            && mc.ops.iter().enumerate().any(|(i, o)| i != *j && o.target == *k && o.edge.is_some() && ours(core, &o.holder) && !tl.is_applied(&op(mc, i)))
            && reds.iter().any(|(w, jw)| w.author == mc.author && w.id != mc.id && tl.is_applied(&op(w, *jw)))
    })
}

/// One way a lost actor's copy may hang on holder `via`.
#[derive(Clone, Copy)]
struct Way {
    /// An ended edge's removal said retain, or its `until` passed under a default to retain, or the
    /// way is alive (an edge, a record edge included, from a holder that is itself kept).
    retain: bool,
    /// The write that ended it: the node must have read the holder just before it.
    end: Option<osis_perm::Point>,
}

/// The ways to each of `actors` the timeline shows.
fn ways(core: &Core, actors: &BTreeSet<Tid>) -> BTreeMap<Tid, BTreeMap<Tid, Way>> {
    let ts = now_ts(core);
    let live = Way { retain: true, end: None };
    let mut out: BTreeMap<Tid, BTreeMap<Tid, Way>> = BTreeMap::new();
    for a in actors {
        let w = out.entry(*a).or_default();
        if let Some(tl) = core.timelines.get(a) {
            let says = |e: osis_perm::EdgeEnd| match e {
                osis_perm::EdgeEnd::Said(k) => k,
                osis_perm::EdgeEnd::Until(key) => crate::apply::validity::retain_in_force(core, a, &key),
            };
            // an ended grant of sync read nothing to keep
            w.extend(tl.ended(a, ts).into_iter().filter(|(_, (_, _, r))| *r >= Role::Read).map(|(h, (e, end, _))| (h, Way { retain: says(e), end })));
        }
        // the roster now at read or above (a grant of sync reads nothing to keep), its record
        // edge included while it stands
        w.extend(core.current_holders(a).into_iter().filter(|(_, r, _)| *r >= Role::Read).map(|(h, _, _)| (h, live)));
    }
    out
}

/// The copies to keep among `lost` and the held copies `marks` (spec/permissions.md §3, Retain), each
/// with the holders it hangs on. A copy hangs on holder H while the node still has H (it is H, reads
/// H, keeps H, or holds H's secrets not dropped in this judging) and the way through H is one that keeps; a holder already recorded goes
/// only on the timeline's word: the edge's end now says erase. Least fixpoint, so holders
/// cannot keep each other.
fn keeps(core: &Core, lost: &BTreeSet<Tid>, marks: &BTreeMap<Tid, BTreeSet<Tid>>) -> BTreeMap<Tid, BTreeSet<Tid>> {
    let me = core.member();
    let own = |h: &Tid| Some(*h) == me || core.key_actors.contains_key(h);
    let all: BTreeSet<Tid> = lost.iter().chain(marks.keys()).copied().collect();
    let ways = ways(core, &all);
    let read_then = |a: &Tid, h: &Tid, end: Option<osis_perm::Point>| {
        let Some(p) = end else { return true };
        own(h) || core.timelines.get(a).is_some_and(|tl| me.iter().chain(core.key_actors.keys()).any(|x| tl.role(x, h, At::before(p)) >= Some(Role::Read)))
    };
    // a holder lost but not dropped in this judging (left to node-sync, or held by a pending grant):
    // the node still has it until it is judged, and a copy hanging on it is judged again then
    let not_dropped = |h: &Tid| !all.contains(h) && core.ix.secrets.get(h).is_some_and(|e| ROLES.iter().any(|r| *r > Role::Sync && e.role(*r).holds_any()));
    let mut kept: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
    loop {
        let mut grew = false;
        for a in &all {
            let (w, old) = (ways.get(a), marks.get(a));
            let has = |h: &Tid| own(h) || readable(core, h) || kept.contains_key(h) || not_dropped(h);
            let mut via: BTreeSet<Tid> = w.into_iter().flatten().filter(|(h, x)| x.retain && has(h) && read_then(a, h, x.end)).map(|(h, _)| *h).collect();
            via.extend(old.into_iter().flatten().filter(|h| has(h) && w.and_then(|w| w.get(*h)).is_none_or(|x| x.retain && read_then(a, h, x.end))));
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
    osis_commit::rewrite(&blob, |ai| frozen.contains(&ai))
}

/// Drops the secrets of `lost` actors (diagnostic each) and forgets what only they read; keeps
/// what the rules keep, and erases the held copies (minus `dropped`, the user's) nothing keeps
/// now. `rejudge`: a role commit may have changed what the held copies hang on.
fn drop_actors(tx: &mut Tx<'_>, mut lost: Vec<Tid>, dropped: &[Tid], rejudge: bool) -> Result<(Vec<Tid>, Forgotten)> {
    // an account this node was removed from: what it read as it goes too
    lost.extend(std::mem::take(&mut tx.core.left));
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
        // lowered to sync: its sync secrets stay, so it is kept unread, and D's sync ticket for it
        // follows (spec/sync-judgement.md §6 Read and unread move, spec/sync-set.md §1)
        let sync = tx.core.ix.secrets.get(a).filter(|_| holds_at(tx.core, a, Role::Sync)).map(|e| e.role(Role::Sync).clone()).filter(|r| r.holds_any());
        #[cfg(debug_assertions)]
        osis_base::trace::note(|| {
            let went = tx.core.ix.secrets.get(a).map_or("none".into(), |e| secrets_brief(e, sync.is_some()));
            let copy = kept.get(a).map_or(String::new(), |v| format!(", read-only copy kept via {}", v.iter().map(Tid::to_string).collect::<Vec<_>>().join(",")));
            format!("lost access {a}: secrets dropped {went}{}{copy}", if sync.is_some() { ", sync kept (unread)" } else { "" })
        });
        match sync {
            Some(r) => {
                let mut kept = ActorEpochs::default();
                *kept.role_mut(Role::Sync) = r;
                tx.core.ix.secrets.insert(*a, kept);
            }
            None => {
                tx.core.ix.secrets.remove(a);
            }
        }
        crate::sync::stranded::drop_asks(tx, a, |_| false)?;
        crate::sync::held::forget_actor(tx, a)?;
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: if kept.contains_key(a) { "lost read access: secrets dropped, a read-only copy kept" } else { "lost read access: secrets and what only they read dropped" }.into() }, tx.core.hlc.mono());
    }
    let set: BTreeSet<Tid> = lost.iter().copied().collect();
    let f = crate::retention::forget::forget(tx, crate::retention::forget::Scope::Lost(&set), &held)?;
    // a kept sync role's history (what it supersedes, its names and floor) is what the entries
    // still held say, as a load reads them: those it opened while it read went with the read
    let ak = crate::flows::ak("secrets.0")?;
    for a in &lost {
        if tx.core.ix.secrets.contains_key(a) {
            crate::apply::observe_state(tx, a, &ak)?;
        }
    }
    Ok((lost, f))
}

/// Which lost actors `Engine::forget_lost` drops.
#[derive(Clone, Copy, Debug)]
pub enum LostScope<'a> {
    /// Every held actor this node lost read access to.
    All,
    /// An app driving the engine alone (`Engine::role_duties`): every held actor whose drop is
    /// due (`Engine::lost_due`; no complete pass is waited for, there being no sync), and the
    /// kept copies judged again where their marks moved (`Engine::copies_due`).
    Due,
    /// Those of these actors this node lost read access to (sync's `Life` per actor once its
    /// pass is done; a self-removal's `removal_done` per actor, so one placed never takes
    /// another still waiting).
    Only(&'a [Tid]),
    /// The kept copies judged again (`Engine::copies_due`).
    Copies,
    /// The user drops these kept copies (`Engine::kept_copies`).
    Kept(&'a [Tid]),
}

/// What `Engine::forget_lost` dropped.
#[derive(Default)]
pub struct Dropped {
    pub actors: Vec<Tid>,
    pub forgotten: Forgotten,
}

/// The actors whose roles reach `a` (`reaches`): `a`, its record chain, and the holders of an
/// edge on any of them, transitively (key actors aside): where a role commit that took `a` from
/// this node was written.
fn reaching(core: &Core, a: &Tid) -> BTreeSet<Tid> {
    let mut seen = BTreeSet::from([*a]);
    let mut work = vec![*a];
    while let Some(t) = work.pop() {
        let up = core.record_chain(&t).filter_map(|s| s.thing()).chain(core.edge_holders(&t).into_iter().map(|(m, _)| m));
        for m in up.collect::<Vec<_>>() {
            if !core.is_key_actor(&m) && seen.insert(m) {
                work.push(m);
            }
        }
    }
    seen
}

/// Whether what this node holds says it lost `a` (spec/permissions.md §3: a node that learns it
/// lost read access): an edge of it, a held key actor or an actor it reads ended or lowered on an actor whose
/// roles reach `a` (`reaching`), or reading-only secrets of it outlived their source commit, or
/// the node holds a role on `a` (its role commits show what it may hold). Secrets taken with no
/// role yet (an entry box a link's redeemer opens before its grant applies, `may_learn`) are no
/// loss until such an edge ends or lowers, or a role shows.
fn loss_seen(core: &Core, a: &Tid) -> bool {
    let ts = now_ts(core);
    // reading-only secrets whose source commit is judged no more (dropped as bad input): what
    // made them readable is gone
    let stale = core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.sources().any(|u| !core.waits.read_any(&u.commit)))));
    // an edge of ours ended, or lowered (to sync: it stays alive) on an actor reaching `a`
    stale || role_here(core, a).is_some() || reaching(core, a).iter().any(|x| core.timelines.on(x).is_some_and(|on| on.holders_gone(ts).keys().chain(on.holders_lowered(ts).iter()).any(|h| ours(core, h))))
}

/// Whether held actor `a` is lost and its drop is this trigger's (spec/permissions.md §3): lost
/// (`judge`), with no own self-removal behind it still waiting (`removal_done` drops those) and
/// not by an `until` passing alone (heard out first, `Leaving::timed`).
fn due_now(tx: &mut Tx<'_>, a: &Tid) -> Result<bool> {
    if !loss_seen(tx.core, a) || judge(tx.core, vec![*a]).is_empty() || lost_by_time(tx.core, a) {
        return Ok(false);
    }
    Ok(!own_leaving(tx, a)?.iter().any(|c| tx.core.ix.held_wait.contains(c)))
}

/// Whether held actor `a` is lost by an `until` passing alone, no own self-removal behind it
/// (`Leaving::timed`).
fn timed_now(tx: &mut Tx<'_>, a: &Tid) -> Result<bool> {
    Ok(!judge(tx.core, vec![*a]).is_empty() && lost_by_time(tx.core, a) && own_leaving(tx, a)?.is_empty())
}

/// The held copies' marks judged now differ from the marks kept (`keeps`): a role commit moved
/// what a copy hangs on, with no drop to judge it.
fn copies_moved(core: &Core) -> bool {
    if core.ix.kept.is_empty() {
        return false;
    }
    let holder_again = |a: &Tid| readable(core, a) && core.ix.secrets.get(a).is_some_and(ActorEpochs::holds_any);
    let marks: BTreeMap<Tid, BTreeSet<Tid>> = core.ix.kept.iter().filter(|(a, _)| !holder_again(a)).map(|(a, v)| (*a, v.clone())).collect();
    let now = keeps(core, &BTreeSet::new(), &marks);
    core.ix.kept.len() != now.len() || core.ix.kept.iter().any(|(a, v)| now.get(a) != Some(v))
}

fn drop_scope(tx: &mut Tx<'_>, scope: LostScope<'_>) -> Result<Dropped> {
    let (cands, rejudge): (Vec<Tid>, bool) = match scope {
        LostScope::All => (tx.core.ix.secrets.keys().copied().collect(), true),
        LostScope::Only(xs) => (xs.to_vec(), false),
        LostScope::Kept(_) => (Vec::new(), false),
        LostScope::Copies => (Vec::new(), true),
        LostScope::Due => {
            let mut due = Vec::new();
            for a in tx.core.ix.secrets.keys().copied().collect::<Vec<_>>() {
                if due_now(tx, &a)? {
                    due.push(a);
                }
            }
            (due, copies_moved(tx.core))
        }
    };
    let lost = judge(tx.core, cands);
    let dropped = match scope {
        LostScope::Kept(xs) => xs,
        _ => &[],
    };
    let (actors, forgotten) = drop_actors(tx, lost, dropped, rejudge)?;
    prune_timed(tx)?;
    Ok(Dropped { actors, forgotten })
}

/// What this node lost read access to and leaves to node-sync (`Engine::lost_leaving`): through
/// its own self-removals, or by an `until` passing alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Leaving {
    /// Each actor lost through own self-removals, and the self-removals behind it.
    pub actors: BTreeMap<Tid, BTreeSet<osis_base::CommitId>>,
    /// Each actor lost by the time alone (`lost_by_time`, no self-removal behind it) and when it
    /// was first judged so (engine ms): dropped once node-sync has heard its sync IDs out, or
    /// `LOST_HEARD_WAIT_MS` after that time.
    pub timed: BTreeMap<Tid, u64>,
    /// When to look again (engine ms): an actor with a self-removal behind it, kept now by a
    /// pending grant, may become lost as that grant ages out; a timed one's wait ends.
    pub recheck_at: Option<u64>,
}

/// A loss by an `until` alone, as `Engine::lost_timed` judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedLoss {
    /// When it drops whatever is heard (`LOST_HEARD_WAIT_MS` after it was first judged).
    pub wait_end: osis_base::WallMs,
    /// Each sync ID of the actor read here, and whether a complete pass of it begun after the
    /// loss was first judged ended.
    pub ids: Vec<(osis_base::SyncId, bool)>,
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
            let lost = judge(tx.core, all);
            let mut out = Leaving::default();
            let again = |out: &mut Leaving, t: u64| out.recheck_at = Some(out.recheck_at.map_or(t, |x| x.min(t)));
            for a in lost {
                let own = own_leaving(tx, &a)?;
                if !own.is_empty() {
                    out.actors.insert(a, own);
                } else if lost_by_time(tx.core, &a) {
                    let since = timed_since(tx, a)?;
                    out.timed.insert(a, since);
                    again(&mut out, since.saturating_add(LOST_HEARD_WAIT_MS));
                }
            }
            prune_timed(tx)?;
            Ok(out)
        })
    }

    /// Whether held actor `a`'s drop is due (spec/permissions.md §3 Lost access): this node
    /// lost read access to it by every path (no pending grant or link race keeping it), no own
    /// self-removal behind it still waits for sync (`removal_done`), and not by an `until`
    /// passing alone. A value of the state, read without a transaction, so a follower (sync's
    /// `Life`, one key per held actor) is due again when anything it read moves; the memo clock is
    /// read up to the next `until` on the actors reaching `a`, so an `until` passing wakes it.
    pub fn lost_due(&mut self, a: &Tid) -> Result<bool> {
        for x in reaching(&self.core, a) {
            self.core.roster_of(&x);
        }
        let a = *a;
        let due = self.core.ix.secrets.contains_key(&a) && self.read(|tx| due_now(tx, &a))?;
        // a loss judged afresh once it ends: a later one waits its own pass (`lost_passed`); a
        // loss by an `until` alone keeps its place (`lost_timed` waits on its pass too)
        if !due && !self.read(|tx| timed_now(tx, &a))? {
            self.judge_cause(crate::sync::held::Cause::Lost(a), false)?;
        }
        Ok(due)
    }

    /// Held actor `a` lost by an `until` passing alone, no own self-removal behind it
    /// (spec/permissions.md §2, `Leaving::timed`): when it drops anyway (`LOST_HEARD_WAIT_MS`
    /// after its loss was first judged, the `T/` record), and per sync ID of it read here whether
    /// a complete pass begun after that ended (`lost_passed`'s place, whose pass this wants).
    /// A value of the state read with the memo clock up to the next `until` on the actors
    /// reaching `a`, as `lost_due` is. None for any other actor.
    pub fn lost_timed(&mut self, a: &Tid) -> Result<Option<TimedLoss>> {
        for x in reaching(&self.core, a) {
            self.core.roster_of(&x);
        }
        let a = *a;
        if !self.core.ix.secrets.contains_key(&a) || !self.read(|tx| timed_now(tx, &a))? {
            return Ok(None);
        }
        let since = self.run(|tx| timed_since(tx, a))?;
        let place = self.judge_cause(crate::sync::held::Cause::Lost(a), true)?;
        let ids = match self.thing_sync(&a)? {
            crate::sync::ThingSync::Read(ids) => ids.iter().map(|s| (*s, self.passed_after(std::iter::once(s), place))).collect(),
            _ => Vec::new(),
        };
        Ok(Some(TimedLoss { wait_end: osis_base::WallMs(since.saturating_add(LOST_HEARD_WAIT_MS)), ids }))
    }

    /// Whether a complete pass of each sync ID of `a` read here began after the loss
    /// (spec/permissions.md §3 Lost access: a node that loses read keeps syncing until it
    /// completes a pass after the cause, then judges again): after the place this node first
    /// judged it lost at (`Cause::Lost`, noted here when sync's `Life` asks, `lost_due` holding;
    /// forgotten by `lost_due` once it does not), so role commits arriving later never hold the
    /// drop off. True with none read.
    pub fn lost_passed(&mut self, a: &Tid) -> Result<bool> {
        let since = self.judge_cause(crate::sync::held::Cause::Lost(*a), true)?;
        let crate::sync::ThingSync::Read(ids) = self.thing_sync(a)? else { return Ok(true) };
        Ok(self.passed_after(ids.iter(), since))
    }

    /// Drops `a` if this node lost read access to it (`LostScope::Only`): sync's `Life` once
    /// `lost_due` and `lost_passed` hold. Whether it dropped.
    pub fn drop_lost(&mut self, a: &Tid) -> Result<bool> {
        Ok(!self.forget_lost(LostScope::Only(&[*a]))?.actors.is_empty())
    }

    /// Whether a held copy's marks moved with no drop to judge them (`LostScope::Copies`): a
    /// stamped read, so a follower is due again when a role commit moves what a copy hangs on.
    pub fn copies_due(&self) -> bool {
        copies_moved(&self.core)
    }

    /// Judges the held copies' marks again (`copies_due`): a copy whose way now says erase goes.
    pub fn rejudge_copies(&mut self) -> Result<()> {
        self.forget_lost(LostScope::Copies).map(|_| ())
    }

    /// Whether `role_duties` has a drop to make now (`lost_due` of any held actor, or
    /// `copies_due`). O(held actors).
    pub fn role_duties_due(&mut self) -> Result<bool> {
        for a in self.held_actors() {
            if self.lost_due(&a)? {
                return Ok(true);
            }
        }
        Ok(self.copies_due())
    }

    /// The lost-access drop for an app driving the engine alone (spec/permissions.md §3): drops
    /// each held actor whose drop is due (`lost_due`) and judges the kept copies again
    /// (`copies_due`), forgetting what only the dropped read. With no sync there is no complete
    /// pass to wait for (`lost_passed`, which sync's `Life` adds). Call it after ingesting and at
    /// the memo clock's wake (`clock_next`). Returns the actors dropped.
    pub fn role_duties(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(LostScope::Due)?.actors)
    }

    /// The actors whose read-only copy this node keeps (spec/permissions.md §3, Retain): no secret, no
    /// sync, no write; `get` and the rest still read what it held. `drop_kept`-able.
    pub fn kept_copies(&self) -> Vec<Tid> {
        self.core.ix.kept.keys().copied().collect()
    }

    /// Whether dropping the secrets of `lost` would forget `t` (erase it or keep a copy):
    /// node-sync hears out the sync IDs whose closure holds such a thing before it drops an actor
    /// an `until` ended (`Leaving::timed`).
    pub fn would_forget(&self, lost: &BTreeSet<Tid>, t: &Tid) -> bool {
        crate::retention::forget::would_forget(&self.core, lost, t)
    }

    /// Whether a client of this node, `actor`, reads `t` as a kept copy (notes/client-port.md §3):
    /// it is a holder the copy hangs on, or an app of the account, holding a role on the account
    /// that is its first admin, with a role now on such a holder (through a holder that is itself
    /// kept, too).
    /// Invariant: a copy is the account's: a role on a holder alone, as one of the holders
    /// the account holds a role through, reads nothing of it, nor does any other client; no write right follows.
    pub fn copy_readable_by(&self, actor: &Tid, t: &Tid) -> bool {
        let core = &self.core;
        let Some(a) = crate::retention::forget::copy_of(core, t) else { return false };
        let app = core.first_admin(actor).is_some_and(|p| core.role_now(actor, &p).is_some());
        let mut seen = BTreeSet::from([a]);
        let mut todo = vec![a];
        while let Some(x) = todo.pop() {
            for h in core.ix.kept.get(&x).into_iter().flatten() {
                if h == actor || (app && core.role_now(actor, h) >= Some(Role::Read)) {
                    return true;
                }
                if seen.insert(*h) {
                    todo.push(*h);
                }
            }
        }
        false
    }

    /// Drops lost actors (`scope`), with what was forgotten (node-sync drops its sync ID
    /// sessions).
    pub fn forget_lost(&mut self, scope: LostScope<'_>) -> Result<Dropped> {
        self.run(|tx| drop_scope(tx, scope))
    }
}

/// Debug builds: the secrets `e` holds per role, as `read[3,4]`; `keep_sync`: its sync ones stay.
#[cfg(debug_assertions)]
pub(crate) fn secrets_brief(e: &ActorEpochs, keep_sync: bool) -> String {
    let roles: Vec<String> = ROLES.iter().filter(|r| !(keep_sync && **r == Role::Sync)).filter_map(|r| {
        let ns: Vec<String> = e.role(*r).epochs().filter(|(_, i)| i.secret.is_some()).map(|(ep, i)| format!("{}{}", ep.n(), if i.checked().is_some() { "" } else { "?" })).collect();
        (!ns.is_empty()).then(|| format!("{}[{}]", format!("{r:?}").to_lowercase(), ns.join(",")))
    }).collect();
    if roles.is_empty() { "none".into() } else { roles.join(" ") }
}

/// Debug builds (`Engine::why_role`): `Engine::lost_due`'s judgement of `a` read without its
/// side effects, clause by clause (`due_now`, `timed_now`).
#[cfg(debug_assertions)]
pub(crate) fn explain_due(tx: &mut Tx<'_>, a: &Tid) -> Result<String> {
    let core = &*tx.core;
    let Some(e) = core.ix.secrets.get(a) else { return Ok("not due: no secrets of it held".into()) };
    let over = over_held(core, a);
    let seen = loss_seen(core, a);
    let lost = !judge(core, vec![*a]).is_empty();
    let timed = lost_by_time(core, a);
    let mut out = format!("held {}; over-held (a secret no role covers) {over}; loss seen {seen}; judged lost {lost}", secrets_brief(e, false));
    if lost {
        out.push_str(&format!("; by an until alone {timed}"));
    }
    if over && !lost {
        let why = if contested(core, a) { "an unfinalized link race on it" } else { "a pending grant or contested holder reaching it (`judge`)" };
        out.push_str(&format!(" (kept by {why})"));
    }
    let leaving = own_leaving(tx, a)?;
    let waiting: Vec<String> = leaving.iter().filter(|c| tx.core.ix.held_wait.contains(c)).map(|c| format!("{c:?}")).collect();
    if !leaving.is_empty() {
        out.push_str(&format!("; own self-removals behind it {}, waiting for sync {waiting:?}", leaving.len()));
    }
    let due = due_now(tx, a)?;
    let timed_due = timed_now(tx, a)?;
    out.push_str(&match (due, timed_due) {
        (true, _) => "; DUE (sync drops it once a complete pass after the cause ends: `lost_passed`)".to_string(),
        (false, true) => "; not due: lost by an until alone, left to sync (`lost_timed`)".to_string(),
        (false, false) if !over => "; not due: its roles cover every secret held".to_string(),
        (false, false) if !seen => "; not due: nothing held says it lost it (no ended or lowered edge of ours reaching it, no role shown)".to_string(),
        (false, false) if !lost => "; not due: kept (above)".to_string(),
        (false, false) => "; not due: an own self-removal behind it waits for sync (`removal_done`)".to_string(),
    });
    Ok(out)
}
