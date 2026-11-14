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
/// aspect's thing of a dropped pending one, due now (empty value); or a roster target with an
/// edge's `until` ahead, due then (value: engine ms, u64 BE). The held actors a role
/// on it reaches are re-evaluated once due, in a transaction of their own (node-sync, every
/// step, with a wake for the next due time). A target with an `until` ahead stays listed until
/// then, so the list may hold every timed edge of the node's things; a step asks by time
/// (`ix.lost_due_at`), not by scanning it.
pub(crate) const LOST_DUE: &[u8] = b"l/";

/// Actors lost by an `until` passing alone (`lost_by_time`), left to node-sync to hear their
/// labels out first (spec/permissions.md §2): `T/` + actor; value: when first judged (engine
/// ms, u64 BE), from which `LOST_HEARD_WAIT_MS` runs. Goes with the actor's drop, or when it
/// reads the actor again.
const TIMED_LOST: &[u8] = b"T/";

/// Kept copies (spec/permissions.md §3, Retain): `K/` + lost actor; value: the tids of the holders
/// its copy hangs on, concatenated, recorded at the drop (durably, spec/permissions.md §3).
const KEPT_COPY: &[u8] = b"K/";

/// The link keys this node keeps reading as (`Engine::keep_bearer`): `B/` + tid, no value.
const BEARERS: &[u8] = b"B/";

/// Sets `t`'s entry in the work list's two indexes.
fn set_due(ix: &mut crate::engine::Indexes, t: Tid, at: u64) {
    if let Some(old) = ix.lost_due.insert(t, at) {
        ix.lost_due_at.remove(&(old, t));
    }
    ix.lost_due_at.insert((at, t));
}

/// Adds `tids` to the work list, due now.
pub(crate) fn mark_lost_due(tx: &mut Tx<'_>, tids: impl IntoIterator<Item = Tid>) -> Result<()> {
    for t in tids {
        tx.txn.put_local(&[LOST_DUE, t.as_bytes()].concat(), &[], osis_store::Shred::No)?;
        set_due(&mut tx.core.ix, t, 0);
    }
    Ok(())
}

/// Adds `t` to the work list, due at `at` (an earlier entry stays).
fn arm_lost_due(tx: &mut Tx<'_>, t: Tid, at: u64) -> Result<()> {
    if tx.core.ix.lost_due.get(&t).is_some_and(|x| *x <= at) {
        return Ok(());
    }
    tx.txn.put_local(&[LOST_DUE, t.as_bytes()].concat(), &at.to_be_bytes(), osis_store::Shred::No)?;
    set_due(&mut tx.core.ix, t, at);
    Ok(())
}

/// The earliest `until` ahead among the edges alive now on `t`: when the clock alone next ends
/// a role there.
fn next_until(core: &Core, t: &Tid) -> Option<u64> {
    let now = core.now().0;
    core.timelines.get(t)?.roster(t, At::now(now_ts(core))).values().filter_map(|e| e.until).map(|u| u.0).filter(|u| *u > now).min()
}

/// Lists each of `targets` due at its next `until` ahead, if any: an `until` passing is a loss
/// with no role commit behind it (spec/permissions.md §2), judged then. Called for every
/// applied role commit's targets (local ones too: a self-demotion with an `until`) and for the
/// entries a trigger run takes.
pub(crate) fn arm_untils(tx: &mut Tx<'_>, targets: impl IntoIterator<Item = Tid>) -> Result<()> {
    for t in targets {
        if let Some(at) = next_until(tx.core, &t) {
            arm_lost_due(tx, t, at)?;
        }
    }
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
    for (t, at) in v {
        set_due(&mut tx.core.ix, t, at);
    }
    let mut v = Vec::new();
    tx.scan(TIMED_LOST, |k, val| {
        let bad = || Error::Corrupt("timed-loss record");
        v.push((Tid::from_bytes(k.try_into().map_err(|_| bad())?), u64::from_be_bytes(val.try_into().map_err(|_| bad())?)));
        Ok(())
    })?;
    tx.core.ix.timed_lost.extend(v);
    let b = tx.scan_keys(BEARERS, "bearer record", Tid::from_bytes)?;
    tx.core.ix.bearers.extend(b);
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

/// Takes the work list's entries due by `by`, returning them; each taken target is listed again
/// at its next `until` ahead.
fn take_due(tx: &mut Tx<'_>, by: u64) -> Result<BTreeSet<Tid>> {
    let due: Vec<(u64, Tid)> = tx.core.ix.lost_due_at.iter().take_while(|(at, _)| *at <= by).copied().collect();
    let mut out = BTreeSet::new();
    for (at, t) in due {
        tx.core.ix.lost_due_at.remove(&(at, t));
        tx.core.ix.lost_due.remove(&t);
        tx.txn.remove_local(&[LOST_DUE, t.as_bytes()].concat(), osis_store::Shred::No)?;
        out.insert(t);
    }
    arm_untils(tx, out.iter().copied())?;
    // an `until` passing moves no state: what a roster reads now is told here
    for thing in &out {
        tx.core.events.queue(crate::events::Event::Roster { thing: *thing });
    }
    Ok(out)
}

/// Whether the node, a held key actor or a link key it keeps reading as holds `min` or above on
/// `a` now (any path, `until` honoured).
fn holds_at(core: &Core, a: &Tid, min: Role) -> bool {
    let at = |m: &Tid| core.role_now(m, a) >= Some(min);
    core.member().into_iter().chain([core.id.tid()]).any(|m| at(&m)) || core.key_actors.keys().chain(core.ix.bearers.iter()).any(at)
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

/// Whether an entry box may give this node secrets of `a` (spec/sync-ids.md §3): as a box
/// may (`may_take`), or while nothing held says the node lost `a`: no ended edge on it of the node,
/// a held key actor or an actor it reads (a link's redeemer opens the label before it holds the
/// grant to its key; the trigger judges `a` once role commits on it apply).
pub(crate) fn may_learn(core: &Core, a: &Tid) -> bool {
    may_take(core, a) || core.timelines.get(a).is_none_or(|tl| !tl.ended(a, now_ts(core)).keys().any(|h| ours(core, h)))
}

/// Whether the node holds secrets of `a` its roles there no longer give (`may_hold`, lost access).
fn over_held(core: &Core, a: &Tid) -> bool {
    let Some(e) = core.ix.secrets.get(a) else { return false };
    ROLES.iter().any(|r| e.role(*r).holds_any()) && !may_hold(core, a)
}

/// Whether all that ended the node's (or a held key actor's) role on `a` is an `until` passing:
/// walked with every edge's time ahead and every finalize undone (it counts as the `until` it
/// finalizes, spec/permissions.md §2), a role is there. A removal saying its own retain is written
/// with `until` 0, gone at every clock, so it never counts.
pub(super) fn lost_by_time(core: &Core, a: &Tid) -> bool {
    let ts = osis_base::Ts::default();
    let Some(tl) = core.timelines.get(a) else { return false };
    let role = |x: &Tid| tl.role_unfinalized(x, a, ts).is_some();
    core.member().as_ref().is_some_and(role) || core.key_actors.keys().any(role)
}

/// How long an actor lost by the time alone waits for node-sync to hear its labels out before
/// it is dropped anyway (spec/permissions.md §2): a host dead or hostile for good holds no
/// erasure off beyond it. `ROLE_KEEP_MS`, past which a node offline does not sync cleanly
/// anyway. Minor consequence: a node out of reach that long loses its unsent writes on what a
/// renewal it has not heard would have kept, and comes back by a re-seal; a later erase before
/// it. At 0 every offline holder loses those; at infinity one dead host keeps every expired
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
    let newer = |x: &Tid, k: &BoxKey| ours(core, &k.holder) && k.role == Role::Read && held.get(x).is_none_or(|n| k.epoch.n > *n);
    crate::apply::keys::pending_secrets_writes(blob, id).into_iter().filter(|(x, w)| w.boxes.keys().any(|k| newer(x, k)) && may_grant(core, &blob.header.author, x) && authentic(core, blob, id, x, known)).map(|(x, _)| x).collect()
}

impl Engine {
    /// Whether a `keys.0` write deciding `g`'s label keys is held but not applied: a pending
    /// commit (parked ones aside) writing the `keys.0` of the actor `g`'s secrets derive from,
    /// signed (`authentic`) by an admin of it now, or a held commit whose valid `keys.0` part on
    /// a thing from `g` up to that actor is missing (its body to be fetched: it may give that
    /// thing secrets of its own). A newer deposit seed, or another actor's, may be on its way
    /// (node-sync holds back a deposit-only step meanwhile). Anyone can send a pending commit
    /// naming any aspect, so an unsigned one never counts: it would hold the step back for good.
    pub fn keys_write_unapplied(&mut self, g: &Tid) -> Result<bool> {
        let a = self.core.secret_actor(g).unwrap_or(*g);
        let keys = osis_base::Ak::new("keys.0").map_err(|_| crate::Error::Misuse("ak"))?;
        let core = &self.core;
        let missing = |x: &Tid| {
            let part = |m: &crate::engine::Meta| m.aspect(x, &keys).is_some_and(|ai| m.valid_at(ai) && matches!(m.missing_as(ai), Some(crate::engine::Missing::Plain | crate::engine::Missing::ToFetch)));
            core.ix.by_aspect.get(&(*x, keys.clone())).into_iter().flatten().any(|(_, c)| core.ix.commits.get(c).is_some_and(part))
        };
        let below: Vec<Tid> = core.record_chain(g).map_while(|s| s.thing()).take_while(|x| *x != a).collect();
        if below.iter().chain([&a]).any(missing) {
            return Ok(true);
        }
        let ids: Vec<osis_base::CommitId> = self.core.ix.pending.iter().filter(|(_, r)| **r != crate::Reason::Parked).map(|(c, _)| *c).collect();
        self.read(|tx| {
            for id in ids {
                let Some(p) = tx.txn.get_pending(&id)? else { continue };
                let Ok(blob) = osis_commit::CommitBlob::decode_stored(&p.bytes) else { continue };
                let h = &blob.header;
                if h.aspect_index(&a, "keys.0").is_some() && tx.core.role_now(&h.author, &a) == Some(Role::Admin) && authentic(tx.core, &blob, &id, &a, crate::apply::kept_verdict(&p)) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
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
fn judge(tx: &mut Tx<'_>, cands: Vec<Tid>) -> Vec<Tid> {
    let unread: Vec<Tid> = cands.into_iter().filter(|a| over_held(tx.core, a)).collect();
    if unread.is_empty() {
        return unread;
    }
    let core = &*tx.core;
    let sourced: Vec<Tid> = core.ix.secrets.iter().filter(|(_, e)| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.reading.iter().any(|u| core.waits.read_any(&u.commit))))).map(|(t, _)| *t).collect();
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
/// labels) it would get back. A redemption is a commit removing its signer's own edge on `k`
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
        // lowered to sync: the account's sync record from its own reading (its sync ID and the
        // sync secrets it held), and S becomes kept unread (spec/sync.md §3; spec/sync-judgement.md
        // §6 Read and unread move)
        let lowered = tx.core.me().is_some_and(|m| tx.core.role_now(&m, a) == Some(osis_base::Role::Sync));
        if lowered && let Some(ep) = tx.core.ix.secrets.get(a).cloned() {
            let syncs: Vec<(osis_crypto::Epoch, osis_crypto::Secret32)> = ep.sync.held().map(|(e, x)| (e, x.clone())).collect();
            if !syncs.is_empty() {
                let ids: Vec<osis_base::SyncId> = crate::flows::home_sync_id(tx, a)?.into_iter().collect();
                crate::sync::records::keep_in(tx, a, &ids, syncs)?;
            }
        }
        tx.core.ix.secrets.remove(a);
        tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: if kept.contains_key(a) { "lost read access: secrets dropped, a read-only copy kept" } else { "lost read access: secrets and what only they read dropped" }.into() }, now);
    }
    let set: BTreeSet<Tid> = lost.iter().copied().collect();
    let f = crate::retention::forget::forget(tx, crate::retention::forget::Scope::Lost(&set), &held)?;
    Ok((lost, f))
}

/// Drops the bearers named on something that no longer hold a role on any of it: the link ended,
/// what they read went with it, and a new link is a new key (spec/permissions.md §7).
fn drop_ended_bearers(tx: &mut Tx<'_>) -> Result<()> {
    let core = &*tx.core;
    let ended: Vec<Tid> = core.ix.bearers.iter().filter(|l| core.ix.held.named_on(l).next().is_some() && !core.ix.held.named_on(l).any(|t| core.role_now(l, t).is_some())).copied().collect();
    for l in ended {
        tx.txn.remove_local(&[BEARERS, l.as_bytes()].concat(), osis_store::Shred::No)?;
        tx.core.ix.bearers.remove(&l);
    }
    Ok(())
}

/// Which lost actors `Engine::forget_lost` drops.
#[derive(Clone, Copy, Debug)]
pub enum LostScope<'a> {
    /// Every held actor this node lost read access to (the work list is done with it).
    All,
    /// The trigger: takes the work list's due entries and drops the held actors a role on one
    /// of their things reaches that this node lost read access to (idempotent: the entries go
    /// in the same transaction), except those lost through its own self-removal or by an
    /// `until` passing alone (`Engine::lost_leaving`: node-sync drops those once placed or
    /// heard out).
    Due,
    /// Those of these actors this node lost read access to (node-sync's `drop_left`: each
    /// actor it waits for is listed on its own, so one heard out or placed never takes another
    /// still waiting with it).
    Only(&'a [Tid]),
    /// The user drops these kept copies (`Engine::kept_copies`).
    Kept(&'a [Tid]),
}

/// What `Engine::forget_lost` dropped.
#[derive(Default)]
pub struct Dropped {
    pub actors: Vec<Tid>,
    pub forgotten: Forgotten,
    /// `LostScope::Due` left a lost actor to node-sync: its own self-removal's placement, or
    /// hearing out the labels of what an `until` ended.
    pub leaving: bool,
}

fn drop_scope(tx: &mut Tx<'_>, scope: LostScope<'_>) -> Result<Dropped> {
    let mut rejudge = false;
    let cands: Vec<Tid> = match scope {
        LostScope::All => {
            take_due(tx, u64::MAX)?;
            rejudge = true;
            tx.core.ix.secrets.keys().copied().collect()
        }
        LostScope::Only(xs) => xs.to_vec(),
        LostScope::Kept(_) => Vec::new(),
        LostScope::Due => {
            let due = take_due(tx, tx.now().0)?;
            // what the change makes due before this node next encrypts under each (spec/permissions.md
            // §2 Finalize, §3 Required rotation): the finalize of a grant past its `until`, the
            // rotation a departure requires, where this node may write them
            if let Ok(me) = tx.core.writer() {
                let mut done = crate::flows::Done::default();
                for t in &due {
                    super::ensure_rotated(tx, me, *t, &mut done)?;
                }
            }
            let core = &*tx.core;
            rejudge = core.ix.kept.iter().any(|(a, via)| due.iter().any(|t| via.contains(t) || reaches(core, t, a)));
            // a box opened late may have given a copy a secret: judged again, it goes
            let copies = core.ix.kept.keys();
            core.ix.secrets.keys().filter(|a| due.iter().any(|t| reaches(core, t, a))).chain(copies).copied().collect()
        }
    };
    let judged = judge(tx, cands);
    let (lost, leaving) = match scope {
        LostScope::All | LostScope::Only(_) | LostScope::Kept(_) => (judged, false),
        LostScope::Due => {
            let (mut lost, mut leaving) = (Vec::new(), false);
            for a in judged {
                // an own self-removal behind it still waiting for sync goes up first
                // (spec/permissions.md §3: `Engine::removal_done` drops it), or its labels are
                // heard out (§2)
                if own_leaving(tx, &a)?.iter().any(|c| tx.core.ix.held_wait.contains(c)) {
                    leaving = true;
                } else if lost_by_time(tx.core, &a) {
                    timed_since(tx, a)?;
                    leaving = true;
                } else {
                    lost.push(a);
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
    if !actors.is_empty() {
        drop_ended_bearers(tx)?;
    }
    prune_timed(tx)?;
    Ok(Dropped { actors, forgotten, leaving })
}

/// What this node lost read access to and leaves to node-sync (`Engine::lost_leaving`): through
/// its own self-removals, or by an `until` passing alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Leaving {
    /// Each actor lost through own self-removals, and the self-removals behind it.
    pub actors: BTreeMap<Tid, BTreeSet<osis_base::CommitId>>,
    /// Each actor lost by the time alone (`lost_by_time`, no self-removal behind it) and when it
    /// was first judged so (engine ms): dropped once node-sync has heard its labels out, or
    /// `LOST_HEARD_WAIT_MS` after that time.
    pub timed: BTreeMap<Tid, u64>,
    /// When to look again (engine ms): an actor with a self-removal behind it, kept now by a
    /// pending grant, may become lost as that grant ages out; a timed one's wait ends.
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
            let lost = judge(tx, all);
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

    /// Keeps reading as link key `l`, whose seed this node forgets (spec/permissions.md §7, Bearer
    /// use: a contact card): what `l` reads stays held and followed for as long as `l` holds its
    /// role, and goes with it (`l`'s edge removed: the link ended).
    pub fn keep_bearer(&mut self, l: &Tid) -> Result<()> {
        self.run(|tx| {
            tx.txn.put_local(&[BEARERS, l.as_bytes()].concat(), &[], osis_store::Shred::No)?;
            tx.core.ix.bearers.insert(*l);
            crate::flows::retake(tx)
        })
    }

    /// Has the lost-access trigger judge what a role on `t` reaches: a held key gave this node
    /// `t`'s secrets without any edge, and the key went (a link not redeemed).
    pub fn judge_lost(&mut self, t: &Tid) -> Result<()> {
        self.run(|tx| mark_lost_due(tx, [*t]))
    }

    /// Whether `role_duties` has work due now: a stamped read of the work list and of the memo
    /// clock up to its first entry, so a follower (sync's `Life`) is due again when either moves,
    /// and the clock's next wake (`clock_next`) is that entry's time.
    pub fn role_duties_due(&self) -> bool {
        debug_assert_eq!(self.core.ix.lost_due.len(), self.core.ix.lost_due_at.len());
        let Some(&(at, _)) = self.core.ix.lost_due_at.first() else { return false };
        self.core.time.until(Some(at)) >= at
    }

    /// The duties a role change makes due, on the targets of received role commits applied or
    /// whose `until` passed (the work list, `role_duties_due`): first what this node owes before it next
    /// encrypts under each, where it may write it (`ensure_rotated`: the finalize of a grant past
    /// its `until`, spec/permissions.md §2; a departure's required rotation, §3), logged as its own
    /// commits; then the lost-access trigger (§3): drops the secrets of the actors they touched that this
    /// node lost read access to by every path, unless a held pending grant reaches them, or its
    /// own self-removal or an `until` passing alone is behind the loss (`lost_leaving`), and
    /// forgets what only those read. node-sync runs it when `role_duties_due` moves to true
    /// (`Life`); an app driving the engine alone calls it after ingesting and when
    /// `role_duties_due` turns true (its memo clock wake, `clock_next`). Returns the actors dropped. The wrap gate refuses meanwhile
    /// (`wrap_blocked`), so a write made before this runs waits for it.
    pub fn role_duties(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(LostScope::Due)?.actors)
    }

    /// The actors whose read-only copy this node keeps (spec/permissions.md §3, Retain): no secret, no
    /// sync, no write; `get` and the rest still read what it held. `drop_kept`-able.
    pub fn kept_copies(&self) -> Vec<Tid> {
        self.core.ix.kept.keys().copied().collect()
    }

    /// Whether dropping the secrets of `lost` would forget `t` (erase it or keep a copy):
    /// node-sync hears out the labels whose closure holds such a thing before it drops an actor
    /// an `until` ended (`Leaving::timed`).
    pub fn would_forget(&self, lost: &BTreeSet<Tid>, t: &Tid) -> bool {
        crate::retention::forget::would_forget(&self.core, lost, t)
    }

    /// Whether a client of this node, `actor`, reads `t` as a kept copy (notes/client-port.md §3):
    /// it is a holder the copy hangs on, or an app of the person, holding a role on the person
    /// that is its first admin, with a role now on such a holder (through a holder that is itself
    /// kept, too).
    /// Invariant: a copy is the person's: a role on a holder alone, as a member of a group the
    /// person is in, reads nothing of it, nor does any other client; no write right follows.
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
