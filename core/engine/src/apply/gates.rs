//! What holds a commit back (spec/commits.md §4): the missing deltas that can (`gating`), and when
//! one counts as held (`counts_held`).
//!
//! Invariant (arrival-order independence): counting as held decides when a commit's held parts join,
//! never what they join to: the delta joins on arrival, judged as ever. So every clause reads only
//! what grows, of any validity and whatever followed it: what let a commit apply goes on letting it
//! apply, at any node in any order. A signer's word counts only from one that could ever have had
//! the right (`signed_by_possible_admin`, `retention::counts_as_purged`), so a forger gets nothing.

use super::validity::{meets, under_required};
use super::{receipt, whole_part};
use crate::engine::write::required_role;
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{CommitId, Role, Tid};
use osis_commit::{CommitBlob, Header, Kind};
use osis_perm::{Frontier, Point, RoleCommit, RosterSnapshot};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;
use std::sync::Arc;

/// The storage class of a commit's aspects: a key's lifetime marker, alike at every node
/// (spec/commits.md §2). A part on an aspect of another is never applied, by anyone, so none is
/// waited for: judged from the header, whatever the part.
pub(super) fn class_of(h: &Header) -> osis_base::Lifetime {
    if h.ephemeral.is_some() { osis_base::Lifetime::Ephemeral } else { osis_base::Lifetime::Durable }
}

/// Whether the missing deltas `gates` (`gating`) still hold back all that they held: one holding
/// the whole commit does not count as held, or none of the others does (each holds only its thing).
pub(crate) fn still_gated(tx: &mut Tx<'_>, h: &Header, id: &CommitId, gates: &[Gate]) -> Result<bool> {
    let mut counted = false;
    for ((ai, _), holds) in gates {
        let here = counts_held(tx, h, id, *ai)?;
        if *holds && !here {
            return Ok(true);
        }
        counted |= here;
    }
    Ok(!counted)
}

/// Whether a missing delta of aspect `ai` counts as held: expired, past keep at most, purged,
/// under a later held snapshot of any validity (`receipt::listed`), its author's removal leaves it invalid, or breaking
/// a held `required.0^` delta by a possible admin (spec/commits.md §4).
pub(super) fn counts_held(tx: &mut Tx<'_>, h: &Header, id: &CommitId, ai: usize) -> Result<bool> {
    let now = tx.now().0;
    let Some(a) = h.aspects.get(ai) else { return Ok(true) };
    // a part on a key of another storage class is dropped alone, wherever it comes from
    if a.ak.lifetime() != class_of(h) {
        return Ok(true);
    }
    Ok(h.expires.is_some_and(|t| t <= now) || at_most_bound(tx.core, h, id, a).is_some_and(|t| t <= now) || crate::retention::counts_as_purged(tx, h, id, ai)? || receipt::listed(tx.core, h, ai) || removed_author(tx.core, h, id, a) || breaks_a_held_setting(tx.core, h, id, a))
}

/// Whether commit `id` waits whole for nothing. A role commit any part of which is held: it may be
/// held only as a copy of some parts (a certificate copy, an inbox blob, spec/sync.md §3), whose rest need
/// never come, and the node cannot tell one from its things' labels' bodies; the rest joins on
/// arrival. An applied commit, unless only creation records of it are applied: it has nothing left
/// to hold back.
pub(super) fn never_whole(core: &crate::engine::Core, h: &Header, id: &CommitId, blob: &CommitBlob, skip: &BTreeSet<(usize, usize)>) -> bool {
    // a part dropped since it applied may be out of `skip` (`takes_late`): that commit was shown
    let opened = |m: &crate::engine::Meta| m.dropped.is_empty() && !skip.is_empty() && skip.iter().all(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == osis_commit::retention::CREATED));
    core.ix.commits.get(id).is_some_and(|m| !opened(m)) || (h.kind == Kind::Role && !blob.parts.is_empty())
}

/// Whether a commit with no part held waits for every thing and delta of it, synced or not, so that
/// whether it is recorded applied does not read what the node syncs when it comes. A lasting header
/// may be all that ever comes under the label (spec/commits.md §5), so a permanent delta or a purge
/// item on a thing the node syncs stands for a held part: the commit waits as if that part were
/// here, for what is on its synced things, and no more than a held part's commit does. The delta
/// itself still gates until a held request counts it as held.
pub(super) fn waits_whole(core: &crate::engine::Core, h: &Header, blob: &CommitBlob, never: bool) -> bool {
    let stands = h.ephemeral.is_none() && (h.aspects.iter().any(|a| h.permanent(a) && core.syncs(&a.tid)) || h.purge.iter().any(|i| core.syncs(i.tid())));
    blob.parts.is_empty() && !never && !stands
}

/// A missing delta and whether it holds the whole commit (`gating`).
pub(crate) type Gate = ((usize, usize), bool);

/// The missing deltas (not in `skip`: applied or gone for good) that can hold something back, each
/// with whether it holds the whole commit: those on a thing the node syncs and all of a commit no
/// part of which is here do; the content deltas of a thing a content part of which is here hold
/// that thing's. The other things' are not this node's to wait for.
pub(crate) fn gating(core: &crate::engine::Core, blob: &CommitBlob, id: &CommitId, skip: &BTreeSet<(usize, usize)>) -> Vec<Gate> {
    let h = &blob.header;
    let never = never_whole(core, h, id, blob, skip);
    let whole = waits_whole(core, h, blob, never);
    let units = held_units(h, blob.parts.iter().map(|p| (p.ai, p.di)).filter(|x| !skip.contains(x)));
    let mut out = Vec::new();
    for x in blob.missing().into_iter().filter(|x| !skip.contains(x)) {
        let Some(a) = h.aspects.get(x.0) else { continue };
        let holds = whole || (!never && core.syncs(&a.tid));
        if holds || (units.contains(&a.tid) && !whole_part(a.ak.as_str())) {
            out.push((x, holds));
        }
    }
    out
}

/// The things with a content part among `parts`: each is a unit of atomic apply whatever the node
/// syncs. A role commit's or roster snapshot's parts and a `created.0` chain copy are not: a
/// copy of some of them is all a node may ever get. Nor is an ephemeral snapshot atomic.
pub(super) fn held_units(h: &Header, parts: impl Iterator<Item = (usize, usize)>) -> BTreeSet<Tid> {
    if h.ephemeral.is_some() && h.kind.delta_kind() == osis_crdt::DeltaKind::Snapshot {
        return BTreeSet::new();
    }
    parts.filter_map(|(ai, _)| h.aspects.get(ai)).filter(|a| !whole_part(a.ak.as_str())).map(|a| a.tid).collect()
}

/// From when missing delta `a` of commit `id` counts as held for its keep at most
/// (spec/commits.md §4): `None` while nothing here shows it could have left.
///
/// A body with no live write goes from hosts with no carrier (§5), and without its body a node
/// cannot tell whether a write is live: the header gives counters and a hash, not positions. What
/// it can tell is the condition such a delete needs: a superseder, which is a commit on the aspect
/// stamped no earlier than this one, and the bound counted from it. An absolute bound passing
/// alone shows nothing: a body with a live write leaves only with a carrier (`receipt::listed`).
/// The last write on an aspect stays as its own body or a carrier unless it expired or was purged,
/// so a killer stamped later stays to be seen; those cases and a killer stamped earlier wait for
/// the aspect's next commit (issues/atomic-wait-no-later-commit.md). A live delta still on its
/// way waits unless such a commit exists and its bound passed; a bound passing here earlier than
/// at its holders (an unrelated later commit, this node's clock) only applies the rest sooner.
/// The clock going back unapplies nothing, and a delta that never comes held only writes every
/// holder's state supersedes or a carrier holds.
pub(crate) fn at_most_bound(core: &crate::engine::Core, h: &Header, id: &CommitId, a: &osis_commit::AspectEntry) -> Option<u64> {
    let held = core.ix.by_aspect.get(&(a.tid, a.ak.clone()))?;
    let later = held.range((h.ts, CommitId([0; 32]))..).find(|x| x.1 != *id)?.0.wall_ms().0;
    osis_commit::retention::body_keep(h, &a.retention, Some(later), Some(later), false).at_most
}

/// Whether a missing delta counts as held for breaking its thing's required retention
/// (spec/commits.md §4): it breaks a held `required.0^` delta ordered before its key, whatever
/// that delta's validity, signed by a possible admin (`Held::ever_admins`). The broken delta may
/// be gone without a right, so its commit's other deltas must not wait for it; a writer's setting
/// says nothing of a delta a host hides. A setting by a possible admin never goes
/// (`never_could_set`), and a valid setting's author is one (`Judge::settings` checks), so no good
/// part waits for good behind one.
fn breaks_a_held_setting(core: &Core, h: &Header, id: &CommitId, a: &osis_commit::AspectEntry) -> bool {
    if !under_required(h, &a.ak) {
        return false;
    }
    let at = Point { ts: h.ts, node: h.author, commit: *id };
    let broken = core.ix.required.get(&a.tid).into_iter().flatten().take_while(|x| x.0 < at).filter(|(_, rules)| ct::required_for(rules, a.ak.as_str()).is_some_and(|q| !meets(q, h, a)));
    signed_by_possible_admin(core, &a.tid, broken.map(|(p, _)| p.node))
}

/// Whether one of `signers` is a possible admin of `t` (`Held::ever_admins`).
fn signed_by_possible_admin(core: &Core, t: &Tid, signers: impl Iterator<Item = Tid>) -> bool {
    signed_by_possible(core, t, Role::Admin, signers)
}

/// Whether one of `signers` is a possible holder of `role` on `t` (`Held::ever_holders`), the set
/// walked only if there is one: what lets a missing delta count as held on a signer's word must not
/// be anyone's.
pub(crate) fn signed_by_possible(core: &Core, t: &Tid, role: Role, signers: impl Iterator<Item = Tid>) -> bool {
    let mut signers = signers.peekable();
    signers.peek().is_some() && {
        let holders = core.ix.held.ever_holders(t, role);
        signers.any(|by| holders.contains(&by))
    }
}

/// Whether another actor's explicit lowering of `a`'s author below the role `a` needs, on `a`'s thing
/// or up its owner chain, is held, signed by a possible admin of that thing (`Held::ever_admins`), and
/// its frontier does not list commit `id` (spec/commits.md §4): the delta, not held here, then need not
/// wait: its author, cut from the label, may never place it. A frontier tells a demotion from a plain
/// grant of a low role, as the write alone cannot.
///
/// So this reads the role commits and ledgers held, never the timeline: a re-grant, the lowering's
/// fall or the fall of its signer's grant would end the release at nodes that learn of them first,
/// while those that applied stay applied. The price: such an author's later commits on that thing,
/// once re-granted, may show part by part as they arrive; so may those of an author an ex-admin
/// claims to lower.
fn removed_author(core: &Core, h: &Header, id: &CommitId, a: &osis_commit::AspectEntry) -> bool {
    let required = if h.kind.is_compaction() { crate::engine::write::snapshot_role(a.ak.as_str()) } else { required_role(a.ak.as_str()) };
    let is_author = |t: &Tid| *t == h.author || *t == h.actor;
    let unlisted = |f: &Option<Arc<Frontier>>| f.as_ref().is_some_and(|f| !f.covers(id));
    core.owner_chain(&a.tid).filter_map(|s| s.thing()).any(|t| {
        let lowered = |r: &&Arc<RoleCommit>| !is_author(&r.author) && unlisted(&r.frontier) && r.ops.iter().any(|o| o.target == t && is_author(&o.holder) && o.edge.as_ref().is_none_or(|e| e.role < required));
        // an entry ends a tenure; a tenure or roster edge of `required` or above starting at its end means no lowering
        let stays = |s: &RosterSnapshot, l: &osis_perm::Tenure| s.roster.get(&l.holder).is_some_and(|e| e.role >= required && e.since == Some(l.until)) || s.ledger.iter().any(|n| n.holder == l.holder && n.role >= required && n.since == Some(l.until) && n.until > l.until);
        // a snapshot whose `roles.0` part is still to come may not show who stays: it says nothing yet
        let in_ledger = |s: &&Arc<RosterSnapshot>| !s.roster.is_empty() && s.ledger.iter().any(|l| is_author(&l.holder) && l.role >= required && unlisted(&l.frontier) && !stays(s, l));
        let signers = core.ix.held.commits_on(&t).iter().filter(lowered).map(|r| r.author).chain(core.ix.held.snapshots_of(&t).iter().filter(in_ledger).map(|s| s.author));
        signed_by_possible_admin(core, &t, signers)
    })
}

