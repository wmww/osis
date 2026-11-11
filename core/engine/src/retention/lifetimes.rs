//! Thing lifetimes by reference (issues/thing-lifetimes.md; oracle: held-model `lifetimes`). A
//! thing listing retainers (`retainers^.0`) is kept while a listed retainer that is itself kept
//! references it, or a listed retainer is unknown here; a thing with no list is standalone and
//! kept. A thing judged unreachable is released by a node holding the right to end it; one
//! without is remembered (`PENDING`) until the right comes, as is a released one until its
//! ending clears the row (`queue_with_listers`), so a release request that fails to be written is
//! judged again (`judge_lifetimes`).
//!
//! Judged from what the node holds, per thing: **known** (a live minting held, not a kept copy),
//! **ended** (an ending held), else **unknown**. The judgment of one thing is a walk up its list
//! through retainers that reference what is below them, stopping at the first standalone or
//! unknown thing (`walk`). No liveness is cached: the kept state is the work list (`WORK`: things
//! a change touched), `HELD` (things whose walk read a thing not heard out, judged again once a
//! label is newly heard out) and `PENDING`. A walk
//! passes through a pending thing like any known thing: `PENDING` may be stale for a thing the
//! same run made reachable (held-model `a_stale_pending_thing_is_walked_through`).
//!
//! What queues (`queue`): a reference to a thing appearing or going, a thing's list changing
//! (`refs::note`); a thing becoming known, ended or forgotten, with its listers; every pending
//! thing once the role timelines change (a right gained). A missed queue only leaks; a walk reads
//! the current held state, so a release never rests on a queue.
//!
//! What a judgment releases goes in one **release request** (`release`): a commit with a
//! `released.0` delta on each thing, expiring `ROLE_KEEP` after it, which every node applies as
//! a purge of the thing's creation (`Header::requests`, `purge`), so it ends there by the one
//! ending path (`end`), never as erasure (no lasting header).

use crate::engine::refs;
use crate::engine::{Core, Mutation, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_store::Shred;
use std::collections::BTreeSet;

/// `lw/<tid>`: things to judge.
pub(crate) const WORK: &[u8] = b"lw/";
/// `lh/<tid>`: things whose walk read a thing not heard out: judged again once one is
/// (`judge_lifetimes` with `held`), not at every judgment of new work.
pub(crate) const HELD: &[u8] = b"lh/";
/// `lp/<tid>`: things judged unreachable and not ended here: this node may not end them, or the
/// release request for them is not applied yet.
pub(crate) const PENDING: &[u8] = b"lp/";

/// What the node holds of a thing, for the judgment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Known,
    Ended,
    Unknown,
}

/// `t` as the judgment reads it; `gone`: released in this run.
pub(crate) fn status(core: &Core, t: &Tid, gone: &BTreeSet<Tid>) -> Status {
    if gone.contains(t) || core.ended(t) {
        Status::Ended
    } else if core.exists(t) && core.mintings(t).next().is_some() && crate::retention::forget::copy_of(core, t).is_none() {
        Status::Known
    } else {
        Status::Unknown
    }
}

/// Queues `t` for judgment if it is known (durable transactions only: no reference or list is
/// ephemeral). A thing not known has nothing to judge; becoming known queues it.
pub(crate) fn queue(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    if tx.txn.is_memory() || status(tx.core, t, &BTreeSet::new()) != Status::Known {
        return Ok(());
    }
    tx.txn.put_local(&[WORK, t.as_bytes()].concat(), &[], Shred::No)?;
    Ok(())
}

/// Queues the things listing `t`, and `t` while known: its status changed (known, ended,
/// unknown). An ended or unknown thing's own rows go, so a forgotten thing leaves none.
pub(crate) fn queue_with_listers(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    if tx.txn.is_memory() {
        return Ok(());
    }
    if status(tx.core, t, &BTreeSet::new()) == Status::Known {
        set(tx, WORK, t, true)?;
    } else {
        set(tx, WORK, t, false)?;
        set(tx, HELD, t, false)?;
        set(tx, PENDING, t, false)?;
    }
    for l in refs::listers(tx, t)? {
        queue(tx, &l)?;
    }
    Ok(())
}

/// `t`'s list: `None` standalone (no list, or one that does not read as `set<tid>`: it cannot be
/// judged, so it is kept).
fn list(tx: &mut Tx<'_>, t: &Tid) -> Result<Option<BTreeSet<Tid>>> {
    let Ok(ak) = Ak::new(refs::RETAINERS) else { return Ok(None) };
    let v = tx.state(t, &ak)?.and_then(osis_crdt::Fragment::read);
    let Some(Value::Set(s)) = v else { return Ok(None) };
    let mut out = BTreeSet::new();
    for x in s {
        let Value::Tid(x) = x else { return Ok(None) };
        out.insert(x);
    }
    Ok(Some(out))
}

/// The things listing `x` that `x` references: whose judgment follows `x`'s.
fn below(tx: &mut Tx<'_>, x: &Tid) -> Result<Vec<Tid>> {
    let mut out = Vec::new();
    for y in refs::listers(tx, x)? {
        if refs::references(tx, x, &y)? {
            out.push(y);
        }
    }
    Ok(out)
}

/// Whether `x` (known) is unreachable: a walk up its list through retainers referencing what is
/// below them finds no standalone or unknown thing. `read`: every thing it read.
fn walk(tx: &mut Tx<'_>, x: &Tid, gone: &BTreeSet<Tid>, read: &mut BTreeSet<Tid>) -> Result<bool> {
    read.insert(*x);
    let mut seen = BTreeSet::from([*x]);
    let mut stack = vec![*x];
    while let Some(y) = stack.pop() {
        crate::costs::count("lifetimes: walked", 1);
        let Some(l) = list(tx, &y)? else { return Ok(false) };
        for r in l {
            read.insert(r);
            match status(tx.core, &r, gone) {
                Status::Unknown => return Ok(false),
                Status::Ended => {}
                Status::Known => {
                    if !seen.contains(&r) && refs::references(tx, &r, &y)? {
                        seen.insert(r);
                        stack.push(r);
                    }
                }
            }
        }
    }
    Ok(true)
}

/// Whether `x` is known and unreachable on the current held state, heard out or not
/// (`Mutation::require_kept`: a writer refusing its own write, the safe side).
pub(crate) fn unreachable_now(tx: &mut Tx<'_>, x: &Tid) -> Result<bool> {
    if status(tx.core, x, &BTreeSet::new()) != Status::Known {
        return Ok(false);
    }
    walk(tx, x, &BTreeSet::new(), &mut BTreeSet::new())
}

/// Whether this node may end `x`: its account, which writes the request (`release`), holds the
/// purge right over every held minting of it (spec/permissions.md §6), as `end` would be judged.
fn may_end(tx: &Tx<'_>, x: &Tid) -> bool {
    let Ok(who) = tx.core.writer() else { return false };
    let Some(ts) = osis_base::Ts::make(tx.now(), 0) else { return false };
    let Ok(ak) = Ak::new(osis_commit::retention::CREATED) else { return false };
    let mut any = false;
    tx.core.mintings(x).all(|(c, _)| {
        any = true;
        super::purge::would_hold_right(tx.core, &who, ts, &c, x, &ak)
    }) && any
}

fn has(tx: &mut Tx<'_>, prefix: &[u8], t: &Tid) -> Result<bool> {
    Ok(tx.txn.get_local(&[prefix, t.as_bytes()].concat())?.is_some())
}

fn set(tx: &mut Tx<'_>, prefix: &[u8], t: &Tid, on: bool) -> Result<()> {
    let k = [prefix, t.as_bytes()].concat();
    if on {
        tx.txn.put_local(&k, &[], Shred::No)?;
    } else {
        tx.txn.remove_local(&k, Shred::No)?;
    }
    Ok(())
}

fn rows(tx: &mut Tx<'_>, prefix: &[u8]) -> Result<Vec<Tid>> {
    let mut out = Vec::new();
    tx.scan(prefix, |k, _| {
        out.push(Tid::from_bytes(k.try_into().map_err(|_| crate::error::Error::Corrupt("lifetimes row"))?));
        Ok(())
    })?;
    Ok(out)
}

/// What one judgment did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Judged {
    /// Unreachable things this node may end, with what only they kept.
    pub release: Vec<Tid>,
    /// Things held: a thing their walk read is not heard out.
    pub waiting: usize,
    /// Things judged.
    pub judged: usize,
    /// The release request written for `release`.
    pub request: Option<CommitId>,
}

/// Whether every group holding `t` (itself included) is heard out: a thing under no label is.
fn heard_thing(core: &Core, t: &Tid, heard: &dyn Fn(&Tid) -> bool) -> bool {
    heard(t) && core.ix.groups.of.get(t).is_none_or(|gs| gs.iter().all(heard))
}

/// Judges the work list (with `held`, the held things; every pending thing when `rights` may have
/// changed): each thing whose walk read only things `heard` says are heard out. Unreachable ones
/// this node may end go in `release` with their cascade; the rest of the unreachable ones are
/// pending.
pub(crate) fn judge(tx: &mut Tx<'_>, heard: &dyn Fn(&Tid) -> bool, held: bool, rights: bool) -> Result<Judged> {
    let mut queue = rows(tx, WORK)?;
    if held {
        queue.extend(rows(tx, HELD)?);
    }
    if rights {
        queue.extend(rows(tx, PENDING)?);
    }
    let mut out = Judged::default();
    let mut gone = BTreeSet::new();
    let mut waiting = BTreeSet::new();
    while let Some(x) = queue.pop() {
        if status(tx.core, &x, &gone) != Status::Known {
            set(tx, WORK, &x, false)?;
            set(tx, HELD, &x, false)?;
            set(tx, PENDING, &x, false)?;
            continue;
        }
        out.judged += 1;
        let mut read = BTreeSet::new();
        let unreachable = walk(tx, &x, &gone, &mut read)?;
        set(tx, WORK, &x, false)?;
        if !read.iter().all(|t| heard_thing(tx.core, t, heard)) {
            set(tx, HELD, &x, true)?;
            waiting.insert(x);
            continue;
        }
        waiting.remove(&x);
        set(tx, HELD, &x, false)?;
        let pending = has(tx, PENDING, &x)?;
        if unreachable {
            if may_end(tx, &x) {
                gone.insert(x);
                out.release.push(x);
                // until the request ends it (`judge_lifetimes`)
                set(tx, PENDING, &x, true)?;
                queue.extend(below(tx, &x)?);
            } else if !pending {
                set(tx, PENDING, &x, true)?;
                queue.extend(below(tx, &x)?);
            }
        } else if pending {
            set(tx, PENDING, &x, false)?;
            queue.extend(below(tx, &x)?);
        }
    }
    out.waiting = waiting.len();
    Ok(out)
}

/// The things judged unreachable here and not ended (`PENDING`).
pub(crate) fn pending(tx: &mut Tx<'_>) -> Result<Vec<Tid>> {
    rows(tx, PENDING)
}

impl crate::engine::Engine {
    /// Whether the lifetime judgment has work (`judge_lifetimes`): a thing queued, or the role
    /// timelines changed while a thing is pending; and whether a thing is held (waits for a
    /// label to be heard out). Two store seeks.
    pub fn lifetimes_due(&mut self) -> Result<(bool, bool)> {
        let rights = self.core.lifetimes_rights;
        self.run(|tx| {
            let due = !tx.txn.scan_local(WORK, &[], 1)?.is_empty() || (rights && !tx.txn.scan_local(PENDING, &[], 1)?.is_empty());
            Ok((due, !tx.txn.scan_local(HELD, &[], 1)?.is_empty()))
        })
    }

    /// Judges the things changes touched (issues/thing-lifetimes.md, The judgment), and with
    /// `held` the things held at an earlier judgment: each whose walk read only things heard out
    /// (each group holding it, itself included, `heard` says is: node-sync, every label of the
    /// group is; a thing under no group is), the rest held. Node-sync passes `held` once a label
    /// is newly heard out, so new work alone does not walk the held things again. The unreachable things this node may
    /// end, with what only they kept, it releases in one request (`release`); the others it may
    /// not end are pending. A released thing is pending too until the request, applied, ends it:
    /// one whose request is refused or fails to be written (an `Err` here) is judged again at the
    /// next change of the role timelines or the next open, or once its list or a reference to
    /// it changes.
    pub fn judge_lifetimes(&mut self, heard: &dyn Fn(&Tid) -> bool, held: bool) -> Result<Judged> {
        let rights = self.core.lifetimes_rights;
        let mut out = self.run(|tx| judge(tx, heard, held, rights))?;
        self.core.lifetimes_rights = false;
        out.request = self.release(&out.release)?;
        Ok(out)
    }

    /// Writes a release request for `xs` as this node's account (spec/commits.md §5 Ending): one
    /// commit with a `released.0` delta on each, so each copy of a delta names only its own
    /// thing; it expires `ROLE_KEEP` after its `ts`. Applied, it ends each thing as a purge of its
    /// creation does. `Permission` when the account may not end one of them; `None` for none.
    pub fn release(&mut self, xs: &[Tid]) -> Result<Option<CommitId>> {
        if xs.is_empty() {
            return Ok(None);
        }
        let now = self.now();
        let mut m = Mutation::new();
        for x in xs {
            m.set(*x, &osis_schema::core_types::RELEASED, &now)?;
        }
        self.commit(m)
    }

    /// The things judged unreachable here and not ended (`PENDING`).
    pub fn lifetimes_pending(&mut self) -> Result<Vec<Tid>> {
        self.run(pending)
    }

    /// How the lifetime judgment reads `t` here (known, ended, unknown).
    pub fn lifetime_status(&self, t: &Tid) -> Status {
        status(&self.core, t, &BTreeSet::new())
    }
}
