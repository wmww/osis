//! Paths per sync ID (spec/sync-ids.md §3, §5 Path, §6 Register): the steps from genesis to the
//! head this store serves. A node keeping S unread holds the path registered with it; a node
//! reading S the path its `sync.0` records (`Store::serve_path`). A head move logs a head event.

use super::entries::add_usage;
use super::rows::{self, R, W};
use super::Env;
use crate::types::Result;
use osis_base::SyncId;
use osis_crypto::Signature;
use osis_engine::sync::{Holding, Path};
use osis_blob::{Step, StepId};
use osis_proto::Code;
use osis_store::{Shred, Transaction};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) fn len(t: &mut Transaction<'_>, s: &SyncId) -> Result<u32> {
    t.get_local(&rows::head_key(s))?.map_or(Ok(0), |v| R::new(&v).u32())
}

/// Step `i` of S's path as its row holds it: its bytes.
pub(crate) fn step_row(t: &mut Transaction<'_>, s: &SyncId, i: u32) -> Result<Option<Vec<u8>>> {
    Ok(t.get_local(&rows::step_key(s, i))?)
}

/// S's path as its rows hold it, parsed: its steps, and each step's ID.
#[derive(Clone, Debug, Default)]
pub(crate) struct Kept {
    pub path: Arc<Path>,
    pub ids: Vec<StepId>,
}

impl Kept {
    pub(crate) fn head(&self) -> Option<(u32, &Step)> {
        let i = self.path.steps.len().checked_sub(1)?;
        Some((i as u32, self.path.steps.get(i)?))
    }
}

/// The durable part's paths parsed (`Kept`), per sync ID: parsed at the first read, then changed
/// by the writes that change the rows (`append`, `truncate`), staged in the
/// transaction and taken at its commit (`end`). A read of one reads its stamp in `Memory::stamps`,
/// which a committed change moves. The memory part holds no path.
#[derive(Clone, Default)]
pub(crate) struct Paths {
    kept: BTreeMap<SyncId, Arc<Kept>>,
    /// This transaction's changes: `None`, no path.
    staged: BTreeMap<SyncId, Option<Arc<Kept>>>,
}

/// The stamp key of S's path in `Memory::stamps`.
#[derive(Hash)]
struct PathOf<'a>(&'static str, &'a SyncId);

impl Paths {
    /// Whether this transaction changed a path.
    pub(crate) fn staged(&self) -> bool {
        !self.staged.is_empty()
    }

    /// The transaction ends, committed or not.
    pub(crate) fn end(&mut self, committed: bool, stamps: &osis_base::memo::Stamps) {
        for (s, k) in std::mem::take(&mut self.staged) {
            if !committed {
                continue;
            }
            stamps.wrote(&PathOf("path", &s), true);
            match k {
                Some(k) => self.kept.insert(s, k),
                None => self.kept.remove(&s),
            };
        }
    }
}

/// S's path, parsed once per change (`Paths`). O(1) once parsed.
pub(crate) fn kept(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<Option<Arc<Kept>>> {
    if t.is_memory() {
        return Ok(None);
    }
    env.mem.stamps.read(&PathOf("path", s));
    if let Some(k) = env.paths.staged.get(s) {
        return Ok(k.clone());
    }
    if let Some(k) = env.paths.kept.get(s) {
        return Ok(Some(k.clone()));
    }
    let n = len(t, s)?;
    if n == 0 {
        return Ok(None);
    }
    let (mut steps, mut ids) = (Vec::with_capacity(n as usize), Vec::with_capacity(n as usize));
    for i in 0..n {
        let Some(r) = step_row(t, s, i)? else { break };
        ids.push(StepId(osis_base::hash::hash(&r)));
        steps.push(Step::parse(&r).map_err(osis_engine::Error::from)?);
    }
    let k = Arc::new(Kept { path: Arc::new(Path { steps }), ids });
    env.paths.kept.insert(*s, k.clone());
    Ok(Some(k))
}

/// Changes S's parsed path as its rows change in this transaction: before they do (a first read
/// parses the rows as they were).
fn change(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, f: impl FnOnce(&mut Kept)) -> Result<()> {
    debug_assert!(!t.is_memory(), "a path written in the memory part");
    let mut k = kept(t, env, s)?.unwrap_or_default();
    f(Arc::make_mut(&mut k));
    let k = (!k.ids.is_empty()).then_some(k);
    env.paths.staged.insert(*s, k);
    Ok(())
}

/// The head and its index.
pub(crate) fn head(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<Option<(u32, Step)>> {
    Ok(kept(t, env, s)?.and_then(|k| k.head().map(|(i, st)| (i, st.clone()))))
}

/// The head's ID.
pub(crate) fn head_id(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<Option<StepId>> {
    Ok(kept(t, env, s)?.and_then(|k| k.ids.last().copied()))
}

pub(crate) fn read(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<Option<Arc<Path>>> {
    Ok(kept(t, env, s)?.map(|k| k.path.clone()))
}

/// Bytes a step counts toward the caps.
fn step_bytes(step: &Step) -> u64 {
    step.to_bytes().len() as u64
}

/// Appends `step` (the head's child, or the genesis step); logs the head event.
pub(crate) fn append(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, step: &Step) -> Result<()> {
    change(t, env, s, |k| {
        Arc::make_mut(&mut k.path).steps.push(step.clone());
        k.ids.push(step.id());
    })?;
    let n = len(t, s)?;
    t.put_local(&rows::step_key(s, n), &step.to_bytes(), Shred::No)?;
    t.put_local(&rows::head_key(s), &W::default().u32(n + 1).take(), Shred::No)?;
    let add = step_bytes(step);
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_add(add))?;
    t.log_head(*s, &step.id().0)?;
    Ok(())
}

/// Drops S's path rows (its usage with them).
pub(crate) fn erase(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<()> {
    truncate(t, env, s, 0)
}

/// Bytes the path rows from index `keep` on count toward the caps.
fn bytes_from(t: &mut Transaction<'_>, s: &SyncId, keep: u32) -> Result<u64> {
    let mut n = 0;
    for i in keep..len(t, s)? {
        n += step_row(t, s, i)?.map_or(0, |r| r.len() as u64);
    }
    Ok(n)
}

/// Drops S's path rows from index `keep` on (its usage with them).
fn truncate(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, keep: u32) -> Result<()> {
    let n = len(t, s)?;
    if keep < n {
        change(t, env, s, |k| {
            Arc::make_mut(&mut k.path).steps.truncate(keep as usize);
            k.ids.truncate(keep as usize);
        })?;
    }
    let mut freed = 0;
    for i in keep..n {
        if let Some(row) = step_row(t, s, i)? {
            freed += row.len() as u64;
        }
        t.remove_local(&rows::step_key(s, i), Shred::No)?;
    }
    if keep == 0 {
        t.remove_local(&rows::head_key(s), Shred::No)?;
    } else if keep < n {
        t.put_local(&rows::head_key(s), &W::default().u32(keep).take(), Shred::No)?;
    }
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_sub(freed))
}

/// A reader's served path: replaced whole by what its `sync.0` records, the head event logged
/// when the head moved.
pub(crate) fn serve(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, path: &Path) -> Result<()> {
    if kept(t, env, s)?.is_some_and(|k| k.path.steps == path.steps) {
        return Ok(());
    }
    erase(t, env, s)?;
    for st in &path.steps {
        append(t, env, s, st)?;
    }
    Ok(())
}

/// Register (spec/sync-ids.md §6, spec/wire.md §11.2 Register) of `steps`, each a child of the
/// one before: 2 a step of another sync ID; 14 a sync ID not kept
/// unread in the sync set; into an empty path a list from a genesis step that verifies (else 1; a
/// list from a child step 13; a later step not verifying under the one before 9), within the caps
/// (else 12); else a list ending at the head (0, nothing changes), or one leaving the path at a
/// step whose delete key is the head's or ending at a step `endorsement` endorses under the
/// head's delete key, each step verifying under the one before, its last deeper than the head
/// (else 9), taken in place of the path after that step: within the caps, and past them at most
/// once per `register_every_ms`. A head moved over a
/// refusal told to a record's source marks S anew (`rows::ANEW_SOME`) unless a mark stands:
/// refusals told under the old head are shown again (spec/sync-streams.md §4 Refused; a
/// connection's are in memory, `Store::take_register`). Answers the code, whether past the caps,
/// and whether the head moved.
///
/// Invariant: a Register moves a store only deeper, and only by the word of its head's delete
/// key: the branch leaves the path at a step bearing that key (its first step signed by it), or
/// its last step carries an endorsement by it (a signature under its own domain over that step's
/// ID, so no step, Delete or other signature passes for one). Either way whoever moves it holds
/// the head's delete key (an admin of the head's admin epoch, who could as well make a child of
/// the head bearing any keys it likes) or relays what such a holder signed: an endorsement grants
/// nothing a child of the head does not, and like a step it stands for good. It names its step,
/// whose ID binds the sync ID and, through `prev`, every step above it, so it moves no store of
/// another sync ID and endorses no other branch; it binds no head, since any store whose head
/// bears its key is one its signer could move by a child. An admin removed at the head's step
/// (a rotation of the admin secret) holds only older delete keys and so neither signs a child of
/// the head nor endorses. A relay (a removed node included) replays only real steps and
/// endorsements: an equal-depth sibling or a shallower path is refused, so it cannot flip a store
/// between siblings or roll it back; a removed admin holding an older delete key than the head's
/// cannot branch below the head.
pub(crate) fn register(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, steps: &[Step], endorsement: Option<&Signature>, past_cap_due: bool) -> Result<(Code, bool, bool)> {
    let Some((first, last)) = steps.first().zip(steps.last()) else { return Ok((Code::MALFORMED, false, false)) };
    if steps.iter().any(|st| st.sync_id != *s) {
        return Ok((Code::MALFORMED, false, false));
    }
    if env.holding(s) != Some(Holding::Unread) {
        return Ok((Code::DECLINED, false, false));
    }
    let chained = |from: &Step, rest: &[Step]| {
        let mut parent = from;
        for st in rest {
            if st.verify_child(parent).is_err() {
                return false;
            }
            parent = st;
        }
        true
    };
    // the index the new steps start at, and those of the list the path does not hold
    let (keep, new) = match head(t, env, s)? {
        None if first.prev.is_some() => return Ok((Code::UNKNOWN_SYNC_ID, false, false)),
        None if first.verify_genesis().is_err() => return Ok((Code::REFUSED, false, false)),
        None if !chained(first, steps.get(1..).unwrap_or_default()) => return Ok((Code::NOT_HEAD_KEY, false, false)),
        None => (0, steps),
        Some((_, h)) if h.id() == last.id() => return Ok((Code::OK, false, false)),
        Some((hi, h)) => {
            let path = kept(t, env, s)?.unwrap_or_default();
            let ids = &path.ids;
            // where the list's first step goes on the path, then past the steps the path holds
            let Some(mut at) = (match first.prev {
                None => Some(0),
                Some(p) => ids.iter().position(|x| *x == p).map(|j| j + 1),
            }) else {
                return Ok((Code::NOT_HEAD_KEY, false, false));
            };
            let mut skip = 0;
            while let Some(st) = steps.get(skip)
                && ids.get(at) == Some(&st.id())
            {
                skip += 1;
                at += 1;
            }
            let new = steps.get(skip..).unwrap_or_default();
            // `at` is at least 1 here: a genesis the path does not hold is no step after one of it
            let Some(fork) = at.checked_sub(1).and_then(|j| path.path.steps.get(j)).cloned() else {
                return Ok((Code::NOT_HEAD_KEY, false, false));
            };
            let by_head = fork.keys.delete == h.keys.delete || endorsement.is_some_and(|e| last.endorsed_by(&h.keys.delete, e));
            if new.is_empty() || at + new.len() <= hi as usize + 1 || !by_head || !chained(&fork, new) {
                return Ok((Code::NOT_HEAD_KEY, false, false));
            }
            (at as u32, new)
        }
    };
    let freed = bytes_from(t, s, keep)?;
    let add = new.iter().map(step_bytes).sum::<u64>().saturating_sub(freed);
    let past = if env.room(t, s, 0, add)? {
        false
    } else if keep == 0 && len(t, s)? == 0 || !past_cap_due {
        return Ok((Code::STORAGE_CAP, false, false));
    } else {
        true
    };
    truncate(t, env, s, keep)?;
    for st in new {
        append(t, env, s, st)?;
    }
    let mark = rows::anew_key(s);
    if t.get_local(&mark)?.is_none() && t.records_any_row(s, rows::tag::TOLD, b"")? {
        t.put_local(&mark, rows::ANEW_SOME, Shred::No)?;
    }
    Ok((Code::OK, past, true))
}

/// Whether `ok` holds of a step on S's path before its head: a stamp or Delete verifying under
/// such a step's keys only is under superseded keys (code 9, spec/sync-ids.md §6).
pub(crate) fn earlier(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, ok: impl Fn(&Step) -> bool) -> Result<bool> {
    let Some(k) = kept(t, env, s)? else { return Ok(false) };
    let n = k.path.steps.len().saturating_sub(1);
    Ok(k.path.steps.iter().take(n).rev().any(ok))
}
