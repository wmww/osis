//! Paths per sync ID (spec/sync-ids.md §3, §5 Path, §6 Register and Behind): the steps from
//! genesis to the head this store serves, each with its claim set until it has been superseded
//! for `ROLE_KEEP`. A node keeping S unread holds the path registered with it; a node reading S
//! the path its `sync.0` records (`Store::serve_path`). A head move logs a head event.

use super::entries::add_usage;
use super::rows::{self, R, StepRow, W};
use super::Env;
use crate::types::Result;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{SyncId, WallMs};
use osis_crypto::{Signature, VerifyingKey};
use osis_engine::sync::{Holding, Path};
use osis_blob::{ClaimSet, Step, StepId};
use osis_proto::{Code, Grant};
use osis_store::{Shred, Transaction};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A credential key a Behind item was signed by (spec/sync-ids.md §6 Behind), its open signature
/// verified by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cred {
    /// A step's sync key.
    Sync(VerifyingKey),
    /// A claim public key of a step's claim set.
    Claim([u8; 32]),
    /// A link key's signing key, whose static entry a claim set may list.
    Signing(VerifyingKey),
}

/// A Behind item's answer (spec/sync-ids.md §6 Behind, spec/wire.md §11.2 Offer): code 0 with
/// the steps after the named one, or with a static Hit's grant (the head's entry box and the path
/// from genesis); else 4 past the step bound, 13 for a sync ID not kept here, 14, with nothing.
pub type Behind = (Code, Option<Grant>);

fn refused(c: Code) -> Behind {
    (c, None)
}

pub(crate) fn len(t: &mut Transaction<'_>, s: &SyncId) -> Result<u32> {
    t.get_local(&rows::head_key(s))?.map_or(Ok(0), |v| R::new(&v).u32())
}

pub(crate) fn step_row(t: &mut Transaction<'_>, s: &SyncId, i: u32) -> Result<Option<StepRow>> {
    t.get_local(&rows::step_key(s, i))?.map(|v| StepRow::decode(&v)).transpose()
}

/// S's path as its rows hold it, parsed: its steps with their claim sets, and each step's ID.
#[derive(Clone, Debug, Default)]
pub(crate) struct Kept {
    pub path: Arc<Path>,
    pub ids: Vec<StepId>,
}

impl Kept {
    pub(crate) fn head(&self) -> Option<(u32, &Step)> {
        let i = self.path.steps.len().checked_sub(1)?;
        Some((i as u32, &self.path.steps.get(i)?.0))
    }
}

/// The durable part's paths parsed (`Kept`), per sync ID: parsed at the first read, then changed
/// by the writes that change the rows (`append`, `truncate`, `drop_claims`), staged in the
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
        ids.push(StepId(osis_base::hash::hash(&r.step)));
        steps.push((Step::parse(&r.step).map_err(osis_engine::Error::from)?, claims(t, s, i)?));
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

pub(crate) fn claims(t: &mut Transaction<'_>, s: &SyncId, i: u32) -> Result<Option<ClaimSet>> {
    Ok(t.get_local(&rows::claims_key(s, i))?.map(|v| ClaimSet::parse(&v)).transpose().map_err(osis_engine::Error::from)?)
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

/// Bytes a step and its claim set count toward the caps.
fn step_bytes(step: &Step, claims: Option<&ClaimSet>) -> u64 {
    (step.to_bytes().len() + claims.map_or(0, |c| c.to_bytes().len())) as u64
}

/// Appends `step` (the head's child, or the genesis step) with its claim set, the parent's set
/// starting its `ROLE_KEEP` at its first child; logs the head event.
pub(crate) fn append(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, step: &Step, claims: Option<&ClaimSet>) -> Result<()> {
    change(t, env, s, |k| {
        Arc::make_mut(&mut k.path).steps.push((step.clone(), claims.cloned()));
        k.ids.push(step.id());
    })?;
    let n = len(t, s)?;
    if let Some(p) = n.checked_sub(1)
        && let Some(mut row) = step_row(t, s, p)?
        && row.superseded.is_none()
    {
        row.superseded = Some(env.now);
        t.put_local(&rows::step_key(s, p), &row.encode(), Shred::No)?;
        if t.get_local(&rows::claims_key(s, p))?.is_some() {
            t.put_local(&rows::claims_due_key(WallMs(env.now.0.saturating_add(ROLE_KEEP_MS)), s, p), &[], Shred::No)?;
        }
    }
    t.put_local(&rows::step_key(s, n), &StepRow { superseded: None, step: step.to_bytes() }.encode(), Shred::No)?;
    if let Some(c) = claims {
        t.put_local(&rows::claims_key(s, n), &c.to_bytes(), Shred::No)?;
    }
    t.put_local(&rows::head_key(s), &W::default().u32(n + 1).take(), Shred::No)?;
    let add = step_bytes(step, claims);
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
        n += step_row(t, s, i)?.map_or(0, |r| r.step.len() as u64);
        n += t.get_local(&rows::claims_key(s, i))?.map_or(0, |c| c.len() as u64);
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
            freed += row.step.len() as u64;
            if let Some(at) = row.superseded {
                t.remove_local(&rows::claims_due_key(WallMs(at.0.saturating_add(ROLE_KEEP_MS)), s, i), Shred::No)?;
            }
        }
        if let Some(c) = t.get_local(&rows::claims_key(s, i))? {
            freed += c.len() as u64;
        }
        t.remove_local(&rows::step_key(s, i), Shred::No)?;
        t.remove_local(&rows::claims_key(s, i), Shred::No)?;
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
    if read(t, env, s)?.as_deref() == Some(path) {
        return Ok(());
    }
    erase(t, env, s)?;
    for (st, c) in &path.steps {
        append(t, env, s, st, c.as_ref())?;
    }
    Ok(())
}

/// Drops claim set `i` of S once superseded for `ROLE_KEEP` (the sweep).
pub(crate) fn drop_claims(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, i: u32) -> Result<()> {
    if let Some(c) = t.get_local(&rows::claims_key(s, i))? {
        change(t, env, s, |k| {
            if let Some(x) = Arc::make_mut(&mut k.path).steps.get_mut(i as usize) {
                x.1 = None;
            }
        })?;
        t.remove_local(&rows::claims_key(s, i), Shred::No)?;
        add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_sub(c.len() as u64))?;
    }
    Ok(())
}

/// Register (spec/sync-ids.md §6, spec/wire.md §11.2 Register) of `steps`, each a child of the
/// one before: 2 a step of another sync ID or a claim set of another hash; 14 a sync ID not kept
/// unread in the sync set; into an empty path a list from a genesis step that verifies (else 1; a
/// list from a child step 13; a later step not verifying under the one before 9), within the caps
/// (else 12); else a list ending at the head (0, nothing changes), or one leaving the path at a
/// step whose delete key is the head's or ending at a step `endorsement` endorses under the
/// head's delete key, each step verifying under the one before, its last deeper than the head
/// (else 9), taken in place of the path after that step: within the caps, past them without its
/// claim sets, and past them even so at most once per `register_every_ms`. A head moved over a
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
pub(crate) fn register(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, steps: &[(&Step, Option<&ClaimSet>)], endorsement: Option<&Signature>, past_cap_due: bool) -> Result<(Code, bool, bool)> {
    let Some(((first, _), (last, _))) = steps.first().zip(steps.last()) else { return Ok((Code::MALFORMED, false, false)) };
    if steps.iter().any(|(st, c)| st.sync_id != *s || c.is_some_and(|c| c.hash() != st.claims_hash || !c.fits(s))) {
        return Ok((Code::MALFORMED, false, false));
    }
    if env.holding(s) != Some(Holding::Unread) {
        return Ok((Code::DECLINED, false, false));
    }
    let chained = |from: &Step, rest: &[(&Step, Option<&ClaimSet>)]| {
        let mut parent = from;
        for (st, _) in rest {
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
            while let Some((st, _)) = steps.get(skip)
                && ids.get(at) == Some(&st.id())
            {
                skip += 1;
                at += 1;
            }
            let new = steps.get(skip..).unwrap_or_default();
            // `at` is at least 1 here: a genesis the path does not hold is no step after one of it
            let Some(fork) = at.checked_sub(1).and_then(|j| path.path.steps.get(j)).map(|(st, _)| st.clone()) else {
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
    let add = |with: bool| new.iter().map(|(st, c)| step_bytes(st, if with { *c } else { None })).sum::<u64>().saturating_sub(freed);
    let (with_claims, past) = if env.room(t, s, 0, add(true))? {
        (true, false)
    } else if keep == 0 && len(t, s)? == 0 {
        return Ok((Code::STORAGE_CAP, false, false));
    } else if env.room(t, s, 0, add(false))? {
        (false, false)
    } else if past_cap_due {
        (false, true)
    } else {
        return Ok((Code::STORAGE_CAP, false, false));
    };
    truncate(t, env, s, keep)?;
    for (st, c) in new {
        append(t, env, s, st, if with_claims { *c } else { None })?;
    }
    let mark = rows::anew_key(s);
    if t.get_local(&mark)?.is_none() && t.records_any_row(s, rows::tag::TOLD, b"")? {
        t.put_local(&mark, rows::ANEW_SOME, Shred::No)?;
    }
    Ok((Code::OK, past, true))
}

/// The code a Behind of S that carries nothing is answered with, whatever it names or shows
/// (spec/sync-ids.md §6 Behind): 13 where this node does not keep S (kept unread with no step
/// registered included), else 14 (a node reading S answers every Behind of S so).
pub(crate) fn behind_refusal(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId) -> Result<Code> {
    Ok(match env.holding(s) {
        None => Code::UNKNOWN_SYNC_ID,
        Some(Holding::Unread) if kept(t, env, s)?.is_none() => Code::UNKNOWN_SYNC_ID,
        Some(_) => Code::DECLINED,
    })
}

/// A Behind item's answer at a node keeping S unread (spec/sync-ids.md §6 Behind): at most
/// `max_steps` steps in it.
pub(crate) fn behind(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, named: Option<&StepId>, cred: &Cred, max_steps: usize) -> Result<Behind> {
    if env.holding(s) != Some(Holding::Unread) {
        return Ok(refused(behind_refusal(t, env, s)?));
    }
    let Some(k) = kept(t, env, s)? else { return Ok(refused(behind_refusal(t, env, s)?)) };
    let path: Vec<&Step> = k.path.steps.iter().map(|(st, _)| st).collect();
    let Some(last) = path.len().checked_sub(1) else { return Ok(refused(behind_refusal(t, env, s)?)) };
    let claims = |i: usize| k.path.steps.get(i).and_then(|(_, c)| c.as_ref());
    let bound = |v: Vec<Step>| if v.is_empty() { refused(Code::RATE_LIMITED) } else { (Code::OK, Some(Grant { entry_box: None, steps: v })) };
    match (named, cred) {
        (Some(id), _) => {
            let Some(i) = k.ids.iter().take(last).position(|x| x == id) else { return Ok(refused(Code::DECLINED)) };
            let Some(named_step) = path.get(i) else { return Ok(refused(Code::DECLINED)) };
            let is_cred = match cred {
                Cred::Sync(k) => named_step.keys.sync == *k,
                Cred::Claim(pk) => claims(i).is_some_and(|c| c.contains(pk)),
                Cred::Signing(key) => claims(i).is_some_and(|c| c.contains(&osis_crypto::static_entry(s, key))),
            };
            if !is_cred {
                return Ok(refused(Code::DECLINED));
            }
            let mut out = Vec::new();
            for st in path.iter().skip(i + 1) {
                if out.len() == max_steps {
                    break;
                }
                let other = st.keys.sync != named_step.keys.sync;
                out.push((*st).clone());
                if other {
                    break;
                }
            }
            Ok(bound(out))
        }
        (None, Cred::Sync(key)) => match path.iter().take(last).rposition(|st| st.keys.sync == *key) {
            Some(j) => Ok(bound(path.get(j + 1).into_iter().take(max_steps).map(|st| (*st).clone()).collect())),
            None => Ok(refused(Code::DECLINED)),
        },
        (None, Cred::Signing(key)) => {
            let Some(c) = claims(last) else { return Ok(refused(Code::DECLINED)) };
            let Some(entry_box) = c.entry_box(s, key).cloned() else { return Ok(refused(Code::DECLINED)) };
            if path.len() > max_steps {
                return Ok(refused(Code::RATE_LIMITED));
            }
            Ok((Code::OK, Some(Grant { entry_box: Some(entry_box), steps: path.into_iter().cloned().collect() })))
        }
        (None, Cred::Claim(_)) => Ok(refused(Code::DECLINED)),
    }
}

/// Whether `ok` holds of a step on S's path before its head: a stamp or Delete verifying under
/// such a step's keys only is under superseded keys (code 9, spec/sync-ids.md §6).
pub(crate) fn earlier(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, ok: impl Fn(&Step) -> bool) -> Result<bool> {
    let Some(k) = kept(t, env, s)? else { return Ok(false) };
    let n = k.path.steps.len().saturating_sub(1);
    Ok(k.path.steps.iter().take(n).rev().any(|(st, _)| ok(st)))
}
