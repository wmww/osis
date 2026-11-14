//! Paths per sync ID (spec/sync-ids.md §3, §5 Path, §6 Register and Behind): the steps from
//! genesis to the head this store serves, each with its claim set until it has been superseded
//! for `ROLE_KEEP`. A node keeping S unread holds the path registered with it; a node reading S
//! the path its `sync.0` records (`Store::serve_path`). A head move logs a head event.

use super::entries::add_usage;
use super::rows::{self, R, StepRow, W};
use super::{Env, Policy};
use crate::types::Result;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{SyncId, WallMs};
use osis_crypto::VerifyingKey;
use osis_engine::sync::{Holding, Path};
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Code, Grant};
use osis_store::{Shred, Transaction};

/// A credential key a Behind item was signed by (spec/sync-ids.md §6 Behind), its open signature
/// verified by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cred {
    /// A step's sync key.
    Sync(VerifyingKey),
    /// A claim public key of a step's claim set.
    Claim([u8; 32]),
    /// A key actor's signing key, whose static entry a claim set may list.
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

pub(crate) fn step(t: &mut Transaction<'_>, s: &SyncId, i: u32) -> Result<Option<Step>> {
    Ok(step_row(t, s, i)?.map(|r| Step::parse(&r.step)).transpose().map_err(osis_engine::Error::from)?)
}

pub(crate) fn claims(t: &mut Transaction<'_>, s: &SyncId, i: u32) -> Result<Option<ClaimSet>> {
    Ok(t.get_local(&rows::claims_key(s, i))?.map(|v| ClaimSet::parse(&v)).transpose().map_err(osis_engine::Error::from)?)
}

/// The head and its index.
pub(crate) fn head(t: &mut Transaction<'_>, s: &SyncId) -> Result<Option<(u32, Step)>> {
    let n = len(t, s)?;
    let Some(i) = n.checked_sub(1) else { return Ok(None) };
    Ok(step(t, s, i)?.map(|st| (i, st)))
}

pub(crate) fn read(t: &mut Transaction<'_>, s: &SyncId) -> Result<Option<Path>> {
    let n = len(t, s)?;
    if n == 0 {
        return Ok(None);
    }
    let mut steps = Vec::with_capacity(n as usize);
    for i in 0..n {
        let Some(st) = step(t, s, i)? else { break };
        steps.push((st, claims(t, s, i)?));
    }
    Ok(Some(Path { steps }))
}

/// The steps alone, from genesis.
fn steps(t: &mut Transaction<'_>, s: &SyncId) -> Result<Vec<Step>> {
    let n = len(t, s)?;
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        out.extend(step(t, s, i)?);
    }
    Ok(out)
}

/// Bytes a step and its claim set count toward the caps.
fn step_bytes(step: &Step, claims: Option<&ClaimSet>) -> u64 {
    (step.to_bytes().len() + claims.map_or(0, |c| c.to_bytes().len())) as u64
}

/// Appends `step` (the head's child, or the genesis step) with its claim set, the parent's set
/// starting its `ROLE_KEEP`; logs the head event.
pub(crate) fn append(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, step: &Step, claims: Option<&ClaimSet>) -> Result<()> {
    let n = len(t, s)?;
    if let Some(p) = n.checked_sub(1)
        && let Some(mut row) = step_row(t, s, p)?
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
    let n = len(t, s)?;
    let mut freed = 0;
    for i in 0..n {
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
    t.remove_local(&rows::head_key(s), Shred::No)?;
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_sub(freed))
}

/// A reader's served path: replaced whole by what its `sync.0` records, the head event logged
/// when the head moved.
pub(crate) fn serve(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, path: &Path) -> Result<()> {
    if read(t, s)?.as_ref() == Some(path) {
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
        t.remove_local(&rows::claims_key(s, i), Shred::No)?;
        add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_sub(c.len() as u64))?;
    }
    Ok(())
}

/// Register (spec/sync-ids.md §6): taken only for a sync ID kept unread in the sync set; a
/// genesis step only into an empty path, else only a child of the head; within the caps, a child
/// past them without its claim set, and past them even so at most once per `register_every_ms`.
pub(crate) fn register(t: &mut Transaction<'_>, env: &mut Env<'_>, policy: &Policy, s: &SyncId, step: &Step, claims: Option<&ClaimSet>, last_past_cap: Option<WallMs>) -> Result<(Code, bool)> {
    if env.holding(s) != Some(Holding::Unread) || step.label != *s {
        return Ok((Code::DECLINED, false));
    }
    if claims.is_some_and(|c| c.hash() != step.claims_hash) {
        return Ok((Code::MALFORMED, false));
    }
    let ok = match head(t, s)? {
        None => step.verify_genesis().is_ok(),
        Some((_, h)) => step.verify_child(&h).is_ok(),
    };
    if !ok {
        return Ok((Code::NOT_HEAD_KEY, false));
    }
    let genesis = step.prev.is_none();
    let fits = |t: &mut Transaction<'_>, env: &mut Env<'_>, add: u64| -> Result<bool> { env.room(t, s, 0, add) };
    let (keep_claims, past) = if fits(t, env, step_bytes(step, claims))? {
        (claims, false)
    } else if genesis {
        return Ok((Code::STORAGE_CAP, false));
    } else if fits(t, env, step_bytes(step, None))? {
        (None, false)
    } else if last_past_cap.is_none_or(|at| env.now.0 >= at.0.saturating_add(policy.register_every_ms)) {
        (None, true)
    } else {
        return Ok((Code::STORAGE_CAP, false));
    };
    append(t, env, s, step, keep_claims)?;
    Ok((Code::OK, past))
}

/// A Behind item's answer at a node keeping S unread (spec/sync-ids.md §6 Behind): at most
/// `max_steps` steps in it.
pub(crate) fn behind(t: &mut Transaction<'_>, env: &Env<'_>, s: &SyncId, named: Option<&StepId>, cred: &Cred, max_steps: usize) -> Result<Behind> {
    if env.holding(s) != Some(Holding::Unread) {
        return Ok(refused(if env.holding(s).is_none() { Code::UNKNOWN_SYNC_ID } else { Code::DECLINED }));
    }
    let path = steps(t, s)?;
    let Some(last) = path.len().checked_sub(1) else { return Ok(refused(Code::UNKNOWN_SYNC_ID)) };
    let bound = |v: Vec<Step>| if v.is_empty() { refused(Code::RATE_LIMITED) } else { (Code::OK, Some(Grant { entry_box: None, steps: v })) };
    match (named, cred) {
        (Some(id), _) => {
            let Some(i) = path.iter().take(last).position(|st| st.id() == *id) else { return Ok(refused(Code::DECLINED)) };
            let Some(named_step) = path.get(i) else { return Ok(refused(Code::DECLINED)) };
            let is_cred = match cred {
                Cred::Sync(k) => named_step.keys.sync == *k,
                Cred::Claim(pk) => claims(t, s, i as u32)?.is_some_and(|c| c.contains(pk)),
                Cred::Signing(k) => claims(t, s, i as u32)?.is_some_and(|c| c.contains(&osis_crypto::static_entry(s, k))),
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
                out.push(st.clone());
                if other {
                    break;
                }
            }
            Ok(bound(out))
        }
        (None, Cred::Sync(k)) => match path.iter().take(last).rposition(|st| st.keys.sync == *k) {
            Some(j) => Ok(bound(path.get(j + 1).into_iter().take(max_steps).cloned().collect())),
            None => Ok(refused(Code::DECLINED)),
        },
        (None, Cred::Signing(k)) => {
            let Some(c) = claims(t, s, last as u32)? else { return Ok(refused(Code::DECLINED)) };
            let Some(entry_box) = c.entry_box(s, k).cloned() else { return Ok(refused(Code::DECLINED)) };
            if path.len() > max_steps {
                return Ok(refused(Code::RATE_LIMITED));
            }
            Ok((Code::OK, Some(Grant { entry_box: Some(entry_box), steps: path })))
        }
        (None, Cred::Claim(_)) => Ok(refused(Code::DECLINED)),
    }
}

/// Whether `sig`-style key `k` is the write key of a step on S's path before its head: a stamp
/// under it is under a superseded key (code 9, spec/sync-ids.md §6).
pub(crate) fn earlier_write(t: &mut Transaction<'_>, s: &SyncId, ok: impl Fn(&VerifyingKey) -> bool) -> Result<bool> {
    let n = len(t, s)?;
    for i in (0..n.saturating_sub(1)).rev() {
        if let Some(st) = step(t, s, i)?
            && ok(&st.keys.write)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
