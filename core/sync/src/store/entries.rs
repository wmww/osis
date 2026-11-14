//! Durable entries: insert, change and remove one, with every row that goes with it (the blob
//! index, the expiry and tombstone sweeps, usage, charges, the node log event) in the caller's
//! transaction, so a crash keeps all of them or none.

use super::rows::{self, EntryRow, Source, Tombstone, Usage, R, W};
use super::{Env, ENTRY_OVERHEAD, TOMB_OVERHEAD};
use crate::types::{Entry, Result};
use osis_base::{BlobId, SyncId};
use osis_engine::sync::Holding;
use osis_store::{Shred, Transaction};

/// The record row tag of the bytes charged to a peer (spec/sync-ids.md §5 Peer budget).
pub(crate) const CHARGES: u8 = b'b';
/// The sync ID the charge row is filed under: charges are per peer, not per sync ID.
pub(crate) const NO_SYNC_ID: SyncId = SyncId([0; 16]);

/// How an entry leaves.
#[derive(Clone, Debug)]
pub(crate) enum Removal {
    /// A tombstone keeps the identical blob out (a verified Delete, the node's own drop).
    Tomb(Tombstone),
    /// Its expiry: every holder removes it alone, so no event and no tombstone.
    Expired,
    /// The caps gave way, or what its connection brought went with it: a deletion event, no
    /// tombstone (fetched again where present).
    Untombed,
}

pub(crate) fn get(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId) -> Result<Option<EntryRow>> {
    t.get_local(&rows::entry_key(s, b))?.map(|v| EntryRow::decode(&v)).transpose()
}

pub(crate) fn to_entry(b: BlobId, r: &EntryRow) -> Entry {
    Entry { blob: b, wrap: r.wrap, stamp: r.stamp, deposited: r.deposited, own: r.own, role: r.role, class: r.class, expires: r.expires }
}

pub(crate) fn tombstone(t: &mut Transaction<'_>, s: &SyncId, b: &BlobId) -> Result<Option<Tombstone>> {
    t.get_local(&rows::tomb_key(s, b))?.map(|v| Tombstone::decode(&v)).transpose()
}

pub(crate) fn usage(t: &mut Transaction<'_>, s: &SyncId) -> Result<Usage> {
    t.get_local(&rows::usage_key(s))?.map_or(Ok(Usage::default()), |v| Usage::decode(&v))
}

/// Writes S's usage, its by-use index row and the unread total with it.
pub(crate) fn put_usage(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, old: Usage, new: Usage) -> Result<()> {
    if old == new {
        return Ok(());
    }
    if old != Usage::default() {
        t.remove_local(&rows::by_use_key(old.bytes, s), Shred::No)?;
    }
    if new == Usage::default() {
        t.remove_local(&rows::usage_key(s), Shred::No)?;
    } else {
        t.put_local(&rows::usage_key(s), &new.encode(), Shred::No)?;
        t.put_local(&rows::by_use_key(new.bytes, s), &[], Shred::No)?;
    }
    if env.holding(s) == Some(Holding::Unread)
        && let Some(total) = env.total.as_mut()
    {
        *total = total.saturating_sub(old.bytes).saturating_add(new.bytes);
    }
    Ok(())
}

/// Changes S's usage by `f`.
pub(crate) fn add_usage(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, f: impl FnOnce(&mut Usage)) -> Result<()> {
    let old = usage(t, s)?;
    let mut new = old;
    f(&mut new);
    put_usage(t, env, s, old, new)
}

/// What an entry row adds to its sync ID's usage: role entries count toward no cap; a deposit
/// waiting for a stamp counts toward the deposit budget too.
fn count(u: &mut Usage, r: &EntryRow, sign: bool) {
    let op = |x: &mut u64, n: u64| *x = if sign { x.saturating_add(n) } else { x.saturating_sub(n) };
    if !r.role {
        op(&mut u.entries, 1);
        op(&mut u.bytes, r.size + ENTRY_OVERHEAD);
    }
    if r.deposited {
        op(&mut u.deposits, 1);
        op(&mut u.deposit_bytes, r.size);
    }
}

/// Bytes charged to record `rec` so far.
pub(crate) fn record_charge(t: &mut Transaction<'_>, rec: &osis_store::RecordId) -> Result<u64> {
    t.record_get_row(rec, CHARGES, &NO_SYNC_ID, b"")?.map_or(Ok(0), |v| R::new(&v).u64())
}

/// Bytes charged to connection `c` so far.
pub(crate) fn conn_charge(t: &mut Transaction<'_>, c: crate::types::ConnId) -> Result<u64> {
    t.get_local(&rows::conn_total_key(c))?.map_or(Ok(0), |v| R::new(&v).u64())
}

fn charge(t: &mut Transaction<'_>, r: &EntryRow, s: &SyncId, b: &BlobId, sign: bool) -> Result<()> {
    let Some(src) = r.charged else { return Ok(()) };
    let k = rows::charged_key(src, s, b);
    if sign {
        t.put_local(&k, &r.size.to_be_bytes(), Shred::No)?;
    } else {
        t.remove_local(&k, Shred::No)?;
    }
    match src {
        Source::Record(rec) => {
            let now = record_charge(t, &rec)?;
            let n = if sign { now.saturating_add(r.size) } else { now.saturating_sub(r.size) };
            if n == 0 {
                t.record_remove_row(&rec, CHARGES, &NO_SYNC_ID, b"")?;
            } else {
                t.record_put_row(&rec, CHARGES, &NO_SYNC_ID, b"", W::default().u64(n).take())?;
            }
        }
        Source::Conn(c) => {
            let now = conn_charge(t, c)?;
            let n = if sign { now.saturating_add(r.size) } else { now.saturating_sub(r.size) };
            if n == 0 {
                t.remove_local(&rows::conn_total_key(c), Shred::No)?;
            } else {
                t.put_local(&rows::conn_total_key(c), &n.to_be_bytes(), Shred::No)?;
            }
        }
    }
    Ok(())
}

/// Whether blob `b`'s bytes are held, on disk or in memory.
pub(crate) fn bytes_len(t: &mut Transaction<'_>, env: &Env<'_>, b: &BlobId) -> Result<Option<u64>> {
    if let Some(v) = env.mem.blobs.get(b) {
        return Ok(Some(v.len() as u64));
    }
    Ok(t.blob_len(b)?)
}

/// Stores a new entry `row` of S (no entry of `b` there yet), with `bytes` when they come with it.
pub(crate) fn insert(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, mut row: EntryRow, bytes: Option<Vec<u8>>) -> Result<()> {
    let fresh = match bytes {
        Some(bytes) if bytes_len(t, env, b)?.is_none() => {
            t.put_blob(b, bytes)?;
            true
        }
        _ => false,
    };
    row.size = bytes_len(t, env, b)?.unwrap_or(0);
    t.put_local(&rows::entry_key(s, b), &row.encode(), Shred::Yes)?;
    t.put_local(&rows::by_blob_key(b, s), &[], Shred::No)?;
    if let Some(at) = row.expires {
        t.put_local(&rows::expiry_key(at, s, b), &[], Shred::No)?;
    }
    if row.deposited {
        t.put_local(&rows::deposited_key(s, b), &[], Shred::No)?;
    }
    env.mem.fed.wrote_added(&(*s, *b), true, true);
    charge(t, &row, s, b, true)?;
    add_usage(t, env, s, |u| count(u, &row, true))?;
    if row.size > 0 {
        t.log_added(*s, *b)?;
    }
    if fresh {
        bytes_arrived(t, env, b)?;
    }
    Ok(())
}

/// Replaces entry `b`'s row (its wrap, stamp, flags, charge); logs `Added` when what a reader
/// sees of it changed.
pub(crate) fn change(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, old: &EntryRow, new: EntryRow) -> Result<()> {
    if *old == new {
        return Ok(());
    }
    charge(t, old, s, b, false)?;
    charge(t, &new, s, b, true)?;
    add_usage(t, env, s, |u| {
        count(u, old, false);
        count(u, &new, true);
    })?;
    t.put_local(&rows::entry_key(s, b), &new.encode(), Shred::Yes)?;
    match (old.deposited, new.deposited) {
        (false, true) => t.put_local(&rows::deposited_key(s, b), &[], Shred::No)?,
        (true, false) => drop(t.remove_local(&rows::deposited_key(s, b), Shred::No)?),
        _ => {}
    }
    let seen = (old.wrap, old.stamp, old.deposited) != (new.wrap, new.stamp, new.deposited);
    if seen {
        env.mem.fed.wrote_added(&(*s, *b), true, true);
    }
    if seen && new.size > 0 {
        t.log_added(*s, *b)?;
    }
    Ok(())
}

/// Removes entry `b` of S if held (`how` it leaves), and its bytes once nothing references them.
/// With a tombstone, the tombstone is made whether or not the entry was held. Whether it was.
pub(crate) fn remove(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, how: Removal) -> Result<bool> {
    let held = get(t, s, b)?;
    if let Some(row) = &held {
        t.remove_local(&rows::entry_key(s, b), Shred::Yes)?;
        t.remove_local(&rows::by_blob_key(b, s), Shred::No)?;
        if let Some(at) = row.expires {
            t.remove_local(&rows::expiry_key(at, s, b), Shred::No)?;
        }
        if row.deposited {
            t.remove_local(&rows::deposited_key(s, b), Shred::No)?;
        }
        charge(t, row, s, b, false)?;
        add_usage(t, env, s, |u| count(u, row, false))?;
        match how {
            Removal::Expired => drop(t.log_remove(s, b)?),
            Removal::Tomb(_) | Removal::Untombed => {
                if row.size > 0 {
                    t.log_deleted(*s, *b, env.now.0)?;
                } else {
                    t.log_remove(s, b)?;
                }
            }
        }
        unref(t, env, b)?;
    }
    if let Removal::Tomb(tomb) = how {
        put_tomb(t, env, s, b, tomb)?;
    }
    Ok(held.is_some())
}

pub(crate) fn put_tomb(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, tomb: Tombstone) -> Result<()> {
    lift(t, env, s, b)?;
    t.put_local(&rows::tomb_at_key(tomb.at, s, b), &[], Shred::No)?;
    t.put_local(&rows::tomb_key(s, b), &tomb.encode(), Shred::No)?;
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_add(TOMB_OVERHEAD))
}

/// Removes S's tombstone of `b`, if any; whether there was one.
pub(crate) fn lift(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId) -> Result<bool> {
    let Some(old) = tombstone(t, s, b)? else { return Ok(false) };
    t.remove_local(&rows::tomb_key(s, b), Shred::No)?;
    t.remove_local(&rows::tomb_at_key(old.at, s, b), Shred::No)?;
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_sub(TOMB_OVERHEAD))?;
    Ok(true)
}

/// Deletes blob `b`'s durable bytes once no entry of any sync ID names it and the engine holds it
/// no more (spec/sync-ids.md §5: bytes once per node).
pub(crate) fn unref(t: &mut Transaction<'_>, env: &Env<'_>, b: &BlobId) -> Result<()> {
    let named = !t.scan_local(&[rows::BY_BLOB, &b.0].concat(), b"", 1)?.is_empty();
    if named || t.get_local(&rows::engine_key(b))?.is_some() || env.mem.engine.contains(b) {
        return Ok(());
    }
    t.delete_blob(b);
    Ok(())
}

/// Bytes of `b` arrived (the engine held them, an entry came with them): every entry naming `b`
/// whose bytes were missing becomes servable, under every sync ID (spec/sync-ids.md §5: a blob
/// fetched under one sync ID is taken under every other naming it).
pub(crate) fn bytes_arrived(t: &mut Transaction<'_>, env: &mut Env<'_>, b: &BlobId) -> Result<()> {
    let Some(size) = bytes_len(t, env, b)? else { return Ok(()) };
    let named = t.scan_local(&[rows::BY_BLOB, &b.0].concat(), b"", usize::MAX)?;
    for (k, _) in named {
        let s = SyncId(k.get(k.len().saturating_sub(16)..).and_then(|x| x.try_into().ok()).unwrap_or_default());
        if let Some(old) = get(t, &s, b)?
            && old.size == 0
        {
            let new = EntryRow { size, ..old.clone() };
            charge(t, &old, &s, b, false)?;
            charge(t, &new, &s, b, true)?;
            add_usage(t, env, &s, |u| {
                count(u, &old, false);
                count(u, &new, true);
            })?;
            t.put_local(&rows::entry_key(&s, b), &new.encode(), Shred::Yes)?;
            t.log_added(s, *b)?;
        }
    }
    Ok(())
}
