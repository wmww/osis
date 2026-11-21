//! Entries: insert, change and remove one, with every row that goes with it (the blob index, the
//! expiry and tombstone sweeps, usage, charges, the log event) in the caller's transaction, so a
//! crash keeps all of them or none.
//!
//! One set of rules for both parts of the store: `t` is a transaction of the durable store or of
//! the memory store (`Inner::ram`, in memory mode: `t.is_memory()`), which hold the same rows. What
//! differs by part is written here by `t.is_memory()`, and nothing else does: the log (the node
//! log, or the memory log's counter, spec/sync-streams.md §3), where charges add up (a peer's
//! record or a connection's row, or memory: an ephemeral entry's charge goes with its source), a
//! tombstone's lifetime (`TOMBSTONE_LIFETIME`, or `MAX_DRIFT`, spec/sync-ids.md §5), and the total
//! of every sync ID kept unread (the durable caps' alone).

use super::rows::{self, EntryRow, Source, Tombstone, Usage, R, W};
use super::{Env, ENTRY_OVERHEAD, TOMB_OVERHEAD};
use crate::types::{Entry, Result};
use osis_base::format::{MAX_DRIFT_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::{BlobId, SyncId, WallMs};
use osis_engine::sync::Holding;
use osis_store::{Shred, Transaction};

/// The record row of the bytes charged to a peer (spec/sync-ids.md §5 Peer budget): record-wide,
/// charges are per peer, not per sync ID.
use super::rows::tag::CHARGES;

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
    // the durable caps' total (`Env::total`); the memory total is summed where read
    if t.is_memory() || env.holding(s) != Some(Holding::Unread) {
        return Ok(());
    }
    if old.fixed() != new.fixed() {
        env.mem.stamps.wrote(&super::UNREAD_FIXED, true);
    }
    if let Some(total) = env.total.as_mut() {
        total.add(&old, false);
        total.add(&new, true);
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

/// What a row of `key` and `value` bytes holds in the memory part: its bytes, the store's kind
/// byte and `MEM_ROW_COST`.
fn mem_row(key: usize, value: usize) -> u64 {
    (1 + key + value) as u64 + osis_store::MEM_ROW_COST
}

/// What entry row `r` holds beside its blob's bytes, in the memory part (`memory`) or durably:
/// in memory exactly what it holds there (`Store::memory_held`): its rows (`insert`'s, and a
/// held-elsewhere row whether or not it is written), its blob's place, its memory log event;
/// durably `ENTRY_OVERHEAD`.
pub(crate) fn overhead(memory: bool, r: &EntryRow) -> u64 {
    if !memory {
        return ENTRY_OVERHEAD;
    }
    let id = |key: usize| mem_row(key, 0);
    let source = |x: Option<Source>| x.map_or(0, |x| mem_row(2 + rows::source_bytes(x).len() + 48, 8));
    let optional = r.expires.map_or(0, |_| id(58)) + if r.deposited { id(50) } else { 0 } + source(r.charged) + source(r.brought);
    mem_row(50, r.encode().len()) + 2 * id(50) + osis_store::MEM_ROW_COST + optional + super::memory::EVENT
}

/// What tombstone `tomb` holds, in the memory part (`memory`, as `overhead`: its rows and its
/// removal event) or durably (`TOMB_OVERHEAD`).
fn tomb_overhead(memory: bool, tomb: &Tombstone) -> u64 {
    if !memory {
        return TOMB_OVERHEAD;
    }
    mem_row(50, tomb.encode().len()) + mem_row(58, 0) + mem_row(50, 0) + super::memory::REMOVAL
}

/// What entry row `r` of blob `b` adds to its sync ID's usage in the memory part (`memory`) or
/// durably: role entries count toward no cap; a deposit waiting for a stamp counts toward the
/// deposit budget too. Its blob counts at what it costs held where that is more than its bytes
/// (`Memory::estimate`, an ephemeral commit's), beside its `overhead`.
pub(crate) fn count(memory: bool, env: &Env<'_>, b: &BlobId, r: &EntryRow, sign: bool) -> impl Fn(&mut Usage) + use<> {
    let held = env.mem.estimate.get(b).copied().unwrap_or(0).max(r.size) + overhead(memory, r);
    let (role, deposited, size) = (r.role, r.deposited, r.size);
    move |u: &mut Usage| {
        let op = |x: &mut u64, n: u64| *x = if sign { x.saturating_add(n) } else { x.saturating_sub(n) };
        if !role {
            op(&mut u.entries, 1);
            op(&mut u.bytes, held);
            op(&mut u.entry_bytes, held);
        }
        if deposited {
            op(&mut u.deposits, 1);
            op(&mut u.deposit_bytes, size);
        }
    }
}

/// Entry `b` of S goes from row `old` to `new`: its charges and S's usage move.
fn recount(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, old: &EntryRow, new: &EntryRow) -> Result<()> {
    charge(t, env, old, s, b, false)?;
    charge(t, env, new, s, b, true)?;
    let (out, into) = (count(t.is_memory(), env, b, old, false), count(t.is_memory(), env, b, new, true));
    add_usage(t, env, s, |u| {
        out(u);
        into(u);
    })
}

/// How an entry's log event moves (`log`).
enum Ev {
    Added,
    Deleted,
    /// No event: an expiry serves none, nor does an entry that was never servable.
    Gone,
}

/// Logs `ev` of entry `b` of S in `t`'s part: the node log, or the memory log.
fn log(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, ev: Ev) -> Result<()> {
    match (t.is_memory(), ev) {
        (true, Ev::Added) => env.mem.event(s, b, None),
        (true, Ev::Deleted) => env.mem.event(s, b, Some(env.now)),
        (true, Ev::Gone) => env.mem.unlog(s, b),
        (false, Ev::Added) => drop(t.log_added(*s, *b)?),
        (false, Ev::Deleted) => drop(t.log_deleted(*s, *b, env.now.0)?),
        (false, Ev::Gone) => drop(t.log_remove(s, b)?),
    }
    Ok(())
}

/// When a tombstone made at `at` in `t`'s part ends.
fn tomb_ends(t: &Transaction<'_>, at: WallMs) -> WallMs {
    WallMs(at.0.saturating_add(if t.is_memory() { MAX_DRIFT_MS } else { TOMBSTONE_LIFETIME_MS }))
}

/// The sync IDs whose entries in `t`'s part name blob `b`.
pub(crate) fn naming(t: &mut Transaction<'_>, b: &BlobId) -> Result<Vec<SyncId>> {
    let named = t.scan_local(&[rows::BY_BLOB, &b.0].concat(), b"", usize::MAX)?;
    Ok(named.into_iter().map(|(k, _)| SyncId(k.get(k.len().saturating_sub(16)..).and_then(|x| x.try_into().ok()).unwrap_or_default())).collect())
}

/// Sets what blob `b` costs held past its bytes (`Memory::estimate`) for every entry naming it;
/// nothing where none does.
pub(crate) fn set_estimate(t: &mut Transaction<'_>, env: &mut Env<'_>, b: &BlobId, n: u64) -> Result<()> {
    let mut held = Vec::new();
    for s in naming(t, b)? {
        held.extend(get(t, &s, b)?.map(|r| (s, r)));
    }
    if held.is_empty() {
        return Ok(());
    }
    for (s, r) in &held {
        add_usage(t, env, s, count(t.is_memory(), env, b, r, false))?;
    }
    env.mem.estimate.insert(*b, n);
    for (s, r) in &held {
        add_usage(t, env, s, count(t.is_memory(), env, b, r, true))?;
    }
    Ok(())
}

/// Bytes charged to record `rec` so far.
pub(crate) fn record_charge(t: &mut Transaction<'_>, rec: &osis_store::RecordId) -> Result<u64> {
    t.record_get_wide_row(rec, CHARGES, b"")?.map_or(Ok(0), |v| R::new(&v).u64())
}

/// Bytes charged to connection `c` so far.
pub(crate) fn conn_charge(t: &mut Transaction<'_>, c: crate::types::ConnId) -> Result<u64> {
    t.get_local(&rows::conn_total_key(c))?.map_or(Ok(0), |v| R::new(&v).u64())
}

fn charge(t: &mut Transaction<'_>, env: &mut Env<'_>, r: &EntryRow, s: &SyncId, b: &BlobId, sign: bool) -> Result<()> {
    // who brought an uncharged one, found again when that peer goes (`Store::gone`)
    if let Some(src) = r.brought {
        let k = rows::brought_key(src, s, b);
        if sign {
            t.put_local(&k, &[], Shred::No)?;
        } else {
            t.remove_local(&k, Shred::No)?;
        }
    }
    let Some(src) = r.charged else { return Ok(()) };
    let k = rows::charged_key(src, s, b);
    if sign {
        t.put_local(&k, &r.size.to_be_bytes(), Shred::No)?;
    } else {
        t.remove_local(&k, Shred::No)?;
    }
    let n = |now: u64| if sign { now.saturating_add(r.size) } else { now.saturating_sub(r.size) };
    match (t.is_memory(), src) {
        (true, _) => {
            let c = env.mem.charges.entry(src).or_default();
            *c = n(*c);
            if *c == 0 {
                env.mem.charges.remove(&src);
            }
        }
        (false, Source::Record(rec)) => {
            let n = n(record_charge(t, &rec)?);
            if n == 0 {
                t.record_remove_wide_row(&rec, CHARGES, b"")?;
            } else {
                t.record_put_wide_row(&rec, CHARGES, b"", W::default().u64(n).take())?;
            }
        }
        (false, Source::Conn(c)) => {
            let n = n(conn_charge(t, c)?);
            if n == 0 {
                t.remove_local(&rows::conn_total_key(c), Shred::No)?;
            } else {
                t.put_local(&rows::conn_total_key(c), &n.to_be_bytes(), Shred::No)?;
            }
        }
    }
    Ok(())
}

/// Stores a new entry `row` of S (no entry of `b` there yet), with `bytes` when they come with it.
pub(crate) fn insert(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, mut row: EntryRow, bytes: Option<Vec<u8>>) -> Result<()> {
    let fresh = match bytes {
        Some(bytes) if t.blob_len(b)?.is_none() => {
            t.put_blob(b, bytes)?;
            true
        }
        _ => false,
    };
    row.size = t.blob_len(b)?.unwrap_or(0);
    t.put_local(&rows::entry_key(s, b), &row.encode(), Shred::Yes)?;
    t.put_local(&rows::by_blob_key(b, s), &[], Shred::No)?;
    if let Some(at) = row.expires {
        t.put_local(&rows::expiry_key(at, s, b), &[], Shred::No)?;
    }
    if row.deposited {
        t.put_local(&rows::deposited_key(s, b), &[], Shred::No)?;
    }
    env.mem.fed.wrote_added(&(*s, *b), true, true);
    charge(t, env, &row, s, b, true)?;
    add_usage(t, env, s, count(t.is_memory(), env, b, &row, true))?;
    if row.size > 0 {
        log(t, env, s, b, Ev::Added)?;
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
    recount(t, env, s, b, old, &new)?;
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
        log(t, env, s, b, Ev::Added)?;
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
        t.remove_local(&rows::elsewhere_key(s, b), Shred::No)?;
        // a source's refusal stands only for an entry held here (spec/sync-streams.md §4
        // Refused): it goes with the entry, however it left (an expiry serves no event)
        for rec in t.records_with_row(s, rows::tag::REFUSED, &b.0, usize::MAX)? {
            t.record_remove_row(&rec, rows::tag::REFUSED, s, &b.0)?;
        }
        env.mem.fed.wrote_added(&(*s, *b), true, true);
        charge(t, env, row, s, b, false)?;
        add_usage(t, env, s, count(t.is_memory(), env, b, row, false))?;
        let ev = match how {
            Removal::Tomb(_) | Removal::Untombed if row.size > 0 => Ev::Deleted,
            _ => Ev::Gone,
        };
        log(t, env, s, b, ev)?;
        unref(t, env, b)?;
    }
    if let Removal::Tomb(tomb) = how {
        put_tomb(t, env, s, b, tomb)?;
    }
    Ok(held.is_some())
}

pub(crate) fn put_tomb(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId, tomb: Tombstone) -> Result<()> {
    lift(t, env, s, b)?;
    t.put_local(&rows::tomb_at_key(tomb_ends(t, tomb.at), s, b), &[], Shred::No)?;
    t.put_local(&rows::tomb_key(s, b), &tomb.encode(), Shred::No)?;
    t.put_local(&[rows::TOMB_BY_BLOB, &b.0, &s.0].concat(), &[], Shred::No)?;
    let n = tomb_overhead(t.is_memory(), &tomb);
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_add(n))
}

/// Removes S's tombstone of `b`, if any; whether there was one.
pub(crate) fn lift(t: &mut Transaction<'_>, env: &mut Env<'_>, s: &SyncId, b: &BlobId) -> Result<bool> {
    let Some(old) = tombstone(t, s, b)? else { return Ok(false) };
    t.remove_local(&rows::tomb_key(s, b), Shred::No)?;
    t.remove_local(&rows::tomb_at_key(tomb_ends(t, old.at), s, b), Shred::No)?;
    t.remove_local(&[rows::TOMB_BY_BLOB, &b.0, &s.0].concat(), Shred::No)?;
    let n = tomb_overhead(t.is_memory(), &old);
    add_usage(t, env, s, |u| u.bytes = u.bytes.saturating_sub(n))?;
    Ok(true)
}

/// Deletes blob `b`'s bytes once no entry of any sync ID names it and the engine holds it no more
/// (spec/sync-ids.md §5: bytes once per node).
pub(crate) fn unref(t: &mut Transaction<'_>, env: &mut Env<'_>, b: &BlobId) -> Result<()> {
    let named = !t.scan_local(&[rows::BY_BLOB, &b.0].concat(), b"", 1)?.is_empty();
    if !named {
        env.mem.unnamed.wrote_added(b, true, true);
        if t.is_memory() {
            env.mem.estimate.remove(b);
        }
    }
    if named || t.get_local(&rows::engine_key(b))?.is_some() {
        return Ok(());
    }
    t.delete_blob(b);
    Ok(())
}

/// Bytes of `b` arrived (the engine held them, an entry came with them): every entry naming `b`
/// whose bytes were missing becomes servable, under every sync ID (spec/sync-ids.md §5: a blob
/// fetched under one sync ID is taken under every other naming it).
pub(crate) fn bytes_arrived(t: &mut Transaction<'_>, env: &mut Env<'_>, b: &BlobId) -> Result<()> {
    let Some(size) = t.blob_len(b)? else { return Ok(()) };
    for s in naming(t, b)? {
        if let Some(old) = get(t, &s, b)?
            && old.size == 0
        {
            let new = EntryRow { size, ..old.clone() };
            recount(t, env, &s, b, &old, &new)?;
            t.put_local(&rows::entry_key(&s, b), &new.encode(), Shred::Yes)?;
            log(t, env, &s, b, Ev::Added)?;
        }
    }
    Ok(())
}
