//! The rows a source keeps of a sync ID (what its stream showed, its stands, the deletes seen
//! there), one mechanism in either part, each row under its owner's tag (`rows::tag`). In the
//! durable part a record source's are its record's rows (`record_put_row`: gone with the record
//! and with S, indexed by osis-store); a connection keeps none there. In the memory part any
//! source's are `C/ src s tag key`, indexed by `K/ s tag len key src`: gone with the source
//! (`forget_source`), with S (`forget_sync`), and at a restart. A connection's rows are all in
//! memory; a record's memory rows are what holds only while its entry is in memory (a refusal of
//! an ephemeral entry). Every read and write stamps per row, a scan per prefix.

use super::rows::tag::{SEEN, STAND};
use super::rows::{self, R, Source};
use osis_base::{SyncId, WallMs};
use osis_store::{Error, KeyValue, Shred, Transaction};

const ROW: &[u8] = b"C/";
const INDEX: &[u8] = b"K/";

/// The part a source's own rows live in (`true`: memory): a record's durably, a connection's in
/// memory.
pub(crate) fn home(src: Source) -> bool {
    matches!(src, Source::Conn(_))
}

/// The parts `src` may keep rows in, memory first.
pub(crate) fn parts(src: Source) -> &'static [bool] {
    match src {
        Source::Record(_) => &[true, false],
        Source::Conn(_) => &[true],
    }
}

fn row_key(src: Source, s: &SyncId, tag: u8, key: &[u8]) -> Vec<u8> {
    [ROW, &rows::source_bytes(src), &s.0, &[tag], key].concat()
}

fn index_prefix(s: &SyncId, tag: u8, key: &[u8]) -> Vec<u8> {
    [INDEX, &s.0, &[tag], &(key.len() as u32).to_be_bytes(), key].concat()
}

/// The durable part's record for `src` in `t` (none in the memory part, or for a connection).
fn record(t: &Transaction<'_>, src: Source) -> Option<osis_store::RecordId> {
    match src {
        Source::Record(rec) if !t.is_memory() => Some(rec),
        _ => None,
    }
}

pub(crate) fn get(t: &mut Transaction<'_>, src: Source, tag: u8, s: &SyncId, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    match record(t, src) {
        Some(rec) => t.record_get_row(&rec, tag, s, key),
        None if t.is_memory() => t.get_local(&row_key(src, s, tag, key)),
        None => Ok(None),
    }
}

/// Writes `src`'s row; a connection's in the durable part writes nothing (it keeps none there).
pub(crate) fn put(t: &mut Transaction<'_>, src: Source, tag: u8, s: &SyncId, key: &[u8], v: Vec<u8>) -> Result<(), Error> {
    match record(t, src) {
        Some(rec) => t.record_put_row(&rec, tag, s, key, v),
        None if t.is_memory() => {
            t.put_local(&row_key(src, s, tag, key), &v, Shred::No)?;
            t.put_local(&[&index_prefix(s, tag, key)[..], &rows::source_bytes(src)].concat(), &[], Shred::No)
        }
        None => {
            debug_assert!(false, "a connection's row written durably");
            Ok(())
        }
    }
}

/// Removes `src`'s row; whether it was there.
pub(crate) fn remove(t: &mut Transaction<'_>, src: Source, tag: u8, s: &SyncId, key: &[u8]) -> Result<bool, Error> {
    match record(t, src) {
        Some(rec) => t.record_remove_row(&rec, tag, s, key),
        None if t.is_memory() => {
            if !t.remove_local(&row_key(src, s, tag, key), Shred::No)? {
                return Ok(false);
            }
            t.remove_local(&[&index_prefix(s, tag, key)[..], &rows::source_bytes(src)].concat(), Shred::No)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// `src`'s rows under `tag` of S, by key (keys alone), at most `limit`. Costs what it returns.
pub(crate) fn rows(t: &mut Transaction<'_>, src: Source, tag: u8, s: &SyncId, limit: usize) -> Result<Vec<KeyValue>, Error> {
    match record(t, src) {
        Some(rec) => t.record_rows(&rec, tag, s, b"", limit),
        None if t.is_memory() => {
            let p = row_key(src, s, tag, b"");
            Ok(t.scan_local(&p, b"", limit)?.into_iter().map(|(k, v)| (k.get(p.len()..).unwrap_or_default().to_vec(), v)).collect())
        }
        None => Ok(Vec::new()),
    }
}

/// The sources keeping row `key` under `tag` of S in `t`'s part, at most `limit`. Costs what it
/// returns.
pub(crate) fn with_row(t: &mut Transaction<'_>, s: &SyncId, tag: u8, key: &[u8], limit: usize) -> Result<Vec<Source>, Error> {
    if !t.is_memory() {
        return Ok(t.records_with_row(s, tag, key, limit)?.into_iter().map(Source::Record).collect());
    }
    let p = index_prefix(s, tag, key);
    t.scan_local(&p, b"", limit)?.into_iter().map(|(k, _)| R::new(k.get(p.len()..).unwrap_or_default()).source().ok().flatten().ok_or(Error::Corrupt("sync source row index"))).collect()
}

/// Whether some source keeps row `key` under `tag` of S in `t`'s part.
pub(crate) fn any_row(t: &mut Transaction<'_>, s: &SyncId, tag: u8, key: &[u8]) -> Result<bool, Error> {
    if !t.is_memory() {
        return t.records_any_row(s, tag, key);
    }
    Ok(!t.scan_local(&index_prefix(s, tag, key), b"", 1)?.is_empty())
}

/// Every source's rows under `tag` in `t`'s part: source, S and key. O(the part's source rows).
pub(crate) fn tag_rows(t: &mut Transaction<'_>, tag: u8) -> Result<Vec<(Source, SyncId, Vec<u8>)>, Error> {
    let mut out = Vec::new();
    if !t.is_memory() {
        for r in t.records_all()? {
            out.extend(t.record_tag_rows(&r.id, tag)?.into_iter().map(|(s, k, _)| (Source::Record(r.id), s, k)));
        }
        return Ok(out);
    }
    for (k, _) in t.scan_local(ROW, b"", usize::MAX)? {
        let (src, s, x, key) = parse(&k)?;
        if x == tag {
            out.push((src, s, key.to_vec()));
        }
    }
    Ok(out)
}

/// A memory row's key parts after `C/`: source, S, tag and key.
fn parse(k: &[u8]) -> Result<(Source, SyncId, u8, &[u8]), Error> {
    let bad = || Error::Corrupt("sync source row");
    let mut r = R::new(k.get(ROW.len()..).unwrap_or_default());
    let src = r.source().ok().flatten().ok_or_else(bad)?;
    let s = SyncId(r.array().map_err(|_| bad())?);
    let tag = r.u8().map_err(|_| bad())?;
    Ok((src, s, tag, r.rest()))
}

/// Whether rows under `tag` age out after `TOMBSTONE_LIFETIME` (`put_aging`): stands and deletes
/// seen.
fn ages(tag: u8) -> bool {
    tag == STAND || tag == SEEN
}

/// Writes `src`'s row under an aging tag, written at `at` (its value starts with it), with its
/// aging row (`w/`, swept by `Store::settle_at`).
pub(crate) fn put_aging(t: &mut Transaction<'_>, src: Source, tag: u8, s: &SyncId, key: &[u8], at: WallMs, v: Vec<u8>) -> Result<(), Error> {
    debug_assert!(ages(tag) && v.get(..8) == Some(&at.0.to_be_bytes()[..]));
    put(t, src, tag, s, key, v)?;
    t.put_local(&rows::aging_key(at, s, tag, key, src), &[], Shred::No)
}

/// Removes `src`'s row and, under an aging tag, its aging row.
pub(crate) fn drop_row(t: &mut Transaction<'_>, src: Source, tag: u8, s: &SyncId, key: &[u8]) -> Result<(), Error> {
    if ages(tag)
        && let Some(at) = get(t, src, tag, s, key)?.and_then(|v| Some(u64::from_be_bytes(v.get(..8)?.try_into().ok()?)))
    {
        t.remove_local(&rows::aging_key(WallMs(at), s, tag, key, src), Shred::No)?;
    }
    remove(t, src, tag, s, key).map(|_| ())
}

/// Every memory row of `src` goes (the source went). O(its rows).
pub(crate) fn forget_source(t: &mut Transaction<'_>, src: Source) -> Result<(), Error> {
    for (k, _) in t.scan_local(&[ROW, &rows::source_bytes(src)[..]].concat(), b"", usize::MAX)? {
        let (src, s, tag, key) = parse(&k)?;
        drop_row(t, src, tag, &s, key)?;
    }
    Ok(())
}

/// Every source's memory rows of S go (S shredded). O(those rows).
pub(crate) fn forget_sync(t: &mut Transaction<'_>, s: &SyncId) -> Result<(), Error> {
    let p = [INDEX, &s.0[..]].concat();
    for (k, _) in t.scan_local(&p, b"", usize::MAX)? {
        let bad = || Error::Corrupt("sync source row index");
        let mut r = R::new(k.get(p.len()..).unwrap_or_default());
        let tag = r.u8().map_err(|_| bad())?;
        let key = r.bytes().map_err(|_| bad())?.to_vec();
        let src = r.source().ok().flatten().ok_or_else(bad)?;
        drop_row(t, src, tag, s, &key)?;
    }
    Ok(())
}
