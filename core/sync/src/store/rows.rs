//! The store's rows: their keys and their bytes. Every row is a local record of the node's one
//! ciphertext store (`osis_store::Transaction::put_local`), keyed by a two-byte tag so each kind is
//! its own stamp family; a memo reading one row moves only when that row (or a scan's prefix)
//! is written.
//!
//! - `E/ s b` an entry (`EntryRow`).
//! - `X/ b s` the sync IDs whose entries name blob `b`: its bytes go once none does and the
//!   engine holds it no more.
//! - `G/ b` the engine holds blob `b` durably (`osis_store::CipherHost::hold`).
//! - `W/ src s b` an entry charged to a source (`source_bytes`): a connection's go when it closes
//!   or at a start, a record's when the record is dropped; `V/ conn` the bytes charged to a
//!   connection in all (a record's total is in the record).
//! - `T/ s b` a tombstone (`Tomb`); `t/ at s b` tombstones by when they were made, for the sweep.
//! - `x/ T s b` entries by prefix expiry, for the sweep.
//! - `P/ s i` step `i` of S's path from genesis (`StepRow`); `Q/ s i` its claim set while held;
//!   `q/ at s i` claim sets by when they may go.
//! - `H/ s` the length of S's path.
//! - `U/ s` S's usage (`Usage`); `u/ !bytes s` sync IDs by bytes used, most first, for "the one using most".
//! - `w/ at s tag key rec` rows a source's record holds of S that age out (stands, deletes seen).

use crate::types::{Error, Result};
use osis_base::{BlobId, SyncId, WallMs};
use osis_crypto::{Signature, WRAP_LEN};
use osis_label::Class;
use osis_store::RecordId;

pub(crate) const ENTRY: &[u8] = b"E/";
pub(crate) const BY_BLOB: &[u8] = b"X/";
pub(crate) const ENGINE: &[u8] = b"G/";
pub(crate) const CHARGED: &[u8] = b"W/";
pub(crate) const CONN_TOTAL: &[u8] = b"V/";
pub(crate) const TOMB: &[u8] = b"T/";
pub(crate) const TOMB_AT: &[u8] = b"t/";
pub(crate) const EXPIRY: &[u8] = b"x/";
pub(crate) const STEP: &[u8] = b"P/";
pub(crate) const CLAIMS: &[u8] = b"Q/";
pub(crate) const CLAIMS_DUE: &[u8] = b"q/";
pub(crate) const USAGE: &[u8] = b"U/";
pub(crate) const BY_USE: &[u8] = b"u/";
pub(crate) const AGING: &[u8] = b"w/";
pub(crate) const HEAD: &[u8] = b"H/";
/// Deposited (unstamped) entries per sync ID: what promotion, clearing and offering read.
pub(crate) const DEPOSITED: &[u8] = b"D/";

pub(crate) fn head_key(s: &SyncId) -> Vec<u8> {
    [HEAD, &s.0].concat()
}

pub(crate) fn entry_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [ENTRY, &s.0, &b.0].concat()
}
pub(crate) fn deposited_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [DEPOSITED, &s.0, &b.0].concat()
}
pub(crate) fn by_blob_key(b: &BlobId, s: &SyncId) -> Vec<u8> {
    [BY_BLOB, &b.0, &s.0].concat()
}
pub(crate) fn engine_key(b: &BlobId) -> Vec<u8> {
    [ENGINE, &b.0].concat()
}
/// A source as a key part: 0 and a connection, or 1 and a record.
pub(crate) fn source_bytes(src: Source) -> Vec<u8> {
    match src {
        Source::Conn(c) => [&[0u8][..], &c.0.to_be_bytes()].concat(),
        Source::Record(r) => [&[1u8][..], &r].concat(),
    }
}
pub(crate) fn charged_key(src: Source, s: &SyncId, b: &BlobId) -> Vec<u8> {
    [CHARGED, &source_bytes(src), &s.0, &b.0].concat()
}
pub(crate) fn conn_total_key(c: crate::types::ConnId) -> Vec<u8> {
    [CONN_TOTAL, &c.0.to_be_bytes()].concat()
}
pub(crate) fn tomb_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [TOMB, &s.0, &b.0].concat()
}
pub(crate) fn tomb_at_key(at: WallMs, s: &SyncId, b: &BlobId) -> Vec<u8> {
    [TOMB_AT, &at.0.to_be_bytes(), &s.0, &b.0].concat()
}
pub(crate) fn expiry_key(t: WallMs, s: &SyncId, b: &BlobId) -> Vec<u8> {
    [EXPIRY, &t.0.to_be_bytes(), &s.0, &b.0].concat()
}
pub(crate) fn step_key(s: &SyncId, i: u32) -> Vec<u8> {
    [STEP, &s.0, &i.to_be_bytes()].concat()
}
pub(crate) fn claims_key(s: &SyncId, i: u32) -> Vec<u8> {
    [CLAIMS, &s.0, &i.to_be_bytes()].concat()
}
pub(crate) fn claims_due_key(at: WallMs, s: &SyncId, i: u32) -> Vec<u8> {
    [CLAIMS_DUE, &at.0.to_be_bytes(), &s.0, &i.to_be_bytes()].concat()
}
pub(crate) fn usage_key(s: &SyncId) -> Vec<u8> {
    [USAGE, &s.0].concat()
}
pub(crate) fn by_use_key(bytes: u64, s: &SyncId) -> Vec<u8> {
    [BY_USE, &(u64::MAX - bytes).to_be_bytes(), &s.0].concat()
}
pub(crate) fn aging_key(at: WallMs, s: &SyncId, tag: u8, key: &[u8], rec: &RecordId) -> Vec<u8> {
    [AGING, &at.0.to_be_bytes(), &s.0, &[tag], &(key.len() as u32).to_be_bytes(), key, rec].concat()
}

/// A plain byte writer.
#[derive(Default)]
pub(crate) struct W(Vec<u8>);

impl W {
    pub(crate) fn u8(mut self, v: u8) -> W {
        self.0.push(v);
        self
    }
    pub(crate) fn u32(mut self, v: u32) -> W {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn u64(mut self, v: u64) -> W {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn raw(mut self, v: &[u8]) -> W {
        self.0.extend_from_slice(v);
        self
    }
    pub(crate) fn take(self) -> Vec<u8> {
        self.0
    }
}

/// A plain byte reader; every short read is a corrupt row.
pub(crate) struct R<'a>(&'a [u8]);

fn corrupt() -> Error {
    Error::Store(osis_store::Error::Corrupt("sync store row"))
}

impl<'a> R<'a> {
    pub(crate) fn new(b: &'a [u8]) -> R<'a> {
        R(b)
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n).ok_or_else(corrupt)?;
        self.0 = b;
        Ok(a)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| corrupt())
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    pub(crate) fn end(&self) -> Result<()> {
        if self.0.is_empty() { Ok(()) } else { Err(corrupt()) }
    }
}

/// The trailing fixed-size ids of a key: `(s, b)` of `prefix || [extra] || s || b`.
pub(crate) fn tail_ids(key: &[u8]) -> Result<(SyncId, BlobId)> {
    let n = key.len();
    let s: [u8; 16] = key.get(n.wrapping_sub(48)..n.wrapping_sub(32)).and_then(|x| x.try_into().ok()).ok_or_else(corrupt)?;
    let b: [u8; 32] = key.get(n.wrapping_sub(32)..).and_then(|x| x.try_into().ok()).ok_or_else(corrupt)?;
    Ok((SyncId(s), BlobId(b)))
}

/// Who brought an unstamped entry, where its charge lives (spec/sync-ids.md §5 Peer budget): the
/// peer's record, durably, or the connection, while it lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    Record(RecordId),
    Conn(crate::types::ConnId),
}

/// An entry as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EntryRow {
    pub wrap: [u8; WRAP_LEN],
    pub stamp: Option<Signature>,
    pub deposited: bool,
    pub own: bool,
    /// Its stamp or deposit signature is a role entry's: outside the caps.
    pub role: bool,
    pub class: Class,
    pub expires: Option<WallMs>,
    /// The blob's size, 0 until its bytes are held.
    pub size: u64,
    /// Charged to this source (spec/sync-ids.md §5 Peer budget) while it gives nothing held.
    pub charged: Option<Source>,
    /// A source showed holding it (spec/sync-status.md §2 Held elsewhere): kept while the entry is.
    pub elsewhere: bool,
}

impl EntryRow {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let flags = u8::from(self.stamp.is_some()) | u8::from(self.deposited) << 1 | u8::from(self.own) << 2 | u8::from(self.role) << 3 | u8::from(self.elsewhere) << 4;
        let mut w = W::default().raw(&self.wrap).u8(flags);
        if let Some(st) = &self.stamp {
            w = w.raw(&st.0);
        }
        w = w.u8(self.class as u8).u64(self.expires.map_or(0, |t| t.0)).u64(self.size);
        match self.charged {
            None => w.u8(0),
            Some(Source::Record(r)) => w.u8(1).raw(&r),
            Some(Source::Conn(c)) => w.u8(2).u64(c.0),
        }
        .take()
    }

    pub(crate) fn decode(v: &[u8]) -> Result<EntryRow> {
        let mut r = R::new(v);
        let wrap = r.array()?;
        let flags = r.u8()?;
        let stamp = if flags & 1 != 0 { Some(Signature(r.array()?)) } else { None };
        let class = match r.u8()? {
            0 => Class::Durable,
            1 => Class::Ephemeral,
            _ => return Err(corrupt()),
        };
        let t = r.u64()?;
        let size = r.u64()?;
        let charged = match r.u8()? {
            0 => None,
            1 => Some(Source::Record(r.array()?)),
            2 => Some(Source::Conn(crate::types::ConnId(r.u64()?))),
            _ => return Err(corrupt()),
        };
        r.end()?;
        Ok(EntryRow { wrap, stamp, deposited: flags & 2 != 0, own: flags & 4 != 0, role: flags & 8 != 0, elsewhere: flags & 16 != 0, class, expires: (t != 0).then_some(WallMs(t)), size, charged })
    }
}

/// A tombstone (spec/sync-ids.md §5): when it was made, whether a verified Delete made it (else
/// the node's own judgement), and what its maker keeps with it (spec/sync-judgement.md §3: what
/// the entry was), opaque here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    pub at: WallMs,
    pub deleted: bool,
    pub note: Vec<u8>,
}

impl Tombstone {
    pub(crate) fn encode(&self) -> Vec<u8> {
        W::default().u64(self.at.0).u8(u8::from(self.deleted)).raw(&self.note).take()
    }
    pub(crate) fn decode(v: &[u8]) -> Result<Tombstone> {
        let mut r = R::new(v);
        Ok(Tombstone { at: WallMs(r.u64()?), deleted: r.u8()? != 0, note: r.rest().to_vec() })
    }
}

/// What a sync ID uses of the store (spec/sync-ids.md §6 Caps, spec/sync-inbox.md §3 Budget):
/// entries and bytes outside role entries (each entry's and tombstone's overhead, its blob, its
/// path's steps and claim sets), and its deposits waiting for a stamp. Kept beside the rows it
/// counts, in their transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub entries: u64,
    pub bytes: u64,
    pub deposits: u64,
    pub deposit_bytes: u64,
}

impl Usage {
    pub(crate) fn encode(&self) -> Vec<u8> {
        W::default().u64(self.entries).u64(self.bytes).u64(self.deposits).u64(self.deposit_bytes).take()
    }
    pub(crate) fn decode(v: &[u8]) -> Result<Usage> {
        let mut r = R::new(v);
        let u = Usage { entries: r.u64()?, bytes: r.u64()?, deposits: r.u64()?, deposit_bytes: r.u64()? };
        r.end()?;
        Ok(u)
    }
}

/// A step of a path as stored: when its child came (the claim set's `ROLE_KEEP` counts from it;
/// 0 while it is the head) and its bytes.
pub(crate) struct StepRow {
    pub superseded: Option<WallMs>,
    pub step: Vec<u8>,
}

impl StepRow {
    pub(crate) fn encode(&self) -> Vec<u8> {
        W::default().u64(self.superseded.map_or(0, |t| t.0)).raw(&self.step).take()
    }
    pub(crate) fn decode(v: &[u8]) -> Result<StepRow> {
        let mut r = R::new(v);
        let t = r.u64()?;
        Ok(StepRow { superseded: (t != 0).then_some(WallMs(t)), step: r.rest().to_vec() })
    }
}
