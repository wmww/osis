//! The store's rows: their keys and their bytes. Every row is a local record of the node's
//! ciphertext store (`osis_store::Transaction::put_local`), keyed by a two-byte tag so each kind is
//! its own stamp family; a memo reading one row moves only when that row (or a scan's prefix)
//! is written. The memory part (`Inner::ram`) keeps the entry rows (`E X G M W B T t Y x U u S`)
//! of ephemeral entries alike, and every source's memory rows (`store::source`: `C/`, `K/`) with
//! their aging rows (`w`); the rest are the durable store's alone.
//!
//! - `E/ s b` an entry (`EntryRow`).
//! - `X/ b s` the sync IDs whose entries name blob `b`: its bytes go once none does and the
//!   engine holds it no more.
//! - `G/ b` the engine holds blob `b` (`osis_store::CipherStore::hold`; in the memory part, held in
//!   memory).
//! - `M/ b` the engine makes blob `b` again whenever asked (`osis_store::CipherStore::made`: a
//!   commit blob from its seal), value its length (u64): no bytes of it are kept but those the
//!   engine holds; read through `store::blob_bytes`.
//! - `W/ src s b` an entry charged to a source (`source_bytes`): a connection's go when it closes
//!   or at a start, a record's when the record is dropped; `V/ conn` the bytes charged to a
//!   connection in all (a record's total is in the record).
//! - `T/ s b` a tombstone (`Tomb`); `t/ at s b` tombstones by when they end, for the sweep;
//!   `Y/ b s` the sync IDs holding a tombstone of blob `b` (whether a delete of it is recent here).
//! - `x/ T s b` entries by prefix expiry, for the sweep.
//! - `P/ s i` step `i` of S's path from genesis: its bytes.
//! - `H/ s` the length of S's path.
//! - `U/ s` S's usage (`Usage`); `u/ !bytes s` sync IDs by bytes used, most first, for "the one using most".
//! - `w/ at s tag key src` rows a source holds of S that age out (stands, deletes seen), in the
//!   part of the row (`store::source`).
//! - `C/ src s tag key` a source's row in the memory part, `K/ s tag len key src` its index
//!   (`store::source`; a record's durable rows are its record's).
//! - `S/ s b` a source showed holding entry `b` of S (spec/sync-status.md §2 Held elsewhere),
//!   kept while the entry is; a row of its own so recording it moves no reader of the entry.
//! - `N/ s` S is owed a pull from the start, gone once streams set the sources' places of S
//!   back to the start (`Store::reset_anew`): value empty, its copy was dropped kept
//!   unread (`Store::set_unheld`, written with the drop; it takes nothing until judged again);
//!   `ANEW_RAISED`, S was raised from kept unread to read (`Store::set_holdings`) or a strong
//!   in its sync unit reaches a thing whose record the engine lacks (`CipherStore::refetch`); `ANEW_SOME`,
//!   pulled from the start only at the sources whose rows say so: told a refusal of S under
//!   another head (spec/sync-streams.md §4 Refused; S's head moved kept unread over a refusal
//!   told to a record's source, `path::register`), or whose room mark is owed (`Store::room_grew`,
//!   `Store::refused_may_be_gone`). `ANEW_SOME` is written over no other mark (those pull from
//!   every source).
//! - `R/ s cap` S kept unread is full (spec/sync-streams.md §4 Full): a pulled entry was refused
//!   for room by `cap` (`store::Cap`); value the bytes the least entry it refused needs under it
//!   and the latest expiry of one (`u64::MAX`: one has none), 8 bytes each (`Store::room_grew`).
//!   Stands only while some source's room mark of S does (`tag::ROOM_AT`, a connection's in
//!   memory).
//! - `F/ s` S's first sync here ended (spec/sync-streams.md §5): a source's stream of S stood at
//!   the end of a listing from the start; gone with S (`shred`).

use crate::types::{Error, Result};
use osis_base::{BlobId, SyncId, WallMs};
use osis_crypto::{Signature, WRAP_LEN};
use osis_blob::Class;
use osis_store::RecordId;

pub(crate) const ENTRY: &[u8] = b"E/";
pub(crate) const BY_BLOB: &[u8] = b"X/";
pub(crate) const ENGINE: &[u8] = b"G/";
pub(crate) const MADE: &[u8] = b"M/";
pub(crate) const CHARGED: &[u8] = b"W/";
pub(crate) const BROUGHT: &[u8] = b"B/";
pub(crate) const CONN_TOTAL: &[u8] = b"V/";
pub(crate) const TOMB: &[u8] = b"T/";
pub(crate) const TOMB_AT: &[u8] = b"t/";
pub(crate) const TOMB_BY_BLOB: &[u8] = b"Y/";
pub(crate) const EXPIRY: &[u8] = b"x/";
pub(crate) const STEP: &[u8] = b"P/";
pub(crate) const USAGE: &[u8] = b"U/";
pub(crate) const BY_USE: &[u8] = b"u/";
pub(crate) const AGING: &[u8] = b"w/";
pub(crate) const HEAD: &[u8] = b"H/";
/// Deposited (unstamped) entries per sync ID: what promotion, clearing and offering read.
pub(crate) const DEPOSITED: &[u8] = b"D/";
pub(crate) const ELSEWHERE: &[u8] = b"S/";
pub(crate) const ANEW: &[u8] = b"N/";
/// `ANEW`'s value for a raise to read (empty: a dropped copy).
pub(crate) const ANEW_RAISED: &[u8] = &[1];
/// `ANEW`'s value for a pull from the start at some sources only (a head move kept unread, a
/// room mark owed).
pub(crate) const ANEW_SOME: &[u8] = &[2];
/// A room mark's value (`tag::ROOM_AT`): it stands.
pub(crate) const ROOM_STANDS: u8 = 0;
/// A room mark's value: S is owed a pull from the start at that source (`ANEW_SOME`).
pub(crate) const ROOM_OWED: u8 = 1;
pub(crate) const ROOM: &[u8] = b"R/";
pub(crate) const FIRST: &[u8] = b"F/";

/// The tags of the rows each module keeps of a source: in a peer's record (`osis_store::
/// Transaction::record_put_row`, `record_put_wide_row` for a row about the record as a whole) or
/// in the memory part (`store::source`), one owner per tag (notes/sync-store.md). All go with
/// the source (a record's with the record, `RECORD_BUDGET`), a sync ID's also with their sync ID.
pub(crate) mod tag {
    // store: the peer budget's charges (record-wide), stands, deletes seen; a room mark: the
    // source's place passed an entry of S refused for room (spec/sync-streams.md §4 Full), value
    // `ROOM_STANDS` or `ROOM_OWED` (S is to be pulled from the start there, `ANEW_SOME`)
    pub(crate) const CHARGES: u8 = b'b';
    pub(crate) const STAND: u8 = b's';
    pub(crate) const SEEN: u8 = b'd';
    pub(crate) const ROOM_AT: u8 = b'f';
    // opens: the record's own state (record-wide), the peer's filter by generation (record-wide),
    // a member of the shared set
    pub(crate) const OPENS: u8 = b'R';
    pub(crate) const FILTER: u8 = b'F';
    pub(crate) const MEMBER: u8 = b'M';
    // streams: the stream's cursor (record-wide), a member at it, where a member not at it
    // joins from (joining, or stopped where it left: one row, so a member leaving one connection
    // and joining another from where it stood writes nothing); what the source showed: an entry
    // present, its head, a refusal standing, whether it keeps S unread as it last joined, that
    // it is full for S (told on a connection: a connection's row); the head this node last told
    // it a refusal of S under
    pub(crate) const CURSOR: u8 = b'c';
    pub(crate) const AT_STREAM: u8 = b'a';
    pub(crate) const JOIN_FROM: u8 = b'j';
    pub(crate) const PRESENT: u8 = b'k';
    pub(crate) const HEAD: u8 = b'h';
    pub(crate) const REFUSED: u8 = b'r';
    pub(crate) const KEPT: u8 = b'u';
    pub(crate) const FULL: u8 = b'n';
    pub(crate) const TOLD: u8 = b't';
    // streams: a member closed on the connection up, its place kept while that connection lasts;
    // the source's anchor (record-wide: `h` held, `n` waiting for a reply to check the held one)
    pub(crate) const CLOSED: u8 = b'l';
    pub(crate) const ANCHOR: u8 = b'g';
}

pub(crate) fn head_key(s: &SyncId) -> Vec<u8> {
    [HEAD, &s.0].concat()
}

pub(crate) fn entry_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [ENTRY, &s.0, &b.0].concat()
}
pub(crate) fn deposited_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [DEPOSITED, &s.0, &b.0].concat()
}
pub(crate) fn elsewhere_key(s: &SyncId, b: &BlobId) -> Vec<u8> {
    [ELSEWHERE, &s.0, &b.0].concat()
}
pub(crate) fn by_blob_key(b: &BlobId, s: &SyncId) -> Vec<u8> {
    [BY_BLOB, &b.0, &s.0].concat()
}
pub(crate) fn engine_key(b: &BlobId) -> Vec<u8> {
    [ENGINE, &b.0].concat()
}
pub(crate) fn made_key(b: &BlobId) -> Vec<u8> {
    [MADE, &b.0].concat()
}
/// A source as a key or row part (`R::source` reads it): 1 and a record, or `CONN` and a
/// connection.
pub(crate) fn source_bytes(src: Source) -> Vec<u8> {
    match src {
        Source::Record(r) => [&[1u8][..], &r].concat(),
        Source::Conn(c) => [&[CONN][..], &c.0.to_be_bytes()].concat(),
    }
}
pub(crate) const CONN: u8 = 2;
pub(crate) fn charged_key(src: Source, s: &SyncId, b: &BlobId) -> Vec<u8> {
    [CHARGED, &source_bytes(src), &s.0, &b.0].concat()
}
pub(crate) fn brought_key(src: Source, s: &SyncId, b: &BlobId) -> Vec<u8> {
    [BROUGHT, &source_bytes(src), &s.0, &b.0].concat()
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
pub(crate) fn anew_key(s: &SyncId) -> Vec<u8> {
    [ANEW, &s.0].concat()
}
pub(crate) fn first_key(s: &SyncId) -> Vec<u8> {
    [FIRST, &s.0].concat()
}
pub(crate) fn usage_key(s: &SyncId) -> Vec<u8> {
    [USAGE, &s.0].concat()
}
pub(crate) fn by_use_key(bytes: u64, s: &SyncId) -> Vec<u8> {
    [BY_USE, &(u64::MAX - bytes).to_be_bytes(), &s.0].concat()
}
pub(crate) fn aging_key(at: WallMs, s: &SyncId, tag: u8, key: &[u8], src: Source) -> Vec<u8> {
    [AGING, &at.0.to_be_bytes(), &s.0, &[tag], &(key.len() as u32).to_be_bytes(), key, &source_bytes(src)].concat()
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
    /// A source (`source_bytes`), or none (0).
    pub(crate) fn source(&mut self) -> Result<Option<Source>> {
        Ok(match self.u8()? {
            0 => None,
            1 => Some(Source::Record(self.array()?)),
            CONN => Some(Source::Conn(crate::types::ConnId(self.u64()?))),
            _ => return Err(corrupt()),
        })
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

/// The sync ID a key ends with.
pub(crate) fn tail_sync(key: &[u8]) -> Result<SyncId> {
    let s: [u8; 16] = key.get(key.len().wrapping_sub(16)..).and_then(|x| x.try_into().ok()).ok_or_else(corrupt)?;
    Ok(SyncId(s))
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
    /// The peer that brought it while uncharged (its stamp vouched, or it gave something held):
    /// charged to it once its stamp no longer vouches (`Store::charge_unvouched`); cleared when
    /// that peer goes.
    pub brought: Option<Source>,
    /// The verdict on its stamp kept where it entered (`Vouch`), under S's head write key then.
    pub vouch: Option<Vouch>,
}

/// A stamp verdict kept with its entry (notes/engine.md, Signature verdicts): the hash of the key
/// a stamp verified under with what it signs (S, the blob, the wrap) and the stamp. A check is a
/// function of those bytes alone, so it runs once where the entry enters and its verdict answers
/// every later check of exactly those bytes and that key (`Store::stamp_under`); another key,
/// wrap or stamp is checked anew. Made only by a check (`check_stamp`, `verify_stamp`), read
/// back only from this node's rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Vouch([u8; 32]);

impl Vouch {
    fn of(key: &osis_crypto::VerifyingKey, s: &SyncId, b: &BlobId, wrap: &[u8], stamp: &Signature) -> Vouch {
        let mut v = Vec::with_capacity(32 + 32 + 64);
        v.extend_from_slice(key.as_bytes());
        v.extend_from_slice(&osis_blob::entry_digest(s, b, wrap));
        v.extend_from_slice(&stamp.0);
        Vouch(osis_base::hash::hash(&v))
    }
}

/// Checks `stamp` on entry `b` of S under `wrap` against `key` (either domain): the domain it
/// verified under, and the verdict to keep with the entry, when it verifies.
pub(crate) fn verify_stamp(key: &osis_crypto::VerifyingKey, s: &SyncId, b: &BlobId, wrap: &[u8], stamp: &Signature) -> Option<(osis_blob::Signed, Vouch)> {
    let signed = osis_blob::verify_stamp(key, s, b, wrap, stamp).ok()?;
    Some((signed, Vouch::of(key, s, b, wrap, stamp)))
}

/// Whether `stamp` on entry `b` of S under `wrap` verifies under `key`: `kept` answers when it is
/// this check's verdict, else it is checked (`verify_stamp`). The verdict when it verifies.
pub(crate) fn check_stamp(key: &osis_crypto::VerifyingKey, s: &SyncId, b: &BlobId, wrap: &[u8], stamp: &Signature, kept: Option<Vouch>) -> Option<Vouch> {
    if kept_answers(key, s, b, wrap, stamp, kept) {
        return kept;
    }
    verify_stamp(key, s, b, wrap, stamp).map(|(_, v)| v)
}

/// Whether `kept` is the verdict that `stamp` on entry `b` of S under `wrap` verifies under `key`.
pub(crate) fn kept_answers(key: &osis_crypto::VerifyingKey, s: &SyncId, b: &BlobId, wrap: &[u8], stamp: &Signature, kept: Option<Vouch>) -> bool {
    kept.is_some_and(|k| k == Vouch::of(key, s, b, wrap, stamp))
}

impl EntryRow {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let flags = u8::from(self.stamp.is_some()) | u8::from(self.deposited) << 1 | u8::from(self.own) << 2 | u8::from(self.role) << 3;
        let mut w = W::default().raw(&self.wrap).u8(flags);
        if let Some(st) = &self.stamp {
            w = w.raw(&st.0);
        }
        w = w.u8(self.class as u8).u64(self.expires.map_or(0, |t| t.0)).u64(self.size);
        let src = |w: W, x: Option<Source>| match x {
            None => w.u8(0),
            Some(x) => w.raw(&source_bytes(x)),
        };
        let w = src(src(w, self.charged), self.brought);
        match &self.vouch {
            Some(v) => w.u8(1).raw(&v.0),
            None => w.u8(0),
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
        let (charged, brought) = (r.source()?, r.source()?);
        let vouch = match r.u8()? {
            0 => None,
            1 => Some(Vouch(r.array()?)),
            _ => return Err(corrupt()),
        };
        r.end()?;
        Ok(EntryRow { wrap, stamp, deposited: flags & 2 != 0, own: flags & 4 != 0, role: flags & 8 != 0, class, expires: (t != 0).then_some(WallMs(t)), size, charged, brought, vouch })
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
/// path's steps), of those the entries' (what give-way frees), and its deposits
/// waiting for a stamp. Kept beside the rows it counts, in their transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub entries: u64,
    pub bytes: u64,
    pub entry_bytes: u64,
    pub deposits: u64,
    pub deposit_bytes: u64,
}

impl Usage {
    /// The bytes no give-way frees: tombstones and path steps.
    pub(crate) fn fixed(&self) -> u64 {
        self.bytes.saturating_sub(self.entry_bytes)
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        W::default().u64(self.entries).u64(self.bytes).u64(self.entry_bytes).u64(self.deposits).u64(self.deposit_bytes).take()
    }
    pub(crate) fn decode(v: &[u8]) -> Result<Usage> {
        let mut r = R::new(v);
        let u = Usage { entries: r.u64()?, bytes: r.u64()?, entry_bytes: r.u64()?, deposits: r.u64()?, deposit_bytes: r.u64()? };
        r.end()?;
        Ok(u)
    }
}
