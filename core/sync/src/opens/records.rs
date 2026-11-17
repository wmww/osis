//! Opens' rows in a peer's record (spec/sync-opens.md §3): the record's own state (`acked_pos`,
//! this side's filter generations, the peer's filter's shape), the peer's filter by generation,
//! each member of the shared set with the beacon it was opened by, and where this side's walk
//! of a sync ID stopped at the peer. Where a closed member stopped lasts its connection and is
//! never written. A record in use is held in memory while a connection holds it; its changes are
//! written at the end of the node's step (`Opens::flush`), after streams wrote the positions
//! they move, so a crash between the two leaves opens' older word, which streams' rows cover
//! (a member left is where streams stopped it).

use super::{Member, OwnFilter, PeerFilter, Record};
use crate::store::rows::tag::{FILTER, MEMBER, OPENS, WALK};
use crate::types::{Credential, RecordId, SourceClass};
use osis_base::SyncId;
use osis_crypto::Epoch;
use osis_store::{Error, Transaction};
use std::collections::{BTreeMap, BTreeSet};

/// What changed in a record since it was last written.
#[derive(Clone, Debug, Default)]
pub(super) struct Dirty {
    /// Its own state (`OPENS` row).
    pub core: bool,
    /// Taken by a connection: most recently used, naming its actors.
    pub used: bool,
    /// Members (and their rejoins) to write as memory holds them.
    pub members: BTreeSet<SyncId>,
    /// Generations of the peer's filter arrived, each encoded.
    pub filter: Option<Arrived>,
    /// Walk stops to write as memory holds them.
    pub walk: BTreeSet<SyncId>,
}

/// Generations of the peer's filter arrived (`true`: the first was whole, replacing every row
/// before it), each with its row.
pub(super) type Arrived = (bool, Vec<(u64, Vec<u8>)>);

type Res<T> = std::result::Result<T, Error>;

fn corrupt() -> Error {
    Error::Corrupt("opens record row")
}

struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n).ok_or_else(corrupt)?;
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Res<u8> {
        self.take(1)?.first().copied().ok_or_else(corrupt)
    }
    fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| corrupt())?))
    }
    fn a32(&mut self) -> Res<[u8; 32]> {
        self.take(32)?.try_into().map_err(|_| corrupt())
    }
    fn opt32(&mut self) -> Res<Option<[u8; 32]>> {
        Ok(if self.u8()? == 1 { Some(self.a32()?) } else { None })
    }
    fn end(&self) -> Res<()> {
        if self.0.is_empty() { Ok(()) } else { Err(corrupt()) }
    }
}

fn opt32(w: &mut Vec<u8>, v: Option<&[u8; 32]>) {
    match v {
        Some(b) => {
            w.push(1);
            w.extend_from_slice(b);
        }
        None => w.push(0),
    }
}

fn encode_core(r: &Record) -> Vec<u8> {
    let mut w = Vec::new();
    let o = &r.own;
    for v in [r.acked_pos, o.generation, o.acked] {
        w.extend_from_slice(&v.to_be_bytes());
    }
    w.push(o.f);
    for v in [o.whole, o.added, o.sent_reach, o.acked_reach] {
        w.extend_from_slice(&v.to_be_bytes());
    }
    match &r.peer {
        Some(p) => {
            w.push(1);
            w.extend_from_slice(&p.generation.to_be_bytes());
            w.push(p.f);
            for v in [p.whole, p.added, p.arrived] {
                w.extend_from_slice(&v.to_be_bytes());
            }
        }
        None => w.push(0),
    }
    w
}

fn class_byte(c: SourceClass) -> u8 {
    match c {
        SourceClass::Store => 0,
        SourceClass::Reader => 1,
    }
}

fn class_of(b: u8) -> Res<SourceClass> {
    match b {
        0 => Ok(SourceClass::Store),
        1 => Ok(SourceClass::Reader),
        _ => Err(corrupt()),
    }
}

fn encode_member(m: &Member, basis: Option<&[u8; 32]>) -> Vec<u8> {
    let mut w = vec![class_byte(m.class), class_byte(m.own)];
    match m.by {
        Credential::ReadSecret(e) => {
            w.push(0);
            w.extend_from_slice(&e.n().to_be_bytes());
            w.extend_from_slice(e.nonce());
        }
        Credential::SyncKey => w.push(1),
        Credential::SyncProof => w.push(2),
        Credential::Claim => w.push(3),
        Credential::Static(k) => {
            w.push(4);
            w.extend_from_slice(&k);
        }
        Credential::Deposit => w.push(5),
        Credential::J => w.push(6),
    }
    match m.until {
        Some(p) => {
            w.push(if m.departed { 2 } else { 1 });
            w.extend_from_slice(&p.to_be_bytes());
        }
        None => w.push(0),
    }
    opt32(&mut w, basis);
    w
}

fn decode_member(v: &[u8]) -> Res<(Member, Option<[u8; 32]>)> {
    let mut r = Rd(v);
    let class = class_of(r.u8()?)?;
    let own = class_of(r.u8()?)?;
    let by = match r.u8()? {
        0 => {
            let n = r.u64()?;
            Credential::ReadSecret(Epoch::new(n, r.a32()?).map_err(|_| corrupt())?)
        }
        1 => Credential::SyncKey,
        2 => Credential::SyncProof,
        3 => Credential::Claim,
        4 => Credential::Static(r.a32()?),
        5 => Credential::Deposit,
        6 => Credential::J,
        _ => return Err(corrupt()),
    };
    let (until, departed) = match r.u8()? {
        0 => (None, false),
        1 => (Some(r.u64()?), false),
        2 => (Some(r.u64()?), true),
        _ => return Err(corrupt()),
    };
    let basis = r.opt32()?;
    r.end()?;
    Ok((Member { class, own, by, until, departed }, basis))
}

/// Record `id` as its rows hold it: none once it is gone. O(its members and its filter's
/// entries): what a connection taking it needs.
pub(super) fn load(t: &mut Transaction<'_>, id: &RecordId) -> Res<Option<Record>> {
    let Some(rec) = t.record(id)? else { return Ok(None) };
    let mut r = Record { r: rec.r, named: rec.named, kept: true, members: BTreeMap::new(), basis: BTreeMap::new(), stopped: BTreeMap::new(), walk: BTreeMap::new(), acked_pos: 0, own: OwnFilter::default(), peer: None };
    if let Some(v) = t.record_get_wide_row(id, OPENS, b"")? {
        let mut d = Rd(&v);
        r.acked_pos = d.u64()?;
        let (generation, acked) = (d.u64()?, d.u64()?);
        let f = d.u8()?;
        r.own = OwnFilter { generation, acked, f, whole: d.u64()?, added: d.u64()?, sent_reach: d.u64()?, acked_reach: d.u64()? };
        if d.u8()? == 1 {
            let generation = d.u64()?;
            let f = d.u8()?;
            r.peer = Some(PeerFilter { generation, f, whole: d.u64()?, added: d.u64()?, arrived: d.u64()?, values: Default::default() });
        }
        d.end()?;
    }
    if let Some(p) = r.peer.as_mut() {
        let end = 1u64.checked_shl(u32::from(p.f)).unwrap_or(u64::MAX);
        let mut values = osis_proto::filter::Beacons::default();
        for (_, v) in t.record_wide_rows(id, FILTER)? {
            let mut run = osis_proto::filter::Run::default();
            run.extend_from_gcs(&v, 0, end).map_err(|_| corrupt())?;
            values.add(run);
        }
        p.values = std::sync::Arc::new(values);
    }
    for (s, _, v) in t.record_tag_rows(id, MEMBER)? {
        let (m, basis) = decode_member(&v)?;
        r.members.insert(s, m);
        r.basis.insert(s, basis);
    }
    for (s, _, v) in t.record_tag_rows(id, WALK)? {
        let mut d = Rd(&v);
        r.walk.insert(s, d.opt32()?);
        d.end()?;
    }
    Ok(Some(r))
}

/// Record `id`'s `acked_pos` as its rows hold it (0 before its own state is written).
pub(super) fn acked_pos(t: &mut Transaction<'_>, id: &RecordId) -> Res<u64> {
    match t.record_get_wide_row(id, OPENS, b"")? {
        Some(v) => Rd(&v).u64(),
        None => Ok(0),
    }
}

/// Writes what changed of record `id` (held as `r`).
pub(super) fn write(t: &mut Transaction<'_>, id: &RecordId, r: &Record, d: Dirty) -> Res<()> {
    if d.used {
        t.record_used(id, &r.named)?;
    }
    if let Some((whole, gens)) = d.filter {
        if whole {
            for (k, _) in t.record_wide_rows(id, FILTER)? {
                t.record_remove_wide_row(id, FILTER, &k)?;
            }
        }
        for (g, v) in gens {
            t.record_put_wide_row(id, FILTER, &g.to_be_bytes(), v)?;
        }
    }
    if d.core {
        t.record_put_wide_row(id, OPENS, b"", encode_core(r))?;
    }
    for s in d.members {
        match r.members.get(&s) {
            Some(m) => t.record_put_row(id, MEMBER, &s, b"", encode_member(m, r.basis.get(&s).copied().flatten().as_ref()))?,
            None => drop(t.record_remove_row(id, MEMBER, &s, b"")?),
        }
    }
    for s in d.walk {
        match r.walk.get(&s) {
            Some(x) => {
                let mut w = Vec::new();
                opt32(&mut w, x.as_ref());
                t.record_put_row(id, WALK, &s, b"", w)?
            }
            None => drop(t.record_remove_row(id, WALK, &s, b"")?),
        }
    }
    Ok(())
}
