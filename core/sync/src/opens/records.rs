//! Opens' rows in a peer's record (spec/sync-opens.md §3): the record's own state (`acked_pos`,
//! this side's filter generations, the peer's filter's shape), the peer's filter by generation,
//! each member of the shared set with the beacon it was opened by, where each member that left
//! rejoins, and each sync ID walked there and not open. A record in use is held in memory while a connection holds it; its changes are
//! written at the end of the node's step (`Opens::flush`), after streams wrote the positions
//! they move, so a crash between the two leaves opens' older word, which streams' rows cover
//! (a member left is where streams stopped it; a rejoin's cursor is kept until opens' own write).

use super::{Member, OwnFilter, PeerFilter, Record, Rejoin};
use crate::store::rows::tag::{FILTER, MEMBER, OPENS, REJOIN, WALK};
use crate::types::{Credential, RecordId, SourceClass};
use osis_base::SyncId;
use osis_crypto::Epoch;
use osis_label::StepId;
use osis_proto::filter::{decode_gcs, encode_gcs};
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

fn encode_member(m: &Member, basis: Option<&[u8; 32]>) -> Vec<u8> {
    let mut w = vec![match m.class {
        SourceClass::Store => 0,
        SourceClass::Reader => 1,
    }];
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
            w.push(1);
            w.extend_from_slice(&p.to_be_bytes());
        }
        None => w.push(0),
    }
    opt32(&mut w, m.step.as_ref().map(|s| &s.0));
    opt32(&mut w, basis);
    w
}

fn decode_member(v: &[u8]) -> Res<(Member, Option<[u8; 32]>)> {
    let mut r = Rd(v);
    let class = match r.u8()? {
        0 => SourceClass::Store,
        1 => SourceClass::Reader,
        _ => return Err(corrupt()),
    };
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
    let until = if r.u8()? == 1 { Some(r.u64()?) } else { None };
    let step = r.opt32()?.map(StepId);
    let basis = r.opt32()?;
    r.end()?;
    Ok((Member { class, by, until, step }, basis))
}

fn encode_rejoin(j: &Rejoin) -> Vec<u8> {
    match j {
        Rejoin::Held => vec![0],
        Rejoin::From(None) => vec![1],
        Rejoin::From(Some(c)) => [&[2u8][..], c].concat(),
    }
}

fn decode_rejoin(v: &[u8]) -> Res<Rejoin> {
    match v.split_first() {
        Some((0, [])) => Ok(Rejoin::Held),
        Some((1, [])) => Ok(Rejoin::From(None)),
        Some((2, c)) => Ok(Rejoin::From(Some(c.to_vec()))),
        _ => Err(corrupt()),
    }
}

/// A generation's values as its row holds them (the filter's own coding).
pub(super) fn encode_values(values: &[u64]) -> Vec<u8> {
    encode_gcs(values, 0)
}

/// Record `id` as its rows hold it: none once it is gone. O(its members, the members that left
/// and its filter's entries): what a connection taking it needs.
pub(super) fn load(t: &mut Transaction<'_>, id: &RecordId) -> Res<Option<Record>> {
    let Some(rec) = t.record(id)? else { return Ok(None) };
    let mut r = Record { r: rec.r, actors: rec.actors, kept: true, members: BTreeMap::new(), basis: BTreeMap::new(), stopped: BTreeMap::new(), walking: BTreeSet::new(), acked_pos: 0, own: OwnFilter::default(), peer: None };
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
        let mut values = Vec::new();
        for (_, v) in t.record_wide_rows(id, FILTER)? {
            values.extend(decode_gcs(&v, 0, end).map_err(|_| corrupt())?);
        }
        values.sort_unstable();
        p.values = std::sync::Arc::new(values);
    }
    for (s, _, v) in t.record_tag_rows(id, MEMBER)? {
        let (m, basis) = decode_member(&v)?;
        r.members.insert(s, m);
        r.basis.insert(s, basis);
    }
    for (s, _, v) in t.record_tag_rows(id, REJOIN)? {
        r.stopped.insert(s, decode_rejoin(&v)?);
    }
    for (s, ..) in t.record_tag_rows(id, WALK)? {
        r.walking.insert(s);
    }
    Ok(Some(r))
}

/// Writes what changed of record `id` (held as `r`).
pub(super) fn write(t: &mut Transaction<'_>, id: &RecordId, r: &Record, d: Dirty) -> Res<()> {
    if d.used {
        t.record_used(id, &r.actors)?;
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
        match r.stopped.get(&s) {
            Some(j) => t.record_put_row(id, REJOIN, &s, b"", encode_rejoin(j))?,
            None => drop(t.record_remove_row(id, REJOIN, &s, b"")?),
        }
        if r.walking.contains(&s) {
            t.record_put_row(id, WALK, &s, b"", Vec::new())?;
        } else {
            t.record_remove_row(id, WALK, &s, b"")?;
        }
    }
    Ok(())
}
