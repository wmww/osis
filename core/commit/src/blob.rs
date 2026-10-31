//! Commit blob plaintext `[Header, signature, [Part*]]` (spec/wire.md §4).

use crate::cbor::{as_idx, as_list, strictly_ascending};
use crate::header::{Header, LIMITS};
use crate::Error;
use osis_base::cbor::{MAJOR_ARRAY, MAJOR_UINT, encode_into, head};
use osis_base::{CommitId, CreationRecord, Value};
use osis_crypto::Signature;

/// One delta of a commit blob: aspect index, index into that aspect's hashes, canonical delta
/// (or snapshot) bytes, and the creation records an ephemeral commit carries beside it
/// (spec/commits.md §2): sorted by tid, distinct; none in a durable commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub ai: usize,
    pub di: usize,
    pub delta: Vec<u8>,
    pub records: Vec<CreationRecord>,
}

impl Part {
    /// A part carrying no records.
    pub fn new(ai: usize, di: usize, delta: Vec<u8>) -> Part {
        Part { ai, di, delta, records: Vec::new() }
    }
}

/// A commit as carried by one blob: the header, the signature and the deltas this blob holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBlob {
    pub header: Header,
    pub signature: Signature,
    /// Sorted by `(ai, di)`, distinct.
    pub parts: Vec<Part>,
}

impl CommitBlob {
    pub fn id(&self) -> CommitId {
        self.header.id()
    }

    /// Canonical plaintext bytes (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        encode_parts(&self.header.encode(), &self.signature, self.parts.iter())
    }

    /// Decodes a commit blob plaintext. Linked header lists stay unresolved; part indices are
    /// checked against the header by [`crate::verify_part`].
    pub fn decode(b: &[u8]) -> Result<CommitBlob, Error> {
        let v = osis_base::decode(b, &LIMITS)?;
        let [hv, sv, pv] = as_list(&v)? else { return Err(Error::Malformed("commit blob arity")) };
        let header = Header::from_value(hv)?;
        let signature = Signature::from_value(sv)?;
        let mut parts = Vec::new();
        for p in as_list(pv)? {
            let [ai, di, d, rs] = as_list(p)? else { return Err(Error::Malformed("part arity")) };
            if !matches!(d, Value::List(_)) {
                return Err(Error::Malformed("part delta"));
            }
            let records = as_list(rs)?.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("creation record"))).collect::<Result<Vec<_>, _>>()?;
            if !strictly_ascending(&records, CreationRecord::tid) {
                return Err(Error::Malformed("part records not sorted and distinct"));
            }
            if !records.is_empty() && header.ephemeral.is_none() {
                return Err(Error::Invalid("creation records beside a durable commit's delta"));
            }
            parts.push(Part { ai: as_idx(ai)?, di: as_idx(di)?, delta: osis_base::encode(d), records });
        }
        if !strictly_ascending(&parts, |p| (p.ai, p.di)) {
            return Err(Error::Malformed("parts not sorted and distinct"));
        }
        let blob = CommitBlob { header, signature, parts };
        if blob.encode() != b {
            return Err(Error::Malformed("commit blob not canonical"));
        }
        Ok(blob)
    }

    /// Deltas the header lists that this blob does not hold (purged, or in another projection).
    pub fn missing(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for (ai, a) in self.header.aspects.iter().enumerate() {
            for di in 0..a.hashes.len() {
                if self.parts.binary_search_by_key(&(ai, di), |p| (p.ai, p.di)).is_err() {
                    out.push((ai, di));
                }
            }
        }
        out
    }
}

/// `[Header, signature, [Part*]]` (a part `[ai, di, delta, [creation*]]`) by concatenation: header bytes and delta bytes are already
/// canonical items.
pub(crate) fn encode_parts<'a>(header: &[u8], sig: &Signature, parts: impl ExactSizeIterator<Item = &'a Part>) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, MAJOR_ARRAY, 3);
    out.extend_from_slice(header);
    encode_into(&sig.to_value(), &mut out);
    head(&mut out, MAJOR_ARRAY, parts.len() as u64);
    for p in parts {
        head(&mut out, MAJOR_ARRAY, 4);
        head(&mut out, MAJOR_UINT, p.ai as u64);
        head(&mut out, MAJOR_UINT, p.di as u64);
        out.extend_from_slice(&p.delta);
        encode_into(&records_value(&p.records), &mut out);
    }
    out
}

/// The records list of a part.
pub(crate) fn records_value(rs: &[CreationRecord]) -> Value {
    Value::List(rs.iter().map(CreationRecord::to_value).collect())
}
